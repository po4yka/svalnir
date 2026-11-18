//! The rearm of an incident by the controller (`policy rearm`).
//!
//! The controller has the budget record of each open incident. A rearm
//! request names the incident and the generation that the user saw; the
//! controller decides it with [`svalnir_core::grant::rearm`] against its
//! own record and the authority record that the agent read, and applies
//! the new generation with [`ControllerState::apply_rearm`].

use svalnir_core::action::ErrorFamily;
use svalnir_core::grant::{
    AuthorityState, ControlClock, IncidentBudget, IncidentCondition, IncidentUsage,
    InstanceInhibition, Rearm, RearmRefusal, RearmRequest, rearm,
};
use svalnir_core::id::ExecutorEpochId;
use svalnir_core::policy::Cooldown;

use super::model::ControllerState;

/// Why the controller did not rearm an incident. The state did not
/// change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RearmFailure {
    /// The grant module refused the rearm.
    Refused(RearmRefusal),
    /// The controller did not take the new generation: a plan of the
    /// incident started after the check, or the record changed.
    NotApplied,
}

impl RearmFailure {
    /// The stable error code of the failure.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Refused(refusal) => refusal.code(),
            Self::NotApplied => "incident_operation_unsettled",
        }
    }

    /// The error family of the failure.
    pub const fn family(&self) -> ErrorFamily {
        match self {
            Self::Refused(refusal) => refusal.family(),
            Self::NotApplied => ErrorFamily::Limits,
        }
    }
}

/// What the controller knows about one open incident for a rearm.
struct Known<'a> {
    budget: &'a IncidentBudget,
    usage: IncidentUsage,
    outstanding_operation: bool,
    unknown_outcome: bool,
    cooldowns: Vec<Cooldown>,
}

impl ControllerState {
    /// The budget record and the condition of the open incident of
    /// `request`. `Err` when no open incident has its identity, or when the
    /// policy state has no usage for it.
    fn known_incident(&self, request: &RearmRequest) -> Result<Known<'_>, RearmRefusal> {
        let planned: bool = self
            .outstanding
            .as_ref()
            .is_some_and(|plan| plan.incident_id == request.incident_id);
        if let Some(record) = self
            .disk_incidents
            .iter()
            .find(|record| record.incident_id == request.incident_id)
        {
            let incident = self
                .policy
                .disk
                .incidents
                .iter()
                .find(|incident| incident.domain == record.domain)
                .ok_or(RearmRefusal::RecordNotUsable)?;
            return Ok(Known {
                budget: &record.budget,
                usage: IncidentUsage::Disk {
                    usage: incident.usage,
                    passes_started: incident.passes_started,
                },
                outstanding_operation: planned || incident.outstanding_operation,
                unknown_outcome: record.unknown_outcome,
                cooldowns: record
                    .observe_until
                    .iter()
                    .chain(incident.cooldown.iter())
                    .cloned()
                    .collect(),
            });
        }
        match &self.memory_incident {
            Some(record) if record.incident_id == request.incident_id => {
                let incident = self
                    .policy
                    .memory
                    .incident
                    .ok_or(RearmRefusal::RecordNotUsable)?;
                Ok(Known {
                    budget: &record.budget,
                    usage: IncidentUsage::Memory {
                        consumed_slots: incident.consumed_slots,
                        reserved_slots: incident.reserved_slots,
                    },
                    outstanding_operation: planned || incident.outstanding_operation,
                    unknown_outcome: record.unknown_outcome,
                    cooldowns: record
                        .observe_until
                        .iter()
                        .chain(record.backoff.iter())
                        .cloned()
                        .collect(),
                })
            }
            _ => Err(RearmRefusal::UnknownIncident),
        }
    }

    /// Rearms an open incident: checks the request with
    /// [`svalnir_core::grant::rearm`] against `authority` less
    /// `inhibition` at `clock` (the standing of the guard, the pause, the
    /// generation, and the condition of the incident), and applies the new
    /// generation with [`ControllerState::apply_rearm`] in the lifetime
    /// `epoch`.
    ///
    /// The caller persists the state before a plan uses the new
    /// generation, and restores the earlier state when the write fails.
    ///
    /// # Errors
    ///
    /// Returns [`RearmFailure::Refused`] with the refusal of the grant
    /// module, and [`RearmFailure::NotApplied`] when the controller did
    /// not take the generation. The state is then not changed.
    pub fn rearm(
        &mut self,
        authority: &AuthorityState,
        inhibition: &InstanceInhibition,
        request: &RearmRequest,
        clock: &ControlClock<'_>,
        epoch: &ExecutorEpochId,
    ) -> Result<Rearm, RearmFailure> {
        let result: Rearm = {
            let known: Known<'_> = self
                .known_incident(request)
                .map_err(RearmFailure::Refused)?;
            let condition: IncidentCondition<'_> = IncidentCondition {
                usage: known.usage,
                outstanding_operation: known.outstanding_operation,
                unknown_outcome: known.unknown_outcome,
                cooldowns: &known.cooldowns,
            };
            rearm(
                authority,
                inhibition,
                known.budget,
                &condition,
                request,
                clock,
            )
            .map_err(RearmFailure::Refused)?
        };
        if !self.apply_rearm(result.budget.clone(), epoch) {
            return Err(RearmFailure::NotApplied);
        }
        Ok(result)
    }
}
