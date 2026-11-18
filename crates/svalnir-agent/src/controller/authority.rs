//! The authority records behind the authority source of the coordinator.
//!
//! The coordinator reads the authority at admission, before each intent,
//! and immediately before each call. The runtime owns the records and
//! replaces them after each controller step and after each read of the
//! authority record of the journal. One mutex guards them; each critical
//! section copies or compares a few values and makes no file, journal, or
//! executor call.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use svalnir_core::action::{ApplicationBinding, Plan};
use svalnir_core::authority::ActionGrant;
use svalnir_core::grant::{
    ActionRequest, AuthorityState, Authorization, AuthorizationContext, ControlClock,
    IncidentBudget, InstanceInhibition, Refusal, authorize,
};
use svalnir_core::id::{IncidentId, PlanId};
use svalnir_core::plan::{CleanupMode, PlanMode};
use svalnir_core::policy::{ControlPlaneProcess, ProtectionContext, ProtectionFact};
use svalnir_core::process::Uid;
use svalnir_core::rule::{RuleMode, RuleRegistry};

use super::model::{TriggerKey, TriggerRecord};
use crate::coordinator::{AuthoritySource, RevisionSnapshot, TimeReading, TriggerStanding};

/// The largest number of automatic plans whose trigger the records keep.
/// The oldest plan is removed first; a plan with no entry has a trigger
/// that is not known, which permits no dispatch.
pub const MAX_PLAN_TRIGGERS: usize = 64;

/// The records that the authority source reads.
pub struct AuthorityRecords {
    /// The user of the agent.
    pub principal: Uid,
    /// The authority record of the journal. `None` when the journal has no
    /// record that this build can use: each automatic step is then
    /// refused, and so is each manual step, which needs a policy revision.
    pub state: Option<AuthorityState>,
    /// The inhibitions of this instance.
    pub inhibition: InstanceInhibition,
    /// The rule registry.
    pub registry: Box<dyn RuleRegistry + Send>,
    /// The budget record of each open incident.
    pub incidents: Vec<IncidentBudget>,
    /// The standing of each trigger at the latest controller step.
    pub triggers: Vec<TriggerRecord>,
    /// The trigger of each automatic plan, in the sequence of the plans.
    pub plans: Vec<(PlanId, TriggerKey)>,
    /// The processes of the control plane, for the hard-protection
    /// catalog.
    pub control_plane: Option<Vec<ControlPlaneProcess>>,
}

impl fmt::Debug for AuthorityRecords {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorityRecords")
            .field("principal", &self.principal)
            .field("has_state", &self.state.is_some())
            .field("incidents", &self.incidents.len())
            .field("plans", &self.plans.len())
            .finish_non_exhaustive()
    }
}

impl AuthorityRecords {
    /// Records with no authority, no incident, and no trigger.
    pub fn new(principal: Uid, registry: Box<dyn RuleRegistry + Send>) -> Self {
        Self {
            principal,
            state: None,
            inhibition: InstanceInhibition::default(),
            registry,
            incidents: Vec::new(),
            triggers: Vec::new(),
            plans: Vec::new(),
            control_plane: None,
        }
    }

    /// Records the trigger of an automatic plan before the plan is given
    /// to the coordinator.
    pub fn bind_plan(&mut self, plan_id: PlanId, trigger: TriggerKey) {
        self.plans.retain(|(known, _)| known != &plan_id);
        if self.plans.len() >= MAX_PLAN_TRIGGERS {
            self.plans.remove(0);
        }
        self.plans.push((plan_id, trigger));
    }
}

/// The shared authority records. Each copy reads the same records.
#[derive(Debug, Clone)]
pub struct SharedAuthority(Arc<Mutex<AuthorityRecords>>);

impl SharedAuthority {
    /// Makes the shared records.
    pub fn new(records: AuthorityRecords) -> Self {
        Self(Arc::new(Mutex::new(records)))
    }

    /// The records. A poisoned lock still has complete records, because
    /// each update is an assignment of a complete value.
    pub fn records(&self) -> MutexGuard<'_, AuthorityRecords> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl AuthoritySource for SharedAuthority {
    fn authorize(
        &self,
        request: &ActionRequest<'_>,
        time: &TimeReading,
    ) -> Result<Authorization, Refusal> {
        let records = self.records();
        // With no record, the state of a user with no policy revision
        // refuses each step with a specific reason.
        let empty: AuthorityState = AuthorityState::new(records.principal);
        let context: AuthorizationContext<'_> = AuthorizationContext {
            state: records.state.as_ref().unwrap_or(&empty),
            inhibition: &records.inhibition,
            registry: records.registry.as_ref(),
            clock: ControlClock {
                clock: &time.clock,
                wall: time.wall,
            },
        };
        authorize(&context, request)
    }

    fn revisions(&self, mode: PlanMode, time: &TimeReading) -> RevisionSnapshot {
        let records = self.records();
        let Some(state) = &records.state else {
            return RevisionSnapshot::default();
        };
        // The rule revisions that can do the mode now. Only the eviction
        // mode binds a rule.
        let rules = if matches!(mode, PlanMode::Cleanup(CleanupMode::Evict)) {
            records
                .registry
                .rules()
                .into_iter()
                .filter(|rule| {
                    rule.layouts
                        .iter()
                        .any(|layout| layout.lifecycle.permits(&RuleMode::ManualEviction))
                })
                .map(|rule| rule.reference.clone())
                .collect()
        } else {
            Vec::new()
        };
        RevisionSnapshot {
            policy_revision: state
                .active
                .as_ref()
                .map(|active| active.revision.revision_id.clone()),
            action_grants: state
                .guards
                .iter()
                .filter_map(|guard| guard.grant.as_ref())
                .filter(|grant| grant.is_in_effect(time.wall))
                .map(ActionGrant::reference)
                .collect(),
            rules,
        }
    }

    fn incident(&self, incident_id: &IncidentId) -> Option<IncidentBudget> {
        self.records()
            .incidents
            .iter()
            .find(|budget| &budget.incident_id == incident_id)
            .cloned()
    }

    fn trigger(&self, plan: &Plan, _time: &TimeReading) -> TriggerStanding {
        let records = self.records();
        let Some((_, key)) = records
            .plans
            .iter()
            .find(|(plan_id, _)| plan_id == &plan.plan_id)
        else {
            return TriggerStanding::Unknown;
        };
        // The trigger class of a plan does not change: a plan of the
        // budget trigger is not supported by the global trigger.
        if key.class() != plan.trigger.class {
            return TriggerStanding::Unknown;
        }
        let standings: BTreeMap<&TriggerKey, &TriggerStanding> = records
            .triggers
            .iter()
            .map(|record| (&record.key, &record.standing))
            .collect();
        standings
            .get(key)
            .map_or(TriggerStanding::Unknown, |standing| (*standing).clone())
    }

    fn protection(&self, binding: &ApplicationBinding) -> ProtectionFact {
        let records = self.records();
        binding.hard_protection(&ProtectionContext {
            principal: records.principal,
            control_plane: records.control_plane.as_deref(),
        })
    }
}
