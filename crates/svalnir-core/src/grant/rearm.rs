//! The budget generation of an incident and its rearm (`policy rearm`).
//!
//! `docs/POLICY_SPEC.md` section 8 and `docs/INTERFACES.md` sections 6 and
//! 13 own the rearm. A rearm is an explicit state transition: it records a
//! new authorized budget generation and keeps the usage of each earlier
//! generation. It does not end a cooldown, it does not settle an operation,
//! it does not resolve an unknown outcome, and it does not change a helper
//! limit. A rearm is separately authorized: it is refused while the guard
//! has no standing (disabled, a revoked or absent grant) and while a pause
//! is in effect.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::authorize::{RefusalReason, standing_refusal};
use super::guard::{GuardStanding, guard_standing};
use super::pause::{ControlClock, pause_status};
use super::state::{AuthorityState, InstanceInhibition, policy_id};
use crate::action::ErrorFamily;
use crate::authority::Generation;
use crate::id::IncidentId;
use crate::policy::{Cooldown, CooldownStatus, PolicyId, WorkUsage};
use crate::process::Uid;
use crate::time::WallTime;

/// The largest number of budget generations of one incident. A rearm of an
/// incident with this number of generations is refused: the history is
/// bounded, and no entry is removed to make room.
pub const MAX_BUDGET_GENERATIONS: usize = 64;

/// The usage of one budget generation of an incident.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "guard", rename_all = "snake_case")]
pub enum IncidentUsage {
    /// The usage of a disk incident.
    Disk {
        /// The charges against the incident ceilings.
        usage: WorkUsage,
        /// The number of passes that the incident started.
        passes_started: u32,
    },
    /// The usage of a memory incident.
    Memory {
        /// The application slots that the incident consumed.
        consumed_slots: u32,
        /// The application slots that the incident reserved.
        reserved_slots: u32,
    },
}

impl IncidentUsage {
    /// The guard of the usage.
    const fn policy(&self) -> PolicyId {
        match self {
            Self::Disk { .. } => PolicyId::DiskGuard,
            Self::Memory { .. } => PolicyId::MemoryGuard,
        }
    }

    /// Whether the usage has a reservation that is not consumed and not
    /// released.
    fn has_reservation(&self) -> bool {
        match self {
            Self::Disk { usage, .. } => {
                usage.reserved_bytes.get() != 0 || usage.reserved_items.get() != 0
            }
            Self::Memory { reserved_slots, .. } => *reserved_slots != 0,
        }
    }
}

/// How a budget generation started.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GenerationBasis {
    /// The incident opened.
    IncidentOpened,
    /// A user rearmed the incident.
    Rearmed,
}

/// The record of one budget generation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetGenerationRecord {
    /// The generation.
    pub generation: Generation,
    /// How the generation started.
    pub basis: GenerationBasis,
    /// The user that authorized the generation. `None` for the generation
    /// that the incident opened with.
    #[serde(deserialize_with = "crate::authority::required_option::deserialize")]
    pub authorized_by: Option<Uid>,
    /// The wall-clock time at which the generation started, for history
    /// only.
    pub started_at: WallTime,
    /// The usage of the generation at the time of the rearm that ended it.
    /// `None` for the current generation: the incident state has its
    /// usage.
    #[serde(deserialize_with = "crate::authority::required_option::deserialize")]
    pub final_usage: Option<IncidentUsage>,
}

/// The budget authority of one incident: the current budget generation and
/// the history of the generations.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IncidentBudget {
    /// The incident.
    pub incident_id: IncidentId,
    /// The guard of the incident.
    #[serde(with = "policy_id")]
    pub policy: PolicyId,
    /// The current budget generation.
    pub generation: Generation,
    /// One entry for each generation, in sequence. The last entry is the
    /// current generation.
    pub history: Vec<BudgetGenerationRecord>,
    /// True when the critical-memory exception of the journal was
    /// configured and granted for an active memory guard at the time the
    /// incident opened. The exception applies to an incident only with this
    /// record (`docs/POLICY_SPEC.md` section 13).
    pub volatile_exception_at_open: bool,
}

impl IncidentBudget {
    /// The record of an incident that opens at `now`, with the first
    /// budget generation.
    pub fn open(
        incident_id: IncidentId,
        policy: PolicyId,
        state: &AuthorityState,
        inhibition: &InstanceInhibition,
        now: WallTime,
    ) -> Self {
        let generation: Generation = Generation::new(1);
        let volatile_exception_at_open: bool = policy == PolicyId::MemoryGuard
            && guard_standing(state, inhibition, policy, now) == GuardStanding::Active
            && state
                .active
                .as_ref()
                .is_some_and(|active| active.scope.memory.allow_volatile_journal_on_critical)
            && state
                .guard(policy)
                .and_then(|guard| guard.grant.as_ref())
                .is_some_and(|grant| grant.allow_volatile_journal_on_critical);
        Self {
            incident_id,
            policy,
            generation,
            history: vec![BudgetGenerationRecord {
                generation,
                basis: GenerationBasis::IncidentOpened,
                authorized_by: None,
                started_at: now,
                final_usage: None,
            }],
            volatile_exception_at_open,
        }
    }
}

/// A request to rearm an incident
/// (`policy rearm POLICY --incident ID --generation GEN`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RearmRequest {
    /// The authenticated user of the request.
    pub principal: Uid,
    /// The guard.
    pub policy: PolicyId,
    /// The incident.
    pub incident_id: IncidentId,
    /// The budget generation that the user saw.
    pub generation: Generation,
}

/// What the caller knows about the incident at the time of the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncidentCondition<'a> {
    /// The usage of the current budget generation.
    pub usage: IncidentUsage,
    /// True when an operation of the incident is not settled.
    pub outstanding_operation: bool,
    /// True when an operation of the incident has an outcome that is not
    /// known and not reconciled, or when the journal cannot show that there
    /// is none.
    pub unknown_outcome: bool,
    /// The cooldowns of the incident and of its targets.
    pub cooldowns: &'a [Cooldown],
}

/// The reason a rearm was refused. The record does not change.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RearmRefusal {
    /// The request is from a different user than the record.
    #[error("the request is from a different user than the authority record")]
    WrongPrincipal,
    /// The request names a different incident or guard than the record.
    #[error("the request does not name the incident of the record")]
    UnknownIncident,
    /// The guard has no automatic authority, or a pause is in effect. The
    /// reason is that of the authorization:
    /// [`RefusalReason::GuardDisabled`], [`RefusalReason::ActionGrantRevoked`],
    /// [`RefusalReason::ActionGrantMissing`],
    /// [`RefusalReason::AutomationPaused`], or a different reason of a guard
    /// with no standing. A generation that the rearm recorded now would be
    /// usable at the next enable or resume with no new decision of the user.
    #[error("the guard has no standing for a rearm: {0}")]
    NotAuthorized(RefusalReason),
    /// The request names a budget generation that is not the current one.
    /// The user must look at the incident again.
    #[error("the budget generation {requested} is not the current generation {current}")]
    GenerationConflict {
        /// The generation that the request names.
        requested: Generation,
        /// The current generation.
        current: Generation,
    },
    /// An operation of the incident is not settled, or the incident has a
    /// reservation.
    #[error("an operation of the incident is not settled")]
    OperationUnsettled,
    /// An earlier outcome of the incident is not known. A rearm does not
    /// resolve it; reconciliation does.
    #[error("an earlier outcome of the incident is not known")]
    UnknownOutcome,
    /// The usage is of a different guard than the incident.
    #[error("the usage is not the usage of the guard of the incident")]
    UsageMismatch,
    /// The incident has the largest number of budget generations.
    #[error("the incident has the largest number of budget generations")]
    HistoryFull,
    /// The record does not agree with itself, or the generation cannot
    /// become larger.
    #[error("the budget record of the incident is not usable")]
    RecordNotUsable,
}

impl RearmRefusal {
    /// The stable error code of the refusal. A refusal of the standing has
    /// the code of its authorization reason.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::WrongPrincipal => "wrong_principal",
            Self::UnknownIncident => "incident_not_found",
            Self::NotAuthorized(reason) => reason.code(),
            Self::GenerationConflict { .. } => "generation_conflict",
            Self::OperationUnsettled => "incident_operation_unsettled",
            Self::UnknownOutcome => "incident_outcome_unknown",
            Self::UsageMismatch | Self::RecordNotUsable => "incident_record_not_usable",
            Self::HistoryFull => "budget_generations_exhausted",
        }
    }

    /// The error family of the refusal (`docs/ACTION_CONTRACTS.md`
    /// section 10).
    pub const fn family(&self) -> ErrorFamily {
        match self {
            Self::WrongPrincipal => ErrorFamily::Authority,
            Self::NotAuthorized(reason) => reason.family(),
            Self::UnknownIncident
            | Self::GenerationConflict { .. }
            | Self::UsageMismatch
            | Self::RecordNotUsable => ErrorFamily::Evidence,
            Self::OperationUnsettled | Self::HistoryFull => ErrorFamily::Limits,
            Self::UnknownOutcome => ErrorFamily::Outcome,
        }
    }
}

/// The result of a rearm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Rearm {
    /// The record to persist before the new generation is used.
    pub budget: IncidentBudget,
    /// The generation that the rearm ended.
    pub previous_generation: Generation,
    /// The generation that the rearm authorized. The caller starts its
    /// usage at zero; the usage of each earlier generation stays in the
    /// history.
    pub new_generation: Generation,
    /// The usage that the rearm recorded for the generation that it ended.
    pub retained_usage: IncidentUsage,
    /// The cooldowns that are not complete at the time of the request, or
    /// whose end is not known. The rearm does not change them: each one
    /// inhibits its work as before.
    pub cooldowns_in_force: Vec<Cooldown>,
}

/// Whether the history of `budget` has exactly one entry for each
/// generation from 1 to the current one, in sequence, and each entry before
/// the last one has its final usage.
fn history_is_complete(budget: &IncidentBudget) -> bool {
    let mut expected: Option<Generation> = Some(Generation::new(1));
    let last: usize = budget.history.len().saturating_sub(1);
    for (index, entry) in budget.history.iter().enumerate() {
        if expected != Some(entry.generation) || (index < last && entry.final_usage.is_none()) {
            return false;
        }
        expected = entry.generation.next();
    }
    budget
        .history
        .last()
        .is_some_and(|entry| entry.generation == budget.generation)
}

/// Rearms an incident: records a new authorized budget generation.
///
/// The request names the incident and the budget generation that the user
/// saw. Only the current generation matches; an earlier generation is a
/// conflict, so two requests for one generation give one rearm.
///
/// The rearm is an expansion. The caller persists [`Rearm::budget`] before
/// it uses the new generation; when the write fails, the earlier record
/// applies.
///
/// The rearm is separately authorized (`docs/POLICY_SPEC.md` section 8).
/// The guard must have the standing [`GuardStanding::Active`] in `state`
/// less `inhibition` at the wall-clock time of `clock`, and no pause of
/// the record or of the instance may be in effect at `clock`, a retained
/// pause of an earlier boot included.
///
/// # Errors
///
/// Returns a [`RearmRefusal`] with the first condition that is not true.
pub fn rearm(
    state: &AuthorityState,
    inhibition: &InstanceInhibition,
    budget: &IncidentBudget,
    condition: &IncidentCondition<'_>,
    request: &RearmRequest,
    clock: &ControlClock<'_>,
) -> Result<Rearm, RearmRefusal> {
    if request.principal != state.principal {
        return Err(RearmRefusal::WrongPrincipal);
    }
    if request.incident_id != budget.incident_id || request.policy != budget.policy {
        return Err(RearmRefusal::UnknownIncident);
    }
    let standing: GuardStanding = guard_standing(state, inhibition, request.policy, clock.wall);
    if let Some(reason) = standing_refusal(standing) {
        return Err(RearmRefusal::NotAuthorized(reason));
    }
    let paused: bool = [state.pause.as_ref(), inhibition.pause.as_ref()]
        .into_iter()
        .any(|pause| pause_status(pause, clock).is_paused());
    if paused {
        return Err(RearmRefusal::NotAuthorized(RefusalReason::AutomationPaused));
    }
    if request.generation != budget.generation {
        return Err(RearmRefusal::GenerationConflict {
            requested: request.generation,
            current: budget.generation,
        });
    }
    if condition.usage.policy() != budget.policy {
        return Err(RearmRefusal::UsageMismatch);
    }
    if condition.unknown_outcome {
        return Err(RearmRefusal::UnknownOutcome);
    }
    if condition.outstanding_operation || condition.usage.has_reservation() {
        return Err(RearmRefusal::OperationUnsettled);
    }
    // The history has one entry for each generation, from the first one.
    // A record with a missing entry does not show the usage of each
    // earlier generation, and its length is not the number of rearms, so
    // the limit below would not apply to it.
    if !history_is_complete(budget) {
        return Err(RearmRefusal::RecordNotUsable);
    }
    if budget.history.len() >= MAX_BUDGET_GENERATIONS {
        return Err(RearmRefusal::HistoryFull);
    }
    let new_generation: Generation = budget
        .generation
        .next()
        .ok_or(RearmRefusal::RecordNotUsable)?;
    let mut next: IncidentBudget = budget.clone();
    // The last entry is the current generation, with no final usage yet.
    match next.history.last_mut() {
        Some(current)
            if current.generation == budget.generation && current.final_usage.is_none() =>
        {
            current.final_usage = Some(condition.usage);
        }
        _ => return Err(RearmRefusal::RecordNotUsable),
    }
    next.history.push(BudgetGenerationRecord {
        generation: new_generation,
        basis: GenerationBasis::Rearmed,
        authorized_by: Some(request.principal),
        started_at: clock.wall,
        final_usage: None,
    });
    next.generation = new_generation;
    let cooldowns_in_force: Vec<Cooldown> = condition
        .cooldowns
        .iter()
        .filter(|cooldown| cooldown.status(clock.clock) != CooldownStatus::Elapsed)
        .cloned()
        .collect();
    Ok(Rearm {
        budget: next,
        previous_generation: budget.generation,
        new_generation,
        retained_usage: condition.usage,
        cooldowns_in_force,
    })
}
