//! The guard controllers.
//!
//! The controller is the deterministic link between the observations and
//! the coordinator. It gives fresh observations and the incident state to
//! the pure evaluation of [`svalnir_core::policy`], keeps the windows, the
//! incidents, the budgets, the cooldowns, and the backoff between two
//! steps, and decides at most one automatic plan.
//!
//! Owning specification: `docs/POLICY_SPEC.md`. See also
//! `docs/ARCHITECTURE.md` sections 6 and 15.
//!
//! # Interface
//!
//! | Item | Use |
//! | --- | --- |
//! | [`step`] | The pure step: state, policy, grants, observations, and time in; the new state, the intents, the status, and the trigger standings out. |
//! | [`ControllerState`] | The state between two steps. [`ControllerState::durable_view`] is the stored form, and [`ControllerState::restore`] makes the state of a new executor lifetime. |
//! | [`Intent`] | What the runtime does: prepare candidates, apply an automatic plan, notify, reduce optional work, or nothing. |
//! | [`ApplyReport`] | What the runtime tells the next step about a plan: admitted, refused, or finished. |
//! | [`ControllerStatus`] | The compact status for a client, with the summary state and a specific reason for each inhibited guard. |
//! | [`SharedAuthority`] | The authority records behind the [`AuthoritySource`](crate::coordinator::AuthoritySource) of the coordinator. |
//!
//! # Decision and side effect
//!
//! [`step`] reads no clock, no file, and no process, and it changes
//! nothing. The runtime collects the observations, reads the time, calls
//! the step, and carries out the intents. A test gives recorded or
//! synthetic observations and moves the time.
//!
//! # Rules of the step
//!
//! - One automatic plan at a time. The memory guard decides first, so a
//!   critical-memory decision never waits for the disk guard or for a
//!   candidate preparation.
//! - The disk guard uses only a prepared candidate set. With a qualified
//!   trigger it asks for [`PreparationMode::KnownOnly`], which lists no
//!   directory. A bounded discovery ([`PreparationMode::Refresh`]) is
//!   optional work of a warning state with no memory pressure.
//! - A rule whose layout does not permit automatic eviction gives the
//!   reason [`BlockedReason::RuleNotValidated`]. The controller does not
//!   select the candidates of such a rule and makes no plan for them.
//! - After each action the incident waits for `observe_after_action`
//!   before the next target or batch is selected. A low benefit ends the
//!   pass of a disk incident and starts a backoff; a memory incident takes
//!   the next eligible application after the backoff, within the same
//!   slots. Nothing makes the policy wider.
//! - No automatic intent is made while a pause is in effect, while the
//!   grant module does not give the standing `active`, or while the journal
//!   has no usable authority record. After the end of a pause, a trigger
//!   needs a measurement that is newer than that end.
//! - A restart keeps the usage and the cooldowns. A plan that was in
//!   progress is charged in full, and its incident permits no automatic
//!   work until it closes or a person rearms it. A record that is not
//!   readable holds each guard until an evaluation shows no pressure.

mod authority;
mod model;
mod step;
#[cfg(test)]
pub(crate) mod tests;

pub use self::authority::{AuthorityRecords, MAX_PLAN_TRIGGERS, SharedAuthority};
pub use self::model::{
    ApplyReport, AutomaticApply, BlockedReason, CONTROLLER_STATE_VERSION,
    CONTROLLER_STATUS_VERSION, CandidateSet, ControllerState, ControllerStatus, DiskIncidentRecord,
    Guard, GuardPhase, GuardStatus, Health, IncidentStatus, Intent, MAX_APPLICATION_COOLDOWNS,
    MAX_PREPARED_CANDIDATES, MAX_REPORTS, MAX_STATUS_REASONS, MemoryIncidentRecord, MonotonicMark,
    Notification, Observations, OperationResult, Outstanding, PreparationMode, PreparedCandidate,
    PriorState, ReduceReason, ReportedCondition, RuleUsage, StepInput, StepOutput, Summary,
    TriggerKey, TriggerRecord,
};
pub use self::step::step;
