//! Deterministic policy evaluation and simulation.
//!
//! Owning specification: `docs/POLICY_SPEC.md`.
//!
//! Each function of this module is pure. The caller gives the validated
//! configuration, the evaluation time, the observations, the candidates, and
//! the state of the earlier evaluation. Equal inputs give an equal result.
//! The module reads no clock, file, or process, and it deletes and signals
//! nothing. Plans, action admission, the executor, and the journal are not
//! in this module.
//!
//! | Item | Contents |
//! | --- | --- |
//! | [`evaluate_disk_guard`], [`plan_cleanup`] | Capacity thresholds, hysteresis, cleanup candidates, and the first batch (sections 9 and 11) |
//! | [`evaluate_memory_guard`], [`plan_intervention`] | Global pressure, application budgets, candidate applications, and the first intervention (section 10) |
//! | [`advance`], [`QualificationWindow`] | Qualification windows as explicit state (section 6) |
//! | [`DecisionReason`], [`Explanation`] | Stable decision reasons (section 7) |
//! | [`TriggerState`], [`controller_summary`] | Incident states and the summary for presentation (section 8) |
//! | [`hard_protection`] | The catalog of hard protections of application and job instances (`docs/ACTION_CONTRACTS.md` section 8) |
//! | [`simulate`] | The simulation report (section 15) |
//! | [`list_policies`], [`show_policy`] | Descriptions of the standing policies |
//!
//! # Rules that each evaluation obeys
//!
//! - An observation that is unavailable, stale, of an unknown unit, or of a
//!   value that this build does not recognize is a problem. It is never a
//!   zero and never a normal state. Its trigger is [`TriggerState::Blocked`].
//! - A window counts only the time between distinct, usable observation
//!   instants that satisfy the predicate. A gap, a problem, a clock
//!   discontinuity, or a changed identity resets it.
//! - A reset does not clear an incident, its usage, or a latched episode.
//! - The state that an evaluation returns has windows and latches only. The
//!   caller owns the usage of an incident, its cooldowns, and its
//!   outstanding-operation flag.

mod control;
mod describe;
mod disk;
mod evidence;
mod file_protection;
mod memory;
mod protection;
mod reason;
mod simulate;
#[cfg(test)]
mod tests;
mod window;

pub use control::{
    AssumedGrants, CandidateDecision, ControllerSummary, Cooldown, CooldownCause, CooldownStatus,
    EvaluationContext, GrantBasis, MAX_APPLICATION_CANDIDATES, MAX_CANDIDATE_PROCESSES,
    MAX_CLEANUP_CANDIDATES, MAX_COOLDOWNS, MAX_CORROBORATING, MAX_REVISION_LABEL_BYTES,
    MAX_VOLUMES, PolicyId, PolicyInputError, ProtectionFact, TriggerState, controller_summary,
};
pub use describe::{
    AgentTimingView, AppBudgetView, DESCRIPTION_NOTE, DiskGuardView, MemoryGuardView,
    PolicyDescription, PolicyListEntry, PolicySettings, ProtectionsView, list_policies,
    show_policy,
};
pub use disk::{
    ActivityFact, CapacityDomainKey, CapacityLevel, CapacityOverview, CleanupCandidate,
    CleanupDecision, CleanupFacts, CleanupPlan, DiskAllowance, DiskEvaluation, DiskGuardState,
    DiskIncident, DiskSnapshot, DiskVolumeState, DomainCapacity, FirstBatch, OwnerFact,
    ProtectedDataClass, RebuildCost, RuleAllowance, RuleReadiness, VolumeEvidence, VolumeTrigger,
    WorkUsage, evaluate_disk_guard, plan_cleanup,
};
pub use evidence::{
    CORROBORATING_MEMORY_METRICS, CorroboratingEvidence, EvaluationClock, EvidenceProblem,
    EvidenceReport,
};
pub use file_protection::{
    FileProtectionContext, VIRTUAL_MEMORY_DIRECTORIES, file_hard_protection,
};
pub use memory::{
    AdmissionTrigger, ApplicationCandidate, ApplicationCooldown, ApplicationDecision,
    ApplicationKind, BudgetState, BudgetTrigger, ConfiguredProtectionMatch, ConfiguredProtections,
    FirstIntervention, FootprintLevel, ForceEscalation, ForegroundStatus, GlobalPressureTrigger,
    InterventionPlan, InventoryEvidence, MemoryEvaluation, MemoryGuardState, MemoryIncident,
    MemorySnapshot, configured_protections, evaluate_memory_guard, plan_intervention,
};
pub use protection::{
    CONTROL_PLANE_BUNDLE_IDENTIFIER, CONTROL_PLANE_EXECUTABLES, ControlPlaneProcess,
    HardProtectionEntry, HardProtectionExplanation, LOCAL_DIRECTORY, ProtectionContext,
    ProtectionMember, ProtectionUnknownCause, SESSION_BUNDLE_IDENTIFIERS, SYSTEM_DIRECTORIES,
    explain_hard_protection, hard_protection,
};
pub use reason::{DecisionReason, Explanation, ReasonDetail};
pub use simulate::{
    CandidateReport, FirstAction, PolicyState, RevisionLabel, RevisionSource, SIMULATION_STATEMENT,
    SimulationInput, SimulationReport, SnapshotStamp, TriggerReport, simulate,
};
pub use window::{
    ContinuityGeneration, OpenWindow, QualificationWindow, QualifyingSample, ResetCause,
    WindowBinding, WindowEvidence, WindowReport, WindowStep, WindowTransition, advance,
};
