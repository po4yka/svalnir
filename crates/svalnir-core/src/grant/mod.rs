//! Activation and grant logic: the pure state transitions of the standing
//! authority of the product.
//!
//! Each function of this module is pure. The caller gives the current
//! record, the request, the time, and each new identity. The result is the
//! new record and a report, or a refusal with its reason. The module reads
//! no clock, file, or random source, and it does no storage: the caller
//! reads and writes the records.
//!
//! | Item | Contents |
//! | --- | --- |
//! | [`AuthorityState`], [`InstanceInhibition`] | The durable authority record of one user, and the volatile state of the running instance that only removes authority |
//! | [`Change`], [`Persistence`], [`Acknowledged`], [`AcknowledgementLevel`] | A change that is not persisted yet, and its acknowledgement level (`docs/INTERFACES.md` section 13) |
//! | [`PolicyScope`], [`difference`], [`effect_on`] | The scope of a revision and the typed difference of two scopes |
//! | [`activate`] | `config apply`: a new [`PolicyRevision`](crate::authority::PolicyRevision) against an expected revision |
//! | [`enable`], [`disable`], [`revoke`], [`guard_standing`] | `policy enable` and `policy disable`: the [`ActionGrant`](crate::authority::ActionGrant) of a guard |
//! | [`pause`], [`resume`], [`pause_status`] | `agent pause` and `agent resume` |
//! | [`IncidentBudget`], [`rearm`] | `policy rearm`: the budget generation of an incident |
//! | [`authorize`] | The authorization question of admission and of each dispatch boundary |
//!
//! # Rules that each function obeys
//!
//! - A change that adds authority applies only after it is durable. A
//!   change that removes authority applies to the running instance at
//!   once, also when it cannot be persisted; the acknowledgement then says
//!   so.
//! - A grant covers the scope that the user accepted and no wider scope.
//!   An activation with a wider scope leaves the grant bound to the earlier
//!   revision until a new acceptance.
//! - Each change and each revocation of a grant makes a larger generation,
//!   so a plan that names an earlier generation does not match.
//! - A profile, an activation, administrative access, and Full Disk Access
//!   make no grant.
//! - A value that this build does not recognize permits nothing.
//!
//! Owning specifications: `docs/ARCHITECTURE.md` section 11,
//! `docs/ACTION_CONTRACTS.md` sections 4, 10, 11, and 12,
//! `docs/POLICY_SPEC.md` sections 2, 5, 8, 13, and 14, and
//! `docs/INTERFACES.md` sections 5, 6, and 13.

mod activation;
mod authorize;
mod guard;
mod pause;
mod rearm;
mod scope;
mod state;
#[cfg(test)]
mod tests;

pub use activation::{
    ActivationRefusal, ActivationReport, ActivationRequest, GuardActivation, activate,
};
pub use authorize::{
    ActionRequest, Authorization, AuthorizationBasis, AuthorizationContext, EvidenceStamp, Refusal,
    RefusalReason, authorize,
};
pub use guard::{
    Acceptance, ControlRefusal, DisableRequest, EnableRefusal, EnableReport, EnableRequest,
    GuardStanding, RestrictionReport, RevokeRequest, disable, enable, guard_standing, revoke,
};
pub use pause::{
    ControlClock, MeasurementFloor, Pause, PauseBasis, PauseDeadline, PauseRefusal, PauseReport,
    PauseRequest, PauseStatus, ResumeRefusal, ResumeReport, ResumeRequest, measurement_floor,
    pause, pause_status, resume,
};
pub use rearm::{
    BudgetGenerationRecord, GenerationBasis, IncidentBudget, IncidentCondition, IncidentUsage,
    MAX_BUDGET_GENERATIONS, Rearm, RearmRefusal, RearmRequest, rearm,
};
pub use scope::{
    AffectedGuards, DiskScope, MemoryScope, PolicyScope, ProtectionTable, RuleScope, ScopeChange,
    ScopeDifference, ScopeDifferenceKind, ScopeEffect, ScopeError, ScopeSubject, Setting,
    Threshold, difference, effect_on,
};
pub use state::{
    Acknowledged, AcknowledgementLevel, ActiveRevision, AuthorityState, Change, GuardAuthority,
    InhibitedGuard, InhibitionCause, InstanceInhibition, Persistence,
};
