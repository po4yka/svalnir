//! The manual plan builder.
//!
//! This module builds an immutable [`Plan`](crate::action::Plan) for a
//! manual cleanup (`MoveToTrash`, `DeleteSelectedFiles`, or manual
//! `EvictRegenerableData`) and for a manual application stop. It also has
//! the checks that a later apply needs and the explanation of a plan.
//!
//! Each function is pure. The caller supplies the identities, the evidence,
//! the clock, and the limits. The module reads no clock, file, or process.
//! A plan reserves nothing and authorizes nothing.
//!
//! Owning specifications: `docs/ACTION_CONTRACTS.md` sections 2 to 5 and 8,
//! `docs/INTERFACES.md` sections 4 to 6, `docs/CLEANUP_RULES.md` sections 5,
//! 8, 9, and 13, and `docs/POLICY_SPEC.md` for `manual_plan_ttl`.
//!
//! | Item | Contents |
//! | --- | --- |
//! | [`build_cleanup_plan`] | A plan for the `trash`, `permanent`, or `evict` mode, with its batches and the entries that were left out |
//! | [`build_stop_plan`] | A plan for one verified application or job instance |
//! | [`split_batches`] | The batches of a filesystem plan under a batch ceiling |
//! | [`check_apply`], [`check_approval`], [`check_expiry`], [`check_revisions`] | The checks before an apply |
//! | [`explain`] | The explanation of a plan for `clean show` |
//!
//! # Rules that each builder obeys
//!
//! - A plan is made only with [`Plan::seal`](crate::action::Plan::seal), so
//!   the checks of the foundation apply and the digest is the digest of the
//!   full plan content.
//! - A target with a protection, an exclusion, or a fact that is not known
//!   is left out, with each reason. A mode, a preset, or a force strategy
//!   cannot include it.
//! - A plan with no target has no value of the plan type. The result then
//!   has no plan and explains each entry that was left out. That result is
//!   not an error.
//! - The result does not depend on the sequence of the input: targets,
//!   steps, members, and grant references have one canonical sequence.
//! - Arithmetic on charges and times is checked. A sum that overflows or a
//!   charge that does not fit leaves the entry out.

mod apply;
mod cleanup;
mod context;
mod explain;
mod mode;
mod paths;
mod reason;
mod stop;
#[cfg(test)]
mod tests;

pub use apply::{
    ApplyRefusal, ApprovalMismatch, BoundRevisions, CurrentRevisions, ExpiryCause, RevisionChange,
    bound_revisions, check_apply, check_approval, check_expiry, check_revisions,
};
pub use cleanup::{
    BatchError, CleanupEntry, CleanupLimits, CleanupRequest, MAX_SELECTED_ENTRIES, ModeSelection,
    RuleEvidence, SelectionPreset, build_cleanup_plan, split_batches,
};
pub use context::{
    PlanBatch, PlanBuildError, PlanContext, PlanOutcome, PlanPreview, SizeEstimate, TargetPreview,
    manual_plan_lifetime,
};
pub use explain::{
    Consequence, ESTIMATE_STATEMENT, ExpiryView, MemberView, PlanExplanation, PlanSummary,
    TargetExplanation, Totals, explain,
};
pub use mode::{CleanupMode, PlanMode, StopKind, mode_of};
pub use reason::{Omission, OmissionReason};
pub use stop::{StopLimits, StopRequest, StopStepIds, StopStrategy, build_stop_plan};
