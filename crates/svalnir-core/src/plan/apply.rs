//! The checks that an apply does before admission.
//!
//! Owning specifications: `docs/ACTION_CONTRACTS.md` section 4 (admission)
//! and `docs/INTERFACES.md` section 5 (manual approval). Each function is
//! pure and reserves nothing. A check that passes is not an admission: the
//! coordinator also checks the principal, the consumption of the plan, the
//! targets, the budgets, and the leases.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::mode::{PlanMode, mode_of};
use crate::action::{ErrorFamily, Plan, PlanApproval, PlanContent, TargetBinding};
use crate::authority::{ActionGrantRef, AuthorityBinding, PrivilegeGrantRef};
use crate::id::{ActionGrantId, PolicyRevisionId};
use crate::policy::EvaluationClock;
use crate::rule::RuleRef;

/// The part of an approval that does not agree with the plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ApprovalMismatch {
    /// The approval names a different plan.
    #[error("the approval names a different plan")]
    PlanId,
    /// The approval names a different digest: the plan that the client
    /// reviewed is not this plan.
    #[error("the approval names a different digest")]
    Digest,
    /// The approval is for a different mode. An approval of one mode does
    /// not apply a plan of a different mode.
    #[error("the approval is for a different mode")]
    Mode,
}

impl ApprovalMismatch {
    /// The error family: `authority`. The plan has no authorization that
    /// is bound to it.
    pub const fn family(&self) -> ErrorFamily {
        ErrorFamily::Authority
    }
}

/// Checks that an approval is bound to a plan: the same plan identity, the
/// same digest, and the same mode.
///
/// The digest covers the mode. The separate comparison of the mode rejects
/// a client that reviewed the digest of this plan and then asks for a
/// different application mode.
///
/// # Errors
///
/// Returns the first [`ApprovalMismatch`], in the sequence plan identity,
/// digest, mode.
pub fn check_approval(
    plan: &Plan,
    approval: &PlanApproval,
    mode: PlanMode,
) -> Result<(), ApprovalMismatch> {
    if approval.plan_id != plan.plan_id {
        return Err(ApprovalMismatch::PlanId);
    }
    if &approval.digest != plan.digest() || !plan.is_bound_by(approval) {
        return Err(ApprovalMismatch::Digest);
    }
    if mode_of(plan) != Some(mode) {
        return Err(ApprovalMismatch::Mode);
    }
    Ok(())
}

/// The reason a plan is not current at a time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ExpiryCause {
    /// The time is at the expiry time of the plan or after it.
    #[error("the plan is expired")]
    Expired,
    /// The clock of the check is in a different clock domain or boot. The
    /// two times are not comparable, so the plan is not shown to be
    /// current.
    #[error("the clock of the check is in a different clock domain or boot")]
    ClockNotComparable,
    /// The time is before the time at which the plan was built.
    #[error("the time of the check is before the time at which the plan was built")]
    BeforeCreation,
}

impl ExpiryCause {
    /// The error family: `limits`. A new plan is necessary.
    pub const fn family(&self) -> ErrorFamily {
        ErrorFamily::Limits
    }
}

/// Checks that a plan is not expired at `clock`.
///
/// The decision is the one of [`Plan::is_expired`]: the plan is expired at
/// its expiry time and after it, and in each context in which the two
/// times are not comparable.
///
/// # Errors
///
/// Returns the [`ExpiryCause`].
pub fn check_expiry(plan: &Plan, clock: &EvaluationClock) -> Result<(), ExpiryCause> {
    if !plan.is_expired(clock) {
        return Ok(());
    }
    let validity = &plan.validity;
    if clock.clock_domain != validity.clock_domain || clock.boot_id != validity.boot_id {
        Err(ExpiryCause::ClockNotComparable)
    } else if clock.now < validity.created_at {
        Err(ExpiryCause::BeforeCreation)
    } else {
        Err(ExpiryCause::Expired)
    }
}

/// The revisions that a plan binds: the policy revision, the grant
/// generations, and the rule revisions of its file targets.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BoundRevisions {
    /// The policy revision and the grant generations.
    pub authority: AuthorityBinding,
    /// The rule revisions, each one time, in their sort sequence.
    pub rules: Vec<RuleRef>,
}

/// The revisions that a plan content binds.
pub fn bound_revisions(plan: &PlanContent) -> BoundRevisions {
    let mut rules: Vec<RuleRef> = plan
        .targets
        .iter()
        .filter_map(|target| match &target.binding {
            TargetBinding::File(file) => file.rule.clone(),
            TargetBinding::OwnerOperation(owner) => Some(owner.rule.clone()),
            TargetBinding::Application(_) | TargetBinding::Process(_) => None,
        })
        .collect();
    rules.sort();
    rules.dedup();
    BoundRevisions {
        authority: plan.authority.clone(),
        rules,
    }
}

/// The revisions that are in effect at the time of a check. The caller
/// reads them from the authorization state and from the rule registry.
#[derive(Debug, Clone, Copy)]
pub struct CurrentRevisions<'a> {
    /// The effective policy revision.
    pub policy_revision: &'a PolicyRevisionId,
    /// The current generation of each action grant that is in effect. A
    /// revoked or expired grant is not in the list.
    pub action_grants: &'a [ActionGrantRef],
    /// The current generation of the privilege grant, when one is in
    /// effect.
    pub privilege_grant: Option<&'a PrivilegeGrantRef>,
    /// The exact rule revisions that the registry has now and that can do
    /// the mode of the plan.
    pub rules: &'a [RuleRef],
}

/// The bound revision that changed after the plan was built.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RevisionChange {
    /// The effective policy revision is not the one of the plan.
    #[error("the effective policy revision is not the one of the plan")]
    PolicyRevision,
    /// An action grant of the plan is not in effect, or has a different
    /// generation.
    #[error("the action grant {0} is not in effect with the generation of the plan")]
    ActionGrant(ActionGrantId),
    /// The privilege grant of the plan is not in effect, or has a
    /// different generation.
    #[error("the privilege grant is not in effect with the generation of the plan")]
    PrivilegeGrant,
    /// A rule revision of the plan is not registered for the mode. No
    /// other revision takes its place.
    #[error("the rule revision {} {} is not registered for the mode", .0.id, .0.revision)]
    Rule(RuleRef),
}

impl RevisionChange {
    /// The error family: `authority` for the policy revision and the
    /// grants, and `eligibility` for a rule revision.
    pub const fn family(&self) -> ErrorFamily {
        match self {
            Self::PolicyRevision | Self::ActionGrant(_) | Self::PrivilegeGrant => {
                ErrorFamily::Authority
            }
            Self::Rule(_) => ErrorFamily::Eligibility,
        }
    }
}

/// Checks that each revision that a plan binds is the one in effect.
///
/// The comparison is exact. A grant that was changed or revoked has a
/// larger generation, so it does not match. A plan that names no grant
/// binds none.
///
/// # Errors
///
/// Returns the first [`RevisionChange`], in the sequence policy revision,
/// action grants, privilege grant, rule revisions.
pub fn check_revisions(
    plan: &PlanContent,
    current: &CurrentRevisions<'_>,
) -> Result<(), RevisionChange> {
    let bound: BoundRevisions = bound_revisions(plan);
    if &bound.authority.policy_revision != current.policy_revision {
        return Err(RevisionChange::PolicyRevision);
    }
    for grant in &bound.authority.action_grants {
        if !current.action_grants.contains(grant) {
            return Err(RevisionChange::ActionGrant(grant.grant_id.clone()));
        }
    }
    if let Some(grant) = &bound.authority.privilege_grant
        && current.privilege_grant != Some(grant)
    {
        return Err(RevisionChange::PrivilegeGrant);
    }
    for rule in bound.rules {
        if !current.rules.contains(&rule) {
            return Err(RevisionChange::Rule(rule));
        }
    }
    Ok(())
}

/// The reason an apply request cannot go to admission.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ApplyRefusal {
    /// The approval is not bound to the plan.
    #[error(transparent)]
    Approval(#[from] ApprovalMismatch),
    /// The plan is not current.
    #[error(transparent)]
    Expiry(#[from] ExpiryCause),
    /// A bound revision changed.
    #[error(transparent)]
    Revision(#[from] RevisionChange),
}

impl ApplyRefusal {
    /// The error family of the refusal.
    pub const fn family(&self) -> ErrorFamily {
        match self {
            Self::Approval(mismatch) => mismatch.family(),
            Self::Expiry(cause) => cause.family(),
            Self::Revision(change) => change.family(),
        }
    }
}

/// Does the three checks of an apply request, in the sequence approval,
/// expiry, revisions.
///
/// # Errors
///
/// Returns the [`ApplyRefusal`] of the first check that fails. A refusal
/// makes no change, and it does not make the plan executable later: an
/// expired plan or a plan with a changed revision needs a new plan.
pub fn check_apply(
    plan: &Plan,
    approval: &PlanApproval,
    mode: PlanMode,
    clock: &EvaluationClock,
    current: &CurrentRevisions<'_>,
) -> Result<(), ApplyRefusal> {
    check_approval(plan, approval, mode)?;
    check_expiry(plan, clock)?;
    check_revisions(plan, current)?;
    Ok(())
}
