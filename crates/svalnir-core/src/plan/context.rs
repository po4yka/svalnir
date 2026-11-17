//! The inputs and the result that the two builders share.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::mode::PlanMode;
use super::reason::Omission;
use crate::action::{
    ErrorFamily, ExecutorRole, PLAN_SCHEMA_VERSION, Plan, PlanContent, PlanError, PlanLimits,
    PlanTarget, PlannedStep, Principal, Trigger, Validity, WorkCharge,
};
use crate::authority::{ActionGrantRef, AuthorityBinding};
use crate::config::{Protections, ValidatedConfig};
use crate::file::LosslessPath;
use crate::id::{PlanId, StepId, TargetId};
use crate::policy::EvaluationClock;
use crate::quantity::{Bytes, Nanoseconds};
use crate::rule::RuleRefusal;
use crate::time::{MonotonicNanos, WallTime};

/// The lifetime of a manual plan: `[agent].manual_plan_ttl` of the
/// configuration (`docs/POLICY_SPEC.md` section 3).
///
/// The result is `None` when the value does not fit in a nanosecond count.
/// The validated configuration has a finite, positive value.
pub fn manual_plan_lifetime(config: &ValidatedConfig) -> Option<Nanoseconds> {
    Nanoseconds::try_from(config.agent().manual_plan_ttl).ok()
}

/// The inputs that each manual plan needs. The caller reads the clock and
/// makes the new plan identity; this module does not.
#[derive(Debug, Clone)]
pub struct PlanContext<'a> {
    /// The identity of the new plan.
    pub plan_id: PlanId,
    /// The authenticated user and client that the plan is for.
    pub principal: Principal,
    /// The policy revision and the grant generations that the plan binds.
    /// A manual plan of the user executor names no privilege grant.
    pub authority: AuthorityBinding,
    /// The time at which the plan is built.
    pub clock: &'a EvaluationClock,
    /// The wall-clock time at which the plan is built, for history only.
    pub created_wall: WallTime,
    /// The time for which the plan is valid. See
    /// [`manual_plan_lifetime`].
    pub lifetime: Nanoseconds,
    /// The `[protections]` table of the effective configuration. It applies
    /// to manual and automatic actions.
    pub protections: &'a Protections,
    /// The home directory of the principal, for a path that starts with
    /// `~/`. With no usable home directory, such a path stays unresolved
    /// and each target that it can apply to is left out.
    pub home_directory: Option<&'a LosslessPath>,
}

/// The reason a builder made no result. The inputs do not describe a
/// request that a plan can express. A target that a protection or a limit
/// leaves out is not an error: see [`PlanOutcome`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum PlanBuildError {
    /// The selection has more entries than the builder examines.
    #[error("the selection has {count} entries; the limit is {limit}")]
    TooManyEntries {
        /// The number of entries.
        count: usize,
        /// The limit.
        limit: usize,
    },
    /// Two entries have the same target identity or the same step
    /// identity, or two steps of one target have the same identity.
    #[error("two entries have the same target identity or step identity")]
    DuplicateIdentity,
    /// Two entries of one root identity have different root paths.
    #[error("two entries of one root identity have different root paths")]
    RootPath,
    /// The `evict` mode has no exact rule revision: the registry refused
    /// the lookup. No generic cleaner takes the place of the rule.
    #[error("the evict mode has no exact rule revision: {0}")]
    Rule(#[source] RuleRefusal),
    /// The rule revision needs an executor that a manual plan does not
    /// have.
    #[error("the rule revision needs an executor that a manual plan does not have")]
    UnsupportedExecutor,
    /// The authority names a privilege grant, or names one action grant
    /// with two generations.
    #[error("the authority of the plan does not agree with a manual plan of the user executor")]
    Authority,
    /// The principal of the protection context is not the principal of the
    /// plan.
    #[error("the protection context is for a different principal")]
    Principal,
    /// The lifetime is zero, or the expiry is not a monotonic time.
    #[error("the lifetime of the plan is zero or its expiry overflows")]
    Lifetime,
    /// A duration is zero or is larger than its bound, or the durations do
    /// not fit in the execution deadline or in the lifetime of the plan.
    #[error("a duration of the plan is zero or does not fit its bound")]
    Limits,
    /// The check of the foundation rejected the plan content.
    #[error("the plan content was rejected: {0}")]
    Plan(#[source] PlanError),
}

impl PlanBuildError {
    /// The error family (`docs/ACTION_CONTRACTS.md` section 10).
    pub const fn family(&self) -> ErrorFamily {
        match self {
            Self::DuplicateIdentity | Self::RootPath | Self::Plan(_) => ErrorFamily::Request,
            Self::Rule(_) | Self::UnsupportedExecutor => ErrorFamily::Eligibility,
            Self::Authority | Self::Principal => ErrorFamily::Authority,
            Self::TooManyEntries { .. } | Self::Lifetime | Self::Limits => ErrorFamily::Limits,
        }
    }
}

impl PlanContext<'_> {
    /// The validity of the plan: from the time of the clock to that time
    /// plus the lifetime.
    pub(super) fn validity(&self) -> Result<Validity, PlanBuildError> {
        if self.lifetime == Nanoseconds::ZERO {
            return Err(PlanBuildError::Lifetime);
        }
        let created_at: MonotonicNanos = self.clock.now;
        let expires_at: MonotonicNanos = created_at
            .checked_add(self.lifetime)
            .ok_or(PlanBuildError::Lifetime)?;
        Ok(Validity {
            clock_domain: self.clock.clock_domain.clone(),
            boot_id: self.clock.boot_id.clone(),
            created_at,
            expires_at,
            created_wall: self.created_wall,
        })
    }

    /// The authority in its canonical sequence: the grant references by
    /// grant identity, each one time.
    pub(super) fn canonical_authority(&self) -> Result<AuthorityBinding, PlanBuildError> {
        // A manual plan has the user executor, which names no privilege
        // grant.
        if self.authority.privilege_grant.is_some() {
            return Err(PlanBuildError::Authority);
        }
        let mut grants: Vec<ActionGrantRef> = self.authority.action_grants.clone();
        grants.sort();
        grants.dedup();
        let has_two_generations: bool = grants
            .windows(2)
            .any(|pair| matches!(pair, [left, right] if left.grant_id == right.grant_id));
        if has_two_generations {
            return Err(PlanBuildError::Authority);
        }
        Ok(AuthorityBinding {
            policy_revision: self.authority.policy_revision.clone(),
            action_grants: grants,
            privilege_grant: None,
        })
    }
}

/// The parts of a plan content that a builder decides.
pub(super) struct PlanParts {
    /// The targets, in their canonical sequence.
    pub(super) targets: Vec<PlanTarget>,
    /// The steps, in execution sequence.
    pub(super) steps: Vec<PlannedStep>,
    /// The limits.
    pub(super) limits: PlanLimits,
}

impl PlanContext<'_> {
    /// Makes the content of a manual plan of the user executor and seals
    /// it. The check of the foundation applies to each plan.
    pub(super) fn seal(&self, parts: PlanParts) -> Result<Plan, PlanBuildError> {
        let record: PlanContent = PlanContent {
            schema_version: PLAN_SCHEMA_VERSION,
            plan_id: self.plan_id.clone(),
            principal: self.principal.clone(),
            trigger: Trigger::manual(),
            authority: self.canonical_authority()?,
            executor: ExecutorRole::User,
            targets: parts.targets,
            steps: parts.steps,
            limits: parts.limits,
            validity: self.validity()?,
        };
        Plan::seal(record).map_err(PlanBuildError::Plan)
    }
}

/// The size estimates of one file entry. Each value is an estimate from
/// the time of the plan. None of them is a budget charge or a promise of
/// reclaimed capacity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct SizeEstimate {
    /// The estimate of the logical size.
    pub logical_bytes: Option<Bytes>,
    /// The estimate of the allocated size.
    pub allocated_bytes: Option<Bytes>,
    /// The estimate of the bytes that a permanent removal can reclaim. A
    /// move to Trash reclaims none.
    pub estimated_reclaimable_bytes: Option<Bytes>,
}

/// The data of one target that the plan content does not have.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetPreview {
    /// The identity of the target.
    pub target_id: TargetId,
    /// The path of a file entry, for display. A display path is not a
    /// deletion capability, and it is not in the plan.
    pub path: Option<LosslessPath>,
    /// The size estimates of a file entry.
    pub estimate: SizeEstimate,
}

/// One batch of a filesystem plan: consecutive steps that the executor
/// runs under one batch ceiling.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PlanBatch {
    /// The steps, in the sequence of the plan.
    pub steps: Vec<StepId>,
    /// The sum of the charges of the targets of the steps.
    pub charge: WorkCharge,
}

/// What a builder knows in addition to the plan content: the display data
/// of the targets, the batches, and the entries that were left out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanPreview {
    /// One record for each target of the plan, in the sequence of the
    /// plan.
    pub targets: Vec<TargetPreview>,
    /// The batches of a filesystem plan. An application plan has none.
    pub batches: Vec<PlanBatch>,
    /// Each entry that was left out, by target identity.
    pub omitted: Vec<Omission>,
    /// The name of the selection preset, when one filtered the entries.
    pub preset: Option<String>,
}

/// The result of a builder.
///
/// `plan` is `None` when no entry is in the plan: a plan has a minimum of
/// one target. That result is valid, and `preview.omitted` explains it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanOutcome {
    /// The mode that was requested.
    pub mode: PlanMode,
    /// The sealed plan, when a minimum of one target is in it.
    pub plan: Option<Plan>,
    /// The display data, the batches, and the entries that were left out.
    pub preview: PlanPreview,
}
