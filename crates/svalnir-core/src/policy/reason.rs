//! Decision reasons.
//!
//! `docs/POLICY_SPEC.md` section 7 owns the reason codes. A reason has a
//! stable code and a detail. The code is the family that the specification
//! names. The detail says which check gave the reason.

use serde::Serialize;

/// The stable code of a decision reason.
///
/// The codes are those of the table in `docs/POLICY_SPEC.md` section 7, and
/// one addition: [`DecisionReason::TargetNotEligible`]. The specification
/// calls its table representative; it has no code for a target that is known
/// to be outside the eligible scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum DecisionReason {
    /// The required class, scope, or escalation is outside the current
    /// authorization.
    ActionNotGranted,
    /// The target violates a product protection.
    HardProtected,
    /// The target violates a current user exclusion.
    UserExcluded,
    /// Required evidence is not available.
    MetricUnavailable,
    /// Required evidence is too old.
    MetricStale,
    /// The admission predicate is not sustained.
    TriggerNotSustained,
    /// The continuation predicate is not satisfied.
    TriggerCleared,
    /// The rule cannot do the requested automatic action.
    RuleNotReady,
    /// The version of the rule is not approved.
    RuleVersionUnapproved,
    /// Further work is temporarily inhibited.
    CooldownActive,
    /// A ceiling admits no further work.
    BudgetExhausted,
    /// Conflicting work requires reconciliation.
    UnknownPriorOutcome,
    /// The required durable admission cannot be established.
    JournalUnavailable,
    /// The target is known to be outside the eligible scope. This code is
    /// not in the table of the specification.
    TargetNotEligible,
}

impl DecisionReason {
    /// Each code, in the sequence of the specification.
    pub const ALL: &'static [Self] = &[
        Self::ActionNotGranted,
        Self::HardProtected,
        Self::UserExcluded,
        Self::MetricUnavailable,
        Self::MetricStale,
        Self::TriggerNotSustained,
        Self::TriggerCleared,
        Self::RuleNotReady,
        Self::RuleVersionUnapproved,
        Self::CooldownActive,
        Self::BudgetExhausted,
        Self::UnknownPriorOutcome,
        Self::JournalUnavailable,
        Self::TargetNotEligible,
    ];

    /// The stable text of the code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ActionNotGranted => "ACTION_NOT_GRANTED",
            Self::HardProtected => "HARD_PROTECTED",
            Self::UserExcluded => "USER_EXCLUDED",
            Self::MetricUnavailable => "METRIC_UNAVAILABLE",
            Self::MetricStale => "METRIC_STALE",
            Self::TriggerNotSustained => "TRIGGER_NOT_SUSTAINED",
            Self::TriggerCleared => "TRIGGER_CLEARED",
            Self::RuleNotReady => "RULE_NOT_READY",
            Self::RuleVersionUnapproved => "RULE_VERSION_UNAPPROVED",
            Self::CooldownActive => "COOLDOWN_ACTIVE",
            Self::BudgetExhausted => "BUDGET_EXHAUSTED",
            Self::UnknownPriorOutcome => "UNKNOWN_PRIOR_OUTCOME",
            Self::JournalUnavailable => "JOURNAL_UNAVAILABLE",
            Self::TargetNotEligible => "TARGET_NOT_ELIGIBLE",
        }
    }
}

/// The check that gave a reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ReasonDetail {
    /// The guard is not enabled in the configuration.
    GuardDisabled,
    /// The profile is `observe`, which permits no automatic intervention.
    ObserveProfile,
    /// The simulation was given no grant for the action class.
    GrantNotAssumed,
    /// The rule is not in `approved_rules`.
    RuleNotApproved,
    /// The application is in no eligible group and has no budget.
    GroupNotEligible,
    /// The target belongs to a different user.
    OtherUser,
    /// The volume of the target is not a selected volume.
    VolumeNotSelected,
    /// No candidate is eligible.
    NoEligibleCandidate,
    /// The target is active.
    TargetActive,

    /// The target has a product protection.
    ProductProtection,
    /// The target has data of a protected class.
    ProtectedDataClass,

    /// The bundle identifier is in a protected list.
    ProtectedBundleId,
    /// The executable path is in a protected list.
    ProtectedExecutablePath,
    /// The application is in the foreground and `protect_foreground` is on.
    ForegroundProtected,
    /// The path is in an exclusion list.
    ExcludedPath,

    /// The snapshot has no observation.
    ObservationMissing,
    /// The observation has no value.
    ObservationUnavailable,
    /// The observation has a value or an availability that this build does
    /// not recognize.
    ObservationUnrecognized,
    /// The observation has a unit that its value type does not accept.
    UnitMismatch,
    /// The observation is of a different metric.
    MetricMismatch,
    /// The observation is of a different scope.
    ScopeMismatch,
    /// The observation does not cover its complete scope.
    CoverageIncomplete,
    /// The observation is from a different clock domain or boot.
    ClockMismatch,
    /// The observation is later than the evaluation time.
    SampleFromFuture,
    /// The observation is older than `decision_sample_max_age`.
    SampleTooOld,
    /// The observation is from before the latest clock discontinuity.
    SampleBeforeDiscontinuity,
    /// A path of the target is not absolute or has a `.` or `..` component,
    /// so a path list cannot be applied to it.
    PathNotCanonical,
    /// No fresh corroborating system observation is available.
    CorroborationMissing,
    /// No volume in the snapshot has the selector.
    SelectorUnresolved,
    /// More than one volume in the snapshot has the selector.
    SelectorAmbiguous,
    /// The capacity-domain membership of the volume is not verified.
    CapacityDomainUnverified,
    /// The membership of a process is not verified.
    MembershipUnverified,
    /// The processes do not belong to one application instance.
    MembersInconsistent,
    /// The foreground status is not known.
    ForegroundUnknown,
    /// A process has no executable evidence, and a protected path applies.
    ExecutableUnknown,
    /// A path starts from the home directory, and no home directory was
    /// given.
    HomeDirectoryUnknown,
    /// The protection status of the target is not known.
    ProtectionUnknown,
    /// The owner of the target is not known.
    OwnerUnknown,
    /// The activity of the target is not known.
    ActivityUnknown,
    /// The work charge or the entry count of the target is not known.
    WorkChargeUnknown,
    /// The candidate has an entry count of zero, so it has nothing to act on.
    NoItems,
    /// The caller gave no per-rule allowance for a rule of the batch, so the
    /// per-rule ceiling was not evaluated.
    RuleCeilingNotEvaluated,
    /// More than one running instance matches the budget.
    AmbiguousInstances,
    /// The process inventory is not complete, so an absent application is
    /// not known to be absent.
    InventoryIncomplete,

    /// The qualification window has not reached its duration.
    WindowNotQualified,
    /// The value does not satisfy the admission predicate.
    PredicateNotTrue,
    /// The latched episode stays open, and its predicate is not true now.
    EpisodeHeld,
    /// The recovery condition holds and its stable window is in progress.
    RecoveryInProgress,

    /// The rule is not ready for automatic action.
    RuleNotReady,
    /// The version of the rule is not approved.
    RuleVersionUnapproved,

    /// The wait between two passes is not complete.
    PassCooldown,
    /// The backoff after a pass with no effect is not complete.
    NoEffectBackoff,
    /// The cooldown of the application is not complete.
    ApplicationCooldown,
    /// The cooldown is from a different clock domain or boot, so its end is
    /// not known.
    CooldownClockUnknown,
    /// An earlier operation of the incident is not settled.
    OperationOutstanding,

    /// The candidate fits an empty batch and does not fit the rest of the
    /// first batch.
    BatchFull,
    /// The charge is larger than the batch ceiling.
    ExceedsBatchLimit,
    /// The charge is larger than the remaining pass allowance.
    ExceedsPassLimit,
    /// The charge is larger than the remaining allowance of its rule.
    ExceedsRuleLimit,
    /// The charge is larger than the remaining incident allowance.
    ExceedsIncidentLimit,
    /// The incident has no pass left.
    PassCountExhausted,
    /// The incident has no application slot left.
    ApplicationSlotsExhausted,
}

/// One reason of a decision: the stable code and the check that gave it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Explanation {
    /// The stable code.
    pub reason: DecisionReason,
    /// The check that gave the reason.
    pub detail: ReasonDetail,
}

impl Explanation {
    /// Makes a reason.
    pub const fn new(reason: DecisionReason, detail: ReasonDetail) -> Self {
        Self { reason, detail }
    }
}

/// Adds a reason to the list when the list does not have it.
pub(super) fn push_reason(reasons: &mut Vec<Explanation>, explanation: Explanation) {
    if !reasons.contains(&explanation) {
        reasons.push(explanation);
    }
}
