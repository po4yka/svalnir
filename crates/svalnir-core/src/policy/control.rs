//! Types that the disk guard and the memory guard share: the evaluation
//! context, the incident states, the controller summary, cooldowns, assumed
//! grants, and the input limits.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::evidence::EvaluationClock;
use super::reason::{DecisionReason, Explanation, ReasonDetail};
use crate::config::{ConfigPath, PathBase, Profile, ValidatedConfig};
use crate::file::LosslessPath;
use crate::id::{BootId, ClockDomainId};
use crate::process::Uid;
use crate::quantity::Nanoseconds;
use crate::time::MonotonicNanos;

/// The largest number of volumes in a disk snapshot.
pub const MAX_VOLUMES: usize = 256;
/// The largest number of cleanup candidates in a disk snapshot.
pub const MAX_CLEANUP_CANDIDATES: usize = 4096;
/// The largest number of application candidates in a memory snapshot.
pub const MAX_APPLICATION_CANDIDATES: usize = 4096;
/// The largest number of processes of one application candidate.
pub const MAX_CANDIDATE_PROCESSES: usize = 1024;
/// The largest number of corroborating observations in a memory snapshot.
pub const MAX_CORROBORATING: usize = 64;
/// The largest number of application cooldowns in the memory-guard state.
pub const MAX_COOLDOWNS: usize = 4096;
/// The largest length of a revision label, in bytes.
pub const MAX_REVISION_LABEL_BYTES: usize = 256;

/// The reason an evaluation input was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum PolicyInputError {
    /// A list of the input has more entries than its limit.
    #[error("the input has {count} {list}; the limit is {limit}")]
    TooManyEntries {
        /// The name of the list.
        list: &'static str,
        /// The number of entries.
        count: usize,
        /// The limit.
        limit: usize,
    },
    /// The revision label is empty, is too long, or has a control character.
    #[error("the revision label is empty, is longer than 256 bytes, or has a control character")]
    InvalidRevisionLabel,
    /// A list of the input has two entries with the same key.
    #[error("the input has a repeated entry in {list}")]
    DuplicateEntry {
        /// The name of the list.
        list: &'static str,
    },
}

/// Checks the length of one input list.
pub(super) const fn check_count(
    list: &'static str,
    count: usize,
    limit: usize,
) -> Result<(), PolicyInputError> {
    if count > limit {
        return Err(PolicyInputError::TooManyEntries { list, count, limit });
    }
    Ok(())
}

/// A standing policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum PolicyId {
    /// The disk guard: the `[disk_guard]` table.
    DiskGuard,
    /// The memory guard: the `[memory_guard]` table.
    MemoryGuard,
}

impl PolicyId {
    /// Each policy, in the sequence of the specification.
    pub const ALL: &'static [Self] = &[Self::DiskGuard, Self::MemoryGuard];

    /// The name of the policy in a command and in a report.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DiskGuard => "disk-guard",
            Self::MemoryGuard => "memory-guard",
        }
    }

    /// Finds the policy for a name.
    pub fn from_text(text: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|policy| policy.as_str() == text)
    }
}

impl std::fmt::Display for PolicyId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// How a simulation got its grants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantBasis {
    /// The caller read the grants from recorded authorization state.
    Recorded,
    /// The grants are an assumption of the request. They do not exist.
    Hypothetical,
}

/// The action grants that an evaluation assumes.
///
/// This module does not read a grant. The caller supplies what it recorded,
/// or a hypothesis, and the report repeats the value with its basis
/// (`docs/POLICY_SPEC.md` section 15). A grant here does not authorize a
/// later operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct AssumedGrants {
    /// Where the values come from.
    pub basis: GrantBasis,
    /// The `EvictRegenerableData` action class.
    pub evict_regenerable_data: bool,
    /// The `RequestApplicationExit` action class.
    pub request_application_exit: bool,
    /// The `ForceApplicationExit` action class.
    pub force_application_exit: bool,
}

impl AssumedGrants {
    /// No grant. The basis says where this fact comes from.
    pub const fn none(basis: GrantBasis) -> Self {
        Self {
            basis,
            evict_regenerable_data: false,
            request_application_exit: false,
            force_application_exit: false,
        }
    }

    /// Each grant, as a hypothesis.
    pub const fn hypothetical_all() -> Self {
        Self {
            basis: GrantBasis::Hypothetical,
            evict_regenerable_data: true,
            request_application_exit: true,
            force_application_exit: true,
        }
    }
}

/// The inputs that each evaluation needs.
#[derive(Debug, Clone, Copy)]
pub struct EvaluationContext<'a> {
    /// The validated configuration.
    pub config: &'a ValidatedConfig,
    /// The time of the evaluation.
    pub clock: &'a EvaluationClock,
    /// The grants that the evaluation assumes.
    pub grants: AssumedGrants,
    /// The user that the evaluation is for. A target of a different user is
    /// not eligible.
    pub principal: Uid,
    /// The home directory of that user, for a path that starts with `~/`.
    /// With no home directory, such a path stays unresolved and each target
    /// that it can apply to is skipped.
    pub home_directory: Option<&'a LosslessPath>,
}

impl EvaluationContext<'_> {
    /// The reasons that inhibit each automatic intervention of a guard,
    /// independent of the target.
    pub(super) fn authority_reasons(&self, enabled: bool, granted: bool) -> Vec<Explanation> {
        let mut reasons: Vec<Explanation> = Vec::new();
        if !granted {
            reasons.push(Explanation::new(
                DecisionReason::ActionNotGranted,
                ReasonDetail::GrantNotAssumed,
            ));
        }
        if !enabled {
            reasons.push(Explanation::new(
                DecisionReason::ActionNotGranted,
                ReasonDetail::GuardDisabled,
            ));
        }
        if self.config.agent().profile == Profile::Observe {
            reasons.push(Explanation::new(
                DecisionReason::ActionNotGranted,
                ReasonDetail::ObserveProfile,
            ));
        }
        reasons
    }
}

/// The incident state of one trigger (`docs/POLICY_SPEC.md` section 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum TriggerState {
    /// The measurement is on the safe side of each threshold.
    Normal,
    /// A warning threshold, a soft threshold, or a warning pressure state.
    /// It can prepare and notify; it authorizes no action.
    Advisory,
    /// Evidence is accumulating. No action is authorized yet.
    Qualifying,
    /// The trigger is qualified. An action still needs an eligible target,
    /// authority, and budget.
    Ready,
    /// An operation of the incident is not settled.
    Acting,
    /// The incident is open while recovery stability is evaluated.
    Recovering,
    /// The episode is latched, and its predicate is not true now. No new
    /// step is permitted, and recovery has not started.
    Held,
    /// The trigger is qualified and a cooldown inhibits further work.
    Cooldown,
    /// The trigger is qualified and a ceiling admits no further work.
    Exhausted,
    /// Required evidence is not usable. This state is not `Normal`.
    Blocked,
}

/// The controller summary for presentation (`README.md`, "How protection
/// works"). It groups the incident states and adds no policy state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ControllerSummary {
    /// Each trigger is normal.
    Normal,
    /// A trigger is advisory, is qualifying, or waits with an open incident.
    Warning,
    /// A trigger is qualified and the guard can intervene.
    Acting,
    /// An incident waits for stable recovery.
    Recovering,
    /// Required evidence of a trigger is not usable.
    Degraded,
}

/// Derives the controller summary from the incident states of the triggers.
///
/// `intervention_permitted` is false when the guard is disabled, the profile
/// is `observe`, or the action class has no grant: a qualified trigger then
/// gives `Warning`, because nothing acts.
///
/// The sequence of precedence is degraded, acting, recovering, warning,
/// normal. Missing required evidence gives `Degraded`, not `Normal`.
pub fn controller_summary(
    states: &[TriggerState],
    intervention_permitted: bool,
) -> ControllerSummary {
    let mut summary: ControllerSummary = ControllerSummary::Normal;
    for state in states {
        let one: ControllerSummary = match state {
            TriggerState::Normal => ControllerSummary::Normal,
            TriggerState::Advisory
            | TriggerState::Qualifying
            | TriggerState::Held
            | TriggerState::Exhausted => ControllerSummary::Warning,
            TriggerState::Ready | TriggerState::Acting | TriggerState::Cooldown => {
                if intervention_permitted {
                    ControllerSummary::Acting
                } else {
                    ControllerSummary::Warning
                }
            }
            TriggerState::Recovering => ControllerSummary::Recovering,
            TriggerState::Blocked => ControllerSummary::Degraded,
        };
        summary = severity_max(summary, one);
    }
    summary
}

/// The more severe of two summaries.
fn severity_max(left: ControllerSummary, right: ControllerSummary) -> ControllerSummary {
    const fn severity(summary: ControllerSummary) -> u8 {
        match summary {
            ControllerSummary::Normal => 0,
            ControllerSummary::Warning => 1,
            ControllerSummary::Recovering => 2,
            ControllerSummary::Acting => 3,
            ControllerSummary::Degraded => 4,
        }
    }
    if severity(right) > severity(left) {
        right
    } else {
        left
    }
}

/// The cause of a cooldown (`docs/POLICY_SPEC.md` section 14).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CooldownCause {
    /// The wait between two passes.
    PassPacing,
    /// The backoff after a pass with no effect.
    NoEffectBackoff,
    /// The cooldown of an application after an intervention.
    ApplicationRelaunch,
}

/// A cooldown that the caller recorded. The evaluation only compares it
/// with the evaluation time.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Cooldown {
    /// The cause.
    pub cause: CooldownCause,
    /// The monotonic time at which the cooldown ends.
    pub until: MonotonicNanos,
    /// The clock domain of `until`.
    pub clock_domain: ClockDomainId,
    /// The boot of `until`.
    pub boot_id: BootId,
}

/// The status of a cooldown at the evaluation time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CooldownStatus {
    /// The cooldown is complete. This permits a new evaluation only.
    Elapsed,
    /// The cooldown is not complete.
    Active {
        /// The time that remains.
        remaining: Nanoseconds,
    },
    /// The cooldown is from a different clock domain or boot. Its end is not
    /// known, so it inhibits work as an active cooldown does.
    Unknown,
}

impl Cooldown {
    /// The status at the evaluation time.
    pub fn status(&self, clock: &EvaluationClock) -> CooldownStatus {
        if self.clock_domain != clock.clock_domain || self.boot_id != clock.boot_id {
            return CooldownStatus::Unknown;
        }
        match self.until.checked_duration_since(clock.now) {
            Some(remaining) if remaining > Nanoseconds::ZERO => {
                CooldownStatus::Active { remaining }
            }
            _ => CooldownStatus::Elapsed,
        }
    }

    /// The reason that an active cooldown gives. `None` when the cooldown
    /// is complete.
    pub(super) fn reason(&self, clock: &EvaluationClock) -> Option<Explanation> {
        let detail: ReasonDetail = match self.status(clock) {
            CooldownStatus::Elapsed => return None,
            CooldownStatus::Unknown => ReasonDetail::CooldownClockUnknown,
            CooldownStatus::Active { .. } => match self.cause {
                CooldownCause::PassPacing => ReasonDetail::PassCooldown,
                CooldownCause::NoEffectBackoff => ReasonDetail::NoEffectBackoff,
                CooldownCause::ApplicationRelaunch => ReasonDetail::ApplicationCooldown,
            },
        };
        Some(Explanation::new(DecisionReason::CooldownActive, detail))
    }
}

/// What the caller knows about a product protection of a target.
///
/// The caller looks the target up and gives the result. For an application
/// or job instance the lookup is [`hard_protection`](super::hard_protection).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionFact {
    /// The target has no product protection.
    NotProtected,
    /// The target has a product protection.
    Protected,
    /// The lookup gave no result. The target is skipped.
    Unknown,
}

/// The decision for one candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateDecision {
    /// No check excludes the candidate.
    Eligible,
    /// A product protection or a user exclusion covers the candidate.
    Protected,
    /// A different check excludes the candidate.
    Skipped,
}

/// The decision that a list of reasons gives.
pub(super) fn decision_of(reasons: &[Explanation]) -> CandidateDecision {
    let protected: bool = reasons.iter().any(|explanation| {
        matches!(
            explanation.reason,
            DecisionReason::HardProtected | DecisionReason::UserExcluded
        )
    });
    if protected {
        CandidateDecision::Protected
    } else if reasons.is_empty() {
        CandidateDecision::Eligible
    } else {
        CandidateDecision::Skipped
    }
}

/// A list of configuration paths as components, ready for a comparison.
///
/// The default APFS volume ignores case and Unicode normalization. This module
/// has no normalization table, so the comparison fails closed:
///
/// - A component is folded with the full Unicode lowercase mapping. A
///   component that is not UTF-8 is folded by ASCII case only.
/// - Two components that are not byte-equal after folding, where either one
///   contains a non-ASCII byte, count as a match. They can be the same name in
///   a different normalization form, and a missed match would expose a
///   protected path.
///
/// The rule over-protects: an entry covers each sibling whose name has a
/// non-ASCII character, at the position of the component that differs. It never
/// under-protects a path that differs only in case or normalization.
#[derive(Debug, Default)]
pub(super) struct PathSet {
    entries: Vec<Vec<Vec<u8>>>,
    /// True when a path starts from the home directory and no usable home
    /// directory was given. A home directory is usable when it is absolute,
    /// canonical, and has no empty component.
    pub(super) unresolved: bool,
}

fn fold(bytes: &[u8]) -> Vec<u8> {
    match std::str::from_utf8(bytes) {
        Ok(text) => text.to_lowercase().into_bytes(),
        Err(_) => bytes.to_ascii_lowercase(),
    }
}

pub(super) fn components(bytes: &[u8]) -> Vec<Vec<u8>> {
    bytes
        .split(|byte| *byte == b'/')
        .filter(|component| !component.is_empty())
        .map(fold)
        .collect()
}

/// True when two folded components name the same entry, or can name it in a
/// different normalization form.
fn component_matches(left: &[u8], right: &[u8]) -> bool {
    left == right || !left.is_ascii() || !right.is_ascii()
}

/// True when `path` starts with all components of `prefix`.
pub(super) fn has_prefix(path: &[Vec<u8>], prefix: &[Vec<u8>]) -> bool {
    path.len() >= prefix.len()
        && path
            .iter()
            .zip(prefix)
            .all(|(left, right)| component_matches(left, right))
}

/// True when the path is absolute and has no `.` or `..` component. A path
/// list cannot be applied to a different path: a component-wise comparison
/// of such a path can miss a protection.
pub(super) fn is_canonical(path: &LosslessPath) -> bool {
    let bytes: &[u8] = path.as_bytes();
    bytes.first() == Some(&b'/')
        && bytes
            .split(|byte| *byte == b'/')
            .all(|component| component != b"." && component != b"..")
}

/// True when a home directory can anchor `~/` paths: it is canonical, it is
/// not the root, and it has no repeated or trailing `/`.
fn is_usable_home(bytes: &[u8]) -> bool {
    let Some(rest) = bytes.strip_prefix(b"/") else {
        return false;
    };
    !rest.is_empty()
        && rest
            .split(|byte| *byte == b'/')
            .all(|component| !component.is_empty() && component != b"." && component != b"..")
}

impl PathSet {
    /// Resolves the paths of one or more configuration lists.
    pub(super) fn resolve<'a>(
        paths: impl Iterator<Item = &'a ConfigPath>,
        home: Option<&LosslessPath>,
    ) -> Self {
        let home_components: Option<Vec<Vec<u8>>> = home
            .map(LosslessPath::as_bytes)
            .filter(|bytes| is_usable_home(bytes))
            .map(components);
        let mut set: Self = Self::default();
        for path in paths {
            let mut entry: Vec<Vec<u8>> = match (path.base(), &home_components) {
                (PathBase::Root, _) => Vec::new(),
                (PathBase::Home, Some(home)) => home.clone(),
                (PathBase::Home, None) => {
                    set.unresolved = true;
                    continue;
                }
            };
            entry.extend(
                path.components()
                    .map(|component| fold(component.as_bytes())),
            );
            set.entries.push(entry);
        }
        set
    }

    /// True when `path` is an entry or is inside an entry.
    pub(super) fn covers(&self, path: &LosslessPath) -> bool {
        let path: Vec<Vec<u8>> = components(path.as_bytes());
        self.entries.iter().any(|entry| has_prefix(&path, entry))
    }

    /// True when `path` is an entry, is inside an entry, or contains an
    /// entry.
    pub(super) fn overlaps(&self, path: &LosslessPath) -> bool {
        let path: Vec<Vec<u8>> = components(path.as_bytes());
        self.entries
            .iter()
            .any(|entry| has_prefix(&path, entry) || has_prefix(entry, &path))
    }
}
