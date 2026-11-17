//! The disk guard.
//!
//! `docs/POLICY_SPEC.md` sections 9 and 11 own the contract.
//! [`evaluate_disk_guard`] classifies the available capacity of each
//! selected volume and advances its qualification windows.
//! [`plan_cleanup`] decides the eligibility of pre-computed cleanup
//! candidates and builds the first batch under the budgets.
//!
//! This module has no rule registry and does no file access. The caller
//! gives each candidate with its rule, its charge, and its eligibility
//! facts.

use std::cmp::Reverse;
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::control::{
    CandidateDecision, Cooldown, EvaluationContext, MAX_CLEANUP_CANDIDATES, MAX_VOLUMES, PathSet,
    PolicyInputError, ProtectionFact, TriggerState, check_count, decision_of, is_canonical,
};
use super::evidence::{
    EvidenceProblem, EvidenceReport, ScopeCheck, Usable, assess, nanoseconds,
    report as evidence_report,
};
use super::reason::{DecisionReason, Explanation, ReasonDetail, push_reason};
use super::window::{QualificationWindow, WindowEvidence, WindowReport, WindowStep, advance};
use crate::config::{DiskGuard, VolumeSelector};
use crate::file::LosslessPath;
use crate::id::{CapacityDomainId, MountId, RuleId, TargetId, VolumeId};
use crate::observation::{Observation, Scope, metric};
use crate::quantity::{Bytes, EntryCount, Nanoseconds};
use crate::volume::{CapacityKey, VolumeIdentity};

/// The capacity evidence of one volume that a selector resolved to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeEvidence {
    /// The selector of the configuration that the caller resolved.
    pub selector: VolumeSelector,
    /// The identity of the volume.
    pub identity: VolumeIdentity,
    /// The `disk.available_bytes` observation of the volume.
    pub available: Observation<Bytes>,
}

/// Whether the rule of a candidate can act automatically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleReadiness {
    /// The registry admits the rule and its version for automatic action.
    Ready,
    /// The rule cannot do the automatic action.
    NotReady,
    /// The version of the rule is not approved.
    VersionUnapproved,
}

/// Who owns the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerFact {
    /// The user that the evaluation is for.
    RequestingUser,
    /// A different user.
    OtherUser,
    /// The owner is not known.
    Unknown,
}

/// Whether the target is in use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "activity", rename_all = "snake_case")]
pub enum ActivityFact {
    /// The checks of the rule show no use.
    Inactive {
        /// The time for which the target is known to be inactive.
        inactive_for: Nanoseconds,
    },
    /// The target is in use.
    Active,
    /// The activity is not known. A large estimate does not override this.
    Unknown,
}

/// The cost to make the data of a target again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebuildCost {
    /// A low cost.
    Low,
    /// A medium cost.
    Medium,
    /// A high cost.
    High,
    /// The cost is not known. It ranks after each known cost.
    Unknown,
}

/// A class of data that generic automatic eviction cannot include.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectedDataClass {
    /// An archive.
    Archive,
    /// A backup.
    Backup,
    /// A database.
    Database,
    /// Model weights.
    ModelWeights,
}

/// The eligibility facts of a cleanup candidate. The caller establishes
/// them; this module does not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CleanupFacts {
    /// Whether the rule can act automatically.
    pub rule_readiness: RuleReadiness,
    /// The product protection of the target.
    pub hard_protection: ProtectionFact,
    /// The protected data classes that the target has.
    pub protected_classes: Vec<ProtectedDataClass>,
    /// The owner of the target.
    pub owner: OwnerFact,
    /// The activity of the target.
    pub activity: ActivityFact,
    /// The cost to make the data again.
    pub rebuild_cost: RebuildCost,
}

/// One pre-computed cleanup candidate: a fixed, bounded target set of one
/// rule. A candidate is indivisible. The caller splits a target into
/// candidates where the rule defines independently safe units.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupCandidate {
    /// The identity of the target.
    pub target_id: TargetId,
    /// The rule that found the target.
    pub rule_id: RuleId,
    /// The volume of the target.
    pub volume_id: VolumeId,
    /// The root path of the target, for the exclusion lists.
    pub path: LosslessPath,
    /// The `work_bytes` charge of the rule. `None` blocks the candidate.
    pub work_bytes: Option<Bytes>,
    /// The number of entries. `None` blocks the candidate.
    pub item_count: Option<EntryCount>,
    /// The estimate of reclaimable bytes. It is not a budget charge.
    pub estimated_reclaimable_bytes: Option<Bytes>,
    /// The eligibility facts.
    pub facts: CleanupFacts,
}

/// The inputs of a disk-guard evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DiskSnapshot {
    /// The volumes that the selectors resolved to.
    pub volumes: Vec<VolumeEvidence>,
    /// The cleanup candidates.
    pub candidates: Vec<CleanupCandidate>,
    /// The per-rule allowances. A rule with no entry has no bound that the
    /// caller states: the per-rule ceiling of `docs/CLEANUP_RULES.md` is not
    /// evaluated for it, and a batch that has a target of the rule is not
    /// admissible.
    pub rule_allowances: Vec<RuleAllowance>,
}

/// What a rule can still charge in the plan: the minimum of its ceiling and
/// its remaining budget, as the caller knows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleAllowance {
    /// The rule.
    pub rule_id: RuleId,
    /// The `work_bytes` that the rule can still charge.
    pub remaining_bytes: Bytes,
    /// The entries that the rule can still charge.
    pub remaining_items: EntryCount,
}

impl DiskSnapshot {
    /// Checks the lengths of the lists and the keys of the entries.
    ///
    /// # Errors
    ///
    /// Returns a [`PolicyInputError`] when a list is longer than its limit,
    /// when two candidates have the same target identity on one volume, or
    /// when two allowances have the same rule.
    pub fn check(&self) -> Result<(), PolicyInputError> {
        check_count("volumes", self.volumes.len(), MAX_VOLUMES)?;
        check_count(
            "cleanup candidates",
            self.candidates.len(),
            MAX_CLEANUP_CANDIDATES,
        )?;
        check_count(
            "rule allowances",
            self.rule_allowances.len(),
            MAX_CLEANUP_CANDIDATES,
        )?;
        let mut targets: BTreeSet<(&str, &str)> = BTreeSet::new();
        for candidate in &self.candidates {
            if !targets.insert((candidate.volume_id.as_str(), candidate.target_id.as_str())) {
                return Err(PolicyInputError::DuplicateEntry {
                    list: "cleanup candidates",
                });
            }
        }
        let mut rules: BTreeSet<&str> = BTreeSet::new();
        for allowance in &self.rule_allowances {
            if !rules.insert(allowance.rule_id.as_str()) {
                return Err(PolicyInputError::DuplicateEntry {
                    list: "rule allowances",
                });
            }
        }
        Ok(())
    }
}

/// The pool of free space that an incident belongs to.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "id", rename_all = "snake_case")]
pub enum CapacityDomainKey {
    /// A verified shared-capacity domain.
    Domain(CapacityDomainId),
    /// One volume with exclusive free space.
    Volume(VolumeId),
}

impl From<CapacityKey<'_>> for CapacityDomainKey {
    fn from(key: CapacityKey<'_>) -> Self {
        match key {
            CapacityKey::Domain(id) => Self::Domain(id.clone()),
            CapacityKey::Volume(id) => Self::Volume(id.clone()),
        }
    }
}

/// The charges against one filesystem ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct WorkUsage {
    /// The consumed `work_bytes`.
    pub consumed_bytes: Bytes,
    /// The reserved `work_bytes`.
    pub reserved_bytes: Bytes,
    /// The consumed entries.
    pub consumed_items: EntryCount,
    /// The reserved entries.
    pub reserved_items: EntryCount,
}

/// `max(0, ceiling - consumed - reserved)`.
const fn remaining(ceiling: u64, consumed: u64, reserved: u64) -> u64 {
    ceiling.saturating_sub(consumed).saturating_sub(reserved)
}

impl WorkUsage {
    /// The usage with a planned charge added to the reserved charges.
    fn with_planned(mut self, (bytes, items): (Bytes, EntryCount)) -> Self {
        self.reserved_bytes = Bytes::new(self.reserved_bytes.get().saturating_add(bytes.get()));
        self.reserved_items =
            EntryCount::new(self.reserved_items.get().saturating_add(items.get()));
        self
    }

    fn bytes_left(&self, ceiling: Bytes) -> Bytes {
        Bytes::new(remaining(
            ceiling.get(),
            self.consumed_bytes.get(),
            self.reserved_bytes.get(),
        ))
    }

    fn items_left(&self, ceiling: EntryCount) -> EntryCount {
        EntryCount::new(remaining(
            ceiling.get(),
            self.consumed_items.get(),
            self.reserved_items.get(),
        ))
    }
}

/// One disk incident. The evaluation opens and closes it. The caller owns
/// the usage, the pass, the cooldown, and the outstanding-operation flag,
/// and changes them when an executor acts.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DiskIncident {
    /// The capacity domain of the incident.
    pub domain: CapacityDomainKey,
    /// The volumes with a trigger episode that did not recover. Only a
    /// stable recovery of the volume removes its entry. The incident stays
    /// open while the list has an entry, also when the volume changes its
    /// capacity domain or its selector, or is not in the snapshot.
    pub unrecovered: Vec<VolumeId>,
    /// The charges against the incident ceilings.
    pub usage: WorkUsage,
    /// The charges of the pass in progress.
    pub current_pass: Option<WorkUsage>,
    /// The number of passes that the incident started.
    pub passes_started: u32,
    /// The cooldown that inhibits the next pass.
    pub cooldown: Option<Cooldown>,
    /// True when an operation of the incident is not settled.
    pub outstanding_operation: bool,
}

impl DiskIncident {
    fn open(domain: CapacityDomainKey) -> Self {
        Self {
            domain,
            unrecovered: Vec::new(),
            usage: WorkUsage::default(),
            current_pass: None,
            passes_started: 0,
            cooldown: None,
            outstanding_operation: false,
        }
    }

    /// True when a new pass cannot start.
    fn passes_exhausted(&self, guard: &DiskGuard) -> bool {
        self.current_pass.is_none() && self.passes_started >= guard.max_passes_per_incident.get()
    }

    /// True when a ceiling of the incident admits no further work.
    fn exhausted(&self, guard: &DiskGuard) -> bool {
        self.usage.bytes_left(guard.incident_limit) == Bytes::ZERO
            || self.usage.items_left(guard.incident_item_limit) == EntryCount::ZERO
            || self.passes_exhausted(guard)
    }
}

/// The window state of one selected volume.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DiskVolumeState {
    /// The selector of the configuration.
    pub selector: String,
    /// The volume that the selector resolved to in the latest evaluation
    /// that had one.
    pub volume_id: Option<VolumeId>,
    /// The window of the entry predicate, or of the continuation predicate
    /// while an incident is open.
    pub entry_window: QualificationWindow,
    /// True when `entry_window` has samples of the continuation predicate.
    /// Such a window does not qualify the narrower entry predicate.
    pub entry_is_continuation: bool,
    /// The window of the emergency predicate.
    pub emergency_window: QualificationWindow,
    /// The window of stable recovery.
    pub recovery_window: QualificationWindow,
}

impl DiskVolumeState {
    fn new(selector: &VolumeSelector) -> Self {
        Self {
            selector: selector.as_str().to_owned(),
            volume_id: None,
            entry_window: QualificationWindow::Idle,
            entry_is_continuation: false,
            emergency_window: QualificationWindow::Idle,
            recovery_window: QualificationWindow::Idle,
        }
    }
}

/// The state of the disk guard that the caller keeps between evaluations.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct DiskGuardState {
    /// One entry for each selected volume.
    pub volumes: Vec<DiskVolumeState>,
    /// The open incidents, one for each capacity domain.
    pub incidents: Vec<DiskIncident>,
}

/// The available capacity against the thresholds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapacityLevel {
    /// At or above `recover_above`.
    AtRecoveryTarget,
    /// At or above `warn_below` and below `recover_above`.
    AboveWarning,
    /// Below `warn_below` and at or above `reclaim_below`.
    Warning,
    /// Below `reclaim_below` and at or above `emergency_below`.
    Reclaim,
    /// Below `emergency_below`.
    Emergency,
    /// No usable capacity observation. This level is not a safe level.
    Unknown,
}

/// The evaluation of one selected volume.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VolumeTrigger {
    /// The selector of the configuration.
    pub selector: String,
    /// The volume that the selector resolved to.
    pub volume_id: Option<VolumeId>,
    /// The mount generation of the volume.
    pub mount_id: Option<MountId>,
    /// The capacity domain of the volume. `None` when the membership is not
    /// verified.
    pub domain: Option<CapacityDomainKey>,
    /// True when the capacity-domain membership is verified.
    pub domain_verified: bool,
    /// The capacity against the thresholds.
    pub level: CapacityLevel,
    /// The incident state of the trigger.
    pub state: TriggerState,
    /// The available capacity, when the observation is usable.
    pub available: Option<Bytes>,
    /// The evidence that the evaluation used.
    pub evidence: EvidenceReport,
    /// The window of the entry or continuation predicate.
    pub entry_window: WindowReport,
    /// The window of the emergency predicate.
    pub emergency_window: WindowReport,
    /// The window of stable recovery.
    pub recovery_window: WindowReport,
    /// True when the capacity domain has an open incident.
    pub incident_open: bool,
    /// The reasons that no action is admissible for this trigger now.
    pub reasons: Vec<Explanation>,
}

/// The available capacity of one capacity domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DomainCapacity {
    /// The domain.
    pub domain: CapacityDomainKey,
    /// The smallest usable available capacity of its selected volumes.
    pub available: Bytes,
    /// The selectors of its selected volumes.
    pub selectors: Vec<String>,
}

/// The available capacity of the selected volumes, with each pool of free
/// space counted one time.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct CapacityOverview {
    /// The capacity of each verified domain.
    pub domains: Vec<DomainCapacity>,
    /// The selectors of volumes that have a usable capacity and no verified
    /// capacity-domain membership. Their capacity is not in the sum.
    pub not_summed: Vec<String>,
    /// The selectors of volumes that have no usable capacity observation.
    /// Their capacity is not in the sum, and `total_available` is `None`.
    pub unusable: Vec<String>,
    /// The sum of the domain capacities. `None` when there is no verified
    /// domain, a selected volume has no usable observation, or the sum
    /// overflows.
    pub total_available: Option<Bytes>,
}

/// The result of [`evaluate_disk_guard`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskEvaluation {
    /// One trigger for each selected volume, in the sequence of the
    /// configuration.
    pub volumes: Vec<VolumeTrigger>,
    /// The capacity of the selected volumes by domain.
    pub capacity: CapacityOverview,
    /// The state that the caller keeps for the next evaluation.
    pub next_state: DiskGuardState,
}

/// The values of the configuration that a volume evaluation uses.
struct Thresholds<'a> {
    guard: &'a DiskGuard,
    sustain: Nanoseconds,
    emergency_sustain: Nanoseconds,
    recovery_stable: Nanoseconds,
    max_age: Nanoseconds,
    max_gap: Nanoseconds,
}

impl Thresholds<'_> {
    fn level(&self, available: Bytes) -> CapacityLevel {
        if available < self.guard.emergency_below {
            CapacityLevel::Emergency
        } else if available < self.guard.reclaim_below {
            CapacityLevel::Reclaim
        } else if available < self.guard.warn_below {
            CapacityLevel::Warning
        } else if available < self.guard.recover_above {
            CapacityLevel::AboveWarning
        } else {
            CapacityLevel::AtRecoveryTarget
        }
    }
}

/// The reason that a trigger state gives when it admits no action.
pub(super) const fn state_reason(state: TriggerState) -> Option<Explanation> {
    let (reason, detail): (DecisionReason, ReasonDetail) = match state {
        TriggerState::Normal | TriggerState::Advisory => (
            DecisionReason::TriggerNotSustained,
            ReasonDetail::PredicateNotTrue,
        ),
        TriggerState::Qualifying => (
            DecisionReason::TriggerNotSustained,
            ReasonDetail::WindowNotQualified,
        ),
        TriggerState::Recovering => (
            DecisionReason::TriggerCleared,
            ReasonDetail::RecoveryInProgress,
        ),
        TriggerState::Held => (DecisionReason::TriggerCleared, ReasonDetail::EpisodeHeld),
        TriggerState::Acting => (
            DecisionReason::CooldownActive,
            ReasonDetail::OperationOutstanding,
        ),
        TriggerState::Ready
        | TriggerState::Cooldown
        | TriggerState::Exhausted
        | TriggerState::Blocked => return None,
    };
    Some(Explanation::new(reason, detail))
}

/// Evaluates the disk guard for one snapshot.
///
/// The function classifies the available capacity of each selected volume
/// against `warn_below`, `reclaim_below`, `emergency_below`, and
/// `recover_above`, and advances the qualification windows of `state`. It
/// opens an incident when an entry predicate qualifies and closes it when
/// each latched volume of the domain has a stable recovery and no operation
/// is outstanding. It does not change the usage of an incident.
///
/// The function is pure: equal arguments give an equal result.
///
/// # Errors
///
/// Returns a [`PolicyInputError`] when a list of the snapshot is longer than
/// its limit.
pub fn evaluate_disk_guard(
    context: &EvaluationContext<'_>,
    state: &DiskGuardState,
    snapshot: &DiskSnapshot,
) -> Result<DiskEvaluation, PolicyInputError> {
    snapshot.check()?;
    let guard: &DiskGuard = context.config.disk_guard();
    let agent = context.config.agent();
    let thresholds: Thresholds<'_> = Thresholds {
        guard,
        sustain: nanoseconds(guard.sustain_for),
        emergency_sustain: nanoseconds(guard.emergency_sustain_for),
        recovery_stable: nanoseconds(guard.recovery_stable_for),
        max_age: nanoseconds(agent.decision_sample_max_age),
        max_gap: nanoseconds(agent.max_qualifying_sample_gap),
    };

    let mut incidents: Vec<DiskIncident> = state.incidents.clone();
    let mut volumes: Vec<VolumeTrigger> = Vec::with_capacity(guard.volumes.len());
    let mut next_volumes: Vec<DiskVolumeState> = Vec::with_capacity(guard.volumes.len());
    for selector in &guard.volumes {
        let prior: DiskVolumeState = state
            .volumes
            .iter()
            .find(|volume| volume.selector == selector.as_str())
            .cloned()
            .unwrap_or_else(|| DiskVolumeState::new(selector));
        let matches: Vec<&VolumeEvidence> = snapshot
            .volumes
            .iter()
            .filter(|volume| volume.selector == *selector)
            .collect();
        let (trigger, next) =
            evaluate_volume(context, &thresholds, &prior, &matches, &mut incidents);
        volumes.push(trigger);
        next_volumes.push(next);
    }

    // An incident closes when each of its volumes has a stable recovery
    // and no operation is outstanding.
    incidents.retain(|incident| incident.outstanding_operation || !incident.unrecovered.is_empty());
    for (trigger, next) in volumes.iter_mut().zip(&next_volumes) {
        let incident: Option<&DiskIncident> =
            incident_index(&incidents, next.volume_id.as_ref(), trigger.domain.as_ref())
                .and_then(|index| incidents.get(index));
        trigger.incident_open = incident.is_some();
        apply_incident(context, guard, trigger, incident);
    }

    Ok(DiskEvaluation {
        capacity: capacity_overview(&volumes),
        volumes,
        next_state: DiskGuardState {
            volumes: next_volumes,
            incidents,
        },
    })
}

/// Applies the incident conditions to a qualified trigger and sets its
/// reasons.
fn apply_incident(
    context: &EvaluationContext<'_>,
    guard: &DiskGuard,
    trigger: &mut VolumeTrigger,
    incident: Option<&DiskIncident>,
) {
    if trigger.state == TriggerState::Ready
        && let Some(incident) = incident
    {
        let cooldown: Option<Explanation> = incident
            .cooldown
            .as_ref()
            .and_then(|cooldown| cooldown.reason(context.clock));
        if incident.outstanding_operation {
            trigger.state = TriggerState::Acting;
        } else if incident.exhausted(guard) {
            trigger.state = TriggerState::Exhausted;
            let detail: ReasonDetail = if incident.passes_exhausted(guard) {
                ReasonDetail::PassCountExhausted
            } else {
                ReasonDetail::ExceedsIncidentLimit
            };
            push_reason(
                &mut trigger.reasons,
                Explanation::new(DecisionReason::BudgetExhausted, detail),
            );
        } else if let Some(reason) = cooldown {
            trigger.state = TriggerState::Cooldown;
            push_reason(&mut trigger.reasons, reason);
        }
    }
    if let Some(reason) = state_reason(trigger.state) {
        push_reason(&mut trigger.reasons, reason);
    }
    if trigger.state == TriggerState::Ready && !trigger.domain_verified {
        push_reason(
            &mut trigger.reasons,
            Explanation::new(
                DecisionReason::MetricUnavailable,
                ReasonDetail::CapacityDomainUnverified,
            ),
        );
    }
}

/// The incident of a volume: the one that has the volume as unrecovered,
/// or the one of the capacity domain of the volume.
fn incident_index(
    incidents: &[DiskIncident],
    volume: Option<&VolumeId>,
    domain: Option<&CapacityDomainKey>,
) -> Option<usize> {
    volume
        .and_then(|volume| {
            incidents
                .iter()
                .position(|incident| incident.unrecovered.contains(volume))
        })
        .or_else(|| {
            domain.and_then(|domain| {
                incidents
                    .iter()
                    .position(|incident| incident.domain == *domain)
            })
        })
}

/// The trigger and the next state of a volume whose evidence is not usable.
/// Each window resets. No incident changes: missing evidence cannot clear
/// an episode.
fn blocked_volume(
    thresholds: &Thresholds<'_>,
    prior: &DiskVolumeState,
    evidence: Option<&VolumeEvidence>,
    report: EvidenceReport,
    problem: &EvidenceProblem,
) -> (VolumeTrigger, DiskVolumeState) {
    let unusable = || WindowEvidence::Unusable(problem.clone());
    let entry: WindowStep = advance(
        &prior.entry_window,
        unusable(),
        thresholds.sustain,
        thresholds.max_gap,
    );
    let emergency: WindowStep = advance(
        &prior.emergency_window,
        unusable(),
        thresholds.emergency_sustain,
        thresholds.max_gap,
    );
    let recovery: WindowStep = advance(
        &prior.recovery_window,
        unusable(),
        thresholds.recovery_stable,
        thresholds.max_gap,
    );
    let known: Option<CapacityDomainKey> = evidence
        .and_then(|volume| volume.identity.capacity_key())
        .map(CapacityDomainKey::from);
    let trigger: VolumeTrigger = VolumeTrigger {
        selector: prior.selector.clone(),
        volume_id: evidence.map(|volume| volume.identity.volume_id.clone()),
        mount_id: evidence.map(|volume| volume.identity.mount_id.clone()),
        domain_verified: known.is_some(),
        domain: known,
        level: CapacityLevel::Unknown,
        state: TriggerState::Blocked,
        available: None,
        evidence: report,
        entry_window: entry.report,
        emergency_window: emergency.report,
        recovery_window: recovery.report,
        incident_open: false,
        reasons: vec![problem.explanation()],
    };
    let next: DiskVolumeState = DiskVolumeState {
        selector: prior.selector.clone(),
        volume_id: trigger
            .volume_id
            .clone()
            .or_else(|| prior.volume_id.clone()),
        entry_window: entry.window,
        entry_is_continuation: prior.entry_is_continuation,
        emergency_window: emergency.window,
        recovery_window: recovery.window,
    };
    (trigger, next)
}

fn evaluate_volume(
    context: &EvaluationContext<'_>,
    thresholds: &Thresholds<'_>,
    prior: &DiskVolumeState,
    matches: &[&VolumeEvidence],
    incidents: &mut Vec<DiskIncident>,
) -> (VolumeTrigger, DiskVolumeState) {
    let evidence: &VolumeEvidence = match matches {
        [one] => one,
        other => {
            let problem: EvidenceProblem = if other.is_empty() {
                EvidenceProblem::SelectorUnresolved
            } else {
                EvidenceProblem::SelectorAmbiguous
            };
            let report: EvidenceReport =
                EvidenceReport::missing(metric::DISK_AVAILABLE_BYTES, problem.clone());
            return blocked_volume(thresholds, prior, None, report, &problem);
        }
    };
    let scope: Scope = Scope::volume(evidence.identity.volume_id.clone());
    let usable = match assess(
        &evidence.available,
        &metric::DISK_AVAILABLE_BYTES,
        ScopeCheck::Exact(&scope),
        context.clock,
        thresholds.max_age,
    ) {
        Ok(usable) => usable,
        Err(problem) => {
            let report: EvidenceReport =
                evidence_report(&evidence.available, context.clock, Some(problem.clone()));
            return blocked_volume(thresholds, prior, Some(evidence), report, &problem);
        }
    };
    measured_volume(context, thresholds, prior, evidence, &usable, incidents)
}

/// Latches a volume with a qualified trigger and a verified capacity domain
/// in its incident. Opens the incident of the domain when the volume has
/// none. Returns the index of the incident.
fn latch_volume(
    incidents: &mut Vec<DiskIncident>,
    incident: Option<usize>,
    domain: &CapacityDomainKey,
    volume_id: &VolumeId,
) -> usize {
    let index: usize = incident.unwrap_or_else(|| {
        incidents.push(DiskIncident::open(domain.clone()));
        incidents.len().saturating_sub(1)
    });
    if let Some(open) = incidents.get_mut(index)
        && !open.unrecovered.contains(volume_id)
    {
        open.unrecovered.push(volume_id.clone());
    }
    index
}

/// Advances the windows of a volume that has a usable capacity.
fn measured_volume(
    context: &EvaluationContext<'_>,
    thresholds: &Thresholds<'_>,
    prior: &DiskVolumeState,
    evidence: &VolumeEvidence,
    usable: &Usable<'_, Bytes>,
    incidents: &mut Vec<DiskIncident>,
) -> (VolumeTrigger, DiskVolumeState) {
    let guard: &DiskGuard = thresholds.guard;
    let volume_id: &VolumeId = &evidence.identity.volume_id;
    let known: Option<CapacityDomainKey> = evidence
        .identity
        .capacity_key()
        .map(CapacityDomainKey::from);
    let available: Bytes = *usable.value;
    let subject: Vec<String> = vec![
        volume_id.as_str().to_owned(),
        evidence.identity.mount_id.as_str().to_owned(),
    ];
    let holds = |predicate: bool| {
        if predicate {
            WindowEvidence::Holds(usable.qualifying(context.clock, subject.clone()))
        } else {
            WindowEvidence::Contradicts
        }
    };

    let mut incident: Option<usize> = incident_index(incidents, Some(volume_id), known.as_ref());
    // With an open incident, the continuation predicate applies: capacity
    // below the recovery target. Otherwise the entry predicate applies. A
    // window of the continuation predicate cannot qualify the narrower
    // entry predicate, so it starts again when the incident is closed.
    let continuation: bool = incident.is_some();
    let entry_threshold: Bytes = if continuation {
        guard.recover_above
    } else {
        guard.reclaim_below
    };
    let prior_entry: &QualificationWindow = if prior.entry_is_continuation && !continuation {
        &QualificationWindow::Idle
    } else {
        &prior.entry_window
    };
    let entry: WindowStep = advance(
        prior_entry,
        holds(available < entry_threshold),
        thresholds.sustain,
        thresholds.max_gap,
    );
    let emergency: WindowStep = advance(
        &prior.emergency_window,
        holds(available < guard.emergency_below),
        thresholds.emergency_sustain,
        thresholds.max_gap,
    );
    let triggered: bool = entry.report.qualified || emergency.report.qualified;

    if triggered && let Some(key) = &known {
        incident = Some(latch_volume(incidents, incident, key, volume_id));
    }
    let at_target: bool = available >= guard.recover_above;
    let recovery: WindowStep = advance(
        &prior.recovery_window,
        holds(incident.is_some() && at_target),
        thresholds.recovery_stable,
        thresholds.max_gap,
    );
    let open: Option<&mut DiskIncident> = incident.and_then(|index| incidents.get_mut(index));
    let mut latched: bool = false;
    if let Some(open) = open {
        if recovery.report.qualified {
            open.unrecovered.retain(|volume| volume != volume_id);
        }
        latched = open.unrecovered.contains(volume_id);
    }

    let state: TriggerState = if triggered {
        TriggerState::Ready
    } else if latched && at_target {
        TriggerState::Recovering
    } else if (incident.is_some() && !at_target) || available < guard.reclaim_below {
        TriggerState::Qualifying
    } else if available < guard.warn_below {
        TriggerState::Advisory
    } else {
        TriggerState::Normal
    };

    let trigger: VolumeTrigger = VolumeTrigger {
        selector: prior.selector.clone(),
        volume_id: Some(volume_id.clone()),
        mount_id: Some(evidence.identity.mount_id.clone()),
        domain_verified: known.is_some(),
        domain: known,
        level: thresholds.level(available),
        state,
        available: Some(available),
        evidence: evidence_report(&evidence.available, context.clock, None),
        entry_window: entry.report,
        emergency_window: emergency.report,
        recovery_window: recovery.report,
        incident_open: incident.is_some(),
        reasons: Vec::new(),
    };
    let next: DiskVolumeState = DiskVolumeState {
        selector: prior.selector.clone(),
        volume_id: Some(volume_id.clone()),
        entry_window: entry.window,
        entry_is_continuation: continuation,
        emergency_window: emergency.window,
        recovery_window: recovery.window,
    };
    (trigger, next)
}

/// Groups the usable capacities by capacity domain. A volume with no
/// verified membership is not in a sum.
fn capacity_overview(volumes: &[VolumeTrigger]) -> CapacityOverview {
    let mut overview: CapacityOverview = CapacityOverview::default();
    for volume in volumes {
        let Some(available) = volume.available else {
            overview.unusable.push(volume.selector.clone());
            continue;
        };
        let verified: Option<&CapacityDomainKey> =
            volume.domain.as_ref().filter(|_| volume.domain_verified);
        let Some(domain) = verified else {
            overview.not_summed.push(volume.selector.clone());
            continue;
        };
        if let Some(entry) = overview
            .domains
            .iter_mut()
            .find(|entry| entry.domain == *domain)
        {
            entry.available = entry.available.min(available);
            entry.selectors.push(volume.selector.clone());
        } else {
            overview.domains.push(DomainCapacity {
                domain: domain.clone(),
                available,
                selectors: vec![volume.selector.clone()],
            });
        }
    }
    overview.total_available = if overview.domains.is_empty() || !overview.unusable.is_empty() {
        None
    } else {
        overview
            .domains
            .iter()
            .try_fold(Bytes::ZERO, |sum, entry| sum.checked_add(entry.available))
    };
    overview
}

/// The decision for one cleanup candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CleanupDecision {
    /// The identity of the target.
    pub target_id: TargetId,
    /// The rule that found the target.
    pub rule_id: RuleId,
    /// The volume of the target.
    pub volume_id: VolumeId,
    /// The decision.
    pub decision: CandidateDecision,
    /// Each reason, with the primary reason first. Empty for an eligible
    /// candidate.
    pub reasons: Vec<Explanation>,
    /// The position among the candidates of the volume that passed the
    /// eligibility checks, from 1. A candidate that only a budget excludes
    /// keeps its rank.
    pub rank: Option<u32>,
    /// True when the first batch has the candidate.
    pub in_first_batch: bool,
    /// The `work_bytes` charge.
    pub work_bytes: Option<Bytes>,
    /// The number of entries.
    pub item_count: Option<EntryCount>,
    /// The estimate of reclaimable bytes. It is not a promise.
    pub estimated_reclaimable_bytes: Option<Bytes>,
}

/// The allowance that the first batch of a volume has.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct DiskAllowance {
    /// The `work_bytes` ceiling of one batch.
    pub batch_limit: Bytes,
    /// The `work_bytes` that the pass can still charge.
    pub pass_remaining: Bytes,
    /// The `work_bytes` that the incident can still charge.
    pub incident_remaining: Bytes,
    /// The entry ceiling of one batch.
    pub batch_item_limit: EntryCount,
    /// The entries that the pass can still charge.
    pub pass_items_remaining: EntryCount,
    /// The entries that the incident can still charge.
    pub incident_items_remaining: EntryCount,
    /// The passes that the incident can still start, the pass in progress
    /// included.
    pub passes_remaining: u32,
    /// The time ceiling of one pass.
    pub pass_time_limit: Nanoseconds,
}

impl DiskAllowance {
    /// `planned` is the charge of the first batches of other volumes of
    /// the same incident in this plan. It counts as reserved.
    fn of(
        guard: &DiskGuard,
        incident: Option<&DiskIncident>,
        planned: (Bytes, EntryCount),
    ) -> Self {
        let usage: WorkUsage = match incident {
            Some(incident) => incident.usage,
            None => WorkUsage::default(),
        }
        .with_planned(planned);
        let started: u32 = incident.map_or(0, |incident| incident.passes_started);
        let in_progress: Option<WorkUsage> = incident.and_then(|incident| incident.current_pass);
        let new_passes: u32 = guard.max_passes_per_incident.get().saturating_sub(started);
        let passes_remaining: u32 = new_passes.saturating_add(u32::from(in_progress.is_some()));
        // With no pass in progress, the first batch starts a new pass. With
        // no pass left, the pass allowance is zero.
        let pass: Option<WorkUsage> = in_progress
            .or((new_passes > 0).then(WorkUsage::default))
            .map(|pass| pass.with_planned(planned));
        Self {
            batch_limit: guard.batch_limit,
            pass_remaining: pass.map_or(Bytes::ZERO, |pass| pass.bytes_left(guard.pass_limit)),
            incident_remaining: usage.bytes_left(guard.incident_limit),
            batch_item_limit: guard.batch_item_limit,
            pass_items_remaining: pass.map_or(EntryCount::ZERO, |pass| {
                pass.items_left(guard.pass_item_limit)
            }),
            incident_items_remaining: usage.items_left(guard.incident_item_limit),
            passes_remaining,
            pass_time_limit: nanoseconds(guard.pass_time_limit),
        }
    }

    /// The reason that the charge cannot be in a batch of this allowance,
    /// with the tightest ceiling first.
    fn exceeded(&self, work: Bytes, items: EntryCount) -> Option<ReasonDetail> {
        // A ceiling with nothing left admits no candidate, also one with a
        // charge of zero.
        let pass_full: bool =
            self.pass_remaining == Bytes::ZERO || self.pass_items_remaining == EntryCount::ZERO;
        let incident_full: bool = self.incident_remaining == Bytes::ZERO
            || self.incident_items_remaining == EntryCount::ZERO;
        if work > self.batch_limit || items > self.batch_item_limit {
            Some(ReasonDetail::ExceedsBatchLimit)
        } else if pass_full || work > self.pass_remaining || items > self.pass_items_remaining {
            if self.passes_remaining == 0 {
                Some(ReasonDetail::PassCountExhausted)
            } else {
                Some(ReasonDetail::ExceedsPassLimit)
            }
        } else if incident_full
            || work > self.incident_remaining
            || items > self.incident_items_remaining
        {
            Some(ReasonDetail::ExceedsIncidentLimit)
        } else {
            None
        }
    }
}

/// The first batch that an incident of one volume would dispatch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FirstBatch {
    /// The selector of the volume.
    pub selector: String,
    /// The volume.
    pub volume_id: Option<VolumeId>,
    /// True when no reason inhibits the batch at this snapshot.
    pub admissible_now: bool,
    /// The reasons that inhibit the batch at this snapshot.
    pub blocked_by: Vec<Explanation>,
    /// The targets of the batch, in rank sequence.
    pub targets: Vec<TargetId>,
    /// The sum of the `work_bytes` charges of the targets.
    pub work_bytes: Bytes,
    /// The sum of the entry counts of the targets.
    pub item_count: EntryCount,
    /// The sum of the estimates of reclaimable bytes. `None` when a target
    /// has no estimate. It is not a promise.
    pub estimated_reclaimable_bytes: Option<Bytes>,
    /// The allowance that the batch was built under.
    pub allowance: DiskAllowance,
    /// The rules of the targets that have no per-rule allowance in the
    /// snapshot. The per-rule ceiling was not evaluated for them, and the
    /// batch is not admissible while the list has an entry.
    pub rules_without_ceiling: Vec<RuleId>,
}

/// The result of [`plan_cleanup`].
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct CleanupPlan {
    /// The decision for each candidate: the ranked candidates of each
    /// selected volume first, then the others by target identity.
    pub decisions: Vec<CleanupDecision>,
    /// The first batch of each selected volume, in the sequence of the
    /// configuration.
    pub first_batches: Vec<FirstBatch>,
}

/// The path lists and the settings that the candidate checks use.
struct CleanupChecks<'a> {
    guard: &'a DiskGuard,
    global_paths: PathSet,
    disk_paths: PathSet,
}

impl CleanupChecks<'_> {
    fn class_protected(&self, class: ProtectedDataClass) -> bool {
        let exclusions = &self.guard.exclusions;
        match class {
            ProtectedDataClass::Archive => exclusions.protect_archives,
            ProtectedDataClass::Backup => exclusions.protect_backups,
            ProtectedDataClass::Database => exclusions.protect_databases,
            ProtectedDataClass::ModelWeights => exclusions.protect_model_weights,
        }
    }

    /// The reasons that exclude a candidate, in the sequence of
    /// `docs/POLICY_SPEC.md` section 7: hard protections, authority, user
    /// exclusions, target eligibility, and observation quality.
    fn reasons(&self, candidate: &CleanupCandidate, volume_selected: bool) -> Vec<Explanation> {
        use DecisionReason as Reason;
        use ReasonDetail as Detail;
        let facts: &CleanupFacts = &candidate.facts;
        let mut reasons: Vec<Explanation> = Vec::new();
        let mut add = |reason: Reason, detail: Detail| {
            push_reason(&mut reasons, Explanation::new(reason, detail));
        };

        if facts.hard_protection == ProtectionFact::Protected {
            add(Reason::HardProtected, Detail::ProductProtection);
        }
        if facts
            .protected_classes
            .iter()
            .any(|class| self.class_protected(*class))
        {
            add(Reason::HardProtected, Detail::ProtectedDataClass);
        }
        if !self.guard.approved_rules.contains(&candidate.rule_id) {
            add(Reason::ActionNotGranted, Detail::RuleNotApproved);
        }
        match facts.rule_readiness {
            RuleReadiness::Ready => {}
            RuleReadiness::NotReady => add(Reason::RuleNotReady, Detail::RuleNotReady),
            RuleReadiness::VersionUnapproved => {
                add(Reason::RuleVersionUnapproved, Detail::RuleVersionUnapproved);
            }
        }
        if self.global_paths.overlaps(&candidate.path) || self.disk_paths.overlaps(&candidate.path)
        {
            add(Reason::UserExcluded, Detail::ExcludedPath);
        }
        match facts.owner {
            OwnerFact::RequestingUser | OwnerFact::Unknown => {}
            OwnerFact::OtherUser => add(Reason::TargetNotEligible, Detail::OtherUser),
        }
        if !volume_selected {
            add(Reason::TargetNotEligible, Detail::VolumeNotSelected);
        }
        if facts.activity == ActivityFact::Active {
            add(Reason::TargetNotEligible, Detail::TargetActive);
        }
        if self.global_paths.unresolved || self.disk_paths.unresolved {
            add(Reason::MetricUnavailable, Detail::HomeDirectoryUnknown);
        }
        if !is_canonical(&candidate.path) {
            add(Reason::MetricUnavailable, Detail::PathNotCanonical);
        }
        if facts.hard_protection == ProtectionFact::Unknown {
            add(Reason::MetricUnavailable, Detail::ProtectionUnknown);
        }
        if facts.owner == OwnerFact::Unknown {
            add(Reason::MetricUnavailable, Detail::OwnerUnknown);
        }
        if facts.activity == ActivityFact::Unknown {
            add(Reason::MetricUnavailable, Detail::ActivityUnknown);
        }
        if candidate.work_bytes.is_none() || candidate.item_count.is_none() {
            add(Reason::MetricUnavailable, Detail::WorkChargeUnknown);
        }
        if candidate.item_count == Some(EntryCount::ZERO) {
            add(Reason::TargetNotEligible, Detail::NoItems);
        }
        reasons
    }
}

/// The rank key of an eligible candidate: the position of its rule in
/// `approved_rules`, the lower rebuild cost, the longer known inactivity,
/// and the target identity.
fn rank_key<'a>(
    guard: &DiskGuard,
    candidate: &'a CleanupCandidate,
) -> (usize, RebuildCost, Reverse<Nanoseconds>, &'a str) {
    let priority: usize = guard
        .approved_rules
        .iter()
        .position(|rule| *rule == candidate.rule_id)
        .unwrap_or(usize::MAX);
    let inactive_for: Nanoseconds = match candidate.facts.activity {
        ActivityFact::Inactive { inactive_for } => inactive_for,
        ActivityFact::Active | ActivityFact::Unknown => Nanoseconds::ZERO,
    };
    (
        priority,
        candidate.facts.rebuild_cost,
        Reverse(inactive_for),
        candidate.target_id.as_str(),
    )
}

fn decision_for(candidate: &CleanupCandidate, reasons: Vec<Explanation>) -> CleanupDecision {
    CleanupDecision {
        target_id: candidate.target_id.clone(),
        rule_id: candidate.rule_id.clone(),
        volume_id: candidate.volume_id.clone(),
        decision: decision_of(&reasons),
        reasons,
        rank: None,
        in_first_batch: false,
        work_bytes: candidate.work_bytes,
        item_count: candidate.item_count,
        estimated_reclaimable_bytes: candidate.estimated_reclaimable_bytes,
    }
}

/// The allowance pool of a volume in a plan: its incident, or its capacity
/// domain when no incident is open.
type Pool = (Option<usize>, Option<CapacityDomainKey>);

/// Decides the eligibility of each cleanup candidate and builds the first
/// batch of each selected volume.
///
/// A candidate must have a rule in `approved_rules`, a ready rule, no
/// protection, no exclusion, the requesting user as its owner, known
/// inactivity, and a known charge. The eligible candidates of a volume are
/// ranked, and the first batch takes them in rank sequence under the batch,
/// pass, per-rule, and incident ceilings. A candidate is indivisible: one
/// whose charge is larger than a remaining ceiling is skipped. The per-rule
/// allowances of the snapshot are charged by the first batches of all volumes
/// in sequence. A rule with no allowance is not bound: the batch lists it in
/// `rules_without_ceiling` and is not admissible.
///
/// The first batch is what an incident would dispatch first. `blocked_by`
/// tells why it is not admissible at this snapshot. The function reserves no
/// budget.
pub fn plan_cleanup(
    context: &EvaluationContext<'_>,
    evaluation: &DiskEvaluation,
    snapshot: &DiskSnapshot,
) -> CleanupPlan {
    let guard: &DiskGuard = context.config.disk_guard();
    let checks: CleanupChecks<'_> = CleanupChecks {
        guard,
        global_paths: PathSet::resolve(
            context.config.protections().excluded_paths.iter(),
            context.home_directory,
        ),
        disk_paths: PathSet::resolve(guard.exclusions.paths.iter(), context.home_directory),
    };
    let authority: Vec<Explanation> =
        context.authority_reasons(guard.enabled, context.grants.evict_regenerable_data);

    let mut plan: CleanupPlan = CleanupPlan::default();
    // The per-rule allowances are shared by the first batches of the plan.
    let mut rule_left: Vec<RuleAllowance> = snapshot.rule_allowances.clone();
    let mut placed: Vec<bool> = vec![false; snapshot.candidates.len()];
    // The charge of the first batches by incident, or by capacity domain
    // when no incident is open: the volumes of one domain share one
    // allowance.
    let incidents: &[DiskIncident] = &evaluation.next_state.incidents;
    let mut planned: Vec<(Pool, (Bytes, EntryCount))> = Vec::new();
    for trigger in &evaluation.volumes {
        let index: Option<usize> = incident_index(
            incidents,
            trigger.volume_id.as_ref(),
            trigger.domain.as_ref(),
        );
        let incident: Option<&DiskIncident> = index.and_then(|index| incidents.get(index));
        let pool: Pool = (index, trigger.domain.clone().filter(|_| index.is_none()));
        let shared: bool = pool.0.is_some() || pool.1.is_some();
        let before: (Bytes, EntryCount) = planned
            .iter()
            .find(|(key, _)| shared && *key == pool)
            .map_or((Bytes::ZERO, EntryCount::ZERO), |(_, charge)| *charge);
        let allowance: DiskAllowance = DiskAllowance::of(guard, incident, before);
        let mut eligible: Vec<&CleanupCandidate> = Vec::new();
        for (index, candidate) in snapshot.candidates.iter().enumerate() {
            if placed[index] || trigger.volume_id.as_ref() != Some(&candidate.volume_id) {
                continue;
            }
            placed[index] = true;
            let reasons: Vec<Explanation> = checks.reasons(candidate, true);
            if reasons.is_empty() {
                eligible.push(candidate);
            } else {
                plan.decisions.push(decision_for(candidate, reasons));
            }
        }
        eligible.sort_by(|left, right| rank_key(guard, left).cmp(&rank_key(guard, right)));
        let batch: FirstBatch = fill_batch(
            trigger,
            &authority,
            allowance,
            &eligible,
            &mut rule_left,
            &mut plan.decisions,
        );
        if shared {
            let charge: (Bytes, EntryCount) = (
                Bytes::new(before.0.get().saturating_add(batch.work_bytes.get())),
                EntryCount::new(before.1.get().saturating_add(batch.item_count.get())),
            );
            match planned.iter_mut().find(|(key, _)| *key == pool) {
                Some((_, total)) => *total = charge,
                None => planned.push((pool, charge)),
            }
        }
        plan.first_batches.push(batch);
    }
    for (index, candidate) in snapshot.candidates.iter().enumerate() {
        if !placed[index] {
            let reasons: Vec<Explanation> = checks.reasons(candidate, false);
            plan.decisions.push(decision_for(candidate, reasons));
        }
    }
    // The ranked candidates keep the sequence of the volumes and the ranks.
    // The others follow by target identity.
    let ranked: usize = plan
        .decisions
        .iter()
        .filter(|decision| decision.rank.is_some())
        .count();
    plan.decisions
        .sort_by_key(|decision| decision.rank.is_none());
    plan.decisions[ranked..].sort_by(|left, right| left.target_id.cmp(&right.target_id));
    plan
}

/// True when the rule has an allowance and the charge is larger than it.
fn exceeds_rule(rules: &[RuleAllowance], rule_id: &RuleId, work: Bytes, items: EntryCount) -> bool {
    rules
        .iter()
        .find(|rule| rule.rule_id == *rule_id)
        .is_some_and(|rule| work > rule.remaining_bytes || items > rule.remaining_items)
}

/// Charges the allowance of the rule of a placed candidate, or records that
/// the rule has none.
fn charge_rule(
    rules: &mut [RuleAllowance],
    candidate: &CleanupCandidate,
    (work, items): (Bytes, EntryCount),
    batch: &mut FirstBatch,
) {
    match rules
        .iter_mut()
        .find(|rule| rule.rule_id == candidate.rule_id)
    {
        Some(rule) => {
            // `exceeds_rule` made sure that the charge fits.
            rule.remaining_bytes = rule
                .remaining_bytes
                .checked_sub(work)
                .unwrap_or(Bytes::ZERO);
            rule.remaining_items = rule
                .remaining_items
                .checked_sub(items)
                .unwrap_or(EntryCount::ZERO);
        }
        None => {
            if !batch.rules_without_ceiling.contains(&candidate.rule_id) {
                batch.rules_without_ceiling.push(candidate.rule_id.clone());
            }
        }
    }
}

/// Sets the reasons that inhibit the batch and its admissibility.
fn finish_batch(
    batch: &mut FirstBatch,
    trigger: &VolumeTrigger,
    authority: &[Explanation],
    budget_block: Option<Explanation>,
) {
    for reason in authority {
        push_reason(&mut batch.blocked_by, *reason);
    }
    if trigger.state != TriggerState::Ready || !trigger.domain_verified {
        for reason in &trigger.reasons {
            push_reason(&mut batch.blocked_by, *reason);
        }
    }
    if batch.targets.is_empty() {
        if let Some(reason) = budget_block {
            push_reason(&mut batch.blocked_by, reason);
        }
        push_reason(
            &mut batch.blocked_by,
            Explanation::new(
                DecisionReason::TargetNotEligible,
                ReasonDetail::NoEligibleCandidate,
            ),
        );
    }
    if !batch.rules_without_ceiling.is_empty() {
        push_reason(
            &mut batch.blocked_by,
            Explanation::new(
                DecisionReason::MetricUnavailable,
                ReasonDetail::RuleCeilingNotEvaluated,
            ),
        );
    }
    batch.admissible_now = batch.blocked_by.is_empty();
}

/// Takes the ranked candidates into the first batch and records a decision
/// for each one.
fn fill_batch(
    trigger: &VolumeTrigger,
    authority: &[Explanation],
    allowance: DiskAllowance,
    ranked: &[&CleanupCandidate],
    rule_left: &mut [RuleAllowance],
    decisions: &mut Vec<CleanupDecision>,
) -> FirstBatch {
    let mut batch: FirstBatch = FirstBatch {
        selector: trigger.selector.clone(),
        volume_id: trigger.volume_id.clone(),
        admissible_now: false,
        blocked_by: Vec::new(),
        targets: Vec::new(),
        work_bytes: Bytes::ZERO,
        item_count: EntryCount::ZERO,
        estimated_reclaimable_bytes: Some(Bytes::ZERO),
        allowance,
        rules_without_ceiling: Vec::new(),
    };
    let mut bytes_left: Bytes = allowance
        .batch_limit
        .min(allowance.pass_remaining)
        .min(allowance.incident_remaining);
    let mut items_left: EntryCount = allowance
        .batch_item_limit
        .min(allowance.pass_items_remaining)
        .min(allowance.incident_items_remaining);
    let mut rank: u32 = 0;
    let mut budget_block: Option<Explanation> = None;
    for candidate in ranked {
        rank = rank.saturating_add(1);
        let mut decision: CleanupDecision = decision_for(candidate, Vec::new());
        decision.rank = Some(rank);
        // The eligibility checks made sure that the two values are known.
        let (Some(work), Some(items)) = (candidate.work_bytes, candidate.item_count) else {
            decisions.push(decision);
            continue;
        };
        if let Some(detail) = allowance.exceeded(work, items) {
            let reason: Explanation = Explanation::new(DecisionReason::BudgetExhausted, detail);
            budget_block.get_or_insert(reason);
            decision.reasons = vec![reason];
            decision.decision = CandidateDecision::Skipped;
        } else if bytes_left == Bytes::ZERO || items_left == EntryCount::ZERO {
            // A ceiling of the batch has nothing left. Not even a charge of
            // zero bytes is placed.
            decision.reasons = vec![Explanation::new(
                DecisionReason::BudgetExhausted,
                ReasonDetail::BatchFull,
            )];
            decision.decision = CandidateDecision::Skipped;
        } else if exceeds_rule(rule_left, &candidate.rule_id, work, items) {
            let reason: Explanation = Explanation::new(
                DecisionReason::BudgetExhausted,
                ReasonDetail::ExceedsRuleLimit,
            );
            budget_block.get_or_insert(reason);
            decision.reasons = vec![reason];
            decision.decision = CandidateDecision::Skipped;
        } else if let (Some(bytes_after), Some(items_after), Some(work_sum), Some(item_sum)) = (
            bytes_left.checked_sub(work),
            items_left.checked_sub(items),
            batch.work_bytes.checked_add(work),
            batch.item_count.checked_add(items),
        ) {
            bytes_left = bytes_after;
            items_left = items_after;
            charge_rule(rule_left, candidate, (work, items), &mut batch);
            batch.work_bytes = work_sum;
            batch.item_count = item_sum;
            batch.targets.push(candidate.target_id.clone());
            batch.estimated_reclaimable_bytes = batch
                .estimated_reclaimable_bytes
                .zip(candidate.estimated_reclaimable_bytes)
                .and_then(|(sum, estimate)| sum.checked_add(estimate));
            decision.in_first_batch = true;
        } else {
            // The candidate fits an empty batch and does not fit the rest of
            // this one. A later batch can take it.
            decision.reasons = vec![Explanation::new(
                DecisionReason::BudgetExhausted,
                ReasonDetail::BatchFull,
            )];
            decision.decision = CandidateDecision::Skipped;
        }
        decisions.push(decision);
    }

    finish_batch(&mut batch, trigger, authority, budget_block);
    batch
}
