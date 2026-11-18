//! The state, the inputs, the intents, and the status of the controller.

use serde::{Deserialize, Serialize};
use svalnir_core::action::{Plan, TriggerClass, WorkCharge};
use svalnir_core::config::ValidatedConfig;
use svalnir_core::file::{FileObjectEvidence, LosslessPath};
use svalnir_core::grant::{AuthorityState, EvidenceStamp, IncidentBudget, InstanceInhibition};
use svalnir_core::id::{
    ExecutorEpochId, IncidentId, MountId, OperationId, PlanId, RootId, RuleId, VolumeId,
};
use svalnir_core::plan::SizeEstimate;
use svalnir_core::policy::{
    CapacityDomainKey, ControlPlaneProcess, Cooldown, MemorySnapshot, PolicyId, PolicyState,
    QualificationWindow, VolumeEvidence,
};
use svalnir_core::process::Uid;
use svalnir_core::quantity::ByteDelta;
use svalnir_core::rule::{RuleCandidate, RuleRegistry};
use svalnir_core::state::PressureState;
use svalnir_core::time::{MonotonicNanos, WallTime};

use crate::coordinator::{IncidentAllowance, TimeReading, TriggerStanding};

/// The version of the stored [`ControllerState`].
pub const CONTROLLER_STATE_VERSION: u32 = 1;

/// The version of the [`ControllerStatus`] record.
pub const CONTROLLER_STATUS_VERSION: u32 = 1;

/// The largest number of prepared candidates that one step reads.
pub const MAX_PREPARED_CANDIDATES: usize = 1024;

/// The largest number of reports that one step reads.
pub const MAX_REPORTS: usize = 64;

/// The largest number of reasons that a status entry keeps.
pub const MAX_STATUS_REASONS: usize = 8;

/// The largest number of application cooldowns that the state keeps. The
/// oldest one is removed first.
pub const MAX_APPLICATION_COOLDOWNS: usize = 256;

/// One guard, with a stable name in the stored records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Guard {
    /// The disk guard.
    Disk,
    /// The memory guard.
    Memory,
}

impl Guard {
    /// The two guards. The memory guard is first: its decision does not
    /// wait for the disk guard.
    pub const ALL: [Self; 2] = [Self::Memory, Self::Disk];

    /// The policy of the guard.
    pub const fn policy(self) -> PolicyId {
        match self {
            Self::Disk => PolicyId::DiskGuard,
            Self::Memory => PolicyId::MemoryGuard,
        }
    }

    /// The name in an identity.
    pub(super) const fn tag(self) -> &'static str {
        match self {
            Self::Disk => "disk",
            Self::Memory => "memory",
        }
    }
}

/// The trigger that an automatic plan depends on.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TriggerKey {
    /// The capacity trigger of one volume.
    Disk {
        /// The volume.
        volume_id: VolumeId,
    },
    /// Sustained global critical memory pressure.
    GlobalMemory,
    /// The stop budget of one configured application.
    Budget {
        /// The identity of the budget in the configuration.
        budget_id: String,
    },
}

impl TriggerKey {
    /// The trigger class of a plan of this trigger.
    pub const fn class(&self) -> TriggerClass {
        match self {
            Self::Disk { .. } => TriggerClass::DiskPressure,
            Self::GlobalMemory => TriggerClass::GlobalCriticalMemory,
            Self::Budget { .. } => TriggerClass::ApplicationBudget,
        }
    }
}

/// The record of one open disk incident. The policy state has the windows,
/// the usage, and the cooldown of the same incident; this record adds the
/// identity and the budget generation, which the policy state does not
/// have.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiskIncidentRecord {
    /// The identity of the incident.
    pub incident_id: IncidentId,
    /// The capacity domain. It is the key of the incident in the policy
    /// state.
    pub domain: CapacityDomainKey,
    /// The budget record of the grant module.
    pub budget: IncidentBudget,
    /// The executor lifetime in which the current budget generation
    /// started.
    pub opened_in: ExecutorEpochId,
    /// False when a restart could not establish that the usage of the
    /// incident was preserved. The incident then permits no automatic
    /// work until it closes or a person rearms it.
    pub established: bool,
    /// True when an operation of the incident ended with an effect that is
    /// not known. It permits no further automatic work in the incident.
    pub unknown_outcome: bool,
    /// The charge of each rule in the pass in progress.
    pub rule_usage: Vec<RuleUsage>,
    /// The time before which the next batch is not selected: the
    /// observation window after an action.
    pub observe_until: Option<Cooldown>,
    /// The error code of the latest plan that the coordinator refused.
    /// The next admitted plan removes it.
    pub last_refusal: Option<String>,
    /// The number of plans in sequence that the coordinator refused. The
    /// wait before the next plan doubles with each one, to a maximum. The
    /// next admitted plan sets it to zero.
    pub refusals: u32,
}

/// The charge of one rule in the pass in progress.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleUsage {
    /// The rule.
    pub rule_id: RuleId,
    /// The charge that the pass consumed or reserved for the rule.
    pub charge: WorkCharge,
}

/// The record of the open memory incident of the user.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryIncidentRecord {
    /// The identity of the incident.
    pub incident_id: IncidentId,
    /// The budget record of the grant module.
    pub budget: IncidentBudget,
    /// The executor lifetime in which the current budget generation
    /// started.
    pub opened_in: ExecutorEpochId,
    /// See [`DiskIncidentRecord::established`].
    pub established: bool,
    /// See [`DiskIncidentRecord::unknown_outcome`].
    pub unknown_outcome: bool,
    /// The time before which the next target is not selected: the
    /// observation window after an action.
    pub observe_until: Option<Cooldown>,
    /// The backoff after an action with a low benefit or a failure.
    pub backoff: Option<Cooldown>,
    /// The error code of the latest plan that the coordinator refused.
    /// The next admitted plan removes it.
    pub last_refusal: Option<String>,
    /// See [`DiskIncidentRecord::refusals`].
    pub refusals: u32,
}

/// The automatic plan that the controller gave to the runtime and whose
/// result it does not have yet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Outstanding {
    /// The guard of the plan.
    pub guard: Guard,
    /// The incident of the plan.
    pub incident_id: IncidentId,
    /// The plan.
    pub plan_id: PlanId,
    /// The operation, after the coordinator admitted the plan.
    pub operation_id: Option<OperationId>,
    /// The trigger of the plan.
    pub trigger: TriggerKey,
    /// The charge of a filesystem plan, by rule.
    pub rules: Vec<RuleUsage>,
    /// The cooldown key of the application of an application plan: the
    /// bundle identifier or the job label.
    pub application: Option<String>,
}

/// The state that the controller keeps between two steps.
///
/// The stored form is [`ControllerState::durable_view`]: the same record
/// with each qualification window idle. A restart needs fresh
/// observations for each window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControllerState {
    /// [`CONTROLLER_STATE_VERSION`].
    pub schema_version: u32,
    /// The windows, the latches, the incidents, and the cooldowns of the
    /// policy evaluation.
    pub policy: PolicyState,
    /// One record for each open disk incident.
    pub disk_incidents: Vec<DiskIncidentRecord>,
    /// The record of the open memory incident.
    pub memory_incident: Option<MemoryIncidentRecord>,
    /// The automatic plan in progress. The controller permits one.
    pub outstanding: Option<Outstanding>,
    /// The counter of the identities that the controller makes.
    pub sequence: u64,
    /// The guards that permit no automatic work until an evaluation shows
    /// no open incident and no pressure: the state before a restart was
    /// not readable.
    pub held_until_recovery: Vec<Guard>,
    /// For each held guard, the time from which each evaluation of this
    /// lifetime showed no pressure and no incident. The hold ends when
    /// that time is as long as the recovery time of the guard. It is not
    /// stored: a restart is not evidence of a recovery.
    #[serde(skip)]
    pub quiet_since: Vec<QuietMark>,
    /// Whether the latest step found a pause in effect.
    pub paused: bool,
    /// The time of the latest end of a pause that this controller saw.
    /// Trigger evidence must be newer.
    pub measurement_floor: Option<MonotonicMark>,
    /// The guard conditions that the latest step reported, so that a
    /// notification is made only for a change.
    pub reported: Vec<ReportedCondition>,
    /// True after a clean stop wrote the record. A record that a running
    /// agent wrote has `false`.
    pub clean_stop: bool,
}

/// A time of the monotonic clock with its clock domain and its boot. A
/// time of a different boot is not comparable.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MonotonicMark {
    /// The time.
    pub at: MonotonicNanos,
    /// The clock domain.
    pub clock_domain: svalnir_core::id::ClockDomainId,
    /// The boot.
    pub boot_id: svalnir_core::id::BootId,
}

/// The start of a continuous time with no pressure and no incident of a
/// guard that waits for recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuietMark {
    /// The guard.
    pub guard: Guard,
    /// The time of the first evaluation of the sequence.
    pub since: MonotonicMark,
    /// The continuity generation of the clock at that time. A time of a
    /// different generation is not comparable: the host slept.
    pub continuity: svalnir_core::policy::ContinuityGeneration,
}

/// The condition of a guard that the latest step reported.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportedCondition {
    /// The guard.
    pub guard: Guard,
    /// The phase.
    pub phase: GuardPhase,
    /// The first reason that inhibits automatic work.
    pub blocked: Option<BlockedReason>,
}

impl Default for ControllerState {
    fn default() -> Self {
        Self {
            schema_version: CONTROLLER_STATE_VERSION,
            policy: PolicyState::default(),
            disk_incidents: Vec::new(),
            memory_incident: None,
            outstanding: None,
            sequence: 0,
            held_until_recovery: Vec::new(),
            quiet_since: Vec::new(),
            paused: false,
            measurement_floor: None,
            reported: Vec::new(),
            clean_stop: false,
        }
    }
}

/// How the state of the lifetime before this one was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PriorState {
    /// The journal has no controller record: this is the first start.
    Absent,
    /// The journal has a record that this build cannot read.
    Unreadable,
    /// The record of the lifetime before this one.
    Recorded(Box<ControllerState>),
}

impl ControllerState {
    /// The identities of the open incidents.
    ///
    /// The retention of the journal keeps the usage row of each of them
    /// (`docs/ACTION_CONTRACTS.md` section 12: a restart does not
    /// replenish a budget during continuing pressure).
    #[must_use]
    pub fn open_incident_ids(&self) -> Vec<IncidentId> {
        self.disk_incidents
            .iter()
            .map(|incident| incident.incident_id.clone())
            .chain(
                self.memory_incident
                    .iter()
                    .map(|incident| incident.incident_id.clone()),
            )
            .collect()
    }

    /// The record to store: this state with each qualification window
    /// idle. The latches, the incidents, the usage, and the cooldowns
    /// stay.
    #[must_use]
    pub fn durable_view(&self) -> Self {
        let mut view: Self = self.clone();
        for volume in &mut view.policy.disk.volumes {
            volume.entry_window = QualificationWindow::Idle;
            volume.emergency_window = QualificationWindow::Idle;
            volume.recovery_window = QualificationWindow::Idle;
        }
        view.policy.memory.critical_window = QualificationWindow::Idle;
        view.policy.memory.recovery_window = QualificationWindow::Idle;
        for budget in &mut view.policy.memory.budgets {
            budget.stop_window = QualificationWindow::Idle;
            budget.recovery_window = QualificationWindow::Idle;
        }
        view.reported.clear();
        view.quiet_since.clear();
        view
    }

    /// The state at the start of an executor lifetime.
    ///
    /// A restart does not replenish a budget and does not shorten a
    /// cooldown: the usage, the latches, and the cooldowns of the record
    /// stay. Each window is idle. A plan that was in progress is charged in
    /// full, and its incident permits no further automatic work until it
    /// closes or a person rearms it, because this lifetime cannot dispatch
    /// the plan again and does not know its effect. After a stop that was
    /// not clean, the same applies to each open incident. With a record
    /// that is not readable, each guard waits for an evaluation that shows
    /// no incident and no pressure.
    #[must_use]
    pub fn restore(prior: PriorState) -> Self {
        let recorded: Self = match prior {
            PriorState::Absent => return Self::default(),
            PriorState::Unreadable => {
                return Self {
                    held_until_recovery: vec![Guard::Memory, Guard::Disk],
                    ..Self::default()
                };
            }
            PriorState::Recorded(recorded) => *recorded,
        };
        if recorded.schema_version != CONTROLLER_STATE_VERSION {
            return Self::restore(PriorState::Unreadable);
        }
        let clean: bool = recorded.clean_stop;
        let mut state: Self = recorded.durable_view();
        state.clean_stop = false;
        // Each window starts again, so each measurement of this lifetime
        // is newer than a pause that ended before it.
        state.measurement_floor = None;
        let interrupted: Option<Outstanding> = state.outstanding.take();
        for record in &mut state.disk_incidents {
            let was_acting: bool = interrupted
                .as_ref()
                .is_some_and(|plan| plan.incident_id == record.incident_id);
            if !clean || was_acting {
                record.established = false;
            }
            if was_acting {
                record.unknown_outcome = true;
            }
        }
        if let Some(record) = &mut state.memory_incident {
            let was_acting: bool = interrupted
                .as_ref()
                .is_some_and(|plan| plan.incident_id == record.incident_id);
            if !clean || was_acting {
                record.established = false;
            }
            if was_acting {
                record.unknown_outcome = true;
            }
        }
        // The reserved charges of the interrupted plan stay charged: a
        // reservation that is backed by a dispatch state that is not
        // resolved is not released.
        // The pass in progress stays: a new lifetime gets no new pass
        // allowance.
        for incident in &mut state.policy.disk.incidents {
            incident.outstanding_operation = false;
            charge_reservation(&mut incident.usage);
            if let Some(pass) = &mut incident.current_pass {
                charge_reservation(pass);
            }
        }
        if let Some(incident) = &mut state.policy.memory.incident {
            incident.outstanding_operation = false;
            incident.consumed_slots = incident
                .consumed_slots
                .saturating_add(incident.reserved_slots);
            incident.reserved_slots = 0;
        }
        state
    }

    /// The record of the open disk incident of `domain`.
    pub fn disk_incident(&self, domain: &CapacityDomainKey) -> Option<&DiskIncidentRecord> {
        self.disk_incidents
            .iter()
            .find(|record| &record.domain == domain)
    }

    /// Replaces the budget record of an incident after an authorized rearm
    /// (`svalnir_core::grant::rearm`). The new generation starts in the
    /// lifetime `epoch` with no usage; each cooldown stays. Returns `false`
    /// when no open incident has the identity of `budget`, when a plan of
    /// that incident is in progress, or when the generation of `budget` is
    /// not newer than the recorded one. A plan in progress keeps its
    /// reservation, and one rearm gives one new generation: the same
    /// record applied again replenishes nothing.
    pub fn apply_rearm(&mut self, budget: IncidentBudget, epoch: &ExecutorEpochId) -> bool {
        if self
            .outstanding
            .as_ref()
            .is_some_and(|plan| plan.incident_id == budget.incident_id)
        {
            return false;
        }
        let recorded: Option<&IncidentBudget> = self
            .disk_incidents
            .iter()
            .map(|record| &record.budget)
            .chain(self.memory_incident.iter().map(|record| &record.budget))
            .find(|recorded| recorded.incident_id == budget.incident_id);
        if recorded.is_some_and(|recorded| budget.generation <= recorded.generation) {
            return false;
        }
        if let Some(index) = self
            .disk_incidents
            .iter()
            .position(|record| record.incident_id == budget.incident_id)
        {
            let domain: CapacityDomainKey = {
                let Some(record) = self.disk_incidents.get_mut(index) else {
                    return false;
                };
                record.budget = budget;
                record.opened_in = epoch.clone();
                record.established = true;
                record.unknown_outcome = false;
                record.rule_usage.clear();
                record.domain.clone()
            };
            if let Some(incident) = self
                .policy
                .disk
                .incidents
                .iter_mut()
                .find(|incident| incident.domain == domain)
            {
                incident.usage = svalnir_core::policy::WorkUsage::default();
                incident.current_pass = None;
                incident.passes_started = 0;
            }
            return true;
        }
        match &mut self.memory_incident {
            Some(record) if record.incident_id == budget.incident_id => {
                record.budget = budget;
                record.opened_in = epoch.clone();
                record.established = true;
                record.unknown_outcome = false;
                if let Some(incident) = &mut self.policy.memory.incident {
                    incident.consumed_slots = 0;
                    incident.reserved_slots = 0;
                }
                true
            }
            _ => false,
        }
    }
}

/// Makes each reserved charge of a usage a consumed charge.
fn charge_reservation(usage: &mut svalnir_core::policy::WorkUsage) {
    use svalnir_core::quantity::{Bytes, EntryCount};
    usage.consumed_bytes = Bytes::new(
        usage
            .consumed_bytes
            .get()
            .saturating_add(usage.reserved_bytes.get()),
    );
    usage.reserved_bytes = Bytes::ZERO;
    usage.consumed_items = EntryCount::new(
        usage
            .consumed_items
            .get()
            .saturating_add(usage.reserved_items.get()),
    );
    usage.reserved_items = EntryCount::ZERO;
}

/// One cleanup candidate that the runtime prepared for the controller: the
/// candidate of the rule with its admission facts, and the binding data of
/// its target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedCandidate {
    /// The candidate of the rule, with the ten eligibility facts.
    pub candidate: RuleCandidate,
    /// The approved root of the target.
    pub root_id: RootId,
    /// The path of the approved root.
    pub root_path: LosslessPath,
    /// The native identifiers of the root directory. The plan binds them
    /// with the root path.
    pub root_object: FileObjectEvidence,
    /// The entry below the root.
    pub relative_entry: LosslessPath,
    /// The mount generation of the volume.
    pub mount_id: MountId,
    /// The type of the object.
    pub object_type: svalnir_core::action::FileObjectType,
    /// The owner of the object, when it is known.
    pub owner: Option<Uid>,
    /// The object of the entry at the time of the evidence.
    pub object: Option<FileObjectEvidence>,
    /// The number of names of the object (`st_nlink`), when it is known.
    /// A rule that skips hard-linked objects needs it for an entry that is
    /// not a directory.
    pub link_count: Option<svalnir_core::quantity::EntryCount>,
    /// The work charge. `None` when it is not known.
    pub charge: Option<WorkCharge>,
    /// The size estimates.
    pub estimate: SizeEstimate,
}

/// The candidates that the runtime prepared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateSet {
    /// The time of the examination of the candidates.
    pub prepared_at: MonotonicNanos,
    /// True when the examination was complete. A set that is not complete
    /// supports no automatic plan.
    pub complete: bool,
    /// The candidates.
    pub candidates: Vec<PreparedCandidate>,
}

/// How the runtime prepares candidates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreparationMode {
    /// Examine the known candidates again. No directory is listed and no
    /// tree is measured. This is the only mode of a resource emergency.
    KnownOnly,
    /// A bounded discovery, as optional work outside an emergency.
    Refresh,
}

/// The fresh observations of one step.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Observations {
    /// The capacity of each selected volume. Empty when no volume was
    /// resolved: each selector is then not resolved, which is not normal.
    pub volumes: Vec<VolumeEvidence>,
    /// The memory snapshot. The default value has no pressure
    /// observation, which is not normal.
    pub memory: MemorySnapshot,
    /// The prepared cleanup candidates, when the runtime has a set.
    pub candidates: Option<CandidateSet>,
}

/// The result of an automatic operation, as the runtime read it from the
/// coordinator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationResult {
    /// The settled state of the operation, in the spelling of the
    /// journal (`Completed`, `Partial`, and so on), for a notification.
    pub state: String,
    /// True when the state is `Completed`: each target has its final
    /// condition.
    pub completed: bool,
    /// True when a call was possibly submitted for a step. Only `false`
    /// releases the charge.
    pub possibly_submitted: bool,
    /// True when the effect of a step is not known.
    pub unknown_outcome: bool,
    /// The observed change of the available capacity. `None` when the
    /// measurement before or after is not available.
    pub capacity_gain: Option<ByteDelta>,
    /// The memory pressure after the operation, when it was measured.
    pub pressure_after: Option<PressureState>,
    /// The end of the cooldown that the coordinator set for the incident.
    pub cooldown_until: Option<MonotonicNanos>,
}

/// What happened to an automatic plan of an earlier step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyReport {
    /// The coordinator admitted the plan.
    Admitted {
        /// The plan.
        plan_id: PlanId,
        /// The operation.
        operation_id: OperationId,
    },
    /// The coordinator refused the plan. Nothing was dispatched.
    Refused {
        /// The plan.
        plan_id: PlanId,
        /// The error code of the refusal.
        code: String,
    },
    /// The operation is finished.
    Finished {
        /// The plan.
        plan_id: PlanId,
        /// The result.
        result: OperationResult,
    },
}

/// The conditions of the agent that inhibit work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each condition is independent of the others"
)]
pub struct Health {
    /// True when the latest journal write failed.
    pub journal_unavailable: bool,
    /// True when the agent is over its own memory budget.
    pub self_over_budget: bool,
    /// True when the agent stops: no new automatic plan starts.
    pub stopping: bool,
    /// True while the restart backoff of the agent is in effect: the
    /// lifetimes before this one did not stop cleanly, and automatic work
    /// waits.
    pub restart_backoff: bool,
}

/// The inputs of one step.
#[derive(Clone, Copy)]
pub struct StepInput<'a> {
    /// The time of the step.
    pub time: &'a TimeReading,
    /// The executor lifetime of this agent.
    pub epoch: &'a ExecutorEpochId,
    /// The user of the agent.
    pub principal: Uid,
    /// The home directory of that user.
    pub home_directory: Option<&'a LosslessPath>,
    /// The configuration to evaluate: the one of the policy revision in
    /// effect, or a proposal when no revision is in effect.
    pub config: &'a ValidatedConfig,
    /// The authority record. `None` when the journal has none that this
    /// build can use: the controller then only observes.
    pub authority: Option<&'a AuthorityState>,
    /// The inhibitions of this instance.
    pub inhibition: &'a InstanceInhibition,
    /// The rule registry.
    pub registry: &'a dyn RuleRegistry,
    /// The fresh observations.
    pub observations: &'a Observations,
    /// What happened to the plans of earlier steps.
    pub reports: &'a [ApplyReport],
    /// The conditions of the agent.
    pub health: Health,
    /// The processes of the control plane, for the hard-protection
    /// catalog.
    pub control_plane: Option<&'a [ControlPlaneProcess]>,
}

impl std::fmt::Debug for StepInput<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StepInput")
            .field("time", &self.time)
            .field("epoch", &self.epoch)
            .field("health", &self.health)
            .finish_non_exhaustive()
    }
}

/// An automatic plan for the coordinator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutomaticApply {
    /// The guard of the plan.
    pub guard: Guard,
    /// The sealed plan.
    pub plan: Plan,
    /// The allowance of the incident, with the usage that the controller
    /// has.
    pub allowance: IncidentAllowance,
    /// The budget record of the incident, for the authorization.
    pub budget: IncidentBudget,
    /// The trigger that must hold at each dispatch boundary.
    pub trigger: TriggerKey,
}

/// The reason that the runtime reduces its optional work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReduceReason {
    /// The disk guard and the memory guard have pressure at the same
    /// time.
    SimultaneousPressure,
    /// A guard has an open incident.
    IncidentOpen,
    /// The agent is over its own budget.
    SelfBudget,
}

/// A change that a person can want to know.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Notification {
    /// A guard changed its phase.
    Phase {
        /// The guard.
        guard: Guard,
        /// The new phase.
        phase: GuardPhase,
    },
    /// Automatic work of a guard is inhibited for a new reason.
    Blocked {
        /// The guard.
        guard: Guard,
        /// The reason.
        reason: BlockedReason,
    },
    /// An automatic operation is finished.
    Finished {
        /// The guard.
        guard: Guard,
        /// The plan.
        plan_id: PlanId,
        /// The settled state of the operation.
        state: String,
        /// True when the measured benefit was low or not known.
        low_benefit: bool,
    },
}

/// What the runtime does after a step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Intent {
    /// Prepare the cleanup candidates of the volumes.
    PrepareCandidates {
        /// The volumes with a trigger.
        volumes: Vec<VolumeId>,
        /// How to prepare them.
        mode: PreparationMode,
    },
    /// Give this automatic plan to the coordinator.
    Apply(Box<AutomaticApply>),
    /// Tell the user.
    Notify(Notification),
    /// Reduce the optional work of the agent.
    ReduceOptionalWork(ReduceReason),
    /// Do nothing. A step with no other intent has this one.
    Idle,
}

/// The summary for presentation (`README.md`, "How protection works").
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Summary {
    /// Each trigger is normal.
    Normal,
    /// A trigger is advisory or qualifying, or a qualified trigger has no
    /// permitted action.
    Warning,
    /// An incident waits for stable recovery.
    Recovering,
    /// A guard acts or observes the outcome of an action.
    Acting,
    /// Required evidence or a required record is not usable.
    Degraded,
}

/// The phase of one guard (`docs/POLICY_SPEC.md` section 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardPhase {
    /// No trigger has pressure.
    Normal,
    /// A warning threshold or an advisory state.
    Warning,
    /// Evidence is accumulating.
    Qualifying,
    /// A trigger is qualified and each admission condition is present.
    Ready,
    /// A plan is in progress, or its outcome is observed.
    Acting,
    /// The incident is open while recovery stability is evaluated.
    Recovering,
    /// A cooldown inhibits further work.
    Cooldown,
    /// A ceiling admits no further automatic work.
    Exhausted,
    /// A trigger is qualified and a condition inhibits automatic work.
    Blocked,
    /// Required evidence is not usable.
    Degraded,
}

/// The reason that a guard with a qualified trigger does no automatic
/// work. Each value is specific, so that a status shows what must change.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum BlockedReason {
    /// The journal has no authority record that this build can use. The
    /// agent only observes.
    ObservationOnly,
    /// The agent stops.
    AgentStopping,
    /// The restart backoff of the agent is in effect.
    RestartBackoff,
    /// A pause is in effect.
    Paused,
    /// A pause ended, and no measurement is newer than its end.
    AwaitingFreshMeasurement,
    /// The guard is not active. `standing` is the standing of the grant
    /// module.
    GuardNotActive {
        /// The standing, in its JSON spelling.
        standing: String,
    },
    /// The journal is not available, and the action needs a durable
    /// record.
    JournalUnavailable,
    /// A restart could not establish the usage of the incident.
    IncidentStateNotEstablished,
    /// An operation of the incident ended with an effect that is not
    /// known.
    UnknownPriorOutcome,
    /// The state before the restart was not readable.
    HeldUntilRecovery,
    /// A plan of the other guard is in progress.
    OtherGuardActing,
    /// The outcome of the latest action is observed.
    ObservingOutcome,
    /// A cooldown or a backoff is in effect.
    Cooldown,
    /// A ceiling of the incident admits no further work.
    Exhausted,
    /// The runtime has no prepared candidate set, or the set is old.
    CandidatesNotPrepared,
    /// A rule of the candidates is not validated for automatic eviction:
    /// its layout is in the `proposed` lifecycle state, or in a different
    /// state that does not permit the mode.
    RuleNotValidated {
        /// The rule.
        rule: String,
    },
    /// The registry does not have the rule revision of a candidate.
    RuleNotRegistered {
        /// The rule.
        rule: String,
    },
    /// No candidate or application is eligible.
    NoEligibleTarget,
    /// The policy evaluation inhibits the action. `reasons` has each
    /// reason as `REASON:detail`.
    Policy {
        /// The reasons.
        reasons: Vec<String>,
    },
    /// The plan builder made no plan.
    PlanNotBuilt {
        /// The cause.
        detail: String,
    },
    /// The coordinator refused the latest plan.
    Refused {
        /// The error code.
        code: String,
    },
}

/// The usage of an incident, for the status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentStatus {
    /// The identity of the incident.
    pub incident_id: IncidentId,
    /// The budget generation.
    pub generation: u64,
    /// False when a restart could not establish the usage.
    pub established: bool,
    /// The consumed and reserved work bytes of a disk incident.
    pub work_bytes: Option<u64>,
    /// The passes that a disk incident started.
    pub passes_started: Option<u32>,
    /// The consumed and reserved application slots of a memory incident.
    pub slots_used: Option<u32>,
    /// The application slots that remain.
    pub slots_remaining: Option<u32>,
}

/// The status of one guard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardStatus {
    /// The guard.
    pub guard: Guard,
    /// The standing of the grant module, in its JSON spelling, or
    /// `observation_only`.
    pub standing: String,
    /// The phase.
    pub phase: GuardPhase,
    /// The incident state of each trigger, as `NAME:state`.
    pub triggers: Vec<String>,
    /// The reasons that inhibit automatic work.
    pub blocked: Vec<BlockedReason>,
    /// The open incidents.
    pub incidents: Vec<IncidentStatus>,
}

/// The compact status of the controller, for a client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControllerStatus {
    /// [`CONTROLLER_STATUS_VERSION`].
    pub schema_version: u32,
    /// The wall-clock time of the step.
    pub evaluated_at: WallTime,
    /// The summary for presentation.
    pub summary: Summary,
    /// Whether a pause is in effect.
    pub paused: bool,
    /// The wall-clock time at which a timed pause ends.
    pub paused_until: Option<WallTime>,
    /// True when the journal has no usable authority record.
    pub observation_only: bool,
    /// The status of each guard.
    pub guards: Vec<GuardStatus>,
    /// The plan in progress.
    pub outstanding_plan: Option<PlanId>,
    /// The operation in progress.
    pub outstanding_operation: Option<OperationId>,
    /// The conditions that make the summary `degraded`.
    pub degraded: Vec<String>,
    /// Whether the controller asked the runtime to reduce optional work.
    pub optional_work_reduced: bool,
}

/// The standing of one trigger, for the authority source of the
/// coordinator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TriggerRecord {
    /// The trigger.
    pub key: TriggerKey,
    /// Whether it holds, with the newest measurement that supports it.
    pub standing: TriggerStanding,
}

/// The result of one step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepOutput {
    /// The new state.
    pub state: ControllerState,
    /// What the runtime does. Never empty.
    pub intents: Vec<Intent>,
    /// The status.
    pub status: ControllerStatus,
    /// The standing of each trigger that this step evaluated.
    pub triggers: Vec<TriggerRecord>,
    /// The budget record of each open incident.
    pub incidents: Vec<IncidentBudget>,
}

/// The evidence stamp of a measurement at `at`, in the clock of `time`.
pub(super) fn stamp(time: &TimeReading, at: MonotonicNanos) -> EvidenceStamp {
    EvidenceStamp {
        acquired_at: at,
        clock_domain: time.clock.clock_domain.clone(),
        boot_id: time.clock.boot_id.clone(),
    }
}
