//! The snapshots of the Memory, Applications, Automation, History, and
//! Diagnostics screens.
//!
//! The types hold no GPUI types and no type of the agent library, so that a
//! fixture can make each of them. A failed query is never a zero: it is
//! [`Measured::Unavailable`] with a reason, or a sentence in `problems`.

use super::model::{GuardState, Measured, OperationPhase};
use std::{
    path::PathBuf,
    time::{Duration, SystemTime},
};
use svalnir_core::{action::ActionClass, policy::PolicyId};

/// The most process rows that a snapshot keeps.
pub const PROCESS_ROWS_MAX: usize = 40;
/// The most application rows that a snapshot keeps.
pub const APPLICATION_ROWS_MAX: usize = 60;
/// The most operations that a history snapshot keeps.
pub const HISTORY_ROWS_MAX: usize = 50;

/// A snapshot that has the time of its reading.
pub trait Captured {
    /// When the snapshot was read.
    fn captured_at(&self) -> SystemTime;
}

/// The memory quantities of the host that the Overview does not show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemorySnapshot {
    /// When the reading was taken.
    pub captured_at: SystemTime,
    /// The wired memory, in bytes.
    pub wired: Measured<u64>,
    /// The physical memory that the compressor occupies, in bytes.
    pub compressor: Measured<u64>,
    /// The size of the data that the compressor holds, before compression.
    pub compressed_data: Measured<u64>,
    /// The free memory, in bytes.
    pub free: Measured<u64>,
    /// The label of the source.
    pub source: &'static str,
}

impl Captured for MemorySnapshot {
    fn captured_at(&self) -> SystemTime {
        self.captured_at
    }
}

/// One process of the current user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessRow {
    /// The process ID at the time of the reading.
    pub pid: i32,
    /// The last component of the executable path, for display only.
    pub name: Option<String>,
    /// The bundle identifier or the job label of a verified membership.
    pub group: Option<String>,
    /// The physical footprint, in bytes.
    pub footprint: Measured<u64>,
    /// The resident size, in bytes. It is a different quantity.
    pub resident: Measured<u64>,
    /// The footprint change since the previous reading of this window.
    /// `Unavailable` on the first reading and for a new process.
    pub growth: Measured<Growth>,
}

/// The kind of an application group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupKind {
    /// A running application.
    Application,
    /// A managed job, for example a launchd job.
    ManagedJob,
}

impl GroupKind {
    /// The label of the kind.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Application => "Application",
            Self::ManagedJob => "Managed job",
        }
    }
}

/// Whether a group is the frontmost application.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Foreground {
    /// A member belongs to the active application.
    Foreground,
    /// Each member belongs to an application that is not active.
    Background,
    /// No foreground evidence applies. This state is not `Background`.
    Unknown,
}

/// The product protection of a group, from the catalog of hard protections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protection {
    /// The catalog protects the group.
    Protected {
        /// The catalog entry that matched the first protected member.
        reason: ProtectionReason,
    },
    /// The catalog does not protect the group.
    NotProtected,
    /// The lookup gave no result. Automation skips such a target.
    Unknown {
        /// Why the catalog cannot classify the first member with no class.
        cause: UnknownCause,
    },
}

/// The entry of the catalog of hard protections that protects a group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectionReason {
    /// A member is a process of a different user.
    DifferentOwner,
    /// A member runs as root.
    RootOwner,
    /// A member is `launchd`.
    Launchd,
    /// The group is an application of the login session.
    SessionApplication,
    /// The group is Svalnir or one of its components.
    ControlPlaneBundle,
    /// A member is this window or one of its parent processes.
    ControlPlaneProcess,
    /// The executable of a member is in a system location.
    SystemLocation,
    /// The executable of a member has the name of a Svalnir executable.
    ControlPlaneExecutable,
}

impl ProtectionReason {
    /// The sentence of the reason.
    #[must_use]
    pub const fn text(self) -> &'static str {
        match self {
            Self::DifferentOwner => "A member is a process of a different user",
            Self::RootOwner => "A member runs as root",
            Self::Launchd => "A member is launchd",
            Self::SessionApplication => "An application of the login session",
            Self::ControlPlaneBundle => "Svalnir or one of its components",
            Self::ControlPlaneProcess => "This window or one of its parent processes",
            Self::SystemLocation => "The executable is in a system location",
            Self::ControlPlaneExecutable => "The executable has the name of a Svalnir executable",
        }
    }
}

/// Why the catalog of hard protections cannot classify a group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnknownCause {
    /// The group has no member.
    NoMember,
    /// A member has no executable evidence.
    NoExecutableEvidence,
    /// The executable path of a member cannot be classified.
    PathNotClassified,
    /// The processes of this window were not found in the reading.
    ControlPlaneNotKnown,
}

impl UnknownCause {
    /// The sentence of the cause.
    #[must_use]
    pub const fn text(self) -> &'static str {
        match self {
            Self::NoMember => "The group has no member",
            Self::NoExecutableEvidence => "A member has no executable evidence",
            Self::PathNotClassified => "The executable path of a member cannot be classified",
            Self::ControlPlaneNotKnown => "The processes of this window were not found",
        }
    }
}

/// The footprint change of one process or group between the two latest
/// readings of this window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Growth {
    /// The change in bytes. A negative value is a decrease.
    pub delta: i128,
    /// The time between the two samples.
    pub elapsed: Duration,
}

/// One application or job instance with its verified members.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationRow {
    /// The opaque identity of the instance. Use it as the row key.
    pub instance: String,
    /// The bundle identifier or the job label.
    pub name: String,
    /// The kind of the group.
    pub kind: GroupKind,
    /// The number of verified member processes.
    pub members: usize,
    /// The sum of the measured footprints of the members.
    pub footprint: Measured<u64>,
    /// The number of members with no footprint value. The sum does not
    /// include them.
    pub unmeasured_members: usize,
    /// The foreground state.
    pub foreground: Foreground,
    /// The hard protection.
    pub protection: Protection,
    /// The sum of the footprint changes of the members since the previous
    /// reading. `Unavailable` when no member has a change value.
    pub growth: Measured<Growth>,
    /// The number of members with no change value. The sum does not
    /// include them.
    pub growth_missing: usize,
}

/// The processes of the current user and their application groups.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessesSnapshot {
    /// When the reading was taken.
    pub captured_at: SystemTime,
    /// The processes with the largest footprint, largest first, at most
    /// [`PROCESS_ROWS_MAX`]. A process with no footprint value comes last.
    pub processes: Vec<ProcessRow>,
    /// The number of processes that the collection recorded.
    pub process_count: usize,
    /// The groups, largest footprint first, at most [`APPLICATION_ROWS_MAX`].
    pub applications: Vec<ApplicationRow>,
    /// The number of groups that the collection found.
    pub application_count: usize,
    /// The number of processes with no verified membership.
    pub unattributed: usize,
    /// The processes of a different user, which the collection does not record.
    pub other_user: usize,
    /// The processes that the collection could not read.
    pub not_readable: usize,
    /// A sentence for each limit of the attribution.
    pub notes: Vec<String>,
    /// The label of the source.
    pub source: &'static str,
}

impl Captured for ProcessesSnapshot {
    fn captured_at(&self) -> SystemTime {
        self.captured_at
    }
}

/// The policy revision in effect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevisionRow {
    /// The identity of the revision.
    pub id: String,
    /// When the revision was activated.
    pub activated_at: SystemTime,
    /// The profile of the revision.
    pub profile: String,
}

/// The action grant of one guard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantRow {
    /// The identity of the grant.
    pub id: String,
    /// The names of the action classes that the grant authorizes.
    pub action_classes: Vec<String>,
    /// The rules that the grant covers, as "id@revision" text.
    pub rules: Vec<String>,
    /// When the grant was made.
    pub granted_at: SystemTime,
    /// When the grant expires. `None`: the grant has no expiry.
    pub expires_at: Option<SystemTime>,
    /// Whether the grant was revoked.
    pub revoked: bool,
    /// Whether the grant was in effect at the time of the reading.
    pub in_effect: bool,
}

/// One open incident of a guard, from the status record of the agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncidentRow {
    /// The incident identity.
    pub id: String,
    /// The budget generation of the incident.
    pub generation: u64,
}

/// One guard with its standing, its grant, and its thresholds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardDetail {
    /// The guard.
    pub policy: PolicyId,
    /// The policy name.
    pub name: &'static str,
    /// The action classes that the revision in effect gives the guard. An
    /// enable accepts exactly these classes.
    pub scope_classes: Vec<ActionClass>,
    /// The open incidents that the last status record of the agent has.
    /// Empty when the record has none or was not read.
    pub incidents: Vec<IncidentRow>,
    /// Whether the guard can act.
    pub standing: GuardState,
    /// One sentence that says why.
    pub detail: &'static str,
    /// Whether the user enabled the guard.
    pub enabled: bool,
    /// Whether the revision in effect requests the guard. `None` when no
    /// revision is in effect.
    pub requested: Option<bool>,
    /// The action grant, when the guard has one.
    pub grant: Option<GrantRow>,
    /// The thresholds of the guard in the revision in effect.
    pub thresholds: Vec<ThresholdRow>,
}

/// A threshold value with the unit of its configuration field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThresholdQuantity {
    /// A size, in bytes.
    Bytes(u64),
    /// A time, in nanoseconds.
    Nanoseconds(u64),
    /// A count.
    Count(u64),
    /// This build does not know the unit of the key. The number has no
    /// known meaning.
    NoUnit(u64),
}

/// One threshold of a guard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThresholdRow {
    /// The key path of the configuration.
    pub key: String,
    /// The value with its unit.
    pub value: ThresholdQuantity,
}

impl ThresholdRow {
    /// The row of `key` with the stored number `value`, with the unit that
    /// the configuration field of `key` has.
    #[must_use]
    pub fn of(key: &str, value: u64) -> Self {
        use svalnir_core::grant::{ThresholdUnit, threshold_unit};
        Self {
            key: key.to_owned(),
            value: match threshold_unit(key) {
                Some(ThresholdUnit::Bytes) => ThresholdQuantity::Bytes(value),
                Some(ThresholdUnit::Nanoseconds) => ThresholdQuantity::Nanoseconds(value),
                Some(ThresholdUnit::Count) => ThresholdQuantity::Count(value),
                None => ThresholdQuantity::NoUnit(value),
            },
        }
    }
}

/// What decides the end of a pause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PauseKind {
    /// The pause has no end time.
    Indefinite,
    /// The monotonic clock of the boot of the pause decides the end.
    Timed,
    /// The pause is of an earlier boot, so its end cannot be established.
    /// It stays until a resume.
    Retained,
}

/// The pause of the authority record, as the agent decides it at the time
/// of the reading.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PauseRow {
    /// No pause is recorded.
    NotPaused,
    /// The pause inhibits automatic intervention.
    Paused {
        /// When the pause started.
        since: SystemTime,
        /// The time that remained at the reading. `None` with no end time
        /// or for a retained pause.
        remaining: Option<Duration>,
        /// The wall-clock end, for display. `None` with no end time or for
        /// a retained pause.
        until: Option<SystemTime>,
        /// What decides the end.
        kind: PauseKind,
    },
    /// The pause reached its end on the monotonic clock. It inhibits
    /// nothing; the record stays until the agent or a resume removes it.
    Expired {
        /// When the pause started.
        since: SystemTime,
    },
}

/// Whether automatic work waits for a measurement that is newer than the
/// end of a pause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreshMeasurement {
    /// No pause ended, and the latest step of the agent did not wait.
    NotNeeded,
    /// The latest step of the agent, in a current status, waited for it.
    Awaiting,
    /// A pause ended, and the journal does not record whether the agent
    /// has a newer measurement.
    NotKnown,
}

/// What the journal says about automation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutomationSnapshot {
    /// When the snapshot was read.
    pub captured_at: SystemTime,
    /// Whether the journal file exists.
    pub journal_present: bool,
    /// The revision in effect.
    pub revision: Option<RevisionRow>,
    /// The guards, in the sequence of the specification.
    pub guards: Vec<GuardDetail>,
    /// The recorded pause. `None` when the authority record was not read.
    pub pause: Option<PauseRow>,
    /// Whether automatic work waits for a fresh measurement after a pause.
    pub measurement: FreshMeasurement,
    /// A sentence for each read that failed.
    pub problems: Vec<String>,
}

impl Captured for AutomationSnapshot {
    fn captured_at(&self) -> SystemTime {
        self.captured_at
    }
}

/// How old the status record of the agent is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusAge {
    /// The agent wrote its status at most 90 s before the reading.
    Current,
    /// The status is older: the agent does not run, or it does not write.
    /// The controller rows are the state at the time of that status.
    Stale {
        /// The age of the status.
        age: Duration,
    },
    /// The status says that the agent stopped. The controller rows are the
    /// state that its next start restores.
    Stopped,
    /// The journal has no usable status record, or its time is later than
    /// the clock of this window.
    Unknown,
}

/// The incident state of the trigger of an application budget at the latest
/// step of the agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TriggerRow {
    /// No pressure.
    Normal,
    /// The footprint is over the soft limit.
    Advisory,
    /// The footprint is over the stop limit, and evidence accumulates.
    Qualifying,
    /// The trigger qualified.
    Ready,
    /// An intervention runs.
    Acting,
    /// The footprint is below the recovery limit, and evidence accumulates.
    Recovering,
    /// The episode is latched, and its predicate is not true now.
    Held,
    /// The trigger qualified, and a cooldown inhibits further work.
    Cooldown,
    /// The trigger qualified, and a ceiling admits no further work.
    Exhausted,
    /// Required evidence is not usable. This state is not `Normal`.
    Blocked,
    /// A state that this build does not know.
    Other,
}

impl TriggerRow {
    /// The label of the state.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Normal => "Normal",
            Self::Advisory => "Advisory",
            Self::Qualifying => "Qualifying",
            Self::Ready => "Ready",
            Self::Acting => "Acting",
            Self::Recovering => "Recovering",
            Self::Held => "Held",
            Self::Cooldown => "Cooldown",
            Self::Exhausted => "Exhausted",
            Self::Blocked => "Blocked",
            Self::Other => "Not known",
        }
    }
}

/// One application budget of the memory guard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetRow {
    /// The identifier of the budget in the configuration.
    pub id: String,
    /// True when the budget had a trigger episode that did not recover.
    pub latched: bool,
    /// The trigger state at the latest step of the agent. `None` when the
    /// status record has no entry for the budget.
    pub trigger: Option<TriggerRow>,
}

/// What a cooldown inhibits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CooldownSubject {
    /// A new stop of one application or job after an intervention.
    Relaunch {
        /// The bundle identifier or the job label.
        application: String,
    },
    /// The next pass of a disk incident.
    DiskPass {
        /// The incident, when the record has one.
        incident: Option<String>,
    },
    /// The next action of an incident: the observation after an action.
    ObserveAfterAction {
        /// The incident.
        incident: String,
    },
    /// The next target of the memory incident after an action with a low
    /// benefit or a failure.
    MemoryBackoff {
        /// The incident.
        incident: String,
    },
}

/// The status of a cooldown at the time of the reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CooldownState {
    /// The cooldown is in effect.
    Active {
        /// The time that remained at the reading.
        remaining: Duration,
    },
    /// The cooldown ended.
    Elapsed,
    /// The cooldown is of a different boot or clock domain, so its end
    /// cannot be established. The agent treats it as active.
    EarlierBoot,
}

/// One cooldown of the controller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CooldownRow {
    /// What the cooldown inhibits.
    pub subject: CooldownSubject,
    /// The cause, as a label.
    pub cause: &'static str,
    /// The status.
    pub state: CooldownState,
}

/// The usage of a budget generation in the controller record, with the
/// reserved charges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsageRow {
    /// The usage of a disk incident.
    Disk {
        /// The consumed bytes.
        consumed_bytes: u64,
        /// The reserved bytes.
        reserved_bytes: u64,
        /// The consumed items.
        consumed_items: u64,
        /// The reserved items.
        reserved_items: u64,
        /// The passes that the incident started.
        passes: u32,
    },
    /// The usage of a memory incident.
    Memory {
        /// The consumed application slots.
        consumed_slots: u32,
        /// The reserved application slots.
        reserved_slots: u32,
    },
}

/// The consumed usage that the journal records for a budget generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalUsageRow {
    /// The usage row of the generation.
    Recorded {
        /// The operations with a consumed application step.
        slots: u32,
        /// The charged bytes of the consumed filesystem steps.
        work_bytes: u64,
        /// The charged items of the consumed filesystem steps.
        items: u64,
    },
    /// The journal has no usage row: no dispatch of the generation was
    /// consumed.
    NoConsumedDispatch,
    /// The row cannot be read.
    Unreadable(String),
}

/// One budget generation of an incident.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerationRow {
    /// The generation.
    pub generation: u64,
    /// True when a person rearmed the incident to start the generation.
    pub rearmed: bool,
    /// When the generation started.
    pub started_at: SystemTime,
    /// The usage at the rearm that ended the generation. `None` for the
    /// current generation.
    pub final_usage: Option<UsageRow>,
    /// The consumed usage of the journal.
    pub journal: JournalUsageRow,
}

/// One open incident of the controller with its budget generations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncidentUsage {
    /// The incident identity.
    pub id: String,
    /// The guard of the incident.
    pub policy: PolicyId,
    /// The current budget generation.
    pub generation: u64,
    /// False when a restart could not establish the usage: the incident
    /// permits no automatic work until it closes or a person rearms it.
    pub established: bool,
    /// True when an operation of the incident has an effect that is not
    /// known.
    pub unknown_outcome: bool,
    /// The usage of the current generation. `None` when the policy state
    /// has no entry for the incident.
    pub current: Option<UsageRow>,
    /// Each budget generation, oldest first.
    pub generations: Vec<GenerationRow>,
}

/// The rows of the controller record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControllerRows {
    /// When the agent wrote the record. It writes the record only when the
    /// state changes, so an old time is not evidence of a stopped agent.
    pub written_at: Option<SystemTime>,
    /// The application budgets.
    pub budgets: Vec<BudgetRow>,
    /// The cooldowns.
    pub cooldowns: Vec<CooldownRow>,
    /// The open incidents.
    pub incidents: Vec<IncidentUsage>,
    /// True when the record had more rows than the reading keeps.
    pub truncated: bool,
}

/// The controller state that the agent records in the journal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControllerSnapshot {
    /// When the snapshot was read.
    pub captured_at: SystemTime,
    /// The age of the status record of the agent.
    pub status_age: StatusAge,
    /// The rows. `Unavailable` has the reason that there are none.
    pub rows: Measured<ControllerRows>,
}

impl Captured for ControllerSnapshot {
    fn captured_at(&self) -> SystemTime {
        self.captured_at
    }
}

impl ControllerSnapshot {
    /// The cooldown of the relaunch of the application `name`, when the
    /// record has one.
    #[must_use]
    pub fn relaunch_cooldown(&self, name: &str) -> Option<&CooldownRow> {
        self.rows.value()?.cooldowns.iter().find(|row| {
            matches!(&row.subject, CooldownSubject::Relaunch { application } if application == name)
        })
    }

    /// The incident `id`, when the record has it.
    #[must_use]
    pub fn incident(&self, id: &str) -> Option<&IncidentUsage> {
        self.rows
            .value()?
            .incidents
            .iter()
            .find(|incident| incident.id == id)
    }
}

/// The observed change of a resource that the journal has for an operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EffectRow {
    /// The available capacity of a volume before and after, in bytes.
    Capacity {
        /// The value before the operation.
        before: Measured<u64>,
        /// The value after the operation.
        after: Measured<u64>,
    },
    /// The memory pressure before and after, as state names.
    Pressure {
        /// The state before the operation.
        before: Measured<String>,
        /// The state after the operation.
        after: Measured<String>,
    },
    /// An observation of a kind that this build does not know.
    Unrecognized,
}

/// One step of an operation, for the detail view of History.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepDetail {
    /// The step identity.
    pub step_id: String,
    /// The action class of the step.
    pub action_class: String,
    /// The target of the step.
    pub target_id: String,
    /// The state name of the step.
    pub state: String,
    /// Whether the external call of the step was submitted, as its name.
    pub dispatch: String,
}

/// One target result of an operation, for the detail view of History.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetDetail {
    /// The target.
    pub target_id: String,
    /// The member of an application target that the result is for. `None`:
    /// the result is for the target as a whole.
    pub member: Option<String>,
    /// The observed effect, as its name.
    pub effect: String,
    /// Whether the call for the target was submitted, as its name.
    pub dispatch: String,
    /// Why work on the target stopped, as its name.
    pub stop_reason: String,
    /// Whether the action caused the observed condition, as its name.
    pub attribution: String,
    /// The error of a target that was skipped, refused, or failed: the code
    /// and the stage, for example `target_protected at admission`.
    pub error: Option<String>,
}

/// One operation of the journal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationDetail {
    /// The operation identity.
    pub operation_id: String,
    /// The phase.
    pub phase: OperationPhase,
    /// The state name of the journal.
    pub state_text: String,
    /// When the operation was admitted.
    pub admitted_at: SystemTime,
    /// The trigger class.
    pub trigger: String,
    /// Whether a guard started the operation.
    pub automatic: bool,
    /// The names of the action classes of the steps, each one time.
    pub action_classes: Vec<String>,
    /// The state name of each step, in the order of the plan.
    pub steps: Vec<String>,
    /// The number of target results for each effect name, in the order of
    /// the first occurrence.
    pub effects: Vec<(String, usize)>,
    /// The resource observations. Empty: the journal has no measurement,
    /// which is not a measurement of no change.
    pub resources: Vec<EffectRow>,
    /// The plan that the operation applies.
    pub plan_id: String,
    /// Each step, in the order of the plan.
    pub step_details: Vec<StepDetail>,
    /// Each target result, in execution sequence.
    pub targets: Vec<TargetDetail>,
}

impl OperationDetail {
    /// The error of each target result that has one, each one time, in the
    /// order of the first occurrence.
    #[must_use]
    pub fn errors(&self) -> Vec<&str> {
        let mut errors: Vec<&str> = Vec::new();
        for error in self
            .targets
            .iter()
            .filter_map(|target| target.error.as_deref())
        {
            if !errors.contains(&error) {
                errors.push(error);
            }
        }
        errors
    }
}

/// The latest operations of the journal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistorySnapshot {
    /// When the snapshot was read.
    pub captured_at: SystemTime,
    /// Whether the journal file exists.
    pub journal_present: bool,
    /// The operations, newest first, at most [`HISTORY_ROWS_MAX`].
    pub operations: Vec<OperationDetail>,
    /// A sentence for each read that failed.
    pub problems: Vec<String>,
}

impl Captured for HistorySnapshot {
    fn captured_at(&self) -> SystemTime {
        self.captured_at
    }
}

/// The state of a capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityLevel {
    /// The probe found the capability.
    Available,
    /// The system denies the capability.
    Denied,
    /// The host or this build does not support the capability.
    Unsupported,
    /// The probe gave no result.
    Unknown,
}

/// How much the product needs a capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Need {
    /// The product does not work without it.
    Required,
    /// A function is not available without it.
    Optional,
    /// The entry informs only.
    Informational,
}

impl Need {
    /// The label of the need.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Required => "Required",
            Self::Optional => "Optional",
            Self::Informational => "Informational",
        }
    }
}

/// One capability of the process that ran the probes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityRow {
    /// The stable identifier, for example `privacy.full_disk_access`.
    pub id: String,
    /// The title.
    pub title: String,
    /// How much the product needs the capability.
    pub need: Need,
    /// The state.
    pub level: CapabilityLevel,
    /// What the probe found.
    pub detail: String,
    /// What the capability enables.
    pub enables: String,
    /// The step that makes the capability available, when one exists.
    pub remediation: Option<String>,
}

/// The verdict of a capability report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Each required capability is available.
    Ready,
    /// A required capability has no result.
    Unverified,
    /// A required capability is denied or not supported.
    Blocked,
}

/// The status record that the agent writes to the journal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentStatusRow {
    /// The process ID of the agent that wrote the record.
    pub process_id: u32,
    /// When that agent started.
    pub started_at: SystemTime,
    /// When the record was written. An old record is not evidence that an
    /// agent runs.
    pub written_at: SystemTime,
    /// The run state, as text.
    pub run_state: &'static str,
    /// The revision that the agent evaluates. `None`: the agent only observes.
    pub revision: Option<String>,
    /// The reason that the authority record is not usable for the agent.
    pub policy_problem: Option<String>,
    /// The verdict of the capability check of the agent.
    pub capability_verdict: Option<String>,
    /// The required capabilities that the agent does not have.
    pub required_not_available: Vec<String>,
    /// The notification capability of the agent, as the one sentence that
    /// the agent wrote at the time of the record. `None`: the record has
    /// no notification capability.
    pub notifications: Option<String>,
    /// The footprint of the agent process, in bytes.
    pub footprint: Measured<u64>,
    /// The footprint budget of the agent, in bytes.
    pub budget: u64,
    /// The conditions that reduce the function of the agent.
    pub degraded: Vec<String>,
    /// The number of stops in sequence that were not clean.
    pub unclean_stops: u32,
    /// Whether the restart backoff inhibits automatic work.
    pub restart_backoff: bool,
}

/// The record of a start of the agent that failed permanently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartFailureRow {
    /// The code of the reason.
    pub code: String,
    /// The message of the reason.
    pub message: String,
    /// When the start failed, when the agent knew the time.
    pub failed_at: Option<SystemTime>,
    /// The version of the agent that failed.
    pub agent_version: String,
}

/// What the client knows about the journal file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalRow {
    /// The path of the file. `None`: the state directory is not known.
    pub path: Option<PathBuf>,
    /// Whether the file exists.
    pub present: bool,
    /// The size of the database, in bytes.
    pub size: Measured<u64>,
    /// The size limit of the database, in bytes.
    pub limit: Measured<u64>,
}

/// The capabilities of this process and the records of the service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticsSnapshot {
    /// When the snapshot was read.
    pub captured_at: SystemTime,
    /// The component that ran the probes, as text.
    pub subject: String,
    /// The verdict of the report.
    pub verdict: Verdict,
    /// The capabilities, in the order of the report.
    pub capabilities: Vec<CapabilityRow>,
    /// The status record of the agent. `Unavailable` has the reason that
    /// there is none.
    pub agent: Measured<AgentStatusRow>,
    /// The start-failure record, when the state directory has one.
    pub start_failure: Option<StartFailureRow>,
    /// The journal file.
    pub journal: JournalRow,
    /// The version of this client.
    pub client_version: &'static str,
    /// A sentence for each read that failed.
    pub problems: Vec<String>,
}

impl Captured for DiagnosticsSnapshot {
    fn captured_at(&self) -> SystemTime {
        self.captured_at
    }
}

/// The measured value, or `None`: a row with no value sorts after each row
/// with a value.
fn sort_key(footprint: &Measured<u64>) -> (bool, u64) {
    match footprint {
        Measured::Value(bytes) => (true, *bytes),
        Measured::Unavailable(_) => (false, 0),
    }
}

/// Orders the processes by footprint, largest first, and keeps at most
/// [`PROCESS_ROWS_MAX`]. A process with no footprint value comes after each
/// process with a value; it is not a process of zero bytes. Equal rows stay
/// in PID order.
#[must_use]
pub fn rank_processes(mut rows: Vec<ProcessRow>) -> Vec<ProcessRow> {
    rows.sort_by(|a, b| {
        sort_key(&b.footprint)
            .cmp(&sort_key(&a.footprint))
            .then(a.pid.cmp(&b.pid))
    });
    rows.truncate(PROCESS_ROWS_MAX);
    rows
}

/// Orders the groups by footprint, largest first, and keeps at most
/// [`APPLICATION_ROWS_MAX`]. Equal rows are in the order of the name.
#[must_use]
pub fn rank_applications(mut rows: Vec<ApplicationRow>) -> Vec<ApplicationRow> {
    rows.sort_by(|a, b| {
        sort_key(&b.footprint)
            .cmp(&sort_key(&a.footprint))
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| a.instance.cmp(&b.instance))
    });
    rows.truncate(APPLICATION_ROWS_MAX);
    rows
}

/// The phase of an operation with its steps. The journal keeps an operation
/// in `Admitted` until it has a result, so an admitted operation with a step
/// that left `Admitted` is in progress.
#[must_use]
pub fn refine_phase(phase: OperationPhase, steps: &[String]) -> OperationPhase {
    if phase == OperationPhase::Pending && steps.iter().any(|step| step != "Admitted") {
        OperationPhase::Running
    } else {
        phase
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process(pid: i32, footprint: Measured<u64>) -> ProcessRow {
        ProcessRow {
            pid,
            name: None,
            group: None,
            footprint,
            resident: Measured::Unavailable("x".into()),
            growth: Measured::Unavailable("x".into()),
        }
    }

    #[test]
    fn a_process_with_no_footprint_is_last_and_not_zero() {
        let rows = rank_processes(vec![
            process(1, Measured::Unavailable("denied".into())),
            process(2, Measured::Value(0)),
            process(3, Measured::Value(9)),
        ]);
        let pids: Vec<i32> = rows.iter().map(|row| row.pid).collect();
        assert_eq!(pids, [3, 2, 1]);
    }

    #[test]
    fn the_process_rows_have_a_bound() {
        let rows: Vec<ProcessRow> = (0..200)
            .map(|pid| process(pid, Measured::Value(u64::try_from(pid).unwrap_or(0))))
            .collect();
        let ranked = rank_processes(rows);
        assert_eq!(ranked.len(), PROCESS_ROWS_MAX);
        assert_eq!(ranked[0].pid, 199);
    }

    #[test]
    fn groups_are_in_footprint_order_then_name_order() {
        let group = |name: &str, footprint: Measured<u64>| ApplicationRow {
            instance: format!("i-{name}"),
            name: name.to_owned(),
            kind: GroupKind::Application,
            members: 1,
            footprint,
            unmeasured_members: 0,
            foreground: Foreground::Unknown,
            protection: Protection::Unknown {
                cause: UnknownCause::NoMember,
            },
            growth: Measured::Unavailable("x".into()),
            growth_missing: 1,
        };
        let rows = rank_applications(vec![
            group("b", Measured::Value(5)),
            group("z", Measured::Unavailable("x".into())),
            group("a", Measured::Value(5)),
            group("c", Measured::Value(7)),
        ]);
        let names: Vec<&str> = rows.iter().map(|row| row.name.as_str()).collect();
        assert_eq!(names, ["c", "a", "b", "z"]);
    }

    #[test]
    fn an_admitted_operation_with_a_started_step_is_running() {
        let steps = |names: &[&str]| -> Vec<String> {
            names.iter().map(|name| (*name).to_owned()).collect()
        };
        assert_eq!(
            refine_phase(OperationPhase::Pending, &steps(&["Admitted", "Admitted"])),
            OperationPhase::Pending
        );
        assert_eq!(
            refine_phase(OperationPhase::Pending, &steps(&["Completed", "Verifying"])),
            OperationPhase::Running
        );
        assert_eq!(
            refine_phase(OperationPhase::Failed, &steps(&["Verifying"])),
            OperationPhase::Failed
        );
        assert_eq!(
            refine_phase(OperationPhase::Pending, &[]),
            OperationPhase::Pending
        );
    }
}
