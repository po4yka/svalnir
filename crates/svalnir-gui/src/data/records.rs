//! The snapshots of the Memory, Applications, Automation, History, and
//! Diagnostics screens.
//!
//! The types hold no GPUI types and no type of the agent library, so that a
//! fixture can make each of them. A failed query is never a zero: it is
//! [`Measured::Unavailable`] with a reason, or a sentence in `problems`.

use super::model::{GuardState, Measured, OperationPhase};
use std::{path::PathBuf, time::SystemTime};

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
    Protected,
    /// The catalog does not protect the group.
    NotProtected,
    /// The lookup gave no result. Automation skips such a target.
    Unknown,
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

/// One guard with its standing, its grant, and its thresholds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardDetail {
    /// The policy name.
    pub name: &'static str,
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
    /// The thresholds of the guard in the revision in effect: the key of
    /// the configuration and the value in its base unit.
    pub thresholds: Vec<(String, u64)>,
}

/// The pause that the authority record has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PauseRow {
    /// No pause is recorded.
    NotPaused,
    /// A pause is recorded.
    Paused {
        /// When the pause started.
        since: SystemTime,
        /// The wall-clock time of the deadline. `None`: no deadline. The
        /// agent ends a pause on its monotonic clock, so this time is for
        /// display only.
        until: Option<SystemTime>,
    },
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
    /// A sentence for each read that failed.
    pub problems: Vec<String>,
}

impl Captured for AutomationSnapshot {
    fn captured_at(&self) -> SystemTime {
        self.captured_at
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
            protection: Protection::Unknown,
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
