//! Immutable, presentation-neutral snapshots that the views read.
//!
//! The types hold no GPUI types. A failed query is never a zero: it is
//! [`Measured::Unavailable`] with a reason.

use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

use svalnir_core::{action::OperationState, grant::GuardStanding};

/// One measured value, or the reason that there is none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Measured<T> {
    /// The measurement succeeded. A zero is a measured zero.
    Value(T),
    /// The measurement has no value; the text is the reason.
    Unavailable(String),
}

impl<T> Measured<T> {
    /// The value, when there is one.
    #[must_use]
    pub fn value(&self) -> Option<&T> {
        match self {
            Self::Value(value) => Some(value),
            Self::Unavailable(_) => None,
        }
    }
}

/// The memory pressure level of the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PressureLevel {
    /// No memory pressure.
    Normal,
    /// The system reports a warning.
    Warning,
    /// The system reports critical pressure.
    Critical,
}

impl PressureLevel {
    /// The label of the level.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Normal => "Normal",
            Self::Warning => "Warning",
            Self::Critical => "Critical",
        }
    }
}

/// One reading of the host. Sizes are bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostSnapshot {
    /// When the reading was taken.
    pub captured_at: SystemTime,
    /// The mount point of the startup data volume, when it is known.
    pub volume_name: Option<String>,
    /// The capacity of the volume.
    pub disk_total: Measured<u64>,
    /// The available capacity, the baseline policy input.
    pub disk_available: Measured<u64>,
    /// The free capacity.
    pub disk_free: Measured<u64>,
    /// The memory pressure.
    pub pressure: Measured<PressureLevel>,
    /// The physical memory.
    pub memory_total: Measured<u64>,
    /// The used swap.
    pub swap_used: Measured<u64>,
    /// The allocated swap.
    pub swap_total: Measured<u64>,
    /// The label of the source: "in-process collection" or "fixture".
    pub source: &'static str,
}

/// What the journal records about the agent.
///
/// The GUI does not read the coordinator lock, because a lock probe can make
/// a starting agent exit. A recent status record is evidence of a recent
/// agent, not proof that one runs now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentState {
    /// The journal does not exist, so no agent ran on this state directory.
    NoJournal,
    /// A status record exists and its `written_at` is younger than three
    /// status intervals of the agent (3 x 30 s).
    Reporting {
        /// When the agent wrote the status record.
        since: SystemTime,
    },
    /// A status record exists and is older than three status intervals.
    Silent {
        /// When the agent wrote the last status record.
        last: SystemTime,
    },
    /// The journal exists and has no status record.
    NoRecord,
    /// The records cannot be read; the text is the reason.
    Unknown(String),
}

impl AgentState {
    /// The label for the status line.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::NoJournal => "no journal",
            Self::Reporting { .. } => "reporting",
            Self::Silent { .. } => "silent",
            Self::NoRecord => "no status",
            Self::Unknown(_) => "unknown",
        }
    }

    /// Whether the records give no sign of a recent agent.
    #[must_use]
    pub const fn is_absent(&self) -> bool {
        matches!(self, Self::NoJournal | Self::NoRecord | Self::Silent { .. })
    }
}

/// The agent state at one time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentSnapshot {
    /// The state.
    pub state: AgentState,
    /// When the state was read.
    pub captured_at: SystemTime,
}

/// A value that loads, may be old, or may fail.
#[derive(Debug, Clone)]
pub enum Loadable<T> {
    /// The first load is not done.
    Loading,
    /// A current value.
    Ready(Arc<T>),
    /// A value older than three poll intervals.
    Stale(Arc<T>),
    /// The load failed; the text is the reason.
    Unavailable(String),
}

impl<T> Loadable<T> {
    /// The value of a `Ready` or `Stale` state.
    #[must_use]
    pub fn value(&self) -> Option<&Arc<T>> {
        match self {
            Self::Ready(value) | Self::Stale(value) => Some(value),
            Self::Loading | Self::Unavailable(_) => None,
        }
    }
}

/// Whether a guard can act.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardState {
    /// The guard has automatic authority.
    Active,
    /// The guard has none, for the reason in the detail.
    Inactive,
}

/// The standing of one guard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardRow {
    /// The policy name.
    pub name: &'static str,
    /// Whether the guard can act.
    pub standing: GuardState,
    /// One short sentence that says why.
    pub detail: &'static str,
}

impl GuardRow {
    /// The row for a guard standing.
    #[must_use]
    pub fn new(name: &'static str, standing: GuardStanding) -> Self {
        Self {
            name,
            standing: if standing == GuardStanding::Active {
                GuardState::Active
            } else {
                GuardState::Inactive
            },
            detail: guard_detail(standing),
        }
    }
}

/// One plain sentence for a guard standing.
#[must_use]
pub const fn guard_detail(standing: GuardStanding) -> &'static str {
    match standing {
        GuardStanding::Active => "The guard can act within the scope of the revision.",
        GuardStanding::NoActiveRevision => "No policy revision is in effect.",
        GuardStanding::Inhibited => "This instance paused the guard after a restriction.",
        GuardStanding::NotRequested => "The configuration in effect does not request the guard.",
        GuardStanding::ObserveProfile => "The profile in effect only observes.",
        GuardStanding::Disabled => "The guard is not enabled.",
        GuardStanding::NoGrant => "The guard has no action grant.",
        GuardStanding::GrantRevoked => "The action grant was revoked.",
        GuardStanding::GrantExpired => "The action grant has expired.",
        GuardStanding::AcceptanceRequired => "The scope grew; a new acceptance is necessary.",
    }
}

/// The phase of an operation, as the interface shows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationPhase {
    /// Admitted, no work yet.
    Pending,
    /// Work is in progress.
    Running,
    /// Each target condition is verified.
    Completed,
    /// Some effects are verified, or the work stopped early.
    Partial,
    /// Nothing was submitted.
    NoAction,
    /// A known failure prevented completion.
    Failed,
    /// The evidence cannot establish the effect.
    Unknown,
}

impl OperationPhase {
    /// The phase and the state name of an operation state, by the table
    /// "Operation states" of `DESIGN.md`.
    #[must_use]
    pub fn of(state: &OperationState) -> (Self, String) {
        let phase: Self = match state {
            OperationState::Admitted => Self::Pending,
            OperationState::Completed => Self::Completed,
            OperationState::Partial | OperationState::Incomplete => Self::Partial,
            OperationState::NoAction => Self::NoAction,
            OperationState::Failed => Self::Failed,
            OperationState::UnknownOutcome | OperationState::Unrecognized(_) => Self::Unknown,
        };
        (phase, state.as_str().to_owned())
    }
}

/// The latest operation of the journal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationRow {
    /// The operation identity.
    pub operation_id: String,
    /// The phase.
    pub state: OperationPhase,
    /// The state name.
    pub state_text: String,
    /// When the operation was admitted.
    pub admitted_at: SystemTime,
    /// The trigger class.
    pub trigger: String,
}

/// What the journal says about the service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceSnapshot {
    /// Whether the journal file exists.
    pub journal_present: bool,
    /// The revision in effect.
    pub active_revision: Option<String>,
    /// The guards.
    pub guards: Vec<GuardRow>,
    /// The latest operation.
    pub latest_operation: Option<OperationRow>,
    /// A sentence for each read that failed.
    pub problems: Vec<String>,
    /// When the snapshot was read.
    pub captured_at: SystemTime,
}

/// Which size of an entry a chart shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SizeMetric {
    /// The allocated size on disk (`st_blocks * 512`).
    Allocated,
    /// The logical size (`st_size`).
    Logical,
}

impl SizeMetric {
    /// The caption that names the metric.
    #[must_use]
    pub const fn caption(self) -> &'static str {
        match self {
            Self::Allocated => "Allocated size on disk",
            Self::Logical => "Logical size",
        }
    }
}

/// The size of one direct child of the scan root. Of the sizes that the
/// scanner records, only the logical and the allocated size are kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildSize {
    /// The name of the child.
    pub name: String,
    /// Whether the child is a directory.
    pub is_directory: bool,
    /// The logical size in bytes.
    pub logical: u64,
    /// The allocated size in bytes.
    pub allocated: u64,
}

impl ChildSize {
    /// The size in `metric`.
    #[must_use]
    pub const fn size(&self, metric: SizeMetric) -> u64 {
        match metric {
            SizeMetric::Allocated => self.allocated,
            SizeMetric::Logical => self.logical,
        }
    }
}

/// How a scan ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanEnd {
    /// The scan examined each directory that it could open.
    Finished,
    /// The caller cancelled the scan.
    Cancelled,
    /// The scan stopped at the entry limit.
    LimitReached,
}

/// One group of regions that the totals do not cover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GapRow {
    /// The cause, as text.
    pub cause_text: String,
    /// The number of regions with this cause.
    pub count: usize,
}

/// The result of one scan, as the views read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanSummary {
    /// The scan root.
    pub root: PathBuf,
    /// The direct children of the root, unsorted.
    pub children: Vec<ChildSize>,
    /// The logical total in bytes.
    pub total_logical: u64,
    /// The allocated total in bytes.
    pub total_allocated: u64,
    /// The number of names that the scan examined.
    pub entries_examined: u64,
    /// Whether the coverage is complete and the scan finished.
    pub complete: bool,
    /// How the scan ended.
    pub ended: ScanEnd,
    /// The regions that the totals do not cover, grouped by cause.
    pub gaps: Vec<GapRow>,
    /// The duration of the scan.
    pub elapsed: Option<Duration>,
    /// When the scan finished.
    pub finished_at: SystemTime,
}

impl ScanSummary {
    /// The total in `metric`.
    #[must_use]
    pub const fn total(&self, metric: SizeMetric) -> u64 {
        match metric {
            SizeMetric::Allocated => self.total_allocated,
            SizeMetric::Logical => self.total_logical,
        }
    }
}

/// The running totals of a scan that has not ended.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanProgress {
    /// The number of entries that the scan listed.
    pub entries: u64,
    /// The path that the scan reads now.
    pub current_path: Option<PathBuf>,
    /// The logical bytes measured so far.
    pub logical: u64,
    /// The allocated bytes measured so far.
    pub allocated: u64,
}

/// The state of the scan of the Storage screen.
#[derive(Debug, Clone)]
pub enum ScanState {
    /// No scan has started.
    Idle,
    /// A scan runs.
    Running {
        /// The scan root.
        root: PathBuf,
        /// The latest progress.
        progress: ScanProgress,
        /// When the scan started.
        started: Instant,
    },
    /// A scan ended.
    Done(Arc<ScanSummary>),
    /// The scan did not run or failed.
    Failed {
        /// The scan root.
        root: PathBuf,
        /// The reason.
        reason: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_states_map_to_phases() {
        let cases = [
            ("Admitted", OperationPhase::Pending),
            ("Completed", OperationPhase::Completed),
            ("Partial", OperationPhase::Partial),
            ("Incomplete", OperationPhase::Partial),
            ("NoAction", OperationPhase::NoAction),
            ("Failed", OperationPhase::Failed),
            ("UnknownOutcome", OperationPhase::Unknown),
            ("SomethingNew", OperationPhase::Unknown),
        ];
        for (text, phase) in cases {
            let (got, name) = OperationPhase::of(&OperationState::from_wire(text));
            assert_eq!(got, phase, "{text}");
            assert_eq!(name, text);
        }
    }

    #[test]
    fn only_the_active_standing_is_active() {
        assert_eq!(
            GuardRow::new("x", GuardStanding::Active).standing,
            GuardState::Active
        );
        let others = [
            GuardStanding::NoActiveRevision,
            GuardStanding::Inhibited,
            GuardStanding::NotRequested,
            GuardStanding::ObserveProfile,
            GuardStanding::Disabled,
            GuardStanding::NoGrant,
            GuardStanding::GrantRevoked,
            GuardStanding::GrantExpired,
            GuardStanding::AcceptanceRequired,
        ];
        for standing in others {
            let row = GuardRow::new("x", standing);
            assert_eq!(row.standing, GuardState::Inactive);
            assert_ne!(row.detail, "");
        }
    }
}
