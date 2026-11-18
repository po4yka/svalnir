//! Immutable, presentation-neutral snapshots that the views read.
//!
//! The types hold no GPUI types. A failed query is never a zero: it is
//! [`Measured::Unavailable`] with a reason.

use std::{sync::Arc, time::SystemTime};

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

/// The state of the coordinator, as far as this window can tell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentState {
    /// A process holds the coordinator lock. The lock does not tell an agent
    /// from a client that runs a request, so this state is a lower bound on
    /// "the agent runs".
    Running,
    /// A client process runs a request as a transient coordinator.
    ClientCoordinator,
    /// No process holds the lock.
    NotRunning,
    /// The lock cannot be read.
    Unknown,
    /// The journal does not exist, so no agent ran on this state directory.
    NoJournal,
}

impl AgentState {
    /// The label for the status line.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::ClientCoordinator => "client coordinator",
            Self::NotRunning => "not running",
            Self::Unknown => "unknown",
            Self::NoJournal => "no journal",
        }
    }

    /// Whether the agent is known to be absent.
    #[must_use]
    pub const fn is_absent(self) -> bool {
        matches!(self, Self::NotRunning | Self::NoJournal)
    }
}

/// The agent state at one time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
