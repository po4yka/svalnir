//! Immutable, presentation-neutral snapshots that the views read.
//!
//! The types hold no GPUI types. A failed query is never a zero: it is
//! [`Measured::Unavailable`] with a reason.

use std::{sync::Arc, time::SystemTime};

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
