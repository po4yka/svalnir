//! The interfaces that the runtime needs from its environment.
//!
//! Each interface is a trait, so a test gives a controlled clock,
//! synthetic observations, and a candidate source in a temporary
//! directory. The implementations for the running system are in
//! [`super::host`].

use std::fmt::Debug;
use std::sync::Arc;

use svalnir_core::id::VolumeId;
use svalnir_core::policy::ControlPlaneProcess;
use svalnir_core::quantity::Bytes;

use crate::controller::{CandidateSet, Notification, Observations, PreparationMode};
use crate::coordinator::{Clock, TimeReading};

/// The clocks of the agent, with the record of a clock discontinuity.
pub trait AgentClock: Debug + Send + Sync {
    /// The current time. `None` when a clock gave no value: the agent then
    /// evaluates nothing and dispatches nothing.
    fn now(&self) -> Option<TimeReading>;

    /// Records that the host slept or that the clock is not continuous.
    /// Each later reading has a larger continuity generation, so each
    /// qualification window starts again and each earlier sample is not
    /// usable.
    fn mark_discontinuity(&self);

    /// Reads whether the host slept after the call before this one. When
    /// it did, or when the clock cannot tell, the clock records a
    /// discontinuity as [`AgentClock::mark_discontinuity`] does and
    /// returns `true`. The driver calls it at each tick, so a sleep is
    /// known before the next collection.
    ///
    /// The default is a clock with no record of the sleep time: it
    /// returns `false`, and only a sample reports a wake.
    fn observe_continuity(&self) -> bool {
        false
    }
}

/// The clock of the agent as the clock of the coordinator.
#[derive(Debug, Clone)]
pub struct ClockHandle(pub Arc<dyn AgentClock>);

impl Clock for ClockHandle {
    fn now(&self) -> Option<TimeReading> {
        self.0.now()
    }
}

/// One collection of the resource signals.
#[derive(Debug, Clone, Default)]
pub struct Sample {
    /// The capacity of each selected volume and the memory snapshot. The
    /// candidate set is not a part of a sample.
    pub observations: Observations,
    /// True when the host slept after the collection before this one. The
    /// runtime then records a clock discontinuity and discards the
    /// prepared candidates.
    pub woke: bool,
    /// The processes of the control plane, when the process inventory
    /// gave them.
    pub control_plane: Option<Vec<ControlPlaneProcess>>,
    /// The collectors that gave no value, as short names.
    pub degraded: Vec<String>,
}

/// The collectors. The collector thread calls it; a collection can take
/// the time of a process inventory.
pub trait Collector: Send {
    /// Reads the resource signals one time.
    fn collect(&mut self) -> Sample;
}

/// The source of the cleanup candidates.
pub trait CandidateSource: Send {
    /// Prepares the candidates of `volumes`.
    ///
    /// [`PreparationMode::KnownOnly`] examines the candidates of an
    /// earlier call again and lists no directory.
    /// [`PreparationMode::Refresh`] is a bounded discovery. `None` means
    /// that the source has no set: the disk guard then makes no plan.
    fn prepare(
        &mut self,
        volumes: &[VolumeId],
        mode: PreparationMode,
        time: &TimeReading,
    ) -> Option<CandidateSet>;
}

/// The receiver of the notifications of the controller.
pub trait Notifier: Send {
    /// Takes one notification.
    fn notify(&mut self, notification: &Notification);
}

/// The measurement of the physical footprint of the agent process.
pub trait SelfFootprint: Send {
    /// The footprint. `None` when the measurement is not available; that
    /// is not a footprint of zero.
    fn footprint(&mut self) -> Option<Bytes>;
}
