//! The interfaces that the runtime needs from its environment.
//!
//! Each interface is a trait, so a test gives a controlled clock,
//! synthetic observations, and a candidate source in a temporary
//! directory. The implementations for the running system are in
//! [`super::host`].

use std::fmt::Debug;
use std::sync::Arc;

use svalnir_core::config::ValidatedConfig;
use svalnir_core::id::VolumeId;
use svalnir_core::observation::Observation;
use svalnir_core::policy::ControlPlaneProcess;
use svalnir_core::quantity::{Bytes, Nanoseconds};

use svalnir_core::state::PressureState;
use svalnir_core::time::MonotonicNanos;

use crate::controller::{CandidateSet, Notification, Observations, PreparationMode};
use crate::coordinator::SettledOperation;
use crate::coordinator::{Clock, TimeReading};
use crate::notify::NotificationStatus;

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
    /// The cumulative sleep time of the host, read before the capacity
    /// collection. The runtime stores it beside the capacity samples as
    /// the evidence of a sleep boundary between two of them. `None` when
    /// the clock gave no acquisition window.
    pub sleep_time: Option<Observation<Nanoseconds>>,
}

/// The collectors. The collector thread calls it; a collection can take
/// the time of a process inventory.
pub trait Collector: Send {
    /// Reads the resource signals one time.
    fn collect(&mut self) -> Sample;
}

/// One request for the cleanup candidates.
#[derive(Debug, Clone, Copy)]
pub struct Preparation<'a> {
    /// The volumes whose candidates the disk guard needs.
    pub volumes: &'a [VolumeId],
    /// How much work the source does.
    pub mode: PreparationMode,
    /// The time of the request.
    pub time: &'a TimeReading,
    /// The configuration in effect: the approved rules of the disk guard
    /// and the exclusions of the user.
    pub config: &'a ValidatedConfig,
}

/// The source of the cleanup candidates.
pub trait CandidateSource: Send {
    /// Prepares the candidates of the volumes of `request`.
    ///
    /// [`PreparationMode::KnownOnly`] examines the candidates of an
    /// earlier discovery again and lists no directory. The call returns
    /// in a short, bounded time.
    /// [`PreparationMode::Refresh`] asks for a bounded discovery. The
    /// call does not wait for it: a source can run the discovery on a
    /// different thread and give the set that it has now. `None` means
    /// that the source has no set: the disk guard then makes no plan.
    fn prepare(&mut self, request: &Preparation<'_>) -> Option<CandidateSet>;

    /// Stops a discovery that runs now. The driver calls it when optional
    /// work is reduced (memory pressure, a pause, the budget of the agent)
    /// and at a stop. The default is a source with no background work.
    fn cancel(&mut self) {}
}

/// The receiver of the changes of state that a person can want to know:
/// the notifications of the controller, the operations that the
/// coordinator settled, and the memory pressure readings.
///
/// A call must not wait for a notification center: the driver calls it on
/// the thread of the controller and the coordinator. `at` is the
/// monotonic time of the agent, for a rate bound.
pub trait Notifier: Send {
    /// Takes one notification of the controller.
    fn notify(&mut self, notification: &Notification, at: MonotonicNanos);

    /// Takes one operation that the coordinator settled.
    fn settled(&mut self, _operation: &SettledOperation, _at: MonotonicNanos) {}

    /// Takes the memory pressure reading of a new sample. `None` is a
    /// reading that is not a value.
    fn pressure(&mut self, _reading: Option<&PressureState>, _at: MonotonicNanos) {}

    /// The notification capability, for the capability summary of the
    /// status record. `None` when the receiver posts no system
    /// notification. The driver writes it only into a status record that
    /// has a capability summary.
    fn status(&self) -> Option<NotificationStatus> {
        None
    }
}

/// The measurement of the physical footprint of the agent process.
pub trait SelfFootprint: Send {
    /// The footprint. `None` when the measurement is not available; that
    /// is not a footprint of zero.
    fn footprint(&mut self) -> Option<Bytes>;
}
