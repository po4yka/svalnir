//! Native memory-pressure events from a Dispatch source.
//!
//! `docs/RESOURCE_MODEL.md` section 10 owns the contract. A
//! [`PressureSubscription`] owns one `DISPATCH_SOURCE_TYPE_MEMORYPRESSURE`
//! source and sends each event to a bounded channel. An event is not a fresh
//! synchronous measurement: it has its own receive time, and the consumer
//! keeps it apart from the poll of [`super::pressure::collect_pressure`].
//!
//! The source reports a change. It does not report the state at subscription
//! time, so a new subscription has no known state until the first event or a
//! poll. When the channel is full, the event is dropped and counted; the
//! consumer then polls to find the current state.

use std::ffi::c_void;
use std::ptr::NonNull;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};

use dispatch2::{
    _dispatch_source_type_memorypressure, DispatchObject, DispatchQueue, DispatchRetained,
    DispatchSource, dispatch_source_type_t,
};
use svalnir_core::observation::{
    MetricKind, Observation, Reading, Sample, UnavailableReason, Unit, metric,
};
use svalnir_core::state::PressureState;
use svalnir_core::time::{MonotonicNanos, WallTime};
use thiserror::Error;

use super::context::{Clock, ClockError, CollectError, CollectionContext, MetricSpec, Provenance};

/// The native API of the event source.
pub const EVENT_NATIVE_API: &str = "dispatch_source(DISPATCH_SOURCE_TYPE_MEMORYPRESSURE)";
/// The native field of the event source.
pub const EVENT_NATIVE_FIELD: &str = "dispatch_source_get_data";

/// The largest capacity of the event channel.
pub const MAX_EVENT_CAPACITY: usize = 1_024;

/// `DISPATCH_MEMORYPRESSURE_NORMAL`.
const FLAG_NORMAL: u64 = 0x1;
/// `DISPATCH_MEMORYPRESSURE_WARN`.
const FLAG_WARNING: u64 = 0x2;
/// `DISPATCH_MEMORYPRESSURE_CRITICAL`.
const FLAG_CRITICAL: u64 = 0x4;
/// The events that the subscription asks for.
const EVENT_MASK: usize = 0x7;

/// The time at which the handler received an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiveTime {
    /// The monotonic time on the clock of the subscription.
    pub monotonic: MonotonicNanos,
    /// The wall-clock time, for display.
    pub wall: WallTime,
}

/// One native memory-pressure event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PressureEvent {
    /// The flags that the source delivered.
    pub native_flags: u64,
    /// The state, when the flags are exactly one known flag. `None` for
    /// coalesced or unknown flags: the consumer polls for the state.
    pub state: Option<PressureState>,
    /// When the handler received the event. Dispatch can deliver an event
    /// later than the change, so this time is an upper bound.
    pub received: Result<ReceiveTime, ClockError>,
}

impl PressureEvent {
    /// Makes the `memory.pressure` observation of this event.
    ///
    /// The acquisition window is the receive time. The source names the
    /// Dispatch adapter, so a consumer can tell an event from a poll. An
    /// event with no single known state is an unavailable reading.
    ///
    /// # Errors
    ///
    /// Returns a [`CollectError`] when the event has no receive time.
    pub fn observation(
        &self,
        context: &CollectionContext,
    ) -> Result<Observation<PressureState>, CollectError> {
        let received: ReceiveTime = self.received?;
        let sample: Sample =
            context.sample(received.monotonic, received.monotonic, received.wall)?;
        let reading: Reading<PressureState> = match &self.state {
            Some(state) => Reading::Available(state.clone()),
            None => Reading::Unavailable(UnavailableReason::InconsistentData),
        };
        Ok(context.observation(
            MetricSpec::new(metric::MEMORY_PRESSURE, Unit::State, MetricKind::State),
            context.host_scope(),
            reading,
            Provenance {
                adapter: &context.adapters.dispatch_memory_pressure,
                native_api: EVENT_NATIVE_API,
                native_field: EVENT_NATIVE_FIELD,
            },
            &sample,
        ))
    }
}

/// Maps the flags of one event to a state. Returns `None` when the flags are
/// not exactly one known flag.
pub fn pressure_state_from_flags(flags: u64) -> Option<PressureState> {
    match flags {
        FLAG_NORMAL => Some(PressureState::Normal),
        FLAG_WARNING => Some(PressureState::Warning),
        FLAG_CRITICAL => Some(PressureState::Critical),
        _ => None,
    }
}

/// The reason a subscription was not made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SubscribeError {
    /// The capacity is zero or larger than [`MAX_EVENT_CAPACITY`].
    #[error("the event capacity is not in the range 1 to 1024")]
    InvalidCapacity,
}

/// The state that the event handler uses. The subscription moves it to the
/// heap and gives the pointer to the Dispatch source as its context.
struct HandlerState {
    /// The source that owns this state. The pointer is valid while a handler
    /// of the source runs, because Dispatch keeps the source for the call.
    source: NonNull<DispatchSource>,
    sender: SyncSender<PressureEvent>,
    dropped: Arc<AtomicU64>,
    clock: Arc<dyn Clock>,
}

// SAFETY: the subscription makes the state on one thread, and Dispatch reads
// and drops it on a queue thread. `SyncSender<PressureEvent>`,
// `Arc<AtomicU64>`, and `Arc<dyn Clock>` (`Clock: Send + Sync`) are `Send`.
// The pointer refers to a `DispatchSource`, which is `Send + Sync`, and the
// state does not own it.
unsafe impl Send for HandlerState {}

/// Sends one event. A full channel drops the event and counts it. A closed
/// channel drops the event: the consumer is gone.
fn deliver(
    sender: &SyncSender<PressureEvent>,
    dropped: &AtomicU64,
    clock: &dyn Clock,
    native_flags: u64,
) {
    let received: Result<ReceiveTime, ClockError> = clock
        .monotonic_now()
        .and_then(|monotonic| clock.wall_now().map(|wall| ReceiveTime { monotonic, wall }));
    let event = PressureEvent {
        native_flags,
        state: pressure_state_from_flags(native_flags),
        received,
    };
    match sender.try_send(event) {
        Ok(()) | Err(TrySendError::Disconnected(_)) => {}
        Err(TrySendError::Full(_)) => {
            dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// The event handler of the source. Dispatch calls it on the serial queue of
/// the subscription with the context of the source.
extern "C" fn handle_event(context: *mut c_void) {
    // SAFETY: the context is the `HandlerState` that `PressureSubscription::
    // start` set before it activated the source. Only `handle_cancel` frees
    // it, and Dispatch calls the cancel handler one time, on the same serial
    // queue, after the last event handler returned. The state is shared and
    // not mutated.
    let state: &HandlerState = unsafe { &*context.cast::<HandlerState>() };
    // SAFETY: libdispatch holds a reference to a source for each handler
    // invocation that it starts (the behavior that `dispatch_source_get_data`
    // in a handler relies on), so the pointer refers to a live source.
    let source: &DispatchSource = unsafe { state.source.as_ref() };
    let native_flags: u64 = u64::try_from(source.data()).unwrap_or(u64::MAX);
    deliver(
        &state.sender,
        &state.dropped,
        state.clock.as_ref(),
        native_flags,
    );
}

/// The cancel handler of the source. It releases the handler state.
extern "C" fn handle_cancel(context: *mut c_void) {
    // SAFETY: the context is the pointer of `Box::into_raw` in
    // `PressureSubscription::start`. Dispatch calls the cancel handler one
    // time, after the last event handler returned, so this is the only
    // release and no reference to the state remains. The drop is on a queue
    // thread; `HandlerState: Send` permits that.
    let state: Box<HandlerState> = unsafe { Box::from_raw(context.cast::<HandlerState>()) };
    drop(state);
}

/// A subscription to the native memory-pressure events of the host.
///
/// The drop cancels the source. Dispatch then calls the cancel handler,
/// which releases the handler state and closes the channel: the receiver
/// reports a disconnect after the events that it already has.
#[derive(Debug)]
pub struct PressureSubscription {
    source: DispatchRetained<DispatchSource>,
    dropped: Arc<AtomicU64>,
}

impl PressureSubscription {
    /// Starts a subscription that sends events to a channel of `capacity`
    /// events. The clock of `context` gives the receive time of each event,
    /// so make the observations of the events with the same context.
    ///
    /// # Errors
    ///
    /// Returns [`SubscribeError::InvalidCapacity`] when `capacity` is zero
    /// or larger than [`MAX_EVENT_CAPACITY`].
    pub fn start(
        context: &CollectionContext,
        capacity: usize,
    ) -> Result<(Self, Receiver<PressureEvent>), SubscribeError> {
        let clock: Arc<dyn Clock> = Arc::clone(context.clock());
        if capacity == 0 || capacity > MAX_EVENT_CAPACITY {
            return Err(SubscribeError::InvalidCapacity);
        }
        let (sender, receiver) = sync_channel::<PressureEvent>(capacity);
        let dropped = Arc::new(AtomicU64::new(0));

        // A serial queue: the handlers of the source do not run at the same
        // time.
        let queue: DispatchRetained<DispatchQueue> =
            DispatchQueue::new("dev.po4yka.svalnir.agent.memory-pressure", None);
        let source_type: dispatch_source_type_t =
            (&raw const _dispatch_source_type_memorypressure).cast_mut();
        // SAFETY: the type is the memory-pressure source type of libdispatch,
        // which takes a handle of zero and a mask of pressure flags. The
        // queue is a valid serial queue. The source is created inactive.
        let source: DispatchRetained<DispatchSource> =
            unsafe { DispatchSource::new(source_type, 0, EVENT_MASK, Some(&queue)) };

        let state: *mut HandlerState = Box::into_raw(Box::new(HandlerState {
            source: NonNull::from(&*source),
            sender,
            dropped: Arc::clone(&dropped),
            clock,
        }));
        // SAFETY: the source is inactive, so no handler reads the context
        // during this call. The pointer stays valid until `handle_cancel`
        // frees it, and each handler reads it as a `HandlerState`.
        unsafe { source.set_context(state.cast::<c_void>()) };
        source.set_event_handler_f(handle_event);
        source.set_cancel_handler_f(handle_cancel);
        source.activate();

        Ok((Self { source, dropped }, receiver))
    }

    /// The number of events that the full channel dropped. When the number
    /// increases, the last received event is not the current state: poll.
    pub fn dropped_events(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

impl Drop for PressureSubscription {
    fn drop(&mut self) {
        // The source is active, so Dispatch runs `handle_cancel` after this
        // call and the handler state is released one time. The field drop
        // then releases the reference of this subscription.
        self.source.cancel();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc::{RecvTimeoutError, sync_channel};
    use std::time::Duration;

    use svalnir_core::observation::UnavailableReason;
    use svalnir_core::state::PressureState;
    use svalnir_core::time::MonotonicNanos;

    use super::super::context::testing::{self, ManualClock};
    use super::super::context::{CollectError, CollectionContext};
    use super::{
        PressureEvent, PressureSubscription, SubscribeError, deliver, pressure_state_from_flags,
    };

    #[test]
    fn exactly_one_known_flag_is_a_state() {
        assert_eq!(pressure_state_from_flags(0x1), Some(PressureState::Normal));
        assert_eq!(pressure_state_from_flags(0x2), Some(PressureState::Warning));
        assert_eq!(
            pressure_state_from_flags(0x4),
            Some(PressureState::Critical)
        );
        for flags in [0, 0x3, 0x5, 0x6, 0x7, 0x8, 0x10, u64::MAX] {
            assert_eq!(pressure_state_from_flags(flags), None, "{flags:#x}");
        }
    }

    #[test]
    fn a_delivered_event_has_its_state_and_receive_time() {
        let (sender, receiver) = sync_channel::<PressureEvent>(4);
        let dropped = AtomicU64::new(0);
        let clock = ManualClock::new(7_000, 1);
        deliver(&sender, &dropped, &clock, 0x4);
        let event = receiver.try_recv().unwrap();
        assert_eq!(event.native_flags, 0x4);
        assert_eq!(event.state, Some(PressureState::Critical));
        assert_eq!(
            event.received.unwrap().monotonic,
            MonotonicNanos::new(7_000)
        );
        assert_eq!(dropped.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn a_full_channel_drops_and_counts_the_event() {
        let (sender, receiver) = sync_channel::<PressureEvent>(2);
        let dropped = AtomicU64::new(0);
        let clock = ManualClock::new(0, 1);
        for flags in [0x1, 0x2, 0x4, 0x2] {
            deliver(&sender, &dropped, &clock, flags);
        }
        assert_eq!(dropped.load(Ordering::Relaxed), 2);
        // The channel keeps the two oldest events and no more.
        assert_eq!(receiver.try_recv().unwrap().native_flags, 0x1);
        assert_eq!(receiver.try_recv().unwrap().native_flags, 0x2);
        assert!(receiver.try_recv().is_err());

        // A closed channel is not an overflow.
        drop(receiver);
        deliver(&sender, &dropped, &clock, 0x1);
        assert_eq!(dropped.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn an_event_observation_names_the_event_source() {
        let (context, clock) = testing::context();
        let (sender, receiver) = sync_channel::<PressureEvent>(4);
        let dropped = AtomicU64::new(0);
        deliver(&sender, &dropped, clock.as_ref(), 0x2);
        deliver(&sender, &dropped, clock.as_ref(), 0x6);

        let warning = receiver.try_recv().unwrap().observation(&context).unwrap();
        assert_eq!(warning.value(), Some(&PressureState::Warning));
        assert_eq!(
            warning.source.adapter_id.as_str(),
            "macos.dispatch_memory_pressure"
        );
        assert_eq!(
            warning.sample.started_monotonic_ns,
            warning.sample.finished_monotonic_ns
        );
        serde_json::to_string(&warning).unwrap();

        // Coalesced flags are not a state, and not `critical`.
        let coalesced = receiver.try_recv().unwrap().observation(&context).unwrap();
        assert_eq!(coalesced.value(), None);
        assert_eq!(
            coalesced.reason(),
            Some(&UnavailableReason::InconsistentData)
        );

        let no_time = PressureEvent {
            native_flags: 0x1,
            state: Some(PressureState::Normal),
            received: Err(super::ClockError::MonotonicUnavailable),
        };
        assert_eq!(
            no_time.observation(&context),
            Err(CollectError::Clock(super::ClockError::MonotonicUnavailable))
        );
    }

    #[test]
    fn a_capacity_out_of_range_is_rejected() {
        let (context, _clock) = testing::context();
        for capacity in [0, 1_025] {
            let result = PressureSubscription::start(&context, capacity);
            assert_eq!(result.unwrap_err(), SubscribeError::InvalidCapacity);
        }
    }

    #[test]
    fn the_drop_of_a_subscription_releases_the_source_and_closes_the_channel() {
        let context = CollectionContext::for_current_process().unwrap();
        for _ in 0..20 {
            let (subscription, receiver) = PressureSubscription::start(&context, 8).unwrap();
            assert_eq!(subscription.dropped_events(), 0);
            drop(subscription);
            // The cancel handler drops the sender. Drain the events that the
            // host sent before the cancel, then see the disconnect.
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            loop {
                match receiver.recv_timeout(Duration::from_secs(10)) {
                    Ok(event) => {
                        assert!(event.native_flags != 0);
                        assert!(std::time::Instant::now() < deadline);
                    }
                    Err(RecvTimeoutError::Disconnected) => break,
                    Err(RecvTimeoutError::Timeout) => {
                        panic!("the cancel handler did not release the handler state")
                    }
                }
            }
        }
    }
}
