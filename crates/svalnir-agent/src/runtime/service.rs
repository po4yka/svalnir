//! The threads of the agent.
//!
//! [`run`] runs the driver on the calling thread and starts one collector
//! thread. See the concurrency design in the documentation of
//! [`crate::runtime`].

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use svalnir_core::time::MonotonicNanos;

use super::driver::{Driver, ShutdownReport, TickReport};
use super::ports::{AgentClock, Collector, Sample};
use crate::coordinator::Idle;

/// The longest time that a thread waits before it reads the stop request
/// again.
const STOP_CHECK: Duration = Duration::from_secs(1);

/// The shortest time between two collections that pressure events start.
const MIN_EVENT_GAP: Duration = Duration::from_millis(250);

/// The intervals of the service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceSettings {
    /// The time between two collections with no pressure and no incident.
    pub sample_interval: Duration,
    /// The time between two collections while a guard has pressure or an
    /// incident.
    pub pressure_sample_interval: Duration,
    /// The longest time between two ticks of the driver. A tick reads the
    /// request queue of the journal, so this is the longest wait of a
    /// client request.
    pub idle_interval: Duration,
}

/// The state that the two threads share. Each critical section moves one
/// value: no collection and no tick runs with the lock held.
#[derive(Debug, Default)]
struct Shared {
    stop: AtomicBool,
    /// True when the stop is a request of the owner of the handle, and
    /// not a failure of the service.
    requested: AtomicBool,
    fast: AtomicBool,
    /// The newest sample that the driver did not take. One sample: a new
    /// one replaces an old one, so the retained samples are bounded.
    slot: Mutex<Option<Sample>>,
    wake: Condvar,
}

impl Shared {
    fn slot(&self) -> MutexGuard<'_, Option<Sample>> {
        self.slot.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The stop request of the service. Each copy is the same request.
#[derive(Debug, Clone, Default)]
pub struct StopHandle(Arc<Shared>);

impl StopHandle {
    /// Makes a handle with no stop request.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Requests the stop. The driver ends its tick, stops new dispatch,
    /// and checkpoints.
    pub fn request_stop(&self) {
        self.0.requested.store(true, Ordering::SeqCst);
        self.0.stop.store(true, Ordering::SeqCst);
        // The lock makes sure that a waiting thread is in its wait or
        // reads the flag before it.
        let _slot = self.0.slot();
        self.0.wake.notify_all();
    }

    /// Whether the service stops or stopped, for a request or for a
    /// failure of its own.
    #[must_use]
    pub fn is_stopped(&self) -> bool {
        self.0.stop.load(Ordering::SeqCst)
    }

    /// Whether [`StopHandle::request_stop`] was called. A service that
    /// stopped with no request had a failure.
    #[must_use]
    pub fn was_requested(&self) -> bool {
        self.0.requested.load(Ordering::SeqCst)
    }
}

/// Waits for the wake time of the coordinator on the thread of the
/// driver. The wait is short, so a stop does not wait for a grace period.
#[derive(Debug)]
pub struct ThreadIdle {
    clock: Arc<dyn AgentClock>,
    /// The longest sleep of one call.
    pub slice: Duration,
}

impl ThreadIdle {
    /// An idle wait that reads `clock`.
    #[must_use]
    pub fn new(clock: Arc<dyn AgentClock>) -> Self {
        Self {
            clock,
            slice: Duration::from_millis(100),
        }
    }
}

impl Idle for ThreadIdle {
    fn idle(&mut self, wake_at: Option<MonotonicNanos>) {
        let now: Option<MonotonicNanos> = self.clock.now().map(|time| time.clock.now);
        let wait: Duration = match (now, wake_at) {
            (Some(now), Some(wake_at)) => wake_at
                .checked_duration_since(now)
                .map_or(Duration::ZERO, Duration::from),
            _ => self.slice,
        };
        std::thread::sleep(wait.min(self.slice));
    }
}

/// The loop of the collector thread: one collection, then a wait for a
/// pressure event, the interval, or the stop.
fn collect_loop<E>(
    shared: &Shared,
    collector: &mut dyn Collector,
    events: &Receiver<E>,
    settings: &ServiceSettings,
) {
    let mut connected: bool = true;
    while !shared.stop.load(Ordering::SeqCst) {
        let sample: Sample = collector.collect();
        let collected_at: Instant = Instant::now();
        {
            // A sample that the driver did not take is replaced. Its wake
            // and its degraded collectors are not lost with it.
            let mut slot = shared.slot();
            let mut sample: Sample = sample;
            if let Some(earlier) = slot.take() {
                sample.woke |= earlier.woke;
                for reason in earlier.degraded {
                    if !sample.degraded.contains(&reason) {
                        sample.degraded.push(reason);
                    }
                }
            }
            *slot = Some(sample);
        }
        shared.wake.notify_all();

        let interval: Duration = if shared.fast.load(Ordering::SeqCst) {
            settings.pressure_sample_interval
        } else {
            settings.sample_interval
        };
        // Wait in bounded parts, so that a stop request is read soon.
        while !shared.stop.load(Ordering::SeqCst) {
            let elapsed: Duration = collected_at.elapsed();
            if elapsed >= interval {
                break;
            }
            let part: Duration = interval.saturating_sub(elapsed).min(STOP_CHECK);
            if !connected {
                std::thread::sleep(part);
                continue;
            }
            match events.recv_timeout(part) {
                Ok(_event) => {
                    // A pressure event starts a fresh assessment. The
                    // other events of a burst, also the ones that arrive
                    // in the gap, start no further one.
                    let gap: Duration = MIN_EVENT_GAP.saturating_sub(collected_at.elapsed());
                    std::thread::sleep(gap);
                    while events.try_recv().is_ok() {}
                    break;
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => connected = false,
            }
        }
    }
}

/// Runs the agent until `stop`.
///
/// The calling thread is the driver thread. The function starts the
/// collector thread, calls [`Driver::tick`] with each new sample and at
/// most each [`ServiceSettings::idle_interval`], and calls
/// [`Driver::shutdown`] after the stop request. It returns after the
/// collector thread ended.
///
/// `events` gives one value for each memory-pressure event of the host. A
/// source that is disconnected leaves the periodic collection.
pub fn run<E: Send>(
    mut driver: Box<Driver>,
    mut collector: Box<dyn Collector>,
    events: Receiver<E>,
    settings: ServiceSettings,
    stop: &StopHandle,
    clock: Arc<dyn AgentClock>,
) -> ShutdownReport {
    let shared: &Shared = &stop.0;
    std::thread::scope(|scope| {
        let spawned = std::thread::Builder::new()
            .name("svalnir-collector".to_owned())
            .spawn_scoped(scope, move || {
                collect_loop(shared, collector.as_mut(), &events, &settings);
            });
        if spawned.is_err() {
            // With no collector thread the agent has no observation. It
            // stops, and the caller reports the stop that is not clean.
            shared.stop.store(true, Ordering::SeqCst);
        }
        loop {
            let sample: Option<Sample> = shared.slot().take();
            let report: TickReport = driver.tick(sample);
            shared.fast.store(report.fast_sampling, Ordering::SeqCst);
            if shared.stop.load(Ordering::SeqCst) {
                break;
            }
            if report.worked {
                continue;
            }
            let now: Option<MonotonicNanos> = clock.now().map(|time| time.clock.now);
            let until_wake: Duration = match (now, report.wake_at) {
                (Some(now), Some(wake_at)) => wake_at
                    .checked_duration_since(now)
                    .map_or(Duration::ZERO, Duration::from),
                _ => settings.idle_interval,
            };
            let wait: Duration = until_wake.min(settings.idle_interval);
            let slot = shared.slot();
            if slot.is_none() && !shared.stop.load(Ordering::SeqCst) {
                let _waited = shared
                    .wake
                    .wait_timeout(slot, wait)
                    .unwrap_or_else(PoisonError::into_inner);
            }
        }
        let mut idle: ThreadIdle = ThreadIdle::new(clock);
        let report: ShutdownReport = driver.shutdown(&mut idle);
        // A service that stopped with no request did not stop cleanly.
        ShutdownReport {
            clean: report.clean && shared.requested.load(Ordering::SeqCst),
        }
    })
}
