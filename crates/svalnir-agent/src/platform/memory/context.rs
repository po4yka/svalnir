//! The collection context: who collects, in which boot, and on which clock.
//!
//! `docs/RESOURCE_MODEL.md` sections 2, 4, and 5 own the identities and the
//! time model. A collector takes a [`CollectionContext`] and stamps each
//! observation with its worker, boot, collector epoch, clock domain, and
//! acquisition window. The volume collectors use the same context.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use svalnir_core::id::{
    AdapterId, BootId, ClockDomainId, CollectorEpochId, IdError, IdentityId, SampleId, WorkerId,
};
use svalnir_core::observation::{
    Coverage, MetricId, MetricKind, Observation, Reading, Sample, Scope, ScopeKind, Source,
    UnavailableReason, Unit, metric,
};
use svalnir_core::quantity::Nanoseconds;
use svalnir_core::time::{MonotonicNanos, WallTime};
use thiserror::Error;

use super::native;
use crate::platform::sleep;

/// The revision of the adapters in this module and in the volume module.
/// Increase it when the definition or the source of a metric changes.
pub const ADAPTER_REVISION: &str = "1";

/// The largest length of a collector epoch that a context accepts. The
/// sample identity has the epoch and a sequence number, and it must fit in
/// an identity of 128 bytes.
pub const MAX_COLLECTOR_EPOCH_LENGTH: usize = 96;

/// The reason a clock gave no time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ClockError {
    /// The monotonic clock query failed or gave a value out of range.
    #[error("the monotonic clock is not available")]
    MonotonicUnavailable,
    /// The wall-clock time is outside the years 0000 to 9999.
    #[error("the wall-clock time is out of range")]
    WallTimeOutOfRange,
}

/// A source of monotonic and wall-clock time.
///
/// The monotonic values of one clock are comparable only in one clock domain
/// and one boot. A test supplies a controlled clock.
pub trait Clock: fmt::Debug + Send + Sync {
    /// Nanoseconds on the monotonic timeline of the clock domain.
    ///
    /// # Errors
    ///
    /// Returns [`ClockError::MonotonicUnavailable`] when the clock gives no
    /// value.
    fn monotonic_now(&self) -> Result<MonotonicNanos, ClockError>;

    /// The UTC wall-clock time, for display and history.
    ///
    /// # Errors
    ///
    /// Returns [`ClockError::WallTimeOutOfRange`] when the time is not
    /// representable.
    fn wall_now(&self) -> Result<WallTime, ClockError>;

    /// The cumulative time that the host slept in the current boot.
    ///
    /// Two samples with different sleep times have a sleep between them (see
    /// [`sleep_between`](crate::platform::sleep::sleep_between)).
    ///
    /// # Errors
    ///
    /// Returns the reason the clock gives no sleep time.
    fn sleep_time(&self) -> Result<Nanoseconds, UnavailableReason>;
}

/// The clock of the host.
///
/// On macOS the monotonic time is `clock_gettime(CLOCK_MONOTONIC_RAW)`. This
/// clock is the same for each process of one boot and continues while the
/// host sleeps, so a sleep shows as a long interval between two samples. The
/// sleep time is that clock minus `clock_gettime(CLOCK_UPTIME_RAW)`, which
/// stops while the host sleeps.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl SystemClock {
    /// The clock domain of the monotonic values of this clock.
    ///
    /// # Errors
    ///
    /// Returns an [`IdError`] when the name is not an identity. The name is
    /// a constant, so a test shows that this does not occur.
    pub fn clock_domain() -> Result<ClockDomainId, IdError> {
        ClockDomainId::new(native::CLOCK_DOMAIN)
    }
}

impl Clock for SystemClock {
    fn monotonic_now(&self) -> Result<MonotonicNanos, ClockError> {
        native::monotonic_raw_nanoseconds()
            .map(MonotonicNanos::new)
            .ok_or(ClockError::MonotonicUnavailable)
    }

    fn wall_now(&self) -> Result<WallTime, ClockError> {
        WallTime::try_from(SystemTime::now()).map_err(|_| ClockError::WallTimeOutOfRange)
    }

    fn sleep_time(&self) -> Result<Nanoseconds, UnavailableReason> {
        sleep::native_sleep_time()
    }
}

/// The identities that a context stamps on each observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextIdentity {
    /// The identity record of the host. It is the scope of each host metric.
    pub host: IdentityId,
    /// The process that collects.
    pub worker_id: WorkerId,
    /// The boot of the host. Counters and monotonic times of two boots are
    /// not comparable.
    pub boot_id: BootId,
    /// The collector lifetime. A restart makes a new epoch.
    pub collector_epoch: CollectorEpochId,
    /// The clock domain of the monotonic timestamps.
    pub clock_domain: ClockDomainId,
}

/// The reason a context was not made.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ContextError {
    /// An identity text is not valid.
    #[error("a collection identity is not valid: {0}")]
    Identity(#[from] IdError),
    /// The collector epoch is longer than [`MAX_COLLECTOR_EPOCH_LENGTH`].
    #[error("the collector epoch is longer than 96 bytes")]
    CollectorEpochTooLong,
    /// The boot identity of the host is not available.
    #[error("the boot identity of the host is not available: {}", .0.as_str())]
    BootIdentityUnavailable(UnavailableReason),
    /// The clock gave no time.
    #[error(transparent)]
    Clock(#[from] ClockError),
}

/// The reason a collection made no observation.
///
/// A failed native query is not this error: it is an unavailable reading in
/// the returned observation. This error means that the envelope itself was
/// not made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CollectError {
    /// The clock gave no time for the acquisition window.
    #[error(transparent)]
    Clock(#[from] ClockError),
    /// An identity that the collector derives is not valid.
    #[error("a derived identity is not valid: {0}")]
    Identity(#[from] IdError),
}

/// The identities of the adapters in this module and in the volume module.
#[derive(Debug, Clone)]
pub(crate) struct AdapterIds {
    /// Typed `sysctlbyname` queries.
    pub(crate) sysctl: AdapterId,
    /// Mach host statistics.
    pub(crate) mach_host: AdapterId,
    /// The Dispatch memory-pressure source.
    #[cfg(target_os = "macos")]
    pub(crate) dispatch_memory_pressure: AdapterId,
    /// `statfs` of one volume.
    pub(crate) statfs: AdapterId,
    /// Foundation volume resource values.
    pub(crate) foundation_volume: AdapterId,
    /// The cumulative sleep time of the host.
    pub(crate) sleep: AdapterId,
    /// The derived entries of the capacity report.
    pub(crate) capacity_report: AdapterId,
    /// The local snapshot list of a volume.
    pub(crate) fs_snapshot: AdapterId,
}

impl AdapterIds {
    fn new() -> Result<Self, IdError> {
        Ok(Self {
            sysctl: AdapterId::new("macos.sysctl")?,
            mach_host: AdapterId::new("macos.mach_host")?,
            #[cfg(target_os = "macos")]
            dispatch_memory_pressure: AdapterId::new("macos.dispatch_memory_pressure")?,
            statfs: AdapterId::new("macos.statfs")?,
            foundation_volume: AdapterId::new("macos.foundation_volume")?,
            sleep: AdapterId::new("macos.clock_sleep")?,
            capacity_report: AdapterId::new("svalnir.capacity_report")?,
            fs_snapshot: AdapterId::new("macos.fs_snapshot")?,
        })
    }
}

/// The registered definition of one metric.
#[derive(Debug, Clone)]
pub(crate) struct MetricSpec {
    pub(crate) id: MetricId,
    pub(crate) unit: Unit,
    pub(crate) kind: MetricKind,
}

impl MetricSpec {
    pub(crate) const fn new(id: MetricId, unit: Unit, kind: MetricKind) -> Self {
        Self { id, unit, kind }
    }
}

/// The native origin of one value.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Provenance<'a> {
    pub(crate) adapter: &'a AdapterId,
    pub(crate) native_api: &'a str,
    pub(crate) native_field: &'a str,
}

/// The start of one acquisition.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Acquisition {
    started: MonotonicNanos,
}

/// The context of one collector lifetime.
///
/// The context is cheap to share by reference between threads. It gives each
/// acquisition a unique sample identity.
#[derive(Debug)]
pub struct CollectionContext {
    identity: ContextIdentity,
    clock: Arc<dyn Clock>,
    next_sample: AtomicU64,
    pub(crate) adapters: AdapterIds,
}

impl CollectionContext {
    /// Makes a context from explicit identities and a clock.
    ///
    /// # Errors
    ///
    /// Returns a [`ContextError`] when the collector epoch is too long.
    pub fn new(identity: ContextIdentity, clock: Arc<dyn Clock>) -> Result<Self, ContextError> {
        if identity.collector_epoch.as_str().len() > MAX_COLLECTOR_EPOCH_LENGTH {
            return Err(ContextError::CollectorEpochTooLong);
        }
        Ok(Self {
            identity,
            clock,
            next_sample: AtomicU64::new(0),
            adapters: AdapterIds::new()?,
        })
    }

    /// Makes the context of this process on the host clock.
    ///
    /// The boot identity is `kern.bootsessionuuid`. The worker identity has
    /// the process ID. The collector epoch has the process ID and the
    /// monotonic time of this call, so each call makes a new epoch. The host
    /// identity is the constant `host_local`: the record of the machine that
    /// the collector runs on.
    ///
    /// # Errors
    ///
    /// Returns a [`ContextError`] when the boot identity or the clock is not
    /// available.
    pub fn for_current_process() -> Result<Self, ContextError> {
        let clock = SystemClock;
        let boot_uuid: String =
            native::boot_session_uuid().map_err(ContextError::BootIdentityUnavailable)?;
        let started: MonotonicNanos = clock.monotonic_now()?;
        let process_id: u32 = std::process::id();
        let identity = ContextIdentity {
            host: IdentityId::new("host_local")?,
            worker_id: WorkerId::new(format!("worker_{process_id}"))?,
            boot_id: BootId::new(format!("boot_{boot_uuid}"))?,
            collector_epoch: CollectorEpochId::new(format!(
                "epoch_{process_id}_{:x}",
                started.get()
            ))?,
            clock_domain: SystemClock::clock_domain()?,
        };
        Self::new(identity, Arc::new(clock))
    }

    /// The identities of this context.
    pub fn identity(&self) -> &ContextIdentity {
        &self.identity
    }

    /// The clock of this context.
    pub fn clock(&self) -> &Arc<dyn Clock> {
        &self.clock
    }

    /// The sleep time of the host at this call, for a rate interval.
    pub fn sleep_time(&self) -> Reading<Nanoseconds> {
        sleep::sleep_reading(self.clock.sleep_time())
    }

    /// The cumulative sleep time of the host as the observation
    /// `host.sleep_time_ns`, for the evidence of a sleep boundary between
    /// two stored samples (`docs/RESOURCE_MODEL.md` section 6).
    ///
    /// A sleep time that the clock cannot give is an unavailable
    /// observation: it is no evidence that the host did not sleep.
    ///
    /// # Errors
    ///
    /// Returns a [`CollectError`] when the clock gives no acquisition
    /// window.
    pub fn sleep_time_observation(&self) -> Result<Observation<Nanoseconds>, CollectError> {
        let acquisition = self.begin()?;
        let reading: Reading<Nanoseconds> = self.sleep_time();
        let sample: Sample = self.finish(acquisition)?;
        Ok(self.observation(
            MetricSpec::new(
                metric::HOST_SLEEP_TIME_NS,
                Unit::Nanosecond,
                MetricKind::Counter,
            ),
            self.host_scope(),
            reading,
            Provenance {
                adapter: &self.adapters.sleep,
                native_api: "clock_gettime",
                native_field: "CLOCK_MONOTONIC_RAW - CLOCK_UPTIME_RAW",
            },
            &sample,
        ))
    }

    /// The scope of a host metric.
    pub fn host_scope(&self) -> Scope {
        Scope {
            kind: ScopeKind::Host,
            identity_id: self.identity.host.clone(),
        }
    }

    /// Starts an acquisition window.
    pub(crate) fn begin(&self) -> Result<Acquisition, CollectError> {
        Ok(Acquisition {
            started: self.clock.monotonic_now()?,
        })
    }

    /// Finishes an acquisition window and makes its sample.
    pub(crate) fn finish(&self, acquisition: Acquisition) -> Result<Sample, CollectError> {
        let finished: MonotonicNanos = self.clock.monotonic_now()?;
        // A clock that goes back is not monotonic: the window is not valid.
        if finished < acquisition.started {
            return Err(CollectError::Clock(ClockError::MonotonicUnavailable));
        }
        self.sample(acquisition.started, finished, self.clock.wall_now()?)
    }

    /// Makes the sample of an acquisition with known times.
    pub(crate) fn sample(
        &self,
        started: MonotonicNanos,
        finished: MonotonicNanos,
        captured_at: WallTime,
    ) -> Result<Sample, CollectError> {
        let sequence: u64 = self.next_sample.fetch_add(1, Ordering::Relaxed);
        let sample_id = SampleId::new(format!(
            "sample_{}_{sequence:x}",
            self.identity.collector_epoch
        ))?;
        Ok(Sample {
            sample_id,
            clock_domain: self.identity.clock_domain.clone(),
            boot_id: self.identity.boot_id.clone(),
            collector_epoch: self.identity.collector_epoch.clone(),
            started_monotonic_ns: started,
            finished_monotonic_ns: finished,
            captured_at,
        })
    }

    /// Makes one observation. The coverage is complete for an available
    /// reading and unknown for a reading with no value.
    pub(crate) fn observation<T>(
        &self,
        spec: MetricSpec,
        scope: Scope,
        reading: Reading<T>,
        provenance: Provenance<'_>,
        sample: &Sample,
    ) -> Observation<T> {
        let coverage: Coverage = if reading.is_available() {
            Coverage::Complete
        } else {
            Coverage::Unknown
        };
        Observation {
            metric_id: spec.id,
            scope,
            reading,
            unit: spec.unit,
            kind: spec.kind,
            coverage,
            source: Source {
                adapter_id: provenance.adapter.clone(),
                adapter_revision: ADAPTER_REVISION.to_owned(),
                native_api: provenance.native_api.to_owned(),
                native_field: provenance.native_field.to_owned(),
                worker_id: self.identity.worker_id.clone(),
            },
            sample: sample.clone(),
        }
    }
}

/// Converts the result of a native query to a reading.
pub(crate) fn reading_from<T>(result: Result<T, UnavailableReason>) -> Reading<T> {
    match result {
        Ok(value) => Reading::Available(value),
        Err(reason) => Reading::Unavailable(reason),
    }
}

/// A controlled clock and a context for tests.
#[cfg(test)]
pub(crate) mod testing {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use svalnir_core::id::{BootId, ClockDomainId, CollectorEpochId, IdentityId, WorkerId};
    use svalnir_core::observation::{Sample, UnavailableReason};
    use svalnir_core::quantity::Nanoseconds;
    use svalnir_core::time::{MonotonicNanos, WallTime};

    use super::{Clock, ClockError, CollectionContext, ContextIdentity};

    /// A clock that a test moves. Each read of the monotonic time also adds
    /// `step` nanoseconds. The sleep time is zero until a test sets it.
    #[derive(Debug)]
    pub(crate) struct ManualClock {
        now: AtomicU64,
        step: u64,
        slept: AtomicU64,
    }

    impl ManualClock {
        pub(crate) fn new(now: u64, step: u64) -> Self {
            Self {
                now: AtomicU64::new(now),
                step,
                slept: AtomicU64::new(0),
            }
        }

        /// Sets the cumulative sleep time of the host.
        pub(crate) fn set_slept(&self, slept: u64) {
            self.slept.store(slept, Ordering::SeqCst);
        }

        pub(crate) fn set(&self, now: u64) {
            self.now.store(now, Ordering::SeqCst);
        }
    }

    impl Clock for ManualClock {
        fn monotonic_now(&self) -> Result<MonotonicNanos, ClockError> {
            Ok(MonotonicNanos::new(
                self.now.fetch_add(self.step, Ordering::SeqCst),
            ))
        }

        fn wall_now(&self) -> Result<WallTime, ClockError> {
            Ok(WallTime::UNIX_EPOCH)
        }

        fn sleep_time(&self) -> Result<Nanoseconds, UnavailableReason> {
            Ok(Nanoseconds::new(self.slept.load(Ordering::SeqCst)))
        }
    }

    pub(crate) fn identity(boot: &str, epoch: &str, clock_domain: &str) -> ContextIdentity {
        ContextIdentity {
            host: IdentityId::new("host_test").unwrap(),
            worker_id: WorkerId::new("worker_test").unwrap(),
            boot_id: BootId::new(boot).unwrap(),
            collector_epoch: CollectorEpochId::new(epoch).unwrap(),
            clock_domain: ClockDomainId::new(clock_domain).unwrap(),
        }
    }

    /// A context on a manual clock that starts at one second and adds one
    /// millisecond at each read.
    pub(crate) fn context() -> (CollectionContext, Arc<ManualClock>) {
        context_with(identity("boot_test", "epoch_test", "clock_test"))
    }

    pub(crate) fn context_with(identity: ContextIdentity) -> (CollectionContext, Arc<ManualClock>) {
        let clock = Arc::new(ManualClock::new(1_000_000_000, 1_000_000));
        let context = CollectionContext::new(identity, clock.clone()).unwrap();
        (context, clock)
    }

    /// A sample of `context` that starts at `started` and takes one
    /// millisecond.
    pub(crate) fn sample_at(context: &CollectionContext, started: u64) -> Sample {
        context
            .sample(
                MonotonicNanos::new(started),
                MonotonicNanos::new(started + 1_000_000),
                WallTime::UNIX_EPOCH,
            )
            .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::sync::Arc;

    use svalnir_core::id::CollectorEpochId;
    use svalnir_core::observation::ScopeKind;
    use svalnir_core::quantity::Nanoseconds;

    #[cfg(target_os = "macos")]
    use super::Clock;
    use super::testing::{self, ManualClock};
    use super::{
        AdapterIds, ClockError, CollectError, CollectionContext, ContextError, SystemClock,
    };

    #[test]
    fn the_constant_identities_are_valid() {
        AdapterIds::new().unwrap();
        SystemClock::clock_domain().unwrap();
    }

    #[test]
    fn each_acquisition_has_a_unique_sample_and_an_ordered_window() {
        let (context, _clock) = testing::context();
        let mut seen = HashSet::new();
        for _ in 0..50 {
            let acquisition = context.begin().unwrap();
            let sample = context.finish(acquisition).unwrap();
            assert_eq!(
                sample.acquisition_duration(),
                Some(Nanoseconds::new(1_000_000))
            );
            assert_eq!(sample.boot_id.as_str(), "boot_test");
            assert_eq!(sample.collector_epoch.as_str(), "epoch_test");
            assert_eq!(sample.clock_domain.as_str(), "clock_test");
            assert!(seen.insert(sample.sample_id));
        }
        assert_eq!(context.host_scope().kind, ScopeKind::Host);
    }

    #[test]
    fn a_clock_that_goes_back_makes_no_sample() {
        let (context, clock) = testing::context();
        let acquisition = context.begin().unwrap();
        clock.set(5);
        assert_eq!(
            context.finish(acquisition),
            Err(CollectError::Clock(ClockError::MonotonicUnavailable))
        );
    }

    #[test]
    fn a_long_collector_epoch_is_rejected() {
        let mut identity = testing::identity("boot_test", "epoch_test", "clock_test");
        identity.collector_epoch = CollectorEpochId::new("e".repeat(97)).unwrap();
        let clock = Arc::new(ManualClock::new(0, 1));
        assert_eq!(
            CollectionContext::new(identity.clone(), clock.clone()).unwrap_err(),
            ContextError::CollectorEpochTooLong
        );
        // The longest permitted epoch gives a sample identity that fits.
        identity.collector_epoch = CollectorEpochId::new("e".repeat(96)).unwrap();
        let context = CollectionContext::new(identity, clock).unwrap();
        let acquisition = context.begin().unwrap();
        context.finish(acquisition).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_host_clock_is_monotonic_and_the_process_context_is_made() {
        let clock = SystemClock;
        let first = clock.monotonic_now().unwrap();
        let second = clock.monotonic_now().unwrap();
        assert!(second >= first);
        clock.wall_now().unwrap();

        let first = CollectionContext::for_current_process().unwrap();
        let second = CollectionContext::for_current_process().unwrap();
        assert_eq!(first.identity().boot_id, second.identity().boot_id);
        assert_eq!(first.identity().worker_id, second.identity().worker_id);
        assert!(first.identity().boot_id.as_str().starts_with("boot_"));
        let sample = first.finish(first.begin().unwrap()).unwrap();
        assert!(sample.acquisition_duration().is_some());
    }
}
