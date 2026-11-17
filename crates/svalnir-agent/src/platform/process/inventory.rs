//! The process inventory: identity, metrics, and application attribution.
//!
//! One collection has four steps:
//!
//! 1. Read the process list and, for each process of the current user, the
//!    identity evidence, the executable, and the resource use.
//! 2. Read the running applications and the responsible-process
//!    relationships.
//! 3. Read the identity evidence of each process again. A process that
//!    exited, or whose evidence changed, is dropped from the snapshot. Thus
//!    each query of steps 1 and 2 ran between two readings that show the
//!    same process generation, and no record has the data of a different
//!    process that got the same PID.
//! 4. Attribute the processes that remain.
//!
//! The list of running applications can be older than the collection:
//! `NSWorkspace` refreshes it, and the active state of each entry, only when
//! the main run loop of the process runs. The macOS source lets the main run
//! loop run before each list after the first one
//! ([`turn_main_run_loop`](crate::platform::run_loop::turn_main_run_loop)).
//! A collector on a thread that is not the main thread, in a process whose
//! main thread does not run its run loop, reads the list of its first call.
//! An entry gives a
//! membership only when its executable path is the path of the recorded
//! process, so a new process that got the PID of an application that quit
//! does not get the membership. The source says whether the list is known to
//! be current ([`ProcessSource::application_list_current`]). When it is not,
//! each foreground state is [`ForegroundState::Unknown`] and
//! [`ProcessSnapshot::application_list_may_be_stale`] is set: an application
//! that launched later can be `Unattributed`, and the active state is not
//! fresh.

use std::collections::BTreeMap;

use svalnir_core::file::LosslessPath;
use svalnir_core::id::{
    AdapterId, ApplicationInstanceId, BootId, ClockDomainId, CollectorEpochId, IdError,
    ProcessGenerationId, SampleId, WorkerId,
};
use svalnir_core::observation::{
    Coverage, MetricId, MetricIdError, MetricKind, Observation, Reading, Sample, Scope, Source,
    UnavailableReason, Unit, metric,
};
use svalnir_core::process::{
    AttributionMethod, ExecutableIdentity, Pid, ProcessAssociation, ProcessIdentity,
    ProcessStartTime, Uid, VerifiedMembership,
};
use svalnir_core::quantity::{Bytes, CounterValue, Nanoseconds};
use svalnir_core::time::{MonotonicNanos, WallTime};

use crate::platform::sleep::{bracketed_sleep_reading, sleep_reading};
use thiserror::Error;

use super::source::{
    ProcessSource, QueryFailure, RawProcessInfo, RawUsage, RunningApplication, Timebase,
};

/// The clock domain of each sample of this adapter:
/// `clock_gettime(CLOCK_MONOTONIC_RAW)`, which continues during sleep.
///
/// The text is that of the memory and volume adapters
/// (`SystemClock::clock_domain`), which read the same clock. One clock has
/// one domain identity: a policy evaluation rejects an observation whose
/// clock domain is not that of the evaluation.
pub const CLOCK_DOMAIN: &str = "macos.clock_monotonic_raw";

/// The adapter identity in the source of each observation.
pub const ADAPTER_ID: &str = "svalnir.process.darwin";

/// The adapter revision in the source of each observation.
pub const ADAPTER_REVISION: &str = "1";

/// The metric name of the cumulative bytes that a process read from disk.
///
/// `docs/RESOURCE_MODEL.md` does not register this name yet.
pub const DISK_READ_METRIC: &str = "process.disk_read_bytes_total";

/// The metric name of the cumulative bytes that a process wrote to disk.
///
/// `docs/RESOURCE_MODEL.md` does not register this name yet.
pub const DISK_WRITTEN_METRIC: &str = "process.disk_written_bytes_total";

const RUSAGE_API: &str = "proc_pid_rusage(RUSAGE_INFO_V4)";

/// The reason a collection gave no snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CollectError {
    /// An identity text is not valid.
    #[error("an identity is not valid: {0}")]
    Id(#[from] IdError),
    /// A metric name is not valid.
    #[error("a metric name is not valid: {0}")]
    Metric(#[from] MetricIdError),
    /// A clock gave no value, so no sample can be recorded.
    #[error("a clock gave no value: {0}")]
    Clock(#[source] QueryFailure),
    /// The kernel gave no process list.
    #[error("the kernel gave no process list: {0}")]
    ProcessList(#[source] QueryFailure),
    /// The host gave no boot session identity.
    #[error("the host gave no boot session identity: {0}")]
    BootSession(#[source] QueryFailure),
}

/// The collector identity that each sample records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectionContext {
    /// The process that collects.
    pub worker_id: WorkerId,
    /// The current boot.
    pub boot_id: BootId,
    /// The lifetime of this collector.
    pub collector_epoch: CollectorEpochId,
}

/// Whether the application of a process is the frontmost application.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ForegroundState {
    /// The process belongs to the active application.
    Foreground,
    /// The process belongs to an application that is not the active
    /// application.
    Background,
    /// The process has no verified application, so no foreground evidence
    /// applies to it. This state is not `Background`.
    Unknown,
}

/// The measurements of one process generation from one acquisition.
///
/// The observations share one sample. Physical footprint and resident size
/// are different quantities from different native fields. A failed query
/// makes each affected observation unavailable with its reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessMetrics {
    /// `process.footprint_bytes`, from `ri_phys_footprint`.
    pub footprint: Observation<Bytes>,
    /// `process.resident_bytes`, from `ri_resident_size`.
    pub resident: Observation<Bytes>,
    /// `process.peak_footprint_bytes`, from `ri_lifetime_max_phys_footprint`.
    /// The peak is over the lifetime of the process.
    pub peak_footprint: Observation<Bytes>,
    /// `process.cpu_time_ns`: user time plus system time, converted from
    /// Mach absolute-time units with `mach_timebase_info`.
    pub cpu_time: Observation<CounterValue>,
    /// [`DISK_READ_METRIC`], from `ri_diskio_bytesread`.
    pub disk_read: Observation<CounterValue>,
    /// [`DISK_WRITTEN_METRIC`], from `ri_diskio_byteswritten`.
    pub disk_written: Observation<CounterValue>,
}

impl ProcessMetrics {
    /// The sample that the observations share.
    pub fn sample(&self) -> &Sample {
        &self.footprint.sample
    }
}

/// One process generation in a snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessRecord {
    /// The identity. `identity.uid` is the effective user ID. The file
    /// evidence of the executable is the file object that is at the path at
    /// collection time. After an update of the application, that object can
    /// be a different file from the image that the process runs.
    pub identity: ProcessIdentity,
    /// The real user ID.
    pub real_uid: Uid,
    /// The parent process ID at collection time. It is a PID, not an
    /// identity, and parentage is not application membership.
    pub parent_pid: Option<Pid>,
    /// The reason there is no executable path, when `identity.executable` is
    /// `None`.
    pub executable_unavailable: Option<UnavailableReason>,
    /// The reason the file evidence of the executable was not read, when the
    /// executable path is known and `identity.executable` has no file
    /// evidence. A consumer can tell a denied query from evidence that was
    /// not collected.
    pub executable_file_unavailable: Option<UnavailableReason>,
    /// Whether the application of the process is frontmost.
    pub foreground: ForegroundState,
    /// The measurements.
    pub metrics: ProcessMetrics,
}

impl ProcessRecord {
    /// A label for display: the last component of the executable path.
    ///
    /// The label is presentation data. Do not use it to select, group, or
    /// address a process.
    pub fn display_label(&self) -> Option<String> {
        let executable: &ExecutableIdentity = self.identity.executable.as_ref()?;
        let name: &[u8] = executable
            .path
            .as_bytes()
            .rsplit(|byte| *byte == b'/')
            .next()?;
        if name.is_empty() {
            return None;
        }
        Some(String::from_utf8_lossy(name).into_owned())
    }
}

/// The processes that a collection found and did not record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Omissions {
    /// Processes of a different effective user. The ordinary inventory does
    /// not record them.
    pub other_user: usize,
    /// Processes whose identity query was denied.
    pub permission_denied: usize,
    /// Processes that exited before or during the collection, and zombies.
    pub exited: usize,
    /// Processes whose identity evidence changed during the collection, for
    /// example a new process with the same PID.
    pub identity_changed: usize,
    /// Processes whose identity query failed for a different cause.
    pub failed: usize,
}

/// The process inventory at one time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessSnapshot {
    /// The boot of the snapshot.
    pub boot_id: BootId,
    /// The clock domain of the monotonic timestamps.
    pub clock_domain: ClockDomainId,
    /// When the collection started.
    pub started_monotonic_ns: MonotonicNanos,
    /// When the collection finished.
    pub finished_monotonic_ns: MonotonicNanos,
    /// The wall-clock time of the collection, for display.
    pub captured_at: WallTime,
    /// The cumulative sleep time of the host during the collection. It has
    /// no value when the host slept during the collection. A CPU use between two snapshots with different sleep times has a sleep
    /// in its interval.
    pub sleep_time: Reading<Nanoseconds>,
    /// The recorded processes, in PID order.
    pub records: Vec<ProcessRecord>,
    /// The processes that were found and not recorded.
    pub omissions: Omissions,
    /// The reason the running applications were not read. When it is set,
    /// no process has an application attribution.
    pub launch_services_unavailable: Option<UnavailableReason>,
    /// The application list is not known to be current. A process with no
    /// attribution can belong to an application that launched after the list
    /// was read, and each foreground state is `Unknown`. A consumer must not
    /// treat `Unattributed` or the foreground state as fresh.
    pub application_list_may_be_stale: bool,
    /// The reason the responsible-process relationship was not read for one
    /// or more processes. Those processes have no `responsible_process`
    /// attribution.
    pub responsible_process_unavailable: Option<UnavailableReason>,
}

impl ProcessSnapshot {
    /// The record of a process generation.
    pub fn find_generation(&self, generation_id: &ProcessGenerationId) -> Option<&ProcessRecord> {
        self.records
            .iter()
            .find(|record| &record.identity.generation_id == generation_id)
    }

    /// The record of the process that had this PID at collection time.
    ///
    /// The PID is a lookup key for this snapshot only. Use the identity of
    /// the record, not the PID, in a later operation.
    pub fn find_pid(&self, pid: Pid) -> Option<&ProcessRecord> {
        self.records
            .binary_search_by_key(&pid, |record| record.identity.pid)
            .ok()
            .and_then(|index| self.records.get(index))
    }

    /// The processes with a verified membership in an application instance.
    pub fn members_of(&self, instance_id: &ApplicationInstanceId) -> Vec<&ProcessRecord> {
        self.records
            .iter()
            .filter(|record| {
                matches!(
                    record.identity.association.verified_membership(),
                    Some(VerifiedMembership::Application { instance_id: found, .. })
                        if found == instance_id
                )
            })
            .collect()
    }
}

/// The data of one process between its first and its last identity reading.
struct Pending {
    info: RawProcessInfo,
    executable: Result<ExecutableIdentity, QueryFailure>,
    file_unavailable: Option<UnavailableReason>,
    usage: Result<RawUsage, QueryFailure>,
    usage_started: MonotonicNanos,
    usage_finished: MonotonicNanos,
}

/// A running application whose registered process is in the snapshot.
struct RegisteredApplication {
    instance_id: ApplicationInstanceId,
    bundle_identifier: String,
    start_time: ProcessStartTime,
    active: bool,
}

/// Collects process snapshots from a [`ProcessSource`].
#[derive(Debug, Clone)]
pub struct ProcessCollector<S> {
    source: S,
    context: CollectionContext,
    adapter_id: AdapterId,
    clock_domain: ClockDomainId,
    disk_read_metric: MetricId,
    disk_written_metric: MetricId,
}

impl<S: ProcessSource> ProcessCollector<S> {
    /// Makes a collector.
    ///
    /// # Errors
    ///
    /// Returns a [`CollectError`] when a fixed identity or metric name of
    /// the adapter is not valid.
    pub fn new(source: S, context: CollectionContext) -> Result<Self, CollectError> {
        Ok(Self {
            source,
            context,
            adapter_id: AdapterId::new(ADAPTER_ID)?,
            clock_domain: ClockDomainId::new(CLOCK_DOMAIN)?,
            disk_read_metric: MetricId::new(DISK_READ_METRIC)?,
            disk_written_metric: MetricId::new(DISK_WRITTEN_METRIC)?,
        })
    }

    /// The source of the collector.
    pub fn source(&self) -> &S {
        &self.source
    }

    /// Collects the processes of the current effective user.
    ///
    /// The call reads data only. It sends no signal and changes no process.
    ///
    /// # Errors
    ///
    /// Returns a [`CollectError`] when a clock or the process list gives no
    /// value. A failure for one process does not fail the collection: the
    /// process is counted in [`Omissions`], or its observation is
    /// unavailable with a reason.
    pub fn collect(&self) -> Result<ProcessSnapshot, CollectError> {
        let started: MonotonicNanos = self.now()?;
        let captured_at: WallTime = self.source.wall_now().map_err(CollectError::Clock)?;
        // The sleep time is read here and again after the last process, so a
        // sleep during the collection gives no sleep time.
        let sleep_before: Reading<Nanoseconds> = sleep_reading(self.source.sleep_time());
        let timebase: Result<Timebase, QueryFailure> = self.source.timebase();
        let mut pids: Vec<Pid> = self.source.list_pids().map_err(CollectError::ProcessList)?;
        pids.sort_unstable();
        pids.dedup();

        let mut omissions: Omissions = Omissions::default();
        let mut pending: BTreeMap<Pid, Pending> = BTreeMap::new();
        for pid in pids {
            if let Some(entry) = self.read_process(pid, &mut omissions)? {
                pending.insert(pid, entry);
            }
        }

        let list_current: bool = self.source.application_list_current();
        let applications: Result<Vec<RunningApplication>, QueryFailure> =
            self.source.running_applications();
        let mut responsible_unavailable: Option<UnavailableReason> = None;
        let mut responsible: BTreeMap<Pid, Pid> = BTreeMap::new();
        for pid in pending.keys() {
            match self.source.responsible_pid(*pid) {
                Ok(owner) => {
                    responsible.insert(*pid, owner);
                }
                // The process exited. The last identity reading drops it.
                Err(QueryFailure::Gone) => {}
                Err(failure) => {
                    responsible_unavailable.get_or_insert(failure.reason());
                }
            }
        }

        // The last identity reading. After it, each entry is one process
        // generation for the full time of the queries above.
        pending.retain(|pid, entry| self.is_same_generation(*pid, entry, &mut omissions));

        let registered: BTreeMap<Pid, RegisteredApplication> = match &applications {
            Ok(list) => registered_applications(list, &pending)?,
            Err(_) => BTreeMap::new(),
        };
        let owners: BTreeMap<Pid, Pid> = responsible_owners(&pending, &responsible, &registered);
        let mut records: Vec<ProcessRecord> = Vec::with_capacity(pending.len());
        for (pid, entry) in &pending {
            let owner: Option<&RegisteredApplication> =
                owners.get(pid).and_then(|owner| registered.get(owner));
            let (association, mut foreground) = associate(registered.get(pid), owner);
            if !list_current {
                foreground = ForegroundState::Unknown;
            }
            records.push(self.record(entry, association, foreground, captured_at, timebase)?);
        }

        let sleep_time: Reading<Nanoseconds> =
            bracketed_sleep_reading(&sleep_before, sleep_reading(self.source.sleep_time()));
        Ok(ProcessSnapshot {
            boot_id: self.context.boot_id.clone(),
            clock_domain: self.clock_domain.clone(),
            started_monotonic_ns: started,
            finished_monotonic_ns: self.now()?,
            captured_at,
            sleep_time,
            records,
            omissions,
            launch_services_unavailable: applications.err().map(QueryFailure::reason),
            application_list_may_be_stale: !list_current,
            responsible_process_unavailable: responsible_unavailable,
        })
    }

    fn now(&self) -> Result<MonotonicNanos, CollectError> {
        self.source.monotonic_now().map_err(CollectError::Clock)
    }

    /// Reads the first identity evidence and the data of one process.
    /// Returns `None` for a process that the inventory does not record.
    fn read_process(
        &self,
        pid: Pid,
        omissions: &mut Omissions,
    ) -> Result<Option<Pending>, CollectError> {
        let info: RawProcessInfo = match self.source.process_info(pid) {
            Ok(info) => info,
            Err(failure) => {
                match failure {
                    QueryFailure::Gone => omissions.exited += 1,
                    QueryFailure::PermissionDenied => omissions.permission_denied += 1,
                    _ => omissions.failed += 1,
                }
                return Ok(None);
            }
        };
        if info.pid != pid {
            omissions.failed += 1;
            return Ok(None);
        }
        if info.zombie {
            omissions.exited += 1;
            return Ok(None);
        }
        if info.effective_uid != self.source.effective_uid() {
            omissions.other_user += 1;
            return Ok(None);
        }

        let mut file_unavailable: Option<UnavailableReason> = None;
        let executable: Result<ExecutableIdentity, QueryFailure> =
            self.source.executable_path(pid).map(|path| {
                let file = match self.source.file_evidence(&path) {
                    Ok(file) => Some(file),
                    Err(failure) => {
                        file_unavailable = Some(failure.reason());
                        None
                    }
                };
                ExecutableIdentity {
                    path,
                    file,
                    code_signature: None,
                }
            });
        let usage_started: MonotonicNanos = self.now()?;
        let usage: Result<RawUsage, QueryFailure> = self.source.usage(pid);
        let usage_finished: MonotonicNanos = self.now()?;
        Ok(Some(Pending {
            info,
            executable,
            file_unavailable,
            usage,
            usage_started,
            usage_finished,
        }))
    }

    /// Reads the identity evidence again and compares it with the first
    /// reading.
    fn is_same_generation(&self, pid: Pid, entry: &Pending, omissions: &mut Omissions) -> bool {
        let first: &RawProcessInfo = &entry.info;
        // An `exec` keeps the PID and the start time and changes the
        // executable. A record must not have the path of one program image
        // and the measurements of a different one.
        let path_now: Option<LosslessPath> = self.source.executable_path(pid).ok();
        let same_executable: bool = path_now.as_ref()
            == entry
                .executable
                .as_ref()
                .ok()
                .map(|executable| &executable.path);
        match self.source.process_info(pid) {
            Ok(last) => {
                let same: bool = same_executable
                    && !last.zombie
                    && last.pid == first.pid
                    && last.start_time == first.start_time
                    && last.effective_uid == first.effective_uid
                    && last.real_uid == first.real_uid;
                if !same && last.zombie && last.start_time == first.start_time {
                    omissions.exited += 1;
                } else if !same {
                    omissions.identity_changed += 1;
                }
                same
            }
            Err(QueryFailure::Gone) => {
                omissions.exited += 1;
                false
            }
            Err(_) => {
                // The evidence cannot be confirmed, so the record is not
                // kept.
                omissions.failed += 1;
                false
            }
        }
    }

    fn record(
        &self,
        entry: &Pending,
        association: ProcessAssociation,
        foreground: ForegroundState,
        captured_at: WallTime,
        timebase: Result<Timebase, QueryFailure>,
    ) -> Result<ProcessRecord, CollectError> {
        let generation_id: ProcessGenerationId =
            generation_id(entry.info.pid, entry.info.start_time)?;
        let sample: Sample = Sample {
            sample_id: SampleId::new(format!(
                "ps-{}-{}",
                entry.usage_started.get(),
                entry.info.pid.get()
            ))?,
            clock_domain: self.clock_domain.clone(),
            boot_id: self.context.boot_id.clone(),
            collector_epoch: self.context.collector_epoch.clone(),
            started_monotonic_ns: entry.usage_started,
            // A clock that goes back is not expected. The sample must not
            // finish before it starts.
            finished_monotonic_ns: entry.usage_finished.max(entry.usage_started),
            captured_at,
        };
        let metrics: ProcessMetrics = self.metrics(&generation_id, &sample, entry.usage, timebase);
        Ok(ProcessRecord {
            identity: ProcessIdentity {
                generation_id,
                pid: entry.info.pid,
                start_time: entry.info.start_time,
                uid: entry.info.effective_uid,
                boot_id: self.context.boot_id.clone(),
                executable: entry.executable.clone().ok(),
                association,
            },
            real_uid: entry.info.real_uid,
            parent_pid: entry.info.parent_pid,
            executable_unavailable: entry
                .executable
                .as_ref()
                .err()
                .map(|failure| failure.reason()),
            executable_file_unavailable: entry.file_unavailable.clone(),
            foreground,
            metrics,
        })
    }

    fn metrics(
        &self,
        generation_id: &ProcessGenerationId,
        sample: &Sample,
        usage: Result<RawUsage, QueryFailure>,
        timebase: Result<Timebase, QueryFailure>,
    ) -> ProcessMetrics {
        let bytes = |field: fn(&RawUsage) -> u64| -> Reading<Bytes> {
            match usage {
                Ok(usage) => Reading::Available(Bytes::new(field(&usage))),
                Err(failure) => Reading::Unavailable(failure.reason()),
            }
        };
        let counter = |field: fn(&RawUsage) -> u64| -> Reading<CounterValue> {
            bytes(field).map(|value| CounterValue::new(value.get()))
        };
        let cpu_time: Reading<CounterValue> = match (usage, timebase) {
            (Err(failure), _) | (Ok(_), Err(failure)) => Reading::Unavailable(failure.reason()),
            (Ok(usage), Ok(timebase)) => usage
                .user_time_mach
                .checked_add(usage.system_time_mach)
                .and_then(|units| timebase.to_nanoseconds(units))
                .map_or(Reading::Unavailable(UnavailableReason::Overflow), |value| {
                    Reading::Available(CounterValue::new(value))
                }),
        };
        let observe = Observer {
            collector: self,
            generation_id,
            sample,
        };
        ProcessMetrics {
            footprint: observe.gauge(
                metric::PROCESS_FOOTPRINT_BYTES,
                "ri_phys_footprint",
                bytes(|usage| usage.physical_footprint),
            ),
            resident: observe.gauge(
                metric::PROCESS_RESIDENT_BYTES,
                "ri_resident_size",
                bytes(|usage| usage.resident_size),
            ),
            peak_footprint: observe.gauge(
                metric::PROCESS_PEAK_FOOTPRINT_BYTES,
                "ri_lifetime_max_phys_footprint",
                bytes(|usage| usage.lifetime_max_physical_footprint),
            ),
            cpu_time: observe.counter(
                metric::PROCESS_CPU_TIME_NS,
                "(ri_user_time + ri_system_time) * mach_timebase_info",
                Unit::Nanosecond,
                cpu_time,
            ),
            disk_read: observe.counter(
                self.disk_read_metric.clone(),
                "ri_diskio_bytesread",
                Unit::Byte,
                counter(|usage| usage.disk_bytes_read),
            ),
            disk_written: observe.counter(
                self.disk_written_metric.clone(),
                "ri_diskio_byteswritten",
                Unit::Byte,
                counter(|usage| usage.disk_bytes_written),
            ),
        }
    }
}

/// Makes the observations of one process generation and one sample.
struct Observer<'a, S> {
    collector: &'a ProcessCollector<S>,
    generation_id: &'a ProcessGenerationId,
    sample: &'a Sample,
}

impl<S> Observer<'_, S> {
    fn gauge(
        &self,
        metric_id: MetricId,
        field: &str,
        reading: Reading<Bytes>,
    ) -> Observation<Bytes> {
        self.observation(metric_id, field, Unit::Byte, MetricKind::Gauge, reading)
    }

    fn counter(
        &self,
        metric_id: MetricId,
        field: &str,
        unit: Unit,
        reading: Reading<CounterValue>,
    ) -> Observation<CounterValue> {
        self.observation(metric_id, field, unit, MetricKind::Counter, reading)
    }

    fn observation<T>(
        &self,
        metric_id: MetricId,
        field: &str,
        unit: Unit,
        kind: MetricKind,
        reading: Reading<T>,
    ) -> Observation<T> {
        Observation {
            metric_id,
            scope: Scope::process(self.generation_id.clone()),
            reading,
            unit,
            kind,
            coverage: Coverage::Complete,
            source: Source {
                adapter_id: self.collector.adapter_id.clone(),
                adapter_revision: ADAPTER_REVISION.to_owned(),
                native_api: RUSAGE_API.to_owned(),
                native_field: field.to_owned(),
                worker_id: self.collector.context.worker_id.clone(),
            },
            sample: self.sample.clone(),
        }
    }
}

/// The identity of a process generation.
///
/// The text has the PID and the start time, so two collections give the same
/// identity for the same generation and a restarted process gets a new one.
/// A consumer must treat the text as opaque. The text gives no authority:
/// an operation compares the evidence in the [`ProcessIdentity`].
///
/// # Errors
///
/// Returns an [`IdError`] when the text is not a valid identity. The format
/// is fixed, so this error is not expected.
pub fn generation_id(
    pid: Pid,
    start_time: ProcessStartTime,
) -> Result<ProcessGenerationId, IdError> {
    ProcessGenerationId::new(format!("pg-{}-{}", pid.get(), start_time.get()))
}

/// The running applications whose registered process is a recorded process
/// generation with the same executable path.
fn registered_applications(
    applications: &[RunningApplication],
    pending: &BTreeMap<Pid, Pending>,
) -> Result<BTreeMap<Pid, RegisteredApplication>, IdError> {
    let mut registered: BTreeMap<Pid, RegisteredApplication> = BTreeMap::new();
    for application in applications {
        if application.terminated || registered.contains_key(&application.pid) {
            continue;
        }
        // An application with no bundle identifier cannot be recorded as an
        // application association. Its process stays unattributed.
        let (Some(bundle_identifier), Some(entry)) = (
            application.bundle_identifier.as_ref(),
            pending.get(&application.pid),
        ) else {
            continue;
        };
        // The list can be older than this collection, so the PID of an
        // entry can now be the PID of a different process. The entry is
        // evidence for the recorded generation only when the two executable
        // paths are the same.
        let recorded_path: Option<&LosslessPath> = entry
            .executable
            .as_ref()
            .ok()
            .map(|executable| &executable.path);
        if recorded_path.is_none() || recorded_path != application.executable_path.as_ref() {
            continue;
        }
        registered.insert(
            application.pid,
            RegisteredApplication {
                instance_id: ApplicationInstanceId::new(format!(
                    "app-{}-{}",
                    entry.info.pid.get(),
                    entry.info.start_time.get()
                ))?,
                bundle_identifier: bundle_identifier.clone(),
                start_time: entry.info.start_time,
                active: application.active,
            },
        );
    }
    Ok(registered)
}

/// The responsible application of each process, as a map from the PID of the
/// process to the PID of the registered application.
///
/// The kernel keeps the responsible process as a PID, and a child inherits
/// it, so the PID alone does not name one process after a PID reuse. A
/// process gets an owner only when
///
/// - the owner started no later than the process, and
/// - the parent chain supports the owner: the parent is the owner process
///   itself, or the parent is in the snapshot and has the same owner
///   instance, or the parent is `launchd` (PID 1).
///
/// A parent is evaluated before its children: the loop runs to a fixed point
/// and has at most one round for each process. A process that was
/// reparented to `launchd` after its parent exited keeps only the start-time
/// check, because the exited parent is not in the snapshot.
fn responsible_owners(
    pending: &BTreeMap<Pid, Pending>,
    responsible: &BTreeMap<Pid, Pid>,
    registered: &BTreeMap<Pid, RegisteredApplication>,
) -> BTreeMap<Pid, Pid> {
    let mut owners: BTreeMap<Pid, Pid> = BTreeMap::new();
    for _ in 0..=pending.len() {
        let mut changed: bool = false;
        for (pid, entry) in pending {
            if owners.contains_key(pid) || registered.contains_key(pid) {
                continue;
            }
            let Some((owner_pid, owner)) = responsible
                .get(pid)
                .filter(|owner| *owner != pid)
                .and_then(|owner| registered.get(owner).map(|found| (*owner, found)))
                .filter(|(_, owner)| owner.start_time <= entry.info.start_time)
            else {
                continue;
            };
            let supported: bool = match entry.info.parent_pid {
                Some(parent) if parent == owner_pid || parent.get() == 1 => true,
                Some(parent) => owners
                    .get(&parent)
                    .and_then(|found| registered.get(found))
                    .is_some_and(|found| found.instance_id == owner.instance_id),
                None => false,
            };
            if supported {
                owners.insert(*pid, owner_pid);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    owners
}

/// The association of a process from positive evidence only.
///
/// `own` is the application whose registered process is this process.
/// `responsible` is the application whose registered process the system
/// names as responsible for this process. With neither, the process is
/// unattributed and its foreground state is unknown.
fn associate(
    own: Option<&RegisteredApplication>,
    responsible: Option<&RegisteredApplication>,
) -> (ProcessAssociation, ForegroundState) {
    let (application, attribution) = match (own, responsible) {
        (Some(application), _) => (application, AttributionMethod::LaunchServices),
        (None, Some(application)) => (application, AttributionMethod::ResponsibleProcess),
        (None, None) => return (ProcessAssociation::Unattributed, ForegroundState::Unknown),
    };
    let foreground: ForegroundState = if application.active {
        ForegroundState::Foreground
    } else {
        ForegroundState::Background
    };
    (
        ProcessAssociation::Application {
            instance_id: application.instance_id.clone(),
            bundle_identifier: application.bundle_identifier.clone(),
            attribution,
        },
        foreground,
    )
}
