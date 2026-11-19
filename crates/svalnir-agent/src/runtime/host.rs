//! The implementations of the runtime interfaces for the running system.
//!
//! Nothing here runs in a test of the runtime: the tests inject a clock,
//! observations, and executors of a temporary directory. A function of
//! this module only reads the host, except the executors that
//! [`system_parts`] makes, which act only for an admitted step.

use std::fmt;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use svalnir_core::config::VolumeSelector;
use svalnir_core::file::LosslessPath;
use svalnir_core::id::{
    BootId, ClockDomainId, CollectorEpochId, ExecutorEpochId, LeaseId, OperationId, SampleId,
    VolumeId,
};
use svalnir_core::observation::{
    Coverage, MetricKind, Observation, Reading, Sample as ObservationSample, Scope, Source,
    UnavailableReason, Unit, metric,
};
use svalnir_core::policy::{
    ContinuityGeneration, CorroboratingEvidence, EvaluationClock, InventoryEvidence,
    MemorySnapshot, ProtectionContext, VolumeEvidence,
};
use svalnir_core::process::{Pid, Uid};
use svalnir_core::quantity::{Bytes, Nanoseconds};
use svalnir_core::state::PressureState;
use svalnir_core::time::{MonotonicNanos, WallTime};
use svalnir_core::volume::VolumeIdentity;
use thiserror::Error;

use super::candidates::RuleCandidateSource;
use super::driver::DriverParts;
use super::ports::{AgentClock, Collector, Notifier, Sample, SelfFootprint};
use super::record::CapabilitySummary;
use crate::capability::{CapabilityReport, WorkerRole, diagnose};
use crate::controller::Notification;
use crate::coordinator::{IdSource, Measurements, SystemProbe, TimeReading};
use crate::executor::fs::{ApprovedRoots, ExecutorLimits, FsExecutor, FsExecutorConfig};
use crate::executor::process::{
    DarwinProcessControl, ExecutorConfig, ExecutorContext, ProcessExecutor, SourceClock,
};
use crate::platform::memory::context::{Clock as HostClock, CollectionContext};
use crate::platform::memory::{collect_memory_snapshot, collect_pressure};
use crate::platform::process::{
    CollectionContext as ProcessContext, DarwinProcessSource, ProcessCollector, ProcessSnapshot,
    ProcessSource, application_candidates, control_plane_of_this_process, instance_count,
};
use crate::platform::sleep::sleep_between;
use crate::platform::volume::{MountedVolume, collect_capacity, volume_at};
use crate::protection::ProtectedLocations;
use crate::rules::{DiscoveryLimits, ReviewedRules, SharedEnvironment, SourceEnvironment};
use crate::store::Store;

/// The logical volume selector that this build resolves.
pub const STARTUP_DATA_SELECTOR: &str = "startup-data";

/// The mount point of the data volume of the startup volume group.
const STARTUP_DATA_MOUNT_POINT: &str = "/System/Volumes/Data";

/// The reason the parts of the running system were not made.
#[derive(Debug, Error)]
pub enum HostError {
    /// The host gave no boot identity or no clock.
    #[error("the collection context is not available: {0}")]
    Context(String),
    /// The rule registry has a defective declaration.
    #[error("the rule registry is not usable: {0}")]
    Registry(String),
    /// The filesystem executor refused its configuration.
    #[error("the filesystem executor is not usable: {0}")]
    Executor(String),
    /// An identity of this lifetime is not valid.
    #[error("an identity of this lifetime is not valid")]
    Identity,
}

impl HostError {
    /// A fixed name of the cause, for a log. The text of the error can
    /// have a path of the user; this name has none.
    #[must_use]
    pub const fn cause(&self) -> &'static str {
        match self {
            Self::Context(_) => "collection_context",
            Self::Registry(_) => "rule_registry",
            Self::Executor(_) => "filesystem_executor",
            Self::Identity => "identity",
        }
    }
}

/// The clock of the agent on the running system.
pub struct SystemAgentClock {
    clock: Arc<dyn HostClock>,
    clock_domain: ClockDomainId,
    boot_id: BootId,
    continuity: AtomicU64,
    last_discontinuity: Mutex<Option<MonotonicNanos>>,
    /// The source of the sleep time and its latest value, for
    /// [`AgentClock::observe_continuity`]. `None`: the clock does not
    /// read the sleep time.
    sleep: Option<SleepWatch>,
}

/// The cumulative sleep time of the host as the clock read it last.
struct SleepWatch {
    context: Arc<CollectionContext>,
    last: Mutex<Reading<Nanoseconds>>,
}

impl fmt::Debug for SystemAgentClock {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SystemAgentClock")
            .field("clock_domain", &self.clock_domain)
            .field("boot_id", &self.boot_id)
            .finish_non_exhaustive()
    }
}

impl SystemAgentClock {
    /// The clock of `context`.
    #[must_use]
    pub fn new(context: &CollectionContext) -> Self {
        let identity = context.identity();
        Self {
            clock: Arc::clone(context.clock()),
            clock_domain: identity.clock_domain.clone(),
            boot_id: identity.boot_id.clone(),
            continuity: AtomicU64::new(0),
            last_discontinuity: Mutex::new(None),
            sleep: None,
        }
    }

    /// The clock of `context` that also reads the cumulative sleep time
    /// of the host, so that [`AgentClock::observe_continuity`] finds a
    /// sleep between two readings.
    #[must_use]
    pub fn watching_sleep(context: &Arc<CollectionContext>) -> Self {
        Self {
            sleep: Some(SleepWatch {
                context: Arc::clone(context),
                last: Mutex::new(context.sleep_time()),
            }),
            ..Self::new(context)
        }
    }
}

impl AgentClock for SystemAgentClock {
    fn now(&self) -> Option<TimeReading> {
        let now: MonotonicNanos = self.clock.monotonic_now().ok()?;
        let wall: WallTime = self.clock.wall_now().ok()?;
        let last_discontinuity: Option<MonotonicNanos> = *self
            .last_discontinuity
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        Some(TimeReading {
            clock: EvaluationClock {
                now,
                clock_domain: self.clock_domain.clone(),
                boot_id: self.boot_id.clone(),
                continuity: ContinuityGeneration::new(self.continuity.load(Ordering::SeqCst)),
                last_discontinuity,
            },
            wall,
        })
    }

    fn mark_discontinuity(&self) {
        self.continuity.fetch_add(1, Ordering::SeqCst);
        // With no clock value, the generation still changes, so each
        // window starts again.
        if let Ok(now) = self.clock.monotonic_now() {
            *self
                .last_discontinuity
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some(now);
        }
    }

    fn observe_continuity(&self) -> bool {
        let Some(watch) = &self.sleep else {
            return false;
        };
        let now: Reading<Nanoseconds> = watch.context.sleep_time();
        let slept: bool = {
            let mut last = watch.last.lock().unwrap_or_else(PoisonError::into_inner);
            // A sleep time that is not available gives no evidence that
            // the host did not sleep.
            let slept: bool = sleep_between(&last, &now).is_err();
            *last = now;
            slept
        };
        if slept {
            self.mark_discontinuity();
        }
        slept
    }
}

/// The identities of the coordinator: the executor lifetime and a
/// counter.
#[derive(Debug)]
pub struct EpochIds {
    epoch: ExecutorEpochId,
    next: u64,
}

impl EpochIds {
    /// The identities of the lifetime `epoch`.
    #[must_use]
    pub const fn new(epoch: ExecutorEpochId) -> Self {
        Self { epoch, next: 0 }
    }

    fn next(&mut self) -> u64 {
        self.next = self.next.saturating_add(1);
        self.next
    }
}

impl IdSource for EpochIds {
    fn operation_id(&mut self) -> Option<OperationId> {
        let next: u64 = self.next();
        OperationId::new(format!("operation-{}-{next}", self.epoch)).ok()
    }

    fn lease_id(&mut self) -> Option<LeaseId> {
        let next: u64 = self.next();
        LeaseId::new(format!("lease-{}-{next}", self.epoch)).ok()
    }
}

/// The identities of the volumes that the collector resolved, for the
/// measurements of outcome verification.
type KnownVolumes = Arc<Mutex<Vec<VolumeIdentity>>>;

/// An observation with no value, for a measurement that did not run. The
/// sample has no time: the observation supports no decision.
fn unavailable<T>(
    context: &CollectionContext,
    adapter_id: svalnir_core::id::AdapterId,
    metric_id: svalnir_core::observation::MetricId,
    scope: Scope,
    unit: Unit,
    kind: MetricKind,
    reason: UnavailableReason,
) -> Observation<T> {
    let identity = context.identity();
    Observation {
        metric_id,
        scope,
        reading: Reading::Unavailable(reason),
        unit,
        kind,
        coverage: Coverage::Unknown,
        source: Source {
            adapter_id,
            adapter_revision: crate::platform::memory::context::ADAPTER_REVISION.to_owned(),
            native_api: "none".to_owned(),
            native_field: "none".to_owned(),
            worker_id: identity.worker_id.clone(),
        },
        sample: ObservationSample {
            sample_id: SampleId::new("sample-not-collected")
                .unwrap_or_else(|_| unreachable_sample_id()),
            clock_domain: identity.clock_domain.clone(),
            boot_id: identity.boot_id.clone(),
            collector_epoch: identity.collector_epoch.clone(),
            started_monotonic_ns: MonotonicNanos::new(0),
            finished_monotonic_ns: MonotonicNanos::new(0),
            captured_at: WallTime::UNIX_EPOCH,
        },
    }
}

/// The identity of a sample that was not collected. The text is a
/// constant that is a valid identity; the worker identity of the context
/// is the fallback, so no path of this function fails.
fn unreachable_sample_id() -> SampleId {
    SampleId::new("s").unwrap_or_else(|_| {
        // `SampleId` accepts each ASCII letter, so this value exists.
        SampleId::new("x").unwrap_or_else(|_| std::process::abort())
    })
}

/// The measurements of outcome verification on the running system.
pub struct SystemMeasurements {
    context: Arc<CollectionContext>,
    volumes: KnownVolumes,
}

impl fmt::Debug for SystemMeasurements {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SystemMeasurements")
            .finish_non_exhaustive()
    }
}

impl SystemMeasurements {
    /// The measurements of `context` for the volumes of `volumes`. A
    /// volume that is not in the list has no capacity value. A transient
    /// coordinator, which has no collector, uses this function with the
    /// volumes of its plan.
    #[must_use]
    pub fn new(context: Arc<CollectionContext>, volumes: Vec<VolumeIdentity>) -> Self {
        Self {
            context,
            volumes: Arc::new(Mutex::new(volumes)),
        }
    }
}

impl Measurements for SystemMeasurements {
    fn capacity(&mut self, volume: &VolumeId) -> Observation<Bytes> {
        let identity: Option<VolumeIdentity> = self
            .volumes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .find(|identity| &identity.volume_id == volume)
            .cloned();
        let measured: Option<Observation<Bytes>> = identity
            .and_then(|identity| collect_capacity(&self.context, &identity).ok())
            .map(|capacity| capacity.available);
        measured.unwrap_or_else(|| {
            unavailable(
                &self.context,
                self.context.adapters.statfs.clone(),
                metric::DISK_AVAILABLE_BYTES,
                Scope::volume(volume.clone()),
                Unit::Byte,
                MetricKind::Gauge,
                UnavailableReason::NotCollected,
            )
        })
    }

    fn memory_pressure(&mut self) -> Observation<PressureState> {
        collect_pressure(&self.context).unwrap_or_else(|_| {
            unavailable(
                &self.context,
                self.context.adapters.sysctl.clone(),
                metric::MEMORY_PRESSURE,
                self.context.host_scope(),
                Unit::State,
                MetricKind::State,
                UnavailableReason::NotCollected,
            )
        })
    }
}

/// The collectors of the running system.
pub struct SystemCollector {
    context: Arc<CollectionContext>,
    principal: Uid,
    selector: Option<VolumeSelector>,
    volumes: KnownVolumes,
    last_sleep: Reading<Nanoseconds>,
}

impl fmt::Debug for SystemCollector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SystemCollector")
            .field("principal", &self.principal)
            .finish_non_exhaustive()
    }
}

/// The volume that the `startup-data` selector names: the data volume of
/// the startup volume group, or the root volume on a host that has no
/// separate data volume.
fn startup_data_volume() -> Option<MountedVolume> {
    let data: &Path = Path::new(STARTUP_DATA_MOUNT_POINT);
    if data.is_dir() {
        volume_at(data).ok()
    } else {
        volume_at(Path::new("/")).ok()
    }
}

/// The evidence that the process inventory is complete. A denied identity
/// query is a process of a different user, which is out of the scope of
/// the inventory. A query that failed for a different cause can be a
/// process of the current user.
fn inventory_evidence(
    snapshot: &ProcessSnapshot,
    collector_epoch: &CollectorEpochId,
) -> Option<InventoryEvidence> {
    let complete: bool = snapshot.omissions.failed == 0
        && snapshot.launch_services_unavailable.is_none()
        && snapshot.responsible_process_unavailable.is_none();
    Some(InventoryEvidence {
        coverage: if complete {
            Coverage::Complete
        } else {
            Coverage::Partial
        },
        sample: ObservationSample {
            sample_id: SampleId::new(format!("inv-{}", snapshot.started_monotonic_ns.get()))
                .ok()?,
            clock_domain: snapshot.clock_domain.clone(),
            boot_id: snapshot.boot_id.clone(),
            collector_epoch: collector_epoch.clone(),
            started_monotonic_ns: snapshot.started_monotonic_ns,
            finished_monotonic_ns: snapshot
                .finished_monotonic_ns
                .max(snapshot.started_monotonic_ns),
            captured_at: snapshot.captured_at,
        },
    })
}

impl SystemCollector {
    fn collect_volumes(&self, sample: &mut Sample) {
        let Some(selector) = &self.selector else {
            sample.degraded.push("volume_selector".to_owned());
            return;
        };
        let Some(mounted) = startup_data_volume() else {
            sample.degraded.push("volume_identity".to_owned());
            return;
        };
        // The identity of the mount is read again at each collection, so
        // a volume that was mounted again has its new mount generation.
        *self.volumes.lock().unwrap_or_else(PoisonError::into_inner) =
            vec![mounted.identity.clone()];
        match collect_capacity(&self.context, &mounted.identity) {
            Ok(capacity) => sample.observations.volumes.push(VolumeEvidence {
                selector: selector.clone(),
                identity: mounted.identity,
                available: capacity.available,
            }),
            Err(_) => sample.degraded.push("volume_capacity".to_owned()),
        }
    }

    fn collect_memory(&self, sample: &mut Sample) {
        let mut memory: MemorySnapshot = MemorySnapshot::default();
        match collect_memory_snapshot(&self.context) {
            Ok(host) => {
                let vm = &host.vm;
                memory.corroborating = vec![
                    CorroboratingEvidence::from_observation(&vm.free),
                    CorroboratingEvidence::from_observation(&vm.active),
                    CorroboratingEvidence::from_observation(&vm.inactive),
                    CorroboratingEvidence::from_observation(&vm.wired),
                    CorroboratingEvidence::from_observation(&vm.compressor_physical),
                    CorroboratingEvidence::from_observation(&host.swap.used),
                ];
                memory.pressure = Some(host.pressure);
            }
            Err(_) => sample.degraded.push("memory".to_owned()),
        }
        let identity = self.context.identity();
        let collected: Option<ProcessSnapshot> = ProcessCollector::new(
            DarwinProcessSource::new(),
            ProcessContext {
                worker_id: identity.worker_id.clone(),
                boot_id: identity.boot_id.clone(),
                collector_epoch: identity.collector_epoch.clone(),
            },
        )
        .ok()
        .and_then(|collector| collector.collect().ok());
        match collected {
            Some(processes) => {
                // This process and its ancestors are the control plane.
                let control_plane = control_plane_of_this_process(&processes);
                memory.applications = application_candidates(
                    &processes,
                    &ProtectionContext {
                        principal: self.principal,
                        control_plane: control_plane.as_deref(),
                    },
                );
                memory.inventory = inventory_evidence(&processes, &identity.collector_epoch);
                memory.application_list_may_be_stale = processes.application_list_may_be_stale;
                // An instance with no candidate is not absent.
                if instance_count(&processes) > memory.applications.len()
                    && let Some(inventory) = &mut memory.inventory
                {
                    inventory.coverage = Coverage::Partial;
                }
                sample.control_plane = control_plane;
            }
            None => sample.degraded.push("process_inventory".to_owned()),
        }
        sample.observations.memory = memory;
    }
}

impl Collector for SystemCollector {
    fn collect(&mut self) -> Sample {
        let mut sample: Sample = Sample::default();
        // A sleep between two collections is a clock discontinuity. A
        // sleep time that is not available gives no evidence that the
        // host did not sleep.
        let sleep: Reading<Nanoseconds> = self.context.sleep_time();
        if sleep_between(&self.last_sleep, &sleep).is_err() {
            sample.woke = true;
            if !sleep.is_available() {
                sample.degraded.push("sleep_time".to_owned());
            }
        }
        self.last_sleep = sleep;
        self.collect_volumes(&mut sample);
        self.collect_memory(&mut sample);
        sample
    }
}

/// Writes each notification to the structured log. A notification has
/// identities and reason names; it has no path and no process argument.
#[derive(Debug, Clone, Copy, Default)]
pub struct LogNotifier;

impl Notifier for LogNotifier {
    fn notify(&mut self, notification: &Notification) {
        if let Ok(event) = serde_json::to_string(notification) {
            tracing::info!(%event, "controller notification");
        } else {
            tracing::warn!("a controller notification was not encoded");
        }
    }
}

/// The physical footprint of this process.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProcessFootprint;

impl SelfFootprint for ProcessFootprint {
    fn footprint(&mut self) -> Option<Bytes> {
        let pid: Pid = Pid::new(i32::try_from(std::process::id()).ok()?).ok()?;
        DarwinProcessSource::new()
            .usage(pid)
            .ok()
            .map(|usage| Bytes::new(usage.physical_footprint))
    }
}

/// The capability check of the start, as the status keeps it.
#[must_use]
pub fn capability_summary() -> CapabilitySummary {
    let report: CapabilityReport = diagnose(WorkerRole::Agent);
    CapabilitySummary {
        verdict: report.summary.verdict.as_str().to_owned(),
        required_not_available: report
            .summary
            .required_not_available
            .iter()
            .map(|capability| capability.as_str().to_owned())
            .collect(),
    }
}

/// The parts of the agent on the running system.
#[derive(Debug)]
pub struct SystemParts {
    /// The parts of the driver.
    pub driver: DriverParts,
    /// The collectors.
    pub collector: Box<SystemCollector>,
    /// The clock, for the service.
    pub clock: Arc<SystemAgentClock>,
    /// The collection context, for the pressure event source.
    pub context: Arc<CollectionContext>,
}

/// Makes the parts of the agent for the running system.
///
/// The executors are the ones that act on the host: the filesystem
/// executor with the Trash of the user, and the process executor of this
/// user. They act only for a step that the coordinator admitted. The
/// process has no fixed approved root: the driver resolves the approved
/// roots of an automatic operation from the rule declarations and the
/// configuration in effect before it applies an automatic plan
/// ([`crate::rules::automatic_roots`]).
///
/// The candidate source is the discovery of the reviewed rules
/// ([`RuleCandidateSource`]). Each reviewed rule of this build is in the
/// `proposed` lifecycle state, so the source examines no rule and each
/// set is empty.
///
/// # Errors
///
/// Returns a [`HostError`] when the host gives no boot identity or clock,
/// the rule registry is defective, or the filesystem executor refuses the
/// home directory.
pub fn system_parts(
    epoch: &ExecutorEpochId,
    principal: Uid,
    home_directory: &LosslessPath,
    state_directory: &Path,
    store: Option<Store>,
) -> Result<SystemParts, HostError> {
    let context: Arc<CollectionContext> = Arc::new(
        CollectionContext::for_current_process()
            .map_err(|error| HostError::Context(error.to_string()))?,
    );
    let clock: Arc<SystemAgentClock> = Arc::new(SystemAgentClock::watching_sleep(&context));
    let registry: ReviewedRules =
        ReviewedRules::new().map_err(|error| HostError::Registry(error.to_string()))?;
    let environment: SharedEnvironment = Arc::new(SourceEnvironment(DarwinProcessSource::new()));
    let candidates: RuleCandidateSource = RuleCandidateSource::new(
        registry.clone(),
        principal,
        ProtectedLocations::resolve(Some(&home_directory.to_path_buf()), Some(state_directory)),
        Arc::clone(&environment),
        DiscoveryLimits::default(),
    );
    let roots: ApprovedRoots =
        ApprovedRoots::new(Vec::new()).map_err(|error| HostError::Executor(error.to_string()))?;
    let filesystem: FsExecutor = FsExecutor::with_system_trash(&FsExecutorConfig {
        home_directory: home_directory.clone(),
        limits: ExecutorLimits::default(),
    })
    .map_err(|error| HostError::Executor(error.to_string()))?;
    let identity = context.identity();
    let application = ProcessExecutor::new(
        DarwinProcessSource::new(),
        DarwinProcessControl,
        SourceClock(DarwinProcessSource::new()),
        ExecutorContext {
            boot_id: identity.boot_id.clone(),
            clock_domain: identity.clock_domain.clone(),
            executor_epoch: epoch.clone(),
        },
        ExecutorConfig::default(),
    );
    let volumes: KnownVolumes = Arc::new(Mutex::new(Vec::new()));
    let collector: SystemCollector = SystemCollector {
        context: Arc::clone(&context),
        principal,
        selector: VolumeSelector::new(STARTUP_DATA_SELECTOR),
        volumes: Arc::clone(&volumes),
        last_sleep: context.sleep_time(),
    };
    let driver: DriverParts = DriverParts {
        clock: Arc::clone(&clock) as Arc<dyn AgentClock>,
        registry: Box::new(registry),
        measurements: Box::new(SystemMeasurements {
            context: Arc::clone(&context),
            volumes,
        }),
        ids: Box::new(EpochIds::new(epoch.clone())),
        filesystem: Box::new(filesystem),
        roots: roots.clone(),
        application: Box::new(application),
        probe: Box::new(SystemProbe::new(roots, DarwinProcessSource::new())),
        candidates: Box::new(candidates),
        environment,
        notifier: Box::new(LogNotifier),
        footprint: Box::new(ProcessFootprint),
        store,
        capabilities: Some(capability_summary()),
    };
    Ok(SystemParts {
        driver,
        collector: Box::new(collector),
        clock,
        context,
    })
}
