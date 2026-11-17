//! Synthetic data for the tests of the command modules.
//!
//! Each value here is made in memory. No function reads the host, except
//! [`environment`], which makes one temporary directory.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use svalnir_agent::capability::{
    CapabilityEntry, CapabilityId, CapabilityReport, Evidence, ProbeSubject, Summary, WorkerRole,
};
use svalnir_agent::platform::memory::{MemorySnapshot, SwapUsage, VmStatistics};
use svalnir_agent::platform::process::{
    ForegroundState, Omissions, ProcessMetrics, ProcessRecord, ProcessSnapshot,
};
use svalnir_agent::platform::volume::{FoundationCapacity, VolumeCapacity};
use svalnir_agent::scan::{
    LargeDirectory, LargeFile, RegionCause, ScanCompletion, ScanLimits, ScanRegion, ScanResult,
    ScanTimestamp, ScanTotals, ScanVolumeEvidence, SharedStorageEvidence,
};
use svalnir_core::file::{DeviceNumber, FileObjectEvidence, InodeNumber, LosslessPath};
use svalnir_core::id::{
    AdapterId, ApplicationInstanceId, BootId, ClockDomainId, CollectorEpochId, IdentityId, MountId,
    ProcessGenerationId, RequestId, SampleId, ScanId, VolumeId, WorkerId,
};
use svalnir_core::observation::{
    Coverage, MetricId, MetricKind, Observation, Reading, Sample, Scope, ScopeKind, Source,
    UnavailableReason, Unit, metric,
};
use svalnir_core::process::{
    AttributionMethod, ExecutableIdentity, Pid, ProcessAssociation, ProcessIdentity,
    ProcessStartTime, Uid,
};
use svalnir_core::quantity::{Bytes, CounterValue, EntryCount, Nanoseconds, PageCount};
use svalnir_core::state::{CapabilityState, PressureState};
use svalnir_core::time::{MonotonicNanos, WallTime};
use svalnir_core::volume::{CapacityDomainMembership, VolumeIdentity};

use crate::environment::Environment;
use crate::interrupt::Interrupt;

pub(crate) const BOOT: &str = "boot_test";
pub(crate) const CLOCK_DOMAIN: &str = "clock_test";
const EPOCH: &str = "epoch_test";
const GIB: u64 = 1024 * 1024 * 1024;
const MIB: u64 = 1024 * 1024;

/// The monotonic start of the first synthetic sample.
const FIRST_SAMPLE_NS: u64 = 1_000_000_000_000;

pub(crate) fn request_id() -> RequestId {
    RequestId::new("request_test").unwrap()
}

/// 2026-01-02T03:04:05Z.
pub(crate) fn wall_time() -> WallTime {
    "2026-01-02T03:04:05Z".parse().unwrap()
}

/// A temporary directory that is removed when the value is dropped.
#[derive(Debug)]
pub(crate) struct TempDirectory {
    path: PathBuf,
}

impl TempDirectory {
    pub(crate) fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path: PathBuf = std::env::temp_dir().join(format!(
            "svalnir-cli-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        // A directory of an earlier run with the same process ID is stale.
        drop(std::fs::remove_dir_all(&path));
        std::fs::create_dir_all(&path).unwrap();
        Self {
            // The scanner and `statfs` see the path without `/tmp` or `/var`
            // symbolic links.
            path: path.canonicalize().unwrap(),
        }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        drop(std::fs::remove_dir_all(&self.path));
    }
}

/// An environment whose state directory, home directory, and invocation
/// directory are in one new temporary directory. The state directory does
/// not exist.
pub(crate) fn environment() -> (Environment, TempDirectory) {
    let directory = TempDirectory::new();
    let home: PathBuf = directory.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let (interrupt, _flag) = Interrupt::manual();
    (
        Environment {
            state_directory_override: Some(directory.path().join("state").into_os_string()),
            home: Some(home),
            current_directory: Some(directory.path().to_path_buf()),
            interrupt,
            seams: crate::seams::Seams::default(),
        },
        directory,
    )
}

fn sample(name: &str, started: u64) -> Sample {
    Sample {
        sample_id: SampleId::new(format!("sample_{name}_{started}")).unwrap(),
        clock_domain: ClockDomainId::new(CLOCK_DOMAIN).unwrap(),
        boot_id: BootId::new(BOOT).unwrap(),
        collector_epoch: CollectorEpochId::new(EPOCH).unwrap(),
        started_monotonic_ns: MonotonicNanos::new(started),
        finished_monotonic_ns: MonotonicNanos::new(started + 1_000),
        captured_at: wall_time(),
    }
}

fn source() -> Source {
    Source {
        adapter_id: AdapterId::new("test.adapter").unwrap(),
        adapter_revision: "1".to_owned(),
        native_api: "test_api".to_owned(),
        native_field: "test_field".to_owned(),
        worker_id: WorkerId::new("worker_test").unwrap(),
    }
}

fn host_scope() -> Scope {
    Scope {
        kind: ScopeKind::Host,
        identity_id: IdentityId::new("host_local").unwrap(),
    }
}

fn observation<T>(
    metric_id: MetricId,
    scope: Scope,
    value: T,
    unit: Unit,
    kind: MetricKind,
    sample: &Sample,
) -> Observation<T> {
    Observation {
        metric_id,
        scope,
        reading: Reading::Available(value),
        unit,
        kind,
        coverage: Coverage::Complete,
        source: source(),
        sample: sample.clone(),
    }
}

/// The host memory at sample `index`. Sample `index` is `index` seconds
/// after sample 0 and has 50 more swap-ins and 20 more swap-outs for each
/// second.
pub(crate) fn memory_snapshot_at(index: u64) -> MemorySnapshot {
    let started: u64 = FIRST_SAMPLE_NS + index * 1_000_000_000;
    let vm_sample: Sample = sample("vm", started);
    let pages = |metric_id: MetricId, count: u64| {
        observation(
            metric_id,
            host_scope(),
            PageCount::new(count),
            Unit::Page,
            MetricKind::Gauge,
            &vm_sample,
        )
    };
    let counter = |metric_id: MetricId, count: u64| {
        observation(
            metric_id,
            host_scope(),
            CounterValue::new(count),
            Unit::Page,
            MetricKind::Counter,
            &vm_sample,
        )
    };
    let swap_sample: Sample = sample("swap", started);
    let swap_bytes = |metric_id: MetricId, bytes: u64| {
        observation(
            metric_id,
            host_scope(),
            Bytes::new(bytes),
            Unit::Byte,
            MetricKind::Gauge,
            &swap_sample,
        )
    };
    MemorySnapshot {
        pressure: observation(
            metric::MEMORY_PRESSURE,
            host_scope(),
            PressureState::Normal,
            Unit::State,
            MetricKind::State,
            &sample("pressure", started),
        ),
        physical: observation(
            metric::MEMORY_PHYSICAL_BYTES,
            host_scope(),
            Bytes::new(16 * GIB),
            Unit::Byte,
            MetricKind::Gauge,
            &sample("physical", started),
        ),
        vm: VmStatistics {
            page_size: Reading::Available(Bytes::new(16_384)),
            sample: vm_sample.clone(),
            sleep_time: Reading::Available(Nanoseconds::ZERO),
            free: pages(metric::MEMORY_VM_FREE_PAGES, 65_536),
            active: pages(metric::MEMORY_VM_ACTIVE_PAGES, 300_000),
            inactive: pages(metric::MEMORY_VM_INACTIVE_PAGES, 200_000),
            wired: pages(metric::MEMORY_VM_WIRED_PAGES, 100_000),
            speculative: pages(metric::MEMORY_VM_SPECULATIVE_PAGES, 10_000),
            internal: pages(metric::MEMORY_VM_INTERNAL_PAGES, 400_000),
            external: pages(metric::MEMORY_VM_EXTERNAL_PAGES, 150_000),
            pageins: counter(metric::MEMORY_VM_PAGEINS_TOTAL, 1_000),
            pageouts: counter(metric::MEMORY_VM_PAGEOUTS_TOTAL, 10),
            compressor_physical: pages(metric::MEMORY_COMPRESSOR_PHYSICAL_PAGES, 50_000),
            compressor_uncompressed: pages(metric::MEMORY_COMPRESSOR_UNCOMPRESSED_PAGES, 150_000),
            compressions: counter(metric::MEMORY_COMPRESSOR_COMPRESSIONS_TOTAL, 7_000),
            decompressions: counter(metric::MEMORY_COMPRESSOR_DECOMPRESSIONS_TOTAL, 6_000),
            swapins: counter(metric::MEMORY_SWAP_SWAPINS_TOTAL, 500 + index * 50),
            swapouts: counter(metric::MEMORY_SWAP_SWAPOUTS_TOTAL, 800 + index * 20),
        },
        swap: SwapUsage {
            allocated: swap_bytes(metric::MEMORY_SWAP_ALLOCATED_BYTES, 4 * GIB),
            used: swap_bytes(metric::MEMORY_SWAP_USED_BYTES, 2 * GIB),
            available: swap_bytes(metric::MEMORY_SWAP_AVAILABLE_BYTES, 2 * GIB),
        },
    }
}

pub(crate) fn memory_snapshot() -> MemorySnapshot {
    memory_snapshot_at(0)
}

/// The startup data volume with 100 GiB available of 500 GiB.
pub(crate) fn volume_capacity() -> (VolumeIdentity, VolumeCapacity, FoundationCapacity) {
    let volume_id: VolumeId = VolumeId::new("volume_test").unwrap();
    let identity = VolumeIdentity {
        volume_id: volume_id.clone(),
        mount_id: MountId::new("mount_test").unwrap(),
        mount_point: LosslessPath::from_bytes(b"/System/Volumes/Data".to_vec()).unwrap(),
        device: DeviceNumber::new(16_777_234),
        filesystem_type: "apfs".to_owned(),
        volume_uuid: Some("00000000-0000-0000-0000-000000000001".to_owned()),
        capacity_domain: CapacityDomainMembership::Exclusive,
    };
    let statfs: Sample = sample("statfs", FIRST_SAMPLE_NS);
    let bytes = |metric_id: MetricId, bytes: u64, kind: MetricKind| {
        observation(
            metric_id,
            Scope::volume(volume_id.clone()),
            Bytes::new(bytes),
            Unit::Byte,
            kind,
            &statfs,
        )
    };
    (
        identity,
        VolumeCapacity {
            total: bytes(metric::DISK_TOTAL_BYTES, 500 * GIB, MetricKind::Gauge),
            free: bytes(metric::DISK_FREE_BYTES, 110 * GIB, MetricKind::Gauge),
            available: bytes(metric::DISK_AVAILABLE_BYTES, 100 * GIB, MetricKind::Gauge),
        },
        FoundationCapacity {
            important: bytes(
                metric::DISK_IMPORTANT_AVAILABLE_BYTES,
                130 * GIB,
                MetricKind::Estimate,
            ),
            opportunistic: bytes(
                metric::DISK_OPPORTUNISTIC_AVAILABLE_BYTES,
                90 * GIB,
                MetricKind::Estimate,
            ),
        },
    )
}

const START_MICROSECONDS: u64 = 1_700_000_000_000_000;

fn process_record(
    pid: i32,
    path: &str,
    association: ProcessAssociation,
    foreground: ForegroundState,
    footprint: Option<u64>,
    resident: Option<u64>,
) -> ProcessRecord {
    let generation_id: ProcessGenerationId =
        ProcessGenerationId::new(format!("pg-{pid}-{START_MICROSECONDS}")).unwrap();
    let scope: Scope = Scope::process(generation_id.clone());
    let usage: Sample = sample(&format!("ps{pid}"), FIRST_SAMPLE_NS);
    let bytes = |metric_id: MetricId, value: Option<u64>| {
        let mut made = observation(
            metric_id,
            scope.clone(),
            Bytes::new(value.unwrap_or(0)),
            Unit::Byte,
            MetricKind::Gauge,
            &usage,
        );
        if value.is_none() {
            made.reading = Reading::Unavailable(UnavailableReason::PermissionDenied);
            made.coverage = Coverage::Unknown;
        }
        made
    };
    let counter = |metric_id: MetricId, value: u64, unit: Unit| {
        observation(
            metric_id,
            scope.clone(),
            CounterValue::new(value),
            unit,
            MetricKind::Counter,
            &usage,
        )
    };
    ProcessRecord {
        identity: ProcessIdentity {
            generation_id,
            pid: Pid::new(pid).unwrap(),
            start_time: ProcessStartTime::new(START_MICROSECONDS),
            uid: Uid::new(501),
            boot_id: BootId::new(BOOT).unwrap(),
            executable: Some(ExecutableIdentity {
                path: LosslessPath::from_bytes(path.as_bytes().to_vec()).unwrap(),
                file: None,
                code_signature: None,
            }),
            association,
        },
        real_uid: Uid::new(501),
        parent_pid: Some(Pid::new(1).unwrap()),
        executable_unavailable: None,
        executable_file_unavailable: Some(UnavailableReason::NotCollected),
        foreground,
        metrics: ProcessMetrics {
            footprint: bytes(metric::PROCESS_FOOTPRINT_BYTES, footprint),
            resident: bytes(metric::PROCESS_RESIDENT_BYTES, resident),
            peak_footprint: bytes(metric::PROCESS_PEAK_FOOTPRINT_BYTES, footprint),
            cpu_time: counter(
                metric::PROCESS_CPU_TIME_NS,
                90_000_000_000,
                Unit::Nanosecond,
            ),
            disk_read: counter(
                MetricId::new("process.disk_read_bytes_total").unwrap(),
                10 * MIB,
                Unit::Byte,
            ),
            disk_written: counter(
                MetricId::new("process.disk_written_bytes_total").unwrap(),
                20 * MIB,
                Unit::Byte,
            ),
        },
    }
}

/// Three processes: an editor (3 GiB) and its helper (1 GiB) in one
/// application instance, and a process with no attribution and no readable
/// usage.
pub(crate) fn process_snapshot() -> ProcessSnapshot {
    let instance = || ApplicationInstanceId::new(format!("app-200-{START_MICROSECONDS}")).unwrap();
    let member = |attribution: AttributionMethod| ProcessAssociation::Application {
        instance_id: instance(),
        bundle_identifier: "com.example.editor".to_owned(),
        attribution,
    };
    ProcessSnapshot {
        boot_id: BootId::new(BOOT).unwrap(),
        clock_domain: ClockDomainId::new(CLOCK_DOMAIN).unwrap(),
        started_monotonic_ns: MonotonicNanos::new(FIRST_SAMPLE_NS),
        finished_monotonic_ns: MonotonicNanos::new(FIRST_SAMPLE_NS + 60_000_000),
        captured_at: wall_time(),
        sleep_time: Reading::Available(Nanoseconds::ZERO),
        records: vec![
            process_record(
                200,
                "/Applications/Editor.app/Contents/MacOS/editor",
                member(AttributionMethod::LaunchServices),
                ForegroundState::Foreground,
                Some(3 * GIB),
                Some(2 * GIB),
            ),
            process_record(
                201,
                "/Applications/Editor.app/Contents/Helpers/helper",
                member(AttributionMethod::ResponsibleProcess),
                ForegroundState::Foreground,
                Some(GIB),
                Some(512 * MIB),
            ),
            process_record(
                300,
                "/usr/local/bin/daemon",
                ProcessAssociation::Unattributed,
                ForegroundState::Unknown,
                None,
                None,
            ),
        ],
        omissions: Omissions {
            other_user: 40,
            permission_denied: 2,
            exited: 1,
            identity_changed: 0,
            failed: 0,
        },
        launch_services_unavailable: None,
        application_list_may_be_stale: false,
        responsible_process_unavailable: None,
    }
}

fn path(text: &[u8]) -> LosslessPath {
    LosslessPath::from_bytes(text.to_vec()).unwrap()
}

/// A scan of `/data/project`. With `partial`, one directory was not
/// readable and one file name has a terminal escape sequence.
pub(crate) fn scan_result(partial: bool) -> ScanResult {
    let object = |inode: u64| FileObjectEvidence {
        device: DeviceNumber::new(42),
        inode: InodeNumber::new(inode),
    };
    let mut largest_files = vec![LargeFile {
        path: path(b"/data/project/big.bin"),
        logical_bytes: Bytes::new(2 * MIB),
        allocated_bytes: Bytes::new(3 * MIB),
        link_count: EntryCount::new(1),
        object: object(11),
    }];
    let mut regions: Vec<ScanRegion> = Vec::new();
    if partial {
        largest_files.push(LargeFile {
            path: path(b"/data/project/a\x1b[31mb"),
            logical_bytes: Bytes::new(MIB),
            allocated_bytes: Bytes::new(MIB),
            link_count: EntryCount::new(1),
            object: object(12),
        });
        regions.push(ScanRegion {
            path: path(b"/data/project/secret"),
            cause: RegionCause::PermissionDenied,
            native_errno: Some(13),
        });
    }
    ScanResult {
        schema_version: 1,
        scan_id: ScanId::new("scan_test").unwrap(),
        root: path(b"/data/project"),
        volume: ScanVolumeEvidence {
            device: DeviceNumber::new(42),
            root_object: object(2),
            filesystem_type: Some("apfs".to_owned()),
            mount_point: Some(path(b"/data")),
            identity: None,
        },
        started: ScanTimestamp {
            wall: Some(wall_time()),
            monotonic_ns: Some(MonotonicNanos::new(FIRST_SAMPLE_NS)),
        },
        finished: ScanTimestamp {
            wall: Some(wall_time()),
            monotonic_ns: Some(MonotonicNanos::new(FIRST_SAMPLE_NS + 250_000_000)),
        },
        elapsed: Some(Nanoseconds::new(250_000_000)),
        completion: ScanCompletion::Finished,
        coverage: if partial {
            Coverage::Partial
        } else {
            Coverage::Complete
        },
        limits: ScanLimits::default(),
        entries_examined: EntryCount::new(5),
        totals: ScanTotals {
            logical_bytes: Bytes::new(3 * MIB),
            allocated_bytes: Bytes::new(4 * MIB),
            entries: EntryCount::new(4),
            files: EntryCount::new(2),
            directories: EntryCount::new(2),
            symlinks: EntryCount::new(0),
            other_entries: EntryCount::new(0),
        },
        shared_storage: SharedStorageEvidence {
            hard_linked_objects: EntryCount::new(0),
            hard_link_names_not_counted_again: EntryCount::new(0),
            hard_link_names_not_tracked: EntryCount::new(0),
            compressed_files: EntryCount::new(0),
            files_allocated_below_logical: EntryCount::new(0),
        },
        largest_files,
        largest_directories: vec![LargeDirectory {
            path: path(b"/data/project/build"),
            logical_bytes: Bytes::new(2 * MIB),
            allocated_bytes: Bytes::new(3 * MIB),
            entries: EntryCount::new(1),
            coverage: Coverage::Complete,
            object: object(3),
        }],
        boundaries: Vec::new(),
        boundaries_omitted: EntryCount::new(0),
        regions,
        regions_omitted: EntryCount::new(0),
    }
}

/// A capability report with each capability available. With `denied`, the
/// memory-pressure source is denied.
pub(crate) fn capability_report(denied: bool) -> CapabilityReport {
    let capabilities: Vec<CapabilityEntry> = CapabilityId::ALL
        .iter()
        .map(|id| {
            let is_denied: bool = denied && id.as_str() == "metrics.memory_pressure";
            CapabilityEntry {
                id: *id,
                title: id.title().to_owned(),
                requirement: id.requirement(),
                state: if is_denied {
                    CapabilityState::Denied
                } else {
                    CapabilityState::Available
                },
                detail: "synthetic finding".to_owned(),
                evidence: Evidence {
                    method: "synthetic".to_owned(),
                    facts: Vec::new(),
                },
                reason: None,
                enables: id.enables().to_owned(),
                remediation: is_denied.then(|| "Run the command in a user session.".to_owned()),
                registration: None,
            }
        })
        .collect();
    CapabilityReport {
        subject: ProbeSubject {
            role: WorkerRole::Cli,
            executable: None,
            pid: None,
            real_uid: Uid::new(501),
            effective_uid: Uid::new(501),
        },
        scope_note: "These results apply to this synthetic process only.".to_owned(),
        probed_at: Some(wall_time()),
        summary: Summary::of(&capabilities),
        capabilities,
    }
}

/// A Trash operation that moves the entry to a directory of the test. It
/// never moves an entry to the Trash of the user.
#[derive(Debug)]
pub(crate) struct DirectoryTrash {
    directory: PathBuf,
}

impl DirectoryTrash {
    pub(crate) fn new(directory: PathBuf) -> Self {
        Self { directory }
    }
}

impl svalnir_agent::executor::fs::TrashBackend for DirectoryTrash {
    fn move_to_trash(
        &self,
        request: &svalnir_agent::executor::fs::TrashRequest<'_>,
    ) -> svalnir_agent::executor::fs::TrashReply {
        use svalnir_agent::executor::fs::{TrashFailure, TrashReply};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let source: PathBuf = request.path.to_path_buf();
        let Some(name) = source.file_name() else {
            return TrashReply::Failed(TrashFailure::Other);
        };
        let mut item_name = name.to_owned();
        item_name.push(format!(".{}", NEXT.fetch_add(1, Ordering::SeqCst)));
        let item: PathBuf = self.directory.join(item_name);
        match std::fs::rename(&source, &item) {
            Ok(()) => {
                use std::os::unix::fs::MetadataExt as _;
                let object = std::fs::symlink_metadata(&item).ok().and_then(|metadata| {
                    Some(FileObjectEvidence {
                        device: DeviceNumber::new(i32::try_from(metadata.dev()).ok()?),
                        inode: InodeNumber::new(metadata.ino()),
                    })
                });
                TrashReply::Moved {
                    item: LosslessPath::from_path(&item).ok(),
                    item_object: object,
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                TrashReply::Failed(TrashFailure::NotFound)
            }
            Err(_) => TrashReply::Failed(TrashFailure::Other),
        }
    }
}
