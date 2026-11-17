//! The request, the limits, and the serializable result of a scan.
//!
//! `docs/RESOURCE_MODEL.md` section 8 owns the size definitions and the
//! aggregation convention. Each size in this file is a logical size or an
//! allocated size. No value in this file is a reclaimable size or an
//! exclusive size.

use std::path::Path;

use serde::{Deserialize, Serialize};
use svalnir_core::file::{DeviceNumber, FileObjectEvidence, LosslessPath, PathError};
use svalnir_core::id::ScanId;
use svalnir_core::observation::{
    Coverage, MetricId, MetricIdError, MetricKind, Observation, Reading, Sample, Scope, Source,
    UnavailableReason, Unit,
};
use svalnir_core::quantity::{Bytes, EntryCount, Nanoseconds};
use svalnir_core::time::{MonotonicNanos, WallTime};
use svalnir_core::volume::VolumeIdentity;
use thiserror::Error;

/// The version of the serialized [`ScanResult`].
pub const SCAN_RESULT_SCHEMA_VERSION: u32 = 1;

/// The metric name of the logical-size total of a scan.
pub const METRIC_SCAN_LOGICAL_BYTES: &str = "scan.logical_bytes";
/// The metric name of the allocated-size total of a scan.
pub const METRIC_SCAN_ALLOCATED_BYTES: &str = "scan.allocated_bytes";
/// The metric name of the exclusive-size total of a scan. A metadata scan
/// cannot measure this quantity, so the observation is always unavailable.
pub const METRIC_SCAN_EXCLUSIVE_BYTES: &str = "scan.exclusive_bytes";
/// The metric name of the entry total of a scan.
pub const METRIC_SCAN_ENTRIES: &str = "scan.entries";

/// The largest permitted [`ScanLimits::max_depth`]. The scan holds one open
/// directory for each level. When the process has no free file descriptor,
/// a deeper directory is a [`RegionCause::ResourceLimit`] region.
pub const MAX_DEPTH_LIMIT: u32 = 1_024;
/// The largest permitted length of a list of largest items.
pub const MAX_LARGEST_ITEMS_LIMIT: usize = 10_000;
/// The largest permitted number of recorded regions or boundaries.
pub const MAX_RECORDED_REGIONS_LIMIT: usize = 100_000;
/// The largest permitted number of hard-linked objects that a scan tracks.
pub const MAX_HARD_LINK_OBJECTS_LIMIT: usize = 16_000_000;

/// The bounds of one scan.
///
/// A scan keeps aggregates and bounded lists. It does not keep each entry.
/// Each limit bounds memory or time, and a limit that stops a part of the
/// scan makes the coverage partial.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanLimits {
    /// The deepest directory level that the scan opens. The root is level 0.
    /// A directory below this level is recorded as an incomplete region.
    pub max_depth: u32,
    /// The largest number of names that the scan examines. The scan stops
    /// when the next name is above this number.
    pub max_entries: EntryCount,
    /// The largest length of [`ScanResult::largest_files`].
    pub max_largest_files: usize,
    /// The largest length of [`ScanResult::largest_directories`].
    pub max_largest_directories: usize,
    /// The largest length of [`ScanResult::regions`]. The scan counts each
    /// region above this number in [`ScanResult::regions_omitted`].
    pub max_recorded_regions: usize,
    /// The largest length of [`ScanResult::boundaries`]. The scan counts
    /// each boundary above this number in [`ScanResult::boundaries_omitted`].
    pub max_recorded_boundaries: usize,
    /// The largest number of hard-linked objects that the scan tracks for
    /// deduplication. A hard-linked name above this number is not counted
    /// and is recorded as an incomplete region.
    pub max_hard_link_objects: usize,
}

impl Default for ScanLimits {
    fn default() -> Self {
        Self {
            max_depth: 128,
            max_entries: EntryCount::new(20_000_000),
            max_largest_files: 100,
            max_largest_directories: 100,
            max_recorded_regions: 1_000,
            max_recorded_boundaries: 256,
            max_hard_link_objects: 1_000_000,
        }
    }
}

impl ScanLimits {
    /// Checks each limit against its permitted maximum.
    ///
    /// # Errors
    ///
    /// Returns [`ScanError::LimitTooLarge`] with the name of the first field
    /// that is above its maximum.
    pub fn validate(&self) -> Result<(), ScanError> {
        let too_large = |field: &'static str| Err(ScanError::LimitTooLarge { field });
        if self.max_depth > MAX_DEPTH_LIMIT {
            return too_large("max_depth");
        }
        if self.max_largest_files > MAX_LARGEST_ITEMS_LIMIT {
            return too_large("max_largest_files");
        }
        if self.max_largest_directories > MAX_LARGEST_ITEMS_LIMIT {
            return too_large("max_largest_directories");
        }
        if self.max_recorded_regions > MAX_RECORDED_REGIONS_LIMIT {
            return too_large("max_recorded_regions");
        }
        if self.max_recorded_boundaries > MAX_RECORDED_REGIONS_LIMIT {
            return too_large("max_recorded_boundaries");
        }
        if self.max_hard_link_objects > MAX_HARD_LINK_OBJECTS_LIMIT {
            return too_large("max_hard_link_objects");
        }
        Ok(())
    }
}

/// The input of one scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanRequest {
    /// The identity of the scan.
    pub scan_id: ScanId,
    /// The root directory. The operating system resolves this path, which
    /// includes a symbolic link in it. The scan follows no symbolic link
    /// below the root.
    pub root: LosslessPath,
    /// The bounds of the scan.
    pub limits: ScanLimits,
    /// The identity of the volume that holds the root, when the caller has
    /// it. The scan fails when its device number is not that of the root.
    pub volume: Option<VolumeIdentity>,
}

/// The reason a scan did not start.
///
/// A failure after the root is open is not an error: it is a region of a
/// partial [`ScanResult`].
#[derive(Debug, Error)]
pub enum ScanError {
    /// A limit is above its permitted maximum.
    #[error("the scan limit `{field}` is above its permitted maximum")]
    LimitTooLarge {
        /// The name of the field of [`ScanLimits`].
        field: &'static str,
    },
    /// The root path cannot be given to the operating system.
    #[error("the root path is not a valid path")]
    RootPath(#[source] PathError),
    /// The root is not a directory.
    #[error("the root is not a directory")]
    RootNotDirectory,
    /// The root cannot be opened or measured.
    #[error("the root directory cannot be opened")]
    RootUnavailable(#[source] std::io::Error),
    /// The root is a dataless placeholder. The scan does not read it,
    /// because that downloads its content.
    #[error("the root is a dataless placeholder")]
    RootNotHydrated,
    /// The device number of the root does not fit the device-number type.
    #[error("the device number of the root is not supported")]
    RootDeviceUnsupported,
    /// The volume identity in the request is for another device.
    #[error("the volume identity is not for the device of the root")]
    VolumeMismatch,
    /// This build has no scanner for the host operating system.
    #[error("the scanner does not support this operating system")]
    Unsupported,
}

/// The kind of a filesystem entry, from `st_mode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    /// A regular file.
    File,
    /// A directory.
    Directory,
    /// A symbolic link. The scan records the link and does not follow it.
    Symlink,
    /// A FIFO, a socket, or a device node. The scan gives it no size.
    Other,
}

/// One measured entry, given to a [`ScanObserver`](super::ScanObserver).
///
/// The scan does not keep this record. The path is valid only during the
/// call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryRecord<'a> {
    /// The path of the entry: the root as requested, then the names below
    /// it.
    pub path: &'a Path,
    /// The kind of the entry.
    pub kind: EntryKind,
    /// The directory level of the entry. An entry of the root is level 1.
    pub depth: u32,
    /// `st_size` of a regular file or a symbolic link. `None` for a
    /// directory, whose `st_size` is not a content length, and for another
    /// kind.
    pub logical_bytes: Option<Bytes>,
    /// `st_blocks * 512`. For a directory this is the allocation of the
    /// directory object, not of its subtree. `None` for a kind that is not
    /// a file, a directory, or a symbolic link.
    pub allocated_bytes: Option<Bytes>,
    /// `st_nlink`: the number of names of the object.
    pub link_count: u64,
    /// `st_dev` and `st_ino`.
    pub object: FileObjectEvidence,
    /// Whether the sizes of this entry are in the totals. This is `false`
    /// for a second or later name of a hard-linked object.
    pub counted_in_totals: bool,
}

#[cfg(unix)]
impl EntryRecord<'_> {
    /// The path with its exact bytes.
    ///
    /// # Errors
    ///
    /// Returns a [`PathError`] when the path is empty or has a NUL byte. The
    /// scanner makes no such path.
    pub fn lossless_path(&self) -> Result<LosslessPath, PathError> {
        LosslessPath::from_path(self.path)
    }
}

/// The totals of one directory, given to a
/// [`ScanObserver`](super::ScanObserver) when the scan leaves the directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryRecord<'a> {
    /// The path of the directory.
    pub path: &'a Path,
    /// The directory level. The root is level 0.
    pub depth: u32,
    /// The logical size of the counted files and symbolic links below the
    /// directory.
    pub logical_bytes: Bytes,
    /// The allocated size of the directory object and of each counted
    /// object below it.
    pub allocated_bytes: Bytes,
    /// The number of counted names below the directory.
    pub entries: EntryCount,
    /// `partial` when a region below the directory is missing.
    pub coverage: Coverage,
    /// `st_dev` and `st_ino` of the directory.
    pub object: FileObjectEvidence,
}

/// The class of a region that the totals do not fully cover.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegionKind {
    /// The scan could not read the region.
    Inaccessible,
    /// The region changed between two steps of the scan.
    Changed,
    /// The scan did not examine the region, or could not count it.
    Incomplete,
}

/// The cause of a region that the totals do not fully cover.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegionCause {
    /// The operating system denied access (`EACCES` or `EPERM`).
    PermissionDenied,
    /// A native call failed for a reason that is not in this list.
    ReadFailed,
    /// The process has no free file descriptor or no memory for the
    /// directory (`EMFILE`, `ENFILE`, or `ENOMEM`).
    ResourceLimit,
    /// The directory is a dataless placeholder (`SF_DATALESS`, or `EDEADLK`
    /// with materialization off). The scan does not read it, because that
    /// downloads its content.
    NotHydrated,
    /// The entry was in the directory listing and was gone at the
    /// measurement (`ENOENT`).
    Disappeared,
    /// The object at the name was replaced between the measurement and the
    /// open.
    IdentityChanged,
    /// The metadata has a negative size, a negative block count, or a value
    /// that no type of the model can hold.
    InconsistentMetadata,
    /// The directory is below [`ScanLimits::max_depth`].
    DepthLimit,
    /// The scan stopped in this directory at [`ScanLimits::max_entries`].
    EntryLimit,
    /// The scan was cancelled in this directory.
    Cancelled,
    /// The name has several hard links and the scan tracks no more
    /// hard-linked objects ([`ScanLimits::max_hard_link_objects`]).
    HardLinkLimit,
    /// A total of this directory is larger than the largest byte or entry
    /// count.
    Overflow,
}

impl RegionCause {
    /// The class of the region.
    pub const fn kind(self) -> RegionKind {
        match self {
            Self::PermissionDenied | Self::ReadFailed | Self::ResourceLimit | Self::NotHydrated => {
                RegionKind::Inaccessible
            }
            Self::Disappeared | Self::IdentityChanged | Self::InconsistentMetadata => {
                RegionKind::Changed
            }
            Self::DepthLimit
            | Self::EntryLimit
            | Self::Cancelled
            | Self::HardLinkLimit
            | Self::Overflow => RegionKind::Incomplete,
        }
    }

    /// The stable reason of `docs/RESOURCE_MODEL.md` section 4 for the
    /// missing measurement.
    pub const fn unavailable_reason(self) -> UnavailableReason {
        match self {
            Self::PermissionDenied => UnavailableReason::PermissionDenied,
            Self::ReadFailed | Self::ResourceLimit => UnavailableReason::TransientFailure,
            Self::Disappeared => UnavailableReason::ResourceGone,
            Self::IdentityChanged => UnavailableReason::IdentityChanged,
            Self::InconsistentMetadata => UnavailableReason::InconsistentData,
            Self::Overflow => UnavailableReason::Overflow,
            Self::NotHydrated
            | Self::DepthLimit
            | Self::EntryLimit
            | Self::Cancelled
            | Self::HardLinkLimit => UnavailableReason::NotCollected,
        }
    }
}

/// One region that the totals do not fully cover.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ScanRegion {
    /// The entry or the directory. For a cancelled or stopped scan this is
    /// the directory in which the scan stopped; each directory above it is
    /// also incomplete.
    pub path: LosslessPath,
    /// The cause.
    pub cause: RegionCause,
    /// The `errno` value of the failed native call, when there is one.
    pub native_errno: Option<i32>,
}

impl ScanRegion {
    /// The class of the region.
    pub const fn kind(&self) -> RegionKind {
        self.cause.kind()
    }
}

/// One mount boundary that the scan did not cross.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MountBoundary {
    /// The entry whose device number is not that of the root.
    pub path: LosslessPath,
    /// The device number of the other filesystem. `None` when the number
    /// does not fit the device-number type.
    pub device: Option<DeviceNumber>,
}

/// One of the largest files of a scan.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LargeFile {
    /// The path of the file. For a hard-linked object this is the first
    /// name that the scan found.
    pub path: LosslessPath,
    /// `st_size`.
    pub logical_bytes: Bytes,
    /// `st_blocks * 512`. Other files can share this storage.
    pub allocated_bytes: Bytes,
    /// `st_nlink`: the number of names of the object.
    pub link_count: EntryCount,
    /// `st_dev` and `st_ino`.
    pub object: FileObjectEvidence,
}

/// One of the largest directories of a scan. The list does not have the
/// root, whose totals are [`ScanResult::totals`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LargeDirectory {
    /// The path of the directory.
    pub path: LosslessPath,
    /// The logical size of the counted files and symbolic links below the
    /// directory.
    pub logical_bytes: Bytes,
    /// The allocated size of the directory object and of each counted
    /// object below it.
    pub allocated_bytes: Bytes,
    /// The number of counted names below the directory.
    pub entries: EntryCount,
    /// `partial` when a region below the directory is missing.
    pub coverage: Coverage,
    /// `st_dev` and `st_ino` of the directory.
    pub object: FileObjectEvidence,
}

/// The totals of a scan.
///
/// The sizes are object totals: an object with several hard links is in the
/// sizes one time. The entry counts are name totals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct ScanTotals {
    /// The sum of `st_size` of the counted regular files and symbolic
    /// links.
    pub logical_bytes: Bytes,
    /// The sum of `st_blocks * 512` of the root directory and of each
    /// counted file, directory, and symbolic link. This is allocated
    /// storage. It is not exclusive storage and it is not reclaimable
    /// storage.
    pub allocated_bytes: Bytes,
    /// The number of counted names below the root. The root is not a name
    /// of this count.
    pub entries: EntryCount,
    /// The number of names that are regular files.
    pub files: EntryCount,
    /// The number of names that are directories.
    pub directories: EntryCount,
    /// The number of names that are symbolic links.
    pub symlinks: EntryCount,
    /// The number of names of another kind.
    pub other_entries: EntryCount,
}

/// Evidence that the allocated total is not exclusive storage.
///
/// A metadata scan cannot find APFS clones or snapshots, so a zero in each
/// field does not show that the allocated total is exclusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct SharedStorageEvidence {
    /// The number of objects that have several hard links and that the scan
    /// counted one time. A value above zero states that hard-linked data
    /// was found. An object can have more names outside the root.
    pub hard_linked_objects: EntryCount,
    /// The number of later names of those objects. Each is in the entry
    /// counts and is not in the sizes.
    pub hard_link_names_not_counted_again: EntryCount,
    /// The number of hard-linked names that the scan did not count because
    /// of [`ScanLimits::max_hard_link_objects`].
    pub hard_link_names_not_tracked: EntryCount,
    /// The number of counted regular files with the `UF_COMPRESSED` flag.
    /// Always zero on a system that has no such flag.
    pub compressed_files: EntryCount,
    /// The number of counted regular files whose allocated size is less
    /// than their logical size: sparse files, compressed files, and
    /// dataless files.
    pub files_allocated_below_logical: EntryCount,
}

impl SharedStorageEvidence {
    /// Whether the scan found an object with several hard links.
    pub fn hard_linked_data_found(&self) -> bool {
        self.hard_linked_objects != EntryCount::ZERO
            || self.hard_link_names_not_tracked != EntryCount::ZERO
    }
}

/// How a scan ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanCompletion {
    /// The scan examined each directory that it could open.
    Finished,
    /// The caller cancelled the scan.
    Cancelled,
    /// The scan stopped at [`ScanLimits::max_entries`].
    EntryLimitReached,
}

/// A time of a scan, from the [`ScanClock`](super::ScanClock) of the caller.
/// A clock that cannot give a value gives `None`, not a substitute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct ScanTimestamp {
    /// The wall-clock time, for display and history.
    pub wall: Option<WallTime>,
    /// The time on the host monotonic timeline of the clock adapter.
    pub monotonic_ns: Option<MonotonicNanos>,
}

/// The filesystem evidence of the root of a scan.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ScanVolumeEvidence {
    /// `st_dev` of the root. The scan examined only entries of this device.
    pub device: DeviceNumber,
    /// `st_dev` and `st_ino` of the root directory that the scan opened.
    pub root_object: FileObjectEvidence,
    /// `f_fstypename` of `fstatfs` on the root, for example `apfs`. `None`
    /// when the query failed or the system has no such field.
    pub filesystem_type: Option<String>,
    /// `f_mntonname` of `fstatfs` on the root. `None` when the query failed
    /// or the system has no such field.
    pub mount_point: Option<LosslessPath>,
    /// The volume identity from the request.
    pub identity: Option<VolumeIdentity>,
}

/// The result of one scan.
///
/// The result has aggregates and bounded lists. `coverage` is `partial`
/// when a region is missing; the totals are then a sum of the measured part
/// only. `complete` means complete for the root, the filesystem of the
/// root, and the collection method. It is not an atomic view of a
/// filesystem that changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanResult {
    /// [`SCAN_RESULT_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// The identity of the scan.
    pub scan_id: ScanId,
    /// The root as requested.
    pub root: LosslessPath,
    /// The filesystem evidence of the root.
    pub volume: ScanVolumeEvidence,
    /// When the scan started.
    pub started: ScanTimestamp,
    /// When the scan finished.
    pub finished: ScanTimestamp,
    /// The duration of the scan on a process-local clock. `None` when the
    /// duration does not fit the type.
    pub elapsed: Option<Nanoseconds>,
    /// How the scan ended.
    pub completion: ScanCompletion,
    /// `complete` or `partial`, for the totals and the lists.
    pub coverage: Coverage,
    /// The limits of the scan.
    pub limits: ScanLimits,
    /// The number of names that the scan examined. This number includes
    /// names that the scan could not measure, and boundaries.
    pub entries_examined: EntryCount,
    /// The totals of the measured part.
    pub totals: ScanTotals,
    /// Evidence that the allocated total is not exclusive storage.
    pub shared_storage: SharedStorageEvidence,
    /// The largest files by allocated size, largest first.
    pub largest_files: Vec<LargeFile>,
    /// The largest directories by allocated size, largest first. A
    /// directory and a directory above it can both be in the list.
    pub largest_directories: Vec<LargeDirectory>,
    /// The mount boundaries that the scan did not cross. A boundary does
    /// not make the coverage partial: it is outside the scope of the scan.
    pub boundaries: Vec<MountBoundary>,
    /// The number of boundaries that are not in `boundaries`.
    pub boundaries_omitted: EntryCount,
    /// The inaccessible, changed, and incomplete regions.
    pub regions: Vec<ScanRegion>,
    /// The number of regions that are not in `regions`.
    pub regions_omitted: EntryCount,
}

/// The totals of a scan as observations of the `scan` scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanObservations {
    /// [`METRIC_SCAN_LOGICAL_BYTES`].
    pub logical_bytes: Observation<Bytes>,
    /// [`METRIC_SCAN_ALLOCATED_BYTES`].
    pub allocated_bytes: Observation<Bytes>,
    /// [`METRIC_SCAN_EXCLUSIVE_BYTES`]. Always unavailable with the reason
    /// `unsupported`.
    pub exclusive_bytes: Observation<Bytes>,
    /// [`METRIC_SCAN_ENTRIES`].
    pub entries: Observation<EntryCount>,
}

impl ScanResult {
    /// The totals as observations with the scope of this scan.
    ///
    /// The caller gives the provenance and the acquisition context, because
    /// the worker identity and the host clock are not part of a scan. Each
    /// observation has the coverage of the scan.
    ///
    /// # Errors
    ///
    /// Returns a [`MetricIdError`] when a metric name of this module is not
    /// a valid metric name. A test checks each name.
    pub fn observations(
        &self,
        source: &Source,
        sample: &Sample,
    ) -> Result<ScanObservations, MetricIdError> {
        let scope: Scope = Scope::scan(self.scan_id.clone());
        let bytes = |name: &str, reading: Reading<Bytes>, kind: MetricKind| {
            Ok(Observation {
                metric_id: MetricId::new(name)?,
                scope: scope.clone(),
                reading,
                unit: Unit::Byte,
                kind,
                coverage: self.coverage.clone(),
                source: source.clone(),
                sample: sample.clone(),
            })
        };
        Ok(ScanObservations {
            logical_bytes: bytes(
                METRIC_SCAN_LOGICAL_BYTES,
                Reading::Available(self.totals.logical_bytes),
                MetricKind::Gauge,
            )?,
            allocated_bytes: bytes(
                METRIC_SCAN_ALLOCATED_BYTES,
                Reading::Available(self.totals.allocated_bytes),
                MetricKind::Gauge,
            )?,
            exclusive_bytes: bytes(
                METRIC_SCAN_EXCLUSIVE_BYTES,
                Reading::Unavailable(UnavailableReason::Unsupported),
                MetricKind::Gauge,
            )?,
            entries: Observation {
                metric_id: MetricId::new(METRIC_SCAN_ENTRIES)?,
                scope: scope.clone(),
                reading: Reading::Available(self.totals.entries),
                unit: Unit::Entry,
                kind: MetricKind::Gauge,
                coverage: self.coverage.clone(),
                source: source.clone(),
                sample: sample.clone(),
            },
        })
    }
}
