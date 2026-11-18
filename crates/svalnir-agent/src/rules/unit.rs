//! The steps that the rules share: the metadata snapshot of one object,
//! the bounded read of a record file, the root checks, the bounds of a
//! discovery, the measurement of one unit with the scanner, and the
//! candidate record.
//!
//! Each step reads metadata or a small record file. No step changes the
//! filesystem. A path check in this file is evidence for a plan and not a
//! guard of a removal: the executor examines each object again, relative
//! to an open directory, immediately before its step.

use std::collections::BTreeSet;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::time::Instant;

use svalnir_core::action::{FileObjectType, WorkCharge};
use svalnir_core::file::{DeviceNumber, FileObjectEvidence, InodeNumber, LosslessPath};
use svalnir_core::id::{ScanId, TargetId};
use svalnir_core::observation::Coverage;
use svalnir_core::policy::{
    ActivityFact, CleanupCandidate, CleanupFacts, OwnerFact, ProtectionFact, RuleReadiness,
};
use svalnir_core::process::Uid;
use svalnir_core::quantity::{Bytes, EntryCount, Nanoseconds};
use svalnir_core::rule::{
    CandidateEligibility, Fact, LayoutSupport, Rule, RuleCandidate, RuleCandidateRecord, RuleMode,
};
use svalnir_core::time::{MonotonicNanos, WallTime};

use super::model::{
    ChangeStamp, DiscoveredCandidate, Discovery, DiscoveryCompletion, DiscoveryControl,
    DiscoveryError, DiscoveryScope, MeasurementSource, ReclaimEstimate, RootEvidence, SizeMeasure,
    SkipReason, SkippedUnit, TargetEvidence, UnitMeasurement,
};
use crate::scan::{
    CancellationToken, EntryKind, EntryRecord, RegionCause, ScanCompletion, ScanError, ScanLimits,
    ScanObserver, ScanRequest, ScanResult, run_scan,
};

/// The number of bytes of one block of `st_blocks`.
const BLOCK_BYTES: u64 = 512;

/// The kind of an object, from `st_mode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ObjectKind {
    Directory,
    RegularFile,
    SymbolicLink,
    Other,
}

/// The metadata of one object at one time, from `lstat` or `fstat`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ObjectSnapshot {
    pub(super) object: FileObjectEvidence,
    pub(super) kind: ObjectKind,
    pub(super) owner: Uid,
    pub(super) link_count: u64,
    /// `st_size`.
    pub(super) size: u64,
    /// `st_blocks * 512`. `None` when the product does not fit.
    pub(super) allocated: Option<u64>,
    pub(super) stamp: ChangeStamp,
}

impl ObjectSnapshot {
    fn from_metadata(metadata: &Metadata) -> io::Result<Self> {
        let unsupported =
            || io::Error::new(io::ErrorKind::InvalidData, "unsupported device number");
        let device: i32 = i32::try_from(metadata.dev()).map_err(|_| unsupported())?;
        let file_type = metadata.file_type();
        let kind: ObjectKind = if file_type.is_symlink() {
            ObjectKind::SymbolicLink
        } else if file_type.is_dir() {
            ObjectKind::Directory
        } else if file_type.is_file() {
            ObjectKind::RegularFile
        } else {
            ObjectKind::Other
        };
        Ok(Self {
            object: FileObjectEvidence {
                device: DeviceNumber::new(device),
                inode: InodeNumber::new(metadata.ino()),
            },
            kind,
            owner: Uid::new(metadata.uid()),
            link_count: metadata.nlink(),
            size: metadata.size(),
            allocated: metadata.blocks().checked_mul(BLOCK_BYTES),
            stamp: ChangeStamp {
                modified_seconds: metadata.mtime(),
                modified_nanoseconds: metadata.mtime_nsec(),
                changed_seconds: metadata.ctime(),
                changed_nanoseconds: metadata.ctime_nsec(),
            },
        })
    }

    /// The modification time. `None` when the time is outside the range of
    /// [`WallTime`].
    pub(super) fn modified(&self) -> Option<WallTime> {
        let nanoseconds: u32 = u32::try_from(self.stamp.modified_nanoseconds).ok()?;
        WallTime::from_unix(self.stamp.modified_seconds, nanoseconds).ok()
    }

    /// The object type of a plan target. `None` for a kind that no rule
    /// removes.
    pub(super) fn object_type(&self) -> Option<FileObjectType> {
        match self.kind {
            ObjectKind::Directory => Some(FileObjectType::Directory),
            ObjectKind::RegularFile => Some(FileObjectType::RegularFile),
            ObjectKind::SymbolicLink => Some(FileObjectType::SymbolicLink),
            ObjectKind::Other => None,
        }
    }
}

/// The metadata of the object at `path`. A symbolic link at the last
/// component is the object; it is not followed.
pub(super) fn lstat(path: &Path) -> io::Result<ObjectSnapshot> {
    ObjectSnapshot::from_metadata(&fs::symlink_metadata(path)?)
}

/// The reason of a failed metadata read, as a skip reason.
pub(super) fn reason_of(error: &io::Error) -> SkipReason {
    match error.kind() {
        io::ErrorKind::NotFound => SkipReason::Vanished,
        io::ErrorKind::PermissionDenied => SkipReason::AccessDenied,
        _ => SkipReason::MeasurementIncomplete,
    }
}

/// The result of the read of one record file.
#[derive(Debug)]
pub(super) enum RecordRead {
    /// No object has the name.
    Absent,
    /// The operating system denied the read.
    Denied,
    /// The object is not a plain file with one name and the expected
    /// owner, is too large, changed during the read, or cannot be read.
    Invalid,
    /// The content and the metadata of the file.
    Read {
        bytes: Vec<u8>,
        snapshot: ObjectSnapshot,
    },
}

/// Reads a record file of no more than `max_bytes`.
///
/// The file must be a regular file with one name and the owner
/// `principal`. The open does not follow a symbolic link and does not
/// block on a FIFO, and the open file is compared with the object that
/// `lstat` gave.
pub(super) fn read_record(path: &Path, max_bytes: u64, principal: Uid) -> RecordRead {
    let before: ObjectSnapshot = match lstat(path) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            return match error.kind() {
                io::ErrorKind::NotFound => RecordRead::Absent,
                io::ErrorKind::PermissionDenied => RecordRead::Denied,
                _ => RecordRead::Invalid,
            };
        }
    };
    if before.kind != ObjectKind::RegularFile
        || before.link_count != 1
        || before.owner != principal
        || before.size > max_bytes
    {
        return RecordRead::Invalid;
    }
    let opened: io::Result<File> = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path);
    let file: File = match opened {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            return RecordRead::Denied;
        }
        Err(_) => return RecordRead::Invalid,
    };
    let Ok(snapshot) = file
        .metadata()
        .and_then(|metadata| ObjectSnapshot::from_metadata(&metadata))
    else {
        return RecordRead::Invalid;
    };
    // The open file is the object of `lstat`, and it still has one name,
    // the expected owner, and a permitted size.
    if snapshot.object != before.object
        || snapshot.kind != ObjectKind::RegularFile
        || snapshot.link_count != 1
        || snapshot.owner != principal
        || snapshot.size > max_bytes
    {
        return RecordRead::Invalid;
    }
    let mut bytes: Vec<u8> = Vec::new();
    // One byte more than the limit shows a file that grew after `lstat`.
    let limit: u64 = max_bytes.saturating_add(1);
    let mut reader = file.take(limit);
    let is_read: bool = reader.read_to_end(&mut bytes).is_ok()
        && u64::try_from(bytes.len()).is_ok_and(|length| length == snapshot.size);
    // A file that changed during the read has other metadata after it.
    let after: Option<ObjectSnapshot> = reader
        .into_inner()
        .metadata()
        .ok()
        .and_then(|metadata| ObjectSnapshot::from_metadata(&metadata).ok());
    if is_read && after == Some(snapshot) {
        RecordRead::Read { bytes, snapshot }
    } else {
        RecordRead::Invalid
    }
}

/// Whether one path is the other path or is below it, by path component.
fn overlaps(first: &Path, second: &Path) -> bool {
    first.starts_with(second) || second.starts_with(first)
}

/// Whether `path` is absolute and has no `.` and no `..` component.
pub(super) fn is_plain_absolute(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

/// Whether `path` is relative, is not empty, and has plain names only.
pub(super) fn is_plain_relative(path: &Path) -> bool {
    let mut components = path.components().peekable();
    components.peek().is_some()
        && components.all(|component| matches!(component, Component::Normal(_)))
}

/// The root of one discovery after its checks.
#[derive(Debug)]
pub(super) struct RootView {
    pub(super) evidence: RootEvidence,
    /// The path as the caller gave it.
    pub(super) path: PathBuf,
    /// The path with each symbolic link of its ancestors resolved, when it
    /// is different from `path`.
    resolved: Option<PathBuf>,
    snapshot: ObjectSnapshot,
    /// The hard exclusions, as given and resolved.
    protected: Vec<PathBuf>,
    /// The user exclusions, as given and resolved.
    excluded: Vec<PathBuf>,
}

/// Each path of `list` as given, and its resolved form when that form is
/// different. A path that cannot be resolved stays as given.
fn with_resolved_forms(list: &[PathBuf]) -> Vec<PathBuf> {
    let mut forms: Vec<PathBuf> = Vec::with_capacity(list.len());
    for path in list {
        forms.push(path.clone());
        if let Ok(resolved) = fs::canonicalize(path)
            && &resolved != path
        {
            forms.push(resolved);
        }
    }
    forms
}

impl RootView {
    /// Checks the root of `scope`: a plain absolute path to a directory
    /// that is not a symbolic link, with the owner of the discovery, on
    /// the bound device, and outside each protected path.
    pub(super) fn open(scope: &DiscoveryScope<'_>) -> Result<Self, DiscoveryError> {
        let path: &Path = &scope.root.path;
        if !is_plain_absolute(path) {
            return Err(DiscoveryError::RootPath);
        }
        let snapshot: ObjectSnapshot = lstat(path).map_err(DiscoveryError::RootUnavailable)?;
        if snapshot.kind != ObjectKind::Directory {
            return Err(DiscoveryError::RootNotDirectory);
        }
        if snapshot.owner != scope.principal {
            return Err(DiscoveryError::RootOwner);
        }
        if snapshot.object.device != scope.root.device {
            return Err(DiscoveryError::RootDevice);
        }
        let resolved: Option<PathBuf> = fs::canonicalize(path)
            .ok()
            .filter(|resolved| resolved != path);
        let protected: Vec<PathBuf> = with_resolved_forms(scope.protected_paths);
        let root_forms = || std::iter::once(path).chain(resolved.as_deref());
        if root_forms().any(|form| protected.iter().any(|entry| overlaps(form, entry))) {
            return Err(DiscoveryError::RootOverlapsProtected);
        }
        let display: LosslessPath =
            LosslessPath::from_path(path).map_err(|_| DiscoveryError::RootPath)?;
        Ok(Self {
            evidence: RootEvidence {
                root_id: scope.root.root_id.clone(),
                path: display,
                object: snapshot.object,
                volume_id: scope.root.volume_id.clone(),
                mount_id: scope.root.mount_id.clone(),
            },
            path: path.to_path_buf(),
            resolved,
            snapshot,
            protected,
            excluded: with_resolved_forms(scope.user_exclusions),
        })
    }

    /// The device of the root.
    pub(super) fn device(&self) -> DeviceNumber {
        self.snapshot.object.device
    }

    /// Whether a hard exclusion or a user exclusion is the unit, is above
    /// it, or is below it.
    pub(super) fn is_excluded(&self, relative: &Path) -> bool {
        let forms = std::iter::once(&self.path).chain(self.resolved.as_ref());
        forms.into_iter().any(|root| {
            let unit: PathBuf = root.join(relative);
            self.protected
                .iter()
                .chain(&self.excluded)
                .any(|entry| overlaps(&unit, entry))
        })
    }

    /// Whether `path` is the root, is in it, or contains it.
    pub(super) fn overlaps_path(&self, path: &Path) -> bool {
        std::iter::once(&self.path)
            .chain(self.resolved.as_ref())
            .any(|root| overlaps(root, path))
    }

    /// Whether the root is `directory` or is below it.
    pub(super) fn is_within(&self, directory: &Path) -> bool {
        std::iter::once(&self.path)
            .chain(self.resolved.as_ref())
            .any(|root| root.starts_with(directory))
    }

    /// Checks that the object at the root path is the object of the first
    /// check.
    pub(super) fn verify_unchanged(&self) -> Result<(), DiscoveryError> {
        match lstat(&self.path) {
            Ok(now) if now.object == self.snapshot.object && now.kind == self.snapshot.kind => {
                Ok(())
            }
            _ => Err(DiscoveryError::RootChanged),
        }
    }
}

/// The evidence of a unit from its snapshot. `None` for a kind that no
/// rule removes, or for a name that is not a valid path.
pub(super) fn target_evidence(
    relative: &Path,
    snapshot: &ObjectSnapshot,
) -> Option<TargetEvidence> {
    Some(TargetEvidence {
        relative_entry: LosslessPath::from_path(relative).ok()?,
        object: snapshot.object,
        object_type: snapshot.object_type()?,
        owner: snapshot.owner,
        link_count: snapshot.link_count,
        stamp: snapshot.stamp,
    })
}

/// The progress of one discovery against its bounds.
#[derive(Debug)]
pub(super) struct Bounds<'a> {
    control: &'a DiscoveryControl<'a>,
    started: Instant,
    units_examined: u64,
    entries_examined: u64,
}

impl<'a> Bounds<'a> {
    pub(super) fn new(control: &'a DiscoveryControl<'a>) -> Result<Self, DiscoveryError> {
        control.limits.validate()?;
        Ok(Self {
            control,
            started: Instant::now(),
            units_examined: 0,
            entries_examined: 0,
        })
    }

    pub(super) fn control(&self) -> &'a DiscoveryControl<'a> {
        self.control
    }

    /// The wall-clock time now, when the clock gives one.
    pub(super) fn wall_now(&self) -> Option<WallTime> {
        self.control.clock.now().wall
    }

    /// The time now on the monotonic timeline of the clock, when the clock
    /// gives one.
    pub(super) fn monotonic_now(&self) -> Option<MonotonicNanos> {
        self.control.clock.now().monotonic_ns
    }

    fn deadline(&self) -> Option<Instant> {
        self.started.checked_add(self.control.limits.max_duration)
    }

    fn is_past_deadline(&self) -> bool {
        self.started.elapsed() >= self.control.limits.max_duration
    }

    fn remaining_entries(&self) -> u64 {
        self.control
            .limits
            .max_entries
            .get()
            .saturating_sub(self.entries_examined)
    }

    /// The reason the discovery must stop before more work, if there is
    /// one.
    pub(super) fn stop(&self) -> Option<DiscoveryCompletion> {
        if self.control.cancel.is_cancelled() {
            Some(DiscoveryCompletion::Cancelled)
        } else if self.is_past_deadline() {
            Some(DiscoveryCompletion::TimeLimitReached)
        } else if self.remaining_entries() == 0 {
            Some(DiscoveryCompletion::EntryLimitReached)
        } else {
            None
        }
    }

    /// Counts one name of the root or one known candidate.
    pub(super) fn take_unit(&mut self) -> Result<(), DiscoveryCompletion> {
        // The entry bound belongs to a measurement: a discovery that
        // measures nothing does not stop at it.
        if self.control.cancel.is_cancelled() {
            return Err(DiscoveryCompletion::Cancelled);
        }
        if self.is_past_deadline() {
            return Err(DiscoveryCompletion::TimeLimitReached);
        }
        if self.units_examined >= u64::from(self.control.limits.max_units) {
            return Err(DiscoveryCompletion::UnitLimitReached);
        }
        self.units_examined = self.units_examined.saturating_add(1);
        Ok(())
    }
}

/// What a rule says about one entry below a unit: a reason that the unit
/// cannot be a candidate, or nothing.
pub(super) type Classifier<'a> = &'a mut dyn FnMut(&Path, EntryKind) -> Option<SkipReason>;

struct UnitObserver<'a> {
    unit: &'a Path,
    caller_cancel: &'a CancellationToken,
    scan_cancel: CancellationToken,
    deadline: Option<Instant>,
    timed_out: bool,
    supports_symlinks: bool,
    /// The sum of the larger size of each counted object. `None` after an
    /// overflow.
    work_bytes: Option<u64>,
    reasons: BTreeSet<SkipReason>,
    classify: Classifier<'a>,
    /// The user of the discovery. Each object below the unit must have
    /// this owner.
    owner: Uid,
    /// The newest modification or status change of an object below the
    /// unit.
    newest_change: Option<WallTime>,
}

/// Examines the owner and the times of one measured entry below a unit.
///
/// The values are those of the record of the scanner: one `fstatat` gave
/// them with the identity and the sizes of the entry, so they are of the
/// object that the scanner measured, and no second read by path is
/// necessary. Returns the newer of the modification time and the
/// status-change time.
///
/// # Errors
///
/// Returns the reason that the unit cannot be a candidate: the owner is
/// not `owner`, or a time is not valid.
pub(super) fn entry_change(entry: &EntryRecord<'_>, owner: Uid) -> Result<WallTime, SkipReason> {
    if entry.owner != owner {
        return Err(SkipReason::WrongOwner);
    }
    match (entry.modified, entry.changed) {
        (Some(modified), Some(changed)) => Ok(modified.max(changed)),
        _ => Err(SkipReason::AgeUnknown),
    }
}

impl ScanObserver for UnitObserver<'_> {
    fn entry_listed(&mut self, _path: &Path) {
        if self.caller_cancel.is_cancelled() {
            self.scan_cancel.cancel();
        } else if self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            self.timed_out = true;
            self.scan_cancel.cancel();
        }
    }

    fn entry_measured(&mut self, entry: &EntryRecord<'_>) {
        if entry.counted_in_totals {
            let logical: u64 = entry.logical_bytes.map_or(0, Bytes::get);
            let allocated: u64 = entry.allocated_bytes.map_or(0, Bytes::get);
            self.work_bytes = self
                .work_bytes
                .and_then(|sum| sum.checked_add(logical.max(allocated)));
        }
        match entry.kind {
            EntryKind::File if entry.link_count > 1 => {
                self.reasons.insert(SkipReason::HardLinked);
            }
            EntryKind::Symlink if !self.supports_symlinks => {
                self.reasons.insert(SkipReason::SymbolicLink);
            }
            EntryKind::Other => {
                self.reasons.insert(SkipReason::UnsupportedObject);
            }
            EntryKind::File | EntryKind::Directory | EntryKind::Symlink => {}
        }
        match entry_change(entry, self.owner) {
            Ok(change) => {
                self.newest_change = Some(
                    self.newest_change
                        .map_or(change, |newest| newest.max(change)),
                );
            }
            Err(reason) => {
                self.reasons.insert(reason);
            }
        }
        match entry.path.strip_prefix(self.unit) {
            Ok(relative) => {
                if let Some(reason) = (self.classify)(relative, entry.kind) {
                    self.reasons.insert(reason);
                }
            }
            // An entry that the rule cannot classify is not shown to be
            // safe.
            Err(_) => {
                self.reasons.insert(SkipReason::MeasurementIncomplete);
            }
        }
    }
}

/// The result of the measurement of one unit.
#[derive(Debug)]
pub(super) enum Measured {
    /// The measurement examined each object of the unit, and the unit has
    /// no object that prevents a candidate.
    Complete(UnitMeasurement),
    /// The unit cannot be a candidate. The list is not empty.
    Rejected(BTreeSet<SkipReason>),
    /// A bound of the discovery stopped the measurement.
    Stopped(DiscoveryCompletion),
}

fn region_reason(cause: RegionCause) -> SkipReason {
    match cause {
        RegionCause::PermissionDenied => SkipReason::AccessDenied,
        RegionCause::Disappeared | RegionCause::IdentityChanged => SkipReason::IdentityChanged,
        RegionCause::ReadFailed
        | RegionCause::ResourceLimit
        | RegionCause::NotHydrated
        | RegionCause::InconsistentMetadata
        | RegionCause::DepthLimit
        | RegionCause::EntryLimit
        | RegionCause::Cancelled
        | RegionCause::HardLinkLimit
        | RegionCause::Overflow => SkipReason::MeasurementIncomplete,
    }
}

/// The scan identity of each unit measurement. The result of the scan is
/// not saved, so the identity names no record.
const UNIT_SCAN_ID: &str = "rule-unit-measurement";

/// Measures the unit at `unit_path` with the scanner.
///
/// `unit` is the snapshot of the unit before the measurement. The scanner
/// follows a symbolic link in the path of its root, so the object that the
/// scanner opened is compared with `unit`. The scan stops at the smaller
/// of the remaining entries of the discovery and the item ceiling of one
/// candidate.
///
/// # Errors
///
/// Returns a [`DiscoveryError`] when the scanner rejects the request of
/// the rule, which is a defect, or when the host has no scanner.
fn measure_unit(
    unit_path: &Path,
    unit: &ObjectSnapshot,
    rule: &Rule,
    bounds: &mut Bounds<'_>,
    classify: Classifier<'_>,
    principal: Uid,
) -> Result<(Measured, Option<WallTime>), DiscoveryError> {
    if let Some(completion) = bounds.stop() {
        return Ok((Measured::Stopped(completion), None));
    }
    let ceiling: WorkCharge = rule.budget.per_candidate;
    let remaining: u64 = bounds.remaining_entries();
    // The unit itself is one item of the charge, so a unit with as many
    // names below it as the ceiling is over the ceiling.
    let scan_limit: u64 = remaining.min(ceiling.items.get());
    let limits: ScanLimits = ScanLimits {
        max_depth: bounds.control.limits.max_depth,
        max_entries: EntryCount::new(scan_limit),
        max_largest_files: 0,
        max_largest_directories: 0,
        max_recorded_regions: 64,
        max_recorded_boundaries: 4,
        max_hard_link_objects: 1_024,
    };
    let request: ScanRequest = ScanRequest {
        scan_id: ScanId::new(UNIT_SCAN_ID)
            .map_err(|_| DiscoveryError::Internal("the scan identity"))?,
        root: LosslessPath::from_path(unit_path)
            .map_err(|_| DiscoveryError::Internal("the unit path"))?,
        limits,
        volume: None,
    };
    let scan_cancel: CancellationToken = CancellationToken::new();
    let mut observer: UnitObserver<'_> = UnitObserver {
        unit: unit_path,
        caller_cancel: bounds.control.cancel,
        scan_cancel: scan_cancel.clone(),
        deadline: bounds.deadline(),
        timed_out: false,
        supports_symlinks: rule
            .exclusions
            .supported_object_types
            .contains(&FileObjectType::SymbolicLink),
        work_bytes: Some(0),
        reasons: BTreeSet::new(),
        classify,
        owner: principal,
        newest_change: None,
    };
    let scanned: Result<ScanResult, ScanError> =
        run_scan(&request, &scan_cancel, bounds.control.clock, &mut observer);
    let result: ScanResult = match scanned {
        Ok(result) => result,
        Err(error) => {
            return scan_refusal(error).map(|reasons| (Measured::Rejected(reasons), None));
        }
    };
    bounds.entries_examined = bounds
        .entries_examined
        .saturating_add(result.entries_examined.get());

    let newest_change: Option<WallTime> = observer.newest_change;
    let scan: FinishedScan<'_> = FinishedScan {
        result: &result,
        reasons: observer.reasons,
        timed_out: observer.timed_out,
        work_bytes: observer.work_bytes,
        scan_limit,
    };
    Ok((scan.conclude(unit, &ceiling), newest_change))
}

/// The skip reason of a scan that did not start.
///
/// # Errors
///
/// Returns a [`DiscoveryError`] when the scanner rejects the request of
/// the rule, which is a defect, or when the host has no scanner.
fn scan_refusal(error: ScanError) -> Result<BTreeSet<SkipReason>, DiscoveryError> {
    let reason: SkipReason = match error {
        ScanError::RootUnavailable(error) => reason_of(&error),
        ScanError::RootNotDirectory => SkipReason::IdentityChanged,
        ScanError::RootNotHydrated | ScanError::RootDeviceUnsupported => {
            SkipReason::MeasurementIncomplete
        }
        ScanError::Unsupported => return Err(DiscoveryError::Unsupported),
        ScanError::LimitTooLarge { .. } | ScanError::RootPath(_) => {
            return Err(DiscoveryError::Internal("the scan request"));
        }
        ScanError::VolumeMismatch => return Err(DiscoveryError::Internal("the scan volume")),
    };
    Ok(BTreeSet::from([reason]))
}

/// A scan of one unit that started, with what its observer found.
struct FinishedScan<'a> {
    result: &'a ScanResult,
    reasons: BTreeSet<SkipReason>,
    timed_out: bool,
    work_bytes: Option<u64>,
    /// The entry limit of the scan.
    scan_limit: u64,
}

impl FinishedScan<'_> {
    /// The measurement of the unit, the reasons that it cannot be a
    /// candidate, or the bound that stopped the scan.
    fn conclude(self, unit: &ObjectSnapshot, ceiling: &WorkCharge) -> Measured {
        let Self {
            result,
            mut reasons,
            timed_out,
            work_bytes,
            scan_limit,
        } = self;
        match result.completion {
            ScanCompletion::Finished => {}
            ScanCompletion::Cancelled => {
                return Measured::Stopped(if timed_out {
                    DiscoveryCompletion::TimeLimitReached
                } else {
                    DiscoveryCompletion::Cancelled
                });
            }
            ScanCompletion::EntryLimitReached => {
                if scan_limit < ceiling.items.get() {
                    return Measured::Stopped(DiscoveryCompletion::EntryLimitReached);
                }
                reasons.insert(SkipReason::OverCandidateCeiling);
            }
        }
        if result.volume.root_object != unit.object {
            reasons.insert(SkipReason::IdentityChanged);
        }
        if !result.boundaries.is_empty() || result.boundaries_omitted != EntryCount::ZERO {
            reasons.insert(SkipReason::MountCrossing);
        }
        if result.shared_storage.hard_linked_data_found() {
            reasons.insert(SkipReason::HardLinked);
        }
        reasons.extend(
            result
                .regions
                .iter()
                .map(|region| region_reason(region.cause)),
        );
        let is_complete: bool = matches!(result.coverage, Coverage::Complete)
            && result.regions_omitted == EntryCount::ZERO;
        if !is_complete && !reasons.contains(&SkipReason::OverCandidateCeiling) {
            reasons.insert(SkipReason::MeasurementIncomplete);
        }

        let totals = result.totals;
        let charge: Option<WorkCharge> = work_bytes
            .zip(unit.allocated)
            .and_then(|(below, own)| below.checked_add(own))
            .zip(totals.entries.checked_add(EntryCount::new(1)))
            .map(|(work_bytes, items)| WorkCharge::new(Bytes::new(work_bytes), items));
        let Some(charge) = charge else {
            reasons.insert(SkipReason::MeasurementIncomplete);
            return Measured::Rejected(reasons);
        };
        if !charge.fits_in(ceiling) {
            reasons.insert(SkipReason::OverCandidateCeiling);
        }
        if !reasons.is_empty() {
            return Measured::Rejected(reasons);
        }
        Measured::Complete(UnitMeasurement {
            source: MeasurementSource::Scanned,
            logical_bytes: totals.logical_bytes,
            allocated_bytes: totals.allocated_bytes,
            files: totals.files,
            directories: totals.directories,
            symlinks: totals.symlinks,
            charge,
            estimate: ReclaimEstimate {
                bytes: totals.allocated_bytes,
                measure: SizeMeasure::AllocatedBytes,
                exclusive_storage_known: false,
                files_allocated_below_logical: result.shared_storage.files_allocated_below_logical,
            },
            measured_at: result.finished.wall,
        })
    }
}

/// What a rule found about one unit.
#[derive(Debug)]
pub(super) struct Assessment {
    /// The unit, relative to the root.
    pub(super) relative: PathBuf,
    /// The layout, when the rule recognized one.
    pub(super) layout: Option<&'static str>,
    /// The evidence of the predicates. Predicates 3, 9, and 10 stay
    /// `unknown`.
    pub(super) eligibility: CandidateEligibility,
    /// The reasons that a predicate is not satisfied.
    pub(super) reasons: BTreeSet<SkipReason>,
    pub(super) evidence: Option<TargetEvidence>,
    pub(super) measurement: Option<UnitMeasurement>,
    /// The activity, as the policy reads it.
    pub(super) activity: ActivityFact,
    /// The newest modification or status change of an object below the
    /// unit. `None` when the unit was not measured in this discovery or
    /// has no object below it.
    pub(super) newest_content_change: Option<WallTime>,
}

impl Assessment {
    /// The assessment of a unit that the rule did not examine: each
    /// predicate is `unknown`.
    pub(super) fn new(relative: PathBuf) -> Self {
        Self {
            relative,
            layout: None,
            eligibility: CandidateEligibility::unknown(),
            reasons: BTreeSet::new(),
            evidence: None,
            measurement: None,
            activity: ActivityFact::Unknown,
            newest_content_change: None,
        }
    }

    /// A skip with one reason, before the rule recognized a layout.
    pub(super) fn skip(relative: PathBuf, reason: SkipReason) -> Self {
        let mut assessment: Self = Self::new(relative);
        assessment.reasons.insert(reason);
        assessment
    }
}

/// The candidate or the skip that an assessment gives.
#[derive(Debug)]
pub(super) enum Concluded {
    Candidate(Box<DiscoveredCandidate>),
    Skipped(Box<SkippedUnit>),
}

/// Makes the candidate or the skip of one assessment.
///
/// A unit is a candidate only when the rule supports its layout (predicate
/// 1), its identity and owner match (2), its content can be made again
/// (4), its protocols are valid (6), no exclusion overlaps it (7), and its
/// complete charge is known (8). The age and the inactivity (5) can be
/// open: such a candidate has blockers. Each other unit is a skip.
///
/// # Errors
///
/// Returns [`DiscoveryError::Internal`] when the assessment is not
/// consistent or the foundation check rejects the record. Each case is a
/// defect of the rule.
pub(super) fn conclude(
    rule: &Rule,
    root: &RootView,
    assessment: Assessment,
) -> Result<Concluded, DiscoveryError> {
    let Assessment {
        relative,
        layout,
        eligibility,
        reasons,
        evidence,
        measurement,
        activity,
        newest_content_change: _,
    } = assessment;
    let relative_entry: LosslessPath = LosslessPath::from_path(&relative)
        .map_err(|_| DiscoveryError::Internal("the unit name"))?;
    let is_classified: bool = eligibility.rule_supports_layout.is_satisfied()
        && eligibility.identity_matches.is_satisfied()
        && eligibility.regenerable.is_satisfied()
        && eligibility.protocols_valid.is_satisfied()
        && eligibility.no_exclusion_overlap.is_satisfied()
        && eligibility.unit_and_charge_known.is_satisfied();
    let parts = (is_classified, layout, evidence, measurement);
    let (true, Some(layout), Some(evidence), Some(measurement)) = parts else {
        let (_, layout, evidence, _) = parts;
        if reasons.is_empty() {
            return Err(DiscoveryError::Internal("a skip with no reason"));
        }
        return Ok(Concluded::Skipped(Box::new(SkippedUnit {
            relative_entry,
            layout: layout.map(str::to_owned),
            reasons: reasons.into_iter().collect(),
            eligibility,
            evidence,
        })));
    };
    let support: &LayoutSupport = rule
        .layouts
        .iter()
        .find(|support| support.layout == layout)
        .ok_or(DiscoveryError::Internal("the layout name"))?;
    let is_inactive: bool = eligibility.age_and_inactivity.is_satisfied();
    if is_inactive != matches!(activity, ActivityFact::Inactive { .. }) {
        return Err(DiscoveryError::Internal("the activity fact"));
    }
    if is_inactive != reasons.is_empty() {
        return Err(DiscoveryError::Internal("the blockers of a candidate"));
    }
    let object: FileObjectEvidence = evidence.object;
    let target_id: TargetId = TargetId::new(format!(
        "file:{}:{}",
        object.device.get(),
        object.inode.get()
    ))
    .map_err(|_| DiscoveryError::Internal("the target identity"))?;
    let path: LosslessPath = LosslessPath::from_path(&root.path.join(&relative))
        .map_err(|_| DiscoveryError::Internal("the unit path"))?;
    // The rule is ready only for a layout that recorded evidence validated
    // for automatic eviction. The state is read; nothing here sets it.
    let is_ready: bool = rule.permits(layout, &RuleMode::AutomaticEviction).is_ok();
    let candidate: CleanupCandidate = CleanupCandidate {
        target_id,
        rule_id: rule.reference.id.clone(),
        volume_id: root.evidence.volume_id.clone(),
        path,
        work_bytes: Some(measurement.charge.work_bytes),
        item_count: Some(measurement.charge.items),
        estimated_reclaimable_bytes: Some(measurement.estimate.bytes),
        facts: CleanupFacts {
            rule_readiness: if is_ready {
                RuleReadiness::Ready
            } else {
                RuleReadiness::NotReady
            },
            hard_protection: ProtectionFact::NotProtected,
            protected_classes: Vec::new(),
            owner: OwnerFact::RequestingUser,
            activity,
            rebuild_cost: rule.rebuild_cost,
        },
    };
    let record: RuleCandidateRecord = RuleCandidateRecord {
        candidate,
        rule: rule.reference.clone(),
        layout: layout.to_owned(),
        eligibility,
    };
    let candidate: RuleCandidate = RuleCandidate::new(rule, record)
        .map_err(|_| DiscoveryError::Internal("the candidate record"))?;
    Ok(Concluded::Candidate(Box::new(DiscoveredCandidate {
        candidate,
        lifecycle: support.lifecycle.clone(),
        root: root.evidence.clone(),
        evidence,
        measurement,
        blockers: reasons.into_iter().collect(),
    })))
}

/// Collects the results of one discovery under its bounds.
#[derive(Debug)]
pub(super) struct Collector<'a> {
    pub(super) bounds: Bounds<'a>,
    candidates: Vec<DiscoveredCandidate>,
    skipped: Vec<SkippedUnit>,
    skipped_omitted: u64,
    observed_at: Option<WallTime>,
}

impl<'a> Collector<'a> {
    pub(super) fn new(control: &'a DiscoveryControl<'a>) -> Result<Self, DiscoveryError> {
        let bounds: Bounds<'a> = Bounds::new(control)?;
        let observed_at: Option<WallTime> = bounds.wall_now();
        Ok(Self {
            bounds,
            candidates: Vec::new(),
            skipped: Vec::new(),
            skipped_omitted: 0,
            observed_at,
        })
    }

    /// The wall-clock time at the start of the discovery. Each age of the
    /// discovery is relative to this time.
    pub(super) fn observed_at(&self) -> Option<WallTime> {
        self.observed_at
    }

    /// Whether the result can hold one more candidate.
    pub(super) fn has_candidate_room(&self) -> bool {
        self.candidates.len() < self.bounds.control.limits.max_candidates
    }

    /// Adds the candidate or the skip of one assessment.
    pub(super) fn add(
        &mut self,
        rule: &Rule,
        root: &RootView,
        assessment: Assessment,
    ) -> Result<(), DiscoveryError> {
        match conclude(rule, root, assessment)? {
            Concluded::Candidate(candidate) => self.candidates.push(*candidate),
            Concluded::Skipped(skipped) => {
                if self.skipped.len() < self.bounds.control.limits.max_skipped {
                    self.skipped.push(*skipped);
                } else {
                    self.skipped_omitted = self.skipped_omitted.saturating_add(1);
                }
            }
        }
        Ok(())
    }

    /// The result. The root is examined again: a root that changed makes
    /// the result unusable.
    pub(super) fn finish(
        self,
        rule: &Rule,
        root: &RootView,
        completion: DiscoveryCompletion,
    ) -> Result<Discovery, DiscoveryError> {
        root.verify_unchanged()?;
        Ok(Discovery {
            rule: rule.reference.clone(),
            root: root.evidence.clone(),
            completion,
            candidates: self.candidates,
            skipped: self.skipped,
            skipped_omitted: self.skipped_omitted,
            units_examined: self.bounds.units_examined,
            entries_examined: EntryCount::new(self.bounds.entries_examined),
            observed_at: self.observed_at,
        })
    }
}

/// The names of the root, sorted, with no more names than the unit limit
/// permits to examine and one more. `ignored` is a name that is not a
/// unit.
///
/// The read stops at one name more than the unit limit, which keeps the
/// memory and the time bounded and shows that the root has more names.
/// The caller examines the other bounds before each name of the list.
pub(super) fn list_root(
    root: &RootView,
    bounds: &Bounds<'_>,
    ignored: Option<&str>,
) -> io::Result<Vec<PathBuf>> {
    let limit: usize = usize::try_from(bounds.control().limits.max_units)
        .unwrap_or(usize::MAX)
        .saturating_add(1);
    let mut names: Vec<PathBuf> = Vec::new();
    for entry in fs::read_dir(&root.path)? {
        if names.len() >= limit {
            break;
        }
        let name: PathBuf = PathBuf::from(entry?.file_name());
        if ignored.is_none_or(|ignored| name.as_os_str() != ignored) {
            names.push(name);
        }
    }
    names.sort();
    Ok(names)
}

/// The known candidates of a discovery with no listing, after the check
/// that each one belongs to the rule revision and to the root.
pub(super) fn check_known<'k>(
    rule: &Rule,
    root: &RootView,
    control: &DiscoveryControl<'_>,
    known: &'k [DiscoveredCandidate],
) -> Result<&'k [DiscoveredCandidate], DiscoveryError> {
    if known.len() > control.limits.max_candidates {
        return Err(DiscoveryError::TooManyKnownCandidates);
    }
    let belongs = |candidate: &DiscoveredCandidate| {
        candidate.candidate.rule == rule.reference
            && candidate.root.root_id == root.evidence.root_id
            && candidate.root.object == root.evidence.object
            && is_plain_relative(&candidate.evidence.relative_entry.to_path_buf())
    };
    if known.iter().all(belongs) {
        Ok(known)
    } else {
        Err(DiscoveryError::KnownCandidate)
    }
}

/// The measurement of a known candidate for a discovery that measures
/// nothing: the earlier measurement when the unit has the same identity
/// and the same times, and `None` when it changed.
fn carried_measurement(
    known: &DiscoveredCandidate,
    now: &ObjectSnapshot,
) -> Option<UnitMeasurement> {
    let unchanged: bool = known.evidence.object == now.object
        && known.evidence.stamp == now.stamp
        && known.evidence.owner == now.owner
        && known.evidence.link_count == now.link_count;
    unchanged.then(|| UnitMeasurement {
        source: MeasurementSource::CarriedFromEarlierDiscovery,
        ..known.measurement.clone()
    })
}

/// The time from `earlier` to `later`. `None` when `later` is before
/// `earlier` or the time does not fit the type.
pub(super) fn elapsed_between(earlier: WallTime, later: WallTime) -> Option<Nanoseconds> {
    const NANOSECONDS_PER_SECOND: i128 = 1_000_000_000;
    let seconds: i128 = i128::from(later.unix_seconds()) - i128::from(earlier.unix_seconds());
    let fraction: i128 =
        i128::from(later.subsecond_nanoseconds()) - i128::from(earlier.subsecond_nanoseconds());
    let nanoseconds: i128 = seconds
        .checked_mul(NANOSECONDS_PER_SECOND)?
        .checked_add(fraction)?;
    u64::try_from(nanoseconds).ok().map(Nanoseconds::new)
}

/// Records in `eligibility` the predicates that the reasons of a rejected
/// measurement do not satisfy.
fn apply_rejection(eligibility: &mut CandidateEligibility, reasons: &BTreeSet<SkipReason>) {
    for reason in reasons {
        match reason {
            SkipReason::ProtectedData => eligibility.no_exclusion_overlap = Fact::NotSatisfied,
            SkipReason::SymbolicLink
            | SkipReason::UnsupportedObject
            | SkipReason::MountCrossing => {
                eligibility.protocols_valid = Fact::NotSatisfied;
            }
            SkipReason::IdentityChanged | SkipReason::Vanished | SkipReason::WrongOwner => {
                eligibility.identity_matches = Fact::NotSatisfied;
            }
            SkipReason::HardLinked | SkipReason::OverCandidateCeiling => {
                eligibility.unit_and_charge_known = Fact::NotSatisfied;
            }
            // Each other reason leaves the charge unknown. A predicate
            // that is `not_satisfied` stays: unknown does not replace it.
            _ => {
                if eligibility.unit_and_charge_known != Fact::NotSatisfied {
                    eligibility.unit_and_charge_known = Fact::Unknown;
                }
            }
        }
    }
}

/// The unit whose charge [`establish_charge`] establishes.
#[derive(Debug, Clone, Copy)]
pub(super) struct UnitUnderMeasurement<'a> {
    /// The path of the unit.
    pub(super) path: &'a Path,
    /// The snapshot of the unit before the measurement.
    pub(super) before: &'a ObjectSnapshot,
    /// The user of the discovery. Each object below the unit must have
    /// this owner.
    pub(super) principal: Uid,
}

/// Establishes the complete charge of a unit (predicate 8): a measurement
/// with the scanner, or, for a known candidate, the earlier measurement
/// when the unit shows no change. Returns the bound that stopped the
/// measurement, if one did.
///
/// # Errors
///
/// Returns the error of [`measure_unit`].
pub(super) fn establish_charge(
    assessment: &mut Assessment,
    known: Option<&DiscoveredCandidate>,
    unit: &UnitUnderMeasurement<'_>,
    rule: &Rule,
    bounds: &mut Bounds<'_>,
    classify: Classifier<'_>,
) -> Result<Option<DiscoveryCompletion>, DiscoveryError> {
    let UnitUnderMeasurement {
        path,
        before,
        principal,
    } = *unit;
    let (measured, newest_change): (Measured, Option<WallTime>) = match known {
        None => measure_unit(path, before, rule, bounds, classify, principal)?,
        // A carried measurement examines no object below the unit: the
        // owners and the times of the content are those of the earlier
        // discovery, and the executor compares each owner again.
        Some(known) => (
            carried_measurement(known, before).map_or_else(
                || Measured::Rejected(BTreeSet::from([SkipReason::MeasurementStale])),
                Measured::Complete,
            ),
            None,
        ),
    };
    assessment.newest_content_change = newest_change;
    match measured {
        Measured::Complete(measurement) => {
            assessment.eligibility.unit_and_charge_known = Fact::Satisfied;
            assessment.measurement = Some(measurement);
        }
        Measured::Rejected(reasons) => {
            apply_rejection(&mut assessment.eligibility, &reasons);
            assessment.reasons.extend(reasons);
        }
        Measured::Stopped(stopped) => return Ok(Some(stopped)),
    }
    Ok(None)
}
