//! The traversal of one root directory.
//!
//! The traversal is a loop with an explicit stack of open directories. The
//! stack has one frame for each level, so its length is at most
//! `max_depth + 1`. The traversal keeps the totals of each open directory,
//! the set of hard-linked objects, and the bounded lists. It keeps no entry.

use std::collections::HashSet;
use std::ffi::{CStr, CString, OsStr};
use std::io;
use std::os::fd::AsFd as _;
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;
use std::time::Instant;

use svalnir_core::file::{DeviceNumber, FileObjectEvidence, InodeNumber, LosslessPath, PathError};
use svalnir_core::observation::Coverage;
use svalnir_core::process::Uid;
use svalnir_core::quantity::{Bytes, EntryCount, Nanoseconds};
use svalnir_core::time::WallTime;

use super::control::{CancellationToken, ScanClock, ScanObserver};
use super::model::{
    DirectoryRecord, EntryKind, EntryRecord, LargeDirectory, LargeFile, MountBoundary, RegionCause,
    SCAN_RESULT_SCHEMA_VERSION, ScanCompletion, ScanError, ScanLimits, ScanRegion, ScanRequest,
    ScanResult, ScanTimestamp, ScanTotals, ScanVolumeEvidence, SharedStorageEvidence,
};
use super::native::{self, DirStream, PrivateAttributes, RawMetadata};
use super::private::{FilePart, MAX_CLONE_FAMILIES, PrivateTally, file_part};
use super::top::TopList;

/// The unit of `st_blocks`, in bytes. This is not `st_blksize` and not the
/// block size of the filesystem.
const STAT_BLOCK_BYTES: u64 = 512;

/// A test changes the metadata of an entry before the scan uses it. This
/// injects a mount boundary, a replaced object, or metadata that is not
/// valid, which a temporary directory cannot make.
#[cfg(test)]
pub(super) type MetadataHook = Box<dyn FnMut(&Path, &mut RawMetadata)>;

/// A test changes the private-size attributes of a file before the scan
/// uses them. This injects a volume that does not report the private size,
/// or a failed call.
#[cfg(test)]
pub(super) type PrivateHook = Box<dyn FnMut(&Path, &mut io::Result<PrivateAttributes>)>;

/// The injection points of a scan. A build that is not a test has none.
#[derive(Default)]
pub(super) struct Injection {
    #[cfg(test)]
    pub(super) metadata: Option<MetadataHook>,
    /// Replaces the descriptor budget that the scan derives from the limit
    /// of the process.
    #[cfg(test)]
    pub(super) descriptor_budget: Option<usize>,
    /// Changes the metadata of an opened directory, which a test uses to
    /// show a directory that is already open on the stack.
    #[cfg(test)]
    pub(super) opened: Option<MetadataHook>,
    /// Changes the result of the private-size call of a file.
    #[cfg(test)]
    pub(super) private: Option<PrivateHook>,
    /// Replaces [`MAX_CLONE_FAMILIES`].
    #[cfg(test)]
    pub(super) clone_family_limit: Option<usize>,
}

fn valid_bytes(value: i64) -> Option<Bytes> {
    u64::try_from(value).ok().map(Bytes::new)
}

fn allocated_from_blocks(blocks: i64) -> Option<Bytes> {
    u64::try_from(blocks)
        .ok()?
        .checked_mul(STAT_BLOCK_BYTES)
        .map(Bytes::new)
}

/// The logical size and the allocated size of an entry. A kind that has no
/// such size gives `None` for it. Returns `None` when a size that the kind
/// has is negative or too large.
fn sizes_of(metadata: &RawMetadata) -> Option<(Option<Bytes>, Option<Bytes>)> {
    match metadata.kind {
        EntryKind::File | EntryKind::Symlink => Some((
            Some(valid_bytes(metadata.size)?),
            Some(allocated_from_blocks(metadata.blocks)?),
        )),
        EntryKind::Directory => Some((None, Some(allocated_from_blocks(metadata.blocks)?))),
        EntryKind::Other => Some((None, None)),
    }
}

fn cause_of(error: &io::Error) -> RegionCause {
    match error.raw_os_error() {
        Some(libc::EACCES | libc::EPERM) => RegionCause::PermissionDenied,
        Some(libc::ENOENT) => RegionCause::Disappeared,
        Some(libc::ENOTDIR | libc::ELOOP) => RegionCause::IdentityChanged,
        Some(libc::EMFILE | libc::ENFILE | libc::ENOMEM) => RegionCause::ResourceLimit,
        // With materialization off for the thread, the kernel gives this
        // error for a call that needs the content of a dataless object.
        Some(libc::EDEADLK) => RegionCause::NotHydrated,
        _ => RegionCause::ReadFailed,
    }
}

/// Adds one to a count. Each count of the scan is at most the number of
/// examined names, which is a `u64`, so the addition cannot overflow.
fn bump(count: &mut EntryCount) {
    if let Some(next) = count.checked_add(EntryCount::new(1)) {
        *count = next;
    }
}

fn as_path(bytes: &[u8]) -> &Path {
    Path::new(OsStr::from_bytes(bytes))
}

/// Sets the path buffer to the path of `name` in the directory whose path is
/// the first `directory_len` bytes of the buffer. `name` is the bytes that
/// `readdir` gave, with or without the NUL terminator. The bytes are kept
/// as they are: a name that is not valid UTF-8 is not changed.
pub(super) fn join_name(path: &mut Vec<u8>, directory_len: usize, name: &[u8]) {
    path.truncate(directory_len);
    if path.last() != Some(&b'/') {
        path.push(b'/');
    }
    path.extend_from_slice(name.strip_suffix(&[0]).unwrap_or(name));
}

fn coverage_of(partial: bool) -> Coverage {
    if partial {
        Coverage::Partial
    } else {
        Coverage::Complete
    }
}

/// How an entry takes part in hard-link deduplication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HardLink {
    /// The object has one name, or is a directory.
    Single,
    /// The first name that the scan found of an object with several names.
    FirstName,
    /// A later name of an object that is in the totals.
    LaterName,
    /// A name of an object that the scan cannot track.
    NotTracked,
}

/// The totals of the names below one directory.
#[derive(Debug, Clone, Copy, Default)]
struct Subtree {
    logical: Bytes,
    allocated: Bytes,
    entries: EntryCount,
}

impl Subtree {
    /// Adds each field of `other` to the field of `self`. A field whose sum
    /// overflows keeps its earlier value, and the other fields still get
    /// their addition. The flag tells whether one field overflowed.
    fn plus(self, other: Self) -> (Self, bool) {
        let logical: Option<Bytes> = self.logical.checked_add(other.logical);
        let allocated: Option<Bytes> = self.allocated.checked_add(other.allocated);
        let entries: Option<EntryCount> = self.entries.checked_add(other.entries);
        let overflow: bool = logical.is_none() || allocated.is_none() || entries.is_none();
        (
            Self {
                logical: logical.unwrap_or(self.logical),
                allocated: allocated.unwrap_or(self.allocated),
                entries: entries.unwrap_or(self.entries),
            },
            overflow,
        )
    }
}

/// One open directory of the traversal.
struct Frame {
    stream: DirStream,
    /// The length of the path of this directory in the path buffer.
    path_len: usize,
    depth: u32,
    object: FileObjectEvidence,
    /// The allocation of the directory object. The frame of the parent
    /// already has this value in its subtree.
    own_allocated: Bytes,
    subtree: Subtree,
    /// Whether a region below this directory is missing.
    partial: bool,
}

/// The totals of the root, after the traversal left it.
struct RootSummary {
    logical: Bytes,
    allocated: Bytes,
    entries: EntryCount,
    partial: bool,
}

struct Walker<'a> {
    limits: ScanLimits,
    root_device: DeviceNumber,
    cancel: &'a CancellationToken,
    observer: &'a mut dyn ScanObserver,
    injection: Injection,
    /// The most open directories (stack frames) at one time.
    descriptor_budget: usize,
    stack: Vec<Frame>,
    /// The path of the entry or directory that the traversal works on.
    path: Vec<u8>,
    /// The name that `readdir` gave, with its NUL terminator.
    name: Vec<u8>,
    examined: EntryCount,
    kinds: ScanTotals,
    shared: SharedStorageEvidence,
    /// The inode numbers of the hard-linked objects that are in the totals.
    /// Each is on the device of the root.
    hard_links: HashSet<u64>,
    /// The private allocated bytes of the root.
    private: PrivateTally,
    largest_files: TopList<LargeFile>,
    largest_directories: TopList<LargeDirectory>,
    boundaries: Vec<MountBoundary>,
    boundaries_omitted: EntryCount,
    regions: Vec<ScanRegion>,
    regions_omitted: EntryCount,
    root: Option<RootSummary>,
}

impl Walker<'_> {
    /// Records the path of the path buffer as a region and marks the
    /// current directory as partial.
    fn record(&mut self, cause: RegionCause, error: Option<&io::Error>) {
        if let Some(frame) = self.stack.last_mut() {
            frame.partial = true;
        }
        if self.regions.len() < self.limits.max_recorded_regions
            && let Ok(path) = LosslessPath::from_bytes(self.path.as_slice())
        {
            self.regions.push(ScanRegion {
                path,
                cause,
                native_errno: error.and_then(io::Error::raw_os_error),
            });
        } else {
            bump(&mut self.regions_omitted);
        }
    }

    fn record_boundary(&mut self, device: Option<DeviceNumber>) {
        if self.boundaries.len() < self.limits.max_recorded_boundaries
            && let Ok(path) = LosslessPath::from_bytes(self.path.as_slice())
        {
            self.boundaries.push(MountBoundary { path, device });
        } else {
            bump(&mut self.boundaries_omitted);
        }
    }

    fn current_name(&self) -> io::Result<&CStr> {
        CStr::from_bytes_with_nul(&self.name)
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))
    }

    fn stat_current(&self) -> io::Result<RawMetadata> {
        let frame: &Frame = self
            .stack
            .last()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
        native::stat_child(frame.stream.descriptor(), self.current_name()?)
    }

    /// Opens the current name as a directory, relative to the current
    /// directory, and checks that the open object is the measured object.
    fn open_current(
        &mut self,
        measured: &RawMetadata,
    ) -> Result<DirStream, (RegionCause, Option<io::Error>)> {
        let failed = |error: io::Error| (cause_of(&error), Some(error));
        let frame: &Frame = self.stack.last().ok_or((RegionCause::ReadFailed, None))?;
        let name: &CStr = self.current_name().map_err(failed)?;
        let descriptor = native::open_child(frame.stream.descriptor(), name).map_err(failed)?;
        let opened: RawMetadata = native::stat_descriptor(descriptor.as_fd()).map_err(failed)?;
        #[cfg(test)]
        let opened: RawMetadata = {
            let mut opened: RawMetadata = opened;
            if let Some(hook) = self.injection.opened.as_mut() {
                hook(as_path(&self.path), &mut opened);
            }
            opened
        };
        if opened.kind != EntryKind::Directory
            || opened.device != measured.device
            || opened.inode != measured.inode
        {
            return Err((RegionCause::IdentityChanged, None));
        }
        if opened.dataless {
            // The directory became a placeholder after the measurement.
            return Err((RegionCause::NotHydrated, None));
        }
        DirStream::from_descriptor(descriptor).map_err(failed)
    }

    #[cfg(test)]
    fn inject(&mut self, mut metadata: RawMetadata) -> RawMetadata {
        if let Some(hook) = self.injection.metadata.as_mut() {
            hook(as_path(&self.path), &mut metadata);
        }
        metadata
    }

    #[cfg(not(test))]
    fn inject(&mut self, metadata: RawMetadata) -> RawMetadata {
        let Injection {} = self.injection;
        metadata
    }

    /// Reads the private-size attributes of the current name.
    fn query_private(&mut self) -> io::Result<PrivateAttributes> {
        let result: io::Result<PrivateAttributes> = match self.stack.last() {
            Some(frame) => {
                native::private_attributes(frame.stream.descriptor(), self.current_name()?)
            }
            None => Err(io::Error::from(io::ErrorKind::NotFound)),
        };
        #[cfg(test)]
        let result: io::Result<PrivateAttributes> = {
            let mut result: io::Result<PrivateAttributes> = result;
            if let Some(hook) = self.injection.private.as_mut() {
                hook(as_path(&self.path), &mut result);
            }
            result
        };
        result
    }

    /// Adds a counted entry to the private allocated bytes. `allocated` is
    /// the allocated size of the entry, which a kind without one does not
    /// have.
    fn tally_private(
        &mut self,
        metadata: &RawMetadata,
        hard_link: HardLink,
        allocated: Option<Bytes>,
    ) {
        let Some(allocated) = allocated else {
            return;
        };
        match (metadata.kind, hard_link) {
            // A later name of a link or a directory adds nothing again.
            (_, HardLink::NotTracked)
            | (EntryKind::Other, _)
            | (EntryKind::Directory | EntryKind::Symlink, HardLink::LaterName) => {}
            (EntryKind::File, HardLink::LaterName) => self.private.add_later_link(metadata.inode),
            (EntryKind::Directory | EntryKind::Symlink, _) => self.private.add_allocated(allocated),
            (EntryKind::File, HardLink::Single | HardLink::FirstName) => {
                let part: FilePart = if metadata.compressed || metadata.dataless {
                    // APFS does not count compressed data in the private
                    // size, and a dataless file has no local data to read.
                    FilePart::Allocated(allocated)
                } else if !self.private.is_available() {
                    return;
                } else {
                    let attributes: io::Result<PrivateAttributes> = self.query_private();
                    match file_part(attributes, metadata.inode, allocated) {
                        Ok(part) => part,
                        Err(cause) => {
                            self.private.fail(cause);
                            return;
                        }
                    }
                };
                if hard_link == HardLink::FirstName {
                    self.private
                        .add_first_link(metadata.inode, metadata.link_count, part);
                } else {
                    self.private.add_file(part);
                }
            }
        }
    }

    /// How the entry takes part in hard-link deduplication. The call
    /// changes nothing: `entry` updates the set and the counts only after
    /// the entry is in the totals.
    fn hard_link_of(&self, metadata: &RawMetadata) -> HardLink {
        if metadata.kind == EntryKind::Directory || metadata.link_count <= 1 {
            HardLink::Single
        } else if self.hard_links.contains(&metadata.inode) {
            HardLink::LaterName
        } else if self.hard_links.len() >= self.limits.max_hard_link_objects {
            HardLink::NotTracked
        } else {
            HardLink::FirstName
        }
    }

    /// Examines the current name. Returns a value when the scan stops.
    fn entry(&mut self) -> Option<ScanCompletion> {
        let (directory_len, depth): (usize, u32) = match self.stack.last() {
            Some(frame) => (frame.path_len, frame.depth),
            None => return Some(ScanCompletion::Finished),
        };
        if self.examined >= self.limits.max_entries {
            return Some(self.stop(ScanCompletion::EntryLimitReached));
        }
        bump(&mut self.examined);
        join_name(&mut self.path, directory_len, &self.name);
        self.observer.entry_listed(as_path(&self.path));

        let metadata: RawMetadata = match self.stat_current() {
            Ok(metadata) => self.inject(metadata),
            Err(error) => {
                self.record(cause_of(&error), Some(&error));
                return None;
            }
        };
        if metadata.device != Some(self.root_device) {
            self.record_boundary(metadata.device);
            return None;
        }
        let object = FileObjectEvidence {
            device: self.root_device,
            inode: InodeNumber::new(metadata.inode),
        };
        let Some((logical, allocated)) = sizes_of(&metadata) else {
            self.record(RegionCause::InconsistentMetadata, None);
            return None;
        };
        let hard_link: HardLink = self.hard_link_of(&metadata);
        if hard_link == HardLink::NotTracked {
            bump(&mut self.shared.hard_link_names_not_tracked);
            self.record(RegionCause::HardLinkLimit, None);
            return None;
        }
        let counted_in_totals: bool = hard_link != HardLink::LaterName;

        let addition = Subtree {
            logical: logical.filter(|_| counted_in_totals).unwrap_or(Bytes::ZERO),
            allocated: allocated
                .filter(|_| counted_in_totals)
                .unwrap_or(Bytes::ZERO),
            entries: EntryCount::new(1),
        };
        let Some(frame) = self.stack.last_mut() else {
            return Some(ScanCompletion::Finished);
        };
        // A field that overflows keeps its earlier value. The entry stays in
        // the other totals, in the hard-link set, and in the counts.
        let (sum, overflow) = frame.subtree.plus(addition);
        frame.subtree = sum;
        if overflow {
            self.record(RegionCause::Overflow, None);
        }
        match hard_link {
            HardLink::FirstName => {
                self.hard_links.insert(metadata.inode);
                bump(&mut self.shared.hard_linked_objects);
            }
            HardLink::LaterName => bump(&mut self.shared.hard_link_names_not_counted_again),
            HardLink::Single | HardLink::NotTracked => {}
        }
        self.tally_private(&metadata, hard_link, allocated);

        bump(match metadata.kind {
            EntryKind::File => &mut self.kinds.files,
            EntryKind::Directory => &mut self.kinds.directories,
            EntryKind::Symlink => &mut self.kinds.symlinks,
            EntryKind::Other => &mut self.kinds.other_entries,
        });
        let child_depth: u32 = depth.saturating_add(1);
        self.observer.entry_measured(&EntryRecord {
            path: as_path(&self.path),
            kind: metadata.kind,
            depth: child_depth,
            logical_bytes: logical,
            allocated_bytes: allocated,
            link_count: metadata.link_count,
            object,
            counted_in_totals,
            owner: Uid::new(metadata.owner),
            modified: wall_time_of(metadata.modified),
            changed: wall_time_of(metadata.changed),
        });

        match (metadata.kind, logical, allocated) {
            (EntryKind::File, Some(logical), Some(allocated)) if counted_in_totals => {
                self.counted_file(&metadata, object, logical, allocated);
            }
            (EntryKind::Directory, _, Some(allocated)) => {
                self.descend(&metadata, object, child_depth, allocated);
            }
            _ => {}
        }
        None
    }

    fn counted_file(
        &mut self,
        metadata: &RawMetadata,
        object: FileObjectEvidence,
        logical: Bytes,
        allocated: Bytes,
    ) {
        if metadata.compressed {
            bump(&mut self.shared.compressed_files);
        }
        if allocated < logical {
            bump(&mut self.shared.files_allocated_below_logical);
        }
        if self.largest_files.admits((allocated, logical), &self.path)
            && let Ok(path) = LosslessPath::from_bytes(self.path.as_slice())
        {
            self.largest_files.offer(LargeFile {
                path,
                logical_bytes: logical,
                allocated_bytes: allocated,
                link_count: EntryCount::new(metadata.link_count),
                object,
            });
        }
    }

    /// Opens the current name, which is a directory on the device of the
    /// root, and makes it the current directory. A directory that the scan
    /// does not open becomes a region.
    fn descend(
        &mut self,
        measured: &RawMetadata,
        object: FileObjectEvidence,
        depth: u32,
        own_allocated: Bytes,
    ) {
        if measured.dataless {
            self.record(RegionCause::NotHydrated, None);
            return;
        }
        if depth > self.limits.max_depth {
            self.record(RegionCause::DepthLimit, None);
            return;
        }
        if self.stack.len() >= self.descriptor_budget {
            self.record(RegionCause::ResourceLimit, None);
            return;
        }
        let stream: DirStream = match self.open_current(measured) {
            Ok(stream) => stream,
            Err((cause, error)) => {
                self.record(cause, error.as_ref());
                return;
            }
        };
        // A bind mount can show a directory below itself on the same
        // device. The inode of an open directory on the stack means a cycle.
        if self.stack.iter().any(|frame| frame.object == object) {
            self.record(RegionCause::IdentityChanged, None);
            return;
        }
        self.observer.directory_opened(as_path(&self.path));
        self.stack.push(Frame {
            stream,
            path_len: self.path.len(),
            depth,
            object,
            own_allocated,
            subtree: Subtree::default(),
            partial: false,
        });
    }

    /// Leaves the current directory: closes it, gives its totals to the
    /// observer and to the list of the largest directories, and adds its
    /// subtree to the directory above it.
    fn finish_directory(&mut self) {
        let Some(frame) = self.stack.pop() else {
            return;
        };
        self.path.truncate(frame.path_len);
        let mut partial: bool = frame.partial;
        let allocated: Bytes = frame
            .own_allocated
            .checked_add(frame.subtree.allocated)
            .unwrap_or_else(|| {
                partial = true;
                self.record(RegionCause::Overflow, None);
                frame.subtree.allocated
            });
        let has_parent: bool = match self.stack.last_mut() {
            Some(parent) => {
                parent.partial |= partial;
                let (sum, overflow) = parent.subtree.plus(frame.subtree);
                parent.subtree = sum;
                if overflow {
                    self.record(RegionCause::Overflow, None);
                }
                true
            }
            None => false,
        };
        self.observer.directory_finished(&DirectoryRecord {
            path: as_path(&self.path),
            depth: frame.depth,
            logical_bytes: frame.subtree.logical,
            allocated_bytes: allocated,
            entries: frame.subtree.entries,
            coverage: coverage_of(partial),
            object: frame.object,
        });
        if !has_parent {
            self.root = Some(RootSummary {
                logical: frame.subtree.logical,
                allocated,
                entries: frame.subtree.entries,
                partial,
            });
            return;
        }
        if self
            .largest_directories
            .admits((allocated, frame.subtree.logical), &self.path)
            && let Ok(path) = LosslessPath::from_bytes(self.path.as_slice())
        {
            self.largest_directories.offer(LargeDirectory {
                path,
                logical_bytes: frame.subtree.logical,
                allocated_bytes: allocated,
                entries: frame.subtree.entries,
                coverage: coverage_of(partial),
                object: frame.object,
            });
        }
    }

    /// Stops the scan in the current directory. Each open directory keeps
    /// the totals that it has and becomes partial.
    fn stop(&mut self, completion: ScanCompletion) -> ScanCompletion {
        let cause: RegionCause = match completion {
            ScanCompletion::Finished => return completion,
            ScanCompletion::Cancelled => RegionCause::Cancelled,
            ScanCompletion::EntryLimitReached => RegionCause::EntryLimit,
        };
        if let Some(frame) = self.stack.last() {
            self.path.truncate(frame.path_len);
        }
        self.record(cause, None);
        while !self.stack.is_empty() {
            self.finish_directory();
        }
        completion
    }

    fn walk(&mut self) -> ScanCompletion {
        loop {
            if self.stack.is_empty() {
                return ScanCompletion::Finished;
            }
            if self.cancel.is_cancelled() {
                return self.stop(ScanCompletion::Cancelled);
            }
            let Some(frame) = self.stack.last_mut() else {
                return ScanCompletion::Finished;
            };
            match frame.stream.next_name(&mut self.name) {
                Ok(true) => {
                    if let Some(completion) = self.entry() {
                        return completion;
                    }
                }
                Ok(false) => self.finish_directory(),
                Err(error) => {
                    let directory_len: usize = frame.path_len;
                    self.path.truncate(directory_len);
                    self.record(cause_of(&error), Some(&error));
                    self.finish_directory();
                }
            }
        }
    }
}

fn root_error(error: io::Error) -> ScanError {
    if error.raw_os_error() == Some(libc::ENOTDIR) {
        ScanError::RootNotDirectory
    } else {
        ScanError::RootUnavailable(error)
    }
}

/// The wall-clock time of a `stat` time, as seconds and nanoseconds.
/// `None` when the nanoseconds are not below one second, or when the time
/// is outside the range of [`WallTime`].
fn wall_time_of((seconds, nanoseconds): (i64, i64)) -> Option<WallTime> {
    WallTime::from_unix(seconds, u32::try_from(nanoseconds).ok()?).ok()
}

/// Scans one root directory and returns the result.
///
/// The call blocks until the scan finishes, stops at a limit, or is
/// cancelled. Run it on a worker thread that the caller owns, not on an
/// event thread. The scan reads metadata only: it reads no file content, it
/// follows no symbolic link below the root, and it changes nothing.
///
/// # Errors
///
/// Returns a [`ScanError`] when the scan cannot start: a limit is not
/// valid, the root cannot be opened or is not a directory, or the volume
/// identity of the request is for another device. A failure below the root
/// is not an error; it is a region of the result.
pub fn run_scan(
    request: &ScanRequest,
    cancel: &CancellationToken,
    clock: &dyn ScanClock,
    observer: &mut dyn ScanObserver,
) -> Result<ScanResult, ScanError> {
    scan_with(request, cancel, clock, observer, Injection::default())
}

/// The open root with its metadata and its filesystem evidence.
struct OpenRoot {
    stream: DirStream,
    metadata: RawMetadata,
    volume: ScanVolumeEvidence,
}

fn open_root(request: &ScanRequest) -> Result<OpenRoot, ScanError> {
    let root: CString = CString::new(request.root.as_bytes())
        .map_err(|_| ScanError::RootPath(PathError::ContainsNul))?;
    let descriptor = native::open_root(&root).map_err(root_error)?;
    let metadata: RawMetadata =
        native::stat_descriptor(descriptor.as_fd()).map_err(ScanError::RootUnavailable)?;
    if metadata.kind != EntryKind::Directory {
        return Err(ScanError::RootNotDirectory);
    }
    if metadata.dataless {
        return Err(ScanError::RootNotHydrated);
    }
    let device: DeviceNumber = metadata.device.ok_or(ScanError::RootDeviceUnsupported)?;
    if request
        .volume
        .as_ref()
        .is_some_and(|volume| volume.device != device)
    {
        return Err(ScanError::VolumeMismatch);
    }
    let root_object = FileObjectEvidence {
        device,
        inode: InodeNumber::new(metadata.inode),
    };
    let filesystem = native::filesystem_evidence(descriptor.as_fd()).ok();
    let volume = ScanVolumeEvidence {
        device,
        root_object,
        filesystem_type: filesystem
            .as_ref()
            .and_then(|evidence| String::from_utf8(evidence.type_name.clone()).ok()),
        mount_point: filesystem
            .and_then(|evidence| LosslessPath::from_bytes(evidence.mount_point).ok()),
        identity: request.volume.clone(),
    };
    let stream: DirStream =
        DirStream::from_descriptor(descriptor).map_err(ScanError::RootUnavailable)?;
    Ok(OpenRoot {
        stream,
        metadata,
        volume,
    })
}

/// The descriptor budget used when the soft limit cannot be read.
const FALLBACK_DESCRIPTOR_BUDGET: usize = 32;

/// The most directories that a scan keeps open at one time. The scan leaves
/// at least three quarters of the soft descriptor limit to the rest of the
/// process, and it never needs more than `max_depth + 1`.
pub(super) fn budget_from_limit(max_depth: u32, soft_limit: Option<u64>) -> usize {
    let needed: usize =
        usize::try_from(max_depth).map_or(usize::MAX, |depth| depth.saturating_add(1));
    let allowed: usize = soft_limit.map_or(FALLBACK_DESCRIPTOR_BUDGET, |limit| {
        usize::try_from(limit / 4).unwrap_or(usize::MAX)
    });
    needed.min(allowed).max(1)
}

#[cfg(test)]
fn descriptor_budget(max_depth: u32, injection: &Injection) -> usize {
    injection
        .descriptor_budget
        .unwrap_or_else(|| budget_from_limit(max_depth, native::soft_descriptor_limit()))
}

#[cfg(not(test))]
fn descriptor_budget(max_depth: u32, _injection: &Injection) -> usize {
    budget_from_limit(max_depth, native::soft_descriptor_limit())
}

#[cfg(test)]
fn clone_family_limit(injection: &Injection) -> usize {
    injection.clone_family_limit.unwrap_or(MAX_CLONE_FAMILIES)
}

#[cfg(not(test))]
fn clone_family_limit(_injection: &Injection) -> usize {
    MAX_CLONE_FAMILIES
}

pub(super) fn scan_with(
    request: &ScanRequest,
    cancel: &CancellationToken,
    clock: &dyn ScanClock,
    observer: &mut dyn ScanObserver,
    injection: Injection,
) -> Result<ScanResult, ScanError> {
    request.limits.validate()?;
    let started: ScanTimestamp = clock.now();
    let begun: Instant = Instant::now();
    // The guard is in effect until this function returns.
    let _no_materialization = native::MaterializationOff::for_this_thread();
    let OpenRoot {
        stream,
        metadata,
        volume,
    } = open_root(request)?;

    let family_limit: usize = clone_family_limit(&injection);
    let mut walker = Walker {
        limits: request.limits,
        root_device: volume.device,
        cancel,
        observer,
        descriptor_budget: descriptor_budget(request.limits.max_depth, &injection),
        injection,
        stack: Vec::new(),
        path: request.root.as_bytes().to_vec(),
        name: Vec::new(),
        examined: EntryCount::ZERO,
        kinds: ScanTotals::default(),
        shared: SharedStorageEvidence::default(),
        hard_links: HashSet::new(),
        private: PrivateTally::new(family_limit),
        largest_files: TopList::new(request.limits.max_largest_files),
        largest_directories: TopList::new(request.limits.max_largest_directories),
        boundaries: Vec::new(),
        boundaries_omitted: EntryCount::ZERO,
        regions: Vec::new(),
        regions_omitted: EntryCount::ZERO,
        root: None,
    };
    walker.observer.directory_opened(as_path(&walker.path));
    let own_allocated: Option<Bytes> = allocated_from_blocks(metadata.blocks);
    walker.stack.push(Frame {
        stream,
        path_len: walker.path.len(),
        depth: 0,
        object: volume.root_object,
        own_allocated: own_allocated.unwrap_or(Bytes::ZERO),
        subtree: Subtree::default(),
        partial: false,
    });
    if let Some(own) = own_allocated {
        walker.private.add_allocated(own);
    }
    if own_allocated.is_none() {
        // The allocation of the root object is not in the totals, and the
        // region makes the coverage partial.
        walker.record(RegionCause::InconsistentMetadata, None);
    }
    let completion: ScanCompletion = walker.walk();

    let finished: ScanTimestamp = clock.now();
    let elapsed: Option<Nanoseconds> = u64::try_from(begun.elapsed().as_nanos())
        .ok()
        .map(Nanoseconds::new);
    let root: RootSummary = walker.root.take().unwrap_or(RootSummary {
        logical: Bytes::ZERO,
        allocated: Bytes::ZERO,
        entries: EntryCount::ZERO,
        partial: true,
    });
    let partial: bool = root.partial
        || completion != ScanCompletion::Finished
        || !walker.regions.is_empty()
        || walker.regions_omitted != EntryCount::ZERO;
    Ok(ScanResult {
        schema_version: SCAN_RESULT_SCHEMA_VERSION,
        scan_id: request.scan_id.clone(),
        root: request.root.clone(),
        volume,
        started,
        finished,
        elapsed,
        completion,
        coverage: coverage_of(partial),
        limits: request.limits,
        entries_examined: walker.examined,
        totals: ScanTotals {
            logical_bytes: root.logical,
            allocated_bytes: root.allocated,
            entries: root.entries,
            ..walker.kinds
        },
        shared_storage: walker.shared,
        private_allocation: walker.private.finish(),
        largest_files: walker.largest_files.into_largest_first(),
        largest_directories: walker.largest_directories.into_largest_first(),
        boundaries: walker.boundaries,
        boundaries_omitted: walker.boundaries_omitted,
        regions: walker.regions,
        regions_omitted: walker.regions_omitted,
    })
}
