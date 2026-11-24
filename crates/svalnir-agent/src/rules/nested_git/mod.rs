//! The Git repositories in a cleanup unit (`docs/CLEANUP_RULES.md`
//! section 6, "Repositories in a unit").
//!
//! A directory that Git ignores, or a generated directory of a tool, can
//! hold a dependency that was cloned with Git. Its commits, its stash, and
//! its changed files exist only in that clone, and the enclosing
//! repository does not see them. A unit that holds a Git repository at any
//! depth is thus not a unit that the next build or install makes again.
//!
//! # Use
//!
//! 1. [`detect`] walks one unit and reports each `.git` object
//!    ([`is_marker`]), each Git directory with no such name
//!    (`is_git_directory`: a bare repository or a separate Git
//!    directory), and the first directory that it cannot read. The walk
//!    is bounded by depth, by entries, and by time, follows no symbolic
//!    link, does not enter another device, and reads each name
//!    relative to an open directory.
//! 2. [`judge`] gives the verdict of a detection. Each problem of the walk
//!    refuses the unit: a directory that the walk cannot read can hold a
//!    repository. Each repository refuses the unit, with one exception: a
//!    clone or a mirror that Swift Package Manager made in its `checkouts`
//!    or `repositories` directory and can make again
//!    ([`SwiftPmCheckouts`], [`swiftpm`]).
//! 3. [`check_unit`] does the two steps.
//!
//! The discovery of an eviction and the inspection of
//! `project.dependency-directory` do not call [`detect`]: their measurement
//! with the scanner already reads each entry of a unit, so they give each
//! entry to a `MarkerTracker`. The filesystem executor applies
//! [`is_marker`] and `is_git_directory` in the measurement of a directory
//! target, before its first removal call, and `git_objects_now` to
//! each directory of the removal pass before it removes the entries of
//! that directory.
//!
//! # What the checks cannot see
//!
//! A check is a check of names at one time. A repository that a process
//! makes after the last check of a directory is not seen. A Git directory
//! outside the unit whose `core.worktree` names a directory in the unit
//! leaves no Git object in the unit, so no check finds that work tree.

pub mod swiftpm;

#[cfg(test)]
mod tests;

use std::ffi::{CStr, CString, OsStr};
use std::io;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use serde::Serialize;
use svalnir_core::action::{AdmittedRepository, MAX_ADMITTED_REPOSITORIES, RepositoryKind};
use svalnir_core::file::{DeviceNumber, FileObjectEvidence, LosslessPath};

use crate::executor::fs::native::{self, DirStream, Kind, Metadata};
use crate::rules::git::{GitTool, GitToolProblem};
use crate::scan::{
    CancellationToken, EntryRecord, RegionCause, ScanCompletion, ScanObserver, ScanResult,
};
use svalnir_core::observation::Coverage;

pub use swiftpm::{Pin, PinsProblem, SwiftPmCheckouts, read_pins};

/// The name of the object that marks a Git work tree: a directory, or a
/// file that names the Git directory of a submodule or of a linked
/// worktree.
pub const GIT_MARKER: &str = ".git";

/// The names that make a directory a Git directory: the file or symbolic
/// link `HEAD`, and the directories `objects` and `refs`. That is the test
/// of Git for a Git directory, with no check of the content of `HEAD`.
pub const GIT_DIRECTORY_NAMES: [&str; 3] = ["HEAD", "objects", "refs"];

/// The largest number of directories that a `MarkerTracker` follows for
/// [`GIT_DIRECTORY_NAMES`]. More such directories count as a repository.
const MAX_TRACKED_FRAMES: usize = 65_536;

/// The number of entries that the walk reads between two readings of the
/// clock and of the cancellation.
const CHECK_INTERVAL: u64 = 256;

/// Whether `name` is the name of a Git marker. The comparison ignores the
/// case of ASCII letters: on a volume that ignores case, Git finds the
/// directory `.GIT` as `.git`.
#[must_use]
pub fn is_marker(name: &[u8]) -> bool {
    name.eq_ignore_ascii_case(GIT_MARKER.as_bytes())
}

/// The bounds of one walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DetectionLimits {
    /// The deepest directory level below the unit that the walk reads.
    pub max_depth: u32,
    /// The largest number of entries that the walk reads.
    pub max_entries: u64,
    /// The longest time of the walk.
    pub max_duration: Duration,
    /// The largest number of repositories that the walk reports.
    pub max_repositories: usize,
}

impl Default for DetectionLimits {
    fn default() -> Self {
        Self {
            max_depth: 64,
            max_entries: 2_000_000,
            max_duration: Duration::from_secs(60),
            max_repositories: MAX_ADMITTED_REPOSITORIES,
        }
    }
}

/// The kind of a Git marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MarkerKind {
    /// A `.git` directory: a work tree with its own Git directory.
    Directory,
    /// A `.git` file: the work tree of a submodule or of a linked
    /// worktree, whose Git directory is in another place.
    File,
    /// A `.git` object of another kind, for example a symbolic link.
    Other,
    /// A Git directory with no `.git` name: a directory with
    /// [`GIT_DIRECTORY_NAMES`], as of a bare repository, a mirror, or a
    /// separate Git directory.
    Bare,
}

/// One repository that the walk found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FoundRepository {
    /// The directory that holds the marker, or the Git directory of a
    /// [`MarkerKind::Bare`] repository, relative to the unit. Empty for the
    /// unit itself.
    pub work_tree: PathBuf,
    /// The kind of the marker.
    pub marker: MarkerKind,
    /// The device and the inode of the marker, or of the Git directory of
    /// a [`MarkerKind::Bare`] repository, as the walk measured them.
    pub object: Option<FileObjectEvidence>,
    /// The name of the marker as the walk read it from the directory, for
    /// example `.GIT` on a volume that ignores case. Empty for a
    /// [`MarkerKind::Bare`] repository.
    pub marker_name: Vec<u8>,
}

/// Why a walk did not examine each entry of the unit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DetectionProblem {
    /// The unit is not a directory that the walk can open from `/` with no
    /// symbolic link on its path.
    UnitUnavailable,
    /// A directory cannot be read.
    Unreadable {
        /// The directory, relative to the unit.
        directory: PathBuf,
    },
    /// A directory is on another device than the unit.
    OtherDevice {
        /// The directory, relative to the unit.
        directory: PathBuf,
    },
    /// A directory is another object than the one that the walk measured.
    Changed {
        /// The directory, relative to the unit.
        directory: PathBuf,
    },
    /// A directory is deeper than [`DetectionLimits::max_depth`].
    DepthLimit,
    /// The unit has more entries than [`DetectionLimits::max_entries`].
    EntryLimit,
    /// The walk passed [`DetectionLimits::max_duration`].
    TimeLimit,
    /// The unit has more repositories than
    /// [`DetectionLimits::max_repositories`].
    RepositoryLimit,
    /// The caller cancelled the walk.
    Cancelled,
}

/// The result of one walk.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct Detection {
    /// The repositories that the walk found, in the sequence of the walk.
    pub repositories: Vec<FoundRepository>,
    /// Why the walk did not examine each entry, when it did not.
    pub problem: Option<DetectionProblem>,
}

/// The stable reason of a refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusalReason {
    /// The unit holds a Git repository, and no exception applies to it.
    NestedRepository,
    /// The unit cannot be opened for the walk.
    UnitUnavailable,
    /// A directory of the unit cannot be read, so it can hold a
    /// repository.
    UnreadableDirectory,
    /// A directory of the unit is on another device.
    OtherDevice,
    /// A bound or a change stopped the walk before it examined each
    /// entry.
    DetectionIncomplete,
    /// The `Package.resolved` file of the checkouts cannot be read.
    PinsUnavailable,
    /// No pin of `Package.resolved` has the identity of the checkout.
    NotPinned,
    /// The remote of the checkout is not the location of its pin, or a
    /// clone of Swift Package Manager of that location.
    LocationNotPinned,
    /// The `HEAD` of the checkout is not the revision of its pin.
    RevisionNotPinned,
    /// The work tree has a changed, untracked, or ignored file, or a file
    /// that a flag hides from `git status`.
    ChangedWorkTree,
    /// The checkout has commits that no remote-tracking reference holds,
    /// or it pushed commits.
    LocalCommits,
    /// The checkout has a stash.
    Stash,
    /// The checkout has linked worktrees.
    LinkedWorktrees,
    /// The configuration of the checkout names a filter driver, which
    /// `git status` would run.
    FilterDriver,
    /// The checkout does not record the updates of its references
    /// (`core.logAllRefUpdates` is false), so its reflogs do not show a
    /// push.
    ReflogDisabled,
    /// A reflog has an entry that is not a fetch or a clone, for example
    /// a push.
    ReflogNotFetch,
    /// A repository in the `repositories` directory is not a bare mirror
    /// with one remote.
    NotMirror,
    /// A checkout of the pin-less mode has no one remote `origin` with a
    /// URL.
    OriginMissing,
    /// The Git directory is not the object that the walk measured.
    IdentityChanged,
    /// No trusted Git executable is available for the checks.
    GitUnavailable,
    /// A Git query failed.
    GitFailed,
}

impl RefusalReason {
    /// The stable name of the reason.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NestedRepository => "nested_repository",
            Self::UnitUnavailable => "repository_check_unit_unavailable",
            Self::UnreadableDirectory => "repository_check_unreadable_directory",
            Self::OtherDevice => "repository_check_other_device",
            Self::DetectionIncomplete => "repository_check_incomplete",
            Self::PinsUnavailable => "swiftpm_pins_unavailable",
            Self::NotPinned => "swiftpm_checkout_not_pinned",
            Self::LocationNotPinned => "swiftpm_location_not_pinned",
            Self::RevisionNotPinned => "swiftpm_revision_not_pinned",
            Self::ChangedWorkTree => "swiftpm_checkout_changed",
            Self::LocalCommits => "swiftpm_checkout_local_commits",
            Self::Stash => "swiftpm_checkout_stash",
            Self::LinkedWorktrees => "swiftpm_checkout_linked_worktrees",
            Self::FilterDriver => "swiftpm_checkout_filter_driver",
            Self::ReflogDisabled => "swiftpm_checkout_reflog_disabled",
            Self::ReflogNotFetch => "swiftpm_reflog_not_fetch",
            Self::NotMirror => "swiftpm_mirror_not_valid",
            Self::OriginMissing => "swiftpm_origin_missing",
            Self::IdentityChanged => "repository_identity_changed",
            Self::GitUnavailable => "swiftpm_git_unavailable",
            Self::GitFailed => "swiftpm_git_failed",
        }
    }
}

/// Why a unit is refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RepositoryRefusal {
    /// The reason.
    pub reason: RefusalReason,
    /// The repository or the directory that the reason is about, relative
    /// to the unit, when the reason has one. Empty for the unit itself.
    pub path: Option<PathBuf>,
}

/// The verdict on one unit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Verdict {
    /// The walk examined each entry, and the unit holds no repository, or
    /// only checkouts that Swift Package Manager can make again.
    Clear,
    /// The unit is refused.
    Refused(RepositoryRefusal),
}

/// The state of one walk.
struct Walk<'a> {
    limits: &'a DetectionLimits,
    cancel: Option<&'a CancellationToken>,
    deadline: Option<Instant>,
    device: Option<DeviceNumber>,
    entries: u64,
    found: Vec<FoundRepository>,
}

/// The device and the inode of a measured object.
fn identity(metadata: &Metadata) -> Option<FileObjectEvidence> {
    Some(FileObjectEvidence {
        device: metadata.device?,
        inode: metadata.inode.into(),
    })
}

/// The kind of the entry `name` of the open directory `directory`, or
/// `None` when it is absent.
fn kind_at(directory: BorrowedFd<'_>, name: &CStr) -> io::Result<Option<Kind>> {
    match native::stat_at(directory, name) {
        Ok(metadata) => Ok(Some(metadata.kind)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) if error.raw_os_error() == Some(libc::ENOTDIR) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Whether the open directory `directory` is a Git directory: it has
/// `HEAD` as a file or a symbolic link, and `objects` and `refs` as
/// directories ([`GIT_DIRECTORY_NAMES`]). Each name is read relative to
/// the open directory, with no symbolic link followed.
///
/// # Errors
///
/// Returns the error of a read that is not an absent name.
pub(crate) fn is_git_directory(directory: BorrowedFd<'_>) -> io::Result<bool> {
    if !matches!(
        kind_at(directory, c"HEAD")?,
        Some(Kind::File | Kind::Symlink)
    ) {
        return Ok(false);
    }
    Ok(kind_at(directory, c"objects")? == Some(Kind::Directory)
        && kind_at(directory, c"refs")? == Some(Kind::Directory))
}

/// One Git object that a directory has now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GitObjectNow {
    /// The name of the `.git` entry of the directory, or `None` when the
    /// directory itself is a Git directory.
    pub(crate) name: Option<Vec<u8>>,
    /// The device and the inode of the object, from `fstat` of the open
    /// directory or `fstatat` of the entry.
    pub(crate) object: Option<FileObjectEvidence>,
    /// Whether the object is a directory. A plan admits only a directory: a
    /// symbolic link or a file with the name `.git` is not admitted.
    pub(crate) is_directory: bool,
}

/// Each Git object of the open directory `directory`: the directory itself
/// when it is a Git directory, and each entry with a Git marker name. The
/// names are read again from the directory.
///
/// # Errors
///
/// Returns the error of a read.
pub(crate) fn git_objects_now(directory: BorrowedFd<'_>) -> io::Result<Vec<GitObjectNow>> {
    let mut found: Vec<GitObjectNow> = Vec::new();
    if is_git_directory(directory)? {
        let object: Option<FileObjectEvidence> = native::stat_descriptor(directory)
            .ok()
            .as_ref()
            .and_then(identity);
        found.push(GitObjectNow {
            name: None,
            object,
            is_directory: true,
        });
    }
    let again: OwnedFd = native::open_directory_at(directory, c".")?;
    let mut stream: DirStream = DirStream::from_descriptor(again)?;
    let mut name: Vec<u8> = Vec::new();
    while stream.next_name(&mut name)? {
        // The name ends with its NUL terminator.
        let plain: &[u8] = name.strip_suffix(&[0]).unwrap_or(&name);
        if !is_marker(plain) {
            continue;
        }
        let entry: CString = CString::new(plain.to_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "name"))?;
        let (object, is_directory): (Option<FileObjectEvidence>, bool) =
            match native::stat_at(stream.descriptor(), &entry) {
                Ok(metadata) => (identity(&metadata), metadata.kind == Kind::Directory),
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(_) => (None, false),
            };
        found.push(GitObjectNow {
            name: Some(plain.to_vec()),
            object,
            is_directory,
        });
    }
    Ok(found)
}

/// Finds the repositories of a unit from the entries of a walk that
/// another module does, for example the scanner: each `.git` entry, and
/// each directory with the names of [`GIT_DIRECTORY_NAMES`].
#[derive(Debug, Default)]
pub(crate) struct MarkerTracker {
    /// The names of [`GIT_DIRECTORY_NAMES`] that each directory has, as
    /// bits.
    frames: std::collections::BTreeMap<PathBuf, u8>,
    /// The first repository: the `.git` entry, or the Git directory.
    first: Option<PathBuf>,
}

impl MarkerTracker {
    /// Examines one entry of the walk, at `relative` below the unit.
    /// Returns whether this entry shows a repository.
    pub(crate) fn note(&mut self, relative: &Path, kind: crate::scan::EntryKind) -> bool {
        use crate::scan::EntryKind;
        let Some(name) = relative.file_name() else {
            return false;
        };
        let name: &[u8] = name.as_bytes();
        if is_marker(name) {
            self.first.get_or_insert_with(|| relative.to_path_buf());
            return true;
        }
        let bit: u8 = match GIT_DIRECTORY_NAMES
            .iter()
            .position(|frame| name.eq_ignore_ascii_case(frame.as_bytes()))
        {
            Some(0) if matches!(kind, EntryKind::File | EntryKind::Symlink) => 1,
            Some(1) if kind == EntryKind::Directory => 2,
            Some(2) if kind == EntryKind::Directory => 4,
            _ => return false,
        };
        let parent: PathBuf = relative
            .parent()
            .map_or_else(PathBuf::new, Path::to_path_buf);
        // A walk with more such directories than the bound counts as a
        // repository: the tracker cannot follow them.
        let full: bool =
            self.frames.len() >= MAX_TRACKED_FRAMES && !self.frames.contains_key(&parent);
        let bits: u8 = if full {
            7
        } else {
            let bits: &mut u8 = self.frames.entry(parent.clone()).or_default();
            *bits |= bit;
            *bits
        };
        if bits == 7 {
            self.first.get_or_insert(parent);
            return true;
        }
        false
    }

    /// The first repository, relative to the unit: the path of the `.git`
    /// entry, or of the Git directory.
    pub(crate) fn first(&self) -> Option<&Path> {
        self.first.as_deref()
    }
}

/// A scan observer that gives each measured entry of a unit to a
/// [`MarkerTracker`], so that a measurement with the scanner also looks
/// for repositories, with no second walk.
#[derive(Debug)]
pub(crate) struct MarkerObserver<'a> {
    unit: &'a Path,
    tracker: MarkerTracker,
    /// Whether an entry was not below the unit.
    outside: bool,
}

impl<'a> MarkerObserver<'a> {
    /// An observer for the scan of the unit at `unit`.
    pub(crate) fn new(unit: &'a Path) -> Self {
        Self {
            unit,
            tracker: MarkerTracker::default(),
            outside: false,
        }
    }

    /// The verdict on the unit after the scan that gave `result`. A
    /// repository refuses the unit, and so does a scan that did not read
    /// each entry: a part that it did not read can hold a repository.
    pub(crate) fn verdict(&self, result: &ScanResult) -> Verdict {
        let refuse = |reason: RefusalReason, path: Option<PathBuf>| {
            Verdict::Refused(RepositoryRefusal { reason, path })
        };
        if let Some(first) = self.tracker.first() {
            // A `.git` entry names its work tree; a Git directory is its
            // own path.
            let is_marker_entry: bool = first
                .file_name()
                .is_some_and(|name| is_marker(name.as_bytes()));
            let path: PathBuf = if is_marker_entry {
                first.parent().map_or_else(PathBuf::new, Path::to_path_buf)
            } else {
                first.to_path_buf()
            };
            return refuse(RefusalReason::NestedRepository, Some(path));
        }
        let relative = |path: &LosslessPath| {
            path.to_path_buf()
                .strip_prefix(self.unit)
                .ok()
                .map(Path::to_path_buf)
        };
        if let Some(region) = result.regions.first() {
            let reason: RefusalReason = if region.cause == RegionCause::PermissionDenied {
                RefusalReason::UnreadableDirectory
            } else {
                RefusalReason::DetectionIncomplete
            };
            return refuse(reason, relative(&region.path));
        }
        if let Some(boundary) = result.boundaries.first() {
            return refuse(RefusalReason::OtherDevice, relative(&boundary.path));
        }
        let is_complete: bool = !self.outside
            && result.completion == ScanCompletion::Finished
            && matches!(result.coverage, Coverage::Complete)
            && result.regions_omitted == svalnir_core::quantity::EntryCount::ZERO
            && result.boundaries_omitted == svalnir_core::quantity::EntryCount::ZERO;
        if is_complete {
            Verdict::Clear
        } else {
            refuse(RefusalReason::DetectionIncomplete, None)
        }
    }
}

impl ScanObserver for MarkerObserver<'_> {
    fn entry_measured(&mut self, entry: &EntryRecord<'_>) {
        match entry.path.strip_prefix(self.unit) {
            Ok(relative) => {
                self.tracker.note(relative, entry.kind);
            }
            Err(_) => self.outside = true,
        }
    }
}

/// The marker kind of an object.
const fn marker_kind(kind: Kind) -> MarkerKind {
    match kind {
        Kind::Directory => MarkerKind::Directory,
        Kind::File => MarkerKind::File,
        Kind::Symlink | Kind::Other => MarkerKind::Other,
    }
}

/// Opens the directory `unit` from `/`, one component at a time, with no
/// symbolic link on the path.
fn open_unit(unit: &Path) -> io::Result<OwnedFd> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidInput, "not a plain absolute path");
    let mut components = unit.components();
    if components.next() != Some(Component::RootDir) {
        return Err(invalid());
    }
    let mut directory: OwnedFd = native::open_filesystem_root()?;
    for component in components {
        let Component::Normal(name) = component else {
            return Err(invalid());
        };
        let name: CString = CString::new(name.as_bytes()).map_err(|_| invalid())?;
        directory = native::open_directory_at(directory.as_fd(), &name)?;
    }
    Ok(directory)
}

impl Walk<'_> {
    /// Reads the clock and the cancellation at an interval of entries.
    fn check_bounds(&mut self) -> Result<(), DetectionProblem> {
        self.entries = self.entries.saturating_add(1);
        if self.entries > self.limits.max_entries {
            return Err(DetectionProblem::EntryLimit);
        }
        if self.entries.is_multiple_of(CHECK_INTERVAL) {
            if self.cancel.is_some_and(CancellationToken::is_cancelled) {
                return Err(DetectionProblem::Cancelled);
            }
            if self
                .deadline
                .is_none_or(|deadline| Instant::now() >= deadline)
            {
                return Err(DetectionProblem::TimeLimit);
            }
        }
        Ok(())
    }

    /// Reads the open directory `descriptor` at `relative` and each
    /// directory below it. `level` is 0 for the unit.
    fn directory(
        &mut self,
        descriptor: OwnedFd,
        relative: &mut PathBuf,
        level: u32,
    ) -> Result<(), DetectionProblem> {
        let unreadable = |relative: &Path| DetectionProblem::Unreadable {
            directory: relative.to_path_buf(),
        };
        // A Git directory with no `.git` name. Its content is the
        // repository itself, so the walk does not enter it.
        match is_git_directory(descriptor.as_fd()) {
            Ok(false) => {}
            Ok(true) => {
                if self.found.len() >= self.limits.max_repositories {
                    return Err(DetectionProblem::RepositoryLimit);
                }
                let object: Option<FileObjectEvidence> =
                    native::stat_descriptor(descriptor.as_fd())
                        .ok()
                        .as_ref()
                        .and_then(identity);
                self.found.push(FoundRepository {
                    work_tree: relative.clone(),
                    marker: MarkerKind::Bare,
                    object,
                    marker_name: Vec::new(),
                });
                return Ok(());
            }
            Err(_) => return Err(unreadable(relative)),
        }
        let mut stream: DirStream =
            DirStream::from_descriptor(descriptor).map_err(|_| unreadable(relative))?;
        let mut buffer: Vec<u8> = Vec::new();
        loop {
            match stream.next_name(&mut buffer) {
                Ok(true) => {}
                Ok(false) => return Ok(()),
                Err(_) => return Err(unreadable(relative)),
            }
            self.check_bounds()?;
            let Ok(name) = CStr::from_bytes_with_nul(&buffer) else {
                return Err(unreadable(relative));
            };
            let metadata: Metadata = match native::stat_at(stream.descriptor(), name) {
                Ok(metadata) => metadata,
                // The entry went away after `readdir` gave its name.
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(_) => return Err(unreadable(relative)),
            };
            let name_bytes: &[u8] = name.to_bytes();
            if is_marker(name_bytes) {
                if self.found.len() >= self.limits.max_repositories {
                    return Err(DetectionProblem::RepositoryLimit);
                }
                self.found.push(FoundRepository {
                    work_tree: relative.clone(),
                    marker: marker_kind(metadata.kind),
                    object: identity(&metadata),
                    marker_name: name_bytes.to_vec(),
                });
                // The Git directory is not a part of the work tree, and
                // its content is the repository itself.
                continue;
            }
            if metadata.kind != Kind::Directory {
                continue;
            }
            relative.push(OsStr::from_bytes(name_bytes));
            let result: Result<(), DetectionProblem> =
                self.child(&stream, name, &metadata, relative, level);
            relative.pop();
            result?;
        }
    }

    /// Opens the directory `name` of `stream`, compares it with
    /// `metadata`, and reads it. `relative` is its path.
    fn child(
        &mut self,
        stream: &DirStream,
        name: &CStr,
        metadata: &Metadata,
        relative: &mut PathBuf,
        level: u32,
    ) -> Result<(), DetectionProblem> {
        if metadata.device.is_none() || metadata.device != self.device {
            return Err(DetectionProblem::OtherDevice {
                directory: relative.clone(),
            });
        }
        let level: u32 = level.saturating_add(1);
        if level > self.limits.max_depth {
            return Err(DetectionProblem::DepthLimit);
        }
        let descriptor: OwnedFd = match native::open_directory_at(stream.descriptor(), name) {
            Ok(descriptor) => descriptor,
            // The directory went away after its measurement.
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(_) => {
                return Err(DetectionProblem::Unreadable {
                    directory: relative.clone(),
                });
            }
        };
        let opened: Metadata = native::stat_descriptor(descriptor.as_fd()).map_err(|_| {
            DetectionProblem::Unreadable {
                directory: relative.clone(),
            }
        })?;
        if opened.inode != metadata.inode || opened.device != metadata.device {
            return Err(DetectionProblem::Changed {
                directory: relative.clone(),
            });
        }
        self.directory(descriptor, relative, level)
    }
}

/// Walks the unit at `unit` and reports each Git marker and the first
/// problem of the walk.
///
/// `unit` is an absolute path with no `.` or `..` component and no
/// symbolic link: the walk opens it from `/` one component at a time.
/// The walk reads each name of a directory with `fstatat` and
/// `AT_SYMLINK_NOFOLLOW` relative to the open directory, opens each
/// directory with `openat`, `O_NOFOLLOW`, and `O_DIRECTORY`, and compares
/// the open directory with its measurement. It does not enter a `.git`
/// directory. It stops at the first problem; the repositories that it
/// found before the problem are in the result.
#[must_use]
pub fn detect(
    unit: &Path,
    limits: &DetectionLimits,
    cancel: Option<&CancellationToken>,
) -> Detection {
    let Ok(descriptor) = open_unit(unit) else {
        return Detection {
            repositories: Vec::new(),
            problem: Some(DetectionProblem::UnitUnavailable),
        };
    };
    let Ok(root) = native::stat_descriptor(descriptor.as_fd()) else {
        return Detection {
            repositories: Vec::new(),
            problem: Some(DetectionProblem::UnitUnavailable),
        };
    };
    let mut walk: Walk<'_> = Walk {
        limits,
        cancel,
        deadline: Instant::now().checked_add(limits.max_duration),
        device: root.device,
        entries: 0,
        found: Vec::new(),
    };
    let mut relative: PathBuf = PathBuf::new();
    let problem: Option<DetectionProblem> = walk.directory(descriptor, &mut relative, 0).err();
    Detection {
        repositories: walk.found,
        problem,
    }
}

/// The refusal of a problem of the walk.
fn refusal_of(problem: &DetectionProblem) -> RepositoryRefusal {
    let (reason, path) = match problem {
        DetectionProblem::UnitUnavailable => (RefusalReason::UnitUnavailable, None),
        DetectionProblem::Unreadable { directory } => {
            (RefusalReason::UnreadableDirectory, Some(directory.clone()))
        }
        DetectionProblem::OtherDevice { directory } => {
            (RefusalReason::OtherDevice, Some(directory.clone()))
        }
        DetectionProblem::Changed { directory } => {
            (RefusalReason::DetectionIncomplete, Some(directory.clone()))
        }
        DetectionProblem::DepthLimit
        | DetectionProblem::EntryLimit
        | DetectionProblem::TimeLimit
        | DetectionProblem::RepositoryLimit
        | DetectionProblem::Cancelled => (RefusalReason::DetectionIncomplete, None),
    };
    RepositoryRefusal { reason, path }
}

/// The admitted repositories of the unit at `unit` from its detection, or
/// the first refusal.
///
/// A problem of the walk refuses the unit. A repository refuses the unit,
/// unless `checkouts` is given and the repository is a checkout that
/// [`swiftpm::check_checkout`] accepts or a mirror that
/// [`swiftpm::check_mirror`] accepts. Each accepted repository is in the
/// result, with the path of its Git object relative to the unit and the
/// identity that the walk measured. Without a Git executable (`git`), each
/// checkout is refused.
///
/// # Errors
///
/// Returns the first [`RepositoryRefusal`].
pub fn judge_admitting(
    unit: &Path,
    detection: &Detection,
    checkouts: Option<&SwiftPmCheckouts>,
    git: Result<&GitTool, GitToolProblem>,
) -> Result<Vec<AdmittedRepository>, RepositoryRefusal> {
    if let Some(problem) = &detection.problem {
        return Err(refusal_of(problem));
    }
    let mut admitted: Vec<AdmittedRepository> = Vec::new();
    let mut pins: Option<Result<Option<Vec<Pin>>, PinsProblem>> = None;
    for repository in &detection.repositories {
        let refuse = |reason: RefusalReason| RepositoryRefusal {
            reason,
            path: Some(repository.work_tree.clone()),
        };
        let work_tree: PathBuf = unit.join(&repository.work_tree);
        let Some((checkouts, managed)) = checkouts.and_then(|checkouts| {
            checkouts
                .managed(&work_tree, repository.marker)
                .map(|managed| (checkouts, managed))
        }) else {
            return Err(refuse(RefusalReason::NestedRepository));
        };
        let Ok(git) = git else {
            return Err(refuse(RefusalReason::GitUnavailable));
        };
        // The pins are read once. The pin-less mode has none.
        let Ok(pins) = pins.get_or_insert_with(|| match checkouts.resolved() {
            Some(resolved) => read_pins(resolved).map(Some),
            None => Ok(None),
        }) else {
            return Err(refuse(RefusalReason::PinsUnavailable));
        };
        let pins: Option<&[Pin]> = pins.as_deref();
        let Some(object) = repository.object else {
            return Err(refuse(RefusalReason::IdentityChanged));
        };
        let (path, kind): (PathBuf, RepositoryKind) = match &managed {
            // The path has the name that the walk read, because the
            // executor compares the name byte by byte.
            swiftpm::Managed::Checkout(_) => (
                repository
                    .work_tree
                    .join(OsStr::from_bytes(&repository.marker_name)),
                RepositoryKind::Checkout,
            ),
            swiftpm::Managed::Mirror => (repository.work_tree.clone(), RepositoryKind::BareMirror),
        };
        let checked: Result<(), RefusalReason> = match managed {
            swiftpm::Managed::Checkout(name) => {
                swiftpm::check_checkout(git, &work_tree, &name, pins, checkouts, repository.object)
            }
            swiftpm::Managed::Mirror => {
                swiftpm::check_mirror(git, &work_tree, pins, repository.object).map(|_| ())
            }
        };
        if let Err(reason) = checked {
            return Err(refuse(reason));
        }
        let path: LosslessPath =
            LosslessPath::from_path(&path).map_err(|_| refuse(RefusalReason::NestedRepository))?;
        admitted.push(AdmittedRepository { path, kind, object });
    }
    Ok(admitted)
}

/// The verdict on the unit at `unit` from its detection. The first refusal
/// of [`judge_admitting`] is the verdict.
#[must_use]
pub fn judge(
    unit: &Path,
    detection: &Detection,
    checkouts: Option<&SwiftPmCheckouts>,
    git: Result<&GitTool, GitToolProblem>,
) -> Verdict {
    match judge_admitting(unit, detection, checkouts, git) {
        Ok(_) => Verdict::Clear,
        Err(refusal) => Verdict::Refused(refusal),
    }
}

/// The repositories that the exception admits in the unit at `unit`: the
/// walk of [`detect`] and the checks of [`judge_admitting`]. The list is
/// sorted by path, so two calls on an unchanged unit give equal lists.
///
/// # Errors
///
/// Returns the first [`RepositoryRefusal`].
pub fn admit_unit(
    unit: &Path,
    checkouts: &SwiftPmCheckouts,
    git: Result<&GitTool, GitToolProblem>,
    limits: &DetectionLimits,
    cancel: Option<&CancellationToken>,
) -> Result<Vec<AdmittedRepository>, RepositoryRefusal> {
    let detection: Detection = detect(unit, limits, cancel);
    let mut admitted: Vec<AdmittedRepository> =
        judge_admitting(unit, &detection, Some(checkouts), git)?;
    admitted.sort_by(|first, second| first.path.as_bytes().cmp(second.path.as_bytes()));
    Ok(admitted)
}

/// The result of the check of the admitted repositories before a step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepositoryRecheck {
    /// The check produced exactly the sealed list.
    Same,
    /// The unit differs from the plan: the stable code of the refusal.
    Refused(&'static str),
    /// The check cannot be made: the stable code.
    Unknown(&'static str),
}

/// The code of the refusal when the unit has a repository that the sealed
/// plan does not admit.
pub const NESTED_REPOSITORY_CODE: &str = "nested_repository";

/// The code of the refusal when the list of admitted repositories that the
/// check gives now is not the sealed list: another path, kind, or identity,
/// or a repository that no longer passes the check (for example after a
/// new commit).
pub const REPOSITORY_CHANGED_CODE: &str = "repository_changed";

/// Runs the checks of the exception again for the unit at `unit`, with the
/// directories of `checkouts` (`None` for a layout with no checkouts), and
/// compares the result with the list `sealed` of the plan. The Git
/// executable `git` is `None` when none passed the checks.
///
/// Only exactly the sealed list passes: the same paths, the same kinds, and
/// the same identities of the Git objects. Without a Git executable, a unit
/// with a repository gives [`RepositoryRecheck::Unknown`].
#[must_use]
pub fn recheck_admitted(
    unit: &Path,
    checkouts: Option<&SwiftPmCheckouts>,
    git: Option<&GitTool>,
    sealed: &[AdmittedRepository],
) -> RepositoryRecheck {
    let git: Result<&GitTool, GitToolProblem> = git.ok_or(GitToolProblem::NotInstalled);
    let limits: DetectionLimits = DetectionLimits::default();
    let detection: Detection = detect(unit, &limits, None);
    match judge_admitting(unit, &detection, checkouts, git) {
        Ok(mut now) => {
            now.sort_by(|first, second| first.path.as_bytes().cmp(second.path.as_bytes()));
            let mut expected: Vec<&AdmittedRepository> = sealed.iter().collect();
            expected.sort_by(|first, second| first.path.as_bytes().cmp(second.path.as_bytes()));
            if now.iter().eq(expected) {
                RepositoryRecheck::Same
            } else {
                RepositoryRecheck::Refused(REPOSITORY_CHANGED_CODE)
            }
        }
        Err(refusal) => match refusal.reason {
            RefusalReason::GitUnavailable => RepositoryRecheck::Unknown("git_unavailable"),
            RefusalReason::UnitUnavailable
            | RefusalReason::UnreadableDirectory
            | RefusalReason::DetectionIncomplete
            | RefusalReason::OtherDevice => {
                RepositoryRecheck::Unknown("repository_check_incomplete")
            }
            RefusalReason::NestedRepository if sealed.is_empty() => {
                RepositoryRecheck::Refused(NESTED_REPOSITORY_CODE)
            }
            _ => RepositoryRecheck::Refused(REPOSITORY_CHANGED_CODE),
        },
    }
}

/// The exception for the clean repositories of Swift Package Manager, as a
/// rule of a manual eviction asks for it: the directories of the checkouts
/// and of the mirrors, with the pins or with none, and the Git executable.
#[derive(Debug, Clone)]
pub struct RepositoryPolicy<'a> {
    /// The checkouts, the mirrors, and the pins of the unit.
    pub checkouts: SwiftPmCheckouts,
    /// The trusted Git executable.
    pub git: Result<&'a GitTool, GitToolProblem>,
}

/// [`detect`] and [`judge`] for the unit at `unit`.
#[must_use]
pub fn check_unit(
    unit: &Path,
    checkouts: Option<&SwiftPmCheckouts>,
    git: Result<&GitTool, GitToolProblem>,
    limits: &DetectionLimits,
    cancel: Option<&CancellationToken>,
) -> Verdict {
    judge(unit, &detect(unit, limits, cancel), checkouts, git)
}
