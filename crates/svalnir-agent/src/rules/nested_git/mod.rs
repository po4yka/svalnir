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
//!    ([`is_marker`]) that it finds, and the first directory that it cannot
//!    read. The walk is bounded by depth, by entries, and by time, follows
//!    no symbolic link, does not enter another device, and reads each name
//!    relative to an open directory.
//! 2. [`judge`] gives the verdict of a detection. Each problem of the walk
//!    refuses the unit: a directory that the walk cannot read can hold a
//!    repository. Each repository refuses the unit, with one exception: a
//!    clone that Swift Package Manager made in its `checkouts` directory
//!    and can make again ([`SwiftPmCheckouts`], [`swiftpm`]).
//! 3. [`check_unit`] does the two steps.
//!
//! The discovery of an eviction does not call [`detect`]: its measurement
//! with the scanner already reads each entry of a unit, so it applies
//! [`is_marker`] to each entry (`rules::unit`). The filesystem executor
//! applies [`is_marker`] in the measurement of a directory target, before
//! its first removal call.
//!
//! # What the walk cannot see
//!
//! The walk finds a repository by the name `.git`. A bare repository has no
//! such name, and the walk does not report it. A name check is a check at
//! one time: a repository that a process makes after the walk is not seen
//! until the next check.

pub mod swiftpm;

#[cfg(test)]
mod tests;

use std::ffi::{CStr, CString, OsStr};
use std::io;
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use serde::Serialize;
use svalnir_core::file::DeviceNumber;

use crate::executor::fs::native::{self, DirStream, Kind, Metadata};
use crate::rules::git::{GitTool, GitToolProblem};
use crate::scan::CancellationToken;

pub use swiftpm::{Pin, PinsProblem, SwiftPmCheckouts, read_pins};

/// The name of the object that marks a Git work tree: a directory, or a
/// file that names the Git directory of a submodule or of a linked
/// worktree.
pub const GIT_MARKER: &str = ".git";

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
            max_repositories: 64,
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
}

/// One repository that the walk found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FoundRepository {
    /// The directory that holds the marker, relative to the unit. Empty
    /// for the unit itself.
    pub work_tree: PathBuf,
    /// The kind of the marker.
    pub marker: MarkerKind,
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

/// The verdict on the unit at `unit` from its detection.
///
/// A problem of the walk refuses the unit. A repository refuses the unit,
/// unless `checkouts` is given and the repository is a checkout that
/// [`swiftpm::check_checkout`] accepts. The first refusal is the verdict.
/// Without a Git executable (`git`), each checkout is refused.
#[must_use]
pub fn judge(
    unit: &Path,
    detection: &Detection,
    checkouts: Option<&SwiftPmCheckouts>,
    git: Result<&GitTool, GitToolProblem>,
) -> Verdict {
    if let Some(problem) = &detection.problem {
        return Verdict::Refused(refusal_of(problem));
    }
    let mut pins: Option<Result<Vec<Pin>, PinsProblem>> = None;
    for repository in &detection.repositories {
        let refuse = |reason: RefusalReason| {
            Verdict::Refused(RepositoryRefusal {
                reason,
                path: Some(repository.work_tree.clone()),
            })
        };
        let work_tree: PathBuf = unit.join(&repository.work_tree);
        let Some((checkouts, name)) = checkouts.and_then(|checkouts| {
            checkouts
                .checkout_name(&work_tree, repository.marker)
                .map(|name| (checkouts, name))
        }) else {
            return refuse(RefusalReason::NestedRepository);
        };
        let Ok(git) = git else {
            return refuse(RefusalReason::GitUnavailable);
        };
        let Ok(pins) = pins.get_or_insert_with(|| read_pins(checkouts.resolved())) else {
            return refuse(RefusalReason::PinsUnavailable);
        };
        if let Err(reason) = swiftpm::check_checkout(git, &work_tree, &name, pins, checkouts) {
            return refuse(reason);
        }
    }
    Verdict::Clear
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
