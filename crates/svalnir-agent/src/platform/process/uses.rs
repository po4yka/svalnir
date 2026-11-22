//! The file paths that the processes of one user use now: open files,
//! mapped files, the working directory, the executable, and the paths that
//! the arguments name.
//!
//! Owning specification: `docs/CLEANUP_RULES.md` section 6, "Use by a
//! running process". The collector reads only. It keeps only the paths that
//! the caller's filter accepts, so the inventory has no path outside the
//! scope of the check and no argument that names no such path. It keeps no
//! command line.
//!
//! An inventory whose list, clock, or global bounds failed has an
//! [`InventoryGap`]. A process of the user whose use queries failed is an
//! [`UnknownProcess`], which can use each path. A use in either case is
//! still evidence of use; only an inventory with no gap and no unknown
//! process shows that a path is not used.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use serde::Serialize;
use svalnir_core::process::{Pid, Uid};
use svalnir_core::time::MonotonicNanos;

use super::source::{ProcessSource, QueryFailure, RawArguments, RawPaths};

/// The kind of use of a path by a process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PathUseKind {
    /// A file descriptor of the process refers to the path.
    OpenFile,
    /// A memory region of the process maps the file at the path.
    MappedFile,
    /// The path is the working directory of the process.
    WorkingDirectory,
    /// The path is the executable of the process.
    Executable,
    /// An argument of the command line names the path.
    Argument,
}

/// One path that one process uses, in the scope of the check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessPathUse {
    /// How the process uses the path.
    pub kind: PathUseKind,
    /// The absolute path as the kernel gave it, or as the argument named
    /// it, joined to the working directory for a relative argument.
    pub path: PathBuf,
}

/// The uses of one process in the scope of the check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessUses {
    /// The process ID at the time of the inventory.
    pub pid: Pid,
    /// The file name of the executable, at most [`MAX_NAME_BYTES`] bytes.
    pub name: String,
    /// The uses, each one time.
    pub uses: Vec<ProcessPathUse>,
}

/// The largest number of bytes of the executable name in a record.
pub const MAX_NAME_BYTES: usize = 64;

/// Why an inventory is not complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InventoryGap {
    /// The clock gave no time.
    ClockUnavailable,
    /// The process list cannot be read.
    ProcessListUnavailable,
    /// The process list has no process of the user.
    ProcessListEmpty,
    /// The process list has more processes than the bound.
    TooManyProcesses,
    /// An identity query of a process of the user, or of a process with no
    /// known owner, was denied.
    ProcessQueryDenied,
    /// A query of a process of the user failed.
    ProcessQueryFailed,
    /// A process has more file descriptors than the bound.
    DescriptorsTruncated,
    /// A process has more memory regions than the bound.
    RegionsTruncated,
    /// The arguments of a process are longer than the bound.
    ArgumentsTruncated,
    /// The inventory passed its time bound.
    DeadlineReached,
}

impl InventoryGap {
    /// The stable name of the gap.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClockUnavailable => "clock_unavailable",
            Self::ProcessListUnavailable => "process_list_unavailable",
            Self::ProcessListEmpty => "process_list_empty",
            Self::TooManyProcesses => "too_many_processes",
            Self::ProcessQueryDenied => "process_query_denied",
            Self::ProcessQueryFailed => "process_query_failed",
            Self::DescriptorsTruncated => "descriptors_truncated",
            Self::RegionsTruncated => "regions_truncated",
            Self::ArgumentsTruncated => "arguments_truncated",
            Self::DeadlineReached => "deadline_reached",
        }
    }
}

/// The bounds of one inventory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UseLimits {
    /// The largest number of process IDs that the inventory examines.
    pub max_processes: usize,
    /// The largest number of file descriptors of one process.
    pub max_descriptors: usize,
    /// The largest number of memory regions of one process.
    pub max_regions: usize,
    /// The largest size of the argument area of one process, in bytes.
    pub max_argument_bytes: usize,
    /// The longest time of the inventory.
    pub max_duration: Duration,
}

impl Default for UseLimits {
    fn default() -> Self {
        Self {
            max_processes: 8_192,
            max_descriptors: 16_384,
            max_regions: 65_536,
            // `kern.argmax` of macOS is 1 MiB.
            max_argument_bytes: 1 << 20,
            max_duration: Duration::from_secs(20),
        }
    }
}

/// A process of the user whose uses are not known: a use query failed, or
/// the process passed a bound. It can use each path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownProcess {
    /// The process ID at the time of the inventory.
    pub pid: Pid,
    /// The file name of the executable, or an empty name when it is not
    /// known.
    pub name: String,
    /// Why the uses are not known.
    pub reason: InventoryGap,
}

/// The largest number of [`UnknownProcess`] records of one inventory. The
/// count of the others is in [`PathInventory::unknown_omitted`].
pub const MAX_UNKNOWN_PROCESSES: usize = 32;

/// The path uses of the processes of one user at one time.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PathInventory {
    /// Each process of the user with at least one use in the scope.
    pub processes: Vec<ProcessUses>,
    /// The processes of the user whose uses are not known, at most
    /// [`MAX_UNKNOWN_PROCESSES`].
    pub unknown: Vec<UnknownProcess>,
    /// The number of unknown processes that are not in `unknown`.
    pub unknown_omitted: u64,
    /// The number of processes of the user that refused a use query and
    /// that run Apple platform code from the sealed system volume. The
    /// check does not see their uses (owner decision of 2026-11-22,
    /// `docs/CLEANUP_RULES.md` section 6).
    pub platform_refused: u64,
    /// The number of processes whose identity query the system denied and
    /// whose owner query did not show a different user: for example a
    /// set-user-ID process or a process that the platform protects. The
    /// check does not see them (`docs/CLEANUP_RULES.md` section 6).
    pub not_visible: u64,
    /// Why the inventory as a whole is not complete. `None` when the list,
    /// the clock, and the bounds of the inventory permitted each process to
    /// be examined. When several gaps apply, this is the first one.
    pub gap: Option<InventoryGap>,
    /// The monotonic time before the first query.
    pub observed_at: Option<MonotonicNanos>,
}

impl PathInventory {
    /// An inventory that has no use and that is not complete.
    #[must_use]
    pub const fn incomplete(gap: InventoryGap, observed_at: Option<MonotonicNanos>) -> Self {
        Self {
            processes: Vec::new(),
            unknown: Vec::new(),
            unknown_omitted: 0,
            platform_refused: 0,
            not_visible: 0,
            gap: Some(gap),
            observed_at,
        }
    }

    fn note(&mut self, gap: InventoryGap) {
        self.gap.get_or_insert(gap);
    }

    fn unknown_process(&mut self, pid: Pid, name: String, reason: InventoryGap) {
        if self.unknown.len() < MAX_UNKNOWN_PROCESSES {
            self.unknown.push(UnknownProcess { pid, name, reason });
        } else {
            self.unknown_omitted = self.unknown_omitted.saturating_add(1);
        }
    }
}

/// `path` with `.` removed and each `..` applied to the component before
/// it, with no call on the filesystem.
fn lexical(path: &Path) -> PathBuf {
    let mut result: PathBuf = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                result.pop();
            }
            other => result.push(other),
        }
    }
    result
}

/// The paths that the arguments name: an absolute argument, the part after
/// the first `=` when it is absolute, and a relative argument joined to the
/// working directory when it is known. The result is lexical; no symbolic
/// link is followed.
pub(super) fn argument_paths(
    arguments: &RawArguments,
    working_directory: Option<&Path>,
) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = Vec::new();
    for value in &arguments.values {
        if value.is_empty() {
            continue;
        }
        let candidate: Option<PathBuf> = if value.first() == Some(&b'/') {
            Some(PathBuf::from(OsStr::from_bytes(value)))
        } else if let Some(after) = value
            .iter()
            .position(|byte| *byte == b'=')
            .and_then(|index| value.get(index + 1..))
            .filter(|after| after.first() == Some(&b'/'))
        {
            Some(PathBuf::from(OsStr::from_bytes(after)))
        } else if value.first() == Some(&b'-') {
            None
        } else {
            working_directory.map(|directory| directory.join(OsStr::from_bytes(value)))
        };
        if let Some(path) = candidate.map(|path| lexical(&path))
            && !paths.contains(&path)
        {
            paths.push(path);
        }
    }
    paths
}

/// The directories of the sealed system volume whose executables the
/// platform blind spot accepts (owner decision of 2026-11-22). The data
/// volume below `/System/Volumes` is not sealed and is not accepted.
const SEALED_SYSTEM_DIRECTORIES: [&str; 6] = [
    "/System",
    "/usr/libexec",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
];

/// Whether `path` is below a directory of the sealed system volume.
pub(super) fn is_on_sealed_system_volume(path: &Path) -> bool {
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
        || path.starts_with("/System/Volumes")
    {
        return false;
    }
    SEALED_SYSTEM_DIRECTORIES
        .iter()
        .any(|directory| path.starts_with(directory) && path != Path::new(directory))
}

/// The file name of `path`, at most [`MAX_NAME_BYTES`] bytes.
fn short_name(path: &Path) -> String {
    let name: String = path
        .file_name()
        .map_or_else(String::new, |name| name.to_string_lossy().into_owned());
    let mut end: usize = name.len().min(MAX_NAME_BYTES);
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    name.get(..end).unwrap_or_default().to_owned()
}

/// The path uses of the processes of `principal` from `source`, with only
/// the paths that `keep` accepts.
///
/// A process of the user is a process whose effective or real user is
/// `principal`. The owner query comes first, so no use query is made of a
/// process of a different user. The calling process is not examined. A
/// process that exited during the reading is not in the inventory. A
/// process whose identity query is denied is counted in
/// [`PathInventory::not_visible`]. A process of the user whose use query
/// fails, or that passes a bound of one process, is an
/// [`UnknownProcess`].
pub fn collect_path_uses<S: ProcessSource + ?Sized>(
    source: &S,
    principal: Uid,
    keep: &dyn Fn(&Path) -> bool,
    limits: UseLimits,
) -> PathInventory {
    let started: Instant = Instant::now();
    let mut inventory: PathInventory = PathInventory {
        observed_at: source.monotonic_now().ok(),
        ..PathInventory::default()
    };
    if inventory.observed_at.is_none() {
        inventory.note(InventoryGap::ClockUnavailable);
    }
    let Ok(mut pids) = source.list_pids() else {
        inventory.note(InventoryGap::ProcessListUnavailable);
        return inventory;
    };
    if pids.len() > limits.max_processes {
        inventory.note(InventoryGap::TooManyProcesses);
        pids.truncate(limits.max_processes);
    }
    let own: u32 = std::process::id();
    let mut seen: usize = 0;
    for pid in pids {
        if started.elapsed() > limits.max_duration {
            inventory.note(InventoryGap::DeadlineReached);
            break;
        }
        if u32::try_from(pid.get()).is_ok_and(|value| value == own) {
            seen += 1;
            continue;
        }
        let is_user = |(effective, real): (Uid, Uid)| effective == principal || real == principal;
        match source.process_owner(pid) {
            Ok(owner) if !is_user(owner) => continue,
            Err(QueryFailure::Gone) => continue,
            // An owner of the user, or no owner: the identity query decides.
            _ => {}
        }
        let info = match source.process_info(pid) {
            Ok(info) => info,
            Err(QueryFailure::Gone) => continue,
            Err(QueryFailure::PermissionDenied) => {
                inventory.not_visible = inventory.not_visible.saturating_add(1);
                continue;
            }
            Err(failure) => {
                let name: String = source
                    .executable_path(pid)
                    .map_or_else(|_| String::new(), |path| short_name(&path.to_path_buf()));
                inventory.unknown_process(pid, name, gap_of(failure));
                continue;
            }
        };
        if info.zombie || !is_user((info.effective_uid, info.real_uid)) {
            continue;
        }
        seen += 1;
        match examine(source, pid, keep, limits) {
            Examined::Exited => {}
            Examined::Known(uses) => inventory.processes.extend(uses),
            Examined::Unknown {
                name,
                reason,
                uses,
                executable,
                only_refused,
            } => {
                // A use that was read before the failure is still a use.
                inventory.processes.extend(uses);
                let platform: bool = only_refused
                    && executable
                        .as_deref()
                        .is_some_and(is_on_sealed_system_volume)
                    && source.apple_platform_code(pid) == Ok(true);
                if platform {
                    inventory.platform_refused = inventory.platform_refused.saturating_add(1);
                } else {
                    inventory.unknown_process(pid, name, reason);
                }
            }
        }
    }
    if seen == 0 && inventory.unknown.is_empty() {
        // A complete inventory has at least the calling process.
        inventory.note(InventoryGap::ProcessListEmpty);
    }
    inventory
}

/// The gap of a failed query of a process of the user that did not exit.
const fn gap_of(failure: QueryFailure) -> InventoryGap {
    match failure {
        QueryFailure::PermissionDenied => InventoryGap::ProcessQueryDenied,
        _ => InventoryGap::ProcessQueryFailed,
    }
}

/// The result of the examination of one process of the user.
enum Examined {
    /// The process exited during the examination.
    Exited,
    /// Each query answered; the record when the process has a use.
    Known(Option<ProcessUses>),
    /// A query failed or a bound was reached.
    Unknown {
        name: String,
        reason: InventoryGap,
        uses: Option<ProcessUses>,
        /// The executable, when its query answered.
        executable: Option<PathBuf>,
        /// Each failure was a refusal (`PermissionDenied`), and no bound
        /// was reached.
        only_refused: bool,
    },
}

/// The uses of one process of the user.
fn examine<S: ProcessSource + ?Sized>(
    source: &S,
    pid: Pid,
    keep: &dyn Fn(&Path) -> bool,
    limits: UseLimits,
) -> Examined {
    let mut reason: Option<InventoryGap> = None;
    let mut only_refused: bool = true;
    let mut fail = |reason: &mut Option<InventoryGap>, failure: QueryFailure| {
        if failure != QueryFailure::PermissionDenied {
            only_refused = false;
        }
        reason.get_or_insert(gap_of(failure));
    };
    let mut bounded: bool = false;
    let mut uses: Vec<ProcessPathUse> = Vec::new();
    let mut add = |kind: PathUseKind, path: PathBuf| {
        if keep(&path) {
            let found: ProcessPathUse = ProcessPathUse { kind, path };
            if !uses.contains(&found) {
                uses.push(found);
            }
        }
    };
    let executable: Option<PathBuf> = match source.executable_path(pid) {
        Ok(path) => Some(path.to_path_buf()),
        Err(QueryFailure::Gone) => return Examined::Exited,
        Err(failure) => {
            fail(&mut reason, failure);
            None
        }
    };
    let name: String = executable.as_deref().map_or_else(String::new, short_name);
    if let Some(path) = &executable {
        add(PathUseKind::Executable, path.clone());
    }
    let working_directory: Option<PathBuf> = match source.working_directory(pid) {
        Ok(path) => Some(path.to_path_buf()),
        Err(QueryFailure::Gone) => return Examined::Exited,
        Err(failure) => {
            fail(&mut reason, failure);
            None
        }
    };
    if let Some(path) = &working_directory {
        add(PathUseKind::WorkingDirectory, path.clone());
    }
    let queries: [(PathUseKind, InventoryGap, Result<RawPaths, QueryFailure>); 2] = [
        (
            PathUseKind::OpenFile,
            InventoryGap::DescriptorsTruncated,
            source.open_file_paths(pid, limits.max_descriptors),
        ),
        (
            PathUseKind::MappedFile,
            InventoryGap::RegionsTruncated,
            source.mapped_file_paths(pid, limits.max_regions),
        ),
    ];
    for (kind, bound, result) in queries {
        match result {
            Ok(found) => {
                if found.truncated {
                    bounded = true;
                    reason.get_or_insert(bound);
                }
                for path in found.paths {
                    add(kind, path.to_path_buf());
                }
            }
            Err(QueryFailure::Gone) => return Examined::Exited,
            Err(failure) => {
                fail(&mut reason, failure);
            }
        }
    }
    match source.arguments(pid, limits.max_argument_bytes) {
        Ok(arguments) => {
            if arguments.truncated {
                bounded = true;
                reason.get_or_insert(InventoryGap::ArgumentsTruncated);
            }
            // The arguments are compared here and dropped with `arguments`.
            for path in argument_paths(&arguments, working_directory.as_deref()) {
                add(PathUseKind::Argument, path);
            }
        }
        Err(QueryFailure::Gone) => return Examined::Exited,
        Err(failure) => {
            fail(&mut reason, failure);
        }
    }
    let record: Option<ProcessUses> = (!uses.is_empty()).then(|| ProcessUses {
        pid,
        name: name.clone(),
        uses,
    });
    match reason {
        None => Examined::Known(record),
        Some(reason) => Examined::Unknown {
            name,
            reason,
            uses: record,
            executable,
            only_refused: only_refused && !bounded,
        },
    }
}
