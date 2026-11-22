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

use std::collections::HashMap;

use svalnir_core::file::{FileObjectEvidence, LosslessPath};

use super::source::{
    ProcessSource, QueryFailure, RawArguments, RawPaths, RawProcessInfo, RawVnode,
};

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
    /// A path from the kernel is not in a scope, and the file at the path
    /// does not have the device and the inode of the vnode, or the kernel
    /// gave no path for a vnode with links.
    PathNotVerified,
    /// The PID named a different process after the queries, two times.
    ProcessReplaced,
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
            Self::PathNotVerified => "path_not_verified",
            Self::ProcessReplaced => "process_replaced",
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

/// The forms of a path for the comparison: with no `..`, the path with `.`
/// removed; with `..`, the part before the first `..` and the lexical form.
/// The directory before a `..` can be a symbolic link, so the lexical form
/// alone can miss a use; the part before `..` is a use of each unit that
/// contains it.
fn path_forms(path: &Path) -> Vec<PathBuf> {
    if !path
        .components()
        .any(|component| component == Component::ParentDir)
    {
        return vec![lexical(path)];
    }
    let prefix: PathBuf = path
        .components()
        .take_while(|component| *component != Component::ParentDir)
        .filter(|component| *component != Component::CurDir)
        .collect();
    vec![prefix, lexical(path)]
}

/// `text` with each `%XX` decoded. A `%` with no two hexadecimal digits
/// stays as it is.
fn percent_decoded(text: &[u8]) -> Vec<u8> {
    let mut result: Vec<u8> = Vec::with_capacity(text.len());
    let mut index: usize = 0;
    while let Some(&byte) = text.get(index) {
        let digits: Option<u8> = (byte == b'%')
            .then(|| text.get(index + 1..index + 3))
            .flatten()
            .and_then(|digits| std::str::from_utf8(digits).ok())
            .and_then(|digits| u8::from_str_radix(digits, 16).ok());
        if let Some(decoded) = digits {
            result.push(decoded);
            index += 3;
        } else {
            result.push(byte);
            index += 1;
        }
    }
    result
}

/// The texts of one argument that can name a path: the argument, the part
/// after its first `=`, the part after an option prefix of one or two
/// characters, the path of a `file://` URL, and each part of a list that
/// `:` separates. The second value is true for a text that can be relative.
fn argument_texts(value: &[u8]) -> Vec<(Vec<u8>, bool)> {
    let mut texts: Vec<(Vec<u8>, bool)> = vec![(value.to_vec(), value.first() != Some(&b'-'))];
    if let Some(after) = value
        .iter()
        .position(|byte| *byte == b'=')
        .and_then(|index| value.get(index + 1..))
    {
        texts.push((after.to_vec(), false));
    }
    if value.first() == Some(&b'-')
        && let Some(slash) = value.iter().position(|byte| *byte == b'/')
        && (2..=3).contains(&slash)
        && let Some(after) = value.get(slash..)
    {
        texts.push((after.to_vec(), false));
    }
    let mut expanded: Vec<(Vec<u8>, bool)> = Vec::new();
    for (text, relative) in texts {
        let text: Vec<u8> = match text.strip_prefix(b"file://".as_slice()) {
            Some(rest) => {
                percent_decoded(rest.strip_prefix(b"localhost".as_slice()).unwrap_or(rest))
            }
            None => text,
        };
        for part in text.split(|byte| *byte == b':') {
            if part.len() != text.len() && !part.is_empty() {
                expanded.push((part.to_vec(), relative));
            }
        }
        expanded.push((text, relative));
    }
    expanded
}

/// The paths that the arguments name, in the forms of
/// `docs/CLEANUP_RULES.md` section 6. A relative text is joined to the
/// working directory when it is known. No symbolic link is followed.
pub(super) fn argument_paths(
    arguments: &RawArguments,
    working_directory: Option<&Path>,
) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = Vec::new();
    for value in &arguments.values {
        for (text, relative) in argument_texts(value) {
            let candidate: Option<PathBuf> = if text.first() == Some(&b'/') {
                Some(PathBuf::from(OsStr::from_bytes(&text)))
            } else if relative && !text.is_empty() && text.first() != Some(&b'-') {
                working_directory.map(|directory| directory.join(OsStr::from_bytes(&text)))
            } else {
                None
            };
            for path in candidate.iter().flat_map(|path| path_forms(path)) {
                if !paths.contains(&path) {
                    paths.push(path);
                }
            }
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

/// The largest number of paths whose file identity one inventory keeps.
const MAX_VERIFIED_PATHS: usize = 65_536;

/// The file identity of each path that an inventory verified.
struct Verifier<'a, S: ProcessSource + ?Sized> {
    source: &'a S,
    known: HashMap<LosslessPath, Vec<FileObjectEvidence>>,
}

/// The shortest path from the kernel that is verified. A cut path fills
/// the buffer of `MAXPATHLEN` (1024) bytes, so a shorter path than half of
/// it is complete (`docs/CLEANUP_RULES.md` section 6).
pub(super) const MIN_VERIFIED_PATH_BYTES: usize = 512;

impl<S: ProcessSource + ?Sized> Verifier<'_, S> {
    /// Whether the path from the kernel is evidence for the vnode
    /// `object`: a complete path, or a longer path at which the file now
    /// has that identity, with or without the resolution of a symbolic link
    /// at its end.
    fn matches(&mut self, path: &LosslessPath, object: FileObjectEvidence) -> bool {
        if path.as_bytes().len() < MIN_VERIFIED_PATH_BYTES {
            return true;
        }
        if let Some(found) = self.known.get(path) {
            return found.contains(&object);
        }
        let found: Vec<FileObjectEvidence> = [
            self.source.file_evidence(path).ok(),
            self.source.link_evidence(path).ok(),
        ]
        .into_iter()
        .flatten()
        .collect();
        let result: bool = found.contains(&object);
        if self.known.len() < MAX_VERIFIED_PATHS {
            self.known.insert(path.clone(), found);
        }
        result
    }
}

/// The path uses of the processes of `principal` from `source`, with only
/// the paths that `keep` accepts.
///
/// A process of the user is a process whose effective or real user is
/// `principal`. The owner query comes first, so no use query is made of a
/// process of a different user. The calling process is not examined. A
/// process that exited during the reading is not in the inventory. A
/// process of the user that fails a query, that passes a bound of one
/// process, or whose path from the kernel cannot be verified is an
/// [`UnknownProcess`], unless it passes the platform gate of
/// `docs/CLEANUP_RULES.md` section 6.
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
    let mut verifier: Verifier<'_, S> = Verifier {
        source,
        known: HashMap::new(),
    };
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
        match source.process_owner(pid) {
            Ok(owner) if !is_user(owner, principal) => continue,
            Err(QueryFailure::Gone) => continue,
            // An owner of the user, or no owner: the identity query decides.
            _ => {}
        }
        if examine_process(
            source,
            pid,
            principal,
            keep,
            limits,
            &mut verifier,
            &mut inventory,
        ) {
            seen += 1;
        }
    }
    if seen == 0 && inventory.unknown.is_empty() {
        // A complete inventory has at least the calling process.
        inventory.note(InventoryGap::ProcessListEmpty);
    }
    inventory
}

/// Whether the owner `(effective, real)` is the user.
fn is_user((effective, real): (Uid, Uid), principal: Uid) -> bool {
    effective == principal || real == principal
}

/// Whether the process passes the platform gate: its executable is on the
/// sealed system volume, and its running code is an Apple platform binary.
fn passes_platform_gate<S: ProcessSource + ?Sized>(
    source: &S,
    pid: Pid,
    executable: Option<&Path>,
) -> bool {
    executable.is_some_and(is_on_sealed_system_volume)
        && source.apple_platform_code(pid) == Ok(true)
}

/// Examines one process whose owner is the user or is not known, and adds
/// the result to `inventory`. Returns whether it is a process of the user
/// that the inventory saw.
fn examine_process<S: ProcessSource + ?Sized>(
    source: &S,
    pid: Pid,
    principal: Uid,
    keep: &dyn Fn(&Path) -> bool,
    limits: UseLimits,
    verifier: &mut Verifier<'_, S>,
    inventory: &mut PathInventory,
) -> bool {
    let mut info: RawProcessInfo = match source.process_info(pid) {
        Ok(info) => info,
        Err(QueryFailure::Gone) => return false,
        Err(failure) => {
            let executable: Result<LosslessPath, QueryFailure> = source.executable_path(pid);
            if executable == Err(QueryFailure::Gone) {
                return false;
            }
            let path: Option<PathBuf> = executable.ok().map(|path| path.to_path_buf());
            if failure == QueryFailure::PermissionDenied
                && passes_platform_gate(source, pid, path.as_deref())
            {
                inventory.not_visible = inventory.not_visible.saturating_add(1);
            } else {
                let name: String = path.as_deref().map_or_else(String::new, short_name);
                inventory.unknown_process(pid, name, gap_of(failure));
            }
            return true;
        }
    };
    for attempt in 0..2 {
        if info.zombie || !is_user((info.effective_uid, info.real_uid), principal) {
            return false;
        }
        let examined: Examined = examine(source, pid, keep, limits, verifier);
        // The PID must name the same process after the queries.
        let after: RawProcessInfo = match source.process_info(pid) {
            Ok(after) => after,
            Err(QueryFailure::Gone) => return false,
            Err(failure) => {
                inventory.unknown_process(pid, String::new(), gap_of(failure));
                return true;
            }
        };
        if after.start_time != info.start_time
            || after.effective_uid != info.effective_uid
            || after.real_uid != info.real_uid
        {
            if attempt == 0 {
                info = after;
                continue;
            }
            inventory.unknown_process(pid, String::new(), InventoryGap::ProcessReplaced);
            return true;
        }
        match examined {
            Examined::Exited => return false,
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
                if only_refused && passes_platform_gate(source, pid, executable.as_deref()) {
                    inventory.platform_refused = inventory.platform_refused.saturating_add(1);
                } else {
                    inventory.unknown_process(pid, name, reason);
                }
            }
        }
        return true;
    }
    true
}

/// The gap of a failed query of a process of the user that did not exit.
const fn gap_of(failure: QueryFailure) -> InventoryGap {
    match failure {
        QueryFailure::PermissionDenied | QueryFailure::AccessDenied => {
            InventoryGap::ProcessQueryDenied
        }
        _ => InventoryGap::ProcessQueryFailed,
    }
}

/// The result of the examination of one process of the user.
enum Examined {
    /// The process exited during the examination.
    Exited,
    /// Each query answered and each path was verified; the record when the
    /// process has a use.
    Known(Option<ProcessUses>),
    /// A query failed, a bound was reached, or a path was not verified.
    Unknown {
        name: String,
        reason: InventoryGap,
        uses: Option<ProcessUses>,
        /// The executable, when its query answered.
        executable: Option<PathBuf>,
        /// Each failure was a refusal with `EPERM`, and no bound was
        /// reached and no path failed the verification.
        only_refused: bool,
    },
}

/// The state of one examination.
struct Findings {
    reason: Option<InventoryGap>,
    only_refused: bool,
    uses: Vec<ProcessPathUse>,
}

impl Findings {
    /// Notes a failed query.
    fn fail(&mut self, failure: QueryFailure) {
        if failure != QueryFailure::PermissionDenied {
            self.only_refused = false;
        }
        self.reason.get_or_insert(gap_of(failure));
    }

    /// Notes a gap that is not a refusal: a bound or a path that was not
    /// verified.
    fn gap(&mut self, gap: InventoryGap) {
        self.only_refused = false;
        self.reason.get_or_insert(gap);
    }

    fn add(&mut self, keep: &dyn Fn(&Path) -> bool, kind: PathUseKind, path: PathBuf) {
        if keep(&path) {
            let found: ProcessPathUse = ProcessPathUse { kind, path };
            if !self.uses.contains(&found) {
                self.uses.push(found);
            }
        }
    }

    /// Adds the use of one vnode, or notes that its path cannot be
    /// verified. A path in the scope is a use with no other check.
    fn vnode<S: ProcessSource + ?Sized>(
        &mut self,
        keep: &dyn Fn(&Path) -> bool,
        verifier: &mut Verifier<'_, S>,
        kind: PathUseKind,
        vnode: &RawVnode,
    ) {
        match &vnode.path {
            Some(path) if keep(&path.to_path_buf()) => self.add(keep, kind, path.to_path_buf()),
            // A vnode with no link has no name, so it is in no unit.
            _ if vnode.vnode.links == 0 => {}
            Some(path) if verifier.matches(path, vnode.vnode.object) => {}
            _ => self.gap(InventoryGap::PathNotVerified),
        }
    }
}

/// `ENOENT`: `proc_pidpath` gives it for an executable with no current
/// name.
const NO_CURRENT_NAME: QueryFailure = QueryFailure::Failed(libc::ENOENT);

/// The uses of one process of the user.
fn examine<S: ProcessSource + ?Sized>(
    source: &S,
    pid: Pid,
    keep: &dyn Fn(&Path) -> bool,
    limits: UseLimits,
    verifier: &mut Verifier<'_, S>,
) -> Examined {
    let mut found: Findings = Findings {
        reason: None,
        only_refused: true,
        uses: Vec::new(),
    };
    let executable: Option<PathBuf> = match source.executable_path(pid) {
        Ok(path) => Some(path.to_path_buf()),
        Err(QueryFailure::Gone) => return Examined::Exited,
        // The file was removed or replaced after the process started. The
        // process is known when each other query answers and each path is
        // verified (`docs/CLEANUP_RULES.md` section 6).
        Err(NO_CURRENT_NAME) => {
            found.only_refused = false;
            None
        }
        Err(failure) => {
            found.fail(failure);
            None
        }
    };
    let name: String = executable.as_deref().map_or_else(String::new, short_name);
    if let Some(path) = &executable {
        found.add(keep, PathUseKind::Executable, path.clone());
    }
    let working_directory: Option<PathBuf> = match source.working_directory_vnode(pid) {
        Ok(vnode) => {
            found.vnode(keep, verifier, PathUseKind::WorkingDirectory, &vnode);
            vnode.path.map(|path| path.to_path_buf())
        }
        Err(QueryFailure::Gone) => return Examined::Exited,
        Err(failure) => {
            found.fail(failure);
            None
        }
    };
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
            Ok(vnodes) => {
                if vnodes.truncated {
                    found.gap(bound);
                }
                for vnode in &vnodes.paths {
                    found.vnode(keep, verifier, kind, vnode);
                }
            }
            Err(QueryFailure::Gone) => return Examined::Exited,
            Err(failure) => found.fail(failure),
        }
    }
    match source.arguments(pid, limits.max_argument_bytes) {
        Ok(arguments) => {
            if arguments.truncated {
                found.gap(InventoryGap::ArgumentsTruncated);
            }
            // The arguments are compared here and dropped with `arguments`.
            for path in argument_paths(&arguments, working_directory.as_deref()) {
                found.add(keep, PathUseKind::Argument, path);
            }
        }
        Err(QueryFailure::Gone) => return Examined::Exited,
        Err(failure) => found.fail(failure),
    }
    let record: Option<ProcessUses> = (!found.uses.is_empty()).then(|| ProcessUses {
        pid,
        name: name.clone(),
        uses: found.uses,
    });
    match found.reason {
        None => Examined::Known(record),
        Some(reason) => Examined::Unknown {
            name,
            reason,
            uses: record,
            executable,
            only_refused: found.only_refused,
        },
    }
}
