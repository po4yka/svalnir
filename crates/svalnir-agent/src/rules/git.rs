//! The read-only Git queries of the rules (`docs/CLEANUP_RULES.md`
//! sections 9 and 12).
//!
//! A rule asks Git whether it ignores a path, which paths its index
//! tracks, and, for a worktree, which work exists nowhere else. Git owns
//! these semantics (the ignore files at each level, the sparse and split
//! index, the object database), so the rules run `git` instead of a second
//! implementation of them. Each query is a fixed argument list of one
//! built-in command that reads the repository and writes nothing.
//!
//! # The executable
//!
//! [`GitTool::locate`] accepts only an executable of a fixed list of
//! paths ([`GIT_CANDIDATES`]), never one from `PATH`. The resolved file
//! must be a regular file of the superuser that only the superuser can
//! change, and so must each directory above it. The shim `/usr/bin/git` is
//! not on the list: without the developer tools it asks the user to
//! install them. A Git of a directory that the user or the `admin` group
//! can change, for example of Homebrew, is refused, so a process of the
//! user cannot replace the program that the rule runs.
//!
//! # The environment and the configuration
//!
//! The command starts with an empty environment and the fixed variables
//! of [`FIXED_ENVIRONMENT`]: no system or global configuration file, no
//! terminal prompt, no optional lock, no lazy fetch of a partial clone, and
//! no replacement object. The command line sets the keys of the
//! configuration of the repository that can run a program for these
//! commands, and the command-line value has precedence over the file:
//! `core.fsmonitor` is off, `core.hooksPath` is `/dev/null`, and
//! `protocol.allow=never`. A `protocol.NAME.allow` key of the repository
//! has precedence over `protocol.allow`, so the environment variable
//! `GIT_ALLOW_PROTOCOL` with a list that names no protocol is the control
//! that permits no transport: Git then ignores each `protocol.*` key. `--no-optional-locks`
//! keeps Git from a write of the index. A caller gives a pathspec with the
//! `:(literal)` prefix, so a path is not a pattern. The Git directory and the
//! work tree are explicit arguments, so Git does not search for a
//! repository above them.
//!
//! No query of this module compares the content of a work tree with the
//! index (`git status`, `git diff-files`): such a comparison can run a
//! clean filter that the configuration of the repository names.
//!
//! # Bounds
//!
//! Each query has a deadline and a bound of its output. A query that
//! passes its deadline is stopped and gives [`GitFailure::Timeout`]; a
//! stopped query has made no change, because each command of this module
//! only reads.

use std::ffi::OsStr;
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde::Serialize;

/// The paths of the executables that [`GitTool::locate`] examines, in
/// sequence: the command-line developer tools, then Xcode.
pub const GIT_CANDIDATES: [&str; 2] = [
    "/Library/Developer/CommandLineTools/usr/bin/git",
    "/Applications/Xcode.app/Contents/Developer/usr/bin/git",
];

/// The only environment variables of a query.
pub const FIXED_ENVIRONMENT: [(&str, &str); 11] = [
    // A list of permitted protocols that names no protocol. With this
    // variable, Git ignores each `protocol.*` key of the configuration, so
    // a lazy fetch of a partial clone cannot run a transport.
    ("GIT_ALLOW_PROTOCOL", "none"),
    ("PATH", "/usr/bin:/bin"),
    ("LC_ALL", "C"),
    ("GIT_CONFIG_NOSYSTEM", "1"),
    ("GIT_CONFIG_GLOBAL", "/dev/null"),
    ("GIT_ATTR_NOSYSTEM", "1"),
    ("GIT_TERMINAL_PROMPT", "0"),
    ("GIT_OPTIONAL_LOCKS", "0"),
    ("GIT_NO_LAZY_FETCH", "1"),
    ("GIT_NO_REPLACE_OBJECTS", "1"),
    ("GIT_PAGER", "cat"),
];

/// The arguments before the command of each query.
const FIXED_ARGUMENTS: [&str; 8] = [
    "--no-optional-locks",
    "--no-pager",
    "-c",
    "core.fsmonitor=false",
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "protocol.allow=never",
];

/// The deadline of one query.
pub const QUERY_DEADLINE: Duration = Duration::from_secs(10);

/// The interval at which a query is examined for its exit.
const POLL_INTERVAL: Duration = Duration::from_millis(2);

/// The mode bits that permit a write by the group or by others.
const GROUP_OR_OTHER_WRITE: u32 = 0o022;

/// Why no executable is accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GitToolProblem {
    /// No path of the list has an executable.
    NotInstalled,
    /// An executable exists, and it or a directory above it does not pass
    /// the ownership and permission checks.
    NotTrusted,
}

/// A Git executable that passed the checks of this module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitTool {
    executable: PathBuf,
}

/// The result of one query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitOutput {
    /// The exit code.
    pub code: i32,
    /// The standard output, at most the bound of the query.
    pub stdout: Vec<u8>,
    /// Whether the output was longer than the bound. The rest was read and
    /// discarded.
    pub truncated: bool,
}

/// Why a query gave no result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GitFailure {
    /// The process did not start.
    NotStarted,
    /// The query passed its deadline and was stopped.
    Timeout,
    /// The process ended with a signal.
    Signaled,
}

impl GitFailure {
    /// The stable name of the failure.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotStarted => "git_not_started",
            Self::Timeout => "git_timeout",
            Self::Signaled => "git_signaled",
        }
    }
}

/// Whether the object of `metadata` belongs to the superuser and only the
/// superuser can change it.
fn is_protected(metadata: &fs::Metadata) -> bool {
    metadata.uid() == 0 && metadata.permissions().mode() & GROUP_OR_OTHER_WRITE == 0
}

/// The resolved path of `path` when it is an executable regular file that
/// passes the checks of [`GitTool::locate`].
fn verified(path: &Path) -> Result<PathBuf, GitToolProblem> {
    let resolved: PathBuf = match fs::canonicalize(path) {
        Ok(resolved) => resolved,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(GitToolProblem::NotInstalled);
        }
        Err(_) => return Err(GitToolProblem::NotTrusted),
    };
    let metadata: fs::Metadata =
        fs::symlink_metadata(&resolved).map_err(|_| GitToolProblem::NotTrusted)?;
    let executable: bool = metadata.permissions().mode() & 0o111 != 0;
    if !metadata.file_type().is_file() || !executable || !is_protected(&metadata) {
        return Err(GitToolProblem::NotTrusted);
    }
    for ancestor in resolved.ancestors().skip(1) {
        let directory: fs::Metadata =
            fs::symlink_metadata(ancestor).map_err(|_| GitToolProblem::NotTrusted)?;
        if !directory.file_type().is_dir() || !is_protected(&directory) {
            return Err(GitToolProblem::NotTrusted);
        }
    }
    Ok(resolved)
}

/// Reads the output of a query to `limit` bytes and discards the rest, so
/// that the process does not wait on a full pipe.
fn read_bounded(mut reader: impl Read, limit: usize) -> (Vec<u8>, bool) {
    let mut kept: Vec<u8> = Vec::new();
    let mut buffer: [u8; 8192] = [0; 8192];
    let mut overflow: bool = false;
    loop {
        match reader.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(count) => {
                let room: usize = limit.saturating_sub(kept.len());
                if count > room {
                    overflow = true;
                }
                kept.extend_from_slice(&buffer[..count.min(room)]);
            }
        }
    }
    (kept, overflow)
}

/// Waits for `child` until `deadline`, and stops it after that time.
fn wait_until(child: &mut Child, deadline: Instant) -> Result<ExitStatus, GitFailure> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(POLL_INTERVAL),
            Ok(None) | Err(_) => {
                // The process only reads, so a stop leaves no partial
                // change. The wait collects the stopped process.
                drop(child.kill());
                drop(child.wait());
                return Err(GitFailure::Timeout);
            }
        }
    }
}

impl GitTool {
    /// The first executable of [`GIT_CANDIDATES`] that passes the checks.
    ///
    /// # Errors
    ///
    /// Returns [`GitToolProblem::NotInstalled`] when no path of the list
    /// has an executable, and [`GitToolProblem::NotTrusted`] when each one
    /// that exists fails a check.
    pub fn locate() -> Result<Self, GitToolProblem> {
        Self::locate_in(&GIT_CANDIDATES)
    }

    /// [`GitTool::locate`] with another list of paths.
    pub(crate) fn locate_in(candidates: &[&str]) -> Result<Self, GitToolProblem> {
        let mut problem: GitToolProblem = GitToolProblem::NotInstalled;
        for candidate in candidates {
            match verified(Path::new(candidate)) {
                Ok(executable) => return Ok(Self { executable }),
                Err(GitToolProblem::NotTrusted) => problem = GitToolProblem::NotTrusted,
                Err(GitToolProblem::NotInstalled) => {}
            }
        }
        Err(problem)
    }

    /// The resolved path of the executable.
    #[must_use]
    pub fn executable(&self) -> &Path {
        &self.executable
    }

    /// Runs one read-only command of Git for the Git directory `git_dir`
    /// and the work tree `work_tree`.
    ///
    /// `arguments` starts with the name of a built-in command. The caller
    /// gives a fixed list. A path argument is relative to the work tree,
    /// which is the working directory of the process; a pathspec has the
    /// prefix `:(literal)`. The standard
    /// input is empty, and the standard error is discarded.
    ///
    /// # Errors
    ///
    /// Returns a [`GitFailure`] when the process does not start, passes
    /// the deadline, or ends with a signal. An output of more than
    /// `max_output` bytes is cut, and [`GitOutput::truncated`] says so.
    pub fn run(
        &self,
        git_dir: &Path,
        work_tree: Option<&Path>,
        arguments: &[&OsStr],
        max_output: usize,
    ) -> Result<GitOutput, GitFailure> {
        let mut command: Command = Command::new(&self.executable);
        command
            .env_clear()
            .envs(FIXED_ENVIRONMENT)
            .current_dir(work_tree.unwrap_or_else(|| Path::new("/")))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .args(FIXED_ARGUMENTS)
            .arg(prefixed("--git-dir=", git_dir));
        if let Some(work_tree) = work_tree {
            command.arg(prefixed("--work-tree=", work_tree));
        }
        command.args(arguments);
        let deadline: Instant = Instant::now() + QUERY_DEADLINE;
        let mut child: Child = command.spawn().map_err(|_| GitFailure::NotStarted)?;
        let Some(stdout) = child.stdout.take() else {
            drop(child.kill());
            drop(child.wait());
            return Err(GitFailure::NotStarted);
        };
        let reader = thread::spawn(move || read_bounded(stdout, max_output));
        let status: Result<ExitStatus, GitFailure> = wait_until(&mut child, deadline);
        // The pipe closes when the process ends, so the thread ends.
        let (stdout, overflow) = reader.join().unwrap_or_default();
        let status: ExitStatus = status?;
        let Some(code) = status.code() else {
            return Err(GitFailure::Signaled);
        };
        Ok(GitOutput {
            code,
            stdout,
            truncated: overflow,
        })
    }
}

/// `prefix` followed by `path`, as one argument.
fn prefixed(prefix: &str, path: &Path) -> std::ffi::OsString {
    let mut argument: std::ffi::OsString = std::ffi::OsString::from(prefix);
    argument.push(path.as_os_str());
    argument
}

/// The Git directory and the work tree of one repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Repository {
    /// The top directory of the work tree.
    pub work_tree: PathBuf,
    /// The Git directory: `.git` of the work tree, or the directory that a
    /// `.git` file names for a linked worktree.
    pub git_dir: PathBuf,
}

/// The largest `.git` file that names a Git directory, in bytes.
const MAX_GIT_FILE_BYTES: u64 = 4 * 1024;

/// The result of the search for the repository of a directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "reason", rename_all = "snake_case")]
pub enum RepositoryLookup {
    /// The directory is in the work tree of this repository.
    Found(Repository),
    /// No directory from the start to the top has `.git`.
    NotFound,
    /// A `.git` object cannot be used. The reason is a stable name.
    Unknown(&'static str),
}

/// The Git directory that the content of a `.git` file names, relative to
/// `directory` when the value is relative. A `..` component removes the
/// component before it, as Git does.
pub(super) fn git_file_target(content: &[u8], directory: &Path) -> Option<PathBuf> {
    let text: &str = std::str::from_utf8(content).ok()?;
    let value: &str = text
        .strip_prefix("gitdir: ")?
        .trim_end_matches(['\n', '\r']);
    if value.is_empty() || value.contains(['\n', '\r', '\0']) {
        return None;
    }
    let joined: PathBuf = directory.join(value);
    let mut normal: PathBuf = PathBuf::new();
    for component in joined.components() {
        match component {
            std::path::Component::ParentDir => {
                if !normal.pop() {
                    return None;
                }
            }
            std::path::Component::CurDir => {}
            other => normal.push(other),
        }
    }
    super::unit::is_plain_absolute(&normal).then_some(normal)
}

/// The repository whose work tree has `start`: the nearest directory from
/// `start` up to `top`, both included, that has `.git`.
///
/// A `.git` directory must have the owner `principal`. A `.git` file is a
/// plain file of no more than 4 KiB with the owner `principal`, and the
/// directory that it names must be on a local filesystem (the walk of
/// `docs/CLEANUP_RULES.md` section 4), have the owner `principal`, and
/// have no symbolic link on its path. A `.git` that is a symbolic link or
/// another object is not followed.
pub(super) fn find_repository(
    start: &Path,
    top: &Path,
    principal: svalnir_core::process::Uid,
    mounts: &crate::platform::volume::MountTable,
) -> RepositoryLookup {
    use super::unit::{ObjectKind, RecordRead, lstat, read_record, walk_local};

    for directory in start.ancestors() {
        if !directory.starts_with(top) {
            break;
        }
        let marker: PathBuf = directory.join(".git");
        match lstat(&marker) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return RepositoryLookup::Unknown("git_marker_not_readable"),
            Ok(snapshot) => {
                return match snapshot.kind {
                    ObjectKind::Directory if snapshot.owner == principal => {
                        RepositoryLookup::Found(Repository {
                            work_tree: directory.to_path_buf(),
                            git_dir: marker,
                        })
                    }
                    ObjectKind::Directory => RepositoryLookup::Unknown("git_dir_owner"),
                    ObjectKind::RegularFile => {
                        let RecordRead::Read { bytes, .. } =
                            read_record(&marker, MAX_GIT_FILE_BYTES, principal)
                        else {
                            return RepositoryLookup::Unknown("git_file_not_readable");
                        };
                        let Some(target) = git_file_target(&bytes, directory) else {
                            return RepositoryLookup::Unknown("git_file_not_supported");
                        };
                        match walk_local(&target, mounts) {
                            Ok(found)
                                if found.kind == ObjectKind::Directory
                                    && found.owner == principal =>
                            {
                                RepositoryLookup::Found(Repository {
                                    work_tree: directory.to_path_buf(),
                                    git_dir: target,
                                })
                            }
                            Ok(_) => RepositoryLookup::Unknown("git_dir_not_usable"),
                            Err(_) => RepositoryLookup::Unknown("git_dir_not_local"),
                        }
                    }
                    _ => RepositoryLookup::Unknown("git_marker_not_supported"),
                };
            }
        }
        if directory == top {
            break;
        }
    }
    RepositoryLookup::NotFound
}
