//! The process evidence of `project.dependency-directory`: the build and
//! package-manager processes of the user, with their working directory
//! and their executable.
//!
//! A process blocks a unit when its working directory is in the project
//! directory or its executable is in the project directory (for example
//! `.venv/bin/python`). A name never makes a directory a unit or a
//! process a target.

use std::path::{Path, PathBuf};

use svalnir_core::process::{Pid, Uid};
use svalnir_core::time::MonotonicNanos;

use crate::platform::process::{DarwinProcessSource, ProcessSource, QueryFailure};

/// The executable names of the build and package-manager processes of the
/// layouts: the JavaScript runtimes and package managers, Python and its
/// installers, `CocoaPods` and Ruby, and the build tools of Xcode. A name
/// that starts with `python3.` or `pip3.` is also one.
pub const BUILD_PROCESS_NAMES: [&str; 25] = [
    "node",
    "npm",
    "npx",
    "pnpm",
    "yarn",
    "bun",
    "deno",
    "corepack",
    "python",
    "python3",
    "Python",
    "pip",
    "pip3",
    "uv",
    "uvx",
    "poetry",
    "pdm",
    "pipenv",
    "hatch",
    "pod",
    "ruby",
    "xcodebuild",
    "XCBBuildService",
    "SWBBuildService",
    "make",
];

/// Whether `name` is the executable name of a build or package-manager
/// process.
#[must_use]
pub fn is_build_process(name: &str) -> bool {
    BUILD_PROCESS_NAMES.contains(&name) || name.starts_with("python3.") || name.starts_with("pip3.")
}

/// One process of the user that can use a generated directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectProcess {
    /// The executable path.
    pub executable: PathBuf,
    /// The working directory, when the process is a build process. `None`
    /// for another process, whose working directory is not read.
    pub working_directory: Option<PathBuf>,
}

/// The processes of the user at one time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildProcesses {
    /// Each process of the user that the inventory read.
    pub processes: Vec<ProjectProcess>,
    /// Why the inventory is not complete: the process list cannot be read,
    /// the clock gave no time, or a query of a process of the user failed.
    /// `None` for a complete inventory. A process of the list blocks a
    /// unit also when the inventory is not complete, but only a complete
    /// inventory shows that no process blocks it.
    pub incomplete: Option<&'static str>,
    /// The monotonic time before the first query.
    pub observed_at: Option<MonotonicNanos>,
}

/// A path in its form below `/System/Volumes/Data` and in its form below
/// `/`: the kernel can give either one for an object of the data volume.
fn forms(path: &Path) -> [PathBuf; 2] {
    const DATA: &str = "/System/Volumes/Data";
    match path.strip_prefix(DATA) {
        Ok(rest) => [path.to_path_buf(), Path::new("/").join(rest)],
        Err(_) => [
            path.to_path_buf(),
            Path::new(DATA).join(path.strip_prefix("/").unwrap_or(path)),
        ],
    }
}

/// Whether `path` is `directory` or is below it, in each form.
fn is_in(path: &Path, directory: &Path) -> bool {
    forms(path)
        .iter()
        .any(|form| forms(directory).iter().any(|base| form.starts_with(base)))
}

impl BuildProcesses {
    /// The executable of the first process that blocks the units of the
    /// project at `project`, when one does.
    #[must_use]
    pub fn blocking(&self, project: &Path) -> Option<&Path> {
        self.processes
            .iter()
            .find(|process| {
                is_in(&process.executable, project)
                    || process
                        .working_directory
                        .as_deref()
                        .is_some_and(|directory| is_in(directory, project))
            })
            .map(|process| process.executable.as_path())
    }
}

/// What the inspection needs to read the process evidence.
pub trait ProcessEvidence {
    /// The build processes of `principal`, read now.
    fn build_processes(&self, principal: Uid) -> BuildProcesses;

    /// The monotonic time now, on the timeline of
    /// [`BuildProcesses::observed_at`].
    fn monotonic_now(&self) -> Option<MonotonicNanos>;
}

/// The inventory of the processes of `principal` from `source`, with the
/// working directory of each build process from `working_directory`.
///
/// A process that exited during the reading is not in the inventory, and a
/// denied identity query is a process of a different user, as in the
/// evidence of `xcode.inactive-derived-data`. A failed query of the
/// executable of a process of the user, or of the working directory of a
/// build process of the user, makes the inventory not complete.
pub(super) fn inventory<S: ProcessSource>(
    source: &S,
    principal: Uid,
    working_directory: impl Fn(Pid) -> Result<PathBuf, QueryFailure>,
) -> BuildProcesses {
    let mut result: BuildProcesses = BuildProcesses {
        processes: Vec::new(),
        incomplete: None,
        observed_at: source.monotonic_now().ok(),
    };
    if result.observed_at.is_none() {
        result.incomplete = Some("clock_unavailable");
    }
    let Ok(pids) = source.list_pids() else {
        result.incomplete = Some("process_list_unavailable");
        return result;
    };
    for pid in pids {
        let info = match source.process_info(pid) {
            Ok(info) => info,
            Err(QueryFailure::Gone | QueryFailure::PermissionDenied) => continue,
            Err(_) => {
                result.incomplete = Some("process_query_failed");
                continue;
            }
        };
        if info.zombie || (info.effective_uid != principal && info.real_uid != principal) {
            continue;
        }
        let executable: PathBuf = match source.executable_path(pid) {
            Ok(path) => path.to_path_buf(),
            Err(QueryFailure::Gone) => continue,
            Err(_) => {
                result.incomplete = Some("executable_query_failed");
                continue;
            }
        };
        let name: String = executable
            .file_name()
            .map_or_else(String::new, |name| name.to_string_lossy().into_owned());
        let working_directory: Option<PathBuf> = if is_build_process(&name) {
            match working_directory(pid) {
                Ok(directory) => Some(directory),
                Err(QueryFailure::Gone) => continue,
                Err(_) => {
                    result.incomplete = Some("working_directory_query_failed");
                    None
                }
            }
        } else {
            None
        };
        result.processes.push(ProjectProcess {
            executable,
            working_directory,
        });
    }
    if result.processes.is_empty() && result.incomplete.is_none() {
        // A complete inventory has the process of the caller.
        result.incomplete = Some("process_list_empty");
    }
    result
}

/// The process evidence of the host.
#[derive(Debug, Clone, Copy, Default)]
pub struct NativeProcessEvidence;

impl ProcessEvidence for NativeProcessEvidence {
    fn build_processes(&self, principal: Uid) -> BuildProcesses {
        let source: DarwinProcessSource = DarwinProcessSource::new();
        #[cfg(target_os = "macos")]
        let query = crate::rules::native::working_directory;
        #[cfg(not(target_os = "macos"))]
        let query = |_: Pid| -> Result<PathBuf, QueryFailure> { Err(QueryFailure::Unsupported) };
        inventory(&source, principal, query)
    }

    fn monotonic_now(&self) -> Option<MonotonicNanos> {
        DarwinProcessSource::new().monotonic_now().ok()
    }
}
