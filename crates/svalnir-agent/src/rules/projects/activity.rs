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

use crate::platform::process::{DarwinProcessSource, PathInventory, ProcessSource, QueryFailure};
use crate::rules::in_use::{UnitScope, inventory_of};

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

    /// The executable of the first build process whose working directory
    /// is above the project at `project` and in `top`, when one is.
    ///
    /// Such a process can write the units of the project: `pnpm install
    /// -r` at the root of a monorepo, `make -C app`, or `npm --prefix app
    /// install`. Its working directory does not show which project it
    /// works on, so the activity of the project is not known.
    #[must_use]
    pub fn above(&self, project: &Path, top: &Path) -> Option<&Path> {
        self.processes
            .iter()
            .find(|process| {
                process
                    .working_directory
                    .as_deref()
                    .is_some_and(|directory| {
                        is_in(directory, top)
                            && is_in(project, directory)
                            && !is_in(directory, project)
                    })
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

    /// The path-use inventory of the processes of `principal`, read now,
    /// with the paths in `scopes` only (`docs/CLEANUP_RULES.md` section 6).
    fn path_uses(&self, principal: Uid, scopes: &[UnitScope]) -> PathInventory;
}

/// The inventory of the processes of `principal` from `source`, with the
/// working directory of each build process from `working_directory`.
///
/// A process that exited during the reading is not in the inventory. For
/// a denied identity query, `owner` gives the effective and the real user
/// of the process: a process of a different user is out of the scope, and
/// each other result makes the inventory not complete. A failed query of the
/// executable of a process of the user, or of the working directory of a
/// build process of the user, makes the inventory not complete.
pub(super) fn inventory<S: ProcessSource>(
    source: &S,
    principal: Uid,
    working_directory: impl Fn(Pid) -> Result<PathBuf, QueryFailure>,
    owner: impl Fn(Pid) -> Result<(Uid, Uid), QueryFailure>,
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
            Err(QueryFailure::Gone) => continue,
            // `proc_pidinfo(PROC_PIDTBSDINFO)` gives no owner for a denied
            // query. The short query gives the owner of such a process; a
            // process of a different user is out of the scope, and a
            // process of the user, or one with no owner, makes the
            // inventory not complete.
            Err(QueryFailure::PermissionDenied) => {
                match owner(pid) {
                    Ok((effective, real)) if effective != principal && real != principal => {}
                    Err(QueryFailure::Gone) => {}
                    _ => result.incomplete = Some("process_query_denied"),
                }
                continue;
            }
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
        let (query, owner) = (
            crate::rules::native::working_directory,
            crate::rules::native::process_owner,
        );
        #[cfg(not(target_os = "macos"))]
        let (query, owner) = (
            |_: Pid| -> Result<PathBuf, QueryFailure> { Err(QueryFailure::Unsupported) },
            |_: Pid| -> Result<(Uid, Uid), QueryFailure> { Err(QueryFailure::Unsupported) },
        );
        inventory(&source, principal, query, owner)
    }

    fn monotonic_now(&self) -> Option<MonotonicNanos> {
        DarwinProcessSource::new().monotonic_now().ok()
    }

    fn path_uses(&self, principal: Uid, scopes: &[UnitScope]) -> PathInventory {
        inventory_of(&DarwinProcessSource::new(), principal, scopes)
    }
}

#[cfg(test)]
mod tests {
    //! The inventory with a synthetic process table.

    use std::path::PathBuf;

    use svalnir_core::file::{FileObjectEvidence, LosslessPath};
    use svalnir_core::observation::UnavailableReason;
    use svalnir_core::process::{Pid, ProcessStartTime, Uid};
    use svalnir_core::quantity::Nanoseconds;
    use svalnir_core::time::{MonotonicNanos, WallTime};

    use super::inventory;
    use crate::platform::process::{
        ProcessSource, QueryFailure, RawProcessInfo, RawUsage, RunningApplication, Timebase,
    };

    const USER: Uid = Uid::new(501);

    /// The process 10 of the user and the process 20, whose identity
    /// query is denied.
    struct Table;

    impl ProcessSource for Table {
        fn effective_uid(&self) -> Uid {
            USER
        }

        fn list_pids(&self) -> Result<Vec<Pid>, QueryFailure> {
            Ok(vec![Pid::new(10).unwrap(), Pid::new(20).unwrap()])
        }

        fn process_info(&self, pid: Pid) -> Result<RawProcessInfo, QueryFailure> {
            if pid.get() == 20 {
                return Err(QueryFailure::PermissionDenied);
            }
            Ok(RawProcessInfo {
                pid,
                parent_pid: None,
                effective_uid: USER,
                real_uid: USER,
                start_time: ProcessStartTime::from_timeval(1_000, 0).unwrap(),
                zombie: false,
            })
        }

        fn executable_path(&self, _pid: Pid) -> Result<LosslessPath, QueryFailure> {
            Ok(LosslessPath::from_bytes("/usr/bin/login").unwrap())
        }

        fn file_evidence(&self, _path: &LosslessPath) -> Result<FileObjectEvidence, QueryFailure> {
            Err(QueryFailure::Unsupported)
        }

        fn usage(&self, _pid: Pid) -> Result<RawUsage, QueryFailure> {
            Err(QueryFailure::Unsupported)
        }

        fn responsible_pid(&self, _pid: Pid) -> Result<Pid, QueryFailure> {
            Err(QueryFailure::Unsupported)
        }

        fn application_list_current(&self) -> bool {
            false
        }

        fn running_applications(&self) -> Result<Vec<RunningApplication>, QueryFailure> {
            Err(QueryFailure::Unsupported)
        }

        fn timebase(&self) -> Result<Timebase, QueryFailure> {
            Err(QueryFailure::Unsupported)
        }

        fn monotonic_now(&self) -> Result<MonotonicNanos, QueryFailure> {
            Ok(MonotonicNanos::new(7_000))
        }

        fn sleep_time(&self) -> Result<Nanoseconds, UnavailableReason> {
            Err(UnavailableReason::Unsupported)
        }

        fn wall_now(&self) -> Result<WallTime, QueryFailure> {
            Err(QueryFailure::Unsupported)
        }
    }

    fn no_directory(_: Pid) -> Result<PathBuf, QueryFailure> {
        Err(QueryFailure::Unsupported)
    }

    #[test]
    fn a_denied_query_keeps_the_inventory_complete_only_for_another_user() {
        let other = |_: Pid| Ok((Uid::new(0), Uid::new(0)));
        let complete = inventory(&Table, USER, no_directory, other);
        assert_eq!(complete.incomplete, None);
        assert_eq!(complete.processes.len(), 1);
        // A denied process of the user, or one with no owner, is not
        // evidence of inactivity.
        for owner in [
            |_: Pid| Ok((USER, USER)),
            |_: Pid| Ok((Uid::new(0), USER)),
            |_: Pid| Err(QueryFailure::PermissionDenied),
        ] {
            let found = inventory(&Table, USER, no_directory, owner);
            assert_eq!(found.incomplete, Some("process_query_denied"));
        }
        // A process that exited between the two queries is not in the
        // inventory.
        let gone = inventory(&Table, USER, no_directory, |_: Pid| Err(QueryFailure::Gone));
        assert_eq!(gone.incomplete, None);
    }
}
