//! The path-use inventory: a synthetic process table for the bounds and the
//! fail-closed cases, and disposable child processes for the native
//! queries. No test signals or examines for an action a process that it did
//! not start; the native inventory only reads the process table.

use std::cell::Cell;
use std::path::{Path, PathBuf};
use std::time::Duration;

use svalnir_core::file::{FileObjectEvidence, LosslessPath};
use svalnir_core::observation::UnavailableReason;
use svalnir_core::process::{Pid, ProcessStartTime, Uid};
use svalnir_core::quantity::Nanoseconds;
use svalnir_core::time::{MonotonicNanos, WallTime};

use super::source::{
    ProcessSource, QueryFailure, RawArguments, RawPaths, RawProcessInfo, RawUsage,
    RunningApplication, Timebase,
};
use super::uses::{InventoryGap, PathUseKind, UseLimits, argument_paths, collect_path_uses};

const USER: Uid = Uid::new(501);
const OTHER: Uid = Uid::new(502);

fn path(text: &str) -> LosslessPath {
    LosslessPath::from_bytes(text).unwrap()
}

/// One synthetic process.
#[derive(Clone)]
struct Entry {
    pid: i32,
    owner: Uid,
    info: Result<(), QueryFailure>,
    open: Result<RawPaths, QueryFailure>,
    mapped: Result<RawPaths, QueryFailure>,
    arguments: Result<RawArguments, QueryFailure>,
    working_directory: &'static str,
    executable: &'static str,
}

impl Entry {
    fn plain(pid: i32) -> Self {
        Self {
            pid,
            owner: USER,
            info: Ok(()),
            open: Ok(RawPaths::default()),
            mapped: Ok(RawPaths::default()),
            arguments: Ok(RawArguments::default()),
            working_directory: "/Users/u",
            executable: "/usr/bin/true",
        }
    }
}

/// A synthetic process table.
struct Table {
    entries: Vec<Entry>,
    list: Result<(), QueryFailure>,
    clock: bool,
    queries: Cell<usize>,
}

impl Table {
    fn new(entries: Vec<Entry>) -> Self {
        Self {
            entries,
            list: Ok(()),
            clock: true,
            queries: Cell::new(0),
        }
    }

    fn entry(&self, pid: Pid) -> Result<&Entry, QueryFailure> {
        self.queries.set(self.queries.get() + 1);
        self.entries
            .iter()
            .find(|entry| entry.pid == pid.get())
            .ok_or(QueryFailure::Gone)
    }
}

impl ProcessSource for Table {
    fn effective_uid(&self) -> Uid {
        USER
    }

    fn list_pids(&self) -> Result<Vec<Pid>, QueryFailure> {
        self.list?;
        Ok(self
            .entries
            .iter()
            .map(|entry| Pid::new(entry.pid).unwrap())
            .collect())
    }

    fn process_info(&self, pid: Pid) -> Result<RawProcessInfo, QueryFailure> {
        let entry: &Entry = self.entry(pid)?;
        entry.info?;
        Ok(RawProcessInfo {
            pid,
            parent_pid: None,
            effective_uid: entry.owner,
            real_uid: entry.owner,
            start_time: ProcessStartTime::from_timeval(1_000, 0).unwrap(),
            zombie: false,
        })
    }

    fn process_owner(&self, pid: Pid) -> Result<(Uid, Uid), QueryFailure> {
        let entry: &Entry = self.entry(pid)?;
        Ok((entry.owner, entry.owner))
    }

    fn executable_path(&self, pid: Pid) -> Result<LosslessPath, QueryFailure> {
        Ok(path(self.entry(pid)?.executable))
    }

    fn working_directory(&self, pid: Pid) -> Result<LosslessPath, QueryFailure> {
        Ok(path(self.entry(pid)?.working_directory))
    }

    fn open_file_paths(&self, pid: Pid, _max: usize) -> Result<RawPaths, QueryFailure> {
        self.entry(pid)?.open.clone()
    }

    fn mapped_file_paths(&self, pid: Pid, _max: usize) -> Result<RawPaths, QueryFailure> {
        self.entry(pid)?.mapped.clone()
    }

    fn arguments(&self, pid: Pid, _max: usize) -> Result<RawArguments, QueryFailure> {
        self.entry(pid)?.arguments.clone()
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
        if self.clock {
            Ok(MonotonicNanos::new(5_000))
        } else {
            Err(QueryFailure::Unsupported)
        }
    }

    fn sleep_time(&self) -> Result<Nanoseconds, UnavailableReason> {
        Err(UnavailableReason::Unsupported)
    }

    fn wall_now(&self) -> Result<WallTime, QueryFailure> {
        Err(QueryFailure::Unsupported)
    }
}

fn under_unit(candidate: &Path) -> bool {
    candidate.starts_with("/Users/u/app/node_modules")
}

fn collect(table: &Table) -> super::PathInventory {
    collect_path_uses(table, USER, &under_unit, UseLimits::default())
}

#[test]
fn each_kind_of_use_is_found_and_paths_outside_the_scope_are_not_kept() {
    let mut entry: Entry = Entry::plain(10);
    entry.open = Ok(RawPaths {
        paths: vec![path("/Users/u/app/node_modules/a.js"), path("/etc/hosts")],
        truncated: false,
    });
    entry.mapped = Ok(RawPaths {
        paths: vec![path("/Users/u/app/node_modules/x.node")],
        truncated: false,
    });
    entry.arguments = Ok(RawArguments {
        values: vec![
            b"node".to_vec(),
            b"--secret=hunter2".to_vec(),
            b"node_modules/.bin/vite".to_vec(),
            b"--config=/Users/u/app/node_modules/c.js".to_vec(),
        ],
        truncated: false,
    });
    entry.working_directory = "/Users/u/app";
    let mut second: Entry = Entry::plain(11);
    second.working_directory = "/Users/u/app/node_modules/pkg";
    second.executable = "/Users/u/app/node_modules/.bin/esbuild";
    let inventory = collect(&Table::new(vec![entry, second, Entry::plain(12)]));
    assert_eq!(inventory.gap, None);
    assert_eq!(inventory.observed_at, Some(MonotonicNanos::new(5_000)));
    // A process with no use in the scope has no record.
    assert_eq!(inventory.processes.len(), 2);
    let kinds: Vec<(PathUseKind, PathBuf)> = inventory.processes[0]
        .uses
        .iter()
        .map(|found| (found.kind, found.path.clone()))
        .collect();
    assert_eq!(
        kinds,
        vec![
            (
                PathUseKind::OpenFile,
                PathBuf::from("/Users/u/app/node_modules/a.js")
            ),
            (
                PathUseKind::MappedFile,
                PathBuf::from("/Users/u/app/node_modules/x.node")
            ),
            (
                PathUseKind::Argument,
                PathBuf::from("/Users/u/app/node_modules/.bin/vite")
            ),
            (
                PathUseKind::Argument,
                PathBuf::from("/Users/u/app/node_modules/c.js")
            ),
        ]
    );
    assert_eq!(inventory.processes[0].name, "true");
    let second: Vec<PathUseKind> = inventory.processes[1]
        .uses
        .iter()
        .map(|found| found.kind)
        .collect();
    assert_eq!(
        second,
        vec![PathUseKind::Executable, PathUseKind::WorkingDirectory]
    );
    // No argument outside the scope is in the inventory.
    let text: String = format!("{inventory:?}");
    assert!(!text.contains("hunter2"));
}

#[test]
fn the_debug_output_of_arguments_has_no_value() {
    let arguments: RawArguments = RawArguments {
        values: vec![b"--token=abc".to_vec()],
        truncated: false,
    };
    let text: String = format!("{arguments:?}");
    assert!(!text.contains("abc"), "{text}");
    assert!(text.contains("count: 1"), "{text}");
}

#[test]
fn argument_paths_are_absolute_assigned_or_relative_to_the_working_directory() {
    let arguments: RawArguments = RawArguments {
        values: vec![
            b"/a/b/../c".to_vec(),
            b"KEY=/d/e".to_vec(),
            b"-x".to_vec(),
            b"./f/g".to_vec(),
            Vec::new(),
        ],
        truncated: false,
    };
    assert_eq!(
        argument_paths(&arguments, Some(Path::new("/w"))),
        vec![
            PathBuf::from("/a/c"),
            PathBuf::from("/d/e"),
            PathBuf::from("/w/f/g")
        ]
    );
    // With no working directory, a relative argument names no path.
    assert_eq!(
        argument_paths(&arguments, None),
        vec![PathBuf::from("/a/c"), PathBuf::from("/d/e")]
    );
}

#[test]
fn an_inventory_that_cannot_be_read_fails_closed() {
    let mut table: Table = Table::new(vec![Entry::plain(10)]);
    table.list = Err(QueryFailure::Failed(5));
    assert_eq!(
        collect(&table).gap,
        Some(InventoryGap::ProcessListUnavailable)
    );
    let mut table: Table = Table::new(vec![Entry::plain(10)]);
    table.clock = false;
    let inventory = collect(&table);
    assert_eq!(inventory.gap, Some(InventoryGap::ClockUnavailable));
    assert_eq!(inventory.observed_at, None);
    // A list with no process of the user is not complete.
    let mut other: Entry = Entry::plain(10);
    other.owner = OTHER;
    assert_eq!(
        collect(&Table::new(vec![other])).gap,
        Some(InventoryGap::ProcessListEmpty)
    );
}

/// The reason of the one unknown process of `inventory`.
fn unknown_reason(inventory: &super::PathInventory) -> Option<InventoryGap> {
    match inventory.unknown.as_slice() {
        [one] => Some(one.reason),
        _ => None,
    }
}

#[test]
fn a_failed_use_query_makes_the_process_unknown_and_names_it() {
    for (failure, gap) in [
        (
            QueryFailure::PermissionDenied,
            InventoryGap::ProcessQueryDenied,
        ),
        (QueryFailure::Failed(5), InventoryGap::ProcessQueryFailed),
        (QueryFailure::Unsupported, InventoryGap::ProcessQueryFailed),
    ] {
        for field in 0..3 {
            let mut entry: Entry = Entry::plain(10);
            match field {
                0 => entry.open = Err(failure),
                1 => entry.mapped = Err(failure),
                _ => entry.arguments = Err(failure),
            }
            let inventory = collect(&Table::new(vec![entry, Entry::plain(11)]));
            // The inventory as a whole is read; the process is unknown.
            assert_eq!(inventory.gap, None);
            assert_eq!(unknown_reason(&inventory), Some(gap));
            assert_eq!(inventory.unknown[0].pid.get(), 10);
            assert_eq!(inventory.unknown[0].name, "true");
        }
    }
    // A process that exited during the reading is not unknown.
    let mut gone: Entry = Entry::plain(10);
    gone.open = Err(QueryFailure::Gone);
    let inventory = collect(&Table::new(vec![gone, Entry::plain(11)]));
    assert_eq!(inventory.gap, None);
    assert_eq!(inventory.unknown, Vec::new());
}

#[test]
fn a_denied_identity_query_is_not_visible_and_another_user_is_out_of_scope() {
    let mut other: Entry = Entry::plain(20);
    other.info = Err(QueryFailure::PermissionDenied);
    other.owner = OTHER;
    let inventory = collect(&Table::new(vec![Entry::plain(10), other.clone()]));
    assert_eq!((inventory.gap, inventory.not_visible), (None, 0));
    // A process of the user whose identity query is denied, for example a
    // set-user-ID process, is counted as not visible.
    other.owner = USER;
    let inventory = collect(&Table::new(vec![Entry::plain(10), other]));
    assert_eq!((inventory.gap, inventory.not_visible), (None, 1));
    assert_eq!(inventory.unknown, Vec::new());
    // No use query is made of a process of a different user.
    let mut foreign: Entry = Entry::plain(30);
    foreign.owner = OTHER;
    foreign.open = Err(QueryFailure::Failed(5));
    let inventory = collect(&Table::new(vec![Entry::plain(10), foreign]));
    assert_eq!(inventory.unknown, Vec::new());
}

#[test]
fn a_use_of_an_unknown_process_is_kept() {
    let mut used: Entry = Entry::plain(10);
    used.working_directory = "/Users/u/app/node_modules";
    used.mapped = Err(QueryFailure::Failed(5));
    let inventory = collect(&Table::new(vec![used]));
    assert_eq!(
        unknown_reason(&inventory),
        Some(InventoryGap::ProcessQueryFailed)
    );
    assert_eq!(inventory.processes.len(), 1);
}

#[test]
fn each_bound_of_one_process_makes_it_unknown_and_the_global_bounds_make_a_gap() {
    let truncated = RawPaths {
        paths: Vec::new(),
        truncated: true,
    };
    let mut entry: Entry = Entry::plain(10);
    entry.open = Ok(truncated.clone());
    assert_eq!(
        unknown_reason(&collect(&Table::new(vec![entry]))),
        Some(InventoryGap::DescriptorsTruncated)
    );
    let mut entry: Entry = Entry::plain(10);
    entry.mapped = Ok(truncated);
    assert_eq!(
        unknown_reason(&collect(&Table::new(vec![entry]))),
        Some(InventoryGap::RegionsTruncated)
    );
    let mut entry: Entry = Entry::plain(10);
    entry.arguments = Ok(RawArguments {
        values: Vec::new(),
        truncated: true,
    });
    assert_eq!(
        unknown_reason(&collect(&Table::new(vec![entry]))),
        Some(InventoryGap::ArgumentsTruncated)
    );
    // The number of unknown records has a bound.
    let entries: Vec<Entry> = (10..10 + i32::try_from(super::MAX_UNKNOWN_PROCESSES).unwrap() + 5)
        .map(|pid| {
            let mut entry: Entry = Entry::plain(pid);
            entry.open = Err(QueryFailure::Failed(5));
            entry
        })
        .collect();
    let inventory = collect(&Table::new(entries));
    assert_eq!(inventory.unknown.len(), super::MAX_UNKNOWN_PROCESSES);
    assert_eq!(inventory.unknown_omitted, 5);
    // The process bound: only the first processes are examined.
    let table: Table = Table::new((10..20).map(Entry::plain).collect());
    let limits: UseLimits = UseLimits {
        max_processes: 3,
        ..UseLimits::default()
    };
    let inventory = collect_path_uses(&table, USER, &under_unit, limits);
    assert_eq!(inventory.gap, Some(InventoryGap::TooManyProcesses));
    // The time bound: a zero duration stops before the first process.
    let table: Table = Table::new((10..20).map(Entry::plain).collect());
    let limits: UseLimits = UseLimits {
        max_duration: Duration::ZERO,
        ..UseLimits::default()
    };
    let inventory = collect_path_uses(&table, USER, &under_unit, limits);
    assert_eq!(inventory.gap, Some(InventoryGap::DeadlineReached));
    assert_eq!(table.queries.get(), 0);
}

#[cfg(target_os = "macos")]
mod native {
    //! The native queries against disposable child processes in temporary
    //! directories.

    use std::fs::File;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    use super::super::native::parse_procargs;
    use super::super::{DarwinProcessSource, PathInventory, PathUseKind, UseLimits};
    use super::collect_path_uses;
    use crate::platform::process::ProcessSource as _;

    /// A child process that the test started. Drop stops and collects it.
    struct ChildGuard(Child);

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _killed: std::io::Result<()> = self.0.kill();
            let _waited: std::io::Result<std::process::ExitStatus> = self.0.wait();
        }
    }

    fn spawn(command: &mut Command) -> ChildGuard {
        ChildGuard(
            command
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        )
    }

    fn resolved(directory: &tempfile::TempDir) -> PathBuf {
        std::fs::canonicalize(directory.path()).unwrap()
    }

    /// The inventory with the scope `root`, read again until the child
    /// `pid` has a use of `kind`, for at most five seconds.
    fn wait_for(root: &Path, pid: u32, kind: PathUseKind) -> PathInventory {
        let source: DarwinProcessSource = DarwinProcessSource::new();
        let keep = |path: &Path| path.starts_with(root);
        let deadline: Instant = Instant::now() + Duration::from_secs(5);
        loop {
            let inventory =
                collect_path_uses(&source, source.effective_uid(), &keep, UseLimits::default());
            let found: bool = inventory.processes.iter().any(|process| {
                u32::try_from(process.pid.get()).is_ok_and(|value| value == pid)
                    && process.uses.iter().any(|found| found.kind == kind)
            });
            if found || Instant::now() > deadline {
                return inventory;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn has(inventory: &PathInventory, pid: u32, kind: PathUseKind, path: &Path) -> bool {
        inventory.processes.iter().any(|process| {
            u32::try_from(process.pid.get()).is_ok_and(|value| value == pid)
                && process
                    .uses
                    .iter()
                    .any(|found| found.kind == kind && found.path == path)
        })
    }

    #[test]
    fn a_child_with_an_open_file_in_the_scope_is_found() {
        let directory = tempfile::tempdir().unwrap();
        let root: PathBuf = resolved(&directory);
        let held: PathBuf = root.join("held.txt");
        std::fs::write(&held, b"x").unwrap();
        let child = spawn(
            Command::new("/bin/sleep")
                .arg("30")
                .stdin(File::open(&held).unwrap()),
        );
        let inventory = wait_for(&root, child.0.id(), PathUseKind::OpenFile);
        assert!(
            has(&inventory, child.0.id(), PathUseKind::OpenFile, &held),
            "{inventory:?}"
        );
    }

    #[test]
    fn a_child_with_its_working_directory_in_the_scope_is_found() {
        let directory = tempfile::tempdir().unwrap();
        let root: PathBuf = resolved(&directory);
        let child = spawn(Command::new("/bin/sleep").arg("30").current_dir(&root));
        let inventory = wait_for(&root, child.0.id(), PathUseKind::WorkingDirectory);
        assert!(
            has(
                &inventory,
                child.0.id(),
                PathUseKind::WorkingDirectory,
                &root
            ),
            "{inventory:?}"
        );
    }

    #[test]
    fn a_child_that_names_a_path_in_an_argument_is_found() {
        let directory = tempfile::tempdir().unwrap();
        let root: PathBuf = resolved(&directory);
        let named: PathBuf = root.join("named/file");
        // `sh` names the path as `$0` and keeps running while `sleep` runs.
        let child = spawn(
            Command::new("/bin/sh")
                .arg("-c")
                .arg("/bin/sleep 30; :")
                .arg(&named),
        );
        let inventory = wait_for(&root, child.0.id(), PathUseKind::Argument);
        assert!(
            has(&inventory, child.0.id(), PathUseKind::Argument, &named),
            "{inventory:?}"
        );
    }

    #[test]
    fn a_child_that_runs_an_executable_from_the_scope_is_found_and_maps_it() {
        let directory = tempfile::tempdir().unwrap();
        let root: PathBuf = resolved(&directory);
        let copy: PathBuf = root.join("sleep");
        std::fs::copy("/bin/sleep", &copy).unwrap();
        let child = spawn(Command::new(&copy).arg("30"));
        let inventory = wait_for(&root, child.0.id(), PathUseKind::MappedFile);
        assert!(
            has(&inventory, child.0.id(), PathUseKind::Executable, &copy),
            "{inventory:?}"
        );
        assert!(
            has(&inventory, child.0.id(), PathUseKind::MappedFile, &copy),
            "{inventory:?}"
        );
    }

    #[test]
    fn the_inventory_of_this_host_has_no_use_of_an_unused_directory() {
        let directory = tempfile::tempdir().unwrap();
        let root: PathBuf = resolved(&directory);
        let source: DarwinProcessSource = DarwinProcessSource::new();
        let keep = |path: &Path| path.starts_with(&root);
        let inventory =
            collect_path_uses(&source, source.effective_uid(), &keep, UseLimits::default());
        assert_eq!(inventory.processes, Vec::new(), "{inventory:?}");
        assert!(inventory.observed_at.is_some());
    }

    #[test]
    fn procargs_parsing_stops_at_the_count_and_reads_no_environment() {
        let mut buffer: Vec<u8> = 2_i32.to_ne_bytes().to_vec();
        buffer.extend_from_slice(b"/bin/x\0\0\0\0a\0b\0SECRET=1\0");
        let parsed = parse_procargs(&buffer, true).unwrap();
        assert_eq!(parsed.values, vec![b"a".to_vec(), b"b".to_vec()]);
        assert!(!parsed.truncated);
        // A buffer with fewer arguments than the count: truncated when the
        // buffer was full, inconsistent when it was not.
        let mut short: Vec<u8> = 3_i32.to_ne_bytes().to_vec();
        short.extend_from_slice(b"/bin/x\0a\0b\0");
        assert!(parse_procargs(&short, false).unwrap().truncated);
        assert!(parse_procargs(&short, true).is_err());
    }
}
