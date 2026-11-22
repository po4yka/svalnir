//! The path-use inventory: a synthetic process table for the bounds and the
//! fail-closed cases, and disposable child processes for the native
//! queries. No test signals or examines for an action a process that it did
//! not start; the native inventory only reads the process table.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use svalnir_core::file::{FileObjectEvidence, LosslessPath};
use svalnir_core::observation::UnavailableReason;
use svalnir_core::process::{Pid, ProcessStartTime, Uid};
use svalnir_core::quantity::Nanoseconds;
use svalnir_core::time::{MonotonicNanos, WallTime};

use super::source::{
    ProcessSource, QueryFailure, RawArguments, RawPaths, RawProcessInfo, RawUsage, RawVnode,
    RunningApplication, Timebase, VnodeObject,
};
use super::uses::{InventoryGap, PathUseKind, UseLimits, argument_paths, collect_path_uses};
use svalnir_core::file::{DeviceNumber, InodeNumber};

const USER: Uid = Uid::new(501);
const OTHER: Uid = Uid::new(502);

fn path(text: &str) -> LosslessPath {
    LosslessPath::from_bytes(text).unwrap()
}

/// The synthetic file identity of the file at `text`.
fn object_of(text: &[u8]) -> FileObjectEvidence {
    let inode: u64 = text.iter().fold(1_469_598_103_u64, |hash, byte| {
        hash.wrapping_mul(1_099_511).wrapping_add(u64::from(*byte))
    });
    FileObjectEvidence {
        device: DeviceNumber::new(7),
        inode: InodeNumber::new(inode),
    }
}

/// A vnode at `text` whose identity is the identity of the file there.
fn vn(text: &str) -> RawVnode {
    RawVnode {
        path: Some(path(text)),
        vnode: VnodeObject {
            object: object_of(text.as_bytes()),
            links: 1,
        },
    }
}

/// The vnodes at `texts`.
fn vns(texts: &[&str]) -> RawPaths {
    RawPaths {
        paths: texts.iter().map(|text| vn(text)).collect(),
        truncated: false,
    }
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
    executable_failure: Option<QueryFailure>,
    platform: Result<bool, QueryFailure>,
    /// The start times of successive identity queries; the last repeats.
    starts: Vec<u64>,
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
            executable_failure: None,
            platform: Err(QueryFailure::Unsupported),
            starts: vec![1_000],
        }
    }
}

/// A synthetic process table.
struct Table {
    entries: Vec<Entry>,
    list: Result<(), QueryFailure>,
    clock: bool,
    queries: Cell<usize>,
    /// The number of identity queries of each PID.
    identity_queries: RefCell<HashMap<i32, usize>>,
}

impl Table {
    fn new(entries: Vec<Entry>) -> Self {
        Self {
            entries,
            list: Ok(()),
            clock: true,
            queries: Cell::new(0),
            identity_queries: RefCell::new(HashMap::new()),
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
        let mut counts = self.identity_queries.borrow_mut();
        let count: &mut usize = counts.entry(pid.get()).or_default();
        let start: u64 = entry.starts[(*count).min(entry.starts.len() - 1)];
        *count += 1;
        Ok(RawProcessInfo {
            pid,
            parent_pid: None,
            effective_uid: entry.owner,
            real_uid: entry.owner,
            start_time: ProcessStartTime::from_timeval(start, 0).unwrap(),
            zombie: false,
        })
    }

    fn process_owner(&self, pid: Pid) -> Result<(Uid, Uid), QueryFailure> {
        let entry: &Entry = self.entry(pid)?;
        Ok((entry.owner, entry.owner))
    }

    fn executable_path(&self, pid: Pid) -> Result<LosslessPath, QueryFailure> {
        let entry: &Entry = self.entry(pid)?;
        match entry.executable_failure {
            Some(failure) => Err(failure),
            None => Ok(path(entry.executable)),
        }
    }

    fn working_directory_vnode(&self, pid: Pid) -> Result<RawVnode, QueryFailure> {
        Ok(vn(self.entry(pid)?.working_directory))
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

    fn apple_platform_code(&self, pid: Pid) -> Result<bool, QueryFailure> {
        self.entry(pid)?.platform
    }

    fn file_evidence(&self, path: &LosslessPath) -> Result<FileObjectEvidence, QueryFailure> {
        Ok(object_of(path.as_bytes()))
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
    entry.open = Ok(vns(&["/Users/u/app/node_modules/a.js", "/etc/hosts"]));
    entry.mapped = Ok(vns(&["/Users/u/app/node_modules/x.node"]));
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
fn argument_paths_have_each_form_and_keep_the_part_before_dot_dot() {
    let arguments: RawArguments = RawArguments {
        values: vec![
            b"/a/b/../c".to_vec(),
            b"KEY=/d/e".to_vec(),
            b"-x".to_vec(),
            b"./f/g".to_vec(),
            Vec::new(),
            b"-I/inc/h".to_vec(),
            b"-oo/out/o".to_vec(),
            b"--opt=/l/1:/l/2".to_vec(),
            b"file:///u/a%20b/c".to_vec(),
            b"file://localhost/v/w".to_vec(),
        ],
        truncated: false,
    };
    let paths: Vec<PathBuf> = argument_paths(&arguments, Some(Path::new("/w")));
    for expected in [
        // `..` is not resolved: the part before it and the lexical form.
        "/a/b", "/a/c", "/d/e", "/w/f/g",
        // An option prefix of one or two characters.
        "/inc/h", "/out/o", // Each part of a `:` list.
        "/l/1", "/l/2", // A `file://` URL, decoded.
        "/u/a b/c", "/v/w",
    ] {
        assert!(
            paths.contains(&PathBuf::from(expected)),
            "{expected}: {paths:?}"
        );
    }
    // An option is not joined to the working directory.
    assert!(!paths.iter().any(|path| path.ends_with("-x")), "{paths:?}");
    // With no working directory, a relative argument names no path.
    let none: Vec<PathBuf> = argument_paths(&arguments, None);
    assert!(!none.contains(&PathBuf::from("/w/f/g")));
    assert!(none.contains(&PathBuf::from("/d/e")));
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
fn a_denied_identity_query_is_not_visible_only_through_the_platform_gate() {
    // A process of a different user is out of scope with no use query.
    let mut other: Entry = Entry::plain(20);
    other.info = Err(QueryFailure::PermissionDenied);
    other.owner = OTHER;
    let inventory = collect(&Table::new(vec![Entry::plain(10), other]));
    assert_eq!((inventory.gap, inventory.not_visible), (None, 0));
    assert_eq!(inventory.unknown, Vec::new());
    // A set-user-ID process of the user, such as `login`, passes only as
    // Apple platform code on the sealed system volume.
    let login = |platform: Result<bool, QueryFailure>, executable: &'static str, failure| {
        let mut entry: Entry = Entry::plain(20);
        entry.info = Err(failure);
        entry.executable = executable;
        entry.platform = platform;
        entry
    };
    let inventory = collect(&Table::new(vec![
        Entry::plain(10),
        login(Ok(true), "/usr/bin/login", QueryFailure::PermissionDenied),
    ]));
    assert_eq!((inventory.not_visible, inventory.unknown.len()), (1, 0));
    for entry in [
        login(Ok(false), "/usr/bin/login", QueryFailure::PermissionDenied),
        login(
            Err(QueryFailure::Failed(-1)),
            "/usr/bin/login",
            QueryFailure::PermissionDenied,
        ),
        login(Ok(true), "/Users/u/bin/su", QueryFailure::PermissionDenied),
        // Only `EPERM` qualifies.
        login(Ok(true), "/usr/bin/login", QueryFailure::AccessDenied),
    ] {
        let inventory = collect(&Table::new(vec![Entry::plain(10), entry]));
        assert_eq!(inventory.not_visible, 0);
        assert_eq!(
            unknown_reason(&inventory),
            Some(InventoryGap::ProcessQueryDenied)
        );
    }
}

#[test]
fn a_path_from_the_kernel_is_evidence_only_when_its_identity_matches() {
    let unverified = |vnode: RawVnode| {
        let mut entry: Entry = Entry::plain(10);
        entry.open = Ok(RawPaths {
            paths: vec![vnode],
            truncated: false,
        });
        collect(&Table::new(vec![entry]))
    };
    // A path that is not complete: the file at the text is a different
    // object, or there is none.
    let mut truncated: RawVnode = vn("/Users/u/x/y");
    truncated.vnode.object = object_of(b"the real deep file");
    let inventory = unverified(truncated.clone());
    assert_eq!(
        unknown_reason(&inventory),
        Some(InventoryGap::PathNotVerified)
    );
    // No path for a vnode with links.
    let mut nameless: RawVnode = truncated.clone();
    nameless.path = None;
    assert_eq!(
        unknown_reason(&unverified(nameless.clone())),
        Some(InventoryGap::PathNotVerified)
    );
    // A vnode with no link is in no unit.
    nameless.vnode.links = 0;
    let inventory = unverified(nameless);
    assert_eq!((inventory.gap, inventory.unknown.len()), (None, 0));
    // A path in the scope is a use with no other check.
    let mut inside: RawVnode = vn("/Users/u/app/node_modules/a");
    inside.vnode.object = object_of(b"other");
    let inventory = unverified(inside);
    assert_eq!(inventory.processes.len(), 1);
    // A platform process whose path is not verified is not in the blind
    // spot.
    let mut agent: Entry = refused("/usr/libexec/dmd", Ok(true));
    agent.mapped = Ok(RawPaths {
        paths: vec![truncated],
        truncated: false,
    });
    let inventory = collect(&Table::new(vec![agent]));
    assert_eq!(inventory.platform_refused, 0);
    assert_eq!(inventory.unknown.len(), 1);
}

#[test]
fn an_executable_with_no_current_name_is_known_only_when_the_rest_is_verified() {
    let mut replaced: Entry = Entry::plain(10);
    replaced.executable_failure = Some(QueryFailure::Failed(libc::ENOENT));
    replaced.mapped = Ok(vns(&["/Applications/A.app/Contents/Frameworks/F"]));
    let inventory = collect(&Table::new(vec![replaced.clone()]));
    assert_eq!((inventory.gap, inventory.unknown.len()), (None, 0));
    // Its working directory stays evidence.
    let mut working: Entry = replaced.clone();
    working.working_directory = "/Users/u/app/node_modules";
    assert_eq!(collect(&Table::new(vec![working])).processes.len(), 1);
    // Another failure of the same process keeps it unknown.
    let mut failed: Entry = replaced.clone();
    failed.open = Err(QueryFailure::Failed(5));
    assert_eq!(collect(&Table::new(vec![failed])).unknown.len(), 1);
    // A path that is not verified keeps it unknown.
    let mut moved: Entry = replaced;
    let mut vnode: RawVnode = vn("/Applications/A.app/Contents/MacOS/A");
    vnode.vnode.object = object_of(b"the old executable");
    moved.mapped = Ok(RawPaths {
        paths: vec![vnode],
        truncated: false,
    });
    assert_eq!(collect(&Table::new(vec![moved])).unknown.len(), 1);
    // Each other failure of `proc_pidpath` keeps it unknown.
    let mut other: Entry = Entry::plain(10);
    other.executable_failure = Some(QueryFailure::Failed(libc::ENOSPC));
    assert_eq!(collect(&Table::new(vec![other])).unknown.len(), 1);
}

#[test]
fn a_pid_that_names_a_different_process_after_the_queries_is_examined_again() {
    // One change: the new process is examined once more.
    let mut once: Entry = Entry::plain(10);
    once.starts = vec![1_000, 2_000];
    let inventory = collect(&Table::new(vec![once]));
    assert_eq!((inventory.gap, inventory.unknown.len()), (None, 0));
    // Two changes: unknown.
    let mut twice: Entry = Entry::plain(10);
    twice.starts = vec![1_000, 2_000, 3_000];
    let inventory = collect(&Table::new(vec![twice]));
    assert_eq!(
        unknown_reason(&inventory),
        Some(InventoryGap::ProcessReplaced)
    );
}

#[test]
fn an_access_refusal_is_not_the_platform_blind_spot() {
    let mut entry: Entry = refused("/usr/libexec/dmd", Ok(true));
    entry.open = Err(QueryFailure::AccessDenied);
    let inventory = collect(&Table::new(vec![entry, Entry::plain(11)]));
    assert_eq!(inventory.platform_refused, 0);
    assert_eq!(
        unknown_reason(&inventory),
        Some(InventoryGap::ProcessQueryDenied)
    );
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

/// A process of the user that refuses its descriptor query, with the
/// executable `executable` and the result `platform` of the signature check.
fn refused(executable: &'static str, platform: Result<bool, QueryFailure>) -> Entry {
    let mut entry: Entry = Entry::plain(10);
    entry.open = Err(QueryFailure::PermissionDenied);
    entry.executable = executable;
    entry.platform = platform;
    entry
}

#[test]
fn a_refused_apple_platform_process_on_the_system_volume_does_not_block() {
    for executable in [
        "/usr/libexec/dmd",
        "/System/Library/PrivateFrameworks/ScreenTimeCore.framework/Versions/A/ScreenTimeAgent",
        "/usr/sbin/cfprefsd",
        "/bin/sh",
    ] {
        let inventory = collect(&Table::new(vec![
            refused(executable, Ok(true)),
            Entry::plain(11),
        ]));
        assert_eq!(inventory.gap, None, "{executable}");
        assert_eq!(inventory.unknown, Vec::new(), "{executable}");
        assert_eq!(inventory.platform_refused, 1, "{executable}");
    }
}

#[test]
fn a_refused_process_without_platform_code_or_a_system_path_blocks() {
    for (executable, platform) in [
        // A signature that is not Apple platform code.
        ("/usr/libexec/dmd", Ok(false)),
        // The signature check failed.
        ("/usr/libexec/dmd", Err(QueryFailure::Failed(-67062))),
        ("/usr/libexec/dmd", Err(QueryFailure::Unsupported)),
        // Platform code outside the sealed system volume.
        ("/Users/u/bin/dmd", Ok(true)),
        ("/Applications/Tool.app/Contents/MacOS/tool", Ok(true)),
        ("/System/Volumes/Data/usr/libexec/dmd", Ok(true)),
        ("/usr/local/bin/tool", Ok(true)),
        ("/usr/libexec/../../Users/u/tool", Ok(true)),
    ] {
        let inventory = collect(&Table::new(vec![
            refused(executable, platform),
            Entry::plain(11),
        ]));
        assert_eq!(inventory.platform_refused, 0, "{executable} {platform:?}");
        assert_eq!(
            unknown_reason(&inventory),
            Some(InventoryGap::ProcessQueryDenied),
            "{executable} {platform:?}"
        );
    }
}

#[test]
fn only_a_refusal_with_no_other_failure_or_bound_is_the_platform_blind_spot() {
    // A failure that is not a refusal.
    let mut failed: Entry = refused("/usr/libexec/dmd", Ok(true));
    failed.open = Err(QueryFailure::Failed(5));
    // A refusal and a bound of the same process.
    let mut bounded: Entry = refused("/usr/libexec/dmd", Ok(true));
    bounded.mapped = Ok(RawPaths {
        paths: Vec::new(),
        truncated: true,
    });
    for entry in [failed, bounded] {
        let inventory = collect(&Table::new(vec![entry, Entry::plain(11)]));
        assert_eq!(inventory.platform_refused, 0);
        assert_eq!(inventory.unknown.len(), 1);
    }
    // A use that the process gave before the refusal still blocks: the
    // record of the use stays.
    let mut used: Entry = refused("/usr/libexec/dmd", Ok(true));
    used.working_directory = "/Users/u/app/node_modules";
    let inventory = collect(&Table::new(vec![used]));
    assert_eq!(inventory.platform_refused, 1);
    assert_eq!(inventory.processes.len(), 1);
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
    fn a_child_that_uses_a_path_longer_than_maxpathlen_is_never_not_in_use() {
        let directory = tempfile::tempdir().unwrap();
        let root: PathBuf = resolved(&directory);
        // Eight levels of 200 bytes: more than 1500 bytes below the root.
        // The shell makes them with relative steps, holds a file there
        // open as the standard input of `sleep`, and works there.
        let level: String = "d".repeat(200);
        let script: String = format!(
            "for i in 1 2 3 4 5 6 7 8; do mkdir {level} && cd {level} || exit 1; done; \
             echo x > held && : > \"$0/ready\" && exec /bin/sleep 30 < held"
        );
        let child = spawn(
            Command::new("/bin/sh")
                .arg("-c")
                .arg(&script)
                .arg(&root)
                .current_dir(&root),
        );
        let deadline: Instant = Instant::now() + Duration::from_secs(5);
        while !root.join("ready").exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(root.join("ready").exists(), "the child made no tree");
        std::thread::sleep(Duration::from_millis(200));
        let source: DarwinProcessSource = DarwinProcessSource::new();
        let keep = |path: &Path| path.starts_with(&root);
        let inventory =
            collect_path_uses(&source, source.effective_uid(), &keep, UseLimits::default());
        let pid: u32 = child.0.id();
        let used: bool = inventory
            .processes
            .iter()
            .any(|process| u32::try_from(process.pid.get()).is_ok_and(|value| value == pid));
        let unknown: bool = inventory
            .unknown
            .iter()
            .any(|process| u32::try_from(process.pid.get()).is_ok_and(|value| value == pid));
        assert!(used || unknown, "the child is not seen: {inventory:?}");
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
