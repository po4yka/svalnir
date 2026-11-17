//! A synthetic [`ProcessSource`] for the tests.
//!
//! Each query reads injected data. The identity query of a PID can give a
//! sequence of results, so a test can make a process exit or be replaced
//! between the first and the last identity reading.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, VecDeque};

use svalnir_core::file::{DeviceNumber, FileObjectEvidence, InodeNumber, LosslessPath};
use svalnir_core::id::{BootId, CollectorEpochId, WorkerId};
use svalnir_core::observation::UnavailableReason;
use svalnir_core::process::{Pid, ProcessStartTime, Uid};
use svalnir_core::quantity::Nanoseconds;
use svalnir_core::time::{MonotonicNanos, WallTime};

use super::inventory::{CollectionContext, ProcessCollector};
use super::source::{
    ProcessSource, QueryFailure, RawProcessInfo, RawUsage, RunningApplication, Timebase,
};

pub(super) const USER: u32 = 501;

pub(super) fn pid(value: i32) -> Pid {
    Pid::new(value).unwrap()
}

pub(super) fn info(process: i32, start_seconds: u64) -> RawProcessInfo {
    RawProcessInfo {
        pid: pid(process),
        parent_pid: Some(pid(1)),
        effective_uid: Uid::new(USER),
        real_uid: Uid::new(USER),
        start_time: ProcessStartTime::from_timeval(start_seconds, 0).unwrap(),
        zombie: false,
    }
}

pub(super) fn usage(footprint: u64, resident: u64) -> RawUsage {
    RawUsage {
        physical_footprint: footprint,
        resident_size: resident,
        lifetime_max_physical_footprint: footprint + 1,
        user_time_mach: 24,
        system_time_mach: 24,
        disk_bytes_read: 10,
        disk_bytes_written: 20,
    }
}

pub(super) fn application(process: i32, bundle: &str, active: bool) -> RunningApplication {
    RunningApplication {
        pid: pid(process),
        bundle_identifier: Some(bundle.to_owned()),
        executable_path: None,
        active,
        terminated: false,
    }
}

pub(super) fn context() -> CollectionContext {
    CollectionContext {
        worker_id: WorkerId::new("worker-test").unwrap(),
        boot_id: BootId::new("boot-test").unwrap(),
        collector_epoch: CollectorEpochId::new("epoch-test").unwrap(),
    }
}

#[derive(Debug)]
pub(super) struct FakeSource {
    pub(super) list: Result<Vec<Pid>, QueryFailure>,
    /// The results of the identity query of each PID, in call order. The
    /// last result repeats.
    pub(super) info: RefCell<BTreeMap<Pid, VecDeque<Result<RawProcessInfo, QueryFailure>>>>,
    pub(super) paths: BTreeMap<Pid, Result<LosslessPath, QueryFailure>>,
    /// The path that the second and each later path query of a PID gives,
    /// for a process that replaces its program image with `exec`.
    pub(super) paths_after_exec: BTreeMap<Pid, LosslessPath>,
    path_queries: RefCell<BTreeMap<Pid, u32>>,
    pub(super) files: BTreeMap<Vec<u8>, FileObjectEvidence>,
    pub(super) usage: BTreeMap<Pid, Result<RawUsage, QueryFailure>>,
    pub(super) responsible: BTreeMap<Pid, Result<Pid, QueryFailure>>,
    pub(super) applications: Result<Vec<RunningApplication>, QueryFailure>,
    pub(super) timebase: Result<Timebase, QueryFailure>,
    pub(super) clock: Cell<u64>,
    /// The cumulative sleep time of the host.
    pub(super) slept: Result<Nanoseconds, UnavailableReason>,
    /// The sleep time that the second and each later query gives, for a
    /// host that sleeps during a collection.
    pub(super) slept_later: Option<Nanoseconds>,
    sleep_queries: Cell<u32>,
    /// The answer of `application_list_current`.
    pub(super) list_current: bool,
    /// The failure of the file evidence query of a path.
    pub(super) file_failures: BTreeMap<Vec<u8>, QueryFailure>,
}

impl FakeSource {
    pub(super) fn new() -> Self {
        Self {
            list: Ok(Vec::new()),
            info: RefCell::new(BTreeMap::new()),
            paths: BTreeMap::new(),
            paths_after_exec: BTreeMap::new(),
            path_queries: RefCell::new(BTreeMap::new()),
            files: BTreeMap::new(),
            usage: BTreeMap::new(),
            responsible: BTreeMap::new(),
            applications: Ok(Vec::new()),
            timebase: Ok(Timebase::new(125, 3).unwrap()),
            clock: Cell::new(1_000_000),
            slept: Ok(Nanoseconds::ZERO),
            slept_later: None,
            sleep_queries: Cell::new(0),
            list_current: true,
            file_failures: BTreeMap::new(),
        }
    }

    /// Adds a process that keeps its identity, with a path, a file object,
    /// and a usage record.
    pub(super) fn with_process(
        mut self,
        record: RawProcessInfo,
        path: &str,
        usage: RawUsage,
    ) -> Self {
        let process: Pid = record.pid;
        self = self.with_info_sequence(process, vec![Ok(record)]);
        self.files.insert(
            path.as_bytes().to_vec(),
            FileObjectEvidence {
                device: DeviceNumber::new(1),
                inode: InodeNumber::new(u64::try_from(process.get()).unwrap()),
            },
        );
        self.paths
            .insert(process, Ok(LosslessPath::from_bytes(path).unwrap()));
        self.usage.insert(process, Ok(usage));
        self
    }

    /// Sets the results of the identity query of a PID, in call order.
    pub(super) fn with_info_sequence(
        mut self,
        process: Pid,
        sequence: Vec<Result<RawProcessInfo, QueryFailure>>,
    ) -> Self {
        if let Ok(list) = self.list.as_mut()
            && !list.contains(&process)
        {
            list.push(process);
        }
        self.info.borrow_mut().insert(process, sequence.into());
        self
    }

    pub(super) fn with_responsible(mut self, process: i32, owner: i32) -> Self {
        self.responsible.insert(pid(process), Ok(pid(owner)));
        self
    }

    /// Adds a running application. With no path in `application`, the entry
    /// gets the executable path of the fake process with the same PID.
    pub(super) fn with_application(mut self, mut application: RunningApplication) -> Self {
        if application.executable_path.is_none()
            && let Some(Ok(path)) = self.paths.get(&application.pid)
        {
            application.executable_path = Some(path.clone());
        }
        if let Ok(list) = self.applications.as_mut() {
            list.push(application);
        }
        self
    }

    pub(super) fn collector(self) -> ProcessCollector<Self> {
        ProcessCollector::new(self, context()).unwrap()
    }
}

impl ProcessSource for FakeSource {
    fn effective_uid(&self) -> Uid {
        Uid::new(USER)
    }

    fn list_pids(&self) -> Result<Vec<Pid>, QueryFailure> {
        self.list.clone()
    }

    fn process_info(&self, pid: Pid) -> Result<RawProcessInfo, QueryFailure> {
        let mut info = self.info.borrow_mut();
        let Some(sequence) = info.get_mut(&pid) else {
            return Err(QueryFailure::Gone);
        };
        if sequence.len() > 1 {
            sequence.pop_front().unwrap_or(Err(QueryFailure::Gone))
        } else {
            sequence.front().copied().unwrap_or(Err(QueryFailure::Gone))
        }
    }

    fn executable_path(&self, pid: Pid) -> Result<LosslessPath, QueryFailure> {
        let mut queries = self.path_queries.borrow_mut();
        let query: &mut u32 = queries.entry(pid).or_insert(0);
        *query += 1;
        if *query > 1
            && let Some(path) = self.paths_after_exec.get(&pid)
        {
            return Ok(path.clone());
        }
        self.paths
            .get(&pid)
            .cloned()
            .unwrap_or(Err(QueryFailure::Gone))
    }

    fn file_evidence(&self, path: &LosslessPath) -> Result<FileObjectEvidence, QueryFailure> {
        if let Some(failure) = self.file_failures.get(path.as_bytes()) {
            return Err(*failure);
        }
        self.files
            .get(path.as_bytes())
            .copied()
            .ok_or(QueryFailure::Gone)
    }

    fn usage(&self, pid: Pid) -> Result<RawUsage, QueryFailure> {
        self.usage
            .get(&pid)
            .copied()
            .unwrap_or(Err(QueryFailure::Gone))
    }

    fn responsible_pid(&self, pid: Pid) -> Result<Pid, QueryFailure> {
        // As on macOS, a process with no other responsible process is
        // responsible for itself.
        self.responsible.get(&pid).copied().unwrap_or(Ok(pid))
    }

    fn application_list_current(&self) -> bool {
        self.list_current
    }

    fn running_applications(&self) -> Result<Vec<RunningApplication>, QueryFailure> {
        self.applications.clone()
    }

    fn timebase(&self) -> Result<Timebase, QueryFailure> {
        self.timebase
    }

    fn monotonic_now(&self) -> Result<MonotonicNanos, QueryFailure> {
        let now: u64 = self.clock.get() + 1_000;
        self.clock.set(now);
        Ok(MonotonicNanos::new(now))
    }

    fn sleep_time(&self) -> Result<Nanoseconds, UnavailableReason> {
        let query: u32 = self.sleep_queries.get();
        self.sleep_queries.set(query.saturating_add(1));
        match self.slept_later {
            Some(later) if query > 0 => Ok(later),
            _ => self.slept.clone(),
        }
    }

    fn wall_now(&self) -> Result<WallTime, QueryFailure> {
        WallTime::from_unix(1_794_830_400, 0).map_err(|_| QueryFailure::Inconsistent)
    }
}
