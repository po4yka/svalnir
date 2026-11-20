//! Tests of the runtime with injected collectors.
//!
//! Each test has its own temporary directory with the journal, an
//! approved root, a home directory, and a Trash directory. A file is
//! removed or moved only below that directory. A process is signaled only
//! when the test started it: the planned identity is the PID and the start
//! time of that child, and a guard kills and collects the child at the end
//! of the test. No test registers a service, and no test reads or writes
//! the state directory, the home directory, or the Trash of the user.

#![cfg(target_os = "macos")]

mod busy;
mod eviction;
mod rearm;

use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use svalnir_core::action::{
    ActionClass, ClientRole, Escalation, ExecutorRole, FileBinding, FileObjectType, Journal,
    OperationState, PLAN_SCHEMA_VERSION, Plan, PlanApproval, PlanContent, PlanLimits, PlanTarget,
    PlannedStep, Principal, TargetBinding, Trigger, Validity, WorkCharge,
};
use svalnir_core::authority::AuthorityBinding;
use svalnir_core::file::{DeviceNumber, FileObjectEvidence, LosslessPath};
use svalnir_core::grant::AuthorityState;
use svalnir_core::id::{
    AdapterId, ApplicationInstanceId, ExecutorEpochId, LeaseId, MountId, OperationId, PlanId,
    PolicyRevisionId, RequestId, RootId, StepId, TargetId, VolumeId,
};
use svalnir_core::observation::Observation;
use svalnir_core::policy::{ApplicationCandidate, ContinuityGeneration, EvaluationClock, PolicyId};
use svalnir_core::process::{
    AttributionMethod, ExecutableIdentity, Pid, ProcessAssociation, ProcessIdentity,
};
use svalnir_core::quantity::{Bytes, EntryCount, Nanoseconds};
use svalnir_core::rule::RuleRegistry;
use svalnir_core::state::PressureState;
use svalnir_core::time::{MonotonicNanos, WallTime};
use tempfile::TempDir;

use super::{
    AgentClock, AgentStatus, CandidateSource, CapabilitySummary, Collector, Driver, DriverParts,
    DriverSettings, DriverStart, LifecycleRecord, Notifier, Preparation, RunState, Sample,
    SelfFootprint, ServiceSettings, ShutdownReport, StopHandle, journal_path, run,
};
use crate::controller::tests::support::{
    CandidateSpec, GIBIBYTE, MOUNT, ROOT_ID, Registry, SECOND, VOLUME, application, boot, capacity,
    clock_domain, config, config_text, enabled, memory, paused, prepared, pressure,
    proposed_registry, rule, user, validated_registry, volume, wall,
};
use crate::controller::{
    BlockedReason, CandidateSet, ControllerState, Guard, GuardPhase, Notification, Observations,
    PreparationMode, Summary,
};
use crate::coordinator::{
    CoordinatorConfig, IdSource, Idle, Measurements, Phase, SystemProbe, TimeReading,
};
use crate::executor::fs::{
    ApprovedRoot, ApprovedRoots, ExecutorLimits, FsExecutor, FsExecutorConfig, TrashBackend,
    TrashReply, TrashRequest,
};
use crate::executor::process::{
    DarwinProcessControl, ExecutorConfig, ExecutorContext, ProcessExecutor, StepClock,
};
use crate::journal::{
    AgentRecord, CoordinatorLock, CoordinatorRole, JournalOptions, OperationJournal, QueuedRequest,
    RequestBody, RequestCompletion, RequestStatus,
};
use crate::platform::process::{DarwinProcessSource, ProcessSource, QueryFailure, generation_id};
use crate::rules::fixture::FixtureEnvironment;

/// The time of a fixed clock at the start of a test.
const START: u64 = 1_000 * SECOND;
/// The time between two samples of a test.
const SAMPLE: u64 = 5 * SECOND;

const CHILD_VARIABLE: &str = "SVALNIR_TEST_RUNTIME_CHILD";
const CHILD_TEST: &str = "runtime::tests::child_entry";
const CHILD_LIFE: Duration = Duration::from_secs(60);

/// The body of a child process. Without the variable, which only the
/// tests of this file set, it does nothing.
#[test]
#[ignore = "the entry of a child process that the tests of this file start"]
fn child_entry() {
    if std::env::var_os(CHILD_VARIABLE).is_none() {
        return;
    }
    // The child ends when its life ends or when the test process that
    // started it does not exist.
    let parent: u32 = std::os::unix::process::parent_id();
    let end: Instant = Instant::now() + CHILD_LIFE;
    while Instant::now() < end && std::os::unix::process::parent_id() == parent {
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// A child process that is killed and collected when the value is
/// dropped.
struct ChildGuard(Child);

impl ChildGuard {
    fn pid(&self) -> Pid {
        Pid::new(i32::try_from(self.0.id()).unwrap()).unwrap()
    }

    fn is_running(&mut self) -> bool {
        self.0.try_wait().unwrap().is_none()
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        // `Child::kill` addresses only the child of this value.
        if let Err(error) = self.0.kill() {
            eprintln!("the child was not killed: {error}");
        }
        if let Err(error) = self.0.wait() {
            eprintln!("the child was not collected: {error}");
        }
    }
}

fn child_command(program: &Path) -> Command {
    let mut command: Command = Command::new(program);
    command
        .env(CHILD_VARIABLE, "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

/// Starts a child. With `ignores_term`, the shell sets the disposition of
/// `SIGTERM` and replaces itself with the test binary, which inherits it.
fn spawn_child(ignores_term: bool) -> ChildGuard {
    let program = std::env::current_exe().unwrap();
    let arguments = ["--ignored", "--exact", CHILD_TEST];
    if !ignores_term {
        return ChildGuard(child_command(&program).args(arguments).spawn().unwrap());
    }
    let child: Child = child_command(Path::new("/bin/sh"))
        .args(["-c", "trap '' TERM; exec \"$0\" \"$@\""])
        .arg(&program)
        .args(arguments)
        .spawn()
        .unwrap();
    let guard = ChildGuard(child);
    let source = DarwinProcessSource::new();
    let limit: Instant = Instant::now() + Duration::from_secs(10);
    loop {
        let replaced: bool = source
            .executable_path(guard.pid())
            .is_ok_and(|path| !path.as_bytes().starts_with(b"/bin/"));
        if replaced {
            return guard;
        }
        assert!(Instant::now() < limit, "the shell did not start the child");
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// The identity of a live child as a plan has it.
fn child_identity(process: Pid) -> ProcessIdentity {
    let source = DarwinProcessSource::new();
    let info = source.process_info(process).unwrap();
    let path = source.executable_path(process).unwrap();
    let file = source.file_evidence(&path).ok();
    ProcessIdentity {
        generation_id: generation_id(process, info.start_time).unwrap(),
        pid: process,
        start_time: info.start_time,
        uid: info.effective_uid,
        boot_id: boot(),
        executable: Some(ExecutableIdentity {
            path,
            file,
            code_signature: None,
        }),
        association: ProcessAssociation::ManagedJob {
            instance_id: ApplicationInstanceId::new("instance-child").unwrap(),
            label: "com.example.test-child".to_owned(),
            attribution: AttributionMethod::LaunchdJob,
        },
    }
}

/// The clock of a test: a base time and an offset that the test moves.
/// With the host as the base, a process state that the executor reads is
/// at the same time as the clock.
#[derive(Debug, Clone)]
struct TestClock {
    host: bool,
    offset: Arc<AtomicU64>,
    discontinuities: Arc<AtomicU64>,
    /// True when the next reading of the continuity finds a sleep.
    slept: Arc<AtomicBool>,
}

impl TestClock {
    fn fixed() -> Self {
        Self {
            host: false,
            offset: Arc::new(AtomicU64::new(0)),
            discontinuities: Arc::new(AtomicU64::new(0)),
            slept: Arc::new(AtomicBool::new(false)),
        }
    }

    fn host() -> Self {
        Self {
            host: true,
            ..Self::fixed()
        }
    }

    fn now(&self) -> u64 {
        let base: u64 = if self.host {
            DarwinProcessSource::new().monotonic_now().unwrap().get()
        } else {
            START
        };
        base + self.offset.load(Ordering::SeqCst)
    }

    fn advance(&self, nanoseconds: u64) {
        self.offset.fetch_add(nanoseconds, Ordering::SeqCst);
    }

    fn reading(&self) -> TimeReading {
        let now: u64 = self.now();
        let generation: u64 = self.discontinuities.load(Ordering::SeqCst);
        TimeReading {
            clock: EvaluationClock {
                now: MonotonicNanos::new(now),
                clock_domain: clock_domain(),
                boot_id: boot(),
                continuity: ContinuityGeneration::new(generation),
                last_discontinuity: None,
            },
            wall: wall(now),
        }
    }
}

impl AgentClock for TestClock {
    fn now(&self) -> Option<TimeReading> {
        Some(self.reading())
    }

    fn mark_discontinuity(&self) {
        self.discontinuities.fetch_add(1, Ordering::SeqCst);
    }

    fn observe_continuity(&self) -> bool {
        let slept: bool = self.slept.swap(false, Ordering::SeqCst);
        if slept {
            self.mark_discontinuity();
        }
        slept
    }
}

impl StepClock for TestClock {
    fn monotonic_now(&self) -> Result<MonotonicNanos, QueryFailure> {
        Ok(MonotonicNanos::new(self.now()))
    }

    fn wall_now(&self) -> Option<WallTime> {
        Some(wall(self.now()))
    }
}

/// Moves the clock of a test to the wake time of the coordinator.
struct TestIdle(TestClock);

impl Idle for TestIdle {
    fn idle(&mut self, wake_at: Option<MonotonicNanos>) {
        let now: u64 = self.0.now();
        match wake_at {
            Some(wake_at) if wake_at.get() > now => self.0.advance(wake_at.get() - now),
            _ => self.0.advance(SECOND / 10),
        }
        // A process state needs a short real time to change.
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// The measurements of a test: the available capacity is larger for each
/// file that is not below the root, and the pressure is a value that the
/// test sets.
#[derive(Debug, Clone)]
struct TestMeasurements {
    clock: TestClock,
    root: PathBuf,
    pressure: Arc<Mutex<PressureState>>,
}

impl Measurements for TestMeasurements {
    fn capacity(&mut self, _volume: &VolumeId) -> Observation<Bytes> {
        let files: u64 = fs::read_dir(&self.root).map_or(0, |entries| entries.count() as u64);
        capacity(
            Some((20_u64.saturating_sub(files)) * GIBIBYTE),
            self.clock.now(),
        )
    }

    fn memory_pressure(&mut self) -> Observation<PressureState> {
        pressure(
            Some(self.pressure.lock().unwrap().clone()),
            self.clock.now(),
        )
    }
}

#[derive(Debug)]
struct TestIds(String, u64);

impl IdSource for TestIds {
    fn operation_id(&mut self) -> Option<OperationId> {
        self.1 += 1;
        OperationId::new(format!("{}-operation-{}", self.0, self.1)).ok()
    }

    fn lease_id(&mut self) -> Option<LeaseId> {
        self.1 += 1;
        LeaseId::new(format!("{}-lease-{}", self.0, self.1)).ok()
    }
}

fn object_of(path: &Path) -> FileObjectEvidence {
    let metadata = fs::symlink_metadata(path).unwrap();
    FileObjectEvidence {
        device: DeviceNumber::new(i32::try_from(metadata.dev()).unwrap()),
        inode: metadata.ino().into(),
    }
}

/// A Trash backend that moves an entry to the Trash directory of the
/// fixture. It refuses each path outside the temporary directory.
#[derive(Debug)]
struct TempTrash(PathBuf);

impl TrashBackend for TempTrash {
    fn move_to_trash(&self, request: &TrashRequest<'_>) -> TrashReply {
        let source: PathBuf = request.path.to_path_buf();
        assert!(source.starts_with(self.0.parent().unwrap()));
        let item: PathBuf = self.0.join(source.file_name().unwrap());
        fs::rename(&source, &item).unwrap();
        TrashReply::Moved {
            item_object: Some(object_of(&item)),
            item: Some(LosslessPath::from_path(&item).unwrap()),
        }
    }
}

/// The environment of the tests with the synthetic rule of the controller
/// tests: the producer of that rule is not active. A build knows no
/// producer evidence for a rule that is not in its registry.
#[derive(Debug, Clone)]
struct TestRuleEnvironment(FixtureEnvironment);

impl crate::scan::ScanClock for TestRuleEnvironment {
    fn now(&self) -> crate::scan::ScanTimestamp {
        self.0.now()
    }
}

impl crate::rules::DiscoveryEnvironment for TestRuleEnvironment {
    fn xcode_evidence(&self, principal: svalnir_core::process::Uid) -> crate::rules::XcodeEvidence {
        self.0.xcode_evidence(principal)
    }

    fn producer_activity(
        &self,
        _rule: &svalnir_core::id::RuleId,
        _principal: svalnir_core::process::Uid,
    ) -> crate::rules::ProducerActivity {
        crate::rules::ProducerActivity::Inactive
    }
}

/// The candidates of a test: each regular file below the root of the
/// fixture, as a candidate of the test rule.
#[derive(Debug)]
struct TempCandidates {
    registry: Registry,
    root: PathBuf,
    modes: Arc<Mutex<Vec<PreparationMode>>>,
    /// The answer of [`CandidateSource::invalidated`], as an `FSEvents`
    /// invalidation of the source gives it.
    invalidated: Arc<AtomicBool>,
}

impl CandidateSource for TempCandidates {
    fn invalidated(&mut self, _at: MonotonicNanos) -> bool {
        self.invalidated.load(Ordering::SeqCst)
    }

    fn watch_status(&self) -> Option<crate::runtime::invalidation::CatalogWatchStatus> {
        Some(crate::runtime::invalidation::CatalogWatchStatus {
            state: crate::runtime::invalidation::CatalogWatchState::Available,
            detail: "test".to_owned(),
            roots: 1,
            counts: crate::runtime::invalidation::InvalidationCounts::default(),
        })
    }

    fn prepare(&mut self, request: &Preparation<'_>) -> Option<CandidateSet> {
        let Preparation { mode, time, .. } = *request;
        // A preparation is a complete discovery: it covers each change.
        if mode == PreparationMode::Refresh {
            self.invalidated.store(false, Ordering::SeqCst);
        }
        self.modes.lock().unwrap().push(mode);
        let rule = self.registry.rules().first().copied()?.clone();
        let mut names: Vec<String> = fs::read_dir(&self.root)
            .ok()?
            .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
            .collect();
        names.sort();
        Some(CandidateSet {
            prepared_at: time.clock.now,
            complete: true,
            candidates: names
                .iter()
                .map(|name| {
                    let spec = CandidateSpec {
                        name: name.clone(),
                        root_path: LosslessPath::from_path(&self.root).unwrap(),
                        root_object: object_of(&self.root),
                        object: object_of(&self.root.join(name)),
                        object_type: FileObjectType::RegularFile,
                        work_bytes: 1_000,
                    };
                    prepared(&rule, &spec)
                })
                .collect(),
            invalidated: false,
        })
    }
}

#[derive(Debug, Clone, Default)]
struct Notes(
    Arc<Mutex<Vec<Notification>>>,
    Arc<Mutex<Vec<crate::coordinator::SettledOperation>>>,
    Arc<Mutex<Vec<Option<PressureState>>>>,
);

impl Notifier for Notes {
    fn notify(&mut self, notification: &Notification, _at: MonotonicNanos) {
        self.0.lock().unwrap().push(notification.clone());
    }

    fn settled(&mut self, operation: &crate::coordinator::SettledOperation, _at: MonotonicNanos) {
        self.1.lock().unwrap().push(operation.clone());
    }

    fn pressure(&mut self, reading: Option<&PressureState>, _at: MonotonicNanos) {
        self.2.lock().unwrap().push(reading.cloned());
    }
}

/// The function of a [`Hook`].
type HookFunction = Box<dyn FnOnce() + Send>;

/// A function that a test runs one time inside a call of the driver.
#[derive(Clone, Default)]
struct Hook(Arc<Mutex<Option<HookFunction>>>);

impl std::fmt::Debug for Hook {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Hook")
    }
}

impl Hook {
    fn set(&self, hook: impl FnOnce() + Send + 'static) {
        *self.0.lock().unwrap() = Some(Box::new(hook));
    }

    fn run(&self) {
        let hook = self.0.lock().unwrap().take();
        if let Some(hook) = hook {
            hook();
        }
    }
}

#[derive(Debug, Clone)]
struct Footprint(Arc<AtomicU64>, Hook);

impl SelfFootprint for Footprint {
    fn footprint(&mut self) -> Option<Bytes> {
        self.1.run();
        Some(Bytes::new(self.0.load(Ordering::SeqCst)))
    }
}

/// Everything that a test holds beside the driver.
struct Bench {
    _temp: TempDir,
    state: PathBuf,
    root: PathBuf,
    trash: PathBuf,
    home: PathBuf,
    clock: TestClock,
    registry: Registry,
    text: String,
    pressure: Arc<Mutex<PressureState>>,
    modes: Arc<Mutex<Vec<PreparationMode>>>,
    invalidated: Arc<AtomicBool>,
    notes: Notes,
    /// When set, the driver has the notifier of the agent with this
    /// center, and a capability summary, in place of [`Notes`].
    center: Option<crate::notify::fake::FakeCenter>,
    footprint: Arc<AtomicU64>,
    /// Runs one time at the next measurement of the footprint of the
    /// agent: after the tick read the authority record and before the
    /// coordinator claims a request.
    footprint_hook: Hook,
    /// The bounded wait of the journal of the driver, when a test sets a
    /// short one.
    busy_timeout: Option<Duration>,
    lifetimes: u32,
}

impl Bench {
    fn new(clock: TestClock, registry: Registry) -> Self {
        let temp: TempDir = tempfile::tempdir().unwrap();
        // The temporary directory of macOS is below the symbolic link
        // `/var`. An approved root has no symbolic link in its path.
        let base: PathBuf = fs::canonicalize(temp.path()).unwrap();
        let directories = ["state", "root", "trash", "home"].map(|name| base.join(name));
        for directory in &directories {
            fs::create_dir(directory).unwrap();
        }
        let [state, root, trash, home] = directories;
        Self {
            _temp: temp,
            state,
            root,
            trash,
            home,
            clock,
            registry,
            text: config_text(&[]),
            pressure: Arc::new(Mutex::new(PressureState::Normal)),
            modes: Arc::new(Mutex::new(Vec::new())),
            invalidated: Arc::new(AtomicBool::new(false)),
            notes: Notes::default(),
            center: None,
            footprint: Arc::new(AtomicU64::new(10 * 1024 * 1024)),
            footprint_hook: Hook::default(),
            busy_timeout: None,
            lifetimes: 0,
        }
    }

    fn journal(&self) -> OperationJournal {
        // The tests do not need the full synchronization of the device.
        let options = JournalOptions {
            full_fsync: false,
            ..JournalOptions::default()
        };
        OperationJournal::open(&journal_path(&self.state), &options).unwrap()
    }

    /// Writes the authority record as an activation and two enable
    /// commands of a client do: the two guards are active.
    fn seed_authority(&self) -> AuthorityState {
        let state: AuthorityState = enabled(&self.text, &self.registry);
        self.write_authority(&state);
        state
    }

    fn write_authority(&self, state: &AuthorityState) {
        let mut journal = self.journal();
        if let Some(active) = &state.active {
            journal
                .record_policy_revision(&active.revision, Some(&self.text))
                .unwrap();
        }
        journal
            .put_agent_record(AgentRecord::Authority, state, None, wall(self.clock.now()))
            .unwrap();
    }

    fn roots(&self) -> ApprovedRoots {
        ApprovedRoots::new(vec![ApprovedRoot {
            root_id: RootId::new(ROOT_ID).unwrap(),
            path: LosslessPath::from_path(&self.root).unwrap(),
            object: object_of(&self.root),
            volume_id: VolumeId::new(VOLUME).unwrap(),
            mount_id: MountId::new(MOUNT).unwrap(),
        }])
        .unwrap()
    }

    fn settings(&self) -> DriverSettings {
        DriverSettings {
            principal: user(),
            home_directory: Some(LosslessPath::from_path(&self.home).unwrap()),
            proposal: config(&[]),
            coordinator: CoordinatorConfig {
                filesystem_adapter: AdapterId::new("svalnir.filesystem").unwrap(),
                process_adapter: AdapterId::new("macos.process").unwrap(),
                batch_targets: 2,
                poll_interval: Nanoseconds::new(SECOND),
                volatile_capacity: 8,
                role: CoordinatorRole::Agent,
            },
            journal: JournalOptions {
                full_fsync: false,
                busy_timeout: self
                    .busy_timeout
                    .unwrap_or(JournalOptions::default().busy_timeout),
                ..JournalOptions::default()
            },
            status_interval: Nanoseconds::new(30 * SECOND),
            maintenance_interval: Nanoseconds::new(3_600 * SECOND),
            self_budget: Bytes::new(64 * 1024 * 1024),
            shutdown_bound: Nanoseconds::new(3 * SECOND),
            coordinator_units: 8,
            sample_stale_after: Nanoseconds::new(180 * SECOND),
        }
    }

    fn parts(&self, epoch: &ExecutorEpochId) -> DriverParts {
        let roots: ApprovedRoots = self.roots();
        let filesystem = FsExecutor::new(
            &FsExecutorConfig {
                home_directory: LosslessPath::from_path(&self.home).unwrap(),
                limits: ExecutorLimits::default(),
            },
            Box::new(TempTrash(self.trash.clone())),
        )
        .unwrap();
        DriverParts {
            clock: Arc::new(self.clock.clone()),
            registry: Box::new(self.registry.clone()),
            measurements: Box::new(TestMeasurements {
                clock: self.clock.clone(),
                root: self.root.clone(),
                pressure: Arc::clone(&self.pressure),
            }),
            ids: Box::new(TestIds(epoch.as_str().to_owned(), 0)),
            filesystem: Box::new(filesystem),
            roots: roots.clone(),
            application: Box::new(ProcessExecutor::new(
                DarwinProcessSource::new(),
                DarwinProcessControl,
                self.clock.clone(),
                ExecutorContext {
                    boot_id: boot(),
                    clock_domain: clock_domain(),
                    executor_epoch: epoch.clone(),
                },
                ExecutorConfig::default(),
            )),
            probe: Box::new(SystemProbe::new(roots, DarwinProcessSource::new())),
            candidates: Box::new(TempCandidates {
                registry: self.registry.clone(),
                root: self.root.clone(),
                modes: Arc::clone(&self.modes),
                invalidated: Arc::clone(&self.invalidated),
            }),
            environment: Arc::new(TestRuleEnvironment(FixtureEnvironment::days_later(0))),
            notifier: match &self.center {
                Some(center) => {
                    Box::new(crate::notify::AgentNotifier::new(Box::new(center.clone())))
                }
                None => Box::new(self.notes.clone()),
            },
            footprint: Box::new(Footprint(
                Arc::clone(&self.footprint),
                self.footprint_hook.clone(),
            )),
            store: None,
            capabilities: self.center.as_ref().map(|_| CapabilitySummary {
                verdict: "ready".to_owned(),
                required_not_available: Vec::new(),
                probed_at: None,
                lines: Vec::new(),
                notifications: None,
                catalog_watch: None,
            }),
        }
    }

    /// Starts a new executor lifetime on the journal of the bench.
    fn try_start(&mut self) -> DriverStart {
        self.lifetimes += 1;
        let epoch = ExecutorEpochId::new(format!("epoch_{}", self.lifetimes)).unwrap();
        Driver::start(
            &self.state,
            epoch.clone(),
            self.settings(),
            self.parts(&epoch),
        )
        .unwrap()
    }

    /// Starts a driver when no coordinator of the test holds the lock.
    ///
    /// A test of a different thread can start a child process at the same
    /// time. Between its `fork` and its `exec`, that child has a copy of
    /// each open file of this process, also of a lock file that a test
    /// dropped a moment before, and the lock stays held for that instant.
    /// The start is thus tried again for a short time.
    fn start(&mut self) -> Box<Driver> {
        for _ in 0..200 {
            match self.try_start() {
                DriverStart::Running(driver) => return driver,
                DriverStart::Busy { .. } => std::thread::sleep(Duration::from_millis(10)),
            }
        }
        panic!("a different coordinator holds the lock");
    }

    fn file(&self, name: &str) -> PathBuf {
        let path: PathBuf = self.root.join(name);
        fs::write(&path, b"regenerable content").unwrap();
        path
    }

    /// A sample at the time of the clock.
    fn sample(
        &self,
        available: u64,
        state: PressureState,
        applications: Vec<ApplicationCandidate>,
    ) -> Sample {
        let at: u64 = self.clock.now();
        *self.pressure.lock().unwrap() = state.clone();
        Sample {
            observations: Observations {
                volumes: vec![volume(Some(available), at)],
                memory: memory(Some(state), at, applications),
                candidates: None,
            },
            woke: false,
            // The test process is not a member of a target of a test.
            control_plane: Some(Vec::new()),
            degraded: Vec::new(),
            sleep_time: None,
        }
    }

    fn status(&self) -> AgentStatus {
        self.journal()
            .agent_record::<AgentStatus>(AgentRecord::Status)
            .unwrap()
            .unwrap()
            .record
    }

    fn lifecycle(&self) -> LifecycleRecord {
        self.journal()
            .agent_record::<LifecycleRecord>(AgentRecord::Lifecycle)
            .unwrap()
            .unwrap()
            .record
    }

    fn controller_record(&self) -> ControllerState {
        self.journal()
            .agent_record::<ControllerState>(AgentRecord::Controller)
            .unwrap()
            .unwrap()
            .record
    }
}

fn blocked(driver: &Driver, guard: Guard) -> Vec<BlockedReason> {
    driver
        .controller_status()
        .unwrap()
        .guards
        .iter()
        .find(|status| status.guard == guard)
        .unwrap()
        .blocked
        .clone()
}

fn phase(driver: &Driver, guard: Guard) -> GuardPhase {
    driver
        .controller_status()
        .unwrap()
        .guards
        .iter()
        .find(|status| status.guard == guard)
        .unwrap()
        .phase
}

#[test]
fn with_no_authority_record_the_agent_only_observes_and_reports_it() {
    let mut bench = Bench::new(TestClock::fixed(), validated_registry());
    bench.file("a");
    let mut driver = bench.start();
    assert_eq!(bench.status().state, RunState::Starting);
    for _ in 0..12 {
        driver.tick(Some(bench.sample(
            5 * GIBIBYTE,
            PressureState::Normal,
            Vec::new(),
        )));
        bench.clock.advance(SAMPLE);
    }
    // The trigger qualified, and nothing was removed.
    assert!(bench.root.join("a").exists());
    assert_eq!(
        blocked(&driver, Guard::Disk),
        vec![BlockedReason::ObservationOnly]
    );
    let status: AgentStatus = bench.status();
    assert_eq!(status.state, RunState::Running);
    assert_eq!(status.policy.revision, None);
    assert_eq!(status.policy.problem, None);
    let controller = status.controller.unwrap();
    assert!(controller.observation_only);
    assert_eq!(controller.summary, Summary::Warning);
    assert_eq!(bench.modes.lock().unwrap().len(), 0);

    // An authority record whose source text is not the text of its
    // revision is not usable: the agent still only observes.
    let state: AuthorityState = enabled(&bench.text, &bench.registry);
    let mut journal = bench.journal();
    journal
        .record_policy_revision(
            &state.active.as_ref().unwrap().revision,
            Some("schema_version = 1\n"),
        )
        .unwrap();
    journal
        .put_agent_record(
            AgentRecord::Authority,
            &state,
            None,
            wall(bench.clock.now()),
        )
        .unwrap();
    for _ in 0..4 {
        driver.tick(Some(bench.sample(
            5 * GIBIBYTE,
            PressureState::Normal,
            Vec::new(),
        )));
        bench.clock.advance(SAMPLE);
    }
    assert!(bench.root.join("a").exists());
    assert_eq!(
        bench.status().policy.problem.as_deref(),
        Some("policy_revision_source_not_usable")
    );
    assert_eq!(
        blocked(&driver, Guard::Disk),
        vec![BlockedReason::ObservationOnly]
    );
    assert!(driver.shutdown(&mut TestIdle(bench.clock.clone())).clean);
}

/// A notification center that denies is a capability in the status
/// record, not an error: the agent runs and observes, and posts nothing.
#[test]
fn a_denied_notification_center_is_reported_in_the_status_record() {
    use crate::notify::CenterAuthorization;
    use crate::notify::fake::FakeCenter;
    use svalnir_core::state::CapabilityState;

    let mut bench = Bench::new(TestClock::fixed(), validated_registry());
    let center = FakeCenter::new(CenterAuthorization::Denied);
    bench.center = Some(center.clone());
    let mut driver = bench.start();
    let mut notifications = None;
    // The worker is a real thread: a deadline of 5 s, as in the tests of
    // the notification service.
    for _ in 0..1_000 {
        driver.tick(Some(bench.sample(
            5 * GIBIBYTE,
            PressureState::Normal,
            Vec::new(),
        )));
        bench.clock.advance(30 * SECOND);
        notifications = bench
            .status()
            .capabilities
            .and_then(|summary| summary.notifications)
            .filter(|status| status.authorization == CenterAuthorization::Denied);
        if notifications.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let notifications = notifications.expect("the status has the capability");
    assert_eq!(notifications.state, CapabilityState::Denied);
    assert_eq!(bench.status().state, RunState::Running);
    assert!(center.with(|state| state.posted.is_empty()));
    assert!(driver.shutdown(&mut TestIdle(bench.clock.clone())).clean);
}

/// A status record of a driver with no capability summary has no
/// notification capability either; a client reads that as "not
/// recorded" (`observe::agent_capabilities`).
#[test]
fn a_status_record_with_no_summary_has_no_notification_capability() {
    let mut bench = Bench::new(TestClock::fixed(), validated_registry());
    let mut driver = bench.start();
    driver.tick(Some(bench.sample(
        5 * GIBIBYTE,
        PressureState::Normal,
        Vec::new(),
    )));
    assert_eq!(bench.status().capabilities, None);
    // The pressure reading of each sample reaches the notifier.
    assert_eq!(
        *bench.notes.2.lock().unwrap(),
        [Some(PressureState::Normal)]
    );
    assert!(driver.shutdown(&mut TestIdle(bench.clock.clone())).clean);
}

#[test]
fn an_automatic_eviction_removes_the_candidates_of_the_test_rule_and_recovers() {
    let mut bench = Bench::new(TestClock::fixed(), validated_registry());
    bench.seed_authority();
    let first: PathBuf = bench.file("a");
    let second: PathBuf = bench.file("b");
    let mut driver = bench.start();

    // The capacity is below the reclaim threshold for the sustain time.
    let mut ticks: u32 = 0;
    while (first.exists() || second.exists()) && ticks < 40 {
        driver.tick(Some(bench.sample(
            5 * GIBIBYTE,
            PressureState::Normal,
            Vec::new(),
        )));
        bench.clock.advance(SAMPLE);
        ticks += 1;
    }
    assert!(!first.exists() && !second.exists(), "after {ticks} ticks");
    // The window of 30 seconds qualified before the first removal.
    assert!(ticks >= 7, "{ticks}");
    // The emergency used the known candidates. No discovery started.
    let modes: Vec<PreparationMode> = bench.modes.lock().unwrap().clone();
    assert_ne!(modes.len(), 0);
    assert!(modes.iter().all(|mode| *mode == PreparationMode::KnownOnly));
    // Nothing was moved to the Trash of the fixture: an eviction is a
    // removal.
    assert_eq!(fs::read_dir(&bench.trash).unwrap().count(), 0);

    // The result is in the state of the controller and in the journal.
    driver.tick(Some(bench.sample(
        5 * GIBIBYTE,
        PressureState::Normal,
        Vec::new(),
    )));
    let state: &ControllerState = driver.controller_state();
    assert!(state.outstanding.is_none());
    let incident = &state.policy.disk.incidents[0];
    assert_eq!(incident.usage.consumed_bytes.get(), 2_000);
    assert_eq!(incident.usage.consumed_items.get(), 2);
    assert_eq!(incident.usage.reserved_bytes.get(), 0);
    let finished: Vec<Notification> = bench
        .notes
        .0
        .lock()
        .unwrap()
        .iter()
        .filter(|note| matches!(note, Notification::Finished { .. }))
        .cloned()
        .collect();
    assert!(
        matches!(
            finished.as_slice(),
            [Notification::Finished { guard: Guard::Disk, state, low_benefit: false, .. }]
                if state == "Completed"
        ),
        "{finished:?}"
    );
    // The coordinator gave the settled operation to the notifier, as an
    // automatic one, which has its notice from the controller only.
    let settled = bench.notes.1.lock().unwrap().clone();
    assert!(
        matches!(
            settled.as_slice(),
            [crate::coordinator::SettledOperation {
                automatic: true,
                stops_application: false,
                state: OperationState::Completed,
                ..
            }]
        ),
        "{settled:?}"
    );
    assert_eq!(crate::notify::settled_notice(&settled[0]), None);
    let journal = bench.journal();
    assert_eq!(journal.unsettled_operation_count().unwrap(), 0);
    let recorded: ControllerState = bench.controller_record();
    assert_eq!(
        recorded.policy.disk.incidents[0].usage.consumed_items.get(),
        2
    );
    assert!(!recorded.clean_stop);
    let status: AgentStatus = bench.status();
    assert_eq!(
        status.policy.revision,
        Some(PolicyRevisionId::new("policy_1").unwrap())
    );
    assert_eq!(status.executor_epoch.as_str(), "epoch_1");
    assert!(!status.limits.over_budget);

    // The capacity is at the recovery target, and the incident closes
    // after the stable time.
    for _ in 0..16 {
        driver.tick(Some(bench.sample(
            30 * GIBIBYTE,
            PressureState::Normal,
            Vec::new(),
        )));
        bench.clock.advance(SAMPLE);
    }
    assert_eq!(driver.controller_state().disk_incidents.len(), 0);
    assert_eq!(phase(&driver, Guard::Disk), GuardPhase::Normal);

    let report: ShutdownReport = driver.shutdown(&mut TestIdle(bench.clock.clone()));
    assert!(report.clean);
    assert!(bench.lifecycle().stopped_cleanly);
    assert!(bench.controller_record().clean_stop);
    assert_eq!(bench.status().state, RunState::Stopped);
    // The registration is released: a new lifetime has no reconciliation.
    let next = bench.start();
    assert_eq!(bench.lifecycle().unclean_stops, 0);
    drop(next);
}

#[test]
fn a_rule_in_the_proposed_state_removes_nothing_and_the_status_says_why() {
    let mut bench = Bench::new(TestClock::fixed(), proposed_registry());
    bench.seed_authority();
    let file: PathBuf = bench.file("a");
    let mut driver = bench.start();
    for _ in 0..20 {
        driver.tick(Some(bench.sample(
            5 * GIBIBYTE,
            PressureState::Normal,
            Vec::new(),
        )));
        bench.clock.advance(SAMPLE);
    }
    assert!(file.exists());
    assert_eq!(
        blocked(&driver, Guard::Disk),
        vec![BlockedReason::RuleNotValidated {
            rule: "test.cache".to_owned()
        }]
    );
    assert_eq!(bench.modes.lock().unwrap().len(), 0);
    assert_eq!(bench.journal().unsettled_operation_count().unwrap(), 0);
    let controller = bench.status().controller.unwrap();
    assert_eq!(controller.summary, Summary::Warning);
}

/// An `FSEvents` invalidation of the candidate source makes the controller
/// evaluate again, and in a warning it asks for a discovery before the set
/// is old. The status record has the capability of the source.
#[test]
fn an_invalidation_asks_for_a_discovery_in_a_warning() {
    let mut bench = Bench::new(TestClock::fixed(), validated_registry());
    bench.seed_authority();
    bench.center = Some(crate::notify::fake::FakeCenter::new(
        crate::notify::CenterAuthorization::Authorized,
    ));
    let mut driver = bench.start();
    for _ in 0..3 {
        driver.tick(Some(bench.sample(
            15 * GIBIBYTE,
            PressureState::Normal,
            Vec::new(),
        )));
        bench.clock.advance(SAMPLE);
    }
    assert_eq!(
        bench.modes.lock().unwrap().as_slice(),
        [PreparationMode::Refresh]
    );
    // A change of an approved root: the next tick, with no new sample,
    // asks for a discovery again.
    bench.invalidated.store(true, Ordering::SeqCst);
    driver.tick(None);
    assert_eq!(
        bench.modes.lock().unwrap().as_slice(),
        [PreparationMode::Refresh, PreparationMode::Refresh]
    );
    assert!(!bench.invalidated.load(Ordering::SeqCst));
    let watch = bench
        .status()
        .capabilities
        .and_then(|summary| summary.catalog_watch)
        .expect("the status has the capability of the source");
    assert_eq!(
        watch.state,
        crate::runtime::invalidation::CatalogWatchState::Available
    );
    assert!(driver.shutdown(&mut TestIdle(bench.clock.clone())).clean);
}

#[test]
fn the_agent_over_its_own_budget_reduces_its_optional_work() {
    let mut bench = Bench::new(TestClock::fixed(), validated_registry());
    bench.seed_authority();
    let mut driver = bench.start();
    // A warning state with no pressure: the candidates are prepared with
    // a discovery.
    for _ in 0..3 {
        driver.tick(Some(bench.sample(
            15 * GIBIBYTE,
            PressureState::Normal,
            Vec::new(),
        )));
        bench.clock.advance(SAMPLE);
    }
    assert_eq!(
        bench.modes.lock().unwrap().as_slice(),
        [PreparationMode::Refresh]
    );
    // The footprint is above the budget: no further discovery starts.
    bench.footprint.store(512 * 1024 * 1024, Ordering::SeqCst);
    bench.clock.advance(1_200 * SECOND);
    for _ in 0..3 {
        driver.tick(Some(bench.sample(
            15 * GIBIBYTE,
            PressureState::Normal,
            Vec::new(),
        )));
        bench.clock.advance(SAMPLE);
    }
    assert_eq!(bench.modes.lock().unwrap().len(), 1);
    let status: AgentStatus = bench.status();
    assert!(status.limits.over_budget);
    assert!(status.limits.optional_work_reduced);
    assert_eq!(status.limits.footprint_bytes, Some(512 * 1024 * 1024));
}

#[test]
fn a_wake_starts_each_window_again() {
    let mut bench = Bench::new(TestClock::fixed(), validated_registry());
    bench.seed_authority();
    let file: PathBuf = bench.file("a");
    let mut driver = bench.start();
    for _ in 0..5 {
        driver.tick(Some(bench.sample(
            5 * GIBIBYTE,
            PressureState::Normal,
            Vec::new(),
        )));
        bench.clock.advance(SAMPLE);
    }
    assert_eq!(phase(&driver, Guard::Disk), GuardPhase::Qualifying);
    // The host slept: the window of before the sleep does not continue.
    let mut woke: Sample = bench.sample(5 * GIBIBYTE, PressureState::Normal, Vec::new());
    woke.woke = true;
    driver.tick(Some(woke));
    bench.clock.advance(SAMPLE);
    for _ in 0..3 {
        driver.tick(Some(bench.sample(
            5 * GIBIBYTE,
            PressureState::Normal,
            Vec::new(),
        )));
        bench.clock.advance(SAMPLE);
    }
    assert!(file.exists());
    assert_eq!(phase(&driver, Guard::Disk), GuardPhase::Qualifying);
    assert_eq!(bench.clock.discontinuities.load(Ordering::SeqCst), 1);
}

/// The memory samples of a child test: critical pressure with the child
/// as the one eligible job.
fn child_sample(bench: &Bench, member: &ProcessIdentity) -> Sample {
    let at: u64 = bench.clock.now();
    bench.sample(
        100 * GIBIBYTE,
        PressureState::Critical,
        vec![application(
            "members-child",
            vec![member.clone()],
            3 * GIBIBYTE,
            at,
        )],
    )
}

/// Ticks with critical samples until the controller has a plan in
/// progress with an admitted operation.
fn run_to_operation(bench: &Bench, driver: &mut Driver, member: &ProcessIdentity) -> OperationId {
    for _ in 0..40 {
        driver.tick(Some(child_sample(bench, member)));
        if let Some(operation_id) = driver
            .controller_state()
            .outstanding
            .as_ref()
            .and_then(|outstanding| outstanding.operation_id.clone())
        {
            return operation_id;
        }
        bench.clock.advance(SAMPLE);
        std::thread::sleep(Duration::from_millis(5));
    }
    panic!(
        "no operation was admitted: {:?}",
        driver.controller_status()
    );
}

#[test]
fn an_automatic_stop_ends_a_child_of_the_test_and_charges_one_slot() {
    let mut bench = Bench::new(TestClock::host(), validated_registry());
    bench.seed_authority();
    let mut child = spawn_child(false);
    let member: ProcessIdentity = child_identity(child.pid());
    let mut driver = bench.start();

    let operation_id: OperationId = run_to_operation(&bench, &mut driver, &member);
    // The graceful request ends the child. The exit is observed, and
    // then the operation is finished.
    let limit: Instant = Instant::now() + Duration::from_secs(20);
    // The child ends at the graceful request. Until its exit, the clock
    // of the test moves less than the real time does, so the grace
    // period of the plan does not end and no force step can be the cause
    // of the exit on a slow host.
    while child.0.try_wait().unwrap().is_none() {
        assert!(Instant::now() < limit, "the child did not end");
        std::thread::sleep(Duration::from_millis(20));
        bench.clock.advance(SECOND / 100);
        driver.tick(None);
    }
    while driver.controller_state().outstanding.is_some() {
        assert!(Instant::now() < limit, "the operation did not finish");
        bench.clock.advance(SECOND);
        std::thread::sleep(Duration::from_millis(20));
        *bench.pressure.lock().unwrap() = PressureState::Normal;
        driver.tick(None);
    }
    let status = child.0.wait().unwrap();
    assert_eq!(status.signal(), Some(libc::SIGTERM));

    let view = driver.operation(&operation_id).unwrap();
    assert_eq!(view.phase, Phase::Finished);
    assert_eq!(view.operation.state(), &OperationState::Completed);
    let incident = driver.controller_state().policy.memory.incident.unwrap();
    assert_eq!((incident.consumed_slots, incident.reserved_slots), (1, 0));
    assert!(bench.notes.0.lock().unwrap().iter().any(|note| matches!(
        note,
        Notification::Finished { guard: Guard::Memory, state, .. } if state == "Completed"
    )));
    assert_eq!(bench.journal().unsettled_operation_count().unwrap(), 0);
    assert!(driver.shutdown(&mut TestIdle(bench.clock.clone())).clean);
}

#[test]
fn a_stop_during_a_grace_period_sends_no_force_step_and_is_clean() {
    let mut bench = Bench::new(TestClock::host(), validated_registry());
    bench.seed_authority();
    let mut child = spawn_child(true);
    let member: ProcessIdentity = child_identity(child.pid());
    let mut driver = bench.start();

    let operation_id: OperationId = run_to_operation(&bench, &mut driver, &member);
    // The graceful request is submitted, and the child ignores it. The
    // operation waits for the grace period of 10 seconds.
    for _ in 0..3 {
        bench.clock.advance(SECOND);
        driver.tick(None);
    }
    assert!(driver.controller_state().outstanding.is_some());
    assert!(child.is_running());
    let view = driver.operation(&operation_id).unwrap();
    let graceful = view
        .operation
        .steps()
        .iter()
        .find(|step| step.action_class() == &ActionClass::RequestApplicationExit)
        .unwrap();
    assert!(graceful.progress().dispatch().is_possibly_submitted());
    assert_ne!(view.phase, Phase::Finished);

    // The stop request arrives in the grace period.
    let report: ShutdownReport = driver.shutdown(&mut TestIdle(bench.clock.clone()));
    assert!(report.clean);
    // No force step was dispatched: the child is alive.
    std::thread::sleep(Duration::from_millis(100));
    assert!(child.is_running());

    let journal = bench.journal();
    let operation = journal.operation(&operation_id).unwrap().unwrap();
    assert!(operation.state().is_settled());
    assert_ne!(operation.state(), &OperationState::Completed);
    let force = operation
        .steps()
        .iter()
        .find(|step| step.action_class() == &ActionClass::ForceApplicationExit)
        .unwrap();
    assert!(!force.progress().dispatch().is_possibly_submitted());
    // The checkpoint: the slot of the submitted request stays charged.
    let recorded: ControllerState = bench.controller_record();
    assert!(recorded.clean_stop);
    assert!(recorded.outstanding.is_none());
    assert_eq!(recorded.policy.memory.incident.unwrap().consumed_slots, 1);
    assert!(bench.lifecycle().stopped_cleanly);
}

#[test]
fn a_start_after_a_crash_reconciles_and_does_not_act_again() {
    let mut bench = Bench::new(TestClock::host(), validated_registry());
    bench.seed_authority();
    let mut child = spawn_child(true);
    let member: ProcessIdentity = child_identity(child.pid());
    let mut driver = bench.start();
    let operation_id: OperationId = run_to_operation(&bench, &mut driver, &member);
    bench.clock.advance(SECOND);
    driver.tick(None);
    // The crash: the process ends with the graceful request submitted and
    // no record of a stop.
    drop(driver);
    assert!(child.is_running());

    let mut driver = bench.start();
    // The operation of the lifetime before this one was reconciled before
    // anything else. It is settled or its effect is not known, and it is
    // never dispatched again.
    let journal = bench.journal();
    let operation = journal.operation(&operation_id).unwrap().unwrap();
    assert_eq!(operation.executor_epoch().as_str(), "epoch_1");
    assert_ne!(operation.state(), &OperationState::Admitted);
    assert_ne!(operation.state(), &OperationState::Completed);
    let lifecycle: LifecycleRecord = bench.lifecycle();
    assert_eq!(lifecycle.unclean_stops, 1);
    assert!(!lifecycle.stopped_cleanly);

    // The incident of before the crash is not established, and the plan
    // that was in progress stays charged.
    let state: &ControllerState = driver.controller_state();
    assert!(state.outstanding.is_none());
    let record = state.memory_incident.clone().unwrap();
    assert!(!record.established);
    assert!(record.unknown_outcome);
    assert_eq!(state.policy.memory.incident.unwrap().consumed_slots, 1);

    // The pressure continues. The restart backoff is in effect at the
    // start; the windows of the new lifetime qualify after it, and then
    // the incident that is not established inhibits the guard.
    driver.tick(Some(child_sample(&bench, &member)));
    assert!(bench.status().restart_backoff);
    bench.clock.advance(SAMPLE);
    let mut reasons: Vec<BlockedReason> = Vec::new();
    for _ in 0..12 {
        driver.tick(Some(child_sample(&bench, &member)));
        for reason in blocked(&driver, Guard::Memory) {
            if !reasons.contains(&reason) {
                reasons.push(reason);
            }
        }
        bench.clock.advance(SAMPLE);
    }
    assert_eq!(reasons, vec![BlockedReason::IncidentStateNotEstablished]);
    assert!(driver.controller_state().outstanding.is_none());
    let status: AgentStatus = bench.status();
    assert_eq!(status.unclean_stops, 1);
    assert_eq!(status.executor_epoch.as_str(), "epoch_2");
    // The child got no second request and no force step.
    assert!(child.is_running());
    let operation = bench.journal().operation(&operation_id).unwrap().unwrap();
    let force = operation
        .steps()
        .iter()
        .find(|step| step.action_class() == &ActionClass::ForceApplicationExit)
        .unwrap();
    assert!(!force.progress().dispatch().is_possibly_submitted());
    assert!(driver.shutdown(&mut TestIdle(bench.clock.clone())).clean);
    // A clean stop resets the count of the restart backoff.
    drop(bench.start());
    assert_eq!(bench.lifecycle().unclean_stops, 0);
}

#[test]
fn a_second_agent_on_the_same_journal_is_busy_and_changes_nothing() {
    let mut bench = Bench::new(TestClock::fixed(), validated_registry());
    let driver = bench.start();
    assert!(matches!(
        bench.try_start(),
        DriverStart::Busy {
            holder: CoordinatorRole::Agent
        }
    ));
    assert_eq!(bench.status().executor_epoch.as_str(), "epoch_1");
    drop(driver);
}

#[test]
fn an_agent_that_finds_the_lock_of_a_client_is_busy_with_a_client_holder() {
    let mut bench = Bench::new(TestClock::fixed(), validated_registry());
    // A client holds the lock as a transient coordinator.
    let client =
        CoordinatorLock::try_acquire(&journal_path(&bench.state), CoordinatorRole::Client).unwrap();
    assert!(matches!(
        bench.try_start(),
        DriverStart::Busy {
            holder: CoordinatorRole::Client
        }
    ));
    // The client releases the lock, and the agent then starts.
    drop(client);
    let driver = bench.start();
    drop(driver);
}

/// Requests the stop of a service when a test ends, also with a panic.
struct StopAtEnd(StopHandle);

impl Drop for StopAtEnd {
    fn drop(&mut self) {
        self.0.request_stop();
    }
}

/// A collector that gives quiet samples at the time of the clock.
struct QuietCollector {
    clock: TestClock,
    collections: Arc<AtomicU64>,
}

impl Collector for QuietCollector {
    fn collect(&mut self) -> Sample {
        self.collections.fetch_add(1, Ordering::SeqCst);
        let at: u64 = self.clock.now();
        Sample {
            observations: Observations {
                volumes: vec![volume(Some(100 * GIBIBYTE), at)],
                memory: memory(Some(PressureState::Normal), at, Vec::new()),
                candidates: None,
            },
            woke: false,
            control_plane: Some(Vec::new()),
            degraded: Vec::new(),
            sleep_time: None,
        }
    }
}

/// A manual Trash plan of a client for the entry `name` below the root.
fn trash_plan(bench: &Bench, name: &str) -> Plan {
    let mut content: PlanContent = trash_content(bench, name);
    content.plan_id = PlanId::new("client-plan").unwrap();
    Plan::seal(content).unwrap()
}

/// A manual plan that moves the files `names` below the root to Trash,
/// one step for each file.
fn trash_plan_of(bench: &Bench, plan: &str, names: &[&str]) -> Plan {
    let mut content: PlanContent = trash_content(bench, names[0]);
    content.plan_id = PlanId::new(plan).unwrap();
    for name in &names[1..] {
        let mut more: PlanContent = trash_content(bench, name);
        let target_id = TargetId::new(format!("client-target-{name}")).unwrap();
        more.targets[0].target_id = target_id.clone();
        more.steps[0].target_id = target_id;
        more.steps[0].step_id = StepId::new(format!("client-step-{name}")).unwrap();
        content.targets.append(&mut more.targets);
        content.steps.append(&mut more.steps);
    }
    content.limits.work = Some(WorkCharge::new(
        Bytes::new(10 * names.len() as u64),
        EntryCount::new(names.len() as u64),
    ));
    Plan::seal(content).unwrap()
}

fn trash_content(bench: &Bench, name: &str) -> PlanContent {
    let now: u64 = bench.clock.now();
    let target_id = TargetId::new("client-target").unwrap();
    PlanContent {
        schema_version: PLAN_SCHEMA_VERSION,
        plan_id: PlanId::new("client-plan").unwrap(),
        principal: Principal {
            uid: user(),
            session: None,
            role: ClientRole::Cli,
        },
        trigger: Trigger::manual(),
        authority: AuthorityBinding {
            policy_revision: PolicyRevisionId::new("policy_1").unwrap(),
            action_grants: Vec::new(),
            privilege_grant: None,
        },
        executor: ExecutorRole::User,
        targets: vec![PlanTarget {
            target_id: target_id.clone(),
            binding: TargetBinding::File(FileBinding {
                root_id: RootId::new(ROOT_ID).unwrap(),
                root_path: LosslessPath::from_path(&bench.root).unwrap(),
                root_object: object_of(&bench.root),
                relative_entry: LosslessPath::from_bytes(name.as_bytes()).unwrap(),
                volume_id: VolumeId::new(VOLUME).unwrap(),
                mount_id: MountId::new(MOUNT).unwrap(),
                object_type: FileObjectType::RegularFile,
                owner: user(),
                object: Some(object_of(&bench.root.join(name))),
                rule: None,
                layout: None,
                charge: WorkCharge::new(Bytes::new(10), EntryCount::new(1)),
            }),
        }],
        steps: vec![PlannedStep {
            step_id: StepId::new("client-step").unwrap(),
            action_class: ActionClass::MoveToTrash,
            target_id,
        }],
        limits: PlanLimits {
            work: Some(WorkCharge::new(Bytes::new(10), EntryCount::new(1))),
            execution_deadline: Nanoseconds::new(60 * SECOND),
            grace: None,
            verification_window: Nanoseconds::new(5 * SECOND),
            escalation: Escalation::None,
        },
        validity: Validity {
            clock_domain: clock_domain(),
            boot_id: boot(),
            created_at: MonotonicNanos::new(now),
            expires_at: MonotonicNanos::new(now + 120 * SECOND),
            created_wall: wall(now),
        },
    }
}

fn apply_request(plan: &Plan, request: &str, now: u64) -> QueuedRequest {
    QueuedRequest {
        request_id: RequestId::new(request).unwrap(),
        principal: plan.principal.clone(),
        body: RequestBody::Apply {
            approval: PlanApproval {
                plan_id: plan.plan_id.clone(),
                digest: plan.digest().clone(),
            },
        },
        enqueued_at: wall(now),
    }
}

#[test]
fn a_stop_claims_no_queued_request_and_is_clean() {
    let mut bench = Bench::new(TestClock::fixed(), validated_registry());
    bench.seed_authority();
    let file: PathBuf = bench.file("client-file");
    let mut driver = bench.start();
    driver.tick(None);
    // A client writes a request while the agent stops.
    let plan: Plan = trash_plan(&bench, "client-file");
    let mut client = bench.journal();
    client.record_plan(&plan).unwrap();
    let request = apply_request(&plan, "request-1", bench.clock.now());
    client.enqueue_request(&request).unwrap();

    let report: ShutdownReport = driver.shutdown(&mut TestIdle(bench.clock.clone()));
    // The request is not claimed and not executed: it stays in the queue
    // for the next coordinator, and the stop is clean.
    assert!(report.clean);
    assert!(file.exists());
    assert_eq!(
        client.request_status(&request.request_id).unwrap(),
        Some(RequestStatus::Queued)
    );
    assert_eq!(client.unsettled_operation_count().unwrap(), 0);
    assert!(bench.lifecycle().stopped_cleanly);
    // The next agent serves the request.
    let mut driver = bench.start();
    driver.tick(None);
    driver.tick(None);
    assert!(!file.exists());
}

#[test]
fn a_stop_ends_the_operation_of_a_client_before_its_next_step_and_is_clean() {
    let mut bench = Bench::new(TestClock::fixed(), validated_registry());
    bench.seed_authority();
    // More targets than the work units of one tick.
    let names: Vec<String> = (0..12).map(|index| format!("client-{index:02}")).collect();
    let names: Vec<&str> = names.iter().map(String::as_str).collect();
    let files: Vec<PathBuf> = names.iter().map(|name| bench.file(name)).collect();
    let present = |files: &[PathBuf]| files.iter().filter(|file| file.exists()).count();
    let mut driver = bench.start();
    let plan: Plan = trash_plan_of(&bench, "client-plan", &names);
    let mut client = bench.journal();
    client.record_plan(&plan).unwrap();
    let request = apply_request(&plan, "request-1", bench.clock.now());
    client.enqueue_request(&request).unwrap();
    // One tick claims the request and does a part of the targets.
    driver.tick(None);
    let left: usize = present(&files);
    assert!(left > 0 && left < files.len(), "{left}");
    let Some(RequestStatus::Completed {
        completion: RequestCompletion::Operation { operation_id },
    }) = client.request_status(&request.request_id).unwrap()
    else {
        panic!("the request was not admitted");
    };

    let report: ShutdownReport = driver.shutdown(&mut TestIdle(bench.clock.clone()));
    // The operation of the client got the stop request: no further step
    // was dispatched, it is settled, and the stop is clean.
    assert!(report.clean);
    assert_eq!(present(&files), left);
    let operation = client.operation(&operation_id).unwrap().unwrap();
    assert!(operation.state().is_settled());
    let last = operation.steps().last().unwrap();
    assert_eq!(
        last.results()[0].stop_reason,
        svalnir_core::action::StopReason::Canceled
    );
    assert!(bench.lifecycle().stopped_cleanly);
}

#[test]
fn a_client_request_through_the_queue_is_served_while_the_loop_runs() {
    let mut bench = Bench::new(TestClock::host(), validated_registry());
    bench.seed_authority();
    let file: PathBuf = bench.file("client-file");
    let driver = bench.start();
    let stop: StopHandle = StopHandle::new();
    let collections: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));
    let collector = Box::new(QuietCollector {
        clock: bench.clock.clone(),
        collections: Arc::clone(&collections),
    });
    // The sender is the pressure event source of the test.
    let (events, receiver) = std::sync::mpsc::sync_channel::<()>(4);
    let settings = ServiceSettings {
        // Longer than the test, so that only a pressure event starts a
        // second collection.
        sample_interval: Duration::from_secs(120),
        pressure_sample_interval: Duration::from_millis(100),
        idle_interval: Duration::from_millis(50),
    };
    let service_stop: StopHandle = stop.clone();
    let clock: Arc<dyn AgentClock> = Arc::new(bench.clock.clone());
    // A failed assertion stops the service, so that its thread does not
    // use the temporary directory after the bench removed it.
    let _stop_at_end = StopAtEnd(stop.clone());
    let service = std::thread::spawn(move || {
        run(driver, collector, receiver, settings, &service_stop, clock)
    });

    // The client: a second connection writes the plan and the request.
    let plan: Plan = trash_plan(&bench, "client-file");
    let mut client = bench.journal();
    client.record_plan(&plan).unwrap();
    let request_id = RequestId::new("request-1").unwrap();
    client
        .enqueue_request(&QueuedRequest {
            request_id: request_id.clone(),
            principal: plan.principal.clone(),
            body: RequestBody::Apply {
                approval: PlanApproval {
                    plan_id: plan.plan_id.clone(),
                    digest: plan.digest().clone(),
                },
            },
            enqueued_at: wall(bench.clock.now()),
        })
        .unwrap();
    let limit: Instant = Instant::now() + Duration::from_secs(20);
    let operation_id: OperationId = loop {
        if let Some(RequestStatus::Completed { completion }) =
            client.request_status(&request_id).unwrap()
        {
            match completion {
                RequestCompletion::Operation { operation_id } => break operation_id,
                other => panic!("the request was not admitted: {other:?}"),
            }
        }
        assert!(Instant::now() < limit, "the request was not served");
        std::thread::sleep(Duration::from_millis(20));
    };
    loop {
        let settled: bool = client
            .operation(&operation_id)
            .unwrap()
            .is_some_and(|operation| operation.state().is_settled());
        if settled {
            break;
        }
        assert!(Instant::now() < limit, "the operation did not settle");
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(!file.exists());
    assert!(bench.trash.join("client-file").exists());

    // A pressure event starts a collection before the sample interval.
    let before: u64 = collections.load(Ordering::SeqCst);
    events.send(()).unwrap();
    let limit: Instant = Instant::now() + Duration::from_secs(5);
    while collections.load(Ordering::SeqCst) == before {
        assert!(Instant::now() < limit, "the event started no collection");
        std::thread::sleep(Duration::from_millis(10));
    }
    // The loop wrote the status while it served the request.
    let status: AgentStatus = bench.status();
    assert_eq!(status.state, RunState::Running);
    assert_eq!(status.controller.unwrap().summary, Summary::Normal);

    stop.request_stop();
    let report: ShutdownReport = service.join().unwrap();
    assert!(report.clean);
    assert_eq!(bench.status().state, RunState::Stopped);
    assert!(bench.lifecycle().stopped_cleanly);
    // The lock is free: a client can start a transient coordinator.
    drop(bench.start());
}

#[test]
fn the_disk_guard_policy_of_the_fixture_names_the_test_rule() {
    // The fixture and the registry agree, so a test of a refusal shows
    // the lifecycle state and not a missing rule.
    let registry = proposed_registry();
    let state: AuthorityState = enabled(&config_text(&[]), &registry);
    let active = state.active.as_ref().unwrap();
    assert!(
        active
            .scope
            .rules(PolicyId::DiskGuard)
            .contains(&rule(svalnir_core::rule::LifecycleState::Proposed).reference)
    );
}

/// Ticks with a low-capacity sample each five seconds to the last sample
/// before the entry window of 30 seconds is complete.
fn run_to_the_end_of_the_window(bench: &Bench, driver: &mut Driver) {
    for _ in 0..6 {
        driver.tick(Some(bench.sample(
            5 * GIBIBYTE,
            PressureState::Normal,
            Vec::new(),
        )));
        bench.clock.advance(SAMPLE);
    }
    assert_eq!(phase(driver, Guard::Disk), GuardPhase::Qualifying);
    assert_eq!(bench.modes.lock().unwrap().len(), 0);
}

#[test]
fn the_first_sample_after_a_wake_does_not_complete_a_window() {
    let mut bench = Bench::new(TestClock::fixed(), validated_registry());
    bench.seed_authority();
    let file: PathBuf = bench.file("a");
    let mut driver = bench.start();
    run_to_the_end_of_the_window(&bench, &mut driver);
    // This sample would complete the window. The host slept before it:
    // the evaluation of the same tick has the new continuity generation,
    // and the trigger is not ready.
    let mut woke: Sample = bench.sample(5 * GIBIBYTE, PressureState::Normal, Vec::new());
    woke.woke = true;
    driver.tick(Some(woke));
    assert_eq!(bench.clock.discontinuities.load(Ordering::SeqCst), 1);
    assert_eq!(phase(&driver, Guard::Disk), GuardPhase::Qualifying);
    assert_eq!(bench.modes.lock().unwrap().len(), 0);
    assert!(driver.controller_state().outstanding.is_none());
    assert!(file.exists());
}

#[test]
fn a_sleep_that_the_clock_finds_between_two_samples_starts_each_window_again() {
    let mut bench = Bench::new(TestClock::fixed(), validated_registry());
    bench.seed_authority();
    let file: PathBuf = bench.file("a");
    let mut driver = bench.start();
    run_to_the_end_of_the_window(&bench, &mut driver);
    // The clock finds the sleep at the tick. The collector did not report
    // it: its sample is from before its next reading of the sleep time.
    bench.clock.slept.store(true, Ordering::SeqCst);
    driver.tick(Some(bench.sample(
        5 * GIBIBYTE,
        PressureState::Normal,
        Vec::new(),
    )));
    assert_eq!(bench.clock.discontinuities.load(Ordering::SeqCst), 1);
    assert_eq!(phase(&driver, Guard::Disk), GuardPhase::Qualifying);
    assert_eq!(bench.modes.lock().unwrap().len(), 0);
    assert!(driver.controller_state().outstanding.is_none());
    assert!(file.exists());
}

#[test]
fn a_pause_in_the_journal_applies_before_the_coordinator_dispatches_the_next_step() {
    let mut bench = Bench::new(TestClock::host(), validated_registry());
    let active: AuthorityState = bench.seed_authority();
    let mut child = spawn_child(true);
    let member: ProcessIdentity = child_identity(child.pid());
    let mut driver = bench.start();
    let operation_id: OperationId = run_to_operation(&bench, &mut driver, &member);
    bench.clock.advance(SECOND);
    driver.tick(None);
    assert!(child.is_running());

    // The user pauses the automation in the grace period. The grace
    // period then ends before the next tick.
    bench.write_authority(&paused(&active, bench.clock.now()));
    bench.clock.advance(15 * SECOND);
    for _ in 0..3 {
        driver.tick(None);
        bench.clock.advance(SECOND);
        std::thread::sleep(Duration::from_millis(20));
    }
    // The force step was not dispatched with the authority of before the
    // pause: the child of the test is alive.
    assert!(child.is_running());
    let operation = bench.journal().operation(&operation_id).unwrap().unwrap();
    let force = operation
        .steps()
        .iter()
        .find(|step| step.action_class() == &ActionClass::ForceApplicationExit)
        .unwrap();
    assert!(!force.progress().dispatch().is_possibly_submitted());
    assert!(driver.controller_status().unwrap().paused);
    let _report: ShutdownReport = driver.shutdown(&mut TestIdle(bench.clock.clone()));
}

#[test]
fn a_pause_and_a_resume_between_two_ticks_need_a_measurement_after_them() {
    let mut bench = Bench::new(TestClock::host(), validated_registry());
    let active: AuthorityState = bench.seed_authority();
    let mut child = spawn_child(false);
    let member: ProcessIdentity = child_identity(child.pid());
    let mut driver = bench.start();
    // Before each tick the user pauses and resumes the automation. The
    // agent reads the record one time for each tick, so the controller
    // sees no pause. The sample of the tick is from before the resume.
    // More ticks than `run_to_operation` needs for an admission.
    for _ in 0..45 {
        let before: Sample = child_sample(&bench, &member);
        bench.clock.advance(SECOND);
        bench.write_authority(&paused(&active, bench.clock.now()));
        bench.write_authority(&active);
        driver.tick(Some(before));
        assert!(
            driver.controller_state().outstanding.is_none(),
            "a sample from before the resume supported a plan"
        );
        bench.clock.advance(SAMPLE - SECOND);
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(child.is_running());
    assert!(!driver.controller_status().unwrap().paused);
    assert_eq!(
        blocked(&driver, Guard::Memory),
        vec![BlockedReason::AwaitingFreshMeasurement]
    );
    // With no further control change, the measurements after the resume
    // support the plan.
    let _operation: OperationId = run_to_operation(&bench, &mut driver, &member);
    let _report: ShutdownReport = driver.shutdown(&mut TestIdle(bench.clock.clone()));
}

#[test]
fn a_lifecycle_record_that_is_not_readable_gives_the_longest_restart_backoff() {
    for record in [
        // A record with a field that this build does not know.
        serde_json::json!({ "schema_version": 1, "of_a_later_build": true }),
        // A record of a different schema version that says "clean".
        serde_json::json!({
            "schema_version": 99,
            "last_start": null,
            "last_stop": null,
            "stopped_cleanly": true,
            "unclean_stops": 0,
            "degraded_reason": null,
        }),
    ] {
        let mut bench = Bench::new(TestClock::fixed(), validated_registry());
        bench.seed_authority();
        bench
            .journal()
            .put_agent_record(
                AgentRecord::Lifecycle,
                &record,
                None,
                wall(bench.clock.now()),
            )
            .unwrap();
        let mut driver = bench.start();
        let lifecycle: LifecycleRecord = bench.lifecycle();
        assert!(!lifecycle.stopped_cleanly);
        assert_eq!(
            super::restart_backoff(lifecycle.unclean_stops),
            super::RESTART_BACKOFF_MAX
        );
        // The backoff of one stop that was not clean is 10 seconds. One
        // minute later the backoff of this start is still in effect.
        bench.clock.advance(60 * SECOND);
        let mut sample: Sample = bench.sample(100 * GIBIBYTE, PressureState::Normal, Vec::new());
        // The names of the collectors do not push the condition of the
        // runtime out of the bounded list.
        sample.degraded = (0..super::MAX_DEGRADED_REASONS)
            .map(|index| format!("collector_{index}"))
            .collect();
        driver.tick(Some(sample));
        let status: AgentStatus = bench.status();
        assert!(status.restart_backoff);
        assert_eq!(status.degraded.len(), super::MAX_DEGRADED_REASONS);
        let reason: String = bench.lifecycle().degraded_reason.unwrap();
        assert_eq!(status.degraded.first(), Some(&reason));
    }
}

/// A collector whose second collection ends with a panic.
struct FailingCollector {
    quiet: QuietCollector,
}

impl Collector for FailingCollector {
    fn collect(&mut self) -> Sample {
        assert!(
            self.quiet.collections.load(Ordering::SeqCst) == 0,
            "the collector of the test fails"
        );
        self.quiet.collect()
    }
}

#[test]
fn a_panic_of_the_collector_thread_stops_the_service_and_the_stop_is_not_clean() {
    let mut bench = Bench::new(TestClock::fixed(), validated_registry());
    let driver = bench.start();
    let stop: StopHandle = StopHandle::new();
    let _stop_at_end = StopAtEnd(stop.clone());
    let collector = Box::new(FailingCollector {
        quiet: QuietCollector {
            clock: bench.clock.clone(),
            collections: Arc::new(AtomicU64::new(0)),
        },
    });
    let (_events, receiver) = std::sync::mpsc::sync_channel::<()>(1);
    let settings = ServiceSettings {
        sample_interval: Duration::from_millis(50),
        pressure_sample_interval: Duration::from_millis(50),
        idle_interval: Duration::from_millis(20),
    };
    let service_stop: StopHandle = stop.clone();
    let clock: Arc<dyn AgentClock> = Arc::new(bench.clock.clone());
    let (done, result) = std::sync::mpsc::channel::<ShutdownReport>();
    let service = std::thread::spawn(move || {
        let report: ShutdownReport =
            run(driver, collector, receiver, settings, &service_stop, clock);
        let _sent = done.send(report);
    });
    // The service ends with no stop request. Without the stop of the
    // driver loop it would run with no observation until a signal.
    let report: ShutdownReport = result
        .recv_timeout(Duration::from_secs(20))
        .expect("the service did not end after the panic of its collector");
    service.join().unwrap();
    assert!(!report.clean);
    assert!(stop.is_stopped());
    assert!(!stop.was_requested());
    // The driver released the coordinator lock: a new lifetime starts.
    drop(bench.start());
}

#[test]
fn the_open_incidents_of_the_controller_are_named_to_the_journal_prune() {
    use svalnir_core::grant::{IncidentBudget, InstanceInhibition};
    use svalnir_core::id::IncidentId;
    use svalnir_core::policy::PolicyId;

    use crate::controller::MemoryIncidentRecord;

    let opened = WallTime::from_unix(1_794_830_400, 0).unwrap();
    let incident = MemoryIncidentRecord {
        incident_id: IncidentId::new("incident_1").unwrap(),
        budget: IncidentBudget::open(
            IncidentId::new("incident_1").unwrap(),
            PolicyId::MemoryGuard,
            &AuthorityState::new(user()),
            &InstanceInhibition::default(),
            opened,
        ),
        opened_in: ExecutorEpochId::new("epoch_1").unwrap(),
        established: true,
        unknown_outcome: false,
        observe_until: None,
        backoff: None,
        last_refusal: None,
        refusals: 0,
    };

    let mut state = ControllerState::default();
    assert_eq!(state.open_incident_ids(), Vec::new());
    // The prune keeps the usage row of each identity in the list. The
    // start time of the incident does not limit the prune: the row has the
    // budget, and no record of the history is necessary for it.
    let mut unknown_start = incident;
    unknown_start.budget.history.clear();
    state.memory_incident = Some(unknown_start);
    assert_eq!(
        state.open_incident_ids(),
        vec![IncidentId::new("incident_1").unwrap()]
    );
}

/// Ticks with the critical samples of the child `ticks` times, with a wake
/// at the tick `wake` when that has a value. Returns the driver.
fn critical_ticks(
    bench: &mut Bench,
    member: &ProcessIdentity,
    ticks: usize,
    wake: Option<usize>,
) -> Box<Driver> {
    let mut driver = bench.start();
    for index in 0..ticks {
        let mut made: Sample = child_sample(bench, member);
        made.woke = wake == Some(index);
        driver.tick(Some(made));
        bench.clock.advance(SAMPLE);
    }
    driver
}

#[test]
fn a_wake_starts_the_window_of_the_memory_guard_again() {
    // Control: six critical samples with no wake qualify the window of
    // 15 seconds, and the controller has a plan in progress.
    let mut control = Bench::new(TestClock::host(), validated_registry());
    control.seed_authority();
    let child = spawn_child(true);
    let member: ProcessIdentity = child_identity(child.pid());
    let driver = critical_ticks(&mut control, &member, 6, None);
    assert!(driver.controller_state().outstanding.is_some());
    drop(driver);
    drop(child);

    // The same six samples with a wake at the fourth one: the window of
    // before the sleep does not continue, so no plan is made.
    let mut bench = Bench::new(TestClock::host(), validated_registry());
    bench.seed_authority();
    let mut child = spawn_child(true);
    let member: ProcessIdentity = child_identity(child.pid());
    let driver = critical_ticks(&mut bench, &member, 6, Some(3));
    assert!(driver.controller_state().outstanding.is_none());
    assert_eq!(phase(&driver, Guard::Memory), GuardPhase::Qualifying);
    assert!(child.is_running());
}

#[test]
fn a_queued_request_at_a_restart_is_served_only_after_the_reconciliation() {
    let mut bench = Bench::new(TestClock::host(), validated_registry());
    bench.seed_authority();
    let file: PathBuf = bench.file("client-file");
    let mut child = spawn_child(true);
    let member: ProcessIdentity = child_identity(child.pid());
    let mut driver = bench.start();
    let operation_id: OperationId = run_to_operation(&bench, &mut driver, &member);
    bench.clock.advance(SECOND);
    driver.tick(None);
    // The crash, and a client request that is queued after it.
    let before = bench.journal().operation(&operation_id).unwrap().unwrap();
    assert_eq!(before.state(), &OperationState::Admitted);
    drop(driver);
    let plan: Plan = trash_plan(&bench, "client-file");
    let mut client = bench.journal();
    client.record_plan(&plan).unwrap();
    let request = apply_request(&plan, "request-1", bench.clock.now());
    client.enqueue_request(&request).unwrap();

    // The start reconciles the operation of the lifetime before it. The
    // request is not served in the start.
    let mut driver = bench.start();
    let operation = bench.journal().operation(&operation_id).unwrap().unwrap();
    assert_eq!(operation.state(), &OperationState::Failed);
    assert!(file.exists());
    assert_eq!(
        client.request_status(&request.request_id).unwrap(),
        Some(RequestStatus::Queued)
    );
    // The next ticks serve it, and the old operation stays settled.
    for _ in 0..3 {
        driver.tick(None);
        bench.clock.advance(SAMPLE);
    }
    assert!(!file.exists());
    assert_ne!(
        client.request_status(&request.request_id).unwrap(),
        Some(RequestStatus::Queued)
    );
    let operation = bench.journal().operation(&operation_id).unwrap().unwrap();
    assert_eq!(operation.state(), &OperationState::Failed);
    assert!(child.is_running());
}
