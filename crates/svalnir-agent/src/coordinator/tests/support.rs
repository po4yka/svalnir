//! The fixtures of the coordinator tests.
//!
//! Each fixture is disposable: a journal database and a file tree in a
//! temporary directory, a controlled clock, synthetic measurements, and a
//! synthetic process host. The authority records are real records of the
//! grant module, made through its activation and enable functions.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use serde_json::{Value, json};
use svalnir_core::action::SlotAllowance;
use svalnir_core::action::{
    ActionClass, ActionError, Admission, ApplicationBinding, Checked, ClientRole, DispatchReceipt,
    DispatchState, Escalation, ExecutorRole, FileBinding, FileObjectType, Journal, JournalError,
    Operation, PLAN_SCHEMA_VERSION, Plan, PlanApproval, PlanContent, PlanLimits, PlanTarget,
    PlannedStep, Principal, RequestEnvelope, Step, TargetBinding, Trigger, TriggerClass, Validity,
    WorkCharge,
};
use svalnir_core::authority::{ActionGrantRef, AuthorityBinding, Generation};
use svalnir_core::config::{ValidatedConfig, parse_and_validate};
use svalnir_core::digest::ContentDigest;
use svalnir_core::file::{DeviceNumber, FileObjectEvidence, LosslessPath};
use svalnir_core::grant::{
    Acceptance, ActionRequest, AuthorityState, Authorization, AuthorizationContext, ControlClock,
    EnableRequest, EvidenceStamp, IncidentBudget, InstanceInhibition, PauseRequest, Persistence,
    Refusal, RevokeRequest, activate, authorize, enable, pause, revoke,
};
use svalnir_core::id::{
    ActionGrantId, AdapterId, ApplicationInstanceId, BootId, ClockDomainId, DecisionId,
    ExecutorEpochId, IncidentId, LeaseId, MembershipSnapshotId, MountId, OperationId, PlanId,
    PolicyRevisionId, ProcessGenerationId, RequestId, RootId, StepId, TargetId, VolumeId,
};
use svalnir_core::observation::{Observation, UnavailableReason};
use svalnir_core::plan::PlanMode;
use svalnir_core::policy::{ContinuityGeneration, EvaluationClock, PolicyId, ProtectionFact};
use svalnir_core::process::{
    AttributionMethod, ExecutableIdentity, Pid, ProcessAssociation, ProcessIdentity,
    ProcessStartTime, Uid,
};
use svalnir_core::quantity::{Bytes, EntryCount, Nanoseconds};
use svalnir_core::rule::{Rule, RuleRegistry};
use svalnir_core::state::PressureState;
use svalnir_core::time::{MonotonicNanos, WallTime};
use tempfile::TempDir;

use super::super::{
    ApplyOutcome, ApplyRequest, AuthoritySource, Clock, Coordinator, CoordinatorConfig,
    CoordinatorJournal, Dependencies, FileProbe, IdSource, Idle, IncidentAllowance, Measurements,
    OperationView, Pacing, Phase, RevisionSnapshot, Start, TargetProbe, TimeReading,
    TriggerStanding,
};
use crate::executor::fs::{
    ApprovedRoot, ApprovedRoots, ExecutorLimits, FsExecutor, FsExecutorConfig, TrashBackend,
    TrashFailure, TrashReply, TrashRequest,
};
use crate::executor::process::{
    ApplicationCallResult, ApplicationExpectation, ApplicationRequest, ExecutorConfig,
    ExecutorContext, GenerationState, ProcessControl, ProcessExecutor, ProcessSignal, SignalResult,
    StepClock,
};
use crate::journal::{
    Acknowledged, Acknowledgment, ClaimedRequest, CoordinationStart, CoordinatorLock,
    IncidentUsage, JournalOptions, OperationJournal, OperationJournalError, QueuedRequest,
    RecoveryPosition, RecoveryRecord, RequestBody, RequestCompletion, VolatilePersistReport,
    VolatileRecord,
};
use crate::platform::process::{
    DarwinProcessSource, ProcessSource, QueryFailure, RawProcessInfo, RawUsage, RunningApplication,
    Timebase,
};
use crate::rules::ReviewedRules;

pub(super) const SECOND: u64 = 1_000_000_000;
/// The time of the test clock at the start of a test.
pub(super) const START: u64 = 200 * SECOND;
/// The grace period of an application plan.
pub(super) const GRACE: u64 = 10 * SECOND;
/// The verification window of a plan.
pub(super) const WINDOW: u64 = 5 * SECOND;
pub(super) const VOLUME: &str = "volume_1";
pub(super) const ROOT_ID: &str = "root_1";

const CONFIG: &str = r#"
schema_version = 1

[agent]
profile = "balanced"
sample_interval = "60s"
pressure_sample_interval = "5s"
decision_sample_max_age = "10s"
max_qualifying_sample_gap = "10s"
plan_ttl = "30s"

[disk_guard]
enabled = false
volumes = ["startup-data"]
warn_below = "20GiB"
reclaim_below = "10GiB"
emergency_below = "2GiB"
recover_above = "25GiB"
sustain_for = "30s"
emergency_sustain_for = "5s"
recovery_stable_for = "60s"
batch_limit = "1GiB"
pass_limit = "8GiB"
incident_limit = "16GiB"
batch_item_limit = 256
pass_item_limit = 2048
incident_item_limit = 4096
max_passes_per_incident = 2
approved_rules = []

[memory_guard]
enabled = true
global_trigger = "critical"
sustain_for = "15s"
grace_period = "10s"
recovery_stable_for = "60s"
max_applications_per_incident = 3
protect_foreground = true
allow_force_quit = true
allow_volatile_journal_on_critical = VOLATILE
eligible_groups = ["background-user-applications", "managed-jobs"]
"#;

/// The effective user of the test process. The filesystem executor acts
/// only for this user.
pub(super) fn user() -> Uid {
    DarwinProcessSource::new().effective_uid()
}

pub(super) fn wall(nanoseconds: u64) -> WallTime {
    WallTime::from_unix(
        1_800_000_000 + i64::try_from(nanoseconds / SECOND).unwrap(),
        0,
    )
    .unwrap()
}

pub(super) fn evaluation_clock(now: u64) -> EvaluationClock {
    EvaluationClock {
        now: MonotonicNanos::new(now),
        clock_domain: ClockDomainId::new("clock_main").unwrap(),
        boot_id: BootId::new("boot_1").unwrap(),
        continuity: ContinuityGeneration::new(0),
        last_discontinuity: None,
    }
}

/// The controlled clock. Each copy reads the same time.
#[derive(Debug, Clone)]
pub(super) struct TestClock(Arc<AtomicU64>, Arc<Mutex<(u64, Option<u64>)>>);

impl TestClock {
    pub(super) fn new() -> Self {
        Self(
            Arc::new(AtomicU64::new(START)),
            Arc::new(Mutex::new((0, None))),
        )
    }

    /// A sleep of the host: the clock counts its time, and the wake is a
    /// clock discontinuity at the new time.
    pub(super) fn sleep(&self, nanoseconds: u64) {
        self.advance(nanoseconds);
        let mut continuity = self.1.lock().unwrap();
        *continuity = (continuity.0 + 1, Some(self.now()));
    }

    pub(super) fn now(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }

    pub(super) fn advance(&self, nanoseconds: u64) {
        self.0.fetch_add(nanoseconds, Ordering::SeqCst);
    }

    pub(super) fn set(&self, nanoseconds: u64) {
        self.0.store(nanoseconds, Ordering::SeqCst);
    }

    pub(super) fn reading(&self) -> TimeReading {
        let (generation, last_discontinuity) = *self.1.lock().unwrap();
        TimeReading {
            clock: EvaluationClock {
                continuity: ContinuityGeneration::new(generation),
                last_discontinuity: last_discontinuity.map(MonotonicNanos::new),
                ..evaluation_clock(self.now())
            },
            wall: wall(self.now()),
        }
    }
}

impl Clock for TestClock {
    fn now(&self) -> Option<TimeReading> {
        Some(self.reading())
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

impl Idle for TestClock {
    fn idle(&mut self, wake_at: Option<MonotonicNanos>) {
        match wake_at {
            Some(wake_at) if wake_at.get() > self.now() => self.set(wake_at.get()),
            _ => self.advance(SECOND),
        }
    }
}

/// The registry of a test: no rule, or the reviewed rules of the agent,
/// each of which is in the proposed lifecycle state.
#[derive(Debug, Default)]
pub(super) struct NoRules(pub(super) Option<ReviewedRules>);

impl RuleRegistry for NoRules {
    fn rules(&self) -> Vec<&Rule> {
        self.0.as_ref().map_or_else(Vec::new, RuleRegistry::rules)
    }
}

#[derive(Debug)]
pub(super) struct Records {
    pub(super) state: AuthorityState,
    pub(super) inhibition: InstanceInhibition,
    pub(super) incidents: BTreeMap<IncidentId, IncidentBudget>,
    /// `None` gives [`TriggerStanding::Unknown`].
    pub(super) trigger_holds: Option<bool>,
    pub(super) protection: ProtectionFact,
    pub(super) registry: NoRules,
}

/// The authority records of a test, behind the grant module.
#[derive(Debug, Clone)]
pub(super) struct TestAuthority(pub(super) Arc<Mutex<Records>>);

fn config(volatile: bool) -> ValidatedConfig {
    let text: String = CONFIG.replace("VOLATILE", if volatile { "true" } else { "false" });
    let validation = parse_and_validate(&text);
    assert!(
        validation.findings().is_empty(),
        "the test configuration has findings: {:?}",
        validation.findings()
    );
    validation.config().unwrap().clone()
}

impl TestAuthority {
    /// A record with the test configuration in effect as `policy_1` and
    /// the memory guard enabled with force quit accepted.
    pub(super) fn new(volatile: bool) -> Self {
        let registry = NoRules::default();
        let config: ValidatedConfig = config(volatile);
        let empty = AuthorityState::new(user());
        let request = svalnir_core::grant::ActivationRequest {
            principal: user(),
            config: &config,
            content: ContentDigest::of_bytes(format!("{config:?}").as_bytes()),
            expected_revision: None,
            revision_id: PolicyRevisionId::new("policy_1").unwrap(),
            now: wall(0),
        };
        let none = InstanceInhibition::default();
        let state: AuthorityState = activate(&empty, &request, &registry)
            .unwrap()
            .acknowledge(&none, Persistence::Durable)
            .state;
        let request = EnableRequest {
            principal: user(),
            policy: PolicyId::MemoryGuard,
            accepted: Acceptance::classes_of(&[Acceptance::ForceQuit]),
            reviewed_revision: Some(PolicyRevisionId::new("policy_1").unwrap()),
            grant_id: ActionGrantId::new("grant_memory").unwrap(),
            now: wall(0),
        };
        let state: AuthorityState = enable(&state, &none, &request)
            .unwrap()
            .acknowledge(&none, Persistence::Durable)
            .state;
        Self(Arc::new(Mutex::new(Records {
            state,
            inhibition: none,
            incidents: BTreeMap::new(),
            trigger_holds: Some(true),
            protection: ProtectionFact::NotProtected,
            registry,
        })))
    }

    pub(super) fn records(&self) -> MutexGuard<'_, Records> {
        self.0.lock().unwrap()
    }

    pub(super) fn memory_grant(&self) -> ActionGrantRef {
        self.records()
            .state
            .guard(PolicyId::MemoryGuard)
            .unwrap()
            .grant
            .as_ref()
            .unwrap()
            .reference()
    }

    /// Opens the budget record of `incident` for the memory guard.
    pub(super) fn open_incident(&self, incident: &IncidentId, now: u64) {
        let mut records = self.records();
        let budget = IncidentBudget::open(
            incident.clone(),
            PolicyId::MemoryGuard,
            &records.state,
            &records.inhibition,
            wall(now),
        );
        records.incidents.insert(incident.clone(), budget);
    }

    /// Pauses all automation durably.
    pub(super) fn pause(&self, now: u64) {
        let mut records = self.records();
        let clock = evaluation_clock(now);
        let control = ControlClock {
            clock: &clock,
            wall: wall(now),
        };
        let request = PauseRequest {
            principal: user(),
            duration: None,
        };
        let change = pause(&records.state, &request, &control).unwrap();
        let acknowledged = change.acknowledge(&records.inhibition, Persistence::Durable);
        records.state = acknowledged.state;
        records.inhibition = acknowledged.inhibition;
    }

    /// Revokes the grant of the memory guard durably.
    pub(super) fn revoke_memory_grant(&self) {
        let mut records = self.records();
        let request = RevokeRequest {
            principal: user(),
            grant_id: ActionGrantId::new("grant_memory").unwrap(),
        };
        let change = revoke(&records.state, &request).unwrap();
        let acknowledged = change.acknowledge(&records.inhibition, Persistence::Durable);
        records.state = acknowledged.state;
        records.inhibition = acknowledged.inhibition;
    }
}

impl AuthoritySource for TestAuthority {
    fn authorize(
        &self,
        request: &ActionRequest<'_>,
        time: &TimeReading,
    ) -> Result<Authorization, Refusal> {
        let records = self.records();
        let context = AuthorizationContext {
            state: &records.state,
            inhibition: &records.inhibition,
            registry: &records.registry,
            clock: ControlClock {
                clock: &time.clock,
                wall: time.wall,
            },
        };
        authorize(&context, request)
    }

    fn revisions(&self, _mode: PlanMode, time: &TimeReading) -> RevisionSnapshot {
        let records = self.records();
        RevisionSnapshot {
            policy_revision: records
                .state
                .active
                .as_ref()
                .map(|active| active.revision.revision_id.clone()),
            action_grants: records
                .state
                .guards
                .iter()
                .filter_map(|guard| guard.grant.as_ref())
                .filter(|grant| grant.is_in_effect(time.wall))
                .map(svalnir_core::authority::ActionGrant::reference)
                .collect(),
            rules: records
                .registry
                .rules()
                .into_iter()
                .map(|rule| rule.reference.clone())
                .collect(),
        }
    }

    fn incident(&self, incident_id: &IncidentId) -> Option<IncidentBudget> {
        self.records().incidents.get(incident_id).cloned()
    }

    fn trigger(&self, _plan: &Plan, time: &TimeReading) -> TriggerStanding {
        match self.records().trigger_holds {
            Some(true) => TriggerStanding::Holds(EvidenceStamp {
                acquired_at: time.clock.now,
                clock_domain: time.clock.clock_domain.clone(),
                boot_id: time.clock.boot_id.clone(),
            }),
            Some(false) => TriggerStanding::Cleared,
            None => TriggerStanding::Unknown,
        }
    }

    fn protection(&self, _processes: &[ProcessIdentity]) -> ProtectionFact {
        self.records().protection
    }
}

fn observation<T>(
    metric: &str,
    scope: &Value,
    unit: &str,
    kind: &str,
    value: Option<&Value>,
) -> Observation<T>
where
    Observation<T>: serde::de::DeserializeOwned,
{
    serde_json::from_value(json!({
        "metric_id": metric,
        "scope": scope,
        "value": value.cloned().unwrap_or(Value::Null),
        "unit": unit,
        "kind": kind,
        "availability": if value.is_some() { "available" } else { "unavailable" },
        "reason": if value.is_some() { Value::Null } else { json!("permission_denied") },
        "coverage": "complete",
        "source": {
            "adapter_id": "test.measurement",
            "adapter_revision": "1",
            "native_api": "test",
            "native_field": "test",
            "worker_id": "worker_1"
        },
        "sample": {
            "sample_id": "sample_1",
            "clock_domain": "clock_main",
            "boot_id": "boot_1",
            "collector_epoch": "collector_1",
            "started_monotonic_ns": "120000000000",
            "finished_monotonic_ns": "120003000000",
            "captured_at": "2026-11-16T12:00:00.003Z"
        }
    }))
    .unwrap()
}

#[derive(Debug, Default)]
pub(super) struct MeasurementState {
    /// The next capacity values. `None` is an unavailable measurement.
    /// With no value left, the last one is given again.
    pub(super) capacity: VecDeque<Option<u64>>,
    pub(super) last_capacity: Option<u64>,
    pub(super) pressure: VecDeque<&'static str>,
    pub(super) last_pressure: Option<&'static str>,
    pub(super) capacity_calls: u32,
    pub(super) pressure_calls: u32,
}

/// Synthetic measurements.
#[derive(Debug, Clone, Default)]
pub(super) struct TestMeasurements(pub(super) Arc<Mutex<MeasurementState>>);

impl Measurements for TestMeasurements {
    fn capacity(&mut self, volume: &VolumeId) -> Observation<Bytes> {
        let mut state = self.0.lock().unwrap();
        state.capacity_calls += 1;
        if let Some(next) = state.capacity.pop_front() {
            state.last_capacity = next;
        }
        let value: Option<Value> = state.last_capacity.map(|bytes| json!(bytes.to_string()));
        observation(
            "disk.available_bytes",
            &json!({ "kind": "volume", "identity_id": volume.as_str() }),
            "byte",
            "gauge",
            value.as_ref(),
        )
    }

    fn memory_pressure(&mut self) -> Observation<PressureState> {
        let mut state = self.0.lock().unwrap();
        state.pressure_calls += 1;
        if let Some(next) = state.pressure.pop_front() {
            state.last_pressure = Some(next);
        }
        let value: Option<Value> = state.last_pressure.map(|text| json!(text));
        observation(
            "memory.pressure",
            &json!({ "kind": "host", "identity_id": "host_1" }),
            "state",
            "state",
            value.as_ref(),
        )
    }
}

/// Identities with a prefix and a counter.
#[derive(Debug)]
pub(super) struct TestIds {
    prefix: String,
    next: u64,
}

impl TestIds {
    pub(super) fn new(prefix: &str) -> Self {
        Self {
            prefix: prefix.to_owned(),
            next: 0,
        }
    }
}

impl IdSource for TestIds {
    fn operation_id(&mut self) -> Option<OperationId> {
        self.next += 1;
        OperationId::new(format!("{}_operation_{}", self.prefix, self.next)).ok()
    }

    fn lease_id(&mut self) -> Option<LeaseId> {
        self.next += 1;
        LeaseId::new(format!("{}_lease_{}", self.prefix, self.next)).ok()
    }
}

// The synthetic process host.

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum NativeCall {
    Signal(i32, ProcessSignal),
}

#[derive(Debug, Default)]
pub(super) struct World {
    /// The running processes: PID to start time in seconds.
    pub(super) processes: BTreeMap<i32, u64>,
    /// The processes that exit at a `SIGTERM`.
    pub(super) exits_on_term: BTreeSet<i32>,
    pub(super) calls: Vec<NativeCall>,
}

/// One shared state behind a process source, the native calls, and the
/// reconciliation probe.
#[derive(Debug, Clone)]
pub(super) struct Host {
    pub(super) world: Arc<Mutex<World>>,
    clock: TestClock,
    /// The result of the file probe, when a test sets one.
    pub(super) file_probe: Arc<Mutex<Option<FileProbe>>>,
    roots: Option<ApprovedRoots>,
}

fn pid(value: i32) -> Pid {
    Pid::new(value).unwrap()
}

fn start_time(seconds: u64) -> ProcessStartTime {
    ProcessStartTime::from_timeval(seconds, 0).unwrap()
}

fn path_of(process: i32) -> String {
    format!("/Applications/Example.app/Contents/MacOS/Example{process}")
}

impl Host {
    pub(super) fn new(clock: &TestClock, roots: Option<ApprovedRoots>) -> Self {
        Self {
            world: Arc::new(Mutex::new(World::default())),
            clock: clock.clone(),
            file_probe: Arc::new(Mutex::new(None)),
            roots,
        }
    }

    pub(super) fn world(&self) -> MutexGuard<'_, World> {
        self.world.lock().unwrap()
    }

    /// Adds a running process, and returns its planned identity.
    pub(super) fn spawn(&self, process: i32) -> ProcessIdentity {
        self.world().processes.insert(process, 1_000);
        member(process)
    }

    pub(super) fn calls(&self) -> Vec<NativeCall> {
        self.world().calls.clone()
    }
}

/// The planned identity of the process `process` of the host.
pub(super) fn member(process: i32) -> ProcessIdentity {
    ProcessIdentity {
        generation_id: ProcessGenerationId::new(format!("pg-{process}")).unwrap(),
        pid: pid(process),
        start_time: start_time(1_000),
        uid: user(),
        boot_id: BootId::new("boot_1").unwrap(),
        executable: Some(ExecutableIdentity {
            path: LosslessPath::from_bytes(path_of(process)).unwrap(),
            file: Some(FileObjectEvidence {
                device: DeviceNumber::new(1),
                inode: u64::try_from(process).unwrap().into(),
            }),
            code_signature: None,
        }),
        association: ProcessAssociation::ManagedJob {
            instance_id: ApplicationInstanceId::new("app_1").unwrap(),
            label: "com.example.job".to_owned(),
            attribution: AttributionMethod::LaunchdJob,
        },
    }
}

impl ProcessSource for Host {
    fn effective_uid(&self) -> Uid {
        user()
    }

    fn list_pids(&self) -> Result<Vec<Pid>, QueryFailure> {
        Ok(self.world().processes.keys().map(|key| pid(*key)).collect())
    }

    fn process_info(&self, process: Pid) -> Result<RawProcessInfo, QueryFailure> {
        let world = self.world();
        let seconds: &u64 = world
            .processes
            .get(&process.get())
            .ok_or(QueryFailure::Gone)?;
        Ok(RawProcessInfo {
            pid: process,
            parent_pid: Some(pid(1)),
            effective_uid: user(),
            real_uid: user(),
            start_time: start_time(*seconds),
            zombie: false,
        })
    }

    fn executable_path(&self, process: Pid) -> Result<LosslessPath, QueryFailure> {
        if self.world().processes.contains_key(&process.get()) {
            Ok(LosslessPath::from_bytes(path_of(process.get())).unwrap())
        } else {
            Err(QueryFailure::Gone)
        }
    }

    fn file_evidence(&self, path: &LosslessPath) -> Result<FileObjectEvidence, QueryFailure> {
        self.world()
            .processes
            .keys()
            .find(|process| path_of(**process).as_bytes() == path.as_bytes())
            .map(|process| FileObjectEvidence {
                device: DeviceNumber::new(1),
                inode: u64::try_from(*process).unwrap().into(),
            })
            .ok_or(QueryFailure::Gone)
    }

    fn usage(&self, _process: Pid) -> Result<RawUsage, QueryFailure> {
        Err(QueryFailure::Unsupported)
    }

    fn responsible_pid(&self, process: Pid) -> Result<Pid, QueryFailure> {
        Ok(process)
    }

    fn application_list_current(&self) -> bool {
        true
    }

    fn running_applications(&self) -> Result<Vec<RunningApplication>, QueryFailure> {
        Ok(Vec::new())
    }

    fn timebase(&self) -> Result<Timebase, QueryFailure> {
        Timebase::new(1, 1).ok_or(QueryFailure::Inconsistent)
    }

    fn monotonic_now(&self) -> Result<MonotonicNanos, QueryFailure> {
        StepClock::monotonic_now(&self.clock)
    }

    fn sleep_time(&self) -> Result<Nanoseconds, UnavailableReason> {
        Ok(Nanoseconds::ZERO)
    }

    fn wall_now(&self) -> Result<WallTime, QueryFailure> {
        Ok(wall(self.clock.now()))
    }
}

impl ProcessControl for Host {
    fn own_process(&self) -> Option<Pid> {
        Some(pid(900))
    }

    fn parent_process(&self) -> Option<Pid> {
        Some(pid(800))
    }

    fn signal(&self, process: Pid, signal: ProcessSignal) -> SignalResult {
        let mut world = self.world();
        world.calls.push(NativeCall::Signal(process.get(), signal));
        let exits: bool =
            matches!(signal, ProcessSignal::Kill) || world.exits_on_term.contains(&process.get());
        if exits {
            world.processes.remove(&process.get());
        }
        SignalResult::Delivered
    }

    fn request_application_exit(
        &self,
        _expected: &ApplicationExpectation<'_>,
        _request: ApplicationRequest,
    ) -> ApplicationCallResult {
        ApplicationCallResult::Accepted
    }
}

impl TargetProbe for Host {
    fn file(&self, target: &TargetBinding) -> FileProbe {
        if let Some(probe) = *self.file_probe.lock().unwrap() {
            return probe;
        }
        let (TargetBinding::File(file), Some(roots)) = (target, &self.roots) else {
            return FileProbe::Unknown;
        };
        let Some(root) = roots.root(&file.root_id) else {
            return FileProbe::Unknown;
        };
        let path: PathBuf = root
            .path
            .to_path_buf()
            .join(file.relative_entry.to_path_buf());
        match fs::symlink_metadata(&path) {
            Ok(_) if file.object == Some(object_of(&path)) => FileProbe::PlannedObject,
            Ok(_) => FileProbe::OtherObject,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => FileProbe::Absent,
            Err(_) => FileProbe::Unknown,
        }
    }

    fn process(&self, planned: &ProcessIdentity) -> GenerationState {
        match self.process_info(planned.pid) {
            Err(QueryFailure::Gone) => GenerationState::Exited,
            Err(failure) => GenerationState::Unknown(failure),
            Ok(info) if info.start_time != planned.start_time => GenerationState::Replaced,
            Ok(_) => GenerationState::Running,
        }
    }
}

// The file tree.

pub(super) fn object_of(path: &Path) -> FileObjectEvidence {
    let metadata = fs::symlink_metadata(path).unwrap();
    FileObjectEvidence {
        device: DeviceNumber::new(i32::try_from(metadata.dev()).unwrap()),
        inode: metadata.ino().into(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TrashMode {
    Move,
    Fail,
}

/// A filesystem executor that reports each removal as a call whose
/// submission is not certain and after which the entry is absent: a
/// final effect with no recorded submission.
#[derive(Debug)]
pub(super) struct UncertainSubmission(pub(super) FsExecutor);

impl super::super::FilesystemExecutor for UncertainSubmission {
    fn execute(
        &self,
        roots: &ApprovedRoots,
        step: crate::executor::fs::AdmittedStep<'_>,
        signal: &dyn crate::executor::fs::StopSignal,
    ) -> crate::executor::fs::StepOutcome {
        self.0
            .execute_step_until(roots, step, signal)
            .map(|mut outcome| {
                let record = outcome.result.clone().into_inner();
                if matches!(record.effect, svalnir_core::action::TargetEffect::Removed) {
                    outcome.result = Checked::new(svalnir_core::action::TargetResultRecord {
                        dispatch: DispatchState::SubmissionUncertain,
                        effect: svalnir_core::action::TargetEffect::AlreadyAbsent,
                        attribution: svalnir_core::action::Attribution::Possible,
                        ..record
                    })
                    .unwrap();
                }
                outcome
            })
    }
}

/// A Trash backend that moves an entry to a directory of the fixture. It
/// refuses each path outside the temporary directory.
#[derive(Debug)]
pub(super) struct FakeTrash {
    directory: PathBuf,
    mode: TrashMode,
}

impl TrashBackend for FakeTrash {
    fn move_to_trash(&self, request: &TrashRequest<'_>) -> TrashReply {
        let source: PathBuf = request.path.to_path_buf();
        assert!(source.starts_with(self.directory.parent().unwrap()));
        if self.mode == TrashMode::Fail {
            return TrashReply::Failed(TrashFailure::Unsupported);
        }
        let item: PathBuf = self.directory.join(source.file_name().unwrap());
        fs::rename(&source, &item).unwrap();
        TrashReply::Moved {
            item_object: Some(object_of(&item)),
            item: Some(LosslessPath::from_path(&item).unwrap()),
        }
    }
}

/// A temporary directory with the journal database, an approved root, a
/// home directory, and a Trash directory.
#[derive(Debug)]
pub(super) struct Tree {
    _temp: TempDir,
    pub(super) database: PathBuf,
    pub(super) root: PathBuf,
    pub(super) trash: PathBuf,
    home: PathBuf,
}

impl Tree {
    pub(super) fn new() -> Self {
        let temp: TempDir = tempfile::tempdir().unwrap();
        // The temporary directory of macOS is below the symbolic link
        // `/var`. An approved root has no symbolic link in its path.
        let base: PathBuf = fs::canonicalize(temp.path()).unwrap();
        let root: PathBuf = base.join("root");
        let trash: PathBuf = base.join("trash");
        let home: PathBuf = base.join("home");
        for directory in [&root, &trash, &home] {
            fs::create_dir(directory).unwrap();
        }
        Self {
            database: base.join("operations.sqlite"),
            _temp: temp,
            root,
            trash,
            home,
        }
    }

    pub(super) fn roots(&self) -> ApprovedRoots {
        ApprovedRoots::new(vec![ApprovedRoot {
            root_id: RootId::new(ROOT_ID).unwrap(),
            path: LosslessPath::from_path(&self.root).unwrap(),
            object: object_of(&self.root),
            volume_id: VolumeId::new(VOLUME).unwrap(),
            mount_id: MountId::new("mount_1").unwrap(),
        }])
        .unwrap()
    }

    pub(super) fn executor(&self, mode: TrashMode) -> FsExecutor {
        let config = FsExecutorConfig {
            home_directory: LosslessPath::from_path(&self.home).unwrap(),
            limits: ExecutorLimits::default(),
        };
        FsExecutor::new(
            &config,
            Box::new(FakeTrash {
                directory: self.trash.clone(),
                mode,
            }),
        )
        .unwrap()
    }

    /// Writes the file `name` below the root.
    pub(super) fn file(&self, name: &str) -> PathBuf {
        let path: PathBuf = self.root.join(name);
        fs::write(&path, b"content").unwrap();
        path
    }

    /// The binding of the entry `name` as it is now.
    pub(super) fn binding(&self, name: &str) -> FileBinding {
        let path: PathBuf = self.root.join(name);
        let file_type = fs::symlink_metadata(&path).unwrap().file_type();
        FileBinding {
            root_id: RootId::new(ROOT_ID).unwrap(),
            root_path: LosslessPath::from_path(&self.root).unwrap(),
            root_object: object_of(&self.root),
            relative_entry: LosslessPath::from_bytes(name.as_bytes()).unwrap(),
            volume_id: VolumeId::new(VOLUME).unwrap(),
            mount_id: MountId::new("mount_1").unwrap(),
            object_type: if file_type.is_dir() {
                FileObjectType::Directory
            } else {
                FileObjectType::RegularFile
            },
            owner: user(),
            object: Some(object_of(&path)),
            rule: None,
            layout: None,
            charge: WorkCharge::new(Bytes::new(10), EntryCount::new(1)),
        }
    }
}

// Plans.

pub(super) fn principal() -> Principal {
    Principal {
        uid: user(),
        session: None,
        role: ClientRole::Cli,
    }
}

fn base_content(plan: &str, now: u64) -> PlanContent {
    PlanContent {
        schema_version: PLAN_SCHEMA_VERSION,
        plan_id: PlanId::new(plan).unwrap(),
        principal: principal(),
        trigger: Trigger::manual(),
        authority: AuthorityBinding {
            policy_revision: PolicyRevisionId::new("policy_1").unwrap(),
            action_grants: Vec::new(),
            privilege_grant: None,
        },
        executor: ExecutorRole::User,
        targets: Vec::new(),
        steps: Vec::new(),
        limits: PlanLimits {
            work: None,
            execution_deadline: Nanoseconds::new(60 * SECOND),
            grace: None,
            verification_window: Nanoseconds::new(WINDOW),
            escalation: Escalation::None,
        },
        validity: Validity {
            clock_domain: ClockDomainId::new("clock_main").unwrap(),
            boot_id: BootId::new("boot_1").unwrap(),
            created_at: MonotonicNanos::new(now),
            expires_at: MonotonicNanos::new(now + 120 * SECOND),
            created_wall: wall(now),
        },
    }
}

/// A manual filesystem plan of `class` with one step for each entry of
/// `names` below the root of `tree`.
pub(super) fn cleanup_plan(
    plan: &str,
    tree: &Tree,
    class: &ActionClass,
    names: &[&str],
    now: u64,
) -> Plan {
    Plan::seal(cleanup_content(plan, tree, class, names, now)).unwrap()
}

/// The content of [`cleanup_plan`], for a test that changes it.
pub(super) fn cleanup_content(
    plan: &str,
    tree: &Tree,
    class: &ActionClass,
    names: &[&str],
    now: u64,
) -> PlanContent {
    let mut content: PlanContent = base_content(plan, now);
    let mut total = WorkCharge::ZERO;
    for name in names {
        let binding: FileBinding = tree.binding(name);
        total = total.checked_add(binding.charge).unwrap();
        let target_id = TargetId::new(format!("{plan}_target_{name}")).unwrap();
        content.steps.push(PlannedStep {
            step_id: StepId::new(format!("{plan}_step_{name}")).unwrap(),
            action_class: class.clone(),
            target_id: target_id.clone(),
        });
        content.targets.push(PlanTarget {
            target_id,
            binding: TargetBinding::File(binding),
        });
    }
    content.limits.work = Some(total);
    content
}

/// A manual application plan with the force strategy `escalation`.
pub(super) fn stop_content(
    plan: &str,
    members: Vec<ProcessIdentity>,
    escalation: Escalation,
    now: u64,
) -> PlanContent {
    use ActionClass::{ForceApplicationExit, RequestApplicationExit};
    let mut content: PlanContent = base_content(plan, now);
    let target_id = TargetId::new(format!("{plan}_app")).unwrap();
    let step = |name: &str, class: ActionClass| PlannedStep {
        step_id: StepId::new(format!("{plan}_{name}")).unwrap(),
        action_class: class,
        target_id: target_id.clone(),
    };
    content.steps = match escalation {
        Escalation::ForceAfterGrace => vec![
            step("graceful", RequestApplicationExit),
            step("force", ForceApplicationExit),
        ],
        Escalation::ImmediateForce => vec![step("force", ForceApplicationExit)],
        _ => vec![step("graceful", RequestApplicationExit)],
    };
    content.limits.grace =
        matches!(escalation, Escalation::ForceAfterGrace).then_some(Nanoseconds::new(GRACE));
    content.limits.escalation = escalation;
    content.targets = vec![PlanTarget {
        target_id,
        binding: TargetBinding::Application(ApplicationBinding {
            instance_id: ApplicationInstanceId::new("app_1").unwrap(),
            membership: MembershipSnapshotId::new("members_1").unwrap(),
            members,
        }),
    }];
    content
}

pub(super) fn stop_plan(
    plan: &str,
    members: Vec<ProcessIdentity>,
    escalation: Escalation,
    now: u64,
) -> Plan {
    Plan::seal(stop_content(plan, members, escalation, now)).unwrap()
}

/// The content of a manual stop plan for the one process `process`, which
/// gets the association `Unattributed`: a target of one process with no
/// verified membership.
pub(super) fn process_stop_content(
    plan: &str,
    mut process: ProcessIdentity,
    escalation: Escalation,
    now: u64,
) -> PlanContent {
    let mut content: PlanContent = stop_content(plan, vec![process.clone()], escalation, now);
    process.association = ProcessAssociation::Unattributed;
    content.targets[0].binding =
        TargetBinding::Process(svalnir_core::action::ProcessBinding { process });
    content
}

pub(super) fn process_stop_plan(
    plan: &str,
    process: ProcessIdentity,
    escalation: Escalation,
    now: u64,
) -> Plan {
    Plan::seal(process_stop_content(plan, process, escalation, now)).unwrap()
}

pub(super) fn incident_id(text: &str) -> IncidentId {
    IncidentId::new(text).unwrap()
}

/// An automatic application plan of the memory guard for `incident`,
/// bound to the current grant of the guard.
pub(super) fn automatic_stop_plan(
    plan: &str,
    authority: &TestAuthority,
    incident: &IncidentId,
    class: TriggerClass,
    members: Vec<ProcessIdentity>,
    escalation: Escalation,
    now: u64,
) -> Plan {
    let mut content: PlanContent = stop_content(plan, members, escalation, now);
    content.trigger = Trigger {
        class,
        incident_id: Some(incident.clone()),
        decision_id: Some(DecisionId::new(format!("{plan}_decision")).unwrap()),
        budget_generation: Some(Generation::new(1)),
    };
    content.principal.role = ClientRole::Agent;
    content.authority.action_grants = vec![authority.memory_grant()];
    Plan::seal(content).unwrap()
}

pub(super) fn approval(plan: &Plan) -> PlanApproval {
    PlanApproval {
        plan_id: plan.plan_id.clone(),
        digest: plan.digest().clone(),
    }
}

/// A request of a client: the plan is in the journal.
pub(super) fn stored_request(plan: &Plan) -> ApplyRequest {
    ApplyRequest {
        approval: approval(plan),
        principal: plan.principal.clone(),
        plan: None,
        incident: None,
    }
}

// The journal wrapper.

/// The point at which the wrapped journal fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum FailPoint {
    RecordPlan,
    Admit,
    /// `admit` returns `Sequence`: the journal has a pending
    /// reconciliation.
    AdmitSequence,
    HasStopFence,
    CommitIntent,
    ConsumeDispatch,
    RecordStep,
    RecordOperation,
    SetStopFence,
    CompleteRequest,
    PersistVolatile,
    RecordEffects,
    /// `recovery_records` gives each consumed dispatch with no outcome
    /// the position `Submitted`, so that the result of the evidence does
    /// not agree with the step: the state machine refuses it.
    RecoveryAsSubmitted,
}

/// A function that a test runs inside a journal call.
#[derive(Default)]
pub(super) struct Hook(pub(super) Option<Box<dyn FnMut() + Send>>);

impl std::fmt::Debug for Hook {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(if self.0.is_some() {
            "Hook(set)"
        } else {
            "Hook(none)"
        })
    }
}

/// A journal that fails at selected points. A failed call writes
/// nothing.
#[derive(Debug)]
pub(super) struct FailingJournal {
    pub(super) inner: OperationJournal,
    pub(super) failing: Arc<Mutex<BTreeSet<FailPoint>>>,
    /// The number of calls of `commit_intent` that reached the journal.
    pub(super) intents: Arc<AtomicU64>,
    /// Runs one time after the next dispatch consumption: after the
    /// intent and before the final check and the executor call.
    pub(super) after_consume: Arc<Mutex<Hook>>,
}

impl FailingJournal {
    fn check(&self, point: FailPoint) -> Result<(), JournalError> {
        if self.failing.lock().unwrap().contains(&point) {
            Err(JournalError::Unavailable)
        } else {
            Ok(())
        }
    }
}

impl Journal for FailingJournal {
    fn record_plan(&mut self, plan: &Plan) -> Result<(), JournalError> {
        self.check(FailPoint::RecordPlan)?;
        self.inner.record_plan(plan)
    }

    fn plan(&self, plan_id: &PlanId) -> Result<Option<Plan>, JournalError> {
        self.inner.plan(plan_id)
    }

    fn admit(
        &mut self,
        approval: &PlanApproval,
        principal: &Principal,
        operation: &Operation,
    ) -> Result<Admission, JournalError> {
        self.check(FailPoint::Admit)?;
        if self
            .failing
            .lock()
            .unwrap()
            .contains(&FailPoint::AdmitSequence)
        {
            return Err(JournalError::Sequence);
        }
        self.inner.admit(approval, principal, operation)
    }

    fn record_rejection(
        &mut self,
        approval: &PlanApproval,
        principal: &Principal,
        error: &ActionError,
    ) -> Result<(), JournalError> {
        self.inner.record_rejection(approval, principal, error)
    }

    fn commit_intent(&mut self, envelope: &RequestEnvelope) -> Result<(), JournalError> {
        self.check(FailPoint::CommitIntent)?;
        self.intents.fetch_add(1, Ordering::SeqCst);
        self.inner.commit_intent(envelope)
    }

    fn consume_dispatch(
        &mut self,
        operation_id: &OperationId,
        step_id: &StepId,
    ) -> Result<DispatchReceipt, JournalError> {
        self.check(FailPoint::ConsumeDispatch)?;
        let receipt = self.inner.consume_dispatch(operation_id, step_id)?;
        let hook = self.after_consume.lock().unwrap().0.take();
        if let Some(mut hook) = hook {
            hook();
        }
        Ok(receipt)
    }

    fn record_step(&mut self, operation_id: &OperationId, step: &Step) -> Result<(), JournalError> {
        self.check(FailPoint::RecordStep)?;
        self.inner.record_step(operation_id, step)
    }

    fn record_operation(&mut self, operation: &Operation) -> Result<(), JournalError> {
        self.check(FailPoint::RecordOperation)?;
        self.inner.record_operation(operation)
    }

    fn operation(&self, operation_id: &OperationId) -> Result<Option<Operation>, JournalError> {
        self.inner.operation(operation_id)
    }

    fn unsettled_operations(&self, limit: usize) -> Result<Vec<Operation>, JournalError> {
        self.inner.unsettled_operations(limit)
    }

    fn set_stop_fence(&mut self, operation_id: &OperationId) -> Result<(), JournalError> {
        self.check(FailPoint::SetStopFence)?;
        self.inner.set_stop_fence(operation_id)
    }

    fn has_stop_fence(&self, operation_id: &OperationId) -> Result<bool, JournalError> {
        self.check(FailPoint::HasStopFence)?;
        self.inner.has_stop_fence(operation_id)
    }
}

impl CoordinatorJournal for FailingJournal {
    fn begin_coordination(
        &mut self,
        lock: &CoordinatorLock,
        epoch: &ExecutorEpochId,
        started_at: WallTime,
    ) -> Result<CoordinationStart, OperationJournalError> {
        self.inner.begin_coordination(lock, epoch, started_at)
    }

    fn complete_reconciliation(
        &mut self,
        epoch: &ExecutorEpochId,
    ) -> Result<(), OperationJournalError> {
        self.inner.complete_reconciliation(epoch)
    }

    fn end_coordination(&mut self, epoch: &ExecutorEpochId) -> Result<(), OperationJournalError> {
        self.inner.end_coordination(epoch)
    }

    fn unsettled_operation_count(&self) -> Result<u64, OperationJournalError> {
        self.inner.unsettled_operation_count()
    }

    fn recovery_records(&self, limit: usize) -> Result<Vec<RecoveryRecord>, OperationJournalError> {
        let mut records: Vec<RecoveryRecord> = self.inner.recovery_records(limit)?;
        if self
            .failing
            .lock()
            .unwrap()
            .contains(&FailPoint::RecoveryAsSubmitted)
        {
            for step in records
                .iter_mut()
                .flat_map(|record| &mut record.unsettled_steps)
            {
                if step.position == RecoveryPosition::DispatchConsumed {
                    step.position = RecoveryPosition::Submitted;
                }
            }
        }
        Ok(records)
    }

    fn incident_usage(
        &self,
        incident_id: &IncidentId,
        generation: Generation,
    ) -> Result<Option<IncidentUsage>, OperationJournalError> {
        self.inner.incident_usage(incident_id, generation)
    }

    fn acknowledge_unknown_outcome(
        &mut self,
        operation_id: &OperationId,
        principal: &Principal,
        at: WallTime,
        epoch: &ExecutorEpochId,
    ) -> Result<Acknowledged, OperationJournalError> {
        self.inner
            .acknowledge_unknown_outcome(operation_id, principal, at, epoch)
    }

    fn acknowledgment(
        &self,
        operation_id: &OperationId,
    ) -> Result<Option<Acknowledgment>, OperationJournalError> {
        self.inner.acknowledgment(operation_id)
    }

    fn record_resource_effects(
        &mut self,
        operation_id: &OperationId,
        effects: &[svalnir_core::action::ResourceEffect],
    ) -> Result<(), OperationJournalError> {
        if self
            .failing
            .lock()
            .unwrap()
            .contains(&FailPoint::RecordEffects)
        {
            return Err(OperationJournalError::NotFound);
        }
        self.inner.record_resource_effects(operation_id, effects)
    }

    fn resource_effects(
        &self,
        operation_id: &OperationId,
    ) -> Result<Vec<svalnir_core::action::ResourceEffect>, OperationJournalError> {
        self.inner.resource_effects(operation_id)
    }

    fn claim_next_request(
        &mut self,
        epoch: &ExecutorEpochId,
    ) -> Result<Option<ClaimedRequest>, OperationJournalError> {
        self.inner.claim_next_request(epoch)
    }

    fn complete_request(
        &mut self,
        request_id: &RequestId,
        epoch: &ExecutorEpochId,
        completion: &RequestCompletion,
    ) -> Result<(), OperationJournalError> {
        if self
            .failing
            .lock()
            .unwrap()
            .contains(&FailPoint::CompleteRequest)
        {
            return Err(OperationJournalError::File(std::io::Error::other(
                "injected failure",
            )));
        }
        self.inner.complete_request(request_id, epoch, completion)
    }

    fn persist_volatile(
        &mut self,
        record: &mut VolatileRecord,
    ) -> Result<VolatilePersistReport, OperationJournalError> {
        let failing: bool = {
            let failing = self.failing.lock().unwrap();
            failing.contains(&FailPoint::Admit) || failing.contains(&FailPoint::PersistVolatile)
        };
        if failing {
            return Err(OperationJournalError::NotFound);
        }
        record.persist_into(&mut self.inner)
    }
}

// The assembled coordinator.

pub(super) type TestCoordinator = Coordinator<FailingJournal>;

/// Everything that a test holds beside the coordinator.
#[derive(Debug)]
pub(super) struct Bench {
    pub(super) tree: Tree,
    pub(super) clock: TestClock,
    pub(super) authority: TestAuthority,
    pub(super) measurements: TestMeasurements,
    pub(super) host: Host,
    pub(super) failing: Arc<Mutex<BTreeSet<FailPoint>>>,
    pub(super) intents: Arc<AtomicU64>,
    pub(super) after_consume: Arc<Mutex<Hook>>,
    pub(super) trash_mode: TrashMode,
    /// The filesystem executor reports each submission as not certain.
    pub(super) uncertain_submission: bool,
    lifetimes: u32,
}

pub(super) fn open_journal(database: &Path) -> OperationJournal {
    // The tests do not need the full synchronization of the device.
    let options = JournalOptions {
        full_fsync: false,
        ..JournalOptions::default()
    };
    OperationJournal::open(database, &options).unwrap()
}

impl Bench {
    pub(super) fn new() -> Self {
        Self::with(false, TrashMode::Move)
    }

    pub(super) fn with(volatile: bool, trash_mode: TrashMode) -> Self {
        let tree = Tree::new();
        let clock = TestClock::new();
        let host = Host::new(&clock, Some(tree.roots()));
        Self {
            tree,
            authority: TestAuthority::new(volatile),
            measurements: TestMeasurements::default(),
            host,
            clock,
            failing: Arc::new(Mutex::new(BTreeSet::new())),
            intents: Arc::new(AtomicU64::new(0)),
            after_consume: Arc::new(Mutex::new(Hook::default())),
            trash_mode,
            uncertain_submission: false,
            lifetimes: 0,
        }
    }

    pub(super) fn fail(&self, point: FailPoint) {
        self.failing.lock().unwrap().insert(point);
    }

    /// Runs `hook` one time after the next dispatch consumption.
    pub(super) fn after_consume(&self, hook: impl FnMut() + Send + 'static) {
        self.after_consume.lock().unwrap().0 = Some(Box::new(hook));
    }

    pub(super) fn intents(&self) -> u64 {
        self.intents.load(Ordering::SeqCst)
    }

    pub(super) fn heal(&self) {
        self.failing.lock().unwrap().clear();
    }

    pub(super) fn dependencies(&self, prefix: &str, epoch: &ExecutorEpochId) -> Dependencies {
        let context = ExecutorContext {
            boot_id: BootId::new("boot_1").unwrap(),
            clock_domain: ClockDomainId::new("clock_main").unwrap(),
            executor_epoch: epoch.clone(),
        };
        Dependencies {
            clock: Box::new(self.clock.clone()),
            authority: Box::new(self.authority.clone()),
            measurements: Box::new(self.measurements.clone()),
            ids: Box::new(TestIds::new(prefix)),
            filesystem: if self.uncertain_submission {
                Box::new(UncertainSubmission(self.tree.executor(self.trash_mode)))
            } else {
                Box::new(self.tree.executor(self.trash_mode))
            },
            roots: self.tree.roots(),
            application: Box::new(ProcessExecutor::new(
                self.host.clone(),
                self.host.clone(),
                self.clock.clone(),
                context,
                ExecutorConfig::default(),
            )),
            probe: Box::new(self.host.clone()),
        }
    }

    pub(super) fn config() -> CoordinatorConfig {
        CoordinatorConfig {
            filesystem_adapter: AdapterId::new("svalnir.filesystem").unwrap(),
            process_adapter: AdapterId::new("macos.process").unwrap(),
            batch_targets: 2,
            poll_interval: Nanoseconds::new(SECOND),
            volatile_capacity: 8,
            role: crate::journal::CoordinatorRole::Client,
        }
    }

    /// Starts a new executor lifetime on the journal of the bench.
    pub(super) fn try_start(&mut self) -> Start<FailingJournal> {
        self.start_with(|_, _| {})
    }

    /// Starts a new executor lifetime after `change` replaced a
    /// collaborator or a setting.
    pub(super) fn start_with(
        &mut self,
        change: impl FnOnce(&mut Dependencies, &mut CoordinatorConfig),
    ) -> Start<FailingJournal> {
        self.lifetimes += 1;
        let prefix: String = format!("life{}", self.lifetimes);
        let epoch = ExecutorEpochId::new(format!("epoch_{}", self.lifetimes)).unwrap();
        let journal = FailingJournal {
            inner: open_journal(&self.tree.database),
            failing: Arc::clone(&self.failing),
            intents: Arc::clone(&self.intents),
            after_consume: Arc::clone(&self.after_consume),
        };
        let mut dependencies: Dependencies = self.dependencies(&prefix, &epoch);
        let mut config: CoordinatorConfig = Self::config();
        change(&mut dependencies, &mut config);
        Coordinator::start(journal, &self.tree.database, epoch, config, dependencies).unwrap()
    }

    /// Starts a coordinator when no coordinator of the test holds the
    /// lock.
    ///
    /// A test of a different thread can start a child process at the same
    /// time. Between its `fork` and its `exec`, that child has a copy of
    /// each open file of this process, also of a lock file that a test
    /// dropped a moment before, and the lock stays held for that instant.
    /// The start is thus tried again for a short time.
    pub(super) fn start(&mut self) -> Box<TestCoordinator> {
        for _ in 0..200 {
            match self.try_start() {
                Start::Coordinating(coordinator) => return coordinator,
                Start::Busy { .. } => std::thread::sleep(std::time::Duration::from_millis(10)),
            }
        }
        panic!("a different coordinator holds the lock");
    }

    /// Stores a plan as a client does, with a connection of its own.
    pub(super) fn store(&self, plan: &Plan) {
        open_journal(&self.tree.database).record_plan(plan).unwrap();
    }
}

/// Applies a plan and returns the identity of its new operation.
pub(super) fn admitted(coordinator: &mut TestCoordinator, request: ApplyRequest) -> OperationId {
    match coordinator.apply(request) {
        ApplyOutcome::Admitted { operation_id } => operation_id,
        other => panic!("the plan was not admitted: {other:?}"),
    }
}

/// The refusal of an apply request.
pub(super) fn refusal(coordinator: &mut TestCoordinator, request: ApplyRequest) -> ActionError {
    match coordinator.apply(request) {
        ApplyOutcome::Refused { error } => error,
        other => panic!("the plan was not refused: {other:?}"),
    }
}

/// Calls `step` until the operation is finished. The clock moves to each
/// wake time.
pub(super) fn run(
    coordinator: &mut TestCoordinator,
    clock: &TestClock,
    operation_id: &OperationId,
) -> OperationView {
    for _ in 0..10_000 {
        let view: OperationView = coordinator.operation(operation_id).unwrap().unwrap();
        if view.phase == Phase::Finished {
            return view;
        }
        let progress = coordinator.step();
        if !progress.worked {
            match progress.wake_at {
                Some(wake_at) if wake_at.get() > clock.now() => clock.set(wake_at.get()),
                _ => clock.advance(SECOND / 10),
            }
        }
    }
    panic!("the operation did not finish");
}

/// A queued request of a client.
pub(super) fn queued(request: &str, body: RequestBody, now: u64) -> QueuedRequest {
    QueuedRequest {
        request_id: RequestId::new(request).unwrap(),
        principal: principal(),
        body,
        enqueued_at: wall(now),
    }
}

/// The allowance of a memory incident with `ceiling` application slots,
/// opened in the executor lifetime `epoch`.
pub(super) fn allowance(
    incident: &IncidentId,
    epoch: &ExecutorEpochId,
    ceiling: u32,
) -> IncidentAllowance {
    IncidentAllowance {
        incident_id: incident.clone(),
        generation: Generation::new(1),
        opened_in: epoch.clone(),
        slots: Some(SlotAllowance::new(ceiling)),
        work: None,
        pacing: Pacing {
            cooldown: Nanoseconds::new(30 * SECOND),
            max_cooldown: Nanoseconds::new(100 * SECOND),
            min_capacity_gain: Bytes::new(1),
        },
    }
}

/// A request of the controller: the plan is in memory, with the
/// allowance of its incident.
pub(super) fn automatic_request(plan: &Plan, allowance: IncidentAllowance) -> ApplyRequest {
    ApplyRequest {
        approval: approval(plan),
        principal: plan.principal.clone(),
        plan: Some(plan.clone()),
        incident: Some(allowance),
    }
}
