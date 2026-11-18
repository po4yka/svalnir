//! A synthetic host for the tests: one shared state behind a process
//! source, the native calls, and a clock.
//!
//! The fake source of the collector module is private to that module, so
//! this file has its own implementation of the same [`ProcessSource`]
//! trait.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use svalnir_core::action::{
    ActionClass, ApplicationBinding, Checked, ClientRole, Correlation, DispatchConsumption,
    DispatchReceipt, Durability, EnvelopeContent, Escalation, EvidenceBinding, ExecutorRole,
    LeaseResource, PLAN_SCHEMA_VERSION, PlanTarget, Principal, RecordingMode, RequestEnvelope,
    Reservation, ResourceLease, StepLimits, TargetBinding, Trigger,
};
use svalnir_core::authority::AuthorityBinding;
use svalnir_core::digest::ContentDigest;
use svalnir_core::file::{DeviceNumber, FileObjectEvidence, InodeNumber, LosslessPath};
use svalnir_core::id::{
    AdapterId, ApplicationInstanceId, BootId, ClockDomainId, ExecutorEpochId, LeaseId,
    MembershipSnapshotId, OperationId, PlanId, PolicyRevisionId, ProcessGenerationId, StepId,
    TargetId,
};
use svalnir_core::observation::UnavailableReason;
use svalnir_core::process::{
    AttributionMethod, ExecutableIdentity, Pid, ProcessAssociation, ProcessIdentity,
    ProcessStartTime, Uid,
};
use svalnir_core::quantity::Nanoseconds;
use svalnir_core::time::{MonotonicNanos, WallTime};

use super::super::{
    ApplicationCallResult, ApplicationExpectation, ApplicationRequest, ExecutorConfig,
    ExecutorContext, ProcessControl, ProcessExecutor, ProcessSignal, SignalResult, StepClock,
};
use crate::platform::process::{
    ProcessSource, QueryFailure, RawProcessInfo, RawUsage, RunningApplication, Timebase,
};

pub(super) const USER: u32 = 501;
pub(super) const OWN_PID: i32 = 900;
pub(super) const PARENT_PID: i32 = 800;
/// The grace period of the envelopes, in nanoseconds.
pub(super) const GRACE: u64 = 10_000;
/// The verification window of the envelopes, in nanoseconds.
pub(super) const WINDOW: u64 = 5_000;
/// The time of the fake clock at the start of a test.
pub(super) const START: u64 = 2_000;
pub(super) const BUNDLE: &str = "com.example.Example";

pub(super) fn pid(value: i32) -> Pid {
    Pid::new(value).unwrap()
}

pub(super) fn start_time(seconds: u64) -> ProcessStartTime {
    ProcessStartTime::from_timeval(seconds, 0).unwrap()
}

fn path_of(process: i32) -> String {
    format!("/Applications/Example.app/Contents/MacOS/Example{process}")
}

/// One process of the fake host.
#[derive(Debug, Clone)]
pub(super) struct FakeProcess {
    pub(super) start_seconds: u64,
    pub(super) effective_uid: u32,
    pub(super) real_uid: u32,
    pub(super) zombie: bool,
    pub(super) path: String,
    pub(super) inode: u64,
}

/// One native call that the executor issued.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum NativeCall {
    Signal(i32, ProcessSignal),
    Application(i32, ApplicationRequest, String, Vec<u8>),
}

#[derive(Debug)]
pub(super) struct World {
    pub(super) now: u64,
    pub(super) clock_fails: bool,
    pub(super) effective_uid: u32,
    pub(super) own: Option<i32>,
    pub(super) parent: Option<i32>,
    pub(super) processes: BTreeMap<i32, FakeProcess>,
    /// A failure of the identity query of a PID.
    pub(super) info_failures: BTreeMap<i32, QueryFailure>,
    /// A failure of the path query of a PID.
    pub(super) path_failures: BTreeMap<i32, QueryFailure>,
    /// The result of a signal call, when it is not `Delivered`.
    pub(super) signal_results: BTreeMap<i32, SignalResult>,
    /// The result of an application call, when it is not `Accepted`.
    pub(super) application_results: BTreeMap<i32, ApplicationCallResult>,
    /// The processes that exit at a call.
    pub(super) exits_on_call: BTreeSet<i32>,
    pub(super) calls: Vec<NativeCall>,
    /// The time that each native call takes, in nanoseconds.
    pub(super) call_duration: u64,
    /// The clock gives no value after the first native call.
    pub(super) clock_fails_after_call: bool,
    /// The number of identity queries.
    pub(super) info_queries: u32,
}

/// The shared state of the fake host.
#[derive(Debug, Clone)]
pub(super) struct Host(pub(super) Rc<RefCell<World>>);

impl Host {
    pub(super) fn new() -> Self {
        Self(Rc::new(RefCell::new(World {
            now: START,
            clock_fails: false,
            effective_uid: USER,
            own: Some(OWN_PID),
            parent: Some(PARENT_PID),
            processes: BTreeMap::new(),
            info_failures: BTreeMap::new(),
            path_failures: BTreeMap::new(),
            signal_results: BTreeMap::new(),
            application_results: BTreeMap::new(),
            exits_on_call: BTreeSet::new(),
            calls: Vec::new(),
            call_duration: 0,
            clock_fails_after_call: false,
            info_queries: 0,
        })))
    }

    /// Adds a running process with the evidence that [`member`] plans.
    pub(super) fn with_process(self, process: i32, start_seconds: u64) -> Self {
        self.0.borrow_mut().processes.insert(
            process,
            FakeProcess {
                start_seconds,
                effective_uid: USER,
                real_uid: USER,
                zombie: false,
                path: path_of(process),
                inode: u64::try_from(process).unwrap(),
            },
        );
        self
    }

    pub(super) fn change(&self, change: impl FnOnce(&mut World)) {
        change(&mut self.0.borrow_mut());
    }

    pub(super) fn advance(&self, nanoseconds: u64) {
        self.0.borrow_mut().now += nanoseconds;
    }

    pub(super) fn exit(&self, process: i32) {
        self.0.borrow_mut().processes.remove(&process);
    }

    pub(super) fn calls(&self) -> Vec<NativeCall> {
        self.0.borrow().calls.clone()
    }

    pub(super) fn executor(&self) -> ProcessExecutor<Host, Host, Host> {
        ProcessExecutor::new(
            self.clone(),
            self.clone(),
            self.clone(),
            context(),
            ExecutorConfig::default(),
        )
    }
}

pub(super) fn context() -> ExecutorContext {
    ExecutorContext {
        boot_id: BootId::new("boot_1").unwrap(),
        clock_domain: ClockDomainId::new("clock_1").unwrap(),
        executor_epoch: ExecutorEpochId::new("epoch_1").unwrap(),
    }
}

impl ProcessSource for Host {
    fn effective_uid(&self) -> Uid {
        Uid::new(self.0.borrow().effective_uid)
    }

    fn list_pids(&self) -> Result<Vec<Pid>, QueryFailure> {
        Ok(self
            .0
            .borrow()
            .processes
            .keys()
            .map(|key| pid(*key))
            .collect())
    }

    fn process_info(&self, process: Pid) -> Result<RawProcessInfo, QueryFailure> {
        let mut world = self.0.borrow_mut();
        world.info_queries += 1;
        if let Some(failure) = world.info_failures.get(&process.get()) {
            return Err(*failure);
        }
        let record: &FakeProcess = world
            .processes
            .get(&process.get())
            .ok_or(QueryFailure::Gone)?;
        Ok(RawProcessInfo {
            pid: process,
            parent_pid: Some(pid(1)),
            effective_uid: Uid::new(record.effective_uid),
            real_uid: Uid::new(record.real_uid),
            start_time: start_time(record.start_seconds),
            zombie: record.zombie,
        })
    }

    fn executable_path(&self, process: Pid) -> Result<LosslessPath, QueryFailure> {
        let world = self.0.borrow();
        if let Some(failure) = world.path_failures.get(&process.get()) {
            return Err(*failure);
        }
        let record: &FakeProcess = world
            .processes
            .get(&process.get())
            .ok_or(QueryFailure::Gone)?;
        if record.zombie {
            return Err(QueryFailure::Gone);
        }
        Ok(LosslessPath::from_bytes(record.path.clone()).unwrap())
    }

    fn file_evidence(&self, path: &LosslessPath) -> Result<FileObjectEvidence, QueryFailure> {
        self.0
            .borrow()
            .processes
            .values()
            .find(|record| record.path.as_bytes() == path.as_bytes())
            .map(|record| FileObjectEvidence {
                device: DeviceNumber::new(1),
                inode: InodeNumber::new(record.inode),
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
        StepClock::monotonic_now(self)
    }

    fn sleep_time(&self) -> Result<Nanoseconds, UnavailableReason> {
        Ok(Nanoseconds::ZERO)
    }

    fn wall_now(&self) -> Result<WallTime, QueryFailure> {
        WallTime::from_unix(1_794_830_400, 0).map_err(|_| QueryFailure::Inconsistent)
    }
}

impl StepClock for Host {
    fn monotonic_now(&self) -> Result<MonotonicNanos, QueryFailure> {
        let world = self.0.borrow();
        if world.clock_fails {
            return Err(QueryFailure::Failed(5));
        }
        Ok(MonotonicNanos::new(world.now))
    }

    fn wall_now(&self) -> Option<WallTime> {
        WallTime::from_unix(1_794_830_400, 0).ok()
    }
}

impl World {
    fn apply(&mut self, process: i32) {
        self.now += self.call_duration;
        if self.clock_fails_after_call {
            self.clock_fails = true;
        }
        if self.exits_on_call.contains(&process) {
            self.processes.remove(&process);
        }
    }
}

impl ProcessControl for Host {
    fn own_process(&self) -> Option<Pid> {
        self.0.borrow().own.map(pid)
    }

    fn parent_process(&self) -> Option<Pid> {
        self.0.borrow().parent.map(pid)
    }

    fn signal(&self, process: Pid, signal: ProcessSignal) -> SignalResult {
        let mut world = self.0.borrow_mut();
        world.calls.push(NativeCall::Signal(process.get(), signal));
        world.apply(process.get());
        world
            .signal_results
            .get(&process.get())
            .copied()
            .unwrap_or(SignalResult::Delivered)
    }

    fn request_application_exit(
        &self,
        expected: &ApplicationExpectation<'_>,
        request: ApplicationRequest,
    ) -> ApplicationCallResult {
        let mut world = self.0.borrow_mut();
        let process: i32 = expected.pid.get();
        world.calls.push(NativeCall::Application(
            process,
            request,
            expected.bundle_identifier.to_owned(),
            expected.executable_path.as_bytes().to_vec(),
        ));
        world.apply(process);
        world
            .application_results
            .get(&process)
            .copied()
            .unwrap_or(ApplicationCallResult::Accepted)
    }
}

// Fixtures of the contract types.

pub(super) fn instance() -> ApplicationInstanceId {
    ApplicationInstanceId::new("app_1").unwrap()
}

/// The registered process of the application.
pub(super) fn application() -> ProcessAssociation {
    ProcessAssociation::Application {
        instance_id: instance(),
        bundle_identifier: BUNDLE.to_owned(),
        attribution: AttributionMethod::LaunchServices,
    }
}

/// A helper of the application.
pub(super) fn helper() -> ProcessAssociation {
    ProcessAssociation::Application {
        instance_id: instance(),
        bundle_identifier: BUNDLE.to_owned(),
        attribution: AttributionMethod::ResponsibleProcess,
    }
}

/// A process of a managed job.
pub(super) fn job() -> ProcessAssociation {
    ProcessAssociation::ManagedJob {
        instance_id: instance(),
        label: "com.example.job".to_owned(),
        attribution: AttributionMethod::LaunchdJob,
    }
}

pub(super) fn generation(process: i32) -> ProcessGenerationId {
    ProcessGenerationId::new(format!("pg-{process}")).unwrap()
}

/// The planned identity of the process that [`Host::with_process`] adds
/// with the same PID and start time.
pub(super) fn member(
    process: i32,
    start_seconds: u64,
    association: ProcessAssociation,
) -> ProcessIdentity {
    ProcessIdentity {
        generation_id: generation(process),
        pid: pid(process),
        start_time: start_time(start_seconds),
        uid: Uid::new(USER),
        boot_id: BootId::new("boot_1").unwrap(),
        executable: Some(ExecutableIdentity {
            path: LosslessPath::from_bytes(path_of(process)).unwrap(),
            file: Some(FileObjectEvidence {
                device: DeviceNumber::new(1),
                inode: InodeNumber::new(u64::try_from(process).unwrap()),
            }),
            code_signature: None,
        }),
        association,
    }
}

/// The operation of each envelope of [`content`].
pub(super) static OPERATION: std::sync::LazyLock<OperationId> =
    std::sync::LazyLock::new(|| OperationId::new("operation_1").unwrap());

/// The graceful step of a [`GracefulRecord`](super::super::GracefulRecord).
/// Each envelope of [`content`] has the step `step_1`.
pub(super) static GRACEFUL_STEP: std::sync::LazyLock<StepId> =
    std::sync::LazyLock::new(|| StepId::new("step_graceful").unwrap());

pub(super) fn target_id() -> TargetId {
    TargetId::new("app").unwrap()
}

/// The content of a manual envelope of `class` with the force strategy
/// `escalation` for `members`.
pub(super) fn content(
    class: ActionClass,
    escalation: Escalation,
    members: Vec<ProcessIdentity>,
    user: u32,
) -> EnvelopeContent {
    let operation: OperationId = OperationId::new("operation_1").unwrap();
    let epoch: ExecutorEpochId = ExecutorEpochId::new("epoch_1").unwrap();
    let grace: Option<Nanoseconds> =
        matches!(escalation, Escalation::ForceAfterGrace).then_some(Nanoseconds::new(GRACE));
    let lease: ResourceLease = ResourceLease {
        lease_id: LeaseId::new("lease_1").unwrap(),
        resource: LeaseResource::ProcessGeneration(members[0].generation_id.clone()),
        owner: operation.clone(),
        executor_epoch: epoch.clone(),
        expires_at: MonotonicNanos::new(1_000_000_000),
    };
    EnvelopeContent {
        schema_version: PLAN_SCHEMA_VERSION,
        action_class: class,
        adapter: AdapterId::new("macos.appkit").unwrap(),
        correlation: Correlation {
            plan_id: PlanId::new("plan_1").unwrap(),
            plan_digest: ContentDigest::of_bytes(b"plan"),
            operation_id: operation,
            step_id: StepId::new("step_1").unwrap(),
            parent_operation_id: None,
        },
        principal: Principal {
            uid: Uid::new(user),
            session: None,
            role: ClientRole::Cli,
        },
        executor: ExecutorRole::User,
        authority: AuthorityBinding {
            policy_revision: PolicyRevisionId::new("policy_1").unwrap(),
            action_grants: Vec::new(),
            privilege_grant: None,
        },
        trigger: Trigger::manual(),
        target: PlanTarget {
            target_id: target_id(),
            binding: TargetBinding::Application(ApplicationBinding {
                instance_id: instance(),
                membership: MembershipSnapshotId::new("members_1").unwrap(),
                members,
            }),
        },
        evidence: EvidenceBinding {
            clock_domain: ClockDomainId::new("clock_1").unwrap(),
            boot_id: BootId::new("boot_1").unwrap(),
            executor_epoch: epoch,
            observed_at: MonotonicNanos::new(1_000),
            valid_until: MonotonicNanos::new(900_000_000),
        },
        limits: StepLimits {
            reservation: Reservation::ApplicationSlot { incident_id: None },
            deadline: MonotonicNanos::new(800_000_000),
            grace,
            verification_window: Nanoseconds::new(WINDOW),
            escalation,
        },
        leases: vec![lease],
        recording: RecordingMode::Durable,
    }
}

pub(super) fn envelope(
    class: ActionClass,
    escalation: Escalation,
    members: Vec<ProcessIdentity>,
) -> RequestEnvelope {
    Checked::new(content(class, escalation, members, USER)).unwrap()
}

pub(super) fn graceful(escalation: Escalation, members: Vec<ProcessIdentity>) -> RequestEnvelope {
    envelope(ActionClass::RequestApplicationExit, escalation, members)
}

pub(super) fn force(escalation: Escalation, members: Vec<ProcessIdentity>) -> RequestEnvelope {
    envelope(ActionClass::ForceApplicationExit, escalation, members)
}

/// The receipt of a durable dispatch consumption by this caller.
pub(super) fn receipt() -> DispatchReceipt {
    DispatchReceipt {
        consumption: DispatchConsumption::Consumed,
        durability: Durability::Durable,
    }
}
