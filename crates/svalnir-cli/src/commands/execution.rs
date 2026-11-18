//! The execution of an approved plan: the transient coordinator of this
//! process, or the request queue of the journal.
//!
//! Milestone 2 has no socket. When no process holds the coordinator lock
//! of the journal, this process takes it, executes the plan with the same
//! coordinator code as the agent, and releases it: a transient coordinator.
//! It evaluates no guard and makes no automatic plan. When a different
//! process holds the lock, this process writes the request to the queue of
//! the journal, and that process executes it; this process then reads the
//! result by its identity.
//!
//! The transient coordinator is the executor of its operation. It
//! continues to its end also after the client wait ended (`--no-wait`, a
//! timeout, or Ctrl+C): the end of a wait cancels nothing.

use std::sync::Arc;
use std::time::{Duration, Instant};

use svalnir_agent::controller::{AuthorityRecords, SharedAuthority};
use svalnir_agent::coordinator::{
    ApplyOutcome, ApplyRequest, Coordinator, CoordinatorConfig, Dependencies, Idle, Phase,
    Progress, Start, SystemProbe,
};
use svalnir_agent::executor::fs::{ApprovedRoots, ExecutorLimits, FsExecutor, FsExecutorConfig};
use svalnir_agent::executor::process::{
    DarwinProcessControl, ExecutorConfig, ExecutorContext, ProcessExecutor, SourceClock,
};
use svalnir_agent::journal::{
    AgentRecord, Enqueued, OperationJournal, QueuedRequest, RequestBody, RequestCompletion,
    RequestStatus,
};
use svalnir_agent::platform::memory::CollectionContext;
use svalnir_agent::platform::process::DarwinProcessSource;
use svalnir_agent::platform::volume;
use svalnir_agent::rules::ReviewedRules;
use svalnir_agent::runtime::host::{EpochIds, SystemAgentClock, SystemMeasurements};
use svalnir_agent::runtime::{AgentClock, ClockHandle, ThreadIdle};
use svalnir_core::action::{
    ActionError, Operation, OperationState, Plan, PlanApproval, TargetBinding,
};
use svalnir_core::file::LosslessPath;
use svalnir_core::grant::AuthorityState;
use svalnir_core::id::{AdapterId, ExecutorEpochId, OperationId, RequestId};
use svalnir_core::policy::ControlPlaneProcess;
use svalnir_core::quantity::Nanoseconds;
use svalnir_core::volume::VolumeIdentity;

use super::operation_view::OperationReport;
use super::session::{self, journal_error, open_journal};
use crate::environment::Environment;
use crate::interrupt::Interrupt;
use crate::output::{ErrorBody, ErrorFamily, ErrorStage, NextAction};

/// The largest number of steps that a transient coordinator uses to
/// reconcile the operations of an earlier executor lifetime.
const MAX_RECONCILIATION_STEPS: u32 = 512;

/// The number of times that the start of the transient coordinator is
/// tried again when the lock is held.
const LOCK_RETRIES: u32 = 3;

/// The time between two tries.
const LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(60);

/// The number of queue reads between two reads of the coordinator lock.
const PRESENCE_CHECK_INTERVAL: u32 = 10;

/// The time between two reads of the journal while a different process
/// executes the request.
const QUEUE_POLL: Duration = Duration::from_millis(100);

/// How long a `--no-wait` request waits for its admission by a different
/// process before it reports the request as queued.
pub(crate) const ADMISSION_WAIT: Duration = Duration::from_secs(10);

/// The longest time for which a transient coordinator continues after the
/// client wait ended. The execution deadline of the plan is shorter.
const MAX_COMPLETION_TIME: Duration = Duration::from_hours(2);

/// What executes the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Executor {
    /// This process, as a transient coordinator.
    TransientCoordinator,
    /// The process that holds the coordinator lock, through the request
    /// queue of the journal.
    QueuedForCoordinator,
}

/// The inputs of an apply.
pub(crate) struct ExecutionInput<'a> {
    pub(crate) environment: &'a Environment,
    pub(crate) plan: &'a Plan,
    /// The authority record of the journal.
    pub(crate) authority: AuthorityState,
    /// The processes that this client must not stop: itself and its
    /// ancestors. `None` when they are not known, which permits no
    /// application step.
    pub(crate) control_plane: Option<Vec<ControlPlaneProcess>>,
    /// The identity of the queue request, when a different process
    /// executes the plan.
    pub(crate) request_id: RequestId,
}

/// The result of an apply request.
pub(crate) enum Applied {
    /// The request was refused. Nothing changed.
    Refused(ActionError),
    /// The plan was applied before; this is its operation.
    Existing(Box<Operation>),
    /// This process admitted the operation and executes it.
    Transient(Box<Running>),
    /// The request is in the queue of the journal.
    Queued(Box<Queued>),
}

/// The number of reads in sequence that a wait tries again when the
/// journal is busy.
pub(crate) const BUSY_READS: u32 = 40;

/// How a wait ended.
pub(crate) enum WaitEnd {
    /// The operation has its final record, or an unknown outcome.
    Finished(OperationReport),
    /// The time of the client ended. Nothing was canceled.
    TimedOut(Option<OperationReport>),
    /// The user interrupted the client. Nothing was canceled.
    Interrupted(Option<OperationReport>),
    /// The coordinator refused the queued request.
    Rejected(ActionError),
    /// The journal gave no answer.
    Failed(ErrorBody),
}

fn execution_error(code: &'static str, message: &str) -> ErrorBody {
    ErrorBody::new(
        code,
        ErrorFamily::Native,
        ErrorStage::Dispatch,
        format!("{message}; the command made no change"),
    )
}

fn coordinator_config() -> Result<CoordinatorConfig, ErrorBody> {
    let adapter = |name: &str| AdapterId::new(name).map_err(|_| session::identity_error());
    Ok(CoordinatorConfig {
        filesystem_adapter: adapter("svalnir.filesystem")?,
        process_adapter: adapter("macos.process")?,
        batch_targets: 8,
        poll_interval: Nanoseconds::new(250_000_000),
        volatile_capacity: 16,
        role: svalnir_agent::journal::CoordinatorRole::Client,
    })
}

/// The volumes of the capacity observations of a plan: the volume at the
/// root path that the sealed plan binds for each file target. The volume is
/// read now, and it is used only when its identity and its mount generation
/// are those of the binding. A root whose volume cannot be read, or that is
/// on a different volume or mount than at the plan, gives no volume: the
/// operation then has no capacity observation for it, and the executor
/// examines the root itself before each call.
fn observed_volumes(plan: &Plan) -> Vec<VolumeIdentity> {
    let mut volumes: Vec<VolumeIdentity> = Vec::new();
    for target in &plan.targets {
        let TargetBinding::File(binding) = &target.binding else {
            continue;
        };
        if volumes
            .iter()
            .any(|volume| volume.volume_id == binding.volume_id)
        {
            continue;
        }
        let Ok(mounted) = volume::volume_at(&binding.root_path.to_path_buf()) else {
            continue;
        };
        if mounted.identity.volume_id == binding.volume_id
            && mounted.identity.mount_id == binding.mount_id
        {
            volumes.push(mounted.identity);
        }
    }
    volumes
}

/// The home directory of the user as a canonical path. The filesystem
/// executor refuses the home directory and each directory that contains
/// it.
fn home_directory(environment: &Environment) -> Result<LosslessPath, ErrorBody> {
    environment
        .home
        .as_ref()
        .and_then(|home| std::fs::canonicalize(home).ok())
        .and_then(|home| LosslessPath::from_path(&home).ok())
        .ok_or_else(|| {
            execution_error(
                "home_directory_unavailable",
                "the home directory of the user is not known, so the filesystem executor cannot protect it",
            )
        })
}

fn dependencies(
    input: &ExecutionInput<'_>,
    epoch: &ExecutorEpochId,
) -> Result<(Dependencies, Arc<dyn AgentClock>, SharedAuthority), ErrorBody> {
    let context: Arc<CollectionContext> = Arc::new(
        CollectionContext::for_current_process()
            .map_err(|error| crate::host::collector_unavailable(&error.to_string()))?,
    );
    let clock: Arc<dyn AgentClock> = Arc::new(SystemAgentClock::new(&context));
    let registry: ReviewedRules = ReviewedRules::new().map_err(|_| {
        execution_error(
            "rule_registry_unavailable",
            "the rule registry of this build is not usable",
        )
    })?;
    // This process has no approved root of its own. The coordinator gives
    // the executor the roots that the file targets of the sealed plan
    // bind, which the digest of the approval covers. The plan document is
    // thus no input of the authorization.
    let roots: ApprovedRoots = ApprovedRoots::default();
    let filesystem: FsExecutor = FsExecutor::new(
        &FsExecutorConfig {
            home_directory: home_directory(input.environment)?,
            limits: ExecutorLimits::default(),
        },
        input.environment.seams.trash_backend(),
    )
    .map_err(|_| {
        execution_error(
            "filesystem_executor_unavailable",
            "the filesystem executor refused the home directory",
        )
    })?;
    let identity = context.identity();
    let application = ProcessExecutor::new(
        DarwinProcessSource::new(),
        DarwinProcessControl,
        SourceClock(DarwinProcessSource::new()),
        ExecutorContext {
            boot_id: identity.boot_id.clone(),
            clock_domain: identity.clock_domain.clone(),
            executor_epoch: epoch.clone(),
        },
        ExecutorConfig::default(),
    );
    let mut records: AuthorityRecords =
        AuthorityRecords::new(session::current_uid(), Box::new(registry));
    records.state = Some(input.authority.clone());
    records.control_plane.clone_from(&input.control_plane);
    let authority: SharedAuthority = SharedAuthority::new(records);
    let volumes: Vec<VolumeIdentity> = observed_volumes(input.plan);
    Ok((
        Dependencies {
            clock: Box::new(ClockHandle(Arc::clone(&clock))),
            authority: Box::new(authority.clone()),
            measurements: Box::new(SystemMeasurements::new(Arc::clone(&context), volumes)),
            ids: Box::new(EpochIds::new(epoch.clone())),
            filesystem: Box::new(filesystem),
            roots: roots.clone(),
            application: Box::new(application),
            probe: Box::new(SystemProbe::new(roots, DarwinProcessSource::new())),
        },
        clock,
        authority,
    ))
}

/// Starts a coordinator on the journal, or reports that a different
/// process holds the coordinator lock.
fn start_coordinator(
    environment: &Environment,
    database: &std::path::Path,
    epoch: &ExecutorEpochId,
    dependencies: Dependencies,
) -> Result<Start<OperationJournal>, ErrorBody> {
    let journal: OperationJournal = open_journal(environment)?;
    let unavailable = || {
        ErrorBody::new(
            "coordinator_unavailable",
            ErrorFamily::Recording,
            ErrorStage::Dispatch,
            "the coordinator lock or the registration of the journal cannot be used; the command made no change",
        )
    };
    let config: CoordinatorConfig = coordinator_config()?;
    // A status query of a different client holds the lock for an instant.
    // The start is tried again before the request goes to the queue, so
    // that such a query does not send the request to a queue that no
    // process serves.
    let mut start = Coordinator::start(
        journal,
        database,
        epoch.clone(),
        config.clone(),
        dependencies,
    )
    .map_err(|_| unavailable())?;
    for _ in 0..LOCK_RETRIES {
        match start {
            Start::Busy {
                journal,
                dependencies,
                holder: _,
            } => {
                std::thread::sleep(LOCK_RETRY_INTERVAL);
                start = Coordinator::start(
                    journal,
                    database,
                    epoch.clone(),
                    config.clone(),
                    *dependencies,
                )
                .map_err(|_| unavailable())?;
            }
            Start::Coordinating(_) => break,
        }
    }
    Ok(start)
}

/// Applies the stored plan of `input`.
///
/// # Errors
///
/// Returns an error when the journal, the clocks, or the executors of
/// this process are not usable. A refusal of the coordinator is
/// [`Applied::Refused`].
pub(crate) fn apply(input: &ExecutionInput<'_>) -> Result<Applied, ErrorBody> {
    let approval = PlanApproval {
        plan_id: input.plan.plan_id.clone(),
        digest: input.plan.digest().clone(),
    };
    let principal = session::principal();
    let epoch: ExecutorEpochId =
        ExecutorEpochId::new(session::new_id("client")).map_err(|_| session::identity_error())?;
    let (dependencies, clock, authority) = dependencies(input, &epoch)?;
    let database = input.environment.journal_path()?;
    let start = start_coordinator(input.environment, &database, &epoch, dependencies)?;
    match start {
        Start::Coordinating(mut coordinator) => {
            // The client read the authority record before the approval
            // question, and a different client can change the record
            // while the question waits. The admission uses the record
            // that the journal has now, read with the coordinator lock.
            let authority_revision: u64 =
                match read_authority_record(coordinator.journal(), &authority) {
                    Ok(revision) => revision,
                    Err(error) => {
                        release(coordinator);
                        return Err(error);
                    }
                };
            // The operations of an earlier executor lifetime are
            // reconciled before a new admission.
            let mut steps: u32 = 0;
            while coordinator.reconciliation_pending() && steps < MAX_RECONCILIATION_STEPS {
                steps = steps.saturating_add(1);
                coordinator.step();
            }
            let outcome: ApplyOutcome = coordinator.apply(ApplyRequest {
                approval,
                principal,
                plan: None,
                incident: None,
            });
            match outcome {
                ApplyOutcome::Admitted { operation_id } => {
                    Ok(Applied::Transient(Box::new(Running {
                        coordinator,
                        clock,
                        operation_id,
                        authority,
                        authority_revision,
                        authority_read_at: Instant::now(),
                    })))
                }
                ApplyOutcome::Existing { operation } => {
                    release(coordinator);
                    Ok(Applied::Existing(operation))
                }
                ApplyOutcome::Refused { error } => {
                    release(coordinator);
                    Ok(Applied::Refused(error))
                }
            }
        }
        Start::Busy { mut journal, .. } => {
            let request = QueuedRequest {
                request_id: input.request_id.clone(),
                principal,
                body: RequestBody::Apply { approval },
                enqueued_at: session::wall_now(),
            };
            match journal
                .enqueue_request(&request)
                .map_err(|error| journal_error(&error))?
            {
                Enqueued::New | Enqueued::Existing(_) => Ok(Applied::Queued(Box::new(Queued {
                    journal,
                    database,
                    plan_id: input.plan.plan_id.clone(),
                    request_id: request.request_id,
                }))),
            }
        }
    }
}

/// The longest time in which a transient coordinator waits for an
/// authority record that it cannot read again. It runs no step in that
/// time, and after it the coordinator has no authority.
const AUTHORITY_READ_GRACE: Duration = Duration::from_secs(2);

/// The time before a transient coordinator reads the authority record
/// again after a read that failed.
const AUTHORITY_READ_RETRY: Duration = Duration::from_millis(50);

/// Reads the authority record of the journal into the records of the
/// coordinator and returns the revision of the record.
///
/// A journal with no record, or with a record of a different user, gives
/// the coordinator no authority: it then refuses each step.
fn read_authority_record(
    journal: &OperationJournal,
    authority: &SharedAuthority,
) -> Result<u64, ErrorBody> {
    let stored = journal
        .agent_record::<AuthorityState>(AgentRecord::Authority)
        .map_err(|error| journal_error(&error))?;
    match stored {
        Some(stored) if stored.record.principal == session::current_uid() => {
            authority.records().state = Some(stored.record);
            Ok(stored.revision)
        }
        Some(stored) => {
            authority.records().state = None;
            Ok(stored.revision)
        }
        None => {
            authority.records().state = None;
            // A journal with no record has the revision 0, so the first
            // record that a client writes changes the revision and is
            // read.
            Ok(0)
        }
    }
}

/// Releases the registration of a coordinator that has no operation. An
/// operation that is not settled keeps the registration, so that the next
/// coordinator reconciles it.
fn release(coordinator: Box<Coordinator<OperationJournal>>) {
    drop((*coordinator).shutdown());
}

/// An operation that this process executes.
pub(crate) struct Running {
    coordinator: Box<Coordinator<OperationJournal>>,
    clock: Arc<dyn AgentClock>,
    operation_id: OperationId,
    /// The authority records of the coordinator.
    authority: SharedAuthority,
    /// The revision of the authority record that the coordinator has.
    authority_revision: u64,
    /// The time of the last read of the authority record that had a
    /// result.
    authority_read_at: Instant,
}

impl Running {
    /// The operation.
    pub(crate) fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    /// The current view of the operation.
    pub(crate) fn report(&self) -> Option<OperationReport> {
        self.coordinator
            .operation(&self.operation_id)
            .ok()
            .flatten()
            .map(|view| OperationReport::of_view(&view))
    }

    fn is_finished(&self) -> bool {
        self.coordinator
            .operation(&self.operation_id)
            .ok()
            .flatten()
            .is_none_or(|view| view.phase == Phase::Finished)
    }

    /// Does one unit of work and waits for the next one when there is
    /// none now.
    fn advance(&mut self) {
        // The record is read before the step. A step does not run with a
        // record that this read did not confirm.
        if !self.refresh_authority() {
            std::thread::sleep(AUTHORITY_READ_RETRY);
            return;
        }
        let progress: Progress = self.coordinator.step();
        if !progress.worked {
            ThreadIdle::new(Arc::clone(&self.clock)).idle(progress.wake_at);
        }
    }

    /// Reads the authority record again when its revision changed, as the
    /// agent does at each tick, so that a change of the policy revision
    /// by a different client stops the later steps.
    ///
    /// A record that cannot be read is not authority. After
    /// [`AUTHORITY_READ_GRACE`] with no read, the coordinator has no
    /// record and refuses each later step, until a read has a result.
    ///
    /// Returns false when the record was not read and the coordinator
    /// still has an earlier record: the caller then runs no step.
    fn refresh_authority(&mut self) -> bool {
        let journal: &OperationJournal = self.coordinator.journal();
        let read: Result<(), ErrorBody> = journal
            .agent_record_revision(AgentRecord::Authority)
            .map_err(|error| journal_error(&error))
            .and_then(|revision| {
                if revision == self.authority_revision {
                    return Ok(());
                }
                read_authority_record(journal, &self.authority).map(|revision| {
                    self.authority_revision = revision;
                })
            });
        match read {
            Ok(()) => {
                self.authority_read_at = Instant::now();
                true
            }
            Err(_) if self.authority_read_at.elapsed() >= AUTHORITY_READ_GRACE => {
                self.authority.records().state = None;
                // The next read that has a result sets the record again.
                self.authority_revision = u64::MAX;
                true
            }
            Err(_) => false,
        }
    }

    /// Executes the operation until it is finished, the time of the
    /// client ends, or the user interrupts the client. The operation
    /// continues after each of the last two: call [`Running::complete`].
    pub(crate) fn wait(&mut self, timeout: Option<Duration>, interrupt: &Interrupt) -> WaitEnd {
        interrupt.arm();
        let started: Instant = Instant::now();
        loop {
            if self.is_finished() {
                return match self.report() {
                    Some(report) => WaitEnd::Finished(report),
                    None => WaitEnd::Failed(ErrorBody::new(
                        "operation_record_unavailable",
                        ErrorFamily::Outcome,
                        ErrorStage::Execution,
                        "the record of the operation cannot be read; query it with `svalnir operations show`",
                    )
                    .with_operation(self.operation_id.as_str())
                    .with_next_action(NextAction::QueryOperation)),
                };
            }
            if interrupt.is_requested() {
                return WaitEnd::Interrupted(self.report());
            }
            if timeout.is_some_and(|timeout| started.elapsed() >= timeout) {
                return WaitEnd::TimedOut(self.report());
            }
            self.advance();
        }
    }

    /// Executes the operation to its end with no client wait, then each
    /// request that this coordinator claimed from the queue, and releases
    /// the coordinator. Returns the last view of the operation.
    pub(crate) fn complete(mut self) -> Option<OperationReport> {
        let started: Instant = Instant::now();
        while !self.is_finished() && started.elapsed() < MAX_COMPLETION_TIME {
            self.advance();
        }
        let report: Option<OperationReport> = self.report();
        // A step also serves the request queue, so this coordinator can
        // have admitted the request of a different client. It executes
        // that work before it stops: an operation that it leaves is never
        // dispatched again.
        while started.elapsed() < MAX_COMPLETION_TIME {
            if !self.refresh_authority() {
                std::thread::sleep(AUTHORITY_READ_RETRY);
                continue;
            }
            let progress: Progress = self.coordinator.step();
            if !progress.worked && progress.wake_at.is_none() {
                break;
            }
            if !progress.worked {
                ThreadIdle::new(Arc::clone(&self.clock)).idle(progress.wake_at);
            }
        }
        release(self.coordinator);
        report
    }
}

/// A request that a different process executes.
pub(crate) struct Queued {
    journal: OperationJournal,
    database: std::path::PathBuf,
    plan_id: svalnir_core::id::PlanId,
    request_id: RequestId,
}

/// What the queue shows for a request.
enum QueueState {
    /// The coordinator did not complete the request.
    Pending,
    Rejected(ActionError),
    Operation(Box<Operation>),
}

impl Queued {
    /// The identity of the request.
    pub(crate) fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    fn state(&self) -> Result<QueueState, ErrorBody> {
        let status: Option<RequestStatus> = self
            .journal
            .request_status(&self.request_id)
            .map_err(|error| journal_error(&error))?;
        match status {
            Some(RequestStatus::Completed {
                completion: RequestCompletion::Operation { operation_id },
            }) => self
                .journal
                .try_operation(&operation_id)
                .map_err(|error| journal_error(&error))?
                .map_or(Ok(QueueState::Pending), |operation| {
                    Ok(QueueState::Operation(Box::new(operation)))
                }),
            Some(RequestStatus::Completed {
                completion: RequestCompletion::Rejected { error },
            }) => Ok(QueueState::Rejected(error)),
            _ => Ok(QueueState::Pending),
        }
    }

    /// The error of a journal read that failed during the wait. It names
    /// the plan and, when the request was admitted, the operation: the
    /// request or the operation continues, and only this client has no
    /// result.
    fn read_failure(&self, error: ErrorBody, last: Option<&OperationReport>) -> ErrorBody {
        let Some(report) = last else {
            return error.with_plan(self.plan_id.as_str());
        };
        ErrorBody::new(
            "operation_record_unavailable",
            ErrorFamily::Outcome,
            ErrorStage::Execution,
            format!(
                "the journal cannot be read now ({}); the operation was admitted and continues, and its result is not known to this response; query it with `svalnir operations show`",
                error.code
            ),
        )
        .with_plan(self.plan_id.as_str())
        .with_operation(report.operation_id.as_str())
        .with_next_action(NextAction::QueryOperation)
    }

    /// Waits for the result of the request. With `admission_only`, the
    /// wait ends when the operation exists.
    pub(crate) fn wait(
        &self,
        timeout: Option<Duration>,
        admission_only: bool,
        interrupt: &Interrupt,
    ) -> WaitEnd {
        interrupt.arm();
        let started: Instant = Instant::now();
        let mut last: Option<OperationReport> = None;
        let mut reads: u32 = 0;
        let mut failed_reads: u32 = 0;
        loop {
            reads = reads.wrapping_add(1);
            let state = self.state();
            // A request that no process serves does not change. The next
            // coordinator serves it.
            if matches!(state, Ok(QueueState::Pending))
                && reads.is_multiple_of(PRESENCE_CHECK_INTERVAL)
                && session::coordinator_presence(&self.database)
                    == session::CoordinatorPresence::NotRunning
                && matches!(self.state(), Ok(QueueState::Pending))
            {
                return WaitEnd::Failed(
                    ErrorBody::new(
                        "coordinator_stopped",
                        ErrorFamily::Evidence,
                        ErrorStage::Dispatch,
                        "the process that held the coordinator lock stopped before it served the request; the request is in the queue and the next coordinator serves it; send the command again to execute the plan in this process",
                    )
                    .with_plan(self.plan_id.as_str())
                    .with_next_action(NextAction::RefreshObservation),
                );
            }
            if state.is_ok() {
                failed_reads = 0;
            }
            match state {
                // A busy journal is read again: a different process
                // writes to it.
                Err(error) if &*error.code == "journal_busy" && failed_reads < BUSY_READS => {
                    failed_reads = failed_reads.saturating_add(1);
                    drop(error);
                }
                Err(error) => return WaitEnd::Failed(self.read_failure(error, last.as_ref())),
                Ok(QueueState::Rejected(error)) => return WaitEnd::Rejected(error),
                Ok(QueueState::Operation(operation)) => {
                    // The coordinator that serves the request records its
                    // observations in the journal.
                    let report = OperationReport::of_record(&operation, None)
                        .with_recorded_effects(&self.journal);
                    let ended: bool = operation.state().is_settled()
                        || operation.state() == &OperationState::UnknownOutcome;
                    if ended || admission_only {
                        return WaitEnd::Finished(report);
                    }
                    last = Some(report);
                }
                Ok(QueueState::Pending) => {}
            }
            if interrupt.is_requested() {
                return WaitEnd::Interrupted(last);
            }
            if timeout.is_some_and(|timeout| started.elapsed() >= timeout) {
                return WaitEnd::TimedOut(last);
            }
            std::thread::sleep(QUEUE_POLL);
        }
    }
}
