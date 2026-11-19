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
    Progress, Start, SystemProbe, code,
};
use svalnir_agent::executor::fs::{ApprovedRoots, ExecutorLimits, FsExecutor, FsExecutorConfig};
use svalnir_agent::executor::process::{
    DarwinProcessControl, ExecutorConfig, ExecutorContext, ProcessExecutor, SourceClock,
};
use svalnir_agent::journal::{
    AgentRecord, CoordinatorLock, CoordinatorRole, Enqueued, LockState, OperationJournal,
    QueuedRequest, RequestBody, RequestCompletion, RequestStatus,
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
use svalnir_core::authority::Generation;
use svalnir_core::file::LosslessPath;
use svalnir_core::grant::{AuthorityState, RearmRequest};
use svalnir_core::id::{AdapterId, ExecutorEpochId, OperationId, RequestId};
use svalnir_core::policy::ControlPlaneProcess;
use svalnir_core::quantity::Nanoseconds;
use svalnir_core::volume::VolumeIdentity;

use super::operation_view::OperationReport;
use super::session::{self, journal_error, open_journal};
use crate::environment::Environment;
use crate::interrupt::{Interrupt, StopSignal};
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

/// The longest time for which a transient coordinator continues after a
/// stop signal, as the stop bound of the agent. An operation that is not
/// settled then keeps the registration, and the next coordinator
/// reconciles it.
const STOP_SIGNAL_BOUND: Duration = Duration::from_secs(10);

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
    /// A stop signal stopped the transient coordinator before the
    /// admission. No operation was admitted.
    Stopped(StopSignal),
}

/// The number of reads in sequence that a wait tries again when the
/// journal is busy.
pub(crate) const BUSY_READS: u32 = 40;

/// The count of the failed reads in sequence of a wait on the journal.
///
/// A busy journal is read again, because a different process writes to it
/// and a read changes nothing. The wait does not go on without a bound:
/// after [`BUSY_READS`] busy reads in sequence the error of the read is
/// the result. A read that succeeds starts the count again, and an error
/// that is not "busy" is never tried again.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct BusyReads(u32);

impl BusyReads {
    /// Records a read that succeeded.
    pub(crate) const fn succeeded(&mut self) {
        self.0 = 0;
    }

    /// Records a read that failed. Returns `true` when the wait reads the
    /// journal again: the failure is a busy journal, and fewer than
    /// [`BUSY_READS`] busy reads came before it in sequence.
    pub(crate) const fn reads_again(&mut self, is_busy: bool) -> bool {
        if is_busy && self.0 < BUSY_READS {
            self.0 = self.0.saturating_add(1);
            true
        } else {
            false
        }
    }
}

/// How a wait ended.
pub(crate) enum WaitEnd {
    /// The operation has its final record, or an unknown outcome.
    Finished(OperationReport),
    /// The time of the client ended. Nothing was canceled.
    TimedOut(Option<OperationReport>),
    /// The user interrupted the client. Nothing was canceled.
    Interrupted(Option<OperationReport>),
    /// A stop signal stopped the transient coordinator: it claimed no
    /// further request and stopped its operations at the next safe point.
    Stopped(StopSignal, Option<OperationReport>),
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
        role: CoordinatorRole::Client,
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

/// The dependencies of a transient coordinator for the plan of `input`.
fn dependencies(
    input: &ExecutionInput<'_>,
    epoch: &ExecutorEpochId,
) -> Result<(Dependencies, Arc<dyn AgentClock>, SharedAuthority), ErrorBody> {
    coordinator_dependencies(
        input.environment,
        &input.authority,
        input.control_plane.as_deref(),
        observed_volumes(input.plan),
        epoch,
    )
}

/// The dependencies of a transient coordinator with the authority record
/// `authority`, the processes that it must not stop, and the volumes
/// that it measures.
fn coordinator_dependencies(
    environment: &Environment,
    authority: &AuthorityState,
    control_plane: Option<&[ControlPlaneProcess]>,
    volumes: Vec<VolumeIdentity>,
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
            home_directory: home_directory(environment)?,
            limits: ExecutorLimits::default(),
        },
        environment.seams.trash_backend(),
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
    records.state = Some(authority.clone());
    records.control_plane = control_plane.map(<[ControlPlaneProcess]>::to_vec);
    let authority: SharedAuthority = SharedAuthority::new(records);
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
            // From now on this process is a coordinator: a stop signal
            // stops it as it stops the agent.
            input.environment.interrupt.arm_stop_signals();
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
            // reconciled before a new admission. After a stop signal, the
            // coordinator claims no request of the queue.
            let interrupt: &Interrupt = &input.environment.interrupt;
            let mut stopped: bool = false;
            let mut steps: u32 = 0;
            while coordinator.reconciliation_pending() && steps < MAX_RECONCILIATION_STEPS {
                if !stopped && interrupt.stop_signal().is_some() {
                    stop_coordinator(&mut coordinator);
                    stopped = true;
                }
                steps = steps.saturating_add(1);
                coordinator.step();
            }
            // A stop signal before the admission admits no operation.
            if let Some(signal) = interrupt.stop_signal() {
                stop_coordinator(&mut coordinator);
                release(coordinator);
                return Ok(Applied::Stopped(signal));
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
                        stop: None,
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

/// The result of an acknowledgment request.
pub(crate) enum Acknowledgment {
    /// The journal has the acknowledgment, and the leases of the
    /// operation are released.
    Recorded {
        /// The time of the acknowledgment.
        acknowledged_at: svalnir_core::time::WallTime,
        /// True when an earlier request recorded it.
        repeated: bool,
        /// What executed the request.
        executor: Executor,
    },
    /// The coordinator refused the request. Nothing changed.
    Refused(ActionError),
    /// A stop signal stopped the transient coordinator before the
    /// acknowledgment. Nothing was recorded.
    Stopped(StopSignal),
}

/// The longest wait for the coordinator that serves a queued
/// acknowledgment, when the command has no `--timeout`.
const ACKNOWLEDGE_WAIT: Duration = Duration::from_secs(30);

/// Acknowledges the `UnknownOutcome` operation `operation_id`. When no
/// process holds the coordinator lock, this process records it as a
/// transient coordinator, after the reconciliation of the operations of
/// an earlier lifetime. Else the request goes to the queue of the
/// journal, and this process waits for its completion.
///
/// # Errors
///
/// Returns an error when the journal, the clocks, or the coordinator of
/// this process are not usable, when the process that holds the lock
/// stops before it serves the request (`coordinator_stopped`), and when
/// the wait ends first (`acknowledgment_pending`).
pub(crate) fn acknowledge(
    environment: &Environment,
    operation_id: &OperationId,
    request_id: &RequestId,
    timeout: Option<Duration>,
) -> Result<Acknowledgment, ErrorBody> {
    let principal = session::principal();
    let epoch: ExecutorEpochId =
        ExecutorEpochId::new(session::new_id("client")).map_err(|_| session::identity_error())?;
    // The acknowledgment needs no grant: the coordinator admits no plan
    // for it.
    let (dependencies, _clock, _authority) = coordinator_dependencies(
        environment,
        &AuthorityState::new(session::current_uid()),
        None,
        Vec::new(),
        &epoch,
    )?;
    let database = environment.journal_path()?;
    match start_coordinator(environment, &database, &epoch, dependencies)? {
        Start::Coordinating(mut coordinator) => {
            environment.interrupt.arm_stop_signals();
            let mut stopped: bool = false;
            let mut steps: u32 = 0;
            while coordinator.reconciliation_pending() && steps < MAX_RECONCILIATION_STEPS {
                // The reconciliation dispatches no step. After a stop
                // signal, the coordinator claims no request of the queue.
                if !stopped && environment.interrupt.stop_signal().is_some() {
                    stop_coordinator(&mut coordinator);
                    stopped = true;
                }
                steps = steps.saturating_add(1);
                coordinator.step();
            }
            // A stop signal before this point records no acknowledgment:
            // the coordinator starts no new work after it.
            if let Some(signal) = environment.interrupt.stop_signal() {
                stop_coordinator(&mut coordinator);
                release(coordinator);
                return Ok(Acknowledgment::Stopped(signal));
            }
            let result = coordinator.acknowledge(operation_id, &principal);
            release(coordinator);
            Ok(match result {
                Ok(acknowledged) => Acknowledgment::Recorded {
                    acknowledged_at: acknowledged.acknowledgment.acknowledged_at,
                    repeated: acknowledged.repeated,
                    executor: Executor::TransientCoordinator,
                },
                Err(error) => Acknowledgment::Refused(*error),
            })
        }
        Start::Busy { mut journal, .. } => {
            let request = QueuedRequest {
                request_id: request_id.clone(),
                principal,
                body: RequestBody::Acknowledge {
                    operation_id: operation_id.clone(),
                },
                enqueued_at: session::wall_now(),
            };
            journal
                .enqueue_request(&request)
                .map_err(|error| journal_error(&error))?;
            let pending = Pending {
                code: "acknowledgment_pending",
                served: "the acknowledgment",
                message: "the coordinator did not serve the acknowledgment before the end of the wait; the request stays in the queue; query the operation again with `svalnir operations show`",
            };
            match wait_for_completion(
                &journal,
                &database,
                request_id,
                timeout.unwrap_or(ACKNOWLEDGE_WAIT),
                &pending,
            )? {
                RequestCompletion::Acknowledged {
                    acknowledged_at,
                    repeated,
                } => Ok(Acknowledgment::Recorded {
                    acknowledged_at,
                    repeated,
                    executor: Executor::QueuedForCoordinator,
                }),
                RequestCompletion::Rejected { error } => Ok(Acknowledgment::Refused(error)),
                _ => Err(unexpected_completion()),
            }
        }
    }
}

/// The end of a wait for a queued request that the coordinator did not
/// serve in time.
struct Pending {
    /// The error code.
    code: &'static str,
    /// The request, for the message of a stopped coordinator.
    served: &'static str,
    /// The message.
    message: &'static str,
}

/// The error for a completion of a different kind than the request: the
/// request identity names a different request.
fn unexpected_completion() -> ErrorBody {
    ErrorBody::new(
        "journal_conflict",
        ErrorFamily::Evidence,
        ErrorStage::Dispatch,
        "the request queue has a completion of a different kind for this request identity; the command made no change",
    )
    .with_next_action(NextAction::RefreshObservation)
}

/// Reads the queue until the coordinator completes the request
/// `request_id`, and returns its completion.
fn wait_for_completion(
    journal: &OperationJournal,
    database: &std::path::Path,
    request_id: &RequestId,
    timeout: Duration,
    pending: &Pending,
) -> Result<RequestCompletion, ErrorBody> {
    let started: Instant = Instant::now();
    let mut reads: u32 = 0;
    let mut busy: BusyReads = BusyReads::default();
    loop {
        reads = reads.wrapping_add(1);
        match journal.request_status(request_id) {
            Ok(Some(RequestStatus::Completed { completion })) => return Ok(completion),
            Ok(_) => busy.succeeded(),
            // A busy journal is read again: a different process writes to
            // it.
            Err(error) => {
                let is_busy: bool = matches!(
                    error,
                    svalnir_agent::journal::OperationJournalError::Busy(_)
                );
                if !busy.reads_again(is_busy) {
                    return Err(journal_error(&error));
                }
            }
        }
        if reads.is_multiple_of(PRESENCE_CHECK_INTERVAL)
            && session::coordinator_presence(database) == session::CoordinatorPresence::NotRunning
        {
            return Err(ErrorBody::new(
                "coordinator_stopped",
                ErrorFamily::Evidence,
                ErrorStage::Dispatch,
                format!(
                    "the process that held the coordinator lock stopped before it served {}; the request is in the queue and the next coordinator serves it",
                    pending.served
                ),
            )
            .with_next_action(NextAction::RefreshObservation));
        }
        if started.elapsed() >= timeout {
            return Err(ErrorBody::new(
                pending.code,
                ErrorFamily::Limits,
                ErrorStage::Dispatch,
                pending.message,
            )
            .with_next_action(NextAction::RefreshObservation));
        }
        std::thread::sleep(QUEUE_POLL);
    }
}

/// The longest wait for the agent that serves a queued rearm, when the
/// command has no `--timeout`.
const REARM_WAIT: Duration = Duration::from_secs(30);

/// The result of a rearm request that the agent decided.
pub(crate) enum RearmResult {
    /// The controller of the agent recorded the new budget generation.
    Rearmed {
        /// The generation that the rearm ended.
        previous_generation: Generation,
        /// The generation that the rearm authorized.
        new_generation: Generation,
    },
    /// The agent refused the rearm. Nothing changed.
    Refused(ActionError),
}

/// Sends a rearm request to the agent through the queue of the journal and
/// waits for its completion.
///
/// The budget generation of an incident is state of the controller of the
/// agent. With no agent that holds the coordinator lock, no process can
/// give the agent a generation, so the command is refused with
/// `agent_not_running` and the client makes no state directory, no
/// journal, and no request.
///
/// # Errors
///
/// Returns `agent_not_running` when no agent holds the coordinator lock,
/// a journal error, `coordinator_stopped` when the agent stops before it
/// serves the request, and `rearm_pending` when the wait ends first.
pub(crate) fn rearm(
    environment: &Environment,
    request: &RearmRequest,
    request_id: &RequestId,
    timeout: Option<Duration>,
) -> Result<RearmResult, ErrorBody> {
    let database = environment.journal_path()?;
    if !matches!(
        CoordinatorLock::probe(&database),
        Ok(LockState::Held(CoordinatorRole::Agent))
    ) {
        return Err(ErrorBody::new(
            code::AGENT_NOT_RUNNING,
            ErrorFamily::Evidence,
            ErrorStage::Dispatch,
            "no agent holds the coordinator lock; the budget generation of an incident is in the controller record of the agent, so only a running agent can rearm it; start the agent with `svalnir agent install` and run the command again; the command made no change",
        )
        .with_next_action(NextAction::RefreshObservation));
    }
    let mut journal: OperationJournal = open_journal(environment)?;
    let queued = QueuedRequest {
        request_id: request_id.clone(),
        principal: session::principal(),
        body: RequestBody::Rearm {
            policy: request.policy,
            incident_id: request.incident_id.clone(),
            generation: request.generation,
        },
        enqueued_at: session::wall_now(),
    };
    journal
        .enqueue_request(&queued)
        .map_err(|error| journal_error(&error))?;
    let pending = Pending {
        code: "rearm_pending",
        served: "the rearm",
        message: "the agent did not serve the rearm before the end of the wait; the request stays in the queue, and the agent decides it at a later tick; read the incident again with `svalnir agent status`",
    };
    match wait_for_completion(
        &journal,
        &database,
        request_id,
        timeout.unwrap_or(REARM_WAIT),
        &pending,
    )? {
        RequestCompletion::Rearmed {
            previous_generation,
            new_generation,
            ..
        } => Ok(RearmResult::Rearmed {
            previous_generation,
            new_generation,
        }),
        RequestCompletion::Rejected { error } => Ok(RearmResult::Refused(error)),
        _ => Err(unexpected_completion()),
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

/// Stops a coordinator as the agent stops at a stop signal: it claims no
/// further request of the queue, and each operation that it executes or
/// that waits gets the stop request, so that no later step is dispatched.
fn stop_coordinator(coordinator: &mut Coordinator<OperationJournal>) {
    coordinator.stop_claims();
    drop(coordinator.cancel_active());
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
    /// The stop signal that stopped the coordinator, with the end of its
    /// bound.
    stop: Option<(StopSignal, Instant)>,
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

    /// Stops the coordinator at the first stop signal. Returns the signal
    /// after a stop.
    fn read_stop_signal(&mut self, interrupt: &Interrupt) -> Option<StopSignal> {
        if self.stop.is_none()
            && let Some(signal) = interrupt.stop_signal()
        {
            stop_coordinator(&mut self.coordinator);
            self.stop = Some((signal, Instant::now() + STOP_SIGNAL_BOUND));
        }
        self.stop.map(|(signal, _)| signal)
    }

    /// Whether the bound after a stop signal ended.
    fn stop_bound_ended(&self) -> bool {
        self.stop
            .is_some_and(|(_, give_up_at)| Instant::now() >= give_up_at)
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
        match authority_after_read(read.is_ok(), self.authority_read_at.elapsed()) {
            AuthorityRead::Fresh => {
                self.authority_read_at = Instant::now();
                true
            }
            AuthorityRead::Withdrawn => {
                self.authority.records().state = None;
                // The next read that has a result sets the record again.
                self.authority_revision = u64::MAX;
                true
            }
            AuthorityRead::Unconfirmed => false,
        }
    }

    /// Executes the operation until it is finished, the time of the
    /// client ends, or the user interrupts the client. The operation
    /// continues after each of the last two: call [`Running::complete`].
    ///
    /// A stop signal stops the coordinator: the wait then ends when the
    /// operation is finished or the stop bound ends, with
    /// [`WaitEnd::Stopped`].
    pub(crate) fn wait(&mut self, timeout: Option<Duration>, interrupt: &Interrupt) -> WaitEnd {
        interrupt.arm();
        let started: Instant = Instant::now();
        loop {
            let stopped: Option<StopSignal> = self.read_stop_signal(interrupt);
            if let Some(signal) = stopped
                && (self.is_finished() || self.stop_bound_ended())
            {
                return WaitEnd::Stopped(signal, self.report());
            }
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
            // After a stop signal, the wait ends with the stop.
            if stopped.is_none() && interrupt.is_requested() {
                return WaitEnd::Interrupted(self.report());
            }
            if stopped.is_none() && timeout.is_some_and(|timeout| started.elapsed() >= timeout) {
                return WaitEnd::TimedOut(self.report());
            }
            self.advance();
        }
    }

    /// Executes the operation to its end with no client wait, then each
    /// request that this coordinator claimed from the queue, and releases
    /// the coordinator. Returns the last view of the operation.
    ///
    /// After a stop signal the coordinator claims no further request,
    /// stops each of its operations at the next safe point, and continues
    /// at most [`STOP_SIGNAL_BOUND`].
    pub(crate) fn complete(mut self, interrupt: &Interrupt) -> Option<OperationReport> {
        let started: Instant = Instant::now();
        let ended = |running: &mut Self| {
            running.read_stop_signal(interrupt);
            started.elapsed() >= MAX_COMPLETION_TIME || running.stop_bound_ended()
        };
        while !self.is_finished() && !ended(&mut self) {
            self.advance();
        }
        let report: Option<OperationReport> = self.report();
        // A step also serves the request queue, so this coordinator can
        // have admitted the request of a different client. It executes
        // that work before it stops: an operation that it leaves is never
        // dispatched again.
        while !ended(&mut self) {
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
        read_failure(
            &self.plan_id,
            error,
            last.map(|report| &report.operation_id),
        )
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
        let mut busy: BusyReads = BusyReads::default();
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
                busy.succeeded();
            }
            match state {
                // A busy journal is read again: a different process
                // writes to it.
                Err(error) if busy.reads_again(&*error.code == "journal_busy") => drop(error),
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

/// What a read of the authority record gives to the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthorityRead {
    /// The record was read.
    Fresh,
    /// The read failed for longer than [`AUTHORITY_READ_GRACE`]: the record
    /// is cleared and the coordinator refuses each step.
    Withdrawn,
    /// The read failed inside the grace period: no step runs.
    Unconfirmed,
}

/// The decision after a read of the authority record. A record that cannot
/// be read is not authority after [`AUTHORITY_READ_GRACE`].
fn authority_after_read(read_ok: bool, since_last_read: Duration) -> AuthorityRead {
    if read_ok {
        AuthorityRead::Fresh
    } else if since_last_read >= AUTHORITY_READ_GRACE {
        AuthorityRead::Withdrawn
    } else {
        AuthorityRead::Unconfirmed
    }
}

/// The error of a journal read that failed during the wait of a request.
/// It names the plan and, when the request was admitted, the operation.
fn read_failure(
    plan_id: &svalnir_core::id::PlanId,
    error: ErrorBody,
    operation: Option<&OperationId>,
) -> ErrorBody {
    let Some(operation_id) = operation else {
        return error.with_plan(plan_id.as_str());
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
    .with_plan(plan_id.as_str())
    .with_operation(operation_id.as_str())
    .with_next_action(NextAction::QueryOperation)
}

#[cfg(test)]
mod decision_tests {
    use std::time::Duration;

    use svalnir_core::id::{OperationId, PlanId};

    use super::{
        AUTHORITY_READ_GRACE, AuthorityRead, ErrorBody, ErrorFamily, ErrorStage, NextAction,
        authority_after_read, read_failure,
    };

    #[test]
    fn a_busy_journal_is_read_again_for_a_bounded_number_of_reads_in_sequence() {
        use super::{BUSY_READS, BusyReads};
        let mut busy = BusyReads::default();
        // An error that is not a busy journal is never tried again, and it
        // does not use a place of the bound.
        assert!(!busy.reads_again(false));
        for _ in 0..BUSY_READS {
            assert!(busy.reads_again(true));
        }
        // The bound is reached: the error of the read is the result.
        assert!(!busy.reads_again(true));
        assert!(!busy.reads_again(true));
        // A read that succeeds starts the count again.
        busy.succeeded();
        for _ in 0..BUSY_READS {
            assert!(busy.reads_again(true));
            assert!(!busy.reads_again(false));
        }
        assert!(!busy.reads_again(true));
    }

    #[test]
    fn a_record_that_cannot_be_read_is_not_authority_after_the_grace_period() {
        let before: Duration = AUTHORITY_READ_GRACE.saturating_sub(Duration::from_millis(1));
        assert_eq!(
            authority_after_read(false, before),
            AuthorityRead::Unconfirmed
        );
        assert_eq!(
            authority_after_read(false, AUTHORITY_READ_GRACE),
            AuthorityRead::Withdrawn
        );
        assert_eq!(
            authority_after_read(false, AUTHORITY_READ_GRACE * 5),
            AuthorityRead::Withdrawn
        );
        assert_eq!(
            authority_after_read(true, AUTHORITY_READ_GRACE * 5),
            AuthorityRead::Fresh
        );
    }

    #[test]
    fn a_failed_read_after_the_admission_names_the_operation() {
        let plan = PlanId::new("plan_1").unwrap();
        let operation = OperationId::new("op_1").unwrap();
        let cause = || {
            ErrorBody::new(
                "journal_busy",
                ErrorFamily::Recording,
                ErrorStage::Storage,
                "busy",
            )
        };
        let before = read_failure(&plan, cause(), None);
        assert_eq!(&*before.code, "journal_busy");
        assert_eq!(before.plan_id.as_deref(), Some("plan_1"));
        assert!(before.operation_id.is_none());

        let after = read_failure(&plan, cause(), Some(&operation));
        assert_eq!(&*after.code, "operation_record_unavailable");
        assert_eq!(after.family, ErrorFamily::Outcome);
        assert_eq!(after.plan_id.as_deref(), Some("plan_1"));
        assert_eq!(after.operation_id.as_deref(), Some("op_1"));
        assert_eq!(after.next_action, NextAction::QueryOperation);
    }
}
