//! `operations show`, `operations wait`, `operations cancel`, and
//! `operations acknowledge`.
//!
//! Each command reads the operation record of the journal. `show` and
//! `wait` change nothing. `cancel` stops the dispatch of the later steps.
//! When the agent holds the coordinator lock, `cancel` writes a cancel
//! request to the request queue of the journal, as the GPUI client does,
//! and the agent decides it: it checks the principal, stops the operation
//! in its executor, and records the stop fence. With no agent, or when the
//! agent does not serve the request in the wait, the client sets the stop
//! fence of the operation in the journal itself: the executor dispatches
//! no further step after it reads the fence. A call that the executor
//! issued is not recalled. `acknowledge`
//! records that the user accepts the unknown outcome of an operation: the
//! coordinator releases its leases, and the result stays `UnknownOutcome`.

use std::time::{Duration, Instant};

use serde::Serialize;
use svalnir_agent::client::{self, AgentPresence};
use svalnir_agent::journal::{
    OperationJournal, OperationJournalError, QueuedRequest, RequestBody, RequestCompletion,
};
use svalnir_core::action::{Operation, OperationState, StopFence};
use svalnir_core::id::{OperationId, RequestId};

use super::apply::{ApplyView, target_paths};
use super::execution::{self, Executor};
use super::operation_view::OperationReport;
use super::session::{self, CoordinatorPresence, coordinator_presence, journal_error};
use super::{CommandFailure, Invocation};
use crate::cli::OperationRef;
use crate::environment::Environment;
use crate::output::{ErrorBody, ErrorFamily, ErrorStage, ExitStatus, Kind, NextAction};
use crate::text::put_line;

/// The time between two reads of the journal.
const POLL: Duration = Duration::from_millis(100);

/// The number of journal reads between two reads of the coordinator lock.
const LOCK_CHECK_INTERVAL: u32 = 10;

/// How long `operations cancel` waits for the executor to settle the
/// operation after the fence, before it reports the fence alone.
const SETTLE_WAIT: Duration = Duration::from_secs(2);

/// How long `operations cancel` waits for the agent to serve its queued
/// request when the command has no `--timeout`. After the wait, the client
/// writes the stop fence itself.
const CANCEL_WAIT: Duration = Duration::from_secs(10);

const NO_COORDINATOR_NOTE: &str = "No process holds the coordinator lock, so no process executes this operation now. The next coordinator reconciles it from fresh evidence before it admits other work; it does not dispatch it again.";

const TIMEOUT_NOTE: &str = "The client wait ended before a final result. Nothing was canceled. The result is not known to this response; query it again with `svalnir operations show`.";

const INTERRUPT_NOTE: &str = "The client was interrupted. Nothing was canceled.";

fn parse(text: &str) -> Result<OperationId, ErrorBody> {
    OperationId::new(text).map_err(|_| {
        session::invalid_identifier("invalid_operation_id", "operation ID", &["operation"])
    })
}

fn not_found(operation_id: &OperationId) -> ErrorBody {
    ErrorBody::new(
        "operation_not_found",
        ErrorFamily::Evidence,
        ErrorStage::Storage,
        "the journal has no operation with this ID: the ID is of a different state directory, or the retention removed the record; the command made no change",
    )
    .with_fields(&["operation"])
    .with_operation(operation_id.as_str())
    .with_next_action(NextAction::RefreshObservation)
}

fn read(journal: &OperationJournal, operation_id: &OperationId) -> Result<Operation, ErrorBody> {
    journal
        .try_operation(operation_id)
        .map_err(|error| journal_error(&error))?
        .ok_or_else(|| not_found(operation_id))
}

/// The view of a journal record, with the resource observations of the
/// journal, and with the display paths and the measurements of the plan
/// document of this client when it has one.
fn report(
    journal: &OperationJournal,
    environment: &Environment,
    operation: &Operation,
) -> OperationReport {
    let stop_fence: Option<bool> = journal.try_has_stop_fence(operation.operation_id()).ok();
    // A document is used only when it agrees with the stored plan.
    let stored = super::clean::load_for_report(journal, environment, operation.plan_id());
    let document = stored.as_ref().and_then(|stored| stored.document.as_ref());
    OperationReport::of_record(operation, stop_fence)
        .with_recorded_effects(journal)
        .with_measurements(document.and_then(|document| document.measurements.as_ref()))
        .with_paths(
            stored
                .as_ref()
                .map_or_else(std::collections::BTreeMap::new, |stored| {
                    target_paths(&stored.plan)
                }),
        )
}

/// Whether the operation has its last record. An unknown outcome is not
/// settled, and it does not change until a reconciliation.
fn is_ended(operation: &Operation) -> bool {
    operation.state().is_settled() || operation.state() == &OperationState::UnknownOutcome
}

/// The result of `operations show`.
#[derive(Debug, Clone, Serialize)]
struct ShowView {
    operation: OperationReport,
    /// Whether a process holds the coordinator lock.
    coordinator: CoordinatorPresence,
    notes: Vec<&'static str>,
}

impl ShowView {
    fn render(&self) -> String {
        let mut out = String::new();
        self.operation.render(&mut out);
        for note in &self.notes {
            put_line!(out, "  Note: {note}");
        }
        out
    }
}

fn open(
    environment: &Environment,
    operation_id: &OperationId,
) -> Result<OperationJournal, ErrorBody> {
    session::open_existing_journal(environment)?.ok_or_else(|| not_found(operation_id))
}

pub(crate) fn show(
    arguments: &OperationRef,
    invocation: &mut Invocation<'_>,
) -> Result<ExitStatus, CommandFailure> {
    let operation_id: OperationId = parse(&arguments.operation)?;
    let environment: &Environment = invocation.environment;
    let journal: OperationJournal = open(environment, &operation_id)?;
    let operation: Operation = read(&journal, &operation_id)?;
    let coordinator: CoordinatorPresence = coordinator_presence(&environment.journal_path()?);
    let view = ShowView {
        operation: report(&journal, environment, &operation),
        coordinator,
        notes: if !is_ended(&operation) && coordinator == CoordinatorPresence::NotRunning {
            vec![NO_COORDINATOR_NOTE]
        } else {
            Vec::new()
        },
    };
    invocation.emit(Kind::Operation, &view, ShowView::render)?;
    // The query succeeded. The state of the operation is in the result.
    Ok(ExitStatus::Success)
}

pub(crate) fn wait(
    arguments: &OperationRef,
    invocation: &mut Invocation<'_>,
) -> Result<ExitStatus, CommandFailure> {
    let operation_id: OperationId = parse(&arguments.operation)?;
    let environment: &Environment = invocation.environment;
    let journal: OperationJournal = open(environment, &operation_id)?;
    let journal_path = environment.journal_path()?;
    let timeout: Option<Duration> = invocation.timeout;
    environment.interrupt.arm();
    let started: Instant = Instant::now();
    let mut reads: u32 = 0;
    let mut busy: execution::BusyReads = execution::BusyReads::default();
    let (wait, operation, note): (&'static str, Operation, Option<&'static str>) = loop {
        let operation: Operation = match read(&journal, &operation_id) {
            Ok(operation) => {
                busy.succeeded();
                operation
            }
            // A busy journal is read again: a different process writes
            // to it. The wait changes nothing, so a repeat is safe.
            Err(error)
                if !environment.interrupt.is_requested()
                    && timeout.is_none_or(|timeout| started.elapsed() < timeout)
                    && busy.reads_again(&*error.code == "journal_busy") =>
            {
                std::thread::sleep(POLL);
                continue;
            }
            Err(error) => {
                return Err(error
                    .with_operation(operation_id.as_str())
                    .with_next_action(NextAction::QueryOperation)
                    .into());
            }
        };
        if is_ended(&operation) {
            break ("finished", operation, None);
        }
        // The lock is read at the first read and then one time each
        // second: a read holds the lock for an instant.
        let check_lock: bool = reads.is_multiple_of(LOCK_CHECK_INTERVAL);
        reads = reads.wrapping_add(1);
        if check_lock && coordinator_presence(&journal_path) == CoordinatorPresence::NotRunning {
            // The operation can have ended between the two reads.
            // A read that fails here keeps the state that was read.
            let operation: Operation = read(&journal, &operation_id).unwrap_or(operation);
            if is_ended(&operation) {
                break ("finished", operation, None);
            }
            break ("no_coordinator", operation, Some(NO_COORDINATOR_NOTE));
        }
        if environment.interrupt.is_requested() {
            break ("interrupted", operation, Some(INTERRUPT_NOTE));
        }
        if timeout.is_some_and(|timeout| started.elapsed() >= timeout) {
            break ("timed_out", operation, Some(TIMEOUT_NOTE));
        }
        std::thread::sleep(POLL);
    };
    let view = ApplyView {
        wait,
        existing_operation: false,
        plan_id: operation.plan_id().clone(),
        executor: None,
        request_id: None,
        operation: Some(report(&journal, environment, &operation)),
        notes: note.into_iter().collect(),
    };
    let status: ExitStatus = view.status();
    invocation.emit_with_status(Kind::Operation, &view, ApplyView::render, status)
}

/// How `operations cancel` reached the operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum CancelPath {
    /// The agent served the cancel request of the queue.
    RequestQueue,
    /// This client wrote the stop fence in the journal: no agent holds the
    /// coordinator lock, or the agent did not serve the request in the
    /// wait.
    StopFence,
    /// The operation was settled before the request, so nothing was
    /// written.
    None,
}

/// The result of `operations cancel`.
#[derive(Debug, Clone, Serialize)]
struct CancelView {
    operation_id: OperationId,
    /// The acknowledgement that the request reached
    /// (`docs/INTERFACES.md` section 12): `durable_stop_fence` when the
    /// journal has the fence and the operation is not settled,
    /// `current_instance` when the agent stopped the operation in its
    /// executor but the journal did not take the fence, and `settled` when
    /// the operation has its final record.
    acknowledgement: &'static str,
    /// True when this request wrote the durable fence, or the agent wrote
    /// it for this request. False when the operation was settled before
    /// the request, and for `current_instance`.
    fence_written: bool,
    /// How the request reached the operation.
    path: CancelPath,
    /// The identity of the queue request, when the request went to the
    /// queue.
    request_id: Option<RequestId>,
    coordinator: CoordinatorPresence,
    operation: OperationReport,
    notes: Vec<&'static str>,
}

const CANCEL_NOTE: &str = "A cancel stops the dispatch of further steps. It does not recall a call that was issued, and it does not undo an effect: the operation can end as Partial, Incomplete, or UnknownOutcome.";

const SETTLED_BEFORE_NOTE: &str =
    "The operation had its final record before the request, so the request changed nothing.";

const NOT_SERVED_NOTE: &str = "The agent did not serve the cancel request before the end of the wait, so this client wrote the stop fence in the journal itself. The request stays in the queue; the agent finds the fence when it serves it.";

const CURRENT_INSTANCE_NOTE: &str = "The agent stopped the operation in its executor, but the journal did not take the stop fence. A restart of the agent before the operation settles does not keep the stop.";

impl CancelView {
    fn render(&self) -> String {
        let mut out = String::new();
        put_line!(
            out,
            "Cancel of operation {}: {}",
            self.operation_id,
            match self.acknowledgement {
                "settled" => "settled; no step is executing",
                "current_instance" =>
                    "stopped in the executor of the agent; the stop fence is not durable",
                _ => "durable stop fence; the executor dispatches no further step",
            }
        );
        put_line!(
            out,
            "  Path: {}",
            match self.path {
                CancelPath::RequestQueue => "the agent served the request of the queue",
                CancelPath::StopFence => "this client wrote the stop fence in the journal",
                CancelPath::None => "no write",
            }
        );
        self.operation.render(&mut out);
        for note in &self.notes {
            put_line!(out, "  Note: {note}");
        }
        out
    }
}

/// Writes the stop fence of `operation_id` in the journal.
fn write_fence(
    journal: &mut OperationJournal,
    operation_id: &OperationId,
) -> Result<(), ErrorBody> {
    journal
        .try_set_stop_fence(operation_id)
        .map_err(|error| match error {
            OperationJournalError::NotFound => not_found(operation_id),
            other => {
                let mut body: ErrorBody = journal_error(&other);
                body.message = format!(
                    "{}; the stop fence was not written, so the cancel is NOT in effect: this client has no executor that it can stop",
                    body.message
                );
                body.with_operation(operation_id.as_str())
            }
        })
}

/// What a cancel request through the queue gave.
enum Queued {
    /// The agent recorded the stop with this fence.
    Served(StopFence),
    /// The agent did not serve the request in the wait: the wait ended,
    /// the agent stopped, or the queue could not be read.
    NotServed,
}

/// Writes the cancel request to the queue and waits for the agent.
///
/// # Errors
///
/// Returns the refusal of the agent, a journal error of the write of the
/// request, and a completion of a different kind.
fn cancel_through_queue(
    journal: &mut OperationJournal,
    journal_path: &std::path::Path,
    operation_id: &OperationId,
    request_id: &RequestId,
    timeout: Duration,
) -> Result<Queued, ErrorBody> {
    let request = QueuedRequest {
        request_id: request_id.clone(),
        principal: session::principal(),
        body: RequestBody::Cancel {
            operation_id: operation_id.clone(),
        },
        enqueued_at: session::wall_now(),
    };
    journal
        .enqueue_request(&request)
        .map_err(|error| journal_error(&error).with_operation(operation_id.as_str()))?;
    match client::wait_for_completion(journal, journal_path, request_id, timeout) {
        Ok(RequestCompletion::Stopped { fence }) => Ok(Queued::Served(fence)),
        Ok(RequestCompletion::Rejected { error }) => {
            Err(session::action_error(&error, "the cancel").with_operation(operation_id.as_str()))
        }
        Ok(_) => Err(execution::unexpected_completion()),
        // The request stays in the queue. The caller writes the fence, so
        // the cancel does not depend on the agent.
        Err(_) => Ok(Queued::NotServed),
    }
}

pub(crate) fn cancel(
    arguments: &OperationRef,
    invocation: &mut Invocation<'_>,
) -> Result<ExitStatus, CommandFailure> {
    let operation_id: OperationId = parse(&arguments.operation)?;
    let environment: &Environment = invocation.environment;
    let mut journal: OperationJournal = open(environment, &operation_id)?;
    let journal_path = environment.journal_path()?;
    let mut operation: Operation = read(&journal, &operation_id)?;
    let mut notes: Vec<&'static str> = Vec::new();
    let mut request_id: Option<RequestId> = None;
    let mut current_instance: bool = false;
    let (fence_written, path): (bool, CancelPath) = if operation.state().is_settled() {
        notes.push(SETTLED_BEFORE_NOTE);
        (false, CancelPath::None)
    } else if client::agent_presence(&journal_path) == AgentPresence::Agent {
        // The agent decides the request, as for the GPUI client.
        request_id = Some(invocation.request_id.clone());
        let queued: Queued = cancel_through_queue(
            &mut journal,
            &journal_path,
            &operation_id,
            invocation.request_id,
            invocation.timeout.unwrap_or(CANCEL_WAIT),
        )?;
        notes.push(CANCEL_NOTE);
        match queued {
            Queued::Served(StopFence::Durable) => (true, CancelPath::RequestQueue),
            Queued::Served(StopFence::CurrentInstance) => {
                current_instance = true;
                notes.push(CURRENT_INSTANCE_NOTE);
                (false, CancelPath::RequestQueue)
            }
            Queued::NotServed => {
                write_fence(&mut journal, &operation_id)?;
                notes.push(NOT_SERVED_NOTE);
                (true, CancelPath::StopFence)
            }
        }
    } else {
        write_fence(&mut journal, &operation_id)?;
        notes.push(CANCEL_NOTE);
        (true, CancelPath::StopFence)
    };
    let stop_requested: bool = fence_written || current_instance;
    let coordinator: CoordinatorPresence = coordinator_presence(&journal_path);
    // An executor that runs settles the operation at its next boundary.
    if stop_requested && coordinator == CoordinatorPresence::Running {
        let started: Instant = Instant::now();
        while started.elapsed() < SETTLE_WAIT {
            // The fence is written. A read that fails here does not
            // change that: the response has the last state that was read.
            match read(&journal, &operation_id) {
                Ok(current) => operation = current,
                Err(_) => break,
            }
            if operation.state().is_settled() {
                break;
            }
            std::thread::sleep(POLL);
        }
    }
    if fence_written && !is_ended(&operation) && coordinator == CoordinatorPresence::NotRunning {
        notes.push(NO_COORDINATOR_NOTE);
    }
    let view = CancelView {
        operation_id,
        acknowledgement: if operation.state().is_settled() {
            "settled"
        } else if current_instance {
            "current_instance"
        } else {
            "durable_stop_fence"
        },
        fence_written,
        path,
        request_id,
        coordinator,
        operation: report(&journal, environment, &operation),
        notes,
    };
    invocation.emit(Kind::Operation, &view, CancelView::render)?;
    Ok(ExitStatus::Success)
}

/// The result of `operations acknowledge`.
#[derive(Debug, Clone, Serialize)]
struct AcknowledgeView {
    operation_id: OperationId,
    /// The time of the acknowledgment that the journal has.
    acknowledged_at: svalnir_core::time::WallTime,
    /// True when an earlier request recorded the acknowledgment. This
    /// request then changed nothing.
    repeated: bool,
    executor: Executor,
    operation: OperationReport,
    notes: Vec<&'static str>,
}

const ACKNOWLEDGE_NOTE: &str = "The acknowledgment releases the leases of the operation, so a later plan for the same targets can be admitted. It does not change the recorded result: the outcome stays unknown, and no call was issued for it.";

impl AcknowledgeView {
    fn render(&self) -> String {
        let mut out = String::new();
        put_line!(
            out,
            "Acknowledgment of operation {}: {}",
            self.operation_id,
            if self.repeated {
                "recorded before; this request changed nothing"
            } else {
                "recorded; the leases are released"
            }
        );
        self.operation.render(&mut out);
        for note in &self.notes {
            put_line!(out, "  Note: {note}");
        }
        out
    }
}

fn not_unknown_outcome(operation_id: &OperationId) -> ErrorBody {
    ErrorBody::new(
        "operation_not_unknown_outcome",
        ErrorFamily::Request,
        ErrorStage::Admission,
        "the operation is not in the state UnknownOutcome, so it has no unknown outcome to acknowledge; the command made no change",
    )
    .with_fields(&["operation"])
    .with_operation(operation_id.as_str())
    .with_next_action(NextAction::CorrectRequest)
}

pub(crate) fn acknowledge(
    arguments: &OperationRef,
    invocation: &mut Invocation<'_>,
) -> Result<ExitStatus, CommandFailure> {
    let operation_id: OperationId = parse(&arguments.operation)?;
    let environment: &Environment = invocation.environment;
    let journal: OperationJournal = open(environment, &operation_id)?;
    let operation: Operation = read(&journal, &operation_id)?;
    if operation.state() != &OperationState::UnknownOutcome {
        return Err(not_unknown_outcome(&operation_id).into());
    }
    let outcome = execution::acknowledge(
        environment,
        &operation_id,
        invocation.request_id,
        invocation.timeout,
    )?;
    let (acknowledged_at, repeated, executor) = match outcome {
        execution::Acknowledgment::Recorded {
            acknowledged_at,
            repeated,
            executor,
        } => (acknowledged_at, repeated, executor),
        execution::Acknowledgment::Refused(error) => {
            return Err(session::action_error(&error, "the acknowledgment").into());
        }
        execution::Acknowledgment::Stopped(signal) => {
            return Err(ErrorBody::new(
                "stopped_by_signal",
                ErrorFamily::Outcome,
                ErrorStage::Dispatch,
                format!(
                    "{} stopped this process before it recorded the acknowledgment; the acknowledgment is not recorded; send the command again",
                    signal.name()
                ),
            )
            .with_operation(operation_id.as_str())
            .with_next_action(NextAction::QueryOperation)
            .into());
        }
    };
    let operation: Operation = read(&journal, &operation_id)?;
    let view = AcknowledgeView {
        operation_id,
        acknowledged_at,
        repeated,
        executor,
        operation: report(&journal, environment, &operation),
        notes: vec![ACKNOWLEDGE_NOTE],
    };
    invocation.emit(Kind::Operation, &view, AcknowledgeView::render)?;
    Ok(ExitStatus::Success)
}
