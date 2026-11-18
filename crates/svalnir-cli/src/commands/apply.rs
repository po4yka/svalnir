//! The apply flow that `clean apply` and `processes stop` share: the
//! approval of the user, the admission, the wait, and the result.
//!
//! The approval binds to the plan identity and the digest that the client
//! read from the journal (`docs/INTERFACES.md` section 5). `--yes` only
//! takes the place of the question: the coordinator does each check of
//! the plan again at admission and before each step.

use std::collections::BTreeMap;

use serde::Serialize;
use svalnir_agent::journal::OperationJournal;
use svalnir_core::action::{Operation, Plan};
use svalnir_core::file::LosslessPath;
use svalnir_core::grant::AuthorityState;
use svalnir_core::id::{OperationId, PlanId, RequestId, TargetId};
use svalnir_core::policy::ControlPlaneProcess;

use super::operation_view::OperationReport;
use super::plan_store::{self, PlanDocument};
use super::session::{self, journal_error};
use super::{CommandFailure, Invocation};
use crate::output::{ErrorBody, ErrorFamily, ErrorStage, ExitStatus, Kind, NextAction};
use crate::seams::Confirmation;
use crate::text::put_line;

const NO_WAIT_NOTE: &str = "The response reports the admission, not the completion. Query the result with `svalnir operations show` or `svalnir operations wait`.";

const TRANSIENT_NOTE: &str = "No agent holds the coordinator lock, so this process executes the operation. It exits when the operation ends; the end of the client wait cancels nothing.";

const QUEUED_NOTE: &str = "A different process holds the coordinator lock. The request is in the queue of the journal, and that process executes it.";

const TIMEOUT_NOTE: &str = "The client wait ended before a final result. Nothing was canceled: the operation continues. The result is not known to this response; query it with `svalnir operations show`.";

const INTERRUPT_NOTE: &str = "The client was interrupted. Nothing was canceled: the operation continues. Cancel it only with `svalnir operations cancel`.";

/// Asks for the approval of a plan. `--yes` gives it with no question.
///
/// # Errors
///
/// Returns an authority error when the user does not approve, or when the
/// session has no terminal and `--yes` is not given.
pub(crate) fn approve(
    invocation: &mut Invocation<'_>,
    yes: bool,
    summary: &str,
    plan_id: &PlanId,
) -> Result<(), ErrorBody> {
    if yes {
        return Ok(());
    }
    // The scope and the consequence are part of the question, so they are
    // shown only to a user who can answer.
    let question: String = format!("{summary}\nApply plan {plan_id}?");
    match invocation
        .environment
        .seams
        .confirm(invocation.stderr, &question)
    {
        Confirmation::Approved => Ok(()),
        Confirmation::Declined => Err(ErrorBody::new(
            "approval_declined",
            ErrorFamily::Authority,
            ErrorStage::Admission,
            "the plan was not approved; the command made no change",
        )
        .with_plan(plan_id.as_str())
        .with_next_action(NextAction::None)),
        Confirmation::NotInteractive => Err(ErrorBody::new(
            "approval_required",
            ErrorFamily::Authority,
            ErrorStage::Admission,
            "the session has no terminal for the approval question; inspect the plan with `svalnir clean show` and give `--yes`; the command made no change",
        )
        .with_plan(plan_id.as_str())
        .with_fields(&["yes"])),
    }
}

/// The error for a plan whose validity ended.
pub(crate) fn plan_expired(plan_id: &PlanId) -> ErrorBody {
    ErrorBody::new(
        "plan_expired",
        ErrorFamily::Limits,
        ErrorStage::Admission,
        "the plan is expired, or it is of a different boot; prepare a new plan; the command made no change",
    )
    .with_plan(plan_id.as_str())
    .with_next_action(NextAction::PrepareNewPlan)
}

/// The response of an asynchronous admission.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct AcceptedView {
    pub(crate) operation_id: Option<OperationId>,
    pub(crate) plan_id: PlanId,
    /// `Admitted` or a later state of the operation, or `queued` when the
    /// coordinator did not admit the request before the response.
    pub(crate) state: String,
    pub(crate) dispatch: Option<String>,
    pub(crate) durability: Option<String>,
    /// The acknowledgement of `docs/INTERFACES.md` section 13.
    pub(crate) acknowledgement: &'static str,
    pub(crate) executor: super::execution::Executor,
    /// The identity of the queue request, when one exists.
    pub(crate) request_id: Option<RequestId>,
    pub(crate) notes: Vec<&'static str>,
}

impl AcceptedView {
    pub(crate) fn render(&self) -> String {
        let mut out = String::new();
        if let Some(operation_id) = &self.operation_id {
            put_line!(
                out,
                "Accepted: operation {operation_id} of plan {} ({})",
                self.plan_id,
                crate::text::escape(&self.state)
            );
        } else {
            put_line!(
                out,
                "Accepted: the request for plan {} is in the queue; it has no operation yet",
                self.plan_id
            );
        }
        if let Some(request_id) = &self.request_id {
            put_line!(out, "  Request: {request_id}");
        }
        for note in &self.notes {
            put_line!(out, "  Note: {note}");
        }
        out
    }
}

/// The response of a command that waited for an operation.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct ApplyView {
    /// `finished`, `timed_out`, `interrupted`, `no_coordinator`, or, for
    /// an existing operation that is not at its end, `not_waited`.
    pub(crate) wait: &'static str,
    /// True when the plan was applied before this request. No second
    /// operation was made.
    pub(crate) existing_operation: bool,
    pub(crate) plan_id: PlanId,
    pub(crate) executor: Option<super::execution::Executor>,
    pub(crate) request_id: Option<RequestId>,
    /// The operation, when it is known.
    pub(crate) operation: Option<OperationReport>,
    pub(crate) notes: Vec<&'static str>,
}

impl ApplyView {
    pub(crate) fn render(&self) -> String {
        let mut out = String::new();
        if self.existing_operation {
            put_line!(
                out,
                "Plan {} was applied before. This is its operation; no second operation was made.",
                self.plan_id
            );
        }
        if let Some(operation) = &self.operation {
            operation.render(&mut out);
        } else {
            put_line!(
                out,
                "Plan {}: the request has no operation yet",
                self.plan_id
            );
        }
        if let Some(request_id) = &self.request_id {
            put_line!(out, "  Request: {request_id}");
        }
        for note in &self.notes {
            put_line!(out, "  Note: {note}");
        }
        out
    }

    /// The exit status of `docs/INTERFACES.md` section 8.
    pub(crate) fn status(&self) -> ExitStatus {
        match (self.wait, &self.operation) {
            ("interrupted", _) => ExitStatus::Interrupted,
            ("finished", Some(operation)) => operation.waited_status(),
            _ => ExitStatus::Conflict,
        }
    }
}

/// The display path of each file target of a plan, from the values that
/// the sealed plan binds and the cleanup roots of the plan document.
pub(crate) fn target_paths(
    plan: &Plan,
    document: Option<&PlanDocument>,
) -> BTreeMap<TargetId, LosslessPath> {
    document.map_or_else(BTreeMap::new, |document| {
        super::clean::bound_paths(plan, document)
    })
}

/// Finds the operation of a plan that was applied before. A plan has at
/// most one operation in the journal.
pub(crate) fn existing_operation(
    journal: &OperationJournal,
    plan_id: &PlanId,
) -> Result<Option<Operation>, ErrorBody> {
    journal
        .operation_of_plan(plan_id)
        .map_err(|error| journal_error(&error))
}

/// The inputs of the apply flow.
pub(crate) struct ApplyFlow<'a> {
    /// The sealed plan of the journal.
    pub(crate) plan: &'a Plan,
    /// The plan document of this client, when it exists.
    pub(crate) document: Option<PlanDocument>,
    pub(crate) authority: AuthorityState,
    pub(crate) control_plane: Option<Vec<ControlPlaneProcess>>,
    pub(crate) no_wait: bool,
    /// True for `--yes`: the approval question is not asked.
    pub(crate) yes: bool,
    /// The scope and the consequence of the plan, for the approval
    /// question.
    pub(crate) summary: String,
    /// The name of the request in an error message.
    pub(crate) what: &'static str,
}

fn existing_view(
    flow: &ApplyFlow<'_>,
    journal: &OperationJournal,
    operation: &Operation,
) -> ApplyView {
    let stop_fence: Option<bool> = journal.try_has_stop_fence(operation.operation_id()).ok();
    let ended: bool = operation.state().is_settled()
        || operation.state() == &svalnir_core::action::OperationState::UnknownOutcome;
    ApplyView {
        // An operation that is not at its end was not waited for: the
        // executor of the first request has it.
        wait: if ended { "finished" } else { "not_waited" },
        existing_operation: true,
        plan_id: flow.plan.plan_id.clone(),
        executor: None,
        request_id: None,
        operation: Some(
            OperationReport::of_record(operation, stop_fence)
                .with_measurements(
                    flow.document
                        .as_ref()
                        .and_then(|document| document.measurements.as_ref()),
                )
                .with_paths(target_paths(flow.plan, flow.document.as_ref())),
        ),
        notes: Vec::new(),
    }
}

/// Emits the view of an existing operation. The exit status is that of
/// the operation. With `--no-wait`, an operation that is in progress is an
/// admitted operation, which is success.
fn emit_existing(
    flow: &ApplyFlow<'_>,
    view: &ApplyView,
    invocation: &mut Invocation<'_>,
) -> Result<ExitStatus, CommandFailure> {
    let in_progress: bool = view
        .operation
        .as_ref()
        .is_some_and(|operation| operation.state == svalnir_core::action::OperationState::Admitted);
    let status: ExitStatus = if flow.no_wait && in_progress {
        ExitStatus::Success
    } else {
        view.status()
    };
    invocation.emit_with_status(Kind::Operation, view, ApplyView::render, status)
}

/// The parts of an `accepted` response that the operation gives.
fn accepted_view(
    flow: &ApplyFlow<'_>,
    report: Option<&OperationReport>,
    operation_id: Option<OperationId>,
    executor: super::execution::Executor,
    request_id: Option<RequestId>,
    notes: Vec<&'static str>,
) -> AcceptedView {
    AcceptedView {
        acknowledgement: if operation_id.is_some() {
            "operation_admitted"
        } else {
            "request_queued"
        },
        plan_id: flow.plan.plan_id.clone(),
        state: report.map_or_else(
            || {
                // An operation that exists is admitted, also when its
                // view cannot be read now.
                if operation_id.is_some() {
                    svalnir_core::action::OperationState::Admitted
                        .as_str()
                        .to_owned()
                } else {
                    "queued".to_owned()
                }
            },
            |report| report.state.as_str().to_owned(),
        ),
        dispatch: report.map(|report| report.dispatch.as_str().to_owned()),
        durability: report.map(|report| report.durability.as_str().to_owned()),
        operation_id,
        executor,
        request_id,
        notes,
    }
}

/// The parts of a wait that ended, or the error that ended it.
#[cfg(target_os = "macos")]
fn wait_parts(
    end: super::execution::WaitEnd,
    what: &str,
) -> Result<(&'static str, Option<OperationReport>, Option<&'static str>), ErrorBody> {
    use super::execution::WaitEnd;
    match end {
        WaitEnd::Finished(report) => Ok(("finished", Some(report), None)),
        WaitEnd::TimedOut(report) => Ok(("timed_out", report, Some(TIMEOUT_NOTE))),
        WaitEnd::Interrupted(report) => Ok(("interrupted", report, Some(INTERRUPT_NOTE))),
        WaitEnd::Rejected(error) => Err(session::action_error(&error, what)),
        WaitEnd::Failed(error) => Err(error),
    }
}

/// Writes the response of an operation that this process executes.
#[cfg(target_os = "macos")]
fn respond_transient(
    flow: &ApplyFlow<'_>,
    running: &mut super::execution::Running,
    invocation: &mut Invocation<'_>,
) -> Result<ExitStatus, CommandFailure> {
    use super::execution::Executor;

    if flow.no_wait {
        let report: Option<OperationReport> = running.report();
        let view: AcceptedView = accepted_view(
            flow,
            report.as_ref(),
            Some(running.operation_id().clone()),
            Executor::TransientCoordinator,
            None,
            vec![NO_WAIT_NOTE, TRANSIENT_NOTE],
        );
        return invocation.emit_with_status(
            Kind::Accepted,
            &view,
            AcceptedView::render,
            ExitStatus::Success,
        );
    }
    let end = running.wait(invocation.timeout, &invocation.environment.interrupt);
    let (wait, operation, note) = wait_parts(end, flow.what)?;
    let view = ApplyView {
        wait,
        existing_operation: false,
        plan_id: flow.plan.plan_id.clone(),
        executor: Some(Executor::TransientCoordinator),
        request_id: None,
        operation: operation
            .map(|report| report.with_paths(target_paths(flow.plan, flow.document.as_ref()))),
        notes: note.into_iter().collect(),
    };
    let status: ExitStatus = view.status();
    invocation.emit_with_status(Kind::Operation, &view, ApplyView::render, status)
}

/// Records the operation of a plan in its plan document, so that a
/// repeated request finds it also after a lost response.
fn record_operation(
    flow: &mut ApplyFlow<'_>,
    operation_id: &OperationId,
    invocation: &mut Invocation<'_>,
) {
    if let Some(document) = &mut flow.document
        && document.operation_id.as_ref() != Some(operation_id)
    {
        document.operation_id = Some(operation_id.clone());
        if plan_store::save_plan(invocation.environment, document).is_err() {
            invocation.warnings.push(crate::output::Warning {
                code: "plan_document_not_updated".into(),
                message: "the plan document was not updated with the operation; the journal has the operation".to_owned(),
            });
        }
    }
}

/// The apply of a plan that this process executes.
#[cfg(target_os = "macos")]
fn run_transient(
    flow: &mut ApplyFlow<'_>,
    mut running: super::execution::Running,
    invocation: &mut Invocation<'_>,
) -> Result<ExitStatus, CommandFailure> {
    record_operation(flow, &running.operation_id().clone(), invocation);
    // The response can fail, for example when the reader of a pipe closed
    // it. The operation is executed to its end in each case: this process
    // is its executor.
    let response: Result<ExitStatus, CommandFailure> =
        respond_transient(flow, &mut running, invocation);
    // The response is complete before the remaining work, so a reader of
    // a pipe has it at once.
    drop(invocation.stdout.flush());
    let last: Option<OperationReport> = running.complete();
    if let (Some(document), Some(measurements)) = (
        &mut flow.document,
        last.as_ref().and_then(OperationReport::measurements),
    ) {
        document.measurements = Some(measurements);
        drop(plan_store::save_plan(invocation.environment, document));
    }
    response
}

/// The apply of a plan that a different process executes.
#[cfg(target_os = "macos")]
fn run_queued(
    flow: &mut ApplyFlow<'_>,
    queued: &super::execution::Queued,
    invocation: &mut Invocation<'_>,
) -> Result<ExitStatus, CommandFailure> {
    use super::execution::{ADMISSION_WAIT, Executor};

    let request_id: RequestId = queued.request_id().clone();
    let end = if flow.no_wait {
        queued.wait(
            Some(invocation.timeout.unwrap_or(ADMISSION_WAIT)),
            true,
            &invocation.environment.interrupt,
        )
    } else {
        queued.wait(invocation.timeout, false, &invocation.environment.interrupt)
    };
    // A wait that failed after the admission still knows the operation:
    // the plan document gets it, so a repeated request finds it.
    if let super::execution::WaitEnd::Failed(error) = &end
        && let Some(operation_id) = error
            .operation_id
            .as_deref()
            .and_then(|text| OperationId::new(text).ok())
    {
        record_operation(flow, &operation_id, invocation);
    }
    let (wait, report, note) = wait_parts(end, flow.what)?;
    if let Some(report) = &report {
        record_operation(flow, &report.operation_id.clone(), invocation);
    }
    if flow.no_wait {
        let view: AcceptedView = accepted_view(
            flow,
            report.as_ref(),
            report.as_ref().map(|report| report.operation_id.clone()),
            Executor::QueuedForCoordinator,
            Some(request_id),
            vec![NO_WAIT_NOTE, QUEUED_NOTE],
        );
        // An interrupt ends the client with its own status. The request
        // stays in the queue.
        let status: ExitStatus = if wait == "interrupted" {
            ExitStatus::Interrupted
        } else {
            ExitStatus::Success
        };
        return invocation.emit_with_status(Kind::Accepted, &view, AcceptedView::render, status);
    }
    let view = ApplyView {
        wait,
        existing_operation: false,
        plan_id: flow.plan.plan_id.clone(),
        executor: Some(Executor::QueuedForCoordinator),
        request_id: Some(request_id),
        operation: report
            .map(|report| report.with_paths(target_paths(flow.plan, flow.document.as_ref()))),
        notes: std::iter::once(QUEUED_NOTE).chain(note).collect(),
    };
    let status: ExitStatus = view.status();
    invocation.emit_with_status(Kind::Operation, &view, ApplyView::render, status)
}

#[cfg(target_os = "macos")]
pub(crate) fn run(
    mut flow: ApplyFlow<'_>,
    invocation: &mut Invocation<'_>,
) -> Result<ExitStatus, CommandFailure> {
    use super::execution::{self, Applied, ExecutionInput};

    // A second apply of a plan reports its operation and makes no new one.
    if let Some(journal) = session::open_existing_journal(invocation.environment)?
        && let Some(operation) = existing_operation(&journal, &flow.plan.plan_id)?
    {
        let view: ApplyView = existing_view(&flow, &journal, &operation);
        return emit_existing(&flow, &view, invocation);
    }
    // An expired plan is refused before the question. `--yes` does not
    // change this, and the coordinator does the check again.
    let now = session::Now::read(&crate::host::Host::open()?)?;
    if svalnir_core::plan::check_expiry(flow.plan, &now.clock).is_err() {
        return Err(plan_expired(&flow.plan.plan_id).into());
    }
    approve(invocation, flow.yes, &flow.summary, &flow.plan.plan_id)?;
    let roots = flow
        .document
        .as_ref()
        .map_or_else(Vec::new, |document| document.roots.clone());
    // From the admission on, Ctrl+C does not end this process: it can be
    // the executor of the operation.
    invocation.environment.interrupt.arm();
    let applied: Applied = execution::apply(&ExecutionInput {
        environment: invocation.environment,
        plan: flow.plan,
        roots: &roots,
        authority: flow.authority.clone(),
        control_plane: flow.control_plane.clone(),
        request_id: invocation.request_id.clone(),
    })?;
    match applied {
        Applied::Refused(error) => Err(session::action_error(&error, flow.what).into()),
        Applied::Existing(operation) => {
            let journal = session::open_journal(invocation.environment)?;
            let view: ApplyView = existing_view(&flow, &journal, &operation);
            emit_existing(&flow, &view, invocation)
        }
        Applied::Transient(running) => run_transient(&mut flow, *running, invocation),
        Applied::Queued(queued) => run_queued(&mut flow, &queued, invocation),
    }
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn run(
    flow: ApplyFlow<'_>,
    _invocation: &mut Invocation<'_>,
) -> Result<ExitStatus, CommandFailure> {
    let _ = (
        &flow.plan,
        &flow.document,
        &flow.authority,
        &flow.control_plane,
        flow.no_wait,
        flow.yes,
        &flow.summary,
        flow.what,
    );
    Err(crate::host::unsupported_platform("clean apply").into())
}
