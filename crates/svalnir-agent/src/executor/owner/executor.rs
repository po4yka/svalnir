//! The owner executor: the worker thread of one step, its checks before
//! the start, the suspended start, the supervised command, and the target
//! result.

use std::ffi::CString;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use svalnir_core::action::{
    ActionError, ActionStage, Attribution, Checked, DispatchState, Durability, EffectEvidence,
    ErrorCode, ErrorFamily, ExecutableBinding, NativeResult, OwnerOperationBinding,
    OwnerOperationBound, RequestEnvelope, ScopeAllocationEffect, ScopeMeasurement, StopReason,
    TargetBinding, TargetEffect, TargetResult, TargetResultRecord,
};
use svalnir_core::process::Uid;
use svalnir_core::time::WallTime;

use super::measure::measure_scope;
use super::model::{
    AdmittedOwnerStep, OwnerExecutorConfig, OwnerFault, OwnerOutcome, OwnerStepOutcome, code,
};
use super::native::{self, Responsibility, StartFailure, Started};
use super::supervise::{self, Command, Ending, StopCell, Supervised, Supervision};
use super::verify::{
    ExecutableKind, ExecutableRefusal, check_executable, has_planned_identity, is_planned_root,
    script_agrees,
};
use crate::executor::fs::{ApprovedRoots, Stop};
use crate::journal::{DescendantChange, MAX_OWNER_DESCENDANTS, OwnerProcess};
use crate::platform::volume::{Locality, MountTable};
use crate::scan::{CancellationToken, WallScanClock};

/// The longest interval between two readings of the stop request.
const MAX_STOP_POLL: Duration = Duration::from_millis(100);

/// The longest time between `SIGTERM` and `SIGKILL`.
const MAX_STOP_GRACE: Duration = Duration::from_secs(2);

/// A refusal before the start: the code and its family.
type Refusal = (&'static str, ErrorFamily);

/// The owner executor of the user.
#[derive(Debug, Clone)]
pub struct OwnerExecutor {
    config: OwnerExecutorConfig,
}

/// The effective user of this process.
fn effective_uid() -> Uid {
    // SAFETY: `geteuid` has no argument, cannot fail, and changes no state.
    Uid::new(unsafe { libc::geteuid() })
}

fn wall_now() -> Option<WallTime> {
    WallTime::try_from(std::time::SystemTime::now()).ok()
}

/// What the worker of a step reports to the coordinator.
#[derive(Debug)]
enum Event {
    /// The command is started and suspended. The worker waits for the
    /// answer of [`OwnerRun::recorded`] before it lets the command run.
    Started(OwnerProcess),
    /// The set of the live descendants of the command changed since the
    /// last report.
    Descendants(DescendantChange),
    /// The step has its result.
    Finished(Box<OwnerStepOutcome>),
}

/// The state of a step that the coordinator reads.
#[derive(Debug)]
pub enum OwnerPoll {
    /// The worker has nothing new.
    Pending,
    /// The command is started and suspended. The coordinator records the
    /// process in the journal and answers with [`OwnerRun::recorded`].
    Started(OwnerProcess),
    /// The set of the live descendants of the command changed. The
    /// coordinator records the change in the journal.
    Descendants(DescendantChange),
    /// The step has its result. The worker thread has ended.
    Finished(Box<OwnerStepOutcome>),
}

/// The handle of one step on its worker thread.
#[derive(Debug)]
pub struct OwnerRun {
    events: Receiver<Event>,
    answer: SyncSender<bool>,
    stop: Arc<StopCell>,
    cancel: CancellationToken,
    thread: Option<JoinHandle<()>>,
    started: bool,
}

impl OwnerRun {
    /// Reads the state of the worker. A worker that ended with no result
    /// gives a fault.
    pub fn poll(&mut self) -> OwnerPoll {
        match self.events.try_recv() {
            Ok(Event::Started(process)) => {
                self.started = true;
                OwnerPoll::Started(process)
            }
            Ok(Event::Descendants(change)) => OwnerPoll::Descendants(change),
            Ok(Event::Finished(outcome)) => {
                self.join();
                OwnerPoll::Finished(outcome)
            }
            Err(TryRecvError::Empty) => OwnerPoll::Pending,
            Err(TryRecvError::Disconnected) => {
                self.join();
                let dispatch: DispatchState = if self.started {
                    DispatchState::SubmissionUncertain
                } else {
                    DispatchState::NotSubmitted
                };
                OwnerPoll::Finished(Box::new(Err(Box::new(OwnerFault {
                    dispatch,
                    scope: None,
                }))))
            }
        }
    }

    /// The answer to [`OwnerPoll::Started`]: whether the journal recorded
    /// the process. With `false`, the worker stops the suspended process
    /// before it runs.
    pub fn recorded(&self, recorded: bool) {
        let _answered: Result<(), mpsc::TrySendError<bool>> = self.answer.try_send(recorded);
    }

    /// Asks the worker to stop the command. The first request is kept. A
    /// measurement of the scope or a digest of an executable in progress
    /// ends at once, so the stop stays bounded.
    pub fn stop(&self, stop: Stop) {
        if let Ok(mut cell) = self.stop.lock()
            && cell.is_none()
        {
            *cell = Some(stop);
        }
        self.cancel.cancel();
    }

    fn join(&mut self) {
        if let Some(thread) = self.thread.take() {
            drop(thread.join());
        }
    }
}

impl Drop for OwnerRun {
    /// A handle that goes before the result stops the command and waits
    /// for the worker, so no command runs with no owner.
    fn drop(&mut self) {
        self.stop(Stop::Canceled);
        let _answered: Result<(), mpsc::TrySendError<bool>> = self.answer.try_send(false);
        self.join();
    }
}

impl OwnerExecutor {
    /// Makes the executor. The stop interval is at most 100 ms, the stop
    /// grace at most 2 seconds, and the set of descendants at most
    /// [`MAX_OWNER_DESCENDANTS`]; a larger value is cut to that bound.
    pub fn new(mut config: OwnerExecutorConfig) -> Self {
        config.stop_poll = config.stop_poll.min(MAX_STOP_POLL);
        config.stop_grace = config.stop_grace.min(MAX_STOP_GRACE);
        config.max_descendants = config.max_descendants.min(MAX_OWNER_DESCENDANTS);
        Self { config }
    }

    /// The settings.
    pub fn config(&self) -> &OwnerExecutorConfig {
        &self.config
    }

    /// Starts one admitted step on a worker thread under the root records
    /// `roots` of this process (`docs/ACTION_CONTRACTS.md` section 7, the
    /// subsection of `RunOwnerOperation`). The call does not wait: the
    /// caller reads the worker with [`OwnerRun::poll`].
    pub fn begin(&self, roots: &ApprovedRoots, step: AdmittedOwnerStep<'_>) -> OwnerRun {
        let (envelope, _) = step.into_parts();
        let (events, receiver) = mpsc::channel();
        let (answer, answers) = mpsc::sync_channel(1);
        let request: Arc<StopCell> = Arc::new(Mutex::new(None));
        let cancel: CancellationToken = CancellationToken::new();
        let worker = Worker {
            config: self.config.clone(),
            roots: roots.clone(),
            envelope: envelope.clone(),
            stop: Arc::clone(&request),
            cancel: cancel.clone(),
        };
        let thread = thread::Builder::new()
            .name("owner-operation".to_owned())
            .spawn(move || {
                let outcome: OwnerStepOutcome = worker.run(&events, &answers);
                drop(events.send(Event::Finished(Box::new(outcome))));
            })
            .ok();
        OwnerRun {
            events: receiver,
            answer,
            stop: request,
            cancel,
            thread,
            started: false,
        }
    }
}

/// The record of the live process `pid` as the leader of its own process
/// group, with its start time. `None` when no such process exists.
pub fn process_record_of(pid: i32) -> Option<OwnerProcess> {
    Some(OwnerProcess {
        pid,
        started: native::start_time(pid)?,
        group: pid,
        descendants: Vec::new(),
        truncated: false,
    })
}

/// The work of one step on its own thread.
struct Worker {
    config: OwnerExecutorConfig,
    roots: ApprovedRoots,
    envelope: RequestEnvelope,
    stop: Arc<StopCell>,
    cancel: CancellationToken,
}

/// The Mach-O file that the worker starts, its argument vector, and the
/// files whose identity the start checks.
struct Program {
    path: CString,
    arguments: Vec<CString>,
    main: ExecutableBinding,
    files: Vec<ExecutableBinding>,
}

fn c_string(text: &[u8]) -> Option<CString> {
    CString::new(text.to_vec()).ok()
}

/// The program of `owner`: the executable, or the interpreter of a script
/// with its interpreter arguments and the path of the script.
fn program(owner: &OwnerOperationBinding) -> Option<Program> {
    let mut arguments: Vec<CString> = Vec::new();
    let (main, files): (&ExecutableBinding, Vec<ExecutableBinding>) =
        if let Some(interpreter) = &owner.interpreter {
            arguments.push(c_string(interpreter.executable.path.as_bytes())?);
            for argument in &interpreter.arguments {
                arguments.push(c_string(argument.as_bytes())?);
            }
            arguments.push(c_string(owner.executable.path.as_bytes())?);
            (
                &interpreter.executable,
                vec![interpreter.executable.clone(), owner.executable.clone()],
            )
        } else {
            arguments.push(c_string(owner.executable.path.as_bytes())?);
            (&owner.executable, vec![owner.executable.clone()])
        };
    for argument in &owner.arguments {
        arguments.push(c_string(argument.as_bytes())?);
    }
    Some(Program {
        path: c_string(main.path.as_bytes())?,
        arguments,
        main: main.clone(),
        files,
    })
}

impl Worker {
    fn owner(&self) -> Option<&OwnerOperationBinding> {
        match &self.envelope.target.binding {
            TargetBinding::OwnerOperation(owner) => Some(owner),
            _ => None,
        }
    }

    fn draft(&self) -> Draft<'_> {
        Draft {
            envelope: &self.envelope,
            adapter: &self.config.adapter,
        }
    }

    /// The result of a stop request that arrived before the command ran.
    fn stopped(&self, halt: Stop) -> OwnerStepOutcome {
        let result: TargetResult = self
            .draft()
            .stopped_before_run(halt.stop_reason())
            .map_err(|NoRecord| no_record(DispatchState::NotSubmitted, None))?;
        Ok(OwnerOutcome {
            result,
            scope: None,
            exit_status: None,
            diagnostic_tail: None,
        })
    }

    /// The result of a refused check, or of the stop request that ended
    /// the check: a cancelled measurement or digest is a stop and not a
    /// changed scope or executable.
    fn refused(&self, refusal: Refusal) -> OwnerStepOutcome {
        match supervise::requested(&self.stop) {
            Some(halt) => self.stopped(halt),
            None => self.skipped(refusal),
        }
    }

    fn skipped(&self, refusal: Refusal) -> OwnerStepOutcome {
        let result: TargetResult = self
            .draft()
            .skipped(refusal.0, refusal.1)
            .map_err(|NoRecord| no_record(DispatchState::NotSubmitted, None))?;
        Ok(OwnerOutcome {
            result,
            scope: None,
            exit_status: None,
            diagnostic_tail: None,
        })
    }

    /// The step on the worker thread.
    fn run(&self, events: &mpsc::Sender<Event>, answers: &Receiver<bool>) -> OwnerStepOutcome {
        let Some(owner) = self.owner() else {
            return self.skipped((code::OWNER_OPERATION_NOT_STARTED, ErrorFamily::Request));
        };
        let before: ScopeMeasurement = match self.check_before_start(owner) {
            Ok(before) => before,
            Err(refusal) => return self.refused(refusal),
        };
        let Some(responsibility) = Responsibility::resolve(&self.config.responsibility) else {
            return self.skipped((code::OWNER_DISCLAIM_UNAVAILABLE, ErrorFamily::Native));
        };
        let Some(program) = program(owner) else {
            return self.skipped((code::OWNER_OPERATION_NOT_STARTED, ErrorFamily::Native));
        };
        // The last check before the start: each file of the program, with
        // its digest, one time for the step. The kind of each file is read
        // from the descriptor of its digest.
        let mut script_kind: Option<ExecutableKind> = None;
        for file in &program.files {
            match check_executable(
                file,
                owner.owner,
                self.config.max_executable_bytes,
                &self.cancel,
            ) {
                Ok(kind) if file.path == owner.executable.path => script_kind = kind,
                // The interpreter of a script is a Mach-O file.
                Ok(kind) => {
                    if kind != Some(ExecutableKind::MachO) {
                        return self
                            .refused((code::OWNER_EXECUTABLE_CHANGED, ErrorFamily::Evidence));
                    }
                }
                Err(ExecutableRefusal::Changed) => {
                    return self.refused((code::OWNER_EXECUTABLE_CHANGED, ErrorFamily::Evidence));
                }
                Err(ExecutableRefusal::NotTrusted) => {
                    return self
                        .refused((code::OWNER_EXECUTABLE_NOT_TRUSTED, ErrorFamily::Eligibility));
                }
            }
        }
        // The `#!` line of the verified script is the interpreter and the
        // interpreter argument of the binding, and a binding has an
        // interpreter exactly for a script.
        if !script_agrees(script_kind.as_ref(), owner.interpreter.as_ref()) {
            return self.skipped((code::OWNER_EXECUTABLE_CHANGED, ErrorFamily::Evidence));
        }
        let environment: Option<Vec<CString>> = owner
            .environment
            .iter()
            .map(|entry| c_string(format!("{}={}", entry.name, entry.value).as_bytes()))
            .collect();
        let (Some(environment), Some(directory)) =
            (environment, c_string(owner.working_directory.as_bytes()))
        else {
            return self.skipped((code::OWNER_OPERATION_NOT_STARTED, ErrorFamily::Native));
        };
        // A stop that arrived during the checks starts no command.
        if let Some(halt) = supervise::requested(&self.stop) {
            return self.stopped(halt);
        }
        let started: Started = match native::spawn_suspended(
            responsibility,
            &program.path,
            &program.arguments,
            &environment,
            &directory,
        ) {
            Ok(started) => started,
            Err(StartFailure::Disclaim) => {
                return self.skipped((code::OWNER_DISCLAIM_UNAVAILABLE, ErrorFamily::Native));
            }
            Err(StartFailure::Spawn) => {
                return self.skipped((code::OWNER_OPERATION_NOT_STARTED, ErrorFamily::Native));
            }
        };
        self.run_started(
            owner,
            &program,
            before,
            started,
            responsibility,
            events,
            answers,
        )
    }

    /// The part of the step after the suspended start: the comparison of
    /// the main text, the record, the resume, and the supervision.
    #[expect(
        clippy::too_many_arguments,
        reason = "the values of one start, which `run` hands on"
    )]
    fn run_started(
        &self,
        owner: &OwnerOperationBinding,
        program: &Program,
        before: ScopeMeasurement,
        started: Started,
        responsibility: Responsibility,
        events: &mpsc::Sender<Event>,
        answers: &Receiver<bool>,
    ) -> OwnerStepOutcome {
        let pid: libc::pid_t = started.pid;
        // The suspended process ran no instruction of the command: its main
        // text must be the bound Mach-O file, and each file must have its
        // planned identity and change time.
        let identical: bool = native::main_text_agrees(pid, &program.main.object)
            && program.files.iter().all(has_planned_identity);
        let start_time = native::start_time(pid);
        let (true, Some(start_time)) = (identical, start_time) else {
            supervise::kill_suspended(pid);
            let code_text: &str = if identical {
                code::OWNER_OPERATION_NOT_STARTED
            } else {
                code::OWNER_EXECUTABLE_CHANGED
            };
            return self.skipped((code_text, ErrorFamily::Evidence));
        };
        let process = OwnerProcess {
            pid,
            started: start_time,
            group: pid,
            descendants: Vec::new(),
            truncated: false,
        };
        // The coordinator records the process before it runs.
        let recorded: bool =
            events.send(Event::Started(process)).is_ok() && self.wait_for_record(answers);
        if !recorded {
            supervise::kill_suspended(pid);
            return self.skipped((code::OWNER_PROCESS_NOT_RECORDED, ErrorFamily::Recording));
        }
        if let Some(halt) = supervise::requested(&self.stop) {
            supervise::kill_suspended(pid);
            return self.stopped(halt);
        }
        let limits = Supervision {
            deadline: Duration::from_nanos(owner.command_deadline.get()),
            stop_poll: self.config.stop_poll,
            stop_grace: self.config.stop_grace,
            max_tracked: self.config.max_descendants,
        };
        let supervised: Supervised = supervise::run(
            Command {
                pid,
                started: start_time,
                stdout: started.stdout,
                stderr: started.stderr,
            },
            responsibility,
            &limits,
            &self.stop,
            &|change: &DescendantChange| {
                drop(events.send(Event::Descendants(change.clone())));
            },
        );
        self.finish(owner, before, &supervised)
    }

    /// Waits for the answer of the coordinator to the start, at most the
    /// record wait, and no longer than a stop request.
    fn wait_for_record(&self, answers: &Receiver<bool>) -> bool {
        let until: Instant = Instant::now() + self.config.record_wait;
        loop {
            let left: Duration = until.saturating_duration_since(Instant::now());
            if left.is_zero() || supervise::requested(&self.stop).is_some() {
                return false;
            }
            match answers.recv_timeout(left.min(self.config.stop_poll)) {
                Ok(recorded) => return recorded,
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return false,
            }
        }
    }

    /// The result of a command that ran.
    fn finish(
        &self,
        owner: &OwnerOperationBinding,
        before: ScopeMeasurement,
        supervised: &Supervised,
    ) -> OwnerStepOutcome {
        // The scope is measured again after an exit. After a stop it is
        // not, so that a stop of the agent stays bounded.
        let after: Option<ScopeMeasurement> = match supervised.ending {
            Ending::Exited { .. } => self.measure(&owner.root_path.to_path_buf()),
            _ => None,
        };
        let scope =
            ScopeAllocationEffect::new(self.envelope.target.target_id.clone(), before, after);
        let home: String = String::from_utf8_lossy(self.config.home_directory.as_bytes()).into();
        let exit_status: Option<i32> = match supervised.ending {
            Ending::Exited { status, .. } => Some(supervise::status_code(status)),
            _ => None,
        };
        // The bound of an automatic step is verified by the measurements:
        // the scope did not grow during the command.
        let bound_verified: bool = !self.envelope.trigger.class.is_automatic()
            || !matches!(owner.bound, OwnerOperationBound::WithinScope)
            || after.is_some_and(|after| {
                after.complete && before.complete && after.allocated_bytes <= before.allocated_bytes
            });
        let out: String = supervise::redacted(&supervised.stdout, &home);
        let err: String = supervise::redacted(&supervised.stderr, &home);
        let tail: String = match (out.is_empty(), err.is_empty()) {
            (true, true) => String::new(),
            (false, true) => format!("stdout: {out}"),
            (true, false) => format!("stderr: {err}"),
            (false, false) => format!("stdout: {out} || stderr: {err}"),
        };
        match self
            .draft()
            .of_ending(supervised, exit_status, bound_verified)
        {
            Ok(result) => Ok(OwnerOutcome {
                result,
                scope: Some(scope),
                exit_status,
                diagnostic_tail: Some(tail),
            }),
            Err(NoRecord) => Err(no_record(DispatchState::Submitted, Some(scope))),
        }
    }

    /// The checks before the start, in the sequence of the specification,
    /// with no check of the executable. Returns the measurement of the
    /// scope before the command.
    fn check_before_start(
        &self,
        owner: &OwnerOperationBinding,
    ) -> Result<ScopeMeasurement, Refusal> {
        let principal: Uid = self.envelope.principal.uid;
        if effective_uid() != principal {
            return Err((code::PRINCIPAL_MISMATCH, ErrorFamily::Authority));
        }
        if self
            .roots
            .root(&owner.root_id)
            .is_some_and(|root| root.path != owner.root_path || root.object != owner.root_object)
        {
            return Err((code::APPROVED_ROOT_MISMATCH, ErrorFamily::Evidence));
        }
        let root: PathBuf = owner.root_path.to_path_buf();
        let locality: Locality = MountTable::read().map_or(Locality::Unknown, |table| match table
            .path_locality(&root)
        {
            Locality::Local => table.device_locality(owner.root_object.device),
            other => other,
        });
        match locality {
            Locality::Local => {}
            Locality::NotLocal => return Err((code::ROOT_NOT_LOCAL, ErrorFamily::Eligibility)),
            Locality::Unknown => {
                return Err((code::ROOT_LOCALITY_UNKNOWN, ErrorFamily::Evidence));
            }
        }
        if !is_planned_root(&root, &owner.root_object, owner.owner) {
            return Err((code::SCOPE_ROOT_CHANGED, ErrorFamily::Evidence));
        }
        let before: ScopeMeasurement = self
            .measure(&root)
            .filter(|measurement| measurement.complete)
            .ok_or((code::SCOPE_NOT_MEASURED, ErrorFamily::Evidence))?;
        // The plan does not authorize data or entries that appeared after
        // it was made.
        if !before.fits_in(&owner.charge) {
            return Err((code::TARGET_GREW, ErrorFamily::Evidence));
        }
        // The root can be replaced during the measurement.
        if !is_planned_root(&root, &owner.root_object, owner.owner) {
            return Err((code::SCOPE_ROOT_CHANGED, ErrorFamily::Evidence));
        }
        Ok(before)
    }

    fn measure(&self, root: &Path) -> Option<ScopeMeasurement> {
        measure_scope(root, self.config.scope, &self.cancel, &WallScanClock)
    }
}

/// A record that the contract types rejected: a defect of the executor.
#[derive(Debug, Clone, Copy)]
struct NoRecord;

/// The fault of a step whose record was rejected.
fn no_record(dispatch: DispatchState, scope: Option<ScopeAllocationEffect>) -> Box<OwnerFault> {
    Box::new(OwnerFault { dispatch, scope })
}

/// The builder of the target result of one step.
struct Draft<'a> {
    envelope: &'a RequestEnvelope,
    adapter: &'a svalnir_core::id::AdapterId,
}

impl Draft<'_> {
    /// The result of a command that started, from the way it ended.
    fn of_ending(
        &self,
        supervised: &Supervised,
        exit_status: Option<i32>,
        bound_verified: bool,
    ) -> Result<TargetResult, NoRecord> {
        match supervised.ending {
            Ending::Exited { status, .. }
                if supervise::is_success(status) && supervised.truncated =>
            {
                self.unknown(
                    exit_status,
                    StopReason::Failed,
                    Some(code::OWNER_DESCENDANTS_TRUNCATED),
                )
            }
            Ending::Exited { status, clean } if supervise::is_success(status) => {
                if !clean {
                    self.unknown(
                        exit_status,
                        StopReason::Failed,
                        Some(code::OWNER_OPERATION_CHILDREN_REMAINED),
                    )
                } else if bound_verified {
                    self.completed()
                } else {
                    self.unknown(
                        exit_status,
                        StopReason::Failed,
                        Some(code::OWNER_OPERATION_BOUND_NOT_VERIFIED),
                    )
                }
            }
            Ending::Exited { .. } | Ending::Lost => self.unknown(
                exit_status,
                StopReason::Failed,
                Some(code::OWNER_OPERATION_FAILED),
            ),
            Ending::Deadline => self.unknown(
                None,
                StopReason::Failed,
                Some(code::OWNER_OPERATION_DEADLINE),
            ),
            Ending::Stopped(halt) => self.unknown(None, halt.stop_reason(), None),
        }
    }

    fn error(
        &self,
        text: &str,
        family: ErrorFamily,
        stage: ActionStage,
        dispatch: DispatchState,
    ) -> Result<ActionError, NoRecord> {
        let correlation = &self.envelope.correlation;
        Ok(ActionError {
            code: ErrorCode::new(text).map_err(|_| NoRecord)?,
            family,
            stage,
            dispatch,
            plan_id: Some(correlation.plan_id.clone()),
            operation_id: Some(correlation.operation_id.clone()),
            step_id: Some(correlation.step_id.clone()),
        })
    }

    fn check(record: TargetResultRecord) -> Result<TargetResult, NoRecord> {
        Checked::new(record).map_err(|_| NoRecord)
    }

    fn not_run(&self, stop_reason: StopReason, failure: Option<ActionError>) -> TargetResultRecord {
        TargetResultRecord {
            target_id: self.envelope.target.target_id.clone(),
            member: None,
            dispatch: DispatchState::NotSubmitted,
            effect: TargetEffect::Skipped,
            evidence: EffectEvidence::none(),
            attribution: Attribution::NotApplicable,
            durability: Durability::Durable,
            stop_reason,
            failure,
        }
    }

    /// A target that got no command.
    fn skipped(&self, text: &str, family: ErrorFamily) -> Result<TargetResult, NoRecord> {
        let failure: ActionError = self.error(
            text,
            family,
            ActionStage::Dispatch,
            DispatchState::NotSubmitted,
        )?;
        Self::check(self.not_run(StopReason::TargetSkipped, Some(failure)))
    }

    /// A command that a stop request ended while it was suspended: it ran
    /// no instruction.
    fn stopped_before_run(&self, stop_reason: StopReason) -> Result<TargetResult, NoRecord> {
        Self::check(self.not_run(stop_reason, None))
    }

    /// A command that exited with status 0 and left no process.
    fn completed(&self) -> Result<TargetResult, NoRecord> {
        Self::check(TargetResultRecord {
            target_id: self.envelope.target.target_id.clone(),
            member: None,
            dispatch: DispatchState::Submitted,
            effect: TargetEffect::OperationCompleted,
            evidence: EffectEvidence {
                native: NativeResult::ExitStatus { status: 0 },
                source: Some(self.adapter.clone()),
                observed_at: wall_now(),
                trash_item: None,
            },
            attribution: Attribution::Possible,
            durability: Durability::Durable,
            stop_reason: StopReason::Completed,
            failure: None,
        })
    }

    /// A command whose effect is not known.
    fn unknown(
        &self,
        exit_status: Option<i32>,
        stop_reason: StopReason,
        text: Option<&str>,
    ) -> Result<TargetResult, NoRecord> {
        let failure: Option<ActionError> = match text {
            Some(text) => Some(self.error(
                text,
                ErrorFamily::Outcome,
                ActionStage::Execution,
                DispatchState::Submitted,
            )?),
            None => None,
        };
        let native: NativeResult = exit_status.map_or(NativeResult::Unavailable, |status| {
            NativeResult::ExitStatus { status }
        });
        Self::check(TargetResultRecord {
            target_id: self.envelope.target.target_id.clone(),
            member: None,
            dispatch: DispatchState::Submitted,
            effect: TargetEffect::UnknownOutcome,
            evidence: EffectEvidence {
                native,
                source: Some(self.adapter.clone()),
                observed_at: wall_now(),
                trash_item: None,
            },
            attribution: Attribution::Possible,
            durability: Durability::Durable,
            stop_reason,
            failure,
        })
    }
}
