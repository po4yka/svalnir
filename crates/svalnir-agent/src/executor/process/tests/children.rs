//! The signal path with live processes.
//!
//! Each test starts its own child process, and the executor signals only
//! that child: the planned identity is the PID and the start time of the
//! child, and the executor checks them before each call. A guard kills and
//! collects the child at the end of the test, also when the test fails.
//!
//! The child is this test binary, started again with [`child_entry`] as
//! its only test. A system program such as `/bin/sleep` cannot be the
//! target: the executor refuses an executable below a system directory.
//!
//! No test in this file starts or terminates an application, so the
//! `NSRunningApplication` calls are not exercised here.

use std::os::unix::process::ExitStatusExt;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use svalnir_core::action::{
    ActionClass, Attribution, Checked, DispatchState, EnvelopeContent, Escalation, NativeResult,
    RequestEnvelope, StepState, TargetEffect, TargetResult, aggregate_step,
};
use svalnir_core::policy::ProtectionFact;
use svalnir_core::process::{ExecutableIdentity, Pid, ProcessIdentity};
use svalnir_core::quantity::Nanoseconds;
use svalnir_core::time::MonotonicNanos;

use super::super::{
    DarwinProcessControl, ExecutorConfig, GenerationState, GracefulRecord, NextStep,
    ProcessExecutor, SourceClock, StepInput, StepReport, StepRun,
};
use super::fake::{content, context, job, receipt};
use crate::platform::process::{DarwinProcessSource, ProcessSource, generation_id};

/// The environment variable that makes [`child_entry`] wait.
const CHILD_VARIABLE: &str = "SVALNIR_TEST_PROCESS_EXECUTOR_CHILD";

/// The full name of [`child_entry`] for the test harness.
const CHILD_TEST: &str = "executor::process::tests::children::child_entry";

/// The longest life of a child, so that a child that a failed test leaves
/// does not stay.
const CHILD_LIFE: Duration = Duration::from_secs(60);

type Executor =
    ProcessExecutor<DarwinProcessSource, DarwinProcessControl, SourceClock<DarwinProcessSource>>;

/// The body of a child process. Without the variable, which only the
/// tests of this file set, it does nothing.
#[test]
#[ignore = "the entry of a child process that the tests of this file start"]
fn child_entry() {
    if std::env::var_os(CHILD_VARIABLE).is_none() {
        return;
    }
    // The child ends when its life ends or when the test process that
    // started it does not exist, so a test process that was killed leaves
    // no child.
    let parent: u32 = std::os::unix::process::parent_id();
    let end: Instant = Instant::now() + CHILD_LIFE;
    while Instant::now() < end && std::os::unix::process::parent_id() == parent {
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// A child process that is killed and collected when the value is dropped.
struct ChildGuard(Child);

impl ChildGuard {
    fn pid(&self) -> Pid {
        Pid::new(i32::try_from(self.0.id()).unwrap()).unwrap()
    }

    fn collect(&mut self) -> ExitStatus {
        self.0.wait().unwrap()
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        // `Child::kill` addresses only the child of this value, and it does
        // nothing for a child that was collected.
        if let Err(error) = self.0.kill() {
            eprintln!("the child was not killed: {error}");
        }
        if let Err(error) = self.0.wait() {
            eprintln!("the child was not collected: {error}");
        }
    }
}

fn child_command(program: &std::path::Path) -> Command {
    let mut command: Command = Command::new(program);
    command
        .env(CHILD_VARIABLE, "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

/// Starts a child that exits on `SIGTERM`.
fn spawn_child() -> ChildGuard {
    let program = std::env::current_exe().unwrap();
    let child: Child = child_command(&program)
        .args(["--ignored", "--exact", CHILD_TEST])
        .spawn()
        .unwrap();
    ChildGuard(child)
}

/// Starts a child that ignores `SIGTERM`. The shell sets the disposition
/// and replaces itself with the test binary, which inherits it. There is
/// one process and no descendant.
fn spawn_child_that_ignores_term(source: DarwinProcessSource) -> ChildGuard {
    let program = std::env::current_exe().unwrap();
    let child: Child = child_command(std::path::Path::new("/bin/sh"))
        .args(["-c", "trap '' TERM; exec \"$0\" \"$@\""])
        .arg(&program)
        .args(["--ignored", "--exact", CHILD_TEST])
        .spawn()
        .unwrap();
    let guard: ChildGuard = ChildGuard(child);
    // Wait until the shell replaced itself.
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
fn identity(source: DarwinProcessSource, process: Pid) -> ProcessIdentity {
    let info = source.process_info(process).unwrap();
    let path = source.executable_path(process).unwrap();
    let file = source.file_evidence(&path).ok();
    ProcessIdentity {
        generation_id: generation_id(process, info.start_time).unwrap(),
        pid: process,
        start_time: info.start_time,
        uid: info.effective_uid,
        boot_id: context().boot_id,
        executable: Some(ExecutableIdentity {
            path,
            file,
            code_signature: None,
        }),
        association: job(),
    }
}

fn executor() -> Executor {
    ProcessExecutor::new(
        DarwinProcessSource::new(),
        DarwinProcessControl::new(),
        SourceClock(DarwinProcessSource::new()),
        context(),
        ExecutorConfig::default(),
    )
}

/// An envelope whose times are on the clock of this host.
fn envelope(
    source: DarwinProcessSource,
    class: ActionClass,
    escalation: Escalation,
    planned: &ProcessIdentity,
) -> RequestEnvelope {
    let now: MonotonicNanos = source.monotonic_now().unwrap();
    let later: MonotonicNanos = now.checked_add(Nanoseconds::new(60_000_000_000)).unwrap();
    let mut content: EnvelopeContent =
        content(class, escalation, vec![planned.clone()], planned.uid.get());
    content.evidence.observed_at = now;
    content.evidence.valid_until = later;
    content.limits.deadline = later;
    content.limits.verification_window = Nanoseconds::new(10_000_000_000);
    if content.limits.grace.is_some() {
        content.limits.grace = Some(Nanoseconds::new(300_000_000));
    }
    content.leases[0].expires_at = later;
    Checked::new(content).unwrap()
}

fn run_to_end(executor: &Executor, mut run: StepRun) -> StepReport {
    let limit: Instant = Instant::now() + Duration::from_secs(30);
    loop {
        match run {
            StepRun::Finished(report) => return report,
            StepRun::Observing(observation) => {
                assert!(Instant::now() < limit, "the step did not finish");
                std::thread::sleep(Duration::from_millis(20));
                run = observation.poll(executor, None).unwrap();
            }
        }
    }
}

fn input<'a>(
    envelope: &'a RequestEnvelope,
    receipt: &'a svalnir_core::action::DispatchReceipt,
) -> StepInput<'a> {
    StepInput {
        envelope,
        receipt,
        protection: ProtectionFact::NotProtected,
        graceful: None,
        stop: None,
    }
}

#[test]
fn a_child_that_exits_on_term_is_verified() {
    let source: DarwinProcessSource = DarwinProcessSource::new();
    let mut child: ChildGuard = spawn_child();
    let planned: ProcessIdentity = identity(source, child.pid());
    let envelope = envelope(
        source,
        ActionClass::RequestApplicationExit,
        Escalation::None,
        &planned,
    );
    let executor: Executor = executor();
    let receipt = receipt();
    let run: StepRun = executor.begin(input(&envelope, &receipt)).unwrap();
    // `kill` returned success. The exit is a later observation.
    assert!(matches!(run, StepRun::Observing(_)));
    let report: StepReport = run_to_end(&executor, run);
    let result: &TargetResult = &report.members[0].result;
    assert_eq!(result.effect, TargetEffect::ExitVerified);
    assert_eq!(result.dispatch, DispatchState::Submitted);
    assert_eq!(result.attribution, Attribution::Established);
    assert_eq!(result.evidence.native, NativeResult::Succeeded);
    assert_eq!(report.members[0].state, Some(GenerationState::Exited));
    assert_eq!(report.next, NextStep::None);
    assert_eq!(
        aggregate_step(&report.results()).unwrap(),
        StepState::Completed
    );
    assert_eq!(child.collect().signal(), Some(libc::SIGTERM));
}

#[test]
fn a_child_that_ignores_term_runs_after_the_grace_period_and_exits_on_kill() {
    let source: DarwinProcessSource = DarwinProcessSource::new();
    let mut child: ChildGuard = spawn_child_that_ignores_term(source);
    let planned: ProcessIdentity = identity(source, child.pid());
    let executor: Executor = executor();
    let receipt = receipt();

    let graceful = envelope(
        source,
        ActionClass::RequestApplicationExit,
        Escalation::ForceAfterGrace,
        &planned,
    );
    let run: StepRun = executor.begin(input(&graceful, &receipt)).unwrap();
    let report: StepReport = run_to_end(&executor, run);
    let result: &TargetResult = &report.members[0].result;
    assert_eq!(result.effect, TargetEffect::StillRunning);
    assert_eq!(result.dispatch, DispatchState::Submitted);
    assert_eq!(report.members[0].state, Some(GenerationState::Running));
    assert!(matches!(report.next, NextStep::Force { .. }));
    assert_eq!(
        aggregate_step(&report.results()).unwrap(),
        StepState::Incomplete
    );

    let results: Vec<TargetResult> = report.results();
    let force = envelope(
        source,
        ActionClass::ForceApplicationExit,
        Escalation::ForceAfterGrace,
        &planned,
    );
    let forced_input = StepInput {
        graceful: Some(GracefulRecord {
            submitted_at: report.submitted_at.unwrap(),
            results: &results,
        }),
        ..input(&force, &receipt)
    };
    let run: StepRun = executor.begin(forced_input).unwrap();
    let forced: StepReport = run_to_end(&executor, run);
    let result: &TargetResult = &forced.members[0].result;
    assert_eq!(result.effect, TargetEffect::ExitVerified);
    assert_eq!(result.attribution, Attribution::Established);
    assert_eq!(child.collect().signal(), Some(libc::SIGKILL));
}

#[test]
fn a_child_that_exited_before_the_call_is_already_exited() {
    let source: DarwinProcessSource = DarwinProcessSource::new();
    let mut child: ChildGuard = spawn_child();
    let planned: ProcessIdentity = identity(source, child.pid());
    // The test ends its own child and does not collect it before the
    // executor runs. A child that was not collected keeps its PID, so the
    // PID cannot belong to another process while the executor has it. A
    // collected child releases the PID, and only the check under test
    // would then prevent a signal to a process of another owner.
    child.0.kill().unwrap();
    let limit: Instant = Instant::now() + Duration::from_secs(10);
    while source
        .process_info(child.pid())
        .is_ok_and(|info| !info.zombie)
    {
        assert!(Instant::now() < limit, "the child did not exit");
        std::thread::sleep(Duration::from_millis(10));
    }
    let executor: Executor = executor();
    let receipt = receipt();
    for (class, escalation) in [
        (ActionClass::RequestApplicationExit, Escalation::None),
        (
            ActionClass::ForceApplicationExit,
            Escalation::ImmediateForce,
        ),
    ] {
        let envelope = envelope(source, class, escalation, &planned);
        let run: StepRun = executor.begin(input(&envelope, &receipt)).unwrap();
        let StepRun::Finished(report) = run else {
            panic!("a call was issued for a process that exited");
        };
        let result: &TargetResult = &report.members[0].result;
        assert_eq!(result.effect, TargetEffect::AlreadyExited);
        assert_eq!(result.dispatch, DispatchState::NotSubmitted);
        assert_eq!(result.evidence.native, NativeResult::NotCalled);
        assert_eq!(report.submitted_at, None);
    }
    assert_eq!(child.collect().signal(), Some(libc::SIGKILL));
}
