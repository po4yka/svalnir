//! Application stops of a live child process.
//!
//! Each test starts its own child, and the coordinator signals only that
//! child: the planned identity is the PID and the start time of the
//! child, and the executor checks them before each call. A guard kills
//! and collects the child at the end of the test, also when the test
//! fails. The clocks are the clocks of the host.
//!
//! The child is this test binary, started again with [`child_entry`] as
//! its only test.

use std::os::unix::process::ExitStatusExt as _;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use svalnir_core::action::{Escalation, OperationState, PlanContent, TargetEffect};
use svalnir_core::id::{ApplicationInstanceId, BootId, ClockDomainId, ExecutorEpochId};
use svalnir_core::process::{
    AttributionMethod, ExecutableIdentity, Pid, ProcessAssociation, ProcessIdentity,
};
use svalnir_core::quantity::Nanoseconds;
use svalnir_core::time::MonotonicNanos;

use super::super::{Clock, Dependencies, OperationView, Phase, Start, SystemProbe, TimeReading};
use super::support::{Bench, admitted, evaluation_clock, stop_content, stored_request};
use crate::executor::process::{
    DarwinProcessControl, ExecutorConfig, ExecutorContext, ProcessExecutor, SourceClock,
};
use crate::platform::process::{DarwinProcessSource, ProcessSource, generation_id};

const CHILD_VARIABLE: &str = "SVALNIR_TEST_COORDINATOR_CHILD";
const CHILD_TEST: &str = "coordinator::tests::children::child_entry";
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

fn child_command(program: &std::path::Path) -> Command {
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
    let child: Child = child_command(std::path::Path::new("/bin/sh"))
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
fn identity(process: Pid) -> ProcessIdentity {
    let source = DarwinProcessSource::new();
    let info = source.process_info(process).unwrap();
    let path = source.executable_path(process).unwrap();
    let file = source.file_evidence(&path).ok();
    ProcessIdentity {
        generation_id: generation_id(process, info.start_time).unwrap(),
        pid: process,
        start_time: info.start_time,
        uid: info.effective_uid,
        boot_id: BootId::new("boot_1").unwrap(),
        executable: Some(ExecutableIdentity {
            path,
            file,
            code_signature: None,
        }),
        association: ProcessAssociation::ManagedJob {
            instance_id: ApplicationInstanceId::new("app_1").unwrap(),
            label: "com.example.job".to_owned(),
            attribution: AttributionMethod::LaunchdJob,
        },
    }
}

/// The clocks of the host, in the clock domain of the test plans.
#[derive(Debug)]
struct HostClock(DarwinProcessSource);

impl Clock for HostClock {
    fn now(&self) -> Option<TimeReading> {
        let now: MonotonicNanos = self.0.monotonic_now().ok()?;
        Some(TimeReading {
            clock: evaluation_clock(now.get()),
            wall: ProcessSource::wall_now(&self.0).ok()?,
        })
    }
}

/// Applies a manual stop plan for a live child and runs it to its end.
fn stop_child(child: &ChildGuard, escalation: Escalation) -> OperationView {
    let mut bench = Bench::new();
    let source = DarwinProcessSource::new();
    let now: u64 = source.monotonic_now().unwrap().get();
    let mut content: PlanContent =
        stop_content("plan_1", vec![identity(child.pid())], escalation, now);
    if content.limits.grace.is_some() {
        content.limits.grace = Some(Nanoseconds::new(300_000_000));
    }
    let plan = svalnir_core::action::Plan::seal(content).unwrap();
    bench.store(&plan);
    let started = bench.start_with(|dependencies: &mut Dependencies, config| {
        dependencies.clock = Box::new(HostClock(DarwinProcessSource::new()));
        dependencies.application = Box::new(ProcessExecutor::new(
            DarwinProcessSource::new(),
            DarwinProcessControl::new(),
            SourceClock(DarwinProcessSource::new()),
            ExecutorContext {
                boot_id: BootId::new("boot_1").unwrap(),
                clock_domain: ClockDomainId::new("clock_main").unwrap(),
                // The first lifetime of a bench.
                executor_epoch: ExecutorEpochId::new("epoch_1").unwrap(),
            },
            ExecutorConfig::default(),
        ));
        dependencies.probe = Box::new(SystemProbe::new(
            dependencies.roots.clone(),
            DarwinProcessSource::new(),
        ));
        config.poll_interval = Nanoseconds::new(20_000_000);
    });
    let Start::Coordinating(mut coordinator) = started else {
        panic!("a different coordinator holds the lock");
    };
    let operation_id = admitted(&mut coordinator, stored_request(&plan));
    let limit: Instant = Instant::now() + Duration::from_secs(30);
    loop {
        let view: OperationView = coordinator.operation(&operation_id).unwrap().unwrap();
        if view.phase == Phase::Finished {
            return view;
        }
        assert!(Instant::now() < limit, "the operation did not finish");
        if !coordinator.step().worked {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

#[test]
fn a_live_child_exits_at_the_graceful_request() {
    let mut child = spawn_child(false);
    let view = stop_child(&child, Escalation::None);
    assert_eq!(view.operation.state(), &OperationState::Completed);
    assert_eq!(
        view.operation.steps()[0].results()[0].effect,
        TargetEffect::ExitVerified
    );
    let status = child.0.wait().unwrap();
    assert_eq!(status.signal(), Some(libc::SIGTERM));
}

#[test]
fn a_live_child_that_ignores_the_request_is_forced_after_the_grace_period() {
    let mut child = spawn_child(true);
    let view = stop_child(&child, Escalation::ForceAfterGrace);
    assert_eq!(view.operation.state(), &OperationState::Completed);
    let steps = view.operation.steps();
    assert_eq!(steps[0].results()[0].effect, TargetEffect::StillRunning);
    assert_eq!(steps[1].results()[0].effect, TargetEffect::ExitVerified);
    let status = child.0.wait().unwrap();
    assert_eq!(status.signal(), Some(libc::SIGKILL));
}
