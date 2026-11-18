//! A stop signal of a client that executes an operation as a transient
//! coordinator.
//!
//! Each test starts the `svalnir` binary as a disposable child process,
//! with a temporary state directory and a temporary home directory, on a
//! plan whose target is a second child process that the test starts. The
//! test signals only these two children.

#![cfg(target_os = "macos")]
#![expect(
    clippy::unwrap_used,
    reason = "a helper of a test fails with the message of the unwrap"
)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;
use svalnir_agent::platform::account::TEST_ACCOUNT_HOME_VARIABLE;
use svalnir_agent::platform::process::{DarwinProcessSource, ProcessSource, generation_id};
use svalnir_core::process::Pid;

const CHILD_VARIABLE: &str = "SVALNIR_TEST_STOP_SIGNAL_CHILD";
const CHILD_TEST: &str = "child_entry";
const CHILD_LIFE: Duration = Duration::from_secs(60);

/// The body of the target process. Without the variable, which only the
/// tests of this file set, it does nothing.
#[test]
#[ignore = "the entry of a child process that the tests of this file start"]
fn child_entry() {
    if std::env::var_os(CHILD_VARIABLE).is_none() {
        return;
    }
    let parent: u32 = std::os::unix::process::parent_id();
    let end: Instant = Instant::now() + CHILD_LIFE;
    while Instant::now() < end && std::os::unix::process::parent_id() == parent {
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// A child process that is killed and collected when the value is
/// dropped, also when the test fails.
struct ChildGuard(Child);

impl ChildGuard {
    fn pid(&self) -> Pid {
        Pid::new(i32::try_from(self.0.id()).unwrap()).unwrap()
    }

    fn has_exited(&mut self) -> bool {
        self.0.try_wait().unwrap().is_some()
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        // `Child::kill` addresses only the child of this value.
        drop(self.0.kill());
        drop(self.0.wait());
    }
}

/// Starts the target: the test binary, which ignores `SIGTERM`, so that
/// only a force step ends it before its life ends.
fn spawn_target() -> ChildGuard {
    let program: PathBuf = std::env::current_exe().unwrap();
    let guard = ChildGuard(
        Command::new("/bin/sh")
            .args(["-c", "trap '' TERM; exec \"$0\" \"$@\""])
            .arg(&program)
            .args(["--ignored", "--exact", CHILD_TEST])
            .env(CHILD_VARIABLE, "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    // The target is the test binary, not the shell.
    let source = DarwinProcessSource::new();
    let limit: Instant = Instant::now() + Duration::from_secs(10);
    loop {
        let ready: bool = source
            .executable_path(guard.pid())
            .is_ok_and(|path| !path.as_bytes().starts_with(b"/bin/"));
        if ready {
            return guard;
        }
        assert!(Instant::now() < limit, "the target did not start");
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// The temporary directories of one test.
struct World {
    _temp: tempfile::TempDir,
    home: PathBuf,
    state: PathBuf,
}

impl World {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let base: PathBuf = temp.path().canonicalize().unwrap();
        let home: PathBuf = base.join("home");
        std::fs::create_dir(&home).unwrap();
        let world = Self {
            state: base.join("state"),
            home,
            _temp: temp,
        };
        let config: PathBuf = base.join("config.toml");
        std::fs::write(&config, "schema_version = 1\n").unwrap();
        let output = world.run(&[
            "config",
            "apply",
            "--config",
            config.to_str().unwrap(),
            "--expected-revision",
            "none",
        ]);
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        world
    }

    /// The `svalnir` command with the directories of this test.
    fn command(&self, arguments: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_svalnir"));
        command
            .args(arguments)
            .args(["--format", "json"])
            .env("HOME", &self.home)
            .env(TEST_ACCOUNT_HOME_VARIABLE, &self.home)
            .env("SVALNIR_STATE_DIR", &self.state)
            .stdin(Stdio::null());
        command
    }

    fn run(&self, arguments: &[&str]) -> Output {
        self.command(arguments).output().unwrap()
    }

    fn result(&self, arguments: &[&str]) -> Value {
        result_of(&self.run(arguments).stdout)
    }
}

fn result_of(stdout: &[u8]) -> Value {
    let envelope: Value = serde_json::from_slice(stdout).unwrap();
    assert!(envelope["error"].is_null(), "{envelope}");
    envelope["result"].clone()
}

/// Waits until the graceful request of the only operation was submitted,
/// and returns the operation.
fn submitted_operation(world: &World, client: &mut Child) -> String {
    let limit: Instant = Instant::now() + Duration::from_secs(20);
    loop {
        assert!(client.try_wait().unwrap().is_none(), "the client ended");
        let history: Value = world.result(&["history"]);
        if let Some(operation) = history["records"][0]["operation_id"].as_str() {
            let show: Value = world.result(&["operations", "show", "--operation", operation]);
            if show["operation"]["dispatch"] == "submitted" {
                return operation.to_owned();
            }
        }
        assert!(Instant::now() < limit, "the request was not submitted");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Starts `processes stop` with a force step after the grace period,
/// sends `signal` to that client after the graceful request, and checks
/// the stop.
fn stop_with(signal: libc::c_int, status: i32, wait: &str) {
    let world = World::new();
    let mut target: ChildGuard = spawn_target();
    let info = DarwinProcessSource::new()
        .process_info(target.pid())
        .unwrap();
    let target_id: String = generation_id(target.pid(), info.start_time)
        .unwrap()
        .to_string();
    let mut client: Child = world
        .command(&[
            "processes",
            "stop",
            "--target",
            &target_id,
            "--grace",
            "30s",
            "--force-after-timeout",
            "--yes",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let operation: String = submitted_operation(&world, &mut client);
    let pid: libc::pid_t = libc::pid_t::try_from(client.id()).unwrap();
    // SAFETY: `pid` is the client that this test started and has not
    // collected, so the process ID names that client.
    let sent: libc::c_int = unsafe { libc::kill(pid, signal) };
    assert_eq!(sent, 0, "the signal was not sent");
    let started: Instant = Instant::now();
    while client.try_wait().unwrap().is_none() {
        let late: bool = started.elapsed() > Duration::from_secs(20);
        if late {
            drop(client.kill());
        }
        assert!(!late, "the client did not stop in 20 s");
        std::thread::sleep(Duration::from_millis(20));
    }
    let output: Output = client.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(status), "{output:?}");
    let result: Value = result_of(&output.stdout);
    assert_eq!(result["wait"], wait, "{result}");
    assert_eq!(result["executor"], "transient_coordinator");
    assert_eq!(result["operation"]["state"], "Incomplete", "{result}");
    // No force step: the target, which ignores `SIGTERM`, stays.
    assert!(!target.has_exited());

    // The journal has the result, and the lock is free.
    let show: Value = world.result(&["operations", "show", "--operation", &operation]);
    assert_eq!(show["operation"]["state"], "Incomplete", "{show}");
    assert_eq!(show["operation"]["stop"]["durable_stop_fence"], true);
    let agent: Value = world.result(&["agent", "status"]);
    assert_eq!(agent["lock_holder"], "none", "{agent}");
    assert_lock_free(&world.state);
}

/// The lock file of the coordinator is not held: an exclusive lock with
/// no wait succeeds.
fn assert_lock_free(state: &Path) {
    use svalnir_agent::journal::{CoordinatorLock, CoordinatorRole};
    let lock =
        CoordinatorLock::try_acquire(&state.join("operations.sqlite"), CoordinatorRole::Client);
    assert!(lock.is_ok(), "the coordinator lock is held");
}

#[test]
fn sigterm_stops_a_transient_coordinator_and_records_the_result() {
    stop_with(libc::SIGTERM, 143, "stopped_by_sigterm");
}

#[test]
fn sighup_stops_a_transient_coordinator_and_records_the_result() {
    stop_with(libc::SIGHUP, 129, "stopped_by_sighup");
}
