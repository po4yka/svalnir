//! The `svalnir-agent` binary runs until a stop signal.
//!
//! Each test starts the binary as a disposable child process and signals
//! only that child. The child gets a temporary state directory and a
//! temporary home directory, so it does not read or write the state
//! directory, the home directory, or the Trash of the user. Its journal
//! has no authority record: the agent only observes, and no guard is
//! active.

#![cfg(target_os = "macos")]
#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "a helper of a test fails with the message of the unwrap"
)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::time::{Duration, Instant};

/// An agent process that is killed and collected when the value is
/// dropped, also when the test fails.
struct Agent(Child);

impl Drop for Agent {
    fn drop(&mut self) {
        // `Child::kill` addresses only the child of this value. A child
        // that ended already gives no error.
        if let Err(error) = self.0.kill() {
            eprintln!("the agent was not killed: {error}");
        }
        if let Err(error) = self.0.wait() {
            eprintln!("the agent was not collected: {error}");
        }
    }
}

/// Waits for the child to end. Kills the child after `limit`.
fn wait_with_limit(child: &mut Child, limit: Duration) -> Option<ExitStatus> {
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return Some(status);
        }
        if started.elapsed() > limit {
            child.kill().unwrap();
            child.wait().unwrap();
            return None;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The directories of one agent process, below one temporary directory.
struct Directories {
    _temp: tempfile::TempDir,
    state: PathBuf,
    home: PathBuf,
}

impl Directories {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        // The home directory of the agent has no symbolic link in its
        // path.
        let base: PathBuf = std::fs::canonicalize(temp.path()).unwrap();
        let home: PathBuf = base.join("home");
        std::fs::create_dir(&home).unwrap();
        Self {
            state: base.join("state"),
            home,
            _temp: temp,
        }
    }
}

fn agent(directories: &Directories) -> Command {
    let mut command: Command = Command::new(env!("CARGO_BIN_EXE_svalnir-agent"));
    command
        .arg("--foreground")
        .arg("--state-dir")
        .arg(&directories.state)
        .env("HOME", &directories.home)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

/// Waits until the agent wrote its journal: the start is then complete,
/// and the signal sources of the main run loop follow at once.
fn wait_for_journal(state: &Path, child: &mut Child) {
    let limit: Instant = Instant::now() + Duration::from_secs(20);
    while !state.join("operations.sqlite").exists() {
        assert!(child.try_wait().unwrap().is_none(), "the agent ended");
        assert!(Instant::now() < limit, "the agent made no journal");
        std::thread::sleep(Duration::from_millis(20));
    }
    // The signal sources of the main run loop follow the start. A signal
    // before them ends the agent with the default action.
    std::thread::sleep(Duration::from_millis(1_500));
}

fn stops_on(signal: libc::c_int) {
    let directories = Directories::new();
    let mut guard = Agent(agent(&directories).spawn().unwrap());
    let child: &mut Child = &mut guard.0;
    wait_for_journal(&directories.state, child);
    // The process is in its run loop: it does not end without a signal.
    assert!(child.try_wait().unwrap().is_none());

    let pid: libc::pid_t = libc::pid_t::try_from(child.id()).unwrap();
    // SAFETY: `pid` is the child that this test started and did not wait
    // for, so the PID is not reused. The call sends one signal.
    assert_eq!(unsafe { libc::kill(pid, signal) }, 0);
    let status: ExitStatus = wait_with_limit(child, Duration::from_secs(20))
        .expect("the agent did not stop after the signal");
    assert!(status.success(), "{status:?}");
    // The agent wrote only below its state directory.
    assert!(directories.state.join("operations.sqlite").exists());
    assert_eq!(std::fs::read_dir(&directories.home).unwrap().count(), 0);
}

#[test]
fn the_agent_runs_until_sigterm_and_ends_with_success() {
    stops_on(libc::SIGTERM);
}

#[test]
fn the_agent_runs_until_sigint_and_ends_with_success() {
    stops_on(libc::SIGINT);
}

#[test]
fn a_second_agent_on_the_same_state_directory_ends_and_changes_nothing() {
    let directories = Directories::new();
    let mut first_guard = Agent(agent(&directories).spawn().unwrap());
    let first: &mut Child = &mut first_guard.0;
    wait_for_journal(&directories.state, first);
    // The second process finds the coordinator lock and ends with
    // success, so a service manager does not start it again.
    let mut second = Agent(agent(&directories).spawn().unwrap());
    let status: ExitStatus = wait_with_limit(&mut second.0, Duration::from_secs(20))
        .expect("the second agent did not end");
    assert!(status.success(), "{status:?}");
    assert!(first.try_wait().unwrap().is_none());

    let pid: libc::pid_t = libc::pid_t::try_from(first.id()).unwrap();
    // SAFETY: `pid` is the child that this test started and did not wait
    // for. The call sends one signal.
    assert_eq!(unsafe { libc::kill(pid, libc::SIGTERM) }, 0);
    let status: ExitStatus = wait_with_limit(first, Duration::from_secs(20))
        .expect("the agent did not stop after the signal");
    assert!(status.success(), "{status:?}");
}

#[test]
fn the_agent_refuses_to_start_without_its_required_arguments() {
    // A temporary home directory, so that an agent that did start by a
    // defect has no access to the home directory of the user.
    let directories = Directories::new();
    let run = |arguments: &[&str]| -> Output {
        Command::new(env!("CARGO_BIN_EXE_svalnir-agent"))
            .args(arguments)
            .env("HOME", &directories.home)
            .stdin(Stdio::null())
            .output()
            .unwrap()
    };
    // No argument: the agent does not select a state directory itself.
    let output: Output = run(&[]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("--state-dir"));
    // The foreground flag is explicit.
    let output: Output = run(&["--state-dir", "/nonexistent/svalnir-test-state"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(!Path::new("/nonexistent/svalnir-test-state").exists());
    // An argument that would make a guard active does not exist.
    let output: Output = run(&["--foreground", "--enable-guards"]);
    assert_eq!(output.status.code(), Some(2));
    let output: Output = run(&["--version"]);
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).starts_with("svalnir-agent "));
}
