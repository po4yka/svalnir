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

use svalnir_agent::journal::{
    AgentRecord, CoordinatorLock, CoordinatorRole, JournalOptions, OperationJournal,
};
use svalnir_agent::platform::account::TEST_ACCOUNT_HOME_VARIABLE;
use svalnir_agent::runtime::start_failure::{StartFailure, StartFailureReason, read_start_failure};
use svalnir_agent::runtime::{AgentStatus, RunState};

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

/// The agent with `HOME` and the home directory of its account record at
/// the temporary home directory. The test build of the binary reads the
/// account record from `SVALNIR_TEST_ACCOUNT_HOME`.
fn agent(directories: &Directories) -> Command {
    let mut command: Command = Command::new(env!("CARGO_BIN_EXE_svalnir-agent"));
    command
        .arg("--foreground")
        .arg("--state-dir")
        .arg(&directories.state)
        .env("HOME", &directories.home)
        .env(TEST_ACCOUNT_HOME_VARIABLE, &directories.home)
        // A variable of the shell must not give a test a real dialog.
        .env_remove(svalnir_agent::notify::TEST_DIALOG_VARIABLE)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

/// A second connection to the journal of an agent that made it.
fn open_journal(state: &Path) -> OperationJournal {
    OperationJournal::open(&state.join("operations.sqlite"), &JournalOptions::default()).unwrap()
}

/// Waits until the agent wrote its journal and then the status `running`.
///
/// The driver thread writes that status after its first sample. The main
/// thread makes the signal sources of its run loop when it started the
/// driver thread, so they exist when the status is `running`. A signal
/// before them ends the agent with the default action. The wait has no
/// fixed time, so a loaded host only makes it longer.
fn wait_until_running(state: &Path, child: &mut Child) {
    let limit: Instant = Instant::now() + Duration::from_secs(30);
    let mut wait = |what: &str| {
        assert!(child.try_wait().unwrap().is_none(), "the agent ended");
        assert!(Instant::now() < limit, "{what}");
        std::thread::sleep(Duration::from_millis(20));
    };
    // The test does not make the journal: the agent does.
    while !state.join("operations.sqlite").exists() {
        wait("the agent made no journal");
    }
    let journal: OperationJournal = open_journal(state);
    loop {
        // A record that is not written yet, or a read that the writer of
        // the agent blocks for a moment, is read again.
        let running: bool = journal
            .agent_record::<AgentStatus>(AgentRecord::Status)
            .ok()
            .flatten()
            .is_some_and(|stored| stored.record.state == RunState::Running);
        if running {
            break;
        }
        wait("the agent did not get to the state `running`");
    }
    // The registration of a signal source completes in one turn of the
    // main run loop.
    std::thread::sleep(Duration::from_millis(200));
}

fn stops_on(signal: libc::c_int) {
    let directories = Directories::new();
    let mut guard = Agent(agent(&directories).spawn().unwrap());
    let child: &mut Child = &mut guard.0;
    wait_until_running(&directories.state, child);
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
    wait_until_running(&directories.state, first);
    // The records that a second agent must not change: the registration
    // of the coordinator, the agent of the status record, and the
    // lifecycle record.
    let journal: OperationJournal = open_journal(&directories.state);
    let records = |journal: &OperationJournal| {
        let status = journal
            .agent_record::<AgentStatus>(AgentRecord::Status)
            .unwrap()
            .unwrap()
            .record;
        let lifecycle = journal
            .agent_record::<serde_json::Value>(AgentRecord::Lifecycle)
            .unwrap()
            .map(|stored| (stored.revision, stored.record));
        (
            journal.coordination().unwrap(),
            status.executor_epoch,
            status.process_id,
            status.started_at,
            lifecycle,
            journal.unsettled_operation_count().unwrap(),
        )
    };
    let before = records(&journal);
    assert_eq!(before.2, first.id());
    // The second process finds the coordinator lock of an agent and ends
    // with success, so a service manager does not start it again.
    let mut second = Agent(agent(&directories).spawn().unwrap());
    let status: ExitStatus = wait_with_limit(&mut second.0, Duration::from_secs(20))
        .expect("the second agent did not end");
    assert!(status.success(), "{status:?}");
    assert!(first.try_wait().unwrap().is_none());
    // It changed nothing: the first agent is still the registered
    // coordinator and the agent of the status record, and the home
    // directory has no entry.
    assert_eq!(records(&journal), before);
    assert_eq!(std::fs::read_dir(&directories.home).unwrap().count(), 0);
    drop(journal);

    let pid: libc::pid_t = libc::pid_t::try_from(first.id()).unwrap();
    // SAFETY: `pid` is the child that this test started and did not wait
    // for. The call sends one signal.
    assert_eq!(unsafe { libc::kill(pid, libc::SIGTERM) }, 0);
    let status: ExitStatus = wait_with_limit(first, Duration::from_secs(20))
        .expect("the agent did not stop after the signal");
    assert!(status.success(), "{status:?}");
}

#[test]
fn an_agent_that_finds_the_lock_of_a_client_ends_with_a_failure_and_starts_later() {
    use std::os::unix::fs::DirBuilderExt as _;

    let directories = Directories::new();
    // The state directory of a client: for this user only.
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&directories.state)
        .unwrap();
    let journal_path: PathBuf = directories.state.join("operations.sqlite");
    // A client holds the coordinator lock as a transient coordinator.
    let client = CoordinatorLock::try_acquire(&journal_path, CoordinatorRole::Client).unwrap();
    let mut refused = Agent(agent(&directories).spawn().unwrap());
    let status: ExitStatus =
        wait_with_limit(&mut refused.0, Duration::from_secs(20)).expect("the agent did not end");
    // The failure status makes a service manager start the agent again:
    // the client releases the lock after its request.
    assert_eq!(status.code(), Some(1), "{status:?}");
    // The refused agent registered no coordinator and wrote no record of
    // an agent, and the home directory has no entry.
    {
        let journal: OperationJournal = open_journal(&directories.state);
        assert_eq!(journal.coordination().unwrap(), None);
        for record in [AgentRecord::Status, AgentRecord::Lifecycle] {
            assert_eq!(journal.agent_record_revision(record).unwrap(), 0);
        }
    }
    assert_eq!(std::fs::read_dir(&directories.home).unwrap().count(), 0);
    drop(client);

    let mut guard = Agent(agent(&directories).spawn().unwrap());
    let child: &mut Child = &mut guard.0;
    wait_until_running(&directories.state, child);
    let pid: libc::pid_t = libc::pid_t::try_from(child.id()).unwrap();
    // SAFETY: `pid` is the child that this test started and did not wait
    // for. The call sends one signal.
    assert_eq!(unsafe { libc::kill(pid, libc::SIGTERM) }, 0);
    let status: ExitStatus = wait_with_limit(child, Duration::from_secs(20))
        .expect("the agent did not stop after the signal");
    assert!(status.success(), "{status:?}");
}

/// Runs an agent that does not start, and returns its exit status and the
/// lines of its standard error stream.
fn refused_start(mut command: Command) -> (ExitStatus, Vec<String>) {
    let mut refused = Agent(command.stderr(Stdio::piped()).spawn().unwrap());
    let status: ExitStatus =
        wait_with_limit(&mut refused.0, Duration::from_secs(20)).expect("the agent did not end");
    let mut stderr: String = String::new();
    std::io::Read::read_to_string(&mut refused.0.stderr.take().unwrap(), &mut stderr).unwrap();
    (status, stderr.lines().map(str::to_owned).collect())
}

/// The line of the start failure on the standard error stream: one line
/// with the reason code.
fn failure_line(lines: &[String], code: &str) {
    let failures: Vec<&String> = lines
        .iter()
        .filter(|line| line.contains("the agent did not start"))
        .collect();
    assert_eq!(failures.len(), 1, "{lines:?}");
    assert!(failures[0].contains(code), "{lines:?}");
    // The stream is not a terminal: a log file gets no escape sequence.
    assert!(
        lines.iter().all(|line| !line.contains('\u{1b}')),
        "{lines:?}"
    );
}

#[test]
fn an_agent_whose_home_is_not_that_of_its_account_record_does_not_start() {
    let directories = Directories::new();
    // A second temporary directory as the home directory of the account
    // record: `HOME` names a different directory.
    let account: PathBuf = directories.home.with_file_name("account");
    std::fs::create_dir(&account).unwrap();
    let mut command: Command = agent(&directories);
    command.env(TEST_ACCOUNT_HOME_VARIABLE, &account);
    let (status, lines) = refused_start(command);
    // A permanent start error: the status that `launchd` does not restart.
    assert_eq!(status.code(), Some(0), "{status:?}");
    failure_line(&lines, "home_mismatch");
    let record: StartFailure = read_start_failure(&directories.state).unwrap().unwrap();
    assert_eq!(record.reason, StartFailureReason::HomeMismatch);
    // The agent made no journal and wrote nothing in either directory.
    assert!(!directories.state.join("operations.sqlite").exists());
    assert_eq!(std::fs::read_dir(&directories.home).unwrap().count(), 0);
    assert_eq!(std::fs::read_dir(&account).unwrap().count(), 0);
}

#[test]
fn a_permanent_start_error_writes_one_record_that_a_later_start_removes() {
    let directories = Directories::new();
    let config: PathBuf = directories.home.with_file_name("config.toml");
    std::fs::write(&config, "schema_version = 99\n").unwrap();
    let mut command: Command = agent(&directories);
    command.arg("--config").arg(&config);
    let (status, lines) = refused_start(command);
    assert_eq!(status.code(), Some(0), "{status:?}");
    failure_line(&lines, "configuration_invalid");
    let first: StartFailure = read_start_failure(&directories.state).unwrap().unwrap();
    assert_eq!(first.reason, StartFailureReason::ConfigurationInvalid);
    assert_eq!(first.agent_version, env!("CARGO_PKG_VERSION"));
    assert!(first.failed_at.is_some());
    assert!(!directories.state.join("operations.sqlite").exists());

    // A second permanent error replaces the record: the state directory
    // has one record.
    let mut command: Command = agent(&directories);
    command
        .arg("--config")
        .arg(directories.home.with_file_name("absent.toml"));
    let (status, lines) = refused_start(command);
    assert_eq!(status.code(), Some(0), "{status:?}");
    failure_line(&lines, "configuration_not_readable");
    let second: StartFailure = read_start_failure(&directories.state).unwrap().unwrap();
    assert_eq!(second.reason, StartFailureReason::ConfigurationNotReadable);
    let records: usize = std::fs::read_dir(&directories.state)
        .unwrap()
        .filter(|entry| {
            entry
                .as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("agent-start-failure")
        })
        .count();
    assert_eq!(records, 1);

    // A successful start removes the record.
    let mut guard = Agent(agent(&directories).spawn().unwrap());
    let child: &mut Child = &mut guard.0;
    wait_until_running(&directories.state, child);
    assert!(read_start_failure(&directories.state).unwrap().is_none());
    let pid: libc::pid_t = libc::pid_t::try_from(child.id()).unwrap();
    // SAFETY: `pid` is the child that this test started and did not wait
    // for. The call sends one signal.
    assert_eq!(unsafe { libc::kill(pid, libc::SIGTERM) }, 0);
    let status: ExitStatus = wait_with_limit(child, Duration::from_secs(20))
        .expect("the agent did not stop after the signal");
    assert!(status.success(), "{status:?}");
}

#[test]
fn a_refused_state_directory_is_a_permanent_start_error_with_no_record() {
    use std::os::unix::fs::DirBuilderExt as _;

    let directories = Directories::new();
    // Other users can read the directory.
    std::fs::DirBuilder::new()
        .mode(0o755)
        .create(&directories.state)
        .unwrap();
    let (status, lines) = refused_start(agent(&directories));
    assert_eq!(status.code(), Some(0), "{status:?}");
    failure_line(&lines, "state_directory_refused");
    // The agent wrote nothing in the refused directory.
    assert_eq!(std::fs::read_dir(&directories.state).unwrap().count(), 0);
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
            .env(TEST_ACCOUNT_HOME_VARIABLE, &directories.home)
            .env_remove(svalnir_agent::notify::TEST_DIALOG_VARIABLE)
            .stdin(Stdio::null())
            .output()
            .unwrap()
    };
    // No argument: the agent does not select a state directory itself.
    let output: Output = run(&[]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("--state-dir"));
    // The foreground flag is explicit. The state directory is a path
    // below the temporary directory of the test, which does not exist.
    let state: &str = directories.state.to_str().unwrap();
    let output: Output = run(&["--state-dir", state]);
    assert_eq!(output.status.code(), Some(2));
    assert!(!directories.state.exists());
    // An argument that would make a guard active does not exist. The
    // other arguments are complete, so the refusal is for this one.
    let output: Output = run(&["--foreground", "--state-dir", state, "--enable-guards"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("an argument is not known"));
    assert!(!directories.state.exists());
    let output: Output = run(&["--version"]);
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).starts_with("svalnir-agent "));
}
