//! Tests of the checks, the supervision, and the measurement of the owner
//! executor. Each test writes its scripts and its scope in a temporary
//! directory that it made; no test runs a real producer tool.

use std::fs;
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use svalnir_core::digest::ContentDigest;
use svalnir_core::process::Uid;
use svalnir_core::quantity::EntryCount;
use tempfile::TempDir;

use super::measure::{ScopeLimits, measure_scope};
use super::model::code;
use super::supervise::{self, CommandSpec, Ending, Supervision};
use super::verify::{ExecutableProblem, examine_executable};
use crate::executor::fs::Stop;
use crate::scan::{CancellationToken, WallScanClock};

fn user() -> Uid {
    // SAFETY: `geteuid` has no argument, cannot fail, and changes no state.
    Uid::new(unsafe { libc::geteuid() })
}

/// A temporary directory with no symbolic link in its path.
fn base() -> (TempDir, PathBuf) {
    let temp: TempDir = tempfile::tempdir().unwrap();
    let path: PathBuf = fs::canonicalize(temp.path()).unwrap();
    (temp, path)
}

fn script(directory: &Path, name: &str, body: &str) -> PathBuf {
    crate::rules::fixture::write_owner_script(directory, name, body).unwrap()
}

fn spec(executable: &Path, home: &Path, arguments: &[&str]) -> CommandSpec {
    CommandSpec {
        executable: executable.to_path_buf(),
        arguments: arguments
            .iter()
            .map(|argument| (*argument).to_owned())
            .collect(),
        environment: vec![
            ("HOME".to_owned(), home.display().to_string()),
            ("PATH".to_owned(), "/usr/bin:/bin".to_owned()),
        ],
        working_directory: home.to_path_buf(),
    }
}

fn limits(deadline: Duration) -> Supervision {
    Supervision {
        deadline,
        stop_poll: Duration::from_millis(20),
        stop_grace: Duration::from_millis(500),
    }
}

fn never() -> Option<Stop> {
    None
}

/// Whether a process with the ID in the file `path` runs.
fn runs(path: &Path) -> bool {
    let pid: libc::pid_t = fs::read_to_string(path).unwrap().trim().parse().unwrap();
    // SAFETY: `kill` takes no pointer; signal 0 only examines the process.
    unsafe { libc::kill(pid, 0) == 0 }
}

#[test]
fn each_code_is_a_valid_error_code() {
    for text in code::ALL {
        assert!(svalnir_core::action::ErrorCode::new(text).is_ok(), "{text}");
    }
}

#[test]
fn an_executable_binds_its_identity_and_its_digest() {
    let (_temp, base) = base();
    let path: PathBuf = script(&base, "tool", "exit 0");
    let binding = examine_executable(&path, user(), 1 << 20).unwrap();
    assert_eq!(
        binding.digest,
        ContentDigest::of_bytes(&fs::read(&path).unwrap())
    );
    assert_eq!(binding.owner, user());
    assert_eq!(binding.mode, 0o755);
    assert!(binding.signature.is_none());
    // A file larger than the limit has no digest.
    assert_eq!(
        examine_executable(&path, user(), 4),
        Err(ExecutableProblem::NotReadable)
    );
}

#[test]
fn an_executable_that_a_different_user_can_change_is_refused() {
    let (_temp, base) = base();
    let path: PathBuf = script(&base, "tool", "exit 0");
    assert_eq!(
        examine_executable(Path::new("tool"), user(), 1 << 20),
        Err(ExecutableProblem::NotFound)
    );
    assert_eq!(
        examine_executable(&base.join("absent"), user(), 1 << 20),
        Err(ExecutableProblem::NotFound)
    );
    let link: PathBuf = base.join("link");
    symlink(&path, &link).unwrap();
    assert_eq!(
        examine_executable(&link, user(), 1 << 20),
        Err(ExecutableProblem::NotExecutable)
    );
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        examine_executable(&path, user(), 1 << 20),
        Err(ExecutableProblem::NotExecutable)
    );
    fs::set_permissions(&path, fs::Permissions::from_mode(0o775)).unwrap();
    assert_eq!(
        examine_executable(&path, user(), 1 << 20),
        Err(ExecutableProblem::NotTrusted)
    );
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(&base, fs::Permissions::from_mode(0o777)).unwrap();
    assert_eq!(
        examine_executable(&path, user(), 1 << 20),
        Err(ExecutableProblem::NotTrusted)
    );
    fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
    // A principal that is not the owner.
    assert_eq!(
        examine_executable(&path, Uid::new(user().get().wrapping_add(1)), 1 << 20),
        Err(ExecutableProblem::NotTrusted)
    );
}

#[test]
fn the_command_has_only_the_environment_and_the_arguments_of_the_plan() {
    let (_temp, base) = base();
    let path: PathBuf = script(
        &base,
        "tool",
        "printf '%s|' \"$@\"\nprintenv CARGO_PKG_NAME || echo absent\npwd",
    );
    let supervised = supervise::run(
        &spec(&path, &base, &["prune", "a b", "$HOME"]),
        &limits(Duration::from_secs(10)),
        &never,
    )
    .unwrap();
    let Ending::Exited {
        status,
        children_remained,
    } = supervised.ending
    else {
        panic!("the command did not exit: {:?}", supervised.ending);
    };
    assert!(status.success());
    assert!(!children_remained);
    let text: String = String::from_utf8(supervised.tail).unwrap();
    // No shell expands an argument, and no variable of the test process
    // reaches the command.
    assert!(text.starts_with("prune|a b|$HOME|"), "{text}");
    assert!(text.contains("absent"), "{text}");
    assert!(text.contains(&base.display().to_string()), "{text}");
}

#[test]
fn the_tail_is_bounded_and_redacted() {
    let (_temp, base) = base();
    let path: PathBuf = script(
        &base,
        "tool",
        "i=0\nwhile [ $i -lt 2000 ]; do echo \"line $i of $HOME\"; i=$((i+1)); done\n\
         printf 'bell\\007end\\n' >&2\nexit 4",
    );
    let supervised = supervise::run(
        &spec(&path, &base, &[]),
        &limits(Duration::from_secs(20)),
        &never,
    )
    .unwrap();
    let Ending::Exited { status, .. } = supervised.ending else {
        panic!("the command did not exit");
    };
    assert_eq!(supervise::status_code(status), 4);
    assert!(supervised.tail.len() <= 4097);
    let text: String = supervise::redacted(&supervised.tail, &base.display().to_string());
    assert!(text.contains("line 1999 of ~"), "{text}");
    assert!(!text.contains(&base.display().to_string()));
    assert!(!text.chars().any(char::is_control));
    assert!(text.contains("bell end"), "{text}");
}

#[test]
fn a_command_past_its_deadline_has_its_whole_group_stopped() {
    let (_temp, base) = base();
    let child_pid: PathBuf = base.join("child.pid");
    let path: PathBuf = script(
        &base,
        "tool",
        &format!("sleep 30 &\necho $! > '{}'\nsleep 30", child_pid.display()),
    );
    let started: Instant = Instant::now();
    let supervised = supervise::run(
        &spec(&path, &base, &[]),
        &limits(Duration::from_millis(500)),
        &never,
    )
    .unwrap();
    assert_eq!(supervised.ending, Ending::Deadline);
    assert!(started.elapsed() < Duration::from_secs(10));
    // The child of the command was in its group, so the stop reached it.
    let until: Instant = Instant::now() + Duration::from_secs(5);
    while runs(&child_pid) && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(!runs(&child_pid));
}

#[test]
fn a_stop_condition_stops_the_group_of_a_running_command() {
    let (_temp, base) = base();
    let path: PathBuf = script(&base, "tool", "sleep 30");
    let checks = std::cell::Cell::new(0_u32);
    let signal = || {
        checks.set(checks.get() + 1);
        (checks.get() > 2).then_some(Stop::Canceled)
    };
    let started: Instant = Instant::now();
    let supervised = supervise::run(
        &spec(&path, &base, &[]),
        &limits(Duration::from_secs(30)),
        &signal,
    )
    .unwrap();
    assert_eq!(supervised.ending, Ending::Stopped(Stop::Canceled));
    assert!(started.elapsed() < Duration::from_secs(10));
}

#[test]
fn a_child_that_stays_after_the_exit_is_seen_and_stopped() {
    let (_temp, base) = base();
    let child_pid: PathBuf = base.join("child.pid");
    let path: PathBuf = script(
        &base,
        "tool",
        &format!("sleep 30 &\necho $! > '{}'\nexit 0", child_pid.display()),
    );
    let supervised = supervise::run(
        &spec(&path, &base, &[]),
        &limits(Duration::from_secs(10)),
        &never,
    )
    .unwrap();
    assert!(matches!(
        supervised.ending,
        Ending::Exited {
            children_remained: true,
            ..
        }
    ));
    let until: Instant = Instant::now() + Duration::from_secs(5);
    while runs(&child_pid) && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(!runs(&child_pid));
}

#[test]
fn a_command_that_does_not_start_is_an_error() {
    let (_temp, base) = base();
    let result = supervise::run(
        &spec(&base.join("absent"), &base, &[]),
        &limits(Duration::from_secs(1)),
        &never,
    );
    assert!(result.is_err());
}

#[test]
fn a_scope_measurement_is_complete_within_its_bounds() {
    let (_temp, base) = base();
    let scope: PathBuf = base.join("scope");
    fs::create_dir_all(scope.join("a/b")).unwrap();
    fs::write(scope.join("a/b/f"), vec![1_u8; 10_000]).unwrap();
    let measurement = measure_scope(
        &scope,
        ScopeLimits::default(),
        &CancellationToken::new(),
        &WallScanClock,
    )
    .unwrap();
    assert!(measurement.complete);
    assert_eq!(measurement.entries, EntryCount::new(3));
    assert!(measurement.measured_at.is_some());
    let small = ScopeLimits {
        max_depth: 256,
        max_entries: EntryCount::new(2),
    };
    let partial = measure_scope(&scope, small, &CancellationToken::new(), &WallScanClock).unwrap();
    assert!(!partial.complete);
    assert!(
        measure_scope(
            &scope.join("a/b/f"),
            ScopeLimits::default(),
            &CancellationToken::new(),
            &WallScanClock
        )
        .is_none()
    );
}
