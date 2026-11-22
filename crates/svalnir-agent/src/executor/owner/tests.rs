//! Tests of the checks, the native start, the supervision, the redaction,
//! and the measurement of the owner executor. Each test writes its scripts
//! and its scope in a temporary directory that it made, and signals only
//! the processes that it started; no test runs a real producer tool.

use std::ffi::CString;
use std::fs;
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use svalnir_core::digest::ContentDigest;
use svalnir_core::process::Uid;
use svalnir_core::quantity::EntryCount;
use tempfile::TempDir;

use super::executor::process_lives;
use super::measure::{ScopeLimits, measure_scope};
use super::model::code;
use super::native::{self, Responsibility, ResponsibilitySymbols};
use super::supervise::{self, Command, Ending, StopCell, Supervision};
use super::verify::{ExecutableKind, ExecutableProblem, examine_executable, examine_program};
use crate::executor::fs::Stop;
use crate::journal::OwnerProcess;
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

fn responsibility() -> Responsibility {
    Responsibility::resolve(&ResponsibilitySymbols::default()).unwrap()
}

fn c(text: &str) -> CString {
    CString::new(text).unwrap()
}

/// Starts `/bin/sh SCRIPT ARGUMENTS` suspended, with `HOME` and a fixed
/// `PATH` only, in `home`.
fn start(script: &Path, home: &Path, arguments: &[&str]) -> Command {
    let mut argv: Vec<CString> = vec![c("/bin/sh"), c(script.to_str().unwrap())];
    argv.extend(arguments.iter().map(|argument| c(argument)));
    let environment: Vec<CString> = vec![
        c(&format!("HOME={}", home.display())),
        c("PATH=/usr/bin:/bin"),
    ];
    let Ok(started) = native::spawn_suspended(
        responsibility(),
        &c("/bin/sh"),
        &argv,
        &environment,
        &c(home.to_str().unwrap()),
    ) else {
        panic!("the start failed");
    };
    Command {
        pid: started.pid,
        started: native::start_time(started.pid).unwrap(),
        stdout: started.stdout,
        stderr: started.stderr,
    }
}

fn limits(deadline: Duration) -> Supervision {
    Supervision {
        deadline,
        stop_poll: Duration::from_millis(20),
        stop_grace: Duration::from_millis(500),
    }
}

fn no_stop() -> StopCell {
    Mutex::new(None)
}

/// Whether the process with the ID in the file `path` runs.
fn runs(path: &Path) -> bool {
    let pid: libc::pid_t = fs::read_to_string(path).unwrap().trim().parse().unwrap();
    // SAFETY: `kill` takes no pointer; signal 0 only examines the process.
    unsafe { libc::kill(pid, 0) == 0 }
}

/// Waits at most 5 seconds until the process of `path` does not run.
fn gone(path: &Path) -> bool {
    let until: Instant = Instant::now() + Duration::from_secs(5);
    while runs(path) && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(20));
    }
    !runs(path)
}

#[test]
fn each_code_is_a_valid_error_code() {
    for text in code::ALL {
        assert!(svalnir_core::action::ErrorCode::new(text).is_ok(), "{text}");
    }
}

#[test]
fn an_executable_binds_its_identity_its_times_and_its_digest() {
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
    // A change of the mode changes the change time and not the content.
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    let again = examine_executable(&path, user(), 1 << 20).unwrap();
    assert_eq!(again.digest, binding.digest);
    assert_ne!(again.changed_at, binding.changed_at);
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
    let link: PathBuf = base.join("link");
    symlink(&path, &link).unwrap();
    assert_eq!(
        examine_executable(&link, user(), 1 << 20),
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
    assert_eq!(
        examine_executable(&path, Uid::new(user().get().wrapping_add(1)), 1 << 20),
        Err(ExecutableProblem::NotTrusted)
    );
}

#[test]
fn a_script_binds_its_interpreter_from_the_declared_locations_only() {
    let (_temp, base) = base();
    let shell: PathBuf = fs::canonicalize("/bin/sh").unwrap();
    let interpreters: Vec<PathBuf> = vec![shell.clone()];
    assert_eq!(
        super::verify::executable_kind(&shell).unwrap(),
        ExecutableKind::MachO
    );
    let direct: PathBuf = script(&base, "direct", "exit 0");
    let (executable, interpreter) =
        examine_program(&direct, &interpreters, user(), 1 << 20).unwrap();
    let interpreter = interpreter.unwrap();
    assert_eq!(interpreter.executable.path.to_path_buf(), shell);
    assert_eq!(interpreter.arguments, Vec::<String>::new());
    assert_eq!(executable.path.to_path_buf(), direct);
    // `env` does not search `PATH`: the name is a declared location.
    let by_env: PathBuf = base.join("by_env");
    fs::write(&by_env, "#!/usr/bin/env sh\nexit 0\n").unwrap();
    fs::set_permissions(&by_env, fs::Permissions::from_mode(0o755)).unwrap();
    let (_, interpreter) = examine_program(&by_env, &interpreters, user(), 1 << 20).unwrap();
    assert_eq!(interpreter.unwrap().executable.path.to_path_buf(), shell);
    let undeclared: PathBuf = base.join("undeclared");
    fs::write(&undeclared, "#!/usr/bin/env perl\nexit 0\n").unwrap();
    fs::set_permissions(&undeclared, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        examine_program(&undeclared, &interpreters, user(), 1 << 20),
        Err(ExecutableProblem::InterpreterNotDeclared)
    );
    let option: PathBuf = base.join("option");
    fs::write(&option, "#!/usr/bin/env -S sh -e\nexit 0\n").unwrap();
    fs::set_permissions(&option, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        examine_program(&option, &interpreters, user(), 1 << 20),
        Err(ExecutableProblem::NotExecutable)
    );
    let text: PathBuf = base.join("text");
    fs::write(&text, "no line\n").unwrap();
    fs::set_permissions(&text, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        examine_program(&text, &interpreters, user(), 1 << 20),
        Err(ExecutableProblem::NotExecutable)
    );
}

#[test]
fn the_responsibility_functions_resolve_and_a_missing_one_refuses() {
    assert!(Responsibility::resolve(&ResponsibilitySymbols::default()).is_some());
    let missing = ResponsibilitySymbols {
        disclaim: c"svalnir_test_no_such_function",
        ..ResponsibilitySymbols::default()
    };
    assert!(Responsibility::resolve(&missing).is_none());
}

#[test]
fn a_suspended_command_is_its_own_responsible_process_with_its_main_text() {
    let (_temp, base) = base();
    let path: PathBuf = script(&base, "tool", "exit 0");
    let command: Command = start(&path, &base, &[]);
    // The disclaim makes the command its own responsible process.
    assert_eq!(
        responsibility().responsible_for(command.pid),
        Some(command.pid)
    );
    let shell = examine_executable(&fs::canonicalize("/bin/sh").unwrap(), user(), 1 << 22);
    // The shell of the system can be root-owned or not readable for the
    // digest; its object is the comparison here.
    let object = shell.map_or_else(
        |_| super::verify::object_of(&fs::metadata("/bin/sh").unwrap()).unwrap(),
        |shell| shell.object,
    );
    assert!(native::main_text_is(command.pid, &object));
    supervise::kill_suspended(command.pid);
}

#[test]
fn the_command_has_only_the_environment_and_the_arguments_of_the_plan() {
    let (_temp, base) = base();
    let path: PathBuf = script(
        &base,
        "tool",
        "printf '%s|' \"$@\"\nprintenv CARGO_PKG_NAME || echo absent\npwd",
    );
    let command: Command = start(&path, &base, &["prune", "a b", "$HOME"]);
    let supervised = supervise::run(
        command,
        responsibility(),
        &limits(Duration::from_secs(10)),
        &no_stop(),
    );
    let Ending::Exited { status, clean } = supervised.ending else {
        panic!("the command did not exit: {:?}", supervised.ending);
    };
    assert!(supervise::is_success(status));
    assert!(clean);
    let text: String = String::from_utf8(supervised.stdout).unwrap();
    assert!(text.starts_with("prune|a b|$HOME|"), "{text}");
    assert!(text.contains("absent"), "{text}");
    assert!(text.contains(&base.display().to_string()), "{text}");
}

#[test]
fn a_command_past_its_deadline_has_its_whole_family_stopped() {
    let (_temp, base) = base();
    let child_pid: PathBuf = base.join("child.pid");
    let path: PathBuf = script(
        &base,
        "tool",
        &format!("sleep 30 &\necho $! > '{}'\nsleep 30", child_pid.display()),
    );
    let started: Instant = Instant::now();
    let supervised = supervise::run(
        start(&path, &base, &[]),
        responsibility(),
        &limits(Duration::from_millis(500)),
        &no_stop(),
    );
    assert_eq!(supervised.ending, Ending::Deadline);
    assert!(started.elapsed() < Duration::from_secs(10));
    assert!(gone(&child_pid));
}

#[test]
fn a_stop_request_stops_a_running_command() {
    let (_temp, base) = base();
    let path: PathBuf = script(&base, "tool", "sleep 30");
    let stop: StopCell = Mutex::new(Some(Stop::Canceled));
    let started: Instant = Instant::now();
    let supervised = supervise::run(
        start(&path, &base, &[]),
        responsibility(),
        &limits(Duration::from_secs(30)),
        &stop,
    );
    assert_eq!(supervised.ending, Ending::Stopped(Stop::Canceled));
    assert!(started.elapsed() < Duration::from_secs(10));
}

#[test]
fn a_child_in_the_group_after_the_exit_is_seen_and_stopped() {
    let (_temp, base) = base();
    let child_pid: PathBuf = base.join("child.pid");
    let path: PathBuf = script(
        &base,
        "tool",
        &format!("sleep 30 &\necho $! > '{}'\nexit 0", child_pid.display()),
    );
    let supervised = supervise::run(
        start(&path, &base, &[]),
        responsibility(),
        &limits(Duration::from_secs(10)),
        &no_stop(),
    );
    assert!(matches!(
        supervised.ending,
        Ending::Exited { clean: false, .. }
    ));
    assert!(gone(&child_pid));
}

#[test]
fn a_child_that_leaves_the_group_with_setsid_is_seen_by_its_responsibility() {
    let (_temp, base) = base();
    let child_pid: PathBuf = base.join("child.pid");
    // The child of `perl` starts a new session, so it is not in the process
    // group of the command; its responsible process is still the command.
    let path: PathBuf = script(
        &base,
        "tool",
        &format!(
            "/usr/bin/perl -e 'use POSIX; my $p = fork(); if ($p == 0) {{ POSIX::setsid(); \
             close(STDOUT); close(STDERR); sleep 30; exit 0 }} open(my $f, \">\", \"{}\"); \
             print $f $p; close($f);'\nsleep 1\nexit 0",
            child_pid.display()
        ),
    );
    let supervised = supervise::run(
        start(&path, &base, &[]),
        responsibility(),
        &limits(Duration::from_secs(20)),
        &no_stop(),
    );
    assert!(
        matches!(supervised.ending, Ending::Exited { clean: false, .. }),
        "{:?}",
        supervised.ending
    );
    assert!(gone(&child_pid));
}

#[test]
fn a_recorded_process_lives_until_its_whole_family_ends() {
    let (_temp, base) = base();
    let path: PathBuf = script(&base, "tool", "sleep 30");
    let command: Command = start(&path, &base, &[]);
    let process = OwnerProcess {
        pid: command.pid,
        started: command.started,
        group: command.pid,
    };
    assert!(process_lives(&process));
    supervise::kill_suspended(command.pid);
    assert!(!process_lives(&process));
}

#[test]
fn the_tail_is_bounded_cut_at_a_line_and_redacted() {
    let home: &str = "/Users/someone";
    let raw: String = format!(
        "partial line\nfetch https://user:secret@registry.example/pkg in {home}/cache\n\
         //registry.example/:_authToken=abc123 set\nAuthorization: Bearer xyz.987\n\
         url?token=t0k&x=1\nbell\u{7}end\n"
    );
    let text: String = supervise::redacted(raw.as_bytes(), home);
    assert!(!text.contains("secret"), "{text}");
    assert!(!text.contains("abc123"), "{text}");
    assert!(!text.contains("xyz.987"), "{text}");
    assert!(!text.contains("t0k"), "{text}");
    assert!(!text.contains(home), "{text}");
    assert!(text.contains("https://***@registry.example"), "{text}");
    assert!(text.contains("~/cache"), "{text}");
    assert!(!text.chars().any(char::is_control), "{text}");
    // A tail at the bound loses its first, cut line.
    let long: String = format!("{}\nlast line\n", "x".repeat(4000));
    let cut: String = supervise::redacted(&long.as_bytes()[long.len() - 2048..], home);
    assert_eq!(cut, "last line");
    assert!(cut.len() <= 2048);
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
}
