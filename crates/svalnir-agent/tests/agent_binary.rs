//! The `svalnir-agent` binary runs until a stop signal.
//!
//! Each test starts the binary as a disposable child process and signals
//! only that child.

#![cfg(target_os = "macos")]
#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "a helper of a test fails with the message of the unwrap"
)]

use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

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

fn stops_on(signal: libc::c_int) {
    let mut child: Child = Command::new(env!("CARGO_BIN_EXE_svalnir-agent"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    // The process is in its run loop: it does not end without a signal.
    std::thread::sleep(Duration::from_millis(500));
    assert!(child.try_wait().unwrap().is_none());

    let pid: libc::pid_t = libc::pid_t::try_from(child.id()).unwrap();
    // SAFETY: `pid` is the child that this test started and did not wait
    // for, so the PID is not reused. The call sends one signal.
    assert_eq!(unsafe { libc::kill(pid, signal) }, 0);
    let status: ExitStatus = wait_with_limit(&mut child, Duration::from_secs(10))
        .expect("the agent did not stop after the signal");
    assert!(status.success(), "{status:?}");
}

#[test]
fn the_agent_runs_until_sigterm_and_ends_with_success() {
    stops_on(libc::SIGTERM);
}

#[test]
fn the_agent_runs_until_sigint_and_ends_with_success() {
    stops_on(libc::SIGINT);
}
