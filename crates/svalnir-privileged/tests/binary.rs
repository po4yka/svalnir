//! The start of the `svalnir-privileged` binary.
//!
//! The test starts the binary as a child process of the test. The binary
//! asks the platform for the listener of its Mach service. Only the launch
//! daemon definition of the product can give that name to a process, and
//! this repository installs no such definition, so the platform refuses
//! the registration. The test installs nothing and needs no elevated
//! right.

#![expect(
    clippy::unwrap_used,
    reason = "a helper of a test fails with the message of the unwrap"
)]

use std::io::Read as _;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const EXIT_TIMEOUT: Duration = Duration::from_secs(30);

fn wait_for_exit(child: &mut Child) -> Option<ExitStatus> {
    let deadline: Instant = Instant::now() + EXIT_TIMEOUT;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return Some(status);
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn the_binary_exits_with_an_error_when_the_platform_refuses_the_registration() {
    let mut child: Child = Command::new(env!("CARGO_BIN_EXE_svalnir-privileged"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let Some(status) = wait_for_exit(&mut child) else {
        // The child is a process that this test started.
        child.kill().unwrap();
        child.wait().unwrap();
        panic!("the binary did not exit: it serves with no registered service");
    };

    let mut stdout: String = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut stdout)
        .unwrap();
    let mut stderr: String = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert_eq!(status.code(), Some(1), "{stderr}");
    assert_eq!(stdout, "");
    assert!(stderr.starts_with("svalnir-privileged: "), "{stderr}");
    #[cfg(target_os = "macos")]
    assert!(
        stderr.contains("refused the registration of the service `dev.po4yka.svalnir.privileged`"),
        "{stderr}"
    );
    assert!(stderr.contains("The helper runs no operation."), "{stderr}");
}
