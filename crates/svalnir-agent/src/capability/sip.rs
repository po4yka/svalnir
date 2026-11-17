//! The System Integrity Protection status of macOS.
//!
//! The status is information only. Svalnir does not ask the user to change
//! it. The probe runs `csrutil status`, the documented read-only query; the
//! tool needs no elevated rights for it.

use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use super::probe::SipFinding;

/// The path of the tool that reports the System Integrity Protection status.
const CSRUTIL: &str = "/usr/bin/csrutil";

/// The time that the System Integrity Protection probe waits for the tool.
const CSRUTIL_TIMEOUT: Duration = Duration::from_secs(5);

/// The largest number of bytes that the probe reads from the tool.
const CSRUTIL_OUTPUT_LIMIT: u64 = 4096;

/// The largest number of characters of an unexpected status that the probe
/// keeps.
const STATUS_TEXT_LIMIT: usize = 200;

/// Reads the status line of `csrutil status`.
fn parse_csrutil_status(output: &str) -> SipFinding {
    const LABEL: &str = "System Integrity Protection status:";
    let Some(status) = output
        .lines()
        .find_map(|line| line.trim().strip_prefix(LABEL))
    else {
        return SipFinding::NotDetermined("The tool printed no status line.".to_owned());
    };
    let status = status.trim().trim_end_matches('.');
    match status {
        "enabled" => SipFinding::Enabled,
        "disabled" => SipFinding::Disabled,
        "" => SipFinding::NotDetermined("The status line is empty.".to_owned()),
        other => SipFinding::Other(other.chars().take(STATUS_TEXT_LIMIT).collect()),
    }
}

/// Runs `csrutil status` and reads its bounded output.
fn run_csrutil() -> SipFinding {
    let child = Command::new(CSRUTIL)
        .arg("status")
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn();
    let mut child = match child {
        Ok(child) => child,
        Err(error) => {
            return SipFinding::NotDetermined(format!("{CSRUTIL} did not start: {error}"));
        }
    };
    let mut output: Vec<u8> = Vec::new();
    let read = match child.stdout.take() {
        // The pipe closes at the end of this arm. A tool that writes more
        // than the limit then gets a write error and stops.
        Some(stdout) => stdout
            .take(CSRUTIL_OUTPUT_LIMIT)
            .read_to_end(&mut output)
            .map(|_| ()),
        None => Ok(()),
    };
    // Wait for the tool in each case, so that no ended child stays.
    let ended = child.wait();
    if let Err(error) = read {
        return SipFinding::NotDetermined(format!("The output is not readable: {error}"));
    }
    match ended {
        Ok(status) if status.success() => parse_csrutil_status(&String::from_utf8_lossy(&output)),
        Ok(status) => SipFinding::NotDetermined(format!("{CSRUTIL} ended with {status}.")),
        Err(error) => SipFinding::NotDetermined(format!("{CSRUTIL} did not end: {error}")),
    }
}

/// Whether a run of the tool has not ended yet. One run at a time bounds
/// the threads and the child processes of a tool that does not end.
static IN_FLIGHT: AtomicBool = AtomicBool::new(false);

/// Reads the status of System Integrity Protection.
pub(super) fn status() -> SipFinding {
    // The tool runs on a worker thread, so that a tool that does not end
    // cannot block the report. The probe does not signal the tool: after the
    // time limit the thread stays until the tool ends.
    if IN_FLIGHT.swap(true, Ordering::AcqRel) {
        return SipFinding::NotDetermined(
            "A previous run of the probe has not ended yet.".to_owned(),
        );
    }
    let (sender, receiver) = mpsc::channel();
    let worker = thread::Builder::new()
        .name("svalnir-sip-probe".to_owned())
        .spawn(move || {
            // The receiver is gone after the time limit; that is not an error.
            let finding = run_csrutil();
            IN_FLIGHT.store(false, Ordering::Release);
            drop(sender.send(finding));
        });
    if let Err(error) = worker {
        IN_FLIGHT.store(false, Ordering::Release);
        return SipFinding::NotDetermined(format!("The probe thread did not start: {error}"));
    }
    receiver.recv_timeout(CSRUTIL_TIMEOUT).unwrap_or_else(|_| {
        SipFinding::NotDetermined(format!(
            "{CSRUTIL} did not answer in {} seconds.",
            CSRUTIL_TIMEOUT.as_secs()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_csrutil_status_line_is_parsed() {
        assert_eq!(
            parse_csrutil_status("System Integrity Protection status: enabled.\n"),
            SipFinding::Enabled
        );
        assert_eq!(
            parse_csrutil_status("System Integrity Protection status: disabled.\n"),
            SipFinding::Disabled
        );
        assert_eq!(
            parse_csrutil_status(
                "System Integrity Protection status: unknown (Custom Configuration).\n\n\
                 Configuration:\n\tApple Internal: disabled\n"
            ),
            SipFinding::Other("unknown (Custom Configuration)".to_owned())
        );
        assert!(matches!(
            parse_csrutil_status("csrutil: failed"),
            SipFinding::NotDetermined(_)
        ));
        assert!(matches!(
            parse_csrutil_status(""),
            SipFinding::NotDetermined(_)
        ));
        let long = format!(
            "System Integrity Protection status: {}",
            "x".repeat(STATUS_TEXT_LIMIT * 2)
        );
        let SipFinding::Other(status) = parse_csrutil_status(&long) else {
            panic!("a long status is an unexpected status");
        };
        assert_eq!(status.chars().count(), STATUS_TEXT_LIMIT);
    }

    #[test]
    fn the_real_tool_returns_a_finding() {
        // The result depends on the host; each variant is a defined finding.
        // A parallel test can have a run in flight; that is `NotDetermined`.
        let finding = status();
        assert_ne!(finding, SipFinding::Unsupported);
    }
}
