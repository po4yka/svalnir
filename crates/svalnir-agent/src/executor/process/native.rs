//! The Darwin termination calls. This file is the only place in the
//! process executor that has `unsafe` code.
//!
//! | Request | Native API |
//! | --- | --- |
//! | Graceful request to an application | `NSRunningApplication.terminate()` |
//! | Force request to an application | `NSRunningApplication.forceTerminate()` |
//! | Graceful request to a job process | `kill(pid, SIGTERM)`, or the configured `SIGINT` or `SIGHUP` |
//! | Force request to a job process or a listed helper | `kill(pid, SIGKILL)` |
//!
//! `kill` gets a PID that is larger than 1 only. Thus the call never has
//! the form for a process group (a negative PID), for the process group of
//! the caller (0), or for each process (-1).
//!
//! A PID is not a process generation. The caller reads the identity of the
//! process immediately before each call, but no macOS interface makes the
//! check and the call one atomic operation. A process that exits in that
//! interval can release its PID to a new process. See the module
//! documentation for the remaining interval.

use objc2::rc::autoreleasepool;
use objc2_app_kit::NSRunningApplication;
use svalnir_core::process::Pid;

use super::control::{
    ApplicationCallResult, ApplicationExpectation, ApplicationRequest, GracefulSignal,
    ProcessControl, ProcessSignal, SignalResult,
};

/// The termination calls of the running macOS host.
#[derive(Debug, Clone, Copy, Default)]
pub struct DarwinProcessControl;

impl DarwinProcessControl {
    /// Makes the control. It holds no native resource.
    pub const fn new() -> Self {
        Self
    }
}

fn pid_of(value: u32) -> Option<Pid> {
    i32::try_from(value)
        .ok()
        .and_then(|value| Pid::new(value).ok())
}

const fn signal_number(signal: ProcessSignal) -> libc::c_int {
    match signal {
        ProcessSignal::Graceful(GracefulSignal::Terminate) => libc::SIGTERM,
        ProcessSignal::Graceful(GracefulSignal::Interrupt) => libc::SIGINT,
        ProcessSignal::Graceful(GracefulSignal::HangUp) => libc::SIGHUP,
        ProcessSignal::Kill => libc::SIGKILL,
    }
}

/// The target of a signal, or `None` for a target that `kill` must not
/// get. PID 1 is `launchd`. A value of 0 or less is a group form.
fn checked_target(pid: Pid) -> Option<libc::pid_t> {
    let target: libc::pid_t = pid.get();
    (target > 1).then_some(target)
}

impl ProcessControl for DarwinProcessControl {
    fn own_process(&self) -> Option<Pid> {
        pid_of(std::process::id())
    }

    fn parent_process(&self) -> Option<Pid> {
        pid_of(std::os::unix::process::parent_id())
    }

    fn signal(&self, pid: Pid, signal: ProcessSignal) -> SignalResult {
        let Some(target) = checked_target(pid) else {
            return SignalResult::InvalidTarget;
        };
        // SAFETY: `kill` takes two integers by value and keeps no pointer.
        // `target` is larger than 1, so the call addresses one process and
        // not a process group.
        let status: libc::c_int = unsafe { libc::kill(target, signal_number(signal)) };
        if status == 0 {
            return SignalResult::Delivered;
        }
        match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::ESRCH) => SignalResult::NoSuchProcess,
            Some(libc::EPERM) => SignalResult::NotPermitted,
            Some(code) => SignalResult::Failed(code),
            None => SignalResult::Failed(0),
        }
    }

    fn request_application_exit(
        &self,
        expected: &ApplicationExpectation<'_>,
        request: ApplicationRequest,
    ) -> ApplicationCallResult {
        autoreleasepool(|_| {
            let Some(application) =
                NSRunningApplication::runningApplicationWithProcessIdentifier(expected.pid.get())
            else {
                return ApplicationCallResult::NotRegistered;
            };
            let bundle_agrees: bool = application
                .bundleIdentifier()
                .is_some_and(|identifier| identifier.to_string() == expected.bundle_identifier);
            let path_agrees: bool = application
                .executableURL()
                .and_then(|url| url.path())
                .is_some_and(|path| {
                    path.to_string().as_bytes() == expected.executable_path.as_bytes()
                });
            if application.processIdentifier() != expected.pid.get()
                || !bundle_agrees
                || !path_agrees
            {
                return ApplicationCallResult::IdentityMismatch;
            }
            if application.isTerminated() {
                return ApplicationCallResult::Terminated;
            }
            let sent: bool = match request {
                ApplicationRequest::Terminate => application.terminate(),
                ApplicationRequest::ForceTerminate => application.forceTerminate(),
            };
            if sent {
                ApplicationCallResult::Accepted
            } else {
                ApplicationCallResult::Declined
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use svalnir_core::process::Pid;

    use super::checked_target;

    /// The test calls only the pure function of the guard. It signals
    /// nothing.
    #[test]
    fn the_signal_of_process_one_is_refused_before_any_system_call() {
        let one: Pid = Pid::new(1).unwrap();
        assert_eq!(checked_target(one), None);
        let ordinary: Pid = Pid::new(2).unwrap();
        assert_eq!(checked_target(ordinary), Some(2));
    }
}
