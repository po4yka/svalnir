//! The safe boundary between the native termination calls and the step
//! logic.
//!
//! [`ProcessControl`] has one method for each native call that changes a
//! process. The Darwin implementation is in `native.rs`. A test gives a
//! synthetic implementation, so the staging and identity logic runs with no
//! live process.

use svalnir_core::file::LosslessPath;
use svalnir_core::process::Pid;
use svalnir_core::time::{MonotonicNanos, WallTime};

use crate::platform::process::{ProcessSource, QueryFailure};

/// The signal of a graceful request to a job process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GracefulSignal {
    /// `SIGTERM`.
    #[default]
    Terminate,
    /// `SIGINT`.
    Interrupt,
    /// `SIGHUP`.
    HangUp,
}

/// One signal that the executor can send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessSignal {
    /// The configured graceful signal.
    Graceful(GracefulSignal),
    /// `SIGKILL`.
    Kill,
}

/// The result of one signal call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalResult {
    /// The call returned success. This is not an observed exit.
    Delivered,
    /// `ESRCH`: no process has the PID. No signal was delivered.
    NoSuchProcess,
    /// `EPERM`: the caller is not permitted to signal the process. No signal
    /// was delivered.
    NotPermitted,
    /// The call failed with this other `errno` value.
    Failed(i32),
    /// The PID does not address one process that can be a target (it is 1
    /// or less). No call was issued.
    InvalidTarget,
}

/// The kind of an exit request to a running application.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplicationRequest {
    /// `NSRunningApplication.terminate()`.
    Terminate,
    /// `NSRunningApplication.forceTerminate()`.
    ForceTerminate,
}

/// The identity that the registered application of a PID must have before
/// a request is sent to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApplicationExpectation<'a> {
    /// The process ID of the verified member.
    pub pid: Pid,
    /// The bundle identifier of the verified membership.
    pub bundle_identifier: &'a str,
    /// The executable path of the verified member.
    pub executable_path: &'a LosslessPath,
}

/// The result of one exit request to a running application.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplicationCallResult {
    /// The call returned `true`: the request was sent. This is not an
    /// observed exit.
    Accepted,
    /// The call returned `false`: the request was not sent, or the
    /// application exited before the call.
    Declined,
    /// Launch Services has no running application with the PID. No call
    /// was issued.
    NotRegistered,
    /// The registered application of the PID has a different PID, bundle
    /// identifier, or executable path. No call was issued.
    IdentityMismatch,
    /// The registered application reports that it terminated. No call was
    /// issued.
    Terminated,
    /// The host has no application backend. No call was issued.
    Unsupported,
}

/// The native calls that change a process.
///
/// Each method addresses one process by its PID, because the native API
/// does. The caller checks the identity of the process immediately before
/// the call. No method has a group form, a name selector, or a descendant
/// sweep.
pub trait ProcessControl {
    /// The process ID of the executor. `None` when it is not known; the
    /// executor then refuses each target.
    fn own_process(&self) -> Option<Pid>;

    /// The process ID of the parent of the executor. `None` when it is not
    /// known; the executor then refuses each target.
    fn parent_process(&self) -> Option<Pid>;

    /// Sends one signal to the process that has this PID now.
    fn signal(&self, pid: Pid, signal: ProcessSignal) -> SignalResult;

    /// Finds the running application of `expected.pid`, compares it with
    /// `expected`, and sends `request` to it when the two agree.
    fn request_application_exit(
        &self,
        expected: &ApplicationExpectation<'_>,
        request: ApplicationRequest,
    ) -> ApplicationCallResult;
}

/// The clock of a step. The caller of the executor controls the time
/// between two calls; the executor only reads the clock.
pub trait StepClock {
    /// The time on the monotonic clock of the executor context.
    ///
    /// # Errors
    ///
    /// Returns a [`QueryFailure`] when the clock gives no value.
    fn monotonic_now(&self) -> Result<MonotonicNanos, QueryFailure>;

    /// The wall-clock time, for history only. `None` when the clock gives
    /// no valid value.
    fn wall_now(&self) -> Option<WallTime>;
}

/// The clock of a [`ProcessSource`] as a [`StepClock`].
#[derive(Debug, Clone, Copy, Default)]
pub struct SourceClock<S>(pub S);

impl<S: ProcessSource> StepClock for SourceClock<S> {
    fn monotonic_now(&self) -> Result<MonotonicNanos, QueryFailure> {
        self.0.monotonic_now()
    }

    fn wall_now(&self) -> Option<WallTime> {
        self.0.wall_now().ok()
    }
}
