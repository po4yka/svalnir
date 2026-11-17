//! The process executor.
//!
//! The executor does one admitted step of an application intervention,
//! `RequestApplicationExit` or `ForceApplicationExit`, on the verified
//! members of one application or managed-job instance, and reports what it
//! observed. It does not select a target, it does not decide policy, and
//! it does not write the journal: [`StepInput`] needs the
//! [`DispatchReceipt`](svalnir_core::action::DispatchReceipt) that the
//! journal gave for the dispatch consumption of the step.
//!
//! Owning specification: `docs/ACTION_CONTRACTS.md` sections 6, 8, and 9.
//!
//! # Sequence
//!
//! 1. [`ProcessExecutor::begin`] does the checks of the step as a whole
//!    and the hard refusals. Then, for each member, it reads the process
//!    again, compares the PID, the start time, the owner, the boot, and
//!    the executable evidence with the planned identity, and issues one
//!    call. It never waits.
//! 2. The caller keeps the [`Observation`] and calls
//!    [`Observation::poll`] at the times it selects. The executor reads
//!    its [`StepClock`]; it does not sleep and it holds no lock. A poll
//!    with a [`StopRequest`] ends the observation.
//! 3. The [`StepReport`] has one
//!    [`TargetResult`](svalnir_core::action::TargetResult) for each member
//!    and a [`NextStep`]. A force step is a second step with its own
//!    envelope and its own receipt. In the strategy `force_after_grace`
//!    it also needs the [`GracefulRecord`] of the graceful step, and the
//!    executor refuses it before the end of the grace period.
//!
//! # Calls
//!
//! | Member | Graceful step | Force step |
//! | --- | --- | --- |
//! | Registered process of an application (`launch_services`) | `NSRunningApplication.terminate()` | `NSRunningApplication.forceTerminate()` |
//! | Listed helper of an application (`responsible_process`) | No call: the request to the application applies, and the exit is observed | `kill(pid, SIGKILL)` |
//! | Process of a managed job (`launchd_job`) | `kill(pid, SIGTERM)`, or the configured signal | `kill(pid, SIGKILL)` |
//!
//! A call addresses one positive PID of a member that the step lists.
//! There is no process group, no name selector, and no descendant sweep.
//!
//! # Outcomes
//!
//! The return value of a call is not a result. A member is `ExitVerified`
//! only after a later reading shows that the planned generation does not
//! exist: no process has the PID, the process is a zombie of the same
//! generation, or the PID belongs to a process with a different start
//! time ([`GenerationState::Replaced`], with the attribution `possible`).
//! `StillRunning` and `UnknownOutcome` (the reading failed) are separate
//! effects. Before the call, a PID that no process has, or a zombie of the
//! planned generation, is `AlreadyExited`, and the executor issues no call
//! for it. A PID that a different generation has before the call is
//! `Skipped` with `process_replaced` for a member that gets a call, and
//! `AlreadyExited` for a helper that gets none.
//!
//! # The interval between the check and the call
//!
//! macOS has no interface that sends a signal to a process generation.
//! `kill` and `NSRunningApplication` address a PID. The executor reads the
//! identity immediately before each call, with the identity query as the
//! last query, but the check and the call are not one atomic operation. A
//! process that exits after the check releases its PID, and the kernel can
//! give that PID to a new process of the same user before the call. The
//! interval has no query, no allocation of a result, and no wait in it for
//! the signal path. For the application path it also has the lookup of the
//! running application by PID, which compares the PID, the bundle
//! identifier, and the executable path again.
//!
//! # Hard refusals
//!
//! Independently of the plan, the executor issues no call when the
//! protection fact of the caller is not `NotProtected`, when a member has
//! PID 1, is the executor or its parent, is a process of another user or
//! of root, or agrees with a catalog rule that needs no control plane, and
//! when the executor cannot establish its own process. A zombie is never
//! signaled: it is recorded as `AlreadyExited`.

mod control;
mod identity;
#[cfg(target_os = "macos")]
mod native;
mod record;
mod step;

#[cfg(test)]
mod tests;

pub use control::{
    ApplicationCallResult, ApplicationExpectation, ApplicationRequest, GracefulSignal,
    ProcessControl, ProcessSignal, SignalResult, SourceClock, StepClock,
};
pub use identity::GenerationState;
#[cfg(target_os = "macos")]
pub use native::DarwinProcessControl;
pub use record::{ExecutorError, code};
pub use step::{
    ExecutorConfig, ExecutorContext, GracefulRecord, MAX_CLOCK_FAILURES, MemberOutcome, NextStep,
    Observation, ProcessExecutor, StepInput, StepReport, StepRun, StopRequest,
};
