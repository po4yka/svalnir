//! The main run loop of the process.
//!
//! `AppKit` refreshes some state only when the main run loop runs in a common
//! mode: the list and the active state of `NSWorkspace.runningApplications`
//! are such state. [`turn_main_run_loop`] gives the evidence that the loop
//! ran, and [`run_main_run_loop_until_stop`] runs the loop for a process that
//! has no other work on its main thread.
//!
//! The module registers no service and changes no other process.

#[cfg(target_os = "macos")]
use std::ffi::c_void;
#[cfg(target_os = "macos")]
use std::sync::atomic::{AtomicI32, Ordering};
#[cfg(target_os = "macos")]
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
#[cfg(target_os = "macos")]
use std::time::Duration;

#[cfg(target_os = "macos")]
use block2::RcBlock;
#[cfg(target_os = "macos")]
use dispatch2::{
    _dispatch_source_type_signal, DispatchObject, DispatchQueue, DispatchRetained, DispatchSource,
    dispatch_source_type_t,
};
#[cfg(target_os = "macos")]
use objc2::rc::autoreleasepool;
#[cfg(target_os = "macos")]
use objc2_foundation::{
    NSArray, NSDate, NSDefaultRunLoopMode, NSRunLoop, NSRunLoopCommonModes, NSThread,
};
use thiserror::Error;

/// The time for which a call on the main thread runs the main run loop.
#[cfg(target_os = "macos")]
const MAIN_THREAD_TURN_SECONDS: f64 = 0.01;

/// The longest wait of a call on another thread for one block on the main
/// run loop.
#[cfg(target_os = "macos")]
const PROBE_TIMEOUT: Duration = Duration::from_millis(100);

/// The number of blocks that a call on another thread waits for. The run
/// loop services its other input between two blocks.
#[cfg(target_os = "macos")]
const PROBE_ROUND_TRIPS: u32 = 2;

/// The probes of the main run loop from the other threads.
#[cfg(target_os = "macos")]
#[derive(Debug, Default)]
struct Probes {
    /// The number of blocks that were given to the main run loop.
    scheduled: u64,
    /// The number of blocks that the main run loop ran.
    executed: u64,
}

#[cfg(target_os = "macos")]
static PROBES: Mutex<Probes> = Mutex::new(Probes {
    scheduled: 0,
    executed: 0,
});
#[cfg(target_os = "macos")]
static PROBE_EXECUTED: Condvar = Condvar::new();

/// The probe counters. A poisoned lock still has valid counters, because
/// each update is one assignment.
#[cfg(target_os = "macos")]
fn probes() -> MutexGuard<'static, Probes> {
    PROBES.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Gives one block to the main run loop and waits for it.
///
/// At most one block waits in the run loop: when the block of an earlier
/// call did not run, this call waits for that block and schedules no new
/// one. Thus a process that never runs its main run loop keeps one block.
#[cfg(target_os = "macos")]
fn probe_main_run_loop() -> bool {
    let mut state: MutexGuard<'static, Probes> = probes();
    if state.scheduled == state.executed {
        state.scheduled += 1;
        let block = RcBlock::new(|| {
            let mut state: MutexGuard<'static, Probes> = probes();
            state.executed = state.scheduled;
            drop(state);
            PROBE_EXECUTED.notify_all();
        });
        autoreleasepool(|_| {
            // SAFETY: the static is a constant string object of Foundation
            // that is valid for the life of the process.
            let common_modes = unsafe { NSRunLoopCommonModes };
            let modes = NSArray::from_slice(&[common_modes]);
            // SAFETY: the block captures nothing and uses only statics that
            // are `Sync`, so it is sendable to the main thread. The run loop
            // copies the block and keeps it until it ran.
            unsafe { NSRunLoop::mainRunLoop().performInModes_block(&modes, &block) };
        });
    }
    let target: u64 = state.scheduled;
    let (state, _timeout) = PROBE_EXECUTED
        .wait_timeout_while(state, PROBE_TIMEOUT, |state| state.executed < target)
        .unwrap_or_else(PoisonError::into_inner);
    state.executed >= target
}

/// Lets the main run loop run and tells whether it ran.
///
/// On the main thread the call runs the main run loop in the default mode
/// for ten milliseconds, so the loop services its pending input. On another
/// thread the call gives two blocks to the main run loop in the common modes
/// and waits at most 100 milliseconds for each: the blocks run only when the
/// main thread runs its run loop.
///
/// A result of `true` is the evidence that `AppKit` state which depends on the
/// main run loop is current. A result of `false` means that there is no such
/// evidence.
#[cfg(target_os = "macos")]
pub fn turn_main_run_loop() -> bool {
    if NSThread::isMainThread_class() {
        autoreleasepool(|_| {
            let limit = NSDate::dateWithTimeIntervalSinceNow(MAIN_THREAD_TURN_SECONDS);
            NSRunLoop::mainRunLoop().runUntilDate(&limit);
        });
        return true;
    }
    (0..PROBE_ROUND_TRIPS).all(|_| probe_main_run_loop())
}

/// This host has no main run loop that Svalnir uses.
#[cfg(not(target_os = "macos"))]
pub fn turn_main_run_loop() -> bool {
    false
}

/// The signal that stopped [`run_main_run_loop_until_stop`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopSignal {
    /// `SIGINT`.
    Interrupt,
    /// `SIGTERM`.
    Terminate,
}

/// The reason the main run loop did not run until a stop signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RunLoopError {
    /// The caller is not the main thread of the process.
    #[error("the caller is not the main thread")]
    NotMainThread,
    /// The run loop has no input source, so it cannot wait.
    #[error("the main run loop has no input source")]
    NoInputSource,
    /// This host has no main run loop that Svalnir uses.
    #[error("the main run loop is not supported on this host")]
    Unsupported,
}

/// The stop signal that a signal source received, or zero.
#[cfg(target_os = "macos")]
static STOP_SIGNAL: AtomicI32 = AtomicI32::new(0);

/// The event handler of a signal source. The context is the signal number.
#[cfg(target_os = "macos")]
extern "C" fn record_stop(context: *mut c_void) {
    // The context is a number and not a pointer to data: it is not read as
    // memory.
    let signal: i32 = i32::try_from(context as usize).unwrap_or(libc::SIGTERM);
    STOP_SIGNAL.store(signal, Ordering::SeqCst);
}

/// The registration handler of a signal source. The context is the signal
/// number.
///
/// Dispatch calls it after the kernel started to record the signal for the
/// source. Only then does the process ignore the default action: a signal
/// that is ignored before that time is recorded nowhere. Before that time
/// the default action ends the process, which is a correct result of a stop
/// signal.
#[cfg(target_os = "macos")]
extern "C" fn ignore_default_action(context: *mut c_void) {
    let signal: libc::c_int = libc::c_int::try_from(context as usize).unwrap_or(0);
    if signal == libc::SIGINT || signal == libc::SIGTERM {
        // SAFETY: `SIG_IGN` is a valid disposition of these two signals. The
        // signal source reads the signal from the kernel event queue, which
        // records a signal that the process ignores.
        unsafe { libc::signal(signal, libc::SIG_IGN) };
    }
}

/// Makes a Dispatch source on the main queue that records `signal`.
#[cfg(target_os = "macos")]
fn stop_source(signal: libc::c_int) -> DispatchRetained<DispatchSource> {
    let source_type: dispatch_source_type_t = (&raw const _dispatch_source_type_signal).cast_mut();
    let handle: usize = usize::try_from(signal).unwrap_or(0);
    // SAFETY: the type is the signal source type of libdispatch, which takes
    // a signal number as its handle and a mask of zero. The main queue is a
    // valid queue. The source is created inactive.
    let source: DispatchRetained<DispatchSource> =
        unsafe { DispatchSource::new(source_type, handle, 0, Some(DispatchQueue::main())) };
    // SAFETY: the source is inactive. The context is the signal number as an
    // address that no handler dereferences, so it has no lifetime.
    unsafe { source.set_context(handle as *mut c_void) };
    source.set_event_handler_f(record_stop);
    source.set_registration_handler_f(ignore_default_action);
    source.activate();
    source
}

/// Runs the main run loop until the process gets `SIGINT` or `SIGTERM`.
///
/// The loop waits for input and does not poll. A signal arrives as an event
/// of a Dispatch source on the main queue, which the run loop services. The
/// call registers no service.
///
/// # Errors
///
/// Returns a [`RunLoopError`] when the caller is not the main thread, or the
/// run loop has no input source.
#[cfg(target_os = "macos")]
pub fn run_main_run_loop_until_stop() -> Result<StopSignal, RunLoopError> {
    if !NSThread::isMainThread_class() {
        return Err(RunLoopError::NotMainThread);
    }
    let sources: [DispatchRetained<DispatchSource>; 2] =
        [stop_source(libc::SIGINT), stop_source(libc::SIGTERM)];
    let result: Result<StopSignal, RunLoopError> = loop {
        match STOP_SIGNAL.load(Ordering::SeqCst) {
            0 => {}
            libc::SIGINT => break Ok(StopSignal::Interrupt),
            _ => break Ok(StopSignal::Terminate),
        }
        let ran: bool = autoreleasepool(|_| {
            // SAFETY: the static is a constant string object of Foundation
            // that is valid for the life of the process.
            let mode = unsafe { NSDefaultRunLoopMode };
            NSRunLoop::mainRunLoop().runMode_beforeDate(mode, &NSDate::distantFuture())
        });
        if !ran {
            break Err(RunLoopError::NoInputSource);
        }
    };
    for source in &sources {
        source.cancel();
    }
    result
}

/// This host has no main run loop that Svalnir uses.
///
/// # Errors
///
/// Returns [`RunLoopError::Unsupported`].
#[cfg(not(target_os = "macos"))]
pub fn run_main_run_loop_until_stop() -> Result<StopSignal, RunLoopError> {
    Err(RunLoopError::Unsupported)
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use std::time::{Duration, Instant};

    use super::{RunLoopError, run_main_run_loop_until_stop, turn_main_run_loop};

    /// The test harness does not run the main run loop, and a test is not on
    /// the main thread.
    #[test]
    fn a_process_that_does_not_run_its_main_run_loop_gives_no_evidence() {
        let started = Instant::now();
        assert!(!turn_main_run_loop());
        // A second call waits for the block of the first call.
        assert!(!turn_main_run_loop());
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn the_run_until_stop_is_refused_off_the_main_thread() {
        assert_eq!(
            run_main_run_loop_until_stop(),
            Err(RunLoopError::NotMainThread)
        );
    }
}
