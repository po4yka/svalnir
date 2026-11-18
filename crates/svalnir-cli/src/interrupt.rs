//! The interrupt request of the user (Ctrl+C), and the stop signals of a
//! transient coordinator.
//!
//! `scan` and `monitor` read this flag between two bounded steps, write what
//! they have, and end with exit status 130. `clean apply`, `processes stop`,
//! and `operations wait` read it to end the client wait. The flag ends a
//! read or a wait only: it changes no agent and no policy, and it cancels
//! no operation.
//!
//! A client that executes an operation as a transient coordinator arms the
//! flag before the admission and keeps it armed: from the admission on,
//! Ctrl+C must not end the process that is the executor of the operation
//! (`docs/INTERFACES.md` section 4).
//!
//! A stop signal (`SIGTERM` or `SIGHUP`) is different: a transient
//! coordinator arms its handler when it holds the coordinator lock, and
//! then stops as the agent does. It claims no further request, stops its
//! active operation at the next safe point, records the result, releases
//! the coordinator, and exits with `128` plus the number of the signal.

#[cfg(test)]
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

/// Set by the signal handler. A handler can only store to a static.
static PROCESS_INTERRUPTED: AtomicBool = AtomicBool::new(false);

/// The number of the first stop signal, or `0`. Set by the signal
/// handler.
static PROCESS_STOP_SIGNAL: AtomicI32 = AtomicI32::new(0);

/// A stop signal that a transient coordinator obeys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StopSignal {
    /// `SIGTERM`, for example from `kill` or from the service manager.
    Terminate,
    /// `SIGHUP`: the terminal of the session closed.
    HangUp,
}

impl StopSignal {
    /// The number of the signal on the supported hosts.
    const fn number(self) -> i32 {
        match self {
            Self::Terminate => 15,
            Self::HangUp => 1,
        }
    }

    fn of_number(number: i32) -> Option<Self> {
        [Self::Terminate, Self::HangUp]
            .into_iter()
            .find(|signal| signal.number() == number)
    }

    /// The exit status: `128` plus the number of the signal.
    pub(crate) const fn exit_status(self) -> crate::output::ExitStatus {
        match self {
            Self::Terminate => crate::output::ExitStatus::Terminated,
            Self::HangUp => crate::output::ExitStatus::HungUp,
        }
    }

    /// The name of the signal.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Terminate => "SIGTERM",
            Self::HangUp => "SIGHUP",
        }
    }
}

/// A flag that tells that the user interrupted the client.
#[derive(Debug, Clone)]
pub(crate) struct Interrupt {
    source: Source,
}

#[derive(Debug, Clone)]
enum Source {
    /// The `SIGINT` flag of this process.
    Process,
    /// A flag and a stop signal that a test sets.
    #[cfg(test)]
    Manual(Arc<AtomicBool>, Arc<AtomicI32>),
}

impl Interrupt {
    /// The flag of this process. Ctrl+C keeps its default action, which ends
    /// the process, until a command calls [`Interrupt::arm`].
    pub(crate) fn for_process() -> Self {
        Self {
            source: Source::Process,
        }
    }

    /// Makes Ctrl+C set this flag and not end the process.
    ///
    /// Only a command that reads the flag between bounded steps calls this
    /// function: `scan`, `monitor`, the apply flow of `clean apply` and
    /// `processes stop`, and `operations wait`. For each other command
    /// Ctrl+C ends the process at once. If the handler cannot be installed, the default
    /// action stays in effect.
    pub(crate) fn arm(&self) {
        match &self.source {
            Source::Process => install_handler(),
            #[cfg(test)]
            Source::Manual(..) => {}
        }
    }

    /// Makes `SIGTERM` and `SIGHUP` record a stop signal and not end the
    /// process. Only a transient coordinator calls this function, when it
    /// holds the coordinator lock. A client that waits on a different
    /// coordinator keeps the default action. If a handler cannot be
    /// installed, the default action of that signal stays in effect.
    pub(crate) fn arm_stop_signals(&self) {
        match &self.source {
            Source::Process => install_stop_handlers(),
            #[cfg(test)]
            Source::Manual(..) => {}
        }
    }

    /// A flag that is set only through the returned handle.
    #[cfg(test)]
    pub(crate) fn manual() -> (Self, Arc<AtomicBool>) {
        let (interrupt, flag, _signal) = Self::manual_with_stop_signal();
        (interrupt, flag)
    }

    /// A flag and a stop signal that are set only through the returned
    /// handles. The stop signal is the number of the signal, or `0`.
    #[cfg(test)]
    pub(crate) fn manual_with_stop_signal() -> (Self, Arc<AtomicBool>, Arc<AtomicI32>) {
        let flag = Arc::new(AtomicBool::new(false));
        let signal = Arc::new(AtomicI32::new(0));
        (
            Self {
                source: Source::Manual(Arc::clone(&flag), Arc::clone(&signal)),
            },
            flag,
            signal,
        )
    }

    /// The first stop signal that the process received after
    /// [`Interrupt::arm_stop_signals`].
    pub(crate) fn stop_signal(&self) -> Option<StopSignal> {
        let number: i32 = match &self.source {
            Source::Process => PROCESS_STOP_SIGNAL.load(Ordering::SeqCst),
            #[cfg(test)]
            Source::Manual(_, signal) => signal.load(Ordering::SeqCst),
        };
        StopSignal::of_number(number)
    }

    /// Whether the user interrupted the client.
    pub(crate) fn is_requested(&self) -> bool {
        match &self.source {
            Source::Process => PROCESS_INTERRUPTED.load(Ordering::SeqCst),
            #[cfg(test)]
            Source::Manual(flag, _) => flag.load(Ordering::SeqCst),
        }
    }
}

#[cfg(unix)]
extern "C" fn record_interrupt(_signal: libc::c_int) {
    // An atomic store is async-signal-safe.
    PROCESS_INTERRUPTED.store(true, Ordering::SeqCst);
}

#[cfg(unix)]
fn install_handler() {
    static INSTALL: std::sync::Once = std::sync::Once::new();
    INSTALL.call_once(|| {
        let handler: extern "C" fn(libc::c_int) = record_interrupt;
        // SAFETY: an all-zero `sigaction` is a valid value on the supported
        // Unix targets.
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = handler as libc::sighandler_t;
        // `sa_flags` stays zero, so `SA_RESTART` is not set: a blocked
        // `write` returns `EINTR` and the caller can read the flag.
        action.sa_flags = 0;
        // SAFETY: the pointer is to the mask field of the live `action`,
        // which `sigemptyset` initializes in place.
        unsafe { libc::sigemptyset(&raw mut action.sa_mask) };
        // SAFETY: `action` is fully initialized. `record_interrupt` has the
        // signature of a signal handler and does only an atomic store, which
        // is async-signal-safe; the pointer is valid for the life of the
        // process. The old-action pointer is null, which `sigaction` permits.
        let installed: libc::c_int =
            unsafe { libc::sigaction(libc::SIGINT, &raw const action, std::ptr::null_mut()) };
        // On failure the default action stays in effect: the process ends
        // on Ctrl+C, and the shell reports status 130.
        let _ = installed;
    });
}

#[cfg(unix)]
extern "C" fn record_stop_signal(signal: libc::c_int) {
    // A compare-and-swap of a lock-free atomic is async-signal-safe. The
    // first signal stays.
    let _first: Result<i32, i32> =
        PROCESS_STOP_SIGNAL.compare_exchange(0, signal, Ordering::SeqCst, Ordering::SeqCst);
}

#[cfg(unix)]
fn install_stop_handlers() {
    static INSTALL: std::sync::Once = std::sync::Once::new();
    INSTALL.call_once(|| {
        let handler: extern "C" fn(libc::c_int) = record_stop_signal;
        for signal in [libc::SIGTERM, libc::SIGHUP] {
            // SAFETY: an all-zero `sigaction` is a valid value on the
            // supported Unix targets.
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            action.sa_sigaction = handler as libc::sighandler_t;
            // `SA_RESTART` lets an interrupted system call of the
            // coordinator continue: the flag is read between two steps.
            action.sa_flags = libc::SA_RESTART;
            // SAFETY: the pointer is to the mask field of the live
            // `action`, which `sigemptyset` initializes in place.
            unsafe { libc::sigemptyset(&raw mut action.sa_mask) };
            // SAFETY: `action` is fully initialized. `record_stop_signal`
            // has the signature of a signal handler and does only an
            // atomic compare-and-swap, which is async-signal-safe; the
            // pointer is valid for the life of the process. The
            // old-action pointer is null, which `sigaction` permits.
            let installed: libc::c_int =
                unsafe { libc::sigaction(signal, &raw const action, std::ptr::null_mut()) };
            // On failure the default action stays in effect.
            let _ = installed;
        }
    });
}

#[cfg(not(unix))]
fn install_handler() {}

#[cfg(not(unix))]
fn install_stop_handlers() {}
