//! The interrupt request of the user (Ctrl+C).
//!
//! `scan` and `monitor` read this flag between two bounded steps, write what
//! they have, and end with exit status 130. The flag disconnects the client
//! only: it changes no agent, policy, or operation.

#[cfg(test)]
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Set by the signal handler. A handler can only store to a static.
static PROCESS_INTERRUPTED: AtomicBool = AtomicBool::new(false);

/// A flag that tells that the user interrupted the client.
#[derive(Debug, Clone)]
pub(crate) struct Interrupt {
    source: Source,
}

#[derive(Debug, Clone)]
enum Source {
    /// The `SIGINT` flag of this process.
    Process,
    /// A flag that a test sets.
    #[cfg(test)]
    Manual(Arc<AtomicBool>),
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
    /// function (`scan` and `monitor`). For each other command Ctrl+C ends
    /// the process at once. If the handler cannot be installed, the default
    /// action stays in effect.
    pub(crate) fn arm(&self) {
        match &self.source {
            Source::Process => install_handler(),
            #[cfg(test)]
            Source::Manual(_) => {}
        }
    }

    /// A flag that is set only through the returned handle.
    #[cfg(test)]
    pub(crate) fn manual() -> (Self, Arc<AtomicBool>) {
        let flag = Arc::new(AtomicBool::new(false));
        (
            Self {
                source: Source::Manual(Arc::clone(&flag)),
            },
            flag,
        )
    }

    /// Whether the user interrupted the client.
    pub(crate) fn is_requested(&self) -> bool {
        match &self.source {
            Source::Process => PROCESS_INTERRUPTED.load(Ordering::SeqCst),
            #[cfg(test)]
            Source::Manual(flag) => flag.load(Ordering::SeqCst),
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
        // SAFETY: `record_interrupt` has the signature of a signal handler
        // and does only an atomic store, which is async-signal-safe. The
        // function pointer is valid for the life of the process. `signal`
        // has no other precondition.
        let previous = unsafe { libc::signal(libc::SIGINT, handler as libc::sighandler_t) };
        // On `SIG_ERR` the default action stays in effect: the process ends
        // on Ctrl+C, and the shell reports status 130.
        let _ = previous;
    });
}

#[cfg(not(unix))]
fn install_handler() {}
