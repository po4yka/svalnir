//! The owner executor: one fixed command of a producer on one measured
//! scope (`RunOwnerOperation`).
//!
//! `docs/ACTION_CONTRACTS.md` section 7 (the subsection of
//! `RunOwnerOperation`) owns the sequence of the checks and the results,
//! and `docs/CLEANUP_RULES.md` section 9 owns the declaration. The
//! executor takes an [`AdmittedOwnerStep`]: a request envelope with the
//! receipt of its durable dispatch consumption, so a call with no consumed
//! dispatch does not compile.
//!
//! Before the start, the executor compares the root record of its process,
//! the mount table, the scope root, and the executable with the sealed
//! plan, and measures the scope again. A failed check starts no command.
//! The command starts by its absolute path, with no shell and no `PATH`
//! lookup, with the arguments, the environment, and the working directory
//! of the plan, an empty standard input, and a process group of its own.
//! A deadline or a stop condition stops the group. The output is kept only
//! as a bounded, redacted tail for the log of the process.
//!
//! The comparison of the executable and its start are two calls: a process
//! of the user that can write to the directory of a user-owned executable
//! can replace it between them. That is a residual risk of a proposed rule
//! (`docs/THREAT_MODEL.md` T-09).

mod executor;
mod family;
mod measure;
mod model;
mod native;
mod supervise;
mod verify;

#[cfg(test)]
mod tests;

pub use executor::{OwnerExecutor, OwnerPoll, OwnerRun, process_record_of};
pub use family::{RECORDED_STOP_GRACE, process_lives, stop_recorded};
pub use measure::{ScopeLimits, measure_scope};
pub use model::{
    AdmittedOwnerStep, OwnerAdmissionRefusal, OwnerExecutorConfig, OwnerFault, OwnerOutcome,
    OwnerStepOutcome, code,
};
pub use native::ResponsibilitySymbols;
pub use verify::{
    ExecutableKind, ExecutableProblem, examine_executable, examine_program, executable_kind,
};
