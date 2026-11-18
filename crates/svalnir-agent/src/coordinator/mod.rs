//! The operation coordinator.
//!
//! The coordinator is the only code that turns an admitted plan into
//! executor calls. It does the admission of a plan (authority, expiry,
//! budgets, leases, recording capacity), holds the single-coordinator
//! lock, serializes conflicting mutations, records the intent, the
//! dispatch consumption, and the outcome of each step, handles
//! cancellation and stop fences, and reconciles the operations that an
//! earlier executor lifetime left unsettled.
//!
//! Owning specifications: `docs/ACTION_CONTRACTS.md` sections 4, 5, 6, 9,
//! 10, 11, 12, and 13, `docs/ARCHITECTURE.md` sections 3, 7, 12, and 15,
//! and `docs/POLICY_SPEC.md` sections 11, 13, and 14.
//!
//! # Interface
//!
//! The same code runs inside the agent and as the transient coordinator
//! that the CLI starts for one request.
//!
//! | Call | Use |
//! | --- | --- |
//! | [`Coordinator::start`] | Takes the coordinator lock and registers the executor lifetime. [`Start::Busy`] tells the caller to write its request to the queue of the journal. |
//! | [`Coordinator::apply`] | Admits a plan as one operation, or returns the operation of an earlier apply, or a refusal. A refusal changes nothing. |
//! | [`Coordinator::step`] | Does one bounded unit of work: a pending reconciliation, the stop requests, one request of the journal queue, and one unit of the active operation. |
//! | [`Coordinator::serve_queue`] | Claims and executes one request of the journal queue. `step` calls it. |
//! | [`Coordinator::operation`] | Reads an operation with its phase, its stop request, and its measurements. |
//! | [`Coordinator::cancel`] | Stops the further dispatch of an operation and returns the acknowledgement level. |
//! | [`Coordinator::run_until_finished`] | Calls `step` until an operation is finished or the time of the caller ends. The end of the time cancels nothing. |
//! | [`Coordinator::shutdown`] | Releases the registration when each operation is settled. |
//! | [`CoordinatorHandle`] | The same query, cancel, and wait calls for a different thread. |
//!
//! # Concurrency design
//!
//! The crate has no asynchronous runtime. One thread, the driver, owns
//! the [`Coordinator`] with its journal connection and its executors, and
//! calls [`Coordinator::step`] in a loop. The driver is the only caller
//! of the journal writes and of the executors, so two steps never run at
//! the same time: the initial implementation permits one intervention
//! action at a time.
//!
//! `step` never sleeps and never waits for an application. The process
//! executor issues its request and returns an observation; `step` reads
//! the observation one time at each poll time, and the grace period is
//! a time in its [`Progress`] result. The caller sleeps between two
//! calls, or does other work.
//!
//! The only state that the driver shares is the status board. Its lock
//! is the scheduling lock: a critical section copies a few values and
//! makes no journal call, no executor call, and no measurement. A
//! [`CoordinatorHandle`] reads the board and writes a stop request to
//! it, so a status query and a cancel are answered while the driver is in
//! a filesystem call, in a journal transaction, or between two readings
//! of a grace period. The driver reads the stop requests at each
//! dispatch boundary: before the intent of a step and immediately before
//! its call.
//!
//! A different process does not share memory with the driver. It writes
//! its request to the queue of the journal, or sets the stop fence of an
//! operation directly; the dispatch consumption of the journal reads the
//! fence in its own transaction.
//!
//! A time is a value of the injected [`Clock`], so a test moves the time
//! between two calls of `step` and each sequence is deterministic.
//!
//! # Rules that the caller must know
//!
//! - The coordinator records no rejection. A refused plan stays
//!   unconsumed and can be applied again before its expiry when the
//!   reason of the refusal can change.
//! - An automatic plan is applied with the allowance of its incident
//!   ([`IncidentAllowance`]). An automatic plan with no allowance (a
//!   request of the journal queue, or a stored plan that a client
//!   applies) is refused with `incident_allowance_missing`.
//! - A cancel request of the journal queue stops only an operation that
//!   the same user applied.
//! - [`Coordinator::shutdown`] releases the registration only when the
//!   journal has each record of the volatile history. If not, the next
//!   lifetime starts as after an unclean stop.
//! - An operation of an earlier executor lifetime is never dispatched
//!   again. Reconciliation settles it from fresh evidence, or it stays
//!   `UnknownOutcome`.
//! - An operation of this lifetime that ends as `UnknownOutcome`, or
//!   whose settled record the journal did not take, keeps its leases and
//!   its reservation. A conflicting plan is refused until a restart
//!   reconciles it, or until the journal takes the record.
//! - The measurements of an operation and the submission time of a
//!   graceful step are in memory only. The journal has no record for
//!   them.
//! - A rule whose layout is in the `proposed` lifecycle state permits no
//!   mode. An automatic eviction with such a rule is refused, and a
//!   manual eviction plan, which binds the rule, is refused with
//!   `rule_mode_not_validated`. A manual plan in the Trash or the
//!   permanent mode binds no rule, so the state of a rule does not
//!   change it.

mod board;
mod core;
mod dispatch;
mod error;
mod ledger;
mod ports;
mod recovery;
#[cfg(test)]
mod tests;

pub use self::board::{
    CoordinatorHandle, MAX_RETAINED_OPERATIONS, OperationView, Phase, StopAcknowledgement,
    StopView, WaitOutcome, WorkTotals,
};
pub use self::core::{
    ApplyOutcome, ApplyRequest, Coordinator, CoordinatorConfig, Dependencies, Idle,
    MAX_INCIDENT_DISPATCHES, MAX_KNOWN_PLANS, MAX_MEASURED_VOLUMES, MAX_WAITING_OPERATIONS,
    Progress, Start,
};
pub use self::error::{CoordinatorError, StartError, code};
pub use self::ledger::{IncidentAllowance, MAX_INCIDENTS, MAX_LEASES, Pacing};
pub use self::ports::{
    ApplicationExecutor, AuthoritySource, Clock, CoordinatorJournal, FileProbe, FilesystemExecutor,
    IdSource, Measurements, RevisionSnapshot, SystemProbe, TargetProbe, TimeReading,
    TriggerStanding,
};
pub use self::recovery::MAX_RECONCILED_OPERATIONS;
