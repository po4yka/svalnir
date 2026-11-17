//! The operation coordinator.
//!
//! Planned responsibility: admission of a plan (authority, expiry,
//! budgets, leases, recording capacity), the single-coordinator lock,
//! serialization of conflicting mutations, the sequence of intent,
//! dispatch consumption, execution, and outcome recording for each step,
//! cancellation and stop fences, and reconciliation of unsettled
//! operations after a restart. A wait for an application exit does not
//! stop observation.
//!
//! Owning specifications: `docs/ACTION_CONTRACTS.md` sections 4, 5, 6,
//! 11, and 12 and `docs/ARCHITECTURE.md` sections 3 and 7.
