//! The process executor.
//!
//! Planned responsibility: `RequestApplicationExit` and
//! `ForceApplicationExit` for one verified application instance and its
//! attributed members, with revalidation of the PID, start time, owner,
//! and executable immediately before each call, a grace period that
//! starts at the submission, and independent observation of the exit. It
//! signals positive individual PIDs only; it has no group form and no
//! process-name selector.
//!
//! Owning specification: `docs/ACTION_CONTRACTS.md` section 8.
