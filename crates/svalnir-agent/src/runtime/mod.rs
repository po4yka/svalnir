//! The runtime of the agent process.
//!
//! Planned responsibility: startup and shutdown, the collection schedule,
//! restart reconciliation before the first admission, the executor epoch,
//! pause and resume, and the transient coordinator that the CLI starts
//! when no agent runs.
//!
//! Owning specification: `docs/ARCHITECTURE.md` sections 3, 12, and 14.
