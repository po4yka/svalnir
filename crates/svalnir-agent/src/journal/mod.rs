//! The operation journal of the user executor.
//!
//! Planned responsibility: the durable implementation of
//! [`svalnir_core::action::Journal`] in `operations.sqlite` in the user
//! state directory (SQLite WAL, `synchronous=FULL`, bounded size), the
//! bounded volatile record of the critical-memory exception
//! ([`svalnir_core::action::VolatileJournal`]), plan storage and single
//! consumption, deduplication of a repeated apply, stop fences, and the
//! queries that restart reconciliation needs. The journal is separate
//! from the rebuildable `catalog.sqlite` of [`crate::store`].
//!
//! Owning specifications: `docs/ACTION_CONTRACTS.md` sections 11 and 12
//! and `docs/ARCHITECTURE.md` section 12.
