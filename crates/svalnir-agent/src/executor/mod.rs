//! The executors of the user agent.
//!
//! An executor does one bounded step of an admitted operation from a
//! [`svalnir_core::action::RequestEnvelope`] and returns the observed
//! [`svalnir_core::action::TargetResult`] values. It revalidates the
//! target identity immediately before the external call. It does not
//! decide policy, and it does not write the journal: the coordinator
//! records the intent and consumes the dispatch before it calls an
//! executor.
//!
//! | Module | Planned responsibility |
//! | --- | --- |
//! | [`fs`] | Trash move and permanent removal |
//! | [`process`] | Graceful termination and force escalation |
//!
//! Owning specification: `docs/ACTION_CONTRACTS.md` sections 7 and 8.

pub mod fs;
pub mod process;
