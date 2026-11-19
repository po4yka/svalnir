//! The executor of the accepted operations.
//!
//! The helper has one operation with an effect:
//! [`BoundedEviction`], the permanent
//! removal of listed entries below one approved root. [`EvictionExecutor`]
//! is the interface of its executor, and [`FsEvictor`] does it on the
//! filesystem of the host.
//!
//! # What the executor checks again
//!
//! The validation is lexical: it reads no file. The executor checks each
//! target again at the time of its call, with descriptor-relative calls
//! that follow no symbolic link (`docs/ACTION_CONTRACTS.md` section 7 and
//! `docs/THREAT_MODEL.md`, `T-04`):
//!
//! | Check | Result when it fails |
//! | --- | --- |
//! | Before each entry: the gate of the service (the grant, the root, the rule, and the deadline of the step, on a new clock reading) | This entry and each later entry are `Skipped`, with no call |
//! | The root opens from `/` name by name, with no symbolic link | Each entry is `Skipped` |
//! | The root is a directory of the helper user or of user 0, and no other user can write to it | Each entry is `Skipped` |
//! | The root is on a local filesystem | Each entry is `Skipped` |
//! | Each directory between the root and the object opens with no symbolic link, is on the filesystem of the root, is a directory of the helper user or of user 0, and no other user can write to it | The entry is `Skipped` |
//! | The object has the type and the native identifiers of the request | The entry is `Skipped` (`helper_target_changed`) |
//! | The object is owned by the helper user or by user 0, has one link, is not dataless, and is not larger than the bound of the entry | The entry is `Skipped` |
//!
//! # Bounded effects
//!
//! One entry is one `unlinkat` call. A directory is removed only when it is
//! empty (`AT_REMOVEDIR`); the executor never removes the content of a
//! directory and never enumerates one. The number of calls is thus not
//! larger than the number of entries of the request.
//!
//! # What the executor cannot do
//!
//! macOS has no removal call that is conditional on the identity of the
//! object. An actor that can write to the parent directory can replace the
//! object between the check and the call. The executor thus requires
//! directories that only the helper user and user 0 can write to, and each
//! removal has the attribution `possible`.

mod fs;

#[cfg(test)]
mod tests;

pub use fs::FsEvictor;
use svalnir_core::time::WallTime;

use crate::response::EntryReport;
use crate::validation::{BoundedEviction, RefusalReason};

/// The result of one execution of an eviction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Execution {
    /// One report for each entry of the eviction, in its sequence.
    pub entries: Vec<EntryReport>,
    /// The reason for which the gate stopped the execution before an
    /// entry, when it did.
    pub stopped: Option<RefusalReason>,
}

/// The check that the executor makes before each entry.
///
/// The service supplies the gate. It reads the clock and asks the state of
/// the helper whether the record still covers the step
/// ([`HelperState::still_covers`](crate::validation::HelperState::still_covers)).
/// `Ok` has the wall-clock time of the check.
pub type Gate<'gate> = dyn FnMut() -> Result<WallTime, RefusalReason> + 'gate;

/// The executor of an accepted eviction.
pub trait EvictionExecutor: Send {
    /// Does the eviction and reports each entry.
    ///
    /// The executor calls `gate` before each entry and submits no call
    /// after the gate refused. The result has one report for each entry of
    /// `eviction`, also when the execution stopped early.
    fn evict(&mut self, eviction: &BoundedEviction, gate: &mut Gate<'_>) -> Execution;
}
