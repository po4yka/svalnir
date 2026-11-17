//! Independent validation of a helper request.
//!
//! The helper trusts nothing that the caller says about authority. It
//! decides with its own state ([`HelperState`]): the grants that an
//! administrator approved, the paths and the rules of their roots, its
//! ceilings, its record of consumed requests, and its clock. The identity
//! of the caller comes from the transport
//! ([`CallerIdentity`](crate::request::CallerIdentity)). A path, a pressure
//! measurement, a rule label, an approval flag, a catalog row, or a budget
//! statement of the caller cannot widen a grant: the request has no field
//! for most of them, and decoding rejects an unknown field.
//!
//! | Item | Use |
//! | --- | --- |
//! | [`validate`] | The pure decision on one request. It records nothing. |
//! | [`HelperState::admit`] | The decision and the consumption of the step, in one call. It gives the [`Dispatch`] that an executor needs. |
//! | [`HelperState::record_progress`] | The next state of a consumed step. |
//! | [`ConsumedRequests`] | The bounded record of consumed requests. When it is full, the helper refuses each new mutation request. |
//! | [`EntryPath`], [`RootPath`] | The lexical checks of a target and of a root. |
//! | [`RefusalReason`] | Each reason for a refusal, with its error family and its code. |
//!
//! This module reads no file and no clock and starts no process. The
//! checks of a target here are lexical. The checks of the object itself
//! (its type, its owner, its identifiers, a symbolic link in its path, a
//! mount crossing) are the work of the executor, at the time of the call.
//!
//! Owning specifications: `docs/ARCHITECTURE.md` section 11,
//! `docs/INTERFACES.md` sections 10 and 12, `docs/ACTION_CONTRACTS.md`
//! sections 4 and 11, and `docs/THREAT_MODEL.md`.

mod decide;
mod path;
mod record;
mod refusal;
mod state;

#[cfg(test)]
mod tests;

pub use decide::{
    Admission, BoundedEntry, BoundedEviction, BoundedOperation, Dispatch, Verdict, validate,
};
pub use path::{
    EntryPath, MAX_COMPONENT_BYTES, MAX_PATH_BYTES, MAX_PATH_DEPTH, PathDefect, RootPath,
};
pub use record::{
    ConsumedRequest, ConsumedRequests, MAX_RECORD_CAPACITY, RateUsage, RecordError, StepKey,
    StepStatus,
};
pub use refusal::{Refusal, RefusalReason};
pub use state::{
    ApprovedRoot, GrantLimits, HelperClock, HelperConfig, HelperGrant, HelperState, MAX_GRANTS,
    MAX_ROOTS_PER_GRANT, MAX_RULES_PER_ROOT, RateCeiling, SUPPORTED_ACTION_CLASS, StateError,
};
