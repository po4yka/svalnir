//! The typed operations of the helper.
//!
//! Planned responsibility: the request type of each supported delegated
//! step, with its parent operation, authenticated principal, exact action
//! class, grant generation, resource scope, target evidence, deadline, and
//! deduplication identity, and the reply type with the delegated step, the
//! observed state, the recording durability, the native result, and the
//! remaining uncertainty. No request has shell text, a script body, a
//! caller-chosen executable, or an unrestricted root path.
//!
//! The shared types are in `svalnir_core::action` and
//! `svalnir_core::authority`.
//!
//! Owning specifications: `docs/INTERFACES.md` section 10 and
//! `docs/ACTION_CONTRACTS.md` sections 3, 11, and 12.
