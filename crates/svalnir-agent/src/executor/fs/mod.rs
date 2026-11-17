//! The filesystem executor.
//!
//! Planned responsibility: `MoveToTrash` through the supported Trash
//! operation, and `DeleteSelectedFiles` and `EvictRegenerableData` through
//! descriptor-relative, no-follow removal of a bounded enumeration under
//! an anchored root. Each unit is revalidated against its
//! [`svalnir_core::action::FileBinding`] before the call. A failed Trash
//! move does not become a permanent removal, and a denied user-scope
//! action is not retried as root.
//!
//! Owning specifications: `docs/ACTION_CONTRACTS.md` section 7 and
//! `docs/CLEANUP_RULES.md` sections 6 and 9.
