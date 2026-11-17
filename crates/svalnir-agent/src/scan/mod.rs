//! Volume-aware filesystem scanner.
//!
//! Planned responsibility: a bounded traversal that can be cancelled, with
//! logical and allocated sizes, hard-link deduplication in one mount
//! identity, no traversal across a mount boundary or through a symbolic
//! link, and coverage that shows each skipped or denied region.
//!
//! Owning specification: `docs/RESOURCE_MODEL.md` section 8.
//! `docs/CLEANUP_RULES.md` owns rule scopes.
//!
//! This module has no content yet.
