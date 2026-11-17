//! Independent validation of a helper request.
//!
//! Planned responsibility: the pure checks that the helper does on each
//! request before it acts: the authenticated principal, the generation
//! and the ceilings of its own `svalnir_core::authority::PrivilegeGrant`,
//! the approved root and scope, the action class, the deadline, and the
//! deduplication state. A path, a pressure measurement, a rule label, an
//! approval flag, a catalog row, or a budget claim of the caller cannot
//! widen the grant.
//!
//! Owning specifications: `docs/ARCHITECTURE.md` section 11,
//! `docs/INTERFACES.md` section 10, and `docs/THREAT_MODEL.md`.
