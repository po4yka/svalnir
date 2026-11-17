//! Activation and grant logic.
//!
//! Planned responsibility: the pure decisions that activate a
//! [`PolicyRevision`](crate::authority::PolicyRevision) against an expected
//! revision, make, change, and revoke an
//! [`ActionGrant`](crate::authority::ActionGrant) with a new generation,
//! check a plan binding against the current records, and rearm an incident
//! budget. The module does no storage: the caller reads and writes the
//! records.
//!
//! Owning specifications: `docs/ARCHITECTURE.md` section 11,
//! `docs/ACTION_CONTRACTS.md` sections 4 and 11, `docs/POLICY_SPEC.md`,
//! and `docs/INTERFACES.md` sections 5 and 13.
