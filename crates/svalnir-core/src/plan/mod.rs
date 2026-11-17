//! The manual plan builder.
//!
//! Planned responsibility: build an immutable [`Plan`](crate::action::Plan)
//! for a manual cleanup (`MoveToTrash`, `DeleteSelectedFiles`, or manual
//! `EvictRegenerableData`) and for a manual application stop, from
//! selected targets, their verified bindings, and the effective policy
//! revision. The builder is pure: the caller supplies the identities, the
//! evidence, and the clock. It reserves nothing and authorizes nothing.
//!
//! Owning specifications: `docs/ACTION_CONTRACTS.md` sections 2, 3, and 7,
//! `docs/INTERFACES.md` sections 5 and 6, and `docs/POLICY_SPEC.md` for
//! `manual_plan_ttl`.
