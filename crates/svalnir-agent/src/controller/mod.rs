//! The guard controllers.
//!
//! Planned responsibility: background disk protection and application
//! budgets. A controller gives fresh observations and the incident state
//! to the pure evaluation of [`svalnir_core::policy`], makes a plan from
//! the decision, gives the plan to the coordinator, remeasures after each
//! bounded step, and keeps the incident budgets, the cooldowns, and the
//! backoff.
//!
//! Owning specification: `docs/POLICY_SPEC.md`.
