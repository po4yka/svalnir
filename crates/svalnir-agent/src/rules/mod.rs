//! The cleanup rule registry and the reviewed rules.
//!
//! Planned responsibility: the implementation of
//! [`svalnir_core::rule::RuleRegistry`] and the two rules of Milestone 2,
//! `svalnir.expired-temporary` and `xcode.inactive-derived-data`: root
//! discovery and identity binding, bounded candidate enumeration, the
//! eligibility evidence of each candidate
//! ([`svalnir_core::rule::CandidateEligibility`]), and the work charge.
//! A rule reads the filesystem. It removes nothing: removal is in
//! [`crate::executor::fs`].
//!
//! Owning specification: `docs/CLEANUP_RULES.md`.
