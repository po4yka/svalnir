//! The cleanup rule registry and the reviewed rules.
//!
//! Owning specification: `docs/CLEANUP_RULES.md`. A rule finds candidates
//! and states the facts that make each one eligible or not. A rule reads
//! the filesystem. It removes nothing: removal is in
//! [`crate::executor::fs`], after planning and admission.
//!
//! # Use
//!
//! 1. Make the registry: [`ReviewedRules::new`]. It implements
//!    [`svalnir_core::rule::RuleRegistry`]. [`ReviewedRules::lookup`] and
//!    [`ReviewedRules::lifecycle`] refuse an unknown rule, revision, or
//!    layout. Each layout of this build is `proposed`, which permits no
//!    mode, so `resolve` refuses each mode.
//! 2. Bind an approved root ([`RootBinding`]) and call the `discover`
//!    function of a rule ([`ExpiredTemporaryRule::discover`],
//!    [`XcodeDerivedDataRule::discover`]) on a worker thread, with a
//!    [`DiscoveryControl`] for the bounds and the cancellation. During a
//!    resource emergency, use [`DiscoveryMode::KnownCandidatesOnly`].
//! 3. Give the candidates of each rule to [`ReviewedRules::claim`], which
//!    gives each overlapping path to one rule revision and reports the
//!    conflicts.
//! 4. A [`DiscoveredCandidate`] has the candidate for the disk policy
//!    ([`svalnir_core::rule::RuleCandidate`]), the identity evidence for
//!    the executor, and [`DiscoveredCandidate::file_binding`] for the
//!    plan builder.
//!
//! # What a discovery establishes
//!
//! A discovery gives evidence for a plan. It is not a guard of a removal:
//! each path check is a check of a name at one time, and the executor
//! examines each object again before its step. A rule establishes
//! predicates 1, 2, 4, 5, 6, 7, and 8 of the specification. Predicates 3
//! (authorized scope), 9 (resources), and 10 (fresh check) stay `unknown`
//! until admission, so no candidate of a discovery is eligible.

#[cfg(unix)]
mod eviction;
#[cfg(unix)]
mod expired_temporary;
#[cfg(all(unix, any(test, all(feature = "test-support", debug_assertions))))]
pub mod fixture;
#[cfg(unix)]
mod model;
#[cfg(unix)]
mod native;
#[cfg(unix)]
mod overlap;
#[cfg(unix)]
mod plist;
#[cfg(unix)]
mod registry;
#[cfg(unix)]
mod unit;
#[cfg(unix)]
mod xcode;

#[cfg(test)]
#[cfg(unix)]
mod eviction_tests;
#[cfg(test)]
#[cfg(unix)]
mod tests;

#[cfg(unix)]
pub use eviction::{
    BoundRoot, DiscoveryEnvironment, DiscoveryHost, EvictionCandidate, EvictionDiscovery,
    EvictionRequest, ProducerActivity, RootProblem, RootReport, RootResult, SharedEnvironment,
    SourceEnvironment, automatic_roots, bind_root, resolve_roots, root_id_of, xcode_evidence,
};
#[cfg(unix)]
pub use expired_temporary::{
    CONTENT_REGENERABLE_INTERMEDIATE, EXPIRED_TEMPORARY_LAYOUT, EXPIRED_TEMPORARY_REVISION,
    EXPIRED_TEMPORARY_RULE_ID, ExpiredTemporaryRule, ITEM_RECORD_KIND, ITEM_RECORD_NAME,
    ROOT_MARKER_KIND, ROOT_MARKER_NAME, TEMPORARY_SCHEMA_VERSION, TemporaryEvidence,
    TemporaryItemRecord, TemporaryRootMarker, UseLeases,
};
#[cfg(unix)]
pub use model::{
    ChangeStamp, DiscoveredCandidate, Discovery, DiscoveryCompletion, DiscoveryControl,
    DiscoveryError, DiscoveryLimits, DiscoveryMode, DiscoveryScope, MAX_SKIPPED_LIMIT,
    MAX_UNITS_LIMIT, MeasurementSource, ReclaimEstimate, RootBinding, RootEvidence, SizeMeasure,
    SkipCategory, SkipReason, SkippedUnit, TargetEvidence, UnitMeasurement,
};
#[cfg(unix)]
pub use overlap::{
    Claim, MAX_REPORTED_CONFLICTS, OverlapConflict, OverlapKind, OverlapResolution,
    resolve_overlaps,
};
#[cfg(unix)]
pub use registry::{ClaimError, RegistryError, ReviewedRules, RuleStatus};
#[cfg(unix)]
pub use xcode::{
    BUILD_CONFIGURATIONS, INDEX_CHILDREN, INTERMEDIATES_CHILDREN, PLATFORM_SUFFIXES,
    ProducerProcesses, SHARED_ROOT_ENTRIES, UNIT_PATHS, XCODE_DERIVED_DATA_LAYOUT,
    XCODE_DERIVED_DATA_REVISION, XCODE_DERIVED_DATA_RULE_ID, XCODE_PRODUCER_EXECUTABLES,
    XcodeDerivedDataRule, XcodeEvidence,
};
