//! Configuration schema and validation.
//!
//! [`parse_and_validate`] reads the text of a configuration document, schema
//! version 1, and gives a [`Validation`]: a [`ValidatedConfig`] or each
//! [`Finding`], and a [`CheckReport`].
//!
//! # The checks that this module does
//!
//! | Check | Contents |
//! | --- | --- |
//! | [`CheckId::Syntax`] | The text is a TOML document of an accepted size |
//! | [`CheckId::Schema`] | Known keys and tables, value types, the grammars of [`crate::byte_size`] and [`crate::duration`], positive values, enumerations, identifier and path grammars, entries that occur again |
//! | [`CheckId::Relationships`] | The required relationships of `docs/POLICY_SPEC.md` section 3 |
//!
//! # The checks that this module cannot do
//!
//! The module is portable and pure. It does not look up a rule in the
//! registry, resolve a volume selector, verify an application identity, ask
//! a worker for its capabilities, or read a grant. The report gives each of
//! these checks the status [`CheckStatus::RequiresAgent`]. The related
//! values stay as validated text: [`crate::id::RuleId`], [`VolumeSelector`],
//! [`BundleId`], and [`ConfigPath`].
//!
//! A [`ValidatedConfig`] is thus a validated proposal. It is not an
//! effective policy revision, and it does not show that an action is
//! authorized.
//!
//! # Omitted keys
//!
//! Each omitted key has the value of the template, revision
//! [`TEMPLATE_REVISION`]. The relationships are checked on the resulting
//! values. An omitted key never enables a guard or expands authority.
//!
//! Owning specifications: `docs/POLICY_SPEC.md` sections 3 and 4 (schema,
//! validation rules) and `docs/INTERFACES.md` section 13 (the report of
//! `config validate`).

mod check;
mod finding;
mod layout;
mod path;
mod reader;
mod schema;
mod template;
#[cfg(test)]
mod tests;
mod validate;

pub use check::{CheckId, CheckOutcome, CheckReport, CheckStatus};
pub use finding::{Finding, FindingCode, Location};
pub use layout::glob_matches;
pub use path::{ConfigPath, ConfigPathError, ExpandPathError, MAX_PATH_BYTES, PathBase};
pub use reader::{MAX_FINDINGS, MAX_LIST_ENTRIES};
pub use schema::{
    AgentConfig, AppBudget, AppBudgetId, AutomaticMode, BundleId, Cleanup,
    DiskExclusions, DiskGuard, EligibleGroup, GlobalTrigger, History, KEPT_OUT_LAYOUT_NAMES,
    MAX_LAYOUT_DIRECTORY_NAMES, MAX_LAYOUT_ENTRIES, MAX_MARKER_COMPONENTS, MAX_QUIET_PERIOD, MAX_SEARCH_ROOTS, MAX_USER_LAYOUTS, MIN_QUIET_PERIOD,
    MemoryGuard, PROTECTED_HOME_NAMES, Privacy, Profile, ProjectCleanup, Protections,
    RestartPolicy, SCHEMA_VERSION, SKIPPED_DIRECTORY_NAMES, UserLayout, ValidatedConfig,
    VolumeSelector,
};
pub use template::{PERSONAL_FOLDERS, TEMPLATE_REVISION};
pub use validate::{MAX_APP_BUDGETS, MAX_DOCUMENT_BYTES, Validation, parse_and_validate};
