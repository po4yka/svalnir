//! The rule `project.dependency-directory` of `docs/CLEANUP_RULES.md`
//! section 12: the generated dependency directories of the projects below
//! the directories that the user names.
//!
//! The rule has the inspection mode and the manual eviction, and no
//! automatic mode. Each of its layouts is `proposed`, so a released build
//! permits no removal under it. The inspection reports each generated
//! directory with its evidence: the project marker, whether Git ignores it
//! and tracks no file in it, the activity of the build processes of the
//! project, the project activity, and its measured size. The discovery for
//! a manual eviction ([`ProjectRequest`]) gives the candidates of each
//! check, and [`recheck_unit`] makes the checks of the layout again before
//! each step.
//!
//! # Roots
//!
//! The inspection examines only the roots of its request ([`SearchRoots`]),
//! each relative to the home directory: the search roots of
//! `[cleanup.projects].search_roots` and of `--root`, which the walk reads,
//! and the project roots that mise records ([`tracked_projects`]), whose
//! units are those of the project directory only. It has no default
//! directory, and the home directory itself is not a root. The walk is
//! bounded by depth, by entries, and by time, follows no symbolic link,
//! and does not cross into another device.
//!
//! # Project activity
//!
//! The inspection assesses the project activity of each unit that Git
//! ignores (`docs/CLEANUP_RULES.md` section 6): the reflog of `HEAD`, the
//! Claude Code transcripts, and, when the configuration turns it on, the
//! Paseo agents. A busy project refuses its unit. A quiet or active project
//! does not refuse it in the inspection. For an eviction, only a quiet
//! project gives predicate 5, or an active project when the request
//! includes active projects ([`ProjectRequest::include_active`]).
//!
//! # A name is not sufficient
//!
//! The layouts are data ([`PROJECT_LAYOUTS`], and the layouts of the
//! configuration with the layout name `user-configured`). A directory with
//! the name of a layout is a unit only when the directory that holds it has
//! a project marker of the layout (a name or a pattern such as `*.csproj`),
//! the unit has the inner marker of the layout when the layout has one, and
//! the unit has no entry at a protected path of the layout. It is a
//! candidate of the manual mode only when Git ignores it and the index
//! of the repository has no path in it, so a committed directory with the
//! same name is never a unit. A directory with a generic name, such as
//! `build`, and no marker is an ordinary directory, which the walk enters.
//! The directory of a layout has one to three names, and its first name can
//! be a pattern such as `cmake-build-*`; a marker can be a directory or a
//! path in a subdirectory. A distinctive directory with no marker of a
//! layout with [`Unmarked::ManualOnly`] is a unit of the unmarked layout
//! name of the layout only when the request allows it (`--allow-unmarked`),
//! for a manual plan only.
//! A Cargo `target` directory is the layout `cargo-target`; the rule
//! `cargo.build-output` is retired and its identity stays reserved.
//!
//! # Layouts of the configuration
//!
//! `[[cleanup.projects.layouts]]` supplies more layouts as parameters of
//! this rule. Each check applies to them unchanged. Their layout name
//! `user-configured` never permits an automatic mode
//! ([`svalnir_core::rule::LayoutSupport::permits`]).

mod activity;
mod discover;
mod inspect;
mod layouts;
mod mise;
mod recency;

#[cfg(test)]
mod discover_tests;
#[cfg(test)]
mod evidence_tests;
#[cfg(test)]
mod layouts_tests;
#[cfg(test)]
mod recency_tests;
#[cfg(test)]
mod tests;

use svalnir_core::action::{Checked, ExecutorRole, FileObjectType, WorkCharge};
use svalnir_core::file::LosslessPath;
use svalnir_core::id::{RuleId, RuleRevisionId};
use svalnir_core::policy::RebuildCost;
use svalnir_core::quantity::{Bytes, EntryCount, Nanoseconds};
use svalnir_core::rule::{
    ActivityCheck, ActivityProtocol, AgeBasis, ApprovedRoot, DeletionMethod, LayoutSupport,
    LifecycleState, OwnerAttribution, Retention, RootBase, Rule, RuleBudget, RuleDeclaration,
    RuleExclusions, RuleMode, RuleOwner, RuleRef, USER_CONFIGURED_LAYOUT,
};

pub(in crate::rules) use activity::inventory;
pub use activity::{
    BUILD_PROCESS_NAMES, BuildProcesses, NativeProcessEvidence, ProcessEvidence, ProjectProcess,
    is_build_process,
};
pub(in crate::rules) use discover::ProjectDiscoveryInput;
pub use discover::{EnvironmentEvidence, ProjectRequest, examined_for};
pub(in crate::rules) use inspect::open_search_root;
pub use inspect::{
    ArgumentRootError, GitAvailability, IN_SEARCH_ROOT, IgnoreBasis, MAX_PROJECT_ROOTS,
    MAX_SEARCH_ROOTS, PROJECT_MARKER_ABSENT_ALLOWED, ProjectActivity, ProjectHost,
    ProjectInspection, ProjectLimits, ProjectUnitOutcome, ProjectUnitReport, REPEATED_ROOT,
    RecheckInput, RootKind, RootSource, SearchCompletion, SearchRootEntry, SearchRootOutcome,
    SearchRootReport, SearchRoots, UNIT_ABSENT, UnitRecheck, VersionControl, argument_root,
    recheck_unit,
};
pub use layouts::{
    DirectoryName, MarkerKind, PROJECT_LAYOUT_COUNT, PROJECT_LAYOUTS, PackageCheckouts,
    ProjectLayout, ProjectMarker, USER_LAYOUT_IMPACT, USER_LAYOUT_WORKFLOW, Unmarked,
};
pub use mise::{
    IgnoredLink, MAX_LINK_BYTES, MAX_TRACKED_CONFIGS, MiseDiscovery, MiseLocations, MiseRoot,
    MiseState, project_root, tracked_projects,
};
pub use recency::{
    ActivitySource, AgentListing, AgentReading, AgentStatus, ClaudeTranscripts, GitHeadActivity,
    HeadActivity, MAX_FOLDER_UNITS, MAX_PASEO_OUTPUT, MAX_TRANSCRIPT_ENTRIES,
    MAX_TRANSCRIPT_FOLDERS, PASEO_ARGUMENTS, PASEO_CANDIDATES, PASEO_DEADLINE, PaseoAgents,
    ProjectRecency, RecencyHost, RecencyState, SourceReading, TranscriptActivity, assess,
    assess_with_head, encode_folder, quiet_period,
};

use super::registry::RegistryError;

/// The identity of the rule.
pub const PROJECT_RULE_ID: &str = "project.dependency-directory";

/// The revision of the rule. Revision `r3` adds the manual eviction and
/// accepts a symbolic link below a unit, which the executor removes and
/// does not follow. Revision `r4` adds 64 layouts, the markers in a
/// subdirectory and of a directory, the pattern names, the units of three
/// names and of `.cache`, the unmarked layout names, the user layouts with
/// a first name of the table, the evidence of an own ignore file, and the
/// overlap of the units of nested project directories.
pub const PROJECT_RULE_REVISION: &str = "r4";

const MINUTE: u64 = 60_000_000_000;
const DAY: u64 = 86_400_000_000_000;
const GIBIBYTE: u64 = 1 << 30;

/// The age after which the process evidence of the rule is not current.
pub const PROJECT_EVIDENCE_EXPIRY: Nanoseconds = Nanoseconds::new(30_000_000_000);

/// The declaration of the rule. Each layout is `proposed`; the
/// implementation has the inspection mode and the manual eviction, and no
/// automatic eviction.
///
/// The retention, the activity windows, and the budget are values of a
/// proposed rule. No promotion record confirms them (section 3).
fn declaration(table: &[ProjectLayout]) -> Result<RuleDeclaration, RegistryError> {
    let path = |text: &str| {
        LosslessPath::from_bytes(text).map_err(|_| RegistryError::Declaration("a path"))
    };
    // One root for each directory of the catalog: two layouts can have the
    // same directory, for example `target`. The roots of the base
    // `user_selected` are hints only: the discovery for an eviction gives
    // them no path, and the approved root of a unit is its generated
    // directory below a root of the request. A layout of the configuration
    // has no entry here, because its directory is known only at run time.
    // The approved root of a manual plan is the root of the request that
    // the discovery bound (`docs/CLEANUP_RULES.md` section 12, "Approved
    // roots"), for each layout and for `user-configured`.
    let mut roots: Vec<ApprovedRoot> = Vec::new();
    for layout in table {
        let root: ApprovedRoot = ApprovedRoot {
            base: RootBase::UserSelected,
            relative: path(layout.directory)?,
        };
        if !roots.contains(&root) {
            roots.push(root);
        }
    }
    Ok(RuleDeclaration {
        reference: RuleRef {
            id: RuleId::new(PROJECT_RULE_ID)
                .map_err(|_| RegistryError::Declaration("the rule identity"))?,
            revision: RuleRevisionId::new(PROJECT_RULE_REVISION)
                .map_err(|_| RegistryError::Declaration("the rule revision"))?,
        },
        owner: RuleOwner {
            producer: "project".to_owned(),
            attribution: OwnerAttribution::ProducerLayout,
        },
        // The layouts of the catalog, then the layout names of their
        // unmarked units, then the one layout of the layouts of the
        // configuration. Each one is `proposed`; an unmarked layout name and
        // `user-configured` permit at most a manual mode also after a
        // promotion (`svalnir_core::rule::is_manual_only_layout`).
        layouts: table
            .iter()
            .map(|layout| layout.layout)
            .chain(table.iter().filter_map(|layout| match layout.unmarked {
                Unmarked::Never => None,
                Unmarked::ManualOnly { layout } => Some(layout),
            }))
            .chain([USER_CONFIGURED_LAYOUT])
            .map(|layout| LayoutSupport {
                layout: layout.to_owned(),
                lifecycle: LifecycleState::Proposed,
            })
            .collect(),
        roots,
        retention: Retention {
            age_basis: AgeBasis::FilesystemMetadata,
            minimum_age: Nanoseconds::new(7 * DAY),
        },
        activity: ActivityProtocol {
            checks: vec![ActivityCheck::ProducerProcessAbsent],
            quiescence: Nanoseconds::new(10 * MINUTE),
            evidence_expiry: PROJECT_EVIDENCE_EXPIRY,
        },
        exclusions: RuleExclusions {
            descendants: Vec::new(),
            // A unit such as `node_modules` has symbolic links, for example
            // in `.bin`. The executor removes a link and does not follow
            // it, and the measurement does not count its target.
            supported_object_types: vec![
                FileObjectType::RegularFile,
                FileObjectType::Directory,
                FileObjectType::SymbolicLink,
            ],
            skip_hard_linked: true,
        },
        // No automatic mode: the rule is for a manual eviction only
        // (owner decision of 2026-11-22).
        modes: vec![RuleMode::Inspection, RuleMode::ManualEviction],
        deletion_method: DeletionMethod::BoundedUnlink,
        executor: ExecutorRole::User,
        rebuild_cost: RebuildCost::Medium,
        budget: RuleBudget {
            per_candidate: WorkCharge::new(Bytes::new(20 * GIBIBYTE), EntryCount::new(2_000_000)),
            per_pass: WorkCharge::new(Bytes::new(100 * GIBIBYTE), EntryCount::new(4_000_000)),
            measurement_expiry: Nanoseconds::new(10 * MINUTE),
        },
    })
}

/// The rule `project.dependency-directory`: its checked declaration and
/// the table of its layouts.
#[derive(Debug, Clone)]
pub struct ProjectRule {
    rule: Rule,
    table: &'static [ProjectLayout],
}

impl ProjectRule {
    /// Makes the rule with the declaration of this build.
    ///
    /// # Errors
    ///
    /// Returns a [`RegistryError`] when the declaration is not complete.
    pub(super) fn new() -> Result<Self, RegistryError> {
        Self::with_table(&PROJECT_LAYOUTS)
    }

    /// Makes the rule with the layouts of the table `table`. A test gives
    /// synthetic layouts here, so that a capability of the walk is proven
    /// with no layout of [`PROJECT_LAYOUTS`].
    pub(super) fn with_table(table: &'static [ProjectLayout]) -> Result<Self, RegistryError> {
        let rule: Rule = Checked::new(declaration(table)?).map_err(RegistryError::Incomplete)?;
        Ok(Self { rule, table })
    }

    /// The layouts of the table of the rule.
    pub(super) fn table(&self) -> &'static [ProjectLayout] {
        self.table
    }

    /// The rule with `lifecycle` for each layout, limited to a manual
    /// mode: a state that permits an automatic eviction becomes
    /// [`LifecycleState::ManualActionValidated`] with the same evidence.
    /// Only a test build has this function
    /// ([`super::ReviewedRules::with_fixture_lifecycle`]).
    #[cfg(any(test, all(feature = "test-support", debug_assertions)))]
    pub(super) fn with_lifecycle(self, lifecycle: &LifecycleState) -> Result<Self, RegistryError> {
        let manual: LifecycleState = match lifecycle {
            LifecycleState::AutomaticEvictionValidated { evidence } => {
                LifecycleState::ManualActionValidated {
                    evidence: evidence.clone(),
                }
            }
            other => other.clone(),
        };
        Ok(Self {
            rule: super::registry::with_lifecycle(&self.rule, &manual)?,
            table: self.table,
        })
    }

    /// The checked declaration of the rule revision.
    pub fn rule(&self) -> &Rule {
        &self.rule
    }
}
