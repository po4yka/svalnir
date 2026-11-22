//! The rule `project.dependency-directory` of `docs/CLEANUP_RULES.md`
//! section 12: the generated dependency directories of the projects below
//! the directories that the user names.
//!
//! The rule has the inspection mode only, and each of its layouts is
//! `proposed`. It finds no candidate, has no discovery for an eviction,
//! and removes nothing. The inspection reports each generated directory
//! with its evidence: the project marker, whether Git ignores it and
//! tracks no file in it, the activity of the build processes of the
//! project, the project activity, and its measured size.
//!
//! # Search roots
//!
//! The inspection examines only the directories that its caller names
//! ([`SearchRoots`]), each relative to the home directory, for example
//! `Developer`. It has no default directory, and the home directory
//! itself is not a search root. The walk is bounded by depth, by entries,
//! and by time, follows no symbolic link, and does not cross into another
//! device.
//!
//! # Project activity
//!
//! The inspection assesses the project activity of each unit that Git
//! ignores (`docs/CLEANUP_RULES.md` section 6): the reflog of `HEAD`, the
//! Claude Code transcripts, and, when the configuration turns it on, the
//! Paseo agents. A busy project refuses its unit. A quiet or active project
//! does not: the state is evidence for a later selection, and
//! [`ProjectRecency::fact`] gives its value for predicate 5.
//!
//! # A name is not sufficient
//!
//! The layouts are data ([`PROJECT_LAYOUTS`], and the layouts of the
//! configuration with the layout name `user-configured`). A directory with
//! the name of a layout is a unit only when the directory that holds it has
//! a project marker of the layout (a name or a pattern such as `*.csproj`),
//! the unit has the inner marker of the layout when the layout has one, and
//! the unit has no entry at a protected path of the layout. It is a
//! candidate of a future manual mode only when Git ignores it and the index
//! of the repository has no path in it, so a committed directory with the
//! same name is never a unit. A directory with a generic name, such as
//! `build`, and no marker is an ordinary directory, which the walk enters.
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
mod inspect;
mod layouts;
mod recency;

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

pub use activity::{
    BUILD_PROCESS_NAMES, BuildProcesses, NativeProcessEvidence, ProcessEvidence, ProjectProcess,
    is_build_process,
};
pub(in crate::rules) use inspect::open_search_root;
pub use inspect::{
    GitAvailability, MAX_SEARCH_ROOTS, ProjectActivity, ProjectHost, ProjectInspection,
    ProjectLimits, ProjectUnitOutcome, ProjectUnitReport, SearchCompletion, SearchRootOutcome,
    SearchRootReport, SearchRoots, VersionControl,
};
pub use layouts::{
    DirectoryName, MarkerKind, PROJECT_LAYOUT_COUNT, PROJECT_LAYOUTS, PackageCheckouts,
    ProjectLayout, ProjectMarker, USER_LAYOUT_IMPACT, USER_LAYOUT_WORKFLOW,
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

/// The revision of the rule.
pub const PROJECT_RULE_REVISION: &str = "r2";

const MINUTE: u64 = 60_000_000_000;
const DAY: u64 = 86_400_000_000_000;
const GIBIBYTE: u64 = 1 << 30;

/// The declaration of the rule. Each layout is `proposed`, and the
/// implementation has the inspection mode only, so no lifecycle state,
/// also a fixture state, can permit a removal.
///
/// The retention, the activity windows, and the budget are values of a
/// proposed rule. No promotion record confirms them (section 3).
fn declaration() -> Result<RuleDeclaration, RegistryError> {
    let path = |text: &str| {
        LosslessPath::from_bytes(text).map_err(|_| RegistryError::Declaration("a path"))
    };
    // One root for each directory of the catalog: two layouts can have the
    // same directory, for example `target`.
    let mut roots: Vec<ApprovedRoot> = Vec::new();
    for layout in &PROJECT_LAYOUTS {
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
        // The layouts of the catalog, then the one layout of the layouts of
        // the configuration. Each one is `proposed`; `user-configured`
        // permits at most a manual mode also after a promotion.
        layouts: PROJECT_LAYOUTS
            .iter()
            .map(|layout| layout.layout)
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
            evidence_expiry: Nanoseconds::new(30_000_000_000),
        },
        exclusions: RuleExclusions {
            descendants: Vec::new(),
            supported_object_types: vec![FileObjectType::RegularFile, FileObjectType::Directory],
            skip_hard_linked: true,
        },
        modes: vec![RuleMode::Inspection],
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

/// The rule `project.dependency-directory`: its checked declaration.
#[derive(Debug, Clone)]
pub struct ProjectRule {
    rule: Rule,
}

impl ProjectRule {
    /// Makes the rule with the declaration of this build.
    ///
    /// # Errors
    ///
    /// Returns a [`RegistryError`] when the declaration is not complete.
    pub(super) fn new() -> Result<Self, RegistryError> {
        let rule: Rule = Checked::new(declaration()?).map_err(RegistryError::Incomplete)?;
        Ok(Self { rule })
    }

    /// The checked declaration of the rule revision.
    pub fn rule(&self) -> &Rule {
        &self.rule
    }
}
