//! The rule `project.dependency-directory` of `docs/CLEANUP_RULES.md`
//! section 12: the generated dependency directories of the projects below
//! the directories that the user names.
//!
//! The rule has the inspection mode only, and each of its layouts is
//! `proposed`. It finds no candidate, has no discovery for an eviction,
//! and removes nothing. The inspection reports each generated directory
//! with its evidence: the project marker, whether Git ignores it and
//! tracks no file in it, the activity of the build processes of the
//! project, and its measured size.
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
//! # A name is not sufficient
//!
//! A directory with the name `node_modules`, `.venv`, or `Pods` is a unit
//! only when the parent has the project marker of its layout as a regular
//! file, and the unit has the inner marker of its layout when the layout
//! has one. It is a candidate of a future manual mode only when Git
//! ignores it and the index of the repository has no path in it, so a
//! committed directory with the same name is never a unit. A Cargo
//! `target` directory belongs to `cargo.build-output` (section 8): the
//! inspection names that rule for it and does not measure it.

mod activity;
mod inspect;

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
    RuleExclusions, RuleMode, RuleOwner, RuleRef,
};

pub use activity::{
    BUILD_PROCESS_NAMES, BuildProcesses, NativeProcessEvidence, ProcessEvidence, ProjectProcess,
    is_build_process,
};
pub use inspect::{
    GitAvailability, MAX_SEARCH_ROOTS, ProjectActivity, ProjectHost, ProjectInspection,
    ProjectLimits, ProjectUnitOutcome, ProjectUnitReport, SearchCompletion, SearchRootOutcome,
    SearchRootReport, SearchRoots, VersionControl,
};

use super::caches::ReclaimBasis;
use super::registry::RegistryError;

/// The identity of the rule.
pub const PROJECT_RULE_ID: &str = "project.dependency-directory";

/// The revision of the rule.
pub const PROJECT_RULE_REVISION: &str = "r1";

/// The rule that owns a Cargo `target` directory (section 8). The
/// inspection names it and does not measure the directory.
pub const CARGO_RULE_ID: &str = "cargo.build-output";

/// One layout of the rule: the name of the generated directory, the
/// project marker in its parent, and the marker in the unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProjectLayout {
    /// The name of the generated directory in the project directory.
    pub directory: &'static str,
    /// The layout name of the declaration.
    pub layout: &'static str,
    /// The names of the project markers. One of them must be a regular
    /// file in the parent.
    pub project_markers: &'static [&'static str],
    /// A regular file that the unit must have, when the layout has one.
    pub inner_marker: Option<&'static str>,
    /// What the reclaim figure of a measured unit is.
    pub reclaim: ReclaimBasis,
    /// The owner workflow, as a text for the user. Svalnir does not run it.
    pub owner_workflow: &'static str,
    /// The consequence of a removal.
    pub rebuild_impact: &'static str,
}

/// The layouts of the rule, in the sequence of the specification.
pub const PROJECT_LAYOUTS: [ProjectLayout; 3] = [
    ProjectLayout {
        directory: "node_modules",
        layout: "node-modules",
        project_markers: &["package.json"],
        inner_marker: None,
        // pnpm and Bun link package files from a store with hard links or
        // clones, so the size of the directory is not its exclusive
        // storage.
        reclaim: ReclaimBasis::LinkedIntoProjects,
        owner_workflow: "Remove the directory in the project, then run the install command of the package manager of the project (`npm install`, `pnpm install`, or `yarn install`) when you need it again. Svalnir does not run them.",
        rebuild_impact: "The next install downloads or links each package again, and can run the install scripts of the packages.",
    },
    ProjectLayout {
        directory: ".venv",
        layout: "python-venv",
        project_markers: &["pyproject.toml"],
        inner_marker: Some("pyvenv.cfg"),
        // uv can link files from its cache into an environment with clones
        // or hard links.
        reclaim: ReclaimBasis::LinkedIntoProjects,
        owner_workflow: "Remove the environment, then make it again with the tool of the project (for example `uv sync` or `python3 -m venv .venv` and an install). Svalnir does not run them.",
        rebuild_impact: "The next sync makes the environment again and downloads each package that no cache has. Packages that a person installed by hand are not in the project files and are lost.",
    },
    ProjectLayout {
        directory: "Pods",
        layout: "cocoapods-pods",
        project_markers: &["Podfile"],
        inner_marker: Some("Manifest.lock"),
        reclaim: ReclaimBasis::AllocatedBytes,
        owner_workflow: "Remove the directory, then run `pod install` in the project when you need it again. Svalnir does not run it.",
        rebuild_impact: "The next `pod install` downloads each pod that the cache of CocoaPods does not have, and needs sources that are still available.",
    },
];

/// The directory name and the project marker of the output of Cargo,
/// which [`CARGO_RULE_ID`] owns.
pub const CARGO_TARGET: (&str, &str) = ("target", "Cargo.toml");

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
        layouts: PROJECT_LAYOUTS
            .iter()
            .map(|layout| LayoutSupport {
                layout: layout.layout.to_owned(),
                lifecycle: LifecycleState::Proposed,
            })
            .collect(),
        roots: PROJECT_LAYOUTS
            .iter()
            .map(|layout| {
                Ok(ApprovedRoot {
                    base: RootBase::UserSelected,
                    relative: path(layout.directory)?,
                })
            })
            .collect::<Result<Vec<ApprovedRoot>, RegistryError>>()?,
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
