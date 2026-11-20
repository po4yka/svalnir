//! The rule `git.linked-worktree` of `docs/CLEANUP_RULES.md` section 12:
//! the linked worktrees of the Git repositories below the directories
//! that the user names.
//!
//! The rule has the inspection mode only, and its layout is `proposed`.
//! It finds no candidate, has no discovery for an eviction, and removes
//! nothing. A worktree can hold work that exists nowhere else, so its
//! removal is manual only, by the specification, and needs the
//! preservation of that work first; this build has no removal. The
//! inspection reports, for each linked worktree, its branch or detached
//! state, whether its index has changes that no commit has, how many
//! tracked files changed in its work tree, how many files Git does not
//! track, and how many commits of its `HEAD` no local branch has.

mod index;
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

pub(in crate::rules) use inspect::MAX_DIRECTORY_ENTRIES;
pub use inspect::{
    Evidence, RepositoryReport, UntrackedFiles, WorktreeHead, WorktreeHost, WorktreeInspection,
    WorktreeLimits, WorktreePresence, WorktreeReport, WorktreeVerdict,
};

use super::registry::RegistryError;

/// The identity of the rule.
pub const WORKTREE_RULE_ID: &str = "git.linked-worktree";

/// The revision of the rule.
pub const WORKTREE_RULE_REVISION: &str = "r1";

/// The layout of the rule: a linked worktree with its record in
/// `.git/worktrees/NAME` of the main repository.
pub const WORKTREE_LAYOUT: &str = "git-linked-worktree";

const MINUTE: u64 = 60_000_000_000;
const DAY: u64 = 86_400_000_000_000;
const GIBIBYTE: u64 = 1 << 30;

/// The declaration of the rule. Its layout is `proposed`, the
/// implementation has the inspection mode only, and the deletion method is
/// the operation of the producer (`git worktree remove`), which this build
/// does not run.
///
/// The retention, the activity windows, and the budget are values of a
/// proposed rule. No promotion record confirms them (section 3).
fn declaration() -> Result<RuleDeclaration, RegistryError> {
    Ok(RuleDeclaration {
        reference: RuleRef {
            id: RuleId::new(WORKTREE_RULE_ID)
                .map_err(|_| RegistryError::Declaration("the rule identity"))?,
            revision: RuleRevisionId::new(WORKTREE_RULE_REVISION)
                .map_err(|_| RegistryError::Declaration("the rule revision"))?,
        },
        owner: RuleOwner {
            producer: "git".to_owned(),
            attribution: OwnerAttribution::ProducerIndex,
        },
        layouts: vec![LayoutSupport {
            layout: WORKTREE_LAYOUT.to_owned(),
            lifecycle: LifecycleState::Proposed,
        }],
        // The records of the linked worktrees of a repository that the
        // walk finds below a directory that the user names.
        roots: vec![ApprovedRoot {
            base: RootBase::UserSelected,
            relative: LosslessPath::from_bytes(".git/worktrees")
                .map_err(|_| RegistryError::Declaration("a path"))?,
        }],
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
            supported_object_types: vec![FileObjectType::Directory],
            skip_hard_linked: true,
        },
        modes: vec![RuleMode::Inspection],
        deletion_method: DeletionMethod::ProducerOperation,
        executor: ExecutorRole::User,
        rebuild_cost: RebuildCost::High,
        budget: RuleBudget {
            per_candidate: WorkCharge::new(Bytes::new(50 * GIBIBYTE), EntryCount::new(2_000_000)),
            per_pass: WorkCharge::new(Bytes::new(100 * GIBIBYTE), EntryCount::new(4_000_000)),
            measurement_expiry: Nanoseconds::new(10 * MINUTE),
        },
    })
}

/// The rule `git.linked-worktree`: its checked declaration.
#[derive(Debug, Clone)]
pub struct WorktreeRule {
    rule: Rule,
}

impl WorktreeRule {
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
