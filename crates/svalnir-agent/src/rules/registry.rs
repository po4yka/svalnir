//! The registry of the reviewed rules of this build.
//!
//! `docs/CLEANUP_RULES.md` sections 2 and 10 own the contract. The
//! registry has the two rules of Milestone 2, the six package and build
//! cache rules of section 10 ([`super::caches`]), and the rule of the
//! project dependency directories ([`super::projects`]), and the three
//! rules of the data that only its owner tool removes
//! ([`super::owner_tools`]), and the rule of the linked Git worktrees
//! ([`super::worktrees`]), and the rules with an owner operation
//! ([`super::producers`]). Of the eleven rules after the first two, the
//! project rule has the inspection mode and the manual eviction, and the
//! other ten have the inspection mode only, except that five of them have
//! a new revision with an owner operation. Each layout of each rule is
//! `proposed`, because no validation record under `docs/VALIDATION.md`
//! exists for a rule. The registry has no function that changes a
//! lifecycle state: a promotion is a new declaration with a reference to
//! its recorded evidence, in a new build.
//!
//! The registry also has the clear rules of [`super::clear`]: each one has
//! the inspection mode and the manual eviction, and no automatic mode.

use svalnir_core::policy::MAX_CLEANUP_CANDIDATES;
use svalnir_core::rule::owner::OwnerOperation;
use svalnir_core::rule::{
    LifecycleState, Rule, RuleDeclarationError, RuleMode, RuleRef, RuleRefusal, RuleRegistry,
};
use thiserror::Error;

use super::caches::{CacheRule, cache_rules};
use super::clear::{ClearRule, ClearRules};
use super::expired_temporary::ExpiredTemporaryRule;
use super::model::DiscoveredCandidate;
use super::overlap::{OverlapResolution, resolve_overlaps};
use super::owner_tools::OwnerToolRules;
use super::producers::{ProducerRule, producer_rules};
use super::projects::ProjectRule;
use super::worktrees::WorktreeRule;
use super::xcode::XcodeDerivedDataRule;

/// The reason the registry cannot be made. Each case is a defect of a
/// declaration of this build.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RegistryError {
    /// A constant of a declaration does not fit its type.
    #[error("a declaration has a value that its type rejects: {0}")]
    Declaration(&'static str),
    /// A declaration is not complete.
    #[error("a declaration is not complete")]
    Incomplete(#[source] RuleDeclarationError),
}

/// The reason the registry does not resolve the overlaps of a candidate
/// list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ClaimError {
    /// The list is longer than the largest candidate list of the policy.
    #[error("the candidate list is longer than the policy permits")]
    TooManyCandidates,
    /// A candidate names a rule revision that is not registered.
    #[error("a candidate names a rule revision that is not registered")]
    Unregistered(#[source] RuleRefusal),
    /// A candidate carries a lifecycle state that is not the state of the
    /// registry for its rule revision and layout.
    #[error("a candidate carries a lifecycle state that the registry does not record")]
    LifecycleMismatch,
}

/// The declaration of `rule` with `lifecycle` for each layout.
#[cfg(any(test, all(feature = "test-support", debug_assertions)))]
pub(super) fn with_lifecycle(
    rule: &Rule,
    lifecycle: &LifecycleState,
) -> Result<Rule, RegistryError> {
    let mut declaration: svalnir_core::rule::RuleDeclaration = (**rule).clone();
    for layout in &mut declaration.layouts {
        layout.lifecycle = lifecycle.clone();
    }
    svalnir_core::action::Checked::new(declaration).map_err(RegistryError::Incomplete)
}

/// The lifecycle state of one rule revision for one layout, with the
/// modes that the state permits. Admission reads this record; it has no
/// other source for the state of a rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleStatus {
    /// The exact rule revision.
    pub reference: RuleRef,
    /// The layout.
    pub layout: String,
    /// The lifecycle state of the revision for the layout.
    pub lifecycle: LifecycleState,
    /// The modes of the implementation that the state permits. The list
    /// is empty for a `proposed` layout.
    pub permitted_modes: Vec<RuleMode>,
}

/// The reviewed rules of this build.
#[derive(Debug, Clone)]
pub struct ReviewedRules {
    expired_temporary: ExpiredTemporaryRule,
    xcode_derived_data: XcodeDerivedDataRule,
    caches: Vec<CacheRule>,
    projects: ProjectRule,
    owner_tools: OwnerToolRules,
    worktrees: WorktreeRule,
    clear: ClearRules,
    producers: Vec<ProducerRule>,
}

impl ReviewedRules {
    /// Makes the registry with the rules of this build.
    ///
    /// # Errors
    ///
    /// Returns a [`RegistryError`] when a declaration of this build is
    /// not complete. A test makes the registry, so a released build does
    /// not return this error.
    pub fn new() -> Result<Self, RegistryError> {
        let caches: Vec<CacheRule> = cache_rules()?;
        let owner_tools: OwnerToolRules = OwnerToolRules::new()?;
        let producers: Vec<ProducerRule> = producer_rules(|id| {
            caches
                .iter()
                .map(CacheRule::rule)
                .chain(owner_tools.rules())
                .find(|rule| rule.reference.id.as_str() == id)
        })?;
        Ok(Self {
            expired_temporary: ExpiredTemporaryRule::new()?,
            xcode_derived_data: XcodeDerivedDataRule::new()?,
            caches,
            projects: ProjectRule::new()?,
            owner_tools,
            worktrees: WorktreeRule::new()?,
            producers,
            clear: ClearRules::new()?,
        }
        .with_producer_revisions())
    }

    /// The registry in which each rule of another module that has an
    /// owner operation has the revision of [`super::producers`] in place of
    /// its own declaration, so one identity has one revision.
    fn with_producer_revisions(self) -> Self {
        let mut registry: Self = self;
        for producer in &registry.producers {
            if !producer.extends() {
                continue;
            }
            let id: &str = producer.rule().reference.id.as_str();
            for cache in &mut registry.caches {
                if cache.rule().reference.id.as_str() == id {
                    *cache = cache.with_rule(producer.rule().clone());
                }
            }
            if registry.owner_tools.homebrew().reference.id.as_str() == id {
                registry.owner_tools = registry.owner_tools.with_homebrew(producer.rule().clone());
            }
        }
        registry
    }

    /// The registry with `lifecycle` for each layout of each rule, for a
    /// fixture test.
    ///
    /// Only a test build has this function: a unit test of this crate, or
    /// a debug build with the feature `test-support`. A released build has
    /// no function that changes a lifecycle state, so each rule of a
    /// released build has the state of its declaration. The state of a
    /// test names no validation record of `docs/VALIDATION.md`; the test
    /// gives a reference that says so.
    ///
    /// The cache rules, the rules of [`super::owner_tools`], and
    /// `git.linked-worktree` keep the state of their declarations: their
    /// implementation has the inspection mode only, so no state permits a
    /// removal under one of them, also in a test build. The exception is
    /// the layout of the scope root of a rule with an owner operation
    /// ([`super::producers`]), which gets at most
    /// [`LifecycleState::ManualActionValidated`]: this build has no
    /// automatic plan of an owner operation.
    /// `project.dependency-directory` gets at most
    /// [`LifecycleState::ManualActionValidated`]: it has no automatic mode.
    /// Each clear rule of [`super::clear`] has the same limit.
    ///
    /// # Errors
    ///
    /// Returns a [`RegistryError`] when a declaration with the state is
    /// not complete.
    #[cfg(any(test, all(feature = "test-support", debug_assertions)))]
    pub fn with_fixture_lifecycle(lifecycle: &LifecycleState) -> Result<Self, RegistryError> {
        let registry: Self = Self::new()?;
        Ok(Self {
            expired_temporary: registry.expired_temporary.with_lifecycle(lifecycle)?,
            xcode_derived_data: registry.xcode_derived_data.with_lifecycle(lifecycle)?,
            caches: registry.caches,
            projects: registry.projects.with_lifecycle(lifecycle)?,
            owner_tools: registry.owner_tools,
            worktrees: registry.worktrees,
            clear: registry.clear.with_lifecycle(lifecycle)?,
            producers: registry
                .producers
                .iter()
                .map(|producer| producer.with_lifecycle(lifecycle))
                .collect::<Result<Vec<ProducerRule>, RegistryError>>()?,
        }
        .with_producer_revisions())
    }

    /// The registry whose rules with an owner operation each have one
    /// executable: the file of the same name in `directory`, a script of
    /// `/bin/sh`, for a fixture test that never runs a producer tool. Only
    /// a test build has this function, as
    /// [`ReviewedRules::with_fixture_lifecycle`].
    ///
    /// # Errors
    ///
    /// Returns a [`RegistryError`] when a declaration with the path is not
    /// complete.
    #[cfg(any(test, all(feature = "test-support", debug_assertions)))]
    pub fn with_owner_fixture_executables(
        self,
        directory: &std::path::Path,
    ) -> Result<Self, RegistryError> {
        let producers: Vec<ProducerRule> = self
            .producers
            .iter()
            .map(|producer| producer.with_fixture_executable(directory))
            .collect::<Result<Vec<ProducerRule>, RegistryError>>()?;
        Ok(Self { producers, ..self })
    }

    /// The rule `svalnir.expired-temporary`.
    pub fn expired_temporary(&self) -> &ExpiredTemporaryRule {
        &self.expired_temporary
    }

    /// The rule `xcode.inactive-derived-data`.
    pub fn xcode_derived_data(&self) -> &XcodeDerivedDataRule {
        &self.xcode_derived_data
    }

    /// The package and build cache rules, in the sequence of
    /// `docs/CLEANUP_RULES.md` section 10.
    pub fn caches(&self) -> &[CacheRule] {
        &self.caches
    }

    /// The cache rule with the identity `id`.
    pub fn cache(&self, id: &str) -> Option<&CacheRule> {
        self.caches
            .iter()
            .find(|cache| cache.rule().reference.id.as_str() == id)
    }

    /// The rule `project.dependency-directory`. It has the inspection mode
    /// and the manual eviction.
    pub fn projects(&self) -> &ProjectRule {
        &self.projects
    }

    /// The rules of the data that only its owner tool removes:
    /// `simulator.devices`, `container.build-cache`, and
    /// `homebrew.cleanup`. They have the inspection mode only.
    pub fn owner_tools(&self) -> &OwnerToolRules {
        &self.owner_tools
    }

    /// The rule `git.linked-worktree`. It has the inspection mode only.
    pub fn worktrees(&self) -> &WorktreeRule {
        &self.worktrees
    }

    /// The clear rules ([`super::clear`]). Each one has the inspection mode
    /// and the manual eviction, and no automatic mode.
    pub fn clear(&self) -> &ClearRules {
        &self.clear
    }

    /// The clear rule with the identity `id`.
    pub fn clear_rule(&self, id: &str) -> Option<&ClearRule> {
        self.clear.get(id)
    }

    /// The rules with an owner operation, in the sequence of
    /// [`super::producers::PRODUCER_SPECS`].
    pub fn producers(&self) -> &[ProducerRule] {
        &self.producers
    }

    /// The rule with an owner operation with the identity `id`.
    pub fn producer(&self, id: &str) -> Option<&ProducerRule> {
        self.producers
            .iter()
            .find(|producer| producer.rule().reference.id.as_str() == id)
    }

    /// The exact revision `reference`.
    ///
    /// # Errors
    ///
    /// Returns [`RuleRefusal::UnknownRule`] when no rule has the
    /// identity, and [`RuleRefusal::UnknownRevision`] when the rule has
    /// another revision. Another revision is not substituted.
    pub fn lookup(&self, reference: &RuleRef) -> Result<&Rule, RuleRefusal> {
        if let Some(rule) = self.rule(reference) {
            return Ok(rule);
        }
        let has_rule: bool = self
            .rules()
            .iter()
            .any(|rule| rule.reference.id == reference.id);
        Err(if has_rule {
            RuleRefusal::UnknownRevision
        } else {
            RuleRefusal::UnknownRule
        })
    }

    /// The lifecycle state of the exact revision `reference` for
    /// `layout`.
    ///
    /// # Errors
    ///
    /// Returns the error of [`ReviewedRules::lookup`], or
    /// [`RuleRefusal::UnknownLayout`] when the revision does not support
    /// the layout.
    pub fn lifecycle(
        &self,
        reference: &RuleRef,
        layout: &str,
    ) -> Result<&LifecycleState, RuleRefusal> {
        self.lookup(reference)?
            .layouts
            .iter()
            .find(|support| support.layout == layout)
            .map(|support| &support.lifecycle)
            .ok_or(RuleRefusal::UnknownLayout)
    }

    /// The lifecycle state of each layout of each registered revision.
    pub fn statuses(&self) -> Vec<RuleStatus> {
        self.rules()
            .into_iter()
            .flat_map(|rule| {
                rule.layouts.iter().map(|support| RuleStatus {
                    reference: rule.reference.clone(),
                    layout: support.layout.clone(),
                    lifecycle: support.lifecycle.clone(),
                    permitted_modes: rule
                        .modes
                        .iter()
                        .filter(|mode| support.permits(mode))
                        .cloned()
                        .collect(),
                })
            })
            .collect()
    }

    /// Gives each path of `candidates` to one rule revision, and reports
    /// each conflict. See [`resolve_overlaps`].
    ///
    /// # Errors
    ///
    /// Returns [`ClaimError::TooManyCandidates`] when the list is longer
    /// than the largest candidate list of the policy, and
    /// [`ClaimError::Unregistered`] when a candidate names a rule revision
    /// that is not registered or a layout that the revision does not
    /// support, and [`ClaimError::LifecycleMismatch`] when the lifecycle
    /// state of a candidate is not the state of the registry.
    pub fn claim(
        &self,
        candidates: Vec<DiscoveredCandidate>,
    ) -> Result<OverlapResolution, ClaimError> {
        if candidates.len() > MAX_CLEANUP_CANDIDATES {
            return Err(ClaimError::TooManyCandidates);
        }
        for candidate in &candidates {
            let recorded: &LifecycleState = self
                .lifecycle(&candidate.candidate.rule, &candidate.candidate.layout)
                .map_err(ClaimError::Unregistered)?;
            if *recorded != candidate.lifecycle {
                return Err(ClaimError::LifecycleMismatch);
            }
        }
        Ok(resolve_overlaps(candidates))
    }
}

impl RuleRegistry for ReviewedRules {
    fn rules(&self) -> Vec<&Rule> {
        let mut rules: Vec<&Rule> = vec![
            self.expired_temporary.rule(),
            self.xcode_derived_data.rule(),
        ];
        rules.extend(self.caches.iter().map(CacheRule::rule));
        rules.push(self.projects.rule());
        rules.extend(self.owner_tools.rules());
        rules.push(self.worktrees.rule());
        rules.extend(
            self.producers
                .iter()
                .filter(|producer| !producer.extends())
                .map(ProducerRule::rule),
        );
        rules.extend(self.clear.rules());
        rules
    }

    fn owner_operation(&self, reference: &RuleRef) -> Option<&OwnerOperation> {
        self.producers
            .iter()
            .find(|producer| &producer.rule().reference == reference)
            .map(ProducerRule::operation)
    }
}
