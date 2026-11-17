//! Cleanup rule declarations, the registry interface, and candidate
//! eligibility.
//!
//! `docs/CLEANUP_RULES.md` sections 2 to 9 own the contract. A rule is a
//! versioned, reviewed classifier for one data lifecycle. A valid rule
//! does not grant permission to act: execution also needs a policy
//! revision, an action grant, OS access, and, where relevant, a privilege
//! grant.
//!
//! This module has the declaration types and the interface. The registry
//! and the rules are in `svalnir-agent` (`rules`).

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::action::{Check, Checked, ExecutorRole, FileObjectType, WorkCharge};
use crate::encoding::wire_enum;
use crate::file::LosslessPath;
use crate::id::{RuleId, RuleRevisionId};
use crate::policy::{
    ActivityFact, CleanupCandidate, OwnerFact, ProtectionFact, RebuildCost, RuleReadiness,
};
use crate::quantity::{Bytes, EntryCount, Nanoseconds};

/// The largest length of a producer name, a layout name, and an evidence
/// reference, in bytes.
pub const MAX_RULE_TEXT_BYTES: usize = 256;

/// The largest number of roots, layouts, and exclusions in one
/// declaration.
pub const MAX_RULE_ENTRIES: usize = 256;

/// A reference to one rule revision: the rule identity and the immutable
/// implementation revision. Plans and grants bind this pair. A display
/// name is not an execution identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RuleRef {
    /// The rule.
    pub id: RuleId,
    /// The implementation revision.
    pub revision: RuleRevisionId,
}

wire_enum! {
    /// One mode of a rule. Approval for one mode does not imply approval
    /// for another mode.
    RuleMode {
        /// Bounded discovery and estimates. No mutation.
        Inspection => "inspection",
        /// A manual move to Trash.
        ManualTrash => "manual_trash",
        /// A manual, plan-bound permanent eviction.
        ManualEviction => "manual_eviction",
        /// Unattended permanent eviction under standing grants.
        AutomaticEviction => "automatic_eviction",
    }
}

impl RuleMode {
    /// Each mode that this build knows.
    pub const ALL: [Self; 4] = [
        Self::Inspection,
        Self::ManualTrash,
        Self::ManualEviction,
        Self::AutomaticEviction,
    ];
}

/// A reference to the recorded evidence that promoted a rule revision.
///
/// The text names a validation record under `docs/VALIDATION.md`. A change
/// of a registry flag is not a promotion.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PromotionEvidence {
    /// The identifier of the validation record.
    pub record: String,
}

/// The lifecycle state of a rule revision for one layout.
///
/// A revision is `Proposed` until recorded evidence promotes it: each
/// validated state has a reference to that evidence, so a validated state
/// with no reference has no value of this type. The check of a
/// [`RuleDeclaration`] rejects an empty reference.
///
/// JSON encodes the state as an object with a `state` field. A `state`
/// that this build does not know decodes to `Unrecognized`, which permits
/// no mode.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum LifecycleState {
    /// Documentation and fixture design. No production execution.
    Proposed,
    /// Bounded discovery and qualified estimates for the tested layouts.
    InspectionValidated {
        /// The recorded evidence.
        evidence: PromotionEvidence,
    },
    /// Explicitly selected, bounded manual actions.
    ManualActionValidated {
        /// The recorded evidence.
        evidence: PromotionEvidence,
    },
    /// Unattended permanent eviction under standing grants and policy.
    AutomaticEvictionValidated {
        /// The recorded evidence.
        evidence: PromotionEvidence,
    },
    /// No new dispatch.
    Disabled {
        /// Whether the reason for the disabling permits inspection.
        inspection_permitted: bool,
    },
    /// The history stays readable. A new plan is rejected.
    Retired,
    /// A state that this build does not recognize.
    #[serde(other)]
    Unrecognized,
}

impl LifecycleState {
    /// Whether the state permits `mode`. A mode that this build does not
    /// recognize is not permitted.
    pub fn permits(&self, mode: &RuleMode) -> bool {
        match self {
            Self::InspectionValidated { .. } => matches!(mode, RuleMode::Inspection),
            Self::ManualActionValidated { .. } => matches!(
                mode,
                RuleMode::Inspection | RuleMode::ManualTrash | RuleMode::ManualEviction
            ),
            Self::AutomaticEvictionValidated { .. } => mode.is_recognized(),
            Self::Disabled {
                inspection_permitted,
            } => *inspection_permitted && matches!(mode, RuleMode::Inspection),
            Self::Proposed | Self::Retired | Self::Unrecognized => false,
        }
    }

    fn evidence(&self) -> Option<&PromotionEvidence> {
        match self {
            Self::InspectionValidated { evidence }
            | Self::ManualActionValidated { evidence }
            | Self::AutomaticEvictionValidated { evidence } => Some(evidence),
            _ => None,
        }
    }
}

wire_enum! {
    /// How a rule attributes data to its producer.
    OwnerAttribution {
        /// Svalnir made the data and has its lifecycle record.
        SvalnirLifecycleRecord => "svalnir_lifecycle_record",
        /// An index or a manifest of the producer names the data.
        ProducerIndex => "producer_index",
        /// The documented layout of the producer under a verified root.
        ProducerLayout => "producer_layout",
    }
}

/// The producer that owns the data of a rule.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RuleOwner {
    /// The producer or the application, for example `xcode`.
    pub producer: String,
    /// How the data is attributed to the producer.
    pub attribution: OwnerAttribution,
}

wire_enum! {
    /// The base that an approved root is relative to. No value is a
    /// user-supplied absolute path.
    RootBase {
        /// The home directory of the authenticated user. No shell
        /// expansion.
        UserHome => "user_home",
        /// The state directory of Svalnir.
        SvalnirState => "svalnir_state",
        /// The location that the configuration of the producer names.
        ProducerConfiguration => "producer_configuration",
    }
}

/// One approved root of a rule. The adapter binds the discovered root to a
/// filesystem identity, a mount generation, and an owner before it is
/// used.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ApprovedRoot {
    /// The base.
    pub base: RootBase,
    /// The path below the base. For `producer_configuration`, this is the
    /// default location, which is a discovery hint only.
    pub relative: LosslessPath,
}

/// One supported layout and its lifecycle state.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LayoutSupport {
    /// The name of the tested producer layout.
    pub layout: String,
    /// The validated state of the rule revision for this layout.
    pub lifecycle: LifecycleState,
}

wire_enum! {
    /// What the age of a candidate derives from.
    AgeBasis {
        /// An index of the producer.
        ProducerIndex => "producer_index",
        /// The lifecycle record of Svalnir.
        SvalnirLifecycleRecord => "svalnir_lifecycle_record",
        /// Validated filesystem metadata. Atime alone is not sufficient.
        FilesystemMetadata => "filesystem_metadata",
    }
}

/// The age policy of a rule.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Retention {
    /// What the age derives from.
    pub age_basis: AgeBasis,
    /// The minimum age of a candidate.
    pub minimum_age: Nanoseconds,
}

wire_enum! {
    /// One check of the activity protocol. No single check is universal
    /// proof that no writer exists.
    ActivityCheck {
        /// The lock of the producer is free.
        ProducerLock => "producer_lock",
        /// No process of the producer runs.
        ProducerProcessAbsent => "producer_process_absent",
        /// No process has an entry of the candidate open.
        OpenFileScan => "open_file_scan",
        /// The lifecycle record of Svalnir shows that the item is sealed.
        SealedLifecycleRecord => "sealed_lifecycle_record",
    }
}

/// The activity protocol of a rule.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ActivityProtocol {
    /// The checks. Each one must pass.
    pub checks: Vec<ActivityCheck>,
    /// The time for which the candidate must be inactive.
    pub quiescence: Nanoseconds,
    /// The time after which the activity evidence is not valid.
    pub evidence_expiry: Nanoseconds,
}

wire_enum! {
    /// How a rule removes one unit.
    DeletionMethod {
        /// Remove each entry of a bounded enumeration by its name relative
        /// to an open directory, with no traversal that finds new
        /// children.
        BoundedUnlink => "bounded_unlink",
        /// A fixed operation of the producer whose effect is bounded.
        ProducerOperation => "producer_operation",
    }
}

/// The exclusions of a rule. They apply each time the rule executes; a
/// grant or a force flag does not override them.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RuleExclusions {
    /// Protected descendants, relative to the root. An exclusion applies
    /// to the entry and to its descendants.
    pub descendants: Vec<LosslessPath>,
    /// The object types that the rule can remove. Each other type is
    /// skipped.
    pub supported_object_types: Vec<FileObjectType>,
    /// Whether an object with more than one hard link is skipped.
    pub skip_hard_linked: bool,
}

/// The work bounds of a rule.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RuleBudget {
    /// The ceiling of one indivisible candidate.
    pub per_candidate: WorkCharge,
    /// The ceiling of the rule in one pass.
    pub per_pass: WorkCharge,
}

/// The declaration of one rule revision. [`Rule`] is the checked form.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RuleDeclaration {
    /// The identity and the revision.
    pub reference: RuleRef,
    /// The producer that owns the data.
    pub owner: RuleOwner,
    /// The supported layouts and their lifecycle states.
    pub layouts: Vec<LayoutSupport>,
    /// The approved roots.
    pub roots: Vec<ApprovedRoot>,
    /// The age policy.
    pub retention: Retention,
    /// The activity protocol.
    pub activity: ActivityProtocol,
    /// The exclusions.
    pub exclusions: RuleExclusions,
    /// The modes that the implementation has. A mode is usable for a
    /// layout only when the lifecycle state of the layout permits it.
    pub modes: Vec<RuleMode>,
    /// How a unit is removed.
    pub deletion_method: DeletionMethod,
    /// The executor.
    pub executor: ExecutorRole,
    /// The cost to make the data again.
    pub rebuild_cost: RebuildCost,
    /// The work bounds.
    pub budget: RuleBudget,
}

/// A rule declaration that is complete.
pub type Rule = Checked<RuleDeclaration>;

/// The reason a declaration is incomplete.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RuleDeclarationError {
    /// A text is empty, is too long, or has a control character.
    #[error("a text of the declaration is empty, is too long, or has a control character")]
    Text,
    /// A list is empty, is too long, or has an entry two times.
    #[error("a list of the declaration is empty, is too long, or has an entry two times")]
    List,
    /// A value is one that this build does not recognize.
    #[error("the declaration has a value that this build does not recognize")]
    Unrecognized,
    /// The minimum age, the quiescence time, or the evidence expiry is
    /// zero.
    #[error("the declaration has no age policy or no activity window")]
    Age,
    /// A part of a work bound is zero, or the candidate ceiling is larger
    /// than the pass ceiling.
    #[error("the declaration has no work bound")]
    Budget,
    /// The rebuild cost is not known.
    #[error("the declaration has no rebuild cost")]
    RebuildCost,
    /// The implementation has no inspection mode, or a layout is
    /// validated for a manual action or for automatic eviction and the
    /// implementation has no such mode.
    #[error("a validated state names a mode that the implementation does not have")]
    Mode,
    /// A root path is absolute, or it has an empty, `.`, or `..`
    /// component.
    #[error("a root path is not a confined relative path")]
    Root,
}

fn check_text(text: &str) -> Result<(), RuleDeclarationError> {
    if text.is_empty() || text.len() > MAX_RULE_TEXT_BYTES || text.chars().any(char::is_control) {
        return Err(RuleDeclarationError::Text);
    }
    Ok(())
}

/// Whether `path` is relative and has no empty, `.`, or `..` component,
/// so that it stays below its base.
fn is_confined(path: &LosslessPath) -> bool {
    path.as_bytes()
        .split(|byte| *byte == b'/')
        .all(|component| !matches!(component, b"" | b"." | b".."))
}

fn check_list<T: PartialEq>(list: &[T]) -> Result<(), RuleDeclarationError> {
    let has_duplicate: bool = list
        .iter()
        .enumerate()
        .any(|(index, entry)| list[..index].contains(entry));
    if list.is_empty() || list.len() > MAX_RULE_ENTRIES || has_duplicate {
        return Err(RuleDeclarationError::List);
    }
    Ok(())
}

impl Check for RuleDeclaration {
    type Error = RuleDeclarationError;

    fn check(&self) -> Result<(), RuleDeclarationError> {
        check_text(&self.owner.producer)?;
        check_list(&self.roots)?;
        check_list(&self.modes)?;
        check_list(&self.activity.checks)?;
        check_list(&self.exclusions.supported_object_types)?;
        if self.exclusions.descendants.len() > MAX_RULE_ENTRIES {
            return Err(RuleDeclarationError::List);
        }
        let layout_names: Vec<&str> = self
            .layouts
            .iter()
            .map(|support| support.layout.as_str())
            .collect();
        check_list(&layout_names)?;

        let recognized: bool = self.owner.attribution.is_recognized()
            && self.retention.age_basis.is_recognized()
            && self.deletion_method.is_recognized()
            && self.executor.is_recognized()
            && self.modes.iter().all(RuleMode::is_recognized)
            && self.roots.iter().all(|root| root.base.is_recognized())
            && self
                .activity
                .checks
                .iter()
                .all(ActivityCheck::is_recognized)
            && self
                .exclusions
                .supported_object_types
                .iter()
                .all(FileObjectType::is_recognized);
        if !recognized {
            return Err(RuleDeclarationError::Unrecognized);
        }

        for support in &self.layouts {
            check_text(&support.layout)?;
            if let Some(evidence) = support.lifecycle.evidence() {
                check_text(&evidence.record)?;
            }
            // A validated state names a mode that the implementation has.
            let has = |mode: &RuleMode| self.modes.contains(mode);
            let state_agrees: bool = match support.lifecycle {
                LifecycleState::Unrecognized => {
                    return Err(RuleDeclarationError::Unrecognized);
                }
                LifecycleState::ManualActionValidated { .. } => {
                    has(&RuleMode::ManualTrash) || has(&RuleMode::ManualEviction)
                }
                LifecycleState::AutomaticEvictionValidated { .. } => {
                    has(&RuleMode::AutomaticEviction)
                }
                _ => true,
            };
            if !state_agrees {
                return Err(RuleDeclarationError::Mode);
            }
        }
        if self.roots.iter().any(|root| !is_confined(&root.relative)) {
            return Err(RuleDeclarationError::Root);
        }

        let zero = Nanoseconds::ZERO;
        if self.retention.minimum_age == zero
            || self.activity.quiescence == zero
            || self.activity.evidence_expiry == zero
        {
            return Err(RuleDeclarationError::Age);
        }
        let budget = &self.budget;
        let has_zero = |charge: &WorkCharge| {
            charge.work_bytes == Bytes::ZERO || charge.items == EntryCount::ZERO
        };
        if has_zero(&budget.per_candidate)
            || has_zero(&budget.per_pass)
            || !budget.per_candidate.fits_in(&budget.per_pass)
        {
            return Err(RuleDeclarationError::Budget);
        }
        if matches!(self.rebuild_cost, RebuildCost::Unknown) {
            return Err(RuleDeclarationError::RebuildCost);
        }
        // Each rule can be inspected.
        if !self.modes.contains(&RuleMode::Inspection) {
            return Err(RuleDeclarationError::Mode);
        }
        Ok(())
    }
}

/// The reason a rule revision cannot do a mode for a layout. No generic
/// cleaner takes its place.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RuleRefusal {
    /// The registry has no rule with the identity.
    #[error("the rule is not registered")]
    UnknownRule,
    /// The registry has the rule and not this revision. Another revision
    /// is not substituted.
    #[error("the rule revision is not registered")]
    UnknownRevision,
    /// The rule revision does not support the layout.
    #[error("the rule revision does not support the layout")]
    UnknownLayout,
    /// The implementation does not have the mode, or the lifecycle state
    /// of the layout does not permit it.
    #[error("the mode is not validated for the layout")]
    ModeNotValidated,
}

impl RuleDeclaration {
    /// Checks that this revision can do `mode` for `layout`.
    ///
    /// # Errors
    ///
    /// Returns [`RuleRefusal::UnknownLayout`] when the declaration does
    /// not have the layout, and [`RuleRefusal::ModeNotValidated`] when the
    /// implementation does not have the mode or the lifecycle state of the
    /// layout does not permit it.
    pub fn permits(&self, layout: &str, mode: &RuleMode) -> Result<(), RuleRefusal> {
        let support: &LayoutSupport = self
            .layouts
            .iter()
            .find(|support| support.layout == layout)
            .ok_or(RuleRefusal::UnknownLayout)?;
        if self.modes.contains(mode) && support.lifecycle.permits(mode) {
            Ok(())
        } else {
            Err(RuleRefusal::ModeNotValidated)
        }
    }
}

/// The reviewed rules that ship with the application.
///
/// User configuration supplies parameters and exclusions. It does not
/// supply a rule.
pub trait RuleRegistry {
    /// Each registered rule revision. A reference is in the list one time
    /// only.
    fn rules(&self) -> Vec<&Rule>;

    /// The exact revision `reference`.
    fn rule(&self, reference: &RuleRef) -> Option<&Rule> {
        self.rules()
            .into_iter()
            .find(|rule| &rule.reference == reference)
    }

    /// The exact revision `reference`, when it can do `mode` for
    /// `layout`.
    ///
    /// # Errors
    ///
    /// Returns [`RuleRefusal::UnknownRule`] or
    /// [`RuleRefusal::UnknownRevision`] when the revision is not
    /// registered, or the error of [`RuleDeclaration::permits`].
    fn resolve(
        &self,
        reference: &RuleRef,
        layout: &str,
        mode: &RuleMode,
    ) -> Result<&Rule, RuleRefusal> {
        let Some(rule) = self.rule(reference) else {
            let has_rule: bool = self
                .rules()
                .iter()
                .any(|rule| rule.reference.id == reference.id);
            return Err(if has_rule {
                RuleRefusal::UnknownRevision
            } else {
                RuleRefusal::UnknownRule
            });
        };
        rule.permits(layout, mode)?;
        Ok(rule)
    }
}

wire_enum! {
    /// Three-valued evidence of one eligibility predicate. Only
    /// `satisfied` is an affirmative result.
    Fact {
        /// The evidence establishes the predicate.
        Satisfied => "satisfied",
        /// The evidence establishes that the predicate does not hold.
        NotSatisfied => "not_satisfied",
        /// The evidence does not establish the predicate.
        Unknown => "unknown",
    }
}

impl Fact {
    /// Whether the predicate is established. `unknown` and a value that
    /// this build does not recognize give `false`.
    pub fn is_satisfied(&self) -> bool {
        matches!(self, Self::Satisfied)
    }
}

/// One of the ten eligibility predicates of the specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EligibilityPredicate {
    /// 1. The exact rule revision supports the producer and the layout.
    RuleSupportsLayout,
    /// 2. The root, volume, object identity, type, and owner match the
    ///    rule.
    IdentityMatches,
    /// 3. The candidate is in the effective authorized scope.
    WithinAuthorizedScope,
    /// 4. The lifecycle of the data establishes regenerability or
    ///    intentional expiry.
    Regenerable,
    /// 5. The minimum age and the inactivity are established.
    AgeAndInactivity,
    /// 6. The activity and namespace protocols are valid.
    ProtocolsValid,
    /// 7. No hard exclusion and no user exclusion overlaps the candidate.
    NoExclusionOverlap,
    /// 8. The complete candidate unit and its work charge are known.
    UnitAndChargeKnown,
    /// 9. Capabilities, leases, durable recording, and budgets are
    ///    available.
    ResourcesAvailable,
    /// 10. A fresh check immediately before the step permits dispatch.
    FreshCheck,
}

/// The evidence of the ten eligibility predicates of one candidate.
///
/// A candidate is eligible only when each predicate is `satisfied`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CandidateEligibility {
    /// Predicate 1.
    pub rule_supports_layout: Fact,
    /// Predicate 2.
    pub identity_matches: Fact,
    /// Predicate 3.
    pub within_authorized_scope: Fact,
    /// Predicate 4.
    pub regenerable: Fact,
    /// Predicate 5.
    pub age_and_inactivity: Fact,
    /// Predicate 6.
    pub protocols_valid: Fact,
    /// Predicate 7.
    pub no_exclusion_overlap: Fact,
    /// Predicate 8.
    pub unit_and_charge_known: Fact,
    /// Predicate 9.
    pub resources_available: Fact,
    /// Predicate 10.
    pub fresh_check: Fact,
}

impl CandidateEligibility {
    /// The evidence of a candidate that no check examined: each predicate
    /// is `unknown`.
    pub const fn unknown() -> Self {
        Self {
            rule_supports_layout: Fact::Unknown,
            identity_matches: Fact::Unknown,
            within_authorized_scope: Fact::Unknown,
            regenerable: Fact::Unknown,
            age_and_inactivity: Fact::Unknown,
            protocols_valid: Fact::Unknown,
            no_exclusion_overlap: Fact::Unknown,
            unit_and_charge_known: Fact::Unknown,
            resources_available: Fact::Unknown,
            fresh_check: Fact::Unknown,
        }
    }

    /// Each predicate with its evidence, in the sequence of the
    /// specification.
    pub fn facts(&self) -> [(EligibilityPredicate, &Fact); 10] {
        use EligibilityPredicate as P;
        [
            (P::RuleSupportsLayout, &self.rule_supports_layout),
            (P::IdentityMatches, &self.identity_matches),
            (P::WithinAuthorizedScope, &self.within_authorized_scope),
            (P::Regenerable, &self.regenerable),
            (P::AgeAndInactivity, &self.age_and_inactivity),
            (P::ProtocolsValid, &self.protocols_valid),
            (P::NoExclusionOverlap, &self.no_exclusion_overlap),
            (P::UnitAndChargeKnown, &self.unit_and_charge_known),
            (P::ResourcesAvailable, &self.resources_available),
            (P::FreshCheck, &self.fresh_check),
        ]
    }

    /// Whether each predicate is `satisfied`.
    pub fn is_eligible(&self) -> bool {
        self.facts().iter().all(|(_, fact)| fact.is_satisfied())
    }

    /// The first predicate that is not `satisfied`, with its evidence.
    pub fn first_blocker(&self) -> Option<(EligibilityPredicate, &Fact)> {
        self.facts()
            .into_iter()
            .find(|(_, fact)| !fact.is_satisfied())
    }
}

/// The fields of one candidate of a rule: the candidate that the policy
/// evaluates, the exact rule revision and layout, and the eligibility
/// evidence. [`RuleCandidate`] is the checked form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleCandidateRecord {
    /// The candidate, as the disk policy reads it.
    pub candidate: CleanupCandidate,
    /// The exact rule revision that found the candidate.
    pub rule: RuleRef,
    /// The layout that the rule found.
    pub layout: String,
    /// The evidence of the eligibility predicates.
    pub eligibility: CandidateEligibility,
}

/// One candidate of a rule whose policy facts agree with its rule
/// declaration and with its evidence.
///
/// The candidate type is the one of the policy module. Only
/// [`RuleCandidate::new`] makes a value, and the record is read through
/// `Deref`: a policy fact is affirmative only when the declaration and the
/// predicate behind it support it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleCandidate(RuleCandidateRecord);

/// The reason a rule candidate was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RuleCandidateError {
    /// The candidate or the record names a different rule revision than
    /// the declaration, or the declaration does not have the layout.
    #[error("the candidate does not belong to the rule revision and the layout")]
    Rule,
    /// A policy fact is affirmative and the predicate behind it is not
    /// `satisfied`.
    #[error("a policy fact is affirmative without satisfied evidence")]
    UnsupportedFact,
    /// A policy fact claims more than the declaration permits: a rule that
    /// is ready for automatic action and not validated for it, a rebuild
    /// cost other than the cost of the declaration, an inactive time
    /// shorter than the quiescence time, or a charge over the candidate
    /// ceiling.
    #[error("a policy fact claims more than the rule declaration permits")]
    Declaration,
}

impl RuleCandidate {
    /// Checks the record against the declaration of its rule revision and
    /// against its own evidence.
    ///
    /// # Errors
    ///
    /// Returns [`RuleCandidateError::Rule`] when `rule` is not the
    /// revision of the record or does not have its layout,
    /// [`RuleCandidateError::Declaration`] when a policy fact claims more
    /// than the declaration permits, and
    /// [`RuleCandidateError::UnsupportedFact`] when a policy fact is
    /// affirmative and its predicate is not `satisfied`:
    ///
    /// | Affirmative policy fact | Predicates |
    /// | --- | --- |
    /// | The rule is ready | 1 |
    /// | The owner is the requesting user | 2 |
    /// | The target is inactive | 5 |
    /// | The target has no product protection | 7 |
    /// | The target has no protected data class | 4 and 7 |
    /// | The rebuild cost is known | 4 |
    /// | The work charge is known | 8 |
    pub fn new(rule: &Rule, record: RuleCandidateRecord) -> Result<Self, RuleCandidateError> {
        let candidate = &record.candidate;
        let facts = &candidate.facts;
        let has_layout: bool = rule
            .layouts
            .iter()
            .any(|support| support.layout == record.layout);
        if candidate.rule_id != record.rule.id || rule.reference != record.rule || !has_layout {
            return Err(RuleCandidateError::Rule);
        }

        let is_ready: bool = matches!(facts.rule_readiness, RuleReadiness::Ready);
        let ready_agrees: bool = !is_ready
            || rule
                .permits(&record.layout, &RuleMode::AutomaticEviction)
                .is_ok();
        let cost_agrees: bool = matches!(facts.rebuild_cost, RebuildCost::Unknown)
            || facts.rebuild_cost == rule.rebuild_cost;
        let activity_agrees: bool = match facts.activity {
            ActivityFact::Inactive { inactive_for } => inactive_for >= rule.activity.quiescence,
            _ => true,
        };
        let charge: Option<WorkCharge> = match (candidate.work_bytes, candidate.item_count) {
            (Some(work_bytes), Some(items)) => Some(WorkCharge::new(work_bytes, items)),
            _ => None,
        };
        let charge_agrees: bool =
            charge.is_none_or(|charge| charge.fits_in(&rule.budget.per_candidate));
        if !(ready_agrees && cost_agrees && activity_agrees && charge_agrees) {
            return Err(RuleCandidateError::Declaration);
        }

        let evidence = &record.eligibility;
        let supported = |affirmative: bool, predicates: &[&Fact]| {
            !affirmative || predicates.iter().all(|fact| fact.is_satisfied())
        };
        let facts_agree: bool = supported(is_ready, &[&evidence.rule_supports_layout])
            && supported(
                matches!(facts.owner, OwnerFact::RequestingUser),
                &[&evidence.identity_matches],
            )
            && supported(
                matches!(facts.activity, ActivityFact::Inactive { .. }),
                &[&evidence.age_and_inactivity],
            )
            && supported(
                matches!(facts.hard_protection, ProtectionFact::NotProtected),
                &[&evidence.no_exclusion_overlap],
            )
            && supported(
                facts.protected_classes.is_empty(),
                &[&evidence.regenerable, &evidence.no_exclusion_overlap],
            )
            && supported(
                !matches!(facts.rebuild_cost, RebuildCost::Unknown),
                &[&evidence.regenerable],
            )
            && supported(charge.is_some(), &[&evidence.unit_and_charge_known]);
        if facts_agree {
            Ok(Self(record))
        } else {
            Err(RuleCandidateError::UnsupportedFact)
        }
    }

    /// Whether each eligibility predicate is `satisfied`. The policy
    /// applies its own protections, budgets, and cooldowns after this.
    pub fn is_eligible(&self) -> bool {
        self.0.eligibility.is_eligible()
    }

    /// The record. A changed record needs a new check.
    pub fn into_inner(self) -> RuleCandidateRecord {
        self.0
    }
}

impl std::ops::Deref for RuleCandidate {
    type Target = RuleCandidateRecord;

    fn deref(&self) -> &RuleCandidateRecord {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        ActivityCheck, ActivityProtocol, AgeBasis, ApprovedRoot, CandidateEligibility,
        DeletionMethod, EligibilityPredicate, Fact, LayoutSupport, LifecycleState,
        OwnerAttribution, PromotionEvidence, Retention, RootBase, Rule, RuleBudget, RuleCandidate,
        RuleCandidateError, RuleCandidateRecord, RuleDeclaration, RuleDeclarationError,
        RuleExclusions, RuleMode, RuleOwner, RuleRef, RuleRefusal, RuleRegistry,
    };
    use crate::action::{Check, Checked, ExecutorRole, FileObjectType, WorkCharge};
    use crate::file::LosslessPath;
    use crate::id::{RuleId, RuleRevisionId, TargetId, VolumeId};
    use crate::policy::{
        ActivityFact, CleanupCandidate, CleanupFacts, OwnerFact, ProtectedDataClass,
        ProtectionFact, RebuildCost, RuleReadiness,
    };
    use crate::quantity::{Bytes, EntryCount, Nanoseconds};

    fn reference(id: &str, revision: &str) -> RuleRef {
        RuleRef {
            id: RuleId::new(id).unwrap(),
            revision: RuleRevisionId::new(revision).unwrap(),
        }
    }

    fn evidence() -> PromotionEvidence {
        PromotionEvidence {
            record: "VAL-07/2026-11-17/expired-temporary".to_owned(),
        }
    }

    fn charge(bytes: u64, items: u64) -> WorkCharge {
        WorkCharge::new(Bytes::new(bytes), EntryCount::new(items))
    }

    fn declaration(lifecycle: LifecycleState) -> RuleDeclaration {
        RuleDeclaration {
            reference: reference("svalnir.expired-temporary", "r1"),
            owner: RuleOwner {
                producer: "svalnir".to_owned(),
                attribution: OwnerAttribution::SvalnirLifecycleRecord,
            },
            layouts: vec![LayoutSupport {
                layout: "temporary-v1".to_owned(),
                lifecycle,
            }],
            roots: vec![ApprovedRoot {
                base: RootBase::SvalnirState,
                relative: LosslessPath::from_bytes("temporary").unwrap(),
            }],
            retention: Retention {
                age_basis: AgeBasis::SvalnirLifecycleRecord,
                minimum_age: Nanoseconds::new(3_600_000_000_000),
            },
            activity: ActivityProtocol {
                checks: vec![ActivityCheck::SealedLifecycleRecord],
                quiescence: Nanoseconds::new(60_000_000_000),
                evidence_expiry: Nanoseconds::new(5_000_000_000),
            },
            exclusions: RuleExclusions {
                descendants: Vec::new(),
                supported_object_types: vec![
                    FileObjectType::RegularFile,
                    FileObjectType::Directory,
                ],
                skip_hard_linked: true,
            },
            modes: RuleMode::ALL.to_vec(),
            deletion_method: DeletionMethod::BoundedUnlink,
            executor: ExecutorRole::User,
            rebuild_cost: RebuildCost::Low,
            budget: RuleBudget {
                per_candidate: charge(1_000_000, 100),
                per_pass: charge(10_000_000, 1_000),
            },
        }
    }

    fn states() -> Vec<LifecycleState> {
        vec![
            LifecycleState::Proposed,
            LifecycleState::InspectionValidated {
                evidence: evidence(),
            },
            LifecycleState::ManualActionValidated {
                evidence: evidence(),
            },
            LifecycleState::AutomaticEvictionValidated {
                evidence: evidence(),
            },
            LifecycleState::Disabled {
                inspection_permitted: true,
            },
            LifecycleState::Disabled {
                inspection_permitted: false,
            },
            LifecycleState::Retired,
            LifecycleState::Unrecognized,
        ]
    }

    #[test]
    fn each_lifecycle_state_permits_only_its_modes() {
        use RuleMode::{AutomaticEviction, Inspection, ManualEviction, ManualTrash};
        let expected: [&[RuleMode]; 8] = [
            &[],
            &[Inspection],
            &[Inspection, ManualTrash, ManualEviction],
            &[Inspection, ManualTrash, ManualEviction, AutomaticEviction],
            &[Inspection],
            &[],
            &[],
            &[],
        ];
        for (state, permitted) in states().iter().zip(expected) {
            for mode in &RuleMode::ALL {
                assert_eq!(
                    state.permits(mode),
                    permitted.contains(mode),
                    "{state:?} {mode}"
                );
            }
            assert!(!state.permits(&RuleMode::from_wire("producer_purge")));
        }
    }

    #[test]
    fn a_lifecycle_state_round_trips_and_a_validated_state_needs_evidence() {
        for state in states() {
            if state == LifecycleState::Unrecognized {
                continue;
            }
            let value = serde_json::to_value(&state).unwrap();
            assert_eq!(
                serde_json::from_value::<LifecycleState>(value).unwrap(),
                state
            );
        }
        assert_eq!(
            serde_json::to_value(LifecycleState::Proposed).unwrap(),
            json!({ "state": "proposed" })
        );
        // A registry flag with no evidence is not a promotion.
        for state in [
            "inspection_validated",
            "manual_action_validated",
            "automatic_eviction_validated",
        ] {
            assert!(
                serde_json::from_value::<LifecycleState>(json!({ "state": state })).is_err(),
                "{state}"
            );
        }
        let newer: LifecycleState =
            serde_json::from_value(json!({ "state": "fleet_validated", "evidence": {} })).unwrap();
        assert_eq!(newer, LifecycleState::Unrecognized);
        for mode in &RuleMode::ALL {
            assert!(!newer.permits(mode));
        }
    }

    #[test]
    fn a_complete_declaration_round_trips() {
        let rule: Rule = Checked::new(declaration(LifecycleState::Proposed)).unwrap();
        let value = serde_json::to_value(&rule).unwrap();
        assert_eq!(
            value["reference"],
            json!({ "id": "svalnir.expired-temporary", "revision": "r1" })
        );
        assert_eq!(
            value["layouts"][0]["lifecycle"],
            json!({ "state": "proposed" })
        );
        assert_eq!(value["retention"]["minimum_age"], json!("3600000000000"));
        assert_eq!(value["modes"][3], json!("automatic_eviction"));
        assert_eq!(serde_json::from_value::<Rule>(value.clone()).unwrap(), rule);
        // Decoding runs the check.
        let mut incomplete = value;
        incomplete["retention"]["minimum_age"] = json!("0");
        assert!(serde_json::from_value::<Rule>(incomplete).is_err());
    }

    #[test]
    #[expect(clippy::too_many_lines, reason = "the test is one table of cases")]
    fn an_incomplete_declaration_is_rejected() {
        type Change = Box<dyn FnOnce(&mut RuleDeclaration)>;
        let cases: Vec<(RuleDeclarationError, Change)> = vec![
            (
                RuleDeclarationError::Text,
                Box::new(|d| d.owner.producer.clear()),
            ),
            (
                RuleDeclarationError::Text,
                Box::new(|d| d.layouts[0].layout = "a\nb".to_owned()),
            ),
            (
                RuleDeclarationError::Text,
                Box::new(|d| {
                    d.layouts[0].lifecycle = LifecycleState::InspectionValidated {
                        evidence: PromotionEvidence {
                            record: String::new(),
                        },
                    };
                }),
            ),
            // No support range, no root, no mode, no activity check.
            (RuleDeclarationError::List, Box::new(|d| d.layouts.clear())),
            (RuleDeclarationError::List, Box::new(|d| d.roots.clear())),
            (RuleDeclarationError::List, Box::new(|d| d.modes.clear())),
            (
                RuleDeclarationError::List,
                Box::new(|d| d.activity.checks.clear()),
            ),
            (
                RuleDeclarationError::List,
                Box::new(|d| d.exclusions.supported_object_types.clear()),
            ),
            (
                RuleDeclarationError::List,
                Box::new(|d| d.modes.push(RuleMode::Inspection)),
            ),
            (
                RuleDeclarationError::List,
                Box::new(|d| d.layouts.push(d.layouts[0].clone())),
            ),
            // No age policy, no activity window.
            (
                RuleDeclarationError::Age,
                Box::new(|d| d.retention.minimum_age = Nanoseconds::ZERO),
            ),
            (
                RuleDeclarationError::Age,
                Box::new(|d| d.activity.quiescence = Nanoseconds::ZERO),
            ),
            (
                RuleDeclarationError::Age,
                Box::new(|d| d.activity.evidence_expiry = Nanoseconds::ZERO),
            ),
            // No work bound.
            (
                RuleDeclarationError::Budget,
                Box::new(|d| d.budget.per_candidate = WorkCharge::ZERO),
            ),
            (
                RuleDeclarationError::Budget,
                Box::new(|d| d.budget.per_pass = WorkCharge::ZERO),
            ),
            (
                RuleDeclarationError::Budget,
                Box::new(|d| d.budget.per_pass = charge(999_999, 1_000)),
            ),
            (
                RuleDeclarationError::RebuildCost,
                Box::new(|d| d.rebuild_cost = RebuildCost::Unknown),
            ),
            (
                RuleDeclarationError::Mode,
                Box::new(|d| d.modes = vec![RuleMode::ManualTrash]),
            ),
            // A validated state for a mode that the implementation does
            // not have.
            (
                RuleDeclarationError::Mode,
                Box::new(|d| {
                    d.modes = vec![RuleMode::Inspection];
                    d.layouts[0].lifecycle = LifecycleState::AutomaticEvictionValidated {
                        evidence: evidence(),
                    };
                }),
            ),
            (
                RuleDeclarationError::Mode,
                Box::new(|d| {
                    d.modes = vec![RuleMode::Inspection, RuleMode::AutomaticEviction];
                    d.layouts[0].lifecycle = LifecycleState::ManualActionValidated {
                        evidence: evidence(),
                    };
                }),
            ),
            // One part of a work ceiling is zero.
            (
                RuleDeclarationError::Budget,
                Box::new(|d| d.budget.per_candidate = charge(0, 100)),
            ),
            (
                RuleDeclarationError::Budget,
                Box::new(|d| d.budget.per_pass = charge(10_000_000, 0)),
            ),
            // A root that is not below its base.
            (
                RuleDeclarationError::Root,
                Box::new(|d| d.roots[0].relative = LosslessPath::from_bytes("/").unwrap()),
            ),
            (
                RuleDeclarationError::Root,
                Box::new(|d| d.roots[0].relative = LosslessPath::from_bytes("../..").unwrap()),
            ),
            (
                RuleDeclarationError::Root,
                Box::new(|d| d.roots[0].relative = LosslessPath::from_bytes("a/./b").unwrap()),
            ),
            (
                RuleDeclarationError::Root,
                Box::new(|d| d.roots[0].relative = LosslessPath::from_bytes("a//b").unwrap()),
            ),
            (
                RuleDeclarationError::Root,
                Box::new(|d| d.roots[0].relative = LosslessPath::from_bytes("a/").unwrap()),
            ),
            (
                RuleDeclarationError::Unrecognized,
                Box::new(|d| d.modes.push(RuleMode::from_wire("producer_purge"))),
            ),
            (
                RuleDeclarationError::Unrecognized,
                Box::new(|d| d.deletion_method = DeletionMethod::from_wire("rm_rf")),
            ),
            (
                RuleDeclarationError::Unrecognized,
                Box::new(|d| d.roots[0].base = RootBase::from_wire("absolute")),
            ),
            (
                RuleDeclarationError::Unrecognized,
                Box::new(|d| d.layouts[0].lifecycle = LifecycleState::Unrecognized),
            ),
        ];
        for (index, (expected, change)) in cases.into_iter().enumerate() {
            let mut declaration = declaration(LifecycleState::Proposed);
            change(&mut declaration);
            assert_eq!(declaration.check(), Err(expected), "case {index}");
        }
    }

    struct Registry(Vec<Rule>);

    impl RuleRegistry for Registry {
        fn rules(&self) -> Vec<&Rule> {
            self.0.iter().collect()
        }
    }

    #[test]
    fn the_registry_resolves_only_the_exact_validated_revision() {
        let manual = LifecycleState::ManualActionValidated {
            evidence: evidence(),
        };
        let mut inspect_only = declaration(manual.clone());
        inspect_only.reference = reference("xcode.inactive-derived-data", "r1");
        inspect_only.modes = vec![RuleMode::Inspection, RuleMode::ManualEviction];
        let registry = Registry(vec![
            Checked::new(declaration(manual)).unwrap(),
            Checked::new(inspect_only).unwrap(),
        ]);
        let r1 = reference("svalnir.expired-temporary", "r1");
        let layout = "temporary-v1";

        let rule = registry
            .resolve(&r1, layout, &RuleMode::ManualEviction)
            .unwrap();
        assert_eq!(rule.reference, r1);
        assert!(registry.rule(&r1).is_some());
        // The lifecycle state does not permit the automatic mode.
        assert_eq!(
            registry.resolve(&r1, layout, &RuleMode::AutomaticEviction),
            Err(RuleRefusal::ModeNotValidated)
        );
        // Another revision is not substituted.
        assert_eq!(
            registry.resolve(
                &reference("svalnir.expired-temporary", "r2"),
                layout,
                &RuleMode::Inspection
            ),
            Err(RuleRefusal::UnknownRevision)
        );
        assert_eq!(
            registry.resolve(
                &reference("npm.content-cache", "r1"),
                layout,
                &RuleMode::Inspection
            ),
            Err(RuleRefusal::UnknownRule)
        );
        assert_eq!(
            registry.resolve(&r1, "temporary-v2", &RuleMode::Inspection),
            Err(RuleRefusal::UnknownLayout)
        );
        // The lifecycle state permits the mode and the implementation
        // does not have it.
        assert_eq!(
            registry.resolve(
                &reference("xcode.inactive-derived-data", "r1"),
                layout,
                &RuleMode::ManualTrash
            ),
            Err(RuleRefusal::ModeNotValidated)
        );
        // A proposed rule does nothing.
        let proposed = Registry(vec![
            Checked::new(declaration(LifecycleState::Proposed)).unwrap(),
        ]);
        for mode in &RuleMode::ALL {
            assert_eq!(
                proposed.resolve(&r1, layout, mode),
                Err(RuleRefusal::ModeNotValidated)
            );
        }
    }

    fn satisfied() -> CandidateEligibility {
        CandidateEligibility {
            rule_supports_layout: Fact::Satisfied,
            identity_matches: Fact::Satisfied,
            within_authorized_scope: Fact::Satisfied,
            regenerable: Fact::Satisfied,
            age_and_inactivity: Fact::Satisfied,
            protocols_valid: Fact::Satisfied,
            no_exclusion_overlap: Fact::Satisfied,
            unit_and_charge_known: Fact::Satisfied,
            resources_available: Fact::Satisfied,
            fresh_check: Fact::Satisfied,
        }
    }

    /// The evidence with `fact` for the predicate at `index`.
    fn with_fact(index: usize, fact: Fact) -> CandidateEligibility {
        let mut eligibility = satisfied();
        let field = match index {
            0 => &mut eligibility.rule_supports_layout,
            1 => &mut eligibility.identity_matches,
            2 => &mut eligibility.within_authorized_scope,
            3 => &mut eligibility.regenerable,
            4 => &mut eligibility.age_and_inactivity,
            5 => &mut eligibility.protocols_valid,
            6 => &mut eligibility.no_exclusion_overlap,
            7 => &mut eligibility.unit_and_charge_known,
            8 => &mut eligibility.resources_available,
            _ => &mut eligibility.fresh_check,
        };
        *field = fact;
        eligibility
    }

    #[test]
    fn an_unknown_fact_is_not_eligible() {
        assert!(satisfied().is_eligible());
        assert_eq!(satisfied().first_blocker(), None);
        assert!(!CandidateEligibility::unknown().is_eligible());
        assert_eq!(
            CandidateEligibility::unknown().first_blocker(),
            Some((EligibilityPredicate::RuleSupportsLayout, &Fact::Unknown))
        );
        let newer = Fact::from_wire("probably");
        for index in 0..10 {
            for fact in [Fact::Unknown, Fact::NotSatisfied, newer.clone()] {
                let eligibility = with_fact(index, fact.clone());
                assert!(!eligibility.is_eligible(), "predicate {index} {fact}");
                let (predicate, blocker) = eligibility.first_blocker().unwrap();
                assert_eq!(predicate, eligibility.facts()[index].0);
                assert_eq!(blocker, &fact);
            }
        }
        assert!(Fact::Satisfied.is_satisfied());
        for fact in [Fact::Unknown, Fact::NotSatisfied, newer] {
            assert!(!fact.is_satisfied());
        }
    }

    #[test]
    fn the_eligibility_evidence_round_trips() {
        let eligibility = with_fact(4, Fact::Unknown);
        let value = serde_json::to_value(&eligibility).unwrap();
        assert_eq!(value["age_and_inactivity"], json!("unknown"));
        assert_eq!(value["fresh_check"], json!("satisfied"));
        assert_eq!(
            serde_json::from_value::<CandidateEligibility>(value.clone()).unwrap(),
            eligibility
        );
        // A value that this build does not know is not `satisfied`, and a
        // missing predicate is not `satisfied`.
        let mut newer = value.clone();
        newer["regenerable"] = json!("probably");
        let decoded: CandidateEligibility = serde_json::from_value(newer).unwrap();
        assert!(!decoded.regenerable.is_recognized());
        assert!(!decoded.is_eligible());
        let mut missing = value;
        missing.as_object_mut().unwrap().remove("fresh_check");
        assert!(serde_json::from_value::<CandidateEligibility>(missing).is_err());
        assert_eq!(
            serde_json::to_string(&EligibilityPredicate::FreshCheck).unwrap(),
            "\"fresh_check\""
        );
    }

    fn candidate_record(eligibility: CandidateEligibility) -> RuleCandidateRecord {
        RuleCandidateRecord {
            candidate: CleanupCandidate {
                target_id: TargetId::new("target_1").unwrap(),
                rule_id: RuleId::new("svalnir.expired-temporary").unwrap(),
                volume_id: VolumeId::new("volume_1").unwrap(),
                path: LosslessPath::from_bytes("/state/temporary/a").unwrap(),
                work_bytes: Some(Bytes::new(4_096)),
                item_count: Some(EntryCount::new(1)),
                estimated_reclaimable_bytes: None,
                facts: CleanupFacts {
                    rule_readiness: RuleReadiness::Ready,
                    hard_protection: ProtectionFact::NotProtected,
                    protected_classes: Vec::new(),
                    owner: OwnerFact::RequestingUser,
                    activity: ActivityFact::Inactive {
                        inactive_for: Nanoseconds::new(7_200_000_000_000),
                    },
                    rebuild_cost: RebuildCost::Low,
                },
            },
            rule: reference("svalnir.expired-temporary", "r1"),
            layout: "temporary-v1".to_owned(),
            eligibility,
        }
    }

    fn automatic_rule() -> Rule {
        Checked::new(declaration(LifecycleState::AutomaticEvictionValidated {
            evidence: evidence(),
        }))
        .unwrap()
    }

    #[test]
    fn a_policy_fact_is_affirmative_only_with_satisfied_evidence() {
        let rule = automatic_rule();
        let candidate = RuleCandidate::new(&rule, candidate_record(satisfied())).unwrap();
        assert!(candidate.is_eligible());
        assert_eq!(candidate.layout, "temporary-v1");
        // An unknown predicate with no affirmative policy fact behind it
        // is a consistent, ineligible candidate.
        let waiting = RuleCandidate::new(&rule, candidate_record(with_fact(8, Fact::Unknown)));
        assert!(!waiting.unwrap().is_eligible());

        // `Ready` (1), the requesting user (2), no protected class and a
        // known rebuild cost (4), `Inactive` (5), no product protection
        // (7), and a known charge (8) each need their predicate.
        for index in [0, 1, 3, 4, 6, 7] {
            for fact in [
                Fact::Unknown,
                Fact::NotSatisfied,
                Fact::from_wire("probably"),
            ] {
                assert_eq!(
                    RuleCandidate::new(&rule, candidate_record(with_fact(index, fact))),
                    Err(RuleCandidateError::UnsupportedFact),
                    "predicate {index}"
                );
            }
        }
        // The same evidence with the unknown policy fact is consistent.
        let mut record = candidate_record(with_fact(4, Fact::Unknown));
        record.candidate.facts.activity = ActivityFact::Unknown;
        assert!(!RuleCandidate::new(&rule, record).unwrap().is_eligible());
        let mut record = candidate_record(with_fact(7, Fact::Unknown));
        record.candidate.work_bytes = None;
        RuleCandidate::new(&rule, record).unwrap();
        let mut record = candidate_record(with_fact(6, Fact::Unknown));
        record.candidate.facts.hard_protection = ProtectionFact::Unknown;
        record.candidate.facts.protected_classes = vec![ProtectedDataClass::Database];
        RuleCandidate::new(&rule, record).unwrap();
        let mut record = candidate_record(with_fact(3, Fact::Unknown));
        record.candidate.facts.rebuild_cost = RebuildCost::Unknown;
        record.candidate.facts.protected_classes = vec![ProtectedDataClass::Database];
        let record = RuleCandidate::new(&rule, record).unwrap().into_inner();
        assert_eq!(record.candidate.facts.rebuild_cost, RebuildCost::Unknown);
    }

    #[test]
    fn a_policy_fact_claims_no_more_than_the_declaration() {
        let rule = automatic_rule();
        let new = |change: &dyn Fn(&mut RuleCandidateRecord)| {
            let mut record = candidate_record(satisfied());
            change(&mut record);
            RuleCandidate::new(&rule, record).map(|_| ())
        };
        // The record names the revision and a layout of the declaration.
        for change in [
            (&|r: &mut RuleCandidateRecord| {
                r.rule = reference("xcode.inactive-derived-data", "r1");
            }) as &dyn Fn(&mut RuleCandidateRecord),
            &|r| r.rule = reference("svalnir.expired-temporary", "r2"),
            &|r| r.layout = "temporary-v2".to_owned(),
            &|r| r.candidate.rule_id = RuleId::new("npm.content-cache").unwrap(),
        ] {
            assert_eq!(new(change), Err(RuleCandidateError::Rule));
        }
        for change in [
            // A cheaper rebuild than the declaration states.
            (&|r: &mut RuleCandidateRecord| r.candidate.facts.rebuild_cost = RebuildCost::Medium)
                as &dyn Fn(&mut RuleCandidateRecord),
            // An inactive time shorter than the quiescence time.
            &|r| {
                r.candidate.facts.activity = ActivityFact::Inactive {
                    inactive_for: Nanoseconds::new(59_999_999_999),
                };
            },
            // A charge over the candidate ceiling.
            &|r| r.candidate.work_bytes = Some(Bytes::new(1_000_001)),
            &|r| r.candidate.item_count = Some(EntryCount::new(101)),
        ] {
            assert_eq!(new(change), Err(RuleCandidateError::Declaration));
        }
        new(&|r| {
            r.candidate.facts.activity = ActivityFact::Inactive {
                inactive_for: Nanoseconds::new(60_000_000_000),
            };
            r.candidate.work_bytes = Some(Bytes::new(1_000_000));
            r.candidate.item_count = Some(EntryCount::new(100));
        })
        .unwrap();

        // `Ready` needs a layout that is validated for automatic eviction.
        for lifecycle in [
            LifecycleState::Proposed,
            LifecycleState::InspectionValidated {
                evidence: evidence(),
            },
            LifecycleState::ManualActionValidated {
                evidence: evidence(),
            },
            LifecycleState::Disabled {
                inspection_permitted: true,
            },
            LifecycleState::Retired,
        ] {
            let rule: Rule = Checked::new(declaration(lifecycle)).unwrap();
            assert_eq!(
                RuleCandidate::new(&rule, candidate_record(satisfied())).map(|_| ()),
                Err(RuleCandidateError::Declaration)
            );
            // The same candidate with a rule that is not ready is
            // consistent.
            let mut record = candidate_record(satisfied());
            record.candidate.facts.rule_readiness = RuleReadiness::NotReady;
            RuleCandidate::new(&rule, record).unwrap();
        }
    }
}
