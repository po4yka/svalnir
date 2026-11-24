//! The builder of a manual cleanup plan.
//!
//! Owning specifications: `docs/INTERFACES.md` section 4 for the modes,
//! `docs/ACTION_CONTRACTS.md` sections 4, 5, and 7 for the protections and
//! the charges, and `docs/CLEANUP_RULES.md` sections 5, 6, 8, and 9 for the
//! exclusions, the eligibility of a rule candidate, and the overlap of
//! entries.

use std::collections::{BTreeMap, BTreeSet};

use thiserror::Error;

use super::context::{
    PlanBatch, PlanBuildError, PlanContext, PlanOutcome, PlanParts, PlanPreview, SizeEstimate,
    TargetPreview,
};
use super::mode::{CleanupMode, PlanMode};
use super::paths::{
    Components, PathSet, components, is_canonical, is_canonical_relative, joins_to,
};
use super::reason::{Omission, OmissionReason, push_reason};
use crate::action::{
    AdmittedRepository, ErrorFamily, Escalation, ExecutorRole, FileBinding, FileObjectType,
    MAX_PLAN_TARGETS, Plan, PlanContent, PlanLimits, PlanTarget, PlannedStep, TargetBinding,
    WorkCharge,
};
use crate::file::{FileObjectEvidence, LosslessPath};
use crate::id::{MountId, RootId, RuleId, StepId, TargetId, VolumeId};
use crate::policy::ProtectionFact;
use crate::process::Uid;
use crate::quantity::{EntryCount, Nanoseconds};
use crate::rule::{
    CandidateEligibility, Fact, Rule, RuleCandidate, RuleMode, RuleRef, RuleRefusal,
};

/// The largest number of entries in one selection: the largest number of
/// targets in one plan. A larger selection is rejected: the caller narrows
/// it.
pub const MAX_SELECTED_ENTRIES: usize = MAX_PLAN_TARGETS;

/// The mode of a cleanup request, with the rule revision of the `evict`
/// mode.
#[derive(Debug, Clone, Copy)]
pub enum ModeSelection<'a> {
    /// `trash`: `MoveToTrash`.
    Trash,
    /// `permanent`: `DeleteSelectedFiles`.
    Permanent,
    /// `evict`: `EvictRegenerableData` of one exact rule revision.
    Evict {
        /// The result of the registry lookup of the exact rule identity and
        /// revision ([`RuleRegistry`](crate::rule::RuleRegistry)). A refusal
        /// gives no plan: no other revision and no generic cleaner takes the
        /// place of the rule.
        rule: Result<&'a Rule, RuleRefusal>,
    },
}

impl ModeSelection<'_> {
    /// The mode.
    pub const fn mode(&self) -> CleanupMode {
        match self {
            Self::Trash => CleanupMode::Trash,
            Self::Permanent => CleanupMode::Permanent,
            Self::Evict { .. } => CleanupMode::Evict,
        }
    }
}

/// The evidence that an entry is a candidate of one rule revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleEvidence {
    /// The exact rule revision that found the entry.
    pub rule: RuleRef,
    /// The layout that the rule found.
    pub layout: String,
    /// The evidence of the ten eligibility predicates.
    pub eligibility: CandidateEligibility,
}

impl RuleEvidence {
    /// The evidence of a checked rule candidate.
    pub fn of(candidate: &RuleCandidate) -> Self {
        Self {
            rule: candidate.rule.clone(),
            layout: candidate.layout.clone(),
            eligibility: candidate.eligibility.clone(),
        }
    }
}

/// One selected entry: a candidate of a scan or of a rule, with its
/// identity evidence and its size estimates.
///
/// The caller establishes each fact. A fact that is not known is `None` or
/// `Unknown`; the builder then leaves the entry out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupEntry {
    /// The identity of the target.
    pub target_id: TargetId,
    /// The identity of the step that removes the entry.
    pub step_id: StepId,
    /// The absolute path of the entry, for the exclusion lists and for
    /// display. The plan does not have it; the plan has the root path and
    /// the relative entry.
    pub path: LosslessPath,
    /// The approved root.
    pub root_id: RootId,
    /// The absolute path of the approved root, as the caller resolved it.
    /// Each entry of one root has the same root path. The plan binds it.
    pub root_path: LosslessPath,
    /// The native identifiers of the root directory, as the caller
    /// measured them. Each entry of one root has the same root object. The
    /// plan binds it.
    pub root_object: FileObjectEvidence,
    /// The entry, relative to the root. `path` is exactly `root_path` and
    /// then this entry.
    pub relative_entry: LosslessPath,
    /// The volume of the entry.
    pub volume_id: VolumeId,
    /// The mount generation of the volume.
    pub mount_id: MountId,
    /// The type of the object.
    pub object_type: FileObjectType,
    /// The owner of the object. `None` when it is not known.
    pub owner: Option<Uid>,
    /// The native identifiers of the object. `None` means that the
    /// evidence is absent; the adapter decides whether it can act.
    pub object: Option<FileObjectEvidence>,
    /// The number of names of the object (`st_nlink`). `None` when it is
    /// not known: an unknown number is not one. The `evict` mode needs it
    /// for a rule that skips hard-linked objects.
    pub link_count: Option<EntryCount>,
    /// The known conservative charge of the entry. `None` when it is not
    /// known: an unknown charge is not zero.
    pub charge: Option<WorkCharge>,
    /// The size estimates.
    pub estimate: SizeEstimate,
    /// The hard protection of the entry (OS-managed storage, swap, and the
    /// control-plane state of Svalnir), as the caller established it.
    pub hard_protection: ProtectionFact,
    /// The other forms of `path` with symbolic links resolved, as the
    /// caller established them for the hard protection: the directory of
    /// the entry resolved and the name, and the entry itself resolved. The
    /// `[protections]` list applies to `path` and to each of these, so an
    /// entry that a symbolic-link component makes look outside an excluded
    /// path is still excluded. Empty when the caller has no other form.
    pub resolved_paths: Vec<LosslessPath>,
    /// The rule evidence, when a rule found the entry. The `evict` mode
    /// needs it.
    pub rule: Option<RuleEvidence>,
    /// The Git repositories in the entry that the discovery admitted
    /// (`docs/CLEANUP_RULES.md` section 6). Empty for an entry with no
    /// repository. The plan binds the list; the executor and the check
    /// before each step compare with it.
    pub repositories: Vec<AdmittedRepository>,
}

/// A selection preset, for example `--profile developer`.
///
/// A preset only filters: an entry that it does not include is left out.
/// It cannot add an entry, enable a rule, remove a protection, or grant
/// authority, and it is not in the plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectionPreset {
    /// The name of the preset, for the explanation.
    pub name: String,
    /// When given, the preset includes only the entries that one of these
    /// rules found.
    pub rules: Option<Vec<RuleId>>,
    /// When given, the preset includes only the entries below one of these
    /// roots.
    pub roots: Option<Vec<RootId>>,
}

impl SelectionPreset {
    fn includes(&self, entry: &CleanupEntry) -> bool {
        let rule_included: bool = self.rules.as_ref().is_none_or(|rules| {
            entry
                .rule
                .as_ref()
                .is_some_and(|evidence| rules.contains(&evidence.rule.id))
        });
        let root_included: bool = self
            .roots
            .as_ref()
            .is_none_or(|roots| roots.contains(&entry.root_id));
        rule_included && root_included
    }
}

/// The limits of a cleanup plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CleanupLimits {
    /// The ceiling of the sum of the charges of the plan: `work_bytes` and
    /// items. The two parts apply independently.
    pub plan: WorkCharge,
    /// The ceiling of one batch. An entry is indivisible: one whose charge
    /// is larger is left out.
    pub batch: WorkCharge,
    /// The time that the execution can use after admission.
    pub execution_deadline: Nanoseconds,
    /// The time for which the outcome of one step is observed.
    pub verification_window: Nanoseconds,
}

/// A request for a manual cleanup plan.
#[derive(Debug, Clone, Copy)]
pub struct CleanupRequest<'a> {
    /// The mode.
    pub mode: ModeSelection<'a>,
    /// The selected entries, in any sequence.
    pub entries: &'a [CleanupEntry],
    /// The selection preset, when the request has one.
    pub preset: Option<&'a SelectionPreset>,
    /// The limits.
    pub limits: CleanupLimits,
}

/// An entry that no check leaves out, with the facts that the plan needs.
struct Eligible<'a> {
    entry: &'a CleanupEntry,
    charge: WorkCharge,
    owner: Uid,
    /// The folded components of the path, for the overlap check.
    path: Components,
}

/// The checks of the `evict` mode.
struct RuleChecks<'a> {
    rule: &'a Rule,
    /// The protected descendants of the rule, relative to a root.
    descendants: PathSet,
}

/// The lists and the settings that the entry checks use.
struct EntryChecks<'a> {
    principal: Uid,
    excluded: PathSet,
    preset: Option<&'a SelectionPreset>,
    rule: Option<RuleChecks<'a>>,
}

impl EntryChecks<'_> {
    /// The reasons that leave an entry out, before the overlap check and
    /// the limits: protections and exclusions first, then the target
    /// eligibility, then the facts that are not known.
    fn reasons(&self, entry: &CleanupEntry) -> Vec<OmissionReason> {
        use OmissionReason as Reason;
        let mut reasons: Vec<Reason> = Vec::new();
        let mut add = |reason: Reason| push_reason(&mut reasons, reason);

        if entry.hard_protection == ProtectionFact::Protected {
            add(Reason::HardProtected);
        }
        if self.excluded.overlaps(&entry.path)
            || entry
                .resolved_paths
                .iter()
                .any(|form| self.excluded.overlaps(form))
        {
            add(Reason::ExcludedPath);
        }
        if entry.owner.is_some_and(|owner| owner != self.principal) {
            add(Reason::OtherUser);
        }
        if !entry.object_type.is_recognized() {
            add(Reason::ObjectTypeNotSupported);
        }
        if self.preset.is_some_and(|preset| !preset.includes(entry)) {
            add(Reason::NotInPreset);
        }
        if let Some(checks) = &self.rule {
            Self::rule_reasons(checks, entry, &mut add);
        }
        if entry
            .charge
            .is_some_and(|charge| charge.items == EntryCount::ZERO)
        {
            add(Reason::NoItems);
        }

        if self.excluded.unresolved {
            add(Reason::HomeDirectoryUnknown);
        }
        // The exclusion lists are applied to `path`, and the plan binds
        // the root and `relative_entry`. The two must name the same entry:
        // the path is exactly the root path and then the relative entry.
        let path_agrees: bool = is_canonical(&entry.path)
            && is_canonical(&entry.root_path)
            && is_canonical_relative(&entry.relative_entry)
            && joins_to(&entry.path, &entry.root_path, &entry.relative_entry);
        if !path_agrees {
            add(Reason::PathNotCanonical);
        }
        if entry.hard_protection == ProtectionFact::Unknown {
            add(Reason::ProtectionUnknown);
        }
        if entry.owner.is_none() {
            add(Reason::OwnerUnknown);
        }
        if self
            .rule
            .as_ref()
            .is_some_and(|checks| Self::skips_links(checks, entry))
            && entry.link_count.is_none()
        {
            add(Reason::LinkCountUnknown);
        }
        if let (Some(_), Some(evidence)) = (&self.rule, &entry.rule) {
            for (predicate, fact) in evidence.eligibility.facts() {
                if !matches!(fact, Fact::Satisfied | Fact::NotSatisfied) {
                    add(Reason::EligibilityUnknown { predicate });
                }
            }
        }
        if entry.charge.is_none() {
            add(Reason::WorkChargeUnknown);
        }
        if let (Some(checks), Some(charge)) = (&self.rule, entry.charge)
            && !charge.fits_in(&checks.rule.budget.per_candidate)
        {
            add(Reason::ExceedsCandidateCeiling);
        }
        reasons
    }

    /// Whether the rule skips the entry when it has more than one name:
    /// the rule has `skip_hard_linked`, and the entry is not a directory.
    fn skips_links(checks: &RuleChecks<'_>, entry: &CleanupEntry) -> bool {
        checks.rule.exclusions.skip_hard_linked
            && !matches!(entry.object_type, FileObjectType::Directory)
    }

    /// The reasons of the `evict` mode that the rule revision gives: the
    /// entry is a candidate of the exact revision, the revision is
    /// validated for manual eviction of the layout, and the mandatory
    /// exclusions and the eligibility predicates of the rule apply
    /// unchanged.
    fn rule_reasons(
        checks: &RuleChecks<'_>,
        entry: &CleanupEntry,
        add: &mut impl FnMut(OmissionReason),
    ) {
        use OmissionReason as Reason;
        let rule: &Rule = checks.rule;
        let Some(evidence) = entry
            .rule
            .as_ref()
            .filter(|evidence| evidence.rule == rule.reference)
        else {
            add(Reason::RuleNotSelected);
            return;
        };
        match rule.permits(&evidence.layout, &RuleMode::ManualEviction) {
            Ok(()) => {}
            Err(RuleRefusal::UnknownLayout) => add(Reason::LayoutNotSupported),
            Err(
                RuleRefusal::ModeNotValidated
                | RuleRefusal::UnknownRule
                | RuleRefusal::UnknownRevision,
            ) => add(Reason::ModeNotValidated),
        }
        if !rule
            .exclusions
            .supported_object_types
            .contains(&entry.object_type)
        {
            add(Reason::ObjectTypeNotSupported);
        }
        if checks.descendants.overlaps(&entry.relative_entry) {
            add(Reason::RuleExclusion);
        }
        // Only a count of one is one name. A count of zero is an object
        // that was unlinked after the measurement.
        // A hard-linked object has a name that the rule did not find. Its
        // removal frees no storage, and the other name can be outside the
        // root. A directory has one name; its link count is the number of
        // its subdirectories.
        if Self::skips_links(checks, entry)
            && entry
                .link_count
                .is_some_and(|count| count != EntryCount::new(1))
        {
            add(Reason::RuleExclusion);
        }
        for (predicate, fact) in evidence.eligibility.facts() {
            if matches!(fact, Fact::NotSatisfied) {
                add(Reason::EligibilityNotSatisfied { predicate });
            }
        }
    }
}

fn omission(entry: &CleanupEntry, reasons: Vec<OmissionReason>) -> Omission {
    Omission {
        target_id: entry.target_id.clone(),
        path: Some(entry.path.clone()),
        reasons,
        charge: entry.charge,
        estimate: entry.estimate,
    }
}

/// Checks the inputs that do not depend on an entry.
fn check_request(request: &CleanupRequest<'_>) -> Result<(), PlanBuildError> {
    let count: usize = request.entries.len();
    if count > MAX_SELECTED_ENTRIES {
        return Err(PlanBuildError::TooManyEntries {
            count,
            limit: MAX_SELECTED_ENTRIES,
        });
    }
    let mut target_ids: BTreeSet<&TargetId> = BTreeSet::new();
    let mut step_ids: BTreeSet<&StepId> = BTreeSet::new();
    for entry in request.entries {
        if !target_ids.insert(&entry.target_id) || !step_ids.insert(&entry.step_id) {
            return Err(PlanBuildError::DuplicateIdentity);
        }
    }
    // One root identity has one path and one object. With two paths, the
    // exclusion check of one entry would not be for the object that the
    // plan binds.
    let mut roots: BTreeMap<&RootId, (&LosslessPath, &FileObjectEvidence)> = BTreeMap::new();
    for entry in request.entries {
        let root = (&entry.root_path, &entry.root_object);
        if *roots.entry(&entry.root_id).or_insert(root) != root {
            return Err(PlanBuildError::RootPath);
        }
    }
    let limits: &CleanupLimits = &request.limits;
    if limits.execution_deadline == Nanoseconds::ZERO
        || limits.verification_window == Nanoseconds::ZERO
    {
        return Err(PlanBuildError::Limits);
    }
    Ok(())
}

/// The rule checks of the request. `None` for a mode with no rule.
fn rule_checks<'a>(mode: &ModeSelection<'a>) -> Result<Option<RuleChecks<'a>>, PlanBuildError> {
    let ModeSelection::Evict { rule } = mode else {
        return Ok(None);
    };
    let rule: &Rule = (*rule).map_err(PlanBuildError::Rule)?;
    // A manual plan has the user executor. A rule of the helper executor
    // needs a privilege grant, which a manual plan does not name.
    if !matches!(rule.executor, ExecutorRole::User) {
        return Err(PlanBuildError::UnsupportedExecutor);
    }
    Ok(Some(RuleChecks {
        rule,
        descendants: PathSet::of_relative(&rule.exclusions.descendants),
    }))
}

/// Builds the plan of a manual cleanup.
///
/// The entries are examined in the sequence of their target identities, so
/// the result does not depend on the sequence of the input. An entry is in
/// the plan only when each of these is true:
///
/// - Its hard protection is `NotProtected`, and no path of
///   `[protections].excluded_paths` is the entry, contains it, or is inside
///   it. The home directory resolves each `~/` path of that list.
/// - Its owner is known and is the principal of the plan.
/// - Its path and its root path are absolute and canonical, and the path
///   is exactly the root path and then the relative entry. The exclusion
///   lists are then applied to the object that the plan binds.
/// - Its object type is one that this build recognizes.
/// - Its charge is known and has a minimum of one item.
/// - The preset, when there is one, includes it.
/// - For the `evict` mode: the entry is a candidate of the exact rule
///   revision, the revision is validated for manual eviction of the layout,
///   no protected descendant of the rule overlaps the entry, the rule
///   removes the object type, for a rule that skips hard-linked objects an
///   entry that is not a directory has a known link count of one, each of
///   the ten eligibility predicates is
///   `satisfied`, and the charge fits the candidate ceiling of the rule.
/// - No other selected entry that passed the checks above is the same
///   path or contains it. The comparison is made before the limits, so an
///   entry inside a parent that a limit leaves out is also left out.
/// - No other selected entry that passed the checks above has the same
///   volume and the same native object identifiers.
/// - Its charge fits one batch and fits in what remains of the plan
///   ceiling. For the `evict` mode, the plan ceiling is not larger than the
///   pass ceiling of the rule.
///
/// Each other entry is in `preview.omitted` with each reason. When no
/// entry is in the plan, the result has no plan; that is not an error.
///
/// The plan has the manual trigger, the user executor, one step for each
/// target, the sum of the charges as its work limit, and no force
/// strategy. The steps and the batches have the sequence of the target
/// identities.
///
/// # Errors
///
/// Returns a [`PlanBuildError`] when the selection is too large, two
/// entries have one identity, one root identity has two root paths or two
/// root objects, a duration is zero, the lifetime is zero or
/// overflows, the authority names a privilege grant or one grant two
/// times, the registry refused the rule of the `evict` mode, the rule
/// needs the helper executor, or the check of the foundation rejects the
/// content.
pub fn build_cleanup_plan(
    context: &PlanContext<'_>,
    request: &CleanupRequest<'_>,
) -> Result<PlanOutcome, PlanBuildError> {
    check_request(request)?;
    // An error of the lifetime or of the authority is an error also when
    // no entry is in the plan.
    context.validity()?;
    context.canonical_authority()?;
    let mode: CleanupMode = request.mode.mode();
    let checks: EntryChecks<'_> = EntryChecks {
        principal: context.principal.uid,
        excluded: PathSet::resolve(
            context.protections.excluded_paths.iter(),
            context.home_directory,
        ),
        preset: request.preset,
        rule: rule_checks(&request.mode)?,
    };

    let mut omitted: Vec<Omission> = Vec::new();
    let eligible: Vec<Eligible<'_>> = examine(&checks, request.entries, &mut omitted);
    let disjoint: Vec<Eligible<'_>> = remove_overlaps(eligible, &mut omitted);
    // The finite bounds of the rule apply unchanged to a manual eviction:
    // the plan charges no more than one pass of the rule.
    let plan_ceiling: WorkCharge = match &checks.rule {
        Some(checks) => request.limits.plan.min(checks.rule.budget.per_pass),
        None => request.limits.plan,
    };
    let included: Vec<Eligible<'_>> =
        fill(disjoint, plan_ceiling, &request.limits.batch, &mut omitted);
    omitted.sort_by(|left, right| left.target_id.cmp(&right.target_id));

    let mut preview: PlanPreview = PlanPreview {
        targets: included
            .iter()
            .map(|eligible| TargetPreview {
                target_id: eligible.entry.target_id.clone(),
                path: Some(eligible.entry.path.clone()),
                estimate: eligible.entry.estimate,
            })
            .collect(),
        batches: Vec::new(),
        omitted,
        preset: request.preset.map(|preset| preset.name.clone()),
    };
    let plan: Option<Plan> = if included.is_empty() {
        None
    } else {
        let rule: Option<RuleRef> = checks
            .rule
            .as_ref()
            .map(|checks| checks.rule.reference.clone());
        let plan: Plan =
            context.seal(plan_parts(&included, mode, rule.as_ref(), &request.limits)?)?;
        preview.batches =
            split_batches(&plan, &request.limits.batch).map_err(|_| PlanBuildError::Limits)?;
        Some(plan)
    };
    Ok(PlanOutcome {
        mode: PlanMode::Cleanup(mode),
        plan,
        preview,
    })
}

/// Examines the entries in the sequence of their target identities. An
/// entry with a reason goes to `omitted`.
fn examine<'a>(
    checks: &EntryChecks<'_>,
    entries: &'a [CleanupEntry],
    omitted: &mut Vec<Omission>,
) -> Vec<Eligible<'a>> {
    let mut sorted: Vec<&CleanupEntry> = entries.iter().collect();
    sorted.sort_by(|left, right| left.target_id.cmp(&right.target_id));
    let mut eligible: Vec<Eligible<'a>> = Vec::new();
    for entry in sorted {
        let reasons: Vec<OmissionReason> = checks.reasons(entry);
        match (reasons.is_empty(), entry.charge, entry.owner) {
            (true, Some(charge), Some(owner)) => eligible.push(Eligible {
                entry,
                charge,
                owner,
                path: components(entry.path.as_bytes()),
            }),
            // An entry with no reason has a known charge and a known
            // owner. These arms keep an unknown fact out if a later change
            // breaks that rule.
            (true, None, _) => {
                omitted.push(omission(entry, vec![OmissionReason::WorkChargeUnknown]));
            }
            (true, _, None) => omitted.push(omission(entry, vec![OmissionReason::OwnerUnknown])),
            (false, _, _) => omitted.push(omission(entry, reasons)),
        }
    }
    eligible
}

/// The targets, the steps, and the limits of the plan: one step for each
/// target, in the sequence of the entries, and the sum of the charges as
/// the work limit.
fn plan_parts(
    included: &[Eligible<'_>],
    mode: CleanupMode,
    rule: Option<&RuleRef>,
    limits: &CleanupLimits,
) -> Result<PlanParts, PlanBuildError> {
    let mut total: WorkCharge = WorkCharge::ZERO;
    let mut targets: Vec<PlanTarget> = Vec::with_capacity(included.len());
    let mut steps: Vec<PlannedStep> = Vec::with_capacity(included.len());
    for Eligible {
        entry,
        charge,
        owner,
        ..
    } in included
    {
        // `fill` admits an entry only when the sum fits the plan ceiling,
        // so this sum does not overflow.
        total = total.checked_add(*charge).ok_or(PlanBuildError::Limits)?;
        targets.push(PlanTarget {
            target_id: entry.target_id.clone(),
            binding: TargetBinding::File(FileBinding {
                root_id: entry.root_id.clone(),
                root_path: entry.root_path.clone(),
                root_object: entry.root_object,
                relative_entry: entry.relative_entry.clone(),
                volume_id: entry.volume_id.clone(),
                mount_id: entry.mount_id.clone(),
                object_type: entry.object_type.clone(),
                owner: *owner,
                object: entry.object,
                rule: rule.cloned(),
                // The layout of the rule evidence of the entry. The plan
                // binds a rule only for the `evict` mode, and each entry of
                // that mode has the evidence of that rule.
                layout: rule
                    .and(entry.rule.as_ref())
                    .map(|evidence| evidence.layout.clone()),
                charge: *charge,
                // Only a rule target admits repositories.
                repositories: if rule.is_some() {
                    entry.repositories.clone()
                } else {
                    Vec::new()
                },
            }),
        });
        steps.push(PlannedStep {
            step_id: entry.step_id.clone(),
            action_class: mode.action_class(),
            target_id: entry.target_id.clone(),
        });
    }
    Ok(PlanParts {
        targets,
        steps,
        limits: PlanLimits {
            work: Some(total),
            execution_deadline: limits.execution_deadline,
            grace: None,
            verification_window: limits.verification_window,
            escalation: Escalation::None,
        },
    })
}

/// True when `path` is `parent` or is inside it: the folded components of
/// `parent` are the first components of `path`.
///
/// The comparison is exact after the case fold. It is not the fail-closed
/// comparison of the exclusion lists, which counts each pair of non-ASCII
/// components as a match: that rule would leave out each second entry of a
/// directory whose names are not ASCII. Two selected entries that are one
/// object in two normalization forms are found by their object identifiers
/// ([`remove_overlaps`]), when the two have them. An entry with no
/// identifiers, and an entry inside a parent whose name has a different
/// normalization form, is not found: the plan then has two steps for one
/// object, and the second step finds its target absent or changed. No
/// protection depends on this comparison.
fn is_same_or_inside(path: &[Vec<u8>], parent: &[Vec<u8>]) -> bool {
    path.len() >= parent.len() && path.iter().zip(parent).all(|(left, right)| left == right)
}

/// Leaves out each entry that is the same path as a different entry or is
/// inside it, and each entry that is the same object as a different entry
/// (`docs/CLEANUP_RULES.md` section 8).
///
/// The entries arrive in the sequence of their target identities. A
/// shorter path is examined first, so a parent stays and its descendants
/// are left out. Of two entries with the same path, the one with the
/// smaller target identity stays. An entry is compared only with the
/// entries that stay.
///
/// Two entries with the same volume and the same native object identifiers
/// are one object with two names: an alias of a root, a name in a
/// different normalization form, or a hard link. The first one stays. One
/// object then has one step and one charge.
fn remove_overlaps<'a>(
    eligible: Vec<Eligible<'a>>,
    omitted: &mut Vec<Omission>,
) -> Vec<Eligible<'a>> {
    let mut by_depth: Vec<(usize, &Eligible<'a>)> = eligible.iter().enumerate().collect();
    // The sort is stable: entries of one depth keep the sequence of their
    // target identities.
    by_depth.sort_by_key(|(_, eligible)| eligible.path.len());
    let mut kept: Vec<&Components> = Vec::new();
    let mut objects: BTreeSet<(&VolumeId, FileObjectEvidence)> = BTreeSet::new();
    let mut stays: Vec<bool> = vec![false; eligible.len()];
    for (index, candidate) in by_depth {
        let path: &Components = &candidate.path;
        let overlaps: bool = kept.iter().any(|parent| is_same_or_inside(path, parent));
        let repeats: bool = candidate
            .entry
            .object
            .is_some_and(|object| objects.contains(&(&candidate.entry.volume_id, object)));
        // The path of an entry that repeats an object also covers the
        // entries inside it: they are inside the object that stays.
        if !overlaps {
            kept.push(path);
        }
        if !overlaps && !repeats {
            if let Some(object) = candidate.entry.object {
                objects.insert((&candidate.entry.volume_id, object));
            }
            if let Some(flag) = stays.get_mut(index) {
                *flag = true;
            }
        }
    }
    let mut disjoint: Vec<Eligible<'a>> = Vec::new();
    for (eligible, stays) in eligible.into_iter().zip(stays) {
        if stays {
            disjoint.push(eligible);
        } else {
            omitted.push(omission(
                eligible.entry,
                vec![OmissionReason::OverlapsSelectedEntry],
            ));
        }
    }
    disjoint
}

/// Takes the entries in sequence under the batch ceiling and the plan
/// ceiling. An entry is indivisible: one that does not fit is left out, and
/// a later, smaller entry can still fit. The selection has no more entries
/// than a plan has targets, so the target count needs no check here.
fn fill<'a>(
    disjoint: Vec<Eligible<'a>>,
    plan_ceiling: WorkCharge,
    batch: &WorkCharge,
    omitted: &mut Vec<Omission>,
) -> Vec<Eligible<'a>> {
    let mut remaining: WorkCharge = plan_ceiling;
    let mut included: Vec<Eligible<'a>> = Vec::new();
    for eligible in disjoint {
        let charge: WorkCharge = eligible.charge;
        let reason: Option<OmissionReason> = if charge.fits_in(batch) {
            // `checked_sub` gives `None` when a part of the charge is
            // larger than what remains.
            match remaining.checked_sub(charge) {
                Some(left) => {
                    remaining = left;
                    None
                }
                None => Some(OmissionReason::ExceedsPlanLimit),
            }
        } else {
            Some(OmissionReason::ExceedsBatchLimit)
        };
        match reason {
            None => included.push(eligible),
            Some(reason) => omitted.push(omission(eligible.entry, vec![reason])),
        }
    }
    included
}

/// The reason a plan has no batches under a batch ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum BatchError {
    /// The charge of one target is larger than the batch ceiling. A target
    /// is indivisible.
    #[error("the charge of a target is larger than the batch ceiling")]
    ExceedsBatch,
    /// A step names a target that the plan does not have, or the sum of
    /// the charges of one batch overflows.
    #[error("the steps and the charges of the plan do not agree")]
    Content,
}

impl BatchError {
    /// The error family (`docs/ACTION_CONTRACTS.md` section 10).
    pub const fn family(&self) -> ErrorFamily {
        match self {
            Self::ExceedsBatch => ErrorFamily::Limits,
            Self::Content => ErrorFamily::Request,
        }
    }
}

/// Splits the steps of a filesystem plan into the batches that the
/// executor runs: consecutive steps, in the sequence of the plan, whose
/// charges together fit `batch`.
///
/// The function is deterministic, so the coordinator gets the batches of
/// the preview again from the stored plan and the same ceiling. An
/// application plan has no batches.
///
/// # Errors
///
/// Returns [`BatchError::ExceedsBatch`] when the charge of one target is
/// larger than `batch`, and [`BatchError::Content`] when a step names no
/// target of the plan.
pub fn split_batches(plan: &PlanContent, batch: &WorkCharge) -> Result<Vec<PlanBatch>, BatchError> {
    let has_application: bool = plan
        .targets
        .iter()
        .any(|target| !matches!(target.binding, TargetBinding::File(_)));
    if has_application {
        return Ok(Vec::new());
    }
    let mut batches: Vec<PlanBatch> = Vec::new();
    let mut current: Option<PlanBatch> = None;
    for step in &plan.steps {
        let target: &PlanTarget = plan.target(&step.target_id).ok_or(BatchError::Content)?;
        let charge: WorkCharge = match &target.binding {
            TargetBinding::File(file) => file.charge,
            TargetBinding::OwnerOperation(owner) => owner.charge,
            TargetBinding::Application(_) | TargetBinding::Process(_) => {
                return Err(BatchError::Content);
            }
        };
        if !charge.fits_in(batch) {
            return Err(BatchError::ExceedsBatch);
        }
        let extended: Option<WorkCharge> = match &current {
            Some(open) => open
                .charge
                .checked_add(charge)
                .filter(|sum| sum.fits_in(batch)),
            None => None,
        };
        if let (Some(open), Some(sum)) = (current.as_mut(), extended) {
            open.steps.push(step.step_id.clone());
            open.charge = sum;
        } else {
            batches.extend(current.take());
            current = Some(PlanBatch {
                steps: vec![step.step_id.clone()],
                charge,
            });
        }
    }
    batches.extend(current);
    Ok(batches)
}
