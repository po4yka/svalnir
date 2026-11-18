//! The explanation of a plan, for `clean show --plan ID` and for the review
//! before an approval.
//!
//! Owning specifications: `docs/CLEANUP_RULES.md` section 13 (preview and
//! explainability) and `docs/INTERFACES.md` section 5 (the scope and the
//! consequence that a client shows before it records an approval).
//!
//! The explanation is data. A client makes its text from it. It keeps an
//! admission charge apart from a size estimate, and it never states an
//! estimate as reclaimed capacity.

use serde::Serialize;

use super::apply::{BoundRevisions, bound_revisions};
use super::context::{PlanBatch, PlanOutcome, SizeEstimate, TargetPreview};
use super::mode::{CleanupMode, PlanMode, StopKind, mode_of};
use super::reason::Omission;
use crate::action::{
    ActionClass, FileObjectType, Plan, PlanTarget, TargetBinding, Validity, WorkCharge,
};
use crate::digest::ContentDigest;
use crate::file::LosslessPath;
use crate::id::{
    ApplicationInstanceId, MembershipSnapshotId, PlanId, ProcessGenerationId, RootId, TargetId,
    VolumeId,
};
use crate::policy::EvaluationClock;
use crate::process::{Pid, Uid};
use crate::quantity::{Bytes, Nanoseconds};
use crate::rule::RuleRef;
use crate::time::{MonotonicNanos, WallTime};

/// The statement that each explanation has about its sizes.
pub const ESTIMATE_STATEMENT: &str = "Each size is an estimate from the time of the plan. An estimate is not a promise of \
     reclaimed capacity, and the admission charge is not a size.";

/// The material consequence of a mode. A client shows it before it records
/// an approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Consequence {
    /// The entries move to Trash. That is not reclaimed capacity.
    TrashNotReclaimed,
    /// The entries are removed permanently. There is no undo.
    PermanentNoUndo,
    /// The rule removes its candidates permanently. There is no undo, and
    /// the producer must make the data again.
    EvictionNoUndo,
    /// The application gets a request to exit and can decline it.
    GracefulExit,
    /// The application gets a request to exit and is forced to exit if it
    /// runs after the grace period.
    ForceAfterGrace,
    /// The application is forced to exit with no request first.
    ImmediateForce,
}

impl Consequence {
    /// The consequence of a mode.
    pub const fn of(mode: PlanMode) -> Self {
        match mode {
            PlanMode::Cleanup(CleanupMode::Trash) => Self::TrashNotReclaimed,
            PlanMode::Cleanup(CleanupMode::Permanent) => Self::PermanentNoUndo,
            PlanMode::Cleanup(CleanupMode::Evict) => Self::EvictionNoUndo,
            PlanMode::Stop(StopKind::Graceful) => Self::GracefulExit,
            PlanMode::Stop(StopKind::ForceAfterGrace) => Self::ForceAfterGrace,
            PlanMode::Stop(StopKind::ImmediateForce) => Self::ImmediateForce,
        }
    }

    /// The statement of the consequence.
    pub const fn statement(self) -> &'static str {
        match self {
            Self::TrashNotReclaimed => {
                "The entries move to Trash. A move to Trash is not reclaimed capacity. Svalnir \
                 does not empty Trash and does not promise that an entry can be restored."
            }
            Self::PermanentNoUndo => {
                "The entries are removed permanently. Permanent removal has no undo."
            }
            Self::EvictionNoUndo => {
                "The rule removes the entries permanently. Permanent removal has no undo. The \
                 producer must make the data again."
            }
            Self::GracefulExit => {
                "The application gets a request to exit. It can decline the request or show a \
                 dialog. No force step follows."
            }
            Self::ForceAfterGrace => {
                "The application gets a request to exit. If it runs after the grace period, it \
                 is forced to exit. Data that is not saved can be lost."
            }
            Self::ImmediateForce => {
                "The application is forced to exit with no request to exit first. Data that is \
                 not saved can be lost."
            }
        }
    }

    /// Whether the mode removes data with no undo, or can lose data that
    /// is not saved.
    pub const fn is_irreversible(self) -> bool {
        !matches!(self, Self::TrashNotReclaimed | Self::GracefulExit)
    }
}

/// The validity of a plan at the time of the explanation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExpiryView {
    /// The wall-clock time at which the plan was built, for display only.
    /// The expiry is a monotonic time.
    pub created_wall: WallTime,
    /// The monotonic time at which the plan was built.
    pub created_at: MonotonicNanos,
    /// The monotonic time at which the plan expires.
    pub expires_at: MonotonicNanos,
    /// The time for which the plan is valid.
    pub lifetime: Option<Nanoseconds>,
    /// Whether the plan is expired at the time of the explanation. It is
    /// also expired when the clock is in a different clock domain or boot.
    pub expired: bool,
    /// The time that remains. `None` when the plan is expired.
    pub remaining: Option<Nanoseconds>,
}

impl ExpiryView {
    fn of(plan: &Plan, clock: &EvaluationClock) -> Self {
        let validity: &Validity = &plan.validity;
        let expired: bool = plan.is_expired(clock);
        Self {
            created_wall: validity.created_wall,
            created_at: validity.created_at,
            expires_at: validity.expires_at,
            lifetime: validity
                .expires_at
                .checked_duration_since(validity.created_at),
            expired,
            remaining: if expired {
                None
            } else {
                validity.expires_at.checked_duration_since(clock.now)
            },
        }
    }
}

/// One member of an application target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MemberView {
    /// The identity of the process generation.
    pub generation_id: ProcessGenerationId,
    /// The process ID at the time of the plan.
    pub pid: Pid,
    /// The executable path, when the plan has the evidence.
    pub executable: Option<LosslessPath>,
}

/// One target of a plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TargetExplanation {
    /// A file entry.
    File {
        /// The identity of the target.
        target_id: TargetId,
        /// The path at the time of the plan, for display. `None` when the
        /// preview has no record of the target.
        path: Option<LosslessPath>,
        /// The approved root.
        root_id: RootId,
        /// The entry, relative to the root.
        relative_entry: LosslessPath,
        /// The volume.
        volume_id: VolumeId,
        /// The type of the object.
        object_type: FileObjectType,
        /// The owner.
        owner: Uid,
        /// Whether the plan has the native identifiers of the object.
        has_object_evidence: bool,
        /// The rule revision that selected the entry.
        rule: Option<RuleRef>,
        /// The admission charge. It is not a size.
        admission_charge: WorkCharge,
        /// The size estimates. The estimate of reclaimable bytes is `None`
        /// for a mode that reclaims no capacity.
        estimate: SizeEstimate,
    },
    /// An application or a managed job.
    Application {
        /// The identity of the target.
        target_id: TargetId,
        /// The running instance.
        instance_id: ApplicationInstanceId,
        /// The member list that the plan froze.
        membership: MembershipSnapshotId,
        /// The members. No other process is a target.
        members: Vec<MemberView>,
    },
}

/// The sums of a plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Totals {
    /// The number of targets.
    pub targets: usize,
    /// The sum of the admission charges of a filesystem plan.
    pub admission_charge: Option<WorkCharge>,
    /// The sum of the estimates of the logical size. `None` when a target
    /// has no estimate.
    pub estimated_logical_bytes: Option<Bytes>,
    /// The sum of the estimates of reclaimable bytes. `None` when a target
    /// has no estimate, and for a mode that reclaims no capacity.
    pub estimated_reclaimable_bytes: Option<Bytes>,
}

/// The fields of a sealed plan that an approval covers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PlanSummary {
    /// The identity of the plan.
    pub plan_id: PlanId,
    /// The digest of the plan content. An approval names it.
    pub digest: ContentDigest,
    /// The action classes of the steps, each one time, in the sequence of
    /// the steps.
    pub action_classes: Vec<ActionClass>,
    /// The policy revision, the grant generations, and the rule revisions
    /// that the plan binds.
    pub revisions: BoundRevisions,
    /// The validity.
    pub expiry: ExpiryView,
    /// The time that the execution can use after admission.
    pub execution_deadline: Nanoseconds,
    /// The grace period between a graceful request and a force step.
    pub grace: Option<Nanoseconds>,
    /// The time for which the outcome of one step is observed.
    pub verification_window: Nanoseconds,
}

/// The explanation of the result of a builder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PlanExplanation {
    /// The mode.
    pub mode: PlanMode,
    /// The consequence of the mode.
    pub consequence: Consequence,
    /// The statement of the consequence.
    pub consequence_statement: &'static str,
    /// Whether the effect of the mode counts as reclaimed capacity. A move
    /// to Trash and an application stop do not.
    pub counts_as_reclaimed_capacity: bool,
    /// The statement about the sizes: [`ESTIMATE_STATEMENT`].
    pub estimate_statement: &'static str,
    /// The sealed plan. `None` when no entry is in the plan; nothing can
    /// be approved then.
    pub plan: Option<PlanSummary>,
    /// The targets, in the sequence of the plan.
    pub targets: Vec<TargetExplanation>,
    /// The sums.
    pub totals: Totals,
    /// The batches of a filesystem plan.
    pub batches: Vec<PlanBatch>,
    /// Each entry that was left out, with each reason.
    pub omitted: Vec<Omission>,
    /// The name of the selection preset, when one filtered the entries. A
    /// preset grants no authority.
    pub preset: Option<String>,
}

/// The explanation of one target. With `reclaims` false, the mode
/// reclaims no capacity, and the target has no estimate of reclaimable
/// bytes: an estimate for a permanent removal is not shown for a move to
/// Trash.
fn target_explanation(
    target: &PlanTarget,
    preview: Option<&TargetPreview>,
    reclaims: bool,
) -> TargetExplanation {
    match &target.binding {
        TargetBinding::File(file) => TargetExplanation::File {
            target_id: target.target_id.clone(),
            path: preview.and_then(|preview| preview.path.clone()),
            root_id: file.root_id.clone(),
            relative_entry: file.relative_entry.clone(),
            volume_id: file.volume_id.clone(),
            object_type: file.object_type.clone(),
            owner: file.owner,
            has_object_evidence: file.object.is_some(),
            rule: file.rule.clone(),
            admission_charge: file.charge,
            estimate: {
                let mut estimate: SizeEstimate = preview.map_or_default(|preview| preview.estimate);
                if !reclaims {
                    estimate.estimated_reclaimable_bytes = None;
                }
                estimate
            },
        },
        TargetBinding::Application(application) => TargetExplanation::Application {
            target_id: target.target_id.clone(),
            instance_id: application.instance_id.clone(),
            membership: application.membership.clone(),
            members: application
                .members
                .iter()
                .map(|member| MemberView {
                    generation_id: member.generation_id.clone(),
                    pid: member.pid,
                    executable: member
                        .executable
                        .as_ref()
                        .map(|executable| executable.path.clone()),
                })
                .collect(),
        },
    }
}

/// The checked sum of one estimate over the targets. `None` when a target
/// has no estimate, when the sum overflows, or when there is no target.
fn sum_estimates(
    targets: &[TargetExplanation],
    part: impl Fn(&SizeEstimate) -> Option<Bytes>,
) -> Option<Bytes> {
    let mut sum: Option<Bytes> = None;
    for target in targets {
        let TargetExplanation::File { estimate, .. } = target else {
            return None;
        };
        let value: Bytes = part(estimate)?;
        sum = Some(match sum {
            Some(sum) => sum.checked_add(value)?,
            None => value,
        });
    }
    sum
}

/// Explains the result of a builder at the time of `clock`.
///
/// The targets come from the sealed plan, so the explanation shows what an
/// approval of the digest covers. The display path and the size estimates
/// of a target come from the preview record with the same target identity;
/// a target with no record has no path and no estimate. The entries that
/// were left out, the batches, and the preset name come from the preview.
pub fn explain(outcome: &PlanOutcome, clock: &EvaluationClock) -> PlanExplanation {
    // The mode of a sealed plan comes from the plan, which the digest
    // covers. The recorded mode applies only when there is no plan.
    let mode: PlanMode = outcome
        .plan
        .as_ref()
        .and_then(|plan| mode_of(plan))
        .unwrap_or(outcome.mode);
    let consequence: Consequence = Consequence::of(mode);
    let reclaims: bool = matches!(
        mode,
        PlanMode::Cleanup(CleanupMode::Permanent | CleanupMode::Evict)
    );
    let preview_of = |target_id: &TargetId| {
        outcome
            .preview
            .targets
            .iter()
            .find(|preview| &preview.target_id == target_id)
    };
    let targets: Vec<TargetExplanation> = outcome.plan.as_ref().map_or_else(Vec::new, |plan| {
        plan.targets
            .iter()
            .map(|target| target_explanation(target, preview_of(&target.target_id), reclaims))
            .collect()
    });
    let summary: Option<PlanSummary> = outcome.plan.as_ref().map(|plan| {
        let mut action_classes: Vec<ActionClass> = Vec::new();
        for step in &plan.steps {
            if !action_classes.contains(&step.action_class) {
                action_classes.push(step.action_class.clone());
            }
        }
        PlanSummary {
            plan_id: plan.plan_id.clone(),
            digest: plan.digest().clone(),
            action_classes,
            revisions: bound_revisions(plan),
            expiry: ExpiryView::of(plan, clock),
            execution_deadline: plan.limits.execution_deadline,
            grace: plan.limits.grace,
            verification_window: plan.limits.verification_window,
        }
    });
    let totals: Totals = Totals {
        targets: targets.len(),
        admission_charge: outcome.plan.as_ref().and_then(|plan| plan.limits.work),
        estimated_logical_bytes: sum_estimates(&targets, |estimate| estimate.logical_bytes),
        estimated_reclaimable_bytes: if reclaims {
            sum_estimates(&targets, |estimate| estimate.estimated_reclaimable_bytes)
        } else {
            None
        },
    };
    PlanExplanation {
        mode,
        consequence,
        consequence_statement: consequence.statement(),
        counts_as_reclaimed_capacity: reclaims,
        estimate_statement: ESTIMATE_STATEMENT,
        plan: summary,
        targets,
        totals,
        batches: outcome.preview.batches.clone(),
        omitted: outcome
            .preview
            .omitted
            .iter()
            .cloned()
            .map(|mut omission| {
                if !reclaims {
                    omission.estimate.estimated_reclaimable_bytes = None;
                }
                omission
            })
            .collect(),
        preset: outcome.preview.preset.clone(),
    }
}
