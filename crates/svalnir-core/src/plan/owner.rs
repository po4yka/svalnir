//! The manual plan of one owner operation (`RunOwnerOperation`).
//!
//! `docs/CLEANUP_RULES.md` section 9 owns the rule of the operation and
//! `docs/ACTION_CONTRACTS.md` section 7 owns its execution. The caller
//! makes the [`OwnerOperationBinding`] from the reviewed declaration of the
//! rule and gives it with the rule revision; this module checks the
//! protections and the lifecycle state of the layout, and seals a plan with
//! one target and one step. It reads no clock, file, or process.

use super::context::{
    PlanBatch, PlanBuildError, PlanContext, PlanOutcome, PlanParts, PlanPreview, SizeEstimate,
    TargetPreview,
};
use super::mode::PlanMode;
use super::paths::PathSet;
use super::reason::{Omission, OmissionReason, push_reason};
use crate::action::{
    ActionClass, Escalation, ExecutorRole, OwnerOperationBinding, Plan, PlanLimits, PlanTarget,
    PlannedStep, TargetBinding, WorkCharge,
};
use crate::id::{StepId, TargetId};
use crate::policy::ProtectionFact;
use crate::quantity::Nanoseconds;
use crate::rule::{Rule, RuleMode, RuleRefusal};

/// The request of one owner-operation plan.
#[derive(Debug, Clone)]
pub struct OwnerPlanRequest<'a> {
    /// The identity of the one target.
    pub target_id: TargetId,
    /// The identity of the one step.
    pub step_id: StepId,
    /// The binding that the caller made from the reviewed declaration.
    pub binding: &'a OwnerOperationBinding,
    /// The exact rule revision of the binding, from the registry. No other
    /// revision takes its place.
    pub rule: Result<&'a Rule, RuleRefusal>,
    /// The hard protection of the scope root.
    pub protection: ProtectionFact,
    /// The window in which the executor measures the scope again after the
    /// command.
    pub verification_window: Nanoseconds,
}

/// The reasons that leave the scope out of the plan, in the sequence of the
/// checks.
fn omissions(
    context: &PlanContext<'_>,
    request: &OwnerPlanRequest<'_>,
    rule: &Rule,
) -> Vec<OmissionReason> {
    let binding: &OwnerOperationBinding = request.binding;
    let mut reasons: Vec<OmissionReason> = Vec::new();
    match request.protection {
        ProtectionFact::NotProtected => {}
        ProtectionFact::Protected => push_reason(&mut reasons, OmissionReason::HardProtected),
        ProtectionFact::Unknown => push_reason(&mut reasons, OmissionReason::ProtectionUnknown),
    }
    let excluded: PathSet = PathSet::resolve(
        context.protections.excluded_paths.iter(),
        context.home_directory,
    );
    if excluded.unresolved {
        push_reason(&mut reasons, OmissionReason::HomeDirectoryUnknown);
    }
    // A command of the producer acts on the whole scope root, so an
    // exclusion inside the root also leaves the root out.
    if excluded.overlaps(&binding.root_path) {
        push_reason(&mut reasons, OmissionReason::ExcludedPath);
    }
    if binding.owner != context.principal.uid {
        push_reason(&mut reasons, OmissionReason::OtherUser);
    }
    if !rule
        .layouts
        .iter()
        .any(|support| support.layout == binding.layout)
    {
        push_reason(&mut reasons, OmissionReason::LayoutNotSupported);
    } else if rule
        .permits(&binding.layout, &RuleMode::ManualEviction)
        .is_err()
    {
        push_reason(&mut reasons, OmissionReason::ModeNotValidated);
    }
    if binding.charge.items.get() == 0 {
        push_reason(&mut reasons, OmissionReason::NoItems);
    }
    if !binding.charge.fits_in(&rule.budget.per_pass) {
        push_reason(&mut reasons, OmissionReason::ExceedsPlanLimit);
    }
    reasons
}

/// Builds the manual plan of one owner operation.
///
/// The plan has the one target of the binding and one `RunOwnerOperation`
/// step. Its work limit is the charge of the measured scope, and its
/// execution deadline is the command deadline and then the verification
/// window. The scope is left out, with each reason, when the root has a
/// hard protection or an unknown one, when a path of
/// `[protections].excluded_paths` is the root, contains it, or is inside
/// it, when the scope is of another user, when the rule revision does not
/// support the layout or its lifecycle state does not permit the manual
/// eviction of the layout, or when the charge does not fit one pass of the
/// rule.
///
/// # Errors
///
/// Returns [`PlanBuildError::Rule`] when the registry refused the rule or
/// when it gave another revision, [`PlanBuildError::UnsupportedExecutor`]
/// for a rule of the helper executor, [`PlanBuildError::Limits`] when the
/// verification window is zero or the command deadline does not fit in the
/// lifetime of the plan, and the errors of the lifetime, the authority,
/// and the seal.
pub fn build_owner_plan(
    context: &PlanContext<'_>,
    request: &OwnerPlanRequest<'_>,
) -> Result<PlanOutcome, PlanBuildError> {
    let rule: &Rule = request.rule.map_err(PlanBuildError::Rule)?;
    let binding: &OwnerOperationBinding = request.binding;
    if rule.reference != binding.rule {
        return Err(PlanBuildError::Rule(RuleRefusal::UnknownRevision));
    }
    if !matches!(rule.executor, ExecutorRole::User) {
        return Err(PlanBuildError::UnsupportedExecutor);
    }
    context.validity()?;
    context.canonical_authority()?;
    let execution_deadline: Nanoseconds = binding
        .command_deadline
        .checked_add(request.verification_window)
        .ok_or(PlanBuildError::Limits)?;
    // Admission refuses a command whose deadline is longer than the time
    // that the plan has left, so a deadline as long as the lifetime gives
    // a plan that no apply can admit.
    if request.verification_window == Nanoseconds::ZERO
        || binding.command_deadline >= context.lifetime
    {
        return Err(PlanBuildError::Limits);
    }
    let estimate: SizeEstimate = SizeEstimate {
        logical_bytes: None,
        allocated_bytes: Some(binding.measured.allocated_bytes),
        // The producer selects its own data, so the plan has no estimate of
        // the bytes that it reclaims.
        estimated_reclaimable_bytes: None,
    };
    let reasons: Vec<OmissionReason> = omissions(context, request, rule);
    let mode: PlanMode = PlanMode::Owner(binding.operation);
    if !reasons.is_empty() {
        return Ok(PlanOutcome {
            mode,
            plan: None,
            preview: PlanPreview {
                targets: Vec::new(),
                batches: Vec::new(),
                omitted: vec![Omission {
                    target_id: request.target_id.clone(),
                    path: Some(binding.root_path.clone()),
                    reasons,
                    charge: Some(binding.charge),
                    estimate,
                }],
                preset: None,
            },
        });
    }
    let charge: WorkCharge = binding.charge;
    let plan: Plan = context.seal(PlanParts {
        targets: vec![PlanTarget {
            target_id: request.target_id.clone(),
            binding: TargetBinding::OwnerOperation(Box::new(binding.clone())),
        }],
        steps: vec![PlannedStep {
            step_id: request.step_id.clone(),
            action_class: ActionClass::RunOwnerOperation,
            target_id: request.target_id.clone(),
        }],
        limits: PlanLimits {
            work: Some(charge),
            execution_deadline,
            grace: None,
            verification_window: request.verification_window,
            escalation: Escalation::None,
        },
    })?;
    Ok(PlanOutcome {
        mode,
        plan: Some(plan),
        preview: PlanPreview {
            targets: vec![TargetPreview {
                target_id: request.target_id.clone(),
                path: Some(binding.root_path.clone()),
                estimate,
            }],
            batches: vec![PlanBatch {
                steps: vec![request.step_id.clone()],
                charge,
            }],
            omitted: Vec::new(),
            preset: None,
        },
    })
}
