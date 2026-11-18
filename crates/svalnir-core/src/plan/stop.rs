//! The builder of a manual application stop plan.
//!
//! Owning specifications: `docs/ACTION_CONTRACTS.md` section 8 for the
//! target, the hard protections, and the strategies, and
//! `docs/INTERFACES.md` sections 5 and 6 for `processes stop`.

use super::context::{
    PlanBuildError, PlanContext, PlanOutcome, PlanParts, PlanPreview, SizeEstimate, TargetPreview,
};
use super::mode::{PlanMode, StopKind};
use super::paths::{PathSet, is_canonical};
use super::reason::{Omission, OmissionReason, push_reason};
use crate::action::{
    ActionClass, ApplicationBinding, CandidateBindingError, Plan, PlanLimits, PlanTarget,
    PlannedStep, TargetBinding,
};
use crate::id::{StepId, TargetId};
use crate::policy::{ApplicationCandidate, ProtectionContext, ProtectionFact, hard_protection};
use crate::process::ProcessAssociation;
use crate::quantity::Nanoseconds;

/// The strategy of a manual application stop.
///
/// The strategy selects the steps of the plan. It does not remove a
/// protection: `--force` is [`StopStrategy::ImmediateForce`], and the
/// builder applies the same protections to each strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StopStrategy {
    /// A graceful request only. The application can decline it.
    Graceful,
    /// A graceful request, and one force step if the target is running
    /// after the grace period (`--force-after-timeout`).
    ForceAfterGrace {
        /// The grace period between the graceful request and the force
        /// step.
        grace: Nanoseconds,
    },
    /// One force step with no graceful request (`--force`).
    ImmediateForce,
}

impl StopStrategy {
    /// The strategy without its durations.
    pub const fn kind(&self) -> StopKind {
        match self {
            Self::Graceful => StopKind::Graceful,
            Self::ForceAfterGrace { .. } => StopKind::ForceAfterGrace,
            Self::ImmediateForce => StopKind::ImmediateForce,
        }
    }

    /// The grace period. Only `ForceAfterGrace` has one.
    pub const fn grace(&self) -> Option<Nanoseconds> {
        match self {
            Self::ForceAfterGrace { grace } => Some(*grace),
            Self::Graceful | Self::ImmediateForce => None,
        }
    }
}

/// The durations of a stop plan and their bounds. A duration that is
/// larger than its bound gives an error: the builder does not make it
/// smaller without notice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StopLimits {
    /// The time that the execution can use after admission.
    pub execution_deadline: Nanoseconds,
    /// The time for which the outcome of one step is observed.
    pub verification_window: Nanoseconds,
    /// The largest grace period.
    pub max_grace: Nanoseconds,
    /// The largest verification window.
    pub max_verification_window: Nanoseconds,
    /// The largest execution deadline.
    pub max_execution_deadline: Nanoseconds,
}

/// The identities of the steps of a stop plan. The caller makes the two;
/// the plan uses the ones that its strategy has.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StopStepIds {
    /// The identity of the graceful step.
    pub graceful: StepId,
    /// The identity of the force step.
    pub force: StepId,
}

/// A request for a manual application stop plan.
#[derive(Debug, Clone)]
pub struct StopRequest<'a> {
    /// The identity of the target (`--target ID`).
    pub target_id: TargetId,
    /// The membership snapshot of one application or job instance, with
    /// the identity evidence of each member and the hard protection that
    /// the caller recorded.
    pub candidate: &'a ApplicationCandidate,
    /// The facts of the control plane, for the catalog of hard
    /// protections. The builder asks the catalog again.
    pub protection: &'a ProtectionContext<'a>,
    /// The strategy.
    pub strategy: StopStrategy,
    /// The identities of the steps.
    pub steps: StopStepIds,
    /// The durations and their bounds.
    pub limits: StopLimits,
}

/// Checks the durations: each one is positive and not larger than its
/// bound, the steps fit in the execution deadline, and a grace period ends
/// before the plan expires.
fn check_limits(request: &StopRequest<'_>, lifetime: Nanoseconds) -> Result<(), PlanBuildError> {
    let limits: &StopLimits = &request.limits;
    let zero: Nanoseconds = Nanoseconds::ZERO;
    let window: Nanoseconds = limits.verification_window;
    if limits.execution_deadline == zero
        || window == zero
        || limits.execution_deadline > limits.max_execution_deadline
        || window > limits.max_verification_window
    {
        return Err(PlanBuildError::Limits);
    }
    // The time that the steps need: one verification window for each step,
    // and the grace period between the two steps.
    let needed: Option<Nanoseconds> = match request.strategy {
        StopStrategy::Graceful | StopStrategy::ImmediateForce => Some(window),
        StopStrategy::ForceAfterGrace { grace } => {
            // A plan that expires before the end of the grace period can
            // never do its force step (`docs/POLICY_SPEC.md` section 3). A
            // wait for a graceful exit does not extend the expiry.
            if grace == zero || grace > limits.max_grace || grace >= lifetime {
                return Err(PlanBuildError::Limits);
            }
            grace
                .checked_add(window)
                .and_then(|sum| sum.checked_add(window))
        }
    };
    match needed {
        Some(needed) if needed <= limits.execution_deadline => Ok(()),
        _ => Err(PlanBuildError::Limits),
    }
}

/// The reasons that the protections and the identity evidence of the
/// target give: hard protections first, then the user protections of
/// `[protections]`, then the facts that are not known.
///
/// The automatic settings of the memory guard (its foreground protection,
/// its eligible groups, its own protected lists, and `allow_force_quit`)
/// do not apply to a manual request.
fn target_reasons(
    context: &PlanContext<'_>,
    request: &StopRequest<'_>,
    binding: &Result<ApplicationBinding, CandidateBindingError>,
) -> Vec<OmissionReason> {
    use OmissionReason as Reason;
    let candidate: &ApplicationCandidate = request.candidate;
    let protections = context.protections;
    let mut reasons: Vec<Reason> = Vec::new();
    let mut add = |reason: Reason| push_reason(&mut reasons, reason);

    // The fact that the caller recorded and the fact that the catalog gives
    // now. Only `NotProtected` in the two permits a target.
    let recorded: ProtectionFact = candidate.hard_protection;
    let current: ProtectionFact = hard_protection(&candidate.processes, request.protection);
    let is_protected: bool = recorded == ProtectionFact::Protected
        || current == ProtectionFact::Protected
        || matches!(binding, Err(CandidateBindingError::Protected));
    if is_protected {
        add(Reason::HardProtected);
    }
    // A protection applies to a claimed identifier, verified or not.
    let bundle_protected: bool = candidate.processes.iter().any(|process| {
        let ProcessAssociation::Application {
            bundle_identifier, ..
        } = &process.association
        else {
            return false;
        };
        protections
            .protected_bundle_ids
            .iter()
            .any(|protected| protected.as_str().eq_ignore_ascii_case(bundle_identifier))
    });
    if bundle_protected {
        add(Reason::ProtectedBundleId);
    }
    let protected_paths: PathSet = PathSet::resolve(
        protections.protected_executable_paths.iter(),
        context.home_directory,
    );
    let executables = || {
        candidate
            .processes
            .iter()
            .filter_map(|process| process.executable.as_ref())
    };
    if executables().any(|executable| protected_paths.covers(&executable.path)) {
        add(Reason::ProtectedExecutablePath);
    }
    if candidate
        .processes
        .iter()
        .any(|process| process.uid != context.principal.uid)
    {
        add(Reason::OtherUser);
    }

    // An identity of a different boot is not evidence of a process of this
    // boot: the process ID and the start time can name another process.
    let other_boot: bool = candidate
        .processes
        .iter()
        .any(|process| process.boot_id != context.clock.boot_id);
    if matches!(binding, Err(CandidateBindingError::Membership)) || other_boot {
        add(Reason::MembershipNotVerified);
    }
    if protected_paths.unresolved {
        add(Reason::HomeDirectoryUnknown);
    }
    if !executables().all(|executable| is_canonical(&executable.path)) {
        add(Reason::PathNotCanonical);
    }
    let is_unknown: bool = recorded == ProtectionFact::Unknown
        || current == ProtectionFact::Unknown
        || matches!(binding, Err(CandidateBindingError::ProtectionUnknown));
    if is_unknown {
        add(Reason::ProtectionUnknown);
    }
    let executables_known: bool = candidate
        .processes
        .iter()
        .all(|process| process.executable.is_some());
    if !protections.protected_executable_paths.is_empty() && !executables_known {
        add(Reason::ExecutableUnknown);
    }
    reasons
}

/// Builds the plan of a manual stop of one application or job instance.
///
/// The target is the membership snapshot of the candidate: the same
/// processes and the same membership identity
/// ([`ApplicationBinding::from_candidate`]). Descendants, executables with
/// a similar name, and process groups are not members. The members have
/// the sequence of their generation identities, so the result does not
/// depend on the sequence of the input.
///
/// The target is in the plan only when each of these is true, for each
/// strategy:
///
/// - The hard protection that the candidate recorded and the fact that the
///   catalog gives now ([`hard_protection`]) are the two `NotProtected`.
/// - No process claims a bundle identifier of
///   `[protections].protected_bundle_ids`, and no executable is at or
///   below a path of `[protections].protected_executable_paths`. With such
///   a path in the configuration, each process has executable evidence.
/// - Each process is a process of the principal, has a verified
///   membership of the same instance, and has an identity of the boot of
///   the clock of the plan.
/// - Each executable path is absolute and canonical, and the home
///   directory resolves each `~/` path of the configuration.
///
/// In each other case the result has no plan, and `preview.omitted` has
/// the target with each reason. That result is not an error.
///
/// A process with no verified membership is not a target of this builder,
/// and the reason is `MembershipNotVerified`. The binding for one such
/// process exists ([`TargetBinding::Process`]), and [`Plan::seal`] has its
/// checks. This builder makes no plan with it, because this build has no
/// executor step that revalidates and signals one process with no
/// membership.
///
/// The steps are one graceful step, one graceful step and then one force
/// step, or one force step, as the strategy says.
///
/// # Errors
///
/// Returns a [`PlanBuildError`] when a duration is zero, is larger than
/// its bound, or does not fit in the execution deadline, when the grace
/// period is not shorter than the lifetime of the plan, when the two step
/// identities are equal, when the protection context is for a different
/// principal, when the lifetime is zero or overflows, when the authority
/// names a privilege grant or one grant two times, or when the check of
/// the foundation rejects the content.
pub fn build_stop_plan(
    context: &PlanContext<'_>,
    request: &StopRequest<'_>,
) -> Result<PlanOutcome, PlanBuildError> {
    // An error of the lifetime or of the authority is an error also when
    // the target is left out.
    context.validity()?;
    context.canonical_authority()?;
    check_limits(request, context.lifetime)?;
    if request.steps.graceful == request.steps.force {
        return Err(PlanBuildError::DuplicateIdentity);
    }
    // The owner rule of the catalog compares with this principal.
    if request.protection.principal != context.principal.uid {
        return Err(PlanBuildError::Principal);
    }
    let kind: StopKind = request.strategy.kind();
    let mode: PlanMode = PlanMode::Stop(kind);

    let binding: Result<ApplicationBinding, CandidateBindingError> =
        ApplicationBinding::from_candidate(request.candidate);
    let reasons: Vec<OmissionReason> = target_reasons(context, request, &binding);
    let mut binding: ApplicationBinding = match binding {
        Ok(binding) if reasons.is_empty() => binding,
        _ => {
            // A binding error always gives a reason. This fallback keeps a
            // target with no binding out if a later change breaks that
            // rule.
            let reasons: Vec<OmissionReason> = if reasons.is_empty() {
                vec![OmissionReason::MembershipNotVerified]
            } else {
                reasons
            };
            return Ok(PlanOutcome {
                mode,
                plan: None,
                preview: PlanPreview {
                    targets: Vec::new(),
                    batches: Vec::new(),
                    omitted: vec![Omission {
                        target_id: request.target_id.clone(),
                        path: None,
                        reasons,
                        charge: None,
                        estimate: SizeEstimate::default(),
                    }],
                    preset: None,
                },
            });
        }
    };
    binding
        .members
        .sort_by(|left, right| left.generation_id.cmp(&right.generation_id));

    let step = |step_id: &StepId, action_class: ActionClass| PlannedStep {
        step_id: step_id.clone(),
        action_class,
        target_id: request.target_id.clone(),
    };
    let graceful: PlannedStep = step(&request.steps.graceful, ActionClass::RequestApplicationExit);
    let force: PlannedStep = step(&request.steps.force, ActionClass::ForceApplicationExit);
    let steps: Vec<PlannedStep> = match kind {
        StopKind::Graceful => vec![graceful],
        StopKind::ForceAfterGrace => vec![graceful, force],
        StopKind::ImmediateForce => vec![force],
    };
    let plan: Plan = context.seal(PlanParts {
        targets: vec![PlanTarget {
            target_id: request.target_id.clone(),
            binding: TargetBinding::Application(binding),
        }],
        steps,
        limits: PlanLimits {
            work: None,
            execution_deadline: request.limits.execution_deadline,
            grace: request.strategy.grace(),
            verification_window: request.limits.verification_window,
            escalation: kind.escalation(),
        },
    })?;
    Ok(PlanOutcome {
        mode,
        plan: Some(plan),
        preview: PlanPreview {
            targets: vec![TargetPreview {
                target_id: request.target_id.clone(),
                path: None,
                estimate: SizeEstimate::default(),
            }],
            batches: Vec::new(),
            omitted: Vec::new(),
            preset: None,
        },
    })
}
