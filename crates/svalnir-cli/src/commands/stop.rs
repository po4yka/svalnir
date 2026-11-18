//! `processes stop`: prepare, authorize, and apply the stop of one process
//! generation through the same plan builder and coordinator as each other
//! intervention (`docs/INTERFACES.md` section 5).
//!
//! The target ID names one process generation, and the plan has that one
//! process and no other: the command never selects the processes of an
//! application by name. A process with a verified membership in an
//! application or a managed job is the only member of an application
//! target. A process with no application or job evidence, for example a
//! process that a shell started, is a target of one process
//! (`docs/ACTION_CONTRACTS.md` section 3), which the executor signals
//! directly after it checks the identity evidence again.
//!
//! The command keeps its plan identity in a stop record of the process
//! generation. A repeated request, for example after a lost response,
//! finds that plan and its operation and makes no second plan.

use std::time::Duration;

use svalnir_agent::journal::OperationJournal;
use svalnir_agent::platform::process::{
    ForegroundState, ProcessRecord, ProcessSnapshot, control_plane_of_this_process,
};
use svalnir_core::action::Plan;
use svalnir_core::authority::AuthorityBinding;
use svalnir_core::id::{MembershipSnapshotId, PlanId, ProcessGenerationId, StepId, TargetId};
use svalnir_core::plan::{
    PlanBuildError, PlanContext, PlanOutcome, StopKind, StopLimits, StopRequest, StopStepIds,
    StopStrategy, build_stop_plan, check_expiry, explain, manual_plan_lifetime,
};
use svalnir_core::policy::{
    ApplicationCandidate, ControlPlaneProcess, ForegroundStatus, ProtectionContext, ProtectionFact,
    hard_protection,
};
use svalnir_core::process::ProcessIdentity;
use svalnir_core::quantity::Nanoseconds;

use super::apply::{self, ApplyFlow};
use super::clean::{StoredPlan, load_plan, outcome_of};
use super::plan_store::{self, PlanDocument, StopRecord};
use super::plan_view;
use super::session::{self, ActiveConfig, Now, journal_error};
use super::{CommandFailure, Invocation, processes};
use crate::cli::ProcessesStopArgs;
use crate::environment::Environment;
use crate::host::Host;
use crate::output::{ErrorBody, ErrorFamily, ErrorStage, ExitStatus, NextAction, Warning};

/// The grace period when `--grace` is not given.
const DEFAULT_GRACE: Duration = Duration::from_secs(10);

/// The time in which the executor observes the exit after a force signal.
const FORCE_VERIFICATION_WINDOW: Nanoseconds = Nanoseconds::new(5 * 1_000_000_000);

/// The longest grace period of a manual stop.
const MAX_GRACE: Nanoseconds = Nanoseconds::new(5 * 60 * 1_000_000_000);

/// The time that the deadline has in addition to the steps.
const DEADLINE_MARGIN: Nanoseconds = Nanoseconds::new(5 * 1_000_000_000);

fn stop_error(code: &'static str, family: ErrorFamily, message: &str) -> ErrorBody {
    ErrorBody::new(
        code,
        family,
        ErrorStage::Admission,
        format!("{message}; the command sent no signal"),
    )
    .with_fields(&["target"])
}

/// The strategy and the durations of the request.
struct Shape {
    strategy: StopStrategy,
    limits: StopLimits,
}

fn shape(arguments: &ProcessesStopArgs) -> Result<Shape, ErrorBody> {
    let grace: Nanoseconds = Nanoseconds::try_from(arguments.grace.unwrap_or(DEFAULT_GRACE))
        .ok()
        .filter(|grace| *grace <= MAX_GRACE)
        .ok_or_else(|| {
            ErrorBody::new(
                "invalid_grace",
                ErrorFamily::Request,
                ErrorStage::Arguments,
                "the grace period is longer than 5 minutes; the command sent no signal",
            )
            .with_fields(&["grace"])
        })?;
    let (strategy, window): (StopStrategy, Nanoseconds) = if arguments.force {
        (StopStrategy::ImmediateForce, FORCE_VERIFICATION_WINDOW)
    } else if arguments.force_after_timeout {
        (
            StopStrategy::ForceAfterGrace { grace },
            FORCE_VERIFICATION_WINDOW,
        )
    } else {
        // With no force step, the grace period is the time in which the
        // executor observes the exit after the graceful request.
        (StopStrategy::Graceful, grace)
    };
    let steps: u64 = window.get().saturating_mul(2);
    let deadline: Nanoseconds = Nanoseconds::new(
        strategy
            .grace()
            .map_or(0, Nanoseconds::get)
            .saturating_add(steps)
            .saturating_add(DEADLINE_MARGIN.get()),
    );
    Ok(Shape {
        strategy,
        limits: StopLimits {
            execution_deadline: deadline,
            verification_window: window,
            max_grace: MAX_GRACE,
            max_verification_window: MAX_GRACE,
            max_execution_deadline: deadline,
        },
    })
}

/// The candidate of a stop plan with one process: the process of the
/// target ID, with the association that the inventory gave it. The plan
/// builder binds it as the only member of its instance, or, with no
/// application or job evidence, as a target of one process.
fn candidate(
    record: &ProcessRecord,
    control_plane: Option<&[ControlPlaneProcess]>,
) -> Result<ApplicationCandidate, ErrorBody> {
    let identity: ProcessIdentity = record.identity.clone();
    let protection = ProtectionContext {
        principal: session::current_uid(),
        control_plane,
    };
    let processes: Vec<ProcessIdentity> = vec![identity];
    Ok(ApplicationCandidate {
        hard_protection: hard_protection(&processes, &protection),
        membership_snapshot: MembershipSnapshotId::new(format!(
            "ms-{}-1",
            record.identity.generation_id
        ))
        .map_err(|_| session::identity_error())?,
        foreground: match record.foreground {
            ForegroundState::Foreground => ForegroundStatus::Foreground,
            ForegroundState::Background => ForegroundStatus::Background,
            ForegroundState::Unknown => ForegroundStatus::Unknown,
        },
        footprint: record.metrics.footprint.clone(),
        processes,
    })
}

fn plan_error(error: &PlanBuildError) -> ErrorBody {
    let code: &'static str = match error {
        PlanBuildError::Limits | PlanBuildError::Lifetime => "stop_durations_not_usable",
        PlanBuildError::Authority | PlanBuildError::Principal => "plan_authority_not_usable",
        _ => "plan_not_buildable",
    };
    ErrorBody::new(
        code,
        error.family(),
        ErrorStage::Admission,
        format!("the stop plan cannot be built: {error}; the command sent no signal"),
    )
}

/// The plan of an earlier request for the same process generation, when
/// it can still be used: it was applied, or it is not expired.
fn earlier_plan(
    journal: &OperationJournal,
    environment: &Environment,
    target: &ProcessGenerationId,
    requested: &Shape,
    now: &Now,
) -> Result<Option<StoredPlan>, ErrorBody> {
    let Some(record) = plan_store::load_stop(environment, target)? else {
        return Ok(None);
    };
    let operation = apply::existing_operation(journal, &record.plan_id)?;
    let blocked = |reason: &str| {
        let mut error: ErrorBody = ErrorBody::new(
            "stop_plan_exists",
            ErrorFamily::Evidence,
            ErrorStage::Admission,
            format!("an earlier request for this process has a plan{reason}; the command made no second plan and sent no signal; query the earlier operation"),
        )
        .with_plan(record.plan_id.as_str())
        .with_fields(&["force", "force_after_timeout", "grace"])
        .with_next_action(NextAction::QueryOperation);
        if let Some(operation) = &operation {
            error = error.with_operation(operation.operation_id().as_str());
        }
        error
    };
    let stored: StoredPlan = match load_plan(Some(journal), environment, &record.plan_id) {
        Ok(stored) => stored,
        // The journal has no such plan and no operation of it: the
        // earlier request stopped before its admission, or the retention
        // removed its records. It sent no signal that a new plan repeats.
        Err(error) if &*error.code == "plan_not_found" && operation.is_none() => {
            return Ok(None);
        }
        // The earlier plan cannot be read, so its effect is not known.
        Err(_) => return Err(blocked(", and its records cannot be read")),
    };
    if operation.is_none() && check_expiry(&stored.plan, &now.clock).is_err() {
        // The earlier plan was never applied and is expired: it has no
        // effect, and a new plan takes its place.
        return Ok(None);
    }
    let same_request: bool = record.kind == requested.strategy.kind()
        && record.grace == requested.strategy.grace()
        && record.verification_window == requested.limits.verification_window;
    if !same_request {
        // A settled operation is complete. A request with a different
        // strategy after it is a new decision of the user, for example a
        // force quit after a graceful request that the process ignored.
        if operation
            .as_ref()
            .is_some_and(|operation| operation.state().is_settled())
        {
            return Ok(None);
        }
        return Err(blocked(
            " with a different strategy, and its operation is not settled",
        ));
    }
    Ok(Some(stored))
}

/// Refuses a process that is protected, or whose protection is not known.
fn check_protection(protection: ProtectionFact) -> Result<(), ErrorBody> {
    match protection {
        ProtectionFact::NotProtected => Ok(()),
        ProtectionFact::Protected => Err(stop_error(
            "target_protected",
            ErrorFamily::Eligibility,
            "a hard protection applies to the process: it is a system process, a process of Svalnir, this client or one of its ancestors, or a process of a different user; `--force` does not change a protection",
        )),
        ProtectionFact::Unknown => Err(stop_error(
            "target_protection_unknown",
            ErrorFamily::Evidence,
            "the protection of the process is not known: it has no executable evidence, or the ancestors of this client are not known",
        )
        .with_next_action(NextAction::RefreshObservation)),
    }
}

/// Builds and records the plan of a new stop request.
fn new_plan(
    journal: &mut OperationJournal,
    environment: &Environment,
    record: &ProcessRecord,
    control_plane: Option<&[ControlPlaneProcess]>,
    requested: &Shape,
    now: &Now,
) -> Result<StoredPlan, ErrorBody> {
    let authority = session::read_authority(journal)?;
    let ActiveConfig { active, config } = session::active_config(journal, &authority.state)?;
    let candidate: ApplicationCandidate = candidate(record, control_plane)?;
    check_protection(candidate.hard_protection)?;
    let plan_text: String = session::new_id("plan");
    let plan_id: PlanId = PlanId::new(plan_text.clone()).map_err(|_| session::identity_error())?;
    let home = environment
        .home
        .as_ref()
        .and_then(|home| std::fs::canonicalize(home).ok())
        .and_then(|home| svalnir_core::file::LosslessPath::from_path(&home).ok());
    let context = PlanContext {
        plan_id: plan_id.clone(),
        principal: session::principal(),
        authority: AuthorityBinding {
            policy_revision: active.revision.revision_id.clone(),
            action_grants: Vec::new(),
            privilege_grant: None,
        },
        clock: &now.clock,
        created_wall: now.wall,
        lifetime: manual_plan_lifetime(&config)
            .ok_or_else(|| plan_error(&PlanBuildError::Lifetime))?,
        protections: config.protections(),
        home_directory: home.as_ref(),
    };
    let identity = |suffix: &str| format!("{plan_text}-{suffix}");
    let request = StopRequest {
        target_id: TargetId::new(identity("app")).map_err(|_| session::identity_error())?,
        candidate: &candidate,
        protection: &ProtectionContext {
            principal: session::current_uid(),
            control_plane,
        },
        strategy: requested.strategy,
        steps: StopStepIds {
            graceful: StepId::new(identity("graceful")).map_err(|_| session::identity_error())?,
            force: StepId::new(identity("force")).map_err(|_| session::identity_error())?,
        },
        limits: requested.limits,
    };
    let outcome: PlanOutcome =
        build_stop_plan(&context, &request).map_err(|error| plan_error(&error))?;
    let Some(plan) = outcome.plan.clone() else {
        let reasons: Vec<String> = outcome
            .preview
            .omitted
            .iter()
            .flat_map(|omission| omission.reasons.iter())
            .copied()
            .map(plan_view::wire_reason)
            .collect();
        return Err(stop_error(
            "target_not_eligible",
            ErrorFamily::Eligibility,
            &format!(
                "the process is not a permitted target ({}); `--force` does not change a protection",
                if reasons.is_empty() {
                    "no reason recorded".to_owned()
                } else {
                    reasons.join(", ")
                }
            ),
        ));
    };
    journal
        .try_record_plan(&plan)
        .map_err(|error| journal_error(&error))?;
    let mut document = PlanDocument::new(plan_id.clone(), plan.digest().clone(), outcome);
    document.stop_target = Some(record.identity.generation_id.clone());
    plan_store::save_plan(environment, &document)?;
    // The stop record is the last write: a request that stops before it
    // leaves a plan that no later request applies.
    plan_store::save_stop(
        environment,
        &StopRecord::new(
            record.identity.generation_id.clone(),
            plan_id,
            requested.strategy.kind(),
            requested.strategy.grace(),
            requested.limits.verification_window,
        ),
    )?;
    plan_store::prune(environment);
    Ok(StoredPlan {
        plan,
        document: Some(document),
        document_state: super::clean::DocumentState::Used,
    })
}

fn kind_text(kind: StopKind) -> &'static str {
    match kind {
        StopKind::Graceful => "a request to exit",
        StopKind::ForceAfterGrace => "a request to exit, then a force quit after the grace period",
        StopKind::ImmediateForce => "an immediate force quit",
    }
}

pub(crate) fn stop(
    arguments: &ProcessesStopArgs,
    invocation: &mut Invocation<'_>,
) -> Result<ExitStatus, CommandFailure> {
    let target: ProcessGenerationId = processes::parse_target(&arguments.target.target)?;
    let requested: Shape = shape(arguments)?;
    if arguments.force && arguments.grace.is_some() {
        invocation.warnings.push(Warning {
            code: "grace_not_used".into(),
            message: "`--force` sends the force signal at once; `--grace` has no effect".to_owned(),
        });
    }
    let environment: &Environment = invocation.environment;
    let host: Host = Host::open()?;
    let now: Now = Now::read(&host)?;
    let mut journal: OperationJournal = session::open_journal(environment)?;

    // One client at a time reads the stop record of a process generation
    // and makes its plan, so two requests make one plan.
    let lock = plan_store::lock_stop(environment, &target)?;
    // An earlier request for the same process generation has the plan.
    // The process of an applied plan can be gone, so this lookup is before
    // the inventory.
    let earlier: Option<StoredPlan> =
        earlier_plan(&journal, environment, &target, &requested, &now)?;
    let snapshot: ProcessSnapshot = processes::collect_snapshot()?;
    let control_plane: Option<Vec<ControlPlaneProcess>> = control_plane_of_this_process(&snapshot);
    let stored: StoredPlan = if let Some(stored) = earlier {
        stored
    } else {
        let record: &ProcessRecord = processes::find_target(&snapshot, &arguments.target.target)?;
        new_plan(
            &mut journal,
            environment,
            record,
            control_plane.as_deref(),
            &requested,
            &now,
        )?
    };
    let authority = session::read_authority(&journal)?.state;
    drop(journal);
    // The plan and its stop record exist: a later request finds them.
    drop(lock);
    let plan: &Plan = &stored.plan;
    let mut summary: String = String::new();
    plan_view::render_question(
        &explain(&outcome_of(&stored)?, &now.clock),
        &[],
        &mut summary,
    );
    crate::text::put_line!(
        summary,
        "This request sends {} to process {target}. Unsaved data of the process can be lost.",
        kind_text(requested.strategy.kind())
    );
    apply::run(
        ApplyFlow {
            plan,
            document: stored.document.clone(),
            authority,
            control_plane,
            no_wait: arguments.apply.no_wait,
            yes: arguments.apply.yes,
            summary,
            what: "the stop of the process",
        },
        invocation,
    )
}
