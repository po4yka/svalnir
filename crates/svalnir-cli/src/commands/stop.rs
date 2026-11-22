//! `processes stop`: prepare, authorize, and apply the stop of one process
//! generation or of one group through the same plan builder and coordinator
//! as each other intervention (`docs/INTERFACES.md` section 5).
//!
//! `--target` names one process generation, and the plan has that one
//! process and no other. A process with a verified membership in an
//! application or a managed job is the only member of an application
//! target. A process with no application or job evidence, for example a
//! process that a shell started, is a target of one process
//! (`docs/ACTION_CONTRACTS.md` section 3), which the executor signals
//! directly after it checks the identity evidence again.
//!
//! `--group` names one application or managed-job instance. The plan has
//! each process with a verified membership in that instance, as the stop of
//! the GPUI client has: both clients get the candidate from
//! [`svalnir_agent::client::group_candidate`] and build the plan with
//! [`svalnir_agent::client::build_manual_stop`]. The command never selects
//! the processes of an application by name. The executor checks the
//! identity of each member again before its signal.
//!
//! The command keeps its plan identity in a stop record of the process
//! generation or of the group. A repeated request, for example after a lost
//! response, finds that plan and its operation and makes no second plan.
//! After the operation of a group is settled, a repeated group request
//! makes a new plan from a new reading, because the members of an instance
//! can change; a member of the earlier plan that exited is not in it.

use std::time::Duration;

use svalnir_agent::client::{self, ManualStopError, ManualStopPlan};
use svalnir_agent::journal::OperationJournal;
use svalnir_agent::platform::process::{
    ForegroundState, ProcessRecord, ProcessSnapshot, control_plane_of_this_process,
};
use svalnir_core::action::Plan;
use svalnir_core::id::{ApplicationInstanceId, MembershipSnapshotId, PlanId};
use svalnir_core::plan::{
    PlanBuildError, PlanOutcome, StopKind, StopLimits, StopStrategy, check_expiry, explain,
};
use svalnir_core::policy::{
    ApplicationCandidate, ControlPlaneProcess, ForegroundStatus, ProtectionContext, ProtectionFact,
    hard_protection,
};
use svalnir_core::process::ProcessIdentity;
use svalnir_core::quantity::Nanoseconds;

use super::apply::{self, ApplyFlow};
use super::clean::{StoredPlan, load_plan, outcome_of};
use super::plan_store::{self, PlanDocument, StopKey, StopRecord};
use super::plan_view;
use super::session::{self, ActiveConfig, Now, journal_error};
use super::{CommandFailure, Invocation, processes};
use crate::cli::{ProcessesStopArgs, StopSubject};
use crate::environment::Environment;
use crate::host::Host;
use crate::output::{ErrorBody, ErrorFamily, ErrorStage, ExitStatus, NextAction, Warning};

/// The wait for the lock file of a stop request when `--timeout` is absent.
const LOCK_WAIT: Duration = Duration::from_secs(10);

// The grace period when `--grace` is not given, the longest one, and the
// stop modes, which each client shares.
use svalnir_agent::client::{
    DEFAULT_STOP_GRACE as DEFAULT_GRACE, MAX_STOP_GRACE as MAX_GRACE, StopMode,
};

/// The argument that names the subject of a request.
const fn fields(key: &StopKey) -> &'static [&'static str] {
    match key {
        StopKey::Process(_) => &["target"],
        StopKey::Group(_) => &["group"],
    }
}

fn stop_error(key: &StopKey, code: &'static str, family: ErrorFamily, message: &str) -> ErrorBody {
    ErrorBody::new(
        code,
        family,
        ErrorStage::Admission,
        format!("{message}; the command sent no signal"),
    )
    .with_fields(fields(key))
}

/// Parses `--target` or `--group`. The parser of the arguments permits
/// exactly one of them.
fn key_of(subject: &StopSubject) -> Result<StopKey, ErrorBody> {
    match (&subject.target, &subject.group) {
        (Some(target), None) => Ok(StopKey::Process(processes::parse_target(target)?)),
        (None, Some(group)) => ApplicationInstanceId::new(group.as_str())
            .map(StopKey::Group)
            .map_err(|_| {
                ErrorBody::new(
                    "invalid_group",
                    ErrorFamily::Request,
                    ErrorStage::Arguments,
                    "the group ID is not valid; use the `Instance` value of `svalnir processes show`; the command made no change",
                )
                .with_fields(&["group"])
                .with_next_action(NextAction::CorrectRequest)
            }),
        _ => Err(ErrorBody::new(
            "invalid_target",
            ErrorFamily::Request,
            ErrorStage::Arguments,
            "give exactly one of `--target` and `--group`; the command made no change",
        )
        .with_fields(&["target", "group"])
        .with_next_action(NextAction::CorrectRequest)),
    }
}

/// The refusal of a group that the reading has no candidate for.
fn group_not_found() -> ErrorBody {
    ErrorBody::new(
        "group_not_found",
        ErrorFamily::Evidence,
        ErrorStage::Collection,
        "the snapshot of this invocation has no process with a verified membership in this instance, or the membership or the footprint of the instance cannot be read: the application exited, the ID is of an earlier launch, or the instance is of another user; the command made no change",
    )
    .with_fields(&["group"])
    .with_next_action(NextAction::RefreshObservation)
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
    let mode: StopMode = if arguments.force {
        StopMode::ImmediateForce
    } else if arguments.force_after_timeout {
        StopMode::ForceAfterGrace
    } else {
        // With no force step, the grace period is the time in which the
        // executor observes the exit after the graceful request.
        StopMode::Graceful
    };
    let (strategy, limits) = client::manual_stop(mode, grace);
    Ok(Shape { strategy, limits })
}

/// The candidate of a stop plan with one process: the process of the
/// target ID, with the association that the inventory gave it. The plan
/// builder binds it as the only member of its instance, or, with no
/// application or job evidence, as a target of one process.
fn process_candidate(
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

/// The candidate of the request: the one process of `--target`, or the
/// verified members of the instance of `--group`.
fn candidate_of(
    key: &StopKey,
    snapshot: &ProcessSnapshot,
    control_plane: Option<&[ControlPlaneProcess]>,
) -> Result<ApplicationCandidate, ErrorBody> {
    match key {
        StopKey::Process(target) => {
            let record: &ProcessRecord = processes::find_target(snapshot, target.as_str())?;
            process_candidate(record, control_plane)
        }
        StopKey::Group(instance) => {
            let protection = ProtectionContext {
                principal: session::current_uid(),
                control_plane,
            };
            client::group_candidate(snapshot, &protection, instance).ok_or_else(group_not_found)
        }
    }
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
    target: &StopKey,
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
            format!("an earlier request for this {} has a plan{reason}; the command made no second plan and sent no signal; query the earlier operation", match target {
                StopKey::Process(_) => "process",
                StopKey::Group(_) => "group",
            }),
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
    // The members of a group can change after its plan, for example when
    // the application starts a helper again. After a settled operation, a
    // repeated group request is a new decision with a new reading, so a
    // member that came later is in the new plan. A process generation
    // cannot change, so a settled operation of `--target` is kept.
    if matches!(target, StopKey::Group(_))
        && operation
            .as_ref()
            .is_some_and(|operation| operation.state().is_settled())
    {
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
/// For a group, one protected member protects the group.
fn check_protection(key: &StopKey, protection: ProtectionFact) -> Result<(), ErrorBody> {
    match protection {
        ProtectionFact::NotProtected => Ok(()),
        ProtectionFact::Protected => Err(stop_error(
            key,
            "target_protected",
            ErrorFamily::Eligibility,
            match key {
                StopKey::Process(_) => "a hard protection applies to the process: it is a system process, a process of Svalnir, this client or one of its ancestors, or a process of a different user; `--force` does not change a protection",
                StopKey::Group(_) => "a hard protection applies to a member of the group: a system process, a process of Svalnir, this client or one of its ancestors, or a process of a different user; one protected member protects the group; `svalnir processes show` gives each member; `--force` does not change a protection",
            },
        )),
        ProtectionFact::Unknown => Err(stop_error(
            key,
            "target_protection_unknown",
            ErrorFamily::Evidence,
            match key {
                StopKey::Process(_) => "the protection of the process is not known: it has no executable evidence, or the ancestors of this client are not known",
                StopKey::Group(_) => "the protection of a member of the group is not known: a member has no executable evidence, or the ancestors of this client are not known",
            },
        )
        .with_next_action(NextAction::RefreshObservation)),
    }
}

/// Builds and records the plan of a new stop request.
fn new_plan(
    journal: &mut OperationJournal,
    environment: &Environment,
    key: &StopKey,
    candidate: &ApplicationCandidate,
    control_plane: Option<&[ControlPlaneProcess]>,
    requested: &Shape,
    now: &Now,
) -> Result<StoredPlan, ErrorBody> {
    let authority = session::read_authority(journal)?;
    let ActiveConfig { active, config } = session::active_config(journal, &authority.state)?;
    check_protection(key, candidate.hard_protection)?;
    let plan_text: String = session::new_id("plan");
    let plan_id: PlanId = PlanId::new(plan_text.clone()).map_err(|_| session::identity_error())?;
    let home = environment
        .home
        .as_ref()
        .and_then(|home| std::fs::canonicalize(home).ok())
        .and_then(|home| svalnir_core::file::LosslessPath::from_path(&home).ok());
    let outcome: PlanOutcome = client::build_manual_stop(&ManualStopPlan {
        plan_id: &plan_text,
        principal: &session::principal(),
        active: &active,
        config: &config,
        clock: &now.clock,
        created_wall: now.wall,
        home_directory: home.as_ref(),
        candidate,
        protection: &ProtectionContext {
            principal: session::current_uid(),
            control_plane,
        },
        strategy: requested.strategy,
        limits: requested.limits,
    })
    .map_err(|error| match error {
        ManualStopError::Identity => session::identity_error(),
        ManualStopError::Build(error) => plan_error(&error),
    })?;
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
            key,
            "target_not_eligible",
            ErrorFamily::Eligibility,
            &format!(
                "the {} is not a permitted target ({}); `--force` does not change a protection",
                match key {
                    StopKey::Process(_) => "process",
                    StopKey::Group(_) => "group",
                },
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
    document.stop_target = Some(key.clone());
    plan_store::save_plan(environment, &document)?;
    // The stop record is the last write: a request that stops before it
    // leaves a plan that no later request applies.
    plan_store::save_stop(
        environment,
        &StopRecord::new(
            key.clone(),
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
    let key: StopKey = key_of(&arguments.subject)?;
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
    // or of a group and makes its plan, so two requests make one plan.
    let lock = plan_store::lock_stop(environment, &key, invocation.timeout.unwrap_or(LOCK_WAIT))?;
    // An earlier request for the same subject has the plan. The processes
    // of an applied plan can be gone, so this lookup is before the
    // inventory.
    let earlier: Option<StoredPlan> = earlier_plan(&journal, environment, &key, &requested, &now)?;
    let mut snapshot: ProcessSnapshot = processes::collect_snapshot()?;
    environment.seams.edit_process_reading(&mut snapshot);
    let control_plane: Option<Vec<ControlPlaneProcess>> = control_plane_of_this_process(&snapshot);
    let stored: StoredPlan = if let Some(stored) = earlier {
        stored
    } else {
        let candidate: ApplicationCandidate =
            candidate_of(&key, &snapshot, control_plane.as_deref())?;
        new_plan(
            &mut journal,
            environment,
            &key,
            &candidate,
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
    match &key {
        StopKey::Process(target) => crate::text::put_line!(
            summary,
            "This request sends {} to process {target}. Unsaved data of the process can be lost.",
            kind_text(requested.strategy.kind())
        ),
        StopKey::Group(instance) => crate::text::put_line!(
            summary,
            "This request sends {} to each process of the list above, the verified members of instance {instance}. Unsaved data of these processes can be lost.",
            kind_text(requested.strategy.kind())
        ),
    }
    apply::run(
        ApplyFlow {
            plan,
            document: stored.document.clone(),
            authority,
            control_plane,
            no_wait: arguments.apply.no_wait,
            yes: arguments.apply.yes,
            summary,
            what: match key {
                StopKey::Process(_) => "the stop of the process",
                StopKey::Group(_) => "the stop of the group",
            },
            require_agent: false,
        },
        invocation,
    )
}
