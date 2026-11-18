//! Tests of the plan, the operation, the envelope, and the outcomes.

use serde_json::{Value, json};

use super::{
    ActionClass, ActionError, ActionStage, ApplicationBinding, Attribution, CandidateBindingError,
    CapacityEffect, Check, Checked, ClientRole, Correlation, DispatchState, Durability,
    EffectEvidence, EnvelopeContent, EnvelopeError, ErrorCode, ErrorFamily, Escalation,
    EvidenceBinding, ExecutorRole, FileBinding, FileObjectType, LeaseResource, NativeResult,
    Operation, OperationError, OperationState, OutcomeError, PLAN_SCHEMA_VERSION, Plan,
    PlanApproval, PlanContent, PlanError, PlanLimits, PlanState, PlanTarget, PlannedStep,
    Principal, RecordingMode, RequestEnvelope, Reservation, ResourceEffect, ResourceLease,
    StepLimits, StepState, StopReason, TargetBinding, TargetEffect, TargetResult,
    TargetResultRecord, TransitionError, Trigger, TriggerClass, Validity, WorkCharge, aggregate,
    aggregate_step,
};
use crate::authority::{ActionGrantRef, AuthorityBinding, Generation, PrivilegeGrantRef};
use crate::digest::ContentDigest;
use crate::file::{DeviceNumber, FileObjectEvidence, InodeNumber, LosslessPath};
use crate::id::{
    ActionGrantId, AdapterId, ApplicationInstanceId, BootId, ClockDomainId, DecisionId,
    ExecutorEpochId, IncidentId, LeaseId, MembershipSnapshotId, MountId, OperationId, PlanId,
    PolicyRevisionId, PrivilegeGrantId, ProcessGenerationId, RootId, RuleId, RuleRevisionId,
    StepId, TargetId, VolumeId,
};
use crate::observation::Observation;
use crate::policy::{
    ApplicationCandidate, ContinuityGeneration, ControlPlaneProcess, EvaluationClock,
    ForegroundStatus, ProtectionContext, ProtectionFact,
};
use crate::process::{
    AttributionMethod, Pid, ProcessAssociation, ProcessIdentity, ProcessStartTime, Uid,
};
use crate::quantity::{ByteDelta, Bytes, EntryCount, Nanoseconds};
use crate::rule::RuleRef;
use crate::time::{MonotonicNanos, WallTime};

// Fixtures.

/// A change of a plan content in a table of rejected plans.
type PlanChange = Box<dyn FnOnce(&mut PlanContent)>;

/// A change of an envelope content in a table of rejected envelopes.
type EnvelopeChange = Box<dyn FnOnce(&mut EnvelopeContent)>;

fn charge(bytes: u64, items: u64) -> WorkCharge {
    WorkCharge::new(Bytes::new(bytes), EntryCount::new(items))
}

fn target_id(text: &str) -> TargetId {
    TargetId::new(text).unwrap()
}

fn step_id(text: &str) -> StepId {
    StepId::new(text).unwrap()
}

fn rule() -> RuleRef {
    RuleRef {
        id: RuleId::new("svalnir.expired-temporary").unwrap(),
        revision: RuleRevisionId::new("r1").unwrap(),
    }
}

fn file_binding(entry: &str, bytes: u64) -> FileBinding {
    FileBinding {
        root_id: RootId::new("root_1").unwrap(),
        relative_entry: LosslessPath::from_bytes(entry).unwrap(),
        volume_id: VolumeId::new("volume_1").unwrap(),
        mount_id: MountId::new("mount_1").unwrap(),
        object_type: FileObjectType::RegularFile,
        owner: Uid::new(501),
        object: Some(FileObjectEvidence {
            device: DeviceNumber::new(16_777_234),
            inode: InodeNumber::new(991),
        }),
        rule: Some(rule()),
        charge: charge(bytes, 1),
    }
}

fn file_target(id: &str, bytes: u64) -> PlanTarget {
    PlanTarget {
        target_id: target_id(id),
        binding: TargetBinding::File(file_binding(id, bytes)),
    }
}

fn member(generation: &str, pid: i32) -> ProcessIdentity {
    ProcessIdentity {
        generation_id: ProcessGenerationId::new(generation).unwrap(),
        pid: Pid::new(pid).unwrap(),
        start_time: ProcessStartTime::from_timeval(1_794_830_400, 0).unwrap(),
        uid: Uid::new(501),
        boot_id: BootId::new("boot_1").unwrap(),
        executable: None,
        association: ProcessAssociation::Application {
            instance_id: ApplicationInstanceId::new("app_1").unwrap(),
            bundle_identifier: "com.example.Example".to_owned(),
            attribution: AttributionMethod::LaunchServices,
        },
    }
}

fn application_binding() -> ApplicationBinding {
    ApplicationBinding {
        instance_id: ApplicationInstanceId::new("app_1").unwrap(),
        membership: MembershipSnapshotId::new("members_1").unwrap(),
        members: vec![member("proc_1", 4242), member("proc_2", 4243)],
    }
}

fn step(id: &str, class: ActionClass, target: &str) -> PlannedStep {
    PlannedStep {
        step_id: step_id(id),
        action_class: class,
        target_id: target_id(target),
    }
}

fn automatic(class: TriggerClass) -> Trigger {
    Trigger {
        class,
        incident_id: Some(IncidentId::new("incident_1").unwrap()),
        decision_id: Some(DecisionId::new("decision_1").unwrap()),
    }
}

fn grant_ref() -> ActionGrantRef {
    ActionGrantRef {
        grant_id: ActionGrantId::new("grant_1").unwrap(),
        generation: Generation::new(1),
    }
}

fn privilege_ref() -> PrivilegeGrantRef {
    PrivilegeGrantRef {
        grant_id: PrivilegeGrantId::new("privilege_1").unwrap(),
        generation: Generation::new(1),
    }
}

fn validity() -> Validity {
    Validity {
        clock_domain: ClockDomainId::new("clock_1").unwrap(),
        boot_id: BootId::new("boot_1").unwrap(),
        created_at: MonotonicNanos::new(1_000),
        expires_at: MonotonicNanos::new(2_000),
        created_wall: WallTime::from_unix(1_794_830_400, 0).unwrap(),
    }
}

fn clock(now: u64) -> EvaluationClock {
    EvaluationClock {
        now: MonotonicNanos::new(now),
        clock_domain: ClockDomainId::new("clock_1").unwrap(),
        boot_id: BootId::new("boot_1").unwrap(),
        continuity: ContinuityGeneration::new(0),
        last_discontinuity: None,
    }
}

/// A manual filesystem plan of `class` with the targets `a` (60 bytes) and
/// `b` (40 bytes).
fn file_content(class: &ActionClass) -> PlanContent {
    PlanContent {
        schema_version: PLAN_SCHEMA_VERSION,
        plan_id: PlanId::new("plan_1").unwrap(),
        principal: Principal {
            uid: Uid::new(501),
            session: None,
            role: ClientRole::Cli,
        },
        trigger: Trigger::manual(),
        authority: AuthorityBinding {
            policy_revision: PolicyRevisionId::new("policy_1").unwrap(),
            action_grants: Vec::new(),
            privilege_grant: None,
        },
        executor: ExecutorRole::User,
        targets: vec![file_target("a", 60), file_target("b", 40)],
        steps: vec![
            step("s1", class.clone(), "a"),
            step("s2", class.clone(), "b"),
        ],
        limits: PlanLimits {
            work: Some(charge(100, 2)),
            execution_deadline: Nanoseconds::new(30_000_000_000),
            grace: None,
            verification_window: Nanoseconds::new(5_000_000_000),
            escalation: Escalation::None,
        },
        validity: validity(),
    }
}

/// A manual application plan with the force strategy `escalation`.
fn application_content(escalation: Escalation) -> PlanContent {
    use ActionClass::{ForceApplicationExit, RequestApplicationExit};
    let steps = match escalation {
        Escalation::ForceAfterGrace => vec![
            step("graceful", RequestApplicationExit, "app"),
            step("force", ForceApplicationExit, "app"),
        ],
        Escalation::ImmediateForce => vec![step("force", ForceApplicationExit, "app")],
        _ => vec![step("graceful", RequestApplicationExit, "app")],
    };
    let grace = matches!(escalation, Escalation::ForceAfterGrace)
        .then_some(Nanoseconds::new(10_000_000_000));
    PlanContent {
        targets: vec![PlanTarget {
            target_id: target_id("app"),
            binding: TargetBinding::Application(application_binding()),
        }],
        steps,
        limits: PlanLimits {
            work: None,
            grace,
            escalation,
            ..file_content(&ActionClass::MoveToTrash).limits
        },
        ..file_content(&ActionClass::MoveToTrash)
    }
}

/// The application plan of an automatic memory trigger.
fn automatic_application_content(class: TriggerClass, escalation: Escalation) -> PlanContent {
    let mut content = application_content(escalation);
    content.trigger = automatic(class);
    content.principal.role = ClientRole::Agent;
    content.authority.action_grants = vec![grant_ref()];
    content
}

fn seal(content: PlanContent) -> Plan {
    Plan::seal(content).unwrap()
}

fn admit(plan: &Plan) -> Operation {
    Operation::admit(
        plan,
        OperationId::new("operation_1").unwrap(),
        ExecutorEpochId::new("epoch_1").unwrap(),
        Durability::Durable,
        WallTime::from_unix(1_794_830_401, 0).unwrap(),
    )
    .unwrap()
}

fn failure(family: ErrorFamily, dispatch: DispatchState) -> ActionError {
    ActionError {
        code: ErrorCode::new("example").unwrap(),
        family,
        stage: ActionStage::Execution,
        dispatch,
        plan_id: None,
        operation_id: None,
        step_id: None,
    }
}

/// A target result record of `effect` with the usual values of that
/// effect.
fn record(target: &str, effect: TargetEffect) -> TargetResultRecord {
    use DispatchState::{NotSubmitted, SubmissionUncertain, Submitted};
    let (dispatch, native, attribution, stop_reason, error) = match effect {
        TargetEffect::Trashed | TargetEffect::Removed | TargetEffect::ExitVerified => (
            Submitted,
            NativeResult::Succeeded,
            Attribution::Established,
            StopReason::Completed,
            None,
        ),
        TargetEffect::AlreadyAbsent | TargetEffect::AlreadyExited => (
            NotSubmitted,
            NativeResult::NotCalled,
            Attribution::NotApplicable,
            StopReason::Completed,
            None,
        ),
        TargetEffect::Skipped => (
            NotSubmitted,
            NativeResult::NotCalled,
            Attribution::NotApplicable,
            StopReason::Canceled,
            None,
        ),
        TargetEffect::Refused => (
            Submitted,
            NativeResult::Errno { errno: 13 },
            Attribution::NotApplicable,
            StopReason::Failed,
            Some(failure(ErrorFamily::Native, Submitted)),
        ),
        TargetEffect::StillRunning => (
            Submitted,
            NativeResult::Succeeded,
            Attribution::NotApplicable,
            StopReason::TriggerCleared,
            None,
        ),
        _ => (
            SubmissionUncertain,
            NativeResult::Unavailable,
            Attribution::Possible,
            StopReason::Completed,
            None,
        ),
    };
    TargetResultRecord {
        target_id: target_id(target),
        member: None,
        dispatch,
        effect,
        evidence: EffectEvidence {
            native,
            ..EffectEvidence::none()
        },
        attribution,
        durability: Durability::Durable,
        stop_reason,
        failure: error,
    }
}

fn result(target: &str, effect: TargetEffect) -> TargetResult {
    Checked::new(record(target, effect)).unwrap()
}

/// A skipped result with the stop reason `FAILED`.
fn failed_skip(target: &str) -> TargetResult {
    Checked::new(TargetResultRecord {
        stop_reason: StopReason::Failed,
        failure: Some(failure(ErrorFamily::Recording, DispatchState::NotSubmitted)),
        ..record(target, TargetEffect::Skipped)
    })
    .unwrap()
}

/// Moves a step from `Admitted` to `Verifying` on the durable path.
fn submit(operation: &mut Operation, step: &str) {
    use DispatchState::{NotSubmitted, Submitted};
    let id = step_id(step);
    for (state, dispatch) in [
        (StepState::IntentCommitted, NotSubmitted),
        (StepState::DispatchConsumed, NotSubmitted),
        (StepState::Verifying, Submitted),
    ] {
        operation
            .advance_step(&id, state, dispatch, Durability::Durable)
            .unwrap();
    }
}

fn settle_step(operation: &mut Operation, step: &str, results: Vec<TargetResult>) {
    operation
        .settle_step(&step_id(step), results, Durability::Durable)
        .unwrap();
}

// Plans.

#[test]
fn a_plan_of_each_filesystem_class_seals() {
    for class in [
        ActionClass::MoveToTrash,
        ActionClass::DeleteSelectedFiles,
        ActionClass::EvictRegenerableData,
    ] {
        let plan = seal(file_content(&class));
        assert_eq!(plan.state(), PlanState::Prepared);
        assert_eq!(plan.steps.len(), 2);
        assert!(plan.target(&target_id("a")).is_some());
        assert!(plan.target(&target_id("z")).is_none());
    }
    // An automatic eviction plan of the agent.
    let mut content = file_content(&ActionClass::EvictRegenerableData);
    content.trigger = automatic(TriggerClass::DiskPressure);
    content.principal.role = ClientRole::Agent;
    content.authority.action_grants = vec![grant_ref()];
    seal(content);
    // A helper plan names the privilege grant, and the helper can remove
    // an object that the user does not own.
    let mut content = file_content(&ActionClass::EvictRegenerableData);
    content.executor = ExecutorRole::Helper;
    content.authority.privilege_grant = Some(privilege_ref());
    content.targets[0] = PlanTarget {
        target_id: target_id("a"),
        binding: TargetBinding::File(FileBinding {
            owner: Uid::new(0),
            ..file_binding("a", 60)
        }),
    };
    seal(content);
    // A manual Trash plan needs no rule.
    let mut content = file_content(&ActionClass::MoveToTrash);
    content.targets[0] = PlanTarget {
        target_id: target_id("a"),
        binding: TargetBinding::File(FileBinding {
            rule: None,
            object: None,
            ..file_binding("a", 60)
        }),
    };
    seal(content);
}

#[test]
fn an_application_plan_of_each_force_strategy_seals() {
    for escalation in [
        Escalation::None,
        Escalation::ForceAfterGrace,
        Escalation::ImmediateForce,
    ] {
        seal(application_content(escalation.clone()));
        for class in [
            TriggerClass::GlobalCriticalMemory,
            TriggerClass::ApplicationBudget,
        ] {
            seal(automatic_application_content(class, escalation.clone()));
        }
    }
}

#[test]
fn the_digest_covers_the_full_content() {
    let content = file_content(&ActionClass::MoveToTrash);
    let plan = seal(content.clone());
    assert_eq!(plan.digest(), seal(content.clone()).digest());
    assert_eq!(
        plan.digest(),
        &ContentDigest::of_json(&content).unwrap(),
        "the digest is the digest of the JSON of the content"
    );

    let mut other_target = content.clone();
    other_target.targets[1] = file_target("b", 39);
    let mut other_expiry = content.clone();
    other_expiry.validity.expires_at = MonotonicNanos::new(2_001);
    let mut other_policy = content.clone();
    other_policy.authority.policy_revision = PolicyRevisionId::new("policy_2").unwrap();
    let mut other_mode = content.clone();
    for step in &mut other_mode.steps {
        step.action_class = ActionClass::DeleteSelectedFiles;
    }
    let mut other_rule = content;
    other_rule.targets[0] = PlanTarget {
        target_id: target_id("a"),
        binding: TargetBinding::File(FileBinding {
            rule: Some(RuleRef {
                revision: RuleRevisionId::new("r2").unwrap(),
                ..rule()
            }),
            ..file_binding("a", 60)
        }),
    };
    for changed in [
        other_target,
        other_expiry,
        other_policy,
        other_mode,
        other_rule,
    ] {
        assert_ne!(seal(changed).digest(), plan.digest());
    }
}

#[test]
fn an_approval_binds_the_identity_and_the_digest() {
    let plan = seal(file_content(&ActionClass::MoveToTrash));
    let approval = PlanApproval {
        plan_id: plan.plan_id.clone(),
        digest: plan.digest().clone(),
    };
    assert!(plan.is_bound_by(&approval));
    // The approval of the Trash plan does not bind the same targets with
    // permanent deletion.
    let delete = seal(file_content(&ActionClass::DeleteSelectedFiles));
    assert!(!delete.is_bound_by(&approval));
    let other_id = PlanApproval {
        plan_id: PlanId::new("plan_2").unwrap(),
        ..approval.clone()
    };
    assert!(!plan.is_bound_by(&other_id));
    let value = serde_json::to_value(&approval).unwrap();
    assert_eq!(
        serde_json::from_value::<PlanApproval>(value).unwrap(),
        approval
    );
}

#[test]
fn a_plan_round_trips_and_a_changed_plan_is_rejected() {
    for content in [
        file_content(&ActionClass::EvictRegenerableData),
        application_content(Escalation::ForceAfterGrace),
    ] {
        let plan = seal(content);
        let value = serde_json::to_value(&plan).unwrap();
        assert_eq!(value["digest"], json!(plan.digest().as_str()));
        assert_eq!(value["content"]["schema_version"], json!(1));
        assert_eq!(serde_json::from_value::<Plan>(value).unwrap(), plan);
    }

    let plan = seal(file_content(&ActionClass::MoveToTrash));
    let value = serde_json::to_value(&plan).unwrap();
    assert_eq!(
        value["content"]["steps"][0]["action_class"],
        json!("MoveToTrash")
    );
    assert_eq!(value["content"]["trigger"]["class"], json!("manual"));
    assert_eq!(
        value["content"]["targets"][0]["binding"]["charge"],
        json!({ "work_bytes": "60", "items": "1" })
    );

    // A changed target with the digest of the reviewed plan.
    let mut changed = value.clone();
    changed["content"]["targets"][0]["binding"]["relative_entry"]["value"] = json!("Documents");
    assert!(serde_json::from_value::<Plan>(changed).is_err());
    // A broader action class with the digest of the reviewed plan.
    let mut changed = value.clone();
    for index in 0..2 {
        changed["content"]["steps"][index]["action_class"] = json!("DeleteSelectedFiles");
    }
    assert!(serde_json::from_value::<Plan>(changed).is_err());
    let mut changed = value.clone();
    changed["digest"] = json!(ContentDigest::of_bytes(b"other").as_str());
    assert!(serde_json::from_value::<Plan>(changed).is_err());
    let mut changed = value.clone();
    changed["approved"] = json!(true);
    assert!(serde_json::from_value::<Plan>(changed).is_err());
    // A field that this build does not read is not dropped silently.
    for pointer in ["/content", "/content/targets/0/binding", "/content/limits"] {
        let mut changed = value.clone();
        changed.pointer_mut(pointer).unwrap()["replacement_path"] = json!("/");
        assert!(
            serde_json::from_value::<Plan>(changed).is_err(),
            "{pointer}"
        );
    }
    // A value that this build does not recognize makes the plan not
    // executable.
    let mut changed = value.clone();
    changed["content"]["steps"][0]["action_class"] = json!("EmptyTrash");
    assert!(serde_json::from_value::<Plan>(changed).is_err());
    let mut changed = value;
    changed["content"]["targets"][0]["binding"]["kind"] = json!("volume");
    assert!(serde_json::from_value::<Plan>(changed).is_err());
}

fn rejected(change: impl FnOnce(&mut PlanContent), base: PlanContent) -> PlanError {
    let mut content = base;
    change(&mut content);
    Plan::seal(content).unwrap_err()
}

#[test]
#[expect(clippy::too_many_lines, reason = "the test is one table of cases")]
fn a_filesystem_plan_that_does_not_agree_with_itself_is_rejected() {
    use ActionClass::{DeleteSelectedFiles, EvictRegenerableData, MoveToTrash};
    let base = || file_content(&EvictRegenerableData);
    let cases: Vec<(PlanError, PlanChange)> = vec![
        (PlanError::SchemaVersion, Box::new(|c| c.schema_version = 2)),
        (PlanError::Count, Box::new(|c| c.targets.clear())),
        (PlanError::Count, Box::new(|c| c.steps.clear())),
        (
            PlanError::Duplicate,
            Box::new(|c| c.targets.push(file_target("a", 1))),
        ),
        (
            PlanError::Duplicate,
            Box::new(|c| c.steps[1].step_id = step_id("s1")),
        ),
        // A step for a target that the plan does not have.
        (
            PlanError::StepTarget,
            Box::new(|c| c.steps[1].target_id = target_id("z")),
        ),
        // A target with no step, and a target with two steps.
        (PlanError::StepTarget, Box::new(|c| drop(c.steps.pop()))),
        (
            PlanError::StepTarget,
            Box::new(|c| c.steps.push(step("s3", EvictRegenerableData, "a"))),
        ),
        // A manual trigger has no incident.
        (
            PlanError::Trigger,
            Box::new(|c| c.trigger.incident_id = Some(IncidentId::new("i").unwrap())),
        ),
        // An automatic trigger needs its incident, the agent role, and a
        // grant.
        (
            PlanError::Trigger,
            Box::new(|c| c.trigger.class = TriggerClass::DiskPressure),
        ),
        (
            PlanError::Authority,
            Box::new(|c| c.trigger = automatic(TriggerClass::DiskPressure)),
        ),
        (
            PlanError::Trigger,
            Box::new(|c| {
                c.trigger = automatic(TriggerClass::DiskPressure);
                c.authority.action_grants = vec![grant_ref()];
            }),
        ),
        // A memory trigger does not select a filesystem class.
        (
            PlanError::Trigger,
            Box::new(|c| {
                c.trigger = automatic(TriggerClass::GlobalCriticalMemory);
                c.principal.role = ClientRole::Agent;
                c.authority.action_grants = vec![grant_ref()];
            }),
        ),
        // An automatic trigger names its decision.
        (
            PlanError::Trigger,
            Box::new(|c| {
                c.trigger = automatic(TriggerClass::DiskPressure);
                c.trigger.decision_id = None;
                c.principal.role = ClientRole::Agent;
                c.authority.action_grants = vec![grant_ref()];
            }),
        ),
        // A helper acts only under its own grant, and the user executor
        // names none.
        (
            PlanError::Authority,
            Box::new(|c| c.executor = ExecutorRole::Helper),
        ),
        (
            PlanError::Authority,
            Box::new(|c| c.authority.privilege_grant = Some(privilege_ref())),
        ),
        // One plan has one filesystem class.
        (
            PlanError::Steps,
            Box::new(|c| c.steps[1].action_class = MoveToTrash),
        ),
        // An application class does not apply to a file target.
        (
            PlanError::Binding,
            Box::new(|c| c.steps[1].action_class = ActionClass::ForceApplicationExit),
        ),
        // Eviction needs the rule revision.
        (
            PlanError::Binding,
            Box::new(|c| {
                c.targets[0].binding = TargetBinding::File(FileBinding {
                    rule: None,
                    ..file_binding("a", 60)
                });
            }),
        ),
        // The user executor does not change the object of another user.
        (
            PlanError::Binding,
            Box::new(|c| {
                c.targets[0].binding = TargetBinding::File(FileBinding {
                    owner: Uid::new(0),
                    ..file_binding("a", 60)
                });
            }),
        ),
        // The limit is the bound of the sum of the charges.
        (PlanError::Limits, Box::new(|c| c.limits.work = None)),
        (
            PlanError::Limits,
            Box::new(|c| c.limits.work = Some(charge(99, 2))),
        ),
        (
            PlanError::Limits,
            Box::new(|c| c.limits.work = Some(charge(100, 1))),
        ),
        (
            PlanError::Limits,
            Box::new(|c| c.targets[0] = file_target("a", u64::MAX)),
        ),
        (
            PlanError::Limits,
            Box::new(|c| c.limits.execution_deadline = Nanoseconds::ZERO),
        ),
        (
            PlanError::Limits,
            Box::new(|c| c.limits.verification_window = Nanoseconds::ZERO),
        ),
        // A filesystem plan has no force strategy and no grace period.
        (
            PlanError::Limits,
            Box::new(|c| c.limits.escalation = Escalation::ImmediateForce),
        ),
        (
            PlanError::Limits,
            Box::new(|c| c.limits.grace = Some(Nanoseconds::new(1))),
        ),
        (
            PlanError::Validity,
            Box::new(|c| c.validity.expires_at = c.validity.created_at),
        ),
        // A value that this build does not recognize.
        (
            PlanError::Unrecognized,
            Box::new(|c| c.steps[0].action_class = ActionClass::from_wire("EmptyTrash")),
        ),
        (
            PlanError::Unrecognized,
            Box::new(|c| c.principal.role = ClientRole::from_wire("plugin")),
        ),
        (
            PlanError::Unrecognized,
            Box::new(|c| c.executor = ExecutorRole::from_wire("root_shell")),
        ),
        (
            PlanError::Unrecognized,
            Box::new(|c| c.trigger.class = TriggerClass::from_wire("thermal")),
        ),
        (
            PlanError::Unrecognized,
            Box::new(|c| {
                c.targets[0].binding = TargetBinding::File(FileBinding {
                    object_type: FileObjectType::from_wire("socket"),
                    ..file_binding("a", 60)
                });
            }),
        ),
    ];
    for (index, (expected, change)) in cases.into_iter().enumerate() {
        assert_eq!(rejected(change, base()), expected, "case {index}");
    }
    // A manual trigger selects each class, and the two manual-only
    // classes have no automatic plan.
    for class in [MoveToTrash, DeleteSelectedFiles] {
        let error = rejected(
            |c| {
                c.trigger = automatic(TriggerClass::DiskPressure);
                c.principal.role = ClientRole::Agent;
                c.authority.action_grants = vec![grant_ref()];
            },
            file_content(&class),
        );
        assert_eq!(error, PlanError::Trigger, "{class}");
    }
}

#[test]
#[expect(clippy::too_many_lines, reason = "the test is one table of cases")]
fn an_application_plan_that_does_not_agree_with_itself_is_rejected() {
    use ActionClass::{ForceApplicationExit, RequestApplicationExit};
    let with_members = |members: Vec<ProcessIdentity>| {
        move |c: &mut PlanContent| {
            c.targets[0].binding = TargetBinding::Application(ApplicationBinding {
                members,
                ..application_binding()
            });
        }
    };
    let other_user = ProcessIdentity {
        uid: Uid::new(0),
        ..member("proc_3", 1)
    };
    let unattributed = ProcessIdentity {
        association: ProcessAssociation::Unattributed,
        ..member("proc_3", 5000)
    };
    // A method that this build does not recognize can be a name match.
    let by_name = ProcessIdentity {
        association: ProcessAssociation::Application {
            instance_id: ApplicationInstanceId::new("app_1").unwrap(),
            bundle_identifier: "com.example.Example".to_owned(),
            attribution: AttributionMethod::from_wire("process_name"),
        },
        ..member("proc_3", 5000)
    };
    let other_instance = ProcessIdentity {
        association: ProcessAssociation::Application {
            instance_id: ApplicationInstanceId::new("app_2").unwrap(),
            bundle_identifier: "com.example.Example".to_owned(),
            attribution: AttributionMethod::LaunchServices,
        },
        ..member("proc_3", 5000)
    };
    let graceful = || application_content(Escalation::None);
    let escalating = || application_content(Escalation::ForceAfterGrace);
    let cases: Vec<(PlanError, PlanContent, PlanChange)> = vec![
        // The steps agree with the force strategy.
        (
            PlanError::Steps,
            graceful(),
            Box::new(|c| c.steps.push(step("force", ForceApplicationExit, "app"))),
        ),
        (
            PlanError::Steps,
            graceful(),
            Box::new(|c| c.steps[0].action_class = ForceApplicationExit),
        ),
        (
            PlanError::Steps,
            escalating(),
            Box::new(|c| c.steps.swap(0, 1)),
        ),
        (
            PlanError::Steps,
            escalating(),
            Box::new(|c| drop(c.steps.pop())),
        ),
        (
            PlanError::Steps,
            application_content(Escalation::ImmediateForce),
            Box::new(|c| c.steps[0].action_class = RequestApplicationExit),
        ),
        (
            PlanError::Steps,
            escalating(),
            Box::new(|c| c.steps.push(step("force2", ForceApplicationExit, "app"))),
        ),
        (
            PlanError::Unrecognized,
            graceful(),
            Box::new(|c| c.limits.escalation = Escalation::from_wire("kill_group")),
        ),
        // A filesystem class does not apply to an application target.
        (
            PlanError::Steps,
            graceful(),
            Box::new(|c| c.steps[0].action_class = ActionClass::MoveToTrash),
        ),
        // A file target and an application target are not in one plan.
        (
            PlanError::Steps,
            graceful(),
            Box::new(|c| {
                c.targets.push(file_target("a", 1));
                c.steps.insert(0, step("s1", ActionClass::MoveToTrash, "a"));
            }),
        ),
        // The grace period exists exactly with force after grace.
        (
            PlanError::Limits,
            escalating(),
            Box::new(|c| c.limits.grace = None),
        ),
        (
            PlanError::Limits,
            escalating(),
            Box::new(|c| c.limits.grace = Some(Nanoseconds::ZERO)),
        ),
        (
            PlanError::Limits,
            graceful(),
            Box::new(|c| c.limits.grace = Some(Nanoseconds::new(1))),
        ),
        (
            PlanError::Limits,
            graceful(),
            Box::new(|c| c.limits.work = Some(charge(1, 1))),
        ),
        // The members have positive evidence for this instance and this
        // user.
        (
            PlanError::Count,
            graceful(),
            Box::new(with_members(Vec::new())),
        ),
        (
            PlanError::Duplicate,
            graceful(),
            Box::new(with_members(vec![member("proc_1", 1), member("proc_1", 2)])),
        ),
        (
            PlanError::Binding,
            graceful(),
            Box::new(with_members(vec![member("proc_1", 1), other_user])),
        ),
        (
            PlanError::Binding,
            graceful(),
            Box::new(with_members(vec![unattributed])),
        ),
        (
            PlanError::Binding,
            graceful(),
            Box::new(with_members(vec![by_name])),
        ),
        (
            PlanError::Binding,
            graceful(),
            Box::new(with_members(vec![other_instance])),
        ),
        // The process-control surface has no helper executor.
        (
            PlanError::Binding,
            graceful(),
            Box::new(|c| {
                c.executor = ExecutorRole::Helper;
                c.authority.privilege_grant = Some(privilege_ref());
            }),
        ),
        // A disk trigger does not select an application intervention.
        (
            PlanError::Trigger,
            graceful(),
            Box::new(|c| {
                c.trigger = automatic(TriggerClass::DiskPressure);
                c.principal.role = ClientRole::Agent;
                c.authority.action_grants = vec![grant_ref()];
            }),
        ),
    ];
    for (index, (expected, base, change)) in cases.into_iter().enumerate() {
        assert_eq!(rejected(change, base), expected, "case {index}");
    }
}

#[test]
fn a_plan_expires_at_its_expiry_and_in_another_clock_context() {
    let plan = seal(file_content(&ActionClass::MoveToTrash));
    assert!(!plan.is_expired(&clock(1_000)));
    assert!(!plan.is_expired(&clock(1_999)));
    assert!(plan.is_expired(&clock(2_000)));
    assert!(plan.is_expired(&clock(u64::MAX)));
    // A time before the plan was built is not comparable.
    assert!(plan.is_expired(&clock(999)));
    let other_boot = EvaluationClock {
        boot_id: BootId::new("boot_2").unwrap(),
        ..clock(1_500)
    };
    assert!(plan.is_expired(&other_boot));
    let other_domain = EvaluationClock {
        clock_domain: ClockDomainId::new("clock_2").unwrap(),
        ..clock(1_500)
    };
    assert!(plan.is_expired(&other_domain));
}

#[test]
fn an_application_binding_is_the_membership_snapshot_of_the_policy_candidate() {
    let candidate =
        |hard_protection: ProtectionFact, processes: Vec<ProcessIdentity>| ApplicationCandidate {
            processes,
            membership_snapshot: MembershipSnapshotId::new("members_1").unwrap(),
            foreground: ForegroundStatus::Background,
            footprint: capacity_observation("volume_1", &json!("1")),
            hard_protection,
        };
    let members = || vec![member("proc_1", 4242), member("proc_2", 4243)];
    let binding =
        ApplicationBinding::from_candidate(&candidate(ProtectionFact::NotProtected, members()));
    assert_eq!(binding, Ok(application_binding()));
    // A hard protection, or an unknown one, gives no target. A manual
    // request does not remove it.
    assert_eq!(
        ApplicationBinding::from_candidate(&candidate(ProtectionFact::Protected, members())),
        Err(CandidateBindingError::Protected)
    );
    assert_eq!(
        ApplicationBinding::from_candidate(&candidate(ProtectionFact::Unknown, members())),
        Err(CandidateBindingError::ProtectionUnknown)
    );
    // The members have positive evidence for one instance.
    let unattributed = ProcessIdentity {
        association: ProcessAssociation::Unattributed,
        ..member("proc_3", 5000)
    };
    let other_instance = ProcessIdentity {
        association: ProcessAssociation::Application {
            instance_id: ApplicationInstanceId::new("app_2").unwrap(),
            bundle_identifier: "com.example.Example".to_owned(),
            attribution: AttributionMethod::LaunchServices,
        },
        ..member("proc_3", 5000)
    };
    for processes in [
        Vec::new(),
        vec![member("proc_1", 4242), unattributed],
        vec![member("proc_1", 4242), other_instance],
    ] {
        assert_eq!(
            ApplicationBinding::from_candidate(&candidate(ProtectionFact::NotProtected, processes)),
            Err(CandidateBindingError::Membership)
        );
    }

    // The binding gives its members to the catalog of hard protections.
    let binding = application_binding();
    let context = |control_plane| ProtectionContext {
        principal: Uid::new(501),
        control_plane,
    };
    // The fixture members have no executable evidence, so the catalog
    // cannot classify them.
    assert_eq!(
        binding.hard_protection(&context(Some(&[]))),
        ProtectionFact::Unknown
    );
    let other_user = ProtectionContext {
        principal: Uid::new(502),
        control_plane: Some(&[]),
    };
    assert_eq!(
        binding.hard_protection(&other_user),
        ProtectionFact::Protected
    );
    let own = [ControlPlaneProcess {
        pid: Pid::new(4242).unwrap(),
        start_time: ProcessStartTime::from_timeval(1_794_830_400, 0).unwrap(),
    }];
    assert_eq!(
        binding.hard_protection(&context(Some(&own))),
        ProtectionFact::Protected
    );
}

// Target results.

#[test]
fn the_usual_result_of_each_effect_is_consistent() {
    for effect in &TargetEffect::ALL {
        let result = result("a", effect.clone());
        let value = serde_json::to_value(&result).unwrap();
        assert_eq!(value["effect"], json!(effect.as_str()));
        assert_eq!(
            serde_json::from_value::<TargetResult>(value).unwrap(),
            result
        );
    }
    let value = serde_json::to_value(result("a", TargetEffect::StillRunning)).unwrap();
    assert_eq!(
        value,
        json!({
            "target_id": "a",
            "member": null,
            "dispatch": "submitted",
            "effect": "StillRunning",
            "evidence": {
                "native": { "kind": "succeeded" },
                "source": null,
                "observed_at": null,
                "trash_item": null,
            },
            "attribution": "not_applicable",
            "durability": "durable",
            "stop_reason": "TRIGGER_CLEARED",
            "failure": null,
        })
    );
}

#[test]
#[expect(clippy::too_many_lines, reason = "the test is one table of cases")]
fn a_result_that_claims_more_than_its_evidence_is_rejected() {
    use DispatchState::{NotSubmitted, SubmissionUncertain, Submitted};
    let check = |change: &dyn Fn(&mut TargetResultRecord), effect: TargetEffect| {
        let mut record = record("a", effect);
        change(&mut record);
        record.check()
    };
    // A verified effect needs a submitted call.
    for effect in [
        TargetEffect::Trashed,
        TargetEffect::Removed,
        TargetEffect::ExitVerified,
        TargetEffect::Refused,
        TargetEffect::StillRunning,
    ] {
        for dispatch in [NotSubmitted, SubmissionUncertain] {
            assert_eq!(
                check(&|r| r.dispatch = dispatch.clone(), effect.clone()),
                Err(OutcomeError::Dispatch),
                "{effect}"
            );
        }
    }
    assert_eq!(
        check(&|r| r.dispatch = Submitted, TargetEffect::Skipped),
        Err(OutcomeError::Dispatch)
    );
    assert_eq!(
        check(&|r| r.dispatch = NotSubmitted, TargetEffect::UnknownOutcome),
        Err(OutcomeError::Dispatch)
    );
    // A verified effect is an effect of the action.
    assert_eq!(
        check(
            &|r| r.attribution = Attribution::NotApplicable,
            TargetEffect::Removed
        ),
        Err(OutcomeError::Attribution)
    );
    check(
        &|r| r.attribution = Attribution::Possible,
        TargetEffect::ExitVerified,
    )
    .unwrap();
    // A no-op is not an effect of the action.
    for attribution in [Attribution::Established, Attribution::Possible] {
        assert_eq!(
            check(
                &|r| r.attribution = attribution.clone(),
                TargetEffect::AlreadyAbsent
            ),
            Err(OutcomeError::Attribution)
        );
        assert_eq!(
            check(
                &|r| r.attribution = attribution.clone(),
                TargetEffect::Skipped
            ),
            Err(OutcomeError::Attribution)
        );
    }
    // After a possible call, the cause of the absence is not established.
    let after_crash = |attribution: Attribution| {
        move |r: &mut TargetResultRecord| {
            r.dispatch = SubmissionUncertain;
            r.evidence.native = NativeResult::Unavailable;
            r.attribution = attribution.clone();
        }
    };
    check(
        &after_crash(Attribution::Possible),
        TargetEffect::AlreadyExited,
    )
    .unwrap();
    for attribution in [Attribution::Established, Attribution::NotApplicable] {
        assert_eq!(
            check(&after_crash(attribution), TargetEffect::AlreadyExited),
            Err(OutcomeError::Attribution)
        );
    }
    assert_eq!(
        check(
            &|r| r.attribution = Attribution::Established,
            TargetEffect::UnknownOutcome
        ),
        Err(OutcomeError::Attribution)
    );
    // A skipped target has a reason, and a refusal is a failure.
    assert_eq!(
        check(
            &|r| r.stop_reason = StopReason::Completed,
            TargetEffect::Skipped
        ),
        Err(OutcomeError::StopReason)
    );
    assert_eq!(
        check(
            &|r| r.stop_reason = StopReason::Completed,
            TargetEffect::Refused
        ),
        Err(OutcomeError::StopReason)
    );
    assert_eq!(
        check(
            &|r| r.stop_reason = StopReason::Failed,
            TargetEffect::Removed
        ),
        Err(OutcomeError::StopReason)
    );
    assert_eq!(
        check(
            &|r| r.stop_reason = StopReason::TargetSkipped,
            TargetEffect::StillRunning
        ),
        Err(OutcomeError::StopReason)
    );
    // A target in its final condition is not a failure.
    for effect in [TargetEffect::AlreadyAbsent, TargetEffect::AlreadyExited] {
        assert_eq!(
            check(
                &|r| {
                    r.stop_reason = StopReason::Failed;
                    r.failure = Some(failure(ErrorFamily::Native, NotSubmitted));
                },
                effect
            ),
            Err(OutcomeError::StopReason)
        );
    }
    // A failure and a precondition skip have an error record, and no
    // other result has one.
    for stop_reason in [StopReason::Failed, StopReason::TargetSkipped] {
        assert_eq!(
            check(
                &|r| r.stop_reason = stop_reason.clone(),
                TargetEffect::Skipped
            ),
            Err(OutcomeError::Failure)
        );
    }
    check(
        &|r| {
            r.stop_reason = StopReason::TargetSkipped;
            r.failure = Some(failure(ErrorFamily::Eligibility, NotSubmitted));
        },
        TargetEffect::Skipped,
    )
    .unwrap();
    assert_eq!(
        check(&|r| r.failure = None, TargetEffect::Refused),
        Err(OutcomeError::Failure)
    );
    assert_eq!(
        check(
            &|r| r.failure = Some(failure(ErrorFamily::Native, Submitted)),
            TargetEffect::Removed
        ),
        Err(OutcomeError::Failure)
    );
    // The native evidence agrees with the dispatch state.
    assert_eq!(
        check(
            &|r| r.evidence.native = NativeResult::NotCalled,
            TargetEffect::Removed
        ),
        Err(OutcomeError::Evidence)
    );
    assert_eq!(
        check(
            &|r| r.evidence.native = NativeResult::Succeeded,
            TargetEffect::Skipped
        ),
        Err(OutcomeError::Evidence)
    );
    // Only a Trash move has an item in Trash.
    let trash_item = |r: &mut TargetResultRecord| {
        r.evidence.trash_item = Some(LosslessPath::from_bytes("/Users/a/.Trash/a 2").unwrap());
    };
    check(&trash_item, TargetEffect::Trashed).unwrap();
    assert_eq!(
        check(&trash_item, TargetEffect::Removed),
        Err(OutcomeError::Evidence)
    );
    assert_eq!(
        check(&trash_item, TargetEffect::Skipped),
        Err(OutcomeError::Evidence)
    );
    // Decoding runs the same check.
    let mut value = serde_json::to_value(result("a", TargetEffect::Removed)).unwrap();
    value["dispatch"] = json!("not_submitted");
    assert!(serde_json::from_value::<TargetResult>(value).is_err());
}

#[test]
fn an_unknown_effect_stays_unknown() {
    let mut value = serde_json::to_value(result("a", TargetEffect::Removed)).unwrap();
    value["effect"] = json!("Archived");
    let decoded: TargetResult = serde_json::from_value(value.clone()).unwrap();
    assert!(!decoded.effect.is_recognized());
    assert!(!decoded.effect.is_verified());
    assert!(!decoded.effect.is_final_condition_met());
    assert!(decoded.effect.is_indeterminate());
    assert_eq!(serde_json::to_value(&decoded).unwrap(), value);
    assert_eq!(
        aggregate(&[decoded, result("b", TargetEffect::Removed)]),
        Ok(OperationState::UnknownOutcome)
    );
    // An unknown stop reason or dispatch state is not read as a normal
    // end.
    for (field, text) in [
        ("stop_reason", "RETIRED"),
        ("dispatch", "queued"),
        ("attribution", "inferred"),
        ("durability", "replicated"),
    ] {
        let mut value = serde_json::to_value(result("a", TargetEffect::Removed)).unwrap();
        value[field] = json!(text);
        let decoded: TargetResult = serde_json::from_value(value).unwrap();
        assert_eq!(aggregate(&[decoded]), Ok(OperationState::UnknownOutcome));
    }
    let native: NativeResult = serde_json::from_value(json!({ "kind": "signal_queued" })).unwrap();
    assert_eq!(native, NativeResult::Unrecognized);
    // A record with an unknown native result or an unknown attribution is
    // not checked, so it is not read as a removal with no call.
    let mut value = serde_json::to_value(result("a", TargetEffect::Removed)).unwrap();
    value["dispatch"] = json!("not_submitted");
    value["evidence"]["native"] = json!({ "kind": "signal_queued" });
    let decoded: TargetResult = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(aggregate(&[decoded]), Ok(OperationState::UnknownOutcome));
    value["evidence"]["native"] = json!({ "kind": "not_called" });
    value["attribution"] = json!("inferred");
    let decoded: TargetResult = serde_json::from_value(value).unwrap();
    assert_eq!(aggregate(&[decoded]), Ok(OperationState::UnknownOutcome));
    assert_eq!(
        serde_json::from_value::<NativeResult>(json!({ "kind": "errno", "errno": 4 })).unwrap(),
        NativeResult::Errno { errno: 4 }
    );
    for effect in &TargetEffect::ALL {
        assert_eq!(
            effect.is_verified(),
            matches!(
                effect,
                TargetEffect::Trashed | TargetEffect::Removed | TargetEffect::ExitVerified
            )
        );
        assert_eq!(
            effect.is_indeterminate(),
            effect == &TargetEffect::UnknownOutcome
        );
    }
}

// Aggregation.

#[test]
#[expect(clippy::too_many_lines, reason = "the test is one table of cases")]
fn aggregation_follows_the_precedence_of_the_specification() {
    use OperationState::{Completed, Failed, Incomplete, NoAction, Partial, UnknownOutcome};
    use TargetEffect as E;
    let trigger_cleared_skip = || {
        Checked::new(TargetResultRecord {
            stop_reason: StopReason::TriggerCleared,
            ..record("app", E::Skipped)
        })
        .unwrap()
    };
    let cases: Vec<(OperationState, Vec<TargetResult>)> = vec![
        (
            Completed,
            vec![result("a", E::Removed), result("b", E::Removed)],
        ),
        (Completed, vec![result("a", E::Trashed)]),
        // Verified actions with a target that was absent.
        (
            Completed,
            vec![result("a", E::Removed), result("b", E::AlreadyAbsent)],
        ),
        // Each target was absent before dispatch.
        (
            NoAction,
            vec![result("a", E::AlreadyAbsent), result("b", E::AlreadyAbsent)],
        ),
        (NoAction, vec![result("a", E::AlreadyExited)]),
        // Canceled before dispatch.
        (
            NoAction,
            vec![result("a", E::Skipped), result("b", E::Skipped)],
        ),
        (
            NoAction,
            vec![result("a", E::AlreadyAbsent), result("b", E::Skipped)],
        ),
        // Cancellation after a verified removal.
        (
            Partial,
            vec![result("a", E::Removed), result("b", E::Skipped)],
        ),
        (
            Partial,
            vec![result("a", E::Removed), result("b", E::Refused)],
        ),
        (Partial, vec![result("a", E::Removed), failed_skip("b")]),
        // A known failure and no verified effect.
        (Failed, vec![result("a", E::Refused)]),
        (Failed, vec![failed_skip("a"), failed_skip("b")]),
        // A settled error is before `NoAction` and before `Incomplete`.
        (Failed, vec![result("a", E::Skipped), failed_skip("b")]),
        (
            Failed,
            vec![result("a", E::AlreadyAbsent), failed_skip("b")],
        ),
        (
            Failed,
            vec![result("app", E::StillRunning), failed_skip("b")],
        ),
        // A submitted graceful request that leaves the application
        // running is not `NoAction`.
        (Incomplete, vec![result("app", E::StillRunning)]),
        // The unknown outcome is before each other result.
        (UnknownOutcome, vec![result("a", E::UnknownOutcome)]),
        (
            UnknownOutcome,
            vec![result("a", E::Removed), result("b", E::UnknownOutcome)],
        ),
        (
            UnknownOutcome,
            vec![result("a", E::UnknownOutcome), result("b", E::Refused)],
        ),
        (
            UnknownOutcome,
            vec![result("a", E::UnknownOutcome), failed_skip("b")],
        ),
        (
            UnknownOutcome,
            vec![result("a", E::UnknownOutcome), result("b", E::Skipped)],
        ),
        // A graceful step and a force step for one target: the last
        // result is the final condition.
        (
            Completed,
            vec![
                result("app", E::StillRunning),
                result("app", E::ExitVerified),
            ],
        ),
        (
            Completed,
            vec![
                result("app", E::ExitVerified),
                result("app", E::AlreadyExited),
            ],
        ),
        (
            Incomplete,
            vec![result("app", E::StillRunning), trigger_cleared_skip()],
        ),
        (
            Failed,
            vec![result("app", E::StillRunning), result("app", E::Refused)],
        ),
        // An unknown graceful outcome stays unknown after a verified
        // force step.
        (
            UnknownOutcome,
            vec![
                result("app", E::UnknownOutcome),
                result("app", E::ExitVerified),
            ],
        ),
    ];
    for (index, (expected, results)) in cases.into_iter().enumerate() {
        assert_eq!(aggregate(&results), Ok(expected), "case {index}");
    }
    assert_eq!(aggregate(&[]), Err(OutcomeError::NoResults));
    assert_eq!(aggregate_step(&[]), Err(OutcomeError::NoResults));
}

#[test]
fn aggregation_keeps_the_members_of_an_application_apart() {
    let for_member = |generation: &str, effect: TargetEffect| {
        Checked::new(TargetResultRecord {
            member: Some(ProcessGenerationId::new(generation).unwrap()),
            ..record("app", effect)
        })
        .unwrap()
    };
    // A verified exit and a member that still runs.
    let results = vec![
        for_member("proc_1", TargetEffect::ExitVerified),
        for_member("proc_2", TargetEffect::StillRunning),
    ];
    assert_eq!(aggregate(&results), Ok(OperationState::Partial));
    assert_eq!(aggregate_step(&results), Ok(StepState::Partial));
    let results = vec![
        for_member("proc_1", TargetEffect::ExitVerified),
        for_member("proc_2", TargetEffect::ExitVerified),
    ];
    assert_eq!(aggregate(&results), Ok(OperationState::Completed));
    // A later record for one member replaces the earlier record for the
    // target as a whole, and the reverse.
    let results = vec![
        result("app", TargetEffect::StillRunning),
        for_member("proc_1", TargetEffect::ExitVerified),
        for_member("proc_2", TargetEffect::ExitVerified),
    ];
    assert_eq!(aggregate(&results), Ok(OperationState::Completed));
    let results = vec![
        for_member("proc_1", TargetEffect::ExitVerified),
        for_member("proc_2", TargetEffect::StillRunning),
        result("app", TargetEffect::ExitVerified),
    ];
    assert_eq!(aggregate(&results), Ok(OperationState::Completed));
    // After a crash, the absence of the target has a possible cause only,
    // and the operation is not `NoAction`.
    let after_crash = Checked::new(TargetResultRecord {
        dispatch: DispatchState::SubmissionUncertain,
        attribution: Attribution::Possible,
        evidence: EffectEvidence {
            native: NativeResult::Unavailable,
            ..EffectEvidence::none()
        },
        ..record("app", TargetEffect::AlreadyExited)
    })
    .unwrap();
    assert_eq!(aggregate(&[after_crash]), Ok(OperationState::Completed));
}

#[test]
fn each_step_state_of_an_aggregate_has_the_name_of_the_operation_state() {
    use TargetEffect as E;
    for (results, state) in [
        (vec![result("a", E::Removed)], StepState::Completed),
        (vec![result("a", E::AlreadyAbsent)], StepState::NoAction),
        (vec![result("a", E::Refused)], StepState::Failed),
        (vec![result("a", E::StillRunning)], StepState::Incomplete),
        (
            vec![result("a", E::UnknownOutcome)],
            StepState::UnknownOutcome,
        ),
    ] {
        assert_eq!(aggregate_step(&results), Ok(state));
    }
}

// Operations.

#[test]
fn an_admitted_operation_has_the_steps_of_its_plan() {
    let plan = seal(file_content(&ActionClass::MoveToTrash));
    let operation = admit(&plan);
    assert_eq!(operation.state(), &OperationState::Admitted);
    assert_eq!(operation.plan_id(), &plan.plan_id);
    assert_eq!(operation.plan_digest(), plan.digest());
    assert_eq!(operation.trigger_class(), &TriggerClass::Manual);
    assert_eq!(operation.dispatch(), DispatchState::NotSubmitted);
    assert_eq!(operation.durability(), Durability::Durable);
    assert_eq!(operation.steps().len(), 2);
    for (step, planned) in operation.steps().iter().zip(&plan.steps) {
        assert_eq!(step.step_id(), &planned.step_id);
        assert_eq!(step.action_class(), &planned.action_class);
        assert_eq!(step.target_id(), &planned.target_id);
        assert_eq!(step.progress().state(), &StepState::Admitted);
        assert_eq!(step.results(), []);
    }
    assert!(operation.step(&step_id("s2")).is_some());
    assert!(operation.step(&step_id("s9")).is_none());
    assert_eq!(operation.target_results(), []);
}

#[test]
fn volatile_admission_is_only_for_a_critical_memory_intervention() {
    let admit_volatile = |content: PlanContent, durability: Durability| {
        Operation::admit(
            &seal(content),
            OperationId::new("operation_1").unwrap(),
            ExecutorEpochId::new("epoch_1").unwrap(),
            durability,
            WallTime::UNIX_EPOCH,
        )
    };
    let volatile = Durability::Volatile;
    let critical = automatic_application_content(
        TriggerClass::GlobalCriticalMemory,
        Escalation::ForceAfterGrace,
    );
    let operation = admit_volatile(critical.clone(), volatile.clone()).unwrap();
    assert_eq!(operation.durability(), Durability::Volatile);
    for step in operation.steps() {
        assert_eq!(step.progress().durability(), &Durability::Volatile);
    }
    // No filesystem action, no manual process control, and no budget
    // trigger.
    let mut evict = file_content(&ActionClass::EvictRegenerableData);
    evict.trigger = automatic(TriggerClass::DiskPressure);
    evict.principal.role = ClientRole::Agent;
    evict.authority.action_grants = vec![grant_ref()];
    for content in [
        file_content(&ActionClass::MoveToTrash),
        evict,
        application_content(Escalation::ForceAfterGrace),
        automatic_application_content(TriggerClass::ApplicationBudget, Escalation::None),
    ] {
        assert_eq!(
            admit_volatile(content, volatile.clone()),
            Err(OperationError::Recording)
        );
    }
    for durability in [Durability::PersistenceFailed, Durability::from_wire("x")] {
        assert_eq!(
            admit_volatile(critical.clone(), durability),
            Err(OperationError::Recording)
        );
    }
}

#[test]
fn a_filesystem_operation_settles_from_its_recorded_results() {
    let plan = seal(file_content(&ActionClass::DeleteSelectedFiles));
    let mut operation = admit(&plan);
    submit(&mut operation, "s1");
    assert_eq!(operation.dispatch(), DispatchState::Submitted);
    // The operation does not settle while a step has no result.
    assert_eq!(operation.settle(), Err(OperationError::Unfinished));
    settle_step(
        &mut operation,
        "s1",
        vec![result("a", TargetEffect::Removed)],
    );
    assert_eq!(operation.settle(), Err(OperationError::Unfinished));
    // The cancellation stops the second step before its intent.
    settle_step(
        &mut operation,
        "s2",
        vec![result("b", TargetEffect::Skipped)],
    );
    let step = operation.step(&step_id("s2")).unwrap();
    assert_eq!(step.progress().state(), &StepState::NoAction);
    assert_eq!(step.progress().dispatch(), &DispatchState::NotSubmitted);
    assert_eq!(operation.settle(), Ok(&OperationState::Partial));
    assert_eq!(operation.target_results().len(), 2);

    // A settled operation does not change.
    assert_eq!(operation.settle(), Err(OperationError::Settled));
    assert_eq!(
        operation.settle_step(
            &step_id("s2"),
            vec![result("b", TargetEffect::AlreadyAbsent)],
            Durability::Durable
        ),
        Err(OperationError::Settled)
    );
    assert_eq!(
        operation.advance_step(
            &step_id("s2"),
            StepState::IntentCommitted,
            DispatchState::NotSubmitted,
            Durability::Durable
        ),
        Err(OperationError::Settled)
    );
}

#[test]
fn a_step_takes_only_results_that_its_progress_supports() {
    let plan = seal(file_content(&ActionClass::DeleteSelectedFiles));
    let mut operation = admit(&plan);
    let s1 = step_id("s1");
    // A verified effect for a step whose dispatch was not consumed.
    assert!(matches!(
        operation.settle_step(
            &s1,
            vec![result("a", TargetEffect::Removed)],
            Durability::Durable
        ),
        Err(OperationError::Transition(
            TransitionError::NotPermitted { .. }
        ))
    ));
    assert_eq!(operation.step(&s1).unwrap().results(), []);
    // A result state has no direct write.
    for state in [
        StepState::Completed,
        StepState::NoAction,
        StepState::Failed,
        StepState::UnknownOutcome,
        StepState::Admitted,
    ] {
        assert_eq!(
            operation.advance_step(&s1, state, DispatchState::Submitted, Durability::Durable),
            Err(OperationError::ResultsRequired)
        );
    }
    assert_eq!(
        operation.settle_step(&s1, Vec::new(), Durability::Durable),
        Err(OperationError::Outcome(OutcomeError::NoResults))
    );
    // A result for a target of a different step.
    assert_eq!(
        operation.settle_step(
            &s1,
            vec![result("b", TargetEffect::Skipped)],
            Durability::Durable
        ),
        Err(OperationError::ResultTarget)
    );
    assert_eq!(
        operation.settle_step(
            &step_id("s9"),
            vec![result("a", TargetEffect::Skipped)],
            Durability::Durable
        ),
        Err(OperationError::UnknownStep)
    );
    // The intent cannot be recorded: the step fails with no call.
    operation
        .settle_step(&s1, vec![failed_skip("a")], Durability::PersistenceFailed)
        .unwrap();
    let step = operation.step(&s1).unwrap();
    assert_eq!(step.progress().state(), &StepState::Failed);
    assert_eq!(operation.durability(), Durability::PersistenceFailed);
    // A skipped result after a submitted call is not possible.
    submit(&mut operation, "s2");
    assert!(matches!(
        operation.settle_step(
            &step_id("s2"),
            vec![result("b", TargetEffect::Skipped)],
            Durability::Durable
        ),
        Err(OperationError::Transition(_))
    ));
    settle_step(
        &mut operation,
        "s2",
        vec![result("b", TargetEffect::Refused)],
    );
    assert_eq!(operation.settle(), Ok(&OperationState::Failed));
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the test is one sequence of scenarios"
)]
fn a_force_step_follows_only_a_settled_graceful_step_that_left_the_target() {
    let plan = seal(application_content(Escalation::ForceAfterGrace));
    let force = step_id("force");
    let intent = |operation: &mut Operation| {
        operation.advance_step(
            &force,
            StepState::IntentCommitted,
            DispatchState::NotSubmitted,
            Durability::Durable,
        )
    };

    // The graceful step is not settled.
    let mut operation = admit(&plan);
    assert_eq!(intent(&mut operation), Err(OperationError::Sequence));
    submit(&mut operation, "graceful");
    assert_eq!(intent(&mut operation), Err(OperationError::Sequence));
    // The application still runs after the grace period: the force step
    // is permitted, and the operation completes with the verified exit.
    settle_step(
        &mut operation,
        "graceful",
        vec![
            Checked::new(TargetResultRecord {
                stop_reason: StopReason::Completed,
                ..record("app", TargetEffect::StillRunning)
            })
            .unwrap(),
        ],
    );
    submit(&mut operation, "force");
    settle_step(
        &mut operation,
        "force",
        vec![result("app", TargetEffect::ExitVerified)],
    );
    assert_eq!(operation.settle(), Ok(&OperationState::Completed));

    // The application exits after the graceful request: no escalation.
    let mut operation = admit(&plan);
    submit(&mut operation, "graceful");
    settle_step(
        &mut operation,
        "graceful",
        vec![result("app", TargetEffect::ExitVerified)],
    );
    assert_eq!(intent(&mut operation), Err(OperationError::Sequence));
    settle_step(
        &mut operation,
        "force",
        vec![result("app", TargetEffect::AlreadyExited)],
    );
    assert_eq!(
        operation.step(&force).unwrap().progress().state(),
        &StepState::NoAction
    );
    assert_eq!(operation.settle(), Ok(&OperationState::Completed));

    // The application was not running at the graceful step: no call and
    // no escalation.
    let mut operation = admit(&plan);
    settle_step(
        &mut operation,
        "graceful",
        vec![result("app", TargetEffect::AlreadyExited)],
    );
    assert_eq!(intent(&mut operation), Err(OperationError::Sequence));
    settle_step(
        &mut operation,
        "force",
        vec![result("app", TargetEffect::AlreadyExited)],
    );
    assert_eq!(operation.settle(), Ok(&OperationState::NoAction));

    // The graceful step was canceled before its call: no force step.
    let mut operation = admit(&plan);
    settle_step(
        &mut operation,
        "graceful",
        vec![result("app", TargetEffect::Skipped)],
    );
    assert_eq!(intent(&mut operation), Err(OperationError::Sequence));

    // The graceful step failed before its call, for example because its
    // intent was not recorded: no force step.
    let mut operation = admit(&plan);
    settle_step(&mut operation, "graceful", vec![failed_skip("app")]);
    assert_eq!(
        operation
            .step(&step_id("graceful"))
            .unwrap()
            .progress()
            .state(),
        &StepState::Failed
    );
    assert_eq!(intent(&mut operation), Err(OperationError::Sequence));
    // A submitted result for the force step needs a consumed dispatch,
    // which needs the sequence check.
    assert!(matches!(
        operation.settle_step(
            &force,
            vec![result("app", TargetEffect::Refused)],
            Durability::Durable
        ),
        Err(OperationError::Transition(TransitionError::Dispatch { .. }))
    ));
    assert_eq!(operation.step(&force).unwrap().results(), []);

    // The backend refused the graceful request and the application still
    // runs: the force step is permitted.
    let mut operation = admit(&plan);
    submit(&mut operation, "graceful");
    settle_step(
        &mut operation,
        "graceful",
        vec![result("app", TargetEffect::Refused)],
    );
    intent(&mut operation).unwrap();

    // The trigger clears during the grace period: the result is
    // `Incomplete`, as in the example of `docs/INTERFACES.md` section 7.
    let mut operation = admit(&plan);
    submit(&mut operation, "graceful");
    settle_step(
        &mut operation,
        "graceful",
        vec![result("app", TargetEffect::StillRunning)],
    );
    let skipped = Checked::new(TargetResultRecord {
        stop_reason: StopReason::TriggerCleared,
        ..record("app", TargetEffect::Skipped)
    })
    .unwrap();
    settle_step(&mut operation, "force", vec![skipped]);
    assert_eq!(operation.settle(), Ok(&OperationState::Incomplete));
    assert_eq!(operation.dispatch(), DispatchState::Submitted);
}

#[test]
fn an_unknown_outcome_blocks_the_next_step_until_reconciliation() {
    let plan = seal(application_content(Escalation::ForceAfterGrace));
    let mut operation = admit(&plan);
    let graceful = step_id("graceful");
    let force = step_id("force");
    for state in [StepState::IntentCommitted, StepState::DispatchConsumed] {
        operation
            .advance_step(
                &graceful,
                state,
                DispatchState::NotSubmitted,
                Durability::Durable,
            )
            .unwrap();
    }
    // A crash after the dispatch consumption.
    settle_step(
        &mut operation,
        "graceful",
        vec![result("app", TargetEffect::UnknownOutcome)],
    );
    let step = operation.step(&graceful).unwrap();
    assert_eq!(step.progress().state(), &StepState::UnknownOutcome);
    assert_eq!(
        step.progress().dispatch(),
        &DispatchState::SubmissionUncertain
    );
    assert_eq!(operation.dispatch(), DispatchState::SubmissionUncertain);
    // No force step while the graceful outcome is unknown.
    assert_eq!(
        operation.advance_step(
            &force,
            StepState::IntentCommitted,
            DispatchState::NotSubmitted,
            Durability::Durable
        ),
        Err(OperationError::Sequence)
    );
    let skipped = Checked::new(TargetResultRecord {
        stop_reason: StopReason::Failed,
        failure: Some(failure(ErrorFamily::Outcome, DispatchState::NotSubmitted)),
        ..record("app", TargetEffect::Skipped)
    })
    .unwrap();
    settle_step(&mut operation, "force", vec![skipped]);
    assert_eq!(operation.settle(), Ok(&OperationState::UnknownOutcome));

    // Reconciliation finds the application absent. The submission stays
    // uncertain, the cause is possible only, and the step settles.
    let mut absent = operation.clone();
    let after_crash = Checked::new(TargetResultRecord {
        dispatch: DispatchState::SubmissionUncertain,
        attribution: Attribution::Possible,
        evidence: EffectEvidence {
            native: NativeResult::Unavailable,
            ..EffectEvidence::none()
        },
        ..record("app", TargetEffect::AlreadyExited)
    })
    .unwrap();
    settle_step(&mut absent, "graceful", vec![after_crash]);
    let step = absent.step(&graceful).unwrap();
    assert_eq!(step.progress().state(), &StepState::Completed);
    assert_eq!(
        step.progress().dispatch(),
        &DispatchState::SubmissionUncertain
    );
    assert_eq!(absent.dispatch(), DispatchState::SubmissionUncertain);

    // Reconciliation proves that no call was submitted. The step and the
    // operation take the settled result.
    let not_submitted = Checked::new(TargetResultRecord {
        stop_reason: StopReason::Failed,
        failure: Some(failure(ErrorFamily::Outcome, DispatchState::NotSubmitted)),
        ..record("app", TargetEffect::Skipped)
    })
    .unwrap();
    settle_step(&mut operation, "graceful", vec![not_submitted]);
    assert_eq!(
        operation.step(&graceful).unwrap().progress().state(),
        &StepState::Failed
    );
    assert_eq!(operation.settle(), Ok(&OperationState::Failed));
    assert_eq!(operation.settle(), Err(OperationError::Settled));
}

#[test]
fn an_operation_round_trips_and_a_state_without_results_is_rejected() {
    let plan = seal(file_content(&ActionClass::DeleteSelectedFiles));
    let mut operation = admit(&plan);
    let value = serde_json::to_value(&operation).unwrap();
    assert_eq!(value["state"], json!("Admitted"));
    assert_eq!(value["operation_id"], json!("operation_1"));
    assert_eq!(value["trigger_class"], json!("manual"));
    assert_eq!(
        value["steps"][0]["progress"],
        json!({ "state": "Admitted", "dispatch": "not_submitted", "durability": "durable" })
    );
    assert_eq!(
        serde_json::from_value::<Operation>(value.clone()).unwrap(),
        operation
    );

    // A written state that no result supports.
    for state in ["Completed", "NoAction", "Failed", "UnknownOutcome"] {
        let mut changed = value.clone();
        changed["state"] = json!(state);
        assert!(
            serde_json::from_value::<Operation>(changed).is_err(),
            "{state}"
        );
    }
    let mut changed = value.clone();
    changed["steps"][0]["progress"]["state"] = json!("NoAction");
    assert!(serde_json::from_value::<Operation>(changed).is_err());
    let mut changed = value.clone();
    changed["steps"] = json!([]);
    assert!(serde_json::from_value::<Operation>(changed).is_err());
    let mut changed = value.clone();
    changed["steps"][1]["step_id"] = json!("s1");
    assert!(serde_json::from_value::<Operation>(changed).is_err());
    let mut changed = value.clone();
    changed["admission_durability"] = json!("persistence_failed");
    assert!(serde_json::from_value::<Operation>(changed).is_err());
    // A filesystem operation has no volatile record.
    let mut changed = value.clone();
    changed["admission_durability"] = json!("volatile");
    for index in 0..2 {
        changed["steps"][index]["progress"]["durability"] = json!("volatile");
    }
    assert!(serde_json::from_value::<Operation>(changed).is_err());
    let mut changed = value.clone();
    changed["steps"][0]["progress"] = json!({
        "state": "DispatchConsumed", "dispatch": "not_submitted", "durability": "volatile"
    });
    assert!(serde_json::from_value::<Operation>(changed).is_err());
    // A result state of the operation with a step that this build cannot
    // read and that has no result.
    let mut changed = value.clone();
    changed["state"] = json!("Completed");
    changed["steps"][0]["progress"]["durability"] = json!("replicated");
    assert!(serde_json::from_value::<Operation>(changed).is_err());

    submit(&mut operation, "s1");
    settle_step(
        &mut operation,
        "s1",
        vec![result("a", TargetEffect::Removed)],
    );
    settle_step(
        &mut operation,
        "s2",
        vec![result("b", TargetEffect::Skipped)],
    );
    operation.settle().unwrap();
    let value = serde_json::to_value(&operation).unwrap();
    assert_eq!(value["state"], json!("Partial"));
    assert_eq!(
        serde_json::from_value::<Operation>(value.clone()).unwrap(),
        operation
    );
    // The same results do not support `Completed`.
    let mut changed = value.clone();
    changed["state"] = json!("Completed");
    assert!(serde_json::from_value::<Operation>(changed).is_err());
    // A result of one step under another step.
    let mut changed = value.clone();
    changed["steps"][1]["results"][0]["target_id"] = json!("a");
    assert!(serde_json::from_value::<Operation>(changed).is_err());

    // A state that this build does not recognize is kept, is not settled,
    // and does not change.
    let mut newer = value;
    newer["state"] = json!("Archived");
    let mut decoded: Operation = serde_json::from_value(newer.clone()).unwrap();
    assert!(!decoded.state().is_recognized());
    assert!(!decoded.state().is_settled());
    assert_eq!(serde_json::to_value(&decoded).unwrap(), newer);
    assert!(decoded.settle().is_err());
    assert_eq!(
        decoded.settle_step(
            &step_id("s2"),
            vec![result("b", TargetEffect::Skipped)],
            Durability::Durable
        ),
        Err(OperationError::Settled)
    );
}

#[test]
fn a_decoded_operation_follows_the_step_sequence_and_the_recording_rule() {
    // A force step that is in progress after a graceful step that
    // completed the target.
    let plan = seal(application_content(Escalation::ForceAfterGrace));
    let mut operation = admit(&plan);
    submit(&mut operation, "graceful");
    settle_step(
        &mut operation,
        "graceful",
        vec![result("app", TargetEffect::ExitVerified)],
    );
    let value = serde_json::to_value(&operation).unwrap();
    assert_eq!(
        serde_json::from_value::<Operation>(value.clone()).unwrap(),
        operation
    );
    for progress in [
        json!({ "state": "IntentCommitted", "dispatch": "not_submitted", "durability": "durable" }),
        json!({ "state": "Verifying", "dispatch": "submitted", "durability": "durable" }),
    ] {
        let mut changed = value.clone();
        changed["steps"][1]["progress"] = progress;
        assert!(serde_json::from_value::<Operation>(changed).is_err());
    }

    // A volatile operation of the critical-memory exception round trips,
    // and the same record with another trigger is rejected.
    let critical = seal(automatic_application_content(
        TriggerClass::GlobalCriticalMemory,
        Escalation::None,
    ));
    let volatile = Operation::admit(
        &critical,
        OperationId::new("operation_1").unwrap(),
        ExecutorEpochId::new("epoch_1").unwrap(),
        Durability::Volatile,
        WallTime::UNIX_EPOCH,
    )
    .unwrap();
    let value = serde_json::to_value(&volatile).unwrap();
    assert_eq!(
        serde_json::from_value::<Operation>(value.clone()).unwrap(),
        volatile
    );
    for trigger in ["manual", "application_budget"] {
        let mut changed = value.clone();
        changed["trigger_class"] = json!(trigger);
        assert!(
            serde_json::from_value::<Operation>(changed).is_err(),
            "{trigger}"
        );
    }
    // A durable admission has no volatile step, and the reverse.
    let mut changed = value.clone();
    changed["admission_durability"] = json!("durable");
    assert!(serde_json::from_value::<Operation>(changed).is_err());
    let mut changed = value;
    changed["steps"][0]["progress"]["durability"] = json!("durable");
    assert!(serde_json::from_value::<Operation>(changed).is_err());
}

// Request envelopes.

fn lease(resource: LeaseResource) -> ResourceLease {
    ResourceLease {
        lease_id: LeaseId::new("lease_1").unwrap(),
        resource,
        owner: OperationId::new("operation_1").unwrap(),
        executor_epoch: ExecutorEpochId::new("epoch_1").unwrap(),
        expires_at: MonotonicNanos::new(5_000),
    }
}

fn file_envelope() -> EnvelopeContent {
    let plan = seal(file_content(&ActionClass::EvictRegenerableData));
    EnvelopeContent {
        schema_version: PLAN_SCHEMA_VERSION,
        action_class: ActionClass::EvictRegenerableData,
        adapter: AdapterId::new("svalnir.expired-temporary").unwrap(),
        correlation: Correlation {
            plan_id: plan.plan_id.clone(),
            plan_digest: plan.digest().clone(),
            operation_id: OperationId::new("operation_1").unwrap(),
            step_id: step_id("s1"),
            parent_operation_id: None,
        },
        principal: plan.principal.clone(),
        executor: plan.executor.clone(),
        authority: plan.authority.clone(),
        trigger: plan.trigger.clone(),
        target: plan.targets[0].clone(),
        evidence: EvidenceBinding {
            clock_domain: ClockDomainId::new("clock_1").unwrap(),
            boot_id: BootId::new("boot_1").unwrap(),
            executor_epoch: ExecutorEpochId::new("epoch_1").unwrap(),
            observed_at: MonotonicNanos::new(1_500),
            valid_until: MonotonicNanos::new(1_600),
        },
        limits: StepLimits {
            reservation: Reservation::Work {
                charge: charge(60, 1),
            },
            deadline: MonotonicNanos::new(4_000),
            grace: None,
            verification_window: Nanoseconds::new(5_000_000_000),
            escalation: Escalation::None,
        },
        leases: vec![lease(LeaseResource::CleanupRoot(
            RootId::new("root_1").unwrap(),
        ))],
        recording: RecordingMode::Durable,
    }
}

fn application_envelope(trigger: TriggerClass, recording: RecordingMode) -> EnvelopeContent {
    let plan = seal(automatic_application_content(trigger, Escalation::None));
    EnvelopeContent {
        action_class: ActionClass::RequestApplicationExit,
        adapter: AdapterId::new("macos.appkit").unwrap(),
        principal: plan.principal.clone(),
        authority: plan.authority.clone(),
        trigger: plan.trigger.clone(),
        target: plan.targets[0].clone(),
        limits: StepLimits {
            reservation: Reservation::ApplicationSlot {
                incident_id: plan.trigger.incident_id.clone(),
            },
            ..file_envelope().limits
        },
        leases: vec![lease(LeaseResource::ProcessGeneration(
            ProcessGenerationId::new("proc_1").unwrap(),
        ))],
        recording,
        ..file_envelope()
    }
}

#[test]
fn an_envelope_round_trips() {
    let critical = application_envelope(
        TriggerClass::GlobalCriticalMemory,
        RecordingMode::VolatileCriticalException,
    );
    for content in [file_envelope(), critical] {
        let envelope: RequestEnvelope = Checked::new(content.clone()).unwrap();
        assert_eq!(*envelope, content);
        let value = serde_json::to_value(&envelope).unwrap();
        assert_eq!(
            serde_json::from_value::<RequestEnvelope>(value).unwrap(),
            envelope
        );
        assert_eq!(envelope.into_inner(), content);
    }
    let value = serde_json::to_value(file_envelope()).unwrap();
    assert_eq!(value["recording"], json!("durable"));
    assert_eq!(
        value["limits"]["reservation"],
        json!({ "kind": "work", "charge": { "work_bytes": "60", "items": "1" } })
    );
    assert_eq!(value["limits"]["deadline"], json!("4000"));
    // Decoding runs the check.
    let mut changed = value;
    changed["recording"] = json!("volatile_critical_exception");
    assert!(serde_json::from_value::<RequestEnvelope>(changed).is_err());
}

#[test]
#[expect(clippy::too_many_lines, reason = "the test is one table of cases")]
fn an_envelope_that_does_not_agree_with_itself_is_rejected() {
    let critical = || {
        application_envelope(
            TriggerClass::GlobalCriticalMemory,
            RecordingMode::VolatileCriticalException,
        )
    };
    let cases: Vec<(EnvelopeError, EnvelopeContent, EnvelopeChange)> = vec![
        (
            EnvelopeError::SchemaVersion,
            file_envelope(),
            Box::new(|e| e.schema_version = 0),
        ),
        (
            EnvelopeError::Unrecognized,
            file_envelope(),
            Box::new(|e| e.action_class = ActionClass::from_wire("EmptyTrash")),
        ),
        (
            EnvelopeError::Unrecognized,
            file_envelope(),
            Box::new(|e| e.recording = RecordingMode::from_wire("best_effort")),
        ),
        // No filesystem mutation has volatile recording.
        (
            EnvelopeError::Recording,
            file_envelope(),
            Box::new(|e| e.recording = RecordingMode::VolatileCriticalException),
        ),
        // The budget trigger has no volatile recording.
        (
            EnvelopeError::Recording,
            application_envelope(
                TriggerClass::ApplicationBudget,
                RecordingMode::VolatileCriticalException,
            ),
            Box::new(|_| {}),
        ),
        // The envelope has its own copy of the target, with the binding
        // rules of the plan.
        (
            EnvelopeError::Unrecognized,
            file_envelope(),
            Box::new(|e| {
                e.target.binding = TargetBinding::File(FileBinding {
                    object_type: FileObjectType::from_wire("socket"),
                    ..file_binding("a", 60)
                });
            }),
        ),
        (
            EnvelopeError::Target,
            file_envelope(),
            Box::new(|e| {
                e.target.binding = TargetBinding::File(FileBinding {
                    owner: Uid::new(0),
                    ..file_binding("a", 60)
                });
            }),
        ),
        (
            EnvelopeError::Target,
            critical(),
            Box::new(|e| {
                e.target.binding = TargetBinding::Application(ApplicationBinding {
                    members: Vec::new(),
                    ..application_binding()
                });
            }),
        ),
        (
            EnvelopeError::Target,
            critical(),
            Box::new(|e| {
                e.target.binding = TargetBinding::Application(ApplicationBinding {
                    members: vec![ProcessIdentity {
                        uid: Uid::new(0),
                        ..member("proc_1", 1)
                    }],
                    ..application_binding()
                });
            }),
        ),
        // The slot is a slot of the incident of the trigger.
        (
            EnvelopeError::Target,
            critical(),
            Box::new(|e| {
                e.limits.reservation = Reservation::ApplicationSlot {
                    incident_id: Some(IncidentId::new("incident_2").unwrap()),
                };
            }),
        ),
        // The trigger identities agree with the trigger class.
        (
            EnvelopeError::Trigger,
            file_envelope(),
            Box::new(|e| e.trigger.incident_id = Some(IncidentId::new("incident_1").unwrap())),
        ),
        (
            EnvelopeError::Trigger,
            critical(),
            Box::new(|e| e.trigger.decision_id = None),
        ),
        // The step agrees with the force strategy and the grace period.
        (
            EnvelopeError::Escalation,
            critical(),
            Box::new(|e| e.action_class = ActionClass::ForceApplicationExit),
        ),
        (
            EnvelopeError::Escalation,
            critical(),
            Box::new(|e| e.limits.escalation = Escalation::ImmediateForce),
        ),
        (
            EnvelopeError::Escalation,
            critical(),
            Box::new(|e| e.limits.escalation = Escalation::ForceAfterGrace),
        ),
        (
            EnvelopeError::Escalation,
            file_envelope(),
            Box::new(|e| e.limits.grace = Some(Nanoseconds::new(1))),
        ),
        // The privilege grant agrees with the executor.
        (
            EnvelopeError::Authority,
            file_envelope(),
            Box::new(|e| e.executor = ExecutorRole::Helper),
        ),
        (
            EnvelopeError::Authority,
            file_envelope(),
            Box::new(|e| e.authority.privilege_grant = Some(privilege_ref())),
        ),
        (
            EnvelopeError::Unrecognized,
            file_envelope(),
            Box::new(|e| e.executor = ExecutorRole::from_wire("root_shell")),
        ),
        // A memory trigger does not select a filesystem class.
        (
            EnvelopeError::Trigger,
            critical(),
            Box::new(|e| e.action_class = ActionClass::EvictRegenerableData),
        ),
        // The class, the target, and the reservation are of one kind.
        (
            EnvelopeError::Target,
            file_envelope(),
            Box::new(|e| e.action_class = ActionClass::RequestApplicationExit),
        ),
        (
            EnvelopeError::Target,
            file_envelope(),
            Box::new(|e| {
                e.limits.reservation = Reservation::ApplicationSlot { incident_id: None };
            }),
        ),
        // The reservation is the full charge of the unit.
        (
            EnvelopeError::Target,
            file_envelope(),
            Box::new(|e| {
                e.limits.reservation = Reservation::Work {
                    charge: charge(59, 1),
                }
            }),
        ),
        (
            EnvelopeError::Target,
            file_envelope(),
            Box::new(|e| {
                e.target.binding = TargetBinding::File(FileBinding {
                    rule: None,
                    ..file_binding("a", 60)
                });
            }),
        ),
        // An automatic slot is a slot of its incident.
        (
            EnvelopeError::Target,
            critical(),
            Box::new(|e| {
                e.limits.reservation = Reservation::ApplicationSlot { incident_id: None };
            }),
        ),
        (
            EnvelopeError::Evidence,
            file_envelope(),
            Box::new(|e| e.evidence.valid_until = e.evidence.observed_at),
        ),
        // The step holds a lease of its own operation and executor
        // lifetime.
        (
            EnvelopeError::Lease,
            file_envelope(),
            Box::new(|e| e.leases.clear()),
        ),
        (
            EnvelopeError::Lease,
            file_envelope(),
            Box::new(|e| e.leases[0].owner = OperationId::new("operation_2").unwrap()),
        ),
        (
            EnvelopeError::Lease,
            file_envelope(),
            Box::new(|e| {
                e.leases[0].executor_epoch = ExecutorEpochId::new("epoch_0").unwrap();
            }),
        ),
    ];
    for (index, (expected, mut content, change)) in cases.into_iter().enumerate() {
        change(&mut content);
        assert_eq!(content.check(), Err(expected), "case {index}");
    }
    // The durable path is permitted for each admitted class.
    let durable_critical =
        application_envelope(TriggerClass::GlobalCriticalMemory, RecordingMode::Durable);
    durable_critical.check().unwrap();
}

// Resource effects.

fn capacity_observation(volume: &str, value: &Value) -> Observation<Bytes> {
    let available = !value.is_null();
    serde_json::from_value(json!({
        "metric_id": "disk.available_bytes",
        "scope": { "kind": "volume", "identity_id": volume },
        "value": value,
        "unit": "byte",
        "kind": "gauge",
        "availability": if available { "available" } else { "unavailable" },
        "reason": if available { Value::Null } else { json!("permission_denied") },
        "coverage": "complete",
        "source": {
            "adapter_id": "macos.statfs",
            "adapter_revision": "1",
            "native_api": "statfs",
            "native_field": "f_bavail * f_bsize",
            "worker_id": "worker_1"
        },
        "sample": {
            "sample_id": "sample_1",
            "clock_domain": "clock_1",
            "boot_id": "boot_1",
            "collector_epoch": "collector_1",
            "started_monotonic_ns": "120000000000",
            "finished_monotonic_ns": "120003000000",
            "captured_at": "2026-11-16T12:00:00.003Z"
        }
    }))
    .unwrap()
}

#[test]
fn a_capacity_change_is_signed_and_is_never_a_guess() {
    let observed = |bytes: &str| capacity_observation("volume_1", &json!(bytes));
    let gain = CapacityEffect::new(observed("1000"), observed("1500"));
    assert_eq!(gain.delta(), Some(ByteDelta::new(500).unwrap()));
    // A negative change is valid.
    let loss = CapacityEffect::new(observed("1500"), observed("1000"));
    assert_eq!(loss.delta(), Some(ByteDelta::new(-500).unwrap()));
    // A completed operation can have no improvement. Zero is a value.
    let none = CapacityEffect::new(observed("1000"), observed("1000"));
    assert_eq!(none.delta(), Some(ByteDelta::ZERO));
    // An observation that is not available gives no change, not zero.
    let unavailable = capacity_observation("volume_1", &Value::Null);
    for effect in [
        CapacityEffect::new(observed("1000"), unavailable.clone()),
        CapacityEffect::new(unavailable.clone(), observed("1000")),
        CapacityEffect::new(unavailable.clone(), unavailable),
    ] {
        assert_eq!(effect.delta(), None);
    }
    // Two scopes have no difference.
    let other = capacity_observation("volume_2", &json!("9000"));
    assert_eq!(CapacityEffect::new(observed("1000"), other).delta(), None);
    assert_eq!(gain.before().value(), Some(&Bytes::new(1_000)));
    assert_eq!(gain.after().value(), Some(&Bytes::new(1_500)));
}

#[test]
fn a_resource_effect_round_trips_and_an_unknown_resource_stays_unknown() {
    let observed = |bytes: &str| capacity_observation("volume_1", &json!(bytes));
    let effect = ResourceEffect::Capacity(CapacityEffect::new(observed("1500"), observed("1000")));
    let value = serde_json::to_value(&effect).unwrap();
    assert_eq!(value["resource"], json!("capacity"));
    assert_eq!(value["delta"], json!("-500"));
    assert_eq!(
        serde_json::from_value::<ResourceEffect>(value.clone()).unwrap(),
        effect
    );
    // A written change that is not the difference of the observations.
    let mut changed = value.clone();
    changed["delta"] = json!("500");
    assert!(serde_json::from_value::<ResourceEffect>(changed).is_err());
    let mut changed = value.clone();
    changed["delta"] = Value::Null;
    assert!(serde_json::from_value::<ResourceEffect>(changed).is_err());

    let unavailable = capacity_observation("volume_1", &Value::Null);
    let unknown = ResourceEffect::Capacity(CapacityEffect::new(observed("1"), unavailable));
    let value = serde_json::to_value(&unknown).unwrap();
    assert_eq!(value["delta"], Value::Null);
    assert_eq!(
        serde_json::from_value::<ResourceEffect>(value).unwrap(),
        unknown
    );

    let newer: ResourceEffect =
        serde_json::from_value(json!({ "resource": "thermal_state", "before": 1 })).unwrap();
    assert_eq!(newer, ResourceEffect::Unrecognized);
}

// Regression tests of the review of Milestone 2.
mod review;
