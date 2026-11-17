//! Tests of the operation journal. Each test uses a database in its own
//! temporary directory. No test changes a file outside that directory, and
//! no test signals a process.

mod coordination;
mod durable;
mod failure;
mod volatile;

use std::path::PathBuf;
use std::time::Duration;

use svalnir_core::action::{
    ActionClass, ActionError, ActionStage, ApplicationBinding, Attribution, Checked, ClientRole,
    Correlation, DispatchState, Durability, EffectEvidence, EnvelopeContent, ErrorCode,
    ErrorFamily, Escalation, EvidenceBinding, ExecutorRole, FileBinding, FileObjectType, Journal,
    LeaseResource, NativeResult, Operation, PLAN_SCHEMA_VERSION, Plan, PlanApproval, PlanContent,
    PlanLimits, PlanTarget, PlannedStep, Principal, RecordingMode, RequestEnvelope, Reservation,
    ResourceLease, StepLimits, StepState, StopReason, TargetBinding, TargetEffect, TargetResult,
    TargetResultRecord, Trigger, TriggerClass, Validity, WorkCharge,
};
use svalnir_core::authority::{ActionGrantRef, AuthorityBinding, Generation};
use svalnir_core::file::{DeviceNumber, FileObjectEvidence, InodeNumber, LosslessPath};
use svalnir_core::id::{
    ActionGrantId, AdapterId, ApplicationInstanceId, BootId, ClockDomainId, DecisionId,
    ExecutorEpochId, IncidentId, LeaseId, MembershipSnapshotId, MountId, OperationId, PlanId,
    PolicyRevisionId, ProcessGenerationId, RootId, RuleId, RuleRevisionId, StepId, TargetId,
    VolumeId,
};
use svalnir_core::process::{
    AttributionMethod, Pid, ProcessAssociation, ProcessIdentity, ProcessStartTime, Uid,
};
use svalnir_core::quantity::{Bytes, EntryCount, Nanoseconds};
use svalnir_core::rule::RuleRef;
use svalnir_core::time::{MonotonicNanos, WallTime};
use tempfile::TempDir;

use super::{JournalOptions, OperationJournal};

/// The wall-clock time of the fixtures, in Unix seconds.
const NOW: i64 = 1_794_830_400;

/// A journal in a new temporary directory. The directory is removed when
/// the value is dropped.
struct Fixture {
    directory: TempDir,
}

impl Fixture {
    fn new() -> Self {
        Self {
            directory: tempfile::tempdir().unwrap(),
        }
    }

    fn path(&self) -> PathBuf {
        self.directory.path().join("operations.sqlite")
    }

    fn open(&self) -> OperationJournal {
        self.open_with(&options())
    }

    fn open_with(&self, options: &JournalOptions) -> OperationJournal {
        OperationJournal::open(&self.path(), options).unwrap()
    }
}

/// The options of the tests: a short busy timeout, and no `F_FULLFSYNC`,
/// which is slow and which no test here can verify.
fn options() -> JournalOptions {
    JournalOptions {
        busy_timeout: Duration::from_millis(50),
        full_fsync: false,
        ..JournalOptions::default()
    }
}

fn wall(offset: i64) -> WallTime {
    WallTime::from_unix(NOW + offset, 0).unwrap()
}

fn epoch(text: &str) -> ExecutorEpochId {
    ExecutorEpochId::new(text).unwrap()
}

fn operation_id(text: &str) -> OperationId {
    OperationId::new(text).unwrap()
}

fn step_id(text: &str) -> StepId {
    StepId::new(text).unwrap()
}

fn target_id(text: &str) -> TargetId {
    TargetId::new(text).unwrap()
}

fn charge(bytes: u64, items: u64) -> WorkCharge {
    WorkCharge::new(Bytes::new(bytes), EntryCount::new(items))
}

fn principal() -> Principal {
    Principal {
        uid: Uid::new(501),
        session: None,
        role: ClientRole::Cli,
    }
}

fn other_principal() -> Principal {
    Principal {
        role: ClientRole::Gui,
        ..principal()
    }
}

fn file_target(id: &str) -> PlanTarget {
    PlanTarget {
        target_id: target_id(id),
        binding: TargetBinding::File(FileBinding {
            root_id: RootId::new("root_1").unwrap(),
            relative_entry: LosslessPath::from_bytes(id).unwrap(),
            volume_id: VolumeId::new("volume_1").unwrap(),
            mount_id: MountId::new("mount_1").unwrap(),
            object_type: FileObjectType::RegularFile,
            owner: Uid::new(501),
            object: Some(FileObjectEvidence {
                device: DeviceNumber::new(16_777_234),
                inode: InodeNumber::new(991),
            }),
            rule: Some(RuleRef {
                id: RuleId::new("svalnir.expired-temporary").unwrap(),
                revision: RuleRevisionId::new("r1").unwrap(),
            }),
            charge: charge(10, 1),
        }),
    }
}

fn validity() -> Validity {
    Validity {
        clock_domain: ClockDomainId::new("clock_1").unwrap(),
        boot_id: BootId::new("boot_1").unwrap(),
        created_at: MonotonicNanos::new(1_000),
        expires_at: MonotonicNanos::new(2_000),
        created_wall: wall(0),
    }
}

/// A manual eviction plan with `count` targets `t0`, `t1`, and so on, and
/// one step `s0`, `s1`, and so on for each target.
fn file_content(plan: &str, count: u64) -> PlanContent {
    PlanContent {
        schema_version: PLAN_SCHEMA_VERSION,
        plan_id: PlanId::new(plan).unwrap(),
        principal: principal(),
        trigger: Trigger::manual(),
        authority: AuthorityBinding {
            policy_revision: PolicyRevisionId::new("policy_1").unwrap(),
            action_grants: Vec::new(),
            privilege_grant: None,
        },
        executor: ExecutorRole::User,
        targets: (0..count)
            .map(|index| file_target(&format!("t{index}")))
            .collect(),
        steps: (0..count)
            .map(|index| PlannedStep {
                step_id: step_id(&format!("s{index}")),
                action_class: ActionClass::EvictRegenerableData,
                target_id: target_id(&format!("t{index}")),
            })
            .collect(),
        limits: PlanLimits {
            work: Some(charge(10 * count, count)),
            execution_deadline: Nanoseconds::new(30_000_000_000),
            grace: None,
            verification_window: Nanoseconds::new(5_000_000_000),
            escalation: Escalation::None,
        },
        validity: validity(),
    }
}

fn file_plan(plan: &str, count: u64) -> Plan {
    Plan::seal(file_content(plan, count)).unwrap()
}

fn incident() -> IncidentId {
    IncidentId::new("incident_1").unwrap()
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

/// An automatic application plan of the agent with the trigger `class` and
/// the force strategy `escalation`. The target is `app`, and the steps are
/// `graceful`, `force`, or the two.
fn application_plan(plan: &str, class: TriggerClass, escalation: Escalation) -> Plan {
    use ActionClass::{ForceApplicationExit, RequestApplicationExit};
    let planned = |id: &str, action_class: ActionClass| PlannedStep {
        step_id: step_id(id),
        action_class,
        target_id: target_id("app"),
    };
    let steps = match escalation {
        Escalation::ForceAfterGrace => vec![
            planned("graceful", RequestApplicationExit),
            planned("force", ForceApplicationExit),
        ],
        Escalation::ImmediateForce => vec![planned("force", ForceApplicationExit)],
        _ => vec![planned("graceful", RequestApplicationExit)],
    };
    let grace = matches!(escalation, Escalation::ForceAfterGrace)
        .then_some(Nanoseconds::new(10_000_000_000));
    let base = file_content(plan, 1);
    Plan::seal(PlanContent {
        principal: Principal {
            role: ClientRole::Agent,
            ..principal()
        },
        trigger: Trigger {
            class,
            incident_id: Some(incident()),
            decision_id: Some(DecisionId::new("decision_1").unwrap()),
        },
        authority: AuthorityBinding {
            action_grants: vec![ActionGrantRef {
                grant_id: ActionGrantId::new("grant_1").unwrap(),
                generation: Generation::new(1),
            }],
            ..base.authority.clone()
        },
        targets: vec![PlanTarget {
            target_id: target_id("app"),
            binding: TargetBinding::Application(ApplicationBinding {
                instance_id: ApplicationInstanceId::new("app_1").unwrap(),
                membership: MembershipSnapshotId::new("members_1").unwrap(),
                members: vec![member("proc_1", 4242)],
            }),
        }],
        steps,
        limits: PlanLimits {
            work: None,
            grace,
            escalation,
            ..base.limits.clone()
        },
        ..base
    })
    .unwrap()
}

fn approval(plan: &Plan) -> PlanApproval {
    PlanApproval {
        plan_id: plan.plan_id.clone(),
        digest: plan.digest().clone(),
    }
}

fn new_operation(plan: &Plan, id: &str, epoch_text: &str, durability: Durability) -> Operation {
    Operation::admit(
        plan,
        operation_id(id),
        epoch(epoch_text),
        durability,
        wall(1),
    )
    .unwrap()
}

/// Records `plan` and admits a durable operation for it.
fn admit(journal: &mut OperationJournal, plan: &Plan, id: &str, epoch_text: &str) -> Operation {
    let operation = new_operation(plan, id, epoch_text, Durability::Durable);
    journal.record_plan(plan).unwrap();
    let admission = journal
        .admit(&approval(plan), &plan.principal, &operation)
        .unwrap();
    assert_eq!(admission, svalnir_core::action::Admission::Admitted);
    operation
}

/// The request envelope of the step `step` of `operation`.
fn envelope(plan: &Plan, operation: &Operation, step: &str) -> RequestEnvelope {
    Checked::new(envelope_content(plan, operation, step)).unwrap()
}

fn envelope_content(plan: &Plan, operation: &Operation, step: &str) -> EnvelopeContent {
    let planned = plan
        .steps
        .iter()
        .find(|planned| planned.step_id == step_id(step))
        .unwrap();
    let target = plan.target(&planned.target_id).unwrap().clone();
    let is_application = planned.action_class.is_application_intervention();
    let lease = |resource: LeaseResource| ResourceLease {
        lease_id: LeaseId::new("lease_1").unwrap(),
        resource,
        owner: operation.operation_id().clone(),
        executor_epoch: operation.executor_epoch().clone(),
        expires_at: MonotonicNanos::new(5_000),
    };
    let (reservation, resource, adapter, recording) = match &target.binding {
        TargetBinding::File(file) => (
            Reservation::Work {
                charge: file.charge,
            },
            LeaseResource::CleanupRoot(file.root_id.clone()),
            "svalnir.expired-temporary",
            RecordingMode::Durable,
        ),
        TargetBinding::Application(application) => (
            Reservation::ApplicationSlot {
                incident_id: plan.trigger.incident_id.clone(),
            },
            LeaseResource::ProcessGeneration(application.members[0].generation_id.clone()),
            "macos.appkit",
            if matches!(plan.trigger.class, TriggerClass::GlobalCriticalMemory) {
                RecordingMode::VolatileCriticalException
            } else {
                RecordingMode::Durable
            },
        ),
    };
    EnvelopeContent {
        schema_version: PLAN_SCHEMA_VERSION,
        action_class: planned.action_class.clone(),
        adapter: AdapterId::new(adapter).unwrap(),
        correlation: Correlation {
            plan_id: plan.plan_id.clone(),
            plan_digest: plan.digest().clone(),
            operation_id: operation.operation_id().clone(),
            step_id: planned.step_id.clone(),
            parent_operation_id: None,
        },
        principal: plan.principal.clone(),
        executor: plan.executor.clone(),
        authority: plan.authority.clone(),
        trigger: plan.trigger.clone(),
        target,
        evidence: EvidenceBinding {
            clock_domain: ClockDomainId::new("clock_1").unwrap(),
            boot_id: BootId::new("boot_1").unwrap(),
            executor_epoch: operation.executor_epoch().clone(),
            observed_at: MonotonicNanos::new(1_500),
            valid_until: MonotonicNanos::new(1_600),
        },
        limits: StepLimits {
            reservation,
            deadline: MonotonicNanos::new(4_000),
            grace: if is_application {
                plan.limits.grace
            } else {
                None
            },
            verification_window: Nanoseconds::new(5_000_000_000),
            escalation: plan.limits.escalation.clone(),
        },
        leases: vec![lease(resource)],
        recording,
    }
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

/// A target result of `effect` with the usual values of that effect.
fn result(target: &str, effect: TargetEffect, durability: Durability) -> TargetResult {
    use DispatchState::{NotSubmitted, SubmissionUncertain, Submitted};
    let (dispatch, native, attribution, stop_reason, error) = match effect {
        TargetEffect::Trashed | TargetEffect::Removed | TargetEffect::ExitVerified => (
            Submitted,
            NativeResult::Succeeded,
            Attribution::Established,
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
    Checked::new(TargetResultRecord {
        target_id: target_id(target),
        member: None,
        dispatch,
        effect,
        evidence: EffectEvidence {
            native,
            ..EffectEvidence::none()
        },
        attribution,
        durability,
        stop_reason,
        failure: error,
    })
    .unwrap()
}

/// Brings the step `step` of the journal and of `operation` to
/// `DispatchConsumed` on the durable path.
fn dispatch(journal: &mut OperationJournal, plan: &Plan, operation: &mut Operation, step: &str) {
    let id = step_id(step);
    journal
        .commit_intent(&envelope(plan, operation, step))
        .unwrap();
    operation
        .advance_step(
            &id,
            StepState::IntentCommitted,
            DispatchState::NotSubmitted,
            Durability::Durable,
        )
        .unwrap();
    let receipt = journal
        .consume_dispatch(operation.operation_id(), &id)
        .unwrap();
    assert_eq!(
        receipt.consumption,
        svalnir_core::action::DispatchConsumption::Consumed
    );
    assert_eq!(receipt.durability, Durability::Durable);
    operation
        .advance_step(
            &id,
            StepState::DispatchConsumed,
            DispatchState::NotSubmitted,
            Durability::Durable,
        )
        .unwrap();
}

/// Records the submission and the removal of the step `step`, which is
/// `DispatchConsumed`.
fn complete(journal: &mut OperationJournal, operation: &mut Operation, step: &str, target: &str) {
    let id = step_id(step);
    operation
        .advance_step(
            &id,
            StepState::Verifying,
            DispatchState::Submitted,
            Durability::Durable,
        )
        .unwrap();
    journal
        .record_step(operation.operation_id(), operation.step(&id).unwrap())
        .unwrap();
    operation
        .settle_step(
            &id,
            vec![result(target, TargetEffect::Removed, Durability::Durable)],
            Durability::Durable,
        )
        .unwrap();
    journal
        .record_step(operation.operation_id(), operation.step(&id).unwrap())
        .unwrap();
}
