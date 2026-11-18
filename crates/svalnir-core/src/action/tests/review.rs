//! Regression tests of the review of Milestone 2. Each test fails without
//! the check that it names.

use serde_json::json;

use super::{
    admit, application_binding, application_content, application_envelope,
    automatic_application_content, charge, failure, file_binding, file_content, file_envelope,
    lease, member, record, result, seal, step, step_id, submit, target_id,
};
use crate::action::{
    ActionClass, BudgetScope, Checked, ClientRole, DispatchState, Durability, EnvelopeContent,
    EnvelopeError, ErrorFamily, Escalation, LeaseResource, NativeResult, Operation, OperationError,
    OutcomeError, Plan, PlanContent, PlanError, PlanTarget, RecordingMode, ResourceLease,
    ScopedAllowance, StepState, StopReason, TargetBinding, TargetEffect, TargetResult,
    TargetResultRecord, TriggerClass, WorkAllowance,
};
use crate::id::{ApplicationInstanceId, ExecutorEpochId, OperationId, ProcessGenerationId, RootId};
use crate::process::ProcessAssociation;
use crate::time::WallTime;

fn sealed_error(content: PlanContent) -> PlanError {
    Plan::seal(content).unwrap_err()
}

fn envelope_error(content: EnvelopeContent) -> EnvelopeError {
    Checked::new(content).unwrap_err()
}

/// A volatile operation of the critical-memory exception.
fn volatile_operation() -> Operation {
    let plan = seal(automatic_application_content(
        TriggerClass::GlobalCriticalMemory,
        Escalation::None,
    ));
    Operation::admit(
        &plan,
        OperationId::new("operation_1").unwrap(),
        ExecutorEpochId::new("epoch_1").unwrap(),
        Durability::Volatile,
        WallTime::UNIX_EPOCH,
    )
    .unwrap()
}

#[test]
fn an_admission_durability_that_is_not_recognized_supports_no_volatile_record_and_no_change() {
    // A permanent removal with a volatile step record is rejected, also
    // when this build cannot read the durability of the admission.
    let plan = seal(file_content(&ActionClass::DeleteSelectedFiles));
    let value = serde_json::to_value(admit(&plan)).unwrap();
    let mut changed = value.clone();
    changed["admission_durability"] = json!("replicated");
    changed["steps"][0]["progress"]["durability"] = json!("volatile");
    assert!(serde_json::from_value::<Operation>(changed).is_err());

    // The record with durable steps is kept, and no step of it changes.
    let mut newer = value;
    newer["admission_durability"] = json!("replicated");
    let mut decoded: Operation = serde_json::from_value(newer.clone()).unwrap();
    assert_eq!(serde_json::to_value(&decoded).unwrap(), newer);
    assert_eq!(
        decoded.advance_step(
            &step_id("s1"),
            StepState::IntentCommitted,
            DispatchState::NotSubmitted,
            Durability::Durable,
        ),
        Err(OperationError::Recording)
    );
    assert_eq!(
        decoded.settle_step(
            &step_id("s1"),
            vec![result("a", TargetEffect::Skipped)],
            Durability::Durable,
        ),
        Err(OperationError::Recording)
    );
    assert_eq!(serde_json::to_value(&decoded).unwrap(), newer);

    // The same for an operation of the exception: its volatile steps are
    // kept, and the volatile dispatch consumption is not permitted.
    let mut newer = serde_json::to_value(volatile_operation()).unwrap();
    newer["admission_durability"] = json!("replicated");
    let mut decoded: Operation = serde_json::from_value(newer).unwrap();
    assert_eq!(
        decoded.advance_step(
            &step_id("graceful"),
            StepState::DispatchConsumed,
            DispatchState::NotSubmitted,
            Durability::Volatile,
        ),
        Err(OperationError::Recording)
    );
}

#[test]
fn the_durability_of_a_result_is_one_that_the_admission_permits() {
    let with_durability = |target: &str, effect: TargetEffect, durability: Durability| {
        let record = TargetResultRecord {
            durability,
            ..record(target, effect)
        };
        let result: TargetResult = Checked::new(record).unwrap();
        result
    };

    // A durable filesystem operation has no volatile result.
    let plan = seal(file_content(&ActionClass::DeleteSelectedFiles));
    let mut operation = admit(&plan);
    submit(&mut operation, "s1");
    let before = operation.clone();
    assert_eq!(
        operation.settle_step(
            &step_id("s1"),
            vec![with_durability(
                "a",
                TargetEffect::Removed,
                Durability::Volatile
            )],
            Durability::Durable,
        ),
        Err(OperationError::Recording)
    );
    assert_eq!(operation, before);
    // A result whose write failed is permitted.
    operation
        .settle_step(
            &step_id("s1"),
            vec![with_durability(
                "a",
                TargetEffect::Removed,
                Durability::PersistenceFailed,
            )],
            Durability::PersistenceFailed,
        )
        .unwrap();
    // The decoded record follows the same rule.
    let mut changed = serde_json::to_value(&operation).unwrap();
    assert!(serde_json::from_value::<Operation>(changed.clone()).is_ok());
    changed["steps"][0]["results"][0]["durability"] = json!("volatile");
    assert!(serde_json::from_value::<Operation>(changed).is_err());

    // A volatile operation has no result that is labeled durable.
    let mut volatile = volatile_operation();
    let id = step_id("graceful");
    volatile
        .advance_step(
            &id,
            StepState::DispatchConsumed,
            DispatchState::NotSubmitted,
            Durability::Volatile,
        )
        .unwrap();
    volatile
        .advance_step(
            &id,
            StepState::Verifying,
            DispatchState::Submitted,
            Durability::Volatile,
        )
        .unwrap();
    assert_eq!(
        volatile.settle_step(
            &id,
            vec![with_durability(
                "app",
                TargetEffect::ExitVerified,
                Durability::Durable
            )],
            Durability::Volatile,
        ),
        Err(OperationError::Recording)
    );
    volatile
        .settle_step(
            &id,
            vec![with_durability(
                "app",
                TargetEffect::ExitVerified,
                Durability::Volatile,
            )],
            Durability::Volatile,
        )
        .unwrap();
    let mut changed = serde_json::to_value(&volatile).unwrap();
    assert!(serde_json::from_value::<Operation>(changed.clone()).is_ok());
    changed["steps"][0]["results"][0]["durability"] = json!("durable");
    assert!(serde_json::from_value::<Operation>(changed).is_err());
}

#[test]
fn the_dispatch_state_of_a_decoded_step_is_the_one_of_its_results() {
    let plan = seal(file_content(&ActionClass::DeleteSelectedFiles));
    let mut operation = admit(&plan);
    submit(&mut operation, "s1");
    operation
        .settle_step(
            &step_id("s1"),
            vec![result("a", TargetEffect::Removed)],
            Durability::Durable,
        )
        .unwrap();
    let value = serde_json::to_value(&operation).unwrap();
    assert_eq!(
        value["steps"][0]["progress"]["dispatch"],
        json!("submitted")
    );
    assert!(serde_json::from_value::<Operation>(value.clone()).is_ok());
    // `Completed` accepts an uncertain submission, and the result says
    // that the call was submitted.
    let mut changed = value;
    changed["steps"][0]["progress"]["dispatch"] = json!("submission_uncertain");
    assert!(serde_json::from_value::<Operation>(changed).is_err());
}

#[test]
fn an_error_of_a_submitted_call_does_not_say_that_no_call_was_submitted() {
    // The next step of the error would be the one of its family, and not
    // `reconcile`.
    let refused = TargetResultRecord {
        failure: Some(failure(ErrorFamily::Native, DispatchState::NotSubmitted)),
        ..record("a", TargetEffect::Refused)
    };
    assert_eq!(Checked::new(refused).unwrap_err(), OutcomeError::Failure);
    let uncertain = TargetResultRecord {
        stop_reason: StopReason::Failed,
        failure: Some(failure(ErrorFamily::Outcome, DispatchState::NotSubmitted)),
        ..record("a", TargetEffect::UnknownOutcome)
    };
    assert_eq!(Checked::new(uncertain).unwrap_err(), OutcomeError::Failure);
    // The error can say more than the record of one target.
    for dispatch in [DispatchState::Submitted, DispatchState::SubmissionUncertain] {
        let record = TargetResultRecord {
            stop_reason: StopReason::Failed,
            failure: Some(failure(ErrorFamily::Outcome, dispatch)),
            ..record("a", TargetEffect::UnknownOutcome)
        };
        assert!(Checked::new(record).is_ok());
    }
}

#[test]
fn two_targets_do_not_bind_one_object() {
    // The same entry of one root with two target identities.
    let mut content = file_content(&ActionClass::DeleteSelectedFiles);
    let TargetBinding::File(first) = content.targets[0].binding.clone() else {
        panic!("a file target");
    };
    let TargetBinding::File(second) = &mut content.targets[1].binding else {
        panic!("a file target");
    };
    second.relative_entry = first.relative_entry;
    assert_eq!(sealed_error(content), PlanError::Duplicate);
    // The same entry name in a different root is a different object.
    let mut content = file_content(&ActionClass::DeleteSelectedFiles);
    let entry = first_entry(&content.targets[0]);
    let TargetBinding::File(second) = &mut content.targets[1].binding else {
        panic!("a file target");
    };
    second.relative_entry = entry.clone();
    second.root_id = RootId::new("root_2").unwrap();
    second.root_path = crate::file::LosslessPath::from_bytes("/Users/a/Library/Logs").unwrap();
    second.root_object.inode = crate::file::InodeNumber::new(3);
    assert!(Plan::seal(content).is_ok());
    // A second root identity for the same root object is not a different
    // root: the entry is the same object.
    let mut content = file_content(&ActionClass::DeleteSelectedFiles);
    let TargetBinding::File(second) = &mut content.targets[1].binding else {
        panic!("a file target");
    };
    second.relative_entry = entry;
    second.root_id = RootId::new("root_2").unwrap();
    assert_eq!(sealed_error(content), PlanError::Duplicate);

    // One application instance with two target identities.
    let two_targets = |binding| {
        let mut content = application_content(Escalation::None);
        content.targets.push(PlanTarget {
            target_id: target_id("app_again"),
            binding: TargetBinding::Application(binding),
        });
        content.steps.push(step(
            "graceful_again",
            ActionClass::RequestApplicationExit,
            "app_again",
        ));
        content
    };
    assert_eq!(
        sealed_error(two_targets(application_binding())),
        PlanError::Duplicate
    );
    // One process generation in two instances.
    let other_instance = ApplicationInstanceId::new("app_2").unwrap();
    let in_other = |generation: &str, pid: i32| {
        let mut process = member(generation, pid);
        if let ProcessAssociation::Application { instance_id, .. } = &mut process.association {
            *instance_id = other_instance.clone();
        }
        process
    };
    let mut binding = application_binding();
    binding.instance_id = other_instance.clone();
    binding.members = vec![in_other("proc_1", 4242)];
    assert_eq!(sealed_error(two_targets(binding)), PlanError::Duplicate);
    // Two instances with different processes are two targets.
    let mut binding = application_binding();
    binding.instance_id = other_instance.clone();
    binding.members = vec![in_other("proc_9", 4250)];
    assert!(Plan::seal(two_targets(binding)).is_ok());
}

fn first_entry(target: &PlanTarget) -> crate::file::LosslessPath {
    match &target.binding {
        TargetBinding::File(file) => file.relative_entry.clone(),
        _ => panic!("a file target"),
    }
}

#[test]
fn a_file_target_has_a_charge_of_one_item_or_more() {
    let mut content = file_content(&ActionClass::DeleteSelectedFiles);
    let TargetBinding::File(file) = &mut content.targets[0].binding else {
        panic!("a file target");
    };
    file.charge = charge(60, 0);
    assert_eq!(sealed_error(content), PlanError::Binding);

    let mut envelope = file_envelope();
    let TargetBinding::File(file) = &mut envelope.target.binding else {
        panic!("a file target");
    };
    file.charge = charge(60, 0);
    envelope.limits.reservation = crate::action::Reservation::Work {
        charge: charge(60, 0),
    };
    assert_eq!(envelope_error(envelope), EnvelopeError::Target);
}

#[test]
fn a_lease_of_an_envelope_is_for_the_conflict_domain_of_its_target() {
    let generation =
        |text: &str| LeaseResource::ProcessGeneration(ProcessGenerationId::new(text).unwrap());
    let root = |text: &str| LeaseResource::CleanupRoot(RootId::new(text).unwrap());

    for resource in [root("root_2"), generation("proc_1")] {
        let mut envelope = file_envelope();
        envelope.leases = vec![lease(resource)];
        assert_eq!(envelope_error(envelope), EnvelopeError::Lease);
    }
    // More leases than the one of the root are permitted.
    let mut envelope = file_envelope();
    envelope.leases.push(lease(root("root_2")));
    assert!(Checked::new(envelope).is_ok());

    let critical = || {
        application_envelope(
            TriggerClass::GlobalCriticalMemory,
            RecordingMode::VolatileCriticalException,
        )
    };
    for resource in [root("root_1"), generation("proc_9")] {
        let mut envelope = critical();
        envelope.leases = vec![lease(resource)];
        assert_eq!(envelope_error(envelope), EnvelopeError::Lease);
    }
    // A lease for one member only does not hold the application: a
    // second operation with a lease for the other member would not
    // conflict with this one.
    for member in ["proc_1", "proc_2"] {
        let mut envelope = critical();
        envelope.leases = vec![lease(generation(member))];
        assert_eq!(envelope_error(envelope), EnvelopeError::Lease);
    }
    let mut envelope = critical();
    envelope.leases = vec![lease(generation("proc_1")), lease(generation("proc_2"))];
    assert!(Checked::new(envelope).is_ok());
}

#[test]
fn an_automatic_envelope_repeats_the_trigger_checks_of_its_plan() {
    let automatic =
        || application_envelope(TriggerClass::ApplicationBudget, RecordingMode::Durable);
    assert!(Checked::new(automatic()).is_ok());
    let mut envelope = automatic();
    envelope.principal.role = ClientRole::Cli;
    assert_eq!(envelope_error(envelope), EnvelopeError::Trigger);
    let mut envelope = automatic();
    envelope.authority.action_grants = Vec::new();
    assert_eq!(envelope_error(envelope), EnvelopeError::Authority);
}

#[test]
fn a_lease_and_a_scoped_allowance_reject_a_field_that_this_build_does_not_know() {
    let held = lease(LeaseResource::CleanupRoot(RootId::new("root_1").unwrap()));
    let mut value = serde_json::to_value(&held).unwrap();
    assert_eq!(
        serde_json::from_value::<ResourceLease>(value.clone()).unwrap(),
        held
    );
    value["shared"] = json!(true);
    assert!(serde_json::from_value::<ResourceLease>(value).is_err());

    let scoped = ScopedAllowance {
        scope: BudgetScope::Batch,
        allowance: WorkAllowance::new(charge(100, 10)),
    };
    let mut value = serde_json::to_value(&scoped).unwrap();
    assert_eq!(
        serde_json::from_value::<ScopedAllowance>(value.clone()).unwrap(),
        scoped
    );
    value["soft"] = json!(true);
    assert!(serde_json::from_value::<ScopedAllowance>(value).is_err());
}

// Tests that the review found weak or absent.

#[test]
fn a_target_that_the_fresh_check_skipped_is_not_a_known_failure() {
    use crate::action::{OperationState, aggregate};
    // A skipped target with the stop reason `TARGET_SKIPPED` has an error
    // record, and that record does not make the operation `Failed`.
    let skipped = |target: &str| -> TargetResult {
        Checked::new(TargetResultRecord {
            stop_reason: StopReason::TargetSkipped,
            failure: Some(failure(
                ErrorFamily::Eligibility,
                DispatchState::NotSubmitted,
            )),
            ..record(target, TargetEffect::Skipped)
        })
        .unwrap()
    };
    let cases: [(OperationState, Vec<TargetResult>); 3] = [
        (OperationState::NoAction, vec![skipped("a"), skipped("b")]),
        (
            OperationState::Partial,
            vec![result("a", TargetEffect::Removed), skipped("b")],
        ),
        (
            OperationState::Incomplete,
            vec![result("app", TargetEffect::StillRunning), skipped("app")],
        ),
    ];
    for (expected, results) in cases {
        assert_eq!(aggregate(&results), Ok(expected));
    }
}

#[test]
fn only_the_two_application_classes_have_the_critical_memory_exception() {
    use crate::action::{RecordingRefusal, check_dispatch_recording, critical_exception_applies};
    // The classes are written here, and not read from the predicates of
    // the type: a predicate that puts a filesystem class in the wrong
    // family fails this test.
    let filesystem = [
        ActionClass::MoveToTrash,
        ActionClass::DeleteSelectedFiles,
        ActionClass::EvictRegenerableData,
    ];
    let application = [
        ActionClass::RequestApplicationExit,
        ActionClass::ForceApplicationExit,
    ];
    let critical = TriggerClass::GlobalCriticalMemory;
    let mode = RecordingMode::VolatileCriticalException;
    for class in &filesystem {
        assert!(class.is_filesystem());
        assert!(!class.is_application_intervention());
        assert!(!critical_exception_applies(class, &critical));
        assert_eq!(
            check_dispatch_recording(class, &critical, &mode, &Durability::Volatile),
            Err(RecordingRefusal::DurableRequired)
        );
    }
    for class in &application {
        assert!(!class.is_filesystem());
        assert!(critical_exception_applies(class, &critical));
        assert_eq!(
            check_dispatch_recording(class, &critical, &mode, &Durability::Volatile),
            Ok(())
        );
        for trigger in [TriggerClass::Manual, TriggerClass::ApplicationBudget] {
            assert!(!critical_exception_applies(class, &trigger));
        }
    }
    assert_eq!(filesystem.len() + application.len(), ActionClass::ALL.len());
}

#[test]
fn an_uncertain_submission_does_not_settle_as_a_definite_failure_or_as_no_action() {
    use crate::action::{StepProgress, TransitionError};
    let mut progress = StepProgress::admitted(Durability::Durable).unwrap();
    for (state, dispatch) in [
        (StepState::IntentCommitted, DispatchState::NotSubmitted),
        (StepState::DispatchConsumed, DispatchState::NotSubmitted),
        (
            StepState::UnknownOutcome,
            DispatchState::SubmissionUncertain,
        ),
    ] {
        progress = progress
            .advance(state, dispatch, Durability::Durable)
            .unwrap();
    }
    for state in [StepState::Failed, StepState::NoAction] {
        assert!(matches!(
            progress.advance(
                state,
                DispatchState::SubmissionUncertain,
                Durability::Durable
            ),
            Err(TransitionError::Dispatch { .. })
        ));
    }
    // Reconciliation that proves that no call was submitted gives
    // `NoAction`.
    assert!(
        progress
            .advance(
                StepState::NoAction,
                DispatchState::NotSubmitted,
                Durability::Durable
            )
            .is_ok()
    );
}

#[test]
fn a_covered_member_is_a_submitted_member_result_and_is_not_a_native_call() {
    let covered = |edit: &dyn Fn(&mut TargetResultRecord)| {
        let mut record = record("a", TargetEffect::StillRunning);
        record.member = Some(ProcessGenerationId::new("proc_2").unwrap());
        record.evidence.native = NativeResult::CoveredByApplicationRequest;
        edit(&mut record);
        Checked::new(record).map(|_: TargetResult| ())
    };
    // A helper of an application that got the graceful request: no call
    // was issued for the helper, and the record says so.
    assert_eq!(covered(&|_| {}), Ok(()));
    assert_eq!(
        covered(&|record| {
            record.effect = TargetEffect::ExitVerified;
            record.attribution = crate::action::Attribution::Possible;
            record.stop_reason = StopReason::Completed;
        }),
        Ok(())
    );
    // The value is for one member only, and only for a submitted request.
    assert_eq!(
        covered(&|record| record.member = None),
        Err(OutcomeError::Evidence)
    );
    assert_eq!(
        covered(&|record| {
            record.effect = TargetEffect::UnknownOutcome;
            record.attribution = crate::action::Attribution::Possible;
            record.dispatch = DispatchState::SubmissionUncertain;
        }),
        Err(OutcomeError::Evidence)
    );
    assert_eq!(
        covered(&|record| {
            record.effect = TargetEffect::Skipped;
            record.dispatch = DispatchState::NotSubmitted;
            record.stop_reason = StopReason::Canceled;
        }),
        Err(OutcomeError::Evidence)
    );
    // A file effect has no application request.
    assert_eq!(
        covered(&|record| {
            record.effect = TargetEffect::Removed;
            record.attribution = crate::action::Attribution::Established;
            record.stop_reason = StopReason::Completed;
        }),
        Err(OutcomeError::Evidence)
    );

    // The wire name is stable, and a name that this build does not know is
    // not read as this value or as a call.
    assert_eq!(
        serde_json::to_value(NativeResult::CoveredByApplicationRequest).unwrap(),
        json!({ "kind": "covered_by_application_request" })
    );
    assert_eq!(
        serde_json::from_value::<NativeResult>(json!({ "kind": "covered_by_job_request" }))
            .unwrap(),
        NativeResult::Unrecognized
    );
}

/// Changes the file binding of the first target of an eviction plan and
/// seals the plan.
fn sealed_with(change: impl FnOnce(&mut crate::action::FileBinding)) -> Result<Plan, PlanError> {
    let mut content = file_content(&ActionClass::EvictRegenerableData);
    let TargetBinding::File(file) = &mut content.targets[0].binding else {
        panic!("the first target is a file target");
    };
    change(file);
    Plan::seal(content)
}

#[test]
fn a_rule_target_binds_its_layout_and_a_target_with_no_rule_binds_none() {
    // The layout is in the sealed plan, so the caller of the authorization
    // cannot name the validated layout of a rule for a target of a
    // proposed layout.
    assert_eq!(
        sealed_with(|file| file.layout = None).unwrap_err(),
        PlanError::Binding
    );
    assert_eq!(
        sealed_with(|file| file.layout = Some(String::new())).unwrap_err(),
        PlanError::Binding
    );
    let mut content = file_content(&ActionClass::MoveToTrash);
    content.targets[0].binding = TargetBinding::File(crate::action::FileBinding {
        rule: None,
        ..file_binding("a", 60)
    });
    assert_eq!(sealed_error(content), PlanError::Binding);

    // The envelope of a step has the same rule.
    let mut envelope = file_envelope();
    let TargetBinding::File(file) = &mut envelope.target.binding else {
        panic!("the target is a file target");
    };
    file.layout = None;
    assert_eq!(envelope_error(envelope), EnvelopeError::Target);

    // The digest covers the layout.
    let first = sealed_with(|_| {}).unwrap();
    let other = sealed_with(|file| file.layout = Some("layout-v2".to_owned())).unwrap();
    assert_ne!(first.digest(), other.digest());
}

#[test]
fn a_file_target_binds_the_path_and_the_object_of_its_root() {
    use crate::file::{DeviceNumber, FileObjectEvidence, InodeNumber, LosslessPath};
    let path = |text: &str| LosslessPath::from_bytes(text).unwrap();
    let first = seal(file_content(&ActionClass::EvictRegenerableData));

    // The digest covers the root path and the root object: an approval of
    // the plan is for that place.
    let moved = {
        let mut content = file_content(&ActionClass::EvictRegenerableData);
        for target in &mut content.targets {
            if let TargetBinding::File(file) = &mut target.binding {
                file.root_path = path("/Users/a/Documents");
            }
        }
        seal(content)
    };
    assert_ne!(first.digest(), moved.digest());
    let replaced = {
        let mut content = file_content(&ActionClass::EvictRegenerableData);
        for target in &mut content.targets {
            if let TargetBinding::File(file) = &mut target.binding {
                file.root_object = FileObjectEvidence {
                    device: DeviceNumber::new(16_777_234),
                    inode: InodeNumber::new(3),
                };
            }
        }
        seal(content)
    };
    assert_ne!(first.digest(), replaced.digest());

    // One root identity has one root. The second target keeps the root of
    // the fixture.
    assert_eq!(
        sealed_with(|file| file.root_path = path("/Users/a/Documents")).unwrap_err(),
        PlanError::Binding
    );
    assert_eq!(
        sealed_with(|file| file.root_object.inode = InodeNumber::new(3)).unwrap_err(),
        PlanError::Binding
    );
    // With its own root identity, a target can have its own root.
    sealed_with(|file| {
        file.root_id = RootId::new("root_2").unwrap();
        file.root_path = path("/Users/a/Documents");
    })
    .unwrap();

    // A root path is absolute and has no `.` and no `..` component.
    for text in ["Users/a/Library/Caches", "/Users/a/../b", "/Users/./a"] {
        let mut content = file_content(&ActionClass::EvictRegenerableData);
        for target in &mut content.targets {
            if let TargetBinding::File(file) = &mut target.binding {
                file.root_path = path(text);
            }
        }
        assert_eq!(sealed_error(content), PlanError::Binding, "{text}");
    }
}

#[test]
fn a_plan_of_the_first_schema_version_is_refused_and_no_field_gets_a_default() {
    let plan = seal(file_content(&ActionClass::EvictRegenerableData));
    let value = serde_json::to_value(&plan).unwrap();
    assert_eq!(value["content"]["schema_version"], json!(2));
    assert_eq!(
        value["content"]["targets"][0]["binding"]["layout"],
        json!("layout-v1")
    );

    // The exact form of version 1: no root path, no root object, and no
    // layout. The plan is not decoded.
    let mut first_version = value.clone();
    first_version["content"]["schema_version"] = json!(1);
    for index in 0..2 {
        let object = first_version["content"]["targets"][index]["binding"]
            .as_object_mut()
            .unwrap();
        for key in ["root_path", "root_object", "layout"] {
            assert!(object.remove(key).is_some(), "{key}");
        }
    }
    assert!(serde_json::from_value::<Plan>(first_version.clone()).is_err());
    // The same form with the number of this version is not decoded: a
    // field that is absent does not get a default.
    first_version["content"]["schema_version"] = json!(2);
    assert!(serde_json::from_value::<Plan>(first_version).is_err());

    // Each new key alone, and each key that has no value, must be present.
    for key in ["root_path", "root_object", "layout", "rule", "object"] {
        let mut changed = value.clone();
        changed["content"]["targets"][0]["binding"]
            .as_object_mut()
            .unwrap()
            .remove(key);
        assert!(serde_json::from_value::<Plan>(changed).is_err(), "{key}");
    }

    // The form of this version with the number of version 1 is refused by
    // its number.
    let mut content = file_content(&ActionClass::EvictRegenerableData);
    content.schema_version = 1;
    assert_eq!(sealed_error(content), PlanError::SchemaVersion);
    let mut envelope = file_envelope();
    envelope.schema_version = 1;
    assert!(Checked::new(envelope).is_err());
}

/// A process of the user with no verified membership, with executable
/// evidence.
fn single_process(generation: &str, pid: i32) -> crate::process::ProcessIdentity {
    crate::process::ProcessIdentity {
        executable: Some(crate::process::ExecutableIdentity {
            path: crate::file::LosslessPath::from_bytes("/Users/a/bin/worker").unwrap(),
            file: None,
            code_signature: None,
        }),
        association: ProcessAssociation::Unattributed,
        ..member(generation, pid)
    }
}

/// A manual stop plan of one process with the force strategy `escalation`.
fn process_content(escalation: Escalation) -> PlanContent {
    let mut content = application_content(escalation);
    content.targets[0].binding = TargetBinding::Process(crate::action::ProcessBinding {
        process: single_process("proc_9", 4_299),
    });
    content
}

/// Changes the process of a process plan and seals the plan.
fn sealed_process(
    change: impl FnOnce(&mut crate::process::ProcessIdentity),
) -> Result<Plan, PlanError> {
    let mut content = process_content(Escalation::None);
    let TargetBinding::Process(binding) = &mut content.targets[0].binding else {
        panic!("the target is a process target");
    };
    change(&mut binding.process);
    Plan::seal(content)
}

#[test]
fn a_process_target_is_one_process_of_the_user_in_a_manual_plan() {
    use crate::process::{Pid, Uid};
    for escalation in [
        Escalation::None,
        Escalation::ForceAfterGrace,
        Escalation::ImmediateForce,
    ] {
        seal(process_content(escalation));
    }

    // A guard selects an application or a job instance, never one process.
    let mut automatic = process_content(Escalation::None);
    automatic.trigger = super::automatic(TriggerClass::GlobalCriticalMemory);
    automatic.principal.role = ClientRole::Agent;
    automatic.authority.action_grants = vec![super::grant_ref()];
    assert_eq!(sealed_error(automatic), PlanError::Trigger);

    // The protections of a member apply to the one process.
    let binding =
        |change: &dyn Fn(&mut crate::process::ProcessIdentity)| sealed_process(change).unwrap_err();
    // A process of another user, a process of root, and `launchd`.
    assert_eq!(
        binding(&|process| process.uid = Uid::new(502)),
        PlanError::Binding
    );
    assert_eq!(
        binding(&|process| process.pid = Pid::new(1).unwrap()),
        PlanError::Binding
    );
    let mut root = process_content(Escalation::None);
    root.principal.uid = Uid::new(0);
    if let TargetBinding::Process(binding) = &mut root.targets[0].binding {
        binding.process.uid = Uid::new(0);
    }
    assert_eq!(sealed_error(root), PlanError::Binding);
    // No executable evidence: an executor cannot revalidate the identity.
    assert_eq!(
        binding(&|process| process.executable = None),
        PlanError::Binding
    );
    // A member of an application is a target through its instance only.
    assert_eq!(
        binding(&|process| process.association = member("proc_9", 4_299).association),
        PlanError::Binding
    );
    // The process-control surface has the user executor only.
    let mut helper = process_content(Escalation::None);
    helper.executor = crate::action::ExecutorRole::Helper;
    helper.authority.privilege_grant = Some(super::privilege_ref());
    assert_eq!(sealed_error(helper), PlanError::Binding);

    // The steps agree with the force strategy, as for an application.
    let mut content = process_content(Escalation::None);
    content.steps = vec![step("force", ActionClass::ForceApplicationExit, "app")];
    assert_eq!(sealed_error(content), PlanError::Steps);
    // A process target has no filesystem step.
    let mut content = process_content(Escalation::None);
    content.steps = vec![step("s1", ActionClass::MoveToTrash, "app")];
    assert!(Plan::seal(content).is_err());
}

#[test]
fn one_process_generation_is_one_target() {
    let two_targets = |second: TargetBinding| {
        let mut content = process_content(Escalation::None);
        content.targets.push(PlanTarget {
            target_id: target_id("other"),
            binding: second,
        });
        content.steps.push(step(
            "graceful_2",
            ActionClass::RequestApplicationExit,
            "other",
        ));
        Plan::seal(content)
    };
    let process = |generation: &str, pid: i32| {
        TargetBinding::Process(crate::action::ProcessBinding {
            process: single_process(generation, pid),
        })
    };
    two_targets(process("proc_8", 4_298)).unwrap();
    // The same generation two times.
    assert_eq!(
        two_targets(process("proc_9", 4_299)).unwrap_err(),
        PlanError::Duplicate
    );
    // The same generation as a member of an application target.
    let mut application = application_binding();
    application.members[0].generation_id = ProcessGenerationId::new("proc_9").unwrap();
    assert_eq!(
        two_targets(TargetBinding::Application(application)).unwrap_err(),
        PlanError::Duplicate
    );
}

#[test]
fn a_process_binding_has_its_own_kind_and_is_not_read_as_an_application() {
    let plan = seal(process_content(Escalation::None));
    let value = serde_json::to_value(&plan).unwrap();
    assert_eq!(
        value["content"]["targets"][0]["binding"]["kind"],
        json!("process")
    );
    assert_eq!(serde_json::from_value::<Plan>(value.clone()).unwrap(), plan);
    // The content of a process binding under each other kind is not a
    // plan: a build that does not know the kind refuses it.
    for kind in ["application", "file", "job"] {
        let mut changed = value.clone();
        changed["content"]["targets"][0]["binding"]["kind"] = json!(kind);
        assert!(serde_json::from_value::<Plan>(changed).is_err(), "{kind}");
    }
    // A member list is not a part of the binding.
    let mut changed = value;
    changed["content"]["targets"][0]["binding"]["members"] = json!([]);
    assert!(serde_json::from_value::<Plan>(changed).is_err());
}

#[test]
fn the_hard_protections_of_the_catalog_apply_to_a_process_target() {
    use crate::policy::{ControlPlaneProcess, ProtectionContext, ProtectionFact};
    let control_plane = [ControlPlaneProcess {
        pid: crate::process::Pid::new(700).unwrap(),
        start_time: member("x", 700).start_time,
    }];
    let context = ProtectionContext {
        principal: crate::process::Uid::new(501),
        control_plane: Some(&control_plane),
    };
    let protection = |change: &dyn Fn(&mut crate::process::ProcessIdentity)| {
        let mut process = single_process("proc_9", 4_299);
        change(&mut process);
        crate::action::ProcessBinding { process }.hard_protection(&context)
    };
    assert_eq!(protection(&|_| {}), ProtectionFact::NotProtected);
    // A process of the operating system, a process of the control plane,
    // and a process that claims a protected bundle identifier.
    assert_eq!(
        protection(&|process| {
            process.executable.as_mut().unwrap().path =
                crate::file::LosslessPath::from_bytes("/usr/libexec/worker").unwrap();
        }),
        ProtectionFact::Protected
    );
    assert_eq!(
        protection(&|process| process.pid = crate::process::Pid::new(700).unwrap()),
        ProtectionFact::Protected
    );
    assert_eq!(
        protection(&|process| {
            process.association = ProcessAssociation::Application {
                instance_id: ApplicationInstanceId::new("app_9").unwrap(),
                bundle_identifier: "com.apple.finder".to_owned(),
                attribution: crate::process::AttributionMethod::from_wire("name_match"),
            };
        }),
        ProtectionFact::Protected
    );
    assert_eq!(
        protection(&|process| process.uid = crate::process::Uid::new(502)),
        ProtectionFact::Protected
    );
    // With no known control plane, the protection is not known.
    let unknown = ProtectionContext {
        principal: crate::process::Uid::new(501),
        control_plane: None,
    };
    let binding = crate::action::ProcessBinding {
        process: single_process("proc_9", 4_299),
    };
    assert_eq!(binding.hard_protection(&unknown), ProtectionFact::Unknown);
}

#[test]
fn the_envelope_of_a_process_step_repeats_the_checks_of_its_plan() {
    let plan = seal(process_content(Escalation::None));
    let envelope = || EnvelopeContent {
        principal: plan.principal.clone(),
        authority: plan.authority.clone(),
        trigger: plan.trigger.clone(),
        target: plan.targets[0].clone(),
        leases: vec![lease(LeaseResource::ProcessGeneration(
            ProcessGenerationId::new("proc_9").unwrap(),
        ))],
        limits: crate::action::StepLimits {
            reservation: crate::action::Reservation::ApplicationSlot { incident_id: None },
            ..application_envelope(TriggerClass::GlobalCriticalMemory, RecordingMode::Durable)
                .limits
        },
        ..application_envelope(TriggerClass::GlobalCriticalMemory, RecordingMode::Durable)
    };
    Checked::new(envelope()).unwrap();

    // The lease is for the generation of the process.
    let mut other_lease = envelope();
    other_lease.leases = vec![lease(LeaseResource::ProcessGeneration(
        ProcessGenerationId::new("proc_1").unwrap(),
    ))];
    assert_eq!(envelope_error(other_lease), EnvelopeError::Lease);
    // The binding rules of the plan apply to the copy of the target.
    let mut other_user = envelope();
    if let TargetBinding::Process(binding) = &mut other_user.target.binding {
        binding.process.uid = crate::process::Uid::new(502);
    }
    assert_eq!(envelope_error(other_user), EnvelopeError::Target);
    // An automatic step has no process target.
    let mut automatic = envelope();
    automatic.trigger = super::automatic(TriggerClass::GlobalCriticalMemory);
    automatic.principal.role = ClientRole::Agent;
    automatic.authority.action_grants = vec![super::grant_ref()];
    automatic.limits.reservation = crate::action::Reservation::ApplicationSlot {
        incident_id: automatic.trigger.incident_id.clone(),
    };
    assert_eq!(envelope_error(automatic), EnvelopeError::Trigger);
    // A work reservation is for a file target.
    let mut work = envelope();
    work.limits.reservation = crate::action::Reservation::Work {
        charge: charge(1, 1),
    };
    assert_eq!(envelope_error(work), EnvelopeError::Target);
}
