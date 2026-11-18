//! Regression tests of the review of Milestone 2. Each test fails without
//! the check that it names.

use serde_json::json;

use super::{
    admit, application_binding, application_content, application_envelope,
    automatic_application_content, charge, failure, file_content, file_envelope, lease, member,
    record, result, seal, step, step_id, submit, target_id,
};
use crate::action::{
    ActionClass, BudgetScope, Checked, ClientRole, DispatchState, Durability, EnvelopeContent,
    EnvelopeError, ErrorFamily, Escalation, LeaseResource, NativeResult, Operation, OperationError,
    OutcomeError, PlanContent, PlanError, PlanTarget, RecordingMode, ResourceLease,
    ScopedAllowance, StepState, StopReason, TargetBinding, TargetEffect, TargetResult,
    TargetResultRecord, TriggerClass, WorkAllowance,
};
use crate::id::{ApplicationInstanceId, ExecutorEpochId, OperationId, ProcessGenerationId, RootId};
use crate::process::ProcessAssociation;
use crate::time::WallTime;

fn sealed_error(content: PlanContent) -> PlanError {
    crate::action::Plan::seal(content).unwrap_err()
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
    second.relative_entry = entry;
    second.root_id = RootId::new("root_2").unwrap();
    assert!(crate::action::Plan::seal(content).is_ok());

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
    assert!(crate::action::Plan::seal(two_targets(binding)).is_ok());
}

fn first_entry(target: &PlanTarget) -> crate::file::LosslessPath {
    match &target.binding {
        TargetBinding::File(file) => file.relative_entry.clone(),
        TargetBinding::Application(_) => panic!("a file target"),
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
    let mut envelope = critical();
    envelope.leases = vec![lease(generation("proc_2"))];
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
