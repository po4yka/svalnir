//! Journal failures at each point of a step, and the restart after a
//! crash at each of those points.

use svalnir_core::action::{
    ActionClass, Attribution, DispatchState, Durability, ErrorFamily, Escalation, Journal as _,
    OperationState, StepState, StopReason, TargetEffect,
};

use super::super::{FileProbe, Phase, code};
use super::support::{
    Bench, FailPoint, NativeCall, admitted, cleanup_plan, open_journal, run, stop_plan,
    stored_request,
};

/// A bench with the files `a` and `b` and an admitted permanent-removal
/// plan for them.
fn admitted_cleanup() -> (
    Bench,
    Box<super::support::TestCoordinator>,
    svalnir_core::id::OperationId,
) {
    let mut bench = Bench::new();
    bench.tree.file("a");
    bench.tree.file("b");
    let plan = cleanup_plan(
        "plan_1",
        &bench.tree,
        &ActionClass::DeleteSelectedFiles,
        &["a", "b"],
        bench.clock.now(),
    );
    bench.store(&plan);
    let mut coordinator = bench.start();
    let operation_id = admitted(&mut coordinator, stored_request(&plan));
    (bench, coordinator, operation_id)
}

fn exists(bench: &Bench, name: &str) -> bool {
    bench.tree.root.join(name).exists()
}

#[test]
fn a_journal_that_fails_before_the_intent_runs_no_filesystem_step() {
    let (bench, mut coordinator, operation_id) = admitted_cleanup();
    bench.fail(FailPoint::CommitIntent);
    bench.fail(FailPoint::RecordStep);
    bench.fail(FailPoint::RecordOperation);
    let view = run(&mut coordinator, &bench.clock, &operation_id);
    // Fail closed: no call was issued.
    assert!(exists(&bench, "a") && exists(&bench, "b"));
    assert_eq!(view.operation.state(), &OperationState::Failed);
    assert_eq!(view.operation.dispatch(), DispatchState::NotSubmitted);
    assert!(view.degraded_recording);
    for step in view.operation.steps() {
        let result = &step.results()[0];
        assert_eq!(result.effect, TargetEffect::Skipped);
        let failure = result.failure.as_ref().unwrap();
        assert_eq!(failure.code.as_str(), code::INTENT_NOT_RECORDED);
        assert_eq!(failure.family, ErrorFamily::Recording);
        assert_eq!(step.progress().durability(), &Durability::PersistenceFailed);
    }
    // The journal does not have the result, and the coordinator does not
    // release its registration while a record is not saved.
    let stored = coordinator
        .journal()
        .inner
        .try_operation(&operation_id)
        .unwrap()
        .unwrap();
    assert_eq!(stored.state(), &OperationState::Admitted);
    // When the journal works again, the record is written.
    bench.heal();
    coordinator.step();
    let stored = coordinator
        .journal()
        .inner
        .try_operation(&operation_id)
        .unwrap()
        .unwrap();
    assert_eq!(stored.state(), &OperationState::Failed);
    assert!(coordinator.shutdown().is_ok());
}

#[test]
fn a_journal_that_fails_between_the_intent_and_the_dispatch_runs_no_step() {
    let (bench, mut coordinator, operation_id) = admitted_cleanup();
    bench.fail(FailPoint::ConsumeDispatch);
    let view = run(&mut coordinator, &bench.clock, &operation_id);
    assert!(exists(&bench, "a") && exists(&bench, "b"));
    assert_eq!(bench.intents(), 1);
    assert_eq!(view.operation.state(), &OperationState::Failed);
    let first = &view.operation.steps()[0];
    assert_eq!(first.progress().state(), &StepState::Failed);
    assert_eq!(
        first.results()[0].failure.as_ref().unwrap().code.as_str(),
        code::DISPATCH_NOT_RECORDED
    );
    // The journal took the result: only the consumption failed.
    let stored = coordinator
        .journal()
        .inner
        .try_operation(&operation_id)
        .unwrap()
        .unwrap();
    assert_eq!(stored, view.operation);
}

#[test]
fn a_journal_that_fails_after_the_dispatch_keeps_the_result_and_runs_no_further_step() {
    let (bench, mut coordinator, operation_id) = admitted_cleanup();
    // The call of the first step is issued, and its result is not saved.
    bench.fail(FailPoint::RecordStep);
    bench.fail(FailPoint::RecordOperation);
    let view = run(&mut coordinator, &bench.clock, &operation_id);
    assert!(!exists(&bench, "a"));
    // The second step does not run with a journal that does not record.
    assert!(exists(&bench, "b"));
    assert_eq!(bench.intents(), 1);
    assert_eq!(view.operation.state(), &OperationState::Partial);
    let steps = view.operation.steps();
    // The removal is not rewritten as not done.
    assert_eq!(steps[0].results()[0].effect, TargetEffect::Removed);
    assert_eq!(
        steps[0].progress().durability(),
        &Durability::PersistenceFailed
    );
    assert_eq!(steps[1].results()[0].effect, TargetEffect::Skipped);
    assert!(view.degraded_recording);
    bench.heal();
    coordinator.step();
    let stored = coordinator
        .journal()
        .inner
        .try_operation(&operation_id)
        .unwrap()
        .unwrap();
    assert_eq!(stored.state(), &OperationState::Partial);
    assert_eq!(stored.steps()[0].results()[0].effect, TargetEffect::Removed);
}

#[test]
fn a_crash_before_the_intent_is_reconciled_with_no_dispatch() {
    let (mut bench, coordinator, operation_id) = admitted_cleanup();
    // The process stops with the operation admitted.
    drop(coordinator);
    let mut coordinator = bench.start();
    assert!(coordinator.reconciliation_pending());
    assert!(
        !coordinator
            .coordination_start()
            .predecessor
            .as_ref()
            .unwrap()
            .released
    );
    coordinator.step();
    assert!(!coordinator.reconciliation_pending());
    let view = coordinator.operation(&operation_id).unwrap().unwrap();
    assert_eq!(view.phase, Phase::Finished);
    assert_eq!(view.operation.state(), &OperationState::Failed);
    for step in view.operation.steps() {
        let failure = step.results()[0].failure.as_ref().unwrap();
        assert_eq!(failure.code.as_str(), code::EXECUTOR_RESTARTED);
        assert_eq!(step.progress().dispatch(), &DispatchState::NotSubmitted);
    }
    // The stale execution is invalid: nothing was dispatched.
    assert!(exists(&bench, "a") && exists(&bench, "b"));
    assert_eq!(bench.intents(), 0);
    assert_eq!(
        coordinator
            .journal()
            .inner
            .unsettled_operation_count()
            .unwrap(),
        0
    );
}

#[test]
fn a_crash_between_the_intent_and_the_dispatch_is_reconciled_with_no_dispatch() {
    let (mut bench, mut coordinator, operation_id) = admitted_cleanup();
    for point in [
        FailPoint::ConsumeDispatch,
        FailPoint::RecordStep,
        FailPoint::RecordOperation,
    ] {
        bench.fail(point);
    }
    coordinator.step();
    drop(coordinator);
    bench.heal();
    let stored = open_journal(&bench.tree.database)
        .operation(&operation_id)
        .unwrap()
        .unwrap();
    assert_eq!(
        stored.steps()[0].progress().state(),
        &StepState::IntentCommitted
    );
    let mut coordinator = bench.start();
    coordinator.step();
    let view = coordinator.operation(&operation_id).unwrap().unwrap();
    assert_eq!(view.operation.state(), &OperationState::Failed);
    // The intent is not evidence that the execution is necessary now.
    assert!(exists(&bench, "a") && exists(&bench, "b"));
    assert_eq!(bench.intents(), 1);
}

#[test]
fn a_crash_after_a_consumed_dispatch_is_unknown_and_is_never_replayed() {
    let (mut bench, mut coordinator, operation_id) = admitted_cleanup();
    bench.fail(FailPoint::RecordStep);
    bench.fail(FailPoint::RecordOperation);
    coordinator.step();
    drop(coordinator);
    bench.heal();
    // The call removed the entry, and the journal has no outcome.
    assert!(!exists(&bench, "a"));
    let stored = open_journal(&bench.tree.database)
        .operation(&operation_id)
        .unwrap()
        .unwrap();
    assert_eq!(
        stored.steps()[0].progress().state(),
        &StepState::DispatchConsumed
    );

    let mut coordinator = bench.start();
    coordinator.step();
    let view = coordinator.operation(&operation_id).unwrap().unwrap();
    let first = &view.operation.steps()[0];
    // The entry is absent now. Who removed it is not established.
    assert_eq!(first.results()[0].effect, TargetEffect::AlreadyAbsent);
    assert_eq!(first.results()[0].attribution, Attribution::Possible);
    assert_eq!(
        first.progress().dispatch(),
        &DispatchState::SubmissionUncertain
    );
    assert_eq!(first.progress().state(), &StepState::Completed);
    // The step that did not start is not run by the new lifetime.
    assert!(exists(&bench, "b"));
    assert_eq!(bench.intents(), 1);
    // No effect is verified as an effect of the operation, and the
    // restart prevented the second step: the aggregate is `Failed`, with
    // a dispatch that stays uncertain.
    assert_eq!(view.operation.state(), &OperationState::Failed);
    assert_eq!(
        view.operation.dispatch(),
        DispatchState::SubmissionUncertain
    );
    // The plan is consumed: a repeated apply returns this operation.
    let plan = open_journal(&bench.tree.database)
        .plan(view.operation.plan_id())
        .unwrap()
        .unwrap();
    let outcome = coordinator.apply(stored_request(&plan));
    assert!(matches!(
        outcome,
        super::super::ApplyOutcome::Existing { .. }
    ));
    assert!(exists(&bench, "b"));
}

#[test]
fn a_result_that_the_state_machine_refuses_records_the_step_as_unknown() {
    let (mut bench, mut coordinator, operation_id) = admitted_cleanup();
    bench.fail(FailPoint::RecordStep);
    bench.fail(FailPoint::RecordOperation);
    coordinator.step();
    drop(coordinator);
    bench.heal();
    assert!(!exists(&bench, "a"));
    // The evidence gives a result that the state machine refuses for the
    // consumed step: a submitted call with no `Verifying` record.
    bench.fail(FailPoint::RecoveryAsSubmitted);
    let mut coordinator = bench.start();
    coordinator.step();
    // Not settled, inspected: the reconciliation is complete, and the
    // consumed step is not left with no outcome.
    assert!(!coordinator.reconciliation_pending());
    let stored = open_journal(&bench.tree.database)
        .operation(&operation_id)
        .unwrap()
        .unwrap();
    let first = &stored.steps()[0];
    assert_eq!(first.progress().state(), &StepState::UnknownOutcome);
    assert_eq!(
        first.progress().dispatch(),
        &DispatchState::SubmissionUncertain
    );
    assert_eq!(first.results()[0].effect, TargetEffect::UnknownOutcome);
    assert_eq!(
        first.results()[0].failure.as_ref().unwrap().code.as_str(),
        code::EFFECT_NOT_ESTABLISHED
    );
    // The step that did not start is not run.
    assert!(exists(&bench, "b"));
    assert_eq!(bench.intents(), 1);
}

#[test]
fn a_consumed_dispatch_with_no_evidence_stays_unknown() {
    for probe in [
        FileProbe::PlannedObject,
        FileProbe::OtherObject,
        FileProbe::Unknown,
    ] {
        let (mut bench, mut coordinator, operation_id) = admitted_cleanup();
        bench.fail(FailPoint::RecordStep);
        bench.fail(FailPoint::RecordOperation);
        coordinator.step();
        drop(coordinator);
        bench.heal();
        // A replacement at the name of the entry is a different target.
        let replacement = bench.tree.file("a");
        *bench.host.file_probe.lock().unwrap() = Some(probe);
        let mut coordinator = bench.start();
        coordinator.step();
        assert!(!coordinator.reconciliation_pending());
        let view = coordinator.operation(&operation_id).unwrap().unwrap();
        assert_eq!(
            view.operation.state(),
            &OperationState::UnknownOutcome,
            "{probe:?}"
        );
        let first = &view.operation.steps()[0];
        assert_eq!(first.progress().state(), &StepState::UnknownOutcome);
        assert_eq!(first.results()[0].effect, TargetEffect::UnknownOutcome);
        assert_eq!(
            first.results()[0].failure.as_ref().unwrap().family,
            ErrorFamily::Outcome
        );
        // The replacement is not removed to complete the old record.
        assert!(replacement.exists());
        assert_eq!(bench.intents(), 1);
        // The operation stays unsettled, and a later restart reads it
        // again with fresh evidence.
        drop(coordinator);
        *bench.host.file_probe.lock().unwrap() = Some(FileProbe::Absent);
        let mut coordinator = bench.start();
        coordinator.step();
        let view = coordinator.operation(&operation_id).unwrap().unwrap();
        assert_eq!(view.operation.state(), &OperationState::Failed);
        assert_eq!(
            view.operation.steps()[0].results()[0].effect,
            TargetEffect::AlreadyAbsent
        );
        assert!(replacement.exists());
    }
}

/// Submits the graceful request of a force-after-grace plan and stops
/// the process of the coordinator during the grace period.
fn crash_during_grace() -> (Bench, svalnir_core::id::OperationId) {
    let mut bench = Bench::new();
    let member = bench.host.spawn(4242);
    let plan = stop_plan(
        "plan_1",
        vec![member],
        Escalation::ForceAfterGrace,
        bench.clock.now(),
    );
    bench.store(&plan);
    let mut coordinator = bench.start();
    let operation_id = admitted(&mut coordinator, stored_request(&plan));
    coordinator.step();
    assert_eq!(bench.host.calls().len(), 1);
    drop(coordinator);
    (bench, operation_id)
}

#[test]
fn a_restart_during_a_grace_period_does_not_force_the_target() {
    let (mut bench, operation_id) = crash_during_grace();
    bench.clock.advance(60 * super::support::SECOND);
    let mut coordinator = bench.start();
    coordinator.step();
    let view = coordinator.operation(&operation_id).unwrap().unwrap();
    // The request was submitted and the target runs. The new lifetime
    // sends no force signal for the old operation.
    assert_eq!(bench.host.calls().len(), 1);
    assert!(bench.host.world().processes.contains_key(&4242));
    let steps = view.operation.steps();
    assert_eq!(steps[0].results()[0].effect, TargetEffect::StillRunning);
    assert_eq!(steps[0].progress().state(), &StepState::Incomplete);
    assert_eq!(steps[1].results()[0].effect, TargetEffect::Skipped);
    assert_eq!(steps[1].results()[0].stop_reason, StopReason::Failed);
    assert_eq!(view.operation.state(), &OperationState::Failed);
    assert_eq!(view.operation.dispatch(), DispatchState::Submitted);
}

#[test]
fn a_restart_finds_the_target_gone_or_replaced_and_signals_nothing() {
    for replaced in [false, true] {
        let (mut bench, operation_id) = crash_during_grace();
        if replaced {
            // The PID has a new process: a different target.
            bench.host.world().processes.insert(4242, 2_000);
        } else {
            bench.host.world().processes.remove(&4242);
        }
        let mut coordinator = bench.start();
        coordinator.step();
        let view = coordinator.operation(&operation_id).unwrap().unwrap();
        assert_eq!(view.operation.state(), &OperationState::Completed);
        let steps = view.operation.steps();
        assert_eq!(steps[0].results()[0].effect, TargetEffect::AlreadyExited);
        // The exit is established. Its cause is not.
        assert_eq!(steps[0].results()[0].attribution, Attribution::Possible);
        assert_eq!(steps[1].results()[0].effect, TargetEffect::AlreadyExited);
        assert_eq!(steps[1].results()[0].dispatch, DispatchState::NotSubmitted);
        let signals: Vec<NativeCall> = bench.host.calls();
        assert_eq!(signals.len(), 1, "no signal after the restart");
        assert_eq!(bench.host.world().processes.contains_key(&4242), replaced);
    }
}

#[test]
fn a_restart_reconciles_a_target_of_one_process_from_the_reading_of_its_generation() {
    for (exited, effect, state) in [
        (true, TargetEffect::AlreadyExited, OperationState::Completed),
        // A graceful request that the process did not follow is not a
        // failure.
        (
            false,
            TargetEffect::StillRunning,
            OperationState::Incomplete,
        ),
    ] {
        let mut bench = Bench::new();
        let process = bench.host.spawn(4242);
        let plan = super::support::process_stop_plan(
            "plan_1",
            process.clone(),
            Escalation::None,
            bench.clock.now(),
        );
        bench.store(&plan);
        let mut coordinator = bench.start();
        let operation_id = admitted(&mut coordinator, stored_request(&plan));
        coordinator.step();
        assert_eq!(bench.host.calls().len(), 1);
        // The process of the coordinator stops in the observation.
        drop(coordinator);
        if exited {
            bench.host.world().processes.remove(&4242);
        }
        let mut coordinator = bench.start();
        coordinator.step();
        let view = coordinator.operation(&operation_id).unwrap().unwrap();
        let [result] = view.operation.steps()[0].results() else {
            panic!("a process target has one result");
        };
        assert_eq!(result.effect, effect);
        assert_eq!(result.member.as_ref(), Some(&process.generation_id));
        assert_eq!(view.operation.state(), &state);
        // The new lifetime sends no signal for the old operation.
        assert_eq!(bench.host.calls().len(), 1);
    }
}

#[test]
fn a_clean_stop_releases_the_registration_and_needs_no_reconciliation() {
    let (mut bench, mut coordinator, operation_id) = admitted_cleanup();
    // An operation that is not settled keeps the registration.
    let Err((returned, _)) = coordinator.shutdown() else {
        panic!("the coordinator stopped with an admitted operation");
    };
    coordinator = returned;
    run(&mut coordinator, &bench.clock, &operation_id);
    assert!(coordinator.shutdown().is_ok());
    let coordinator = bench.start();
    assert!(!coordinator.reconciliation_pending());
    assert!(
        coordinator
            .coordination_start()
            .predecessor
            .as_ref()
            .unwrap()
            .released
    );
}
