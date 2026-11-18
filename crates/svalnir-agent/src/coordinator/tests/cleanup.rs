//! Manual cleanup operations: the Trash mode and the permanent mode.

use svalnir_core::action::{
    ActionClass, DispatchState, Durability, OperationState, ResourceEffect, StepState, TargetEffect,
};
use svalnir_core::quantity::{ByteDelta, EntryCount};

use super::super::{OperationView, Phase};
use super::support::{Bench, TrashMode, admitted, cleanup_plan, run, stored_request};

fn capacity_delta(view: &OperationView) -> Option<ByteDelta> {
    match view.resource_effects.as_slice() {
        [ResourceEffect::Capacity(effect)] => effect.delta(),
        other => panic!("the operation has no single capacity effect: {other:?}"),
    }
}

#[test]
fn a_permanent_cleanup_removes_each_target_and_reports_the_measured_capacity() {
    let mut bench = Bench::new();
    let files = [
        bench.tree.file("a"),
        bench.tree.file("b"),
        bench.tree.file("c"),
    ];
    bench.measurements.0.lock().unwrap().capacity = [Some(1_000), Some(1_000), Some(1_400)].into();
    let plan = cleanup_plan(
        "plan_1",
        &bench.tree,
        &ActionClass::DeleteSelectedFiles,
        &["a", "b", "c"],
        bench.clock.now(),
    );
    bench.store(&plan);
    let mut coordinator = bench.start();
    let operation_id = admitted(&mut coordinator, stored_request(&plan));
    let view = run(&mut coordinator, &bench.clock, &operation_id);

    assert_eq!(view.phase, Phase::Finished);
    assert_eq!(view.operation.state(), &OperationState::Completed);
    assert!(files.iter().all(|file| !file.exists()));
    for step in view.operation.steps() {
        assert_eq!(step.progress().state(), &StepState::Completed);
        assert_eq!(step.progress().dispatch(), &DispatchState::Submitted);
        assert_eq!(step.progress().durability(), &Durability::Durable);
        assert_eq!(step.results()[0].effect, TargetEffect::Removed);
    }
    // The work of the calls and the measured change are separate facts.
    assert_eq!(view.work.removed_entries, EntryCount::new(3));
    assert_eq!(capacity_delta(&view), Some(ByteDelta::new(400).unwrap()));
    assert!(!view.degraded_recording);
    // The journal has the same settled operation.
    let stored = coordinator
        .journal()
        .inner
        .try_operation(&operation_id)
        .unwrap()
        .unwrap();
    assert_eq!(stored, view.operation);
    assert!(coordinator.shutdown().is_ok());
}

#[test]
fn a_trash_cleanup_moves_each_target_and_reports_no_reclaimed_capacity() {
    let mut bench = Bench::new();
    let file = bench.tree.file("a");
    // The capacity does not change: a move to Trash reclaims nothing.
    bench.measurements.0.lock().unwrap().capacity = [Some(1_000)].into();
    let plan = cleanup_plan(
        "plan_1",
        &bench.tree,
        &ActionClass::MoveToTrash,
        &["a"],
        bench.clock.now(),
    );
    bench.store(&plan);
    let mut coordinator = bench.start();
    let operation_id = admitted(&mut coordinator, stored_request(&plan));
    let view = run(&mut coordinator, &bench.clock, &operation_id);

    assert_eq!(view.operation.state(), &OperationState::Completed);
    assert!(!file.exists());
    assert!(bench.tree.trash.join("a").exists());
    assert_eq!(
        view.operation.steps()[0].results()[0].effect,
        TargetEffect::Trashed
    );
    assert_eq!(view.work.trashed_entries, EntryCount::new(1));
    assert_eq!(view.work.removed_entries, EntryCount::ZERO);
    assert_eq!(capacity_delta(&view), Some(ByteDelta::ZERO));
}

#[test]
fn a_failed_trash_move_is_never_a_permanent_removal() {
    let mut bench = Bench::with(false, TrashMode::Fail);
    let file = bench.tree.file("a");
    let plan = cleanup_plan(
        "plan_1",
        &bench.tree,
        &ActionClass::MoveToTrash,
        &["a"],
        bench.clock.now(),
    );
    bench.store(&plan);
    let mut coordinator = bench.start();
    let operation_id = admitted(&mut coordinator, stored_request(&plan));
    let view = run(&mut coordinator, &bench.clock, &operation_id);

    assert!(file.exists());
    assert_eq!(view.operation.state(), &OperationState::Failed);
    assert_eq!(
        view.operation.steps()[0].results()[0].effect,
        TargetEffect::Refused
    );
}

#[test]
fn a_removal_with_no_capacity_change_reports_the_removal_and_no_improvement() {
    let mut bench = Bench::new();
    let file = bench.tree.file("a");
    // The measurement after the removal is not available.
    bench.measurements.0.lock().unwrap().capacity = [Some(1_000), None].into();
    let plan = cleanup_plan(
        "plan_1",
        &bench.tree,
        &ActionClass::DeleteSelectedFiles,
        &["a"],
        bench.clock.now(),
    );
    bench.store(&plan);
    let mut coordinator = bench.start();
    let operation_id = admitted(&mut coordinator, stored_request(&plan));
    let view = run(&mut coordinator, &bench.clock, &operation_id);

    assert!(!file.exists());
    assert_eq!(view.operation.state(), &OperationState::Completed);
    // An unavailable measurement gives no change. It does not give zero.
    assert_eq!(capacity_delta(&view), None);
}

#[test]
fn a_target_that_was_replaced_after_the_plan_is_skipped_and_the_others_run() {
    let mut bench = Bench::new();
    let replaced = bench.tree.file("a");
    let kept = bench.tree.file("b");
    let plan = cleanup_plan(
        "plan_1",
        &bench.tree,
        &ActionClass::DeleteSelectedFiles,
        &["a", "b"],
        bench.clock.now(),
    );
    bench.store(&plan);
    // A different object takes the name of the first target.
    std::fs::remove_file(&replaced).unwrap();
    std::fs::create_dir(&replaced).unwrap();
    std::fs::write(replaced.join("new"), b"new").unwrap();
    let mut coordinator = bench.start();
    let operation_id = admitted(&mut coordinator, stored_request(&plan));
    let view = run(&mut coordinator, &bench.clock, &operation_id);
    // The replacement and its new entry are outside the operation.
    assert!(replaced.join("new").exists());
    assert!(!kept.exists());
    assert_eq!(view.operation.state(), &OperationState::Partial);
    let first = &view.operation.steps()[0];
    assert_eq!(first.progress().state(), &StepState::NoAction);
    assert_eq!(first.results()[0].effect, TargetEffect::Skipped);
    assert_eq!(first.results()[0].dispatch, DispatchState::NotSubmitted);
    assert!(first.results()[0].failure.is_some());
    assert_eq!(view.work.removed_entries, EntryCount::new(1));
}

/// A filesystem executor that reports a fault after calls that removed
/// entries.
#[derive(Debug)]
struct FaultAfterWork;

impl super::super::FilesystemExecutor for FaultAfterWork {
    fn execute(
        &self,
        _roots: &crate::executor::fs::ApprovedRoots,
        _step: crate::executor::fs::AdmittedStep<'_>,
        _stop: &dyn crate::executor::fs::StopSignal,
    ) -> crate::executor::fs::StepOutcome {
        use svalnir_core::quantity::Bytes;

        Err(crate::executor::fs::ExecutionFault {
            target_id: svalnir_core::id::TargetId::new("plan_1_target_a").unwrap(),
            dispatch: DispatchState::Submitted,
            reason: crate::executor::fs::FaultReason::Record(
                svalnir_core::action::OutcomeError::Evidence,
            ),
            work: crate::executor::fs::ProcessedWork {
                removed_entries: EntryCount::new(3),
                removed_logical_bytes: Bytes::new(30),
                removed_allocated_bytes: Bytes::new(4096),
                exact: true,
                ..crate::executor::fs::ProcessedWork::default()
            },
            trash_item: None,
        })
    }
}

#[test]
fn the_work_of_a_target_whose_executor_reported_a_fault_stays_in_the_totals() {
    let mut bench = Bench::new();
    bench.tree.file("a");
    let plan = cleanup_plan(
        "plan_1",
        &bench.tree,
        &ActionClass::DeleteSelectedFiles,
        &["a"],
        bench.clock.now(),
    );
    bench.store(&plan);
    let started = bench.start_with(|dependencies, _| {
        dependencies.filesystem = Box::new(FaultAfterWork);
    });
    let super::super::Start::Coordinating(mut coordinator) = started else {
        panic!("a different coordinator holds the lock");
    };
    let operation_id = admitted(&mut coordinator, stored_request(&plan));
    let view = run(&mut coordinator, &bench.clock, &operation_id);
    // The effect of the target is not known, and the entries that the
    // calls removed before the fault are counted.
    let result = &view.operation.steps()[0].results()[0];
    assert_eq!(result.effect, TargetEffect::UnknownOutcome);
    assert_eq!(result.dispatch, DispatchState::Submitted);
    assert_eq!(view.work.removed_entries, EntryCount::new(3));
    assert_eq!(
        view.work.removed_logical_bytes,
        svalnir_core::quantity::Bytes::new(30)
    );
    assert_eq!(view.operation.state(), &OperationState::UnknownOutcome);
}
