//! Manual cleanup operations: the Trash mode and the permanent mode.

use svalnir_core::action::{
    ActionClass, DispatchState, Durability, Journal as _, OperationState, ResourceEffect,
    StepState, TargetEffect,
};
use svalnir_core::quantity::{ByteDelta, EntryCount};

use super::super::{OperationView, Phase};
use super::support::{Bench, TrashMode, admitted, cleanup_plan, open_journal, run, stored_request};

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

        Err(Box::new(crate::executor::fs::ExecutionFault {
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
        }))
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

#[test]
fn a_manual_operation_acts_under_the_roots_that_its_sealed_plan_binds() {
    let mut bench = Bench::new();
    let file = bench.tree.file("a");
    let plan = cleanup_plan(
        "plan_1",
        &bench.tree,
        &ActionClass::DeleteSelectedFiles,
        &["a"],
        bench.clock.now(),
    );
    bench.store(&plan);
    // A coordinator that did not build the plan has no root of its own:
    // an agent that takes the request from the queue, or a client that
    // executes the request of a different client.
    let started = bench.start_with(|dependencies, _| {
        dependencies.roots = crate::executor::fs::ApprovedRoots::default();
    });
    let super::super::Start::Coordinating(mut coordinator) = started else {
        panic!("a different coordinator holds the lock");
    };
    let operation_id = admitted(&mut coordinator, stored_request(&plan));
    let view = run(&mut coordinator, &bench.clock, &operation_id);
    // The target is not refused as outside the approved roots.
    assert_eq!(view.operation.state(), &OperationState::Completed);
    assert_eq!(
        view.operation.steps()[0].results()[0].effect,
        TargetEffect::Removed
    );
    assert!(!file.exists());
}

#[test]
fn a_root_record_of_the_process_that_is_not_the_root_of_the_plan_stops_the_target() {
    use svalnir_core::file::LosslessPath;

    let mut bench = Bench::new();
    let file = bench.tree.file("a");
    let plan = cleanup_plan(
        "plan_1",
        &bench.tree,
        &ActionClass::DeleteSelectedFiles,
        &["a"],
        bench.clock.now(),
    );
    bench.store(&plan);
    // The process has a record with the root identity of the plan and a
    // different directory. The record of the process is used, so the
    // executor finds the disagreement.
    let other = bench.tree.root.join("elsewhere");
    std::fs::create_dir(&other).unwrap();
    let mut record = bench
        .tree
        .roots()
        .root(&root_id_of(&plan))
        .cloned()
        .unwrap();
    record.path = LosslessPath::from_path(&other).unwrap();
    record.object = super::support::object_of(&other);
    let configured = crate::executor::fs::ApprovedRoots::new(vec![record]).unwrap();
    let started = bench.start_with(|dependencies, _| dependencies.roots = configured);
    let super::super::Start::Coordinating(mut coordinator) = started else {
        panic!("a different coordinator holds the lock");
    };
    let operation_id = admitted(&mut coordinator, stored_request(&plan));
    let view = run(&mut coordinator, &bench.clock, &operation_id);
    let result = &view.operation.steps()[0].results()[0];
    assert_eq!(result.effect, TargetEffect::Skipped);
    assert_eq!(
        result.failure.as_ref().map(|error| error.code.as_str()),
        Some("approved_root_mismatch")
    );
    assert!(file.exists());
}

fn root_id_of(plan: &svalnir_core::action::Plan) -> svalnir_core::id::RootId {
    let svalnir_core::action::TargetBinding::File(file) = &plan.targets[0].binding else {
        panic!("the plan has no file target");
    };
    file.root_id.clone()
}

#[test]
fn an_automatic_plan_gets_no_root_from_its_own_content() {
    use svalnir_core::action::{ClientRole, Plan, TargetBinding, Trigger, TriggerClass};
    use svalnir_core::id::{DecisionId, RuleId, RuleRevisionId};
    use svalnir_core::rule::RuleRef;

    use super::super::approved_roots_of;
    use super::support::{cleanup_content, incident_id};

    let bench = Bench::new();
    bench.tree.file("a");
    let mut content = cleanup_content(
        "plan_1",
        &bench.tree,
        &ActionClass::EvictRegenerableData,
        &["a"],
        bench.clock.now(),
    );
    for target in &mut content.targets {
        let TargetBinding::File(file) = &mut target.binding else {
            panic!("the plan has no file target");
        };
        file.rule = Some(RuleRef {
            id: RuleId::new("svalnir.expired-temporary").unwrap(),
            revision: RuleRevisionId::new("r1").unwrap(),
        });
        file.layout = Some("layout-v1".to_owned());
    }
    let manual = Plan::seal(content.clone()).unwrap();
    content.trigger = Trigger {
        class: TriggerClass::DiskPressure,
        incident_id: Some(incident_id("incident_1")),
        decision_id: Some(DecisionId::new("decision_1").unwrap()),
        budget_generation: Some(svalnir_core::authority::Generation::new(1)),
    };
    content.principal.role = ClientRole::Agent;
    content.authority.action_grants = vec![bench.authority.memory_grant()];
    let automatic = Plan::seal(content).unwrap();

    let none = crate::executor::fs::ApprovedRoots::default();
    // The manual plan: the root that its target binds.
    let roots = approved_roots_of(&manual, &none).unwrap();
    assert_eq!(roots.len(), 1);
    assert!(roots.root(&root_id_of(&manual)).is_some());
    // The automatic plan: only the roots of the process, here none.
    assert!(approved_roots_of(&automatic, &none).unwrap().is_empty());
    let configured = bench.tree.roots();
    assert_eq!(approved_roots_of(&automatic, &configured).unwrap().len(), 1);
}

#[test]
fn the_recovery_probe_reads_below_the_root_of_the_plan_and_not_below_a_different_record() {
    use svalnir_core::action::TargetBinding;
    use svalnir_core::file::LosslessPath;

    use super::super::{FileProbe, SystemProbe, TargetProbe as _};
    use crate::executor::fs::ApprovedRoots;
    use crate::platform::process::DarwinProcessSource;

    let bench = Bench::new();
    let file = bench.tree.file("a");
    let target = TargetBinding::File(bench.tree.binding("a"));
    // A process with no root record of its own reads below the root that
    // the sealed plan binds.
    let probe = SystemProbe::new(ApprovedRoots::default(), DarwinProcessSource::new());
    assert_eq!(probe.file(&target), FileProbe::PlannedObject);
    // A record with the root identity of the plan and a different
    // directory gives no conclusion, also when that directory has no
    // entry with the name.
    let other = bench.tree.root.join("elsewhere");
    std::fs::create_dir(&other).unwrap();
    let mut record = bench
        .tree
        .roots()
        .root(&root_id_of_binding(&target))
        .cloned()
        .unwrap();
    record.path = LosslessPath::from_path(&other).unwrap();
    record.object = super::support::object_of(&other);
    let different = SystemProbe::new(
        ApprovedRoots::new(vec![record]).unwrap(),
        DarwinProcessSource::new(),
    );
    assert_eq!(different.file(&target), FileProbe::Unknown);
    // The record of the root of the plan gives the same reading as no
    // record.
    let same = SystemProbe::new(bench.tree.roots(), DarwinProcessSource::new());
    assert_eq!(same.file(&target), FileProbe::PlannedObject);
    std::fs::remove_file(&file).unwrap();
    assert_eq!(probe.file(&target), FileProbe::Absent);
    assert_eq!(same.file(&target), FileProbe::Absent);
    assert_eq!(different.file(&target), FileProbe::Unknown);
}

fn root_id_of_binding(target: &svalnir_core::action::TargetBinding) -> svalnir_core::id::RootId {
    let svalnir_core::action::TargetBinding::File(file) = target else {
        panic!("the target is not a file target");
    };
    file.root_id.clone()
}

#[test]
fn the_capacity_observations_of_an_operation_are_in_the_journal_for_each_client() {
    let mut bench = Bench::new();
    bench.tree.file("a");
    bench.measurements.0.lock().unwrap().capacity = [Some(1_000), Some(1_400)].into();
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
    assert_eq!(capacity_delta(&view), ByteDelta::new(400).ok());
    assert!(!view.degraded_recording);
    // A different process reads the same observations from the journal.
    let client = open_journal(&bench.tree.database);
    assert_eq!(
        client.resource_effects(&operation_id).unwrap(),
        view.resource_effects
    );
    // A coordinator of a later lifetime gives them in its view.
    drop(coordinator.shutdown().unwrap());
    let later = bench.start();
    let stored = later.operation(&operation_id).unwrap().unwrap();
    assert_eq!(stored.resource_effects, view.resource_effects);
}

#[test]
fn observations_that_the_journal_did_not_take_do_not_change_the_outcome() {
    let mut bench = Bench::new();
    let file = bench.tree.file("a");
    let plan = cleanup_plan(
        "plan_1",
        &bench.tree,
        &ActionClass::DeleteSelectedFiles,
        &["a"],
        bench.clock.now(),
    );
    bench.store(&plan);
    let mut coordinator = bench.start();
    bench.fail(super::support::FailPoint::RecordEffects);
    let operation_id = admitted(&mut coordinator, stored_request(&plan));
    let view = run(&mut coordinator, &bench.clock, &operation_id);
    // The operation is settled with its result, and the recording is
    // reported as degraded.
    assert_eq!(view.operation.state(), &OperationState::Completed);
    assert!(!file.exists());
    assert!(view.degraded_recording);
    let client = open_journal(&bench.tree.database);
    assert_eq!(client.resource_effects(&operation_id).unwrap(), Vec::new());
}

#[test]
fn a_result_with_an_uncertain_submission_and_a_final_effect_is_unknown() {
    let mut bench = Bench::new();
    bench.uncertain_submission = true;
    let file = bench.tree.file("a");
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
    // The entry is removed, and the submission of the call is not
    // certain. The step has no `Verifying` record, so the effect is not
    // established: the step and the operation are `UnknownOutcome`, and
    // the operation is not parked until a restart.
    assert!(!file.exists());
    let step = &view.operation.steps()[0];
    assert_eq!(step.progress().state(), &StepState::UnknownOutcome);
    assert_eq!(
        step.progress().dispatch(),
        &DispatchState::SubmissionUncertain
    );
    assert_eq!(step.results()[0].effect, TargetEffect::UnknownOutcome);
    assert_eq!(view.operation.state(), &OperationState::UnknownOutcome);
    let stored = open_journal(&bench.tree.database)
        .operation(&operation_id)
        .unwrap()
        .unwrap();
    assert_eq!(stored, view.operation);
}
