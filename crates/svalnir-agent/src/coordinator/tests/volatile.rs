//! The critical-memory exception of the journal: used only for the exact
//! action that the grant module authorizes.

use svalnir_core::action::{
    ActionClass, Durability, ErrorFamily, Escalation, Journal as _, OperationState, TriggerClass,
};

use super::super::code;
use super::support::{
    Bench, FailPoint, TrashMode, admitted, allowance, automatic_request, automatic_stop_plan,
    cleanup_plan, incident_id, open_journal, refusal, run, stop_plan, stored_request,
};

fn failing_bench(volatile: bool) -> Bench {
    let bench = Bench::with(volatile, TrashMode::Move);
    bench
        .authority
        .open_incident(&incident_id("incident_1"), bench.clock.now());
    bench
}

#[test]
fn a_critical_memory_intervention_uses_the_volatile_record_when_it_is_authorized() {
    let mut bench = failing_bench(true);
    let incident = incident_id("incident_1");
    let member = bench.host.spawn(4242);
    bench.host.world().exits_on_term.insert(4242);
    let plan = automatic_stop_plan(
        "plan_1",
        &bench.authority,
        &incident,
        TriggerClass::GlobalCriticalMemory,
        vec![member],
        Escalation::None,
        bench.clock.now(),
    );
    let mut coordinator = bench.start();
    // The durable journal does not record.
    bench.fail(FailPoint::RecordPlan);
    bench.fail(FailPoint::Admit);
    bench.fail(FailPoint::CommitIntent);
    let request = automatic_request(&plan, allowance(&incident, coordinator.executor_epoch(), 3));
    let operation_id = admitted(&mut coordinator, request);
    let view = run(&mut coordinator, &bench.clock, &operation_id);
    assert_eq!(bench.host.calls().len(), 1);
    assert_eq!(view.operation.state(), &OperationState::Completed);
    // The history is marked: it is never reported as durably committed.
    assert!(view.degraded_recording);
    assert_eq!(view.operation.durability(), Durability::Volatile);
    let step = &view.operation.steps()[0];
    assert_eq!(step.progress().durability(), &Durability::Volatile);
    assert_eq!(step.results()[0].durability, Durability::Volatile);
    // No durable intent was written, and the slot is consumed.
    assert_eq!(bench.intents(), 0);
    assert_eq!(coordinator.remaining_slots(&incident), Some(2));
    assert!(
        open_journal(&bench.tree.database)
            .operation(&operation_id)
            .unwrap()
            .is_none()
    );

    // When the journal works again, the next admission writes the
    // volatile history, and it stays marked volatile.
    bench.heal();
    let file = bench.tree.file("a");
    let manual = cleanup_plan(
        "plan_2",
        &bench.tree,
        &ActionClass::DeleteSelectedFiles,
        &["a"],
        bench.clock.now(),
    );
    bench.store(&manual);
    let manual_id = admitted(&mut coordinator, stored_request(&manual));
    run(&mut coordinator, &bench.clock, &manual_id);
    assert!(!file.exists());
    let stored = open_journal(&bench.tree.database)
        .operation(&operation_id)
        .unwrap()
        .unwrap();
    assert_eq!(stored.state(), &OperationState::Completed);
    assert_eq!(stored.durability(), Durability::Volatile);
}

#[test]
fn the_exception_is_refused_when_the_configuration_does_not_permit_it() {
    let mut bench = failing_bench(false);
    let incident = incident_id("incident_1");
    let member = bench.host.spawn(4242);
    let plan = automatic_stop_plan(
        "plan_1",
        &bench.authority,
        &incident,
        TriggerClass::GlobalCriticalMemory,
        vec![member],
        Escalation::None,
        bench.clock.now(),
    );
    let mut coordinator = bench.start();
    bench.fail(FailPoint::Admit);
    let request = automatic_request(&plan, allowance(&incident, coordinator.executor_epoch(), 3));
    let error = refusal(&mut coordinator, request);
    assert_eq!(error.code.as_str(), code::ADMISSION_NOT_RECORDED);
    assert_eq!(error.family, ErrorFamily::Recording);
    assert_eq!(bench.host.calls(), Vec::new());
    // The refusal left no reservation.
    assert_eq!(coordinator.remaining_slots(&incident), Some(3));
}

#[test]
fn the_exception_never_applies_to_a_budget_trigger_a_manual_stop_or_a_file() {
    let mut bench = failing_bench(true);
    let incident = incident_id("incident_1");
    let member = bench.host.spawn(4242);
    let now = bench.clock.now();
    let budget_plan = automatic_stop_plan(
        "plan_budget",
        &bench.authority,
        &incident,
        TriggerClass::ApplicationBudget,
        vec![member.clone()],
        Escalation::None,
        now,
    );
    let manual_stop = stop_plan("plan_manual", vec![member], Escalation::None, now);
    let file = bench.tree.file("a");
    let cleanup = cleanup_plan(
        "plan_file",
        &bench.tree,
        &ActionClass::MoveToTrash,
        &["a"],
        now,
    );
    bench.store(&manual_stop);
    bench.store(&cleanup);
    let mut coordinator = bench.start();
    bench.fail(FailPoint::Admit);
    let epoch = coordinator.executor_epoch().clone();
    let requests = [
        automatic_request(&budget_plan, allowance(&incident, &epoch, 3)),
        stored_request(&manual_stop),
        stored_request(&cleanup),
    ];
    for request in requests {
        let error = refusal(&mut coordinator, request);
        assert_eq!(error.code.as_str(), code::ADMISSION_NOT_RECORDED);
        assert_eq!(error.family, ErrorFamily::Recording);
    }
    assert_eq!(bench.host.calls(), Vec::new());
    assert!(file.exists());
    assert_eq!(coordinator.remaining_slots(&incident), Some(3));
}
