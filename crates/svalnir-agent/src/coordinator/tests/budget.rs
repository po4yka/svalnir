//! Incident allowances, cooldowns, and the restart rules of a budget.

use svalnir_core::action::{ErrorFamily, Escalation, OperationState, Plan, TriggerClass};
use svalnir_core::id::{ExecutorEpochId, IncidentId};

use super::super::code;
use super::support::{
    Bench, SECOND, TestCoordinator, TrashMode, admitted, allowance, automatic_request,
    automatic_stop_plan, incident_id, refusal, run, stop_plan, stored_request,
};

/// An automatic graceful plan for a new process `process` of the host
/// that exits at the request.
fn plan_for(bench: &Bench, incident: &IncidentId, process: i32) -> Plan {
    let member = bench.host.spawn(process);
    bench.host.world().exits_on_term.insert(process);
    automatic_stop_plan(
        &format!("plan_{process}"),
        &bench.authority,
        incident,
        TriggerClass::GlobalCriticalMemory,
        vec![member],
        Escalation::None,
        bench.clock.now(),
    )
}

fn run_plan(
    bench: &Bench,
    coordinator: &mut TestCoordinator,
    incident: &IncidentId,
    epoch: &ExecutorEpochId,
    process: i32,
    ceiling: u32,
) {
    let plan = plan_for(bench, incident, process);
    let request = automatic_request(&plan, allowance(incident, epoch, ceiling));
    let operation_id = admitted(coordinator, request);
    let view = run(coordinator, &bench.clock, &operation_id);
    assert_eq!(view.operation.state(), &OperationState::Completed);
}

#[test]
fn an_exhausted_incident_allowance_refuses_the_next_intervention() {
    let mut bench = Bench::new();
    let incident = incident_id("incident_1");
    bench.authority.open_incident(&incident, bench.clock.now());
    // The pressure improves, so no cooldown follows the first operation.
    bench.measurements.0.lock().unwrap().pressure = ["critical", "normal"].into();
    let mut coordinator = bench.start();
    let epoch = coordinator.executor_epoch().clone();
    run_plan(&bench, &mut coordinator, &incident, &epoch, 4242, 1);
    assert_eq!(coordinator.remaining_slots(&incident), Some(0));
    assert_eq!(coordinator.cooldown_until(&incident), None);

    let second = plan_for(&bench, &incident, 4343);
    // The controller gives the same ceiling with no usage. The counter
    // of the coordinator does not go back.
    let error = refusal(
        &mut coordinator,
        automatic_request(&second, allowance(&incident, &epoch, 1)),
    );
    assert_eq!(error.code.as_str(), code::BUDGET_EXHAUSTED);
    assert_eq!(error.family, ErrorFamily::Limits);
    assert_eq!(bench.host.calls().len(), 1);
    assert!(bench.host.world().processes.contains_key(&4343));
    // A refusal changes nothing: the plan of the controller has no record
    // in the journal. The plan that was admitted has one.
    {
        use svalnir_core::action::Journal as _;
        let journal = super::support::open_journal(&bench.tree.database);
        assert!(journal.plan(&second.plan_id).unwrap().is_none());
        let first = svalnir_core::id::PlanId::new("plan_4242").unwrap();
        assert!(journal.plan(&first).unwrap().is_some());
    }

    // A manual operation uses its own one-shot limit: it is admitted, and
    // it does not spend or reset the incident counter.
    let manual = stop_plan(
        "plan_manual",
        vec![super::support::member(4343)],
        Escalation::None,
        bench.clock.now(),
    );
    bench.store(&manual);
    let operation_id = admitted(&mut coordinator, stored_request(&manual));
    run(&mut coordinator, &bench.clock, &operation_id);
    assert_eq!(coordinator.remaining_slots(&incident), Some(0));
}

#[test]
fn a_low_benefit_action_starts_a_cooldown_that_backs_off() {
    let mut bench = Bench::new();
    let incident = incident_id("incident_1");
    bench.authority.open_incident(&incident, bench.clock.now());
    // The pressure does not improve.
    bench.measurements.0.lock().unwrap().pressure = ["critical"].into();
    let mut coordinator = bench.start();
    let epoch = coordinator.executor_epoch().clone();
    run_plan(&bench, &mut coordinator, &incident, &epoch, 4242, 5);
    let until = coordinator.cooldown_until(&incident).unwrap();
    assert_eq!(until.get(), bench.clock.now() + 30 * SECOND);

    let second = plan_for(&bench, &incident, 4343);
    let request = || automatic_request(&second, allowance(&incident, &epoch, 5));
    let error = refusal(&mut coordinator, request());
    assert_eq!(error.code.as_str(), code::COOLDOWN_ACTIVE);
    assert_eq!(error.family, ErrorFamily::Limits);
    assert_eq!(bench.host.calls().len(), 1);
    // The end of the cooldown permits a new admission only. The refusal
    // changed nothing, so the same plan is applied.
    bench.clock.set(until.get());
    let operation_id = admitted(&mut coordinator, request());
    run(&mut coordinator, &bench.clock, &operation_id);
    // The second low-benefit action doubles the cooldown, and the third
    // one has the maximum.
    let until = coordinator.cooldown_until(&incident).unwrap();
    assert_eq!(until.get(), bench.clock.now() + 60 * SECOND);
    bench.clock.set(until.get());
    run_plan(&bench, &mut coordinator, &incident, &epoch, 4444, 5);
    let until = coordinator.cooldown_until(&incident).unwrap();
    assert_eq!(until.get(), bench.clock.now() + 100 * SECOND);
    assert_eq!(coordinator.remaining_slots(&incident), Some(2));
}

#[test]
fn a_restart_does_not_replenish_the_allowance_of_an_incident() {
    let mut bench = Bench::new();
    let incident = incident_id("incident_1");
    bench.authority.open_incident(&incident, bench.clock.now());
    bench.measurements.0.lock().unwrap().pressure = ["critical", "normal"].into();
    let mut coordinator = bench.start();
    let first_epoch = coordinator.executor_epoch().clone();
    run_plan(&bench, &mut coordinator, &incident, &first_epoch, 4242, 1);
    assert!(coordinator.shutdown().is_ok());

    // The new lifetime has no counter in memory, and the controller
    // gives the allowance with no usage. The journal has the consumed
    // dispatch of the incident.
    let mut coordinator = bench.start();
    let second = plan_for(&bench, &incident, 4343);
    let request = || automatic_request(&second, allowance(&incident, &first_epoch, 1));
    // An incident that continues starts with its longest cooldown: the
    // cooldown and the backoff of the earlier lifetime are not in the
    // journal, and a restart does not shorten them.
    let error = refusal(&mut coordinator, request());
    assert_eq!(error.code.as_str(), code::COOLDOWN_ACTIVE);
    // The longest cooldown of the incident: 100 seconds.
    bench.clock.advance(101 * SECOND);
    let error = refusal(&mut coordinator, request());
    assert_eq!(error.code.as_str(), code::BUDGET_EXHAUSTED);
    assert_eq!(coordinator.remaining_slots(&incident), Some(0));
    assert_eq!(bench.host.calls().len(), 1);
}

#[test]
fn a_prune_and_a_restart_do_not_replenish_the_allowance_of_an_open_incident() {
    let mut bench = Bench::new();
    let incident = incident_id("incident_1");
    bench.authority.open_incident(&incident, bench.clock.now());
    bench.measurements.0.lock().unwrap().pressure = ["critical", "normal"].into();
    let mut coordinator = bench.start();
    let first_epoch = coordinator.executor_epoch().clone();
    run_plan(&bench, &mut coordinator, &incident, &first_epoch, 4242, 2);
    // The process stops with no release, so the controller record can be
    // behind the journal.
    drop(coordinator);

    // The retention removes the settled operation of the incident. The
    // incident is open, so its usage row stays.
    let mut journal = super::support::open_journal(&bench.tree.database);
    let cutoff = svalnir_core::time::WallTime::from_unix(4_000_000_000, 0).unwrap();
    let report = journal
        .prune(cutoff, 16, std::slice::from_ref(&incident))
        .unwrap();
    assert_eq!(report.operations, 1);
    drop(journal);

    // The controller gives the allowance with no usage. The usage row
    // has the slot of the first operation.
    let mut coordinator = bench.start();
    let second = plan_for(&bench, &incident, 4343);
    let request = || automatic_request(&second, allowance(&incident, &first_epoch, 2));
    let error = refusal(&mut coordinator, request());
    assert_eq!(error.code.as_str(), code::COOLDOWN_ACTIVE);
    assert_eq!(coordinator.remaining_slots(&incident), Some(1));
    bench.clock.advance(101 * SECOND);
    let operation_id = admitted(&mut coordinator, request());
    run(&mut coordinator, &bench.clock, &operation_id);
    assert_eq!(coordinator.remaining_slots(&incident), Some(0));
    assert_eq!(bench.host.calls().len(), 2);
}

#[test]
fn an_unclean_restart_with_the_volatile_exception_exhausts_the_slots() {
    for clean in [true, false] {
        let mut bench = Bench::with(true, TrashMode::Move);
        let incident = incident_id("incident_1");
        bench.authority.open_incident(&incident, bench.clock.now());
        assert!(
            bench.authority.records().incidents[&incident].volatile_exception_at_open,
            "the incident was opened with the exception"
        );
        let coordinator = bench.start();
        let first_epoch = coordinator.executor_epoch().clone();
        if clean {
            assert!(coordinator.shutdown().is_ok());
        } else {
            // The process stops with no release of its registration. Its
            // volatile record, which can have had counts, is lost.
            drop(coordinator);
        }
        let mut coordinator = bench.start();
        bench.clock.advance(101 * SECOND);
        let plan = plan_for(&bench, &incident, 4242);
        let request = automatic_request(&plan, allowance(&incident, &first_epoch, 3));
        if clean {
            admitted(&mut coordinator, request);
        } else {
            // The journal shows no consumed dispatch, and that is not
            // evidence that the lost record had none.
            let error = refusal(&mut coordinator, request);
            assert_eq!(error.code.as_str(), code::BUDGET_EXHAUSTED);
            assert_eq!(coordinator.remaining_slots(&incident), Some(0));
            assert_eq!(bench.host.calls(), Vec::new());
        }
    }
}

#[test]
fn a_refused_request_keeps_the_reservation_of_an_admitted_operation() {
    let mut bench = Bench::new();
    let incident = incident_id("incident_1");
    bench.authority.open_incident(&incident, bench.clock.now());
    bench.measurements.0.lock().unwrap().pressure = ["critical", "normal"].into();
    let mut coordinator = bench.start();
    let epoch = coordinator.executor_epoch().clone();
    let first = plan_for(&bench, &incident, 4242);
    let operation_id = admitted(
        &mut coordinator,
        automatic_request(&first, allowance(&incident, &epoch, 2)),
    );
    // A second plan for the same process generation is refused for its
    // lease. The controller gave the allowance again with no usage.
    let second = automatic_stop_plan(
        "plan_second",
        &bench.authority,
        &incident,
        TriggerClass::GlobalCriticalMemory,
        vec![super::support::member(4242)],
        Escalation::None,
        bench.clock.now(),
    );
    let error = refusal(
        &mut coordinator,
        automatic_request(&second, allowance(&incident, &epoch, 2)),
    );
    assert_eq!(error.code.as_str(), code::LEASE_UNAVAILABLE);
    // The reserved slot of the first operation is counted.
    assert_eq!(coordinator.remaining_slots(&incident), Some(1));
    let view = run(&mut coordinator, &bench.clock, &operation_id);
    assert_eq!(view.operation.state(), &OperationState::Completed);
    assert_eq!(bench.host.calls().len(), 1);
    assert_eq!(coordinator.remaining_slots(&incident), Some(1));
}
