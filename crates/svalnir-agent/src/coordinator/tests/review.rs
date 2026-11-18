//! Regression tests for the defects that the independent review of the
//! coordinator found.

use svalnir_core::action::{
    ActionClass, ErrorFamily, Escalation, Journal as _, OperationState, Plan, StopFence,
    TriggerClass,
};
use svalnir_core::authority::Generation;
use svalnir_core::id::{IncidentId, RequestId};

use super::super::{ApplyOutcome, ApplyRequest, CoordinatorError, StopAcknowledgement, code};
use super::support::{
    Bench, FailPoint, SECOND, TrashMode, admitted, allowance, approval, automatic_request,
    automatic_stop_plan, cleanup_plan, incident_id, open_journal, principal, queued, refusal, run,
    stored_request,
};
use crate::journal::{RequestBody, RequestCompletion, RequestStatus};

fn status(bench: &Bench, request: &str) -> Option<RequestStatus> {
    open_journal(&bench.tree.database)
        .request_status(&RequestId::new(request).unwrap())
        .unwrap()
}

/// An automatic graceful plan of the memory guard for a new process that
/// exits at the request.
fn memory_plan(bench: &Bench, incident: &IncidentId, process: i32) -> Plan {
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

#[test]
fn a_stop_with_volatile_history_that_is_not_saved_is_not_a_clean_stop() {
    let mut bench = Bench::with(true, TrashMode::Move);
    let incident = incident_id("incident_1");
    bench.authority.open_incident(&incident, bench.clock.now());
    bench.measurements.0.lock().unwrap().pressure = ["critical", "normal"].into();
    let plan = memory_plan(&bench, &incident, 4242);
    let mut coordinator = bench.start();
    let first_epoch = coordinator.executor_epoch().clone();
    bench.fail(FailPoint::RecordPlan);
    bench.fail(FailPoint::Admit);
    bench.fail(FailPoint::CommitIntent);
    let operation_id = admitted(
        &mut coordinator,
        automatic_request(&plan, allowance(&incident, &first_epoch, 3)),
    );
    let view = run(&mut coordinator, &bench.clock, &operation_id);
    assert_eq!(view.operation.state(), &OperationState::Completed);
    assert_eq!(coordinator.remaining_slots(&incident), Some(2));

    // The journal accepts the release and does not take the volatile
    // history. The stop is then not a clean one.
    bench.heal();
    bench.fail(FailPoint::PersistVolatile);
    let Err((coordinator, error)) = coordinator.shutdown() else {
        panic!("the registration was released with volatile history that is not saved");
    };
    assert!(matches!(error, CoordinatorError::Unsettled));
    drop(coordinator);
    bench.heal();
    assert!(
        open_journal(&bench.tree.database)
            .operation(&operation_id)
            .unwrap()
            .is_none(),
        "the journal has no record of the volatile slot"
    );

    // The next lifetime does not give the incident its slots back.
    let mut coordinator = bench.start();
    bench.clock.advance(101 * SECOND);
    let second = memory_plan(&bench, &incident, 4343);
    let error = refusal(
        &mut coordinator,
        automatic_request(&second, allowance(&incident, &first_epoch, 3)),
    );
    assert_eq!(error.code.as_str(), code::BUDGET_EXHAUSTED);
    assert_eq!(coordinator.remaining_slots(&incident), Some(0));
    assert_eq!(bench.host.calls().len(), 1);
}

#[test]
fn slots_that_were_exhausted_for_safety_do_not_come_back_with_a_larger_ceiling() {
    let mut bench = Bench::with(true, TrashMode::Move);
    let incident = incident_id("incident_1");
    bench.authority.open_incident(&incident, bench.clock.now());
    let coordinator = bench.start();
    let first_epoch = coordinator.executor_epoch().clone();
    // An unclean stop: the volatile counts are possibly lost.
    drop(coordinator);
    let mut coordinator = bench.start();
    bench.clock.advance(101 * SECOND);
    let plan = memory_plan(&bench, &incident, 4242);
    let error = refusal(
        &mut coordinator,
        automatic_request(&plan, allowance(&incident, &first_epoch, 3)),
    );
    assert_eq!(error.code.as_str(), code::BUDGET_EXHAUSTED);
    // The controller gives a larger ceiling for the same generation.
    let error = refusal(
        &mut coordinator,
        automatic_request(&plan, allowance(&incident, &first_epoch, 5)),
    );
    assert_eq!(error.code.as_str(), code::BUDGET_EXHAUSTED);
    assert_eq!(coordinator.remaining_slots(&incident), Some(0));
    // A rearm makes a new generation, which starts with the given usage.
    let mut rearmed = allowance(&incident, coordinator.executor_epoch(), 5);
    rearmed.generation = Generation::new(2);
    admitted(&mut coordinator, automatic_request(&plan, rearmed));
    assert_eq!(coordinator.remaining_slots(&incident), Some(4));
    // An allowance of the generation before it is not a rearm.
    let other = memory_plan(&bench, &incident, 4343);
    let error = refusal(
        &mut coordinator,
        automatic_request(&other, allowance(&incident, &first_epoch, 9)),
    );
    assert_eq!(error.code.as_str(), code::INCIDENT_ALLOWANCE_MISSING);
    assert_eq!(coordinator.remaining_slots(&incident), Some(4));
}

#[test]
fn a_stored_automatic_plan_with_no_allowance_does_not_use_the_incident_of_the_guard() {
    let mut bench = Bench::new();
    let incident = incident_id("incident_1");
    bench.authority.open_incident(&incident, bench.clock.now());
    bench.measurements.0.lock().unwrap().pressure = ["critical", "normal"].into();
    let mut coordinator = bench.start();
    let epoch = coordinator.executor_epoch().clone();
    // The guard acts one time, so the ledger has the incident.
    let first = memory_plan(&bench, &incident, 4242);
    let operation_id = admitted(
        &mut coordinator,
        automatic_request(&first, allowance(&incident, &epoch, 3)),
    );
    run(&mut coordinator, &bench.clock, &operation_id);
    assert_eq!(coordinator.remaining_slots(&incident), Some(2));
    assert_eq!(coordinator.cooldown_until(&incident), None);

    // A client applies a stored automatic plan of the same incident: a
    // direct apply, and a request of the journal queue.
    let second = memory_plan(&bench, &incident, 4343);
    bench.store(&second);
    let error = refusal(&mut coordinator, stored_request(&second));
    assert_eq!(error.code.as_str(), code::INCIDENT_ALLOWANCE_MISSING);
    let body = RequestBody::Apply {
        approval: approval(&second),
    };
    open_journal(&bench.tree.database)
        .enqueue_request(&queued("request_1", body, bench.clock.now()))
        .unwrap();
    assert!(coordinator.serve_queue());
    let Some(RequestStatus::Completed {
        completion: RequestCompletion::Rejected { error },
    }) = status(&bench, "request_1")
    else {
        panic!("the queued automatic plan was not rejected");
    };
    assert_eq!(error.code.as_str(), code::INCIDENT_ALLOWANCE_MISSING);
    assert_eq!(coordinator.remaining_slots(&incident), Some(2));
    assert_eq!(bench.host.calls().len(), 1);
    assert!(bench.host.world().processes.contains_key(&4343));
}

#[test]
fn a_plan_identity_with_different_content_is_not_the_plan_of_the_earlier_apply() {
    let mut bench = Bench::new();
    bench.tree.file("a");
    let other_file = bench.tree.file("b");
    let now = bench.clock.now();
    let class = ActionClass::DeleteSelectedFiles;
    let plan = cleanup_plan("plan_1", &bench.tree, &class, &["a"], now);
    bench.store(&plan);
    let mut coordinator = bench.start();
    let operation_id = admitted(&mut coordinator, stored_request(&plan));
    run(&mut coordinator, &bench.clock, &operation_id);

    // The same identity, a different target, and an approval of the new
    // content.
    let changed = cleanup_plan("plan_1", &bench.tree, &class, &["b"], now);
    assert_ne!(changed.digest(), plan.digest());
    let outcome = coordinator.apply(ApplyRequest {
        approval: approval(&changed),
        principal: principal(),
        plan: Some(changed),
        incident: None,
    });
    let ApplyOutcome::Refused { error } = outcome else {
        panic!("the changed plan got the operation of the first one: {outcome:?}");
    };
    assert_eq!(error.code.as_str(), code::PLAN_CONFLICT);
    assert_eq!(error.family, ErrorFamily::Request);
    assert!(other_file.exists());
}

#[test]
fn a_result_that_the_journal_did_not_take_is_not_acknowledged_as_settled() {
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
    let mut coordinator = bench.start();
    let handle = coordinator.handle();
    let operation_id = admitted(&mut coordinator, stored_request(&plan));
    bench.fail(FailPoint::RecordOperation);
    let view = run(&mut coordinator, &bench.clock, &operation_id);
    assert_eq!(view.operation.state(), &OperationState::Completed);
    assert!(view.degraded_recording);
    let stored = open_journal(&bench.tree.database)
        .operation(&operation_id)
        .unwrap()
        .unwrap();
    assert!(!stored.state().is_settled());

    // The journal has no result, so no caller gets `Settled`.
    let level = handle.cancel(&operation_id).unwrap();
    assert_ne!(level, StopAcknowledgement::Settled);
    let level = coordinator.cancel(&operation_id).unwrap();
    assert_ne!(level, StopAcknowledgement::Settled);
    let cancel = RequestBody::Cancel {
        operation_id: operation_id.clone(),
    };
    open_journal(&bench.tree.database)
        .enqueue_request(&queued("request_1", cancel, bench.clock.now()))
        .unwrap();

    // When the journal takes the record, the operation is settled.
    bench.heal();
    coordinator.step();
    let stored = open_journal(&bench.tree.database)
        .operation(&operation_id)
        .unwrap()
        .unwrap();
    assert_eq!(stored.state(), &OperationState::Completed);
    assert_eq!(
        handle.cancel(&operation_id),
        Some(StopAcknowledgement::Settled)
    );
    assert_eq!(
        coordinator.cancel(&operation_id).unwrap(),
        StopAcknowledgement::Settled
    );
    assert!(coordinator.shutdown().is_ok());
}

#[test]
fn a_completion_that_the_journal_did_not_record_is_written_again() {
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
    let body = RequestBody::Apply {
        approval: approval(&plan),
    };
    open_journal(&bench.tree.database)
        .enqueue_request(&queued("request_1", body, bench.clock.now()))
        .unwrap();
    let mut coordinator = bench.start();
    bench.fail(FailPoint::CompleteRequest);
    assert!(coordinator.serve_queue());
    assert!(matches!(
        status(&bench, "request_1"),
        Some(RequestStatus::Claimed { .. })
    ));
    // No new claim while the completion is not written.
    assert!(!coordinator.serve_queue());

    bench.heal();
    coordinator.step();
    let Some(RequestStatus::Completed {
        completion: RequestCompletion::Operation { operation_id },
    }) = status(&bench, "request_1")
    else {
        panic!("the request of this lifetime has no completion");
    };
    run(&mut coordinator, &bench.clock, &operation_id);
    assert!(!file.exists());
    assert_eq!(bench.intents(), 1);
}

#[test]
fn a_queued_cancel_of_a_different_user_does_not_stop_the_operation() {
    let mut bench = Bench::new();
    bench.tree.file("a");
    let second = bench.tree.file("b");
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
    coordinator.step();
    let mut cancel = queued(
        "request_1",
        RequestBody::Cancel {
            operation_id: operation_id.clone(),
        },
        bench.clock.now(),
    );
    cancel.principal.uid = svalnir_core::process::Uid::new(principal().uid.get() + 1);
    open_journal(&bench.tree.database)
        .enqueue_request(&cancel)
        .unwrap();
    let view = run(&mut coordinator, &bench.clock, &operation_id);
    let Some(RequestStatus::Completed {
        completion: RequestCompletion::Rejected { error },
    }) = status(&bench, "request_1")
    else {
        panic!("the cancel of a different user was not rejected");
    };
    assert_eq!(error.code.as_str(), code::PRINCIPAL_MISMATCH);
    assert_eq!(error.family, ErrorFamily::Authority);
    assert_eq!(view.operation.state(), &OperationState::Completed);
    assert!(view.stop.is_none());
    assert!(!second.exists());
}

#[test]
fn a_deadline_that_ends_during_the_recording_of_a_step_stops_the_call() {
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
    let operation_id = admitted(&mut coordinator, stored_request(&plan));
    // The storage transactions of the intent and of the consumption take
    // longer than the validity of the plan.
    let clock = bench.clock.clone();
    bench.after_consume(move || clock.advance(500 * SECOND));
    let view = run(&mut coordinator, &bench.clock, &operation_id);
    assert!(file.exists(), "the call was issued after the expiry");
    assert_eq!(view.operation.state(), &OperationState::NoAction);
    assert_eq!(bench.intents(), 1);
}

#[test]
fn a_cancel_of_a_volatile_operation_is_not_reported_as_a_durable_stop() {
    let mut bench = Bench::with(true, TrashMode::Move);
    let incident = incident_id("incident_1");
    bench.authority.open_incident(&incident, bench.clock.now());
    let plan = memory_plan(&bench, &incident, 4242);
    let mut coordinator = bench.start();
    bench.fail(FailPoint::RecordPlan);
    bench.fail(FailPoint::Admit);
    bench.fail(FailPoint::CommitIntent);
    let epoch = coordinator.executor_epoch().clone();
    let operation_id = admitted(
        &mut coordinator,
        automatic_request(&plan, allowance(&incident, &epoch, 3)),
    );
    let view = run(&mut coordinator, &bench.clock, &operation_id);
    assert_eq!(view.operation.state(), &OperationState::Completed);
    let cancel = RequestBody::Cancel {
        operation_id: operation_id.clone(),
    };
    open_journal(&bench.tree.database)
        .enqueue_request(&queued("request_1", cancel, bench.clock.now()))
        .unwrap();
    assert!(coordinator.serve_queue());
    assert_eq!(
        status(&bench, "request_1"),
        Some(RequestStatus::Completed {
            completion: RequestCompletion::Stopped {
                fence: StopFence::CurrentInstance
            }
        })
    );
}

#[test]
fn a_new_incident_does_not_remove_the_cooldown_of_an_earlier_one() {
    let mut bench = Bench::new();
    let first = incident_id("incident_0");
    bench.authority.open_incident(&first, bench.clock.now());
    // The pressure does not improve: the first incident gets a cooldown.
    bench.measurements.0.lock().unwrap().pressure = ["critical"].into();
    let mut coordinator = bench.start();
    let epoch = coordinator.executor_epoch().clone();
    let plan = memory_plan(&bench, &first, 4000);
    let operation_id = admitted(
        &mut coordinator,
        automatic_request(&plan, allowance(&first, &epoch, 5)),
    );
    run(&mut coordinator, &bench.clock, &operation_id);
    let until = coordinator.cooldown_until(&first).unwrap();
    assert!(until.get() > bench.clock.now());

    // More incidents than the ledger keeps. Each one is refused for the
    // lease of the process generation, after the ledger took its record.
    let holder = bench.host.spawn(4100);
    let manual = super::support::stop_plan(
        "plan_holder",
        vec![holder.clone()],
        Escalation::None,
        bench.clock.now(),
    );
    bench.store(&manual);
    let holder_id = admitted(&mut coordinator, stored_request(&manual));
    for index in 1..=super::super::MAX_INCIDENTS {
        let incident = incident_id(&format!("incident_{index}"));
        bench.authority.open_incident(&incident, bench.clock.now());
        let plan = automatic_stop_plan(
            &format!("plan_other_{index}"),
            &bench.authority,
            &incident,
            TriggerClass::GlobalCriticalMemory,
            vec![holder.clone()],
            Escalation::None,
            bench.clock.now(),
        );
        let error = refusal(
            &mut coordinator,
            automatic_request(&plan, allowance(&incident, &epoch, 5)),
        );
        assert_eq!(error.code.as_str(), code::LEASE_UNAVAILABLE, "{index}");
    }
    assert!(bench.clock.now() < until.get());
    assert_eq!(coordinator.cooldown_until(&first), Some(until));
    let again = memory_plan(&bench, &first, 4001);
    let error = refusal(
        &mut coordinator,
        automatic_request(&again, allowance(&first, &epoch, 5)),
    );
    assert_eq!(error.code.as_str(), code::COOLDOWN_ACTIVE);
    assert!(coordinator.operation(&holder_id).unwrap().is_some());
}

#[test]
fn a_stop_fence_that_cannot_be_read_is_an_error_and_not_no_fence() {
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
    let mut coordinator = bench.start();
    let operation_id = admitted(&mut coordinator, stored_request(&plan));
    run(&mut coordinator, &bench.clock, &operation_id);
    assert!(coordinator.shutdown().is_ok());
    // A second lifetime has the operation only in the journal.
    let coordinator = bench.start();
    bench.fail(FailPoint::HasStopFence);
    assert!(matches!(
        coordinator.operation(&operation_id),
        Err(CoordinatorError::Record(_))
    ));
    bench.heal();
    let view = coordinator.operation(&operation_id).unwrap().unwrap();
    assert_eq!(view.stop, None);
    assert_eq!(view.operation.state(), &OperationState::Completed);
}
