//! An `UnknownOutcome` operation of an earlier lifetime holds its leases,
//! the coordinator reconciles it again at an interval, and an
//! acknowledgment releases the leases.

use svalnir_core::action::{ActionClass, ErrorFamily, Journal as _, OperationState};
use svalnir_core::id::{OperationId, RequestId};

use super::super::{FileProbe, HELD_RECONCILIATION_INTERVAL, code};
use super::support::{
    Bench, FailPoint, TestCoordinator, admitted, cleanup_plan, open_journal, principal, queued,
    refusal, stored_request,
};
use crate::journal::{RequestBody, RequestCompletion, RequestStatus};

/// A bench whose journal has an `UnknownOutcome` operation of an earlier
/// lifetime: the entry `a` is at its name after a consumed dispatch, so
/// no evidence settles the step. Returns the coordinator of the new
/// lifetime after its reconciliation.
fn unknown_after_restart() -> (Bench, Box<TestCoordinator>, OperationId) {
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
    bench.fail(FailPoint::RecordStep);
    bench.fail(FailPoint::RecordOperation);
    coordinator.step();
    drop(coordinator);
    bench.heal();
    // A replacement at the name of the entry is a different target.
    bench.tree.file("a");
    *bench.host.file_probe.lock().unwrap() = Some(FileProbe::PlannedObject);
    let mut coordinator = bench.start();
    coordinator.step();
    assert!(!coordinator.reconciliation_pending());
    let stored = open_journal(&bench.tree.database)
        .operation(&operation_id)
        .unwrap()
        .unwrap();
    assert_eq!(stored.state(), &OperationState::UnknownOutcome);
    (bench, coordinator, operation_id)
}

/// A plan for the entry `name` below the same cleanup root.
fn conflicting(bench: &Bench, plan: &str, name: &str) -> svalnir_core::action::Plan {
    bench.tree.file(name);
    let plan = cleanup_plan(
        plan,
        &bench.tree,
        &ActionClass::DeleteSelectedFiles,
        &[name],
        bench.clock.now(),
    );
    bench.store(&plan);
    plan
}

#[test]
fn an_unknown_operation_of_an_earlier_lifetime_holds_its_lease_until_it_is_settled() {
    let (bench, mut coordinator, operation_id) = unknown_after_restart();
    let second = conflicting(&bench, "plan_2", "c");
    // The conflicting plan is refused as for a live lease.
    let error = refusal(&mut coordinator, stored_request(&second));
    assert_eq!(error.code.as_str(), code::LEASE_UNAVAILABLE);
    assert_eq!(error.family, ErrorFamily::Limits);

    // The entry goes. Before the interval, no new reconciliation reads it.
    *bench.host.file_probe.lock().unwrap() = Some(FileProbe::Absent);
    let progress = coordinator.step();
    assert!(progress.wake_at.is_some());
    bench.clock.advance(HELD_RECONCILIATION_INTERVAL.get() / 2);
    coordinator.step();
    let error = refusal(&mut coordinator, stored_request(&second));
    assert_eq!(error.code.as_str(), code::LEASE_UNAVAILABLE);

    // After the interval the reconciliation settles the operation and
    // releases its lease.
    bench.clock.advance(HELD_RECONCILIATION_INTERVAL.get());
    coordinator.step();
    let stored = open_journal(&bench.tree.database)
        .operation(&operation_id)
        .unwrap()
        .unwrap();
    assert_eq!(stored.state(), &OperationState::Completed);
    let third = conflicting(&bench, "plan_3", "d");
    admitted(&mut coordinator, stored_request(&third));
}

#[test]
fn an_acknowledgment_releases_the_lease_and_keeps_the_unknown_result() {
    let (mut bench, mut coordinator, operation_id) = unknown_after_restart();
    let second = conflicting(&bench, "plan_2", "c");
    assert_eq!(
        refusal(&mut coordinator, stored_request(&second))
            .code
            .as_str(),
        code::LEASE_UNAVAILABLE
    );

    let first = coordinator
        .acknowledge(&operation_id, &principal())
        .unwrap();
    assert!(!first.repeated);
    admitted(&mut coordinator, stored_request(&second));
    // The recorded result stays `UnknownOutcome`, with the
    // acknowledgment.
    let journal = open_journal(&bench.tree.database);
    assert_eq!(
        journal.operation(&operation_id).unwrap().unwrap().state(),
        &OperationState::UnknownOutcome
    );
    assert_eq!(
        journal.acknowledgment(&operation_id).unwrap(),
        Some(first.acknowledgment.clone())
    );
    drop(journal);
    // A repeated acknowledgment is the first one.
    let repeated = coordinator
        .acknowledge(&operation_id, &principal())
        .unwrap();
    assert!(repeated.repeated);
    assert_eq!(repeated.acknowledgment, first.acknowledgment);

    // An unknown operation and an operation in a different state are
    // refused.
    let error = coordinator
        .acknowledge(&OperationId::new("operation_none").unwrap(), &principal())
        .unwrap_err();
    assert_eq!(error.code.as_str(), code::OPERATION_NOT_FOUND);
    assert_eq!(error.family, ErrorFamily::Evidence);
    let plan_of_second = open_journal(&bench.tree.database)
        .operation_of_plan(&second.plan_id)
        .unwrap()
        .unwrap();
    let error = coordinator
        .acknowledge(plan_of_second.operation_id(), &principal())
        .unwrap_err();
    assert_eq!(error.code.as_str(), code::OPERATION_NOT_UNKNOWN_OUTCOME);
    assert_eq!(error.family, ErrorFamily::Request);

    // A restart does not hold the lease of the acknowledged operation.
    super::support::run(
        &mut coordinator,
        &bench.clock,
        plan_of_second.operation_id(),
    );
    assert!(coordinator.shutdown().is_ok());
    let mut coordinator = bench.start();
    coordinator.step();
    let third = conflicting(&bench, "plan_3", "d");
    admitted(&mut coordinator, stored_request(&third));
}

#[test]
fn a_queued_acknowledgment_is_served_by_the_coordinator() {
    let (bench, mut coordinator, operation_id) = unknown_after_restart();
    let body = RequestBody::Acknowledge {
        operation_id: operation_id.clone(),
    };
    open_journal(&bench.tree.database)
        .enqueue_request(&queued("request_1", body, bench.clock.now()))
        .unwrap();
    coordinator.step();
    let status = open_journal(&bench.tree.database)
        .request_status(&RequestId::new("request_1").unwrap())
        .unwrap();
    assert!(
        matches!(
            status,
            Some(RequestStatus::Completed {
                completion: RequestCompletion::Acknowledged {
                    repeated: false,
                    ..
                }
            })
        ),
        "{status:?}"
    );
    let second = conflicting(&bench, "plan_2", "c");
    admitted(&mut coordinator, stored_request(&second));
}
