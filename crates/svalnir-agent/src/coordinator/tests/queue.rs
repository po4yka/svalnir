//! The request queue service: a client writes a request, the coordinator
//! executes it, and the client reads the result.

use svalnir_core::action::{ActionClass, ErrorFamily, Journal as _, OperationState, StopFence};
use svalnir_core::id::{OperationId, RequestId};

use super::super::code;
use super::support::{
    Bench, admitted, approval, cleanup_plan, open_journal, queued, run, stored_request,
};
use crate::journal::{RequestBody, RequestCompletion, RequestStatus};

fn completion(bench: &Bench, request: &str) -> RequestCompletion {
    let status = open_journal(&bench.tree.database)
        .request_status(&RequestId::new(request).unwrap())
        .unwrap();
    match status {
        Some(RequestStatus::Completed { completion }) => completion,
        other => panic!("the request {request} is not complete: {other:?}"),
    }
}

#[test]
fn a_transient_coordinator_serves_a_request_that_was_queued_before_its_start() {
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
    // One step claims the request, admits the plan, and completes the
    // request with the operation identity.
    coordinator.step();
    let RequestCompletion::Operation { operation_id } = completion(&bench, "request_1") else {
        panic!("the request has no operation");
    };
    run(&mut coordinator, &bench.clock, &operation_id);
    assert!(!file.exists());
    assert!(coordinator.shutdown().is_ok());
    let stored = open_journal(&bench.tree.database)
        .operation(&operation_id)
        .unwrap()
        .unwrap();
    assert_eq!(stored.state(), &OperationState::Completed);
}

#[test]
fn a_queued_request_that_is_refused_has_its_rejection_and_no_operation() {
    let mut bench = Bench::new();
    let file = bench.tree.file("a");
    let plan = cleanup_plan(
        "plan_1",
        &bench.tree,
        &ActionClass::DeleteSelectedFiles,
        &["a"],
        bench.clock.now(),
    );
    // The client did not store the plan.
    let mut client = open_journal(&bench.tree.database);
    let apply = RequestBody::Apply {
        approval: approval(&plan),
    };
    client
        .enqueue_request(&queued("request_1", apply, bench.clock.now()))
        .unwrap();
    let cancel = RequestBody::Cancel {
        operation_id: OperationId::new("operation_none").unwrap(),
    };
    client
        .enqueue_request(&queued("request_2", cancel, bench.clock.now()))
        .unwrap();
    let mut coordinator = bench.start();
    assert!(coordinator.serve_queue());
    assert!(coordinator.serve_queue());
    assert!(!coordinator.serve_queue());
    let RequestCompletion::Rejected { error } = completion(&bench, "request_1") else {
        panic!("the apply was not rejected");
    };
    assert_eq!(error.code.as_str(), code::PLAN_NOT_FOUND);
    let RequestCompletion::Rejected { error } = completion(&bench, "request_2") else {
        panic!("the cancel was not rejected");
    };
    assert_eq!(error.code.as_str(), code::OPERATION_NOT_FOUND);
    assert_eq!(error.family, ErrorFamily::Request);
    assert!(file.exists());
    assert_eq!(client.unsettled_operation_count().unwrap(), 0);
}

#[test]
fn a_queued_cancel_stops_the_operation_with_a_durable_fence() {
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
    let cancel = RequestBody::Cancel {
        operation_id: operation_id.clone(),
    };
    open_journal(&bench.tree.database)
        .enqueue_request(&queued("request_1", cancel, bench.clock.now()))
        .unwrap();
    let view = run(&mut coordinator, &bench.clock, &operation_id);
    assert_eq!(
        completion(&bench, "request_1"),
        RequestCompletion::Stopped {
            fence: StopFence::Durable
        }
    );
    assert_eq!(view.operation.state(), &OperationState::Partial);
    assert!(second.exists());
}

#[test]
fn a_request_that_a_pending_reconciliation_stopped_is_held_and_executed_after_it() {
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
    let mut client = open_journal(&bench.tree.database);
    let apply = RequestBody::Apply {
        approval: approval(&plan),
    };
    client
        .enqueue_request(&queued("request_1", apply, bench.clock.now()))
        .unwrap();
    let cancel = RequestBody::Cancel {
        operation_id: OperationId::new("operation_none").unwrap(),
    };
    client
        .enqueue_request(&queued("request_2", cancel, bench.clock.now()))
        .unwrap();
    let database = bench.tree.database.clone();
    let status = |request: &str| {
        open_journal(&database)
            .request_status(&RequestId::new(request).unwrap())
            .unwrap()
    };
    let mut coordinator = bench.start();
    // The journal reports a pending reconciliation at the admission. The
    // request is not rejected: it stays claimed with no completion.
    bench.fail(super::support::FailPoint::AdmitSequence);
    assert!(coordinator.serve_queue());
    assert!(coordinator.reconciliation_pending());
    assert!(!matches!(
        status("request_1"),
        Some(RequestStatus::Completed { .. })
    ));
    // The held request is first: no later request is claimed before it.
    assert!(!coordinator.serve_queue());
    assert_eq!(status("request_2"), Some(RequestStatus::Queued));
    assert!(file.exists());

    bench.heal();
    // The reconciliation completes, and then this lifetime executes the
    // held request.
    for _ in 0..4 {
        coordinator.step();
    }
    let RequestCompletion::Operation { operation_id } = completion(&bench, "request_1") else {
        panic!("the held request has no operation");
    };
    run(&mut coordinator, &bench.clock, &operation_id);
    assert!(!file.exists());
    assert!(matches!(
        status("request_2"),
        Some(RequestStatus::Completed { .. })
    ));
}
