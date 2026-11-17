//! The coordinator lock, the registration of the coordinator, and the
//! request queue.

use svalnir_core::action::{
    Admission, DispatchConsumption, DispatchState, Durability, ErrorFamily, Journal, JournalError,
    StopFence,
};
use svalnir_core::id::RequestId;

use super::super::{
    ClaimedRequest, CoordinatorLock, CoordinatorLockError, Enqueued, MAX_OPEN_REQUESTS,
    OperationJournal, OperationJournalError, QueuedRequest, RequestBody, RequestCompletion,
    RequestStatus, SequenceViolation, coordinator_lock_path,
};
use super::{
    Fixture, admit, approval, dispatch, envelope, epoch, failure, file_plan, new_operation,
    operation_id, other_principal, principal, step_id, wall,
};

fn request_id(text: &str) -> RequestId {
    RequestId::new(text).unwrap()
}

fn apply_request(id: &str, plan: &str) -> QueuedRequest {
    QueuedRequest {
        request_id: request_id(id),
        principal: principal(),
        body: RequestBody::Apply {
            approval: approval(&file_plan(plan, 1)),
        },
        enqueued_at: wall(0),
    }
}

fn is_sequence(error: &OperationJournalError, expected: &SequenceViolation) -> bool {
    matches!(error, OperationJournalError::Sequence(violation) if violation == expected)
}

// The lock.

#[test]
fn a_second_coordinator_cannot_take_the_lock_while_the_first_holds_it() {
    let fixture = Fixture::new();
    let path = fixture.path();
    let first = CoordinatorLock::try_acquire(&path).unwrap();
    let directory = std::fs::canonicalize(fixture.directory.path()).unwrap();
    assert_eq!(first.database(), directory.join("operations.sqlite"));
    assert!(coordinator_lock_path(&path).exists());
    assert!(
        coordinator_lock_path(&path)
            .to_string_lossy()
            .ends_with("operations.sqlite.coordinator-lock")
    );

    // Two open files of the lock, as two processes have.
    for _ in 0..2 {
        assert!(matches!(
            CoordinatorLock::try_acquire(&path),
            Err(CoordinatorLockError::Held)
        ));
    }
    // The holder goes away, as on a stop of its process. The lock is free,
    // and the lock file stays.
    drop(first);
    let second = CoordinatorLock::try_acquire(&path).unwrap();
    assert!(matches!(
        CoordinatorLock::try_acquire(&path),
        Err(CoordinatorLockError::Held)
    ));
    drop(second);

    // The lock of a different database is not the lock of this one.
    let other = Fixture::new();
    let _other_lock = CoordinatorLock::try_acquire(&other.path()).unwrap();
    let _lock = CoordinatorLock::try_acquire(&path).unwrap();
}

#[cfg(unix)]
#[test]
fn a_lock_path_that_is_a_symbolic_link_is_refused() {
    let fixture = Fixture::new();
    let target = fixture.directory.path().join("elsewhere");
    std::fs::write(&target, b"").unwrap();
    std::os::unix::fs::symlink(&target, coordinator_lock_path(&fixture.path())).unwrap();
    assert!(matches!(
        CoordinatorLock::try_acquire(&fixture.path()),
        Err(CoordinatorLockError::Io(_))
    ));
}

#[test]
fn a_clean_stop_needs_no_reconciliation() {
    let fixture = Fixture::new();
    let mut journal = fixture.open();
    assert_eq!(journal.coordination().unwrap(), None);
    let lock = CoordinatorLock::try_acquire(&fixture.path()).unwrap();
    let start = journal
        .begin_coordination(&lock, &epoch("epoch_1"), wall(0))
        .unwrap();
    assert_eq!(start.predecessor, None);
    assert!(!start.reconciliation_pending);
    let record = journal.coordination().unwrap().unwrap();
    assert_eq!(record.executor_epoch, epoch("epoch_1"));
    assert_eq!(record.process_id, std::process::id());
    assert!(!record.released && !record.reconciliation_pending);

    assert_eq!(journal.unsettled_operation_count().unwrap(), 0);
    // A restart makes a new lifetime: the same one is refused.
    assert!(matches!(
        journal.begin_coordination(&lock, &epoch("epoch_1"), wall(1)),
        Err(OperationJournalError::Conflict)
    ));
    // The lock of a different journal registers no coordinator here.
    let other = Fixture::new();
    let other_lock = CoordinatorLock::try_acquire(&other.path()).unwrap();
    assert!(matches!(
        journal.begin_coordination(&other_lock, &epoch("epoch_2"), wall(1)),
        Err(OperationJournalError::LockMismatch)
    ));

    let plan = file_plan("plan_1", 2);
    let mut operation = admit(&mut journal, &plan, "operation_1", "epoch_1");
    dispatch(&mut journal, &plan, &mut operation, "s0");
    journal
        .commit_intent(&envelope(&plan, &operation, "s1"))
        .unwrap();

    // Only the registered lifetime releases the registration.
    let error = journal.end_coordination(&epoch("epoch_0")).unwrap_err();
    assert!(is_sequence(&error, &SequenceViolation::ExecutorEpoch));
    journal.end_coordination(&epoch("epoch_1")).unwrap();
    assert!(journal.coordination().unwrap().unwrap().released);
    // After the release, the journal consumes no dispatch of that
    // lifetime.
    let error = journal
        .try_consume_dispatch(operation.operation_id(), &step_id("s1"))
        .unwrap_err();
    assert!(is_sequence(&error, &SequenceViolation::ExecutorEpoch));
    drop((journal, lock));

    let mut journal = fixture.open();
    let lock = CoordinatorLock::try_acquire(&fixture.path()).unwrap();
    let start = journal
        .begin_coordination(&lock, &epoch("epoch_2"), wall(2))
        .unwrap();
    assert!(!start.reconciliation_pending);
    let predecessor = start.predecessor.unwrap();
    assert_eq!(predecessor.executor_epoch, epoch("epoch_1"));
    assert!(predecessor.released);
    // New work of the new lifetime is admitted at once.
    admit(
        &mut journal,
        &file_plan("plan_2", 1),
        "operation_2",
        "epoch_2",
    );
    assert_eq!(journal.unsettled_operation_count().unwrap(), 2);
    // The lifetime of a stored operation is not used again.
    journal.end_coordination(&epoch("epoch_2")).unwrap();
    assert!(matches!(
        journal.begin_coordination(&lock, &epoch("epoch_1"), wall(3)),
        Err(OperationJournalError::Conflict)
    ));
}

#[test]
fn the_first_registration_finds_work_that_was_written_with_no_coordinator() {
    let fixture = Fixture::new();
    let mut journal = fixture.open();
    let plan = file_plan("plan_1", 1);
    let mut operation = admit(&mut journal, &plan, "operation_1", "epoch_0");
    dispatch(&mut journal, &plan, &mut operation, "s0");
    drop(journal);

    let mut journal = fixture.open();
    // A different spelling of the database path gives the same lock.
    let spelled = fixture.directory.path().join(".").join("operations.sqlite");
    let lock = CoordinatorLock::try_acquire(&spelled).unwrap();
    assert!(matches!(
        CoordinatorLock::try_acquire(&fixture.path()),
        Err(CoordinatorLockError::Held)
    ));
    let start = journal
        .begin_coordination(&lock, &epoch("epoch_1"), wall(0))
        .unwrap();
    assert_eq!(start.predecessor, None);
    assert!(start.reconciliation_pending);
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one scenario: each part needs the state that the part before it made"
)]
fn an_unclean_stop_needs_reconciliation_before_new_admission_and_dispatch() {
    let fixture = Fixture::new();
    let mut journal = fixture.open();
    let lock = CoordinatorLock::try_acquire(&fixture.path()).unwrap();
    journal
        .begin_coordination(&lock, &epoch("epoch_1"), wall(0))
        .unwrap();
    let plan = file_plan("plan_1", 2);
    let mut operation = admit(&mut journal, &plan, "operation_1", "epoch_1");
    let id = operation.operation_id().clone();
    dispatch(&mut journal, &plan, &mut operation, "s0");
    journal
        .commit_intent(&envelope(&plan, &operation, "s1"))
        .unwrap();
    operation
        .advance_step(
            &step_id("s1"),
            svalnir_core::action::StepState::IntentCommitted,
            DispatchState::NotSubmitted,
            Durability::Durable,
        )
        .unwrap();
    let pending_plan = file_plan("plan_2", 1);
    journal.record_plan(&pending_plan).unwrap();

    // The process stops with no release. The operating system frees the
    // lock; the registration stays.
    drop((journal, lock));
    let mut journal = fixture.open();
    let lock = CoordinatorLock::try_acquire(&fixture.path()).unwrap();
    let start = journal
        .begin_coordination(&lock, &epoch("epoch_2"), wall(5))
        .unwrap();
    assert!(start.reconciliation_pending);
    let predecessor = start.predecessor.unwrap();
    assert_eq!(predecessor.executor_epoch, epoch("epoch_1"));
    assert!(!predecessor.released);
    assert!(
        journal
            .coordination()
            .unwrap()
            .unwrap()
            .reconciliation_pending
    );

    // The free lock is not evidence that the work stopped: the journal
    // admits nothing and consumes no dispatch.
    let next = new_operation(&pending_plan, "operation_2", "epoch_2", Durability::Durable);
    let error = journal
        .try_admit(&approval(&pending_plan), &principal(), &next)
        .unwrap_err();
    assert!(is_sequence(
        &error,
        &SequenceViolation::ReconciliationPending
    ));
    assert_eq!(
        journal.admit(&approval(&pending_plan), &principal(), &next),
        Err(JournalError::Sequence)
    );
    let error = journal
        .try_consume_dispatch(&id, &step_id("s1"))
        .unwrap_err();
    assert!(is_sequence(
        &error,
        &SequenceViolation::ReconciliationPending
    ));
    assert_eq!(journal.operation(next.operation_id()), Ok(None));

    // The reads and the records of reconciliation are available.
    let records = journal.recovery_records(10).unwrap();
    assert_eq!(records.len(), 1);
    assert!(records[0].unsettled_steps[0].dispatch_consumed);
    assert_eq!(
        journal
            .consume_dispatch(&id, &step_id("s0"))
            .unwrap()
            .consumption,
        DispatchConsumption::AlreadyConsumed
    );
    journal.set_stop_fence(&id).unwrap();

    // A stop in the reconciliation keeps it pending for the next lifetime.
    journal.end_coordination(&epoch("epoch_2")).unwrap();
    drop((journal, lock));
    let mut journal = fixture.open();
    let lock = CoordinatorLock::try_acquire(&fixture.path()).unwrap();
    let start = journal
        .begin_coordination(&lock, &epoch("epoch_3"), wall(9))
        .unwrap();
    assert!(start.reconciliation_pending);

    // Only the registered lifetime completes the reconciliation.
    let error = journal
        .complete_reconciliation(&epoch("epoch_2"))
        .unwrap_err();
    assert!(is_sequence(&error, &SequenceViolation::ExecutorEpoch));
    journal.complete_reconciliation(&epoch("epoch_3")).unwrap();
    assert!(
        !journal
            .coordination()
            .unwrap()
            .unwrap()
            .reconciliation_pending
    );

    // New work of the new lifetime is admitted. The operation of the
    // earlier lifetime is not executable again.
    let next = new_operation(&pending_plan, "operation_2", "epoch_3", Durability::Durable);
    assert_eq!(
        journal.admit(&approval(&pending_plan), &principal(), &next),
        Ok(Admission::Admitted)
    );
    let stale = new_operation(
        &file_plan("plan_3", 1),
        "operation_3",
        "epoch_1",
        Durability::Durable,
    );
    journal.record_plan(&file_plan("plan_3", 1)).unwrap();
    let error = journal
        .try_admit(&approval(&file_plan("plan_3", 1)), &principal(), &stale)
        .unwrap_err();
    assert!(is_sequence(&error, &SequenceViolation::ExecutorEpoch));
    // `s1` of the earlier lifetime has an intent and no fence is needed to
    // stop it: its lifetime is over.
    let unfenced = fixture.open();
    unfenced
        .connection
        .execute("UPDATE operation SET stop_fence = 0", [])
        .unwrap();
    let error = journal
        .try_consume_dispatch(&id, &step_id("s1"))
        .unwrap_err();
    assert!(is_sequence(&error, &SequenceViolation::ExecutorEpoch));
    let stored = journal.operation(&id).unwrap().unwrap();
    assert_eq!(stored, operation);
}

// The request queue.

#[test]
fn a_request_is_enqueued_one_time_and_claimed_by_one_claimer() {
    let fixture = Fixture::new();
    let mut client = fixture.open();
    let first = apply_request("request_1", "plan_1");
    let second = QueuedRequest {
        request_id: request_id("request_2"),
        principal: other_principal(),
        body: RequestBody::Cancel {
            operation_id: operation_id("operation_1"),
        },
        enqueued_at: wall(1),
    };
    assert_eq!(client.request_status(&first.request_id).unwrap(), None);
    assert_eq!(client.enqueue_request(&first).unwrap(), Enqueued::New);
    assert_eq!(
        client.enqueue_request(&first).unwrap(),
        Enqueued::Existing(RequestStatus::Queued)
    );
    // The same identity with different content is an invalid request.
    assert!(matches!(
        client.enqueue_request(&apply_request("request_1", "plan_2")),
        Err(OperationJournalError::Conflict)
    ));
    assert_eq!(client.enqueue_request(&second).unwrap(), Enqueued::New);

    // No claim without a registered coordinator.
    let mut agent = fixture.open();
    let error = agent.claim_next_request(&epoch("epoch_1")).unwrap_err();
    assert!(is_sequence(&error, &SequenceViolation::ExecutorEpoch));
    let lock = CoordinatorLock::try_acquire(&fixture.path()).unwrap();
    agent
        .begin_coordination(&lock, &epoch("epoch_1"), wall(2))
        .unwrap();

    // Two connections of the coordinator claim: each request goes to one
    // claimer, the oldest first.
    let mut worker = fixture.open();
    let claimed_first = agent.claim_next_request(&epoch("epoch_1")).unwrap();
    let claimed_second = worker.claim_next_request(&epoch("epoch_1")).unwrap();
    assert_eq!(
        claimed_first,
        Some(ClaimedRequest {
            request: first.clone(),
            redelivered: false
        })
    );
    assert_eq!(
        claimed_second,
        Some(ClaimedRequest {
            request: second.clone(),
            redelivered: false
        })
    );
    assert_eq!(agent.claim_next_request(&epoch("epoch_1")).unwrap(), None);
    assert_eq!(worker.claim_next_request(&epoch("epoch_1")).unwrap(), None);
    assert_eq!(
        client.request_status(&first.request_id).unwrap(),
        Some(RequestStatus::Claimed {
            executor_epoch: epoch("epoch_1")
        })
    );
    assert_eq!(
        client.enqueue_request(&first).unwrap(),
        Enqueued::Existing(RequestStatus::Claimed {
            executor_epoch: epoch("epoch_1")
        })
    );

    // The completion.
    let done = RequestCompletion::Operation {
        operation_id: operation_id("operation_1"),
    };
    let error = agent
        .complete_request(&first.request_id, &epoch("epoch_0"), &done)
        .unwrap_err();
    assert!(is_sequence(&error, &SequenceViolation::Claim));
    assert!(matches!(
        agent.complete_request(&request_id("request_9"), &epoch("epoch_1"), &done),
        Err(OperationJournalError::NotFound)
    ));
    agent
        .complete_request(&first.request_id, &epoch("epoch_1"), &done)
        .unwrap();
    agent
        .complete_request(&first.request_id, &epoch("epoch_1"), &done)
        .unwrap();
    let stopped = RequestCompletion::Stopped {
        fence: StopFence::CurrentInstance,
    };
    assert!(matches!(
        agent.complete_request(&first.request_id, &epoch("epoch_1"), &stopped),
        Err(OperationJournalError::Conflict)
    ));
    worker
        .complete_request(&second.request_id, &epoch("epoch_1"), &stopped)
        .unwrap();
    assert_eq!(
        client.request_status(&first.request_id).unwrap(),
        Some(RequestStatus::Completed { completion: done })
    );
    assert_eq!(
        client.request_status(&second.request_id).unwrap(),
        Some(RequestStatus::Completed {
            completion: stopped
        })
    );

    // A prune removes the completed requests.
    assert_eq!(client.prune(wall(100), 10).unwrap().requests, 2);
    assert_eq!(client.request_status(&first.request_id).unwrap(), None);
}

#[test]
fn a_request_that_a_stopped_coordinator_claimed_is_delivered_again() {
    let fixture = Fixture::new();
    let mut journal = fixture.open();
    let lock = CoordinatorLock::try_acquire(&fixture.path()).unwrap();
    journal
        .begin_coordination(&lock, &epoch("epoch_1"), wall(0))
        .unwrap();
    let request = apply_request("request_1", "plan_1");
    let rejected = apply_request("request_2", "plan_2");
    journal.enqueue_request(&request).unwrap();
    journal.enqueue_request(&rejected).unwrap();
    assert!(
        journal
            .claim_next_request(&epoch("epoch_1"))
            .unwrap()
            .is_some()
    );
    assert!(
        journal
            .claim_next_request(&epoch("epoch_1"))
            .unwrap()
            .is_some()
    );
    let rejection = RequestCompletion::Rejected {
        error: failure(ErrorFamily::Authority, DispatchState::NotSubmitted),
    };
    journal
        .complete_request(&rejected.request_id, &epoch("epoch_1"), &rejection)
        .unwrap();

    // The coordinator stops with the first request claimed.
    drop((journal, lock));
    let mut journal = fixture.open();
    let lock = CoordinatorLock::try_acquire(&fixture.path()).unwrap();
    let start = journal
        .begin_coordination(&lock, &epoch("epoch_2"), wall(5))
        .unwrap();
    assert_eq!(start.requeued_requests, 1);
    assert_eq!(
        journal.request_status(&request.request_id).unwrap(),
        Some(RequestStatus::Queued)
    );
    // The earlier lifetime cannot claim or complete.
    let error = journal.claim_next_request(&epoch("epoch_1")).unwrap_err();
    assert!(is_sequence(&error, &SequenceViolation::ExecutorEpoch));
    assert_eq!(
        journal.claim_next_request(&epoch("epoch_2")).unwrap(),
        Some(ClaimedRequest {
            request: request.clone(),
            redelivered: true
        })
    );
    let error = journal
        .complete_request(
            &request.request_id,
            &epoch("epoch_1"),
            &RequestCompletion::Operation {
                operation_id: operation_id("operation_1"),
            },
        )
        .unwrap_err();
    assert!(is_sequence(&error, &SequenceViolation::Claim));
    // The completed request stays completed.
    assert_eq!(
        journal.request_status(&rejected.request_id).unwrap(),
        Some(RequestStatus::Completed {
            completion: rejection
        })
    );
    assert_eq!(journal.claim_next_request(&epoch("epoch_2")).unwrap(), None);
}

#[test]
fn the_queue_has_a_bounded_number_of_open_requests() {
    let fixture = Fixture::new();
    let mut journal: OperationJournal = fixture.open();
    for index in 0..MAX_OPEN_REQUESTS {
        let request = apply_request(&format!("request_{index}"), "plan_1");
        assert_eq!(journal.enqueue_request(&request).unwrap(), Enqueued::New);
    }
    let over = apply_request("request_over", "plan_1");
    let error = journal.enqueue_request(&over).unwrap_err();
    assert!(matches!(
        error,
        OperationJournalError::QueueFull { limit } if limit == MAX_OPEN_REQUESTS
    ));
    assert_eq!(error.to_journal_error(), JournalError::Full);
    assert_eq!(journal.request_status(&over.request_id).unwrap(), None);
    // A request that is in the queue is answered.
    assert_eq!(
        journal
            .enqueue_request(&apply_request("request_0", "plan_1"))
            .unwrap(),
        Enqueued::Existing(RequestStatus::Queued)
    );

    // A completed request makes a place.
    let lock = CoordinatorLock::try_acquire(&fixture.path()).unwrap();
    journal
        .begin_coordination(&lock, &epoch("epoch_1"), wall(0))
        .unwrap();
    let claimed = journal
        .claim_next_request(&epoch("epoch_1"))
        .unwrap()
        .unwrap();
    journal
        .complete_request(
            &claimed.request.request_id,
            &epoch("epoch_1"),
            &RequestCompletion::Stopped {
                fence: StopFence::Durable,
            },
        )
        .unwrap();
    assert_eq!(journal.enqueue_request(&over).unwrap(), Enqueued::New);
}

#[test]
fn a_prune_keeps_a_plan_that_an_open_request_names() {
    let fixture = Fixture::new();
    let mut journal = fixture.open();
    let named = file_plan("plan_1", 1);
    let unused = file_plan("plan_2", 1);
    journal.record_plan(&named).unwrap();
    journal.record_plan(&unused).unwrap();
    journal
        .enqueue_request(&apply_request("request_1", "plan_1"))
        .unwrap();

    assert_eq!(journal.prune(wall(100), 10).unwrap().unused_plans, 1);
    assert_eq!(journal.plan(&named.plan_id), Ok(Some(named)));
    assert_eq!(journal.plan(&unused.plan_id), Ok(None));
    // The request stays open.
    assert_eq!(
        journal.request_status(&request_id("request_1")).unwrap(),
        Some(RequestStatus::Queued)
    );
}
