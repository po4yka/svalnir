//! Fail-closed behavior: a full database, a failed commit, a locked
//! database, and the size limits.

use rusqlite::Connection;
use rusqlite::ffi;
use svalnir_core::action::{
    Admission, DispatchConsumption, DispatchState, Durability, ErrorFamily, Journal, JournalError,
    Operation, StepState, TargetEffect,
};
use svalnir_core::id::RequestId;
use svalnir_core::quantity::Bytes;

use super::super::{
    AdmissionStop, Enqueued, JournalOptions, OperationJournal, OperationJournalError,
    QueuedRequest, RequestBody,
};
use super::{
    Fixture, admit, approval, dispatch, envelope, failure, file_plan, new_operation, options,
    principal, result, step_id, wall,
};

fn inject(journal: &mut OperationJournal, code: std::ffi::c_int) {
    journal.commit_fault.code = Some(code);
}

fn request(id: &str) -> QueuedRequest {
    QueuedRequest {
        request_id: RequestId::new(id).unwrap(),
        principal: principal(),
        body: RequestBody::Apply {
            approval: approval(&file_plan("plan_1", 1)),
        },
        enqueued_at: wall(0),
    }
}

/// Sets the hard limit of the connection to the current size of the
/// database and removes the admission reserve, so that only `SQLite`
/// refuses a write.
fn fill(journal: &mut OperationJournal) {
    let pages: i64 = journal
        .connection
        .pragma_query_value(None, "page_count", |row| row.get(0))
        .unwrap();
    let applied: i64 = journal
        .connection
        .pragma_update_and_check(None, "max_page_count", pages, |row| row.get(0))
        .unwrap();
    assert_eq!(applied, pages);
    journal.limits.reserve_pages = 0;
}

#[test]
fn each_storage_failure_has_its_own_error() {
    let error = |code: std::ffi::c_int| -> OperationJournalError {
        rusqlite::Error::SqliteFailure(ffi::Error::new(code), None).into()
    };
    assert!(matches!(
        error(ffi::SQLITE_FULL),
        OperationJournalError::Full(_)
    ));
    assert!(matches!(
        error(ffi::SQLITE_BUSY),
        OperationJournalError::Busy(_)
    ));
    assert!(matches!(
        error(ffi::SQLITE_LOCKED),
        OperationJournalError::Busy(_)
    ));
    assert!(matches!(
        error(ffi::SQLITE_CORRUPT),
        OperationJournalError::Corrupt(_)
    ));
    assert!(matches!(
        error(ffi::SQLITE_NOTADB),
        OperationJournalError::Corrupt(_)
    ));
    for code in [
        ffi::SQLITE_IOERR,
        ffi::SQLITE_IOERR_FSYNC,
        ffi::SQLITE_CANTOPEN,
    ] {
        assert!(matches!(error(code), OperationJournalError::Io(_)));
    }
    assert!(matches!(
        error(ffi::SQLITE_READONLY),
        OperationJournalError::ReadOnly(_)
    ));
    assert!(matches!(
        error(ffi::SQLITE_NOMEM),
        OperationJournalError::Sqlite(_)
    ));

    // The value of the interface. No failure is a success, and each one
    // is a recording failure.
    for (code, expected) in [
        (ffi::SQLITE_FULL, JournalError::Full),
        (ffi::SQLITE_IOERR_FSYNC, JournalError::Sync),
        (ffi::SQLITE_CORRUPT, JournalError::Corrupt),
        (ffi::SQLITE_BUSY, JournalError::Unavailable),
        (ffi::SQLITE_READONLY, JournalError::Unavailable),
        (ffi::SQLITE_NOMEM, JournalError::Unavailable),
    ] {
        let error = error(code);
        assert!(error.is_storage_failure());
        assert_eq!(error.to_journal_error(), expected);
        assert_eq!(error.to_journal_error().family(), ErrorFamily::Recording);
    }
    for stop in [AdmissionStop::Database, AdmissionStop::WriteAheadLog] {
        let error = OperationJournalError::AdmissionStopped(stop);
        assert_eq!(error.to_journal_error(), JournalError::Full);
    }
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one scenario: each part needs the state that the part before it made"
)]
fn a_failed_commit_records_nothing_at_each_write_point() {
    let fixture = Fixture::new();
    let mut journal = fixture.open();
    let plan = file_plan("plan_1", 2);
    let mut operation = new_operation(&plan, "operation_1", "epoch_1", Durability::Durable);
    let id = operation.operation_id().clone();
    let s0 = step_id("s0");
    let full = ffi::SQLITE_FULL;

    // The plan.
    inject(&mut journal, full);
    assert_eq!(journal.record_plan(&plan), Err(JournalError::Full));
    assert_eq!(journal.plan(&plan.plan_id), Ok(None));
    journal.record_plan(&plan).unwrap();

    // The rejection: a later apply is not rejected by a record that was
    // not written.
    inject(&mut journal, full);
    let rejection = failure(ErrorFamily::Authority, DispatchState::NotSubmitted);
    assert_eq!(
        journal.record_rejection(&approval(&plan), &principal(), &rejection),
        Err(JournalError::Full)
    );

    // The admission: no operation and no plan consumption.
    inject(&mut journal, full);
    assert_eq!(
        journal.admit(&approval(&plan), &principal(), &operation),
        Err(JournalError::Full)
    );
    assert_eq!(journal.operation(&id), Ok(None));
    assert_eq!(
        journal.admit(&approval(&plan), &principal(), &operation),
        Ok(Admission::Admitted)
    );

    // The intent: the step stays `Admitted`, and its dispatch cannot be
    // consumed.
    let intent = envelope(&plan, &operation, "s0");
    inject(&mut journal, ffi::SQLITE_IOERR_FSYNC);
    assert_eq!(journal.commit_intent(&intent), Err(JournalError::Sync));
    assert_eq!(journal.operation(&id), Ok(Some(operation.clone())));
    assert_eq!(
        journal.consume_dispatch(&id, &s0),
        Err(JournalError::Sequence)
    );
    journal.commit_intent(&intent).unwrap();
    operation
        .advance_step(
            &s0,
            StepState::IntentCommitted,
            DispatchState::NotSubmitted,
            Durability::Durable,
        )
        .unwrap();

    // The dispatch consumption: the call returns an error and no receipt,
    // so the caller submits nothing. The step is not recorded as
    // dispatched, in this connection and in a different one.
    inject(&mut journal, full);
    assert_eq!(journal.consume_dispatch(&id, &s0), Err(JournalError::Full));
    assert_eq!(journal.operation(&id), Ok(Some(operation.clone())));
    let second = fixture.open();
    assert_eq!(second.operation(&id), Ok(Some(operation.clone())));
    let records = second.recovery_records(10).unwrap();
    assert!(!records[0].unsettled_steps[0].dispatch_consumed);
    drop(second);
    // The next call consumes the step: the failed call consumed nothing.
    assert_eq!(
        journal.consume_dispatch(&id, &s0).unwrap().consumption,
        DispatchConsumption::Consumed
    );
    operation
        .advance_step(
            &s0,
            StepState::DispatchConsumed,
            DispatchState::NotSubmitted,
            Durability::Durable,
        )
        .unwrap();

    // The submission and the outcome.
    operation
        .advance_step(
            &s0,
            StepState::Verifying,
            DispatchState::Submitted,
            Durability::Durable,
        )
        .unwrap();
    inject(&mut journal, full);
    assert_eq!(
        journal.record_step(&id, operation.step(&s0).unwrap()),
        Err(JournalError::Full)
    );
    let stored = journal.operation(&id).unwrap().unwrap();
    assert_eq!(
        stored.step(&s0).unwrap().progress().state(),
        &StepState::DispatchConsumed
    );
    journal
        .record_step(&id, operation.step(&s0).unwrap())
        .unwrap();

    // The operation record.
    for (step, target) in [("s0", "t0"), ("s1", "t1")] {
        let effect = if step == "s0" {
            TargetEffect::Removed
        } else {
            TargetEffect::Skipped
        };
        operation
            .settle_step(
                &step_id(step),
                vec![result(target, effect, Durability::Durable)],
                Durability::Durable,
            )
            .unwrap();
    }
    operation.settle().unwrap();
    inject(&mut journal, full);
    assert_eq!(
        journal.record_operation(&operation),
        Err(JournalError::Full)
    );
    let stored = journal.operation(&id).unwrap().unwrap();
    assert!(!stored.state().is_settled());
    assert_eq!(
        stored.step(&s0).unwrap().progress().state(),
        &StepState::Verifying
    );
    assert_eq!(journal.unsettled_operations(10).unwrap().len(), 1);

    // The stop fence: the caller then reports a current-instance stop.
    inject(&mut journal, full);
    assert_eq!(journal.set_stop_fence(&id), Err(JournalError::Full));
    assert_eq!(journal.has_stop_fence(&id), Ok(false));

    // The request queue.
    inject(&mut journal, full);
    assert!(matches!(
        journal.enqueue_request(&request("request_1")),
        Err(OperationJournalError::Full(_))
    ));
    assert_eq!(
        journal
            .request_status(&RequestId::new("request_1").unwrap())
            .unwrap(),
        None
    );

    // Each call works after the failures, and the record is complete.
    journal.record_operation(&operation).unwrap();
    assert_eq!(journal.operation(&id), Ok(Some(operation)));
}

#[test]
fn a_full_database_refuses_the_plan_the_admission_and_the_intent() {
    let fixture = Fixture::new();
    let mut journal = fixture.open();
    let plan = file_plan("plan_1", 120);
    let operation = admit(&mut journal, &plan, "operation_1", "epoch_1");
    let id = operation.operation_id().clone();
    let large = file_plan("plan_2", 200);
    let stored_large = file_plan("plan_3", 200);
    journal.record_plan(&stored_large).unwrap();
    fill(&mut journal);

    // A plan and an admission need new pages.
    let error = journal.try_record_plan(&large).unwrap_err();
    assert!(matches!(error, OperationJournalError::Full(_)), "{error:?}");
    assert_eq!(journal.plan(&large.plan_id), Ok(None));
    let pending = new_operation(&stored_large, "operation_3", "epoch_1", Durability::Durable);
    assert_eq!(
        journal.admit(&approval(&stored_large), &principal(), &pending),
        Err(JournalError::Full)
    );
    assert_eq!(journal.operation(pending.operation_id()), Ok(None));

    // The intents fill the free space of the step pages. From the first
    // intent that `SQLite` refuses, no intent is recorded, and no dispatch
    // of those steps can be consumed.
    let mut recorded: u64 = 0;
    let mut refused: u64 = 0;
    for index in 0..120_u64 {
        let step = format!("s{index}");
        match journal.commit_intent(&envelope(&plan, &operation, &step)) {
            Ok(()) => {
                assert_eq!(refused, 0, "an intent was recorded after a refusal");
                recorded += 1;
            }
            Err(error) => {
                assert_eq!(error, JournalError::Full);
                refused += 1;
                assert_eq!(
                    journal.consume_dispatch(&id, &step_id(&step)),
                    Err(JournalError::Sequence)
                );
            }
        }
    }
    assert!(refused > 0, "the limit refused no intent");
    let stored = journal.operation(&id).unwrap().unwrap();
    let committed = stored
        .steps()
        .iter()
        .filter(|step| matches!(step.progress().state(), StepState::IntentCommitted))
        .count();
    assert_eq!(u64::try_from(committed).unwrap(), recorded);
    let records = journal.recovery_records(10).unwrap();
    assert!(
        records[0]
            .unsettled_steps
            .iter()
            .all(|step| !step.dispatch_consumed
                && step.intent.is_some()
                    == matches!(step.step.progress().state(), StepState::IntentCommitted))
    );

    // The database is in order, and a larger limit accepts the writes.
    drop(journal);
    let mut journal = fixture.open();
    assert_eq!(journal.operation(&id), Ok(Some(stored)));
    journal.record_plan(&large).unwrap();
}

#[test]
fn a_full_database_keeps_the_last_recorded_state_of_a_step() {
    let fixture = Fixture::new();
    let mut journal = fixture.open();
    let plan = file_plan("plan_1", 150);
    let mut operation = admit(&mut journal, &plan, "operation_1", "epoch_1");
    let id = operation.operation_id().clone();
    for index in 0..150_u64 {
        dispatch(&mut journal, &plan, &mut operation, &format!("s{index}"));
    }
    fill(&mut journal);

    // Each outcome makes its step record larger. From the first outcome
    // that `SQLite` refuses, the journal keeps `DispatchConsumed`: it does
    // not report an outcome that it did not record.
    let mut refused: u64 = 0;
    let mut memory: Operation = operation.clone();
    for index in 0..150_u64 {
        let step = step_id(&format!("s{index}"));
        memory
            .advance_step(
                &step,
                StepState::Verifying,
                DispatchState::Submitted,
                Durability::Durable,
            )
            .unwrap();
        memory
            .settle_step(
                &step,
                // Several results, so that the record needs a new page.
                vec![
                    result(
                        &format!("t{index}"),
                        TargetEffect::Removed,
                        Durability::Durable,
                    );
                    12
                ],
                Durability::Durable,
            )
            .unwrap();
        match journal.record_step(&id, memory.step(&step).unwrap()) {
            Ok(()) => assert_eq!(refused, 0, "an outcome was recorded after a refusal"),
            Err(error) => {
                assert_eq!(error, JournalError::Full);
                refused += 1;
                let stored = journal.operation(&id).unwrap().unwrap();
                assert_eq!(
                    stored.step(&step).unwrap().progress().state(),
                    &StepState::DispatchConsumed
                );
            }
        }
    }
    assert!(refused > 0, "the limit refused no outcome");
    // The consumptions stay: no step can be dispatched again.
    assert_eq!(
        journal
            .consume_dispatch(&id, &step_id("s149"))
            .unwrap()
            .consumption,
        DispatchConsumption::AlreadyConsumed
    );
}

#[test]
fn a_locked_database_is_reported_as_busy_and_records_nothing() {
    let fixture = Fixture::new();
    let mut journal = fixture.open();
    let plan = file_plan("plan_1", 1);
    let operation = admit(&mut journal, &plan, "operation_1", "epoch_1");
    let id = operation.operation_id().clone();
    journal
        .commit_intent(&envelope(&plan, &operation, "s0"))
        .unwrap();

    let other = Connection::open(fixture.path()).unwrap();
    other.execute_batch("BEGIN IMMEDIATE").unwrap();
    let error = journal
        .try_consume_dispatch(&id, &step_id("s0"))
        .unwrap_err();
    assert!(matches!(error, OperationJournalError::Busy(_)), "{error:?}");
    assert_eq!(error.to_journal_error(), JournalError::Unavailable);
    assert_eq!(journal.set_stop_fence(&id), Err(JournalError::Unavailable));
    // A read does not wait for the writer.
    assert_eq!(journal.has_stop_fence(&id), Ok(false));
    other.execute_batch("ROLLBACK").unwrap();

    assert_eq!(
        journal
            .consume_dispatch(&id, &step_id("s0"))
            .unwrap()
            .consumption,
        DispatchConsumption::Consumed
    );
}

#[test]
fn new_work_stops_before_the_hard_limit_and_admitted_work_continues() {
    let fixture = Fixture::new();
    let mut journal = fixture.open();
    let plan = file_plan("plan_1", 1);
    let mut operation = admit(&mut journal, &plan, "operation_1", "epoch_1");
    let stored = file_plan("plan_2", 1);
    journal.record_plan(&stored).unwrap();
    drop(journal);

    // The reserve is as large as the limit: no free space is for new work.
    let limit = Bytes::new(1024 * 1024);
    let mut journal = fixture.open_with(&JournalOptions {
        max_database_size: limit,
        admission_reserve: limit,
        ..options()
    });
    let stopped = |error: OperationJournalError| {
        assert!(
            matches!(
                error,
                OperationJournalError::AdmissionStopped(AdmissionStop::Database)
            ),
            "{error:?}"
        );
        assert!(error.is_storage_failure());
    };
    stopped(
        journal
            .try_record_plan(&file_plan("plan_3", 1))
            .unwrap_err(),
    );
    let pending = new_operation(&stored, "operation_2", "epoch_1", Durability::Durable);
    stopped(
        journal
            .try_admit(&approval(&stored), &principal(), &pending)
            .unwrap_err(),
    );
    assert_eq!(
        journal.admit(&approval(&stored), &principal(), &pending),
        Err(JournalError::Full)
    );
    let rejection = failure(ErrorFamily::Authority, DispatchState::NotSubmitted);
    stopped(
        journal
            .try_record_rejection(&approval(&stored), &principal(), &rejection)
            .unwrap_err(),
    );
    stopped(journal.enqueue_request(&request("request_1")).unwrap_err());
    assert_eq!(journal.operation(pending.operation_id()), Ok(None));
    assert_eq!(journal.plan(&file_plan("plan_3", 1).plan_id), Ok(None));

    // The records of the admitted operation use the reserve.
    dispatch(&mut journal, &plan, &mut operation, "s0");
    super::complete(&mut journal, &mut operation, "s0", "t0");
    operation.settle().unwrap();
    journal.record_operation(&operation).unwrap();
    // A repeated apply of a consumed plan is a read, and it is answered.
    assert!(matches!(
        journal.admit(&approval(&plan), &principal(), &operation),
        Ok(Admission::Existing { .. })
    ));
    drop(journal);

    // A write-ahead log above its limit stops new work also.
    let mut journal = fixture.open_with(&JournalOptions {
        max_wal_size: Bytes::new(0),
        ..options()
    });
    journal.set_stop_fence(operation.operation_id()).unwrap();
    assert!(journal.size().unwrap().write_ahead_log.get() > 0);
    let error = journal
        .try_record_plan(&file_plan("plan_3", 1))
        .unwrap_err();
    assert!(matches!(
        error,
        OperationJournalError::AdmissionStopped(AdmissionStop::WriteAheadLog)
    ));
    // A complete checkpoint cuts the log, and the journal has no function
    // that makes the database file smaller.
    assert!(journal.checkpoint().unwrap());
    assert_eq!(journal.size().unwrap().write_ahead_log.get(), 0);
    assert_eq!(
        journal.enqueue_request(&request("request_1")).unwrap(),
        Enqueued::New
    );
}
