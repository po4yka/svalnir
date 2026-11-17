//! The `Journal` interface on the durable path, the revisions, the
//! recovery queries, and the retention.

use rusqlite::Connection;
use svalnir_core::action::{
    ActionClass, Admission, Checked, DispatchConsumption, DispatchState, Durability, ErrorFamily,
    Escalation, Journal, JournalError, Operation, OperationState, Plan, StepState, TargetEffect,
    TriggerClass,
};
use svalnir_core::authority::{ActionGrant, ActionGrantRef, Generation, PolicyRevision};
use svalnir_core::digest::ContentDigest;
use svalnir_core::file::LosslessPath;
use svalnir_core::id::{ActionGrantId, PlanId, PolicyRevisionId, RuleId, RuleRevisionId};
use svalnir_core::policy::RebuildCost;
use svalnir_core::process::Uid;
use svalnir_core::quantity::Nanoseconds;
use svalnir_core::rule::{
    ActivityCheck, ActivityProtocol, AgeBasis, ApprovedRoot, DeletionMethod, LayoutSupport,
    LifecycleState, OwnerAttribution, Retention, RootBase, Rule, RuleBudget, RuleDeclaration,
    RuleExclusions, RuleMode, RuleOwner, RuleRef,
};

use super::super::migration::{APPLICATION_ID, MIGRATIONS, Migration};
use super::super::{
    JOURNAL_VERSION, JournalOptions, MAX_REVISION_SOURCE_BYTES, OperationJournal,
    OperationJournalError, RecoveryPosition, SequenceViolation,
};
use super::{
    Fixture, admit, approval, charge, complete, dispatch, envelope, envelope_content, epoch,
    failure, file_content, file_plan, incident, new_operation, operation_id, options,
    other_principal, principal, result, step_id, wall,
};

fn pragma(journal: &OperationJournal, name: &str) -> i64 {
    journal
        .connection
        .pragma_query_value(None, name, |row| row.get(0))
        .unwrap()
}

// Open, settings, and migrations.

#[test]
fn the_open_sets_and_verifies_the_writer_settings() {
    let fixture = Fixture::new();
    let journal = fixture.open_with(&JournalOptions::default());
    let mode: String = journal
        .connection
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .unwrap();
    assert_eq!(mode, "wal");
    assert_eq!(pragma(&journal, "synchronous"), 2);
    assert_eq!(pragma(&journal, "fullfsync"), 1);
    assert_eq!(pragma(&journal, "checkpoint_fullfsync"), 1);
    assert_eq!(pragma(&journal, "foreign_keys"), 1);
    assert_eq!(pragma(&journal, "wal_autocheckpoint"), 1000);
    assert_eq!(journal.version().unwrap(), JOURNAL_VERSION);
    let size = journal.size().unwrap();
    assert_eq!(
        size.limit.get() / size.page_size.get(),
        64 * 1024 * 1024 / 4096
    );
    assert!(size.used.get() > 0 && size.used <= size.database);
    drop(journal);

    // The option sets the two `F_FULLFSYNC` settings off, and nothing else.
    let journal = fixture.open();
    assert_eq!(pragma(&journal, "synchronous"), 2);
    assert_eq!(pragma(&journal, "fullfsync"), 0);
    assert_eq!(pragma(&journal, "checkpoint_fullfsync"), 0);
}

#[test]
fn a_path_that_is_not_a_durable_file_is_refused() {
    for path in ["", ":memory:"] {
        let error = OperationJournal::open(path.as_ref(), &options()).unwrap_err();
        assert!(matches!(error, OperationJournalError::InvalidPath(_)));
    }
    // The journal makes no directory.
    let fixture = Fixture::new();
    let missing = fixture
        .directory
        .path()
        .join("missing")
        .join("operations.sqlite");
    let error = OperationJournal::open(&missing, &options()).unwrap_err();
    assert!(matches!(error, OperationJournalError::Io(_)), "{error:?}");
    assert!(!missing.parent().unwrap().exists());
}

#[test]
fn a_database_of_a_newer_build_is_refused_and_not_changed() {
    let fixture = Fixture::new();
    drop(fixture.open());
    let raw = Connection::open(fixture.path()).unwrap();
    raw.pragma_update(None, "user_version", JOURNAL_VERSION + 1)
        .unwrap();
    let objects = |raw: &Connection| -> i64 {
        raw.query_row("SELECT count(*) FROM sqlite_schema", [], |row| row.get(0))
            .unwrap()
    };
    let before = objects(&raw);

    let error = OperationJournal::open(&fixture.path(), &options()).unwrap_err();
    assert!(matches!(
        error,
        OperationJournalError::NewerVersion { found, supported }
            if found == JOURNAL_VERSION + 1 && supported == JOURNAL_VERSION
    ));
    assert_eq!(error.to_journal_error(), JournalError::Unavailable);
    let version: i64 = raw
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(version, i64::from(JOURNAL_VERSION + 1));
    assert_eq!(objects(&raw), before);
}

#[test]
fn a_database_that_is_not_a_journal_is_refused() {
    let fixture = Fixture::new();
    let raw = Connection::open(fixture.path()).unwrap();
    raw.execute_batch("CREATE TABLE other (value TEXT)")
        .unwrap();
    let error = OperationJournal::open(&fixture.path(), &options()).unwrap_err();
    assert!(matches!(error, OperationJournalError::NotAJournal));
    // The catalog store has a different application identity.
    assert_ne!(APPLICATION_ID, 0x5356_4C4E);

    // A file that is not a database.
    let fixture = Fixture::new();
    std::fs::write(fixture.path(), vec![0x5A_u8; 8192]).unwrap();
    let error = OperationJournal::open(&fixture.path(), &options()).unwrap_err();
    assert!(
        matches!(error, OperationJournalError::Corrupt(_)),
        "{error:?}"
    );
    assert_eq!(error.to_journal_error(), JournalError::Corrupt);
}

#[test]
fn a_failed_migration_keeps_the_previous_version() {
    let fixture = Fixture::new();
    let defective = [
        MIGRATIONS[0],
        Migration {
            version: 2,
            sql: "CREATE TABLE extra (value TEXT); CREATE TABLE plan (value TEXT);",
        },
    ];
    let error = OperationJournal::open_with_migrations(&fixture.path(), &options(), &defective)
        .unwrap_err();
    assert!(matches!(
        error,
        OperationJournalError::Migration { version: 2, .. }
    ));
    let journal = fixture.open();
    assert_eq!(journal.version().unwrap(), 1);
    let extra: i64 = journal
        .connection
        .query_row(
            "SELECT count(*) FROM sqlite_schema WHERE name = 'extra'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(extra, 0);

    let out_of_order = [Migration {
        version: 2,
        sql: "",
    }];
    let error = OperationJournal::open_with_migrations(&fixture.path(), &options(), &out_of_order)
        .unwrap_err();
    assert!(matches!(
        error,
        OperationJournalError::MigrationOrder { version: 2 }
    ));
}

// Plans and admission.

#[test]
fn a_plan_is_stored_one_time_and_read_back() {
    let fixture = Fixture::new();
    let mut journal = fixture.open();
    let plan = file_plan("plan_1", 2);
    assert_eq!(journal.plan(&plan.plan_id), Ok(None));
    journal.record_plan(&plan).unwrap();
    journal.record_plan(&plan).unwrap();
    assert_eq!(journal.plan(&plan.plan_id), Ok(Some(plan.clone())));

    // The same identity with different content is not an update.
    let different = file_plan("plan_1", 3);
    assert_eq!(journal.record_plan(&different), Err(JournalError::Conflict));
    assert_eq!(journal.plan(&plan.plan_id), Ok(Some(plan.clone())));

    drop(journal);
    let journal = fixture.open();
    assert_eq!(journal.plan(&plan.plan_id), Ok(Some(plan)));
    assert_eq!(journal.plan(&PlanId::new("plan_2").unwrap()), Ok(None));
}

#[test]
fn a_plan_makes_one_operation_and_a_repeated_apply_returns_it() {
    let fixture = Fixture::new();
    let mut journal = fixture.open();
    let plan = file_plan("plan_1", 2);
    let operation = admit(&mut journal, &plan, "operation_1", "epoch_1");
    assert_eq!(
        journal.operation(operation.operation_id()),
        Ok(Some(operation.clone()))
    );
    assert_eq!(journal.operation(&operation_id("operation_9")), Ok(None));

    // A repeated apply, also with a new operation identity, returns the
    // operation of the first apply in its current state.
    let mut current = operation.clone();
    dispatch(&mut journal, &plan, &mut current, "s0");
    for id in ["operation_1", "operation_2"] {
        let again = new_operation(&plan, id, "epoch_1", Durability::Durable);
        assert_eq!(
            journal.admit(&approval(&plan), &principal(), &again),
            Ok(Admission::Existing {
                operation: Box::new(current.clone())
            })
        );
    }
    assert_eq!(journal.operation(&operation_id("operation_2")), Ok(None));
    assert_eq!(journal.unsettled_operations(10).unwrap().len(), 1);

    // An apply of a different principal is a conflict.
    let again = new_operation(&plan, "operation_3", "epoch_1", Durability::Durable);
    assert_eq!(
        journal.admit(&approval(&plan), &other_principal(), &again),
        Err(JournalError::Conflict)
    );
}

#[test]
fn an_apply_that_does_not_agree_with_the_stored_plan_is_refused() {
    let fixture = Fixture::new();
    let mut journal = fixture.open();
    let plan = file_plan("plan_1", 2);
    let operation = new_operation(&plan, "operation_1", "epoch_1", Durability::Durable);

    // The plan is not stored.
    assert_eq!(
        journal.admit(&approval(&plan), &principal(), &operation),
        Err(JournalError::NotFound)
    );
    journal.record_plan(&plan).unwrap();

    // The approval names a different digest.
    let mut wrong = approval(&plan);
    wrong.digest = ContentDigest::of_bytes(b"other");
    assert_eq!(
        journal.admit(&wrong, &principal(), &operation),
        Err(JournalError::Conflict)
    );

    // The operation is the operation of a different plan.
    let other = file_plan("plan_2", 2);
    journal.record_plan(&other).unwrap();
    let foreign = new_operation(&other, "operation_1", "epoch_1", Durability::Durable);
    assert_eq!(
        journal.admit(&approval(&plan), &principal(), &foreign),
        Err(JournalError::Conflict)
    );

    // The operation is not a new admission.
    let mut started = operation.clone();
    started
        .settle_step(
            &step_id("s0"),
            vec![result("t0", TargetEffect::Skipped, Durability::Durable)],
            Durability::Durable,
        )
        .unwrap();
    let error = journal
        .try_admit(&approval(&plan), &principal(), &started)
        .unwrap_err();
    assert!(matches!(
        error,
        OperationJournalError::Sequence(SequenceViolation::NotNewAdmission)
    ));
    assert_eq!(error.to_journal_error(), JournalError::Sequence);

    // A volatile admission does not go through the durable path.
    let critical = super::application_plan(
        "plan_3",
        TriggerClass::GlobalCriticalMemory,
        Escalation::None,
    );
    journal.record_plan(&critical).unwrap();
    let volatile = new_operation(&critical, "operation_3", "epoch_1", Durability::Volatile);
    assert_eq!(
        journal.admit(&approval(&critical), &critical.principal, &volatile),
        Err(JournalError::Sequence)
    );

    // Nothing was admitted, and the plan is not consumed.
    assert_eq!(journal.unsettled_operations(10), Ok(Vec::new()));
    assert_eq!(
        journal.admit(&approval(&plan), &principal(), &operation),
        Ok(Admission::Admitted)
    );
    // The identity of an operation is used one time.
    let reused = new_operation(&other, "operation_1", "epoch_1", Durability::Durable);
    assert_eq!(
        journal.admit(&approval(&other), &principal(), &reused),
        Err(JournalError::Conflict)
    );
}

#[test]
fn a_recorded_rejection_is_the_result_of_each_later_apply() {
    let fixture = Fixture::new();
    let mut journal = fixture.open();
    let plan = file_plan("plan_1", 1);
    let rejection = failure(ErrorFamily::Authority, DispatchState::NotSubmitted);
    assert_eq!(
        journal.record_rejection(&approval(&plan), &principal(), &rejection),
        Err(JournalError::NotFound)
    );
    journal.record_plan(&plan).unwrap();
    journal
        .record_rejection(&approval(&plan), &principal(), &rejection)
        .unwrap();
    // The first rejection stays.
    let later = failure(ErrorFamily::Limits, DispatchState::NotSubmitted);
    journal
        .record_rejection(&approval(&plan), &principal(), &later)
        .unwrap();

    let operation = new_operation(&plan, "operation_1", "epoch_1", Durability::Durable);
    assert_eq!(
        journal.admit(&approval(&plan), &principal(), &operation),
        Ok(Admission::Rejected {
            error: rejection.clone()
        })
    );
    assert_eq!(
        journal.admit(&approval(&plan), &other_principal(), &operation),
        Err(JournalError::Conflict)
    );
    assert_eq!(journal.operation(operation.operation_id()), Ok(None));

    // A plan that has an operation takes no rejection.
    let admitted = file_plan("plan_2", 1);
    admit(&mut journal, &admitted, "operation_2", "epoch_1");
    assert_eq!(
        journal.record_rejection(&approval(&admitted), &principal(), &rejection),
        Err(JournalError::Conflict)
    );
}

// The lifecycle of a step.

#[test]
fn an_operation_goes_through_its_lifecycle_and_stays_after_a_reopen() {
    let fixture = Fixture::new();
    let mut journal = fixture.open();
    let plan = file_plan("plan_1", 2);
    let mut operation = admit(&mut journal, &plan, "operation_1", "epoch_1");

    dispatch(&mut journal, &plan, &mut operation, "s0");
    assert_eq!(
        journal.operation(operation.operation_id()),
        Ok(Some(operation.clone()))
    );
    complete(&mut journal, &mut operation, "s0", "t0");
    dispatch(&mut journal, &plan, &mut operation, "s1");
    complete(&mut journal, &mut operation, "s1", "t1");
    assert_eq!(journal.unsettled_operations(10).unwrap().len(), 1);

    assert_eq!(operation.settle().unwrap(), &OperationState::Completed);
    journal.record_operation(&operation).unwrap();
    // The same record again is not an error.
    journal.record_operation(&operation).unwrap();
    assert_eq!(journal.unsettled_operations(10), Ok(Vec::new()));
    assert_eq!(journal.recovery_records(10).unwrap(), Vec::new());

    drop(journal);
    let mut journal = fixture.open();
    assert_eq!(
        journal.operation(operation.operation_id()),
        Ok(Some(operation.clone()))
    );
    // A settled operation does not change.
    assert_eq!(
        journal.record_step(
            operation.operation_id(),
            new_operation(&plan, "operation_1", "epoch_1", Durability::Durable)
                .step(&step_id("s0"))
                .unwrap()
        ),
        Err(JournalError::Sequence)
    );
    assert_eq!(
        journal.consume_dispatch(operation.operation_id(), &step_id("s0")),
        Ok(svalnir_core::action::DispatchReceipt {
            consumption: DispatchConsumption::AlreadyConsumed,
            durability: Durability::Durable,
        })
    );
}

#[test]
fn a_dispatch_is_consumed_one_time() {
    let fixture = Fixture::new();
    let mut journal = fixture.open();
    let plan = file_plan("plan_1", 2);
    let mut operation = admit(&mut journal, &plan, "operation_1", "epoch_1");
    let id = operation.operation_id().clone();

    // A step with no intent is not consumed.
    assert_eq!(
        journal.consume_dispatch(&id, &step_id("s0")),
        Err(JournalError::Sequence)
    );
    assert_eq!(
        journal.consume_dispatch(&id, &step_id("s9")),
        Err(JournalError::NotFound)
    );
    assert_eq!(
        journal.consume_dispatch(&operation_id("operation_9"), &step_id("s0")),
        Err(JournalError::NotFound)
    );

    // The same intent again is not an error. A different intent for the
    // same step is not an update.
    let intent = envelope(&plan, &operation, "s0");
    journal.commit_intent(&intent).unwrap();
    journal.commit_intent(&intent).unwrap();
    let mut changed = envelope_content(&plan, &operation, "s0");
    changed.limits.deadline = svalnir_core::time::MonotonicNanos::new(4_001);
    assert_eq!(
        journal.commit_intent(&Checked::new(changed).unwrap()),
        Err(JournalError::Conflict)
    );
    // An intent of a different executor lifetime is not an intent of this
    // operation.
    let later = new_operation(&plan, "operation_1", "epoch_2", Durability::Durable);
    assert_eq!(
        journal.commit_intent(&envelope(&plan, &later, "s1")),
        Err(JournalError::Conflict)
    );

    let consumed = |journal: &mut OperationJournal| {
        journal
            .consume_dispatch(&id, &step_id("s0"))
            .unwrap()
            .consumption
    };
    assert_eq!(consumed(&mut journal), DispatchConsumption::Consumed);
    assert_eq!(consumed(&mut journal), DispatchConsumption::AlreadyConsumed);
    // A second connection sees the consumption.
    let mut second = fixture.open();
    assert_eq!(consumed(&mut second), DispatchConsumption::AlreadyConsumed);
    assert_eq!(consumed(&mut journal), DispatchConsumption::AlreadyConsumed);

    operation
        .advance_step(
            &step_id("s0"),
            StepState::IntentCommitted,
            DispatchState::NotSubmitted,
            Durability::Durable,
        )
        .unwrap();
    operation
        .advance_step(
            &step_id("s0"),
            StepState::DispatchConsumed,
            DispatchState::NotSubmitted,
            Durability::Durable,
        )
        .unwrap();
    assert_eq!(journal.operation(&id), Ok(Some(operation)));
}

#[test]
fn a_stop_fence_inhibits_the_next_dispatch() {
    let fixture = Fixture::new();
    let mut journal = fixture.open();
    let plan = file_plan("plan_1", 2);
    let mut operation = admit(&mut journal, &plan, "operation_1", "epoch_1");
    let id = operation.operation_id().clone();
    dispatch(&mut journal, &plan, &mut operation, "s0");
    journal
        .commit_intent(&envelope(&plan, &operation, "s1"))
        .unwrap();

    assert_eq!(journal.has_stop_fence(&id), Ok(false));
    assert_eq!(
        journal.set_stop_fence(&operation_id("operation_9")),
        Err(JournalError::NotFound)
    );
    assert_eq!(
        journal.has_stop_fence(&operation_id("operation_9")),
        Err(JournalError::NotFound)
    );
    // A different connection, for example of a client, sets the fence.
    let mut client = fixture.open();
    client.set_stop_fence(&id).unwrap();
    client.set_stop_fence(&id).unwrap();
    assert_eq!(journal.has_stop_fence(&id), Ok(true));

    let receipt = journal.consume_dispatch(&id, &step_id("s1")).unwrap();
    assert_eq!(receipt.consumption, DispatchConsumption::Fenced);
    assert!(!receipt.permits_submission(
        &ActionClass::EvictRegenerableData,
        &TriggerClass::Manual,
        &svalnir_core::action::RecordingMode::Durable
    ));
    // The fenced step is not consumed, and the earlier consumption stays.
    let stored = journal.operation(&id).unwrap().unwrap();
    assert_eq!(
        stored.step(&step_id("s1")).unwrap().progress().state(),
        &StepState::IntentCommitted
    );
    assert_eq!(
        journal
            .consume_dispatch(&id, &step_id("s0"))
            .unwrap()
            .consumption,
        DispatchConsumption::AlreadyConsumed
    );
    let records = journal.recovery_records(10).unwrap();
    assert!(records[0].stop_fence);
    assert!(!records[0].unsettled_steps[1].dispatch_consumed);

    // The fence survives a restart. The outcome of the issued call is
    // recorded as it is.
    drop((journal, client));
    let mut journal = fixture.open();
    assert_eq!(journal.has_stop_fence(&id), Ok(true));
    complete(&mut journal, &mut operation, "s0", "t0");
}

#[test]
fn a_change_that_the_state_machine_does_not_permit_is_not_written() {
    let fixture = Fixture::new();
    let mut journal = fixture.open();
    let plan = file_plan("plan_1", 2);
    let operation = admit(&mut journal, &plan, "operation_1", "epoch_1");
    let id = operation.operation_id().clone();
    let s0 = step_id("s0");

    // In memory: the step goes to `Verifying` and to a result.
    let mut ahead = operation.clone();
    for (state, submitted) in [
        (StepState::IntentCommitted, DispatchState::NotSubmitted),
        (StepState::DispatchConsumed, DispatchState::NotSubmitted),
        (StepState::Verifying, DispatchState::Submitted),
    ] {
        ahead
            .advance_step(&s0, state.clone(), submitted, Durability::Durable)
            .unwrap();
        // The journal has the step as `Admitted`: no intent and no
        // consumption. It takes none of the three states.
        let error = journal
            .try_record_step(&id, ahead.step(&s0).unwrap())
            .unwrap_err();
        let expected_boundary = !matches!(state, StepState::Verifying);
        match error {
            OperationJournalError::Sequence(SequenceViolation::Boundary) => {
                assert!(expected_boundary);
            }
            OperationJournalError::Sequence(SequenceViolation::Transition(_)) => {
                assert!(!expected_boundary);
            }
            other => panic!("{other:?}"),
        }
    }
    ahead
        .settle_step(
            &s0,
            vec![result("t0", TargetEffect::Removed, Durability::Durable)],
            Durability::Durable,
        )
        .unwrap();
    assert_eq!(
        journal.record_step(&id, ahead.step(&s0).unwrap()),
        Err(JournalError::Sequence)
    );
    // An operation record with that step is refused as a whole.
    assert_eq!(
        journal.record_operation(&ahead),
        Err(JournalError::Sequence)
    );
    // A step of a different operation or with a different identity.
    assert_eq!(
        journal.record_step(&operation_id("operation_9"), ahead.step(&s0).unwrap()),
        Err(JournalError::NotFound)
    );
    let other = file_plan("plan_2", 3);
    let foreign = new_operation(&other, "operation_1", "epoch_1", Durability::Durable);
    assert_eq!(
        journal.record_step(&id, foreign.step(&step_id("s2")).unwrap()),
        Err(JournalError::NotFound)
    );
    assert_eq!(
        journal.record_operation(&foreign),
        Err(JournalError::Conflict)
    );

    // Nothing was written.
    assert_eq!(journal.operation(&id), Ok(Some(operation.clone())));
    drop(journal);
    let journal = fixture.open();
    assert_eq!(journal.operation(&id), Ok(Some(operation)));
}

#[test]
fn a_result_that_was_kept_in_memory_is_recorded_after_a_failed_write() {
    let fixture = Fixture::new();
    let mut journal = fixture.open();
    let plan = file_plan("plan_1", 1);
    let mut operation = admit(&mut journal, &plan, "operation_1", "epoch_1");
    let id = operation.operation_id().clone();
    let s0 = step_id("s0");
    dispatch(&mut journal, &plan, &mut operation, "s0");

    // The write of the submission failed. The caller kept the submission
    // and the result with the durability `persistence_failed`.
    operation
        .advance_step(
            &s0,
            StepState::Verifying,
            DispatchState::Submitted,
            Durability::PersistenceFailed,
        )
        .unwrap();
    operation
        .settle_step(
            &s0,
            vec![result(
                "t0",
                TargetEffect::Removed,
                Durability::PersistenceFailed,
            )],
            Durability::PersistenceFailed,
        )
        .unwrap();
    operation.settle().unwrap();

    // The journal has `DispatchConsumed`. It takes the result, and the
    // record keeps the durability that the caller gave.
    journal.record_operation(&operation).unwrap();
    let stored = journal.operation(&id).unwrap().unwrap();
    assert_eq!(stored, operation);
    assert_eq!(stored.durability(), Durability::PersistenceFailed);
    assert_eq!(stored.state(), &OperationState::Completed);
}

// Recovery.

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one scenario: each part needs the state that the part before it made"
)]
fn a_reopen_after_a_stop_between_intent_and_outcome_gives_the_recorded_evidence() {
    let fixture = Fixture::new();
    let mut journal = fixture.open();
    let plan = file_plan("plan_1", 4);
    let mut operation = admit(&mut journal, &plan, "operation_1", "epoch_1");
    let id = operation.operation_id().clone();

    // s0: consumed, no outcome. s1: submitted, no outcome. s2: intent
    // only. s3: admitted.
    dispatch(&mut journal, &plan, &mut operation, "s0");
    dispatch(&mut journal, &plan, &mut operation, "s1");
    operation
        .advance_step(
            &step_id("s1"),
            StepState::Verifying,
            DispatchState::Submitted,
            Durability::Durable,
        )
        .unwrap();
    journal
        .record_step(&id, operation.step(&step_id("s1")).unwrap())
        .unwrap();
    let intent = envelope(&plan, &operation, "s2");
    journal.commit_intent(&intent).unwrap();
    operation
        .advance_step(
            &step_id("s2"),
            StepState::IntentCommitted,
            DispatchState::NotSubmitted,
            Durability::Durable,
        )
        .unwrap();

    // The process stops: the connection goes away with no settled result.
    drop(journal);
    let mut journal = fixture.open();
    assert_eq!(
        journal.unsettled_operations(10),
        Ok(vec![operation.clone()])
    );
    assert_eq!(journal.unsettled_operations(0), Ok(Vec::new()));

    let records = journal.recovery_records(10).unwrap();
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(record.operation, operation);
    assert!(!record.stop_fence);
    let positions: Vec<(RecoveryPosition, bool, bool)> = record
        .unsettled_steps
        .iter()
        .map(|step| (step.position, step.dispatch_consumed, step.intent.is_some()))
        .collect();
    assert_eq!(
        positions,
        vec![
            (RecoveryPosition::DispatchConsumed, true, true),
            (RecoveryPosition::Submitted, true, true),
            (RecoveryPosition::IntentCommitted, false, true),
            (RecoveryPosition::Admitted, false, false),
        ]
    );
    assert_eq!(record.unsettled_steps[2].intent, Some(intent));

    // A consumed step is not submitted again after the restart.
    assert_eq!(
        journal
            .consume_dispatch(&id, &step_id("s0"))
            .unwrap()
            .consumption,
        DispatchConsumption::AlreadyConsumed
    );

    // Reconciliation cannot establish the effect of s0 and s1. It records
    // that, and it records that s2 and s3 issued no call.
    // The call of s0 was possibly submitted. The call of s1 was submitted.
    let unknown = result("t0", TargetEffect::UnknownOutcome, Durability::Durable);
    let mut submitted =
        result("t1", TargetEffect::UnknownOutcome, Durability::Durable).into_inner();
    submitted.dispatch = DispatchState::Submitted;
    let submitted = Checked::new(submitted).unwrap();
    for (step, outcome) in [("s0", unknown), ("s1", submitted)] {
        operation
            .settle_step(&step_id(step), vec![outcome], Durability::Durable)
            .unwrap();
    }
    for (step, target) in [("s2", "t2"), ("s3", "t3")] {
        operation
            .settle_step(
                &step_id(step),
                vec![result(target, TargetEffect::Skipped, Durability::Durable)],
                Durability::Durable,
            )
            .unwrap();
    }
    assert_eq!(operation.settle().unwrap(), &OperationState::UnknownOutcome);
    journal.record_operation(&operation).unwrap();

    // `UnknownOutcome` is kept: the operation is not settled, also after
    // another restart.
    drop(journal);
    let mut journal = fixture.open();
    let records = journal.recovery_records(10).unwrap();
    assert_eq!(
        records[0].operation.state(),
        &OperationState::UnknownOutcome
    );
    let positions: Vec<RecoveryPosition> = records[0]
        .unsettled_steps
        .iter()
        .map(|step| step.position)
        .collect();
    assert_eq!(positions, vec![RecoveryPosition::UnknownOutcome; 2]);

    // Later evidence settles one step. The operation keeps its state while
    // the other step is unknown.
    operation
        .settle_step(
            &step_id("s0"),
            vec![result("t0", TargetEffect::Removed, Durability::Durable)],
            Durability::Durable,
        )
        .unwrap();
    journal
        .record_step(&id, operation.step(&step_id("s0")).unwrap())
        .unwrap();
    let stored = journal.operation(&id).unwrap().unwrap();
    assert_eq!(stored, operation);
    assert_eq!(stored.state(), &OperationState::UnknownOutcome);
}

#[test]
fn the_unsettled_operations_are_read_the_oldest_first_to_a_limit() {
    let fixture = Fixture::new();
    let mut journal = fixture.open();
    let mut operations: Vec<Operation> = Vec::new();
    for index in 0..3 {
        let plan = file_plan(&format!("plan_{index}"), 1);
        operations.push(admit(
            &mut journal,
            &plan,
            &format!("operation_{index}"),
            "epoch_1",
        ));
    }
    assert_eq!(
        journal.unsettled_operations(2),
        Ok(operations[..2].to_vec())
    );
    assert_eq!(journal.recovery_records(1).unwrap().len(), 1);

    // A settled operation is not in the list.
    let mut first = operations[0].clone();
    first
        .settle_step(
            &step_id("s0"),
            vec![result("t0", TargetEffect::Skipped, Durability::Durable)],
            Durability::Durable,
        )
        .unwrap();
    assert_eq!(first.settle().unwrap(), &OperationState::NoAction);
    journal.record_operation(&first).unwrap();
    assert_eq!(
        journal.unsettled_operations(10),
        Ok(operations[1..].to_vec())
    );
}

#[test]
fn a_stored_record_that_is_not_consistent_is_reported_as_corrupt() {
    let fixture = Fixture::new();
    let mut journal = fixture.open();
    let plan = file_plan("plan_1", 1);
    let operation = admit(&mut journal, &plan, "operation_1", "epoch_1");
    let id = operation.operation_id().clone();

    // A state that the results do not support.
    journal
        .connection
        .execute(
            "UPDATE step SET record = json_set(record, '$.progress.state', 'Completed')",
            [],
        )
        .unwrap();
    assert_eq!(journal.operation(&id), Err(JournalError::Corrupt));
    assert_eq!(journal.unsettled_operations(10), Err(JournalError::Corrupt));
    assert!(matches!(
        journal.recovery_records(10),
        Err(OperationJournalError::Decode {
            table: "operation",
            ..
        })
    ));
    // No write uses the record.
    assert_eq!(
        journal.commit_intent(&envelope(&plan, &operation, "s0")),
        Err(JournalError::Corrupt)
    );
    assert_eq!(journal.set_stop_fence(&id), Ok(()));

    // A plan whose content does not agree with its digest.
    journal
        .connection
        .execute(
            "UPDATE plan SET content = json_set(content, '$.content.schema_version', 2)",
            [],
        )
        .unwrap();
    assert_eq!(journal.plan(&plan.plan_id), Err(JournalError::Corrupt));
}

// Revisions.

fn rule(revision: &str) -> Rule {
    Checked::new(RuleDeclaration {
        reference: RuleRef {
            id: RuleId::new("svalnir.expired-temporary").unwrap(),
            revision: RuleRevisionId::new(revision).unwrap(),
        },
        owner: RuleOwner {
            producer: "svalnir".to_owned(),
            attribution: OwnerAttribution::SvalnirLifecycleRecord,
        },
        layouts: vec![LayoutSupport {
            layout: "temporary-v1".to_owned(),
            lifecycle: LifecycleState::Proposed,
        }],
        roots: vec![ApprovedRoot {
            base: RootBase::SvalnirState,
            relative: LosslessPath::from_bytes("temporary").unwrap(),
        }],
        retention: Retention {
            age_basis: AgeBasis::SvalnirLifecycleRecord,
            minimum_age: Nanoseconds::new(3_600_000_000_000),
        },
        activity: ActivityProtocol {
            checks: vec![ActivityCheck::SealedLifecycleRecord],
            quiescence: Nanoseconds::new(60_000_000_000),
            evidence_expiry: Nanoseconds::new(5_000_000_000),
        },
        exclusions: RuleExclusions {
            descendants: Vec::new(),
            supported_object_types: vec![svalnir_core::action::FileObjectType::RegularFile],
            skip_hard_linked: true,
        },
        modes: RuleMode::ALL.to_vec(),
        deletion_method: DeletionMethod::BoundedUnlink,
        executor: svalnir_core::action::ExecutorRole::User,
        rebuild_cost: RebuildCost::Low,
        budget: RuleBudget {
            per_candidate: charge(1_000_000, 100),
            per_pass: charge(10_000_000, 1_000),
        },
    })
    .unwrap()
}

fn grant(generation: u64, revoked: bool) -> ActionGrant {
    ActionGrant {
        grant_id: ActionGrantId::new("grant_1").unwrap(),
        generation: Generation::new(generation),
        principal: Uid::new(501),
        policy_revision: PolicyRevisionId::new("policy_1").unwrap(),
        action_classes: vec![ActionClass::EvictRegenerableData],
        rules: vec![rule("r1").reference.clone()],
        escalations: Vec::new(),
        allow_volatile_journal_on_critical: false,
        granted_at: wall(0),
        expires_at: None,
        revoked,
    }
}

#[test]
fn the_revisions_that_an_operation_binds_to_are_stored_and_read() {
    let fixture = Fixture::new();
    let mut journal = fixture.open();
    let policy = PolicyRevision {
        revision_id: PolicyRevisionId::new("policy_1").unwrap(),
        schema_version: 1,
        content: ContentDigest::of_bytes(b"[disk]\n"),
        activated_at: wall(0),
    };
    assert_eq!(journal.policy_revision(&policy.revision_id).unwrap(), None);
    journal
        .record_policy_revision(&policy, Some("[disk]\n"))
        .unwrap();
    journal.record_policy_revision(&policy, None).unwrap();
    journal
        .record_policy_revision(&policy, Some("[disk]\n"))
        .unwrap();
    assert!(matches!(
        journal.record_policy_revision(&policy, Some("[memory]\n")),
        Err(OperationJournalError::Conflict)
    ));
    let changed = PolicyRevision {
        schema_version: 2,
        ..policy.clone()
    };
    assert!(matches!(
        journal.record_policy_revision(&changed, None),
        Err(OperationJournalError::Conflict)
    ));
    let large = "x".repeat(MAX_REVISION_SOURCE_BYTES + 1);
    let second = PolicyRevision {
        revision_id: PolicyRevisionId::new("policy_2").unwrap(),
        ..policy.clone()
    };
    assert!(matches!(
        journal.record_policy_revision(&second, Some(&large)),
        Err(OperationJournalError::RecordTooLarge { .. })
    ));
    journal.record_policy_revision(&second, None).unwrap();

    // Each generation of a grant is its own record.
    let first = grant(1, false);
    let revoked = grant(2, true);
    journal.record_action_grant(&first).unwrap();
    journal.record_action_grant(&first).unwrap();
    journal.record_action_grant(&revoked).unwrap();
    assert!(matches!(
        journal.record_action_grant(&grant(1, true)),
        Err(OperationJournalError::Conflict)
    ));

    let r1 = rule("r1");
    journal.record_rule_revision(&r1).unwrap();
    journal.record_rule_revision(&rule("r2")).unwrap();

    // The records stay after a reopen, and after the configuration that
    // made them is gone.
    drop(journal);
    let journal = fixture.open();
    assert_eq!(
        journal.policy_revision(&policy.revision_id).unwrap(),
        Some(policy.clone())
    );
    assert_eq!(
        journal.policy_revision_source(&policy.revision_id).unwrap(),
        Some("[disk]\n".to_owned())
    );
    assert_eq!(
        journal.policy_revision_source(&second.revision_id).unwrap(),
        None
    );
    assert_eq!(
        journal.action_grant(&first.reference()).unwrap(),
        Some(first)
    );
    assert_eq!(
        journal.action_grant(&revoked.reference()).unwrap(),
        Some(revoked)
    );
    let absent = ActionGrantRef {
        grant_id: ActionGrantId::new("grant_1").unwrap(),
        generation: Generation::new(3),
    };
    assert_eq!(journal.action_grant(&absent).unwrap(), None);
    assert_eq!(journal.rule_revision(&r1.reference).unwrap(), Some(r1));
    let unknown = RuleRef {
        id: RuleId::new("xcode.inactive-derived-data").unwrap(),
        revision: RuleRevisionId::new("r1").unwrap(),
    };
    assert_eq!(journal.rule_revision(&unknown).unwrap(), None);
}

// Budget evidence and retention.

#[test]
fn the_consumed_dispatches_of_an_incident_are_read_after_a_reopen() {
    let fixture = Fixture::new();
    let mut journal = fixture.open();
    let plan = super::application_plan(
        "plan_1",
        TriggerClass::ApplicationBudget,
        Escalation::ForceAfterGrace,
    );
    let mut operation = new_operation(&plan, "operation_1", "epoch_1", Durability::Durable);
    journal.record_plan(&plan).unwrap();
    journal
        .admit(&approval(&plan), &plan.principal, &operation)
        .unwrap();
    assert_eq!(
        journal.consumed_dispatches(&incident(), 10).unwrap(),
        Vec::new()
    );
    dispatch(&mut journal, &plan, &mut operation, "graceful");
    journal
        .commit_intent(&envelope(&plan, &operation, "force"))
        .unwrap_err();

    drop(journal);
    let journal = fixture.open();
    let consumed = journal.consumed_dispatches(&incident(), 10).unwrap();
    assert_eq!(consumed.len(), 1);
    assert_eq!(consumed[0].operation_id, operation_id("operation_1"));
    assert_eq!(consumed[0].step_id, step_id("graceful"));
    assert_eq!(consumed[0].executor_epoch, epoch("epoch_1"));
    assert_eq!(consumed[0].intent, envelope(&plan, &operation, "graceful"));
    assert_eq!(
        journal.consumed_dispatches(&incident(), 0).unwrap(),
        Vec::new()
    );
    let other = svalnir_core::id::IncidentId::new("incident_2").unwrap();
    assert_eq!(journal.consumed_dispatches(&other, 10).unwrap(), Vec::new());
}

fn settle_as_no_action(journal: &mut OperationJournal, operation: &mut Operation) {
    operation
        .settle_step(
            &step_id("s0"),
            vec![result("t0", TargetEffect::Skipped, Durability::Durable)],
            Durability::Durable,
        )
        .unwrap();
    operation.settle().unwrap();
    journal.record_operation(operation).unwrap();
}

#[test]
fn a_prune_removes_settled_records_and_an_old_request_is_rejected() {
    let fixture = Fixture::new();
    let mut journal = fixture.open();
    let settled_plan = file_plan("plan_settled", 1);
    let mut settled = admit(&mut journal, &settled_plan, "operation_settled", "epoch_1");
    settle_as_no_action(&mut journal, &mut settled);
    let open_plan = file_plan("plan_open", 1);
    let open = admit(&mut journal, &open_plan, "operation_open", "epoch_1");
    let rejected_plan = file_plan("plan_rejected", 1);
    journal.record_plan(&rejected_plan).unwrap();
    let rejection = failure(ErrorFamily::Authority, DispatchState::NotSubmitted);
    journal
        .record_rejection(&approval(&rejected_plan), &principal(), &rejection)
        .unwrap();
    let unused_plan: Plan = file_plan("plan_unused", 1);
    journal.record_plan(&unused_plan).unwrap();

    // A cutoff before the records removes nothing.
    assert_eq!(
        journal.prune(wall(-10), 100).unwrap(),
        super::super::PruneReport::default()
    );
    let report = journal.prune(wall(100), 100).unwrap();
    assert_eq!(
        (report.operations, report.rejections, report.unused_plans),
        (1, 1, 1)
    );
    assert_eq!(
        journal.prune(wall(100), 100).unwrap(),
        super::super::PruneReport::default()
    );

    // The operation that is not settled stays with its plan.
    assert_eq!(journal.operation(open.operation_id()), Ok(Some(open)));
    assert_eq!(journal.plan(&open_plan.plan_id), Ok(Some(open_plan)));
    assert_eq!(journal.operation(settled.operation_id()), Ok(None));
    assert_eq!(journal.plan(&settled_plan.plan_id), Ok(None));

    // An old request for a pruned plan is rejected. It is not a new
    // request, and the plan is not stored again.
    for plan in [&settled_plan, &rejected_plan] {
        let again = new_operation(plan, "operation_again", "epoch_1", Durability::Durable);
        assert_eq!(
            journal.admit(&approval(plan), &principal(), &again),
            Err(JournalError::Expired)
        );
        assert_eq!(journal.record_plan(plan), Err(JournalError::Expired));
        assert_eq!(
            journal.record_rejection(&approval(plan), &principal(), &rejection),
            Err(JournalError::Expired)
        );
    }
    assert_eq!(
        journal.operation(&operation_id("operation_again")),
        Ok(None)
    );
    // A plan that no apply consumed has no consumption to keep.
    journal.record_plan(&unused_plan).unwrap();
    // The content of a plan with the identity of a pruned plan is not
    // read: the identity is used.
    let reused = Plan::seal(file_content("plan_settled", 2)).unwrap();
    assert_eq!(journal.record_plan(&reused), Err(JournalError::Expired));
}
