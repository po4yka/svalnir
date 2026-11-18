//! The acknowledgment of an `UnknownOutcome` operation.

use svalnir_core::action::{Durability, Journal as _, Operation, OperationState, TargetEffect};

use super::super::coordination::CoordinatorLock;
use super::super::{CoordinatorRole, OperationJournal, OperationJournalError, SequenceViolation};
use super::{
    Fixture, admit, complete, dispatch, epoch, file_plan, operation_id, other_principal, principal,
    result, step_id, wall,
};

/// Admits a one-step plan, consumes its dispatch, and records the
/// operation as `UnknownOutcome`.
fn unknown_operation(journal: &mut OperationJournal, plan: &str, id: &str) -> Operation {
    let plan = file_plan(plan, 1);
    let mut operation = admit(journal, &plan, id, "epoch_1");
    dispatch(journal, &plan, &mut operation, "s0");
    operation
        .settle_step(
            &step_id("s0"),
            vec![result(
                "t0",
                TargetEffect::UnknownOutcome,
                Durability::Durable,
            )],
            Durability::Durable,
        )
        .unwrap();
    operation.settle().unwrap();
    assert_eq!(operation.state(), &OperationState::UnknownOutcome);
    journal.record_operation(&operation).unwrap();
    operation
}

#[test]
fn an_acknowledgment_is_durable_and_repeated_and_does_not_change_the_result() {
    let fixture = Fixture::new();
    let mut journal = fixture.open();
    let lock = CoordinatorLock::try_acquire(&fixture.path(), CoordinatorRole::Client).unwrap();
    journal
        .begin_coordination(&lock, &epoch("epoch_1"), wall(0))
        .unwrap();
    let operation = unknown_operation(&mut journal, "plan_1", "operation_1");
    let id = operation.operation_id().clone();
    assert_eq!(journal.acknowledgment(&id).unwrap(), None);

    let first = journal
        .acknowledge_unknown_outcome(&id, &principal(), wall(10), &epoch("epoch_1"))
        .unwrap();
    assert!(!first.repeated);
    assert_eq!(first.acknowledgment.acknowledged_at, wall(10));
    assert_eq!(first.acknowledgment.principal, principal());
    // The recorded result stays `UnknownOutcome`.
    assert_eq!(journal.operation(&id), Ok(Some(operation.clone())));

    // A repeated acknowledgment returns the first one and writes nothing.
    let second = journal
        .acknowledge_unknown_outcome(&id, &other_principal(), wall(20), &epoch("epoch_1"))
        .unwrap();
    assert!(second.repeated);
    assert_eq!(second.acknowledgment, first.acknowledgment);

    // A new handle on the same file, as after a restart, reads it.
    drop(journal);
    let journal: OperationJournal = fixture.open();
    assert_eq!(
        journal.acknowledgment(&id).unwrap(),
        Some(first.acknowledgment)
    );
    assert_eq!(journal.operation(&id), Ok(Some(operation)));
}

#[test]
fn an_acknowledgment_of_an_unknown_operation_or_of_a_different_state_is_refused() {
    let fixture = Fixture::new();
    let mut journal = fixture.open();
    let lock = CoordinatorLock::try_acquire(&fixture.path(), CoordinatorRole::Client).unwrap();
    journal
        .begin_coordination(&lock, &epoch("epoch_1"), wall(0))
        .unwrap();
    assert!(matches!(
        journal.acknowledge_unknown_outcome(
            &operation_id("operation_9"),
            &principal(),
            wall(10),
            &epoch("epoch_1")
        ),
        Err(OperationJournalError::NotFound)
    ));

    // A settled operation.
    let plan = file_plan("plan_1", 1);
    let mut settled = admit(&mut journal, &plan, "operation_1", "epoch_1");
    dispatch(&mut journal, &plan, &mut settled, "s0");
    complete(&mut journal, &mut settled, "s0", "t0");
    settled.settle().unwrap();
    journal.record_operation(&settled).unwrap();
    // An operation that is not settled and is not `UnknownOutcome`.
    let open_plan = file_plan("plan_2", 1);
    let open = admit(&mut journal, &open_plan, "operation_2", "epoch_1");
    for operation in [&settled, &open] {
        assert!(matches!(
            journal.acknowledge_unknown_outcome(
                operation.operation_id(),
                &principal(),
                wall(10),
                &epoch("epoch_1")
            ),
            Err(OperationJournalError::Sequence(
                SequenceViolation::NotUnknownOutcome
            ))
        ));
        assert_eq!(
            journal.acknowledgment(operation.operation_id()).unwrap(),
            None
        );
    }

    // A coordinator that is not the registered one writes nothing.
    let unknown = unknown_operation(&mut journal, "plan_3", "operation_3");
    assert!(matches!(
        journal.acknowledge_unknown_outcome(
            unknown.operation_id(),
            &principal(),
            wall(10),
            &epoch("epoch_2")
        ),
        Err(OperationJournalError::Sequence(
            SequenceViolation::ExecutorEpoch
        ))
    ));
    assert_eq!(
        journal.acknowledgment(unknown.operation_id()).unwrap(),
        None
    );
}

#[test]
fn an_acknowledged_operation_is_not_read_by_a_reconciliation() {
    let fixture = Fixture::new();
    let mut journal = fixture.open();
    let lock = CoordinatorLock::try_acquire(&fixture.path(), CoordinatorRole::Client).unwrap();
    journal
        .begin_coordination(&lock, &epoch("epoch_1"), wall(0))
        .unwrap();
    let first = unknown_operation(&mut journal, "plan_1", "operation_1");
    let second = unknown_operation(&mut journal, "plan_2", "operation_2");
    assert_eq!(journal.unsettled_operation_count().unwrap(), 2);
    journal
        .acknowledge_unknown_outcome(
            first.operation_id(),
            &principal(),
            wall(10),
            &epoch("epoch_1"),
        )
        .unwrap();
    // The acknowledged operation holds nothing, and it does not use the
    // bound of a reconciliation. The other one is read.
    assert_eq!(journal.unsettled_operation_count().unwrap(), 1);
    let records = journal.recovery_records(16).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].operation.operation_id(), second.operation_id());
    // The record of the acknowledged operation does not change.
    assert_eq!(journal.operation(first.operation_id()), Ok(Some(first)));
}
