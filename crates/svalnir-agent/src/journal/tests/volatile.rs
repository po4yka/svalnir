//! The bounded in-memory record of the critical-memory exception and its
//! later write to the durable journal.

use svalnir_core::action::{
    Checked, DispatchConsumption, DispatchState, Durability, Escalation, Journal, JournalError,
    Operation, OperationState, Plan, RecordingMode, StepState, TargetEffect, TriggerClass,
    VolatileJournal, VolatileJournalError,
};

use super::super::{OperationJournalError, SequenceViolation, VolatileRecord};
use super::{
    Fixture, admit, application_plan, approval, envelope, envelope_content, epoch, file_plan,
    incident, new_operation, operation_id, result, step_id,
};

fn critical(plan: &str, escalation: Escalation) -> Plan {
    application_plan(plan, TriggerClass::GlobalCriticalMemory, escalation)
}

fn volatile_operation(plan: &Plan, id: &str, epoch_text: &str) -> Operation {
    new_operation(plan, id, epoch_text, Durability::Volatile)
}

#[test]
fn the_record_has_its_lifetime_and_its_bound() {
    let mut record = VolatileRecord::new(epoch("epoch_2"), 3);
    assert_eq!(record.executor_epoch(), &epoch("epoch_2"));
    assert_eq!(record.capacity(), 3);
    assert_eq!(record.remaining_capacity(), 3);
    assert_eq!(record.pending_operations(), Vec::new());

    // An operation reserves one place for each step.
    let first = critical("plan_1", Escalation::ForceAfterGrace);
    let operation = volatile_operation(&first, "operation_1", "epoch_2");
    record
        .register(&first, &first.principal, operation.clone())
        .unwrap();
    assert_eq!(record.remaining_capacity(), 1);
    // The same registration again reserves nothing.
    record
        .register(&first, &first.principal, operation.clone())
        .unwrap();
    assert_eq!(record.remaining_capacity(), 1);

    // An operation that does not fit is refused as a whole.
    let second = critical("plan_2", Escalation::ForceAfterGrace);
    assert_eq!(
        record.register(
            &second,
            &second.principal,
            volatile_operation(&second, "operation_2", "epoch_2")
        ),
        Err(VolatileJournalError::Full)
    );
    assert_eq!(record.remaining_capacity(), 1);
    assert!(record.operation(&operation_id("operation_2")).is_none());
    let third = critical("plan_3", Escalation::None);
    record
        .register(
            &third,
            &third.principal,
            volatile_operation(&third, "operation_3", "epoch_2"),
        )
        .unwrap();
    assert_eq!(record.remaining_capacity(), 0);
    let fourth = critical("plan_4", Escalation::None);
    assert_eq!(
        record.register(
            &fourth,
            &fourth.principal,
            volatile_operation(&fourth, "operation_4", "epoch_2")
        ),
        Err(VolatileJournalError::Full)
    );
    assert_eq!(record.pending_operations().len(), 2);

    // A place is not free again after a step has its result.
    let intent = envelope(
        &third,
        record.operation(&operation_id("operation_3")).unwrap(),
        "graceful",
    );
    record.record_intent_and_consumption(&intent).unwrap();
    assert_eq!(record.remaining_capacity(), 0);
}

#[test]
fn a_registration_is_only_for_a_new_volatile_admission_of_this_lifetime() {
    let mut record = VolatileRecord::new(epoch("epoch_2"), 8);
    let plan = critical("plan_1", Escalation::None);

    // An operation of an earlier lifetime.
    assert_eq!(
        record.register(
            &plan,
            &plan.principal,
            volatile_operation(&plan, "operation_1", "epoch_1")
        ),
        Err(VolatileJournalError::EarlierEpoch)
    );
    // A durable admission is not a record of the exception.
    assert_eq!(
        record.register(
            &plan,
            &plan.principal,
            new_operation(&plan, "operation_1", "epoch_2", Durability::Durable)
        ),
        Err(VolatileJournalError::NotPermitted)
    );
    // The operation of a different plan.
    let other = critical("plan_2", Escalation::None);
    assert_eq!(
        record.register(
            &plan,
            &plan.principal,
            volatile_operation(&other, "operation_1", "epoch_2")
        ),
        Err(VolatileJournalError::NotPermitted)
    );
    assert_eq!(record.remaining_capacity(), 8);

    record
        .register(
            &plan,
            &plan.principal,
            volatile_operation(&plan, "operation_1", "epoch_2"),
        )
        .unwrap();
    // One operation for each plan, and one plan for each identity.
    assert_eq!(
        record.register(
            &plan,
            &plan.principal,
            volatile_operation(&plan, "operation_2", "epoch_2")
        ),
        Err(VolatileJournalError::NotPermitted)
    );
    assert_eq!(
        record.register(
            &other,
            &other.principal,
            volatile_operation(&other, "operation_1", "epoch_2")
        ),
        Err(VolatileJournalError::NotPermitted)
    );
    assert_eq!(record.remaining_capacity(), 7);
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one scenario: each part needs the state that the part before it made"
)]
fn a_consumption_stays_valid_for_the_executor_lifetime() {
    let mut record = VolatileRecord::new(epoch("epoch_2"), 4);
    let plan = critical("plan_1", Escalation::ForceAfterGrace);
    let mut operation = volatile_operation(&plan, "operation_1", "epoch_2");
    let id = operation.operation_id().clone();
    let graceful = step_id("graceful");
    let intent = envelope(&plan, &operation, "graceful");

    // No record before the registration.
    assert_eq!(
        record.record_intent_and_consumption(&intent),
        Err(VolatileJournalError::NotFound)
    );
    record
        .register(&plan, &plan.principal, operation.clone())
        .unwrap();

    let receipt = record.record_intent_and_consumption(&intent).unwrap();
    assert_eq!(receipt.consumption, DispatchConsumption::Consumed);
    assert_eq!(receipt.durability, Durability::Volatile);
    assert!(receipt.permits_submission(
        &intent.action_class,
        &intent.trigger.class,
        &intent.recording
    ));
    // The step goes from `Admitted` to `DispatchConsumed`. It never has
    // the state `IntentCommitted`, which is durable.
    operation
        .advance_step(
            &graceful,
            StepState::DispatchConsumed,
            DispatchState::NotSubmitted,
            Durability::Volatile,
        )
        .unwrap();
    assert_eq!(record.operation(&id), Some(&operation));

    // A duplicate stays consumed, and it submits no second call.
    for _ in 0..2 {
        let receipt = record.record_intent_and_consumption(&intent).unwrap();
        assert_eq!(receipt.consumption, DispatchConsumption::AlreadyConsumed);
        assert!(!receipt.permits_submission(
            &intent.action_class,
            &intent.trigger.class,
            &intent.recording
        ));
    }
    // The same step with different content is not an update.
    let mut changed = envelope_content(&plan, &operation, "graceful");
    changed.limits.deadline = svalnir_core::time::MonotonicNanos::new(4_001);
    assert_eq!(
        record.record_intent_and_consumption(&Checked::new(changed).unwrap()),
        Err(VolatileJournalError::NotPermitted)
    );
    // The force step needs the result of the graceful step first.
    let force = envelope(&plan, &operation, "force");
    assert_eq!(
        record.record_intent_and_consumption(&force),
        Err(VolatileJournalError::NotPermitted)
    );

    // The outcome: the application runs after the graceful request.
    operation
        .advance_step(
            &graceful,
            StepState::Verifying,
            DispatchState::Submitted,
            Durability::Volatile,
        )
        .unwrap();
    record
        .record_step(&id, operation.step(&graceful).unwrap())
        .unwrap();
    operation
        .settle_step(
            &graceful,
            vec![result(
                "app",
                TargetEffect::StillRunning,
                Durability::Volatile,
            )],
            Durability::Volatile,
        )
        .unwrap();
    record
        .record_step(&id, operation.step(&graceful).unwrap())
        .unwrap();
    // The same record again is not an error.
    record
        .record_step(&id, operation.step(&graceful).unwrap())
        .unwrap();
    assert_eq!(record.operation(&id), Some(&operation));

    // A current-instance stop inhibits the force step.
    assert_eq!(
        record.stop(&operation_id("operation_9")),
        Err(VolatileJournalError::NotFound)
    );
    record.stop(&id).unwrap();
    let receipt = record.record_intent_and_consumption(&force).unwrap();
    assert_eq!(receipt.consumption, DispatchConsumption::Fenced);
    assert!(!receipt.permits_submission(
        &force.action_class,
        &force.trigger.class,
        &force.recording
    ));
    assert_eq!(record.operation(&id), Some(&operation));

    // The step that issued no call gets its result, and the operation
    // settles from the results.
    assert_eq!(
        record.settle_operation(&id),
        Err(VolatileJournalError::NotPermitted)
    );
    operation
        .settle_step(
            &step_id("force"),
            vec![result("app", TargetEffect::Skipped, Durability::Volatile)],
            Durability::Volatile,
        )
        .unwrap();
    record
        .record_step(&id, operation.step(&step_id("force")).unwrap())
        .unwrap();
    assert_eq!(record.settle_operation(&id), Ok(OperationState::Incomplete));
    assert_eq!(operation.settle().unwrap(), &OperationState::Incomplete);
    assert_eq!(record.operation(&id), Some(&operation));
    assert_eq!(record.pending_operations(), vec![operation.clone()]);
    assert_eq!(operation.durability(), Durability::Volatile);

    // A change that the state machine does not permit changes nothing.
    let unknown = volatile_operation(&plan, "operation_1", "epoch_2");
    assert_eq!(
        record.record_step(&id, unknown.step(&graceful).unwrap()),
        Err(VolatileJournalError::NotPermitted)
    );
    assert_eq!(
        record.record_step(
            &operation_id("operation_9"),
            unknown.step(&graceful).unwrap()
        ),
        Err(VolatileJournalError::NotFound)
    );
    assert_eq!(record.operation(&id), Some(&operation));
}

#[test]
fn a_request_of_an_earlier_lifetime_or_outside_the_exception_is_refused() {
    let plan = critical("plan_1", Escalation::None);
    let old = volatile_operation(&plan, "operation_1", "epoch_1");
    let old_intent = envelope(&plan, &old, "graceful");

    // The executor of the lifetime `epoch_1` consumed the step and
    // stopped. A new lifetime has a new, empty record.
    let mut earlier = VolatileRecord::new(epoch("epoch_1"), 4);
    earlier.register(&plan, &plan.principal, old).unwrap();
    assert_eq!(
        earlier
            .record_intent_and_consumption(&old_intent)
            .unwrap()
            .consumption,
        DispatchConsumption::Consumed
    );
    drop(earlier);
    let mut record = VolatileRecord::new(epoch("epoch_2"), 4);
    // The old request is not replayed: it is refused, and it is not a new
    // request.
    assert_eq!(
        record.record_intent_and_consumption(&old_intent),
        Err(VolatileJournalError::EarlierEpoch)
    );

    // A filesystem action has no volatile record.
    let file = file_plan("plan_2", 1);
    let file_operation = new_operation(&file, "operation_2", "epoch_2", Durability::Durable);
    assert_eq!(
        record.record_intent_and_consumption(&envelope(&file, &file_operation, "s0")),
        Err(VolatileJournalError::NotPermitted)
    );
    // An operation that an application-budget violation admitted has
    // none, and an envelope whose mode is `durable` has none.
    let budget = application_plan("plan_3", TriggerClass::ApplicationBudget, Escalation::None);
    let budget_operation = new_operation(&budget, "operation_3", "epoch_2", Durability::Durable);
    assert_eq!(
        record.record_intent_and_consumption(&envelope(&budget, &budget_operation, "graceful")),
        Err(VolatileJournalError::NotPermitted)
    );
    let current = volatile_operation(&plan, "operation_1", "epoch_2");
    record
        .register(&plan, &plan.principal, current.clone())
        .unwrap();
    let mut durable_mode = envelope_content(&plan, &current, "graceful");
    durable_mode.recording = RecordingMode::Durable;
    assert_eq!(
        record.record_intent_and_consumption(&Checked::new(durable_mode).unwrap()),
        Err(VolatileJournalError::NotPermitted)
    );
    assert_eq!(record.operation(current.operation_id()), Some(&current));
}

#[test]
fn the_volatile_records_are_written_to_the_durable_journal_later() {
    let fixture = Fixture::new();
    let mut journal = fixture.open();
    let mut record = VolatileRecord::new(epoch("epoch_2"), 4);
    let plan = critical("plan_1", Escalation::None);
    let mut operation = volatile_operation(&plan, "operation_1", "epoch_2");
    let id = operation.operation_id().clone();
    let graceful = step_id("graceful");
    let intent = envelope(&plan, &operation, "graceful");
    record
        .register(&plan, &plan.principal, operation.clone())
        .unwrap();
    record.record_intent_and_consumption(&intent).unwrap();
    for state in [StepState::DispatchConsumed, StepState::Verifying] {
        let submitted = if matches!(state, StepState::Verifying) {
            DispatchState::Submitted
        } else {
            DispatchState::NotSubmitted
        };
        operation
            .advance_step(&graceful, state, submitted, Durability::Volatile)
            .unwrap();
    }
    record
        .record_step(&id, operation.step(&graceful).unwrap())
        .unwrap();

    // The durable journal is not available: the write fails, and the
    // record stays pending.
    journal.commit_fault.code = Some(rusqlite::ffi::SQLITE_FULL);
    let error = record.persist_into(&mut journal).unwrap_err();
    assert!(matches!(error, OperationJournalError::Full(_)));
    assert_eq!(journal.operation(&id), Ok(None));
    assert_eq!(journal.plan(&plan.plan_id), Ok(None));
    assert_eq!(record.pending_operations().len(), 1);

    // The journal is available again, while the operation runs.
    assert_eq!(record.persist_into(&mut journal).unwrap().written, 1);
    assert_eq!(record.persist_into(&mut journal).unwrap().written, 0);
    assert_eq!(record.pending_operations(), Vec::new());
    let stored = journal.operation(&id).unwrap().unwrap();
    assert_eq!(stored, operation);
    // The history stays marked `volatile`.
    assert_eq!(stored.durability(), Durability::Volatile);
    assert_eq!(journal.plan(&plan.plan_id), Ok(Some(plan.clone())));
    let records = journal.recovery_records(10).unwrap();
    assert!(records[0].unsettled_steps[0].dispatch_consumed);
    assert_eq!(records[0].unsettled_steps[0].intent, Some(intent.clone()));
    // The budget evidence of the incident has the consumption.
    let consumed = journal.consumed_dispatches(&incident(), 10).unwrap();
    assert_eq!(consumed.len(), 1);
    assert_eq!(consumed[0].intent, intent);

    // The record keeps the consumption after the write.
    assert_eq!(
        record
            .record_intent_and_consumption(&intent)
            .unwrap()
            .consumption,
        DispatchConsumption::AlreadyConsumed
    );
    // The durable journal has it also: no second dispatch on that path,
    // and the plan is consumed.
    assert_eq!(
        journal
            .consume_dispatch(&id, &graceful)
            .unwrap()
            .consumption,
        DispatchConsumption::AlreadyConsumed
    );
    let again = volatile_operation(&plan, "operation_2", "epoch_2");
    assert!(matches!(
        journal.admit(&approval(&plan), &plan.principal, &again),
        Ok(svalnir_core::action::Admission::Existing { .. })
    ));

    // The later outcome is written by the next call.
    operation
        .settle_step(
            &graceful,
            vec![result(
                "app",
                TargetEffect::ExitVerified,
                Durability::Volatile,
            )],
            Durability::Volatile,
        )
        .unwrap();
    record
        .record_step(&id, operation.step(&graceful).unwrap())
        .unwrap();
    assert_eq!(record.settle_operation(&id), Ok(OperationState::Completed));
    operation.settle().unwrap();
    assert_eq!(record.persist_into(&mut journal).unwrap().written, 1);
    drop(journal);
    let mut journal = fixture.open();
    let stored = journal.operation(&id).unwrap().unwrap();
    assert_eq!(stored, operation);
    assert_eq!(stored.durability(), Durability::Volatile);
    assert_eq!(journal.unsettled_operations(10), Ok(Vec::new()));

    // The journal does not go back to an earlier state of the record.
    let stale = super::super::VolatileOperationRecord {
        plan: plan.clone(),
        principal: plan.principal.clone(),
        operation: volatile_operation(&plan, "operation_1", "epoch_2"),
        intents: Vec::new(),
    };
    assert!(matches!(
        journal.persist_volatile(&stale),
        Err(OperationJournalError::Sequence(_))
    ));
    assert_eq!(journal.operation(&id), Ok(Some(operation)));
}

#[test]
fn a_record_whose_operation_has_a_step_that_its_plan_does_not_have_is_not_written() {
    let fixture = Fixture::new();
    let mut journal = fixture.open();
    let plan = critical("plan_1", Escalation::None);
    // An operation with the identity and the digest of the plan and a
    // step that the plan does not have.
    let mut altered: serde_json::Value =
        serde_json::to_value(volatile_operation(&plan, "operation_1", "epoch_2")).unwrap();
    let step: &mut serde_json::Value = &mut altered["steps"][0];
    assert!(step["target_id"].is_string(), "{step}");
    step["target_id"] = serde_json::Value::String("target_that_the_plan_does_not_have".into());
    let other_steps = super::super::VolatileOperationRecord {
        plan: plan.clone(),
        principal: plan.principal.clone(),
        operation: serde_json::from_value(altered).unwrap(),
        intents: Vec::new(),
    };
    assert!(matches!(
        journal.persist_volatile(&other_steps),
        Err(OperationJournalError::Conflict)
    ));
    assert!(
        journal
            .operation(other_steps.operation.operation_id())
            .unwrap()
            .is_none()
    );
}

#[test]
fn a_record_that_is_not_a_volatile_record_is_not_written() {
    let fixture = Fixture::new();
    let mut journal = fixture.open();
    let plan = critical("plan_1", Escalation::None);

    // A durable admission.
    let durable = super::super::VolatileOperationRecord {
        plan: plan.clone(),
        principal: plan.principal.clone(),
        operation: new_operation(&plan, "operation_1", "epoch_2", Durability::Durable),
        intents: Vec::new(),
    };
    assert!(matches!(
        journal.persist_volatile(&durable),
        Err(OperationJournalError::Sequence(
            SequenceViolation::NotVolatile
        ))
    ));
    // A plan that is not the plan of the operation.
    let other = critical("plan_2", Escalation::None);
    let mismatched = super::super::VolatileOperationRecord {
        plan: other.clone(),
        principal: other.principal.clone(),
        operation: volatile_operation(&plan, "operation_1", "epoch_2"),
        intents: Vec::new(),
    };
    assert!(matches!(
        journal.persist_volatile(&mismatched),
        Err(OperationJournalError::Conflict)
    ));
    // An intent for a step that is not consumed.
    let admitted = volatile_operation(&plan, "operation_1", "epoch_2");
    let unconsumed = super::super::VolatileOperationRecord {
        plan: plan.clone(),
        principal: plan.principal.clone(),
        intents: vec![envelope(&plan, &admitted, "graceful")],
        operation: admitted.clone(),
    };
    assert!(matches!(
        journal.persist_volatile(&unconsumed),
        Err(OperationJournalError::Conflict)
    ));
    // A consumed step with no intent.
    let mut consumed_step = admitted;
    consumed_step
        .advance_step(
            &step_id("graceful"),
            StepState::DispatchConsumed,
            DispatchState::NotSubmitted,
            Durability::Volatile,
        )
        .unwrap();
    let no_intent = super::super::VolatileOperationRecord {
        plan: plan.clone(),
        principal: plan.principal.clone(),
        operation: consumed_step.clone(),
        intents: Vec::new(),
    };
    assert!(matches!(
        journal.persist_volatile(&no_intent),
        Err(OperationJournalError::Conflict)
    ));
    assert_eq!(journal.plan(&plan.plan_id), Ok(None));
    // A second write of the operation with a different principal.
    let other_plan = critical("plan_9", Escalation::None);
    let mut written = volatile_operation(&other_plan, "operation_9", "epoch_2");
    let intent = envelope(&other_plan, &written, "graceful");
    written
        .advance_step(
            &step_id("graceful"),
            StepState::DispatchConsumed,
            DispatchState::NotSubmitted,
            Durability::Volatile,
        )
        .unwrap();
    let mut good = super::super::VolatileOperationRecord {
        plan: other_plan.clone(),
        principal: other_plan.principal.clone(),
        operation: written,
        intents: vec![intent],
    };
    journal.persist_volatile(&good).unwrap();
    journal.persist_volatile(&good).unwrap();
    good.principal = super::other_principal();
    assert!(matches!(
        journal.persist_volatile(&good),
        Err(OperationJournalError::Conflict)
    ));
    // A plan that a durable operation consumed: the consumption check
    // refuses the volatile operation.
    admit(&mut journal, &plan, "operation_durable", "epoch_2");
    let consumed = super::super::VolatileOperationRecord {
        plan: plan.clone(),
        principal: plan.principal.clone(),
        operation: volatile_operation(&plan, "operation_1", "epoch_2"),
        intents: Vec::new(),
    };
    assert!(matches!(
        journal.persist_volatile(&consumed),
        Err(OperationJournalError::Conflict)
    ));
    assert_eq!(journal.operation(&operation_id("operation_1")), Ok(None));
    let budget = application_plan("plan_1", TriggerClass::ApplicationBudget, Escalation::None);
    assert_eq!(journal.record_plan(&budget), Err(JournalError::Conflict));
}

#[test]
fn a_durable_stop_reaches_the_volatile_record_and_a_refused_record_blocks_no_other() {
    let fixture = Fixture::new();
    let mut journal = fixture.open();
    let mut record = VolatileRecord::new(epoch("epoch_2"), 8);

    // The plan of the first operation gets a durable operation before the
    // volatile record is written: the journal refuses that record.
    let taken = critical("plan_1", Escalation::None);
    record
        .register(
            &taken,
            &taken.principal,
            volatile_operation(&taken, "operation_1", "epoch_2"),
        )
        .unwrap();
    admit(&mut journal, &taken, "operation_durable", "epoch_2");

    let plan = critical("plan_2", Escalation::ForceAfterGrace);
    let mut operation = volatile_operation(&plan, "operation_2", "epoch_2");
    let id = operation.operation_id().clone();
    let graceful = step_id("graceful");
    record
        .register(&plan, &plan.principal, operation.clone())
        .unwrap();
    // The same identity with a different principal is not a repeat.
    assert_eq!(
        record.register(&plan, &super::other_principal(), operation.clone()),
        Err(VolatileJournalError::NotPermitted)
    );
    record
        .record_intent_and_consumption(&envelope(&plan, &operation, "graceful"))
        .unwrap();

    // The refused record does not stop the write of the next one.
    let report = record.persist_into(&mut journal).unwrap();
    assert_eq!(report.written, 1);
    assert_eq!(report.refused, vec![operation_id("operation_1")]);
    assert!(journal.operation(&id).unwrap().is_some());
    assert_eq!(record.pending_operations().len(), 1);

    // A client sets a durable stop fence. The graceful request leaves the
    // application running.
    journal.set_stop_fence(&id).unwrap();
    for (state, submitted) in [
        (StepState::DispatchConsumed, DispatchState::NotSubmitted),
        (StepState::Verifying, DispatchState::Submitted),
    ] {
        operation
            .advance_step(&graceful, state, submitted, Durability::Volatile)
            .unwrap();
    }
    operation
        .settle_step(
            &graceful,
            vec![result(
                "app",
                TargetEffect::StillRunning,
                Durability::Volatile,
            )],
            Durability::Volatile,
        )
        .unwrap();
    record
        .record_step(&id, operation.step(&graceful).unwrap())
        .unwrap();

    // The next write reads the fence, and the force step is not consumed.
    assert_eq!(record.persist_into(&mut journal).unwrap().written, 1);
    let receipt = record
        .record_intent_and_consumption(&envelope(&plan, &operation, "force"))
        .unwrap();
    assert_eq!(receipt.consumption, DispatchConsumption::Fenced);
    assert_eq!(record.operation(&id), Some(&operation));
    assert_eq!(journal.operation(&id), Ok(Some(operation)));
}
