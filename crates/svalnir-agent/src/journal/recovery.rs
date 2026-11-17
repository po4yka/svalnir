//! The queries of restart reconciliation.
//!
//! A restart reads each operation that is not settled with what the
//! journal recorded before the stop. The records are evidence. They do not
//! show that an external call did or did not occur after a consumed
//! dispatch, and no function of this module changes a record.

use rusqlite::params;
use svalnir_core::action::{Operation, RequestEnvelope, Step, StepState};
use svalnir_core::id::{ExecutorEpochId, IncidentId, OperationId, StepId};

use super::error::OperationJournalError;
use super::{OperationJournal, decode, durable, row};

/// The last trustworthy record of a step that is not settled, as the
/// recovery matrix of `docs/ACTION_CONTRACTS.md` section 12 names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryPosition {
    /// The step is admitted and has no intent. No call was issued.
    Admitted,
    /// The step has a durable intent, and its dispatch was not consumed.
    /// No call was issued. The intent is not evidence that the execution
    /// is necessary now.
    IntentCommitted,
    /// The dispatch was consumed, and the journal has no submission and no
    /// outcome. A call was possibly issued.
    DispatchConsumed,
    /// The call was submitted, and the journal has no conclusive outcome.
    Submitted,
    /// The step has the state `UnknownOutcome`. It keeps that state until
    /// evidence settles it.
    UnknownOutcome,
    /// The record has a value that this build does not recognize. It
    /// supports no conclusion.
    Unrecognized,
}

/// One step that is not settled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepRecovery {
    /// The step record.
    pub step: Step,
    /// The intent: the request envelope with the target evidence, the
    /// budget reservation, and the leases.
    pub intent: Option<RequestEnvelope>,
    /// Whether the dispatch of the step was consumed. A consumed step is
    /// not submitted again.
    pub dispatch_consumed: bool,
    /// The last trustworthy record.
    pub position: RecoveryPosition,
}

/// One operation that is not settled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryRecord {
    /// The operation with each step.
    pub operation: Operation,
    /// Whether the operation has a durable stop fence.
    pub stop_fence: bool,
    /// The steps that are not settled, in execution sequence.
    pub unsettled_steps: Vec<StepRecovery>,
}

/// One consumed dispatch of an incident.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumedDispatch {
    /// The operation.
    pub operation_id: OperationId,
    /// The step.
    pub step_id: StepId,
    /// The executor lifetime that admitted the operation.
    pub executor_epoch: ExecutorEpochId,
    /// The intent, which has the budget reservation that the consumption
    /// charged.
    pub intent: RequestEnvelope,
}

fn position_of(step: &Step, dispatch_consumed: bool) -> RecoveryPosition {
    match step.progress().state() {
        StepState::Admitted if dispatch_consumed => RecoveryPosition::Unrecognized,
        StepState::Admitted => RecoveryPosition::Admitted,
        StepState::IntentCommitted if dispatch_consumed => RecoveryPosition::DispatchConsumed,
        StepState::IntentCommitted => RecoveryPosition::IntentCommitted,
        StepState::DispatchConsumed => RecoveryPosition::DispatchConsumed,
        StepState::Verifying => RecoveryPosition::Submitted,
        StepState::UnknownOutcome => RecoveryPosition::UnknownOutcome,
        _ => RecoveryPosition::Unrecognized,
    }
}

impl OperationJournal {
    /// Reads the operations that are not settled, the oldest first, to a
    /// maximum of `limit`, each with its stop fence and with the intent
    /// and the dispatch consumption of each step that is not settled.
    ///
    /// # Errors
    ///
    /// Returns a storage error, which includes
    /// [`OperationJournalError::Decode`] for a record that is not
    /// consistent. The function returns no part of the list on an error.
    /// The list always starts at the oldest operation: give a limit that
    /// is not smaller than [`OperationJournal::unsettled_operation_count`].
    pub fn recovery_records(
        &self,
        limit: usize,
    ) -> Result<Vec<RecoveryRecord>, OperationJournalError> {
        let transaction = self.read_transaction()?;
        let mut records: Vec<RecoveryRecord> = Vec::new();
        for seq in durable::unsettled_rows(&transaction, limit)? {
            let operation: Operation = row::load_operation(&transaction, seq)?;
            let stop_fence: bool = row::find_operation(&transaction, operation.operation_id())?
                .ok_or(OperationJournalError::row("operation", "operation_id"))?
                .stop_fence;
            let intents = row::load_intents(&transaction, seq)?;
            if intents.len() != operation.steps().len() {
                return Err(OperationJournalError::row("step", "position"));
            }
            let mut unsettled_steps: Vec<StepRecovery> = Vec::new();
            for (step, (step_id, intent, dispatch_consumed)) in
                operation.steps().iter().zip(intents)
            {
                if step.step_id() != &step_id {
                    return Err(OperationJournalError::row("step", "step_id"));
                }
                if step.progress().state().is_settled() {
                    continue;
                }
                unsettled_steps.push(StepRecovery {
                    step: step.clone(),
                    intent,
                    dispatch_consumed,
                    position: position_of(step, dispatch_consumed),
                });
            }
            records.push(RecoveryRecord {
                operation,
                stop_fence,
                unsettled_steps,
            });
        }
        Ok(records)
    }

    /// The number of operations that are not settled. A caller compares
    /// it with the length of a list that it read with a limit, so that a
    /// list that is not complete is not taken as complete.
    ///
    /// # Errors
    ///
    /// Returns a storage error.
    pub fn unsettled_operation_count(&self) -> Result<u64, OperationJournalError> {
        let count: i64 = self.connection.query_row(
            "SELECT count(*) FROM operation WHERE settled = 0",
            [],
            |row| row.get(0),
        )?;
        u64::try_from(count).map_err(|_| OperationJournalError::row("operation", "settled"))
    }

    /// Reads the consumed dispatches of the operations of one incident,
    /// the oldest first, to a maximum of `limit`. A restart uses them to
    /// establish the consumed budget of the incident. A list that has
    /// `limit` entries is possibly not complete.
    ///
    /// A consumed dispatch stays in the list when its step issued no call:
    /// a consumed step is not reactivated.
    ///
    /// # Errors
    ///
    /// Returns a storage error.
    pub fn consumed_dispatches(
        &self,
        incident_id: &IncidentId,
        limit: usize,
    ) -> Result<Vec<ConsumedDispatch>, OperationJournalError> {
        let limit: i64 = i64::try_from(limit).unwrap_or(i64::MAX);
        let mut statement = self.connection.prepare(
            "SELECT operation.operation_id, step.step_id, operation.executor_epoch, step.intent \
             FROM operation JOIN step ON step.operation_seq = operation.seq \
             WHERE operation.incident_id = ?1 AND step.dispatch_consumed = 1 \
             ORDER BY operation.seq, step.position LIMIT ?2",
        )?;
        let mut rows = statement.query(params![incident_id.as_str(), limit])?;
        let mut dispatches: Vec<ConsumedDispatch> = Vec::new();
        while let Some(row) = rows.next()? {
            let operation_id: String = row.get(0)?;
            let step_id: String = row.get(1)?;
            let executor_epoch: String = row.get(2)?;
            let intent: String = row.get(3)?;
            dispatches.push(ConsumedDispatch {
                operation_id: OperationId::new(operation_id)
                    .map_err(|_| OperationJournalError::row("operation", "operation_id"))?,
                step_id: StepId::new(step_id)
                    .map_err(|_| OperationJournalError::row("step", "step_id"))?,
                executor_epoch: ExecutorEpochId::new(executor_epoch)
                    .map_err(|_| OperationJournalError::row("operation", "executor_epoch"))?,
                intent: decode("step", &intent)?,
            });
        }
        Ok(dispatches)
    }
}
