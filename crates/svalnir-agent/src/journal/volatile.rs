//! The bounded in-memory record of the critical-memory exception.
//!
//! [`VolatileRecord`] implements `svalnir_core::action::VolatileJournal`
//! for one executor lifetime. It is for one case only: the durable journal
//! is not available, and admission permitted the critical-memory exception
//! for an application intervention whose original trigger is global
//! critical memory. It never records a filesystem action.
//!
//! A crash loses the record. The record does not replace the conservative
//! budget rule after a restart.
//!
//! # Bound
//!
//! The record holds a fixed number of steps for its lifetime. The
//! registration of an operation reserves one place for each of its steps.
//! A place is never free again: the consumption of a step stays valid for
//! the executor lifetime, also after the record was written to the durable
//! journal, so a repeated request finds it. When the places are used, the
//! record refuses a new operation, and the exception is not available
//! until the next executor lifetime.

use svalnir_core::action::{
    DispatchConsumption, DispatchReceipt, DispatchState, Durability, Operation, OperationState,
    Plan, Principal, RequestEnvelope, Step, StepState, VolatileJournal, VolatileJournalError,
    check_dispatch_recording,
};
use svalnir_core::id::{ExecutorEpochId, OperationId};

use super::OperationJournal;
use super::error::{OperationJournalError, SequenceViolation};
use super::transition::{self, Boundary};

/// One operation of the critical-memory exception with the records that
/// the durable journal keeps for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolatileOperationRecord {
    /// The plan of the operation.
    pub plan: Plan,
    /// The principal that applied the plan.
    pub principal: Principal,
    /// The operation. Its history has the durability `volatile`.
    pub operation: Operation,
    /// The intent of each step whose dispatch was consumed, in the
    /// sequence of the consumptions.
    pub intents: Vec<RequestEnvelope>,
}

impl VolatileOperationRecord {
    /// Checks that the parts of the record agree with each other.
    pub(super) fn check(&self) -> Result<(), OperationJournalError> {
        let operation: &Operation = &self.operation;
        if !matches!(operation.durability(), Durability::Volatile) {
            return Err(SequenceViolation::NotVolatile.into());
        }
        let has_intent = |step: &Step| {
            self.intents
                .iter()
                .filter(|intent| &intent.correlation.step_id == step.step_id())
                .count()
        };
        // A step has one intent or none. A step whose dispatch was
        // consumed has one, and a step that is `Admitted` has none.
        let steps_agree: bool = operation.steps().iter().all(|step| {
            let consumed: bool = matches!(
                step.progress().state(),
                StepState::DispatchConsumed | StepState::Verifying
            ) || step.progress().dispatch().is_possibly_submitted();
            let admitted: bool = matches!(step.progress().state(), StepState::Admitted);
            match has_intent(step) {
                0 => !consumed,
                1 => !admitted,
                _ => false,
            }
        });
        let intents_agree: bool = steps_agree
            && self
                .intents
                .iter()
                .all(|intent| envelope_agrees(operation, intent));
        // The steps and the trigger of the operation are those of the
        // plan. The fields of the record are public, so a caller other
        // than `VolatileRecord::register` can make one.
        if operation.plan_id() == &self.plan.plan_id
            && operation.plan_digest() == self.plan.digest()
            && super::durable::steps_are_of_plan(&self.plan, operation)
            && intents_agree
        {
            Ok(())
        } else {
            Err(OperationJournalError::Conflict)
        }
    }
}

/// Whether `envelope` is a request for a step of `operation`.
fn envelope_agrees(operation: &Operation, envelope: &RequestEnvelope) -> bool {
    let correlation = &envelope.correlation;
    operation.operation_id() == &correlation.operation_id
        && operation.plan_id() == &correlation.plan_id
        && operation.plan_digest() == &correlation.plan_digest
        && operation.executor_epoch() == &envelope.evidence.executor_epoch
        && operation.trigger_class() == &envelope.trigger.class
        && operation.step(&correlation.step_id).is_some_and(|step| {
            step.action_class() == &envelope.action_class
                && step.target_id() == &envelope.target.target_id
        })
}

#[derive(Debug)]
struct Entry {
    record: VolatileOperationRecord,
    /// The current-instance stop of the operation.
    stopped: bool,
    /// Whether the durable journal does not have the current state.
    unwritten: bool,
}

/// The bounded in-memory record of the critical-memory exception, for one
/// executor lifetime.
#[derive(Debug)]
pub struct VolatileRecord {
    epoch: ExecutorEpochId,
    capacity: usize,
    reserved: usize,
    entries: Vec<Entry>,
}

impl VolatileRecord {
    /// Makes an empty record for the executor lifetime `epoch` that holds
    /// a maximum of `capacity` steps.
    pub fn new(epoch: ExecutorEpochId, capacity: usize) -> Self {
        Self {
            epoch,
            capacity,
            reserved: 0,
            entries: Vec::new(),
        }
    }

    /// The number of steps that a new operation can have.
    pub fn remaining_capacity(&self) -> usize {
        self.capacity.saturating_sub(self.reserved)
    }

    fn entry_mut(&mut self, operation_id: &OperationId) -> Option<&mut Entry> {
        self.entries
            .iter_mut()
            .find(|entry| entry.record.operation.operation_id() == operation_id)
    }

    /// Registers the new volatile admission `operation` of `plan` and
    /// reserves one place for each of its steps. The same operation again
    /// is not an error.
    ///
    /// The caller makes the operation with `Operation::admit` and the
    /// durability `volatile`, which `svalnir-core` accepts only for an
    /// application intervention with a global critical-memory trigger. The
    /// caller does the admission checks of the exception.
    ///
    /// # Errors
    ///
    /// Returns [`VolatileJournalError::EarlierEpoch`] when the operation
    /// is of a different executor lifetime,
    /// [`VolatileJournalError::NotPermitted`] when the operation is not a
    /// new volatile admission of `plan`, or when the record has a
    /// different operation with the same identity or for the same plan,
    /// and [`VolatileJournalError::Full`] when the record has fewer free
    /// places than the operation has steps.
    pub fn register(
        &mut self,
        plan: &Plan,
        principal: &Principal,
        operation: Operation,
    ) -> Result<(), VolatileJournalError> {
        if operation.executor_epoch() != &self.epoch {
            return Err(VolatileJournalError::EarlierEpoch);
        }
        let is_new = |step: &Step| {
            matches!(step.progress().state(), StepState::Admitted)
                && matches!(step.progress().dispatch(), DispatchState::NotSubmitted)
                && step.results().is_empty()
        };
        let permitted: bool = matches!(operation.durability(), Durability::Volatile)
            && matches!(operation.state(), OperationState::Admitted)
            && operation.plan_id() == &plan.plan_id
            && operation.plan_digest() == plan.digest()
            && operation.steps().iter().all(is_new);
        if !permitted || operation.steps().is_empty() {
            return Err(VolatileJournalError::NotPermitted);
        }
        for entry in &self.entries {
            let existing: &Operation = &entry.record.operation;
            let same_identity: bool = existing.operation_id() == operation.operation_id();
            if same_identity
                && entry.record.plan.digest() == plan.digest()
                && &entry.record.principal == principal
            {
                // A repeated registration. The record keeps its state.
                return Ok(());
            }
            if same_identity || existing.plan_id() == operation.plan_id() {
                return Err(VolatileJournalError::NotPermitted);
            }
        }
        let reserved: usize = self
            .reserved
            .checked_add(operation.steps().len())
            .filter(|reserved| *reserved <= self.capacity)
            .ok_or(VolatileJournalError::Full)?;
        self.reserved = reserved;
        self.entries.push(Entry {
            record: VolatileOperationRecord {
                plan: plan.clone(),
                principal: principal.clone(),
                operation,
                intents: Vec::new(),
            },
            stopped: false,
            unwritten: true,
        });
        Ok(())
    }

    /// Records a stop of an operation for the current executor instance.
    /// Each later consumption of the operation returns
    /// [`DispatchConsumption::Fenced`]. The stop does not survive a
    /// restart, and it does not recall a call that was issued.
    ///
    /// # Errors
    ///
    /// Returns [`VolatileJournalError::NotFound`] when the record has no
    /// operation with the identity.
    pub fn stop(&mut self, operation_id: &OperationId) -> Result<(), VolatileJournalError> {
        let entry: &mut Entry = self
            .entry_mut(operation_id)
            .ok_or(VolatileJournalError::NotFound)?;
        entry.stopped = true;
        Ok(())
    }

    /// Aggregates the target results of an operation into its state, with
    /// `Operation::settle`.
    ///
    /// # Errors
    ///
    /// Returns [`VolatileJournalError::NotFound`] when the record has no
    /// operation with the identity, and
    /// [`VolatileJournalError::NotPermitted`] when the operation is
    /// settled or a step has no result.
    pub fn settle_operation(
        &mut self,
        operation_id: &OperationId,
    ) -> Result<OperationState, VolatileJournalError> {
        let entry: &mut Entry = self
            .entry_mut(operation_id)
            .ok_or(VolatileJournalError::NotFound)?;
        let mut operation: Operation = entry.record.operation.clone();
        let state: OperationState = operation
            .settle()
            .map_err(|_| VolatileJournalError::NotPermitted)?
            .clone();
        entry.record.operation = operation;
        entry.unwritten = true;
        Ok(state)
    }

    /// The operation with the identity `operation_id`.
    pub fn operation(&self, operation_id: &OperationId) -> Option<&Operation> {
        self.entries
            .iter()
            .map(|entry| &entry.record.operation)
            .find(|operation| operation.operation_id() == operation_id)
    }

    /// The records that the durable journal does not have in their current
    /// state, in the sequence of their registration.
    pub fn pending_records(&self) -> Vec<&VolatileOperationRecord> {
        self.entries
            .iter()
            .filter(|entry| entry.unwritten)
            .map(|entry| &entry.record)
            .collect()
    }

    /// Writes each pending record to the durable journal. The records keep
    /// the durability `volatile`, and this record keeps each consumption.
    ///
    /// When the durable journal has a stop fence for an operation, the
    /// operation is stopped in this record also: each later consumption of
    /// it returns [`DispatchConsumption::Fenced`].
    ///
    /// A record that the journal refuses because of its content or of the
    /// stored state (for example a plan that a durable operation consumed)
    /// stays pending and is in [`VolatilePersistReport::refused`]. The
    /// call continues with the next record.
    ///
    /// Call this function before a durable admission: the durable journal
    /// has the plan consumption of a volatile operation only after it.
    ///
    /// # Errors
    ///
    /// Returns the storage failure of
    /// [`OperationJournal::persist_volatile`] for the first record that
    /// the journal could not write. The records before it are written, and
    /// that record and the records after it stay pending.
    pub fn persist_into(
        &mut self,
        journal: &mut OperationJournal,
    ) -> Result<VolatilePersistReport, OperationJournalError> {
        let mut report = VolatilePersistReport::default();
        for entry in self.entries.iter_mut().filter(|entry| entry.unwritten) {
            match journal.persist_volatile(&entry.record) {
                Ok(stop_fence) => {
                    entry.stopped |= stop_fence;
                    entry.unwritten = false;
                    report.written = report.written.saturating_add(1);
                }
                Err(error) if error.is_storage_failure() => return Err(error),
                Err(_) => report
                    .refused
                    .push(entry.record.operation.operation_id().clone()),
            }
        }
        Ok(report)
    }
}

/// What one call of [`VolatileRecord::persist_into`] did.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VolatilePersistReport {
    /// The number of records that the durable journal has now.
    pub written: usize,
    /// The operations whose records the journal refused. They stay
    /// pending, and their history is in the volatile record only.
    pub refused: Vec<OperationId>,
}

impl VolatileJournal for VolatileRecord {
    fn executor_epoch(&self) -> &ExecutorEpochId {
        &self.epoch
    }

    fn capacity(&self) -> usize {
        self.capacity
    }

    fn record_intent_and_consumption(
        &mut self,
        envelope: &RequestEnvelope,
    ) -> Result<DispatchReceipt, VolatileJournalError> {
        if envelope.evidence.executor_epoch != self.epoch {
            return Err(VolatileJournalError::EarlierEpoch);
        }
        check_dispatch_recording(
            &envelope.action_class,
            &envelope.trigger.class,
            &envelope.recording,
            &Durability::Volatile,
        )
        .map_err(|_| VolatileJournalError::NotPermitted)?;
        let capacity: usize = self.capacity;
        let consumed: usize = self
            .entries
            .iter()
            .map(|entry| entry.record.intents.len())
            .sum();
        let entry: &mut Entry = self
            .entry_mut(&envelope.correlation.operation_id)
            .ok_or(VolatileJournalError::NotFound)?;
        let step_id = &envelope.correlation.step_id;
        if entry.record.operation.step(step_id).is_none() {
            return Err(VolatileJournalError::NotFound);
        }
        if !envelope_agrees(&entry.record.operation, envelope) {
            return Err(VolatileJournalError::NotPermitted);
        }
        let receipt = |consumption: DispatchConsumption| DispatchReceipt {
            consumption,
            durability: Durability::Volatile,
        };
        let earlier: Option<&RequestEnvelope> = entry
            .record
            .intents
            .iter()
            .find(|intent| &intent.correlation.step_id == step_id);
        if let Some(earlier) = earlier {
            // The same identity with different content is not an update.
            return if earlier == envelope {
                Ok(receipt(DispatchConsumption::AlreadyConsumed))
            } else {
                Err(VolatileJournalError::NotPermitted)
            };
        }
        if entry.stopped {
            return Ok(receipt(DispatchConsumption::Fenced));
        }
        if consumed >= capacity {
            return Err(VolatileJournalError::Full);
        }
        let mut operation: Operation = entry.record.operation.clone();
        operation
            .advance_step(
                step_id,
                StepState::DispatchConsumed,
                DispatchState::NotSubmitted,
                Durability::Volatile,
            )
            .map_err(|_| VolatileJournalError::NotPermitted)?;
        entry.record.operation = operation;
        entry.record.intents.push(envelope.clone());
        entry.unwritten = true;
        Ok(receipt(DispatchConsumption::Consumed))
    }

    fn record_step(
        &mut self,
        operation_id: &OperationId,
        step: &Step,
    ) -> Result<(), VolatileJournalError> {
        let entry: &mut Entry = self
            .entry_mut(operation_id)
            .ok_or(VolatileJournalError::NotFound)?;
        // The change is made on a copy, so a rejected change leaves the
        // record as it was.
        let mut operation: Operation = entry.record.operation.clone();
        match transition::apply_step(&mut operation, step, Boundary::Refused) {
            Ok(false) => Ok(()),
            Ok(true) => {
                entry.record.operation = operation;
                entry.unwritten = true;
                Ok(())
            }
            Err(OperationJournalError::NotFound) => Err(VolatileJournalError::NotFound),
            Err(_) => Err(VolatileJournalError::NotPermitted),
        }
    }

    fn pending_operations(&self) -> Vec<Operation> {
        self.pending_records()
            .into_iter()
            .map(|record| record.operation.clone())
            .collect()
    }
}
