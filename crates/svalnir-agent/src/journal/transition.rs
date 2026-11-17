//! The changes of a stored operation.
//!
//! Each change goes through `Operation::advance_step`,
//! `Operation::settle_step`, and `Operation::settle` of `svalnir-core`. This
//! module finds the permitted calls that bring a stored record to a given
//! record, and it rejects a given record that those calls do not make.

use svalnir_core::action::{
    DispatchState, Operation, OperationError, Step, StepState, TransitionError,
};
use svalnir_core::id::StepId;

use super::error::{OperationJournalError, SequenceViolation};

/// Whether a record can move a step to `IntentCommitted` or
/// `DispatchConsumed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Boundary {
    /// The durable path: only the intent call and the dispatch consumption
    /// make those states.
    Refused,
    /// The record of the critical-memory exception, which made the states
    /// in volatile state with its own intent and consumption.
    Permitted,
}

fn transition(error: OperationError) -> OperationJournalError {
    SequenceViolation::Transition(error).into()
}

/// Brings the step of `operation` that has the identity of `desired` to
/// `desired`. Returns `false` when the stored step is `desired`.
///
/// On an error `operation` can have a part of the change. The caller then
/// discards it.
///
/// A caller that kept a result in memory after a failed write gives the
/// result state only. For that case this function records the submission
/// (`Verifying`) of a step whose dispatch was consumed before the result.
pub(super) fn apply_step(
    operation: &mut Operation,
    desired: &Step,
    boundary: Boundary,
) -> Result<bool, OperationJournalError> {
    let step_id: &StepId = desired.step_id();
    let current: &Step = operation
        .step(step_id)
        .ok_or(OperationJournalError::NotFound)?;
    if current == desired {
        return Ok(false);
    }
    if current.action_class() != desired.action_class()
        || current.target_id() != desired.target_id()
    {
        return Err(OperationJournalError::Conflict);
    }
    let progress = desired.progress();
    let makes_boundary: bool = matches!(
        progress.state(),
        StepState::IntentCommitted | StepState::DispatchConsumed
    ) && current.progress().state() != progress.state();
    if makes_boundary && boundary == Boundary::Refused {
        return Err(SequenceViolation::Boundary.into());
    }
    let was_consumed: bool = matches!(current.progress().state(), StepState::DispatchConsumed);
    let durability = progress.durability().clone();
    if desired.results().is_empty() {
        operation
            .advance_step(
                step_id,
                progress.state().clone(),
                progress.dispatch().clone(),
                durability,
            )
            .map_err(transition)?;
    } else {
        let results = desired.results().to_vec();
        match operation.settle_step(step_id, results.clone(), durability.clone()) {
            Ok(()) => {}
            Err(OperationError::Transition(TransitionError::NotPermitted { .. }))
                if was_consumed && matches!(progress.dispatch(), DispatchState::Submitted) =>
            {
                operation
                    .advance_step(
                        step_id,
                        StepState::Verifying,
                        DispatchState::Submitted,
                        durability.clone(),
                    )
                    .map_err(transition)?;
                operation
                    .settle_step(step_id, results, durability)
                    .map_err(transition)?;
            }
            Err(error) => return Err(transition(error)),
        }
    }
    if operation.step(step_id) == Some(desired) {
        Ok(true)
    } else {
        Err(SequenceViolation::Mismatch.into())
    }
}

/// Brings `operation` to `desired`: each step, and then the state. Returns
/// the identities of the steps that changed.
///
/// On an error `operation` can have a part of the change. The caller then
/// discards it.
///
/// # Errors
///
/// Returns [`OperationJournalError::Conflict`] when the two records are not
/// records of the same admission, and a sequence error when the permitted
/// changes do not make `desired`.
pub(super) fn apply_operation(
    operation: &mut Operation,
    desired: &Operation,
    boundary: Boundary,
) -> Result<Vec<StepId>, OperationJournalError> {
    let same_admission: bool = operation.operation_id() == desired.operation_id()
        && operation.plan_id() == desired.plan_id()
        && operation.plan_digest() == desired.plan_digest()
        && operation.trigger_class() == desired.trigger_class()
        && operation.executor_epoch() == desired.executor_epoch()
        && operation.admitted_at() == desired.admitted_at()
        && operation.steps().len() == desired.steps().len();
    if !same_admission {
        return Err(OperationJournalError::Conflict);
    }
    let mut changed: Vec<StepId> = Vec::new();
    for step in desired.steps() {
        if apply_step(operation, step, boundary)? {
            changed.push(step.step_id().clone());
        }
    }
    if operation.state() != desired.state() {
        operation.settle().map_err(transition)?;
    }
    if operation == desired {
        Ok(changed)
    } else {
        // This also covers a different durability of the admission.
        Err(SequenceViolation::Mismatch.into())
    }
}
