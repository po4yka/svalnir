//! The operation record and its steps.
//!
//! `docs/ACTION_CONTRACTS.md` sections 2, 6, and 9 own the contract. An
//! operation is one admitted application of a plan. It has the steps of the
//! plan and no other step, and it keeps the trigger class of the plan.
//!
//! The fields are private. A step changes only through
//! [`Operation::advance_step`] and [`Operation::settle_step`], and the
//! state of the operation changes only through [`Operation::settle`], which
//! aggregates the recorded target results. No caller can write a state
//! that the results do not support.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::class::{ActionClass, TriggerClass};
use super::journal::critical_exception_applies;
use super::outcome::{OutcomeError, TargetResult, aggregate, aggregate_step};
use super::plan::Plan;
use super::state::{
    DispatchState, Durability, OperationState, StepProgress, StepState, TransitionError,
};
use crate::digest::ContentDigest;
use crate::id::{ExecutorEpochId, OperationId, PlanId, StepId, TargetId};
use crate::time::WallTime;

/// One step of an operation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
    #[serde(rename = "step_id")]
    id: StepId,
    action_class: ActionClass,
    target_id: TargetId,
    progress: StepProgress,
    results: Vec<TargetResult>,
}

impl Step {
    /// The identity of the step.
    pub fn step_id(&self) -> &StepId {
        &self.id
    }

    /// The action class of the step.
    pub fn action_class(&self) -> &ActionClass {
        &self.action_class
    }

    /// The target of the step.
    pub fn target_id(&self) -> &TargetId {
        &self.target_id
    }

    /// The state, the dispatch state, and the durability of the step.
    pub fn progress(&self) -> &StepProgress {
        &self.progress
    }

    /// The target results. The list is empty until the step has a result.
    pub fn results(&self) -> &[TargetResult] {
        &self.results
    }
}

/// The reason a change of an operation was rejected. The operation is not
/// changed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum OperationError {
    /// The recording mode is not permitted for the plan. Volatile
    /// recording is only for an application intervention with a global
    /// critical-memory trigger.
    #[error("the recording mode is not permitted for the plan")]
    Recording,
    /// The operation has no step with the identity.
    #[error("the operation has no step with the identity")]
    UnknownStep,
    /// The operation is settled. A settled operation does not change.
    #[error("the operation is settled")]
    Settled,
    /// An earlier step for the same target is not settled, completed the
    /// target, or issued no call. A force step follows only a graceful
    /// step that was submitted and left the target running.
    #[error("an earlier step for the same target does not permit this step")]
    Sequence,
    /// A result state needs target results. Use `settle_step`.
    #[error("a result state needs target results")]
    ResultsRequired,
    /// A target result names a different target than the step.
    #[error("a target result names a different target than the step")]
    ResultTarget,
    /// A step has no result. Record a skipped result for a step that did
    /// not run.
    #[error("a step has no result")]
    Unfinished,
    /// The decoded record does not agree with itself.
    #[error("the operation record does not agree with itself")]
    Inconsistent,
    /// The state change is not permitted.
    #[error(transparent)]
    Transition(#[from] TransitionError),
    /// The target results do not aggregate.
    #[error(transparent)]
    Outcome(#[from] OutcomeError),
}

/// One admitted application of a plan.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "OperationWire")]
pub struct Operation {
    #[serde(rename = "operation_id")]
    id: OperationId,
    plan_id: PlanId,
    plan_digest: ContentDigest,
    trigger_class: TriggerClass,
    executor_epoch: ExecutorEpochId,
    state: OperationState,
    admission_durability: Durability,
    admitted_at: WallTime,
    steps: Vec<Step>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OperationWire {
    operation_id: OperationId,
    plan_id: PlanId,
    plan_digest: ContentDigest,
    trigger_class: TriggerClass,
    executor_epoch: ExecutorEpochId,
    state: OperationState,
    admission_durability: Durability,
    admitted_at: WallTime,
    steps: Vec<Step>,
}

impl TryFrom<OperationWire> for Operation {
    type Error = OperationError;

    fn try_from(wire: OperationWire) -> Result<Self, Self::Error> {
        let operation = Self {
            id: wire.operation_id,
            plan_id: wire.plan_id,
            plan_digest: wire.plan_digest,
            trigger_class: wire.trigger_class,
            executor_epoch: wire.executor_epoch,
            state: wire.state,
            admission_durability: wire.admission_durability,
            admitted_at: wire.admitted_at,
            steps: wire.steps,
        };
        operation.check_decoded()?;
        Ok(operation)
    }
}

impl Operation {
    /// Makes the operation of an admitted plan. Each step is `Admitted`
    /// and not submitted.
    ///
    /// The caller does the admission checks of the specification. This
    /// function checks only the recording mode.
    ///
    /// # Errors
    ///
    /// Returns [`OperationError::Recording`] when `durability` is not
    /// `durable` and the critical-memory exception does not apply to each
    /// step of the plan, or when `durability` is not `durable` or
    /// `volatile`.
    pub fn admit(
        plan: &Plan,
        operation_id: OperationId,
        executor_epoch: ExecutorEpochId,
        durability: Durability,
        admitted_at: WallTime,
    ) -> Result<Self, OperationError> {
        let trigger_class: TriggerClass = plan.trigger.class.clone();
        let durability_agrees: bool = match durability {
            Durability::Durable => true,
            Durability::Volatile => plan
                .steps
                .iter()
                .all(|step| critical_exception_applies(&step.action_class, &trigger_class)),
            _ => false,
        };
        if !durability_agrees {
            return Err(OperationError::Recording);
        }
        let mut steps: Vec<Step> = Vec::with_capacity(plan.steps.len());
        for planned in &plan.steps {
            steps.push(Step {
                id: planned.step_id.clone(),
                action_class: planned.action_class.clone(),
                target_id: planned.target_id.clone(),
                progress: StepProgress::admitted(durability.clone())?,
                results: Vec::new(),
            });
        }
        Ok(Self {
            id: operation_id,
            plan_id: plan.plan_id.clone(),
            plan_digest: plan.digest().clone(),
            trigger_class,
            executor_epoch,
            state: OperationState::Admitted,
            admission_durability: durability,
            admitted_at,
            steps,
        })
    }

    /// The identity of the operation.
    pub fn operation_id(&self) -> &OperationId {
        &self.id
    }

    /// The plan that the operation applies.
    pub fn plan_id(&self) -> &PlanId {
        &self.plan_id
    }

    /// The digest of the plan that the operation applies.
    pub fn plan_digest(&self) -> &ContentDigest {
        &self.plan_digest
    }

    /// The original trigger class. It does not change.
    pub fn trigger_class(&self) -> &TriggerClass {
        &self.trigger_class
    }

    /// The executor lifetime that admitted the operation.
    pub fn executor_epoch(&self) -> &ExecutorEpochId {
        &self.executor_epoch
    }

    /// The state of the operation.
    pub fn state(&self) -> &OperationState {
        &self.state
    }

    /// The wall-clock time of the admission, for history only.
    pub fn admitted_at(&self) -> WallTime {
        self.admitted_at
    }

    /// The steps, in execution sequence.
    pub fn steps(&self) -> &[Step] {
        &self.steps
    }

    /// The step with the identity `step_id`.
    pub fn step(&self, step_id: &StepId) -> Option<&Step> {
        self.steps.iter().find(|step| &step.id == step_id)
    }

    /// Whether an external call of a step was submitted: `submitted` when
    /// a step is submitted, `submission_uncertain` when no step is
    /// submitted and one is uncertain. A step with a dispatch state that
    /// this build does not recognize makes the result uncertain.
    pub fn dispatch(&self) -> DispatchState {
        let mut dispatch = DispatchState::NotSubmitted;
        for step in &self.steps {
            match step.progress.dispatch() {
                DispatchState::Submitted => return DispatchState::Submitted,
                DispatchState::NotSubmitted => {}
                _ => dispatch = DispatchState::SubmissionUncertain,
            }
        }
        dispatch
    }

    /// How the operation was recorded: the durability of the admission,
    /// or `persistence_failed` when a write of a step failed after it.
    pub fn durability(&self) -> Durability {
        let failed = |step: &Step| !matches!(step.progress.durability(), Durability::Durable);
        if self.admission_durability.is_durable() && self.steps.iter().any(failed) {
            Durability::PersistenceFailed
        } else {
            self.admission_durability.clone()
        }
    }

    /// All target results, in execution sequence.
    pub fn target_results(&self) -> Vec<TargetResult> {
        self.steps
            .iter()
            .flat_map(|step| step.results.iter().cloned())
            .collect()
    }

    fn open_step(&mut self, step_id: &StepId) -> Result<usize, OperationError> {
        if !matches!(
            self.state,
            OperationState::Admitted | OperationState::UnknownOutcome
        ) {
            return Err(OperationError::Settled);
        }
        self.steps
            .iter()
            .position(|step| &step.id == step_id)
            .ok_or(OperationError::UnknownStep)
    }

    /// Whether each earlier step for the target of the step at `index`
    /// submitted a call and left work for a later step: its state is
    /// `Incomplete`, `Partial`, or `Failed`, and its call was submitted.
    /// A step that failed before its call permits no later step.
    ///
    /// `Completed` means that the target is in its final condition.
    /// `NoAction` means that the target was not running or that the step
    /// was stopped before its call; a stop also stops the later step.
    /// A state that is not settled, which includes `UnknownOutcome`,
    /// needs its result first.
    fn earlier_steps_permit(&self, index: usize) -> bool {
        let target: &TargetId = &self.steps[index].target_id;
        self.steps[..index]
            .iter()
            .filter(|step| &step.target_id == target)
            .all(|step| {
                matches!(
                    step.progress.state(),
                    StepState::Incomplete | StepState::Partial | StepState::Failed
                ) && matches!(step.progress.dispatch(), DispatchState::Submitted)
            })
    }

    /// Moves a step to `IntentCommitted`, `DispatchConsumed`, or
    /// `Verifying`.
    ///
    /// # Errors
    ///
    /// Returns an [`OperationError`] when:
    ///
    /// - The operation is settled, or it has no step `step_id`.
    /// - `state` is a result state. A result needs target results.
    /// - An earlier step for the same target does not have the state
    ///   `Incomplete`, `Partial`, or `Failed` with a submitted call.
    /// - [`StepProgress::advance`] rejects the change.
    pub fn advance_step(
        &mut self,
        step_id: &StepId,
        state: StepState,
        dispatch: DispatchState,
        durability: Durability,
    ) -> Result<(), OperationError> {
        let index: usize = self.open_step(step_id)?;
        if !matches!(
            state,
            StepState::IntentCommitted | StepState::DispatchConsumed | StepState::Verifying
        ) {
            return Err(OperationError::ResultsRequired);
        }
        if !self.earlier_steps_permit(index) {
            return Err(OperationError::Sequence);
        }
        let step: &mut Step = &mut self.steps[index];
        step.progress = step.progress.advance(state, dispatch, durability)?;
        Ok(())
    }

    /// Records the target results of a step and moves the step to the
    /// state that the results aggregate to.
    ///
    /// The dispatch state of the step comes from the results: `submitted`
    /// when a result is submitted, `submission_uncertain` when no result
    /// is submitted and one is uncertain. A step in `UnknownOutcome` takes
    /// new results when reconciliation establishes them.
    ///
    /// # Errors
    ///
    /// Returns an [`OperationError`] when:
    ///
    /// - The operation is settled, or it has no step `step_id`.
    /// - `results` is empty, or a result names a different target.
    /// - [`StepProgress::advance`] rejects the change, for example a
    ///   verified effect for a step whose dispatch was not consumed.
    pub fn settle_step(
        &mut self,
        step_id: &StepId,
        results: Vec<TargetResult>,
        durability: Durability,
    ) -> Result<(), OperationError> {
        let index: usize = self.open_step(step_id)?;
        let step: &mut Step = &mut self.steps[index];
        if results
            .iter()
            .any(|result| result.target_id != step.target_id)
        {
            return Err(OperationError::ResultTarget);
        }
        let state: StepState = aggregate_step(&results)?;
        let mut dispatch = DispatchState::NotSubmitted;
        for result in &results {
            match result.dispatch {
                DispatchState::Submitted => {
                    dispatch = DispatchState::Submitted;
                    break;
                }
                DispatchState::NotSubmitted => {}
                _ => dispatch = DispatchState::SubmissionUncertain,
            }
        }
        step.progress = step.progress.advance(state, dispatch, durability)?;
        step.results = results;
        Ok(())
    }

    /// Aggregates the target results into the state of the operation.
    ///
    /// # Errors
    ///
    /// Returns an [`OperationError`] when the operation is settled, when a
    /// step has no result, or when the results do not aggregate.
    pub fn settle(&mut self) -> Result<&OperationState, OperationError> {
        if self.state.is_settled() {
            return Err(OperationError::Settled);
        }
        if self.steps.iter().any(|step| step.results.is_empty()) {
            return Err(OperationError::Unfinished);
        }
        let next: OperationState = aggregate(&self.target_results())?;
        self.state = self.state.transition(next)?;
        Ok(&self.state)
    }

    fn check_decoded(&self) -> Result<(), OperationError> {
        let mut step_ids: BTreeSet<&StepId> = BTreeSet::new();
        for step in &self.steps {
            if !step_ids.insert(&step.id)
                || step
                    .results
                    .iter()
                    .any(|result| result.target_id != step.target_id)
            {
                return Err(OperationError::Inconsistent);
            }
        }
        if self.steps.is_empty() {
            return Err(OperationError::Inconsistent);
        }
        // Each check reads only values that this build recognizes. A value
        // that it does not recognize is kept and supports nothing.
        let admission_agrees: bool = match self.admission_durability {
            Durability::Durable | Durability::Unrecognized(_) => true,
            Durability::Volatile => self
                .steps
                .iter()
                .all(|step| critical_exception_applies(&step.action_class, &self.trigger_class)),
            Durability::PersistenceFailed => false,
        };
        if !admission_agrees {
            return Err(OperationError::Inconsistent);
        }
        for (index, step) in self.steps.iter().enumerate() {
            if !step.progress.is_recognized() {
                continue;
            }
            let state: &StepState = step.progress.state();
            let has_result_state: bool =
                state.is_settled() || matches!(state, StepState::UnknownOutcome);
            let results_agree: bool = if has_result_state {
                aggregate_step(&step.results).is_ok_and(|expected| &expected == state)
            } else {
                step.results.is_empty()
            };
            // The record of a step is as durable as the admission permits.
            let durability_agrees: bool = matches!(
                (&self.admission_durability, step.progress.durability()),
                (
                    Durability::Durable,
                    Durability::Durable | Durability::PersistenceFailed
                ) | (Durability::Volatile, Durability::Volatile)
                    | (Durability::Unrecognized(_), _)
            );
            // A step that has an intent or a call follows the sequence
            // rule of `advance_step`.
            let started: bool = step.progress.dispatch().is_possibly_submitted()
                || matches!(
                    state,
                    StepState::IntentCommitted | StepState::DispatchConsumed | StepState::Verifying
                );
            let sequence_agrees: bool = !started || self.earlier_steps_permit(index);
            if !(results_agree && durability_agrees && sequence_agrees) {
                return Err(OperationError::Inconsistent);
            }
        }
        let state_agrees: bool = match self.state {
            OperationState::Admitted | OperationState::Unrecognized(_) => true,
            _ => {
                self.steps.iter().all(|step| !step.results.is_empty())
                    && aggregate(&self.target_results()).is_ok_and(|state| state == self.state)
            }
        };
        if state_agrees {
            Ok(())
        } else {
            Err(OperationError::Inconsistent)
        }
    }
}
