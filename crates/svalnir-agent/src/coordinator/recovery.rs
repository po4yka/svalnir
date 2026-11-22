//! Reconciliation of the operations that an earlier executor lifetime
//! left unsettled.
//!
//! `docs/ACTION_CONTRACTS.md` section 12 owns the recovery matrix.
//! Reconciliation is observational: it reads the journal and the current
//! condition of each target, and it writes what the evidence establishes.
//! It issues no executor call. It never removes an entry again and never
//! signals a process, also when a record then stays incomplete. A missing
//! record is not evidence that nothing occurred: a step whose dispatch
//! was consumed is `UnknownOutcome` until the evidence settles it.

use svalnir_core::action::{
    ActionError, ActionStage, Attribution, Checked, DispatchState, Durability, EffectEvidence,
    ErrorFamily, FileObjectType, NativeResult, Operation, OperationState, Plan, StepReconciliation,
    StepState, StopReason, TargetBinding, TargetEffect, TargetResult, TargetResultRecord,
};
use svalnir_core::id::{OperationId, ProcessGenerationId, StepId, TargetId};
use svalnir_core::quantity::Nanoseconds;
use svalnir_core::time::MonotonicNanos;

use super::board::{OperationView, Phase, StopAcknowledgement, StopView, WorkTotals};
use super::core::{Coordinator, lease_resources_of};
use super::dispatch::{Fault, skipped, unknown_outcome};
use super::error::{action_error, action_error_with, code};
use super::ports::{CoordinatorJournal, FileProbe};
use crate::executor::process::GenerationState;
use crate::journal::{RecoveryPosition, RecoveryRecord, StepRecovery};

/// The largest number of operations that one reconciliation reads.
pub const MAX_RECONCILED_OPERATIONS: usize = 4096;

/// The time between two reconciliations of the `UnknownOutcome`
/// operations of an earlier lifetime whose leases the coordinator holds:
/// 60 seconds.
pub const HELD_RECONCILIATION_INTERVAL: Nanoseconds = Nanoseconds::new(60_000_000_000);

/// A result that the current condition of a target establishes.
fn observed(
    target_id: &TargetId,
    member: Option<ProcessGenerationId>,
    dispatch: &DispatchState,
    effect: TargetEffect,
    failure: Option<ActionError>,
) -> Result<TargetResult, Fault> {
    let (attribution, stop_reason) = match effect {
        TargetEffect::Refused => (Attribution::NotApplicable, StopReason::Failed),
        TargetEffect::StillRunning => (Attribution::NotApplicable, StopReason::Completed),
        // The target is in its final condition. Who caused the condition
        // is not established.
        _ => (Attribution::Possible, StopReason::Completed),
    };
    Checked::new(TargetResultRecord {
        target_id: target_id.clone(),
        member,
        dispatch: dispatch.clone(),
        effect,
        evidence: EffectEvidence {
            native: NativeResult::Unavailable,
            ..EffectEvidence::none()
        },
        attribution,
        durability: Durability::Durable,
        stop_reason,
        failure,
    })
    .map_err(|_| Fault)
}

impl<J: CoordinatorJournal> Coordinator<J> {
    /// Reconciles each operation of the journal that is not settled and
    /// that this lifetime did not admit. The pending reconciliation of the
    /// journal ends when each result is written.
    pub(super) fn reconcile(&mut self) {
        let Ok(count) = self.journal.unsettled_operation_count() else {
            return;
        };
        let limit: usize = usize::try_from(count)
            .unwrap_or(MAX_RECONCILED_OPERATIONS)
            .clamp(1, MAX_RECONCILED_OPERATIONS);
        let Ok(records) = self.journal.recovery_records(limit) else {
            return;
        };
        let complete: bool = usize::try_from(count).is_ok_and(|count| count <= records.len());
        let mut written: bool = true;
        for record in records {
            if self.is_of_this_lifetime(record.operation.operation_id()) {
                continue;
            }
            written &= self.reconcile_record(record);
        }
        if !(written && complete) {
            return;
        }
        if self.start.reconciliation_pending
            && self.journal.complete_reconciliation(&self.epoch).is_err()
        {
            return;
        }
        self.start.reconciliation_pending = false;
        self.reconciliation_pending = false;
    }

    /// Holds the resources of an `UnknownOutcome` operation of an earlier
    /// lifetime, so that a conflicting plan is refused as for a live
    /// lease, until a reconciliation settles the operation or a user
    /// acknowledges it. An acknowledged operation holds nothing. A read
    /// of the acknowledgment that fails holds the resources.
    fn hold_unknown(
        &mut self,
        operation: &Operation,
        plan: Option<&Plan>,
        unsettled_steps: &[StepRecovery],
    ) {
        let operation_id: &OperationId = operation.operation_id();
        if matches!(self.journal.acknowledgment(operation_id), Ok(Some(_))) {
            self.ledger.release_unknown(operation_id);
            return;
        }
        // The plan has each target. With no plan, the intents of the
        // steps have the targets that a call can have changed.
        let resources = match plan {
            Some(plan) => lease_resources_of(plan.targets.iter().map(|target| &target.binding)),
            None => lease_resources_of(
                unsettled_steps
                    .iter()
                    .filter_map(|step| step.intent.as_ref())
                    .map(|intent| &intent.target.binding),
            ),
        };
        self.ledger.hold_unknown(operation_id, resources);
    }

    /// Reconciles again the `UnknownOutcome` operations whose resources
    /// the ledger holds, when [`HELD_RECONCILIATION_INTERVAL`] passed
    /// since the last time. A reconciliation that settles an operation
    /// releases its resources. The call reads the journal one time; it
    /// issues no executor call.
    pub(super) fn reconcile_held(&mut self, now: MonotonicNanos) {
        if self.ledger.held_unknown().next().is_none() {
            self.held_reconciliation_at = None;
            return;
        }
        let next: MonotonicNanos = now
            .checked_add(HELD_RECONCILIATION_INTERVAL)
            .unwrap_or(MonotonicNanos::new(u64::MAX));
        match self.held_reconciliation_at {
            Some(at) if now >= at => {}
            Some(_) => return,
            None => {
                self.held_reconciliation_at = Some(next);
                return;
            }
        }
        self.held_reconciliation_at = Some(next);
        let held: std::collections::BTreeSet<OperationId> =
            self.ledger.held_unknown().cloned().collect();
        let Ok(count) = self.journal.unsettled_operation_count() else {
            return;
        };
        let limit: usize = usize::try_from(count)
            .unwrap_or(MAX_RECONCILED_OPERATIONS)
            .clamp(1, MAX_RECONCILED_OPERATIONS);
        let Ok(records) = self.journal.recovery_records(limit) else {
            return;
        };
        let complete: bool = usize::try_from(count).is_ok_and(|count| count <= records.len());
        let mut found: std::collections::BTreeSet<OperationId> = std::collections::BTreeSet::new();
        for record in records {
            if held.contains(record.operation.operation_id()) {
                found.insert(record.operation.operation_id().clone());
                self.reconcile_record(record);
            }
        }
        // An operation that is not in a complete list is settled.
        if complete {
            for operation_id in held.difference(&found) {
                self.ledger.release_unknown(operation_id);
            }
        }
    }

    fn is_of_this_lifetime(&self, operation_id: &OperationId) -> bool {
        self.active
            .iter()
            .chain(self.waiting.iter())
            .chain(self.parked.values())
            .any(|active| active.operation.operation_id() == operation_id)
    }

    /// The results that the current condition of a target establishes
    /// for a step whose dispatch was consumed. `None` when the evidence
    /// does not settle the step.
    fn evidence(
        &self,
        target_id: &TargetId,
        binding: &TargetBinding,
        dispatch: &DispatchState,
        failure: &dyn Fn(&str, DispatchState) -> ActionError,
    ) -> Option<Vec<TargetResult>> {
        let submitted: bool = matches!(dispatch, DispatchState::Submitted);
        match binding {
            TargetBinding::File(file) => match self.probe.file(binding) {
                FileProbe::Absent => {
                    observed(target_id, None, dispatch, TargetEffect::AlreadyAbsent, None)
                        .ok()
                        .map(|result| vec![result])
                }
                // The planned object is at its name after a call that was
                // submitted: the call did not remove it. A directory can
                // be removed in part, so it is not settled.
                FileProbe::PlannedObject
                    if submitted && !matches!(file.object_type, FileObjectType::Directory) =>
                {
                    observed(
                        target_id,
                        None,
                        dispatch,
                        TargetEffect::Refused,
                        Some(failure(code::OBJECT_STILL_PRESENT, dispatch.clone())),
                    )
                    .ok()
                    .map(|result| vec![result])
                }
                // A different object at the name is a different target.
                FileProbe::PlannedObject | FileProbe::OtherObject | FileProbe::Unknown => None,
            },
            // No evidence settles the effect of a command of a producer: the
            // step stays `UnknownOutcome`, and its leases stay
            // (`docs/ACTION_CONTRACTS.md` section 7).
            TargetBinding::OwnerOperation(_) => None,
            // The members of an application target, or the one process
            // of a process target.
            TargetBinding::Application(_) | TargetBinding::Process(_) => {
                let mut results: Vec<TargetResult> = Vec::new();
                for member in binding.processes().unwrap_or_default() {
                    let effect: TargetEffect = match self.probe.process(member) {
                        // A reused PID is a different process. The planned
                        // generation is gone.
                        GenerationState::Exited | GenerationState::Replaced => {
                            TargetEffect::AlreadyExited
                        }
                        GenerationState::Running if submitted => TargetEffect::StillRunning,
                        GenerationState::Running | GenerationState::Unknown(_) => return None,
                    };
                    results.push(
                        observed(
                            target_id,
                            Some(member.generation_id.clone()),
                            dispatch,
                            effect,
                            None,
                        )
                        .ok()?,
                    );
                }
                (!results.is_empty()).then_some(results)
            }
        }
    }

    /// Settles what the evidence establishes for one operation. Returns
    /// false when a write of the journal failed.
    fn reconcile_record(&mut self, record: RecoveryRecord) -> bool {
        let RecoveryRecord {
            mut operation,
            stop_fence,
            unsettled_steps,
        } = record;
        let plan: Option<Plan> = self.journal.plan(operation.plan_id()).ok().flatten();
        let before_reconciliation: OperationState = operation.state().clone();
        let mut written: bool = true;
        for recovery in &unsettled_steps {
            written &= self
                .reconcile_step(&mut operation, plan.as_ref(), stop_fence, recovery)
                .is_complete();
        }
        let each_has_result: bool = operation
            .steps()
            .iter()
            .all(|step| !step.results().is_empty());
        if each_has_result && written {
            let before: OperationState = operation.state().clone();
            let mut settled: Operation = operation.clone();
            // An operation that stays `UnknownOutcome` has no new state.
            if settled.settle().is_ok() && settled.state() != &before {
                if self.journal.record_operation(&settled).is_ok() {
                    operation = settled;
                } else {
                    written = false;
                }
            }
        }
        let finished: bool = operation.state().is_settled();
        // An operation that this reconciliation settled, or whose
        // `UnknownOutcome` it resolved, has a new final record. An
        // operation with no readable plan has no notice: its trigger and
        // its targets are not known.
        if finished
            && written
            && operation.state() != &before_reconciliation
            && let Some(plan) = plan.as_ref()
        {
            self.keep_settled(&operation, plan);
        }
        // A step whose dispatch was consumed and that has no settled
        // record possibly issued a call, also when the state machine
        // refused each result for it and the operation stays in an
        // earlier state. Its resources are held as for `UnknownOutcome`.
        let consumed_unsettled: bool = !finished
            && unsettled_steps.iter().any(|recovery| {
                recovery.dispatch_consumed
                    && operation
                        .step(recovery.step.step_id())
                        .is_none_or(|step| !step.progress().state().is_settled())
            });
        if operation.state() == &OperationState::UnknownOutcome || consumed_unsettled {
            self.hold_unknown(&operation, plan.as_ref(), &unsettled_steps);
        } else if finished {
            self.ledger.release_unknown(operation.operation_id());
        }
        self.board.publish(OperationView {
            stop: stop_fence.then_some(StopView {
                reason: StopReason::Canceled,
                acknowledgement: if finished {
                    StopAcknowledgement::Settled
                } else {
                    StopAcknowledgement::DurableFence
                },
            }),
            operation,
            phase: Phase::Finished,
            resource_effects: Vec::new(),
            work: WorkTotals::default(),
            degraded_recording: false,
        });
        written
    }

    /// The results that reconciliation writes for one step, as a list of
    /// writes: the first write of a consumed step marks it as unknown,
    /// and a second one is what the evidence establishes.
    fn step_writes(
        &self,
        operation: &Operation,
        plan: Option<&Plan>,
        stop_fence: bool,
        recovery: &StepRecovery,
    ) -> Vec<Vec<TargetResult>> {
        let operation_id: &OperationId = operation.operation_id();
        let plan_id = operation.plan_id();
        let step_id: &StepId = recovery.step.step_id();
        let target_id: &TargetId = recovery.step.target_id();
        let failure = |text: &str, dispatch: DispatchState| {
            action_error_with(
                text,
                ErrorFamily::Outcome,
                ActionStage::Reconciliation,
                dispatch,
                Some(plan_id),
                Some(operation_id),
                Some(step_id),
            )
        };
        let binding: Option<TargetBinding> = plan
            .and_then(|plan| plan.target(target_id))
            .map(|target| target.binding.clone())
            .or_else(|| {
                recovery
                    .intent
                    .as_ref()
                    .map(|intent| intent.target.binding.clone())
            });
        let evidence = |dispatch: &DispatchState| {
            binding
                .as_ref()
                .and_then(|binding| self.evidence(target_id, binding, dispatch, &failure))
        };
        let unknown = |dispatch: DispatchState| {
            unknown_outcome(
                target_id,
                dispatch.clone(),
                failure(code::EFFECT_NOT_ESTABLISHED, dispatch),
            )
            .ok()
            .map(|result| vec![result])
        };
        let mut writes: Vec<Vec<TargetResult>> = Vec::new();
        match recovery.position {
            // No call was issued, and the step does not run now: its
            // executor lifetime ended.
            RecoveryPosition::Admitted | RecoveryPosition::IntentCommitted => {
                writes.extend(
                    not_started(operation, step_id, target_id, stop_fence)
                        .ok()
                        .map(|result| vec![result]),
                );
            }
            // A call was possibly issued. The step is unknown first.
            RecoveryPosition::DispatchConsumed => {
                let uncertain = DispatchState::SubmissionUncertain;
                writes.extend(unknown(uncertain.clone()));
                writes.extend(evidence(&uncertain));
            }
            RecoveryPosition::Submitted => {
                let submitted = DispatchState::Submitted;
                writes.extend(evidence(&submitted).or_else(|| unknown(submitted)));
            }
            RecoveryPosition::UnknownOutcome => {
                writes.extend(evidence(recovery.step.progress().dispatch()));
            }
            // A record that this build does not recognize supports no
            // conclusion. It stays as it is.
            RecoveryPosition::Unrecognized => {}
        }
        writes
    }

    /// Settles one step of an earlier lifetime with what the evidence
    /// establishes.
    ///
    /// A result that the result check or the state machine refuses gives
    /// [`StepReconciliation::Inspected`]: the step is recorded as
    /// `UnknownOutcome` when its dispatch was consumed, and it stays as
    /// the journal has it when no call was possible.
    fn reconcile_step(
        &mut self,
        operation: &mut Operation,
        plan: Option<&Plan>,
        stop_fence: bool,
        recovery: &StepRecovery,
    ) -> StepReconciliation {
        let operation_id: OperationId = operation.operation_id().clone();
        let step_id: StepId = recovery.step.step_id().clone();
        let durability: Durability = recovery.step.progress().durability().clone();
        for results in self.step_writes(operation, plan, stop_fence, recovery) {
            let given: usize = results.len();
            let mut next: Operation = operation.clone();
            let results: Vec<TargetResult> = results
                .into_iter()
                .filter_map(|result| {
                    Checked::new(TargetResultRecord {
                        durability: durability.clone(),
                        ..result.into_inner()
                    })
                    .ok()
                })
                .collect();
            if results.len() != given
                || next
                    .settle_step(&step_id, results, durability.clone())
                    .is_err()
            {
                return self.record_inspected(operation, &step_id, recovery.dispatch_consumed);
            }
            let saved: bool = next
                .step(&step_id)
                .is_some_and(|step| self.journal.record_step(&operation_id, step).is_ok());
            if !saved {
                return StepReconciliation::NotRecorded;
            }
            *operation = next;
        }
        StepReconciliation::Recorded
    }

    /// Records a step whose result was refused: not settled, inspected.
    /// A step whose dispatch was consumed gets the state `UnknownOutcome`,
    /// so that the record does not show a consumed step with no outcome.
    /// A step that is `UnknownOutcome`, and a step that issued no call,
    /// keep their record.
    fn record_inspected(
        &mut self,
        operation: &mut Operation,
        step_id: &StepId,
        dispatch_consumed: bool,
    ) -> StepReconciliation {
        let Some(step) = operation.step(step_id) else {
            return StepReconciliation::Inspected;
        };
        if !dispatch_consumed || matches!(step.progress().state(), StepState::UnknownOutcome) {
            return StepReconciliation::Inspected;
        }
        // A consumed dispatch with no recorded submission possibly issued
        // a call.
        let dispatch: DispatchState = match step.progress().dispatch() {
            DispatchState::NotSubmitted => DispatchState::SubmissionUncertain,
            other => other.clone(),
        };
        let durability: Durability = step.progress().durability().clone();
        let failure: ActionError = action_error_with(
            code::EFFECT_NOT_ESTABLISHED,
            ErrorFamily::Outcome,
            ActionStage::Reconciliation,
            dispatch.clone(),
            Some(operation.plan_id()),
            Some(operation.operation_id()),
            Some(step_id),
        );
        let result: Option<TargetResult> = unknown_outcome(step.target_id(), dispatch, failure)
            .ok()
            .and_then(|result| {
                Checked::new(TargetResultRecord {
                    durability: durability.clone(),
                    ..result.into_inner()
                })
                .ok()
            });
        let mut next: Operation = operation.clone();
        let Some(result) = result else {
            return StepReconciliation::Inspected;
        };
        if next.settle_step(step_id, vec![result], durability).is_err() {
            // The state machine refuses `UnknownOutcome` also. The step
            // stays as the journal has it.
            return StepReconciliation::Inspected;
        }
        let saved: bool = next.step(step_id).is_some_and(|step| {
            self.journal
                .record_step(operation.operation_id(), step)
                .is_ok()
        });
        if !saved {
            return StepReconciliation::NotRecorded;
        }
        *operation = next;
        StepReconciliation::Inspected
    }
}

/// The result of a step of an earlier lifetime that got no call.
///
/// A force step whose target is in its final condition after the earlier
/// step is not necessary. Each other step is skipped: with the
/// cancellation when the operation has a stop fence, and as a failure of
/// the restart when it has none.
fn not_started(
    operation: &Operation,
    step_id: &StepId,
    target_id: &TargetId,
    stop_fence: bool,
) -> Result<TargetResult, Fault> {
    let earlier: Vec<&TargetResult> = operation
        .steps()
        .iter()
        .take_while(|step| step.step_id() != step_id)
        .filter(|step| step.target_id() == target_id)
        .flat_map(|step| step.results().iter())
        .collect();
    let earlier_done: bool = !earlier.is_empty()
        && earlier
            .iter()
            .all(|result| result.effect.is_final_condition_met());
    if earlier_done {
        return Checked::new(TargetResultRecord {
            target_id: target_id.clone(),
            member: None,
            dispatch: DispatchState::NotSubmitted,
            effect: TargetEffect::AlreadyExited,
            evidence: EffectEvidence::none(),
            attribution: Attribution::NotApplicable,
            durability: Durability::Durable,
            stop_reason: StopReason::Completed,
            failure: None,
        })
        .map_err(|_| Fault);
    }
    if stop_fence {
        return skipped(target_id, StopReason::Canceled, None);
    }
    skipped(
        target_id,
        StopReason::Failed,
        Some(action_error(
            code::EXECUTOR_RESTARTED,
            ErrorFamily::Evidence,
            ActionStage::Reconciliation,
            Some(operation.plan_id()),
            Some(operation.operation_id()),
            Some(step_id),
        )),
    )
}
