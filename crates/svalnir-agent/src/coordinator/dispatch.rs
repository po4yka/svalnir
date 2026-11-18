//! The dispatch of the steps of the active operation.
//!
//! For each step, in this sequence: the boundary check, the intent, the
//! dispatch consumption with its budget charge, the final check, the
//! executor call, and the record of the outcome. A step changes only
//! through the functions of [`Operation`], so each state is one that the
//! state machine of `docs/ACTION_CONTRACTS.md` section 6 permits.

use std::cell::Cell;

use svalnir_core::action::{
    ActionClass, ActionError, ActionStage, Attribution, CapacityEffect, Checked, Correlation,
    DispatchConsumption, DispatchReceipt, DispatchState, Durability, EffectEvidence,
    EnvelopeContent, ErrorFamily, Escalation, EvidenceBinding, NativeResult, Operation,
    OperationState, PLAN_SCHEMA_VERSION, PlanTarget, PlannedStep, RequestEnvelope, Reservation,
    ResourceEffect, StepLimits, StepState, StopReason, TargetBinding, TargetEffect, TargetResult,
    TargetResultRecord, VolatileJournal, VolatileJournalError, WorkCharge,
};
use svalnir_core::grant::{ActionRequest, RefusalReason};
use svalnir_core::id::{OperationId, StepId, TargetId, VolumeId};
use svalnir_core::quantity::ByteDelta;
use svalnir_core::state::PressureState;
use svalnir_core::time::MonotonicNanos;

use super::board::{Phase, StopAcknowledgement, StopView, WorkTotals};
use super::core::{Active, Coordinator, GracefulOutcome, MAX_MEASURED_VOLUMES, Observing};
use super::error::{action_error, action_error_with, code};
use super::ledger::Benefit;
use super::ports::{CoordinatorJournal, TimeReading, TriggerStanding};
use crate::executor::fs::{AdmittedStep, FsTargetOutcome, ProcessedWork, StepOutcome, Stop};
use crate::executor::process::{
    ExecutorError, GracefulRecord, NextStep, StepInput, StepReport, StepRun, StopRequest,
};

/// The result of one unit of work on the active operation.
#[derive(Debug)]
pub(super) enum Advance {
    /// The operation has more work that can start now.
    Continue(Box<Active>),
    /// The operation waits until a time.
    Wait(Box<Active>, MonotonicNanos),
    /// The operation left the active place: it is settled, or it is
    /// parked for reconciliation.
    Finished,
}

/// A defect: a record that the contract types rejected. The operation is
/// parked, and a restart reconciles it.
#[derive(Debug, Clone, Copy)]
pub(super) struct Fault;

/// What follows one step.
#[derive(Debug)]
enum StepEnd {
    /// The step has its result. The next step follows.
    Next,
    /// The operation stops. Each step with no result is skipped.
    Stop(StopReason, Option<ActionError>),
    /// The step waits until a time.
    Wait(MonotonicNanos),
}

/// A change of one step.
#[derive(Debug, Clone)]
enum Change {
    Advance(StepState, DispatchState),
    Settle(Vec<TargetResult>),
}

fn with_durability(
    results: Vec<TargetResult>,
    durability: &Durability,
) -> Result<Vec<TargetResult>, Fault> {
    results
        .into_iter()
        .map(|result| {
            Checked::new(TargetResultRecord {
                durability: durability.clone(),
                ..result.into_inner()
            })
            .map_err(|_| Fault)
        })
        .collect()
}

fn apply(
    operation: &mut Operation,
    step_id: &StepId,
    change: &Change,
    durability: &Durability,
) -> Result<(), Fault> {
    match change {
        Change::Advance(state, dispatch) => operation
            .advance_step(step_id, state.clone(), dispatch.clone(), durability.clone())
            .map_err(|_| Fault),
        Change::Settle(results) => operation
            .settle_step(
                step_id,
                with_durability(results.clone(), durability)?,
                durability.clone(),
            )
            .map_err(|_| Fault),
    }
}

/// A result for a target that got no call.
pub(super) fn skipped(
    target_id: &TargetId,
    reason: StopReason,
    failure: Option<ActionError>,
) -> Result<TargetResult, Fault> {
    Checked::new(TargetResultRecord {
        target_id: target_id.clone(),
        member: None,
        dispatch: DispatchState::NotSubmitted,
        effect: TargetEffect::Skipped,
        evidence: EffectEvidence::none(),
        attribution: Attribution::NotApplicable,
        durability: Durability::Durable,
        stop_reason: reason,
        failure,
    })
    .map_err(|_| Fault)
}

/// A result for a target whose effect is not known after a call that
/// was, or possibly was, submitted.
pub(super) fn unknown_outcome(
    target_id: &TargetId,
    dispatch: DispatchState,
    failure: ActionError,
) -> Result<TargetResult, Fault> {
    Checked::new(TargetResultRecord {
        target_id: target_id.clone(),
        member: None,
        dispatch,
        effect: TargetEffect::UnknownOutcome,
        evidence: EffectEvidence {
            native: NativeResult::Unavailable,
            ..EffectEvidence::none()
        },
        attribution: Attribution::Possible,
        durability: Durability::Durable,
        stop_reason: StopReason::Failed,
        failure: Some(failure),
    })
    .map_err(|_| Fault)
}

/// A result for a force step that is not necessary: each member is in
/// its final condition after the graceful step.
fn already_exited(target_id: &TargetId) -> Result<TargetResult, Fault> {
    Checked::new(TargetResultRecord {
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
    .map_err(|_| Fault)
}

/// The record of a result with no submitted call, for a step whose
/// dispatch was consumed. Such a step can only go to `NoAction`, so a
/// result with the stop reason `FAILED` gets `TARGET_SKIPPED` and keeps
/// its error: the final check did not permit the target, and no call was
/// issued.
fn without_failed_stop(result: TargetResult) -> Result<TargetResult, Fault> {
    if matches!(result.dispatch, DispatchState::NotSubmitted)
        && matches!(result.stop_reason, StopReason::Failed)
    {
        return Checked::new(TargetResultRecord {
            stop_reason: StopReason::TargetSkipped,
            ..result.into_inner()
        })
        .map_err(|_| Fault);
    }
    Ok(result)
}

/// The stop reason of a refused authorization at a dispatch boundary.
fn stop_reason_of(reason: RefusalReason) -> StopReason {
    match reason {
        RefusalReason::AutomationPaused => StopReason::Paused,
        RefusalReason::PlanExpired => StopReason::DeadlineExpired,
        RefusalReason::NoActivePolicyRevision
        | RefusalReason::PolicyRevisionMismatch
        | RefusalReason::GuardInhibited
        | RefusalReason::GuardNotRequested
        | RefusalReason::ObserveProfile
        | RefusalReason::GuardDisabled
        | RefusalReason::AcceptanceRequired
        | RefusalReason::ActionGrantMismatch
        | RefusalReason::RuleNotRegistered
        | RefusalReason::LayoutNotSupported
        | RefusalReason::RuleModeNotValidated => StopReason::PolicyChanged,
        RefusalReason::TriggerEvidenceMissing
        | RefusalReason::TriggerEvidenceStale
        | RefusalReason::MeasurementBeforeResume => StopReason::TriggerCleared,
        // A revoked, expired, or missing grant, and each other reason.
        _ => StopReason::AuthorityMissing,
    }
}

/// The stop of the filesystem executor for a stop reason of the final
/// check.
fn stop_signal_of(reason: &StopReason) -> Stop {
    match reason {
        StopReason::Paused => Stop::Paused,
        StopReason::PolicyChanged => Stop::PolicyChanged,
        StopReason::TriggerCleared => Stop::TriggerCleared,
        StopReason::DeadlineExpired => Stop::DeadlineExpired,
        StopReason::AuthorityMissing => Stop::AuthorityMissing,
        _ => Stop::Canceled,
    }
}

fn stop_request_of(reason: &StopReason) -> StopRequest {
    match reason {
        StopReason::Paused => StopRequest::Paused,
        StopReason::PolicyChanged => StopRequest::PolicyChanged,
        StopReason::TriggerCleared => StopRequest::TriggerCleared,
        StopReason::DeadlineExpired => StopRequest::DeadlineExpired,
        StopReason::AuthorityMissing => StopRequest::AuthorityMissing,
        _ => StopRequest::Canceled,
    }
}

/// Adds the work of one target to the totals of an operation. A sum that
/// does not fit makes the totals inexact.
fn add_work(totals: &mut WorkTotals, work: &ProcessedWork) {
    let mut exact: bool = work.exact;
    let entries = [
        (&mut totals.removed_entries, work.removed_entries),
        (&mut totals.trashed_entries, work.trashed_entries),
    ];
    for (sum, part) in entries {
        match sum.checked_add(part) {
            Some(next) => *sum = next,
            None => exact = false,
        }
    }
    let sizes = [
        (
            &mut totals.removed_logical_bytes,
            work.removed_logical_bytes,
        ),
        (
            &mut totals.removed_allocated_bytes,
            work.removed_allocated_bytes,
        ),
    ];
    for (sum, part) in sizes {
        match sum.checked_add(part) {
            Some(next) => *sum = next,
            None => exact = false,
        }
    }
    totals.exact &= exact;
}

fn is_force(step: &PlannedStep) -> bool {
    matches!(step.action_class, ActionClass::ForceApplicationExit)
}

impl<J: CoordinatorJournal> Coordinator<J> {
    /// Applies a change of one step and records it.
    ///
    /// A durable operation writes the record to the journal first. When
    /// the write fails, the step keeps the change in memory with the
    /// durability `persistence_failed`, and a later boundary writes it
    /// again. A volatile operation writes to the volatile record.
    fn record(
        &mut self,
        active: &mut Active,
        step_id: &StepId,
        change: &Change,
    ) -> Result<(), Fault> {
        let operation_id: OperationId = active.operation.operation_id().clone();
        if active.volatile {
            apply(
                &mut active.operation,
                step_id,
                change,
                &Durability::Volatile,
            )?;
            if let Some(step) = active.operation.step(step_id) {
                // The volatile record is degraded history already. A step
                // that it does not take stays in memory.
                let _kept: Result<(), VolatileJournalError> =
                    self.volatile.record_step(&operation_id, step);
            }
            return Ok(());
        }
        if !active.unsaved.contains(step_id) {
            let mut next: Operation = active.operation.clone();
            apply(&mut next, step_id, change, &Durability::Durable)?;
            let saved: bool = next
                .step(step_id)
                .is_some_and(|step| self.journal.record_step(&operation_id, step).is_ok());
            if saved {
                active.operation = next;
                return Ok(());
            }
        }
        apply(
            &mut active.operation,
            step_id,
            change,
            &Durability::PersistenceFailed,
        )?;
        active.unsaved.insert(step_id.clone());
        active.degraded = true;
        Ok(())
    }

    /// Writes the step records that an earlier write did not save.
    /// Returns true when the journal has each record.
    fn flush(&mut self, active: &mut Active) -> bool {
        let operation_id: OperationId = active.operation.operation_id().clone();
        let pending: Vec<StepId> = active.unsaved.iter().cloned().collect();
        for step_id in pending {
            let saved: bool = active
                .operation
                .step(&step_id)
                .is_some_and(|step| self.journal.record_step(&operation_id, step).is_ok());
            if !saved {
                return false;
            }
            active.unsaved.remove(&step_id);
        }
        true
    }

    fn envelope(&self, active: &Active, step: &PlannedStep) -> Result<RequestEnvelope, Fault> {
        let plan = &active.plan;
        let target: PlanTarget = plan.target(&step.target_id).cloned().ok_or(Fault)?;
        let (adapter, reservation) = match &target.binding {
            TargetBinding::File(file) => (
                self.config.filesystem_adapter.clone(),
                Reservation::Work {
                    charge: file.charge,
                },
            ),
            TargetBinding::Application(_) => (
                self.config.process_adapter.clone(),
                Reservation::ApplicationSlot {
                    incident_id: plan.trigger.incident_id.clone(),
                },
            ),
            // Admission refuses a plan with a process target, so no step
            // of one gets an envelope.
            TargetBinding::Process(_) => return Err(Fault),
        };
        Checked::new(EnvelopeContent {
            schema_version: PLAN_SCHEMA_VERSION,
            action_class: step.action_class.clone(),
            adapter,
            correlation: Correlation {
                plan_id: plan.plan_id.clone(),
                plan_digest: plan.digest().clone(),
                operation_id: active.operation.operation_id().clone(),
                step_id: step.step_id.clone(),
                parent_operation_id: None,
            },
            principal: plan.principal.clone(),
            executor: plan.executor.clone(),
            authority: plan.authority.clone(),
            trigger: plan.trigger.clone(),
            target,
            evidence: EvidenceBinding {
                clock_domain: plan.validity.clock_domain.clone(),
                boot_id: plan.validity.boot_id.clone(),
                executor_epoch: self.epoch.clone(),
                observed_at: plan.validity.created_at,
                valid_until: plan.validity.expires_at,
            },
            limits: StepLimits {
                reservation,
                deadline: active.deadline,
                grace: plan.limits.grace,
                verification_window: plan.limits.verification_window,
                escalation: plan.limits.escalation.clone(),
            },
            leases: active.leases.clone(),
            recording: active.recording(),
        })
        .map_err(|_| Fault)
    }

    /// The check of a dispatch boundary: the stop request, the deadline,
    /// the plan expiry, the leases, the trigger, and the authorization.
    /// `Some` is the reason to dispatch no further step.
    fn boundary(
        &self,
        active: &Active,
        step: &PlannedStep,
        stage: &ActionStage,
        time: &TimeReading,
    ) -> Option<StopReason> {
        let operation_id: &OperationId = active.operation.operation_id();
        if let Some(stop) = &active.stop {
            return Some(stop.reason.clone());
        }
        if self.board.stop_requested(operation_id) {
            return Some(StopReason::Canceled);
        }
        let now: MonotonicNanos = time.clock.now;
        if now >= active.deadline
            || active.plan.is_expired(&time.clock)
            || !self.ledger.holds(&active.leases, operation_id, now)
        {
            return Some(StopReason::DeadlineExpired);
        }
        let mut incident = None;
        let mut evidence = None;
        if active.is_automatic() {
            match self.authority.trigger(&active.plan, time) {
                TriggerStanding::Holds(stamp) => evidence = Some(stamp),
                TriggerStanding::Cleared | TriggerStanding::Unknown => {
                    return Some(StopReason::TriggerCleared);
                }
            }
            incident = active
                .plan
                .trigger
                .incident_id
                .as_ref()
                .and_then(|incident_id| self.authority.incident(incident_id));
        }
        let recording = active.recording();
        let request = ActionRequest {
            principal: active.principal.uid,
            plan: &active.plan,
            step_id: &step.step_id,
            stage: stage.clone(),
            approval: Some(&active.approval),
            recording: &recording,
            incident: incident.as_ref(),
            evidence: evidence.as_ref(),
        };
        self.authority
            .authorize(&request, time)
            .err()
            .map(|refusal| stop_reason_of(refusal.reason))
    }

    /// The final check immediately before a call: the boundary check and
    /// the durable stop fence, which a different process can write.
    ///
    /// The check reads the time again. The measurements, the intent, and
    /// the dispatch consumption are between the first check of the step
    /// and this one, and a storage transaction can take long: a deadline,
    /// a plan expiry, a lease, or a grant can end in that interval. With
    /// no time, no call is issued.
    fn final_check(&self, active: &Active, step: &PlannedStep) -> Option<StopReason> {
        let Some(time) = self.clock.now() else {
            return Some(StopReason::DeadlineExpired);
        };
        let time: &TimeReading = &time;
        if let Some(reason) = self.boundary(active, step, &ActionStage::Dispatch, time) {
            return Some(reason);
        }
        if active.volatile {
            return None;
        }
        // A fence that cannot be read permits no dispatch.
        match self.journal.has_stop_fence(active.operation.operation_id()) {
            Ok(false) => None,
            Ok(true) | Err(_) => Some(StopReason::Canceled),
        }
    }

    fn step_error(
        active: &Active,
        step: &PlannedStep,
        text: &str,
        family: ErrorFamily,
        stage: ActionStage,
    ) -> ActionError {
        action_error(
            text,
            family,
            stage,
            Some(&active.plan.plan_id),
            Some(active.operation.operation_id()),
            Some(&step.step_id),
        )
    }

    /// Records the intent and consumes the dispatch of a step. `Ok(Ok)`
    /// is the receipt of a consumption by this call. `Ok(Err)` ends the
    /// step with no call.
    fn consume(
        &mut self,
        active: &mut Active,
        step: &PlannedStep,
        envelope: &RequestEnvelope,
    ) -> Result<Result<DispatchReceipt, StepEnd>, Fault> {
        let step_id: &StepId = &step.step_id;
        let operation_id: OperationId = active.operation.operation_id().clone();
        if active.volatile {
            let Ok(receipt) = self.volatile.record_intent_and_consumption(envelope) else {
                let error = Self::step_error(
                    active,
                    step,
                    code::VOLATILE_RECORD_REFUSED,
                    ErrorFamily::Recording,
                    ActionStage::Intent,
                );
                return Ok(Err(StepEnd::Stop(StopReason::Failed, Some(error))));
            };
            return match receipt.consumption {
                DispatchConsumption::Consumed => {
                    active
                        .operation
                        .advance_step(
                            step_id,
                            StepState::DispatchConsumed,
                            DispatchState::NotSubmitted,
                            Durability::Volatile,
                        )
                        .map_err(|_| Fault)?;
                    Ok(Ok(receipt))
                }
                DispatchConsumption::Fenced => {
                    if active.stop.is_none() {
                        active.stop = Some(StopView {
                            reason: StopReason::Canceled,
                            acknowledgement: StopAcknowledgement::CurrentInstance,
                        });
                    }
                    Ok(Err(StepEnd::Stop(StopReason::Canceled, None)))
                }
                // A different caller consumed the step.
                DispatchConsumption::AlreadyConsumed => Err(Fault),
            };
        }
        // Fail closed: with no durable intent the step does not run.
        if self.journal.commit_intent(envelope).is_err() {
            let error = Self::step_error(
                active,
                step,
                code::INTENT_NOT_RECORDED,
                ErrorFamily::Recording,
                ActionStage::Intent,
            );
            return Ok(Err(StepEnd::Stop(StopReason::Failed, Some(error))));
        }
        active
            .operation
            .advance_step(
                step_id,
                StepState::IntentCommitted,
                DispatchState::NotSubmitted,
                Durability::Durable,
            )
            .map_err(|_| Fault)?;
        let Ok(receipt) = self.journal.consume_dispatch(&operation_id, step_id) else {
            let error = Self::step_error(
                active,
                step,
                code::DISPATCH_NOT_RECORDED,
                ErrorFamily::Recording,
                ActionStage::Dispatch,
            );
            return Ok(Err(StepEnd::Stop(StopReason::Failed, Some(error))));
        };
        match receipt.consumption {
            DispatchConsumption::Consumed => {
                active
                    .operation
                    .advance_step(
                        step_id,
                        StepState::DispatchConsumed,
                        DispatchState::NotSubmitted,
                        receipt.durability.clone(),
                    )
                    .map_err(|_| Fault)?;
                Ok(Ok(receipt))
            }
            DispatchConsumption::Fenced => {
                active.stop = Some(StopView {
                    reason: StopReason::Canceled,
                    acknowledgement: StopAcknowledgement::DurableFence,
                });
                Ok(Err(StepEnd::Stop(StopReason::Canceled, None)))
            }
            // A different caller consumed the step. This caller issues no
            // call, and it does not know the effect of the other one.
            DispatchConsumption::AlreadyConsumed => Err(Fault),
        }
    }

    /// Ends a consumed step with no call: the charge goes back to the
    /// reservation, and the step gets a skipped result.
    fn end_without_call(
        &mut self,
        active: &mut Active,
        step: &PlannedStep,
        charge: Option<WorkCharge>,
        charged: bool,
        reason: StopReason,
        failure: Option<ActionError>,
    ) -> Result<(), Fault> {
        if charged {
            self.ledger
                .refund(&mut active.hold, charge)
                .map_err(|_| Fault)?;
        }
        let result: TargetResult = skipped(&step.target_id, reason, failure)?;
        self.record(active, &step.step_id, &Change::Settle(vec![result]))
    }

    /// Charges the budget of a step whose dispatch was consumed. `None`
    /// means that no allowance has room: the step then ended with a
    /// skipped result and no call.
    fn charge_consumed(
        &mut self,
        active: &mut Active,
        step: &PlannedStep,
        charge: Option<WorkCharge>,
    ) -> Result<Option<bool>, Fault> {
        if let Ok(charged) = self.ledger.charge(&mut active.hold, charge) {
            return Ok(Some(charged));
        }
        let error = Self::step_error(
            active,
            step,
            code::BUDGET_EXHAUSTED,
            ErrorFamily::Limits,
            ActionStage::Dispatch,
        );
        self.end_without_call(
            active,
            step,
            charge,
            false,
            StopReason::TargetSkipped,
            Some(error),
        )?;
        Ok(None)
    }

    /// The target result of a filesystem call, with its work added to the
    /// totals of the operation.
    fn filesystem_result(
        active: &mut Active,
        step: &PlannedStep,
        outcome: StepOutcome,
    ) -> Result<TargetResult, Fault> {
        match outcome {
            Ok(FsTargetOutcome { result, work, .. }) => {
                add_work(&mut active.work, &work);
                Ok(result)
            }
            Err(fault) if matches!(fault.dispatch, DispatchState::NotSubmitted) => skipped(
                &step.target_id,
                StopReason::TargetSkipped,
                Some(Self::step_error(
                    active,
                    step,
                    code::EXECUTOR_FAULT,
                    ErrorFamily::Outcome,
                    ActionStage::Execution,
                )),
            ),
            Err(fault) => unknown_outcome(
                &step.target_id,
                fault.dispatch.clone(),
                action_error_with(
                    code::EXECUTOR_FAULT,
                    ErrorFamily::Outcome,
                    ActionStage::Execution,
                    fault.dispatch,
                    Some(&active.plan.plan_id),
                    Some(active.operation.operation_id()),
                    Some(&step.step_id),
                ),
            ),
        }
    }

    fn advance_filesystem(
        &mut self,
        active: &mut Active,
        step: &PlannedStep,
        time: &TimeReading,
    ) -> Result<StepEnd, Fault> {
        let Some(TargetBinding::File(file)) = active
            .plan
            .target(&step.target_id)
            .map(|t| t.binding.clone())
        else {
            return Err(Fault);
        };
        let charge: Option<WorkCharge> = Some(file.charge);
        if let Some(reason) = self.boundary(active, step, &ActionStage::Intent, time) {
            return Ok(StepEnd::Stop(reason, None));
        }
        self.take_baseline(active);
        let envelope: RequestEnvelope = self.envelope(active, step)?;
        let receipt: DispatchReceipt = match self.consume(active, step, &envelope)? {
            Ok(receipt) => receipt,
            Err(end) => return Ok(end),
        };
        // The budget charge belongs to the dispatch consumption.
        let Some(charged) = self.charge_consumed(active, step, charge)? else {
            return Ok(StepEnd::Next);
        };
        if let Some(reason) = self.final_check(active, step) {
            self.end_without_call(active, step, charge, charged, reason.clone(), None)?;
            return Ok(StepEnd::Stop(reason, None));
        }
        let Ok(admitted) = AdmittedStep::new(&envelope, &receipt) else {
            let error = Self::step_error(
                active,
                step,
                code::EXECUTOR_REFUSED_STEP,
                ErrorFamily::Request,
                ActionStage::Dispatch,
            );
            self.end_without_call(
                active,
                step,
                charge,
                charged,
                StopReason::TargetSkipped,
                Some(error),
            )?;
            return Ok(StepEnd::Next);
        };
        // The executor call. The status board is not locked here. The
        // executor reads the signal between the entries of a directory
        // target. The signal is the final check, read again: the stop
        // request, the deadline, the plan expiry, the leases, the trigger,
        // the authorization, and the durable stop fence.
        let stopped: Cell<Option<StopReason>> = Cell::new(None);
        let outcome: StepOutcome = {
            let active: &Active = active;
            let signal = || -> Option<Stop> {
                let stop: Stop = stop_signal_of(&self.final_check(active, step)?);
                stopped.set(Some(stop.stop_reason()));
                Some(stop)
            };
            self.filesystem.execute(&self.roots, admitted, &signal)
        };
        let result: TargetResult = Self::filesystem_result(active, step, outcome)?;
        self.settle_called(active, step, vec![result], charge, charged, false)?;
        // A stop inside a directory target ends the operation: the target
        // has the result that the executor gave (no call, a part removed,
        // or no effect), and each later step is skipped.
        if let Some(reason) = stopped.take() {
            return Ok(StepEnd::Stop(reason, None));
        }
        active.since_measurement = active.since_measurement.saturating_add(1);
        if active.since_measurement >= self.config.batch_targets.max(1) {
            self.measure(active);
        }
        Ok(StepEnd::Next)
    }

    /// Records the results of a step after its executor call returned.
    fn settle_called(
        &mut self,
        active: &mut Active,
        step: &PlannedStep,
        results: Vec<TargetResult>,
        charge: Option<WorkCharge>,
        charged: bool,
        verifying: bool,
    ) -> Result<(), Fault> {
        let submitted: bool = results
            .iter()
            .any(|result| matches!(result.dispatch, DispatchState::Submitted));
        let possibly: bool = results
            .iter()
            .any(|result| result.dispatch.is_possibly_submitted());
        let results: Vec<TargetResult> = if possibly {
            results
        } else {
            // The executor established that it issued no call.
            if charged {
                self.ledger
                    .refund(&mut active.hold, charge)
                    .map_err(|_| Fault)?;
            }
            results
                .into_iter()
                .map(without_failed_stop)
                .collect::<Result<_, _>>()?
        };
        if possibly && let (Some(unused), Some(charge)) = (active.unused, charge) {
            active.unused = unused.checked_sub(charge);
        }
        if submitted && !verifying {
            self.record(
                active,
                &step.step_id,
                &Change::Advance(StepState::Verifying, DispatchState::Submitted),
            )?;
        }
        self.record(active, &step.step_id, &Change::Settle(results))
    }

    fn advance_application(
        &mut self,
        active: &mut Active,
        step: &PlannedStep,
        time: &TimeReading,
    ) -> Result<StepEnd, Fault> {
        let Some(TargetBinding::Application(binding)) = active
            .plan
            .target(&step.target_id)
            .map(|t| t.binding.clone())
        else {
            return Err(Fault);
        };
        let follows_graceful: bool =
            is_force(step) && matches!(active.plan.limits.escalation, Escalation::ForceAfterGrace);
        let prior: Option<GracefulOutcome> = active.graceful.get(&step.target_id).cloned();
        if follows_graceful
            && let Some(end) = self.before_force(active, step, prior.as_ref(), time)?
        {
            return Ok(end);
        }
        if let Some(reason) = self.boundary(active, step, &ActionStage::Intent, time) {
            return Ok(StepEnd::Stop(reason, None));
        }
        self.take_baseline(active);
        let envelope: RequestEnvelope = self.envelope(active, step)?;
        let receipt: DispatchReceipt = match self.consume(active, step, &envelope)? {
            Ok(receipt) => receipt,
            Err(end) => return Ok(end),
        };
        // One slot for the operation, charged with the dispatch
        // consumption of its first step.
        let Some(charged) = self.charge_consumed(active, step, None)? else {
            let error = Self::step_error(
                active,
                step,
                code::BUDGET_EXHAUSTED,
                ErrorFamily::Limits,
                ActionStage::Dispatch,
            );
            return Ok(StepEnd::Stop(StopReason::Failed, Some(error)));
        };
        if let Some(reason) = self.final_check(active, step) {
            self.end_without_call(active, step, None, charged, reason.clone(), None)?;
            return Ok(StepEnd::Stop(reason, None));
        }
        let graceful: Option<GracefulRecord<'_>> = match (&prior, follows_graceful) {
            (Some(prior), true) => prior.submitted_at.map(|submitted_at| GracefulRecord {
                submitted_at,
                results: &prior.results,
            }),
            _ => None,
        };
        let input = StepInput {
            envelope: &envelope,
            receipt: &receipt,
            protection: self.authority.protection(&binding),
            graceful,
            stop: None,
        };
        // The executor call. It issues the request and returns; the exit
        // is observed in the later calls of `step`.
        let run: Result<StepRun, ExecutorError> = self.application.begin(input);
        self.after_begin(active, step, run, charged, time)
    }

    /// Decides whether the force step of the strategy `force_after_grace`
    /// can start. `Some` ends the step with no dispatch: the grace period
    /// is not complete, a stop request ended the graceful step, or the
    /// force step is not applicable.
    fn before_force(
        &mut self,
        active: &mut Active,
        step: &PlannedStep,
        prior: Option<&GracefulOutcome>,
        time: &TimeReading,
    ) -> Result<Option<StepEnd>, Fault> {
        let not_applicable = |text: &str, family: ErrorFamily| {
            skipped(
                &step.target_id,
                StopReason::TargetSkipped,
                Some(Self::step_error(
                    active,
                    step,
                    text,
                    family,
                    ActionStage::Dispatch,
                )),
            )
        };
        let result: TargetResult = match prior.map(|graceful| (graceful, graceful.next)) {
            None => not_applicable(code::FORCE_NOT_APPLICABLE, ErrorFamily::Eligibility)?,
            Some((graceful, NextStep::Force { not_before })) => {
                if time.clock.now < not_before {
                    // A stop request and the deadline end the wait.
                    let stopped: Option<StopReason> = match &active.stop {
                        Some(view) => Some(view.reason.clone()),
                        None if self.board.stop_requested(active.operation.operation_id()) => {
                            Some(StopReason::Canceled)
                        }
                        None if time.clock.now >= active.deadline => {
                            Some(StopReason::DeadlineExpired)
                        }
                        None => None,
                    };
                    return Ok(Some(match stopped {
                        Some(reason) => StepEnd::Stop(reason, None),
                        None => StepEnd::Wait(not_before),
                    }));
                }
                if graceful.submitted_at.is_some() {
                    return Ok(None);
                }
                not_applicable(code::GRACE_NOT_ESTABLISHED, ErrorFamily::Evidence)?
            }
            Some((_, NextStep::Stopped(request))) => {
                return Ok(Some(StepEnd::Stop(request.reason(), None)));
            }
            Some((_, NextStep::Reconcile)) => {
                not_applicable(code::RECONCILE_BEFORE_FORCE, ErrorFamily::Outcome)?
            }
            Some((graceful, NextStep::None | NextStep::ForceNotPermitted)) => {
                let done: bool = !graceful.results.is_empty()
                    && graceful
                        .results
                        .iter()
                        .all(|result| result.effect.is_final_condition_met());
                if done {
                    already_exited(&step.target_id)?
                } else {
                    not_applicable(code::FORCE_NOT_APPLICABLE, ErrorFamily::Eligibility)?
                }
            }
        };
        self.record(active, &step.step_id, &Change::Settle(vec![result]))?;
        Ok(Some(StepEnd::Next))
    }

    /// Records what the start of an application step returned.
    fn after_begin(
        &mut self,
        active: &mut Active,
        step: &PlannedStep,
        run: Result<StepRun, ExecutorError>,
        charged: bool,
        time: &TimeReading,
    ) -> Result<StepEnd, Fault> {
        match run {
            Ok(StepRun::Finished(report)) => {
                self.take_report(active, step, &report, charged, false)?;
                Ok(StepEnd::Next)
            }
            Ok(StepRun::Observing(observation)) => {
                self.record(
                    active,
                    &step.step_id,
                    &Change::Advance(StepState::Verifying, DispatchState::Submitted),
                )?;
                let window_end: MonotonicNanos = observation.window_ends_at();
                let next_poll: MonotonicNanos = self.next_poll(time.clock.now, window_end);
                active.observing = Some(Observing {
                    observation,
                    next_poll,
                    charged,
                });
                Ok(StepEnd::Wait(next_poll))
            }
            // The checks before the first call: no call was issued.
            Err(
                ExecutorError::NotApplicationStep
                | ExecutorError::DispatchNotConsumed(_)
                | ExecutorError::Recording(_)
                | ExecutorError::GracefulRecord,
            ) => {
                let error = Self::step_error(
                    active,
                    step,
                    code::EXECUTOR_REFUSED_STEP,
                    ErrorFamily::Request,
                    ActionStage::Dispatch,
                );
                self.end_without_call(
                    active,
                    step,
                    None,
                    charged,
                    StopReason::TargetSkipped,
                    Some(error),
                )?;
                Ok(StepEnd::Next)
            }
            // A defect of the executor after its checks. A call to a
            // member was possibly issued, so the charge stays and the
            // effect is not known.
            Err(_) => {
                let dispatch = DispatchState::SubmissionUncertain;
                let failure: ActionError = action_error_with(
                    code::EXECUTOR_FAULT,
                    ErrorFamily::Outcome,
                    ActionStage::Execution,
                    dispatch.clone(),
                    Some(&active.plan.plan_id),
                    Some(active.operation.operation_id()),
                    Some(&step.step_id),
                );
                let result = unknown_outcome(&step.target_id, dispatch, failure)?;
                self.record(active, &step.step_id, &Change::Settle(vec![result]))?;
                Ok(StepEnd::Stop(StopReason::Failed, None))
            }
        }
    }

    fn next_poll(&self, now: MonotonicNanos, window_end: MonotonicNanos) -> MonotonicNanos {
        now.checked_add(self.config.poll_interval)
            .map_or(window_end, |next| next.min(window_end))
    }

    /// Records the report of a finished application step.
    fn take_report(
        &mut self,
        active: &mut Active,
        step: &PlannedStep,
        report: &StepReport,
        charged: bool,
        verifying: bool,
    ) -> Result<(), Fault> {
        let results: Vec<TargetResult> = report.results();
        if !is_force(step) {
            active.graceful.insert(
                step.target_id.clone(),
                GracefulOutcome {
                    submitted_at: report.submitted_at,
                    results: results.clone(),
                    next: report.next,
                },
            );
        }
        self.settle_called(active, step, results, None, charged, verifying)
    }

    /// Reads an exit observation one time when its poll time came, or at
    /// once when the operation has a stop request.
    fn advance_observation(
        &mut self,
        active: &mut Active,
        step: &PlannedStep,
        observing: Observing,
        time: &TimeReading,
    ) -> Result<StepEnd, Fault> {
        let now: MonotonicNanos = time.clock.now;
        let request: Option<StopRequest> = match &active.stop {
            Some(view) => Some(stop_request_of(&view.reason)),
            None if self.board.stop_requested(active.operation.operation_id()) => {
                Some(StopRequest::Canceled)
            }
            None if now >= active.deadline => Some(StopRequest::DeadlineExpired),
            None => None,
        };
        if request.is_none() && now < observing.next_poll {
            let until: MonotonicNanos = observing.next_poll;
            active.observing = Some(observing);
            return Ok(StepEnd::Wait(until));
        }
        let Observing {
            observation,
            charged,
            ..
        } = observing;
        match self.application.poll(observation, request) {
            Ok(StepRun::Observing(observation)) => {
                let window_end: MonotonicNanos = observation.window_ends_at();
                // A window that ended is read again at the next call.
                let next_poll: MonotonicNanos = self.next_poll(now, window_end).max(now);
                active.observing = Some(Observing {
                    observation,
                    next_poll,
                    charged,
                });
                if next_poll > now {
                    Ok(StepEnd::Wait(next_poll))
                } else {
                    Ok(StepEnd::Wait(now))
                }
            }
            Ok(StepRun::Finished(report)) => {
                self.take_report(active, step, &report, charged, true)?;
                Ok(StepEnd::Next)
            }
            Err(_) => {
                // A call was issued, and the executor gave no result.
                let failure: ActionError = action_error_with(
                    code::EXECUTOR_FAULT,
                    ErrorFamily::Outcome,
                    ActionStage::Verification,
                    DispatchState::Submitted,
                    Some(&active.plan.plan_id),
                    Some(active.operation.operation_id()),
                    Some(&step.step_id),
                );
                let result = unknown_outcome(&step.target_id, DispatchState::Submitted, failure)?;
                self.record(active, &step.step_id, &Change::Settle(vec![result]))?;
                Ok(StepEnd::Stop(StopReason::Failed, None))
            }
        }
    }

    /// Does one unit of work on the active operation.
    pub(super) fn advance(&mut self, mut active: Box<Active>, time: &TimeReading) -> Advance {
        // A record that an earlier write did not save goes to the journal
        // before the next step. With no journal, no further step runs.
        if !active.volatile
            && !active.unsaved.is_empty()
            && active.observing.is_none()
            && !self.flush(&mut active)
        {
            let error: ActionError = action_error(
                code::INTENT_NOT_RECORDED,
                ErrorFamily::Recording,
                ActionStage::Intent,
                Some(&active.plan.plan_id),
                Some(active.operation.operation_id()),
                None,
            );
            self.stop_and_finish(active, &StopReason::Failed, Some(error), Some(time));
            return Advance::Finished;
        }
        let Some(step) = active.plan.steps.get(active.next_step).cloned() else {
            self.finish(active, Some(time));
            return Advance::Finished;
        };
        let is_file: bool = matches!(
            active.plan.target(&step.target_id).map(|t| &t.binding),
            Some(TargetBinding::File(_))
        );
        let end: Result<StepEnd, Fault> = match active.observing.take() {
            Some(observing) => self.advance_observation(&mut active, &step, observing, time),
            None if is_file => self.advance_filesystem(&mut active, &step, time),
            None => self.advance_application(&mut active, &step, time),
        };
        match end {
            Ok(StepEnd::Next) => {
                active.next_step = active.next_step.saturating_add(1);
                self.board.publish(active.view(Phase::Running));
                Advance::Continue(active)
            }
            Ok(StepEnd::Wait(until)) => {
                let phase: Phase = active
                    .observing
                    .as_ref()
                    .map_or(Phase::Running, |observing| Phase::Observing {
                        until: observing.observation.window_ends_at(),
                    });
                self.board.publish(active.view(phase));
                if until <= time.clock.now {
                    Advance::Continue(active)
                } else {
                    Advance::Wait(active, until)
                }
            }
            Ok(StepEnd::Stop(reason, failure)) => {
                self.stop_and_finish(active, &reason, failure, Some(time));
                Advance::Finished
            }
            Err(Fault) => {
                self.park(active);
                Advance::Finished
            }
        }
    }

    /// Gives each step that has no result a skipped result with the stop
    /// reason, and settles the operation.
    pub(super) fn stop_and_finish(
        &mut self,
        mut active: Box<Active>,
        reason: &StopReason,
        failure: Option<ActionError>,
        time: Option<&TimeReading>,
    ) {
        if active.stop.is_none() && !matches!(reason, &StopReason::Failed) {
            active.stop = Some(StopView {
                reason: reason.clone(),
                acknowledgement: StopAcknowledgement::CurrentInstance,
            });
        }
        // A stop reason `FAILED` or `TARGET_SKIPPED` has an error record.
        let needs_failure: bool =
            matches!(reason, &(StopReason::Failed | StopReason::TargetSkipped));
        let failure: Option<ActionError> = if needs_failure {
            Some(failure.unwrap_or_else(|| {
                action_error(
                    code::EFFECT_NOT_ESTABLISHED,
                    ErrorFamily::Outcome,
                    ActionStage::Dispatch,
                    Some(&active.plan.plan_id),
                    Some(active.operation.operation_id()),
                    None,
                )
            }))
        } else {
            None
        };
        let open: Vec<(StepId, TargetId, StepState)> = active
            .operation
            .steps()
            .iter()
            .filter(|step| step.results().is_empty())
            .map(|step| {
                (
                    step.step_id().clone(),
                    step.target_id().clone(),
                    step.progress().state().clone(),
                )
            })
            .collect();
        for (step_id, target_id, state) in open {
            let result: Result<TargetResult, Fault> = match state {
                // The call of the step was issued, and it has no result.
                StepState::Verifying => unknown_outcome(
                    &target_id,
                    DispatchState::Submitted,
                    action_error_with(
                        code::EFFECT_NOT_ESTABLISHED,
                        ErrorFamily::Outcome,
                        ActionStage::Verification,
                        DispatchState::Submitted,
                        Some(&active.plan.plan_id),
                        Some(active.operation.operation_id()),
                        Some(&step_id),
                    ),
                ),
                // A consumed step can only go to `NoAction`.
                StepState::DispatchConsumed if matches!(reason, &StopReason::Failed) => {
                    skipped(&target_id, StopReason::TargetSkipped, failure.clone())
                }
                _ => skipped(&target_id, reason.clone(), failure.clone()),
            };
            let recorded: Result<(), Fault> = result.and_then(|result| {
                self.record(&mut active, &step_id, &Change::Settle(vec![result]))
            });
            if recorded.is_err() {
                self.park(active);
                return;
            }
        }
        self.finish(active, time);
    }

    /// Takes the measurements before the first step of an operation.
    fn take_baseline(&mut self, active: &mut Active) {
        if active.baseline.taken {
            return;
        }
        active.baseline.taken = true;
        let mut volumes: Vec<VolumeId> = Vec::new();
        let mut has_application: bool = false;
        for target in &active.plan.targets {
            match &target.binding {
                TargetBinding::File(file) => {
                    if !volumes.contains(&file.volume_id) && volumes.len() < MAX_MEASURED_VOLUMES {
                        volumes.push(file.volume_id.clone());
                    }
                }
                TargetBinding::Application(_) | TargetBinding::Process(_) => {
                    has_application = true;
                }
            }
        }
        for volume in volumes {
            let before = self.measurements.capacity(&volume);
            active.baseline.capacity.push((volume, before));
        }
        if has_application {
            active.baseline.pressure = Some(self.measurements.memory_pressure());
        }
    }

    /// Takes the measurements after a batch and replaces the resource
    /// effects of the operation. The values are observations: a change is
    /// not exact causal reclamation, and no value is not zero.
    fn measure(&mut self, active: &mut Active) {
        active.since_measurement = 0;
        if !active.baseline.taken {
            return;
        }
        let mut effects: Vec<ResourceEffect> = Vec::new();
        for (volume, before) in &active.baseline.capacity {
            let after = self.measurements.capacity(volume);
            effects.push(ResourceEffect::Capacity(CapacityEffect::new(
                before.clone(),
                after,
            )));
        }
        if let Some(before) = &active.baseline.pressure {
            effects.push(ResourceEffect::MemoryPressure {
                before: before.clone(),
                after: self.measurements.memory_pressure(),
            });
        }
        active.effects = effects;
    }

    /// The benefit of a settled automatic operation, from its
    /// measurements.
    fn benefit(active: &Active, min_gain: Option<ByteDelta>) -> Benefit {
        if !super::core::possibly_submitted(&active.operation) {
            return Benefit::NoCall;
        }
        if matches!(
            active.operation.state(),
            OperationState::Failed | OperationState::UnknownOutcome
        ) {
            return Benefit::LowOrFailed;
        }
        let improved: bool = active.effects.iter().any(|effect| match effect {
            ResourceEffect::Capacity(capacity) => capacity
                .delta()
                .zip(min_gain)
                .is_some_and(|(delta, min_gain)| delta > ByteDelta::ZERO && delta >= min_gain),
            ResourceEffect::MemoryPressure { before, after } => {
                match (before.value(), after.value()) {
                    (Some(before), Some(after)) => pressure_rank(after)
                        .zip(pressure_rank(before))
                        .is_some_and(|(after, before)| after < before),
                    _ => false,
                }
            }
            ResourceEffect::Unrecognized => false,
        });
        if improved {
            Benefit::Observed
        } else {
            Benefit::LowOrFailed
        }
    }

    /// Settles an operation whose steps each have a result.
    pub(super) fn finish(&mut self, mut active: Box<Active>, time: Option<&TimeReading>) {
        if possibly_called(&active.operation) {
            self.measure(&mut active);
        }
        if active.operation.settle().is_err() {
            self.park(active);
            return;
        }
        let operation_id: OperationId = active.operation.operation_id().clone();
        let recorded: bool = if active.volatile {
            drop(self.volatile.settle_operation(&operation_id));
            true
        } else {
            self.flush(&mut active) && self.journal.record_operation(&active.operation).is_ok()
        };
        let unknown: bool = matches!(active.operation.state(), OperationState::UnknownOutcome);
        if let Some(stop) = &mut active.stop
            && !unknown
            && recorded
        {
            stop.acknowledgement = StopAcknowledgement::Settled;
        }
        if !recorded {
            active.degraded = true;
            active.unrecorded = true;
        }
        self.board.publish(active.view(Phase::Finished));
        self.board.set_recorded(&operation_id, recorded);
        if unknown || !recorded {
            // The leases and the reservation stay: a conflicting step
            // needs a reconciliation first.
            self.parked.insert(operation_id, active);
            return;
        }
        self.release(&mut active, time);
    }

    /// Releases the leases and the unused reservation of a settled
    /// operation, and applies the pacing of its incident.
    pub(super) fn release(&mut self, active: &mut Active, time: Option<&TimeReading>) {
        let operation_id: OperationId = active.operation.operation_id().clone();
        let unused: Option<WorkCharge> = active.unused;
        self.ledger.release(&mut active.hold, unused);
        self.ledger.release_leases(&operation_id);
        if let (Some(incident_id), Some(time)) = (active.hold.incident().cloned(), time) {
            let min_gain: Option<ByteDelta> = self.ledger.min_capacity_gain(&incident_id);
            let benefit: Benefit = Self::benefit(active, min_gain);
            self.ledger.pace(&incident_id, benefit, time.clock.now);
        }
    }

    /// Takes an operation out of the active place with no settlement: a
    /// record was rejected, so its state is not established. Its leases
    /// and its reservation stay, its journal record stays unsettled, and
    /// a restart reconciles it.
    pub(super) fn park(&mut self, mut active: Box<Active>) {
        active.degraded = true;
        active.observing = None;
        self.board.publish(active.view(Phase::Finished));
        self.parked
            .insert(active.operation.operation_id().clone(), active);
    }

    /// Writes the records of the parked operations that have a result
    /// in memory and not in the journal. An operation that the journal
    /// took and that is settled is released. An `UnknownOutcome`
    /// operation stays parked with its leases.
    pub(super) fn retry_parked(&mut self, time: &TimeReading) {
        let pending: Vec<OperationId> = self
            .parked
            .iter()
            .filter(|(_, active)| active.unrecorded && !active.volatile)
            .map(|(operation_id, _)| operation_id.clone())
            .collect();
        for operation_id in pending {
            let Some(mut active) = self.parked.remove(&operation_id) else {
                continue;
            };
            let saved: bool =
                self.flush(&mut active) && self.journal.record_operation(&active.operation).is_ok();
            if saved {
                active.unrecorded = false;
                self.board.set_recorded(&operation_id, true);
            }
            if saved && active.operation.state().is_settled() {
                if let Some(stop) = &mut active.stop {
                    stop.acknowledgement = StopAcknowledgement::Settled;
                }
                self.release(&mut active, Some(time));
                self.board.publish(active.view(Phase::Finished));
            } else {
                self.parked.insert(operation_id, active);
            }
        }
    }
}

/// The rank of a pressure state. A state that this build does not
/// recognize has no rank.
fn pressure_rank(state: &PressureState) -> Option<u8> {
    match state {
        PressureState::Normal => Some(0),
        PressureState::Warning => Some(1),
        PressureState::Critical => Some(2),
        PressureState::Unrecognized(_) => None,
    }
}

fn possibly_called(operation: &Operation) -> bool {
    operation
        .steps()
        .iter()
        .any(|step| step.progress().dispatch().is_possibly_submitted())
}
