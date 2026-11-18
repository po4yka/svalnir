//! The journal interface.
//!
//! `docs/ACTION_CONTRACTS.md` sections 11 and 12 and `docs/ARCHITECTURE.md`
//! section 12 own the contract. This module has the interface and its
//! types. The durable implementation is in `svalnir-agent`
//! (`operations.sqlite`), and the helper has its own journal: the journal
//! of the agent is not proof that the helper recorded an intent.
//!
//! The contract of [`Journal`]:
//!
//! - A method returns `Ok` only after its record is durable. On an error,
//!   the caller does not issue the associated external call.
//! - A plan is consumed one time. A repeated apply returns the operation
//!   or the rejection that exists; it makes no second operation.
//! - The dispatch of a step is consumed one time, before the external
//!   call. A repeated dispatch makes no second call.
//! - A filesystem action always needs the durable journal.
//!   [`check_dispatch_recording`] is the rule.
//! - The journal is evidence for recovery. It is not an undo log.
//!
//! [`VolatileJournal`] is the bounded record of the critical-memory
//! exception.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::class::{ActionClass, TriggerClass};
use super::envelope::{RecordingMode, RequestEnvelope};
use super::error::{ActionError, ErrorFamily};
use super::operation::{Operation, Step};
use super::plan::{Plan, PlanApproval, Principal};
use super::state::Durability;
use crate::id::{ExecutorEpochId, OperationId, PlanId, StepId};

/// Whether the critical-memory exception can apply to a step: the step is
/// an application intervention and the original trigger is global critical
/// memory.
///
/// The exception never applies to a filesystem action, to manual process
/// control, or to an operation that an application-budget violation
/// admitted. A value that this build does not recognize gives `false`.
/// This function is a necessary condition only: admission also needs the
/// option, the grants, fresh pressure evidence, and bounded volatile
/// capacity.
pub fn critical_exception_applies(class: &ActionClass, trigger: &TriggerClass) -> bool {
    class.is_application_intervention() && matches!(trigger, TriggerClass::GlobalCriticalMemory)
}

/// The reason a dispatch is not permitted with the recording that exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RecordingRefusal {
    /// The intent and the dispatch consumption are not durable, and the
    /// critical-memory exception does not apply to the step.
    #[error("the step needs durable recording")]
    DurableRequired,
    /// The record is not durable and not volatile: a write failed, or the
    /// value is one that this build does not recognize.
    #[error("the step has no usable record")]
    NoRecord,
}

/// Checks that the record of a step permits its external call.
///
/// `recorded` is the durability of the intent and of the dispatch
/// consumption. `mode` is the recording that admission permitted for the
/// step.
///
/// # Errors
///
/// Returns [`RecordingRefusal::DurableRequired`] when `recorded` is
/// `volatile` and the step is not an application intervention that was
/// admitted under the critical-memory exception, and
/// [`RecordingRefusal::NoRecord`] when `recorded` is not `durable` and not
/// `volatile`.
pub fn check_dispatch_recording(
    class: &ActionClass,
    trigger: &TriggerClass,
    mode: &RecordingMode,
    recorded: &Durability,
) -> Result<(), RecordingRefusal> {
    match recorded {
        Durability::Durable => Ok(()),
        Durability::Volatile => {
            if matches!(mode, RecordingMode::VolatileCriticalException)
                && critical_exception_applies(class, trigger)
            {
                Ok(())
            } else {
                Err(RecordingRefusal::DurableRequired)
            }
        }
        _ => Err(RecordingRefusal::NoRecord),
    }
}

/// The reason a journal call failed. No record was made.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum JournalError {
    /// The journal cannot be opened or read.
    #[error("the journal is not available")]
    Unavailable,
    /// A different process held the lock of the journal for longer than
    /// the bounded wait of the call. The call wrote nothing. The storage
    /// did not fail: a later attempt can record. A locked journal is a
    /// refusal of this attempt, and it does not permit the critical-memory
    /// exception (`docs/ACTION_CONTRACTS.md` section 12).
    #[error("the journal is locked by a different process")]
    Busy,
    /// The storage is full, or the journal is at its size limit.
    #[error("the journal storage is full")]
    Full,
    /// The record was not synchronized to storage.
    #[error("the journal did not synchronize the record")]
    Sync,
    /// A stored record cannot be decoded.
    #[error("a journal record cannot be decoded")]
    Corrupt,
    /// The journal has no record with the identity.
    #[error("the journal has no record with the identity")]
    NotFound,
    /// The identity exists with different content. The same identity with
    /// different content is an invalid request; it is not an update.
    #[error("the identity exists with different content")]
    Conflict,
    /// The record is older than the retention of consumption records. An
    /// old request is rejected; it is not a new request.
    #[error("the record is older than the retention")]
    Expired,
    /// The record does not agree with the stored state, for example a
    /// dispatch consumption for a step that has no intent.
    #[error("the record does not agree with the stored state")]
    Sequence,
}

impl JournalError {
    /// The error family: `request` for a conflict, an old request, or a
    /// record out of sequence, and `recording` for a locked journal and
    /// each storage failure.
    pub fn family(&self) -> ErrorFamily {
        match self {
            Self::Conflict | Self::Expired | Self::Sequence | Self::NotFound => {
                ErrorFamily::Request
            }
            Self::Unavailable | Self::Busy | Self::Full | Self::Sync | Self::Corrupt => {
                ErrorFamily::Recording
            }
        }
    }
}

/// The result of an apply request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "admission", rename_all = "snake_case")]
pub enum Admission {
    /// The plan was not consumed. The journal recorded the consumption and
    /// the operation in one transaction.
    Admitted,
    /// An earlier apply consumed the plan. This is its operation in its
    /// current state. No second operation was made.
    Existing {
        /// The operation of the earlier apply.
        operation: Box<Operation>,
    },
    /// An earlier apply was rejected and the rejection was recorded.
    Rejected {
        /// The recorded rejection.
        error: ActionError,
    },
}

/// The result of a dispatch consumption.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DispatchConsumption {
    /// The step was not consumed. It is consumed now, and this caller can
    /// submit the external call one time.
    Consumed,
    /// The step was consumed before. This caller does not submit a call;
    /// it queries the state of the step.
    AlreadyConsumed,
    /// The operation has a stop fence. The step is not consumed and this
    /// caller does not submit a call.
    Fenced,
}

/// What a journal recorded for a dispatch consumption: the result, and
/// the durability of the record as the journal knows it.
///
/// The caller gives `durability` to [`check_dispatch_recording`]. It does
/// not use its own memory of which journal it called.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchReceipt {
    /// The result of the consumption.
    pub consumption: DispatchConsumption,
    /// The durability of the intent and consumption records.
    pub durability: Durability,
}

impl DispatchReceipt {
    /// Whether this caller can submit the external call of a step of
    /// `class` with the original trigger `trigger` and the recording mode
    /// `mode`: this call consumed the step, and
    /// [`check_dispatch_recording`] permits the record.
    pub fn permits_submission(
        &self,
        class: &ActionClass,
        trigger: &TriggerClass,
        mode: &RecordingMode,
    ) -> bool {
        matches!(self.consumption, DispatchConsumption::Consumed)
            && check_dispatch_recording(class, trigger, mode, &self.durability).is_ok()
    }
}

/// How a cancellation was recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopFence {
    /// The stop fence is durable. It survives a restart.
    Durable,
    /// The stop applies to the current executor instance only: the write
    /// failed or was not available.
    CurrentInstance,
}

/// The durable operation journal of one executor.
///
/// Each method that takes `&mut self` returns `Ok` only after its record
/// is durable.
pub trait Journal {
    /// Stores an immutable plan. The same plan again is not an error.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::Conflict`] when the identity of the plan
    /// exists with a different digest, or a storage error.
    fn record_plan(&mut self, plan: &Plan) -> Result<(), JournalError>;

    /// Reads a stored plan.
    ///
    /// # Errors
    ///
    /// Returns a storage error. A plan that does not exist is `Ok(None)`.
    fn plan(&self, plan_id: &PlanId) -> Result<Option<Plan>, JournalError>;

    /// Consumes the plan of `approval` for `operation`, or returns the
    /// result of the earlier apply.
    ///
    /// The plan consumption, the operation, and its budget reservations
    /// are one transaction. A plan is consumed one time for its plan
    /// identity, for each principal together. A repeated apply of the
    /// principal that consumed the plan returns
    /// [`Admission::Existing`] or [`Admission::Rejected`].
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::NotFound`] when the plan is not stored,
    /// [`JournalError::Conflict`] when the digest of `approval` is not the
    /// digest of the stored plan, when the identity of `operation` exists
    /// for a different plan, or when a different principal consumed the
    /// plan, [`JournalError::Expired`] when the
    /// consumption record is older than the retention, or a storage error.
    fn admit(
        &mut self,
        approval: &PlanApproval,
        principal: &Principal,
        operation: &Operation,
    ) -> Result<Admission, JournalError>;

    /// Records that the apply of a plan was rejected before admission, so
    /// that a repeated apply returns the same rejection.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::Conflict`] when the plan has an operation
    /// or when the digest of `approval` is not the digest of the stored
    /// plan, or a storage error. A refused call records nothing.
    fn record_rejection(
        &mut self,
        approval: &PlanApproval,
        principal: &Principal,
        error: &ActionError,
    ) -> Result<(), JournalError>;

    /// Records the intent of one step with its budget context. The step
    /// goes to `IntentCommitted` only after this call returns `Ok`.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::Conflict`] when the step has an intent with
    /// different content, or when the envelope is not the content of the
    /// stored plan (the target binding, the principal, the trigger, the
    /// authority, the executor, the escalation, or the grace period),
    /// [`JournalError::NotFound`] when the journal does not have the plan
    /// or the operation, or a storage error. A refused call records
    /// nothing.
    fn commit_intent(&mut self, envelope: &RequestEnvelope) -> Result<(), JournalError>;

    /// Consumes the dispatch of one step and its budget charge in one
    /// transaction. The same transaction reads the stop fence of the
    /// operation: when a fence exists, the result is
    /// [`DispatchConsumption::Fenced`] and the step is not consumed. The
    /// external call follows only [`DispatchConsumption::Consumed`]. The
    /// durability of the receipt is `durable`.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::Sequence`] when the step has no intent, or
    /// a storage error.
    fn consume_dispatch(
        &mut self,
        operation_id: &OperationId,
        step_id: &StepId,
    ) -> Result<DispatchReceipt, JournalError>;

    /// Records the progress and the target results of one step: the
    /// submission, the native response, and the observed outcome.
    ///
    /// # Errors
    ///
    /// Returns a storage error. The caller then keeps the result in
    /// memory with the durability `persistence_failed`.
    fn record_step(&mut self, operation_id: &OperationId, step: &Step) -> Result<(), JournalError>;

    /// Records the state of an operation.
    ///
    /// # Errors
    ///
    /// Returns a storage error.
    fn record_operation(&mut self, operation: &Operation) -> Result<(), JournalError>;

    /// Reads an operation.
    ///
    /// # Errors
    ///
    /// Returns a storage error. An operation that does not exist is
    /// `Ok(None)`.
    fn operation(&self, operation_id: &OperationId) -> Result<Option<Operation>, JournalError>;

    /// Reads the operations that are not settled, the oldest first, to a
    /// maximum of `limit`. A restart reconciles them before it admits
    /// conflicting work.
    ///
    /// # Errors
    ///
    /// Returns a storage error.
    fn unsettled_operations(&self, limit: usize) -> Result<Vec<Operation>, JournalError>;

    /// Records a stop fence for an operation. A fence inhibits the next
    /// dispatch; it does not recall a call that was issued. After this
    /// call returns `Ok`, each later `consume_dispatch` of a step that is
    /// not consumed returns [`DispatchConsumption::Fenced`]. A step that
    /// was consumed before the fence returns
    /// [`DispatchConsumption::AlreadyConsumed`]. Neither result permits a
    /// call.
    ///
    /// # Errors
    ///
    /// Returns a storage error. The caller then inhibits the dispatch of
    /// the current instance and reports [`StopFence::CurrentInstance`].
    fn set_stop_fence(&mut self, operation_id: &OperationId) -> Result<(), JournalError>;

    /// Whether an operation has a durable stop fence.
    ///
    /// # Errors
    ///
    /// Returns a storage error. The caller then does not dispatch.
    fn has_stop_fence(&self, operation_id: &OperationId) -> Result<bool, JournalError>;
}

/// The reason a volatile record was refused. No record was made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum VolatileJournalError {
    /// The request was not admitted under the critical-memory exception.
    #[error("the request was not admitted under the critical-memory exception")]
    NotPermitted,
    /// The request is from an earlier executor lifetime. It is not
    /// replayed.
    #[error("the request is from an earlier executor lifetime")]
    EarlierEpoch,
    /// The bounded record is full.
    #[error("the volatile record is full")]
    Full,
    /// The record has no step with the identity.
    #[error("the volatile record has no step with the identity")]
    NotFound,
}

/// The bounded in-memory record of the critical-memory exception, for one
/// executor lifetime.
///
/// A crash loses the record. After a restart that cannot establish the
/// earlier incident and budget state, the budget is exhausted
/// ([`SlotAllowance::exhausted`](super::budget::SlotAllowance::exhausted)).
pub trait VolatileJournal {
    /// The executor lifetime of the record.
    fn executor_epoch(&self) -> &ExecutorEpochId;

    /// The largest number of steps that the record can hold.
    fn capacity(&self) -> usize;

    /// Records the intent, the dispatch consumption, and the budget
    /// consumption of one step together, before the external call. The
    /// durability of the receipt is `volatile`. The executor of the
    /// exception keeps the current-instance stop of an operation in
    /// memory, and the result is [`DispatchConsumption::Fenced`] for an
    /// operation that it stopped.
    ///
    /// # Errors
    ///
    /// Returns [`VolatileJournalError::NotPermitted`] when
    /// [`check_dispatch_recording`] does not permit a volatile record for
    /// the action class, the trigger, and the recording mode of
    /// `envelope`,
    /// [`VolatileJournalError::EarlierEpoch`] when the executor lifetime
    /// of `envelope` is not the lifetime of this record, and
    /// [`VolatileJournalError::Full`] when the record is at its capacity.
    fn record_intent_and_consumption(
        &mut self,
        envelope: &RequestEnvelope,
    ) -> Result<DispatchReceipt, VolatileJournalError>;

    /// Records the progress and the target results of one step.
    ///
    /// # Errors
    ///
    /// Returns [`VolatileJournalError::NotFound`] when the step has no
    /// record.
    fn record_step(
        &mut self,
        operation_id: &OperationId,
        step: &Step,
    ) -> Result<(), VolatileJournalError>;

    /// The operations of the record, to write to the durable journal when
    /// it is available again. Their history stays marked `volatile`.
    fn pending_operations(&self) -> Vec<Operation>;
}

#[cfg(test)]
mod tests {
    use super::{
        Admission, DispatchConsumption, DispatchReceipt, JournalError, RecordingRefusal, StopFence,
        check_dispatch_recording, critical_exception_applies,
    };
    use crate::action::class::{ActionClass, TriggerClass};
    use crate::action::envelope::RecordingMode;
    use crate::action::error::ErrorFamily;
    use crate::action::state::Durability;

    fn triggers() -> [TriggerClass; 5] {
        [
            TriggerClass::Manual,
            TriggerClass::DiskPressure,
            TriggerClass::GlobalCriticalMemory,
            TriggerClass::ApplicationBudget,
            TriggerClass::from_wire("thermal"),
        ]
    }

    #[test]
    fn the_exception_applies_only_to_a_critical_memory_intervention() {
        for class in &ActionClass::ALL {
            for trigger in triggers() {
                let expected = class.is_application_intervention()
                    && trigger == TriggerClass::GlobalCriticalMemory;
                assert_eq!(
                    critical_exception_applies(class, &trigger),
                    expected,
                    "{class} {trigger}"
                );
            }
        }
        assert!(!critical_exception_applies(
            &ActionClass::from_wire("UnloadModel"),
            &TriggerClass::GlobalCriticalMemory
        ));
    }

    #[test]
    fn a_filesystem_action_fails_closed_without_a_durable_record() {
        let modes = [
            RecordingMode::Durable,
            RecordingMode::VolatileCriticalException,
            RecordingMode::from_wire("best_effort"),
        ];
        for class in ActionClass::ALL
            .iter()
            .filter(|class| class.is_filesystem())
        {
            for trigger in triggers() {
                for mode in &modes {
                    assert_eq!(
                        check_dispatch_recording(class, &trigger, mode, &Durability::Durable),
                        Ok(())
                    );
                    assert_eq!(
                        check_dispatch_recording(class, &trigger, mode, &Durability::Volatile),
                        Err(RecordingRefusal::DurableRequired)
                    );
                    for failed in [Durability::PersistenceFailed, Durability::from_wire("x")] {
                        assert_eq!(
                            check_dispatch_recording(class, &trigger, mode, &failed),
                            Err(RecordingRefusal::NoRecord)
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn a_volatile_record_permits_only_the_admitted_exception() {
        let volatile = Durability::Volatile;
        let exception = RecordingMode::VolatileCriticalException;
        let critical = TriggerClass::GlobalCriticalMemory;
        for class in [
            ActionClass::RequestApplicationExit,
            ActionClass::ForceApplicationExit,
        ] {
            assert_eq!(
                check_dispatch_recording(&class, &critical, &exception, &volatile),
                Ok(())
            );
            // Admission did not permit the exception.
            assert_eq!(
                check_dispatch_recording(&class, &critical, &RecordingMode::Durable, &volatile),
                Err(RecordingRefusal::DurableRequired)
            );
            // Manual process control and the budget trigger have no
            // exception.
            for trigger in [TriggerClass::Manual, TriggerClass::ApplicationBudget] {
                assert_eq!(
                    check_dispatch_recording(&class, &trigger, &exception, &volatile),
                    Err(RecordingRefusal::DurableRequired)
                );
            }
            assert_eq!(
                check_dispatch_recording(
                    &class,
                    &critical,
                    &exception,
                    &Durability::PersistenceFailed
                ),
                Err(RecordingRefusal::NoRecord)
            );
        }
    }

    #[test]
    fn a_receipt_permits_submission_only_for_a_consumed_step_with_a_usable_record() {
        let exit = ActionClass::RequestApplicationExit;
        let evict = ActionClass::EvictRegenerableData;
        let critical = TriggerClass::GlobalCriticalMemory;
        let exception = RecordingMode::VolatileCriticalException;
        let receipt = |consumption, durability| DispatchReceipt {
            consumption,
            durability,
        };
        let durable = receipt(DispatchConsumption::Consumed, Durability::Durable);
        assert!(durable.permits_submission(&evict, &TriggerClass::Manual, &RecordingMode::Durable));
        assert!(durable.permits_submission(&exit, &critical, &exception));
        // A repeated dispatch and a fenced operation submit no call.
        for consumption in [
            DispatchConsumption::AlreadyConsumed,
            DispatchConsumption::Fenced,
        ] {
            let receipt = receipt(consumption, Durability::Durable);
            assert!(!receipt.permits_submission(
                &evict,
                &TriggerClass::Manual,
                &RecordingMode::Durable
            ));
        }
        // The journal reports a volatile record: no filesystem call.
        let volatile = receipt(DispatchConsumption::Consumed, Durability::Volatile);
        assert!(!volatile.permits_submission(&evict, &TriggerClass::DiskPressure, &exception));
        assert!(volatile.permits_submission(&exit, &critical, &exception));
        assert!(!volatile.permits_submission(&exit, &critical, &RecordingMode::Durable));
        let value = serde_json::to_value(&volatile).unwrap();
        assert_eq!(
            value,
            serde_json::json!({ "consumption": "consumed", "durability": "volatile" })
        );
        assert_eq!(
            serde_json::from_value::<DispatchReceipt>(value).unwrap(),
            volatile
        );
    }

    #[test]
    fn a_journal_error_has_its_family() {
        for error in [
            JournalError::Unavailable,
            JournalError::Busy,
            JournalError::Full,
            JournalError::Sync,
            JournalError::Corrupt,
        ] {
            assert_eq!(error.family(), ErrorFamily::Recording, "{error}");
        }
        for error in [
            JournalError::Conflict,
            JournalError::Expired,
            JournalError::Sequence,
            JournalError::NotFound,
        ] {
            assert_eq!(error.family(), ErrorFamily::Request, "{error}");
        }
    }

    #[test]
    fn the_result_values_round_trip() {
        for (value, text) in [
            (DispatchConsumption::Consumed, "\"consumed\""),
            (DispatchConsumption::AlreadyConsumed, "\"already_consumed\""),
            (DispatchConsumption::Fenced, "\"fenced\""),
        ] {
            assert_eq!(serde_json::to_string(&value).unwrap(), text);
            assert_eq!(
                serde_json::from_str::<DispatchConsumption>(text).unwrap(),
                value
            );
        }
        // An unknown value is rejected. It is not read as `consumed`.
        assert!(serde_json::from_str::<DispatchConsumption>("\"maybe\"").is_err());
        for (value, text) in [
            (StopFence::Durable, "\"durable\""),
            (StopFence::CurrentInstance, "\"current_instance\""),
        ] {
            assert_eq!(serde_json::to_string(&value).unwrap(), text);
            assert_eq!(serde_json::from_str::<StopFence>(text).unwrap(), value);
        }
        assert!(serde_json::from_str::<StopFence>("\"none\"").is_err());
        let admitted = serde_json::to_value(Admission::Admitted).unwrap();
        assert_eq!(admitted, serde_json::json!({ "admission": "admitted" }));
        assert_eq!(
            serde_json::from_value::<Admission>(admitted).unwrap(),
            Admission::Admitted
        );
        assert!(
            serde_json::from_value::<Admission>(serde_json::json!({ "admission": "queued" }))
                .is_err()
        );
    }
}
