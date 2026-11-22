//! The acknowledgment of an `UnknownOutcome` operation.
//!
//! `docs/ACTION_CONTRACTS.md` section 12 owns the rule. An
//! `UnknownOutcome` operation holds the leases of its targets until a
//! reconciliation settles it. A user who accepts that the outcome stays
//! unknown acknowledges the operation (`svalnir operations acknowledge`).
//! The acknowledgment is durable, it releases the leases, and it does not
//! change the recorded result.

use svalnir_core::action::{ActionError, ActionStage, ErrorFamily, OperationState, Principal};
use svalnir_core::id::OperationId;

use super::core::Coordinator;
use super::error::{action_error, code};
use super::ports::{CoordinatorJournal, TimeReading};
use crate::journal::{Acknowledged, OperationJournalError, SequenceViolation};

impl<J: CoordinatorJournal> Coordinator<J> {
    /// Records the acknowledgment of the `UnknownOutcome` operation
    /// `operation_id` by `principal` and releases its leases. A repeated
    /// acknowledgment returns the first one and changes nothing.
    ///
    /// # Errors
    ///
    /// Returns the refusal, which changed nothing:
    ///
    /// | Code | Family | Cause |
    /// | --- | --- | --- |
    /// | `operation_not_found` | `evidence` | The journal has no such operation |
    /// | `operation_not_unknown_outcome` | `request` | The operation is in a different state |
    /// | `principal_mismatch` | `authority` | A different user applied the operation in this lifetime |
    /// | `reconciliation_pending` | `outcome` | The reconciliation after a restart is not complete |
    /// | `owner_process_alive` | `outcome` | A process of the command of an owner step lives |
    /// | `clock_unavailable` | `native` | The clock gave no value |
    /// | `acknowledgment_not_recorded` | `recording` | The journal did not record it |
    pub fn acknowledge(
        &mut self,
        operation_id: &OperationId,
        principal: &Principal,
    ) -> Result<Acknowledged, Box<ActionError>> {
        let refusal = |text: &str, family: ErrorFamily| {
            Box::new(action_error(
                text,
                family,
                ActionStage::Reconciliation,
                None,
                Some(operation_id),
                None,
            ))
        };
        if self.reconciliation_pending {
            return Err(refusal(code::RECONCILIATION_PENDING, ErrorFamily::Outcome));
        }
        if self
            .applicant(operation_id)
            .is_some_and(|applicant| applicant.uid != principal.uid)
        {
            return Err(refusal(code::PRINCIPAL_MISMATCH, ErrorFamily::Authority));
        }
        // A command of an owner step that still runs keeps the leases: the
        // records of the journal are read again, and the processes are
        // examined now (`docs/ACTION_CONTRACTS.md` section 7).
        let processes = self
            .journal
            .owner_processes(operation_id)
            .map_err(|_| refusal(code::ACKNOWLEDGMENT_NOT_RECORDED, ErrorFamily::Recording))?;
        if processes
            .iter()
            .any(|process| self.probe.owner_process_lives(process))
        {
            return Err(refusal(code::OWNER_PROCESS_ALIVE, ErrorFamily::Outcome));
        }
        let Some(time) = self.clock.now() else {
            return Err(refusal(code::CLOCK_UNAVAILABLE, ErrorFamily::Native));
        };
        let acknowledged: Acknowledged = self
            .journal
            .acknowledge_unknown_outcome(operation_id, principal, time.wall, &self.epoch)
            .map_err(|error| match error {
                OperationJournalError::NotFound => {
                    refusal(code::OPERATION_NOT_FOUND, ErrorFamily::Evidence)
                }
                OperationJournalError::Sequence(SequenceViolation::NotUnknownOutcome) => {
                    refusal(code::OPERATION_NOT_UNKNOWN_OUTCOME, ErrorFamily::Request)
                }
                _ => refusal(code::ACKNOWLEDGMENT_NOT_RECORDED, ErrorFamily::Recording),
            })?;
        self.release_acknowledged(operation_id, &time);
        Ok(acknowledged)
    }

    /// Releases the leases of an acknowledged operation: the resources
    /// that the ledger holds for an operation of an earlier lifetime, or
    /// the leases and the reservation of an `UnknownOutcome` operation of
    /// this lifetime.
    fn release_acknowledged(&mut self, operation_id: &OperationId, time: &TimeReading) {
        self.ledger.release_unknown(operation_id);
        let unknown: bool = self.parked.get(operation_id).is_some_and(|active| {
            !active.unrecorded && active.operation.state() == &OperationState::UnknownOutcome
        });
        if unknown && let Some(mut active) = self.parked.remove(operation_id) {
            self.release(&mut active, Some(time));
        }
    }
}
