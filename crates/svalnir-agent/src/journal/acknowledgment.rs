//! The acknowledgment of an operation with an unknown outcome.
//!
//! An `UnknownOutcome` operation of an earlier executor lifetime holds the
//! leases of its targets until reconciliation settles it
//! (`docs/ACTION_CONTRACTS.md` section 12). For a target that no evidence
//! can settle, the user acknowledges the operation
//! (`svalnir operations acknowledge`). The acknowledgment releases the
//! leases. It does not change the recorded result: the operation stays
//! `UnknownOutcome`, and its history shows the acknowledgment and its
//! time. The row goes with its operation (`ON DELETE CASCADE`).

use rusqlite::{OptionalExtension, params};
use svalnir_core::action::{Operation, OperationState, Principal};
use svalnir_core::id::{ExecutorEpochId, OperationId};
use svalnir_core::time::WallTime;

use super::error::{OperationJournalError, SequenceViolation};
use super::{OperationJournal, commit, coordination, decode, encode, row};

/// The durable acknowledgment of an `UnknownOutcome` operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Acknowledgment {
    /// The wall-clock time of the acknowledgment, to the second.
    pub acknowledged_at: WallTime,
    /// The user and the client that acknowledged the operation.
    pub principal: Principal,
}

/// The result of an acknowledgment call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Acknowledged {
    /// The acknowledgment that the journal has.
    pub acknowledgment: Acknowledgment,
    /// True when an earlier call recorded the acknowledgment. The call
    /// then changed nothing.
    pub repeated: bool,
}

fn read(
    connection: &rusqlite::Connection,
    seq: i64,
) -> Result<Option<Acknowledgment>, OperationJournalError> {
    let stored: Option<(String, i64)> = connection
        .query_row(
            "SELECT principal, acknowledged_unix_s FROM operation_acknowledgment \
             WHERE operation_seq = ?1",
            [seq],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    stored
        .map(|(principal, seconds)| {
            Ok(Acknowledgment {
                acknowledged_at: WallTime::from_unix(seconds, 0).map_err(|_| {
                    OperationJournalError::row("operation_acknowledgment", "acknowledged_unix_s")
                })?,
                principal: decode("operation_acknowledgment", &principal)?,
            })
        })
        .transpose()
}

impl OperationJournal {
    /// Records the acknowledgment of the `UnknownOutcome` operation
    /// `operation_id` by `principal` at `at`. `epoch` is the executor
    /// lifetime of the coordinator that records it.
    ///
    /// A repeated call returns the first acknowledgment and changes
    /// nothing. The state of the operation does not change.
    ///
    /// # Errors
    ///
    /// Returns [`OperationJournalError::NotFound`] when the journal has
    /// no such operation, [`OperationJournalError::Sequence`] with
    /// [`SequenceViolation::NotUnknownOutcome`] when the operation is in a
    /// different state, or with [`SequenceViolation::ExecutorEpoch`] when
    /// `epoch` is not the registered coordinator, and a storage error. On
    /// an error nothing was written.
    pub fn acknowledge_unknown_outcome(
        &mut self,
        operation_id: &OperationId,
        principal: &Principal,
        at: WallTime,
        epoch: &ExecutorEpochId,
    ) -> Result<Acknowledged, OperationJournalError> {
        let Self {
            connection,
            commit_fault,
            ..
        } = self;
        let transaction = Self::write_transaction(connection)?;
        let seq: i64 = row::find_operation(&transaction, operation_id)?
            .ok_or(OperationJournalError::NotFound)?
            .seq;
        if let Some(acknowledgment) = read(&transaction, seq)? {
            return Ok(Acknowledged {
                acknowledgment,
                repeated: true,
            });
        }
        let operation: Operation = row::load_operation(&transaction, seq)?;
        if operation.state() != &OperationState::UnknownOutcome {
            return Err(SequenceViolation::NotUnknownOutcome.into());
        }
        coordination::check_registered(&transaction, epoch)?;
        let seconds: i64 = at.unix_seconds();
        transaction.execute(
            "INSERT INTO operation_acknowledgment \
             (operation_seq, principal, acknowledged_unix_s) VALUES (?1, ?2, ?3)",
            params![seq, encode(principal)?, seconds],
        )?;
        commit(transaction, commit_fault)?;
        Ok(Acknowledged {
            acknowledgment: Acknowledgment {
                acknowledged_at: WallTime::from_unix(seconds, 0).map_err(|_| {
                    OperationJournalError::row("operation_acknowledgment", "acknowledged_unix_s")
                })?,
                principal: principal.clone(),
            },
            repeated: false,
        })
    }

    /// The acknowledgment of an operation. `None` when the operation has
    /// none, or when the journal has no such operation.
    ///
    /// # Errors
    ///
    /// Returns a decode error for a stored record that is not valid, or a
    /// storage error.
    pub fn acknowledgment(
        &self,
        operation_id: &OperationId,
    ) -> Result<Option<Acknowledgment>, OperationJournalError> {
        let transaction = self.read_transaction()?;
        let Some(stored) = row::find_operation(&transaction, operation_id)? else {
            return Ok(None);
        };
        read(&transaction, stored.seq)
    }
}
