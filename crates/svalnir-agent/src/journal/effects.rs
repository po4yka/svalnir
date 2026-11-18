//! The resource observations of an operation.
//!
//! The coordinator measures the available capacity of each volume of a
//! filesystem operation, and the memory pressure of an application
//! operation, before the first step and after the last one. The record of
//! the operation has no such value. This table keeps the observations
//! with the operation, so each client reads them from the journal and not
//! only the client that executed the operation.
//!
//! An observation is not an effect of the operation: a capacity change is
//! not exact causal reclamation, and an observation that is not available
//! is not zero (`docs/ACTION_CONTRACTS.md` section 9).

use rusqlite::{OptionalExtension, params};
use svalnir_core::action::ResourceEffect;
use svalnir_core::id::{ExecutorEpochId, OperationId};

use super::error::OperationJournalError;
use super::{OperationJournal, commit, coordination, decode, encode};

/// The largest size of the record of the resource observations of one
/// operation, in bytes of JSON.
pub const MAX_RESOURCE_EFFECTS_BYTES: usize = 64 * 1024;

impl OperationJournal {
    /// Records the resource observations of an operation. A second call
    /// for the operation replaces the record of the first one: the
    /// coordinator measures again after each batch, and the last
    /// measurement is the record.
    ///
    /// The retention removes the record with its operation.
    ///
    /// # Errors
    ///
    /// Returns [`OperationJournalError::NotFound`] when the journal has
    /// no such operation, [`OperationJournalError::RecordTooLarge`] for
    /// a record of more than [`MAX_RESOURCE_EFFECTS_BYTES`],
    /// [`OperationJournalError::Sequence`] when the executor lifetime of
    /// the operation is not the registered coordinator, or a storage
    /// error. On an error nothing was written.
    pub fn record_resource_effects(
        &mut self,
        operation_id: &OperationId,
        effects: &[ResourceEffect],
    ) -> Result<(), OperationJournalError> {
        let content: String = encode(&effects)?;
        if content.len() > MAX_RESOURCE_EFFECTS_BYTES {
            return Err(OperationJournalError::RecordTooLarge {
                size: content.len(),
                limit: MAX_RESOURCE_EFFECTS_BYTES,
            });
        }
        let Self {
            connection,
            commit_fault,
            ..
        } = self;
        let transaction = Self::write_transaction(connection)?;
        let stored: Option<(i64, String)> = transaction
            .query_row(
                "SELECT seq, executor_epoch FROM operation WHERE operation_id = ?1",
                [operation_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((seq, epoch)) = stored else {
            return Err(OperationJournalError::NotFound);
        };
        // Only the coordinator that executes the operation has its
        // measurements.
        let epoch: ExecutorEpochId = ExecutorEpochId::new(epoch)
            .map_err(|_| OperationJournalError::row("operation", "executor_epoch"))?;
        coordination::check_registered(&transaction, &epoch)?;
        transaction.execute(
            "INSERT INTO operation_effect (operation_seq, content) VALUES (?1, ?2) \
             ON CONFLICT (operation_seq) DO UPDATE SET content = excluded.content",
            params![seq, content],
        )?;
        commit(transaction, commit_fault)
    }

    /// The resource observations of an operation. The list is empty when
    /// the journal has no record for the operation: no measurement was
    /// recorded, which is not a measurement of no change.
    ///
    /// # Errors
    ///
    /// Returns a decode error when the stored record is not a list of
    /// observations, or a storage error.
    pub fn resource_effects(
        &self,
        operation_id: &OperationId,
    ) -> Result<Vec<ResourceEffect>, OperationJournalError> {
        let content: Option<String> = self
            .connection
            .query_row(
                "SELECT effect.content FROM operation_effect AS effect \
                 JOIN operation ON operation.seq = effect.operation_seq \
                 WHERE operation.operation_id = ?1",
                [operation_id.as_str()],
                |row| row.get(0),
            )
            .optional()?;
        content.map_or(Ok(Vec::new()), |content| {
            decode("operation_effect", &content)
        })
    }
}
