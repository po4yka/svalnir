//! The process of the command of an owner step (`docs/ACTION_CONTRACTS.md`
//! section 7, the subsection of `RunOwnerOperation`).
//!
//! The coordinator records the process ID, the start time, and the process
//! group of the command while the process is suspended, before it runs. A
//! later acknowledgment of the operation reads the record again and is
//! refused while a process of the command lives. The row goes with its
//! operation (`ON DELETE CASCADE`).

use rusqlite::params;
use svalnir_core::id::{OperationId, StepId};
use svalnir_core::process::ProcessStartTime;

use super::error::OperationJournalError;
use super::{OperationJournal, commit, row};

/// The process of the command of one owner step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnerProcess {
    /// The process ID of the command.
    pub pid: i32,
    /// The start time of the process, as the kernel reports it.
    pub started: ProcessStartTime,
    /// The process group of the command. The command is its leader.
    pub group: i32,
}

/// The largest number of process records that one operation has: one for
/// each step of a plan.
const MAX_OWNER_PROCESSES: i64 = 4096;

impl OperationJournal {
    /// Records the process of the command of the step `step_id` of
    /// `operation_id`. A second record of one step replaces the first.
    ///
    /// # Errors
    ///
    /// Returns [`OperationJournalError::NotFound`] when the journal has no
    /// such operation, and a storage error. On an error nothing was
    /// written.
    pub fn record_owner_process(
        &mut self,
        operation_id: &OperationId,
        step_id: &StepId,
        process: &OwnerProcess,
    ) -> Result<(), OperationJournalError> {
        let started: i64 = i64::try_from(process.started.get())
            .map_err(|_| OperationJournalError::row("owner_process", "started_us"))?;
        let Self {
            connection,
            commit_fault,
            ..
        } = self;
        let transaction = Self::write_transaction(connection)?;
        let seq: i64 = row::find_operation(&transaction, operation_id)?
            .ok_or(OperationJournalError::NotFound)?
            .seq;
        transaction.execute(
            "INSERT OR REPLACE INTO owner_process \
             (operation_seq, step_id, pid, started_us, process_group) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![seq, step_id.as_str(), process.pid, started, process.group],
        )?;
        commit(transaction, commit_fault)?;
        Ok(())
    }

    /// The process records of the owner steps of `operation_id`. Empty
    /// when the operation has none or the journal has no such operation.
    ///
    /// # Errors
    ///
    /// Returns a decode error for a stored record that is not valid, or a
    /// storage error.
    pub fn owner_processes(
        &self,
        operation_id: &OperationId,
    ) -> Result<Vec<OwnerProcess>, OperationJournalError> {
        let transaction = self.read_transaction()?;
        let Some(stored) = row::find_operation(&transaction, operation_id)? else {
            return Ok(Vec::new());
        };
        let mut statement = transaction.prepare(
            "SELECT pid, started_us, process_group FROM owner_process \
             WHERE operation_seq = ?1 ORDER BY step_id LIMIT ?2",
        )?;
        let rows = statement.query_map(params![stored.seq, MAX_OWNER_PROCESSES], |row| {
            Ok((
                row.get::<_, i32>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i32>(2)?,
            ))
        })?;
        let mut processes: Vec<OwnerProcess> = Vec::new();
        for entry in rows {
            let (pid, started, group) = entry?;
            let started: u64 = u64::try_from(started)
                .map_err(|_| OperationJournalError::row("owner_process", "started_us"))?;
            processes.push(OwnerProcess {
                pid,
                started: ProcessStartTime::new(started),
                group,
            });
        }
        Ok(processes)
    }
}
