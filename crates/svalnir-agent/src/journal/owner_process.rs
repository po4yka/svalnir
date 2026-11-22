//! The processes of the command of an owner step (`docs/ACTION_CONTRACTS.md`
//! section 7, the subsection of `RunOwnerOperation`).
//!
//! The coordinator records the process ID, the start time, and the process
//! group of the command while the process is suspended, before it runs, and
//! then each change of the set of its live descendants that the worker
//! finds. A record whose set overflowed, or whose change the journal could
//! not write, is truncated. A reconciliation stops each recorded process
//! that still lives, and an acknowledgment of the operation is refused
//! while one lives or while a truncated record is not cleared. The rows go
//! with their operation (`ON DELETE CASCADE`).

use rusqlite::params;
use svalnir_core::id::{OperationId, StepId};
use svalnir_core::process::ProcessStartTime;

use super::error::OperationJournalError;
use super::{OperationJournal, commit, row};

/// One process by its identity: the process ID and the start time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProcessRecord {
    /// The process ID.
    pub pid: i32,
    /// The start time, as the kernel reports it.
    pub started: ProcessStartTime,
}

/// The process of the command of one owner step, with its descendants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerProcess {
    /// The process ID of the command.
    pub pid: i32,
    /// The start time of the process, as the kernel reports it.
    pub started: ProcessStartTime,
    /// The process group of the command. The command is its leader.
    pub group: i32,
    /// The live descendants that the worker recorded, at most
    /// [`MAX_OWNER_DESCENDANTS`].
    pub descendants: Vec<ProcessRecord>,
    /// True when the set of descendants is not complete: it overflowed,
    /// or the journal did not write a change of it. A truncated record
    /// counts as a live process until the system started again after the
    /// command (`docs/ACTION_CONTRACTS.md` section 7, "Recovery").
    pub truncated: bool,
}

/// One change of the set of the live descendants of a command.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DescendantChange {
    /// The descendants that the worker found since its last report.
    pub found: Vec<ProcessRecord>,
    /// The reported descendants that ended and left the set.
    pub gone: Vec<ProcessRecord>,
    /// True when a live descendant found no room in the set.
    pub truncated: bool,
}

/// The largest number of process records that one operation has: one for
/// each step of a plan.
const MAX_OWNER_PROCESSES: i64 = 4096;

/// The largest number of descendants that the journal keeps for one step.
pub const MAX_OWNER_DESCENDANTS: usize = 4096;

fn started_of(started: ProcessStartTime) -> Result<i64, OperationJournalError> {
    i64::try_from(started.get())
        .map_err(|_| OperationJournalError::row("owner_process", "started_us"))
}

fn start_time(value: i64) -> Result<ProcessStartTime, OperationJournalError> {
    u64::try_from(value)
        .map(ProcessStartTime::new)
        .map_err(|_| OperationJournalError::row("owner_process", "started_us"))
}

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
        let started: i64 = started_of(process.started)?;
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
             (operation_seq, step_id, pid, started_us, process_group, truncated) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                seq,
                step_id.as_str(),
                process.pid,
                started,
                process.group,
                i64::from(process.truncated)
            ],
        )?;
        commit(transaction, commit_fault)?;
        Ok(())
    }

    /// Applies `change` to the descendants of the command of the step
    /// `step_id`: the gone descendants go, and the found ones are added. A
    /// descendant that the journal has is not added again. The journal
    /// keeps at most [`MAX_OWNER_DESCENDANTS`] for one step: a found
    /// descendant with no room, or a truncated change, makes the record
    /// truncated, and a truncated record stays truncated.
    ///
    /// # Errors
    ///
    /// Returns [`OperationJournalError::NotFound`] when the journal has no
    /// such operation or no process of the step, and a storage error. On an
    /// error nothing was written.
    pub fn record_owner_descendants(
        &mut self,
        operation_id: &OperationId,
        step_id: &StepId,
        change: &DescendantChange,
    ) -> Result<(), OperationJournalError> {
        let Self {
            connection,
            commit_fault,
            ..
        } = self;
        let transaction = Self::write_transaction(connection)?;
        let seq: i64 = row::find_operation(&transaction, operation_id)?
            .ok_or(OperationJournalError::NotFound)?
            .seq;
        let leaders: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM owner_process WHERE operation_seq = ?1 AND step_id = ?2",
            params![seq, step_id.as_str()],
            |row| row.get(0),
        )?;
        if leaders == 0 {
            return Err(OperationJournalError::NotFound);
        }
        for descendant in &change.gone {
            transaction.execute(
                "DELETE FROM owner_descendant \
                 WHERE operation_seq = ?1 AND step_id = ?2 AND pid = ?3 AND started_us = ?4",
                params![
                    seq,
                    step_id.as_str(),
                    descendant.pid,
                    started_of(descendant.started)?
                ],
            )?;
        }
        let count: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM owner_descendant WHERE operation_seq = ?1 AND step_id = ?2",
            params![seq, step_id.as_str()],
            |row| row.get(0),
        )?;
        let mut room: usize =
            MAX_OWNER_DESCENDANTS.saturating_sub(usize::try_from(count).unwrap_or(usize::MAX));
        let mut truncated: bool = change.truncated;
        for descendant in &change.found {
            let started: i64 = started_of(descendant.started)?;
            if room == 0 {
                let known: bool = transaction.query_row(
                    "SELECT EXISTS (SELECT 1 FROM owner_descendant \
                     WHERE operation_seq = ?1 AND step_id = ?2 AND pid = ?3 AND started_us = ?4)",
                    params![seq, step_id.as_str(), descendant.pid, started],
                    |row| row.get(0),
                )?;
                truncated |= !known;
                continue;
            }
            let added: usize = transaction.execute(
                "INSERT OR IGNORE INTO owner_descendant \
                 (operation_seq, step_id, pid, started_us) VALUES (?1, ?2, ?3, ?4)",
                params![seq, step_id.as_str(), descendant.pid, started],
            )?;
            room = room.saturating_sub(added);
        }
        if truncated {
            transaction.execute(
                "UPDATE owner_process SET truncated = 1 WHERE operation_seq = ?1 AND step_id = ?2",
                params![seq, step_id.as_str()],
            )?;
        }
        commit(transaction, commit_fault)?;
        Ok(())
    }

    /// The process records of the owner steps of `operation_id`, each with
    /// its descendants. Empty when the operation has none or the journal
    /// has no such operation.
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
            "SELECT step_id, pid, started_us, process_group, truncated FROM owner_process \
             WHERE operation_seq = ?1 ORDER BY step_id LIMIT ?2",
        )?;
        let rows = statement.query_map(params![stored.seq, MAX_OWNER_PROCESSES], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i32>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i32>(3)?,
                row.get::<_, i64>(4)? != 0,
            ))
        })?;
        let mut leaders: Vec<(String, i32, i64, i32, bool)> = Vec::new();
        for entry in rows {
            leaders.push(entry?);
        }
        let mut descendants_of = transaction.prepare(
            "SELECT pid, started_us FROM owner_descendant \
             WHERE operation_seq = ?1 AND step_id = ?2 ORDER BY pid LIMIT ?3",
        )?;
        let limit: i64 = i64::try_from(MAX_OWNER_DESCENDANTS).unwrap_or(i64::MAX);
        let mut processes: Vec<OwnerProcess> = Vec::new();
        for (step_id, pid, started, group, truncated) in leaders {
            let rows = descendants_of.query_map(params![stored.seq, step_id, limit], |row| {
                Ok((row.get::<_, i32>(0)?, row.get::<_, i64>(1)?))
            })?;
            let mut descendants: Vec<ProcessRecord> = Vec::new();
            for entry in rows {
                let (pid, started) = entry?;
                descendants.push(ProcessRecord {
                    pid,
                    started: start_time(started)?,
                });
            }
            processes.push(OwnerProcess {
                pid,
                started: start_time(started)?,
                group,
                descendants,
                truncated,
            });
        }
        Ok(processes)
    }
}
