//! The single-coordinator lock and the registration of the coordinator.
//!
//! Two records work together:
//!
//! - [`CoordinatorLock`] is an exclusive advisory `flock` on a lock file
//!   beside the database. A second coordinator cannot take it while the
//!   process of the first one runs. The operating system releases it when
//!   that process stops, also on a crash, so no process identity or time
//!   limit decides that a lock is stale.
//! - The `coordinator` row of the database has the executor lifetime of
//!   the coordinator and whether it released its registration.
//!
//! The lock shows only that a process stopped. A call that the process
//! issued can complete after it. When a new coordinator finds a
//! registration that was not released, the journal records that a
//! reconciliation is pending and refuses each admission and each dispatch
//! consumption until [`OperationJournal::complete_reconciliation`].

use std::fs::{File, OpenOptions, TryLockError};
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OptionalExtension, params};
use svalnir_core::id::ExecutorEpochId;
use svalnir_core::time::WallTime;
use thiserror::Error;

use super::error::{OperationJournalError, SequenceViolation};
use super::{OperationJournal, commit};

/// The path of the coordinator lock file of the journal at `database`: the
/// path of the database with `.coordinator-lock` after it.
pub fn coordinator_lock_path(database: &Path) -> PathBuf {
    let mut name = database.as_os_str().to_owned();
    name.push(".coordinator-lock");
    PathBuf::from(name)
}

/// The path of `database` with each symbolic link resolved, so that two
/// spellings of one database path give one lock file. The database file
/// can be absent: then only its directory is resolved. A path that cannot
/// be resolved stays as it is; the open of the lock file then reports the
/// failure.
pub(super) fn canonical_path(database: &Path) -> PathBuf {
    if let Ok(resolved) = std::fs::canonicalize(database) {
        return resolved;
    }
    match (database.parent(), database.file_name()) {
        (Some(parent), Some(name)) if !parent.as_os_str().is_empty() => {
            std::fs::canonicalize(parent)
                .map_or_else(|_| database.to_path_buf(), |parent| parent.join(name))
        }
        _ => database.to_path_buf(),
    }
}

/// The reason the coordinator lock was not taken.
#[derive(Debug, Error)]
pub enum CoordinatorLockError {
    /// A different coordinator holds the lock.
    #[error("a different coordinator holds the coordinator lock")]
    Held,
    /// The lock file cannot be opened or locked.
    #[error("the coordinator lock file cannot be opened or locked")]
    Io(#[source] std::io::Error),
}

/// The exclusive lock of the one coordinator of a journal.
///
/// The lock is held while this value exists. The operating system releases
/// it when the value is dropped and when the process stops.
///
/// The lock is advisory: it stops a second coordinator, and it does not
/// stop a write to the database. A filesystem that does not support
/// `flock` (some network volumes) gives [`CoordinatorLockError::Io`].
#[derive(Debug)]
pub struct CoordinatorLock {
    // The lock belongs to this open file. It is not read or written.
    _file: File,
    database: PathBuf,
}

impl CoordinatorLock {
    /// Takes the coordinator lock of the journal at `database`, and makes
    /// the lock file when it does not exist. The call does not wait.
    ///
    /// # Errors
    ///
    /// Returns [`CoordinatorLockError::Held`] when a different open file,
    /// in this process or in a different one, holds the lock, and
    /// [`CoordinatorLockError::Io`] when the file cannot be opened or
    /// locked, which includes a lock path that is a symbolic link.
    pub fn try_acquire(database: &Path) -> Result<Self, CoordinatorLockError> {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // The file has no content. Only the owner opens it, and a
            // symbolic link at the path is refused.
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let file: File = options
            .open(coordinator_lock_path(&canonical_path(database)))
            .map_err(CoordinatorLockError::Io)?;
        match file.try_lock() {
            Ok(()) => Ok(Self {
                _file: file,
                database: canonical_path(database),
            }),
            Err(TryLockError::WouldBlock) => Err(CoordinatorLockError::Held),
            Err(TryLockError::Error(error)) => Err(CoordinatorLockError::Io(error)),
        }
    }

    /// The database path that the lock was taken for, with each symbolic
    /// link resolved. A hard link to the database file is a different
    /// path; the lock does not detect it.
    pub fn database(&self) -> &Path {
        &self.database
    }
}

/// The registration of a coordinator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoordinatorRecord {
    /// The executor lifetime of the coordinator.
    pub executor_epoch: ExecutorEpochId,
    /// The process identity of the coordinator, for diagnostics only. It
    /// is not evidence that a process runs or stopped.
    pub process_id: u32,
    /// The wall-clock time of the registration in Unix seconds, for
    /// history only.
    pub started_unix_seconds: i64,
    /// Whether the coordinator released its registration. `false` after
    /// the lock was free means that the coordinator stopped uncleanly.
    pub released: bool,
    /// Whether a reconciliation is pending.
    pub reconciliation_pending: bool,
}

/// The result of the registration of a coordinator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoordinationStart {
    /// The registration of the coordinator before this one.
    pub predecessor: Option<CoordinatorRecord>,
    /// Whether the journal refuses admission and dispatch until
    /// [`OperationJournal::complete_reconciliation`]: the predecessor did
    /// not release its registration, or it left a pending reconciliation,
    /// or the journal has no predecessor and has an operation that is not
    /// settled.
    pub reconciliation_pending: bool,
    /// The number of requests that an earlier executor lifetime claimed
    /// and did not complete. They are in the queue again.
    pub requeued_requests: usize,
}

pub(super) fn read_coordinator(
    connection: &Connection,
) -> Result<Option<CoordinatorRecord>, OperationJournalError> {
    let row: Option<(String, i64, i64, bool, bool)> = connection
        .query_row(
            "SELECT executor_epoch, process_id, started_unix_s, released, reconciliation_pending \
             FROM coordinator WHERE id = 1",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()?;
    let Some((epoch, process_id, started_unix_seconds, released, reconciliation_pending)) = row
    else {
        return Ok(None);
    };
    Ok(Some(CoordinatorRecord {
        executor_epoch: ExecutorEpochId::new(epoch)
            .map_err(|_| OperationJournalError::row("coordinator", "executor_epoch"))?,
        process_id: u32::try_from(process_id)
            .map_err(|_| OperationJournalError::row("coordinator", "process_id"))?,
        started_unix_seconds,
        released,
        reconciliation_pending,
    }))
}

/// Checks that the journal accepts an admission or a dispatch consumption
/// of the executor lifetime `epoch`.
///
/// A journal with no registration has no coordinator protocol in use, and
/// the check passes. With a registration, the lifetime must be the
/// registered one, the registration must not be released, and no
/// reconciliation can be pending. Thus an operation of an earlier executor
/// lifetime is not dispatched again.
pub(super) fn check_work_gate(
    connection: &Connection,
    epoch: &ExecutorEpochId,
) -> Result<(), OperationJournalError> {
    let Some(record) = read_coordinator(connection)? else {
        return Ok(());
    };
    if record.reconciliation_pending {
        Err(SequenceViolation::ReconciliationPending.into())
    } else if record.released || &record.executor_epoch != epoch {
        Err(SequenceViolation::ExecutorEpoch.into())
    } else {
        Ok(())
    }
}

/// Checks that `epoch` is the registered lifetime and is not released.
pub(super) fn check_registered(
    connection: &Connection,
    epoch: &ExecutorEpochId,
) -> Result<(), OperationJournalError> {
    match read_coordinator(connection)? {
        Some(record) if !record.released && &record.executor_epoch == epoch => Ok(()),
        _ => Err(SequenceViolation::ExecutorEpoch.into()),
    }
}

impl OperationJournal {
    /// Registers the coordinator that holds `lock` with its new executor
    /// lifetime `epoch`.
    ///
    /// When the coordinator before this one did not release its
    /// registration, the journal records a pending reconciliation. The
    /// requests that an earlier lifetime claimed and did not complete go
    /// back to the queue, marked as delivered again, in the same
    /// transaction.
    ///
    /// # Errors
    ///
    /// Returns [`OperationJournalError::LockMismatch`] when `lock` is the
    /// lock of a different database path,
    /// [`OperationJournalError::Conflict`] when `epoch` is the lifetime of
    /// the registration that exists or of a stored operation (a restart
    /// makes a new lifetime), or a storage error.
    pub fn begin_coordination(
        &mut self,
        lock: &CoordinatorLock,
        epoch: &ExecutorEpochId,
        started_at: WallTime,
    ) -> Result<CoordinationStart, OperationJournalError> {
        if lock.database() != canonical_path(&self.path) {
            return Err(OperationJournalError::LockMismatch);
        }
        let Self {
            connection,
            commit_fault,
            ..
        } = self;
        let transaction = Self::write_transaction(connection)?;
        let predecessor: Option<CoordinatorRecord> = read_coordinator(&transaction)?;
        if predecessor
            .as_ref()
            .is_some_and(|record| &record.executor_epoch == epoch)
        {
            return Err(OperationJournalError::Conflict);
        }
        // A restart makes a new lifetime: an operation of `epoch` would be
        // executable again.
        let used: bool = transaction.query_row(
            "SELECT EXISTS (SELECT 1 FROM operation WHERE executor_epoch = ?1)",
            [epoch.as_str()],
            |row| row.get(0),
        )?;
        if used {
            return Err(OperationJournalError::Conflict);
        }
        // With no registration, work that is not settled was written
        // outside the coordinator protocol, and nothing shows that its
        // writer stopped cleanly.
        let reconciliation_pending: bool = match &predecessor {
            Some(record) => record.reconciliation_pending || !record.released,
            None => transaction.query_row(
                "SELECT EXISTS (SELECT 1 FROM operation WHERE settled = 0)",
                [],
                |row| row.get(0),
            )?,
        };
        transaction.execute(
            "INSERT INTO coordinator \
             (id, executor_epoch, process_id, started_unix_s, released, reconciliation_pending) \
             VALUES (1, ?1, ?2, ?3, 0, ?4) \
             ON CONFLICT (id) DO UPDATE SET \
             executor_epoch = excluded.executor_epoch, process_id = excluded.process_id, \
             started_unix_s = excluded.started_unix_s, released = 0, \
             reconciliation_pending = excluded.reconciliation_pending",
            params![
                epoch.as_str(),
                i64::from(std::process::id()),
                started_at.unix_seconds(),
                reconciliation_pending,
            ],
        )?;
        let requeued_requests: usize = transaction.execute(
            "UPDATE request SET state = 'queued', claim_epoch = NULL, redelivered = 1 \
             WHERE state = 'claimed' AND claim_epoch <> ?1",
            [epoch.as_str()],
        )?;
        commit(transaction, commit_fault)?;
        Ok(CoordinationStart {
            predecessor,
            reconciliation_pending,
            requeued_requests,
        })
    }

    /// Records that the coordinator of the lifetime `epoch` inspected each
    /// operation that is not settled. The journal then accepts admission
    /// and dispatch again. An operation whose evidence cannot settle it
    /// keeps its state; this call changes no operation.
    ///
    /// # Errors
    ///
    /// Returns [`OperationJournalError::Sequence`] when `epoch` is not the
    /// registered lifetime, or a storage error.
    pub fn complete_reconciliation(
        &mut self,
        epoch: &ExecutorEpochId,
    ) -> Result<(), OperationJournalError> {
        self.update_registration(
            epoch,
            "UPDATE coordinator SET reconciliation_pending = 0 WHERE id = 1",
        )
    }

    /// Releases the registration of the coordinator of the lifetime
    /// `epoch`, before a clean stop. A pending reconciliation stays
    /// pending.
    ///
    /// # Errors
    ///
    /// Returns [`OperationJournalError::Sequence`] when `epoch` is not the
    /// registered lifetime, or a storage error.
    pub fn end_coordination(
        &mut self,
        epoch: &ExecutorEpochId,
    ) -> Result<(), OperationJournalError> {
        self.update_registration(epoch, "UPDATE coordinator SET released = 1 WHERE id = 1")
    }

    fn update_registration(
        &mut self,
        epoch: &ExecutorEpochId,
        statement: &'static str,
    ) -> Result<(), OperationJournalError> {
        let Self {
            connection,
            commit_fault,
            ..
        } = self;
        let transaction = Self::write_transaction(connection)?;
        check_registered(&transaction, epoch)?;
        transaction.execute(statement, [])?;
        commit(transaction, commit_fault)
    }

    /// Reads the registration of the coordinator.
    ///
    /// # Errors
    ///
    /// Returns a storage error.
    pub fn coordination(&self) -> Result<Option<CoordinatorRecord>, OperationJournalError> {
        read_coordinator(&self.connection)
    }
}
