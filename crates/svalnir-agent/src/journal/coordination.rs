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

/// The kind of process that holds the coordinator lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CoordinatorRole {
    /// The persistent agent.
    Agent,
    /// A client that executes a request as a transient coordinator.
    Client,
}

impl CoordinatorRole {
    /// The text of the role in the lock file.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::Client => "client",
        }
    }

    /// The role of the lock file content `text`. Each content that is not
    /// exactly the text of the agent role is the client role: a second
    /// agent then ends with a failure and is started again, and does not
    /// stay stopped while no agent runs.
    fn of_lock_content(text: &[u8]) -> Self {
        if text == Self::Agent.as_str().as_bytes() {
            Self::Agent
        } else {
            Self::Client
        }
    }
}

/// What a reading of the coordinator lock shows. The reading takes no
/// lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockState {
    /// No process holds the lock, or the lock file does not exist.
    Free,
    /// A process holds the lock. The role is the content of the lock
    /// file; see [`CoordinatorLock::holder_role`] for its limits.
    Held(CoordinatorRole),
}

/// The largest number of bytes of the lock file that a reader takes.
const MAX_ROLE_BYTES: u64 = 16;

/// The exclusive lock of the one coordinator of a journal.
///
/// The lock is held while this value exists. The operating system releases
/// it when the value is dropped and when the process stops.
///
/// The lock is advisory: it stops a second coordinator, and it does not
/// stop a write to the database. A filesystem that does not support
/// `flock` (some network volumes) gives [`CoordinatorLockError::Io`].
///
/// The content of the lock file is the role of the holder, as text. The
/// holder writes it immediately after it takes the lock and removes it
/// when the value is dropped. The content is a hint for a process that
/// found the lock held; it is not evidence that a process runs.
#[derive(Debug)]
pub struct CoordinatorLock {
    // The lock belongs to this open file.
    file: File,
    database: PathBuf,
}

impl Drop for CoordinatorLock {
    fn drop(&mut self) {
        // The role of a holder that stopped is not the role of the next
        // one. A failure leaves the old text, which the next holder
        // replaces.
        let _cleared: std::io::Result<()> = self.file.set_len(0);
    }
}

fn lock_file_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // A symbolic link at the path is refused.
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options
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
    pub fn try_acquire(
        database: &Path,
        role: CoordinatorRole,
    ) -> Result<Self, CoordinatorLockError> {
        use std::io::{Seek as _, SeekFrom, Write as _};

        let mut options = lock_file_options();
        options.write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // Only the owner opens the file.
            options.mode(0o600);
        }
        // One resolution of the path: the recorded database path is the
        // one whose lock file is locked.
        let database: PathBuf = canonical_path(database);
        let mut file: File = options
            .open(coordinator_lock_path(&database))
            .map_err(CoordinatorLockError::Io)?;
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => return Err(CoordinatorLockError::Held),
            Err(TryLockError::Error(error)) => return Err(CoordinatorLockError::Io(error)),
        }
        // The role is written under the lock. A holder with no role text
        // is read as a client, so a failure here is an error of the lock:
        // an agent must not be read as a client for its lifetime.
        file.set_len(0)
            .and_then(|()| file.seek(SeekFrom::Start(0)))
            .and_then(|_| file.write_all(role.as_str().as_bytes()))
            .map_err(CoordinatorLockError::Io)?;
        Ok(Self { file, database })
    }

    /// Reads the role text of the lock file of the journal at `database`,
    /// for a caller that found the lock held.
    ///
    /// The text is that of the last process that took the lock and did
    /// not drop it in the ordinary way. In the instant between the lock
    /// and the write of a new holder, and after a holder that could not
    /// clear its text, the text is that of an earlier holder. A text that
    /// cannot be read, and each text that is not the agent role, is
    /// [`CoordinatorRole::Client`].
    pub fn holder_role(database: &Path) -> CoordinatorRole {
        use std::io::Read as _;

        let path: PathBuf = coordinator_lock_path(&canonical_path(database));
        let mut text: Vec<u8> = Vec::new();
        let read: std::io::Result<usize> = lock_file_options()
            .open(path)
            .and_then(|file| file.take(MAX_ROLE_BYTES).read_to_end(&mut text));
        match read {
            Ok(_) => CoordinatorRole::of_lock_content(&text),
            Err(_) => CoordinatorRole::Client,
        }
    }

    /// Reads whether a process holds the coordinator lock of the journal
    /// at `database`. The call takes no lock, makes no file, and does not
    /// wait, so a coordinator that starts at the same time is not refused
    /// by this reading.
    ///
    /// The reading uses `fcntl(F_GETLK)`. On macOS an `flock` lock and an
    /// `fcntl` lock of one file are in one list of the kernel, so the
    /// query reports the `flock` lock of a coordinator. A system where
    /// the two kinds are separate reports [`LockState::Free`] for a held
    /// lock; a caller that then tries to take the lock gets
    /// [`CoordinatorLockError::Held`].
    ///
    /// # Errors
    ///
    /// Returns [`CoordinatorLockError::Io`] when the lock file exists and
    /// cannot be opened or queried, which includes a lock path that is a
    /// symbolic link.
    pub fn probe(database: &Path) -> Result<LockState, CoordinatorLockError> {
        use std::os::fd::AsRawFd as _;

        let path: PathBuf = coordinator_lock_path(&canonical_path(database));
        let file: File = match lock_file_options().open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(LockState::Free);
            }
            Err(error) => return Err(CoordinatorLockError::Io(error)),
        };
        // The query for a write lock on the full file: each lock of a
        // different owner conflicts with it.
        let mut query = libc::flock {
            l_start: 0,
            l_len: 0,
            l_pid: 0,
            l_type: libc::F_WRLCK,
            // `SEEK_SET`: the range starts at the start of the file.
            l_whence: 0,
        };
        // SAFETY: `file` is an open descriptor for the duration of the
        // call, and `query` is a valid, initialized `flock` structure that
        // the kernel reads and writes in place. `F_GETLK` changes no lock.
        let status: libc::c_int =
            unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETLK, &raw mut query) };
        if status == -1 {
            return Err(CoordinatorLockError::Io(std::io::Error::last_os_error()));
        }
        if query.l_type == libc::F_UNLCK {
            return Ok(LockState::Free);
        }
        Ok(LockState::Held(Self::holder_role(database)))
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
    /// or the journal has an operation that is not settled.
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
    /// registration, or an operation is not settled, the journal records
    /// a pending reconciliation. The
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
        // Work that is not settled needs an inspection before new work,
        // also after a release: a release does not show that each
        // operation of the lifetime has a result. With no registration,
        // such work was written outside the coordinator protocol.
        let unsettled: bool = transaction.query_row(
            "SELECT EXISTS (SELECT 1 FROM operation WHERE settled = 0)",
            [],
            |row| row.get(0),
        )?;
        let reconciliation_pending: bool = unsettled
            || predecessor
                .as_ref()
                .is_some_and(|record| record.reconciliation_pending || !record.released);
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
