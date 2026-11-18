//! The operation journal of the user executor.
//!
//! [`OperationJournal`] is the durable implementation of
//! [`svalnir_core::action::Journal`] in an `SQLite` database
//! (`operations.sqlite` in the user state directory), and
//! [`VolatileRecord`] is the bounded in-memory implementation of
//! [`svalnir_core::action::VolatileJournal`] for the critical-memory
//! exception. The journal is separate from the rebuildable
//! `catalog.sqlite` of [`crate::store`], and it has stronger durability.
//!
//! Owning specifications: `docs/ACTION_CONTRACTS.md` sections 2, 6, 11, and
//! 12 and `docs/ARCHITECTURE.md` section 12.
//!
//! # Use
//!
//! [`OperationJournal::open`] opens the database at the path that the
//! caller gives and migrates it to [`JOURNAL_VERSION`]. The journal does
//! not find a default path and does not make a directory. An
//! `OperationJournal` is one connection; it is `Send` and not `Sync`.
//!
//! A client records a plan ([`Journal::record_plan`]) and puts a request in
//! the queue ([`OperationJournal::enqueue_request`]). One coordinator
//! holds the [`CoordinatorLock`], registers its executor lifetime
//! ([`OperationJournal::begin_coordination`]), claims requests, and writes
//! the operation records through the [`Journal`] interface.
//!
//! # What a call guarantees
//!
//! Each call that writes runs in one immediate transaction and returns `Ok`
//! only after `SQLite` committed it with the settings below. On an error
//! the call wrote nothing that a reader can see, and the caller does not
//! issue the associated external call. The journal is evidence for
//! recovery. It is not an undo log: a transaction cannot include an unlink
//! or a signal.
//!
//! One case is not symmetrical. When the synchronization of a commit fails,
//! `SQLite` reports the failure and rolls the transaction back, but the
//! frames of the transaction can be in the log file. If the process stops
//! before a later write replaces them, the recovery of the log can make
//! that transaction visible. Thus a record can exist for a call that
//! returned an error. The reverse does not occur with these settings. A
//! consumed dispatch that has no outcome needs reconciliation in the two
//! cases.
//!
//! A step and an operation change only through the functions of
//! `svalnir-core` (`Operation::advance_step`, `Operation::settle_step`,
//! `Operation::settle`). A change that those functions do not permit is an
//! error and not a write.
//!
//! # Settings
//!
//! Each connection sets these `SQLite` settings. It reads back each one
//! but `busy_timeout`, and a setting that is not in effect fails the open.
//! For `max_page_count` it keeps the value that `SQLite` reports, which is
//! larger than the request when the database is larger.
//!
//! | Setting | Value | Reason |
//! | --- | --- | --- |
//! | `busy_timeout` | [`JournalOptions::busy_timeout`] | A locked database gives [`OperationJournalError::Busy`] after a bounded wait |
//! | `journal_mode` | `WAL` | The architectural baseline. A file for which `SQLite` reports a different mode is refused with [`OperationJournalError::WalUnavailable`] |
//! | `synchronous` | `FULL` | The log is synchronized at each commit, so a commit that returned is not lost on a power failure when the synchronization reaches the storage |
//! | `fullfsync`, `checkpoint_fullfsync` | [`JournalOptions::full_fsync`], default on | See "Synchronization" |
//! | `foreign_keys` | `ON` | The steps of an operation are removed with the operation |
//! | `wal_autocheckpoint` | 1000 pages | The automatic checkpoint of `SQLite`, set explicitly |
//! | `journal_size_limit` | 4 MiB | The log file is cut to this size when a checkpoint resets the log |
//! | `max_page_count` | From [`JournalOptions::max_database_size`] | The hard limit of the database size; a write above it gives [`OperationJournalError::Full`] |
//!
//! The open flags do not permit a URI filename.
//!
//! # Synchronization
//!
//! `synchronous=FULL` makes `SQLite` call `fsync`. On macOS, `fsync` does
//! not ask the drive to write its cache to permanent storage; only the
//! `F_FULLFSYNC` request of `fcntl` does. `F_FULLFSYNC` is a separate
//! `SQLite` setting (`fullfsync`), and `FULL` does not imply it.
//!
//! This journal sets `fullfsync` and `checkpoint_fullfsync` by default. The
//! journal is the record that makes a dispatch single-use. If a power
//! failure removes a committed dispatch consumption after the external
//! call, a later executor sees a step that was not dispatched. The cost is
//! one drive cache flush for each commit, which is slow on some drives; an
//! operation with many steps has three commits for each step.
//! [`JournalOptions::full_fsync`] can set the two settings off. On a system
//! other than macOS the settings have no effect.
//!
//! No test in this repository removes power. The durability of a commit on
//! a power failure is not verified.
//!
//! # Size
//!
//! The hard limit applies to the size of the database in pages. `SQLite`
//! does not record the limit in the file, so each connection sets it. The
//! limit does not include the write-ahead log.
//!
//! New work stops before the hard limit. A call that admits new work
//! ([`Journal::record_plan`], [`Journal::admit`],
//! [`Journal::record_rejection`], and
//! [`OperationJournal::enqueue_request`]) fails with
//! [`OperationJournalError::AdmissionStopped`] when the free space below
//! the hard limit is smaller than [`JournalOptions::admission_reserve`], or
//! when the log file is larger than [`JournalOptions::max_wal_size`]. The
//! reserve is for the records of the operations that are admitted: the
//! intents, the dispatch consumptions, and the outcomes. The completion of
//! a request, the registration of a coordinator, and the later write of a
//! volatile record use it also. The reserve is not a guarantee: an
//! operation with many large results can use more, and its write then
//! fails with [`OperationJournalError::Full`]. The options are not
//! checked against each other: a reserve that is not smaller than the hard
//! limit, or a log limit below 4 MiB, stops new work.
//!
//! [`OperationJournal::prune`] removes old settled records.
//! [`OperationJournal::checkpoint`] moves the log into the database. No
//! other function calls them, and the coordinator keeps them out of an
//! emergency path. A deletion puts pages on the free list, and later
//! inserts use them again. No function runs `VACUUM`.
//!
//! # Coordinator lock
//!
//! [`CoordinatorLock`] is an exclusive advisory `flock` on a lock file
//! beside the database. The operating system releases it when the process
//! that holds it stops, also on a crash. The release shows only that the
//! process stopped. It does not show that the work of the process stopped:
//! an operating-system call that the process issued can complete after it.
//! For that reason the journal also records the registration of the
//! coordinator. A registration that was not released marks an unclean stop,
//! and the journal then refuses each admission and each dispatch
//! consumption until the new coordinator calls
//! [`OperationJournal::complete_reconciliation`]. A registration that
//! finds an operation that is not settled does the same, also after a
//! release. A journal that has no
//! registration applies no such gate; the first registration finds work
//! that is not settled and marks the reconciliation as pending.
//!
//! [`Journal`]: svalnir_core::action::Journal
//! [`Journal::record_plan`]: svalnir_core::action::Journal::record_plan
//! [`Journal::admit`]: svalnir_core::action::Journal::admit
//! [`Journal::record_rejection`]: svalnir_core::action::Journal::record_rejection

mod coordination;
mod durable;
mod error;
mod migration;
mod record;
mod recovery;
mod request;
mod retention;
mod revision;
mod row;
#[cfg(test)]
mod tests;
mod transition;
mod volatile;

use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::{Connection, OpenFlags, Transaction, TransactionBehavior};
use serde::Serialize;
use serde::de::DeserializeOwned;
use svalnir_core::action::Operation;
use svalnir_core::quantity::Bytes;

pub use self::coordination::{
    CoordinationStart, CoordinatorLock, CoordinatorLockError, CoordinatorRecord, CoordinatorRole,
    LockState, coordinator_lock_path,
};
pub use self::error::{AdmissionStop, OperationJournalError, SequenceViolation};
pub use self::migration::JOURNAL_VERSION;
use self::migration::{MIGRATIONS, Migration};
pub use self::record::{AgentRecord, MAX_AGENT_RECORD_BYTES, StoredAgentRecord};
pub use self::recovery::{ConsumedDispatch, RecoveryPosition, RecoveryRecord, StepRecovery};
pub use self::request::{
    ClaimedRequest, Enqueued, MAX_OPEN_REQUESTS, QueuedRequest, REQUEST_NOT_DECODABLE, RequestBody,
    RequestCompletion, RequestStatus,
};
pub use self::retention::PruneReport;
pub use self::revision::MAX_REVISION_SOURCE_BYTES;
pub use self::volatile::{VolatileOperationRecord, VolatilePersistReport, VolatileRecord};

/// The size to which the write-ahead log file is cut after a checkpoint.
const JOURNAL_SIZE_LIMIT_BYTES: i64 = 4 * 1024 * 1024;

/// The number of log pages after which `SQLite` runs a checkpoint.
const WAL_AUTOCHECKPOINT_PAGES: i64 = 1000;

/// The largest `max_page_count` that `SQLite` accepts.
const MAX_PAGE_COUNT: u64 = 4_294_967_294;

/// The value that `PRAGMA synchronous` reports for `FULL`.
const SYNCHRONOUS_FULL: i64 = 2;

/// The settings of one journal connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalOptions {
    /// How long a call waits for a lock of a different connection before it
    /// fails with [`OperationJournalError::Busy`].
    pub busy_timeout: Duration,
    /// The hard limit of the database size. A limit smaller than the
    /// database leaves it as it is and refuses growth.
    pub max_database_size: Bytes,
    /// The free space below the hard limit that new work does not use.
    pub admission_reserve: Bytes,
    /// The size of the write-ahead log file above which new work stops.
    pub max_wal_size: Bytes,
    /// Whether a commit and a checkpoint ask the drive to write its cache
    /// (`F_FULLFSYNC` on macOS). See the module documentation.
    pub full_fsync: bool,
}

impl Default for JournalOptions {
    /// A busy timeout of 2 seconds, a database limit of 64 MiB, an
    /// admission reserve of 4 MiB, a log limit of 16 MiB, and `F_FULLFSYNC`
    /// on.
    fn default() -> Self {
        Self {
            busy_timeout: Duration::from_secs(2),
            max_database_size: Bytes::new(64 * 1024 * 1024),
            admission_reserve: Bytes::new(4 * 1024 * 1024),
            max_wal_size: Bytes::new(16 * 1024 * 1024),
            full_fsync: true,
        }
    }
}

/// The size of the journal, from the `SQLite` page counters and the log
/// file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalSize {
    /// The size of one page.
    pub page_size: Bytes,
    /// The size of the database with its free pages.
    pub database: Bytes,
    /// The size of the pages that hold data.
    pub used: Bytes,
    /// The hard limit of `database` that this connection applies.
    pub limit: Bytes,
    /// The size of the write-ahead log file. Zero when the file does not
    /// exist.
    pub write_ahead_log: Bytes,
}

/// The operation of the latest write, with the revision that the database
/// records for it. A write of the same operation uses it in place of a
/// read of each step.
struct CachedOperation {
    seq: i64,
    revision: i64,
    operation: Operation,
}

/// One connection to the operation journal.
pub struct OperationJournal {
    connection: Connection,
    path: PathBuf,
    options: JournalOptions,
    limits: SizeLimits,
    cache: Option<CachedOperation>,
    /// The plan of the latest intent. A plan is found by its identity and
    /// its content digest, so a cached value is never stale.
    plan_cache: Option<svalnir_core::action::Plan>,
    commit_fault: CommitFault,
}

/// The size limits of one connection, in pages and bytes.
#[derive(Debug, Clone, Copy)]
struct SizeLimits {
    page_size: u64,
    page_limit: u64,
    reserve_pages: u64,
    max_wal_bytes: u64,
}

/// A commit failure that a test injects. In a build that is not a test
/// build it has no state and gives no failure.
#[derive(Debug, Default)]
struct CommitFault {
    /// The result code of the next commit. That commit writes nothing.
    #[cfg(test)]
    code: Option<std::ffi::c_int>,
}

impl CommitFault {
    fn take(&mut self) -> Option<std::ffi::c_int> {
        #[cfg(test)]
        {
            self.code.take()
        }
        #[cfg(not(test))]
        {
            let Self {} = self;
            None
        }
    }
}

impl fmt::Debug for OperationJournal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OperationJournal")
            .field("options", &self.options)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

fn open_flags() -> OpenFlags {
    OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_CREATE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
}

/// Reads one integer setting.
fn pragma_i64(connection: &Connection, name: &'static str) -> Result<i64, OperationJournalError> {
    Ok(connection.pragma_query_value(None, name, |row| row.get(0))?)
}

fn pragma_u64(connection: &Connection, name: &'static str) -> Result<u64, OperationJournalError> {
    u64::try_from(pragma_i64(connection, name)?)
        .map_err(|_| OperationJournalError::row("pragma", name))
}

/// Sets one integer setting and checks that `SQLite` reports the value.
fn set_checked(
    connection: &Connection,
    name: &'static str,
    value: i64,
) -> Result<(), OperationJournalError> {
    connection.pragma_update(None, name, value)?;
    if pragma_i64(connection, name)? == value {
        Ok(())
    } else {
        Err(OperationJournalError::Setting { setting: name })
    }
}

/// Sets the writer settings of the module documentation and checks each
/// one.
fn apply_settings(
    connection: &Connection,
    options: &JournalOptions,
) -> Result<(), OperationJournalError> {
    // `SQLite` reports the mode in effect and does not fail when it cannot
    // set `WAL`.
    let mode: String =
        connection.pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))?;
    if !mode.eq_ignore_ascii_case("wal") {
        return Err(OperationJournalError::WalUnavailable { mode });
    }
    set_checked(connection, "synchronous", SYNCHRONOUS_FULL)?;
    let full_fsync: i64 = i64::from(options.full_fsync);
    set_checked(connection, "fullfsync", full_fsync)?;
    set_checked(connection, "checkpoint_fullfsync", full_fsync)?;
    set_checked(connection, "foreign_keys", 1)?;
    for (name, value) in [
        ("wal_autocheckpoint", WAL_AUTOCHECKPOINT_PAGES),
        ("journal_size_limit", JOURNAL_SIZE_LIMIT_BYTES),
    ] {
        let applied: i64 =
            connection.pragma_update_and_check(None, name, value, |row| row.get(0))?;
        if applied != value {
            return Err(OperationJournalError::Setting { setting: name });
        }
    }
    Ok(())
}

/// Encodes a record as the JSON that `svalnir-core` writes.
fn encode<T: Serialize>(record: &T) -> Result<String, OperationJournalError> {
    serde_json::to_string(record).map_err(OperationJournalError::Encode)
}

/// Decodes a stored record. The decoding runs the check of the type.
fn decode<T: DeserializeOwned>(
    table: &'static str,
    text: &str,
) -> Result<T, OperationJournalError> {
    serde_json::from_str(text).map_err(OperationJournalError::decode(table))
}

impl OperationJournal {
    /// Opens the journal file at `path` and migrates it to
    /// [`JOURNAL_VERSION`]. A file that does not exist is made; its
    /// directory must exist.
    ///
    /// # Errors
    ///
    /// Returns [`OperationJournalError::InvalidPath`] for an empty path or
    /// `:memory:`. Returns [`OperationJournalError::NewerVersion`] or
    /// [`OperationJournalError::NotAJournal`] for a database that this
    /// build must not use; the content of the database is then not changed.
    /// Returns [`OperationJournalError::WalUnavailable`] or
    /// [`OperationJournalError::Setting`] when a required setting is not in
    /// effect, [`OperationJournalError::Migration`] when a migration fails,
    /// or a storage error.
    pub fn open(path: &Path, options: &JournalOptions) -> Result<Self, OperationJournalError> {
        Self::open_with_migrations(path, options, MIGRATIONS)
    }

    fn open_with_migrations(
        path: &Path,
        options: &JournalOptions,
        migrations: &[Migration],
    ) -> Result<Self, OperationJournalError> {
        // Refuse a defective migration list before the open makes a file.
        let supported: u32 = migration::supported_version(migrations)?;
        if path.as_os_str().is_empty() || path.as_os_str() == ":memory:" {
            return Err(OperationJournalError::InvalidPath(
                path.display().to_string(),
            ));
        }
        let mut connection: Connection = Connection::open_with_flags(path, open_flags())?;
        connection.busy_timeout(options.busy_timeout)?;
        // Refuse a database of a newer build or of a different application
        // before a setting can change the file.
        migration::recorded_version(&connection, supported)?;
        apply_settings(&connection, options)?;

        let page_size: u64 = pragma_u64(&connection, "page_size")?.max(1);
        let pages: u64 = (options.max_database_size.get() / page_size).clamp(1, MAX_PAGE_COUNT);
        // `SQLite` does not set a limit below the current page count; it
        // returns the limit that is in effect.
        let applied: i64 = connection.pragma_update_and_check(
            None,
            "max_page_count",
            i64::try_from(pages).unwrap_or(i64::MAX),
            |row| row.get(0),
        )?;
        let page_limit: u64 = u64::try_from(applied)
            .map_err(|_| OperationJournalError::row("pragma", "max_page_count"))?;

        migration::migrate(&mut connection, migrations)?;
        Ok(Self {
            connection,
            path: path.to_path_buf(),
            options: *options,
            limits: SizeLimits {
                page_size,
                page_limit,
                reserve_pages: options.admission_reserve.get().div_ceil(page_size),
                max_wal_bytes: options.max_wal_size.get(),
            },
            cache: None,
            plan_cache: None,
            commit_fault: CommitFault::default(),
        })
    }

    /// The path that the journal was opened with.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reads the journal version that the database records.
    ///
    /// # Errors
    ///
    /// Returns a storage error.
    pub fn version(&self) -> Result<u32, OperationJournalError> {
        u32::try_from(pragma_u64(&self.connection, "user_version")?)
            .map_err(|_| OperationJournalError::row("pragma", "user_version"))
    }

    /// Reads the size of the journal.
    ///
    /// # Errors
    ///
    /// Returns a storage error.
    pub fn size(&self) -> Result<JournalSize, OperationJournalError> {
        let pages: u64 = pragma_u64(&self.connection, "page_count")?;
        let free: u64 = pragma_u64(&self.connection, "freelist_count")?;
        let bytes = |pages: u64| Bytes::new(pages.saturating_mul(self.limits.page_size));
        Ok(JournalSize {
            page_size: Bytes::new(self.limits.page_size),
            database: bytes(pages),
            used: bytes(pages.saturating_sub(free)),
            limit: bytes(self.limits.page_limit),
            write_ahead_log: Bytes::new(wal_size(&self.path)?),
        })
    }

    /// Moves the write-ahead log into the database and cuts the log file.
    /// Returns `true` when the checkpoint is complete, and `false` when a
    /// reader or a writer of a different connection prevented a part of it.
    ///
    /// This function is maintenance. No other function calls it, and the
    /// automatic checkpoint of `SQLite` stays in effect.
    ///
    /// # Errors
    ///
    /// Returns a storage error.
    pub fn checkpoint(&mut self) -> Result<bool, OperationJournalError> {
        let busy: i64 =
            self.connection
                .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))?;
        Ok(busy == 0)
    }

    /// Starts the immediate transaction of one write.
    fn write_transaction(
        connection: &mut Connection,
    ) -> Result<Transaction<'_>, OperationJournalError> {
        Ok(connection.transaction_with_behavior(TransactionBehavior::Immediate)?)
    }

    /// Starts a read transaction, so that the statements of one read see
    /// one snapshot.
    fn read_transaction(&self) -> Result<Transaction<'_>, OperationJournalError> {
        Ok(self.connection.unchecked_transaction()?)
    }
}

/// Commits the transaction of one write. On an error the transaction is
/// rolled back.
fn commit(
    transaction: Transaction<'_>,
    fault: &mut CommitFault,
) -> Result<(), OperationJournalError> {
    if let Some(code) = fault.take() {
        drop(transaction);
        return Err(rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(code), None).into());
    }
    transaction.commit()?;
    Ok(())
}

/// The size of the write-ahead log file of the database at `path`. A file
/// that does not exist has the size zero.
fn wal_size(path: &Path) -> Result<u64, OperationJournalError> {
    let mut name = path.as_os_str().to_owned();
    name.push("-wal");
    match std::fs::metadata(PathBuf::from(name)) {
        Ok(metadata) => Ok(metadata.len()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(OperationJournalError::File(error)),
    }
}

/// Checks that the journal can admit new work and keep its size limits.
///
/// `connection` is the transaction of the write. The check runs before the
/// insert of the new record, so one admission can use a part of the
/// reserve that is as large as its own rows.
fn check_admission_capacity(
    connection: &Connection,
    path: &Path,
    limits: &SizeLimits,
) -> Result<(), OperationJournalError> {
    let pages: u64 = pragma_u64(connection, "page_count")?;
    let free: u64 = pragma_u64(connection, "freelist_count")?;
    let used: u64 = pages.saturating_sub(free);
    let headroom: u64 = limits.page_limit.saturating_sub(used);
    if headroom < limits.reserve_pages {
        return Err(OperationJournalError::AdmissionStopped(
            AdmissionStop::Database,
        ));
    }
    if wal_size(path)? > limits.max_wal_bytes {
        return Err(OperationJournalError::AdmissionStopped(
            AdmissionStop::WriteAheadLog,
        ));
    }
    Ok(())
}
