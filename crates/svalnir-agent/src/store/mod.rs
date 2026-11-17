//! Local `SQLite` state.
//!
//! The versioned state store with its migrations and the bounded history of
//! observations and scans. In Milestone 1 it keeps metric history samples
//! and saved scan records. It is the rebuildable catalog and telemetry
//! storage of `docs/ARCHITECTURE.md`, section 12. The operation journal,
//! plans, grants, and policy revisions are not in this database.
//!
//! Owning specification: `docs/ARCHITECTURE.md`. `docs/INTERFACES.md`
//! section 2 owns the state-store version.
//!
//! # Use
//!
//! [`Store::open`] opens the database at the path that the caller gives and
//! migrates it to [`STATE_STORE_VERSION`]. The store does not find a default
//! path and does not make a directory. A `Store` is one connection; it is
//! `Send` and not `Sync`.
//!
//! # Settings
//!
//! Each connection sets these `SQLite` settings:
//!
//! | Setting | Value | Reason |
//! | --- | --- | --- |
//! | `busy_timeout` | [`StoreOptions::busy_timeout`] | A locked database gives [`StoreError::Busy`] after a bounded wait |
//! | `journal_mode` | `WAL` (`memory` for a store in memory) | A reader in a different process does not block the writer |
//! | `synchronous` | `NORMAL`; `FULL` when `WAL` is not in effect for a file | History can be rebuilt; with `WAL`, a power loss can lose the last commits and does not corrupt the file. `SQLite` does not fail when it cannot set `WAL` (for example on some network volumes), so the store reads the mode that it reports and takes `FULL` in a different mode for a file |
//! | `foreign_keys` | `ON` | Later versions can add references between tables |
//! | `secure_delete` | `ON` | A deleted row is overwritten with zeros in the database file |
//! | `journal_size_limit` | 4 MiB | The write-ahead log file is cut to this size when a checkpoint resets the log |
//! | `max_page_count` | From [`StoreOptions::max_database_size`] | The hard limit of the database size in pages; a write above it gives [`StoreError::Full`] |
//!
//! The open flags do not permit a URI filename. `SQLite` checkpoints the
//! write-ahead log automatically at 1000 pages, which is its default.
//!
//! # Size
//!
//! The hard limit applies to the size of the database in pages, which is
//! the size of the main file after a complete checkpoint. `SQLite` does not
//! record the limit in the file: it applies to the connection that sets it,
//! so each connection that writes must set it. The limit does not include
//! the write-ahead log and its index file. The log has about 4 MiB between
//! automatic checkpoints, but it grows above that while a reader of a
//! different connection prevents a checkpoint.
//!
//! A deletion puts pages on the free list of the database, and later
//! inserts use them again; the database does not become smaller. Thus the
//! size that retention controls is the used size: the database size minus
//! its free pages ([`StoreSize::used`]). Only [`Store::compact`] makes the
//! database smaller, and no other function calls it. A deletion also
//! writes to the log, so that retention fails with [`StoreError::Full`] or
//! [`StoreError::Io`] on a volume that has no space.

mod error;
mod migration;
mod query;
mod retention;
mod sample;
mod scan;
#[cfg(test)]
mod tests;

use std::fmt;
use std::path::Path;
use std::time::Duration;

use rusqlite::{Connection, OpenFlags};
use svalnir_core::quantity::{Bytes, EntryCount};

pub use self::error::StoreError;
pub use self::migration::STATE_STORE_VERSION;
use self::migration::{MIGRATIONS, Migration};
pub use self::query::{QueryLimit, TimeOrder, TimeRange};
pub use self::retention::{DEFAULT_MAX_BATCHES, RetentionPolicy, RetentionReport};
pub use self::sample::{EncodedSample, MAX_SAMPLE_BATCH, SampleQuery, SampleRow};
pub use self::scan::{MAX_SCAN_RESULT_BYTES, ScanQuery, ScanRecord, ScanSummary};

/// The size to which the write-ahead log file is cut after a checkpoint.
const JOURNAL_SIZE_LIMIT_BYTES: i64 = 4 * 1024 * 1024;

/// The largest `max_page_count` that `SQLite` accepts.
const MAX_PAGE_COUNT: u64 = 4_294_967_294;

/// The `synchronous` setting for the journal mode that `SQLite` reports.
fn synchronous_for(mode: &str, is_file: bool) -> &'static str {
    let durable_mode: bool =
        mode.eq_ignore_ascii_case("wal") || (!is_file && mode.eq_ignore_ascii_case("memory"));
    if durable_mode { "NORMAL" } else { "FULL" }
}

/// The settings of one store connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreOptions {
    /// How long an operation waits for a lock of a different connection
    /// before it fails with [`StoreError::Busy`].
    pub busy_timeout: Duration,
    /// The hard limit of the database size: `max_database_size` of the
    /// `[history]` configuration. `None` sets no limit. A limit smaller than
    /// the database leaves it as it is and refuses growth. The limit is in
    /// effect only for this connection; see the module documentation.
    pub max_database_size: Option<Bytes>,
}

impl Default for StoreOptions {
    /// A busy timeout of 2 seconds and no size limit.
    fn default() -> Self {
        Self {
            busy_timeout: Duration::from_secs(2),
            max_database_size: None,
        }
    }
}

/// The size of the database, from the `SQLite` page counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreSize {
    /// The size of one page.
    pub page_size: Bytes,
    /// The size of the database, with its free pages: the page count that
    /// this connection sees, which includes pages that are only in the
    /// write-ahead log at this time. It is the size of the main file after
    /// a complete checkpoint. The size of the log file is not included.
    pub file: Bytes,
    /// The size of the pages that hold data: `file` minus `free`.
    pub used: Bytes,
    /// The size of the free pages, which later inserts use again.
    pub free: Bytes,
    /// The hard limit of `file` that this connection applies, as a whole
    /// number of pages. `None` when the options set no limit.
    pub limit: Option<Bytes>,
}

/// One connection to the state store.
pub struct Store {
    connection: Connection,
    page_limit: Option<u64>,
}

impl fmt::Debug for Store {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Store")
            .field("page_limit", &self.page_limit)
            .finish_non_exhaustive()
    }
}

impl Store {
    /// Opens the database file at `path` and migrates it to
    /// [`STATE_STORE_VERSION`]. A file that does not exist is made; its
    /// directory must exist.
    ///
    /// An empty path and the name `:memory:` are refused: `SQLite` opens an
    /// in-memory database or a private temporary file for them, and the
    /// history would be lost silently.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidPath`] for an empty path or `:memory:`.
    /// Returns [`StoreError::NewerVersion`] or [`StoreError::NotAStateStore`]
    /// for a database that this build must not use; the content of the
    /// database is then not changed (`SQLite` can make or remove the
    /// write-ahead log files of a database that is in that mode). Returns [`StoreError::Migration`] when a migration
    /// fails; the database then keeps its previous version. Returns a
    /// storage error, for example [`StoreError::Io`] when the file cannot be
    /// opened or [`StoreError::Corrupt`] when it is not a database.
    pub fn open(path: &Path, options: &StoreOptions) -> Result<Self, StoreError> {
        Self::open_with_migrations(path, options, MIGRATIONS)
    }

    /// Opens a new database in memory, for tests and for a run that must
    /// not write a file.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Store::open`].
    pub fn open_in_memory(options: &StoreOptions) -> Result<Self, StoreError> {
        let connection: Connection = Connection::open_in_memory_with_flags(open_flags())?;
        Self::prepare(connection, options, MIGRATIONS, false)
    }

    fn open_with_migrations(
        path: &Path,
        options: &StoreOptions,
        migrations: &[Migration],
    ) -> Result<Self, StoreError> {
        // Refuse a defective migration list before the open makes a file.
        migration::supported_version(migrations)?;
        if path.as_os_str().is_empty() || path.as_os_str() == ":memory:" {
            return Err(StoreError::InvalidPath(path.display().to_string()));
        }
        let connection: Connection = Connection::open_with_flags(path, open_flags())?;
        Self::prepare(connection, options, migrations, true)
    }

    fn prepare(
        connection: Connection,
        options: &StoreOptions,
        migrations: &[Migration],
        is_file: bool,
    ) -> Result<Self, StoreError> {
        // Refuse a defective migration list, a database of a newer build,
        // or a database of a different application before a setting can
        // change the file.
        let supported: u32 = migration::supported_version(migrations)?;
        connection.busy_timeout(options.busy_timeout)?;
        migration::recorded_version(&connection, supported)?;

        // `SQLite` reports the mode in effect and does not fail when it
        // cannot set `WAL`. An in-memory database reports `memory`, which is
        // correct. A file in a different mode has no write-ahead log, so
        // `NORMAL` would weaken durability: take `FULL` there.
        let mode: String =
            connection.pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))?;
        connection.pragma_update(None, "synchronous", synchronous_for(&mode, is_file))?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        let _secure: i64 =
            connection.pragma_update_and_check(None, "secure_delete", "ON", |row| row.get(0))?;
        let _limit: i64 = connection.pragma_update_and_check(
            None,
            "journal_size_limit",
            JOURNAL_SIZE_LIMIT_BYTES,
            |row| row.get(0),
        )?;

        let mut store: Self = Self {
            connection,
            page_limit: None,
        };
        if let Some(limit) = options.max_database_size {
            let page_size: u64 = store.pragma_u64("page_size")?;
            let pages: u64 = (limit.get() / page_size.max(1)).clamp(1, MAX_PAGE_COUNT);
            // `SQLite` does not set a limit below the current page count; it
            // returns the limit that is in effect.
            let applied: i64 = store.connection.pragma_update_and_check(
                None,
                "max_page_count",
                i64::try_from(pages).unwrap_or(i64::MAX),
                |row| row.get(0),
            )?;
            store.page_limit =
                Some(u64::try_from(applied).map_err(|_| StoreError::InvalidRow {
                    table: "pragma",
                    column: "max_page_count",
                })?);
        }

        migration::migrate(&mut store.connection, migrations)?;
        Ok(store)
    }

    /// Reads the state-store version that the database records.
    ///
    /// # Errors
    ///
    /// Returns a storage error.
    pub fn version(&self) -> Result<u32, StoreError> {
        u32::try_from(self.pragma_u64("user_version")?).map_err(|_| StoreError::InvalidRow {
            table: "pragma",
            column: "user_version",
        })
    }

    /// Measures the database. The call reads three page counters and does
    /// not scan the tables.
    ///
    /// # Errors
    ///
    /// Returns a storage error.
    pub fn size(&self) -> Result<StoreSize, StoreError> {
        let page_size: u64 = self.pragma_u64("page_size")?;
        let page_count: u64 = self.pragma_u64("page_count")?;
        let free_count: u64 = self.pragma_u64("freelist_count")?;
        let bytes = |pages: u64| Bytes::new(pages.saturating_mul(page_size));
        Ok(StoreSize {
            page_size: Bytes::new(page_size),
            file: bytes(page_count),
            used: bytes(page_count.saturating_sub(free_count)),
            free: bytes(free_count),
            limit: self.page_limit.map(bytes),
        })
    }

    /// Rebuilds the database with `VACUUM` and then runs
    /// [`Store::checkpoint`], which returns the free pages to the
    /// filesystem. Returns `false` when a different connection prevented
    /// the complete checkpoint; the main file then becomes smaller at a
    /// later checkpoint.
    ///
    /// This is heavy work: it copies the database to a temporary file and
    /// then into the write-ahead log, so that it needs free space of about
    /// two times the used size. No other function of the store calls it.
    /// Do not call it during a resource emergency.
    ///
    /// # Errors
    ///
    /// Returns a storage error, for example [`StoreError::Full`] when the
    /// space is not available; the content of the database then is not
    /// changed.
    pub fn compact(&mut self) -> Result<bool, StoreError> {
        self.connection.execute_batch("VACUUM")?;
        self.checkpoint()
    }

    /// Moves the write-ahead log into the database file and cuts the log
    /// file to zero length. Returns `false` when a different connection
    /// prevented a complete checkpoint.
    ///
    /// # Errors
    ///
    /// Returns a storage error.
    pub fn checkpoint(&mut self) -> Result<bool, StoreError> {
        let blocked: i64 =
            self.connection
                .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))?;
        Ok(blocked == 0)
    }

    /// Deletes all metric samples and all scan records in one transaction:
    /// the history-deletion operation. Returns the number of deleted
    /// samples and the number of deleted scan records.
    ///
    /// The file keeps its size. [`Store::compact`] returns the space, and
    /// [`Store::checkpoint`] removes the write-ahead log, which can hold
    /// copies of deleted rows until then.
    ///
    /// # Errors
    ///
    /// Returns a storage error; the store then keeps all history.
    pub fn delete_all_history(&mut self) -> Result<(EntryCount, EntryCount), StoreError> {
        let transaction = self.connection.transaction()?;
        let samples: usize = transaction.execute("DELETE FROM metric_sample", [])?;
        let scans: usize = transaction.execute("DELETE FROM scan_record", [])?;
        transaction.commit()?;
        let count = |rows: usize| EntryCount::new(u64::try_from(rows).unwrap_or(u64::MAX));
        Ok((count(samples), count(scans)))
    }

    fn pragma_u64(&self, name: &'static str) -> Result<u64, StoreError> {
        let value: i64 = self
            .connection
            .pragma_query_value(None, name, |row| row.get(0))?;
        u64::try_from(value).map_err(|_| StoreError::InvalidRow {
            table: "pragma",
            column: name,
        })
    }

    fn count_rows(&self, sql: &str, table: &'static str) -> Result<EntryCount, StoreError> {
        let count: i64 = self
            .connection
            .prepare_cached(sql)?
            .query_row([], |row| row.get(0))?;
        u64::try_from(count)
            .map(EntryCount::new)
            .map_err(|_| StoreError::InvalidRow {
                table,
                column: "count",
            })
    }
}

fn open_flags() -> OpenFlags {
    OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_CREATE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
}
