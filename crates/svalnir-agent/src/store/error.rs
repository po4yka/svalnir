//! Typed errors of the state store.

use rusqlite::ffi::ErrorCode;
use svalnir_core::id::ScanId;
use svalnir_core::observation::ObservationError;
use thiserror::Error;

/// A failure of a state-store operation.
///
/// The storage failures are separate variants, so that a caller can stop
/// mutation when durable recording fails. [`StoreError::recording_failed`]
/// groups them.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum StoreError {
    /// `SQLITE_FULL`: the database is at its size limit, or the volume or the
    /// temporary storage has no space. The operation wrote nothing.
    #[error("the state store is full; the operation wrote nothing")]
    Full(#[source] rusqlite::Error),
    /// `SQLITE_BUSY`: a different connection held a lock for longer than
    /// the busy timeout. Also `SQLITE_LOCKED`, a lock conflict for which
    /// `SQLite` does not wait. The operation wrote nothing.
    #[error("the state store is locked by a different connection")]
    Busy(#[source] rusqlite::Error),
    /// `SQLITE_CORRUPT` or `SQLITE_NOTADB`: the file is damaged or is not an
    /// `SQLite` database.
    #[error("the state store file is corrupt or is not an SQLite database")]
    Corrupt(#[source] rusqlite::Error),
    /// `SQLITE_IOERR`, `SQLITE_CANTOPEN`, or `SQLITE_PERM`: the operating
    /// system refused or failed a file operation. A volume with no space
    /// can give this error in place of [`StoreError::Full`], for example
    /// when a sync or the shared-memory file fails.
    #[error("a file operation of the state store failed")]
    Io(#[source] rusqlite::Error),
    /// `SQLITE_READONLY`: the database file or its directory is not writable.
    #[error("the state store is read-only")]
    ReadOnly(#[source] rusqlite::Error),
    /// A newer build wrote the database. This build did not change its
    /// content.
    /// To repair, use a build that supports the version, or move the file
    /// away so that a new store is made.
    #[error(
        "the state store has version {found}, and this build supports versions up to {supported}; \
         use a newer build or move the file away"
    )]
    NewerVersion {
        /// The version that the database records.
        found: u32,
        /// The newest version that this build can read and write.
        supported: u32,
    },
    /// The file is an `SQLite` database that Svalnir did not make. This
    /// build did not change its content.
    #[error("the database is not a Svalnir state store")]
    NotAStateStore,
    /// The statements of a migration failed and were rolled back. The
    /// database keeps the version that it had before this migration. A
    /// storage failure in a migration is its own variant, for example
    /// [`StoreError::Busy`].
    #[error("the migration to state-store version {version} failed and was rolled back")]
    Migration {
        /// The version that the failed migration makes.
        version: u32,
        /// The cause.
        #[source]
        source: Box<StoreError>,
    },
    /// The migration list of the build is not `1, 2, 3, ...` in order.
    #[error("the migration list is not in order at version {version}")]
    MigrationOrder {
        /// The version that is out of order.
        version: u32,
    },
    /// The observation cannot be written as JSON.
    #[error("the observation cannot be encoded")]
    Encode(#[source] serde_json::Error),
    /// The observation has a value and a unit that do not agree, so that it
    /// cannot be read back.
    #[error("the observation cannot be stored")]
    Observation(#[source] ObservationError),
    /// A stored observation cannot be read as the requested value type.
    #[error("the stored observation cannot be decoded as the requested type")]
    Decode(#[source] serde_json::Error),
    /// The scan result text is not JSON.
    #[error("the scan result is not valid JSON")]
    InvalidScanResult(#[source] serde_json::Error),
    /// The scan result text is larger than the limit for one record.
    #[error("the scan result has {size} bytes, and the limit is {limit} bytes")]
    ScanResultTooLarge {
        /// The size of the text in bytes.
        size: usize,
        /// The limit in bytes.
        limit: usize,
    },
    /// A scan record with this identifier is in the store. The store did not
    /// replace it.
    #[error("a scan record with the identifier `{0}` is in the store")]
    DuplicateScan(ScanId),
    /// One insert call has more samples than the limit for one transaction.
    #[error("the batch has {size} samples, and the limit is {limit}")]
    BatchTooLarge {
        /// The number of samples in the batch.
        size: usize,
        /// The limit.
        limit: usize,
    },
    /// The query limit is zero or larger than the maximum.
    #[error("the query limit {limit} is not in the range 1 to {maximum}")]
    InvalidLimit {
        /// The requested limit.
        limit: u32,
        /// The maximum.
        maximum: u32,
    },
    /// A stored value is outside the range of its core type. The store does
    /// not replace it with a default.
    #[error("the stored value `{column}` of `{table}` is not valid")]
    InvalidRow {
        /// The table, or `pragma` for a database setting.
        table: &'static str,
        /// The column or setting.
        column: &'static str,
    },
    /// The path is empty or is the `SQLite` name `:memory:`, which does not
    /// open a durable file. Use `Store::open_in_memory` for a store in
    /// memory. Nothing was opened.
    #[error("the state store path `{0}` does not name a durable file")]
    InvalidPath(String),
    /// A different `SQLite` failure.
    #[error("the state store operation failed")]
    Sqlite(#[source] rusqlite::Error),
}

impl StoreError {
    /// Tells if a write may have failed to record durably. It is `true` for
    /// each storage failure: full, locked, corrupt, read-only, I/O, and any
    /// other `SQLite` failure ([`StoreError::Sqlite`], for example
    /// `SQLITE_NOMEM`, `SQLITE_PROTOCOL`, `SQLITE_INTERRUPT`, or
    /// `SQLITE_CONSTRAINT`), and for a duplicate scan record. It is `false`
    /// only for an error that the store raises before it attempts a write:
    /// a refused input, a refused path, a database that this build must not
    /// use, or a read-side decode failure. A caller that needs a durable
    /// record must stop the related mutation when this is true. A failed
    /// write is never reported as recorded.
    pub fn recording_failed(&self) -> bool {
        match self {
            Self::Full(_)
            | Self::Busy(_)
            | Self::Corrupt(_)
            | Self::Io(_)
            | Self::ReadOnly(_)
            | Self::Sqlite(_)
            | Self::DuplicateScan(_) => true,
            Self::Migration { source, .. } => source.recording_failed(),
            _ => false,
        }
    }
}

impl From<rusqlite::Error> for StoreError {
    fn from(error: rusqlite::Error) -> Self {
        match error.sqlite_error_code() {
            Some(ErrorCode::DiskFull) => Self::Full(error),
            Some(ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked) => Self::Busy(error),
            Some(ErrorCode::DatabaseCorrupt | ErrorCode::NotADatabase) => Self::Corrupt(error),
            Some(
                ErrorCode::SystemIoFailure | ErrorCode::CannotOpen | ErrorCode::PermissionDenied,
            ) => Self::Io(error),
            Some(ErrorCode::ReadOnly) => Self::ReadOnly(error),
            _ => Self::Sqlite(error),
        }
    }
}
