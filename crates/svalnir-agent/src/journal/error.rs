//! Typed errors of the operation journal.

use rusqlite::ffi::ErrorCode;
use svalnir_core::action::{JournalError, OperationError};
use thiserror::Error;

/// The limit that stopped an admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionStop {
    /// The database has less free space below its hard limit than the
    /// admission reserve.
    Database,
    /// The write-ahead log file is larger than its limit.
    WriteAheadLog,
}

/// The reason a record does not agree with the stored state.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SequenceViolation {
    /// The step has no intent record.
    #[error("the step has no intent record")]
    NoIntent,
    /// The state machine of the foundation does not permit the change.
    #[error("the change is not permitted")]
    Transition(#[source] OperationError),
    /// The record that the permitted changes make is not the given record.
    #[error("the permitted changes do not make the given record")]
    Mismatch,
    /// The record moves a step to `IntentCommitted` or `DispatchConsumed`.
    /// Only the intent call and the dispatch consumption make those states.
    #[error("the intent and the dispatch consumption have their own calls")]
    Boundary,
    /// The operation is not a new admission: it has a state other than
    /// `Admitted`, a step that is not `Admitted`, or a durability other
    /// than `durable`.
    #[error("the operation is not a new durable admission")]
    NotNewAdmission,
    /// The operation was not admitted with the durability `volatile`.
    #[error("the operation is not a volatile admission")]
    NotVolatile,
    /// A coordinator that stopped without a release left work, and the
    /// reconciliation of that work is not complete.
    #[error("the reconciliation after an unclean stop is not complete")]
    ReconciliationPending,
    /// The executor lifetime is not the lifetime of the registered
    /// coordinator, or the coordinator released its registration.
    #[error("the executor lifetime is not the lifetime of the coordinator")]
    ExecutorEpoch,
    /// The request is not claimed by the executor lifetime.
    #[error("the request is not claimed by the executor lifetime")]
    Claim,
    /// An acknowledgment names an operation that is not `UnknownOutcome`.
    #[error("the operation is not in the state UnknownOutcome")]
    NotUnknownOutcome,
}

/// A failure of an operation-journal call.
///
/// Each storage failure is a separate variant. A call that returns an error
/// made no record, and the caller does not issue the associated external
/// call. [`OperationJournalError::to_journal_error`] gives the value of the
/// `Journal` interface.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum OperationJournalError {
    /// `SQLITE_FULL`: the database is at its hard limit, or the volume or
    /// the temporary storage has no space. The call wrote nothing.
    #[error("the operation journal is full; the call wrote nothing")]
    Full(#[source] rusqlite::Error),
    /// The journal cannot keep its size limits, and it admits no new work.
    /// Records of admitted operations are not stopped.
    #[error("the operation journal admits no new work: a size limit cannot be kept")]
    AdmissionStopped(AdmissionStop),
    /// The request queue has its largest number of open requests.
    #[error("the request queue has {limit} open requests, which is its limit")]
    QueueFull {
        /// The limit.
        limit: u32,
    },
    /// `SQLITE_BUSY` or `SQLITE_LOCKED`: a different connection held a lock
    /// for longer than the busy timeout. The call wrote nothing.
    #[error("the operation journal is locked by a different connection")]
    Busy(#[source] rusqlite::Error),
    /// `SQLITE_CORRUPT` or `SQLITE_NOTADB`: the file is damaged or is not an
    /// `SQLite` database.
    #[error("the operation journal file is corrupt or is not an SQLite database")]
    Corrupt(#[source] rusqlite::Error),
    /// `SQLITE_IOERR`, `SQLITE_CANTOPEN`, or `SQLITE_PERM`: the operating
    /// system refused or failed a file operation, which includes a failed
    /// synchronization. A volume with no space can give this error in place
    /// of [`OperationJournalError::Full`].
    #[error("a file operation of the operation journal failed")]
    Io(#[source] rusqlite::Error),
    /// `SQLITE_READONLY`: the file or its directory is not writable.
    #[error("the operation journal is read-only")]
    ReadOnly(#[source] rusqlite::Error),
    /// A file operation outside `SQLite` failed: the size of the
    /// write-ahead log file could not be read.
    #[error("a file of the operation journal cannot be read")]
    File(#[source] std::io::Error),
    /// A stored record cannot be decoded, or it does not pass the check of
    /// its type.
    #[error("a record of `{table}` cannot be decoded")]
    Decode {
        /// The table of the record.
        table: &'static str,
        /// The cause.
        #[source]
        source: serde_json::Error,
    },
    /// A stored plan has a plan schema version that is not that of this
    /// build. There is no migration: the user makes a new plan.
    #[error(
        "the stored plan has schema version {found}, and this build reads version {supported} \
         only; make a new plan"
    )]
    PlanVersion {
        /// The version that the stored plan records.
        found: u32,
        /// The version of this build.
        supported: u32,
    },
    /// A record cannot be encoded as JSON.
    #[error("a record cannot be encoded")]
    Encode(#[source] serde_json::Error),
    /// A stored value is outside the range of its type, or stored values do
    /// not agree with each other.
    #[error("the stored value `{column}` of `{table}` is not valid")]
    InvalidRow {
        /// The table, or `pragma` for a database setting.
        table: &'static str,
        /// The column or setting.
        column: &'static str,
    },
    /// The write-ahead log mode is not available for the file. The journal
    /// does not open in a different mode.
    #[error("the write-ahead log mode is not available: the journal mode is `{mode}`")]
    WalUnavailable {
        /// The journal mode that `SQLite` reports.
        mode: String,
    },
    /// `SQLite` did not apply a required setting.
    #[error("the setting `{setting}` of the operation journal is not in effect")]
    Setting {
        /// The setting.
        setting: &'static str,
    },
    /// A newer build wrote the database. This build did not change its
    /// content.
    #[error(
        "the operation journal has version {found}, and this build supports versions up to \
         {supported}; use a newer build"
    )]
    NewerVersion {
        /// The version that the database records.
        found: u32,
        /// The newest version that this build can read and write.
        supported: u32,
    },
    /// An earlier build wrote the database. The journal has no migration,
    /// and this build did not change its content.
    #[error(
        "the operation journal has version {found}, and this build supports version {supported} \
         only; the journal has no migration"
    )]
    OlderVersion {
        /// The version that the database records.
        found: u32,
        /// The version that this build can read and write.
        supported: u32,
    },
    /// A read-only open found a database with no journal schema. A
    /// read-only open makes no schema.
    #[error(
        "the operation journal has version {found}, and this build reads version {supported}; \
         a read-only open makes no schema"
    )]
    SchemaNotCurrent {
        /// The version that the database records.
        found: u32,
        /// The version that this build reads.
        supported: u32,
    },
    /// The file is an `SQLite` database that is not an operation journal.
    /// This build did not change its content.
    #[error("the database is not a Svalnir operation journal")]
    NotAJournal,
    /// The path is empty or is the `SQLite` name `:memory:`, which does not
    /// open a durable file. Nothing was opened.
    #[error("the journal path `{0}` does not name a durable file")]
    InvalidPath(String),
    /// A text is larger than the limit for one record. Nothing was
    /// written.
    #[error("the text has {size} bytes, and the limit is {limit} bytes")]
    RecordTooLarge {
        /// The size of the text in bytes.
        size: usize,
        /// The limit in bytes.
        limit: usize,
    },
    /// The coordinator lock is the lock of a different database.
    #[error("the coordinator lock is not the lock of this journal")]
    LockMismatch,
    /// The journal has no record with the identity.
    #[error("the journal has no record with the identity")]
    NotFound,
    /// The identity exists with different content.
    #[error("the identity exists with different content")]
    Conflict,
    /// The consumption record of the plan was pruned. An old request is
    /// rejected; it is not a new request.
    #[error("the record is older than the retention")]
    Expired,
    /// The record does not agree with the stored state. Nothing was
    /// written.
    #[error("the record does not agree with the stored state")]
    Sequence(#[source] SequenceViolation),
    /// A different `SQLite` failure.
    #[error("the operation journal call failed")]
    Sqlite(#[source] rusqlite::Error),
}

impl OperationJournalError {
    /// The value of the `Journal` interface for this failure.
    ///
    /// | Failure | Value |
    /// | --- | --- |
    /// | Full, admission stopped, queue full | `Full` |
    /// | A failed file operation or synchronization | `Sync` |
    /// | Corrupt file, record that cannot be decoded, plan of a different schema version, value out of range | `Corrupt` |
    /// | A locked database (`Busy`), `NotFound`, `Conflict`, `Expired`, `Sequence` | The same name |
    /// | Each other failure | `Unavailable` |
    pub fn to_journal_error(&self) -> JournalError {
        match self {
            Self::Full(_) | Self::AdmissionStopped(_) | Self::QueueFull { .. } => {
                JournalError::Full
            }
            Self::Io(_) | Self::File(_) => JournalError::Sync,
            Self::Corrupt(_)
            | Self::Decode { .. }
            | Self::PlanVersion { .. }
            | Self::InvalidRow { .. } => JournalError::Corrupt,
            Self::Busy(_) => JournalError::Busy,
            Self::NotFound => JournalError::NotFound,
            Self::Conflict => JournalError::Conflict,
            Self::Expired => JournalError::Expired,
            Self::Sequence(_) => JournalError::Sequence,
            _ => JournalError::Unavailable,
        }
    }

    /// Whether the storage failed. It is `false` for a request that the
    /// journal refused because of its content or of the stored state.
    pub fn is_storage_failure(&self) -> bool {
        !matches!(
            self,
            Self::NotFound
                | Self::Conflict
                | Self::Expired
                | Self::Sequence(_)
                | Self::LockMismatch
                | Self::RecordTooLarge { .. }
                | Self::InvalidPath(_)
        )
    }

    pub(super) fn decode(table: &'static str) -> impl FnOnce(serde_json::Error) -> Self {
        move |source| Self::Decode { table, source }
    }

    pub(super) const fn row(table: &'static str, column: &'static str) -> Self {
        Self::InvalidRow { table, column }
    }
}

impl From<rusqlite::Error> for OperationJournalError {
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

impl From<SequenceViolation> for OperationJournalError {
    fn from(violation: SequenceViolation) -> Self {
        Self::Sequence(violation)
    }
}
