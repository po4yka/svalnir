//! The schema of the journal and the recorded journal version.
//!
//! The version is the `SQLite` `user_version` header field. The
//! `application_id` header field marks the file as a Svalnir operation
//! journal. A new, empty database gets the schema and the two fields in one
//! transaction, so that a failed creation leaves an empty database.
//!
//! The journal has no migration. A journal of a different version is
//! refused and is not changed. To change the schema, change [`SCHEMA`] and
//! increase [`JOURNAL_VERSION`].

use rusqlite::{Connection, TransactionBehavior};

use super::error::OperationJournalError;

/// The journal version that this build makes and supports.
///
/// It is independent of the configuration, CLI, IPC, and state-store
/// versions.
pub const JOURNAL_VERSION: u32 = 4;

/// The `application_id` of a Svalnir operation journal: the ASCII text
/// `SVLJ`. The catalog store has a different value, so that one file is
/// not opened as the other.
pub(super) const APPLICATION_ID: i64 = 0x5356_4C4A;

/// The schema of [`JOURNAL_VERSION`].
///
/// A JSON column has the encoding that `svalnir-core` writes for the type.
/// The other columns of a row are copies for the keys, the indexes, and the
/// filters; the JSON is the record.
///
/// - `plan`: each immutable plan. `created_unix_s` is the wall-clock time
///   of the plan, for retention only.
/// - `plan_consumption`: one row for each plan that an apply consumed, with
///   the operation or the recorded rejection. `pruned = 1` is the row of a
///   plan whose records the retention removed; an apply of that plan is
///   rejected as old.
/// - `operation`: the operation without its steps (`header`), the stop
///   fence, and `revision`, which each write of the operation or of one of
///   its steps increases.
/// - `step`: one row for each step, with the intent (the request
///   envelope) and the dispatch consumption.
/// - `incident_usage`: the consumed budget of each incident: the number of
///   operations with a consumed application step (`slots`) and the sum of
///   the work charges of the consumed filesystem steps (`work_bytes`,
///   `items`). The consumption of a dispatch changes the row in its own
///   transaction. `last_admitted_unix_s` is the admission time of the
///   latest operation that changed the row, for retention only. The row
///   does not go with an operation: the retention removes it only when its
///   incident is not open.
/// - `revision`: the policy revisions, the action grants, and the rule
///   revisions that operations bind to.
/// - `request`: the request queue between a client and the coordinator.
/// - `coordinator`: the registration of the coordinator that holds the
///   coordinator lock, and the reconciliation that an unclean stop needs.
/// - `agent_record`: the named records that the agent and a client share:
///   the authority state, the state of the controller, the status of the
///   agent, and its lifecycle record. One row for each name; a write
///   replaces the row and increases its `revision`.
/// - `operation_effect`: the resource observations of an operation (the
///   available capacity and the memory pressure before and after it), as
///   the JSON list of the `ResourceEffect` values of `svalnir-core`. One
///   row for each operation that has a record; a write replaces the row.
///   The row goes with its operation (`ON DELETE CASCADE`).
const SCHEMA: &str = "
CREATE TABLE plan (
    plan_id TEXT NOT NULL PRIMARY KEY,
    digest TEXT NOT NULL,
    created_unix_s INTEGER NOT NULL,
    content TEXT NOT NULL CHECK (json_valid(content))
) STRICT;
CREATE INDEX plan_by_time ON plan (created_unix_s);
CREATE TABLE plan_consumption (
    plan_id TEXT NOT NULL PRIMARY KEY,
    digest TEXT NOT NULL,
    principal TEXT NOT NULL CHECK (json_valid(principal)),
    operation_id TEXT UNIQUE,
    rejection TEXT CHECK (rejection IS NULL OR json_valid(rejection)),
    consumed_unix_s INTEGER NOT NULL,
    pruned INTEGER NOT NULL DEFAULT 0 CHECK (pruned IN (0, 1)),
    CHECK ((operation_id IS NULL) <> (rejection IS NULL))
) STRICT;
CREATE INDEX plan_consumption_by_time ON plan_consumption (consumed_unix_s) WHERE pruned = 0;
CREATE TABLE operation (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    operation_id TEXT NOT NULL UNIQUE,
    plan_id TEXT NOT NULL UNIQUE,
    executor_epoch TEXT NOT NULL,
    incident_id TEXT,
    state TEXT NOT NULL,
    settled INTEGER NOT NULL CHECK (settled IN (0, 1)),
    stop_fence INTEGER NOT NULL DEFAULT 0 CHECK (stop_fence IN (0, 1)),
    admitted_unix_s INTEGER NOT NULL,
    revision INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0),
    header TEXT NOT NULL CHECK (json_valid(header))
) STRICT;
CREATE INDEX operation_unsettled ON operation (seq) WHERE settled = 0;
CREATE INDEX operation_by_incident ON operation (incident_id, seq) WHERE incident_id IS NOT NULL;
CREATE TABLE step (
    operation_seq INTEGER NOT NULL REFERENCES operation (seq) ON DELETE CASCADE,
    position INTEGER NOT NULL CHECK (position >= 0),
    step_id TEXT NOT NULL,
    state TEXT NOT NULL,
    record TEXT NOT NULL CHECK (json_valid(record)),
    intent TEXT CHECK (intent IS NULL OR json_valid(intent)),
    intent_digest TEXT,
    dispatch_consumed INTEGER NOT NULL DEFAULT 0 CHECK (dispatch_consumed IN (0, 1)),
    PRIMARY KEY (operation_seq, position),
    UNIQUE (operation_seq, step_id),
    CHECK ((intent IS NULL) = (intent_digest IS NULL)),
    CHECK (dispatch_consumed = 0 OR intent IS NOT NULL)
) STRICT, WITHOUT ROWID;
CREATE TABLE incident_usage (
    incident_id TEXT NOT NULL PRIMARY KEY,
    slots INTEGER NOT NULL CHECK (slots >= 0),
    work_bytes INTEGER NOT NULL CHECK (work_bytes >= 0),
    items INTEGER NOT NULL CHECK (items >= 0),
    last_admitted_unix_s INTEGER NOT NULL
) STRICT, WITHOUT ROWID;
CREATE INDEX incident_usage_by_time ON incident_usage (last_admitted_unix_s);
CREATE TABLE revision (
    kind TEXT NOT NULL CHECK (kind IN ('policy', 'action_grant', 'rule')),
    id TEXT NOT NULL,
    revision TEXT NOT NULL,
    digest TEXT NOT NULL,
    content TEXT NOT NULL CHECK (json_valid(content)),
    source TEXT,
    PRIMARY KEY (kind, id, revision)
) STRICT, WITHOUT ROWID;
CREATE TABLE request (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id TEXT NOT NULL UNIQUE,
    digest TEXT NOT NULL,
    payload TEXT NOT NULL CHECK (json_valid(payload)),
    enqueued_unix_s INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('queued', 'claimed', 'completed')),
    claim_epoch TEXT,
    redelivered INTEGER NOT NULL DEFAULT 0 CHECK (redelivered IN (0, 1)),
    completion TEXT CHECK (completion IS NULL OR json_valid(completion)),
    CHECK ((state = 'queued') = (claim_epoch IS NULL)),
    CHECK ((state = 'completed') = (completion IS NOT NULL))
) STRICT;
CREATE INDEX request_open ON request (seq) WHERE state <> 'completed';
CREATE TABLE coordinator (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    executor_epoch TEXT NOT NULL,
    process_id INTEGER NOT NULL,
    started_unix_s INTEGER NOT NULL,
    released INTEGER NOT NULL CHECK (released IN (0, 1)),
    reconciliation_pending INTEGER NOT NULL CHECK (reconciliation_pending IN (0, 1))
) STRICT;
CREATE TABLE agent_record (
    name TEXT NOT NULL PRIMARY KEY
        CHECK (name IN ('authority', 'controller', 'status', 'lifecycle')),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    updated_unix_s INTEGER NOT NULL,
    content TEXT NOT NULL CHECK (json_valid(content))
) STRICT, WITHOUT ROWID;
CREATE TABLE operation_effect (
    operation_seq INTEGER NOT NULL PRIMARY KEY
        REFERENCES operation (seq) ON DELETE CASCADE,
    content TEXT NOT NULL CHECK (json_valid(content))
) STRICT, WITHOUT ROWID;
";

/// Reads the recorded version without a change to the database.
///
/// Returns 0 for a new, empty database and [`JOURNAL_VERSION`] for a
/// journal of this build.
///
/// # Errors
///
/// Returns [`OperationJournalError::NewerVersion`] or
/// [`OperationJournalError::OlderVersion`] for a journal of a different
/// version, and [`OperationJournalError::NotAJournal`] when the database is
/// not an operation journal.
pub(super) fn recorded_version(connection: &Connection) -> Result<u32, OperationJournalError> {
    // One statement reads the three values from one snapshot.
    let (application_id, user_version, object_count): (i64, i64, i64) = connection.query_row(
        "SELECT (SELECT application_id FROM pragma_application_id), \
         (SELECT user_version FROM pragma_user_version), \
         (SELECT count(*) FROM sqlite_schema)",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    if application_id == APPLICATION_ID {
        let found: u32 =
            u32::try_from(user_version).map_err(|_| OperationJournalError::NotAJournal)?;
        return match found.cmp(&JOURNAL_VERSION) {
            std::cmp::Ordering::Equal => Ok(found),
            std::cmp::Ordering::Greater => Err(OperationJournalError::NewerVersion {
                found,
                supported: JOURNAL_VERSION,
            }),
            std::cmp::Ordering::Less => Err(OperationJournalError::OlderVersion {
                found,
                supported: JOURNAL_VERSION,
            }),
        };
    }
    if application_id == 0 && user_version == 0 && object_count == 0 {
        Ok(0)
    } else {
        Err(OperationJournalError::NotAJournal)
    }
}

/// Makes the schema in a new, empty database. A journal of this build is
/// not changed.
///
/// The schema and the two header fields are written in one immediate
/// transaction. A different connection can make the schema between the
/// first read and the lock; the call then makes nothing.
///
/// # Errors
///
/// Returns the errors of [`recorded_version`], or the storage error. On an
/// error the database is not changed.
pub(super) fn create(connection: &mut Connection) -> Result<(), OperationJournalError> {
    if recorded_version(connection)? == JOURNAL_VERSION {
        return Ok(());
    }
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if recorded_version(&transaction)? == JOURNAL_VERSION {
        return Ok(());
    }
    transaction.execute_batch(SCHEMA)?;
    transaction.pragma_update(None, "application_id", APPLICATION_ID)?;
    transaction.pragma_update(None, "user_version", JOURNAL_VERSION)?;
    transaction.commit()?;
    Ok(())
}
