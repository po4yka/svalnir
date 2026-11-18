//! Ordered, forward-only migrations and the recorded journal version.
//!
//! The version is the `SQLite` `user_version` header field. The
//! `application_id` header field marks the file as a Svalnir operation
//! journal. The two fields change in the transaction of the migration, so
//! that a failed migration leaves the previous version.
//!
//! To add a version, add one [`Migration`] at the end of [`MIGRATIONS`] and
//! increase [`JOURNAL_VERSION`]. Do not change or remove an entry that a
//! released build used.

use rusqlite::{Connection, TransactionBehavior};

use super::error::OperationJournalError;

/// The journal version that this build makes and supports.
///
/// It is independent of the configuration, CLI, IPC, and state-store
/// versions.
pub const JOURNAL_VERSION: u32 = 3;

/// The `application_id` of a Svalnir operation journal: the ASCII text
/// `SVLJ`. The catalog store has a different value, so that one file is
/// not opened as the other.
pub(super) const APPLICATION_ID: i64 = 0x5356_4C4A;

/// One schema step. It runs in one transaction.
#[derive(Debug, Clone, Copy)]
pub(super) struct Migration {
    /// The version that the database has after this step.
    pub(super) version: u32,
    /// The statements of the step.
    pub(super) sql: &'static str,
}

/// The migrations of this build, in order from version 1.
pub(super) const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        sql: SCHEMA_V1,
    },
    Migration {
        version: 2,
        sql: SCHEMA_V2,
    },
    Migration {
        version: 3,
        sql: SCHEMA_V3,
    },
];

/// Version 1.
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
/// - `revision`: the policy revisions, the action grants, and the rule
///   revisions that operations bind to.
/// - `request`: the request queue between a client and the coordinator.
/// - `coordinator`: the registration of the coordinator that holds the
///   coordinator lock, and the reconciliation that an unclean stop needs.
const SCHEMA_V1: &str = "
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
";

/// Version 2.
///
/// - `agent_record`: the named records that the agent and a client share:
///   the authority state, the state of the controller, the status of the
///   agent, and its lifecycle record. One row for each name; a write
///   replaces the row and increases its `revision`.
const SCHEMA_V2: &str = "
CREATE TABLE agent_record (
    name TEXT NOT NULL PRIMARY KEY
        CHECK (name IN ('authority', 'controller', 'status', 'lifecycle')),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    updated_unix_s INTEGER NOT NULL,
    content TEXT NOT NULL CHECK (json_valid(content))
) STRICT, WITHOUT ROWID;
";

/// Version 3.
///
/// - `operation_effect`: the resource observations of an operation (the
///   available capacity and the memory pressure before and after it), as
///   the JSON list of the `ResourceEffect` values of `svalnir-core`. One
///   row for each operation that has a record; a write replaces the row.
///   The row goes with its operation (`ON DELETE CASCADE`).
///
/// The step adds one table and changes no row of version 2. A database of
/// version 2 has no observation for its operations, and a read gives an
/// empty list for them.
const SCHEMA_V3: &str = "
CREATE TABLE operation_effect (
    operation_seq INTEGER NOT NULL PRIMARY KEY
        REFERENCES operation (seq) ON DELETE CASCADE,
    content TEXT NOT NULL CHECK (json_valid(content))
) STRICT, WITHOUT ROWID;
";

/// Reads the recorded version without a change to the database.
///
/// Returns 0 for a new, empty database.
///
/// # Errors
///
/// Returns [`OperationJournalError::NewerVersion`] when the version is
/// larger than `supported`, and [`OperationJournalError::NotAJournal`] when
/// the database is not an operation journal.
pub(super) fn recorded_version(
    connection: &Connection,
    supported: u32,
) -> Result<u32, OperationJournalError> {
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
        if found > supported {
            return Err(OperationJournalError::NewerVersion { found, supported });
        }
        return Ok(found);
    }
    if application_id == 0 && user_version == 0 && object_count == 0 {
        Ok(0)
    } else {
        Err(OperationJournalError::NotAJournal)
    }
}

/// Checks that `migrations` has the versions 1, 2, 3, and so on in order,
/// and returns the last version, or 0 for an empty list.
///
/// # Errors
///
/// Returns [`OperationJournalError::MigrationOrder`] for a list that is not
/// in order.
pub(super) fn supported_version(migrations: &[Migration]) -> Result<u32, OperationJournalError> {
    for (index, migration) in migrations.iter().enumerate() {
        let expected: Option<u32> = u32::try_from(index)
            .ok()
            .and_then(|index| index.checked_add(1));
        if expected != Some(migration.version) {
            return Err(OperationJournalError::MigrationOrder {
                version: migration.version,
            });
        }
    }
    Ok(migrations.last().map_or(0, |migration| migration.version))
}

/// Brings the database to the last version of `migrations`.
///
/// Each step runs in one immediate transaction, which also records the new
/// version. A step that a different connection applied first is skipped.
///
/// # Errors
///
/// Returns [`OperationJournalError::Migration`] when the statements of a
/// step fail, and the storage error itself when the storage fails in a
/// step. In the two cases the database has the version of the step before.
/// Returns the errors of [`recorded_version`] for a database that this
/// build must not change.
pub(super) fn migrate(
    connection: &mut Connection,
    migrations: &[Migration],
) -> Result<u32, OperationJournalError> {
    use OperationJournalError as E;
    let supported: u32 = supported_version(migrations)?;
    let mut current: u32 = recorded_version(connection, supported)?;
    for migration in migrations {
        if current >= migration.version {
            continue;
        }
        current = apply(connection, *migration, supported).map_err(|source| match source {
            direct @ (E::NewerVersion { .. }
            | E::NotAJournal
            | E::Full(_)
            | E::Busy(_)
            | E::Corrupt(_)
            | E::Io(_)
            | E::ReadOnly(_)) => direct,
            source => E::Migration {
                version: migration.version,
                source: Box::new(source),
            },
        })?;
    }
    Ok(current)
}

/// Runs one migration in a transaction and returns the version after it.
fn apply(
    connection: &mut Connection,
    migration: Migration,
    supported: u32,
) -> Result<u32, OperationJournalError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    // A different connection can migrate between the first read and the lock.
    let current: u32 = recorded_version(&transaction, supported)?;
    if current >= migration.version {
        return Ok(current);
    }
    transaction.execute_batch(migration.sql)?;
    transaction.pragma_update(None, "application_id", APPLICATION_ID)?;
    transaction.pragma_update(None, "user_version", migration.version)?;
    transaction.commit()?;
    Ok(migration.version)
}
