//! Ordered, forward-only migrations and the recorded state-store version.
//!
//! The version is the `SQLite` `user_version` header field. The
//! `application_id` header field marks the file as a Svalnir state store.
//! The two fields change in the transaction of the migration, so that a
//! failed migration leaves the previous version.
//!
//! To add a version, add one [`Migration`] at the end of [`MIGRATIONS`] and
//! increase [`STATE_STORE_VERSION`]. Do not change or remove an entry that a
//! released build used.

use rusqlite::{Connection, TransactionBehavior};

use super::error::StoreError;

/// The state-store version that this build makes and supports.
///
/// It is independent of the configuration, CLI, IPC, and journal versions
/// (`docs/INTERFACES.md`, section 2).
pub const STATE_STORE_VERSION: u32 = 1;

/// The `application_id` of a Svalnir state store: the ASCII text `SVLN`.
pub(super) const APPLICATION_ID: i64 = 0x5356_4C4E;

/// One schema step. It runs in one transaction.
#[derive(Debug, Clone, Copy)]
pub(super) struct Migration {
    /// The version that the database has after this step.
    pub(super) version: u32,
    /// The statements of the step.
    pub(super) sql: &'static str,
}

/// The migrations of this build, in order from version 1.
pub(super) const MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    sql: SCHEMA_V1,
}];

/// Version 1: metric history samples and saved scan records.
///
/// A timestamp is two columns, the Unix second and the nanosecond in the
/// second, because the range of the core `WallTime` in nanoseconds does not
/// fit a 64-bit integer. The `observation` column is the canonical JSON of
/// the core `Observation`; the other sample columns are copies for the
/// indexes and filters. An unavailable row has a reason and is never a
/// zero value.
const SCHEMA_V1: &str = "
CREATE TABLE metric_sample (
    id INTEGER PRIMARY KEY,
    metric_id TEXT NOT NULL,
    scope_kind TEXT NOT NULL,
    scope_identity TEXT NOT NULL,
    captured_unix_s INTEGER NOT NULL,
    captured_subsec_ns INTEGER NOT NULL
        CHECK (captured_subsec_ns BETWEEN 0 AND 999999999),
    availability TEXT NOT NULL,
    reason TEXT,
    observation TEXT NOT NULL CHECK (json_valid(observation)),
    CHECK ((availability = 'unavailable') = (reason IS NOT NULL))
) STRICT;
CREATE INDEX metric_sample_by_time
    ON metric_sample (captured_unix_s, captured_subsec_ns);
CREATE INDEX metric_sample_by_series
    ON metric_sample (metric_id, scope_kind, scope_identity, captured_unix_s, captured_subsec_ns);
CREATE TABLE scan_record (
    scan_id TEXT NOT NULL PRIMARY KEY,
    root BLOB NOT NULL,
    started_unix_s INTEGER NOT NULL,
    started_subsec_ns INTEGER NOT NULL
        CHECK (started_subsec_ns BETWEEN 0 AND 999999999),
    finished_unix_s INTEGER NOT NULL,
    finished_subsec_ns INTEGER NOT NULL
        CHECK (finished_subsec_ns BETWEEN 0 AND 999999999),
    result TEXT NOT NULL CHECK (json_valid(result)),
    result_size INTEGER NOT NULL CHECK (result_size >= 0)
) STRICT;
CREATE INDEX scan_record_by_time
    ON scan_record (started_unix_s, started_subsec_ns);
";

/// Reads the recorded version without a change to the database.
///
/// Returns 0 for a new, empty database.
///
/// # Errors
///
/// Returns [`StoreError::NewerVersion`] when the version is larger than
/// `supported`, and [`StoreError::NotAStateStore`] when a different
/// application made the database.
pub(super) fn recorded_version(connection: &Connection, supported: u32) -> Result<u32, StoreError> {
    // One statement reads the three values from one snapshot. Separate
    // statements can see the state before and after the migration of a
    // different connection.
    let (application_id, user_version, object_count): (i64, i64, i64) = connection.query_row(
        "SELECT (SELECT application_id FROM pragma_application_id), \
         (SELECT user_version FROM pragma_user_version), \
         (SELECT count(*) FROM sqlite_schema)",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    if application_id == APPLICATION_ID {
        let found: u32 = u32::try_from(user_version).map_err(|_| StoreError::NotAStateStore)?;
        if found > supported {
            return Err(StoreError::NewerVersion { found, supported });
        }
        return Ok(found);
    }
    if application_id == 0 && user_version == 0 && object_count == 0 {
        Ok(0)
    } else {
        Err(StoreError::NotAStateStore)
    }
}

/// Checks that `migrations` has the versions 1, 2, 3, and so on in order,
/// and returns the last version, or 0 for an empty list.
///
/// # Errors
///
/// Returns [`StoreError::MigrationOrder`] for a list that is not in order.
pub(super) fn supported_version(migrations: &[Migration]) -> Result<u32, StoreError> {
    for (index, migration) in migrations.iter().enumerate() {
        let expected: Option<u32> = u32::try_from(index)
            .ok()
            .and_then(|index| index.checked_add(1));
        if expected != Some(migration.version) {
            return Err(StoreError::MigrationOrder {
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
/// Returns [`StoreError::Migration`] when the statements of a step fail,
/// and the storage error itself (for example [`StoreError::Busy`] or
/// [`StoreError::Full`]) when the storage fails in a step. In the two cases
/// the database has the version of the step before. Returns the errors of
/// [`recorded_version`] for a database that this build must not change.
pub(super) fn migrate(
    connection: &mut Connection,
    migrations: &[Migration],
) -> Result<u32, StoreError> {
    let supported: u32 = supported_version(migrations)?;
    let mut current: u32 = recorded_version(connection, supported)?;
    for migration in migrations {
        if current >= migration.version {
            continue;
        }
        current = apply(connection, *migration, supported).map_err(|source| match source {
            // A refusal or a storage failure keeps its own variant, so that
            // a caller can match it.
            direct @ (StoreError::NewerVersion { .. }
            | StoreError::NotAStateStore
            | StoreError::Full(_)
            | StoreError::Busy(_)
            | StoreError::Corrupt(_)
            | StoreError::Io(_)
            | StoreError::ReadOnly(_)) => direct,
            source => StoreError::Migration {
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
) -> Result<u32, StoreError> {
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
