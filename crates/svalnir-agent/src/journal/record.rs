//! The named records of the agent.
//!
//! Milestone 2 has no socket. The agent and a client share state through
//! the journal file: the authority record that an activation or a grant
//! command writes, the incident and budget state of the controller, the
//! status of the agent, and its lifecycle record. Each of them is one row
//! that a write replaces.
//!
//! A record is not an operation record. It has no part in an admission,
//! and the journal does not read its content. A write does not use the
//! admission reserve check: a replaced row of a bounded size is not new
//! work, and the status of the agent must stay writable when the journal
//! refuses new plans.
//!
//! Each record has a revision that each write increases. A writer that
//! read a record gives the revision that it read; a different writer
//! between the read and the write then gives
//! [`OperationJournalError::Conflict`], and nothing is written.

use rusqlite::{OptionalExtension, params};
use serde::Serialize;
use serde::de::DeserializeOwned;
use svalnir_core::time::WallTime;

use super::error::OperationJournalError;
use super::{OperationJournal, commit, decode, encode};

/// The largest size of the JSON of one agent record, in bytes.
pub const MAX_AGENT_RECORD_BYTES: usize = 512 * 1024;

/// The name of an agent record. The set is closed, so the table has a
/// fixed number of rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AgentRecord {
    /// The authority state: the policy revision in effect, each guard
    /// with its grant, and the pause (`svalnir_core::grant::AuthorityState`).
    Authority,
    /// The incident, budget, and cooldown state of the controller.
    Controller,
    /// The compact status of the agent, for a client.
    Status,
    /// The lifecycle record of the agent: the last start and stop, and the
    /// restart backoff.
    Lifecycle,
}

impl AgentRecord {
    /// Each name.
    pub const ALL: [Self; 4] = [
        Self::Authority,
        Self::Controller,
        Self::Status,
        Self::Lifecycle,
    ];

    /// The name in the `agent_record` table.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Authority => "authority",
            Self::Controller => "controller",
            Self::Status => "status",
            Self::Lifecycle => "lifecycle",
        }
    }
}

/// A stored agent record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredAgentRecord<T> {
    /// The record.
    pub record: T,
    /// The revision of the row. The first write gives 1.
    pub revision: u64,
    /// The wall-clock time of the write, in seconds since the Unix epoch.
    pub updated_unix_seconds: i64,
}

impl OperationJournal {
    /// Writes an agent record in one transaction and returns its new
    /// revision.
    ///
    /// `expected_revision` is the revision that the writer read: `Some(0)`
    /// expects that the record does not exist. `None` replaces the record
    /// whatever its revision is; use it only for a record that has one
    /// writer.
    ///
    /// # Errors
    ///
    /// Returns [`OperationJournalError::Conflict`] when the stored revision
    /// is not the expected one, [`OperationJournalError::RecordTooLarge`]
    /// when the JSON is larger than [`MAX_AGENT_RECORD_BYTES`], or a storage
    /// error. On an error nothing was written.
    pub fn put_agent_record<T: Serialize>(
        &mut self,
        name: AgentRecord,
        record: &T,
        expected_revision: Option<u64>,
        now: WallTime,
    ) -> Result<u64, OperationJournalError> {
        let content: String = encode(record)?;
        if content.len() > MAX_AGENT_RECORD_BYTES {
            return Err(OperationJournalError::RecordTooLarge {
                size: content.len(),
                limit: MAX_AGENT_RECORD_BYTES,
            });
        }
        let Self {
            connection,
            commit_fault,
            ..
        } = self;
        let transaction = Self::write_transaction(connection)?;
        let stored: Option<i64> = transaction
            .query_row(
                "SELECT revision FROM agent_record WHERE name = ?1",
                [name.as_str()],
                |row| row.get(0),
            )
            .optional()?;
        let current: u64 = match stored {
            Some(revision) => u64::try_from(revision)
                .map_err(|_| OperationJournalError::row("agent_record", "revision"))?,
            None => 0,
        };
        if expected_revision.is_some_and(|expected| expected != current) {
            return Err(OperationJournalError::Conflict);
        }
        let next: u64 = current
            .checked_add(1)
            .ok_or_else(|| OperationJournalError::row("agent_record", "revision"))?;
        let next_column: i64 = i64::try_from(next)
            .map_err(|_| OperationJournalError::row("agent_record", "revision"))?;
        transaction.execute(
            "INSERT INTO agent_record (name, revision, updated_unix_s, content) \
             VALUES (?1, ?2, ?3, ?4) \
             ON CONFLICT (name) DO UPDATE SET revision = excluded.revision, \
             updated_unix_s = excluded.updated_unix_s, content = excluded.content",
            params![name.as_str(), next_column, now.unix_seconds(), content],
        )?;
        commit(transaction, commit_fault)?;
        Ok(next)
    }

    /// Reads an agent record.
    ///
    /// # Errors
    ///
    /// Returns a decode error when the stored JSON is not a `T`, or a
    /// storage error. A record that does not exist is `Ok(None)`.
    pub fn agent_record<T: DeserializeOwned>(
        &self,
        name: AgentRecord,
    ) -> Result<Option<StoredAgentRecord<T>>, OperationJournalError> {
        let stored: Option<(i64, i64, String)> = self
            .connection
            .query_row(
                "SELECT revision, updated_unix_s, content FROM agent_record WHERE name = ?1",
                [name.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((revision, updated_unix_seconds, content)) = stored else {
            return Ok(None);
        };
        Ok(Some(StoredAgentRecord {
            record: decode("agent_record", &content)?,
            revision: u64::try_from(revision)
                .map_err(|_| OperationJournalError::row("agent_record", "revision"))?,
            updated_unix_seconds,
        }))
    }

    /// Reads the revision of an agent record with no decoding. A record
    /// that does not exist has the revision 0.
    ///
    /// # Errors
    ///
    /// Returns a storage error.
    pub fn agent_record_revision(&self, name: AgentRecord) -> Result<u64, OperationJournalError> {
        let stored: Option<i64> = self
            .connection
            .query_row(
                "SELECT revision FROM agent_record WHERE name = ?1",
                [name.as_str()],
                |row| row.get(0),
            )
            .optional()?;
        match stored {
            Some(revision) => u64::try_from(revision)
                .map_err(|_| OperationJournalError::row("agent_record", "revision")),
            None => Ok(0),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};
    use svalnir_core::time::WallTime;

    use super::{AgentRecord, MAX_AGENT_RECORD_BYTES};
    use crate::journal::{JournalOptions, OperationJournal, OperationJournalError};

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct Example {
        text: String,
    }

    fn example(text: &str) -> Example {
        Example {
            text: text.to_owned(),
        }
    }

    fn wall(seconds: i64) -> WallTime {
        WallTime::from_unix(seconds, 0).unwrap()
    }

    fn journal(directory: &tempfile::TempDir) -> OperationJournal {
        let options = JournalOptions {
            full_fsync: false,
            ..JournalOptions::default()
        };
        OperationJournal::open(&directory.path().join("operations.sqlite"), &options).unwrap()
    }

    #[test]
    fn a_record_is_replaced_and_its_revision_increases() {
        let directory = tempfile::tempdir().unwrap();
        let mut journal = journal(&directory);
        assert_eq!(
            journal
                .agent_record::<Example>(AgentRecord::Status)
                .unwrap(),
            None
        );
        assert_eq!(
            journal.agent_record_revision(AgentRecord::Status).unwrap(),
            0
        );
        let first = journal
            .put_agent_record(AgentRecord::Status, &example("one"), Some(0), wall(10))
            .unwrap();
        let second = journal
            .put_agent_record(AgentRecord::Status, &example("two"), None, wall(20))
            .unwrap();
        assert_eq!((first, second), (1, 2));
        let stored = journal
            .agent_record::<Example>(AgentRecord::Status)
            .unwrap()
            .unwrap();
        assert_eq!(stored.record, example("two"));
        assert_eq!(stored.revision, 2);
        assert_eq!(stored.updated_unix_seconds, 20);
        // A different name is a different record.
        assert_eq!(
            journal
                .agent_record::<Example>(AgentRecord::Controller)
                .unwrap(),
            None
        );
    }

    #[test]
    fn a_write_with_a_stale_revision_is_a_conflict_and_writes_nothing() {
        let directory = tempfile::tempdir().unwrap();
        let mut journal = journal(&directory);
        journal
            .put_agent_record(AgentRecord::Authority, &example("one"), Some(0), wall(1))
            .unwrap();
        // A second connection writes between the read and the write.
        let mut other = journal_at(&directory);
        other
            .put_agent_record(AgentRecord::Authority, &example("two"), Some(1), wall(2))
            .unwrap();
        let result =
            journal.put_agent_record(AgentRecord::Authority, &example("three"), Some(1), wall(3));
        assert!(matches!(result, Err(OperationJournalError::Conflict)));
        let again =
            journal.put_agent_record(AgentRecord::Authority, &example("three"), Some(0), wall(3));
        assert!(matches!(again, Err(OperationJournalError::Conflict)));
        let stored = journal
            .agent_record::<Example>(AgentRecord::Authority)
            .unwrap()
            .unwrap();
        assert_eq!((stored.record, stored.revision), (example("two"), 2));
    }

    fn journal_at(directory: &tempfile::TempDir) -> OperationJournal {
        journal(directory)
    }

    #[test]
    fn a_record_that_is_too_large_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let mut journal = journal(&directory);
        let large = example(&"x".repeat(MAX_AGENT_RECORD_BYTES));
        let result = journal.put_agent_record(AgentRecord::Controller, &large, None, wall(1));
        assert!(matches!(
            result,
            Err(OperationJournalError::RecordTooLarge { .. })
        ));
        assert_eq!(
            journal
                .agent_record_revision(AgentRecord::Controller)
                .unwrap(),
            0
        );
    }

    #[test]
    fn a_record_of_a_different_type_is_a_decode_error() {
        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Other {
            #[expect(dead_code, reason = "the field is only decoded")]
            number: u32,
        }
        let directory = tempfile::tempdir().unwrap();
        let mut journal = journal(&directory);
        journal
            .put_agent_record(AgentRecord::Lifecycle, &example("one"), None, wall(1))
            .unwrap();
        assert!(
            journal
                .agent_record::<Other>(AgentRecord::Lifecycle)
                .is_err()
        );
    }
}
