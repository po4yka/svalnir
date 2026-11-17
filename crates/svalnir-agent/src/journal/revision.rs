//! The revisions that operations bind to.
//!
//! An operation names a policy revision, the generations of its action
//! grants, and the rule revision of each file target. A change of the
//! configuration file must not change what a recorded action means, so the
//! journal keeps each of those records. This module stores and reads them.
//! The activation and revocation logic is in `svalnir_core::grant`.
//!
//! A record is immutable: the same identity with different content is a
//! conflict. A new generation of a grant is a new record. No function
//! removes a revision, and a new revision is new work: the journal refuses
//! it with `AdmissionStopped` when it cannot keep its size limits.

use rusqlite::{OptionalExtension, params};
use serde::Serialize;
use serde::de::DeserializeOwned;
use svalnir_core::authority::{ActionGrant, ActionGrantRef, PolicyRevision};
use svalnir_core::digest::ContentDigest;
use svalnir_core::id::PolicyRevisionId;
use svalnir_core::rule::{Rule, RuleRef};

use super::error::OperationJournalError;
use super::{OperationJournal, check_admission_capacity, commit, decode, encode};

/// The largest size of the source text of a policy revision, in bytes.
pub const MAX_REVISION_SOURCE_BYTES: usize = 1024 * 1024;

const POLICY: &str = "policy";
const ACTION_GRANT: &str = "action_grant";
const RULE: &str = "rule";

/// The `revision` key of a policy revision, which has one record for each
/// identity.
const SINGLE: &str = "-";

impl OperationJournal {
    fn store_revision<T: Serialize>(
        &mut self,
        kind: &'static str,
        id: &str,
        revision: &str,
        record: &T,
        source: Option<&str>,
    ) -> Result<(), OperationJournalError> {
        if let Some(size) = source.map(str::len)
            && size > MAX_REVISION_SOURCE_BYTES
        {
            return Err(OperationJournalError::RecordTooLarge {
                size,
                limit: MAX_REVISION_SOURCE_BYTES,
            });
        }
        let content: String = encode(record)?;
        let digest: ContentDigest =
            ContentDigest::of_json(record).map_err(OperationJournalError::Encode)?;
        let Self {
            connection,
            path,
            limits,
            commit_fault,
            ..
        } = self;
        let transaction = Self::write_transaction(connection)?;
        let stored: Option<(String, Option<String>)> = transaction
            .query_row(
                "SELECT digest, source FROM revision \
                 WHERE kind = ?1 AND id = ?2 AND revision = ?3",
                params![kind, id, revision],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((stored_digest, stored_source)) = stored {
            let same_source: bool = source.is_none() || source == stored_source.as_deref();
            return if stored_digest == digest.as_str() && same_source {
                Ok(())
            } else {
                Err(OperationJournalError::Conflict)
            };
        }
        // A new revision is new work: it does not use the reserve of the
        // admitted operations.
        check_admission_capacity(&transaction, path, limits)?;
        transaction.execute(
            "INSERT INTO revision (kind, id, revision, digest, content, source) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![kind, id, revision, digest.as_str(), content, source],
        )?;
        commit(transaction, commit_fault)
    }

    fn load_revision<T: DeserializeOwned + Serialize>(
        &self,
        kind: &'static str,
        id: &str,
        revision: &str,
    ) -> Result<Option<T>, OperationJournalError> {
        let stored: Option<(String, String)> = self
            .connection
            .query_row(
                "SELECT content, digest FROM revision \
                 WHERE kind = ?1 AND id = ?2 AND revision = ?3",
                params![kind, id, revision],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((content, digest)) = stored else {
            return Ok(None);
        };
        let record: T = decode("revision", &content)?;
        let actual: ContentDigest =
            ContentDigest::of_json(&record).map_err(OperationJournalError::Encode)?;
        if actual.as_str() == digest {
            Ok(Some(record))
        } else {
            Err(OperationJournalError::row("revision", "digest"))
        }
    }

    /// Stores an activated policy revision. `source` is the text of the
    /// validated configuration, when the caller has it; the journal keeps
    /// it as it is and does not read it. The same record again is not an
    /// error.
    ///
    /// # Errors
    ///
    /// Returns [`OperationJournalError::Conflict`] when the identity exists
    /// with different content or a different source,
    /// [`OperationJournalError::RecordTooLarge`] when `source` is larger
    /// than [`MAX_REVISION_SOURCE_BYTES`],
    /// [`OperationJournalError::AdmissionStopped`] when the journal cannot
    /// keep its size limits, or a storage error.
    pub fn record_policy_revision(
        &mut self,
        revision: &PolicyRevision,
        source: Option<&str>,
    ) -> Result<(), OperationJournalError> {
        self.store_revision(
            POLICY,
            revision.revision_id.as_str(),
            SINGLE,
            revision,
            source,
        )
    }

    /// Reads a policy revision.
    ///
    /// # Errors
    ///
    /// Returns a storage error. A revision that does not exist is
    /// `Ok(None)`.
    pub fn policy_revision(
        &self,
        revision_id: &PolicyRevisionId,
    ) -> Result<Option<PolicyRevision>, OperationJournalError> {
        self.load_revision(POLICY, revision_id.as_str(), SINGLE)
    }

    /// Reads the source text of a policy revision.
    ///
    /// # Errors
    ///
    /// Returns a storage error. A revision that does not exist, or that
    /// has no source, is `Ok(None)`.
    pub fn policy_revision_source(
        &self,
        revision_id: &PolicyRevisionId,
    ) -> Result<Option<String>, OperationJournalError> {
        let source: Option<Option<String>> = self
            .connection
            .query_row(
                "SELECT source FROM revision WHERE kind = ?1 AND id = ?2 AND revision = ?3",
                params![POLICY, revision_id.as_str(), SINGLE],
                |row| row.get(0),
            )
            .optional()?;
        Ok(source.flatten())
    }

    /// Stores one generation of an action grant. The same record again is
    /// not an error.
    ///
    /// # Errors
    ///
    /// Returns [`OperationJournalError::Conflict`] when the grant and the
    /// generation exist with different content, or a storage error.
    pub fn record_action_grant(
        &mut self,
        grant: &ActionGrant,
    ) -> Result<(), OperationJournalError> {
        self.store_revision(
            ACTION_GRANT,
            grant.grant_id.as_str(),
            &grant.generation.get().to_string(),
            grant,
            None,
        )
    }

    /// Reads one generation of an action grant.
    ///
    /// # Errors
    ///
    /// Returns a storage error. A generation that does not exist is
    /// `Ok(None)`.
    pub fn action_grant(
        &self,
        reference: &ActionGrantRef,
    ) -> Result<Option<ActionGrant>, OperationJournalError> {
        self.load_revision(
            ACTION_GRANT,
            reference.grant_id.as_str(),
            &reference.generation.get().to_string(),
        )
    }

    /// Stores one revision of a rule. The same record again is not an
    /// error.
    ///
    /// # Errors
    ///
    /// Returns [`OperationJournalError::Conflict`] when the rule and the
    /// revision exist with different content, or a storage error.
    pub fn record_rule_revision(&mut self, rule: &Rule) -> Result<(), OperationJournalError> {
        self.store_revision(
            RULE,
            rule.reference.id.as_str(),
            rule.reference.revision.as_str(),
            rule,
            None,
        )
    }

    /// Reads one revision of a rule. The decoding checks the declaration
    /// again.
    ///
    /// # Errors
    ///
    /// Returns a storage error. A revision that does not exist is
    /// `Ok(None)`.
    pub fn rule_revision(
        &self,
        reference: &RuleRef,
    ) -> Result<Option<Rule>, OperationJournalError> {
        self.load_revision(RULE, reference.id.as_str(), reference.revision.as_str())
    }
}
