//! Retention of settled records.
//!
//! [`OperationJournal::prune`] is the only function that removes a record.
//! It removes settled work only. For each plan that an apply consumed, the
//! consumption row stays as a small marker, so an old apply of a pruned
//! plan is rejected as old and is not a new request. No function removes a
//! marker, so the markers grow with the number of consumed plans. A
//! completed request leaves no marker: the same request again is a new
//! request, and the marker of its plan rejects it at admission.
//!
//! The usage row of an incident (`incident_usage`) does not go with the
//! operations of the incident. A prune keeps the row while the caller
//! names the incident as open, so the budget of an open incident survives
//! the removal of its settled operations.

use rusqlite::{Connection, params};
use svalnir_core::id::IncidentId;
use svalnir_core::time::WallTime;

use super::error::OperationJournalError;
use super::{OperationJournal, commit, incident};

/// What one prune call removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PruneReport {
    /// The settled operations that were removed with their steps and
    /// plans.
    pub operations: usize,
    /// The recorded rejections whose plans were removed.
    pub rejections: usize,
    /// The plans that no apply consumed and that were removed.
    pub unused_plans: usize,
    /// The completed requests that were removed.
    pub requests: usize,
    /// The usage rows of closed incidents that were removed.
    pub incident_usage: usize,
}

/// Reads the plan identities that `statement` selects for the cutoff and
/// the limit.
fn select_plans(
    connection: &Connection,
    statement: &'static str,
    cutoff: i64,
    limit: i64,
) -> Result<Vec<String>, OperationJournalError> {
    let mut statement = connection.prepare(statement)?;
    let rows = statement.query_map(params![cutoff, limit], |row| row.get(0))?;
    let mut plans: Vec<String> = Vec::new();
    for plan in rows {
        plans.push(plan?);
    }
    Ok(plans)
}

/// Removes the plan `plan_id` and marks its consumption as pruned.
fn remove_plan(connection: &Connection, plan_id: &str) -> Result<(), OperationJournalError> {
    connection
        .prepare_cached("UPDATE plan_consumption SET pruned = 1 WHERE plan_id = ?1")?
        .execute([plan_id])?;
    connection
        .prepare_cached("DELETE FROM plan WHERE plan_id = ?1")?
        .execute([plan_id])?;
    Ok(())
}

impl OperationJournal {
    /// Removes settled records that are older than `cutoff`, to a maximum
    /// of `limit` records of each kind in one transaction:
    ///
    /// - A settled operation that was admitted before `cutoff`, with its
    ///   steps, its intents, and its plan.
    /// - The plan of a recorded rejection, when the plan was built before
    ///   `cutoff`.
    /// - A plan that was built before `cutoff`, that no apply consumed, and
    ///   that no open request names. Such a plan leaves no marker: the same
    ///   plan can be stored again, and the admission checks of the
    ///   coordinator then find that its validity is over.
    /// - A completed request that was made before `cutoff`.
    /// - The usage row of an incident that is not in `open_incidents`,
    ///   when the latest operation that changed it was admitted before
    ///   `cutoff`.
    ///
    /// An operation that is not settled, which includes `UnknownOutcome`,
    /// a request that is not completed, and the usage row of an incident
    /// in `open_incidents` are never removed. The settled operations of an
    /// open incident are removed: its usage row keeps its budget. The
    /// revisions that operations bind to are never removed.
    ///
    /// The caller gives a `cutoff` that is older than the validity of each
    /// request that can arrive: after the prune, an apply of a pruned plan
    /// returns the error `Expired`.
    ///
    /// This function is maintenance. It writes to the write-ahead log, so
    /// it can fail on a volume that has no space. It makes free pages that
    /// later inserts use again; it does not make the file smaller.
    ///
    /// # Errors
    ///
    /// Returns a storage error. On an error nothing was removed.
    pub fn prune(
        &mut self,
        cutoff: WallTime,
        limit: u32,
        open_incidents: &[IncidentId],
    ) -> Result<PruneReport, OperationJournalError> {
        let Self {
            connection,
            cache,
            commit_fault,
            ..
        } = self;
        *cache = None;
        let cutoff: i64 = cutoff.unix_seconds();
        let limit: i64 = i64::from(limit);
        let transaction = Self::write_transaction(connection)?;

        let settled: Vec<String> = select_plans(
            &transaction,
            "SELECT plan_id FROM operation \
             WHERE settled = 1 AND admitted_unix_s < ?1 ORDER BY seq LIMIT ?2",
            cutoff,
            limit,
        )?;
        for plan_id in &settled {
            // The steps go with their operation (`ON DELETE CASCADE`).
            transaction
                .prepare_cached("DELETE FROM operation WHERE plan_id = ?1")?
                .execute([plan_id])?;
            remove_plan(&transaction, plan_id)?;
        }
        let rejected: Vec<String> = select_plans(
            &transaction,
            "SELECT plan_id FROM plan_consumption \
             WHERE pruned = 0 AND rejection IS NOT NULL AND consumed_unix_s < ?1 \
             ORDER BY consumed_unix_s LIMIT ?2",
            cutoff,
            limit,
        )?;
        for plan_id in &rejected {
            remove_plan(&transaction, plan_id)?;
        }
        let unused_plans: usize = transaction.execute(
            "DELETE FROM plan WHERE plan_id IN ( \
             SELECT plan_id FROM plan WHERE created_unix_s < ?1 \
             AND plan_id NOT IN (SELECT plan_id FROM plan_consumption) \
             AND plan_id NOT IN ( \
             SELECT json_extract(payload, '$.body.approval.plan_id') FROM request \
             WHERE state <> 'completed' \
             AND json_extract(payload, '$.body.approval.plan_id') IS NOT NULL) \
             ORDER BY created_unix_s LIMIT ?2)",
            params![cutoff, limit],
        )?;
        let requests: usize = transaction.execute(
            "DELETE FROM request WHERE seq IN ( \
             SELECT seq FROM request WHERE state = 'completed' AND enqueued_unix_s < ?1 \
             ORDER BY seq LIMIT ?2)",
            params![cutoff, limit],
        )?;
        let incident_usage: usize = incident::prune(&transaction, cutoff, open_incidents, limit)?;
        commit(transaction, commit_fault)?;
        Ok(PruneReport {
            operations: settled.len(),
            rejections: rejected.len(),
            unused_plans,
            requests,
            incident_usage,
        })
    }
}
