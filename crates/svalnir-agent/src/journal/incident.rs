//! The consumed budget of each incident.
//!
//! The journal keeps one `incident_usage` row for each incident that has a
//! consumed dispatch. The consumption of a dispatch changes the row in its
//! own transaction, so the row and the consumed steps always agree. The
//! row does not go with an operation: a prune removes the settled
//! operations of an open incident and keeps its row, so a restart reads
//! the usage of the incident with no dependence on the retention
//! (`docs/ACTION_CONTRACTS.md` section 12).

use rusqlite::{Connection, OptionalExtension, params};
use svalnir_core::action::{RequestEnvelope, Reservation, WorkCharge};
use svalnir_core::id::{IncidentId, StepId};
use svalnir_core::quantity::{Bytes, EntryCount};

use super::error::OperationJournalError;
use super::{OperationJournal, row};

/// The consumed budget of one incident, as the journal records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IncidentUsage {
    /// The operations of the incident with a consumed application step. A
    /// graceful step and its force step use one slot.
    pub slots: u32,
    /// The sum of the charges of the consumed filesystem steps.
    pub work: WorkCharge,
}

/// The stored values of one row.
struct UsageRow {
    slots: i64,
    work_bytes: i64,
    items: i64,
}

fn invalid(column: &'static str) -> OperationJournalError {
    OperationJournalError::row("incident_usage", column)
}

fn read_row(
    connection: &Connection,
    incident_id: &str,
) -> Result<Option<UsageRow>, OperationJournalError> {
    Ok(connection
        .prepare_cached(
            "SELECT slots, work_bytes, items FROM incident_usage WHERE incident_id = ?1",
        )?
        .query_row([incident_id], |row| {
            Ok(UsageRow {
                slots: row.get(0)?,
                work_bytes: row.get(1)?,
                items: row.get(2)?,
            })
        })
        .optional()?)
}

/// Charges the consumed dispatch of the step `step_id` of the operation
/// row `seq` to the usage of the incident of the operation. An operation
/// with no incident changes nothing.
///
/// The caller marked the dispatch as consumed in the same transaction. An
/// application step uses a slot only when no other consumed step of the
/// operation has an application slot.
///
/// # Errors
///
/// Returns [`OperationJournalError::InvalidRow`] when the step has no
/// intent or when a sum is larger than a stored integer can hold, and a
/// storage error. The caller then writes nothing: the consumption fails
/// closed, and no external call follows it.
pub(super) fn charge(
    connection: &Connection,
    seq: i64,
    step_id: &StepId,
) -> Result<(), OperationJournalError> {
    let (incident_id, admitted): (Option<String>, i64) = connection
        .prepare_cached("SELECT incident_id, admitted_unix_s FROM operation WHERE seq = ?1")?
        .query_row([seq], |row| Ok((row.get(0)?, row.get(1)?)))?;
    let Some(incident_id) = incident_id else {
        return Ok(());
    };
    let mut charge: Option<&Reservation> = None;
    let mut slot_used: bool = false;
    let intents: Vec<(StepId, Option<RequestEnvelope>, bool)> = row::load_intents(connection, seq)?;
    for (id, intent, consumed) in &intents {
        let Some(intent) = intent else {
            continue;
        };
        if id == step_id {
            charge = Some(&intent.limits.reservation);
        } else if *consumed {
            slot_used |= matches!(
                intent.limits.reservation,
                Reservation::ApplicationSlot { .. }
            );
        }
    }
    let (slots, work): (i64, WorkCharge) = match charge.ok_or(invalid("intent"))? {
        Reservation::Work { charge } => (0, *charge),
        Reservation::ApplicationSlot { .. } => (i64::from(!slot_used), WorkCharge::ZERO),
    };
    let to_i64 =
        |value: u64, column: &'static str| i64::try_from(value).map_err(|_| invalid(column));
    let before: UsageRow = read_row(connection, &incident_id)?.unwrap_or(UsageRow {
        slots: 0,
        work_bytes: 0,
        items: 0,
    });
    let after = UsageRow {
        slots: before.slots.checked_add(slots).ok_or(invalid("slots"))?,
        work_bytes: before
            .work_bytes
            .checked_add(to_i64(work.work_bytes.get(), "work_bytes")?)
            .ok_or(invalid("work_bytes"))?,
        items: before
            .items
            .checked_add(to_i64(work.items.get(), "items")?)
            .ok_or(invalid("items"))?,
    };
    connection
        .prepare_cached(
            "INSERT INTO incident_usage \
             (incident_id, slots, work_bytes, items, last_admitted_unix_s) \
             VALUES (?1, ?2, ?3, ?4, ?5) \
             ON CONFLICT (incident_id) DO UPDATE SET \
             slots = excluded.slots, work_bytes = excluded.work_bytes, items = excluded.items, \
             last_admitted_unix_s = max(last_admitted_unix_s, excluded.last_admitted_unix_s)",
        )?
        .execute(params![
            incident_id,
            after.slots,
            after.work_bytes,
            after.items,
            admitted
        ])?;
    Ok(())
}

/// Removes the usage rows of the incidents that are not in `open` and
/// whose latest operation was admitted before `cutoff`, to a maximum of
/// `limit` rows. Returns the number of removed rows.
pub(super) fn prune(
    connection: &Connection,
    cutoff: i64,
    open: &[IncidentId],
    limit: i64,
) -> Result<usize, OperationJournalError> {
    // The open incidents can take `open.len()` rows of the selection.
    let open_rows: i64 = i64::try_from(open.len()).unwrap_or(i64::MAX);
    let mut statement = connection.prepare(
        "SELECT incident_id FROM incident_usage WHERE last_admitted_unix_s < ?1 \
         ORDER BY last_admitted_unix_s LIMIT ?2",
    )?;
    let rows = statement.query_map(params![cutoff, limit.saturating_add(open_rows)], |row| {
        row.get::<_, String>(0)
    })?;
    let mut closed: Vec<String> = Vec::new();
    for incident_id in rows {
        let incident_id: String = incident_id?;
        if open.iter().any(|open| open.as_str() == incident_id) {
            continue;
        }
        if i64::try_from(closed.len()).unwrap_or(i64::MAX) >= limit {
            break;
        }
        closed.push(incident_id);
    }
    for incident_id in &closed {
        connection
            .prepare_cached("DELETE FROM incident_usage WHERE incident_id = ?1")?
            .execute([incident_id])?;
    }
    Ok(closed.len())
}

impl OperationJournal {
    /// Reads the consumed budget of one incident. `None` means that the
    /// journal has no consumed dispatch of the incident, or that the
    /// retention removed the row of the incident after it closed.
    ///
    /// A restart reads this value to know the usage of an incident that
    /// continues, so that the restart does not give the incident a slot or
    /// work that it used before.
    ///
    /// # Errors
    ///
    /// Returns [`OperationJournalError::InvalidRow`] for a stored value
    /// outside the range of its type, and a storage error.
    pub fn incident_usage(
        &self,
        incident_id: &IncidentId,
    ) -> Result<Option<IncidentUsage>, OperationJournalError> {
        let Some(stored) = read_row(&self.connection, incident_id.as_str())? else {
            return Ok(None);
        };
        let unsigned =
            |value: i64, column: &'static str| u64::try_from(value).map_err(|_| invalid(column));
        Ok(Some(IncidentUsage {
            slots: u32::try_from(stored.slots).map_err(|_| invalid("slots"))?,
            work: WorkCharge::new(
                Bytes::new(unsigned(stored.work_bytes, "work_bytes")?),
                EntryCount::new(unsigned(stored.items, "items")?),
            ),
        }))
    }
}
