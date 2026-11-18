//! The rows of an operation and of its steps.
//!
//! An operation is one `operation` row, which has the JSON of the operation
//! without its steps, and one `step` row for each step, which has the JSON
//! of the step. A read puts the two together and decodes the result as an
//! `Operation`, so the consistency check of `svalnir-core` runs on each
//! read.

use rusqlite::{Connection, OptionalExtension, params};
use serde_json::Value;
use svalnir_core::action::{Operation, RequestEnvelope, Step};
use svalnir_core::id::{IncidentId, OperationId, StepId};

use super::error::OperationJournalError;
use super::{decode, encode};

/// The name of the field of the operation JSON that has the steps.
const STEPS_FIELD: &str = "steps";

/// The key values of one `operation` row.
#[derive(Debug, Clone, Copy)]
pub(super) struct OperationRow {
    pub(super) seq: i64,
    pub(super) revision: i64,
    pub(super) stop_fence: bool,
}

/// The intent and the dispatch consumption of one `step` row.
#[derive(Debug)]
pub(super) struct StepRow {
    pub(super) intent_digest: Option<String>,
    pub(super) dispatch_consumed: bool,
}

/// Reads the key values of the operation `operation_id`.
pub(super) fn find_operation(
    connection: &Connection,
    operation_id: &OperationId,
) -> Result<Option<OperationRow>, OperationJournalError> {
    Ok(connection
        .query_row(
            "SELECT seq, revision, stop_fence FROM operation WHERE operation_id = ?1",
            [operation_id.as_str()],
            |row| {
                Ok(OperationRow {
                    seq: row.get(0)?,
                    revision: row.get(1)?,
                    stop_fence: row.get(2)?,
                })
            },
        )
        .optional()?)
}

/// The JSON of `operation` without its steps.
fn header_of(operation: &Operation) -> Result<String, OperationJournalError> {
    let mut value: Value =
        serde_json::to_value(operation).map_err(OperationJournalError::Encode)?;
    let removed: Option<Value> = value
        .as_object_mut()
        .and_then(|object| object.remove(STEPS_FIELD));
    if removed.is_none() {
        return Err(OperationJournalError::row("operation", "header"));
    }
    encode(&value)
}

/// Reads the operation of the row `seq`.
///
/// # Errors
///
/// Returns [`OperationJournalError::Decode`] when the stored record is not
/// a consistent operation.
pub(super) fn load_operation(
    connection: &Connection,
    seq: i64,
) -> Result<Operation, OperationJournalError> {
    let header: String = connection.query_row(
        "SELECT header FROM operation WHERE seq = ?1",
        [seq],
        |row| row.get(0),
    )?;
    let mut value: Value = decode("operation", &header)?;
    let mut statement = connection
        .prepare_cached("SELECT record FROM step WHERE operation_seq = ?1 ORDER BY position")?;
    let mut steps: Vec<Value> = Vec::new();
    let mut rows = statement.query([seq])?;
    while let Some(row) = rows.next()? {
        let record: String = row.get(0)?;
        steps.push(decode("step", &record)?);
    }
    let object = value
        .as_object_mut()
        .ok_or(OperationJournalError::row("operation", "header"))?;
    if object
        .insert(STEPS_FIELD.to_owned(), Value::Array(steps))
        .is_some()
    {
        return Err(OperationJournalError::row("operation", "header"));
    }
    serde_json::from_value(value).map_err(OperationJournalError::decode("operation"))
}

/// Inserts `operation` and its steps and returns the row identity.
pub(super) fn insert_operation(
    connection: &Connection,
    operation: &Operation,
    incident: Option<&IncidentId>,
) -> Result<i64, OperationJournalError> {
    connection.execute(
        "INSERT INTO operation \
         (operation_id, plan_id, executor_epoch, incident_id, state, settled, admitted_unix_s, header) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            operation.operation_id().as_str(),
            operation.plan_id().as_str(),
            operation.executor_epoch().as_str(),
            incident.map(IncidentId::as_str),
            operation.state().as_str(),
            operation.state().is_settled(),
            operation.admitted_at().unix_seconds(),
            header_of(operation)?,
        ],
    )?;
    let seq: i64 = connection.last_insert_rowid();
    let mut statement = connection.prepare_cached(
        "INSERT INTO step (operation_seq, position, step_id, state, record) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
    )?;
    for (position, step) in operation.steps().iter().enumerate() {
        let position: i64 =
            i64::try_from(position).map_err(|_| OperationJournalError::row("step", "position"))?;
        statement.execute(params![
            seq,
            position,
            step.step_id().as_str(),
            step.progress().state().as_str(),
            encode(step)?,
        ])?;
    }
    Ok(seq)
}

/// Checks that a statement changed one row.
fn one_row(
    changed: usize,
    table: &'static str,
    column: &'static str,
) -> Result<(), OperationJournalError> {
    if changed == 1 {
        Ok(())
    } else {
        Err(OperationJournalError::row(table, column))
    }
}

/// Writes the record of one step of the operation row `seq`.
pub(super) fn write_step(
    connection: &Connection,
    seq: i64,
    step: &Step,
) -> Result<(), OperationJournalError> {
    let changed: usize = connection
        .prepare_cached(
            "UPDATE step SET record = ?1, state = ?2 WHERE operation_seq = ?3 AND step_id = ?4",
        )?
        .execute(params![
            encode(step)?,
            step.progress().state().as_str(),
            seq,
            step.step_id().as_str(),
        ])?;
    one_row(changed, "step", "step_id")
}

/// Writes the state of the operation row `seq` and the new revision.
pub(super) fn write_operation(
    connection: &Connection,
    seq: i64,
    operation: &Operation,
    revision: i64,
) -> Result<(), OperationJournalError> {
    let changed: usize = connection.execute(
        "UPDATE operation SET state = ?1, settled = ?2, header = ?3, revision = ?4 WHERE seq = ?5",
        params![
            operation.state().as_str(),
            operation.state().is_settled(),
            header_of(operation)?,
            revision,
            seq,
        ],
    )?;
    one_row(changed, "operation", "seq")
}

/// Writes the new revision of the operation row `seq`.
pub(super) fn write_revision(
    connection: &Connection,
    seq: i64,
    revision: i64,
) -> Result<(), OperationJournalError> {
    let changed: usize = connection
        .prepare_cached("UPDATE operation SET revision = ?1 WHERE seq = ?2")?
        .execute(params![revision, seq])?;
    one_row(changed, "operation", "seq")
}

/// Reads the intent and the dispatch consumption of one step.
pub(super) fn step_row(
    connection: &Connection,
    seq: i64,
    step_id: &StepId,
) -> Result<StepRow, OperationJournalError> {
    connection
        .prepare_cached(
            "SELECT intent_digest, dispatch_consumed FROM step \
             WHERE operation_seq = ?1 AND step_id = ?2",
        )?
        .query_row(params![seq, step_id.as_str()], |row| {
            Ok(StepRow {
                intent_digest: row.get(0)?,
                dispatch_consumed: row.get(1)?,
            })
        })
        .optional()?
        .ok_or(OperationJournalError::NotFound)
}

/// Writes the intent of one step.
pub(super) fn write_intent(
    connection: &Connection,
    seq: i64,
    step_id: &StepId,
    intent: &str,
    digest: &str,
) -> Result<(), OperationJournalError> {
    let changed: usize = connection
        .prepare_cached(
            "UPDATE step SET intent = ?1, intent_digest = ?2 \
             WHERE operation_seq = ?3 AND step_id = ?4 AND intent IS NULL",
        )?
        .execute(params![intent, digest, seq, step_id.as_str()])?;
    one_row(changed, "step", "intent")
}

/// Writes the dispatch consumption of one step that has an intent, and
/// charges it to the usage of the incident of the operation.
pub(super) fn write_dispatch_consumed(
    connection: &Connection,
    seq: i64,
    step_id: &StepId,
) -> Result<(), OperationJournalError> {
    let changed: usize = connection
        .prepare_cached(
            "UPDATE step SET dispatch_consumed = 1 \
             WHERE operation_seq = ?1 AND step_id = ?2 \
             AND dispatch_consumed = 0 AND intent IS NOT NULL",
        )?
        .execute(params![seq, step_id.as_str()])?;
    one_row(changed, "step", "dispatch_consumed")?;
    // The budget charge of the incident is in the transaction of the
    // consumption.
    super::incident::charge(connection, seq, step_id)
}

/// Reads the intents of the operation row `seq`, in step sequence: for
/// each step, the request envelope and whether the dispatch was consumed.
pub(super) fn load_intents(
    connection: &Connection,
    seq: i64,
) -> Result<Vec<(StepId, Option<RequestEnvelope>, bool)>, OperationJournalError> {
    let mut statement = connection.prepare_cached(
        "SELECT step_id, intent, dispatch_consumed FROM step \
         WHERE operation_seq = ?1 ORDER BY position",
    )?;
    let mut rows = statement.query([seq])?;
    let mut intents: Vec<(StepId, Option<RequestEnvelope>, bool)> = Vec::new();
    while let Some(row) = rows.next()? {
        let step_id: String = row.get(0)?;
        let step_id: StepId =
            StepId::new(step_id).map_err(|_| OperationJournalError::row("step", "step_id"))?;
        let intent: Option<String> = row.get(1)?;
        let intent: Option<RequestEnvelope> = intent
            .map(|text| decode::<RequestEnvelope>("step", &text))
            .transpose()?;
        intents.push((step_id, intent, row.get(2)?));
    }
    Ok(intents)
}
