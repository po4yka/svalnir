//! The `Journal` interface over the database.

use rusqlite::{Connection, OptionalExtension, params};
use svalnir_core::action::{
    ActionError, Admission, DispatchConsumption, DispatchReceipt, DispatchState, Durability,
    Journal, JournalError, Operation, OperationState, Plan, PlanApproval, Principal,
    RequestEnvelope, Step, StepState,
};
use svalnir_core::digest::ContentDigest;
use svalnir_core::id::{OperationId, PlanId, StepId};

use super::error::{OperationJournalError, SequenceViolation};
use super::row::{self, OperationRow, StepRow};
use super::transition::{self, Boundary};
use super::volatile::VolatileOperationRecord;
use super::{
    CachedOperation, OperationJournal, check_admission_capacity, commit, coordination, decode,
    encode,
};

/// One `plan` row.
struct StoredPlan {
    digest: String,
    created_unix_s: i64,
    content: String,
}

/// One `plan_consumption` row.
struct Consumption {
    principal: String,
    operation_id: Option<String>,
    rejection: Option<String>,
    pruned: bool,
}

fn find_plan(
    connection: &Connection,
    plan_id: &PlanId,
) -> Result<Option<StoredPlan>, OperationJournalError> {
    Ok(connection
        .query_row(
            "SELECT digest, created_unix_s, content FROM plan WHERE plan_id = ?1",
            [plan_id.as_str()],
            |row| {
                Ok(StoredPlan {
                    digest: row.get(0)?,
                    created_unix_s: row.get(1)?,
                    content: row.get(2)?,
                })
            },
        )
        .optional()?)
}

fn find_consumption(
    connection: &Connection,
    plan_id: &PlanId,
) -> Result<Option<Consumption>, OperationJournalError> {
    Ok(connection
        .query_row(
            "SELECT principal, operation_id, rejection, pruned FROM plan_consumption \
             WHERE plan_id = ?1",
            [plan_id.as_str()],
            |row| {
                Ok(Consumption {
                    principal: row.get(0)?,
                    operation_id: row.get(1)?,
                    rejection: row.get(2)?,
                    pruned: row.get(3)?,
                })
            },
        )
        .optional()?)
}

fn insert_plan(connection: &Connection, plan: &Plan) -> Result<(), OperationJournalError> {
    connection.execute(
        "INSERT INTO plan (plan_id, digest, created_unix_s, content) VALUES (?1, ?2, ?3, ?4)",
        params![
            plan.plan_id.as_str(),
            plan.digest().as_str(),
            plan.validity.created_wall.unix_seconds(),
            encode(plan)?,
        ],
    )?;
    Ok(())
}

/// Inserts the consumption of a plan: its operation, or its rejection.
fn insert_consumption(
    connection: &Connection,
    plan_id: &PlanId,
    digest: &str,
    principal: &Principal,
    operation_id: Option<&OperationId>,
    rejection: Option<&ActionError>,
    consumed_unix_s: i64,
) -> Result<(), OperationJournalError> {
    connection.execute(
        "INSERT INTO plan_consumption \
         (plan_id, digest, principal, operation_id, rejection, consumed_unix_s) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            plan_id.as_str(),
            digest,
            encode(principal)?,
            operation_id.map(OperationId::as_str),
            rejection.map(encode).transpose()?,
            consumed_unix_s,
        ],
    )?;
    Ok(())
}

/// The result of the earlier apply that `consumption` records.
fn earlier_admission(
    connection: &Connection,
    consumption: &Consumption,
    principal: &Principal,
) -> Result<Admission, OperationJournalError> {
    if consumption.pruned {
        return Err(OperationJournalError::Expired);
    }
    let consumer: Principal = decode("plan_consumption", &consumption.principal)?;
    if &consumer != principal {
        return Err(OperationJournalError::Conflict);
    }
    if let Some(rejection) = &consumption.rejection {
        return Ok(Admission::Rejected {
            error: decode("plan_consumption", rejection)?,
        });
    }
    let missing = || OperationJournalError::row("plan_consumption", "operation_id");
    let operation_id: OperationId = consumption
        .operation_id
        .as_deref()
        .and_then(|text| OperationId::new(text).ok())
        .ok_or_else(missing)?;
    let stored: OperationRow =
        row::find_operation(connection, &operation_id)?.ok_or_else(missing)?;
    Ok(Admission::Existing {
        operation: Box::new(row::load_operation(connection, stored.seq)?),
    })
}

/// Checks that `operation` is the new durable admission of `plan`: the
/// steps of the plan, each one `Admitted` with no call and no result.
fn check_new_admission(plan: &Plan, operation: &Operation) -> Result<(), OperationJournalError> {
    let same_steps: bool = operation.steps().len() == plan.steps.len()
        && operation
            .steps()
            .iter()
            .zip(&plan.steps)
            .all(|(step, planned)| {
                step.step_id() == &planned.step_id
                    && step.action_class() == &planned.action_class
                    && step.target_id() == &planned.target_id
            });
    if !same_steps || operation.trigger_class() != &plan.trigger.class {
        return Err(OperationJournalError::Conflict);
    }
    let is_new = |step: &Step| {
        matches!(step.progress().state(), StepState::Admitted)
            && matches!(step.progress().dispatch(), DispatchState::NotSubmitted)
            && matches!(step.progress().durability(), Durability::Durable)
            && step.results().is_empty()
    };
    if matches!(operation.state(), OperationState::Admitted)
        && matches!(operation.durability(), Durability::Durable)
        && operation.steps().iter().all(is_new)
    {
        Ok(())
    } else {
        Err(SequenceViolation::NotNewAdmission.into())
    }
}

impl OperationJournal {
    /// Runs one change of the operation `operation_id` in one transaction.
    ///
    /// `apply` changes the operation with the functions of `svalnir-core`
    /// and returns the identities of the steps that it changed. It can also
    /// write the other columns of a step row. This function writes the
    /// changed step records, the state of the operation, and the new
    /// revision.
    fn mutate<T>(
        &mut self,
        operation_id: &OperationId,
        apply: impl FnOnce(
            &Connection,
            &OperationRow,
            &mut Operation,
        ) -> Result<(T, Vec<StepId>), OperationJournalError>,
    ) -> Result<T, OperationJournalError> {
        let Self {
            connection,
            cache,
            commit_fault,
            ..
        } = self;
        // The cache stays empty when this call fails.
        let cached: Option<CachedOperation> = cache.take();
        let transaction = Self::write_transaction(connection)?;
        let stored: OperationRow = row::find_operation(&transaction, operation_id)?
            .ok_or(OperationJournalError::NotFound)?;
        let mut operation: Operation = match cached {
            Some(cached) if cached.seq == stored.seq && cached.revision == stored.revision => {
                cached.operation
            }
            _ => row::load_operation(&transaction, stored.seq)?,
        };
        let state_before: OperationState = operation.state().clone();
        let (value, changed) = apply(&transaction, &stored, &mut operation)?;
        let state_changed: bool = &state_before != operation.state();
        let mut revision: i64 = stored.revision;
        if state_changed || !changed.is_empty() {
            revision = revision
                .checked_add(1)
                .ok_or(OperationJournalError::row("operation", "revision"))?;
            for step_id in &changed {
                let step: &Step = operation
                    .step(step_id)
                    .ok_or(OperationJournalError::NotFound)?;
                row::write_step(&transaction, stored.seq, step)?;
            }
            if state_changed {
                row::write_operation(&transaction, stored.seq, &operation, revision)?;
            } else {
                row::write_revision(&transaction, stored.seq, revision)?;
            }
        }
        commit(transaction, commit_fault)?;
        *cache = Some(CachedOperation {
            seq: stored.seq,
            revision,
            operation,
        });
        Ok(value)
    }

    /// [`Journal::record_plan`] with the detailed failure.
    ///
    /// # Errors
    ///
    /// Returns the failure that [`Journal::record_plan`] reports as a
    /// [`JournalError`], with its cause.
    pub fn try_record_plan(&mut self, plan: &Plan) -> Result<(), OperationJournalError> {
        let Self {
            connection,
            path,
            limits,
            commit_fault,
            ..
        } = self;
        let transaction = Self::write_transaction(connection)?;
        if let Some(stored) = find_plan(&transaction, &plan.plan_id)? {
            return if stored.digest == plan.digest().as_str() {
                Ok(())
            } else {
                Err(OperationJournalError::Conflict)
            };
        }
        // A consumption with no plan is the record of a pruned plan.
        if find_consumption(&transaction, &plan.plan_id)?.is_some() {
            return Err(OperationJournalError::Expired);
        }
        check_admission_capacity(&transaction, path, limits)?;
        insert_plan(&transaction, plan)?;
        commit(transaction, commit_fault)
    }

    /// [`Journal::plan`] with the detailed failure.
    ///
    /// # Errors
    ///
    /// Returns the failure that [`Journal::plan`] reports as a
    /// [`JournalError`], with its cause.
    pub fn try_plan(&self, plan_id: &PlanId) -> Result<Option<Plan>, OperationJournalError> {
        let Some(stored) = find_plan(&self.connection, plan_id)? else {
            return Ok(None);
        };
        let plan: Plan = decode("plan", &stored.content)?;
        if &plan.plan_id == plan_id && plan.digest().as_str() == stored.digest {
            Ok(Some(plan))
        } else {
            Err(OperationJournalError::row("plan", "content"))
        }
    }

    /// [`Journal::admit`] with the detailed failure.
    ///
    /// # Errors
    ///
    /// Returns the failure that [`Journal::admit`] reports as a
    /// [`JournalError`], with its cause.
    pub fn try_admit(
        &mut self,
        approval: &PlanApproval,
        principal: &Principal,
        operation: &Operation,
    ) -> Result<Admission, OperationJournalError> {
        let Self {
            connection,
            path,
            limits,
            commit_fault,
            ..
        } = self;
        let transaction = Self::write_transaction(connection)?;
        let consumption: Option<Consumption> = find_consumption(&transaction, &approval.plan_id)?;
        let Some(stored) = find_plan(&transaction, &approval.plan_id)? else {
            return Err(if consumption.is_some() {
                OperationJournalError::Expired
            } else {
                OperationJournalError::NotFound
            });
        };
        if stored.digest != approval.digest.as_str()
            || operation.plan_id() != &approval.plan_id
            || operation.plan_digest() != &approval.digest
        {
            return Err(OperationJournalError::Conflict);
        }
        if let Some(consumption) = consumption {
            return earlier_admission(&transaction, &consumption, principal);
        }
        if row::find_operation(&transaction, operation.operation_id())?.is_some() {
            return Err(OperationJournalError::Conflict);
        }
        let plan: Plan = decode("plan", &stored.content)?;
        check_new_admission(&plan, operation)?;
        coordination::check_work_gate(&transaction, operation.executor_epoch())?;
        check_admission_capacity(&transaction, path, limits)?;
        row::insert_operation(&transaction, operation, plan.trigger.incident_id.as_ref())?;
        insert_consumption(
            &transaction,
            &approval.plan_id,
            &stored.digest,
            principal,
            Some(operation.operation_id()),
            None,
            operation.admitted_at().unix_seconds(),
        )?;
        commit(transaction, commit_fault)?;
        Ok(Admission::Admitted)
    }

    /// [`Journal::record_rejection`] with the detailed failure.
    ///
    /// # Errors
    ///
    /// Returns the failure that [`Journal::record_rejection`] reports as a
    /// [`JournalError`], with its cause.
    pub fn try_record_rejection(
        &mut self,
        approval: &PlanApproval,
        principal: &Principal,
        error: &ActionError,
    ) -> Result<(), OperationJournalError> {
        let Self {
            connection,
            path,
            limits,
            commit_fault,
            ..
        } = self;
        let transaction = Self::write_transaction(connection)?;
        let consumption: Option<Consumption> = find_consumption(&transaction, &approval.plan_id)?;
        let Some(stored) = find_plan(&transaction, &approval.plan_id)? else {
            return Err(if consumption.is_some() {
                OperationJournalError::Expired
            } else {
                OperationJournalError::NotFound
            });
        };
        if stored.digest != approval.digest.as_str() {
            return Err(OperationJournalError::Conflict);
        }
        if let Some(consumption) = consumption {
            // The first rejection stays. A repeated apply returns it.
            return match earlier_admission(&transaction, &consumption, principal)? {
                Admission::Rejected { .. } => Ok(()),
                Admission::Admitted | Admission::Existing { .. } => {
                    Err(OperationJournalError::Conflict)
                }
            };
        }
        check_admission_capacity(&transaction, path, limits)?;
        insert_consumption(
            &transaction,
            &approval.plan_id,
            &stored.digest,
            principal,
            None,
            Some(error),
            stored.created_unix_s,
        )?;
        commit(transaction, commit_fault)
    }

    /// [`Journal::commit_intent`] with the detailed failure.
    ///
    /// # Errors
    ///
    /// Returns the failure that [`Journal::commit_intent`] reports as a
    /// [`JournalError`], with its cause.
    pub fn try_commit_intent(
        &mut self,
        envelope: &RequestEnvelope,
    ) -> Result<(), OperationJournalError> {
        let correlation = &envelope.correlation;
        let intent: String = encode(envelope)?;
        let digest: ContentDigest =
            ContentDigest::of_json(envelope).map_err(OperationJournalError::Encode)?;
        self.mutate(
            &correlation.operation_id,
            |connection, stored, operation| {
                let step: &Step = operation
                    .step(&correlation.step_id)
                    .ok_or(OperationJournalError::NotFound)?;
                let agrees: bool = operation.plan_id() == &correlation.plan_id
                    && operation.plan_digest() == &correlation.plan_digest
                    && operation.executor_epoch() == &envelope.evidence.executor_epoch
                    && operation.trigger_class() == &envelope.trigger.class
                    && step.action_class() == &envelope.action_class
                    && step.target_id() == &envelope.target.target_id;
                if !agrees {
                    return Err(OperationJournalError::Conflict);
                }
                let recorded: StepRow =
                    row::step_row(connection, stored.seq, &correlation.step_id)?;
                if let Some(recorded) = recorded.intent_digest {
                    return if recorded == digest.as_str() {
                        Ok(((), Vec::new()))
                    } else {
                        Err(OperationJournalError::Conflict)
                    };
                }
                operation
                    .advance_step(
                        &correlation.step_id,
                        StepState::IntentCommitted,
                        DispatchState::NotSubmitted,
                        Durability::Durable,
                    )
                    .map_err(SequenceViolation::Transition)?;
                row::write_intent(
                    connection,
                    stored.seq,
                    &correlation.step_id,
                    &intent,
                    digest.as_str(),
                )?;
                Ok(((), vec![correlation.step_id.clone()]))
            },
        )
    }

    /// [`Journal::consume_dispatch`] with the detailed failure. The result has no durability: a
    /// consumption of this journal is durable.
    ///
    /// # Errors
    ///
    /// Returns the failure that [`Journal::consume_dispatch`] reports as a
    /// [`JournalError`], with its cause.
    pub fn try_consume_dispatch(
        &mut self,
        operation_id: &OperationId,
        step_id: &StepId,
    ) -> Result<DispatchConsumption, OperationJournalError> {
        self.mutate(operation_id, |connection, stored, operation| {
            let recorded: StepRow = row::step_row(connection, stored.seq, step_id)?;
            if recorded.dispatch_consumed {
                return Ok((DispatchConsumption::AlreadyConsumed, Vec::new()));
            }
            if recorded.intent_digest.is_none() {
                return Err(SequenceViolation::NoIntent.into());
            }
            if stored.stop_fence {
                return Ok((DispatchConsumption::Fenced, Vec::new()));
            }
            coordination::check_work_gate(connection, operation.executor_epoch())?;
            operation
                .advance_step(
                    step_id,
                    StepState::DispatchConsumed,
                    DispatchState::NotSubmitted,
                    Durability::Durable,
                )
                .map_err(SequenceViolation::Transition)?;
            row::write_dispatch_consumed(connection, stored.seq, step_id)?;
            Ok((DispatchConsumption::Consumed, vec![step_id.clone()]))
        })
    }

    /// [`Journal::record_step`] with the detailed failure.
    ///
    /// # Errors
    ///
    /// Returns the failure that [`Journal::record_step`] reports as a
    /// [`JournalError`], with its cause.
    pub fn try_record_step(
        &mut self,
        operation_id: &OperationId,
        step: &Step,
    ) -> Result<(), OperationJournalError> {
        self.mutate(operation_id, |_, _, operation| {
            let changed: bool = transition::apply_step(operation, step, Boundary::Refused)?;
            let changed: Vec<StepId> = if changed {
                vec![step.step_id().clone()]
            } else {
                Vec::new()
            };
            Ok(((), changed))
        })
    }

    /// [`Journal::record_operation`] with the detailed failure.
    ///
    /// # Errors
    ///
    /// Returns the failure that [`Journal::record_operation`] reports as a
    /// [`JournalError`], with its cause.
    pub fn try_record_operation(
        &mut self,
        operation: &Operation,
    ) -> Result<(), OperationJournalError> {
        self.mutate(operation.operation_id(), |_, _, stored| {
            let changed: Vec<StepId> =
                transition::apply_operation(stored, operation, Boundary::Refused)?;
            Ok(((), changed))
        })
    }

    /// [`Journal::operation`] with the detailed failure.
    ///
    /// # Errors
    ///
    /// Returns the failure that [`Journal::operation`] reports as a
    /// [`JournalError`], with its cause.
    pub fn try_operation(
        &self,
        operation_id: &OperationId,
    ) -> Result<Option<Operation>, OperationJournalError> {
        let transaction = self.read_transaction()?;
        let Some(stored) = row::find_operation(&transaction, operation_id)? else {
            return Ok(None);
        };
        Ok(Some(row::load_operation(&transaction, stored.seq)?))
    }

    /// [`Journal::unsettled_operations`] with the detailed failure.
    ///
    /// # Errors
    ///
    /// Returns the failure that [`Journal::unsettled_operations`] reports as a
    /// [`JournalError`], with its cause.
    pub fn try_unsettled_operations(
        &self,
        limit: usize,
    ) -> Result<Vec<Operation>, OperationJournalError> {
        let transaction = self.read_transaction()?;
        let mut operations: Vec<Operation> = Vec::new();
        for seq in unsettled_rows(&transaction, limit)? {
            operations.push(row::load_operation(&transaction, seq)?);
        }
        Ok(operations)
    }

    /// [`Journal::set_stop_fence`] with the detailed failure.
    ///
    /// # Errors
    ///
    /// Returns the failure that [`Journal::set_stop_fence`] reports as a
    /// [`JournalError`], with its cause.
    pub fn try_set_stop_fence(
        &mut self,
        operation_id: &OperationId,
    ) -> Result<(), OperationJournalError> {
        let Self {
            connection,
            commit_fault,
            ..
        } = self;
        let transaction = Self::write_transaction(connection)?;
        let changed: usize = transaction.execute(
            "UPDATE operation SET stop_fence = 1 WHERE operation_id = ?1",
            [operation_id.as_str()],
        )?;
        if changed != 1 {
            return Err(OperationJournalError::NotFound);
        }
        commit(transaction, commit_fault)
    }

    /// [`Journal::has_stop_fence`] with the detailed failure.
    ///
    /// # Errors
    ///
    /// Returns the failure that [`Journal::has_stop_fence`] reports as a
    /// [`JournalError`], with its cause.
    pub fn try_has_stop_fence(
        &self,
        operation_id: &OperationId,
    ) -> Result<bool, OperationJournalError> {
        row::find_operation(&self.connection, operation_id)?
            .map(|stored| stored.stop_fence)
            .ok_or(OperationJournalError::NotFound)
    }

    /// Writes one operation of the critical-memory exception, with its
    /// plan, its intents, and its dispatch consumptions, after the durable
    /// journal is available again. The records keep the durability
    /// `volatile`.
    ///
    /// A record that the journal has already is brought to the given
    /// state. The call is thus safe to repeat while the operation runs.
    ///
    /// The call is not new work: the admission stop and the coordinator
    /// gate do not apply to it. It records what was done.
    ///
    /// Returns whether the journal has a durable stop fence for the
    /// operation. The caller then stops the operation in its volatile
    /// record also.
    ///
    /// The plan of a volatile operation is not consumed in this journal
    /// before this call. Write each pending volatile record before a
    /// durable admission, so that a repeated apply of the plan finds the
    /// consumption.
    ///
    /// # Errors
    ///
    /// Returns [`OperationJournalError::Sequence`] when the operation is
    /// not a volatile admission or when the journal has a later state of
    /// it, [`OperationJournalError::Conflict`] when the record does not
    /// agree with itself or with a stored plan, operation, or intent,
    /// [`OperationJournalError::Expired`] when the plan was pruned, or a
    /// storage error. On an error nothing was written.
    pub fn persist_volatile(
        &mut self,
        record: &VolatileOperationRecord,
    ) -> Result<bool, OperationJournalError> {
        record.check()?;
        let Self {
            connection,
            cache,
            commit_fault,
            ..
        } = self;
        *cache = None;
        let transaction = Self::write_transaction(connection)?;
        let plan: &Plan = &record.plan;
        let operation: &Operation = &record.operation;
        let consumption: Option<Consumption> = find_consumption(&transaction, &plan.plan_id)?;
        match find_plan(&transaction, &plan.plan_id)? {
            Some(stored) if stored.digest == plan.digest().as_str() => {}
            Some(_) => return Err(OperationJournalError::Conflict),
            None if consumption.is_some() => return Err(OperationJournalError::Expired),
            None => insert_plan(&transaction, plan)?,
        }
        let existing: Option<OperationRow> =
            row::find_operation(&transaction, operation.operation_id())?;
        let stop_fence: bool = existing.is_some_and(|stored| stored.stop_fence);
        let seq: i64 = match existing {
            None => {
                if consumption.is_some() {
                    return Err(OperationJournalError::Conflict);
                }
                insert_consumption(
                    &transaction,
                    &plan.plan_id,
                    plan.digest().as_str(),
                    &record.principal,
                    Some(operation.operation_id()),
                    None,
                    operation.admitted_at().unix_seconds(),
                )?;
                row::insert_operation(&transaction, operation, plan.trigger.incident_id.as_ref())?
            }
            Some(stored) => {
                // The stored consumption is the consumption of this
                // operation by this principal.
                let consumer: Option<Principal> = consumption
                    .as_ref()
                    .filter(|consumption| {
                        consumption.operation_id.as_deref()
                            == Some(operation.operation_id().as_str())
                    })
                    .map(|consumption| decode("plan_consumption", &consumption.principal))
                    .transpose()?;
                if consumer.as_ref() != Some(&record.principal) {
                    return Err(OperationJournalError::Conflict);
                }
                let mut current: Operation = row::load_operation(&transaction, stored.seq)?;
                let changed: Vec<StepId> =
                    transition::apply_operation(&mut current, operation, Boundary::Permitted)?;
                for step_id in &changed {
                    let step: &Step = current
                        .step(step_id)
                        .ok_or(OperationJournalError::NotFound)?;
                    row::write_step(&transaction, stored.seq, step)?;
                }
                let revision: i64 = stored
                    .revision
                    .checked_add(1)
                    .ok_or(OperationJournalError::row("operation", "revision"))?;
                row::write_operation(&transaction, stored.seq, &current, revision)?;
                stored.seq
            }
        };
        for intent in &record.intents {
            let step_id: &StepId = &intent.correlation.step_id;
            let digest: ContentDigest =
                ContentDigest::of_json(intent).map_err(OperationJournalError::Encode)?;
            match row::step_row(&transaction, seq, step_id)?.intent_digest {
                Some(recorded) if recorded == digest.as_str() => {}
                Some(_) => return Err(OperationJournalError::Conflict),
                None => {
                    row::write_intent(
                        &transaction,
                        seq,
                        step_id,
                        &encode(intent)?,
                        digest.as_str(),
                    )?;
                    row::write_dispatch_consumed(&transaction, seq, step_id)?;
                }
            }
        }
        commit(transaction, commit_fault)?;
        Ok(stop_fence)
    }
}

/// The row identities of the operations that are not settled, the oldest
/// first, to a maximum of `limit`.
pub(super) fn unsettled_rows(
    connection: &Connection,
    limit: usize,
) -> Result<Vec<i64>, OperationJournalError> {
    let limit: i64 = i64::try_from(limit).unwrap_or(i64::MAX);
    let mut statement =
        connection.prepare("SELECT seq FROM operation WHERE settled = 0 ORDER BY seq LIMIT ?1")?;
    let rows = statement.query_map([limit], |row| row.get(0))?;
    let mut sequence: Vec<i64> = Vec::new();
    for seq in rows {
        sequence.push(seq?);
    }
    Ok(sequence)
}

/// Reports a failed call and gives the value of the `Journal` interface.
/// The report has the error only: it has no path, no process argument, and
/// no record content.
fn report(error: &OperationJournalError) -> JournalError {
    if error.is_storage_failure() {
        tracing::warn!(error = %error, "an operation-journal call failed; nothing was recorded");
    }
    error.to_journal_error()
}

impl Journal for OperationJournal {
    fn record_plan(&mut self, plan: &Plan) -> Result<(), JournalError> {
        self.try_record_plan(plan).map_err(|error| report(&error))
    }

    fn plan(&self, plan_id: &PlanId) -> Result<Option<Plan>, JournalError> {
        self.try_plan(plan_id).map_err(|error| report(&error))
    }

    fn admit(
        &mut self,
        approval: &PlanApproval,
        principal: &Principal,
        operation: &Operation,
    ) -> Result<Admission, JournalError> {
        self.try_admit(approval, principal, operation)
            .map_err(|error| report(&error))
    }

    fn record_rejection(
        &mut self,
        approval: &PlanApproval,
        principal: &Principal,
        error: &ActionError,
    ) -> Result<(), JournalError> {
        self.try_record_rejection(approval, principal, error)
            .map_err(|error| report(&error))
    }

    fn commit_intent(&mut self, envelope: &RequestEnvelope) -> Result<(), JournalError> {
        self.try_commit_intent(envelope)
            .map_err(|error| report(&error))
    }

    fn consume_dispatch(
        &mut self,
        operation_id: &OperationId,
        step_id: &StepId,
    ) -> Result<DispatchReceipt, JournalError> {
        self.try_consume_dispatch(operation_id, step_id)
            .map(|consumption| DispatchReceipt {
                consumption,
                durability: Durability::Durable,
            })
            .map_err(|error| report(&error))
    }

    fn record_step(&mut self, operation_id: &OperationId, step: &Step) -> Result<(), JournalError> {
        self.try_record_step(operation_id, step)
            .map_err(|error| report(&error))
    }

    fn record_operation(&mut self, operation: &Operation) -> Result<(), JournalError> {
        self.try_record_operation(operation)
            .map_err(|error| report(&error))
    }

    fn operation(&self, operation_id: &OperationId) -> Result<Option<Operation>, JournalError> {
        self.try_operation(operation_id)
            .map_err(|error| report(&error))
    }

    fn unsettled_operations(&self, limit: usize) -> Result<Vec<Operation>, JournalError> {
        self.try_unsettled_operations(limit)
            .map_err(|error| report(&error))
    }

    fn set_stop_fence(&mut self, operation_id: &OperationId) -> Result<(), JournalError> {
        self.try_set_stop_fence(operation_id)
            .map_err(|error| report(&error))
    }

    fn has_stop_fence(&self, operation_id: &OperationId) -> Result<bool, JournalError> {
        self.try_has_stop_fence(operation_id)
            .map_err(|error| report(&error))
    }
}
