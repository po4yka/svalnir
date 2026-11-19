//! `history`: the operations of the journal and their observed outcomes.
//!
//! The view keeps apart, for each operation: the size estimates of its
//! plan, the entries that were moved to Trash, the entries that were
//! permanently removed, and the observed capacity change. The journal
//! records the target results and the resource observations of each
//! operation, for each executor. The estimates are in the plan document of
//! the client that prepared the plan, so a record of a plan with no
//! document in this state directory has none.

use serde::Serialize;
use svalnir_agent::journal::OperationJournal;
use svalnir_core::action::{Operation, OperationState, ResourceEffect, TriggerClass};
use svalnir_core::id::{OperationId, PlanId};
use svalnir_core::plan::{PlanMode, mode_of};
use svalnir_core::quantity::Bytes;
use svalnir_core::time::WallTime;

use super::operation_view::{EffectCounts, WorkView};
use super::plan_store::PlanDocument;
use super::plan_view;
use super::session::{self, journal_error};
use super::{CommandFailure, Invocation};
use crate::cli::HistoryArgs;
use crate::environment::Environment;
use crate::output::{ErrorBody, ExitStatus, Kind};
use crate::text::{escape, human_byte_delta, human_bytes, put_line};

/// The number of records when `--limit` is not given.
pub(crate) const DEFAULT_LIMIT: usize = 20;

/// The largest number of records of one query.
pub(crate) const MAX_LIMIT: usize = 200;

const HISTORY_NOTE: &str = "A size estimate is from the time of the plan and is not a result. A move to Trash is not reclaimed capacity. An observed capacity change includes other activity on the volume. The coordinator that executed an operation records its resource observations in the journal, so a record has them for an operation of the agent and for an operation of a client; an operation with no observation in the journal shows the value as not in this view. The journal is evidence for recovery; it is not an undo record.";

/// The size estimates of the plan of an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) struct EstimateView {
    pub(crate) targets: usize,
    /// `None` when a target has no estimate.
    pub(crate) estimated_logical_bytes: Option<Bytes>,
    /// `None` when a target has no estimate, and for a move to Trash.
    pub(crate) estimated_reclaimable_bytes: Option<Bytes>,
}

impl EstimateView {
    fn of(document: &PlanDocument) -> Self {
        let targets = &document.outcome.preview.targets;
        let sum = |value: fn(&svalnir_core::plan::SizeEstimate) -> Option<Bytes>| {
            targets.iter().try_fold(Bytes::ZERO, |total, target| {
                total.checked_add(value(&target.estimate)?)
            })
        };
        Self {
            targets: targets.len(),
            estimated_logical_bytes: sum(|estimate| estimate.logical_bytes),
            estimated_reclaimable_bytes: sum(|estimate| estimate.estimated_reclaimable_bytes),
        }
    }
}

/// One operation of the history.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct HistoryRecord {
    pub(crate) operation_id: OperationId,
    pub(crate) plan_id: PlanId,
    pub(crate) admitted_at: WallTime,
    pub(crate) trigger_class: TriggerClass,
    /// The mode of the plan, when the journal has the plan.
    pub(crate) mode: Option<PlanMode>,
    pub(crate) state: OperationState,
    /// False for `Admitted` and for `UnknownOutcome`.
    pub(crate) settled: bool,
    /// The observed result of each target, by effect.
    pub(crate) effects: EffectCounts,
    /// The estimates of the plan. Not a result.
    pub(crate) estimate: Option<EstimateView>,
    /// What the executor acted on, as it measured it.
    pub(crate) work: Option<WorkView>,
    /// The before and after observations, from the journal or from the
    /// plan document of this client. `None` when neither has a record.
    pub(crate) resource_effects: Option<Vec<ResourceEffect>>,
    /// The time at which a user acknowledged the `UnknownOutcome` result.
    /// The state stays `UnknownOutcome`.
    pub(crate) acknowledged_at: Option<WallTime>,
}

impl HistoryRecord {
    pub(crate) fn new(
        operation: &Operation,
        mode: Option<PlanMode>,
        document: Option<&PlanDocument>,
        recorded: Option<Vec<ResourceEffect>>,
    ) -> Self {
        let measurements = document
            .and_then(|document| document.measurements.as_ref())
            .filter(|measurements| &measurements.operation_id == operation.operation_id());
        Self {
            operation_id: operation.operation_id().clone(),
            plan_id: operation.plan_id().clone(),
            admitted_at: operation.admitted_at(),
            trigger_class: operation.trigger_class().clone(),
            mode,
            state: operation.state().clone(),
            settled: operation.state().is_settled(),
            effects: EffectCounts::of(&operation.target_results()),
            estimate: document.map(EstimateView::of),
            work: measurements.map(|measurements| measurements.work),
            resource_effects: recorded
                .or_else(|| measurements.map(|measurements| measurements.resource_effects.clone())),
            acknowledged_at: None,
        }
    }

    /// Reads the plan and the plan document of an operation.
    pub(crate) fn read(
        journal: &OperationJournal,
        environment: &Environment,
        operation: &Operation,
    ) -> Self {
        // A document is used only when it agrees with the stored plan.
        let stored = super::clean::load_for_report(journal, environment, operation.plan_id());
        Self {
            acknowledged_at: super::operation_view::acknowledged_at(
                journal,
                operation.operation_id(),
            ),
            ..Self::new(
                operation,
                stored.as_ref().and_then(|stored| mode_of(&stored.plan)),
                stored.as_ref().and_then(|stored| stored.document.as_ref()),
                super::operation_view::recorded_effects(journal, operation.operation_id()),
            )
        }
    }

    fn is_trash(&self) -> bool {
        self.mode == Some(PlanMode::Cleanup(svalnir_core::plan::CleanupMode::Trash))
    }

    pub(crate) fn render(&self, out: &mut String) {
        put_line!(
            out,
            "{}  {}  {}  {}",
            self.admitted_at,
            escape(self.state.as_str()),
            self.mode.as_ref().map_or_else(
                || "mode not known".to_owned(),
                |mode| plan_view::mode_text(*mode)
            ),
            self.operation_id
        );
        if let Some(at) = self.acknowledged_at {
            put_line!(out, "    Acknowledged: {at}; the outcome stays unknown");
        }
        put_line!(out, "    Observed results: {}", self.effects.summary());
        if let Some(estimate) = &self.estimate {
            put_line!(
                out,
                "    Estimate of the plan: {} targets, {} logical, {} reclaimable",
                estimate.targets,
                estimate
                    .estimated_logical_bytes
                    .map_or_else(|| "not known".to_owned(), |bytes| human_bytes(bytes.get())),
                estimate.estimated_reclaimable_bytes.map_or_else(
                    || {
                        if self.effects.moved_to_trash > 0 || self.is_trash() {
                            "none (a move to Trash)".to_owned()
                        } else {
                            "not known".to_owned()
                        }
                    },
                    |bytes| human_bytes(bytes.get())
                ),
            );
        }
        if let Some(work) = &self.work {
            put_line!(
                out,
                "    Permanently removed (estimate): {}{} entries, {} allocated   Moved to Trash: {} entries",
                if work.exact { "" } else { "at least " },
                work.removed_entries.get(),
                human_bytes(work.removed_allocated_bytes.get()),
                work.trashed_entries.get()
            );
        }
        match &self.resource_effects {
            None => out.push_str("    Observed capacity change: not in this view (no record, or a record that could not be read)\n"),
            Some(effects) => {
                for effect in effects {
                    if let ResourceEffect::Capacity(capacity) = effect {
                        put_line!(
                            out,
                            "    Observed capacity change: {}",
                            capacity.delta().map_or_else(
                                || "no value".to_owned(),
                                |delta| human_byte_delta(delta.get())
                            )
                        );
                    }
                }
            }
        }
    }
}

/// The result of `history`.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct HistoryView {
    /// `present` or `absent`.
    journal: &'static str,
    limit: usize,
    /// The newest operations, the newest first.
    records: Vec<HistoryRecord>,
    /// True when the journal can have more records than `limit`.
    possibly_more: bool,
    note: &'static str,
}

impl HistoryView {
    pub(crate) fn new(journal_present: bool, limit: usize, records: Vec<HistoryRecord>) -> Self {
        Self {
            journal: if journal_present { "present" } else { "absent" },
            possibly_more: records.len() >= limit,
            limit,
            records,
            note: HISTORY_NOTE,
        }
    }

    /// The records of the view.
    pub(crate) fn into_records(self) -> Vec<HistoryRecord> {
        self.records
    }

    pub(crate) fn render(&self) -> String {
        let mut out = String::new();
        if self.records.is_empty() {
            out.push_str("No operation is recorded.\n");
        }
        for record in &self.records {
            record.render(&mut out);
        }
        if self.possibly_more {
            put_line!(
                out,
                "The view has the newest {} operations; the journal can have more.",
                self.limit
            );
        }
        put_line!(out, "\n{}", self.note);
        out
    }
}

/// Reads the newest operations.
pub(crate) fn collect(environment: &Environment, limit: usize) -> Result<HistoryView, ErrorBody> {
    let Some(journal) = session::open_existing_journal(environment)? else {
        return Ok(HistoryView::new(false, limit, Vec::new()));
    };
    let records: Vec<HistoryRecord> = journal
        .recent_operations(limit)
        .map_err(|error| journal_error(&error))?
        .iter()
        .map(|operation| HistoryRecord::read(&journal, environment, operation))
        .collect();
    Ok(HistoryView::new(true, limit, records))
}

pub(crate) fn history(
    arguments: &HistoryArgs,
    invocation: &mut Invocation<'_>,
) -> Result<ExitStatus, CommandFailure> {
    let requested: usize = arguments.limit.map_or(DEFAULT_LIMIT, |limit| {
        usize::try_from(limit).unwrap_or(usize::MAX)
    });
    let limit: usize = requested.min(MAX_LIMIT);
    if requested > MAX_LIMIT {
        invocation.warnings.push(crate::output::Warning {
            code: "limit_reduced".into(),
            message: format!(
                "`--limit` is larger than {MAX_LIMIT}; the view has {MAX_LIMIT} records"
            ),
        });
    }
    let view: HistoryView = collect(invocation.environment, limit)?;
    invocation.emit(Kind::Report, &view, HistoryView::render)?;
    Ok(ExitStatus::Success)
}
