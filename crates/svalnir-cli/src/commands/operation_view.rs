//! The view of one operation, for `clean apply`, `processes stop`,
//! `operations show`, `operations wait`, and `history`.
//!
//! The view keeps four quantities apart (`docs/ACTION_CONTRACTS.md`
//! section 9): the entries that were moved to Trash, the entries that were
//! permanently removed, the size estimates of the plan, and the observed
//! capacity change of a volume. A move to Trash is never reported as
//! reclaimed capacity, and an observed capacity change is never reported
//! as the reclaimed size.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use svalnir_agent::coordinator::{OperationView, Phase, WorkTotals};
use svalnir_agent::journal::OperationJournal;
use svalnir_core::action::{
    DispatchState, Durability, Operation, OperationState, ResourceEffect, TargetEffect,
    TargetResult, TriggerClass,
};
use svalnir_core::file::LosslessPath;
use svalnir_core::id::{ExecutorEpochId, OperationId, PlanId, TargetId};
use svalnir_core::quantity::{Bytes, EntryCount};
use svalnir_core::time::WallTime;

use crate::output::ExitStatus;
use crate::text::{escape, human_byte_delta, human_bytes, put_line};

/// The largest number of target lines in the text form.
const TEXT_TARGET_LIMIT: usize = 40;

/// The statement about a move to Trash.
pub(crate) const TRASH_NOTE: &str = "An entry that was moved to Trash still uses its storage. A move to Trash is not reclaimed capacity.";

/// The statement about an observed capacity change.
pub(crate) const CAPACITY_NOTE: &str = "The observed capacity change is the available capacity of the volume after the operation minus the value before it. Other activity on the volume contributes to it, so it is not the reclaimed size.";

/// The statement about a view that has no measurement.
const NO_MEASUREMENT_NOTE: &str = "This view has no resource observation for the operation: the journal has no record of one, or the record could not be read. A value that is not in the view is not a measurement of no change.";

/// The statement about a record that the durable journal does not have.
const DEGRADED_NOTE: &str = "A record of this operation is not in the durable journal. The state is that of the executing process; a restart reconciles the operation from fresh evidence.";

/// The number of target records with each effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
pub(crate) struct EffectCounts {
    /// Entries that were moved to Trash. Not reclaimed capacity.
    pub(crate) moved_to_trash: u64,
    /// Entries whose name is absent after a removal call. Each one has the
    /// attribution `possible`: macOS has no conditional unlink, so the
    /// call can have removed a replacement of the planned object.
    pub(crate) permanently_removed: u64,
    /// Processes whose exit was observed after the request.
    pub(crate) exit_verified: u64,
    pub(crate) already_absent: u64,
    pub(crate) already_exited: u64,
    pub(crate) skipped: u64,
    pub(crate) refused: u64,
    pub(crate) still_running: u64,
    /// Records whose effect is not known, or not recognized by this build.
    pub(crate) unknown_outcome: u64,
}

impl EffectCounts {
    pub(crate) fn of(results: &[TargetResult]) -> Self {
        let mut counts = Self::default();
        for result in results {
            let slot: &mut u64 = match &result.effect {
                TargetEffect::Trashed => &mut counts.moved_to_trash,
                TargetEffect::Removed => &mut counts.permanently_removed,
                TargetEffect::ExitVerified => &mut counts.exit_verified,
                TargetEffect::AlreadyAbsent => &mut counts.already_absent,
                TargetEffect::AlreadyExited => &mut counts.already_exited,
                TargetEffect::Skipped => &mut counts.skipped,
                TargetEffect::Refused => &mut counts.refused,
                TargetEffect::StillRunning => &mut counts.still_running,
                // A value that this build does not recognize is never read
                // as a known result.
                _ => &mut counts.unknown_outcome,
            };
            *slot = slot.saturating_add(1);
        }
        counts
    }

    /// One line for the text form, with only the effects that occurred.
    pub(crate) fn summary(&self) -> String {
        let parts: Vec<String> = [
            (self.permanently_removed, "permanently removed"),
            (self.moved_to_trash, "moved to Trash"),
            (self.exit_verified, "exit observed"),
            (self.already_absent, "already absent"),
            (self.already_exited, "already exited"),
            (self.skipped, "skipped"),
            (self.refused, "refused"),
            (self.still_running, "still running"),
            (self.unknown_outcome, "unknown outcome"),
        ]
        .iter()
        .filter(|(count, _)| *count > 0)
        .map(|(count, name)| format!("{count} {name}"))
        .collect();
        if parts.is_empty() {
            "no target record".to_owned()
        } else {
            parts.join(", ")
        }
    }
}

/// What the executor acted on, as it measured it. These values are not
/// reclaimed capacity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct WorkView {
    pub(crate) removed_entries: EntryCount,
    pub(crate) removed_logical_bytes: Bytes,
    pub(crate) removed_allocated_bytes: Bytes,
    pub(crate) trashed_entries: EntryCount,
    /// False when a count is a lower bound. Each count is an estimate:
    /// macOS has no conditional unlink, so each removal has the
    /// attribution `possible`.
    pub(crate) exact: bool,
}

impl From<WorkTotals> for WorkView {
    fn from(work: WorkTotals) -> Self {
        Self {
            removed_entries: work.removed_entries,
            removed_logical_bytes: work.removed_logical_bytes,
            removed_allocated_bytes: work.removed_allocated_bytes,
            trashed_entries: work.trashed_entries,
            exact: work.exact,
        }
    }
}

/// The measurements of an operation that its executor has. The client
/// that executed the operation keeps them in the plan document. The journal
/// has the resource observations for each client, and not the work totals.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Measurements {
    pub(crate) operation_id: OperationId,
    pub(crate) work: WorkView,
    /// The before and after observations.
    pub(crate) resource_effects: Vec<ResourceEffect>,
}

/// The stop request of an operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct StopFenceView {
    /// True when the journal has a stop fence for the operation: the
    /// executor dispatches no further step.
    pub(crate) durable_stop_fence: bool,
}

/// One operation.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct OperationReport {
    pub(crate) operation_id: OperationId,
    pub(crate) plan_id: PlanId,
    /// The state. `Admitted` is not a final result.
    pub(crate) state: OperationState,
    /// True for `Completed`, `Partial`, `Incomplete`, `NoAction`, and
    /// `Failed`. `UnknownOutcome` is not settled: it needs reconciliation.
    pub(crate) settled: bool,
    pub(crate) dispatch: DispatchState,
    pub(crate) durability: Durability,
    pub(crate) trigger_class: TriggerClass,
    pub(crate) admitted_at: WallTime,
    pub(crate) executor_epoch: ExecutorEpochId,
    /// `waiting`, `running`, `observing`, or `finished`, when the process
    /// that executes the operation gave the view.
    pub(crate) phase: Option<&'static str>,
    pub(crate) stop: Option<StopFenceView>,
    pub(crate) effects: EffectCounts,
    pub(crate) target_results: Vec<TargetResult>,
    /// The display path of each file target: the root path and the
    /// relative entry that the sealed plan binds. A display path is not
    /// evidence.
    pub(crate) target_paths: BTreeMap<TargetId, LosslessPath>,
    /// What the executor acted on. `None` when this client has no record.
    pub(crate) work: Option<WorkView>,
    /// The before and after observations, from the process that executes
    /// the operation, from the journal, or from the plan document of this
    /// client. `None` when none of them has a record; an empty list when
    /// the executor measured nothing.
    pub(crate) resource_effects: Option<Vec<ResourceEffect>>,
    /// True when a record of the operation is not in the durable journal.
    pub(crate) degraded_recording: Option<bool>,
    /// The time at which a user acknowledged the `UnknownOutcome` result
    /// (`operations acknowledge`). The acknowledgment released the leases
    /// of the operation and did not change its result.
    pub(crate) acknowledged_at: Option<WallTime>,
    pub(crate) notes: Vec<&'static str>,
}

/// The time of the acknowledgment that the journal has for an operation.
/// `None` when it has none, or when the record cannot be read.
pub(crate) fn acknowledged_at(
    journal: &OperationJournal,
    operation_id: &OperationId,
) -> Option<WallTime> {
    journal
        .acknowledgment(operation_id)
        .ok()
        .flatten()
        .map(|acknowledgment| acknowledgment.acknowledged_at)
}

/// The resource observations that the journal has for an operation.
/// `None` when the journal has no record, or when the record cannot be
/// read: an observation that is not recorded is not an empty measurement.
pub(crate) fn recorded_effects(
    journal: &OperationJournal,
    operation_id: &OperationId,
) -> Option<Vec<ResourceEffect>> {
    journal
        .resource_effects(operation_id)
        .ok()
        .filter(|effects| !effects.is_empty())
}

fn phase_text(phase: Phase) -> &'static str {
    match phase {
        Phase::Waiting => "waiting",
        Phase::Running => "running",
        Phase::Observing { .. } => "observing",
        Phase::Finished => "finished",
    }
}

impl OperationReport {
    /// The view of a journal record.
    pub(crate) fn of_record(operation: &Operation, stop_fence: Option<bool>) -> Self {
        let results: Vec<TargetResult> = operation.target_results();
        Self {
            operation_id: operation.operation_id().clone(),
            plan_id: operation.plan_id().clone(),
            state: operation.state().clone(),
            settled: operation.state().is_settled(),
            dispatch: operation.dispatch(),
            durability: operation.durability(),
            trigger_class: operation.trigger_class().clone(),
            admitted_at: operation.admitted_at(),
            executor_epoch: operation.executor_epoch().clone(),
            phase: None,
            stop: stop_fence.map(|durable_stop_fence| StopFenceView { durable_stop_fence }),
            effects: EffectCounts::of(&results),
            target_results: results,
            target_paths: BTreeMap::new(),
            work: None,
            resource_effects: None,
            degraded_recording: None,
            acknowledged_at: None,
            notes: Vec::new(),
        }
        .with_notes()
    }

    /// The view of the process that executes the operation.
    pub(crate) fn of_view(view: &OperationView) -> Self {
        let mut report = Self::of_record(&view.operation, None);
        report.phase = Some(phase_text(view.phase));
        report.work = Some(view.work.into());
        report.resource_effects = Some(view.resource_effects.clone());
        report.degraded_recording = Some(view.degraded_recording);
        report.with_notes()
    }

    /// Adds the resource observations that the journal has for the
    /// operation. Each client reads them, also a client that did not
    /// execute the operation. A journal with no record, or a record that
    /// cannot be read, adds nothing: the view then says that no
    /// observation is recorded.
    #[must_use]
    pub(crate) fn with_recorded_effects(mut self, journal: &OperationJournal) -> Self {
        if self.resource_effects.is_none() {
            self.resource_effects = recorded_effects(journal, &self.operation_id);
        }
        self.acknowledged_at = acknowledged_at(journal, &self.operation_id);
        self.with_notes()
    }

    /// Adds the measurements that the plan document has, where the view
    /// has none.
    #[must_use]
    pub(crate) fn with_measurements(mut self, measurements: Option<&Measurements>) -> Self {
        if let Some(measurements) = measurements
            && measurements.operation_id == self.operation_id
        {
            if self.work.is_none() {
                self.work = Some(measurements.work);
            }
            if self.resource_effects.is_none() {
                self.resource_effects = Some(measurements.resource_effects.clone());
            }
        }
        self.with_notes()
    }

    /// Adds the display paths of the plan document.
    #[must_use]
    pub(crate) fn with_paths(mut self, paths: BTreeMap<TargetId, LosslessPath>) -> Self {
        self.target_paths = paths;
        self
    }

    /// The measurements of this view, for the plan document.
    pub(crate) fn measurements(&self) -> Option<Measurements> {
        Some(Measurements {
            operation_id: self.operation_id.clone(),
            work: self.work?,
            resource_effects: self.resource_effects.clone()?,
        })
    }

    fn with_notes(mut self) -> Self {
        let mut notes: Vec<&'static str> = Vec::new();
        if self.effects.moved_to_trash > 0 {
            notes.push(TRASH_NOTE);
        }
        notes.extend(observation_note(self.resource_effects.as_deref()));
        if self.degraded_recording == Some(true) {
            notes.push(DEGRADED_NOTE);
        }
        self.notes = notes;
        self
    }

    /// The exit status of a command that waited for this operation
    /// (`docs/INTERFACES.md` section 8). An unknown outcome and a state
    /// that is not final give 5.
    pub(crate) fn waited_status(&self) -> ExitStatus {
        match &self.state {
            OperationState::Completed | OperationState::NoAction => ExitStatus::Success,
            OperationState::Partial | OperationState::Incomplete => ExitStatus::Partial,
            OperationState::Failed => ExitStatus::Failure,
            _ => ExitStatus::Conflict,
        }
    }

    /// The text form.
    pub(crate) fn render(&self, out: &mut String) {
        put_line!(
            out,
            "Operation {} (plan {}): {}{}",
            self.operation_id,
            self.plan_id,
            escape(self.state.as_str()),
            if self.settled {
                ""
            } else if self.state == OperationState::UnknownOutcome {
                " - the effect is not known; reconcile before conflicting work"
            } else {
                " - not a final result"
            }
        );
        put_line!(
            out,
            "  Dispatch: {}   Recording: {}   Admitted: {}",
            escape(self.dispatch.as_str()),
            escape(self.durability.as_str()),
            self.admitted_at
        );
        if let Some(phase) = self.phase {
            put_line!(out, "  Phase: {phase}");
        }
        if let Some(stop) = &self.stop
            && stop.durable_stop_fence
        {
            out.push_str("  Stop fence: durable; the executor dispatches no further step\n");
        }
        if let Some(at) = self.acknowledged_at {
            put_line!(
                out,
                "  Acknowledged: {at}; the leases are released, and the outcome stays unknown"
            );
        }
        put_line!(out, "  Results: {}", self.effects.summary());
        if let Some(work) = &self.work {
            if work.removed_entries.get() > 0 {
                put_line!(
                    out,
                    "  Permanently removed: {}{} entries, {} logical, {} allocated (an estimate: the sizes that the executor measured before each call)",
                    if work.exact { "" } else { "at least " },
                    work.removed_entries.get(),
                    human_bytes(work.removed_logical_bytes.get()),
                    human_bytes(work.removed_allocated_bytes.get()),
                );
            }
            if work.trashed_entries.get() > 0 {
                put_line!(
                    out,
                    "  Moved to Trash: {} entries (not reclaimed capacity)",
                    work.trashed_entries.get()
                );
            }
        }
        match &self.resource_effects {
            None => out.push_str("  Resource observation: not recorded for this view\n"),
            Some(effects) => {
                for effect in effects {
                    render_effect(effect, out);
                }
            }
        }
        if !self.target_results.is_empty() {
            out.push_str("  Targets:\n");
        }
        for result in self.target_results.iter().take(TEXT_TARGET_LIMIT) {
            let label: String = self
                .target_paths
                .get(&result.target_id)
                .map_or_else(|| result.target_id.to_string(), LosslessPath::display_label);
            let member: String = result
                .member
                .as_ref()
                .map_or_else(String::new, |member| format!(" [{member}]"));
            let failure: String = result.failure.as_ref().map_or_else(String::new, |failure| {
                format!(" ({})", escape(failure.code.as_str()))
            });
            put_line!(
                out,
                "    {}  {}  {label}{member}{failure}",
                escape(result.effect.as_str()),
                escape(result.stop_reason.as_str()),
            );
        }
        if self.target_results.len() > TEXT_TARGET_LIMIT {
            put_line!(
                out,
                "    ... and {} more; `--format json` has each record",
                self.target_results.len() - TEXT_TARGET_LIMIT
            );
        }
        for note in &self.notes {
            put_line!(out, "  Note: {note}");
        }
    }
}

/// The statement about the resource observations of a view. The capacity
/// statement is only for a view with a capacity observation: a process
/// stop has a memory-pressure observation and no capacity.
fn observation_note(effects: Option<&[ResourceEffect]>) -> Option<&'static str> {
    match effects {
        Some(effects)
            if effects
                .iter()
                .any(|effect| matches!(effect, ResourceEffect::Capacity(_))) =>
        {
            Some(CAPACITY_NOTE)
        }
        Some(_) => None,
        None => Some(NO_MEASUREMENT_NOTE),
    }
}

fn render_effect(effect: &ResourceEffect, out: &mut String) {
    match effect {
        ResourceEffect::Capacity(capacity) => {
            let scope: String = escape(capacity.before().scope.identity_id.as_str());
            if let Some(delta) = capacity.delta() {
                put_line!(
                    out,
                    "  Observed capacity change of {scope}: {} (other activity contributes to this value)",
                    human_byte_delta(delta.get())
                );
            } else {
                put_line!(
                    out,
                    "  Observed capacity change of {scope}: no value (a measurement was not available)"
                );
            }
        }
        ResourceEffect::MemoryPressure { before, after } => {
            let state = |observation: &svalnir_core::observation::Observation<
                svalnir_core::state::PressureState,
            >| {
                crate::text::observed(observation, |state| {
                    serde_json::to_value(state)
                        .ok()
                        .and_then(|value| value.as_str().map(escape))
                        .unwrap_or_else(|| "unknown".to_owned())
                })
            };
            put_line!(
                out,
                "  Observed memory pressure: {} before, {} after",
                state(before),
                state(after)
            );
        }
        ResourceEffect::Unrecognized => {
            out.push_str("  A resource observation of a kind that this build does not recognize\n");
        }
    }
}

#[cfg(test)]
mod tests {
    use svalnir_core::action::OperationState;

    use svalnir_core::action::ResourceEffect;

    use super::{EffectCounts, NO_MEASUREMENT_NOTE, observation_note};

    #[test]
    fn only_a_capacity_observation_has_the_capacity_note() {
        assert_eq!(observation_note(Some(&[])), None);
        assert_eq!(
            observation_note(Some(&[ResourceEffect::Unrecognized])),
            None
        );
        assert_eq!(observation_note(None), Some(NO_MEASUREMENT_NOTE));
    }

    #[test]
    fn an_empty_count_has_a_text() {
        assert_eq!(EffectCounts::default().summary(), "no target record");
        let counts = EffectCounts {
            moved_to_trash: 2,
            permanently_removed: 1,
            ..EffectCounts::default()
        };
        assert_eq!(counts.summary(), "1 permanently removed, 2 moved to Trash");
    }

    #[test]
    fn unknown_outcome_is_not_settled() {
        assert!(!OperationState::UnknownOutcome.is_settled());
        assert!(OperationState::Failed.is_settled());
    }
}
