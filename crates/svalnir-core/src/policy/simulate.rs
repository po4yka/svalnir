//! Policy simulation.
//!
//! `docs/POLICY_SPEC.md` section 15 owns the contract. [`simulate`]
//! evaluates one fixed snapshot with the predicates, the sequence, and the
//! bounds of [`evaluate_disk_guard`] and [`evaluate_memory_guard`]. It
//! reserves no budget, changes no state, and authorizes nothing.

use serde::{Deserialize, Serialize};

use super::control::{
    AssumedGrants, ControllerSummary, EvaluationContext, MAX_REVISION_LABEL_BYTES, PolicyId,
    PolicyInputError, TriggerState, controller_summary,
};
use super::disk::{
    CapacityOverview, CleanupDecision, CleanupPlan, DiskEvaluation, DiskGuardState, DiskSnapshot,
    FirstBatch, VolumeTrigger, evaluate_disk_guard, plan_cleanup,
};
use super::evidence::EvaluationClock;
use super::memory::{
    ApplicationDecision, BudgetTrigger, FirstIntervention, GlobalPressureTrigger, InterventionPlan,
    MemoryEvaluation, MemoryGuardState, MemorySnapshot, evaluate_memory_guard, plan_intervention,
};
use crate::time::WallTime;

/// The statement that each simulation report has.
pub const SIMULATION_STATEMENT: &str = "This report is a statement about this snapshot only. \
     It reserves no budget, requests no permission, and does not authorize a later operation. \
     A later operation can find different files, processes, capacity, and pressure.";

/// Where the simulated configuration comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RevisionSource {
    /// The revision that the agent reports as effective.
    Effective,
    /// A proposal, for example the file of `--config`. It is not active.
    Proposed,
}

/// The label of the configuration revision that a simulation was given.
/// The simulation repeats it and gives it no meaning.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct RevisionLabel {
    source: RevisionSource,
    label: String,
}

impl RevisionLabel {
    /// Makes a label.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyInputError::InvalidRevisionLabel`] when the text is
    /// empty, is longer than [`MAX_REVISION_LABEL_BYTES`], or has a control
    /// character.
    pub fn new(source: RevisionSource, label: impl Into<String>) -> Result<Self, PolicyInputError> {
        let label: String = label.into();
        if label.is_empty()
            || label.len() > MAX_REVISION_LABEL_BYTES
            || label.chars().any(char::is_control)
        {
            return Err(PolicyInputError::InvalidRevisionLabel);
        }
        Ok(Self { source, label })
    }

    /// Where the configuration comes from.
    pub const fn source(&self) -> RevisionSource {
        self.source
    }

    /// The text of the label.
    pub fn label(&self) -> &str {
        &self.label
    }
}

/// The state of the two guards that the caller keeps between evaluations.
/// The default value has no window and no incident.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct PolicyState {
    /// The state of the disk guard.
    pub disk: DiskGuardState,
    /// The state of the memory guard.
    pub memory: MemoryGuardState,
}

/// The inputs of [`simulate`].
#[derive(Debug, Clone, Copy)]
pub struct SimulationInput<'a> {
    /// The policy to simulate.
    pub policy: PolicyId,
    /// The label of the configuration revision.
    pub revision: &'a RevisionLabel,
    /// The configuration, the evaluation time, the assumed grants, and the
    /// user.
    pub context: EvaluationContext<'a>,
    /// The wall-clock time of the snapshot, for display only.
    pub snapshot_time: WallTime,
    /// The windows and incidents that the caller holds. A simulation reads
    /// them and does not change them.
    pub state: &'a PolicyState,
    /// The disk snapshot. The memory-guard simulation does not read it.
    pub disk: &'a DiskSnapshot,
    /// The memory snapshot. The disk-guard simulation does not read it.
    pub memory: &'a MemorySnapshot,
}

/// The time of the snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SnapshotStamp {
    /// The wall-clock time, for display only.
    pub captured_at: WallTime,
    /// The monotonic time and its clock context.
    pub clock: EvaluationClock,
}

/// One trigger of a simulation, with its state and its evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TriggerReport {
    /// The capacity trigger of one selected volume.
    DiskCapacity(VolumeTrigger),
    /// The global-pressure trigger.
    GlobalPressure(GlobalPressureTrigger),
    /// The trigger of one application budget.
    ApplicationBudget(BudgetTrigger),
}

impl TriggerReport {
    /// The incident state of the trigger.
    pub const fn state(&self) -> TriggerState {
        match self {
            Self::DiskCapacity(trigger) => trigger.state,
            Self::GlobalPressure(trigger) => trigger.state,
            Self::ApplicationBudget(trigger) => trigger.state,
        }
    }
}

/// One candidate of a simulation, with its decision and its reasons.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[expect(
    clippy::large_enum_variant,
    reason = "a report has one kind of candidate, and a box adds an allocation for each one"
)]
pub enum CandidateReport {
    /// A cleanup candidate.
    Cleanup(CleanupDecision),
    /// A candidate application or managed job.
    Application(ApplicationDecision),
}

/// What an incident would do first under the budgets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FirstAction {
    /// The first eviction batch of one selected volume.
    CleanupBatch(FirstBatch),
    /// The first application intervention.
    ApplicationExit(FirstIntervention),
}

impl FirstAction {
    /// True when no reason inhibits the action at this snapshot.
    pub const fn admissible_now(&self) -> bool {
        match self {
            Self::CleanupBatch(batch) => batch.admissible_now,
            Self::ApplicationExit(intervention) => intervention.admissible_now,
        }
    }
}

/// The report of a simulation.
///
/// A report in which each candidate is skipped is a successful result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SimulationReport {
    /// The simulated policy.
    pub policy: PolicyId,
    /// The label of the configuration revision, as it was given.
    pub revision: RevisionLabel,
    /// The schema version of the configuration.
    pub schema_version: u32,
    /// The template revision of the configuration.
    pub template_revision: u32,
    /// The profile of the configuration.
    pub profile: &'static str,
    /// True when the configuration enables the guard.
    pub enabled: bool,
    /// The time of the snapshot.
    pub snapshot: SnapshotStamp,
    /// The grants that the simulation assumed, with their basis.
    pub assumed_grants: AssumedGrants,
    /// The controller summary of this guard.
    pub summary: ControllerSummary,
    /// Each trigger, with its state and the evidence that it used.
    pub triggers: Vec<TriggerReport>,
    /// Each candidate, with its decision and its reasons.
    pub candidates: Vec<CandidateReport>,
    /// What an incident would do first under the budgets.
    pub first_actions: Vec<FirstAction>,
    /// The capacity of the selected volumes by domain. Only the disk guard
    /// has it.
    pub capacity: Option<CapacityOverview>,
    /// The statement that the report is about this snapshot only.
    pub statement: &'static str,
}

/// Simulates one policy against one snapshot.
///
/// The function is pure: equal inputs give an equal report. It does not
/// return a new state, so a simulation cannot advance a window or open an
/// incident.
///
/// # Errors
///
/// Returns a [`PolicyInputError`] when a list of the snapshot or of the
/// state is longer than its limit.
pub fn simulate(input: &SimulationInput<'_>) -> Result<SimulationReport, PolicyInputError> {
    let context: &EvaluationContext<'_> = &input.context;
    let config = context.config;
    let (enabled, granted): (bool, bool) = match input.policy {
        PolicyId::DiskGuard => (
            config.disk_guard().enabled,
            context.grants.evict_regenerable_data,
        ),
        PolicyId::MemoryGuard => (
            config.memory_guard().enabled,
            context.grants.request_application_exit,
        ),
    };
    let mut capacity: Option<CapacityOverview> = None;
    let (triggers, candidates, first_actions): (
        Vec<TriggerReport>,
        Vec<CandidateReport>,
        Vec<FirstAction>,
    ) = match input.policy {
        PolicyId::DiskGuard => {
            let evaluation: DiskEvaluation =
                evaluate_disk_guard(context, &input.state.disk, input.disk)?;
            let plan: CleanupPlan = plan_cleanup(context, &evaluation, input.disk);
            capacity = Some(evaluation.capacity);
            (
                evaluation
                    .volumes
                    .into_iter()
                    .map(TriggerReport::DiskCapacity)
                    .collect(),
                plan.decisions
                    .into_iter()
                    .map(CandidateReport::Cleanup)
                    .collect(),
                plan.first_batches
                    .into_iter()
                    .map(FirstAction::CleanupBatch)
                    .collect(),
            )
        }
        PolicyId::MemoryGuard => {
            let evaluation: MemoryEvaluation =
                evaluate_memory_guard(context, &input.state.memory, input.memory)?;
            let plan: InterventionPlan = plan_intervention(context, &evaluation, input.memory);
            let mut triggers: Vec<TriggerReport> =
                vec![TriggerReport::GlobalPressure(evaluation.global)];
            triggers.extend(
                evaluation
                    .budgets
                    .into_iter()
                    .map(TriggerReport::ApplicationBudget),
            );
            (
                triggers,
                plan.decisions
                    .into_iter()
                    .map(CandidateReport::Application)
                    .collect(),
                vec![FirstAction::ApplicationExit(plan.first)],
            )
        }
    };
    let states: Vec<TriggerState> = triggers.iter().map(TriggerReport::state).collect();
    let permitted: bool = context.authority_reasons(enabled, granted).is_empty();
    Ok(SimulationReport {
        policy: input.policy,
        revision: input.revision.clone(),
        schema_version: config.schema_version(),
        template_revision: config.template_revision(),
        profile: config.agent().profile.as_str(),
        enabled,
        snapshot: SnapshotStamp {
            captured_at: input.snapshot_time,
            clock: context.clock.clone(),
        },
        assumed_grants: context.grants,
        summary: controller_summary(&states, permitted),
        triggers,
        candidates,
        first_actions,
        capacity,
        statement: SIMULATION_STATEMENT,
    })
}
