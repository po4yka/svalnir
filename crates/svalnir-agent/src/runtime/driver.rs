//! The driver: the single-threaded core of the agent.
//!
//! One thread owns the [`Driver`] and calls [`Driver::tick`]. A tick does
//! bounded work and never sleeps: it gives the coordinator a bounded
//! number of work units, reads the result of the automatic plan in
//! progress, does one controller step, carries out the intents, writes the
//! records that changed, and does one unit of maintenance. A grace period
//! is a wake time in the [`TickReport`], so a test moves an injected clock
//! between two ticks.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Serialize;
use svalnir_core::action::{OperationState, PlanApproval, ResourceEffect};
use svalnir_core::config::{ValidatedConfig, parse_and_validate};
use svalnir_core::digest::ContentDigest;
use svalnir_core::file::LosslessPath;
use svalnir_core::grant::{AuthorityState, InstanceInhibition, MeasurementFloor};
use svalnir_core::id::{ExecutorEpochId, OperationId};
use svalnir_core::process::Uid;
use svalnir_core::quantity::{ByteDelta, Bytes, Nanoseconds};
use svalnir_core::rule::RuleRegistry;
use svalnir_core::time::{MonotonicNanos, WallTime};
use thiserror::Error;

use super::ports::{AgentClock, CandidateSource, ClockHandle, Notifier, Sample, SelfFootprint};
use super::record::{
    AGENT_STATUS_VERSION, AgentStatus, CapabilitySummary, LifecycleRecord, MAX_DEGRADED_REASONS,
    PolicySource, RunState, SelfLimits, restart_backoff,
};
use crate::controller::{
    ApplyReport, AuthorityRecords, AutomaticApply, ControllerState, ControllerStatus, Guard,
    GuardPhase, Health, Intent, Observations, OperationResult, PreparationMode, PriorState,
    SharedAuthority, StepInput, StepOutput, TriggerKey, step,
};
use crate::coordinator::{
    ApplicationExecutor, ApplyOutcome, ApplyRequest, Coordinator, CoordinatorConfig, Dependencies,
    FilesystemExecutor, IdSource, Idle, Measurements, OperationView, Phase, Start, StartError,
    TargetProbe, TimeReading,
};
use crate::executor::fs::ApprovedRoots;
use crate::journal::{AgentRecord, JournalOptions, OperationJournal, OperationJournalError};
use crate::store::{EncodedSample, RetentionPolicy, Store};

/// The file name of the operation journal in the state directory.
pub const JOURNAL_FILE_NAME: &str = "operations.sqlite";

/// The error code that the driver reports to the controller when it did
/// not give a plan to the coordinator, because the state of the controller
/// was not recorded.
pub const CODE_STATE_NOT_RECORDED: &str = "controller_state_not_recorded";

/// The largest number of operations that one prune call removes.
const PRUNE_LIMIT: u32 = 256;

/// The settings of the driver.
#[derive(Debug, Clone)]
pub struct DriverSettings {
    /// The user of the agent.
    pub principal: Uid,
    /// The home directory of that user.
    pub home_directory: Option<LosslessPath>,
    /// The configuration that the agent evaluates when the journal has no
    /// policy revision in effect. It gives no authority: the agent then
    /// only observes.
    pub proposal: ValidatedConfig,
    /// The settings of the coordinator.
    pub coordinator: CoordinatorConfig,
    /// The settings of the journal connections.
    pub journal: JournalOptions,
    /// The longest time between two writes of a status that did not
    /// change.
    pub status_interval: Nanoseconds,
    /// The time between two units of maintenance.
    pub maintenance_interval: Nanoseconds,
    /// The budget of the physical footprint of the agent.
    pub self_budget: Bytes,
    /// The longest time that a stop waits for the operation in progress.
    pub shutdown_bound: Nanoseconds,
    /// The largest number of work units that one tick gives to the
    /// coordinator.
    pub coordinator_units: u32,
    /// The age of the newest sample above which a tick evaluates it again
    /// with no new sample. The evaluation then finds that the sample is
    /// old, and the status shows it: a collector that stopped is not a
    /// normal state.
    pub sample_stale_after: Nanoseconds,
}

/// What the driver needs from its environment, beside the journal.
pub struct DriverParts {
    /// The clocks.
    pub clock: Arc<dyn AgentClock>,
    /// The rule registry.
    pub registry: Box<dyn RuleRegistry + Send>,
    /// The measurements of outcome verification.
    pub measurements: Box<dyn Measurements + Send>,
    /// The identities of the coordinator.
    pub ids: Box<dyn IdSource + Send>,
    /// The filesystem executor.
    pub filesystem: Box<dyn FilesystemExecutor + Send>,
    /// The approved roots.
    pub roots: ApprovedRoots,
    /// The process executor.
    pub application: Box<dyn ApplicationExecutor + Send>,
    /// The probe of restart reconciliation.
    pub probe: Box<dyn TargetProbe + Send>,
    /// The source of the cleanup candidates.
    pub candidates: Box<dyn CandidateSource>,
    /// The receiver of the notifications.
    pub notifier: Box<dyn Notifier>,
    /// The measurement of the footprint of the agent.
    pub footprint: Box<dyn SelfFootprint>,
    /// The catalog store, for retained samples. `None`: the agent retains
    /// no sample.
    pub store: Option<Store>,
    /// The capability check of the start.
    pub capabilities: Option<CapabilitySummary>,
}

impl std::fmt::Debug for DriverParts {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DriverParts")
            .finish_non_exhaustive()
    }
}

/// The reason the driver did not start.
#[derive(Debug, Error)]
pub enum DriverError {
    /// The journal did not open.
    #[error("the operation journal did not open: {0}")]
    Journal(#[source] OperationJournalError),
    /// The coordinator did not start.
    #[error("the coordinator did not start: {0}")]
    Coordinator(#[source] StartError),
    /// A clock gave no value.
    #[error("a clock gave no value")]
    Clock,
    /// The reconciliation of the operations of an earlier lifetime did
    /// not complete in its bound.
    #[error("the reconciliation of unfinished operations did not complete")]
    Reconciliation,
}

/// The result of a start.
#[derive(Debug)]
pub enum DriverStart {
    /// This process is the agent.
    Running(Box<Driver>),
    /// A different coordinator holds the lock: an agent runs already, or
    /// a client executes a request. This process changed nothing.
    Busy,
}

/// What a tick did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TickReport {
    /// True when the tick did work that can make more work at once.
    pub worked: bool,
    /// The time at which the coordinator has work again.
    pub wake_at: Option<MonotonicNanos>,
    /// True when the controller wants the short sample interval: a guard
    /// has pressure or an incident.
    pub fast_sampling: bool,
}

/// How the agent stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShutdownReport {
    /// True when each operation was settled, the coordinator released its
    /// registration, and the records of a clean stop were written.
    pub clean: bool,
}

/// The single-threaded core of the agent.
#[expect(
    clippy::struct_excessive_bools,
    reason = "each flag is an independent condition of the agent"
)]
pub struct Driver {
    // `None` only after the coordinator released its registration.
    coordinator: Option<Box<Coordinator<OperationJournal>>>,
    /// The connection for the agent records and the maintenance.
    records: OperationJournal,
    settings: DriverSettings,
    epoch: ExecutorEpochId,
    clock: Arc<dyn AgentClock>,
    authority: SharedAuthority,
    candidates: Box<dyn CandidateSource>,
    notifier: Box<dyn Notifier>,
    footprint: Box<dyn SelfFootprint>,
    store: Option<Store>,
    capabilities: Option<CapabilitySummary>,

    state: ControllerState,
    /// The durable view that the journal has.
    stored: Option<ControllerState>,
    reports: Vec<ApplyReport>,
    observations: Observations,
    sample_degraded: Vec<String>,
    has_sample: bool,
    last_sample_at: Option<MonotonicNanos>,
    /// True when the controller wants the short sample interval.
    fast_sampling: bool,

    /// The effective configuration, when the journal has a usable policy
    /// revision.
    effective: Option<ValidatedConfig>,
    authority_revision: Option<u64>,
    policy: PolicySource,

    lifecycle: LifecycleRecord,
    started_at: WallTime,
    automation_not_before: Option<MonotonicNanos>,
    journal_unavailable: bool,
    optional_reduced: bool,
    stopping: bool,
    last_status: Option<ControllerStatus>,
    last_status_at: Option<MonotonicNanos>,
    last_maintenance_at: Option<MonotonicNanos>,
    last_footprint: Option<Bytes>,
    over_budget: bool,
}

impl std::fmt::Debug for Driver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Driver")
            .field("epoch", &self.epoch)
            .field("stopping", &self.stopping)
            .finish_non_exhaustive()
    }
}

/// The records of the lifetime before this one, as a start finds them.
struct Restored {
    lifecycle: LifecycleRecord,
    state: ControllerState,
    /// The durable view that the journal has.
    stored: Option<ControllerState>,
    journal_unavailable: bool,
}

impl Restored {
    /// Reads the lifecycle record and the state of the controller, and
    /// writes the two records of the new lifetime.
    fn read(records: &mut OperationJournal, time: &TimeReading) -> Self {
        // A record that is not readable is not the record of a clean
        // stop: it counts as one stop that was not clean.
        let earlier: LifecycleRecord =
            match records.agent_record::<LifecycleRecord>(AgentRecord::Lifecycle) {
                Ok(None) => LifecycleRecord::default(),
                Ok(Some(stored)) => stored.record,
                Err(_) => LifecycleRecord {
                    stopped_cleanly: false,
                    ..LifecycleRecord::default()
                },
            };
        let lifecycle: LifecycleRecord = earlier.started(time.wall);
        let mut journal_unavailable: bool = records
            .put_agent_record(AgentRecord::Lifecycle, &lifecycle, None, time.wall)
            .is_err();
        let prior: PriorState =
            match records.agent_record::<ControllerState>(AgentRecord::Controller) {
                Ok(None) => PriorState::Absent,
                Ok(Some(stored)) => PriorState::Recorded(Box::new(stored.record)),
                Err(_) => PriorState::Unreadable,
            };
        let state: ControllerState = ControllerState::restore(prior);
        // The record of a running agent is not the record of a clean stop.
        let view: ControllerState = state.durable_view();
        let stored: Option<ControllerState> = records
            .put_agent_record(AgentRecord::Controller, &view, None, time.wall)
            .is_ok()
            .then_some(view);
        journal_unavailable |= stored.is_none();
        Self {
            lifecycle,
            state,
            stored,
            journal_unavailable,
        }
    }
}

/// The JSON spelling of a value that serializes as one string.
fn wire<T: Serialize>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(text)) => text,
        Ok(other) => other.to_string(),
        Err(_) => "unknown".to_owned(),
    }
}

/// The path of the operation journal in `state_directory`.
#[must_use]
pub fn journal_path(state_directory: &Path) -> PathBuf {
    state_directory.join(JOURNAL_FILE_NAME)
}

impl Driver {
    /// Starts the agent on the journal of `state_directory`.
    ///
    /// The sequence is: open the journal, take the coordinator lock and
    /// register the executor lifetime `epoch`, reconcile the operations
    /// that an earlier lifetime left unsettled, read the lifecycle record
    /// and the state of the controller, and read the authority record. No
    /// request is claimed and no plan is admitted before the
    /// reconciliation is complete.
    ///
    /// # Errors
    ///
    /// Returns a [`DriverError`] when the journal or the coordinator did
    /// not start, a clock gave no value, or the reconciliation did not
    /// complete.
    pub fn start(
        state_directory: &Path,
        epoch: ExecutorEpochId,
        settings: DriverSettings,
        parts: DriverParts,
    ) -> Result<DriverStart, DriverError> {
        let database: PathBuf = journal_path(state_directory);
        let journal: OperationJournal =
            OperationJournal::open(&database, &settings.journal).map_err(DriverError::Journal)?;
        let mut records: OperationJournal =
            OperationJournal::open(&database, &settings.journal).map_err(DriverError::Journal)?;
        let time: TimeReading = parts.clock.now().ok_or(DriverError::Clock)?;

        let authority: SharedAuthority =
            SharedAuthority::new(AuthorityRecords::new(settings.principal, parts.registry));
        let dependencies: Dependencies = Dependencies {
            clock: Box::new(ClockHandle(Arc::clone(&parts.clock))),
            authority: Box::new(authority.clone()),
            measurements: parts.measurements,
            ids: parts.ids,
            filesystem: parts.filesystem,
            roots: parts.roots,
            application: parts.application,
            probe: parts.probe,
        };
        let mut coordinator: Box<Coordinator<OperationJournal>> = match Coordinator::start(
            journal,
            &database,
            epoch.clone(),
            settings.coordinator.clone(),
            dependencies,
        )
        .map_err(DriverError::Coordinator)?
        {
            Start::Coordinating(coordinator) => coordinator,
            Start::Busy { .. } => return Ok(DriverStart::Busy),
        };

        // Reconcile before anything else. A step does the pending
        // reconciliation first and claims no request while it is pending.
        let mut units: u32 = 0;
        while coordinator.reconciliation_pending() {
            if units >= settings.coordinator_units.max(1).saturating_mul(64) {
                return Err(DriverError::Reconciliation);
            }
            units = units.saturating_add(1);
            coordinator.step();
        }

        let Restored {
            lifecycle,
            state,
            stored,
            journal_unavailable,
        } = Restored::read(&mut records, &time);
        let backoff: Nanoseconds = restart_backoff(lifecycle.unclean_stops);
        let automation_not_before: Option<MonotonicNanos> =
            (backoff > Nanoseconds::ZERO).then(|| {
                time.clock
                    .now
                    .checked_add(backoff)
                    .unwrap_or(MonotonicNanos::new(u64::MAX))
            });

        let mut driver: Self = Self {
            coordinator: Some(coordinator),
            records,
            settings,
            epoch,
            clock: parts.clock,
            authority,
            candidates: parts.candidates,
            notifier: parts.notifier,
            footprint: parts.footprint,
            store: parts.store,
            capabilities: parts.capabilities,
            state,
            stored,
            reports: Vec::new(),
            observations: Observations::default(),
            sample_degraded: Vec::new(),
            has_sample: false,
            last_sample_at: None,
            fast_sampling: false,
            effective: None,
            authority_revision: None,
            policy: PolicySource {
                revision: None,
                problem: None,
            },
            lifecycle,
            started_at: time.wall,
            automation_not_before,
            journal_unavailable,
            optional_reduced: false,
            stopping: false,
            last_status: None,
            last_status_at: None,
            last_maintenance_at: None,
            last_footprint: None,
            over_budget: false,
        };
        driver.load_authority();
        driver.write_status(&time, RunState::Starting, None);
        Ok(DriverStart::Running(Box::new(driver)))
    }

    /// The executor lifetime of this agent.
    pub const fn epoch(&self) -> &ExecutorEpochId {
        &self.epoch
    }

    /// The state of the controller.
    pub const fn controller_state(&self) -> &ControllerState {
        &self.state
    }

    /// The status of the latest controller step.
    pub const fn controller_status(&self) -> Option<&ControllerStatus> {
        self.last_status.as_ref()
    }

    /// Reads an operation of the coordinator.
    pub fn operation(&self, operation_id: &OperationId) -> Option<OperationView> {
        self.coordinator
            .as_ref()
            .and_then(|coordinator| coordinator.operation(operation_id).ok().flatten())
    }

    /// Reads the authority record of the journal when it changed, with the
    /// configuration of its policy revision.
    ///
    /// The effective policy is the one that the journal records: the
    /// source text of the revision in effect, whose digest is the content
    /// digest of the revision. With no record, or with a record that this
    /// build cannot use, the agent only observes.
    ///
    /// Returns `true` when the record was read again.
    fn load_authority(&mut self) -> bool {
        let revision: Option<u64> = self
            .records
            .agent_record_revision(AgentRecord::Authority)
            .ok();
        if revision.is_some() && revision == self.authority_revision {
            return false;
        }
        self.authority_revision = revision;
        let (state, effective, problem): (
            Option<AuthorityState>,
            Option<ValidatedConfig>,
            Option<&'static str>,
        ) = match self
            .records
            .agent_record::<AuthorityState>(AgentRecord::Authority)
        {
            Ok(None) => (None, None, None),
            Err(_) => (None, None, Some("authority_record_not_readable")),
            Ok(Some(stored)) if stored.record.principal != self.settings.principal => {
                (None, None, Some("authority_record_of_a_different_user"))
            }
            Ok(Some(stored)) => match &stored.record.active {
                // No revision is in effect: no guard is active, and the
                // proposal is evaluated for the status.
                None => (Some(stored.record), None, None),
                Some(active) => {
                    let source: Option<String> = self
                        .records
                        .policy_revision_source(&active.revision.revision_id)
                        .ok()
                        .flatten();
                    let config: Option<ValidatedConfig> = source
                        .filter(|text| {
                            ContentDigest::of_bytes(text.as_bytes()) == active.revision.content
                        })
                        .and_then(|text| parse_and_validate(&text).config().cloned());
                    match config {
                        Some(config) => (Some(stored.record), Some(config), None),
                        None => (None, None, Some("policy_revision_source_not_usable")),
                    }
                }
            },
        };
        self.policy = PolicySource {
            revision: state
                .as_ref()
                .and_then(|state| state.active.as_ref())
                .map(|active| active.revision.revision_id.clone()),
            problem: problem.map(str::to_owned),
        };
        // A record that was not read is read again at the next tick.
        if matches!(
            problem,
            Some("authority_record_not_readable" | "policy_revision_source_not_usable")
        ) {
            self.authority_revision = None;
        }
        self.effective = effective;
        self.authority.records().state = state;
        true
    }

    /// The inhibition of this instance: the end of the latest pause that
    /// the controller saw.
    fn inhibition(&self) -> InstanceInhibition {
        InstanceInhibition {
            guards: Vec::new(),
            pause: None,
            measurement_floor: self
                .state
                .measurement_floor
                .as_ref()
                .map(|mark| MeasurementFloor {
                    at: mark.at,
                    clock_domain: mark.clock_domain.clone(),
                    boot_id: mark.boot_id.clone(),
                }),
        }
    }

    /// Reads the result of the automatic plan in progress, when its
    /// operation is finished.
    fn collect_finished(&mut self, time: &TimeReading) {
        let Some(outstanding) = self.state.outstanding.clone() else {
            return;
        };
        let (Some(operation_id), Some(coordinator)) =
            (&outstanding.operation_id, self.coordinator.as_ref())
        else {
            return;
        };
        let result: OperationResult = match coordinator.operation(operation_id) {
            Ok(Some(view)) if view.phase == Phase::Finished => {
                let operation = &view.operation;
                let mut gain: Option<ByteDelta> = None;
                let mut gain_known: bool = false;
                let mut pressure_after = None;
                for effect in &view.resource_effects {
                    match effect {
                        ResourceEffect::Capacity(capacity) => {
                            let delta: Option<ByteDelta> = capacity.delta();
                            gain = if gain_known {
                                gain.zip(delta)
                                    .and_then(|(sum, delta)| sum.checked_add(delta))
                            } else {
                                delta
                            };
                            gain_known = true;
                        }
                        ResourceEffect::MemoryPressure { after, .. } => {
                            pressure_after = after.value().cloned();
                        }
                        ResourceEffect::Unrecognized => {}
                    }
                }
                OperationResult {
                    state: wire(operation.state()),
                    completed: matches!(operation.state(), OperationState::Completed),
                    possibly_submitted: operation.dispatch().is_possibly_submitted(),
                    unknown_outcome: matches!(operation.state(), OperationState::UnknownOutcome)
                        || operation
                            .target_results()
                            .iter()
                            .any(|result| result.effect.is_indeterminate()),
                    capacity_gain: gain,
                    pressure_after,
                    cooldown_until: coordinator
                        .cooldown_until(&outstanding.incident_id)
                        .filter(|until| *until > time.clock.now),
                }
            }
            // A read that failed gives no result. The next tick reads
            // again.
            Ok(Some(_)) | Err(_) => return,
            // The coordinator has no record of the operation that it
            // admitted. Its effect is not known, and it stays charged.
            Ok(None) => OperationResult {
                state: wire(&OperationState::UnknownOutcome),
                completed: false,
                possibly_submitted: true,
                unknown_outcome: true,
                capacity_gain: None,
                pressure_after: None,
                cooldown_until: None,
            },
        };
        self.reports.push(ApplyReport::Finished {
            plan_id: outstanding.plan_id,
            result,
        });
    }

    /// Writes the durable view of the controller state when it changed.
    /// Returns `false` when the journal did not take it.
    fn persist(&mut self, time: &TimeReading) -> bool {
        let view: ControllerState = self.state.durable_view();
        if self.stored.as_ref() == Some(&view) {
            return true;
        }
        let written: bool = self
            .records
            .put_agent_record(AgentRecord::Controller, &view, None, time.wall)
            .is_ok();
        if written {
            self.stored = Some(view);
        }
        self.journal_unavailable = !written;
        written
    }

    fn apply(&mut self, apply: AutomaticApply, recorded: bool) {
        let plan_id = apply.plan.plan_id.clone();
        // The usage of the incident must be recorded before a plan uses
        // it. The only action with no durable record is the
        // critical-memory exception, which the incident recorded when it
        // opened.
        let exception: bool = apply.guard == Guard::Memory
            && matches!(apply.trigger, TriggerKey::GlobalMemory)
            && apply.budget.volatile_exception_at_open;
        let Some(coordinator) = self.coordinator.as_mut().filter(|_| recorded || exception) else {
            self.reports.push(ApplyReport::Refused {
                plan_id,
                code: CODE_STATE_NOT_RECORDED.to_owned(),
            });
            return;
        };
        self.authority
            .records()
            .bind_plan(plan_id.clone(), apply.trigger.clone());
        let request: ApplyRequest = ApplyRequest {
            approval: PlanApproval {
                plan_id: plan_id.clone(),
                digest: apply.plan.digest().clone(),
            },
            principal: apply.plan.principal.clone(),
            plan: Some(apply.plan),
            incident: Some(apply.allowance),
        };
        let report: ApplyReport = match coordinator.apply(request) {
            ApplyOutcome::Admitted { operation_id } => ApplyReport::Admitted {
                plan_id,
                operation_id,
            },
            ApplyOutcome::Existing { operation } => ApplyReport::Admitted {
                plan_id,
                operation_id: operation.operation_id().clone(),
            },
            ApplyOutcome::Refused { error } => ApplyReport::Refused {
                plan_id,
                code: error.code.as_str().to_owned(),
            },
        };
        // The step of the same tick reads an admission, so the status has
        // the operation at once.
        if let (ApplyReport::Admitted { operation_id, .. }, Some(outstanding)) =
            (&report, &mut self.state.outstanding)
        {
            outstanding.operation_id = Some(operation_id.clone());
        }
        self.reports.push(report);
    }

    /// Gives the coordinator a bounded number of work units.
    fn run_coordinator(&mut self) -> (bool, Option<MonotonicNanos>) {
        let Some(coordinator) = self.coordinator.as_mut() else {
            return (false, None);
        };
        let mut worked: bool = false;
        let mut wake_at: Option<MonotonicNanos> = None;
        for _ in 0..self.settings.coordinator_units.max(1) {
            let progress = coordinator.step();
            wake_at = progress.wake_at;
            if !progress.worked {
                break;
            }
            worked = true;
        }
        (worked, wake_at)
    }

    /// Measures the footprint of the agent against its budget.
    fn measure_self(&mut self) {
        self.last_footprint = self.footprint.footprint();
        self.over_budget = self
            .last_footprint
            .is_some_and(|footprint| footprint > self.settings.self_budget);
    }

    /// Takes a new sample: the observations replace the earlier ones, and
    /// a wake discards what the time before the sleep supported.
    fn take_sample(&mut self, sample: Sample, time: &TimeReading) {
        self.last_sample_at = Some(time.clock.now);
        if sample.woke {
            // The windows start again, and a candidate set from before
            // the sleep is not a fresh check.
            self.clock.mark_discontinuity();
            self.observations.candidates = None;
        }
        let candidates = self.observations.candidates.take();
        self.observations = sample.observations;
        self.observations.candidates = candidates;
        self.sample_degraded = sample.degraded;
        self.has_sample = true;
        self.authority.records().control_plane = sample.control_plane;
        self.retain_sample();
    }

    /// Writes the pressure and capacity observations of the sample to the
    /// catalog store. Retained samples are optional work: they are dropped
    /// before an action record.
    fn retain_sample(&mut self) {
        if self.optional_reduced {
            return;
        }
        let Some(store) = &mut self.store else {
            return;
        };
        let mut encoded: Vec<EncodedSample> = Vec::new();
        if let Some(pressure) = &self.observations.memory.pressure
            && let Ok(sample) = EncodedSample::encode(pressure)
        {
            encoded.push(sample);
        }
        for volume in &self.observations.volumes {
            if let Ok(sample) = EncodedSample::encode(&volume.available) {
                encoded.push(sample);
            }
        }
        if !encoded.is_empty() && store.insert_samples(&encoded).is_err() {
            self.sample_degraded.push("sample_store".to_owned());
        }
    }

    /// Does one bounded unit of work.
    ///
    /// `sample` is the newest collection, when the collectors made one
    /// after the tick before this one. With no sample, the step evaluates
    /// the latest observations again: an observation that got old is then
    /// not usable, which inhibits each action that depends on it.
    pub fn tick(&mut self, sample: Option<Sample>) -> TickReport {
        let Some(time) = self.clock.now() else {
            return TickReport {
                worked: false,
                wake_at: None,
                fast_sampling: false,
            };
        };
        let (mut worked, mut wake_at) = self.run_coordinator();
        self.collect_finished(&time);
        let authority_changed: bool = self.load_authority();
        let has_new_sample: bool = sample.is_some();
        if let Some(sample) = sample {
            self.take_sample(sample, &time);
        }
        self.measure_self();

        // The controller evaluates a new sample, a report, a plan in
        // progress, a change of the authority, and a sample that got old.
        // Between two samples of a quiet host it does not evaluate the
        // same sample again, because the age of the sample is then the
        // only change.
        let stale: bool = self.last_sample_at.is_none_or(|at| {
            time.clock
                .now
                .checked_duration_since(at)
                .is_none_or(|age| age >= self.settings.sample_stale_after)
        });
        let evaluate: bool = has_new_sample
            || authority_changed
            || stale
            || self.stopping
            || self.last_status.is_none()
            || !self.reports.is_empty()
            || self.state.outstanding.is_some();
        let mut status: Option<ControllerStatus> = None;
        if evaluate {
            let (acted, new_status) = self.evaluate(&time);
            status = Some(new_status);
            if acted {
                let (again, wake) = self.run_coordinator();
                worked |= acted || again;
                wake_at = wake;
            }
        }

        let run_state: RunState = if self.stopping {
            RunState::Stopping
        } else {
            RunState::Running
        };
        self.write_status(&time, run_state, status);
        self.maintain(&time);
        TickReport {
            worked,
            wake_at,
            fast_sampling: self.fast_sampling,
        }
    }

    /// Does one controller step and carries out its intents. Returns
    /// whether an intent made work for the coordinator, and the status.
    fn evaluate(&mut self, time: &TimeReading) -> (bool, ControllerStatus) {
        let restart_backoff: bool = self
            .automation_not_before
            .is_some_and(|not_before| time.clock.now < not_before);
        let inhibition: InstanceInhibition = self.inhibition();
        let reports: Vec<ApplyReport> = std::mem::take(&mut self.reports);
        let output: StepOutput = {
            let records = self.authority.records();
            let input: StepInput<'_> = StepInput {
                time,
                epoch: &self.epoch,
                principal: self.settings.principal,
                home_directory: self.settings.home_directory.as_ref(),
                config: self.effective.as_ref().unwrap_or(&self.settings.proposal),
                authority: records.state.as_ref(),
                inhibition: &inhibition,
                registry: records.registry.as_ref(),
                observations: &self.observations,
                reports: &reports,
                health: Health {
                    journal_unavailable: self.journal_unavailable,
                    self_over_budget: self.over_budget,
                    stopping: self.stopping,
                    restart_backoff,
                },
                control_plane: records.control_plane.as_deref(),
            };
            step(&self.state, &input)
        };
        self.state = output.state;
        {
            let mut records = self.authority.records();
            records.incidents = output.incidents;
            records.triggers = output.triggers;
            records.inhibition = self.inhibition();
        }
        let recorded: bool = self.persist(time);

        let mut acted: bool = false;
        self.optional_reduced = false;
        for intent in output.intents {
            match intent {
                Intent::Apply(apply) => {
                    self.apply(*apply, recorded);
                    acted = true;
                }
                Intent::PrepareCandidates { volumes, mode } => {
                    // A discovery is optional work. The known candidates
                    // are examined in each case.
                    if mode == PreparationMode::KnownOnly || !self.optional_reduced {
                        self.observations.candidates =
                            self.candidates.prepare(&volumes, mode, time);
                        acted = true;
                    }
                }
                Intent::Notify(notification) => self.notifier.notify(&notification),
                Intent::ReduceOptionalWork(_) => self.optional_reduced = true,
                Intent::Idle => {}
            }
        }
        // The admission of this step is a part of the durable state.
        self.persist(time);
        // The short sample interval while a guard has pressure, so that a
        // qualification window gets its samples.
        self.fast_sampling = self.state.outstanding.is_some()
            || output
                .status
                .guards
                .iter()
                .any(|guard| !matches!(guard.phase, GuardPhase::Normal | GuardPhase::Degraded));
        (acted, output.status)
    }

    /// Writes the status record when the status changed, or when the
    /// status interval ended.
    fn write_status(
        &mut self,
        time: &TimeReading,
        state: RunState,
        status: Option<ControllerStatus>,
    ) {
        // The time of the evaluation is not a change of the status.
        let comparable = |status: &ControllerStatus| {
            let mut copy: ControllerStatus = status.clone();
            copy.evaluated_at = WallTime::UNIX_EPOCH;
            copy
        };
        let changed: bool = match (&status, &self.last_status) {
            (Some(new), Some(old)) => comparable(new) != comparable(old),
            // A tick with no evaluation has no new status.
            (None, _) => false,
            (Some(_), None) => true,
        };
        let due: bool = self.last_status_at.is_none_or(|at| {
            time.clock
                .now
                .checked_duration_since(at)
                .is_none_or(|age| age >= self.settings.status_interval)
        });
        if let Some(status) = status {
            self.last_status = Some(status);
        }
        if !(changed || due || state != RunState::Running) {
            return;
        }
        let mut degraded: Vec<String> = self.sample_degraded.clone();
        if !self.has_sample && state == RunState::Running {
            degraded.push("no_sample".to_owned());
        }
        if self.journal_unavailable {
            degraded.push("journal_unavailable".to_owned());
        }
        if let Some(reason) = &self.lifecycle.degraded_reason {
            degraded.push(reason.clone());
        }
        degraded.truncate(MAX_DEGRADED_REASONS);
        let record: AgentStatus = AgentStatus {
            schema_version: AGENT_STATUS_VERSION,
            executor_epoch: self.epoch.clone(),
            process_id: std::process::id(),
            started_at: self.started_at,
            written_at: time.wall,
            state,
            controller: self.last_status.clone(),
            policy: self.policy.clone(),
            capabilities: self.capabilities.clone(),
            limits: SelfLimits {
                footprint_bytes: self.last_footprint.map(Bytes::get),
                budget_bytes: self.settings.self_budget.get(),
                over_budget: self.over_budget,
                optional_work_reduced: self.optional_reduced,
            },
            degraded,
            unclean_stops: self.lifecycle.unclean_stops,
            restart_backoff: self
                .automation_not_before
                .is_some_and(|not_before| time.clock.now < not_before),
        };
        match self
            .records
            .put_agent_record(AgentRecord::Status, &record, None, time.wall)
        {
            Ok(_) => {
                self.last_status_at = Some(time.clock.now);
                self.journal_unavailable = false;
            }
            Err(_) => self.journal_unavailable = true,
        }
    }

    /// One unit of maintenance: the retention of the journal and of the
    /// catalog store, and a checkpoint. Maintenance is optional work. It
    /// does not run while the agent reduces its work, so no compaction or
    /// large delete runs in an incident.
    fn maintain(&mut self, time: &TimeReading) {
        if self.optional_reduced || self.stopping {
            return;
        }
        let due: bool = self.last_maintenance_at.is_none_or(|at| {
            time.clock
                .now
                .checked_duration_since(at)
                .is_none_or(|age| age >= self.settings.maintenance_interval)
        });
        if !due {
            return;
        }
        self.last_maintenance_at = Some(time.clock.now);
        let history = self
            .effective
            .as_ref()
            .unwrap_or(&self.settings.proposal)
            .history();
        let retention_seconds: i64 = i64::try_from(history.retention.as_secs()).unwrap_or(i64::MAX);
        if let Ok(cutoff) = WallTime::from_unix(
            time.wall.unix_seconds().saturating_sub(retention_seconds),
            0,
        ) && self.records.prune(cutoff, PRUNE_LIMIT).is_err()
        {
            self.sample_degraded.push("journal_retention".to_owned());
        }
        // A checkpoint that a reader prevented runs again at the next
        // unit.
        let _complete: Result<bool, OperationJournalError> = self.records.checkpoint();
        if let Some(store) = &mut self.store {
            let policy: RetentionPolicy =
                RetentionPolicy::for_history(history.retention, history.max_database_size);
            if store.apply_retention(time.wall, &policy).is_err() {
                self.sample_degraded.push("store_retention".to_owned());
            }
        }
    }

    /// Stops the agent.
    ///
    /// No new automatic plan starts. The operation in progress gets a stop
    /// request, so its current step ends at its safe boundary and no later
    /// step is dispatched; the driver waits for it at most
    /// [`DriverSettings::shutdown_bound`]. The state of the controller is
    /// then written. The stop is clean when each operation is settled and
    /// the coordinator released its registration. In each other case the
    /// registration stays, and the next start reconciles.
    pub fn shutdown(mut self, idle: &mut dyn Idle) -> ShutdownReport {
        self.stopping = true;
        let give_up_at: Option<MonotonicNanos> = self.clock.now().map(|time| {
            time.clock
                .now
                .checked_add(self.settings.shutdown_bound)
                .unwrap_or(MonotonicNanos::new(u64::MAX))
        });
        if let (Some(coordinator), Some(operation_id)) = (
            self.coordinator.as_mut(),
            self.state
                .outstanding
                .as_ref()
                .and_then(|outstanding| outstanding.operation_id.clone()),
        ) {
            // A refused stop request means that the operation is settled
            // or not known. The wait below reads which.
            let _acknowledgement = coordinator.cancel(&operation_id);
            if let Some(give_up_at) = give_up_at {
                let _outcome = coordinator.run_until_finished(&operation_id, give_up_at, idle);
            }
        }
        // The bookkeeping of the result, with no new plan.
        self.tick(None);

        // With a plan whose result is not known, the registration stays,
        // so that the next start reconciles.
        let mut released: bool = false;
        while self.state.outstanding.is_none()
            && let Some(coordinator) = self.coordinator.take()
        {
            match coordinator.shutdown() {
                Ok(_journal) => {
                    released = true;
                }
                Err((coordinator, _error)) => {
                    let now: Option<MonotonicNanos> = self.clock.now().map(|time| time.clock.now);
                    let time_left: bool = matches!(
                        (now, give_up_at),
                        (Some(now), Some(give_up_at)) if now < give_up_at
                    );
                    self.coordinator = Some(coordinator);
                    if !time_left {
                        break;
                    }
                    let (worked, wake_at) = self.run_coordinator();
                    if !worked {
                        idle.idle(wake_at);
                    }
                }
            }
        }

        let clean: bool = released;
        let Some(time) = self.clock.now() else {
            return ShutdownReport { clean: false };
        };
        // The lifecycle record says "clean" only when the controller
        // record does. With a failed write, the next start finds a stop
        // that was not clean: its incidents are not established, and the
        // stop is counted.
        let mut written: bool = false;
        if clean {
            let mut view: ControllerState = self.state.durable_view();
            view.clean_stop = true;
            written = self
                .records
                .put_agent_record(AgentRecord::Controller, &view, None, time.wall)
                .is_ok();
            if written {
                self.lifecycle = self.lifecycle.stopped(time.wall);
                written = self
                    .records
                    .put_agent_record(AgentRecord::Lifecycle, &self.lifecycle, None, time.wall)
                    .is_ok();
            }
        }
        self.write_status(&time, RunState::Stopped, None);
        let _complete: Result<bool, OperationJournalError> = self.records.checkpoint();
        ShutdownReport {
            clean: clean && written,
        }
    }
}
