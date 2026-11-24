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
use svalnir_core::action::{ErrorFamily, OperationState, PlanApproval, ResourceEffect};
use svalnir_core::config::{ValidatedConfig, parse_and_validate};
use svalnir_core::digest::ContentDigest;
use svalnir_core::file::LosslessPath;
use svalnir_core::grant::{AuthorityState, ControlClock, InstanceInhibition, MeasurementFloor};
use svalnir_core::id::{ExecutorEpochId, OperationId, RuleId};
use svalnir_core::observation::Observation;
use svalnir_core::process::Uid;
use svalnir_core::quantity::{ByteDelta, Bytes, Nanoseconds};
use svalnir_core::rule::RuleRegistry;
use svalnir_core::time::{MonotonicNanos, WallTime};
use thiserror::Error;

use super::ports::{
    AgentClock, CandidateSource, ClockHandle, Notifier, Preparation, Sample, SelfFootprint,
};
use super::record::{
    AGENT_STATUS_VERSION, AgentStatus, CapabilitySummary, LIFECYCLE_VERSION, LifecycleRecord,
    MAX_DEGRADED_REASONS, PolicySource, RunState, SelfLimits, restart_backoff,
};
use crate::controller::{
    ApplyReport, AuthorityRecords, AutomaticApply, ControllerState, ControllerStatus, Guard,
    GuardPhase, Health, Intent, Observations, OperationResult, PreparationMode, PriorState,
    SharedAuthority, StepInput, StepOutput, TriggerKey, step,
};
use crate::coordinator::{
    ApplicationExecutor, ApplyOutcome, ApplyRequest, Coordinator, CoordinatorConfig, Dependencies,
    FilesystemExecutor, IdSource, Idle, Measurements, OperationView, OwnerOperationExecutor, Phase,
    Start, StartError, TargetProbe, TimeReading, code, rearm_rejection,
};
use crate::executor::fs::ApprovedRoots;
use crate::journal::{
    AgentRecord, CoordinatorRole, JournalOptions, OperationJournal, OperationJournalError,
    RequestCompletion,
};
use crate::protection::ProtectedLocations;
use crate::rules::projects::PaseoAgents;
use crate::rules::{SharedEnvironment, automatic_roots};
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
    /// The owner executor.
    pub owner: Box<dyn OwnerOperationExecutor + Send>,
    /// The probe of restart reconciliation.
    pub probe: Box<dyn TargetProbe + Send>,
    /// The source of the cleanup candidates.
    pub candidates: Box<dyn CandidateSource>,
    /// The process table and the clock of the fresh activity check before
    /// a step of an eviction.
    pub environment: SharedEnvironment,
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
    /// A different coordinator holds the lock. This process changed
    /// nothing.
    Busy {
        /// The kind of the holder. With [`CoordinatorRole::Agent`], an
        /// agent runs already and this process is not necessary. With
        /// [`CoordinatorRole::Client`], a client executes a request and
        /// releases the lock after it, or the role is not known: the
        /// agent must start again.
        holder: CoordinatorRole,
    },
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
    /// The authority record was not read, or was not usable, at the
    /// latest read.
    authority_unread: bool,
    /// A read of the authority record found that this instance did not
    /// see each state of the record. The tick makes the floor from it.
    authority_states_unseen: bool,
    /// The time of the latest tick that found states of the authority
    /// record that this instance did not see.
    unseen_change_floor: Option<MeasurementFloor>,
    policy: PolicySource,

    lifecycle: LifecycleRecord,
    started_at: WallTime,
    automation_not_before: Option<MonotonicNanos>,
    record_health: RecordHealth,
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

/// Whether the journal has the two records that the driver writes in each
/// tick: the state of the controller and the status.
///
/// Each record has its own flag. A status write that succeeds says
/// nothing about the controller record, so it does not clear a failed
/// write of that record: the step of the next tick must still see that
/// the journal does not have the state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct RecordHealth {
    controller_unrecorded: bool,
    status_unrecorded: bool,
}

impl RecordHealth {
    /// The health after the writes of a start. `unavailable` is true when
    /// the journal did not take the lifecycle record or the controller
    /// record. No later write is a write of the lifecycle record, so the
    /// condition stays until the journal takes the two records of a
    /// tick: the state of the controller and the status.
    const fn at_start(unavailable: bool) -> Self {
        Self {
            controller_unrecorded: unavailable,
            status_unrecorded: unavailable,
        }
    }

    /// Records whether the journal has the present state of the
    /// controller.
    const fn controller_written(&mut self, written: bool) {
        self.controller_unrecorded = !written;
    }

    /// Records the result of a write of the controller record. A locked
    /// journal is not a storage failure: it changes no flag.
    const fn controller_persisted(&mut self, persisted: Persisted) {
        match persisted {
            Persisted::Written => self.controller_written(true),
            Persisted::Failed => self.controller_written(false),
            Persisted::Busy => {}
        }
    }

    /// Records the result of a write of the status record.
    const fn status_written(&mut self, written: bool) {
        self.status_unrecorded = !written;
    }

    /// True when the journal did not take one of the two records.
    const fn unavailable(self) -> bool {
        self.controller_unrecorded || self.status_unrecorded
    }
}

/// The result of a write of the controller record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Persisted {
    /// The journal has the present state of the controller.
    Written,
    /// A different process held the lock of the journal for longer than
    /// the bounded wait. The write recorded nothing, and the next tick
    /// writes again. This is not a storage failure.
    Busy,
    /// The storage of the journal failed.
    Failed,
}

impl Persisted {
    /// The result of a write of an agent record.
    const fn of(result: &Result<u64, OperationJournalError>) -> Self {
        match result {
            Ok(_) => Self::Written,
            Err(OperationJournalError::Busy(_)) => Self::Busy,
            Err(_) => Self::Failed,
        }
    }

    /// The refusal code of an automatic plan after this write, or `None`
    /// when the plan goes to the coordinator. `exception` is true when the
    /// critical-memory exception is authorized for the plan.
    ///
    /// A locked journal is a refusal with `admission_not_recorded`: the
    /// controller plans again at its next evaluation with no pacing wait,
    /// and the exception does not apply. Only a storage failure permits
    /// the exception.
    const fn refusal(self, exception: bool) -> Option<&'static str> {
        match self {
            Self::Written => None,
            Self::Busy => Some(code::ADMISSION_NOT_RECORDED),
            Self::Failed if exception => None,
            Self::Failed => Some(CODE_STATE_NOT_RECORDED),
        }
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
        // A record that is not readable, or that has a different schema
        // version, is not the record of a clean stop, and its count of
        // stops is not known: the restart backoff is then the longest
        // one. A lost record must not make a crash loop faster.
        let earlier: LifecycleRecord = match records
            .agent_record::<LifecycleRecord>(AgentRecord::Lifecycle)
        {
            Ok(None) => LifecycleRecord::default(),
            Ok(Some(stored)) if stored.record.schema_version == LIFECYCLE_VERSION => stored.record,
            Ok(Some(_)) | Err(_) => LifecycleRecord::unreadable(),
        };
        let lifecycle: LifecycleRecord = earlier.started(time.wall);
        // A locked journal is not a storage failure.
        let mut journal_unavailable: bool = Persisted::of(&records.put_agent_record(
            AgentRecord::Lifecycle,
            &lifecycle,
            None,
            time.wall,
        )) == Persisted::Failed;
        let prior: PriorState =
            match records.agent_record::<ControllerState>(AgentRecord::Controller) {
                Ok(None) => PriorState::Absent,
                Ok(Some(stored)) => PriorState::Recorded(Box::new(stored.record)),
                Err(_) => PriorState::Unreadable,
            };
        let state: ControllerState = ControllerState::restore(prior);
        // The record of a running agent is not the record of a clean stop.
        let view: ControllerState = state.durable_view();
        let persisted: Persisted = Persisted::of(&records.put_agent_record(
            AgentRecord::Controller,
            &view,
            None,
            time.wall,
        ));
        journal_unavailable |= persisted == Persisted::Failed;
        let stored: Option<ControllerState> = (persisted == Persisted::Written).then_some(view);
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

/// The authority records of a start, with no authority record of the
/// journal: the locations of the catalog of protected file locations (the
/// home directory of the user and the state directory of this agent, each
/// with its symbolic links resolved), and the environment of the fresh
/// activity check.
fn authority_records(
    settings: &DriverSettings,
    state_directory: &Path,
    registry: Box<dyn RuleRegistry + Send>,
    environment: SharedEnvironment,
) -> AuthorityRecords {
    let mut records: AuthorityRecords = AuthorityRecords::new(settings.principal, registry);
    records.locations = ProtectedLocations::resolve(
        settings
            .home_directory
            .as_ref()
            .map(LosslessPath::to_path_buf)
            .as_deref(),
        Some(state_directory),
    );
    records.environment = Some(environment);
    records
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
        // The connection of the coordinator, and one for the records of the
        // driver.
        let open = || OperationJournal::open(&database, &settings.journal);
        let journal: OperationJournal = open().map_err(DriverError::Journal)?;
        let mut records: OperationJournal = open().map_err(DriverError::Journal)?;
        let time: TimeReading = parts.clock.now().ok_or(DriverError::Clock)?;

        let authority: SharedAuthority = SharedAuthority::new(authority_records(
            &settings,
            state_directory,
            parts.registry,
            parts.environment,
        ));
        let dependencies: Dependencies = Dependencies {
            clock: Box::new(ClockHandle(Arc::clone(&parts.clock))),
            authority: Box::new(authority.clone()),
            measurements: parts.measurements,
            ids: parts.ids,
            filesystem: parts.filesystem,
            roots: parts.roots,
            application: parts.application,
            owner: parts.owner,
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
            Start::Busy { holder, .. } => return Ok(DriverStart::Busy { holder }),
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
            authority_unread: false,
            authority_states_unseen: false,
            unseen_change_floor: None,
            policy: PolicySource {
                revision: None,
                problem: None,
            },
            lifecycle,
            started_at: time.wall,
            automation_not_before,
            record_health: RecordHealth::at_start(journal_unavailable),
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
        // Each write of the record adds one to its revision counter. A
        // counter that is more than one above the counter of the latest
        // read shows a state of the record that this instance did not
        // see, for example a pause and its resume between two ticks. The
        // same is true for the first read after a read that failed. The
        // controller saw no pause then, so it makes no floor for the
        // resume; the tick makes one in its place.
        let skipped: bool = match (self.authority_revision, revision) {
            (Some(seen), Some(now)) => now > seen.saturating_add(1),
            _ => false,
        };
        if skipped || (self.authority_unread && revision.is_some()) {
            self.authority_states_unseen = true;
        }
        self.authority_unread = revision.is_none();
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
            self.authority_unread = true;
        }
        // The layouts of the configuration in effect, for the check of a
        // unit of `project.dependency-directory` before its step.
        let layouts: Vec<svalnir_core::config::UserLayout> = effective
            .as_ref()
            .map_or_else(Vec::new, |config| config.cleanup().projects.layouts.clone());
        let home: Option<PathBuf> = self
            .settings
            .home_directory
            .as_ref()
            .map(LosslessPath::to_path_buf);
        let agents: PaseoAgents = effective.as_ref().map_or_else(
            || PaseoAgents::new(false, None),
            |config| PaseoAgents::from_settings(&config.cleanup().projects, home.as_deref()),
        );
        self.effective = effective;
        let mut records = self.authority.records();
        records.state = state;
        records.project_layouts = layouts;
        records.project_agents = agents;
        true
    }

    /// The inhibition of this instance: the later of the end of the
    /// latest pause that the controller saw and the time of the latest
    /// tick that found control changes that this instance did not see.
    fn inhibition(&self) -> InstanceInhibition {
        let seen: Option<MeasurementFloor> =
            self.state
                .measurement_floor
                .as_ref()
                .map(|mark| MeasurementFloor {
                    at: mark.at,
                    clock_domain: mark.clock_domain.clone(),
                    boot_id: mark.boot_id.clone(),
                });
        // The controller compares the boot and the clock domain of a
        // floor. A floor of a different timeline is not later.
        let measurement_floor: Option<MeasurementFloor> =
            match (seen, self.unseen_change_floor.clone()) {
                (Some(seen), Some(unseen)) => {
                    let same_timeline: bool =
                        seen.clock_domain == unseen.clock_domain && seen.boot_id == unseen.boot_id;
                    Some(if same_timeline && seen.at > unseen.at {
                        seen
                    } else {
                        unseen
                    })
                }
                (seen, unseen) => unseen.or(seen),
            };
        InstanceInhibition {
            guards: Vec::new(),
            pause: None,
            measurement_floor,
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
                        ResourceEffect::ScopeAllocation(_) | ResourceEffect::Unrecognized => {}
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

    /// Writes the durable view of the controller state when it changed,
    /// and returns whether the journal has it. A locked journal does not
    /// mark the journal as unavailable.
    fn persist(&mut self, time: &TimeReading) -> Persisted {
        let view: ControllerState = self.state.durable_view();
        if self.stored.as_ref() == Some(&view) {
            self.record_health.controller_written(true);
            return Persisted::Written;
        }
        let persisted: Persisted = Persisted::of(&self.records.put_agent_record(
            AgentRecord::Controller,
            &view,
            None,
            time.wall,
        ));
        if persisted == Persisted::Written {
            self.stored = Some(view);
        }
        self.record_health.controller_persisted(persisted);
        persisted
    }

    fn apply(&mut self, apply: AutomaticApply, persisted: Persisted) {
        let plan_id = apply.plan.plan_id.clone();
        // The usage of the incident must be recorded before a plan uses
        // it. The only action with no durable record is the
        // critical-memory exception, which the incident recorded when it
        // opened.
        let exception: bool = apply.guard == Guard::Memory
            && matches!(apply.trigger, TriggerKey::GlobalMemory)
            && apply.budget.volatile_exception_at_open;
        let refusal: Option<&'static str> = persisted.refusal(exception);
        let Some(coordinator) = self.coordinator.as_mut().filter(|_| refusal.is_none()) else {
            self.reports.push(ApplyReport::Refused {
                plan_id,
                code: refusal.unwrap_or(CODE_STATE_NOT_RECORDED).to_owned(),
            });
            return;
        };
        {
            let mut records = self.authority.records();
            records.bind_plan(plan_id.clone(), apply.trigger.clone());
            // The approved roots of an automatic operation come from the
            // rule declarations and the configuration in effect, as the
            // host is now. No root comes from the plan.
            if apply.guard == Guard::Disk {
                let approved: &[RuleId] = &self
                    .effective
                    .as_ref()
                    .unwrap_or(&self.settings.proposal)
                    .disk_guard()
                    .approved_rules;
                let roots: ApprovedRoots =
                    automatic_roots(records.registry.as_ref(), approved, &records.locations);
                records.automatic_roots = roots;
            }
        }
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

    /// Gives the operations that the coordinator settled to the notifier.
    /// The coordinator also settles an operation in the second run of a
    /// tick; that one goes to the notifier in the next tick.
    fn notify_settled(&mut self, time: &TimeReading) {
        let Some(coordinator) = self.coordinator.as_mut() else {
            return;
        };
        for operation in coordinator.take_settled() {
            self.notifier.settled(&operation, time.clock.now);
        }
    }

    /// Decides the rearm request that the coordinator claimed, when it has
    /// one, and records its completion. Returns `true` when a request was
    /// decided.
    ///
    /// The controller checks the request against the present authority
    /// record and the inhibition of this instance. The record is read
    /// again after the claim, so that a `policy disable` or an `agent
    /// pause` that the journal has before the decision applies to it, also
    /// when it came after the read at the start of the tick. An accepted
    /// rearm is in effect only when the journal recorded the controller
    /// state with the new generation: when that write fails, the earlier
    /// state stays, and the request is rejected with `rearm_not_recorded`.
    fn serve_rearm(&mut self, time: &TimeReading) -> bool {
        let Some(pending) = self
            .coordinator
            .as_mut()
            .and_then(|coordinator| coordinator.take_rearm())
        else {
            return false;
        };
        if self.load_authority() {
            self.floor_unseen_states(time);
        }
        let authority: AuthorityState = self
            .authority
            .records()
            .state
            .clone()
            .unwrap_or_else(|| AuthorityState::new(self.settings.principal));
        let inhibition: InstanceInhibition = self.inhibition();
        let control: ControlClock<'_> = ControlClock {
            clock: &time.clock,
            wall: time.wall,
        };
        let before: ControllerState = self.state.clone();
        let completion: RequestCompletion = match self.state.rearm(
            &authority,
            &inhibition,
            &pending.request,
            &control,
            &self.epoch,
        ) {
            Ok(rearm) if self.persist(time) == Persisted::Written => RequestCompletion::Rearmed {
                incident_id: pending.request.incident_id.clone(),
                previous_generation: rearm.previous_generation,
                new_generation: rearm.new_generation,
            },
            Ok(_) => {
                self.state = before;
                RequestCompletion::Rejected {
                    error: rearm_rejection(code::REARM_NOT_RECORDED, ErrorFamily::Recording),
                }
            }
            Err(failure) => RequestCompletion::Rejected {
                error: rearm_rejection(failure.code(), failure.family()),
            },
        };
        if let Some(coordinator) = self.coordinator.as_mut() {
            coordinator.complete_rearm(pending.request_id, completion);
        }
        true
    }

    /// Sets the measurement floor of this instance at `time` when a read
    /// of the authority record found that it missed a state of the record.
    fn floor_unseen_states(&mut self, time: &TimeReading) {
        if std::mem::take(&mut self.authority_states_unseen) {
            // "Resuming always refreshes measurements": a sample of
            // before this tick supports no automatic action.
            self.unseen_change_floor = Some(MeasurementFloor {
                at: time.clock.now,
                clock_domain: time.clock.clock_domain.clone(),
                boot_id: time.clock.boot_id.clone(),
            });
            // The authorization of the coordinator reads the inhibition
            // of the records. It gets the floor before the coordinator
            // dispatches a step in this tick, and not only after the
            // evaluation of the controller.
            let inhibition: InstanceInhibition = self.inhibition();
            self.authority.records().inhibition = inhibition;
        }
    }

    /// Measures the footprint of the agent against its budget.
    fn measure_self(&mut self) {
        self.last_footprint = self.footprint.footprint();
        self.over_budget = self
            .last_footprint
            .is_some_and(|footprint| footprint > self.settings.self_budget);
    }

    /// Takes a new sample: the observations replace the earlier ones, and
    /// a wake discards what the time before the sleep supported. Returns
    /// whether the sample reported a wake: a clock reading from before
    /// this call then has the continuity generation of before the sleep.
    fn take_sample(&mut self, sample: Sample, time: &TimeReading) -> bool {
        let woke: bool = sample.woke;
        self.last_sample_at = Some(time.clock.now);
        if sample.woke {
            // The windows start again, and a candidate set from before
            // the sleep is not a fresh check.
            self.clock.mark_discontinuity();
            self.observations.candidates = None;
        }
        let candidates = self.observations.candidates.take();
        self.observations = sample.observations;
        self.notifier.pressure(
            self.observations
                .memory
                .pressure
                .as_ref()
                .and_then(|pressure| pressure.value()),
            time.clock.now,
        );
        self.observations.candidates = candidates;
        self.sample_degraded = sample.degraded;
        self.has_sample = true;
        self.authority.records().control_plane = sample.control_plane;
        self.retain_sample(sample.sleep_time.as_ref());
        woke
    }

    /// Writes the pressure and capacity observations of the sample to the
    /// catalog store. Retained samples are optional work: they are dropped
    /// before an action record.
    fn retain_sample(&mut self, sleep_time: Option<&Observation<Nanoseconds>>) {
        // The footprint of this tick counts at once, and not only after
        // the next evaluation.
        if self.optional_reduced || self.over_budget {
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
        let mut capacity_samples: usize = 0;
        for volume in &self.observations.volumes {
            if let Ok(sample) = EncodedSample::encode(&volume.available) {
                encoded.push(sample);
                capacity_samples += 1;
            }
        }
        // The sleep time is the evidence of a sleep boundary between two
        // stored capacity samples, for the estimate of the time to a
        // threshold. It has a meaning only beside those samples.
        if capacity_samples > 0
            && let Some(sleep) = sleep_time
            && let Ok(sample) = EncodedSample::encode(sleep)
        {
            encoded.push(sample);
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
        const NOTHING: TickReport = TickReport {
            worked: false,
            wake_at: None,
            fast_sampling: false,
        };
        // A sleep of the host that the clock finds between two ticks is
        // known before the next collection reports it.
        let mut discontinuity: bool = self.clock.observe_continuity();
        if discontinuity {
            self.observations.candidates = None;
        }
        let Some(mut time) = self.clock.now() else {
            return NOTHING;
        };
        // The authority record is read before the coordinator dispatches
        // a step: a pause, a disabled guard, or a revoked grant that is in
        // the journal applies to the work of this tick.
        let authority_changed: bool = self.load_authority();
        // A floor of a different boot or clock domain is not a time of
        // this timeline. It is removed, so that the floor of the instance
        // is always a floor of the current timeline or none.
        if self.unseen_change_floor.as_ref().is_some_and(|floor| {
            floor.clock_domain != time.clock.clock_domain || floor.boot_id != time.clock.boot_id
        }) {
            self.unseen_change_floor = None;
        }
        self.floor_unseen_states(&time);
        self.measure_self();
        let has_new_sample: bool = sample.is_some();
        if let Some(sample) = sample {
            discontinuity |= self.take_sample(sample, &time);
        }
        if discontinuity {
            // The reading of before the discontinuity has the earlier
            // continuity generation. The evaluation and the coordinator
            // of this tick must not use it: each window starts again
            // with the first sample after a wake.
            let Some(after) = self.clock.now() else {
                return NOTHING;
            };
            time = after;
        }
        let (mut worked, mut wake_at) = self.run_coordinator();
        self.notify_settled(&time);
        let rearmed: bool = self.serve_rearm(&time);
        worked |= rearmed;
        self.collect_finished(&time);
        let invalidated: bool = self.read_invalidation(&time);

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
            || rearmed
            || invalidated
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

    /// Reads the `FSEvents` invalidation of the candidate source. Returns
    /// true when the candidate set of the observations became invalidated
    /// in this call, so that the controller evaluates it: in the warning
    /// band it then asks for a bounded discovery. The read is short and
    /// lists no directory, so it runs also in an incident.
    fn read_invalidation(&mut self, time: &TimeReading) -> bool {
        let invalidated: bool = self.candidates.invalidated(time.clock.now);
        match &mut self.observations.candidates {
            Some(set) if invalidated && !set.invalidated => {
                set.invalidated = true;
                true
            }
            _ => false,
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
                    journal_unavailable: self.record_health.unavailable(),
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
        let persisted: Persisted = self.persist(time);

        let mut acted: bool = false;
        self.optional_reduced = false;
        for intent in output.intents {
            match intent {
                Intent::Apply(apply) => {
                    self.apply(*apply, persisted);
                    acted = true;
                }
                Intent::PrepareCandidates { volumes, mode } => {
                    // A discovery is optional work. The known candidates
                    // are examined in each case.
                    if mode == PreparationMode::KnownOnly || !self.optional_reduced {
                        let request: Preparation<'_> = Preparation {
                            volumes: &volumes,
                            mode,
                            time,
                            config: self.effective.as_ref().unwrap_or(&self.settings.proposal),
                        };
                        self.observations.candidates = self.candidates.prepare(&request);
                        acted = true;
                    }
                }
                Intent::Notify(notification) => {
                    self.notifier.notify(&notification, time.clock.now);
                }
                Intent::ReduceOptionalWork(_) => {
                    self.optional_reduced = true;
                    // A discovery that runs now is optional work.
                    self.candidates.cancel();
                }
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
        // The conditions of the runtime are first, so that the bound
        // drops a name of a collector and not one of them.
        let mut degraded: Vec<String> = Vec::new();
        if self.record_health.unavailable() {
            degraded.push("journal_unavailable".to_owned());
        }
        if let Some(reason) = &self.lifecycle.degraded_reason {
            degraded.push(reason.clone());
        }
        if !self.has_sample && state == RunState::Running {
            degraded.push("no_sample".to_owned());
        }
        degraded.extend(self.sample_degraded.iter().cloned());
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
            capabilities: self.capabilities.clone().map(|mut summary| {
                summary.notifications = self.notifier.status();
                summary.catalog_watch = self.candidates.watch_status();
                summary
            }),
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
                self.record_health.status_written(true);
            }
            // A locked journal is not a storage failure. The next status
            // write tries again.
            Err(OperationJournalError::Busy(_)) => {}
            Err(_) => self.record_health.status_written(false),
        }
    }

    /// One unit of maintenance: the retention of the journal and of the
    /// catalog store, and a checkpoint. Maintenance is optional work. It
    /// does not run while the agent reduces its work, so no compaction or
    /// large delete runs in an incident.
    fn maintain(&mut self, time: &TimeReading) {
        if self.optional_reduced || self.over_budget || self.stopping {
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
        let retention_cutoff: Option<WallTime> = WallTime::from_unix(
            time.wall.unix_seconds().saturating_sub(retention_seconds),
            0,
        )
        .ok();
        // The usage row of an open incident stays, so the prune keeps the
        // budget of the incident when it removes its settled operations.
        if let Some(cutoff) = retention_cutoff
            && self
                .records
                .prune(cutoff, PRUNE_LIMIT, &self.state.open_incident_ids())
                .is_err()
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
    /// No new automatic plan starts, and the coordinator claims no
    /// further request of the journal queue: a queued request stays there
    /// for the next coordinator. Each operation in progress, automatic or
    /// of a client, gets a stop request, so its current step ends at its
    /// safe boundary and no later step is dispatched; the driver waits
    /// for them at most [`DriverSettings::shutdown_bound`]. The state of
    /// the controller is then written. The stop is clean when each
    /// operation is settled and the coordinator released its
    /// registration. In each other case the registration stays, and the
    /// next start reconciles.
    pub fn shutdown(mut self, idle: &mut dyn Idle) -> ShutdownReport {
        self.stopping = true;
        self.candidates.cancel();
        let give_up_at: Option<MonotonicNanos> = self.clock.now().map(|time| {
            time.clock
                .now
                .checked_add(self.settings.shutdown_bound)
                .unwrap_or(MonotonicNanos::new(u64::MAX))
        });
        let outstanding: Option<OperationId> = self
            .state
            .outstanding
            .as_ref()
            .and_then(|outstanding| outstanding.operation_id.clone());
        if let Some(coordinator) = self.coordinator.as_mut() {
            // No new client work: before the first step of the stop.
            coordinator.stop_claims();
            let mut stopped: Vec<OperationId> = coordinator.cancel_active();
            if let Some(operation_id) = outstanding
                && !stopped.contains(&operation_id)
            {
                // A refused stop request means that the operation is
                // settled or not known. The wait below reads which.
                let _acknowledgement = coordinator.cancel(&operation_id);
                stopped.push(operation_id);
            }
            if let Some(give_up_at) = give_up_at {
                for operation_id in &stopped {
                    let _outcome = coordinator.run_until_finished(operation_id, give_up_at, idle);
                }
            }
        }
        // The bookkeeping of the result, with no new plan.
        self.tick(None);

        // A record that the journal did not take is written again while
        // the bound permits.
        while self
            .coordinator
            .as_ref()
            .is_some_and(|coordinator| coordinator.has_work_in_progress())
        {
            let now: Option<MonotonicNanos> = self.clock.now().map(|time| time.clock.now);
            let time_left: bool = matches!(
                (now, give_up_at),
                (Some(now), Some(give_up_at)) if now < give_up_at
            );
            if !time_left {
                break;
            }
            let (worked, wake_at) = self.run_coordinator();
            if !worked {
                idle.idle(wake_at);
            }
        }

        // One release call. A refusal is a stop without release: an
        // operation is not settled, a reconciliation is pending, or the
        // journal did not take the volatile history. A further call
        // cannot change that in this lifetime. With a plan whose result
        // is not known, the release is not asked. In each of these cases
        // the registration stays, so that the next start reconciles.
        let mut released: bool = false;
        if self.state.outstanding.is_none()
            && let Some(coordinator) = self.coordinator.take()
        {
            match coordinator.shutdown() {
                Ok(_journal) => released = true,
                Err((coordinator, _error)) => self.coordinator = Some(coordinator),
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

#[cfg(test)]
mod record_health_tests {
    use super::{CODE_STATE_NOT_RECORDED, Persisted, RecordHealth, code};

    #[test]
    fn a_locked_journal_is_a_refusal_and_only_a_storage_failure_permits_the_exception() {
        for exception in [false, true] {
            assert_eq!(Persisted::Written.refusal(exception), None);
            assert_eq!(
                Persisted::Busy.refusal(exception),
                Some(code::ADMISSION_NOT_RECORDED)
            );
        }
        assert_eq!(Persisted::Failed.refusal(true), None);
        assert_eq!(
            Persisted::Failed.refusal(false),
            Some(CODE_STATE_NOT_RECORDED)
        );
        // A locked journal does not mark the journal as unavailable, and
        // it does not clear a storage failure.
        let mut health = RecordHealth::default();
        health.controller_persisted(Persisted::Busy);
        assert!(!health.unavailable());
        health.controller_persisted(Persisted::Failed);
        assert!(health.unavailable());
        health.controller_persisted(Persisted::Busy);
        assert!(health.unavailable());
        health.controller_persisted(Persisted::Written);
        assert!(!health.unavailable());
    }

    #[test]
    fn a_status_write_does_not_clear_a_failed_controller_write() {
        let mut health = RecordHealth::default();
        assert!(!health.unavailable());
        // The journal did not take the state of the controller, and then
        // it took the status record of the same tick.
        health.controller_written(false);
        health.status_written(true);
        assert!(health.unavailable());
        // Only a write of the controller record clears its flag.
        health.status_written(true);
        assert!(health.unavailable());
        health.controller_written(true);
        assert!(!health.unavailable());
        // A failed status write is its own cause.
        health.status_written(false);
        assert!(health.unavailable());
        health.controller_written(true);
        assert!(health.unavailable());
        health.status_written(true);
        assert!(!health.unavailable());
        // A failed write at the start stays until the journal takes the
        // two records, in each sequence.
        let mut started = RecordHealth::at_start(true);
        started.status_written(true);
        assert!(started.unavailable());
        started.controller_written(true);
        assert!(!started.unavailable());
        let mut started = RecordHealth::at_start(true);
        started.controller_written(true);
        assert!(started.unavailable());
        started.status_written(true);
        assert!(!started.unavailable());
        assert!(!RecordHealth::at_start(false).unavailable());
    }
}
