//! Read-only readings of the agent records for a client process: the
//! controller state with its budgets, cooldowns, and incident usage, and the
//! pause as the agent decides it.
//!
//! A reading opens no journal for writes and writes nothing. It reads the
//! agent records of the journal ([`AgentRecord`]) and the usage rows of the
//! incidents. It does not query the coordinator lock: the age of the status
//! record of the agent ([`Freshness`]) is the evidence that a client has
//! about a running agent.
//!
//! The monotonic clock of a client is the clock of the agent: the same
//! system-wide `CLOCK_MONOTONIC_RAW`, the same clock domain, and the same
//! boot identity (`kern.bootsessionuuid`). A pause or a cooldown that the
//! agent recorded in this boot thus has the same status for the client at
//! the same time. A record of a different boot gives the status that the
//! agent also gives for it: retained or unknown, never ended.

use std::path::Path;

use serde::Serialize;
use svalnir_core::authority::Generation;
use svalnir_core::grant::{
    AuthorityState, BudgetGenerationRecord, ControlClock, GenerationBasis, IncidentBudget,
    MAX_BUDGET_GENERATIONS, PauseStatus, pause_status,
};
use svalnir_core::id::{IncidentId, OperationId, PlanId};
use svalnir_core::policy::{
    ContinuityGeneration, Cooldown, CooldownCause, CooldownStatus, EvaluationClock, MAX_VOLUMES,
    TriggerState,
};
use svalnir_core::process::Uid;
use svalnir_core::quantity::Nanoseconds;
use svalnir_core::time::{MonotonicNanos, WallTime};

use super::{Host, open_existing_journal_read_only, read_authority};
use crate::controller::{
    BlockedReason, CONTROLLER_STATE_VERSION, ControllerState, ControllerStatus, Guard,
    MAX_APPLICATION_COOLDOWNS,
};
use crate::journal::{AgentRecord, IncidentUsage, OperationJournal, StoredAgentRecord};
use crate::platform::memory::ClockError;
use crate::runtime::{AGENT_STATUS_VERSION, AgentStatus, RunState};

/// The age of the status record of the agent above which a client shows the
/// records as stale: three status intervals of the agent binary, which
/// writes its status at least each 30 seconds.
// TODO(npochaev): share the status interval of the agent binary (now a
// literal in `main.rs`) as a constant, and derive this value from it.
pub const STATUS_MAX_AGE: Nanoseconds = Nanoseconds::new(90_000_000_000);

/// The largest number of incidents that a controller reading has: one disk
/// incident for each selected volume, and the memory incident.
pub const MAX_READ_INCIDENTS: usize = MAX_VOLUMES + 1;

const NANOSECONDS_PER_SECOND: i128 = 1_000_000_000;

/// The clocks of a client process at one time, read as the agent reads
/// them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientClock {
    /// The monotonic time with its clock domain and its boot. A client has
    /// no continuity generation and no discontinuity; a pause and a
    /// cooldown do not use them.
    pub clock: EvaluationClock,
    /// The wall-clock time.
    pub wall: WallTime,
}

impl ClientClock {
    /// Reads the clocks of the collection context of `host`.
    ///
    /// # Errors
    ///
    /// Returns a [`ClockError`] when a clock gives no value.
    pub fn read(host: &Host) -> Result<Self, ClockError> {
        let context = host.context();
        let identity = context.identity();
        Ok(Self {
            clock: EvaluationClock {
                now: context.clock().monotonic_now()?,
                clock_domain: identity.clock_domain.clone(),
                boot_id: identity.boot_id.clone(),
                continuity: ContinuityGeneration::new(0),
                last_discontinuity: None,
            },
            wall: context.clock().wall_now()?,
        })
    }

    /// The clock of a control decision.
    #[must_use]
    pub fn control(&self) -> ControlClock<'_> {
        ControlClock {
            clock: &self.clock,
            wall: self.wall,
        }
    }
}

/// How old the status record of the agent is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "freshness", rename_all = "snake_case")]
pub enum Freshness {
    /// The agent wrote its status at most [`STATUS_MAX_AGE`] ago, and the
    /// status does not say that the agent stopped.
    Current {
        /// The age of the status.
        age: Nanoseconds,
    },
    /// The status is older than [`STATUS_MAX_AGE`]: the agent does not run,
    /// or it does not write. The records show the state at the time of the
    /// status, not now.
    Stale {
        /// The age of the status.
        age: Nanoseconds,
    },
    /// The status says that the agent stopped. The controller record is
    /// the state that the next start of the agent restores.
    Stopped,
    /// The journal has no usable status record, or the wall clock of this
    /// process is before the time of the status.
    Unknown,
}

/// A record of the journal as a client read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordReading<T> {
    /// The journal has no such record.
    Absent,
    /// The journal has a record that this build cannot read: a decode
    /// error, a different schema version, or a storage error.
    Unreadable {
        /// The cause.
        reason: String,
    },
    /// The record.
    Recorded(T),
}

impl<T> RecordReading<T> {
    /// The record, when the reading has one.
    pub const fn recorded(&self) -> Option<&T> {
        match self {
            Self::Recorded(record) => Some(record),
            Self::Absent | Self::Unreadable { .. } => None,
        }
    }
}

/// The journal of a client reading.
#[derive(Debug)]
pub enum JournalReading<T> {
    /// The journal file does not exist: no agent and no command used this
    /// state directory.
    Absent,
    /// The journal file exists and cannot be opened for reads.
    Unreadable {
        /// The cause.
        reason: String,
    },
    /// The reading of the journal.
    Read(T),
}

/// The wall-clock time of a write of a record.
fn written_at<T>(stored: &StoredAgentRecord<T>) -> Option<WallTime> {
    WallTime::from_unix(stored.updated_unix_seconds, 0).ok()
}

/// The time from `earlier` to `later`. `None` when `later` is before
/// `earlier`.
fn wall_elapsed(earlier: WallTime, later: WallTime) -> Option<Nanoseconds> {
    let nanoseconds = |time: WallTime| {
        i128::from(time.unix_seconds()) * NANOSECONDS_PER_SECOND
            + i128::from(time.subsecond_nanoseconds())
    };
    let elapsed: i128 = nanoseconds(later).checked_sub(nanoseconds(earlier))?;
    u64::try_from(elapsed).ok().map(Nanoseconds::new)
}

/// The status record of the agent with its age.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusReading {
    /// The record.
    pub status: AgentStatus,
    /// The revision of the record.
    pub revision: u64,
    /// The freshness of the record at the time of the reading.
    pub freshness: Freshness,
}

/// The freshness of a status written at `written_at` in the state `state`,
/// at `now`.
#[must_use]
pub fn freshness(written_at: WallTime, state: RunState, now: WallTime) -> Freshness {
    if state == RunState::Stopped {
        return Freshness::Stopped;
    }
    match wall_elapsed(written_at, now) {
        Some(age) if age <= STATUS_MAX_AGE => Freshness::Current { age },
        Some(age) => Freshness::Stale { age },
        None => Freshness::Unknown,
    }
}

/// Reads the status record of the agent.
#[must_use]
pub fn read_status(journal: &OperationJournal, now: WallTime) -> RecordReading<StatusReading> {
    match journal.agent_record::<AgentStatus>(AgentRecord::Status) {
        Ok(None) => RecordReading::Absent,
        Err(error) => RecordReading::Unreadable {
            reason: error.to_string(),
        },
        Ok(Some(stored)) if stored.record.schema_version != AGENT_STATUS_VERSION => {
            RecordReading::Unreadable {
                reason: format!(
                    "the status record has the schema version {}",
                    stored.record.schema_version
                ),
            }
        }
        Ok(Some(stored)) => RecordReading::Recorded(StatusReading {
            freshness: freshness(stored.record.written_at, stored.record.state, now),
            revision: stored.revision,
            status: stored.record,
        }),
    }
}

/// The window state of one application budget.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BudgetReading {
    /// The identifier of the budget in the configuration.
    pub budget_id: String,
    /// True when the budget has a trigger episode that did not recover.
    /// The controller record has it; a restart keeps it.
    pub latched: bool,
    /// The incident state of the budget trigger at the latest step of the
    /// agent, from its status record. `None` when the status has no entry
    /// for the budget or its text is not a state of this build. The stored
    /// controller state has no window: a restart needs fresh observations.
    pub trigger: Option<TriggerState>,
}

/// What a cooldown inhibits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "subject", rename_all = "snake_case")]
pub enum CooldownSubject {
    /// One application or job: the relaunch cooldown after an
    /// intervention. The key is the bundle identifier or the job label.
    Application {
        /// The key.
        application: String,
    },
    /// The next pass of a disk incident.
    DiskIncident {
        /// The incident, when the controller record has one for the domain.
        incident_id: Option<IncidentId>,
    },
    /// The next batch or target of an incident: the observation window
    /// after an action.
    ObserveAfterAction {
        /// The incident.
        incident_id: IncidentId,
    },
    /// The next target of the memory incident after an action with a low
    /// benefit or a failure.
    MemoryBackoff {
        /// The incident.
        incident_id: IncidentId,
    },
}

/// One cooldown with its status at the time of the reading.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CooldownReading {
    /// What the cooldown inhibits.
    pub subject: CooldownSubject,
    /// The cause.
    pub cause: CooldownCause,
    /// The monotonic end of the cooldown in the boot of the record.
    pub until: MonotonicNanos,
    /// The status at the clock of this process. A cooldown of a different
    /// boot is [`CooldownStatus::Unknown`]: the agent also treats it as
    /// active.
    pub status: CooldownStatus,
}

impl CooldownReading {
    fn of(subject: CooldownSubject, cooldown: &Cooldown, clock: &EvaluationClock) -> Self {
        Self {
            subject,
            cause: cooldown.cause,
            until: cooldown.until,
            status: cooldown.status(clock),
        }
    }
}

/// The consumed usage of one budget generation, as the journal records it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalUsage {
    /// The usage row of the generation.
    Recorded(IncidentUsage),
    /// The journal has no usage row: no dispatch of the generation was
    /// consumed. This is the usage zero only for a generation of an open
    /// incident, whose rows the retention keeps.
    NoConsumedDispatch,
    /// The row cannot be read.
    Unreadable {
        /// The cause.
        reason: String,
    },
}

/// One budget generation of an incident.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerationReading {
    /// The generation.
    pub generation: Generation,
    /// How the generation started.
    pub basis: GenerationBasis,
    /// The user that authorized a rearm. `None` for the first generation.
    pub authorized_by: Option<Uid>,
    /// The wall-clock time at which the generation started.
    pub started_at: WallTime,
    /// The usage of the controller at the rearm that ended the generation,
    /// with the reserved charges. `None` for the current generation.
    pub final_usage: Option<svalnir_core::grant::IncidentUsage>,
    /// The consumed usage that the journal records for the generation.
    pub journal: JournalUsage,
}

/// One open incident of the controller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncidentReading {
    /// The identity of the incident.
    pub incident_id: IncidentId,
    /// The guard of the incident.
    pub guard: Guard,
    /// The current budget generation.
    pub generation: Generation,
    /// False when a restart could not establish the usage: the incident
    /// permits no automatic work until it closes or a person rearms it.
    pub established: bool,
    /// True when an operation of the incident ended with an effect that is
    /// not known.
    pub unknown_outcome: bool,
    /// The usage of the current generation in the controller record, with
    /// the reserved charges. `None` when the policy state has no entry for
    /// the incident.
    pub current_usage: Option<svalnir_core::grant::IncidentUsage>,
    /// Each budget generation, in sequence, at most
    /// [`MAX_BUDGET_GENERATIONS`].
    pub generations: Vec<GenerationReading>,
}

/// The automatic plan in progress.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutstandingReading {
    /// The guard of the plan.
    pub guard: Guard,
    /// The incident of the plan.
    pub incident_id: IncidentId,
    /// The plan.
    pub plan_id: PlanId,
    /// The operation, after the coordinator admitted the plan.
    pub operation_id: Option<OperationId>,
}

/// The controller state of the journal for a client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControllerReading {
    /// The revision of the controller record.
    pub revision: u64,
    /// The wall-clock time of the write of the record. The agent writes
    /// the record only when the state changes, so an old record is not
    /// evidence of a stopped agent; see [`Freshness`].
    pub written_at: Option<WallTime>,
    /// True when a clean stop wrote the record.
    pub clean_stop: bool,
    /// The application budgets, in the sequence of the record.
    pub budgets: Vec<BudgetReading>,
    /// The cooldowns, at most [`MAX_APPLICATION_COOLDOWNS`] of applications
    /// and one of each kind for each incident.
    pub cooldowns: Vec<CooldownReading>,
    /// The open incidents, at most [`MAX_READ_INCIDENTS`].
    pub incidents: Vec<IncidentReading>,
    /// True when the record had more incidents, cooldowns, or generations
    /// than the reading keeps.
    pub truncated: bool,
    /// The guards that wait for an evaluation with no incident and no
    /// pressure, because the state before a restart was not readable.
    pub held_until_recovery: Vec<Guard>,
    /// The automatic plan in progress.
    pub outstanding: Option<OutstandingReading>,
}

fn generation_readings(
    journal: &OperationJournal,
    budget: &IncidentBudget,
    truncated: &mut bool,
) -> Vec<GenerationReading> {
    if budget.history.len() > MAX_BUDGET_GENERATIONS {
        *truncated = true;
    }
    budget
        .history
        .iter()
        .take(MAX_BUDGET_GENERATIONS)
        .map(|record: &BudgetGenerationRecord| GenerationReading {
            generation: record.generation,
            basis: record.basis,
            authorized_by: record.authorized_by,
            started_at: record.started_at,
            final_usage: record.final_usage,
            journal: match journal.incident_usage(&budget.incident_id, record.generation) {
                Ok(Some(usage)) => JournalUsage::Recorded(usage),
                Ok(None) => JournalUsage::NoConsumedDispatch,
                Err(error) => JournalUsage::Unreadable {
                    reason: error.to_string(),
                },
            },
        })
        .collect()
}

/// The incident state of each budget trigger in the status of the agent,
/// from the texts `budget.ID:STATE` of the memory guard.
fn budget_triggers(status: Option<&ControllerStatus>) -> Vec<(String, Option<TriggerState>)> {
    let Some(status) = status else {
        return Vec::new();
    };
    status
        .guards
        .iter()
        .filter(|guard| guard.guard == Guard::Memory)
        .flat_map(|guard| guard.triggers.iter())
        .filter_map(|text| {
            let rest: &str = text.strip_prefix("budget.")?;
            let (budget_id, state) = rest.rsplit_once(':')?;
            Some((budget_id.to_owned(), trigger_state(state)))
        })
        .collect()
}

/// The trigger state with the JSON spelling `text`.
fn trigger_state(text: &str) -> Option<TriggerState> {
    use TriggerState as State;
    [
        State::Normal,
        State::Advisory,
        State::Qualifying,
        State::Ready,
        State::Acting,
        State::Recovering,
        State::Held,
        State::Cooldown,
        State::Exhausted,
        State::Blocked,
    ]
    .into_iter()
    .find(|state| {
        serde_json::to_value(state)
            .ok()
            .as_ref()
            .and_then(|value| value.as_str())
            == Some(text)
    })
}

/// The application budgets of `state`, with the trigger state of each one
/// in `status`.
fn budget_readings(
    state: &ControllerState,
    status: Option<&ControllerStatus>,
) -> Vec<BudgetReading> {
    let triggers: Vec<(String, Option<TriggerState>)> = budget_triggers(status);
    state
        .policy
        .memory
        .budgets
        .iter()
        .map(|budget| BudgetReading {
            budget_id: budget.budget_id.clone(),
            latched: budget.latched,
            trigger: triggers
                .iter()
                .find(|(id, _)| *id == budget.budget_id)
                .and_then(|(_, trigger)| *trigger),
        })
        .collect()
}

/// The application cooldowns and the pass cooldowns of `state`.
fn policy_cooldowns(
    state: &ControllerState,
    clock: &EvaluationClock,
    truncated: &mut bool,
) -> Vec<CooldownReading> {
    let applications = &state.policy.memory.cooldowns;
    let incidents = &state.policy.disk.incidents;
    if applications.len() > MAX_APPLICATION_COOLDOWNS || incidents.len() > MAX_VOLUMES {
        *truncated = true;
    }
    let application_cooldowns = applications
        .iter()
        .take(MAX_APPLICATION_COOLDOWNS)
        .map(|entry| {
            CooldownReading::of(
                CooldownSubject::Application {
                    application: entry.application.clone(),
                },
                &entry.cooldown,
                clock,
            )
        });
    let pass_cooldowns = incidents.iter().take(MAX_VOLUMES).filter_map(|incident| {
        incident.cooldown.as_ref().map(|cooldown| {
            CooldownReading::of(
                CooldownSubject::DiskIncident {
                    incident_id: state
                        .disk_incident(&incident.domain)
                        .map(|record| record.incident_id.clone()),
                },
                cooldown,
                clock,
            )
        })
    });
    application_cooldowns.chain(pass_cooldowns).collect()
}

/// The open incidents of `state`, and the cooldowns of their records.
fn incident_readings(
    journal: &OperationJournal,
    state: &ControllerState,
    clock: &EvaluationClock,
    truncated: &mut bool,
) -> (Vec<IncidentReading>, Vec<CooldownReading>) {
    let mut incidents: Vec<IncidentReading> = Vec::new();
    let mut cooldowns: Vec<CooldownReading> = Vec::new();
    // One place of `MAX_READ_INCIDENTS` is for the memory incident.
    if state.disk_incidents.len() > MAX_VOLUMES {
        *truncated = true;
    }
    for record in state.disk_incidents.iter().take(MAX_VOLUMES) {
        if let Some(cooldown) = &record.observe_until {
            cooldowns.push(CooldownReading::of(
                CooldownSubject::ObserveAfterAction {
                    incident_id: record.incident_id.clone(),
                },
                cooldown,
                clock,
            ));
        }
        let current_usage = state
            .policy
            .disk
            .incidents
            .iter()
            .find(|incident| incident.domain == record.domain)
            .map(|incident| svalnir_core::grant::IncidentUsage::Disk {
                usage: incident.usage,
                passes_started: incident.passes_started,
            });
        incidents.push(IncidentReading {
            incident_id: record.incident_id.clone(),
            guard: Guard::Disk,
            generation: record.budget.generation,
            established: record.established,
            unknown_outcome: record.unknown_outcome,
            current_usage,
            generations: generation_readings(journal, &record.budget, truncated),
        });
    }
    if let Some(record) = &state.memory_incident {
        let windows = [
            (
                CooldownSubject::ObserveAfterAction {
                    incident_id: record.incident_id.clone(),
                },
                &record.observe_until,
            ),
            (
                CooldownSubject::MemoryBackoff {
                    incident_id: record.incident_id.clone(),
                },
                &record.backoff,
            ),
        ];
        for (subject, cooldown) in windows {
            if let Some(cooldown) = cooldown {
                cooldowns.push(CooldownReading::of(subject, cooldown, clock));
            }
        }
        incidents.push(IncidentReading {
            incident_id: record.incident_id.clone(),
            guard: Guard::Memory,
            generation: record.budget.generation,
            established: record.established,
            unknown_outcome: record.unknown_outcome,
            current_usage: state.policy.memory.incident.map(|incident| {
                svalnir_core::grant::IncidentUsage::Memory {
                    consumed_slots: incident.consumed_slots,
                    reserved_slots: incident.reserved_slots,
                }
            }),
            generations: generation_readings(journal, &record.budget, truncated),
        });
    }
    (incidents, cooldowns)
}

/// The controller reading of a decoded state.
fn controller_reading(
    journal: &OperationJournal,
    stored: &StoredAgentRecord<ControllerState>,
    status: Option<&ControllerStatus>,
    clock: &EvaluationClock,
) -> ControllerReading {
    let state: &ControllerState = &stored.record;
    let mut truncated: bool = false;
    let mut cooldowns: Vec<CooldownReading> = policy_cooldowns(state, clock, &mut truncated);
    let (incidents, incident_cooldowns) = incident_readings(journal, state, clock, &mut truncated);
    cooldowns.extend(incident_cooldowns);
    ControllerReading {
        revision: stored.revision,
        written_at: written_at(stored),
        clean_stop: state.clean_stop,
        budgets: budget_readings(state, status),
        cooldowns,
        incidents,
        truncated,
        held_until_recovery: state.held_until_recovery.clone(),
        outstanding: state.outstanding.as_ref().map(|plan| OutstandingReading {
            guard: plan.guard,
            incident_id: plan.incident_id.clone(),
            plan_id: plan.plan_id.clone(),
            operation_id: plan.operation_id.clone(),
        }),
    }
}

/// Reads the controller state of the journal: the application budgets, the
/// cooldowns with their status at `clock`, and the usage of each budget
/// generation of each open incident.
///
/// `status` is the controller status of the agent, for the trigger state of
/// each budget; give `None` when the client has no status record.
#[must_use]
pub fn read_controller(
    journal: &OperationJournal,
    status: Option<&ControllerStatus>,
    clock: &EvaluationClock,
) -> RecordReading<ControllerReading> {
    match journal.agent_record::<ControllerState>(AgentRecord::Controller) {
        Ok(None) => RecordReading::Absent,
        Err(error) => RecordReading::Unreadable {
            reason: error.to_string(),
        },
        Ok(Some(stored)) if stored.record.schema_version != CONTROLLER_STATE_VERSION => {
            RecordReading::Unreadable {
                reason: format!(
                    "the controller record has the schema version {}",
                    stored.record.schema_version
                ),
            }
        }
        Ok(Some(stored)) => {
            RecordReading::Recorded(controller_reading(journal, &stored, status, clock))
        }
    }
}

/// What the journal does not record about the pause of the agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PauseUnknown {
    /// A pause or a resume ended, and automatic work waits for a
    /// measurement that is newer than that time. The agent does not record
    /// its measurements in the journal, so a client cannot know whether one
    /// newer measurement exists.
    FreshMeasurement,
}

/// What the latest step of the agent saw, from its status record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentStepPause {
    /// The wall-clock time of the step.
    pub evaluated_at: WallTime,
    /// Whether a pause was in effect at the step.
    pub paused: bool,
    /// The wall-clock end of a timed pause at the step.
    pub paused_until: Option<WallTime>,
    /// True when a guard waited for a fresh measurement after the end of a
    /// pause at the step.
    pub awaiting_fresh_measurement: bool,
    /// The freshness of the status record.
    pub freshness: Freshness,
}

/// The pause as the agent decides it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PauseReading {
    /// The status of the pause of the authority record at the clock of this
    /// process. The agent of this build has no pause that it does not
    /// record (`InstanceInhibition::pause` is always `None`), so in the
    /// boot of the record this is the status that the agent decides at the
    /// same time. A pause of a different boot is
    /// [`PauseBasis::Retained`](svalnir_core::grant::PauseBasis), as it is
    /// for the agent.
    pub status: PauseStatus,
    /// The pause at the latest step of the agent. `None` with no usable
    /// status record.
    pub agent_step: Option<AgentStepPause>,
    /// What the reading cannot know. It has
    /// [`PauseUnknown::FreshMeasurement`] when the pause is expired or when
    /// the latest step of the agent waited for a fresh measurement.
    pub unknown: Vec<PauseUnknown>,
}

/// The pause of `authority` at `clock`, with the step of the agent of
/// `status`.
#[must_use]
pub fn pause_reading(
    authority: &AuthorityState,
    status: Option<&StatusReading>,
    clock: &ClientClock,
) -> PauseReading {
    let pause_status: PauseStatus = pause_status(authority.pause.as_ref(), &clock.control());
    let agent_step: Option<AgentStepPause> = status.and_then(|reading| {
        let controller: &ControllerStatus = reading.status.controller.as_ref()?;
        Some(AgentStepPause {
            evaluated_at: controller.evaluated_at,
            paused: controller.paused,
            paused_until: controller.paused_until,
            awaiting_fresh_measurement: controller.guards.iter().any(|guard| {
                guard
                    .blocked
                    .contains(&BlockedReason::AwaitingFreshMeasurement)
            }),
            freshness: reading.freshness,
        })
    });
    let mut unknown: Vec<PauseUnknown> = Vec::new();
    if matches!(pause_status, PauseStatus::Expired { .. })
        || agent_step
            .as_ref()
            .is_some_and(|step| step.awaiting_fresh_measurement)
    {
        unknown.push(PauseUnknown::FreshMeasurement);
    }
    PauseReading {
        status: pause_status,
        agent_step,
        unknown,
    }
}

/// The agent records of one journal for a client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentRecordsReading {
    /// The status record of the agent.
    pub status: RecordReading<StatusReading>,
    /// The controller state.
    pub controller: RecordReading<ControllerReading>,
    /// The pause. An authority record that cannot be read gives no pause.
    pub pause: RecordReading<PauseReading>,
}

/// Reads the agent records of an open journal at `clock`.
#[must_use]
pub fn read_agent_records(
    journal: &OperationJournal,
    uid: Uid,
    clock: &ClientClock,
) -> AgentRecordsReading {
    let status: RecordReading<StatusReading> = read_status(journal, clock.wall);
    let controller_status: Option<&ControllerStatus> = status
        .recorded()
        .and_then(|reading| reading.status.controller.as_ref());
    let controller: RecordReading<ControllerReading> =
        read_controller(journal, controller_status, &clock.clock);
    let pause: RecordReading<PauseReading> = match read_authority(journal, uid) {
        Ok(stored) => {
            RecordReading::Recorded(pause_reading(&stored.state, status.recorded(), clock))
        }
        Err(error) => RecordReading::Unreadable {
            reason: error.to_string(),
        },
    };
    AgentRecordsReading {
        status,
        controller,
        pause,
    }
}

/// Opens the journal at `journal_path` for reads only and reads its agent
/// records at `clock`. The function makes no file and writes nothing.
#[must_use]
pub fn read_agent_records_at(
    journal_path: &Path,
    uid: Uid,
    clock: &ClientClock,
) -> JournalReading<AgentRecordsReading> {
    match open_existing_journal_read_only(journal_path) {
        Ok(None) => JournalReading::Absent,
        Err(error) => JournalReading::Unreadable {
            reason: error.to_string(),
        },
        Ok(Some(journal)) => JournalReading::Read(read_agent_records(&journal, uid, clock)),
    }
}
