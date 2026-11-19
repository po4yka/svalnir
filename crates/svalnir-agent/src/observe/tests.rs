//! Tests of the readings of a client. Each test uses a journal in its own
//! temporary directory. No test reads the clocks of the host, changes a file
//! outside its directory, or signals a process.

use std::path::{Path, PathBuf};

use svalnir_core::authority::Generation;
use svalnir_core::grant::{
    AuthorityState, BudgetGenerationRecord, GenerationBasis, IncidentBudget, Pause, PauseBasis,
    PauseDeadline, PauseStatus,
};
use svalnir_core::id::{BootId, ClockDomainId, ExecutorEpochId, IncidentId};
use svalnir_core::policy::{
    ApplicationCooldown, BudgetState, ContinuityGeneration, Cooldown, CooldownCause,
    CooldownStatus, EvaluationClock, MemoryIncident, PolicyId, QualificationWindow, TriggerState,
};
use svalnir_core::process::Uid;
use svalnir_core::quantity::{Bytes, EntryCount, Nanoseconds};
use svalnir_core::time::{MonotonicNanos, WallTime};
use tempfile::TempDir;

use super::{
    AgentCapabilityReading, ClientClock, ControllerReading, CooldownSubject, Freshness,
    JournalReading, JournalUsage, PauseUnknown, RecordReading, STATUS_MAX_AGE,
    read_agent_records_at,
};
use crate::controller::{
    BlockedReason, CONTROLLER_STATUS_VERSION, ControllerState, ControllerStatus, Guard, GuardPhase,
    GuardStatus, MemoryIncidentRecord, Summary,
};
use crate::journal::{AgentRecord, IncidentUsage, JournalOptions, OperationJournal};
use crate::runtime::{AGENT_STATUS_VERSION, AgentStatus, PolicySource, RunState, SelfLimits};

const USER: Uid = Uid::new(501);
const SECOND: u64 = 1_000_000_000;
const DOMAIN: &str = "macos.clock_monotonic_raw";
const BOOT: &str = "boot_a";

fn wall(seconds: i64) -> WallTime {
    WallTime::from_unix(1_800_000_000 + seconds, 0).unwrap()
}

fn clock_at(boot: &str, monotonic_seconds: u64, wall_seconds: i64) -> ClientClock {
    ClientClock {
        clock: EvaluationClock {
            now: MonotonicNanos::new(monotonic_seconds * SECOND),
            clock_domain: ClockDomainId::new(DOMAIN).unwrap(),
            boot_id: BootId::new(boot).unwrap(),
            continuity: ContinuityGeneration::new(0),
            last_discontinuity: None,
        },
        wall: wall(wall_seconds),
    }
}

fn clock(monotonic_seconds: u64, wall_seconds: i64) -> ClientClock {
    clock_at(BOOT, monotonic_seconds, wall_seconds)
}

struct Fixture {
    _directory: TempDir,
    path: PathBuf,
}

impl Fixture {
    /// A directory with a journal that has the schema and no record.
    fn new() -> Self {
        let directory: TempDir = tempfile::tempdir().unwrap();
        let path: PathBuf = directory.path().join("operations.sqlite");
        drop(writer(&path));
        Self {
            _directory: directory,
            path,
        }
    }

    fn put<T: serde::Serialize>(&self, name: AgentRecord, record: &T, at: i64) {
        writer(&self.path)
            .put_agent_record(name, record, None, wall(at))
            .unwrap();
    }

    fn read(&self, clock: &ClientClock) -> super::AgentRecordsReading {
        match read_agent_records_at(&self.path, USER, clock) {
            JournalReading::Read(reading) => reading,
            other => panic!("the journal was not read: {other:?}"),
        }
    }
}

fn writer(path: &Path) -> OperationJournal {
    let options = JournalOptions {
        full_fsync: false,
        ..JournalOptions::default()
    };
    OperationJournal::open(path, &options).unwrap()
}

fn cooldown(boot: &str, until_seconds: u64) -> Cooldown {
    Cooldown {
        cause: CooldownCause::ApplicationRelaunch,
        until: MonotonicNanos::new(until_seconds * SECOND),
        clock_domain: ClockDomainId::new(DOMAIN).unwrap(),
        boot_id: BootId::new(boot).unwrap(),
    }
}

fn controller_status(triggers: Vec<String>, blocked: Vec<BlockedReason>) -> ControllerStatus {
    ControllerStatus {
        schema_version: CONTROLLER_STATUS_VERSION,
        evaluated_at: wall(0),
        summary: Summary::Normal,
        paused: false,
        paused_until: None,
        observation_only: false,
        guards: vec![GuardStatus {
            guard: Guard::Memory,
            standing: "active".to_owned(),
            phase: GuardPhase::Normal,
            triggers,
            blocked,
            incidents: Vec::new(),
        }],
        outstanding_plan: None,
        outstanding_operation: None,
        degraded: Vec::new(),
        optional_work_reduced: false,
    }
}

fn agent_status(
    written_at: i64,
    state: RunState,
    controller: Option<ControllerStatus>,
) -> AgentStatus {
    AgentStatus {
        schema_version: AGENT_STATUS_VERSION,
        executor_epoch: ExecutorEpochId::new("epoch_1").unwrap(),
        process_id: 4242,
        started_at: wall(0),
        written_at: wall(written_at),
        state,
        controller,
        policy: PolicySource {
            revision: None,
            problem: None,
        },
        capabilities: None,
        limits: SelfLimits {
            footprint_bytes: None,
            budget_bytes: 64 * 1024 * 1024,
            over_budget: false,
            optional_work_reduced: false,
        },
        degraded: Vec::new(),
        unclean_stops: 0,
        restart_backoff: false,
    }
}

/// A memory incident with two budget generations: the first ended with a
/// rearm, and the second is current.
fn memory_incident() -> MemoryIncidentRecord {
    let incident_id: IncidentId = IncidentId::new("incident_m").unwrap();
    MemoryIncidentRecord {
        incident_id: incident_id.clone(),
        budget: IncidentBudget {
            incident_id,
            policy: PolicyId::MemoryGuard,
            generation: Generation::new(2),
            history: vec![
                BudgetGenerationRecord {
                    generation: Generation::new(1),
                    basis: GenerationBasis::IncidentOpened,
                    authorized_by: None,
                    started_at: wall(0),
                    final_usage: Some(svalnir_core::grant::IncidentUsage::Memory {
                        consumed_slots: 3,
                        reserved_slots: 0,
                    }),
                },
                BudgetGenerationRecord {
                    generation: Generation::new(2),
                    basis: GenerationBasis::Rearmed,
                    authorized_by: Some(USER),
                    started_at: wall(50),
                    final_usage: None,
                },
            ],
            volatile_exception_at_open: false,
        },
        opened_in: ExecutorEpochId::new("epoch_1").unwrap(),
        established: true,
        unknown_outcome: false,
        observe_until: Some(Cooldown {
            cause: CooldownCause::ApplicationRelaunch,
            ..cooldown(BOOT, 120)
        }),
        backoff: None,
        last_refusal: None,
        refusals: 0,
    }
}

fn controller_state() -> ControllerState {
    let mut state: ControllerState = ControllerState::default();
    state.policy.memory.budgets = vec![BudgetState {
        budget_id: "build-worker".to_owned(),
        stop_window: QualificationWindow::Idle,
        recovery_window: QualificationWindow::Idle,
        latched: true,
    }];
    state.policy.memory.cooldowns = vec![
        ApplicationCooldown {
            application: "com.example.Active".to_owned(),
            cooldown: cooldown(BOOT, 400),
        },
        ApplicationCooldown {
            application: "com.example.Elapsed".to_owned(),
            cooldown: cooldown(BOOT, 50),
        },
        ApplicationCooldown {
            application: "com.example.OtherBoot".to_owned(),
            cooldown: cooldown("boot_b", 50),
        },
    ];
    state.policy.memory.incident = Some(MemoryIncident {
        consumed_slots: 1,
        reserved_slots: 1,
        outstanding_operation: false,
    });
    state.memory_incident = Some(memory_incident());
    state
}

/// Writes the usage row of one generation, as a consumed dispatch does.
fn put_usage(path: &Path, incident_id: &str, generation: i64, slots: i64) {
    let connection = rusqlite::Connection::open(path).unwrap();
    connection
        .execute(
            "INSERT INTO incident_usage \
             (incident_id, generation, slots, work_bytes, items, last_admitted_unix_s) \
             VALUES (?1, ?2, ?3, 0, 0, 1800000000)",
            rusqlite::params![incident_id, generation, slots],
        )
        .unwrap();
}

#[test]
fn an_absent_journal_is_absent_and_no_file_is_made() {
    let directory: TempDir = tempfile::tempdir().unwrap();
    let path: PathBuf = directory.path().join("operations.sqlite");
    assert!(matches!(
        read_agent_records_at(&path, USER, &clock(100, 100)),
        JournalReading::Absent
    ));
    assert!(
        std::fs::read_dir(directory.path())
            .unwrap()
            .next()
            .is_none()
    );
}

#[test]
fn a_journal_that_cannot_be_read_is_unreadable() {
    let directory: TempDir = tempfile::tempdir().unwrap();
    let garbage: PathBuf = directory.path().join("garbage.sqlite");
    std::fs::write(&garbage, b"this is not a database").unwrap();
    let empty: PathBuf = directory.path().join("empty.sqlite");
    std::fs::write(&empty, b"").unwrap();
    for path in [garbage, empty, directory.path().to_path_buf()] {
        assert!(
            matches!(
                read_agent_records_at(&path, USER, &clock(100, 100)),
                JournalReading::Unreadable { .. }
            ),
            "{}",
            path.display()
        );
    }
}

#[test]
fn a_journal_with_no_record_gives_absent_records_and_no_pause() {
    let fixture: Fixture = Fixture::new();
    let reading = fixture.read(&clock(100, 100));
    assert_eq!(reading.status, RecordReading::Absent);
    assert_eq!(reading.controller, RecordReading::Absent);
    let pause = reading.pause.recorded().unwrap();
    assert_eq!(pause.status, PauseStatus::NotPaused);
    assert_eq!(pause.agent_step, None);
    assert_eq!(pause.unknown, Vec::new());
}

#[test]
fn the_freshness_of_the_status_follows_its_age_and_state() {
    let fixture: Fixture = Fixture::new();
    fixture.put(
        AgentRecord::Status,
        &agent_status(100, RunState::Running, None),
        100,
    );
    let freshness = |wall_seconds: i64| match fixture.read(&clock(1, wall_seconds)).status {
        RecordReading::Recorded(status) => status.freshness,
        other => panic!("{other:?}"),
    };
    assert_eq!(
        freshness(130),
        Freshness::Current {
            age: Nanoseconds::new(30 * SECOND)
        }
    );
    assert_eq!(
        freshness(190),
        Freshness::Current {
            age: STATUS_MAX_AGE
        }
    );
    assert_eq!(
        freshness(191),
        Freshness::Stale {
            age: Nanoseconds::new(91 * SECOND)
        }
    );
    // A wall clock before the status gives no age.
    assert_eq!(freshness(99), Freshness::Unknown);

    fixture.put(
        AgentRecord::Status,
        &agent_status(100, RunState::Stopped, None),
        100,
    );
    assert_eq!(freshness(10_000), Freshness::Stopped);

    let mut other_version: AgentStatus = agent_status(100, RunState::Running, None);
    other_version.schema_version = AGENT_STATUS_VERSION + 1;
    fixture.put(AgentRecord::Status, &other_version, 100);
    assert!(matches!(
        fixture.read(&clock(1, 100)).status,
        RecordReading::Unreadable { .. }
    ));
}

#[test]
fn the_capability_summary_of_the_agent_has_the_freshness_of_its_status() {
    use crate::capability::{CapabilityId, Requirement};
    use crate::runtime::{CapabilityLine, CapabilitySummary};
    use svalnir_core::state::CapabilityState;

    let fixture: Fixture = Fixture::new();
    let capabilities = |wall_seconds: i64| {
        super::agent_capabilities(&fixture.read(&clock(1, wall_seconds)).status)
    };
    // No status record: no agent wrote one.
    assert_eq!(capabilities(100), AgentCapabilityReading::NoStatus);

    // A status record with no summary is not a summary with no line.
    fixture.put(
        AgentRecord::Status,
        &agent_status(100, RunState::Running, None),
        100,
    );
    assert_eq!(
        capabilities(130),
        AgentCapabilityReading::NotRecorded {
            freshness: Freshness::Current {
                age: Nanoseconds::new(30 * SECOND)
            }
        }
    );

    let summary: CapabilitySummary = CapabilitySummary {
        verdict: "blocked".to_owned(),
        required_not_available: vec!["metrics.swap_usage".to_owned()],
        probed_at: Some(wall(90)),
        lines: vec![CapabilityLine {
            id: CapabilityId::MetricsSwapUsage,
            title: "Swap usage query".to_owned(),
            requirement: Requirement::Required,
            state: CapabilityState::Denied,
            detail: "The system refused the query: injected".to_owned(),
            remediation: None,
        }],
        notifications: None,
    };
    let mut status: AgentStatus = agent_status(100, RunState::Running, None);
    status.capabilities = Some(summary.clone());
    fixture.put(AgentRecord::Status, &status, 100);
    assert_eq!(
        capabilities(400),
        AgentCapabilityReading::Recorded {
            summary: summary.clone(),
            freshness: Freshness::Stale {
                age: Nanoseconds::new(300 * SECOND)
            }
        }
    );

    // A record of a different schema version is not a summary.
    status.schema_version = AGENT_STATUS_VERSION + 1;
    fixture.put(AgentRecord::Status, &status, 100);
    assert!(matches!(
        capabilities(130),
        AgentCapabilityReading::Unreadable { .. }
    ));
}

#[test]
fn the_controller_reading_has_the_budgets_the_cooldowns_and_the_usage_of_each_generation() {
    let fixture: Fixture = Fixture::new();
    fixture.put(
        AgentRecord::Controller,
        &controller_state().durable_view(),
        60,
    );
    fixture.put(
        AgentRecord::Status,
        &agent_status(
            100,
            RunState::Running,
            Some(controller_status(
                vec![
                    "global:normal".to_owned(),
                    "budget.build-worker:cooldown".to_owned(),
                ],
                Vec::new(),
            )),
        ),
        100,
    );
    put_usage(&fixture.path, "incident_m", 1, 3);

    let reading = fixture.read(&clock(100, 110));
    let controller: &ControllerReading = reading.controller.recorded().unwrap();
    assert_eq!(controller.revision, 1);
    assert_eq!(controller.written_at, Some(wall(60)));
    assert!(!controller.clean_stop);
    assert!(!controller.truncated);

    assert_eq!(controller.budgets.len(), 1);
    assert_eq!(controller.budgets[0].budget_id, "build-worker");
    assert!(controller.budgets[0].latched);
    assert_eq!(controller.budgets[0].trigger, Some(TriggerState::Cooldown));

    let status_of = |application: &str| {
        controller
            .cooldowns
            .iter()
            .find(|cooldown| {
                cooldown.subject
                    == CooldownSubject::Application {
                        application: application.to_owned(),
                    }
            })
            .map(|cooldown| cooldown.status)
            .unwrap()
    };
    assert_eq!(
        status_of("com.example.Active"),
        CooldownStatus::Active {
            remaining: Nanoseconds::new(300 * SECOND)
        }
    );
    assert_eq!(status_of("com.example.Elapsed"), CooldownStatus::Elapsed);
    // A cooldown of a different boot inhibits, as it does for the agent.
    assert_eq!(status_of("com.example.OtherBoot"), CooldownStatus::Unknown);
    assert!(controller.cooldowns.iter().any(|cooldown| matches!(
        &cooldown.subject,
        CooldownSubject::ObserveAfterAction { incident_id } if incident_id.as_str() == "incident_m"
    )));

    assert_eq!(controller.incidents.len(), 1);
    let incident = &controller.incidents[0];
    assert_eq!(incident.guard, Guard::Memory);
    assert_eq!(incident.generation, Generation::new(2));
    assert_eq!(
        incident.current_usage,
        Some(svalnir_core::grant::IncidentUsage::Memory {
            consumed_slots: 1,
            reserved_slots: 1
        })
    );
    assert_eq!(incident.generations.len(), 2);
    assert_eq!(
        incident.generations[0].journal,
        JournalUsage::Recorded(IncidentUsage {
            slots: 3,
            work: svalnir_core::action::WorkCharge::new(Bytes::ZERO, EntryCount::ZERO),
        })
    );
    // The current generation has no consumed dispatch: no row.
    assert_eq!(
        incident.generations[1].journal,
        JournalUsage::NoConsumedDispatch
    );
    assert_eq!(incident.generations[1].basis, GenerationBasis::Rearmed);
    assert_eq!(incident.generations[1].authorized_by, Some(USER));
}

#[test]
fn a_controller_record_that_this_build_cannot_read_is_unreadable() {
    let fixture: Fixture = Fixture::new();
    let mut other_version: ControllerState = ControllerState::default();
    other_version.schema_version += 1;
    fixture.put(AgentRecord::Controller, &other_version, 1);
    assert!(matches!(
        fixture.read(&clock(1, 1)).controller,
        RecordReading::Unreadable { .. }
    ));
    fixture.put(
        AgentRecord::Controller,
        &serde_json::json!({ "schema_version": 1, "unknown": true }),
        1,
    );
    assert!(matches!(
        fixture.read(&clock(1, 1)).controller,
        RecordReading::Unreadable { .. }
    ));
}

fn paused_until(boot: &str, monotonic_seconds: u64) -> AuthorityState {
    let mut state: AuthorityState = AuthorityState::new(USER);
    state.pause = Some(Pause {
        started_wall: wall(0),
        deadline: Some(PauseDeadline {
            monotonic: MonotonicNanos::new(monotonic_seconds * SECOND),
            clock_domain: ClockDomainId::new(DOMAIN).unwrap(),
            boot_id: BootId::new(boot).unwrap(),
            wall: wall(i64::try_from(monotonic_seconds).unwrap()),
        }),
    });
    state
}

#[test]
fn the_pause_is_decided_on_the_monotonic_clock_of_its_boot() {
    let fixture: Fixture = Fixture::new();
    fixture.put(AgentRecord::Authority, &paused_until(BOOT, 300), 1);

    // The wall clock is past the recorded end; the monotonic clock is not.
    let pause = fixture.read(&clock(200, 10_000)).pause;
    let pause = pause.recorded().unwrap();
    assert_eq!(
        pause.status,
        PauseStatus::Paused {
            remaining: Some(Nanoseconds::new(100 * SECOND)),
            until: Some(wall(300)),
            basis: PauseBasis::Monotonic,
        }
    );
    assert_eq!(pause.unknown, Vec::new());

    // At the end, the pause is expired, and the reading cannot know whether
    // the agent has a newer measurement.
    let expired = fixture.read(&clock(300, 0)).pause;
    let expired = expired.recorded().unwrap();
    assert_eq!(
        expired.status,
        PauseStatus::Expired {
            floor: MonotonicNanos::new(300 * SECOND)
        }
    );
    assert_eq!(expired.unknown, vec![PauseUnknown::FreshMeasurement]);

    // A pause of a different boot stays until a resume.
    let retained = fixture.read(&clock_at("boot_b", 999, 999)).pause;
    assert!(matches!(
        retained.recorded().unwrap().status,
        PauseStatus::Paused {
            basis: PauseBasis::Retained,
            ..
        }
    ));
}

#[test]
fn the_pause_reading_has_the_step_of_the_agent() {
    let fixture: Fixture = Fixture::new();
    let mut controller: ControllerStatus =
        controller_status(Vec::new(), vec![BlockedReason::AwaitingFreshMeasurement]);
    controller.evaluated_at = wall(90);
    fixture.put(
        AgentRecord::Status,
        &agent_status(90, RunState::Running, Some(controller)),
        90,
    );
    let reading = fixture.read(&clock(1, 100));
    let pause = reading.pause.recorded().unwrap();
    assert_eq!(pause.status, PauseStatus::NotPaused);
    let step = pause.agent_step.as_ref().unwrap();
    assert!(step.awaiting_fresh_measurement);
    assert_eq!(step.evaluated_at, wall(90));
    assert!(matches!(step.freshness, Freshness::Current { .. }));
    assert_eq!(pause.unknown, vec![PauseUnknown::FreshMeasurement]);
}

#[test]
fn an_authority_record_of_a_different_user_gives_no_pause() {
    let fixture: Fixture = Fixture::new();
    fixture.put(
        AgentRecord::Authority,
        &AuthorityState::new(Uid::new(502)),
        1,
    );
    assert!(matches!(
        fixture.read(&clock(1, 1)).pause,
        RecordReading::Unreadable { .. }
    ));
}

#[test]
fn a_reading_does_not_change_the_journal_file() {
    let fixture: Fixture = Fixture::new();
    fixture.put(
        AgentRecord::Controller,
        &controller_state().durable_view(),
        60,
    );
    fixture.put(AgentRecord::Authority, &paused_until(BOOT, 300), 60);
    let before: Vec<u8> = std::fs::read(&fixture.path).unwrap();
    let _reading = fixture.read(&clock(100, 100));
    assert_eq!(std::fs::read(&fixture.path).unwrap(), before);
}
