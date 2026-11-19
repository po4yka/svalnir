//! The fixed data of the Memory, Applications, Automation, History, and
//! Diagnostics screens for each fixture scenario. Values are not
//! measurements.

use super::{
    fixture::FixtureScenario,
    model::{GuardRow, Measured, OperationPhase},
    records::{
        AgentStatusRow, ApplicationRow, AutomationSnapshot, BudgetRow, CapabilityLevel,
        CapabilityRow, ControllerRows, ControllerSnapshot, CooldownRow, CooldownState,
        CooldownSubject, DiagnosticsSnapshot, EffectRow, Foreground, FreshMeasurement,
        GenerationRow, GrantRow, GroupKind, Growth, GuardDetail, HistorySnapshot, IncidentRow,
        IncidentUsage, JournalRow, JournalUsageRow, MemorySnapshot, Need, OperationDetail,
        PauseKind, PauseRow, ProcessRow, ProcessesSnapshot, Protection, ProtectionReason,
        RevisionRow, StartFailureRow, StatusAge, ThresholdRow, TriggerRow, UnknownCause, UsageRow,
        Verdict, rank_applications, rank_processes,
    },
};
use std::{
    path::PathBuf,
    time::{Duration, SystemTime},
};
use svalnir_core::{action::ActionClass, grant::GuardStanding, policy::PolicyId};

const MB: u64 = 1_000_000;
const GB: u64 = 1_000_000_000;
const SOURCE: &str = "fixture";

/// The time of a reading: 12 minutes in the past for the `stale` scenario.
fn reading_time(scenario: FixtureScenario) -> SystemTime {
    let now: SystemTime = SystemTime::now();
    if scenario == FixtureScenario::Stale {
        now.checked_sub(Duration::from_mins(12)).unwrap_or(now)
    } else {
        now
    }
}

fn back(now: SystemTime, seconds: u64) -> SystemTime {
    now.checked_sub(Duration::from_secs(seconds)).unwrap_or(now)
}

fn not_in_fixture(what: &str) -> String {
    format!("{what} is not available in this fixture")
}

/// The memory quantities of `scenario`.
pub(super) fn memory(scenario: FixtureScenario) -> Result<MemorySnapshot, String> {
    let mut snapshot = MemorySnapshot {
        captured_at: reading_time(scenario),
        wired: Measured::Value(4 * GB + 200 * MB),
        compressor: Measured::Value(2 * GB + 100 * MB),
        compressed_data: Measured::Value(6 * GB + 400 * MB),
        free: Measured::Value(3 * GB + 900 * MB),
        source: SOURCE,
    };
    match scenario {
        FixtureScenario::Unavailable => return Err(not_in_fixture("the memory reading")),
        FixtureScenario::Pressure => {
            snapshot.compressor = Measured::Value(7 * GB + 800 * MB);
            snapshot.compressed_data = Measured::Value(21 * GB);
            snapshot.free = Measured::Value(180 * MB);
        }
        _ => {}
    }
    Ok(snapshot)
}

/// One fixture process: the PID, the name, the group, and the footprint and
/// the resident size in MB. A footprint of `None` is an unavailable value.
type FixtureProcess = (i32, &'static str, Option<&'static str>, Option<u64>, u64);

const PROCESSES: [FixtureProcess; 12] = [
    (412, "Xcode", Some("com.apple.dt.Xcode"), Some(3_840), 2_950),
    (
        418,
        "SourceKitService",
        Some("com.apple.dt.Xcode"),
        Some(1_260),
        990,
    ),
    (731, "Safari", Some("com.apple.Safari"), Some(940), 610),
    (
        742,
        "com.apple.WebKit.WebContent",
        Some("com.apple.Safari"),
        Some(1_480),
        1_120,
    ),
    (
        743,
        "com.apple.WebKit.WebContent",
        Some("com.apple.Safari"),
        None,
        0,
    ),
    (655, "Finder", Some("com.apple.finder"), Some(310), 240),
    (903, "Terminal", Some("com.apple.Terminal"), Some(180), 150),
    (1204, "svalnir-gui", Some("dev.svalnir.gui"), Some(140), 120),
    (
        377,
        "sync-agent",
        Some("com.example.sync.agent"),
        Some(96),
        70,
    ),
    (2210, "cargo", None, Some(520), 480),
    (2231, "rustc", None, Some(2_050), 1_900),
    (188, "distnoted", None, Some(12), 9),
];

/// One fixture group: the name, the kind, the foreground state, and the
/// protection.
type FixtureGroup = (&'static str, GroupKind, Foreground, Protection);

/// The footprint change of a fixture process since the previous reading, in
/// MB, over 5 s. `None`: the process is new since that reading.
fn fixture_growth(pid: i32, scale: u64) -> Measured<Growth> {
    let megabytes: i128 = match pid {
        412 => 24,
        418 => 6,
        731 => -3,
        742 => 18,
        2231 => 140,
        2210 => 0,
        // A process that started after the previous reading.
        377 => {
            return Measured::Unavailable(
                "the process is new since the previous reading".to_owned(),
            );
        }
        _ => 1,
    };
    Measured::Value(Growth {
        delta: megabytes * i128::from(MB) * i128::from(scale),
        elapsed: Duration::from_secs(5),
    })
}

const GROUPS: [FixtureGroup; 6] = [
    (
        "com.apple.dt.Xcode",
        GroupKind::Application,
        Foreground::Foreground,
        Protection::NotProtected,
    ),
    (
        "com.apple.Safari",
        GroupKind::Application,
        Foreground::Background,
        Protection::NotProtected,
    ),
    (
        "com.apple.finder",
        GroupKind::Application,
        Foreground::Background,
        Protection::Protected {
            reason: ProtectionReason::SessionApplication,
        },
    ),
    (
        "com.apple.Terminal",
        GroupKind::Application,
        Foreground::Background,
        Protection::Unknown {
            cause: UnknownCause::NoExecutableEvidence,
        },
    ),
    (
        "dev.svalnir.gui",
        GroupKind::Application,
        Foreground::Background,
        Protection::Protected {
            reason: ProtectionReason::ControlPlaneBundle,
        },
    ),
    (
        "com.example.sync.agent",
        GroupKind::ManagedJob,
        Foreground::Unknown,
        Protection::NotProtected,
    ),
];

/// The processes of `scenario`.
pub(super) fn processes(scenario: FixtureScenario) -> Result<ProcessesSnapshot, String> {
    if scenario == FixtureScenario::Unavailable {
        return Err(not_in_fixture("the process list"));
    }
    // Under pressure each footprint is larger.
    let scale: u64 = if scenario == FixtureScenario::Pressure {
        3
    } else {
        1
    };
    let rows: Vec<ProcessRow> = PROCESSES
        .iter()
        .map(|(pid, name, group, footprint, resident)| ProcessRow {
            pid: *pid,
            name: Some((*name).to_owned()),
            group: group.map(str::to_owned),
            footprint: footprint.map_or_else(
                || Measured::Unavailable("the process exited during the reading".to_owned()),
                |megabytes| Measured::Value(megabytes * MB * scale),
            ),
            resident: if footprint.is_some() {
                Measured::Value(resident * MB * scale)
            } else {
                Measured::Unavailable("the process exited during the reading".to_owned())
            },
            growth: if footprint.is_some() {
                fixture_growth(*pid, scale)
            } else {
                Measured::Unavailable("the process exited during the reading".to_owned())
            },
        })
        .collect();
    let applications: Vec<ApplicationRow> = GROUPS
        .iter()
        .map(|(name, kind, foreground, protection)| {
            let members: Vec<&ProcessRow> = rows
                .iter()
                .filter(|row| row.group.as_deref() == Some(*name))
                .collect();
            let measured: Vec<u64> = members
                .iter()
                .filter_map(|row| row.footprint.value().copied())
                .collect();
            let changes: Vec<Growth> = members
                .iter()
                .filter_map(|row| row.growth.value().copied())
                .collect();
            ApplicationRow {
                growth: if changes.is_empty() {
                    Measured::Unavailable(
                        "the process is new since the previous reading".to_owned(),
                    )
                } else {
                    Measured::Value(Growth {
                        delta: changes.iter().map(|change| change.delta).sum(),
                        elapsed: Duration::from_secs(5),
                    })
                },
                growth_missing: members.len() - changes.len(),
                instance: format!("fixture-{name}"),
                name: (*name).to_owned(),
                kind: *kind,
                members: members.len(),
                footprint: Measured::Value(measured.iter().sum()),
                unmeasured_members: members.len() - measured.len(),
                foreground: *foreground,
                protection: *protection,
            }
        })
        .collect();
    Ok(ProcessesSnapshot {
        captured_at: reading_time(scenario),
        process_count: rows.len(),
        unattributed: rows.iter().filter(|row| row.group.is_none()).count(),
        processes: rank_processes(rows),
        application_count: applications.len(),
        applications: rank_applications(applications),
        other_user: 148,
        not_readable: 2,
        notes: Vec::new(),
        source: SOURCE,
    })
}

/// The standing of `policy` in `scenario`; the same rule as the service
/// snapshot of the fixture.
fn standing(scenario: FixtureScenario, policy: PolicyId) -> GuardStanding {
    match scenario {
        FixtureScenario::Healthy | FixtureScenario::Stale | FixtureScenario::Drift => {
            if policy == PolicyId::DiskGuard {
                GuardStanding::Active
            } else {
                GuardStanding::Disabled
            }
        }
        FixtureScenario::Pressure => GuardStanding::Active,
        FixtureScenario::Unavailable => GuardStanding::Disabled,
        FixtureScenario::AgentAbsent => GuardStanding::NoActiveRevision,
    }
}

fn thresholds(policy: PolicyId) -> Vec<ThresholdRow> {
    // The stored values of a policy scope: a size in bytes, a time in
    // nanoseconds. The row takes the unit of the configuration field.
    const GIB: u64 = 1024 * 1024 * 1024;
    const MINUTE: u64 = 60_000_000_000;
    let pairs: &[(&str, u64)] = if policy == PolicyId::DiskGuard {
        &[
            ("disk_guard.warn_below", 40 * GIB),
            ("disk_guard.reclaim_below", 25 * GIB),
            ("disk_guard.emergency_below", 10 * GIB),
            ("disk_guard.recover_above", 50 * GIB),
            ("disk_guard.sustain_for", 2 * MINUTE),
            ("disk_guard.max_passes_per_incident", 3),
        ]
    } else {
        &[
            ("memory_guard.sustain_for", 2 * MINUTE),
            ("memory_guard.grace_period", 10_000_000_000),
            ("memory_guard.max_applications_per_incident", 2),
            (
                "memory_guard.app_budgets[build-worker].footprint_stop",
                6 * GIB,
            ),
            (
                "memory_guard.app_budgets[build-worker].cooldown",
                15 * MINUTE,
            ),
        ]
    };
    pairs
        .iter()
        .map(|(key, value)| ThresholdRow::of(key, *value))
        .collect()
}

/// The pause and the problems of `scenario`.
fn fixture_pause(snapshot: &mut AutomationSnapshot, scenario: FixtureScenario) {
    let captured_at: SystemTime = snapshot.captured_at;
    match scenario {
        FixtureScenario::Pressure => {
            snapshot.pause = Some(PauseRow::Paused {
                since: back(captured_at, 600),
                remaining: Some(Duration::from_mins(20)),
                until: Some(captured_at + Duration::from_mins(20)),
                kind: PauseKind::Timed,
            });
        }
        FixtureScenario::Stale => {
            snapshot.pause = Some(PauseRow::Paused {
                since: back(captured_at, 7200),
                remaining: None,
                until: None,
                kind: PauseKind::Indefinite,
            });
        }
        FixtureScenario::Drift => {
            snapshot.pause = Some(PauseRow::Expired {
                since: back(captured_at, 3700),
            });
            snapshot.measurement = FreshMeasurement::Awaiting;
        }
        FixtureScenario::Unavailable => {
            snapshot.revision = None;
            snapshot.guards.clear();
            snapshot.pause = None;
            snapshot
                .problems
                .push("The authority record cannot be read in this fixture.".to_owned());
        }
        _ => {}
    }
}

/// The authority record of `scenario`.
pub(super) fn automation(scenario: FixtureScenario) -> AutomationSnapshot {
    let captured_at: SystemTime = reading_time(scenario);
    let present: bool = scenario != FixtureScenario::AgentAbsent;
    let mut snapshot = AutomationSnapshot {
        captured_at,
        journal_present: present,
        revision: present.then(|| RevisionRow {
            id: "rev-fixture-1".to_owned(),
            activated_at: back(captured_at, 3 * 86_400),
            profile: "balanced".to_owned(),
        }),
        guards: PolicyId::ALL
            .iter()
            .map(|policy| {
                let standing: GuardStanding = standing(scenario, *policy);
                let row: GuardRow = GuardRow::new(policy.as_str(), standing);
                let granted: bool = standing == GuardStanding::Active;
                GuardDetail {
                    policy: *policy,
                    name: row.name,
                    scope_classes: if !present {
                        Vec::new()
                    } else if *policy == PolicyId::DiskGuard {
                        vec![ActionClass::EvictRegenerableData]
                    } else {
                        vec![
                            ActionClass::RequestApplicationExit,
                            ActionClass::ForceApplicationExit,
                        ]
                    },
                    // Under memory pressure the memory guard has an open
                    // incident. The stale status record also names one,
                    // which the stale controller reading cannot confirm.
                    incidents: if matches!(
                        scenario,
                        FixtureScenario::Pressure | FixtureScenario::Stale
                    ) && *policy == PolicyId::MemoryGuard
                    {
                        vec![IncidentRow {
                            id: "inc-fixture-memory-1".to_owned(),
                            generation: 2,
                        }]
                    } else {
                        Vec::new()
                    },
                    standing: row.standing,
                    detail: row.detail,
                    enabled: granted || standing == GuardStanding::NoGrant,
                    requested: present.then_some(true),
                    grant: granted.then(|| GrantRow {
                        id: format!("grant-fixture-{}", policy.as_str()),
                        action_classes: if *policy == PolicyId::DiskGuard {
                            vec!["EvictRegenerableData".to_owned()]
                        } else {
                            vec![
                                "RequestApplicationExit".to_owned(),
                                "ForceApplicationExit".to_owned(),
                            ]
                        },
                        rules: if *policy == PolicyId::DiskGuard {
                            vec!["xcode.derived-data@1".to_owned()]
                        } else {
                            Vec::new()
                        },
                        granted_at: back(captured_at, 3 * 86_400),
                        expires_at: None,
                        revoked: false,
                        in_effect: true,
                    }),
                    thresholds: if present {
                        thresholds(*policy)
                    } else {
                        Vec::new()
                    },
                }
            })
            .collect(),
        pause: Some(PauseRow::NotPaused),
        measurement: FreshMeasurement::NotNeeded,
        problems: Vec::new(),
    };
    fixture_pause(&mut snapshot, scenario);
    snapshot
}

fn budget(id: &str, latched: bool, trigger: Option<TriggerRow>) -> BudgetRow {
    BudgetRow {
        id: id.to_owned(),
        latched,
        trigger,
    }
}

fn relaunch(application: &str, state: CooldownState) -> CooldownRow {
    CooldownRow {
        subject: CooldownSubject::Relaunch {
            application: application.to_owned(),
        },
        cause: "Relaunch cooldown",
        state,
    }
}

/// The controller rows under memory pressure: an open memory incident with
/// a rearmed generation.
fn pressure_rows(captured_at: SystemTime) -> ControllerRows {
    ControllerRows {
        written_at: Some(back(captured_at, 40)),
        budgets: vec![
            budget("build-worker", true, Some(TriggerRow::Qualifying)),
            budget("browser", false, Some(TriggerRow::Acting)),
        ],
        cooldowns: vec![
            relaunch(
                "com.apple.Safari",
                CooldownState::Active {
                    remaining: Duration::from_secs(540),
                },
            ),
            relaunch("com.example.indexer", CooldownState::EarlierBoot),
            CooldownRow {
                subject: CooldownSubject::ObserveAfterAction {
                    incident: "inc-fixture-memory-1".to_owned(),
                },
                cause: "Pass pacing",
                state: CooldownState::Active {
                    remaining: Duration::from_secs(40),
                },
            },
        ],
        incidents: vec![IncidentUsage {
            id: "inc-fixture-memory-1".to_owned(),
            policy: PolicyId::MemoryGuard,
            generation: 2,
            established: true,
            unknown_outcome: false,
            current: Some(UsageRow::Memory {
                consumed_slots: 1,
                reserved_slots: 1,
            }),
            generations: vec![
                GenerationRow {
                    generation: 1,
                    rearmed: false,
                    started_at: back(captured_at, 1800),
                    final_usage: Some(UsageRow::Memory {
                        consumed_slots: 2,
                        reserved_slots: 0,
                    }),
                    journal: JournalUsageRow::Recorded {
                        slots: 2,
                        work_bytes: 0,
                        items: 0,
                    },
                },
                GenerationRow {
                    generation: 2,
                    rearmed: true,
                    started_at: back(captured_at, 300),
                    final_usage: None,
                    journal: JournalUsageRow::NoConsumedDispatch,
                },
            ],
        }],
        truncated: false,
    }
}

/// The controller rows of a disk incident with one pass.
fn drift_rows(captured_at: SystemTime) -> ControllerRows {
    ControllerRows {
        written_at: Some(back(captured_at, 90)),
        budgets: vec![budget("build-worker", false, Some(TriggerRow::Normal))],
        cooldowns: vec![CooldownRow {
            subject: CooldownSubject::DiskPass {
                incident: Some("inc-fixture-disk-1".to_owned()),
            },
            cause: "Pass pacing",
            state: CooldownState::Active {
                remaining: Duration::from_secs(150),
            },
        }],
        incidents: vec![IncidentUsage {
            id: "inc-fixture-disk-1".to_owned(),
            policy: PolicyId::DiskGuard,
            generation: 1,
            established: true,
            unknown_outcome: false,
            current: Some(UsageRow::Disk {
                consumed_bytes: 3 * GB,
                reserved_bytes: 0,
                consumed_items: 1_240,
                reserved_items: 0,
                passes: 1,
            }),
            generations: vec![GenerationRow {
                generation: 1,
                rearmed: false,
                started_at: back(captured_at, 900),
                final_usage: None,
                journal: JournalUsageRow::Recorded {
                    slots: 0,
                    work_bytes: 3 * GB,
                    items: 1_240,
                },
            }],
        }],
        truncated: false,
    }
}

/// The controller rows with no incident.
fn quiet_rows(captured_at: SystemTime) -> ControllerRows {
    ControllerRows {
        written_at: Some(back(captured_at, 3 * 3600)),
        budgets: vec![
            budget("build-worker", false, Some(TriggerRow::Normal)),
            budget("browser", false, Some(TriggerRow::Advisory)),
        ],
        cooldowns: vec![
            relaunch(
                "com.example.sync.agent",
                CooldownState::Active {
                    remaining: Duration::from_secs(240),
                },
            ),
            relaunch("com.apple.Safari", CooldownState::Elapsed),
        ],
        incidents: Vec::new(),
        truncated: false,
    }
}

/// The controller record of `scenario`.
pub(super) fn controller(scenario: FixtureScenario) -> ControllerSnapshot {
    let captured_at: SystemTime = reading_time(scenario);
    let rows: ControllerRows = match scenario {
        FixtureScenario::Unavailable => {
            return ControllerSnapshot {
                captured_at,
                status_age: StatusAge::Unknown,
                rows: Measured::Unavailable(not_in_fixture("the controller record")),
            };
        }
        FixtureScenario::AgentAbsent => {
            return ControllerSnapshot {
                captured_at,
                status_age: StatusAge::Unknown,
                rows: Measured::Unavailable("No journal exists in the state directory.".to_owned()),
            };
        }
        FixtureScenario::Pressure => pressure_rows(captured_at),
        FixtureScenario::Drift => drift_rows(captured_at),
        FixtureScenario::Healthy | FixtureScenario::Stale => quiet_rows(captured_at),
    };
    ControllerSnapshot {
        captured_at,
        status_age: if scenario == FixtureScenario::Stale {
            StatusAge::Stale {
                age: Duration::from_mins(12),
            }
        } else {
            StatusAge::Current
        },
        rows: Measured::Value(rows),
    }
}

fn names(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| (*item).to_owned()).collect()
}

/// The operations of the fixture journal, newest first.
fn operations(now: SystemTime, scenario: FixtureScenario) -> Vec<OperationDetail> {
    let capacity = |before: u64, after: u64| EffectRow::Capacity {
        before: Measured::Value(before),
        after: Measured::Value(after),
    };
    let mut list: Vec<OperationDetail> = vec![
        OperationDetail {
            operation_id: "op_fixture_0001".to_owned(),
            phase: OperationPhase::Completed,
            state_text: "Completed".to_owned(),
            admitted_at: back(now, 300),
            trigger: "disk_pressure".to_owned(),
            automatic: true,
            action_classes: names(&["EvictRegenerableData"]),
            steps: names(&["Completed", "Completed", "Completed"]),
            effects: vec![("Removed".to_owned(), 3)],
            resources: vec![capacity(22 * GB, 31 * GB + 400 * MB)],
        },
        OperationDetail {
            operation_id: "op_fixture_0000".to_owned(),
            phase: OperationPhase::Partial,
            state_text: "Partial".to_owned(),
            admitted_at: back(now, 7_500),
            trigger: "manual".to_owned(),
            automatic: false,
            action_classes: names(&["MoveToTrash"]),
            steps: names(&["Completed", "Failed", "Completed", "NoAction"]),
            effects: vec![
                ("Trashed".to_owned(), 2),
                ("Refused".to_owned(), 1),
                ("Skipped".to_owned(), 1),
            ],
            // A move to the Trash has no capacity observation.
            resources: Vec::new(),
        },
        OperationDetail {
            operation_id: "op_fixture_00zz".to_owned(),
            phase: OperationPhase::Unknown,
            state_text: "UnknownOutcome".to_owned(),
            admitted_at: back(now, 90_000),
            trigger: "application_budget".to_owned(),
            automatic: true,
            action_classes: names(&["RequestApplicationExit", "ForceApplicationExit"]),
            steps: names(&["Completed", "Verifying"]),
            effects: vec![("UnknownOutcome".to_owned(), 1)],
            resources: vec![EffectRow::Pressure {
                before: Measured::Value("critical".to_owned()),
                after: Measured::Unavailable("the reading failed".to_owned()),
            }],
        },
        OperationDetail {
            operation_id: "op_fixture_00yy".to_owned(),
            phase: OperationPhase::Failed,
            state_text: "Failed".to_owned(),
            admitted_at: back(now, 180_000),
            trigger: "manual".to_owned(),
            automatic: false,
            action_classes: names(&["DeleteSelectedFiles"]),
            steps: names(&["Failed"]),
            effects: vec![("Refused".to_owned(), 1)],
            resources: Vec::new(),
        },
        OperationDetail {
            operation_id: "op_fixture_00xx".to_owned(),
            phase: OperationPhase::NoAction,
            state_text: "NoAction".to_owned(),
            admitted_at: back(now, 260_000),
            trigger: "disk_pressure".to_owned(),
            automatic: true,
            action_classes: names(&["EvictRegenerableData"]),
            steps: names(&["NoAction"]),
            effects: vec![("AlreadyAbsent".to_owned(), 1)],
            resources: Vec::new(),
        },
    ];
    if scenario == FixtureScenario::Pressure {
        list.insert(
            0,
            OperationDetail {
                operation_id: "op_fixture_0002".to_owned(),
                phase: OperationPhase::Running,
                state_text: "Admitted".to_owned(),
                admitted_at: back(now, 40),
                trigger: "global_critical_memory".to_owned(),
                automatic: true,
                action_classes: names(&["RequestApplicationExit"]),
                steps: names(&["Completed", "Verifying", "Admitted"]),
                effects: vec![("ExitVerified".to_owned(), 1)],
                resources: Vec::new(),
            },
        );
    }
    list
}

/// The history of `scenario`.
pub(super) fn history(scenario: FixtureScenario) -> HistorySnapshot {
    let captured_at: SystemTime = reading_time(scenario);
    let mut snapshot = HistorySnapshot {
        captured_at,
        journal_present: scenario != FixtureScenario::AgentAbsent,
        operations: Vec::new(),
        problems: Vec::new(),
    };
    match scenario {
        FixtureScenario::AgentAbsent => {}
        FixtureScenario::Unavailable => snapshot
            .problems
            .push("The operations cannot be read in this fixture.".to_owned()),
        _ => snapshot.operations = operations(captured_at, scenario),
    }
    snapshot
}

fn capability(
    id: &str,
    title: &str,
    need: Need,
    level: CapabilityLevel,
    detail: &str,
    enables: &str,
    remediation: Option<&str>,
) -> CapabilityRow {
    CapabilityRow {
        id: id.to_owned(),
        title: title.to_owned(),
        need,
        level,
        detail: detail.to_owned(),
        enables: enables.to_owned(),
        remediation: remediation.map(str::to_owned),
    }
}

/// The capability rows of the fixture. `blocked` makes a required capability
/// have no result and denies Full Disk Access.
fn capabilities(blocked: bool) -> Vec<CapabilityRow> {
    let (metrics, metrics_detail) = if blocked {
        (
            CapabilityLevel::Unknown,
            "The probe gave no result in this fixture.",
        )
    } else {
        (
            CapabilityLevel::Available,
            "Each metric source gave a value.",
        )
    };
    vec![
        capability(
            "platform.supported",
            "Supported platform",
            Need::Required,
            CapabilityLevel::Available,
            "The host is a supported macOS release.",
            "Each function of the product.",
            None,
        ),
        capability(
            "metrics.memory",
            "Memory metrics",
            Need::Required,
            metrics,
            metrics_detail,
            "The memory pressure, swap, and footprint readings.",
            None,
        ),
        capability(
            "privacy.full_disk_access",
            "Full Disk Access",
            Need::Optional,
            CapabilityLevel::Denied,
            "A protected location refused the read.",
            "A scan of the protected locations of the home directory.",
            Some(
                "Open System Settings, Privacy & Security, Full Disk Access, and add the component.",
            ),
        ),
        capability(
            "service.background_agent",
            "Background agent",
            Need::Optional,
            if blocked {
                CapabilityLevel::Unsupported
            } else {
                CapabilityLevel::Available
            },
            if blocked {
                "No registration file of the agent exists."
            } else {
                "The registration file of the agent exists."
            },
            "Protection while no window is open.",
            blocked.then_some("Install the agent with the command `svalnir agent install`."),
        ),
        capability(
            "system.integrity_protection",
            "System Integrity Protection",
            Need::Informational,
            CapabilityLevel::Available,
            "System Integrity Protection is on.",
            "The protection of system locations by the operating system.",
            None,
        ),
    ]
}

/// The diagnostics of `scenario`.
pub(super) fn diagnostics(scenario: FixtureScenario) -> DiagnosticsSnapshot {
    let captured_at: SystemTime = reading_time(scenario);
    let blocked: bool = scenario == FixtureScenario::Unavailable;
    let present: bool = scenario != FixtureScenario::AgentAbsent;
    let agent: Measured<AgentStatusRow> = if !present {
        Measured::Unavailable("No journal exists in the state directory.".to_owned())
    } else if blocked {
        Measured::Unavailable("The status record cannot be read in this fixture.".to_owned())
    } else {
        Measured::Value(AgentStatusRow {
            process_id: 512,
            started_at: back(captured_at, 86_400),
            // The stale status record is 12 min old.
            written_at: back(
                captured_at,
                if scenario == FixtureScenario::Stale {
                    720
                } else {
                    12
                },
            ),
            run_state: "running",
            revision: Some("rev-fixture-1".to_owned()),
            policy_problem: None,
            // The capability summary of the agent: blocked under pressure,
            // no check in the drift record, and ready in the others.
            capability_verdict: match scenario {
                FixtureScenario::Pressure => Some("blocked".to_owned()),
                FixtureScenario::Drift => None,
                _ => Some("ready".to_owned()),
            },
            required_not_available: if scenario == FixtureScenario::Pressure {
                vec!["privacy.full_disk_access".to_owned()]
            } else {
                Vec::new()
            },
            footprint: Measured::Value(38 * MB),
            budget: 120 * MB,
            degraded: if scenario == FixtureScenario::Pressure {
                vec!["optional_work_reduced".to_owned()]
            } else {
                Vec::new()
            },
            unclean_stops: 0,
            restart_backoff: false,
        })
    };
    DiagnosticsSnapshot {
        captured_at,
        subject: "Fixture process".to_owned(),
        verdict: if blocked {
            Verdict::Unverified
        } else {
            Verdict::Ready
        },
        capabilities: capabilities(blocked),
        agent,
        start_failure: (!present).then(|| StartFailureRow {
            code: "configuration_invalid".to_owned(),
            message: "the configuration is not valid".to_owned(),
            failed_at: Some(back(captured_at, 3_600)),
            agent_version: "0.0.0-fixture".to_owned(),
        }),
        journal: JournalRow {
            path: Some(PathBuf::from("/fixture/state/operations.sqlite")),
            present,
            size: if present {
                Measured::Value(4 * MB)
            } else {
                Measured::Unavailable("no journal exists".to_owned())
            },
            limit: if present {
                Measured::Value(256 * MB)
            } else {
                Measured::Unavailable("no journal exists".to_owned())
            },
        },
        client_version: env!("CARGO_PKG_VERSION"),
        problems: if blocked {
            vec!["The start-failure record cannot be read in this fixture.".to_owned()]
        } else {
            Vec::new()
        },
    }
}
