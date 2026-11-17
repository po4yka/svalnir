//! Simulation reports, the controller summary, and the policy
//! descriptions.

use serde_json::{Value, json};

use super::{BASE_CONFIG, GIB, Harness, MIB, app, base_config, disk_snapshot, memory_snapshot};
use crate::file::LosslessPath;
use crate::id::{RuleId, TargetId, VolumeId};
use crate::observation::{Reading, UnavailableReason};
use crate::policy::{
    ActivityFact, ApplicationCandidate, AssumedGrants, CandidateReport, CleanupCandidate,
    CleanupFacts, ControllerSummary, DESCRIPTION_NOTE, DecisionReason, DiskSnapshot,
    EvaluationClock, FirstAction, ForegroundStatus, GrantBasis, MAX_APPLICATION_CANDIDATES,
    MAX_REVISION_LABEL_BYTES, MemorySnapshot, OwnerFact, PolicyDescription, PolicyId,
    PolicyInputError, PolicyListEntry, PolicySettings, PolicyState, ProtectionFact, RebuildCost,
    RevisionLabel, RevisionSource, RuleReadiness, SIMULATION_STATEMENT, SimulationInput,
    SimulationReport, TriggerState, controller_summary, list_policies, show_policy, simulate,
};
use crate::quantity::{Bytes, EntryCount, Nanoseconds};
use crate::state::PressureState;
use crate::time::WallTime;

fn label() -> RevisionLabel {
    RevisionLabel::new(RevisionSource::Proposed, "proposal:config.toml").unwrap()
}

fn cleanup_candidate(id: &str, protection: ProtectionFact) -> CleanupCandidate {
    CleanupCandidate {
        target_id: TargetId::new(id).unwrap(),
        rule_id: RuleId::new("svalnir.expired-temporary").unwrap(),
        volume_id: VolumeId::new("vol_data").unwrap(),
        path: LosslessPath::from_bytes(format!("/Users/tester/Library/Caches/{id}")).unwrap(),
        work_bytes: Some(Bytes::new(100 * MIB)),
        item_count: Some(EntryCount::new(10)),
        estimated_reclaimable_bytes: Some(Bytes::new(90 * MIB)),
        facts: CleanupFacts {
            rule_readiness: RuleReadiness::Ready,
            hard_protection: protection,
            protected_classes: Vec::new(),
            owner: OwnerFact::RequestingUser,
            activity: ActivityFact::Inactive {
                inactive_for: Nanoseconds::new(1),
            },
            rebuild_cost: RebuildCost::Low,
        },
    }
}

/// Simulates `policy` at `seconds` with the state of the harness.
fn run(
    harness: &Harness,
    policy: PolicyId,
    seconds: u64,
    disk: &DiskSnapshot,
    memory: &MemorySnapshot,
) -> Result<SimulationReport, PolicyInputError> {
    let clock: EvaluationClock = harness.clock(seconds);
    let state: PolicyState = PolicyState {
        disk: harness.disk.clone(),
        memory: harness.memory.clone(),
    };
    let revision: RevisionLabel = label();
    simulate(&SimulationInput {
        policy,
        revision: &revision,
        context: harness.context(&clock),
        snapshot_time: WallTime::from_unix(1_800_000_000, 0).unwrap(),
        state: &state,
        disk,
        memory,
    })
}

fn disk_report(harness: &Harness, seconds: u64, disk: &DiskSnapshot) -> SimulationReport {
    run(
        harness,
        PolicyId::DiskGuard,
        seconds,
        disk,
        &MemorySnapshot::default(),
    )
    .unwrap()
}

fn memory_report(harness: &Harness, seconds: u64, memory: &MemorySnapshot) -> SimulationReport {
    run(
        harness,
        PolicyId::MemoryGuard,
        seconds,
        &DiskSnapshot::default(),
        memory,
    )
    .unwrap()
}

#[test]
fn a_disk_simulation_reports_the_trigger_the_candidates_and_the_first_batch() {
    let mut harness: Harness = Harness::new();
    harness.disk_hold(0, 30, 9 * GIB);
    let mut snapshot: DiskSnapshot = disk_snapshot(9 * GIB, 35);
    snapshot.candidates = vec![
        cleanup_candidate("cache_b", ProtectionFact::NotProtected),
        cleanup_candidate("cache_a", ProtectionFact::Protected),
    ];
    let before: PolicyState = PolicyState {
        disk: harness.disk.clone(),
        memory: harness.memory.clone(),
    };
    let report: SimulationReport = disk_report(&harness, 35, &snapshot);

    assert_eq!(report.policy, PolicyId::DiskGuard);
    assert_eq!(report.revision, label());
    assert!(report.enabled);
    assert_eq!(report.profile, "balanced");
    assert_eq!(report.summary, ControllerSummary::Acting);
    assert_eq!(report.statement, SIMULATION_STATEMENT);
    assert_eq!(report.triggers.len(), 1);
    assert_eq!(report.triggers[0].state(), TriggerState::Ready);
    assert_eq!(report.candidates.len(), 2);
    assert_eq!(report.first_actions.len(), 1);
    assert!(report.first_actions[0].admissible_now());
    // A simulation reads the state and does not change it.
    assert_eq!(harness.disk, before.disk);

    let value: Value = serde_json::to_value(&report).unwrap();
    assert_eq!(value["policy"], "disk-guard");
    assert_eq!(
        value["revision"],
        json!({ "source": "proposed", "label": "proposal:config.toml" })
    );
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["snapshot"]["captured_at"], "2027-01-15T08:00:00Z");
    assert_eq!(value["snapshot"]["clock"]["now"], "35000000000");
    assert_eq!(value["assumed_grants"]["basis"], "hypothetical");
    assert_eq!(value["summary"], "acting");

    let trigger: &Value = &value["triggers"][0];
    assert_eq!(trigger["kind"], "disk_capacity");
    assert_eq!(trigger["selector"], "startup-data");
    assert_eq!(trigger["state"], "ready");
    assert_eq!(trigger["level"], "reclaim");
    assert_eq!(trigger["available"], (9 * GIB).to_string());
    assert_eq!(trigger["evidence"]["metric_id"], "disk.available_bytes");
    assert_eq!(trigger["evidence"]["value"], (9 * GIB).to_string());
    assert_eq!(trigger["evidence"]["age"], "0");
    assert_eq!(trigger["evidence"]["usable"], true);
    assert_eq!(trigger["entry_window"]["transition"], "qualified");
    assert_eq!(trigger["entry_window"]["observed_for"], "35000000000");
    assert_eq!(trigger["emergency_window"]["transition"], "idle");
    assert_eq!(
        trigger["domain"],
        json!({ "kind": "domain", "id": "domain_disk3" })
    );

    let eligible: &Value = &value["candidates"][0];
    assert_eq!(eligible["kind"], "cleanup");
    assert_eq!(eligible["target_id"], "cache_b");
    assert_eq!(eligible["decision"], "eligible");
    assert_eq!(eligible["rank"], 1);
    assert_eq!(eligible["in_first_batch"], true);
    let protected: &Value = &value["candidates"][1];
    assert_eq!(protected["decision"], "protected");
    assert_eq!(
        protected["reasons"],
        json!([{ "reason": "HARD_PROTECTED", "detail": "product_protection" }])
    );

    let first: &Value = &value["first_actions"][0];
    assert_eq!(first["kind"], "cleanup_batch");
    assert_eq!(first["admissible_now"], true);
    assert_eq!(first["targets"], json!(["cache_b"]));
    assert_eq!(first["work_bytes"], (100 * MIB).to_string());
    assert_eq!(first["estimated_reclaimable_bytes"], (90 * MIB).to_string());
    assert_eq!(
        first["allowance"]["incident_remaining"],
        (16 * GIB).to_string()
    );
    assert_eq!(value["capacity"]["total_available"], (9 * GIB).to_string());
    assert_eq!(value["statement"], SIMULATION_STATEMENT);
}

#[test]
fn a_memory_simulation_reports_each_trigger_and_the_first_intervention() {
    let harness: Harness = Harness::new();
    let mut foreground: ApplicationCandidate = app("Editor", 5 * GIB, 0);
    foreground.foreground = ForegroundStatus::Foreground;
    let snapshot: MemorySnapshot = memory_snapshot(
        PressureState::Critical,
        0,
        vec![foreground, app("BuildWorker", 7 * GIB, 0)],
    );
    let report: SimulationReport = memory_report(&harness, 0, &snapshot);
    // One snapshot with no earlier window cannot qualify a trigger.
    assert_eq!(report.summary, ControllerSummary::Warning);
    assert_eq!(report.triggers.len(), 2);

    let value: Value = serde_json::to_value(&report).unwrap();
    assert_eq!(value["policy"], "memory-guard");
    let global: &Value = &value["triggers"][0];
    assert_eq!(global["kind"], "global_pressure");
    assert_eq!(global["state"], "qualifying");
    assert_eq!(global["pressure"], "critical");
    assert_eq!(global["evidence"]["value"], "critical");
    assert_eq!(
        global["corroborating_metrics"],
        json!(["memory.swap.used_bytes"])
    );
    assert_eq!(global["critical_window"]["transition"], "started");
    assert_eq!(
        global["reasons"],
        json!([{ "reason": "TRIGGER_NOT_SUSTAINED", "detail": "window_not_qualified" }])
    );
    let budget: &Value = &value["triggers"][1];
    assert_eq!(budget["kind"], "application_budget");
    assert_eq!(budget["budget_id"], "build-worker");
    assert_eq!(budget["level"], "stop");
    assert_eq!(budget["footprint"], (7 * GIB).to_string());
    assert_eq!(budget["instance_id"], "app_BuildWorker");

    let worker: &Value = &value["candidates"][0];
    assert_eq!(worker["kind"], "application");
    assert_eq!(worker["name"], "com.example.BuildWorker");
    assert_eq!(worker["decision"], "eligible");
    assert_eq!(worker["first_intervention"], true);
    assert_eq!(worker["admission"], json!([]));
    let editor: &Value = &value["candidates"][1];
    assert_eq!(editor["decision"], "protected");
    assert_eq!(
        editor["reasons"],
        json!([{ "reason": "USER_EXCLUDED", "detail": "foreground_protected" }])
    );

    let first: &Value = &value["first_actions"][0];
    assert_eq!(first["kind"], "application_exit");
    assert_eq!(first["admissible_now"], false);
    assert_eq!(first["target"], "members_BuildWorker");
    assert_eq!(first["admission_trigger"], Value::Null);
    assert_eq!(first["first_step"], "request_application_exit");
    assert_eq!(first["grace_period"], "10000000000");
    assert_eq!(first["force_escalation"], "permitted");
    assert_eq!(first["slots_remaining"], 3);
    assert_eq!(value["capacity"], Value::Null);
}

#[test]
fn equal_inputs_give_equal_reports() {
    let mut harness: Harness = Harness::new();
    harness.disk_hold(0, 30, 9 * GIB);
    harness.worker_hold(0, 30, 7 * GIB);
    let mut disk: DiskSnapshot = disk_snapshot(9 * GIB, 35);
    disk.candidates = (0..50)
        .map(|index| cleanup_candidate(&format!("cache_{index}"), ProtectionFact::NotProtected))
        .collect();
    let memory: MemorySnapshot = memory_snapshot(
        PressureState::Critical,
        35,
        vec![
            app("BuildWorker", 7 * GIB, 35),
            app("Editor", 3 * GIB, 35),
            app("Protected", 9 * GIB, 35),
        ],
    );
    for policy in [PolicyId::DiskGuard, PolicyId::MemoryGuard] {
        let first: SimulationReport = run(&harness, policy, 35, &disk, &memory).unwrap();
        let second: SimulationReport = run(&harness, policy, 35, &disk, &memory).unwrap();
        assert_eq!(first, second);
        assert_eq!(
            serde_json::to_string(&first).unwrap(),
            serde_json::to_string(&second).unwrap()
        );
    }
}

#[test]
fn a_simulation_that_skips_each_candidate_is_a_successful_result() {
    let harness: Harness = Harness::new();
    let mut disk: DiskSnapshot = disk_snapshot(GIB, 0);
    disk.candidates = vec![
        cleanup_candidate("cache_a", ProtectionFact::Protected),
        cleanup_candidate("cache_b", ProtectionFact::Unknown),
    ];
    let report: SimulationReport = disk_report(&harness, 0, &disk);
    assert!(report.candidates.iter().all(|candidate| match candidate {
        CandidateReport::Cleanup(decision) => decision.rank.is_none(),
        CandidateReport::Application(_) => false,
    }));
    let FirstAction::CleanupBatch(batch) = &report.first_actions[0] else {
        panic!("the disk guard gives a cleanup batch");
    };
    assert_eq!(batch.targets, []);
    assert!(!batch.admissible_now);

    let mut protected: ApplicationCandidate = app("Protected", 50 * GIB, 0);
    protected.hard_protection = ProtectionFact::Protected;
    let memory: MemorySnapshot = memory_snapshot(PressureState::Critical, 0, vec![protected]);
    let report: SimulationReport = memory_report(&harness, 0, &memory);
    let FirstAction::ApplicationExit(first) = &report.first_actions[0] else {
        panic!("the memory guard gives an application intervention");
    };
    assert_eq!(first.target, None);
    assert!(
        first
            .blocked_by
            .iter()
            .any(|explanation| explanation.reason == DecisionReason::TargetNotEligible)
    );
}

#[test]
fn missing_required_metrics_give_a_degraded_summary() {
    let harness: Harness = Harness::new();
    // No volume and no pressure observation.
    let disk: SimulationReport = disk_report(&harness, 0, &DiskSnapshot::default());
    assert_eq!(disk.summary, ControllerSummary::Degraded);
    assert_eq!(disk.triggers[0].state(), TriggerState::Blocked);
    let memory: SimulationReport = memory_report(&harness, 0, &MemorySnapshot::default());
    assert_eq!(memory.summary, ControllerSummary::Degraded);

    // An unavailable capacity, with a value field of zero bytes.
    let mut unavailable: DiskSnapshot = disk_snapshot(0, 0);
    unavailable.volumes[0].available.reading =
        Reading::Unavailable(UnavailableReason::PermissionDenied);
    let report: SimulationReport = disk_report(&harness, 0, &unavailable);
    assert_eq!(report.summary, ControllerSummary::Degraded);
    let value: Value = serde_json::to_value(&report).unwrap();
    assert_eq!(value["triggers"][0]["available"], Value::Null);
    assert_eq!(
        value["triggers"][0]["evidence"]["problem"],
        json!({ "problem": "unavailable", "reason": "permission_denied" })
    );
    assert_eq!(value["capacity"]["total_available"], Value::Null);
}

#[test]
fn a_guard_that_cannot_intervene_gives_a_warning_and_not_acting() {
    let ready = |harness: &mut Harness| -> SimulationReport {
        harness.disk_hold(0, 30, 9 * GIB);
        disk_report(harness, 35, &disk_snapshot(9 * GIB, 35))
    };
    assert_eq!(
        ready(&mut Harness::new()).summary,
        ControllerSummary::Acting
    );

    let mut no_grant: Harness = Harness::new();
    no_grant.grants = AssumedGrants::none(GrantBasis::Recorded);
    let report: SimulationReport = ready(&mut no_grant);
    assert_eq!(report.summary, ControllerSummary::Warning);
    assert_eq!(report.triggers[0].state(), TriggerState::Ready);
    assert_eq!(report.assumed_grants.basis, GrantBasis::Recorded);

    let observe: String = BASE_CONFIG.replace(r#"profile = "balanced""#, r#"profile = "observe""#);
    assert_eq!(
        ready(&mut Harness::with_config(&observe)).summary,
        ControllerSummary::Warning
    );
    let disabled: String = BASE_CONFIG.replacen("enabled = true", "enabled = false", 1);
    let report: SimulationReport = ready(&mut Harness::with_config(&disabled));
    assert_eq!(report.summary, ControllerSummary::Warning);
    assert!(!report.enabled);
}

#[test]
fn the_controller_summary_groups_the_incident_states() {
    use ControllerSummary as Summary;
    use TriggerState as State;
    // (states, intervention permitted, summary)
    let cases: [(&[State], bool, Summary); 16] = [
        (&[], true, Summary::Normal),
        (&[State::Normal], true, Summary::Normal),
        (&[State::Advisory], true, Summary::Warning),
        (&[State::Qualifying], true, Summary::Warning),
        (&[State::Held], true, Summary::Warning),
        (&[State::Exhausted], true, Summary::Warning),
        (&[State::Ready], true, Summary::Acting),
        (&[State::Acting], true, Summary::Acting),
        (&[State::Cooldown], true, Summary::Acting),
        (&[State::Ready], false, Summary::Warning),
        (&[State::Recovering], true, Summary::Recovering),
        (&[State::Blocked], true, Summary::Degraded),
        (&[State::Normal, State::Blocked], false, Summary::Degraded),
        (
            &[State::Advisory, State::Recovering],
            true,
            Summary::Recovering,
        ),
        (
            &[State::Recovering, State::Ready, State::Normal],
            true,
            Summary::Acting,
        ),
        (
            &[State::Ready, State::Blocked, State::Recovering],
            true,
            Summary::Degraded,
        ),
    ];
    for (states, permitted, summary) in cases {
        assert_eq!(controller_summary(states, permitted), summary, "{states:?}");
    }
}

#[test]
fn a_snapshot_above_its_limits_and_a_bad_label_are_rejected() {
    let harness: Harness = Harness::new();
    let mut memory: MemorySnapshot = memory_snapshot(PressureState::Normal, 0, Vec::new());
    memory.applications = vec![app("Editor", GIB, 0); MAX_APPLICATION_CANDIDATES + 1];
    let error: PolicyInputError = run(
        &harness,
        PolicyId::MemoryGuard,
        0,
        &DiskSnapshot::default(),
        &memory,
    )
    .unwrap_err();
    assert_eq!(
        error,
        PolicyInputError::TooManyEntries {
            list: "application candidates",
            count: MAX_APPLICATION_CANDIDATES + 1,
            limit: MAX_APPLICATION_CANDIDATES,
        }
    );
    // The disk guard does not read the memory snapshot.
    assert!(
        run(
            &harness,
            PolicyId::DiskGuard,
            0,
            &DiskSnapshot::default(),
            &memory
        )
        .is_ok()
    );

    let too_long: String = "r".repeat(MAX_REVISION_LABEL_BYTES + 1);
    for text in ["", too_long.as_str(), "revision\n7"] {
        assert_eq!(
            RevisionLabel::new(RevisionSource::Effective, text),
            Err(PolicyInputError::InvalidRevisionLabel)
        );
    }
    let longest: String = "r".repeat(MAX_REVISION_LABEL_BYTES);
    let accepted: RevisionLabel = RevisionLabel::new(RevisionSource::Effective, longest).unwrap();
    assert_eq!(accepted.source(), RevisionSource::Effective);
    assert_eq!(accepted.label().len(), MAX_REVISION_LABEL_BYTES);
}

#[test]
fn each_policy_name_and_reason_code_has_its_stable_text() {
    assert_eq!(PolicyId::from_text("disk-guard"), Some(PolicyId::DiskGuard));
    assert_eq!(
        PolicyId::from_text("memory-guard"),
        Some(PolicyId::MemoryGuard)
    );
    assert_eq!(PolicyId::from_text("cpu-guard"), None);
    assert_eq!(PolicyId::MemoryGuard.to_string(), "memory-guard");
    for reason in DecisionReason::ALL {
        assert_eq!(
            serde_json::to_value(reason).unwrap(),
            Value::String(reason.as_str().to_owned())
        );
    }
    // The codes of the table in `docs/POLICY_SPEC.md` section 7.
    let specification: &str = include_str!("../../../../../docs/POLICY_SPEC.md");
    for reason in DecisionReason::ALL {
        let in_table: bool = specification.contains(&format!("`{}`", reason.as_str()));
        assert_eq!(
            in_table,
            *reason != DecisionReason::TargetNotEligible,
            "{reason:?}"
        );
    }
}

#[test]
fn the_policy_list_and_description_repeat_the_configuration() {
    let config = base_config();
    let list: Vec<PolicyListEntry> = list_policies(&config);
    assert_eq!(
        serde_json::to_value(&list).unwrap(),
        json!([
            {
                "policy": "disk-guard",
                "enabled": true,
                "profile": "balanced",
                "intervention_requested": true,
                "action_classes": ["EvictRegenerableData"],
                "trigger_count": 1
            },
            {
                "policy": "memory-guard",
                "enabled": true,
                "profile": "balanced",
                "intervention_requested": true,
                "action_classes": ["RequestApplicationExit", "ForceApplicationExit"],
                "trigger_count": 2
            }
        ])
    );

    let disk: PolicyDescription = show_policy(&config, PolicyId::DiskGuard);
    assert!(matches!(disk.settings, PolicySettings::DiskGuard(_)));
    assert_eq!(disk.note, DESCRIPTION_NOTE);
    let value: Value = serde_json::to_value(&disk).unwrap();
    assert_eq!(value["policy"], "disk-guard");
    assert_eq!(value["settings"]["reclaim_below"], (10 * GIB).to_string());
    assert_eq!(value["settings"]["sustain_for"], "30000000000");
    assert_eq!(value["settings"]["max_passes_per_incident"], 2);
    assert_eq!(
        value["settings"]["approved_rules"],
        json!(["svalnir.expired-temporary", "xcode.inactive-derived-data"])
    );
    assert_eq!(value["settings"]["excluded_paths"], json!(["~/Documents"]));
    assert_eq!(value["agent"]["max_qualifying_sample_gap"], "10000000000");
    let explicit: Vec<&str> = disk.explicit_keys.iter().map(String::as_str).collect();
    assert!(explicit.contains(&"disk_guard.warn_below"));
    assert!(explicit.contains(&"agent.profile"));
    assert!(!explicit.contains(&"disk_guard.pass_cooldown"));
    assert!(explicit.iter().all(|key| !key.starts_with("memory_guard.")));

    let memory: Value = serde_json::to_value(show_policy(&config, PolicyId::MemoryGuard)).unwrap();
    assert_eq!(memory["settings"]["global_trigger"], "critical");
    assert_eq!(
        memory["settings"]["app_budgets"][0]["footprint_stop"],
        (6 * GIB).to_string()
    );
    assert_eq!(
        memory["settings"]["eligible_groups"],
        json!(["background-user-applications", "managed-jobs"])
    );
    assert_eq!(
        memory["settings"]["protected_executable_paths"],
        json!(["/Applications/Keep.app"])
    );

    // The template: each guard is disabled and the profile is `observe`.
    let template = super::config_from("schema_version = 1\n");
    for entry in list_policies(&template) {
        assert!(!entry.enabled);
        assert!(!entry.intervention_requested);
        assert_eq!(entry.profile, "observe");
    }
}
