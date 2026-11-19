//! The memory guard: the global-pressure trigger, the application-budget
//! trigger, candidate eligibility, ranking, and the first intervention.

use super::{
    BASE_CONFIG, GIB, Harness, SECOND, app, app_with, application_association, memory_snapshot,
    monotonic, process,
};
use crate::id::{ApplicationInstanceId, BootId, ClockDomainId};
use crate::observation::{Coverage, Reading, UnavailableReason, Unit};
use crate::policy::{
    AdmissionTrigger, ApplicationCandidate, ApplicationCooldown, ApplicationDecision,
    ApplicationKind, AssumedGrants, BudgetTrigger, CandidateDecision, Cooldown, CooldownCause,
    CooldownStatus, DecisionReason, EvaluationClock, Explanation, FootprintLevel, ForceEscalation,
    ForegroundStatus, GrantBasis, InterventionPlan, MemoryEvaluation, MemoryIncident,
    MemorySnapshot, ProtectionFact, ReasonDetail, ResetCause, TriggerState, WindowTransition,
    plan_intervention,
};
use crate::process::{AttributionMethod, ProcessAssociation, Uid};
use crate::quantity::{Bytes, Nanoseconds};
use crate::state::PressureState;

fn explanation(reason: DecisionReason, detail: ReasonDetail) -> Explanation {
    Explanation::new(reason, detail)
}

/// Gives the same pressure state every five seconds, from `from` to `to`.
fn pressure_hold(
    harness: &mut Harness,
    from: u64,
    to: u64,
    state: &PressureState,
) -> MemoryEvaluation {
    let mut last: Option<MemoryEvaluation> = None;
    for seconds in (from..=to).step_by(5) {
        last = Some(harness.pressure_at(seconds, state.clone()));
    }
    last.unwrap()
}

#[test]
fn only_sustained_critical_pressure_makes_the_global_trigger_ready() {
    // (pressure state, state after 300 seconds)
    let cases: [(PressureState, TriggerState); 4] = [
        (PressureState::Normal, TriggerState::Normal),
        (PressureState::Warning, TriggerState::Advisory),
        (PressureState::Critical, TriggerState::Ready),
        (PressureState::from_wire("urgent"), TriggerState::Blocked),
    ];
    for (pressure, state) in cases {
        let mut harness: Harness = Harness::new();
        let evaluation: MemoryEvaluation = pressure_hold(&mut harness, 0, 300, &pressure);
        assert_eq!(evaluation.global.state, state, "{pressure}");
        assert_eq!(
            harness.memory.incident.is_some(),
            state == TriggerState::Ready
        );
    }
}

#[test]
fn critical_pressure_needs_the_sustained_duration() {
    let mut harness: Harness = Harness::new();
    let before: MemoryEvaluation = pressure_hold(&mut harness, 0, 10, &PressureState::Critical);
    assert_eq!(before.global.state, TriggerState::Qualifying);
    assert_eq!(
        before.global.reasons,
        [explanation(
            DecisionReason::TriggerNotSustained,
            ReasonDetail::WindowNotQualified
        )]
    );
    assert!(harness.memory.incident.is_none());

    let ready: MemoryEvaluation = harness.pressure_at(15, PressureState::Critical);
    assert_eq!(ready.global.state, TriggerState::Ready);
    assert!(ready.global.latched);
    assert_eq!(ready.global.pressure, Some(PressureState::Critical));
    assert_eq!(ready.slots_remaining, 3);
    assert_eq!(harness.memory.incident, Some(MemoryIncident::default()));
}

#[test]
fn an_unknown_pressure_state_is_blocked_and_resets_the_window() {
    let mut harness: Harness = Harness::new();
    pressure_hold(&mut harness, 0, 10, &PressureState::Critical);
    let unknown: MemoryEvaluation = harness.pressure_at(15, PressureState::from_wire("urgent"));
    assert_eq!(unknown.global.state, TriggerState::Blocked);
    assert_eq!(unknown.global.pressure, None);
    assert_eq!(
        unknown.global.reasons,
        [explanation(
            DecisionReason::MetricUnavailable,
            ReasonDetail::ObservationUnrecognized
        )]
    );
    assert!(matches!(
        unknown.global.critical_window.transition,
        WindowTransition::Reset(ResetCause::EvidenceUnusable { .. })
    ));
    // The time before the unknown state does not count.
    let again: MemoryEvaluation = pressure_hold(&mut harness, 20, 30, &PressureState::Critical);
    assert_eq!(again.global.state, TriggerState::Qualifying);
    assert_eq!(
        harness
            .pressure_at(35, PressureState::Critical)
            .global
            .state,
        TriggerState::Ready
    );
}

#[test]
fn pressure_evidence_that_is_not_usable_blocks_the_global_trigger() {
    type Change = Box<dyn Fn(&mut MemorySnapshot)>;
    let cases: Vec<(Change, DecisionReason, ReasonDetail)> = vec![
        (
            Box::new(|snapshot| snapshot.pressure = None),
            DecisionReason::MetricUnavailable,
            ReasonDetail::ObservationMissing,
        ),
        (
            Box::new(|snapshot| {
                snapshot.pressure.as_mut().unwrap().reading =
                    Reading::Unavailable(UnavailableReason::NotInitialized);
            }),
            DecisionReason::MetricUnavailable,
            ReasonDetail::ObservationUnavailable,
        ),
        (
            Box::new(|snapshot| snapshot.corroborating.clear()),
            DecisionReason::MetricUnavailable,
            ReasonDetail::CorroborationMissing,
        ),
        (
            // The corroborating observation is 15 seconds old.
            Box::new(|snapshot| snapshot.corroborating = vec![super::corroboration(0)]),
            DecisionReason::MetricUnavailable,
            ReasonDetail::CorroborationMissing,
        ),
        (
            Box::new(|snapshot| snapshot.corroborating[0].available = false),
            DecisionReason::MetricUnavailable,
            ReasonDetail::CorroborationMissing,
        ),
        (
            Box::new(|snapshot| snapshot.corroborating[0].coverage = Coverage::Partial),
            DecisionReason::MetricUnavailable,
            ReasonDetail::CorroborationMissing,
        ),
        (
            // The pressure state does not corroborate itself.
            Box::new(|snapshot| {
                snapshot.corroborating[0].metric_id = crate::observation::metric::MEMORY_PRESSURE;
            }),
            DecisionReason::MetricUnavailable,
            ReasonDetail::CorroborationMissing,
        ),
        (
            // The pressure observation is 15 seconds old.
            Box::new(|snapshot| {
                snapshot.pressure = Some(super::pressure_observation(PressureState::Critical, 0));
            }),
            DecisionReason::MetricStale,
            ReasonDetail::SampleTooOld,
        ),
    ];
    for (change, reason, detail) in cases {
        let mut harness: Harness = Harness::new();
        pressure_hold(&mut harness, 0, 10, &PressureState::Critical);
        let mut snapshot: MemorySnapshot = memory_snapshot(PressureState::Critical, 15, Vec::new());
        change(&mut snapshot);
        let evaluation: MemoryEvaluation = harness.memory(15, &snapshot);
        assert_eq!(evaluation.global.state, TriggerState::Blocked, "{detail:?}");
        assert_eq!(evaluation.global.reasons, [explanation(reason, detail)]);
        assert!(!evaluation.global.critical_window.qualified);
        assert!(harness.memory.incident.is_none());
    }
}

#[test]
fn a_gap_or_a_wake_resets_the_global_window() {
    let mut harness: Harness = Harness::new();
    pressure_hold(&mut harness, 0, 10, &PressureState::Critical);
    let after_gap: MemoryEvaluation = harness.pressure_at(25, PressureState::Critical);
    assert_eq!(
        after_gap.global.critical_window.transition,
        WindowTransition::Restarted(ResetCause::Gap)
    );
    harness.continuity += 1;
    let after_wake: MemoryEvaluation = harness.pressure_at(30, PressureState::Critical);
    assert_eq!(
        after_wake.global.critical_window.transition,
        WindowTransition::Restarted(ResetCause::ClockDiscontinuity)
    );
    assert_eq!(
        pressure_hold(&mut harness, 35, 40, &PressureState::Critical)
            .global
            .state,
        TriggerState::Qualifying
    );
    assert_eq!(
        harness
            .pressure_at(45, PressureState::Critical)
            .global
            .state,
        TriggerState::Ready
    );
}

#[test]
fn a_warning_holds_the_incident_and_recovery_needs_normal_pressure() {
    let mut harness: Harness = Harness::new();
    pressure_hold(&mut harness, 0, 15, &PressureState::Critical);

    // A warning state permits no new step and is not recovery.
    let held: MemoryEvaluation = pressure_hold(&mut harness, 20, 200, &PressureState::Warning);
    assert_eq!(held.global.state, TriggerState::Held);
    assert!(held.global.latched);
    assert_eq!(
        held.global.reasons,
        [explanation(
            DecisionReason::TriggerCleared,
            ReasonDetail::EpisodeHeld
        )]
    );
    assert!(harness.memory.incident.is_some());

    // Critical pressure must qualify again.
    assert_eq!(
        pressure_hold(&mut harness, 205, 215, &PressureState::Critical)
            .global
            .state,
        TriggerState::Qualifying
    );
    assert_eq!(
        harness
            .pressure_at(220, PressureState::Critical)
            .global
            .state,
        TriggerState::Ready
    );

    // Normal pressure for less than the stable interval, then a warning.
    assert_eq!(
        pressure_hold(&mut harness, 225, 280, &PressureState::Normal)
            .global
            .state,
        TriggerState::Recovering
    );
    assert_eq!(
        harness
            .pressure_at(285, PressureState::Warning)
            .global
            .state,
        TriggerState::Held
    );
    assert_eq!(
        pressure_hold(&mut harness, 290, 345, &PressureState::Normal)
            .global
            .state,
        TriggerState::Recovering
    );
    let recovered: MemoryEvaluation = harness.pressure_at(350, PressureState::Normal);
    assert_eq!(recovered.global.state, TriggerState::Normal);
    assert!(!recovered.global.latched);
    assert!(harness.memory.incident.is_none());
}

fn budget(evaluation: &MemoryEvaluation) -> &BudgetTrigger {
    &evaluation.budgets[0]
}

#[test]
fn each_footprint_boundary_gives_its_level() {
    // (footprint, level, state of the first sample, advisory)
    let cases: [(u64, FootprintLevel, TriggerState, bool); 5] = [
        (
            4 * GIB - 1,
            FootprintLevel::BelowSoft,
            TriggerState::Normal,
            false,
        ),
        (4 * GIB, FootprintLevel::Soft, TriggerState::Advisory, true),
        (
            6 * GIB - 1,
            FootprintLevel::Soft,
            TriggerState::Advisory,
            true,
        ),
        (
            6 * GIB,
            FootprintLevel::Stop,
            TriggerState::Qualifying,
            true,
        ),
        (
            60 * GIB,
            FootprintLevel::Stop,
            TriggerState::Qualifying,
            true,
        ),
    ];
    for (footprint, level, state, advisory) in cases {
        let evaluation: MemoryEvaluation = Harness::new().worker_at(0, footprint);
        let trigger: &BudgetTrigger = budget(&evaluation);
        assert_eq!(trigger.level, level, "{footprint}");
        assert_eq!(trigger.state, state, "{footprint}");
        assert_eq!(trigger.advisory, advisory, "{footprint}");
        assert_eq!(trigger.footprint, Some(Bytes::new(footprint)));
    }
}

#[test]
fn the_budget_trigger_is_ready_with_normal_global_pressure() {
    let mut harness: Harness = Harness::new();
    let before: MemoryEvaluation = harness.worker_hold(0, 25, 6 * GIB);
    assert_eq!(budget(&before).state, TriggerState::Qualifying);
    assert!(harness.memory.incident.is_none());

    let ready: MemoryEvaluation = harness.worker_at(30, 6 * GIB);
    assert_eq!(budget(&ready).state, TriggerState::Ready);
    assert!(budget(&ready).latched);
    assert_eq!(ready.global.state, TriggerState::Normal);
    assert_eq!(ready.global.pressure, Some(PressureState::Normal));
    assert!(harness.memory.incident.is_some());

    let clock: EvaluationClock = harness.clock(30);
    let snapshot: MemorySnapshot = memory_snapshot(
        PressureState::Normal,
        30,
        vec![app("BuildWorker", 6 * GIB, 30)],
    );
    let plan: InterventionPlan = plan_intervention(&harness.context(&clock), &ready, &snapshot);
    assert!(plan.first.admissible_now, "{:?}", plan.first.blocked_by);
    assert_eq!(
        plan.first.admission_trigger,
        Some(AdmissionTrigger::ApplicationBudget {
            budget_id: "build-worker".to_owned()
        })
    );
    assert_eq!(
        plan.first.target.as_ref().unwrap().as_str(),
        "members_BuildWorker"
    );
    assert_eq!(plan.first.grace_period, Nanoseconds::new(10 * SECOND));
    assert_eq!(plan.first.slots_remaining, 3);
}

#[test]
fn a_soft_threshold_is_advisory_only() {
    let mut harness: Harness = Harness::new();
    let evaluation: MemoryEvaluation = harness.worker_hold(0, 600, 6 * GIB - 1);
    assert_eq!(budget(&evaluation).state, TriggerState::Advisory);
    assert!(budget(&evaluation).advisory);
    assert!(!budget(&evaluation).latched);
    assert!(!budget(&evaluation).stop_window.qualified);
    assert!(harness.memory.incident.is_none());

    let clock: EvaluationClock = harness.clock(600);
    let snapshot: MemorySnapshot = memory_snapshot(
        PressureState::Normal,
        600,
        vec![app("BuildWorker", 6 * GIB - 1, 600)],
    );
    let plan: InterventionPlan =
        plan_intervention(&harness.context(&clock), &evaluation, &snapshot);
    assert!(!plan.first.admissible_now);
    assert_eq!(plan.first.admission_trigger, None);
}

#[test]
fn a_large_footprint_alone_is_not_a_trigger() {
    let mut harness: Harness = Harness::new();
    let mut last: Option<(MemoryEvaluation, MemorySnapshot)> = None;
    for seconds in (0..=600).step_by(5) {
        // No budget names this application, and the pressure is normal.
        let snapshot: MemorySnapshot = memory_snapshot(
            PressureState::Normal,
            seconds,
            vec![app("Huge", 500 * GIB, seconds)],
        );
        last = Some((harness.memory(seconds, &snapshot), snapshot));
    }
    let (evaluation, snapshot) = last.unwrap();
    assert_eq!(evaluation.global.state, TriggerState::Normal);
    assert!(harness.memory.incident.is_none());

    let clock: EvaluationClock = harness.clock(600);
    let plan: InterventionPlan =
        plan_intervention(&harness.context(&clock), &evaluation, &snapshot);
    assert_eq!(plan.decisions[0].decision, CandidateDecision::Eligible);
    assert_eq!(plan.decisions[0].admission, []);
    assert!(!plan.first.admissible_now);
    assert_eq!(
        plan.first.blocked_by,
        [explanation(
            DecisionReason::TriggerNotSustained,
            ReasonDetail::PredicateNotTrue
        )]
    );
}

#[test]
fn a_new_process_generation_resets_the_budget_window() {
    let mut harness: Harness = Harness::new();
    harness.worker_hold(0, 10, 7 * GIB);
    // The same PID with a new start: a new generation of the application.
    let mut last: Option<MemoryEvaluation> = None;
    for seconds in (15..=40).step_by(5) {
        let worker: ApplicationCandidate = app_with(
            "BuildWorker",
            "gen_reused_pid",
            "members_BuildWorker",
            7 * GIB,
            seconds,
        );
        let evaluation: MemoryEvaluation = harness.memory(
            seconds,
            &memory_snapshot(PressureState::Normal, seconds, vec![worker]),
        );
        if seconds == 15 {
            assert_eq!(
                budget(&evaluation).stop_window.transition,
                WindowTransition::Restarted(ResetCause::IdentityChanged)
            );
        }
        last = Some(evaluation);
    }
    // 40 s is 30 seconds after the first sample and 25 seconds after the
    // new generation.
    assert_eq!(budget(&last.unwrap()).state, TriggerState::Qualifying);
    let worker: ApplicationCandidate = app_with(
        "BuildWorker",
        "gen_reused_pid",
        "members_BuildWorker",
        7 * GIB,
        45,
    );
    let ready: MemoryEvaluation = harness.memory(
        45,
        &memory_snapshot(PressureState::Normal, 45, vec![worker]),
    );
    assert_eq!(budget(&ready).state, TriggerState::Ready);
}

#[test]
fn a_membership_change_resets_the_budget_window() {
    let mut harness: Harness = Harness::new();
    harness.worker_hold(0, 25, 7 * GIB);
    // A helper process joined: a new membership snapshot with two members.
    let mut worker: ApplicationCandidate = app_with(
        "BuildWorker",
        "gen_BuildWorker",
        "members_BuildWorker_2",
        7 * GIB,
        30,
    );
    worker.processes.push(process(
        "BuildWorker",
        "gen_helper",
        application_association("BuildWorker"),
    ));
    let evaluation: MemoryEvaluation = harness.memory(
        30,
        &memory_snapshot(PressureState::Normal, 30, vec![worker]),
    );
    assert_eq!(budget(&evaluation).state, TriggerState::Qualifying);
    assert_eq!(
        budget(&evaluation).stop_window.transition,
        WindowTransition::Restarted(ResetCause::IdentityChanged)
    );
    assert!(harness.memory.incident.is_none());
}

#[test]
fn a_footprint_below_stop_holds_the_episode_until_stable_recovery() {
    let mut harness: Harness = Harness::new();
    harness.worker_hold(0, 30, 7 * GIB);
    harness.memory.incident.as_mut().unwrap().consumed_slots = 1;

    // Below stop and above recover: no further step, and the episode stays.
    let held: MemoryEvaluation = harness.worker_hold(35, 200, 3 * GIB + 1);
    assert_eq!(budget(&held).state, TriggerState::Held);
    assert!(budget(&held).latched);
    assert_eq!(
        budget(&held).reasons,
        [explanation(
            DecisionReason::TriggerCleared,
            ReasonDetail::EpisodeHeld
        )]
    );
    assert_eq!(harness.memory.incident.unwrap().consumed_slots, 1);

    // At the recovery threshold for less than the stable interval.
    let recovering: MemoryEvaluation = harness.worker_hold(205, 260, 3 * GIB);
    assert_eq!(budget(&recovering).state, TriggerState::Recovering);
    assert!(harness.memory.incident.is_some());

    let recovered: MemoryEvaluation = harness.worker_at(265, 3 * GIB);
    assert_eq!(budget(&recovered).state, TriggerState::Normal);
    assert!(!budget(&recovered).latched);
    assert!(harness.memory.incident.is_none());
}

#[test]
fn an_exit_recovers_the_episode_only_after_the_cooldown_with_a_complete_inventory() {
    let mut harness: Harness = Harness::new();
    harness.worker_hold(0, 30, 7 * GIB);

    // The application is absent. The cooldown is 10 minutes and the stable
    // interval is 60 seconds: the longer one applies.
    let mut last: Option<MemoryEvaluation> = None;
    for seconds in (35..=630).step_by(5) {
        last = Some(harness.pressure_at(seconds, PressureState::Normal));
    }
    let waiting: MemoryEvaluation = last.take().unwrap();
    assert_eq!(budget(&waiting).state, TriggerState::Recovering);
    assert_eq!(budget(&waiting).level, FootprintLevel::NotRunning);
    assert_eq!(
        budget(&waiting).recovery_window.required,
        Nanoseconds::new(600 * SECOND)
    );

    // An inventory that is not complete does not show that the
    // application is absent.
    let mut partial: MemorySnapshot = memory_snapshot(PressureState::Normal, 635, Vec::new());
    partial.inventory.as_mut().unwrap().coverage = Coverage::Partial;
    let blocked: MemoryEvaluation = harness.memory(635, &partial);
    assert_eq!(budget(&blocked).state, TriggerState::Blocked);
    assert_eq!(
        budget(&blocked).reasons,
        [explanation(
            DecisionReason::MetricUnavailable,
            ReasonDetail::InventoryIncomplete
        )]
    );
    assert!(budget(&blocked).latched);

    // The window starts again.
    for seconds in (640..=1235).step_by(5) {
        last = Some(harness.pressure_at(seconds, PressureState::Normal));
    }
    assert_eq!(budget(&last.unwrap()).state, TriggerState::Recovering);
    let recovered: MemoryEvaluation = harness.pressure_at(1240, PressureState::Normal);
    assert_eq!(budget(&recovered).state, TriggerState::Normal);
    assert!(harness.memory.incident.is_none());
}

#[test]
fn ambiguous_or_unverified_attribution_blocks_the_budget() {
    // Two verified instances of the application.
    let mut harness: Harness = Harness::new();
    let mut second: ApplicationCandidate =
        app_with("BuildWorker", "gen_second", "members_second", 7 * GIB, 0);
    second.processes[0].association = ProcessAssociation::Application {
        instance_id: ApplicationInstanceId::new("app_BuildWorker_2").unwrap(),
        bundle_identifier: "com.example.BuildWorker".to_owned(),
        attribution: AttributionMethod::LaunchServices,
    };
    let two: MemorySnapshot = memory_snapshot(
        PressureState::Normal,
        0,
        vec![app("BuildWorker", 7 * GIB, 0), second],
    );
    let evaluation: MemoryEvaluation = harness.memory(0, &two);
    assert_eq!(budget(&evaluation).state, TriggerState::Blocked);
    assert_eq!(
        budget(&evaluation).reasons[0].detail,
        ReasonDetail::AmbiguousInstances
    );

    // A process that claims the bundle identifier with an attribution
    // method that this build does not recognize.
    let mut claimed: ApplicationCandidate = app("BuildWorker", 7 * GIB, 0);
    claimed.processes[0].association = ProcessAssociation::Application {
        instance_id: ApplicationInstanceId::new("app_BuildWorker").unwrap(),
        bundle_identifier: "com.example.BuildWorker".to_owned(),
        attribution: AttributionMethod::from_wire("parentage"),
    };
    let unverified: MemorySnapshot = memory_snapshot(PressureState::Normal, 0, vec![claimed]);
    let evaluation: MemoryEvaluation = Harness::new().memory(0, &unverified);
    assert_eq!(budget(&evaluation).state, TriggerState::Blocked);
    assert_eq!(
        budget(&evaluation).reasons[0].detail,
        ReasonDetail::MembershipUnverified
    );
}

/// Plans the intervention at `seconds` with normal pressure and one
/// candidate, and returns the decision for the candidate.
fn decide(
    harness: &mut Harness,
    seconds: u64,
    candidate: ApplicationCandidate,
) -> ApplicationDecision {
    let snapshot: MemorySnapshot = memory_snapshot(PressureState::Normal, seconds, vec![candidate]);
    let evaluation: MemoryEvaluation = harness.memory(seconds, &snapshot);
    let clock: EvaluationClock = harness.clock(seconds);
    plan_intervention(&harness.context(&clock), &evaluation, &snapshot)
        .decisions
        .remove(0)
}

fn job(name: &str, footprint: u64, seconds: u64) -> ApplicationCandidate {
    let mut candidate: ApplicationCandidate = app(name, footprint, seconds);
    candidate.processes[0].association = ProcessAssociation::ManagedJob {
        instance_id: ApplicationInstanceId::new(format!("job_{name}")).unwrap(),
        label: format!("com.example.job.{name}"),
        attribution: AttributionMethod::LaunchdJob,
    };
    candidate
}

#[test]
#[expect(clippy::too_many_lines, reason = "the test is one table of cases")]
fn each_candidate_fact_gives_its_decision_and_reason() {
    use CandidateDecision::{Protected, Skipped};
    use DecisionReason as Reason;
    use ReasonDetail as Detail;
    type Change = Box<dyn FnOnce(&mut ApplicationCandidate)>;
    let association = |change: fn(&mut ProcessAssociation)| -> Change {
        Box::new(move |one| change(&mut one.processes[0].association))
    };
    let cases: Vec<(&str, &str, Change, CandidateDecision, Reason, Detail)> = vec![
        (
            "foreground",
            "Editor",
            Box::new(|one| one.foreground = ForegroundStatus::Foreground),
            Protected,
            Reason::UserExcluded,
            Detail::ForegroundProtected,
        ),
        (
            "foreground unknown",
            "Editor",
            Box::new(|one| one.foreground = ForegroundStatus::Unknown),
            Skipped,
            Reason::MetricUnavailable,
            Detail::ForegroundUnknown,
        ),
        (
            "protected bundle identifier",
            "Protected",
            Box::new(|_| {}),
            Protected,
            Reason::UserExcluded,
            Detail::ProtectedBundleId,
        ),
        (
            "protected bundle identifier, different case, unverified",
            "Editor",
            association(|one| {
                *one = ProcessAssociation::Application {
                    instance_id: ApplicationInstanceId::new("app_x").unwrap(),
                    bundle_identifier: "COM.EXAMPLE.PROTECTED".to_owned(),
                    attribution: AttributionMethod::from_wire("parentage"),
                };
            }),
            Protected,
            Reason::UserExcluded,
            Detail::ProtectedBundleId,
        ),
        (
            "protected executable path",
            "Keep",
            Box::new(|_| {}),
            Protected,
            Reason::UserExcluded,
            Detail::ProtectedExecutablePath,
        ),
        (
            "hard protected",
            "Editor",
            Box::new(|one| one.hard_protection = ProtectionFact::Protected),
            Protected,
            Reason::HardProtected,
            Detail::ProductProtection,
        ),
        (
            "protection unknown",
            "Editor",
            Box::new(|one| one.hard_protection = ProtectionFact::Unknown),
            Skipped,
            Reason::MetricUnavailable,
            Detail::ProtectionUnknown,
        ),
        (
            "unattributed",
            "Editor",
            association(|one| *one = ProcessAssociation::Unattributed),
            Skipped,
            Reason::MetricUnavailable,
            Detail::MembershipUnverified,
        ),
        (
            "unrecognized association",
            "Editor",
            association(|one| *one = ProcessAssociation::Unrecognized),
            Skipped,
            Reason::MetricUnavailable,
            Detail::MembershipUnverified,
        ),
        (
            "attribution method of a different kind",
            "Editor",
            association(|one| {
                if let ProcessAssociation::Application { attribution, .. } = one {
                    *attribution = AttributionMethod::LaunchdJob;
                }
            }),
            Skipped,
            Reason::MetricUnavailable,
            Detail::MembershipUnverified,
        ),
        (
            "members of two instances",
            "Editor",
            Box::new(|one| {
                one.processes.push(process(
                    "Other",
                    "gen_other",
                    application_association("Other"),
                ));
            }),
            Skipped,
            Reason::MetricUnavailable,
            Detail::MembersInconsistent,
        ),
        (
            "no process",
            "Editor",
            Box::new(|one| one.processes.clear()),
            Skipped,
            Reason::MetricUnavailable,
            Detail::MembershipUnverified,
        ),
        (
            "other user",
            "Editor",
            Box::new(|one| one.processes[0].uid = Uid::new(0)),
            Skipped,
            Reason::TargetNotEligible,
            Detail::OtherUser,
        ),
        (
            "executable unknown",
            "Editor",
            Box::new(|one| one.processes[0].executable = None),
            Skipped,
            Reason::MetricUnavailable,
            Detail::ExecutableUnknown,
        ),
        (
            "executable path with a parent component",
            "Editor",
            Box::new(|one| {
                one.processes[0].executable.as_mut().unwrap().path =
                    crate::file::LosslessPath::from_bytes(
                        "/Applications/Editor.app/../Keep.app/Contents/MacOS/Keep",
                    )
                    .unwrap();
            }),
            Skipped,
            Reason::MetricUnavailable,
            Detail::PathNotCanonical,
        ),
        (
            "footprint unavailable",
            "Editor",
            Box::new(|one| {
                one.footprint.reading = Reading::Unavailable(UnavailableReason::PermissionDenied);
            }),
            Skipped,
            Reason::MetricUnavailable,
            Detail::ObservationUnavailable,
        ),
        (
            "footprint of some members",
            "Editor",
            Box::new(|one| one.footprint.coverage = Coverage::Partial),
            Skipped,
            Reason::MetricUnavailable,
            Detail::CoverageIncomplete,
        ),
        (
            "resident size in the place of the footprint",
            "Editor",
            Box::new(|one| {
                one.footprint.metric_id = crate::observation::metric::PROCESS_RESIDENT_BYTES;
            }),
            Skipped,
            Reason::MetricUnavailable,
            Detail::MetricMismatch,
        ),
        (
            "footprint in pages",
            "Editor",
            Box::new(|one| one.footprint.unit = Unit::Page),
            Skipped,
            Reason::MetricUnavailable,
            Detail::UnitMismatch,
        ),
        (
            "footprint of a different snapshot",
            "Editor",
            Box::new(|one| {
                one.membership_snapshot =
                    crate::id::MembershipSnapshotId::new("members_later").unwrap();
            }),
            Skipped,
            Reason::MetricUnavailable,
            Detail::ScopeMismatch,
        ),
    ];
    for (name, application, change, decision, reason, detail) in cases {
        let mut candidate: ApplicationCandidate = app(application, 2 * GIB, 0);
        change(&mut candidate);
        let decided: ApplicationDecision = decide(&mut Harness::new(), 0, candidate);
        assert_eq!(decided.decision, decision, "{name}");
        assert_eq!(decided.reasons[0], explanation(reason, detail), "{name}");
        assert_eq!(decided.rank, None, "{name}");
        assert!(!decided.first_intervention, "{name}");
    }

    let eligible: ApplicationDecision = decide(&mut Harness::new(), 0, app("Editor", 2 * GIB, 0));
    assert_eq!(eligible.decision, CandidateDecision::Eligible);
    assert_eq!(eligible.reasons, []);
    assert_eq!(eligible.kind, Some(ApplicationKind::Application));
    assert_eq!(eligible.name.as_deref(), Some("com.example.Editor"));
    assert_eq!(eligible.rank, Some(1));

    let managed: ApplicationDecision = decide(&mut Harness::new(), 0, job("Indexer", 2 * GIB, 0));
    assert_eq!(managed.decision, CandidateDecision::Eligible);
    assert_eq!(managed.kind, Some(ApplicationKind::ManagedJob));
}

#[test]
fn a_stale_footprint_skips_the_candidate() {
    let mut harness: Harness = Harness::new();
    let mut snapshot: MemorySnapshot = memory_snapshot(PressureState::Normal, 20, Vec::new());
    // The footprint is 20 seconds old.
    snapshot.applications = vec![app("Editor", 2 * GIB, 0)];
    let evaluation: MemoryEvaluation = harness.memory(20, &snapshot);
    let clock: EvaluationClock = harness.clock(20);
    let plan: InterventionPlan =
        plan_intervention(&harness.context(&clock), &evaluation, &snapshot);
    assert_eq!(plan.decisions[0].decision, CandidateDecision::Skipped);
    assert_eq!(
        plan.decisions[0].reasons,
        [explanation(
            DecisionReason::MetricStale,
            ReasonDetail::SampleTooOld
        )]
    );
    assert_eq!(plan.decisions[0].footprint, None);
}

#[test]
fn the_configuration_decides_foreground_and_group_eligibility() {
    // With `protect_foreground` off, the foreground status has no effect.
    let text: String =
        BASE_CONFIG.replace("protect_foreground = true", "protect_foreground = false");
    for foreground in [ForegroundStatus::Foreground, ForegroundStatus::Unknown] {
        let mut candidate: ApplicationCandidate = app("Editor", 2 * GIB, 0);
        candidate.foreground = foreground;
        let decided: ApplicationDecision = decide(&mut Harness::with_config(&text), 0, candidate);
        assert_eq!(
            decided.decision,
            CandidateDecision::Eligible,
            "{foreground:?}"
        );
    }

    // With no eligible group, only an application with a budget is in scope.
    let text: String = BASE_CONFIG.replace(
        r#"eligible_groups = ["background-user-applications", "managed-jobs"]"#,
        "eligible_groups = []",
    );
    let out_of_scope: [ApplicationCandidate; 2] =
        [app("Editor", 2 * GIB, 0), job("Indexer", 2 * GIB, 0)];
    for candidate in out_of_scope {
        let decided: ApplicationDecision = decide(&mut Harness::with_config(&text), 0, candidate);
        assert_eq!(decided.decision, CandidateDecision::Skipped);
        assert_eq!(
            decided.reasons,
            [explanation(
                DecisionReason::TargetNotEligible,
                ReasonDetail::GroupNotEligible
            )]
        );
    }
    let with_budget: ApplicationDecision = decide(
        &mut Harness::with_config(&text),
        0,
        app("BuildWorker", 2 * GIB, 0),
    );
    assert_eq!(with_budget.decision, CandidateDecision::Eligible);
    assert_eq!(with_budget.budget_id.as_deref(), Some("build-worker"));
}

#[test]
fn a_cooldown_of_the_application_skips_a_new_instance() {
    let cooldown = |until: u64, boot: &str| ApplicationCooldown {
        application: "com.example.Editor".to_owned(),
        cooldown: Cooldown {
            cause: CooldownCause::ApplicationRelaunch,
            until: monotonic(until),
            clock_domain: ClockDomainId::new("clock_main").unwrap(),
            boot_id: BootId::new(boot).unwrap(),
        },
    };
    // (end of the cooldown, boot, reason at 100 s)
    let cases: [(u64, &str, Option<ReasonDetail>); 4] = [
        (101, "boot_1", Some(ReasonDetail::ApplicationCooldown)),
        (100, "boot_1", None),
        (50, "boot_1", None),
        (50, "boot_0", Some(ReasonDetail::CooldownClockUnknown)),
    ];
    for (until, boot, detail) in cases {
        let mut harness: Harness = Harness::new();
        harness.memory.cooldowns.push(cooldown(until, boot));
        // A relaunch: a new instance and generation of the same application.
        let mut relaunched: ApplicationCandidate = app_with(
            "Editor",
            "gen_relaunched",
            "members_relaunched",
            2 * GIB,
            100,
        );
        relaunched.processes[0].association = ProcessAssociation::Application {
            instance_id: ApplicationInstanceId::new("app_Editor_2").unwrap(),
            bundle_identifier: "com.example.Editor".to_owned(),
            attribution: AttributionMethod::LaunchServices,
        };
        let decided: ApplicationDecision = decide(&mut harness, 100, relaunched);
        let expected: Vec<Explanation> = detail
            .map(|detail| explanation(DecisionReason::CooldownActive, detail))
            .into_iter()
            .collect();
        assert_eq!(decided.reasons, expected, "until {until} in {boot}");
        // The evaluation keeps the cooldowns of the caller.
        assert_eq!(harness.memory.cooldowns.len(), 1);
    }

    let active: Cooldown = cooldown(101, "boot_1").cooldown;
    assert_eq!(
        active.status(&super::clock_at(100, 0)),
        CooldownStatus::Active {
            remaining: Nanoseconds::new(SECOND)
        }
    );
    assert_eq!(
        active.status(&super::clock_at(101, 0)),
        CooldownStatus::Elapsed
    );
}

#[test]
fn eligible_candidates_are_ranked_in_the_sequence_of_the_specification() {
    let mut harness: Harness = Harness::new();
    let candidates = |seconds: u64| {
        vec![
            app("Beta", 8 * GIB, seconds),
            app("Gamma", 9 * GIB, seconds),
            app("Protected", 90 * GIB, seconds),
            app("BuildWorker", GIB, seconds),
            app("Alpha", 8 * GIB, seconds),
        ]
    };
    let snapshot: MemorySnapshot = memory_snapshot(PressureState::Normal, 0, candidates(0));
    let evaluation: MemoryEvaluation = harness.memory(0, &snapshot);
    let clock: EvaluationClock = harness.clock(0);
    let plan: InterventionPlan =
        plan_intervention(&harness.context(&clock), &evaluation, &snapshot);
    let order: Vec<(&str, Option<u32>)> = plan
        .decisions
        .iter()
        .map(|decision| (decision.membership_snapshot.as_str(), decision.rank))
        .collect();
    // The application with a budget is first, then the larger footprint,
    // then the instance identity. The protected application has no rank,
    // however large it is.
    assert_eq!(
        order,
        [
            ("members_BuildWorker", Some(1)),
            ("members_Gamma", Some(2)),
            ("members_Alpha", Some(3)),
            ("members_Beta", Some(4)),
            ("members_Protected", None),
        ]
    );
    assert!(plan.decisions[0].first_intervention);
    assert_eq!(
        plan.decisions
            .iter()
            .filter(|decision| decision.first_intervention)
            .count(),
        1
    );

    // The sequence of the input has no effect.
    let mut reversed: MemorySnapshot = snapshot.clone();
    reversed.applications.reverse();
    let again: InterventionPlan =
        plan_intervention(&harness.context(&clock), &evaluation, &reversed);
    assert_eq!(again, plan);
}

/// Critical pressure and the build worker above its stop threshold, every
/// five seconds to `to`.
fn both_triggers(harness: &mut Harness, to: u64) -> (MemoryEvaluation, MemorySnapshot) {
    let mut last: Option<(MemoryEvaluation, MemorySnapshot)> = None;
    for seconds in (0..=to).step_by(5) {
        let snapshot: MemorySnapshot = memory_snapshot(
            PressureState::Critical,
            seconds,
            vec![
                app("BuildWorker", 7 * GIB, seconds),
                app("Editor", 20 * GIB, seconds),
            ],
        );
        last = Some((harness.memory(seconds, &snapshot), snapshot));
    }
    last.unwrap()
}

#[test]
fn the_global_trigger_admits_the_top_ranked_eligible_application() {
    let mut harness: Harness = Harness::new();
    // At 15 s the global trigger is ready, and the budget is not.
    let (evaluation, snapshot) = both_triggers(&mut harness, 15);
    assert_eq!(evaluation.global.state, TriggerState::Ready);
    assert_eq!(budget(&evaluation).state, TriggerState::Qualifying);
    let clock: EvaluationClock = harness.clock(15);
    let plan: InterventionPlan =
        plan_intervention(&harness.context(&clock), &evaluation, &snapshot);
    assert!(plan.first.admissible_now);
    assert_eq!(
        plan.first.admission_trigger,
        Some(AdmissionTrigger::GlobalPressure)
    );
    // The explicitly configured application is before the larger one.
    assert_eq!(
        plan.first.target.as_ref().unwrap().as_str(),
        "members_BuildWorker"
    );
    assert_eq!(plan.first.force_escalation, ForceEscalation::Permitted);
    assert_eq!(plan.first.first_step, "request_application_exit");
}

#[test]
fn two_triggers_for_one_application_give_one_intervention_and_one_incident() {
    let mut harness: Harness = Harness::new();
    let (evaluation, snapshot) = both_triggers(&mut harness, 30);
    assert_eq!(evaluation.global.state, TriggerState::Ready);
    assert_eq!(budget(&evaluation).state, TriggerState::Ready);
    assert_eq!(harness.memory.incident, Some(MemoryIncident::default()));

    let clock: EvaluationClock = harness.clock(30);
    let plan: InterventionPlan =
        plan_intervention(&harness.context(&clock), &evaluation, &snapshot);
    let budget_trigger: AdmissionTrigger = AdmissionTrigger::ApplicationBudget {
        budget_id: "build-worker".to_owned(),
    };
    assert_eq!(
        plan.decisions[0].admission,
        [budget_trigger.clone(), AdmissionTrigger::GlobalPressure]
    );
    assert_eq!(
        plan.decisions[1].admission,
        [AdmissionTrigger::GlobalPressure]
    );
    assert_eq!(plan.first.admission_trigger, Some(budget_trigger));
    assert_eq!(
        plan.decisions
            .iter()
            .filter(|decision| decision.first_intervention)
            .count(),
        1
    );
    assert_eq!(plan.first.slots_remaining, 3);
    assert_eq!(plan.first.slots_limit, 3);
}

#[test]
fn the_application_slots_are_exact_at_the_limit() {
    // (consumed, reserved, remaining, state)
    let cases: [(u32, u32, u32, TriggerState); 5] = [
        (0, 0, 3, TriggerState::Ready),
        (2, 0, 1, TriggerState::Ready),
        (2, 1, 0, TriggerState::Exhausted),
        (3, 0, 0, TriggerState::Exhausted),
        (u32::MAX, u32::MAX, 0, TriggerState::Exhausted),
    ];
    for (consumed, reserved, remaining, state) in cases {
        let mut harness: Harness = Harness::new();
        both_triggers(&mut harness, 30);
        let incident: MemoryIncident = MemoryIncident {
            consumed_slots: consumed,
            reserved_slots: reserved,
            outstanding_operation: false,
        };
        harness.memory.incident = Some(incident);
        let snapshot: MemorySnapshot = memory_snapshot(
            PressureState::Critical,
            35,
            vec![app("BuildWorker", 7 * GIB, 35)],
        );
        let evaluation: MemoryEvaluation = harness.memory(35, &snapshot);
        assert_eq!(evaluation.slots_remaining, remaining);
        assert_eq!(evaluation.global.state, state, "{consumed} + {reserved}");
        assert_eq!(budget(&evaluation).state, state, "{consumed} + {reserved}");
        // The evaluation does not change the usage.
        assert_eq!(harness.memory.incident, Some(incident));

        let clock: EvaluationClock = harness.clock(35);
        let plan: InterventionPlan =
            plan_intervention(&harness.context(&clock), &evaluation, &snapshot);
        assert_eq!(plan.first.admissible_now, remaining > 0);
        assert_eq!(
            plan.first.blocked_by.contains(&explanation(
                DecisionReason::BudgetExhausted,
                ReasonDetail::ApplicationSlotsExhausted
            )),
            remaining == 0
        );
    }
}

#[test]
fn an_outstanding_operation_inhibits_the_next_intervention() {
    let mut harness: Harness = Harness::new();
    both_triggers(&mut harness, 30);
    harness
        .memory
        .incident
        .as_mut()
        .unwrap()
        .outstanding_operation = true;
    let snapshot: MemorySnapshot = memory_snapshot(
        PressureState::Critical,
        35,
        vec![app("Editor", 7 * GIB, 35)],
    );
    let evaluation: MemoryEvaluation = harness.memory(35, &snapshot);
    assert_eq!(evaluation.global.state, TriggerState::Acting);
    let clock: EvaluationClock = harness.clock(35);
    let plan: InterventionPlan =
        plan_intervention(&harness.context(&clock), &evaluation, &snapshot);
    assert!(!plan.first.admissible_now);
    assert_eq!(
        plan.first.blocked_by,
        [explanation(
            DecisionReason::CooldownActive,
            ReasonDetail::OperationOutstanding
        )]
    );

    // The incident stays open through recovery while the operation is
    // outstanding.
    for seconds in (40..=120).step_by(5) {
        harness.pressure_at(seconds, PressureState::Normal);
    }
    assert!(harness.memory.incident.is_some());
}

#[test]
fn authority_decides_whether_the_first_intervention_is_admissible() {
    use DecisionReason as Reason;
    use ReasonDetail as Detail;
    let plan_with = |harness: &mut Harness| -> InterventionPlan {
        let (evaluation, snapshot) = both_triggers(harness, 30);
        let clock: EvaluationClock = harness.clock(30);
        plan_intervention(&harness.context(&clock), &evaluation, &snapshot)
    };

    let mut no_grant: Harness = Harness::new();
    no_grant.grants = AssumedGrants::none(GrantBasis::Recorded);
    let plan: InterventionPlan = plan_with(&mut no_grant);
    assert_eq!(
        plan.first.blocked_by,
        [explanation(
            Reason::ActionNotGranted,
            Detail::GrantNotAssumed
        )]
    );
    assert_eq!(plan.first.force_escalation, ForceEscalation::NotGranted);
    // The eligibility of a candidate does not depend on the grant.
    assert_eq!(plan.decisions[0].decision, CandidateDecision::Eligible);

    let mut no_force_grant: Harness = Harness::new();
    no_force_grant.grants.force_application_exit = false;
    let plan: InterventionPlan = plan_with(&mut no_force_grant);
    assert!(plan.first.admissible_now);
    assert_eq!(plan.first.force_escalation, ForceEscalation::NotGranted);

    let text: String = BASE_CONFIG.replace("allow_force_quit = true", "allow_force_quit = false");
    let plan: InterventionPlan = plan_with(&mut Harness::with_config(&text));
    assert!(plan.first.admissible_now);
    assert_eq!(
        plan.first.force_escalation,
        ForceEscalation::NotAllowedByPolicy
    );

    let text: String = BASE_CONFIG
        .replace(r#"profile = "balanced""#, r#"profile = "observe""#)
        .replace(
            "[memory_guard]\nenabled = true",
            "[memory_guard]\nenabled = false",
        );
    let plan: InterventionPlan = plan_with(&mut Harness::with_config(&text));
    assert_eq!(
        plan.first.blocked_by,
        [
            explanation(Reason::ActionNotGranted, Detail::GuardDisabled),
            explanation(Reason::ActionNotGranted, Detail::ObserveProfile),
        ]
    );
}

#[test]
fn a_plan_with_no_eligible_candidate_names_no_target() {
    let mut harness: Harness = Harness::new();
    let mut last: Option<(MemoryEvaluation, MemorySnapshot)> = None;
    for seconds in (0..=15).step_by(5) {
        let mut foreground: ApplicationCandidate = app("Editor", 20 * GIB, seconds);
        foreground.foreground = ForegroundStatus::Foreground;
        let snapshot: MemorySnapshot =
            memory_snapshot(PressureState::Critical, seconds, vec![foreground]);
        last = Some((harness.memory(seconds, &snapshot), snapshot));
    }
    let (evaluation, snapshot) = last.unwrap();
    assert_eq!(evaluation.global.state, TriggerState::Ready);
    let clock: EvaluationClock = harness.clock(15);
    let plan: InterventionPlan =
        plan_intervention(&harness.context(&clock), &evaluation, &snapshot);
    // Critical pressure does not select a protected target.
    assert_eq!(plan.first.target, None);
    assert!(!plan.first.admissible_now);
    assert_eq!(
        plan.first.blocked_by,
        [explanation(
            DecisionReason::TargetNotEligible,
            ReasonDetail::NoEligibleCandidate
        )]
    );
    assert_eq!(plan.decisions[0].decision, CandidateDecision::Protected);
}

#[test]
fn the_footprint_of_the_candidate_is_the_only_memory_value_that_is_read() {
    // The corroborating observation has a large swap value, and the
    // pressure is normal: nothing qualifies.
    let mut harness: Harness = Harness::new();
    let mut last: Option<MemoryEvaluation> = None;
    for seconds in (0..=300).step_by(5) {
        let mut snapshot: MemorySnapshot = memory_snapshot(
            PressureState::Normal,
            seconds,
            vec![app("Editor", 2 * GIB, seconds)],
        );
        snapshot.corroborating = vec![crate::policy::CorroboratingEvidence::from_observation(
            &super::observation(
                crate::observation::metric::MEMORY_SWAP_USED_BYTES,
                super::host_scope(),
                Reading::Available(Bytes::new(900 * GIB)),
                Unit::Byte,
                crate::observation::MetricKind::Gauge,
                seconds,
            ),
        )];
        last = Some(harness.memory(seconds, &snapshot));
    }
    let evaluation: MemoryEvaluation = last.unwrap();
    assert_eq!(evaluation.global.state, TriggerState::Normal);
    assert_eq!(evaluation.global.corroborating_metrics.len(), 1);
    assert!(harness.memory.incident.is_none());
}

#[test]
fn a_budget_binds_its_application_without_regard_to_ascii_case() {
    let mut harness: Harness = Harness::new();
    let mut last: Option<MemoryEvaluation> = None;
    for seconds in (0..=30).step_by(5) {
        let mut worker: ApplicationCandidate = app("BuildWorker", 7 * GIB, seconds);
        worker.processes[0].association = ProcessAssociation::Application {
            instance_id: ApplicationInstanceId::new("app_BuildWorker").unwrap(),
            bundle_identifier: "COM.EXAMPLE.BUILDWORKER".to_owned(),
            attribution: AttributionMethod::LaunchServices,
        };
        let snapshot: MemorySnapshot =
            memory_snapshot(PressureState::Normal, seconds, vec![worker]);
        last = Some(harness.memory(seconds, &snapshot));
    }
    // An exact comparison would see no running instance, and a complete
    // inventory would then show the application as absent.
    let evaluation: MemoryEvaluation = last.unwrap();
    assert_eq!(budget(&evaluation).level, FootprintLevel::Stop);
    assert_eq!(budget(&evaluation).state, TriggerState::Ready);
}

#[test]
fn a_target_with_no_admission_trigger_is_never_admissible() {
    // The evaluation has a ready budget for one instance. The snapshot of
    // the plan has a different instance of the application.
    let text: String = BASE_CONFIG.replace(
        r#"eligible_groups = ["background-user-applications", "managed-jobs"]"#,
        "eligible_groups = []",
    );
    let mut harness: Harness = Harness::with_config(&text);
    let evaluation: MemoryEvaluation = harness.worker_hold(0, 30, 7 * GIB);
    assert_eq!(budget(&evaluation).state, TriggerState::Ready);
    let mut other: ApplicationCandidate =
        app_with("BuildWorker", "gen_other", "members_other", 7 * GIB, 30);
    other.processes[0].association = ProcessAssociation::Application {
        instance_id: ApplicationInstanceId::new("app_BuildWorker_other").unwrap(),
        bundle_identifier: "com.example.BuildWorker".to_owned(),
        attribution: AttributionMethod::LaunchServices,
    };
    let snapshot: MemorySnapshot = memory_snapshot(PressureState::Normal, 30, vec![other]);
    let clock: EvaluationClock = harness.clock(30);
    let plan: InterventionPlan =
        plan_intervention(&harness.context(&clock), &evaluation, &snapshot);
    assert_eq!(plan.first.admission_trigger, None);
    assert!(!plan.first.admissible_now);
    assert_eq!(
        plan.first.blocked_by,
        [explanation(
            DecisionReason::TriggerNotSustained,
            ReasonDetail::PredicateNotTrue
        )]
    );
}

#[test]
fn a_metric_of_another_resource_does_not_corroborate_memory_pressure() {
    use crate::observation::metric;
    for other in [
        metric::DISK_OPPORTUNISTIC_AVAILABLE_BYTES,
        metric::PROCESS_CPU_CORE_EQUIVALENT_PERCENT,
        metric::MEMORY_PHYSICAL_BYTES,
    ] {
        let mut harness: Harness = Harness::new();
        pressure_hold(&mut harness, 0, 10, &PressureState::Critical);
        let mut snapshot: MemorySnapshot = memory_snapshot(PressureState::Critical, 15, Vec::new());
        snapshot.corroborating[0].metric_id = other.clone();
        let evaluation: MemoryEvaluation = harness.memory(15, &snapshot);
        assert_eq!(evaluation.global.state, TriggerState::Blocked, "{other:?}");
        assert_eq!(
            evaluation.global.reasons,
            [explanation(
                DecisionReason::MetricUnavailable,
                ReasonDetail::CorroborationMissing
            )]
        );
    }
}

#[test]
fn an_unrecognized_process_keeps_a_latched_budget_from_recovering_by_absence() {
    let mut harness: Harness = Harness::new();
    let ready: MemoryEvaluation = harness.worker_hold(0, 30, 7 * GIB);
    assert_eq!(budget(&ready).state, TriggerState::Ready);
    let mut latest: Option<MemoryEvaluation> = None;
    for seconds in (35..=700).step_by(5) {
        let mut unknown: ApplicationCandidate = app("Mystery", GIB, seconds);
        unknown.processes[0].association = ProcessAssociation::Unrecognized;
        let snapshot: MemorySnapshot =
            memory_snapshot(PressureState::Normal, seconds, vec![unknown]);
        latest = Some(harness.memory(seconds, &snapshot));
    }
    let evaluation: MemoryEvaluation = latest.unwrap();
    assert_eq!(budget(&evaluation).level, FootprintLevel::Unknown);
    assert!(budget(&evaluation).latched);
    assert!(harness.memory.incident.is_some());
    assert_eq!(
        budget(&evaluation).reasons,
        [explanation(
            DecisionReason::MetricUnavailable,
            ReasonDetail::MembershipUnverified
        )]
    );
}

#[test]
fn a_managed_job_ranks_before_a_larger_background_application() {
    let mut harness: Harness = Harness::new();
    let snapshot: MemorySnapshot = memory_snapshot(
        PressureState::Normal,
        0,
        vec![app("Editor", 2 * GIB, 0), job("Indexer", GIB / 5, 0)],
    );
    let evaluation: MemoryEvaluation = harness.memory(0, &snapshot);
    let clock: EvaluationClock = harness.clock(0);
    let plan: InterventionPlan =
        plan_intervention(&harness.context(&clock), &evaluation, &snapshot);
    assert_eq!(plan.decisions[0].kind, Some(ApplicationKind::ManagedJob));
    assert_eq!(plan.decisions[0].rank, Some(1));
    assert_eq!(plan.decisions[1].kind, Some(ApplicationKind::Application));
    assert_eq!(plan.decisions[1].rank, Some(2));
}

#[test]
fn a_stale_application_list_makes_each_application_candidate_inadmissible() {
    let mut harness: Harness = Harness::new();
    let mut snapshot: MemorySnapshot = memory_snapshot(
        PressureState::Normal,
        0,
        vec![app("Editor", 2 * GIB, 0), job("Indexer", GIB, 0)],
    );
    snapshot.application_list_may_be_stale = true;
    let evaluation: MemoryEvaluation = harness.memory(0, &snapshot);
    let clock: EvaluationClock = harness.clock(0);
    let plan: InterventionPlan =
        plan_intervention(&harness.context(&clock), &evaluation, &snapshot);
    let editor: &ApplicationDecision = plan
        .decisions
        .iter()
        .find(|decision| decision.kind == Some(ApplicationKind::Application))
        .unwrap();
    assert_eq!(editor.decision, CandidateDecision::Skipped);
    assert_eq!(
        editor.reasons,
        [explanation(
            DecisionReason::MetricStale,
            ReasonDetail::ApplicationListStale
        )]
    );
    let indexer: &ApplicationDecision = plan
        .decisions
        .iter()
        .find(|decision| decision.kind == Some(ApplicationKind::ManagedJob))
        .unwrap();
    assert_eq!(indexer.decision, CandidateDecision::Eligible);
}

#[test]
fn a_stale_application_list_blocks_a_ready_budget_and_proves_no_absence() {
    let mut harness: Harness = Harness::new();
    let ready: MemoryEvaluation = harness.worker_hold(0, 30, 7 * GIB);
    assert_eq!(budget(&ready).state, TriggerState::Ready);
    let mut snapshot: MemorySnapshot = memory_snapshot(
        PressureState::Normal,
        35,
        vec![app("BuildWorker", 7 * GIB, 35)],
    );
    snapshot.application_list_may_be_stale = true;
    let evaluation: MemoryEvaluation = harness.memory(35, &snapshot);
    let clock: EvaluationClock = harness.clock(35);
    let plan: InterventionPlan =
        plan_intervention(&harness.context(&clock), &evaluation, &snapshot);
    assert_eq!(plan.decisions[0].decision, CandidateDecision::Skipped);
    assert!(!plan.first.admissible_now);

    let mut absent: MemorySnapshot = memory_snapshot(PressureState::Normal, 40, Vec::new());
    absent.application_list_may_be_stale = true;
    let evaluation: MemoryEvaluation = harness.memory(40, &absent);
    assert_eq!(budget(&evaluation).level, FootprintLevel::Unknown);
    assert!(budget(&evaluation).latched);
}

#[test]
fn the_configured_protections_of_an_instance_agree_with_the_decision() {
    use crate::file::LosslessPath;
    use crate::grant::ProtectionTable;
    use crate::policy::{ConfiguredProtections, configured_protections};

    let mut harness: Harness = Harness::new();
    let home: LosslessPath = LosslessPath::from_bytes("/Users/tester").unwrap();
    for (name, detail) in [
        ("Protected", Some(ReasonDetail::ProtectedBundleId)),
        ("Keep", Some(ReasonDetail::ProtectedExecutablePath)),
        ("Editor", None),
    ] {
        let candidate: ApplicationCandidate = app(name, GIB, 0);
        let reading: ConfiguredProtections =
            configured_protections(&harness.config, Some(&home), &candidate.processes);
        let decision: ApplicationDecision = decide(&mut harness, 0, candidate);
        let decided: Vec<ReasonDetail> = decision
            .reasons
            .iter()
            .map(|reason| reason.detail)
            .filter(|detail| {
                matches!(
                    detail,
                    ReasonDetail::ProtectedBundleId | ReasonDetail::ProtectedExecutablePath
                )
            })
            .collect();
        let read: Vec<ReasonDetail> = reading.matches.iter().map(|found| found.detail).collect();
        assert_eq!(read, decided, "{name}");
        assert_eq!(read, detail.into_iter().collect::<Vec<_>>(), "{name}");
        assert!(!reading.home_unresolved);
        assert!(!reading.executable_unknown);
        assert!(!reading.path_not_canonical);
        if let Some(found) = reading.matches.first() {
            assert_eq!(found.table, ProtectionTable::MemoryGuard);
        }
    }
    let matched =
        configured_protections(&harness.config, Some(&home), &app("Keep", GIB, 0).processes);
    assert_eq!(matched.matches[0].entry, "/Applications/Keep.app");

    let mut no_executable: ApplicationCandidate = app("Editor", GIB, 0);
    no_executable.processes[0].executable = None;
    assert!(
        configured_protections(&harness.config, None, &no_executable.processes).executable_unknown
    );
}
