//! The disk guard: thresholds, the sustained window, the emergency
//! shortening, recovery hysteresis, capacity domains, and cleanup candidates.

use super::{
    BASE_CONFIG, GIB, Harness, MIB, SECOND, capacity_reading, disk_snapshot, shared, volume,
    volume_evidence,
};
use crate::config::VolumeSelector;
use crate::file::LosslessPath;
use crate::id::{BootId, ClockDomainId, MountId, RuleId, TargetId, VolumeId};
use crate::observation::{Coverage, Reading, UnavailableReason, Unit};
use crate::policy::{
    ActivityFact, AssumedGrants, CandidateDecision, CapacityDomainKey, CapacityLevel,
    CleanupCandidate, CleanupDecision, CleanupFacts, CleanupPlan, Cooldown, CooldownCause,
    DecisionReason, DiskEvaluation, DiskSnapshot, EvaluationClock, Explanation, GrantBasis,
    MAX_CLEANUP_CANDIDATES, OwnerFact, PolicyInputError, ProtectedDataClass, ProtectionFact,
    ReasonDetail, RebuildCost, ResetCause, RuleReadiness, TriggerState, VolumeEvidence,
    VolumeTrigger, WindowTransition, WorkUsage, evaluate_disk_guard, plan_cleanup,
};
use crate::quantity::{Bytes, EntryCount, Nanoseconds};
use crate::volume::CapacityDomainMembership;

fn explanation(reason: DecisionReason, detail: ReasonDetail) -> Explanation {
    Explanation::new(reason, detail)
}

#[test]
fn each_threshold_boundary_gives_its_level_and_state() {
    // (available bytes, level, state of the first sample)
    let cases: [(u64, CapacityLevel, TriggerState); 9] = [
        (
            30 * GIB,
            CapacityLevel::AtRecoveryTarget,
            TriggerState::Normal,
        ),
        (
            25 * GIB,
            CapacityLevel::AtRecoveryTarget,
            TriggerState::Normal,
        ),
        (
            25 * GIB - 1,
            CapacityLevel::AboveWarning,
            TriggerState::Normal,
        ),
        (20 * GIB, CapacityLevel::AboveWarning, TriggerState::Normal),
        (20 * GIB - 1, CapacityLevel::Warning, TriggerState::Advisory),
        (10 * GIB, CapacityLevel::Warning, TriggerState::Advisory),
        (
            10 * GIB - 1,
            CapacityLevel::Reclaim,
            TriggerState::Qualifying,
        ),
        (2 * GIB, CapacityLevel::Reclaim, TriggerState::Qualifying),
        (
            2 * GIB - 1,
            CapacityLevel::Emergency,
            TriggerState::Qualifying,
        ),
    ];
    for (bytes, level, state) in cases {
        let mut harness: Harness = Harness::new();
        let trigger: VolumeTrigger = harness.disk_at(0, bytes);
        assert_eq!(trigger.level, level, "{bytes} bytes");
        assert_eq!(trigger.state, state, "{bytes} bytes");
        assert_eq!(trigger.available, Some(Bytes::new(bytes)));
        assert!(!trigger.incident_open);
    }
}

#[test]
fn a_warning_never_becomes_ready() {
    let mut harness: Harness = Harness::new();
    let trigger: VolumeTrigger = harness.disk_hold(0, 300, 15 * GIB);
    assert_eq!(trigger.state, TriggerState::Advisory);
    assert_eq!(harness.disk.incidents, []);
}

#[test]
fn the_reclaim_threshold_needs_the_sustained_duration() {
    let mut harness: Harness = Harness::new();
    let before: VolumeTrigger = harness.disk_hold(0, 25, 9 * GIB);
    assert_eq!(before.state, TriggerState::Qualifying);
    assert_eq!(
        before.reasons,
        [explanation(
            DecisionReason::TriggerNotSustained,
            ReasonDetail::WindowNotQualified
        )]
    );
    assert_eq!(harness.disk.incidents, []);

    let ready: VolumeTrigger = harness.disk_at(30, 9 * GIB);
    assert_eq!(ready.state, TriggerState::Ready);
    assert!(ready.entry_window.qualified);
    assert!(!ready.emergency_window.qualified);
    assert!(ready.incident_open);
    assert_eq!(ready.reasons, []);
    assert_eq!(harness.disk.incidents.len(), 1);
    assert_eq!(harness.disk.incidents[0].usage, WorkUsage::default());
}

#[test]
fn a_gap_resets_the_sustained_window() {
    let mut harness: Harness = Harness::new();
    harness.disk_hold(0, 10, 9 * GIB);
    // No sample for 15 seconds; the largest gap is 10 seconds.
    let after_gap: VolumeTrigger = harness.disk_at(25, 9 * GIB);
    assert_eq!(
        after_gap.entry_window.transition,
        WindowTransition::Restarted(ResetCause::Gap)
    );
    assert_eq!(
        harness.disk_hold(30, 50, 9 * GIB).state,
        TriggerState::Qualifying
    );
    assert_eq!(harness.disk_at(55, 9 * GIB).state, TriggerState::Ready);
}

#[test]
fn a_stale_sample_blocks_the_trigger_and_resets_the_window() {
    let mut harness: Harness = Harness::new();
    harness.disk_hold(0, 10, 9 * GIB);
    // The evaluation at 25 s reads the sample of 10 s again: its age is
    // 15 seconds and the largest age is 10 seconds.
    let stale: VolumeTrigger = harness
        .disk(25, &disk_snapshot(9 * GIB, 10))
        .volumes
        .remove(0);
    assert_eq!(stale.state, TriggerState::Blocked);
    assert_eq!(stale.level, CapacityLevel::Unknown);
    assert_eq!(stale.available, None);
    assert_eq!(
        stale.reasons,
        [explanation(
            DecisionReason::MetricStale,
            ReasonDetail::SampleTooOld
        )]
    );
    assert!(matches!(
        stale.entry_window.transition,
        WindowTransition::Reset(ResetCause::EvidenceUnusable { .. })
    ));

    // The window needs the full duration again.
    assert_eq!(
        harness.disk_hold(30, 55, 9 * GIB).state,
        TriggerState::Qualifying
    );
    assert_eq!(harness.disk_at(60, 9 * GIB).state, TriggerState::Ready);
}

#[test]
fn a_sample_at_the_age_limit_is_fresh() {
    let mut harness: Harness = Harness::new();
    let at_limit: VolumeTrigger = harness
        .disk(10, &disk_snapshot(9 * GIB, 0))
        .volumes
        .remove(0);
    assert_eq!(at_limit.state, TriggerState::Qualifying);
    assert_eq!(at_limit.evidence.age, Some(Nanoseconds::new(10 * SECOND)));
}

#[test]
fn a_clock_discontinuity_resets_the_sustained_window() {
    let mut harness: Harness = Harness::new();
    harness.disk_hold(0, 10, 9 * GIB);
    // The caller reports a wake.
    harness.continuity += 1;
    let after_wake: VolumeTrigger = harness.disk_at(15, 9 * GIB);
    assert_eq!(
        after_wake.entry_window.transition,
        WindowTransition::Restarted(ResetCause::ClockDiscontinuity)
    );
    assert_eq!(
        harness.disk_hold(20, 40, 9 * GIB).state,
        TriggerState::Qualifying
    );
    assert_eq!(harness.disk_at(45, 9 * GIB).state, TriggerState::Ready);
}

#[test]
fn a_sample_of_a_different_boot_or_clock_domain_is_not_usable() {
    for change in ["boot", "domain", "future"] {
        let mut harness: Harness = Harness::new();
        harness.disk_hold(0, 10, 9 * GIB);
        let mut snapshot: DiskSnapshot = disk_snapshot(9 * GIB, 15);
        let sample = &mut snapshot.volumes[0].available.sample;
        match change {
            "boot" => sample.boot_id = BootId::new("boot_2").unwrap(),
            "domain" => sample.clock_domain = ClockDomainId::new("clock_other").unwrap(),
            _ => {
                sample.started_monotonic_ns = super::monotonic(16);
                sample.finished_monotonic_ns = super::monotonic(16);
            }
        }
        let trigger: VolumeTrigger = harness.disk(15, &snapshot).volumes.remove(0);
        assert_eq!(trigger.state, TriggerState::Blocked, "{change}");
        assert_eq!(
            trigger.reasons[0].reason,
            DecisionReason::MetricStale,
            "{change}"
        );
    }
}

#[test]
fn a_new_mount_generation_resets_the_sustained_window() {
    let mut harness: Harness = Harness::new();
    harness.disk_hold(0, 25, 9 * GIB);
    let mut snapshot: DiskSnapshot = disk_snapshot(9 * GIB, 30);
    snapshot.volumes[0].identity.mount_id = MountId::new("mount_data_2").unwrap();
    let remounted: VolumeTrigger = harness.disk(30, &snapshot).volumes.remove(0);
    assert_eq!(remounted.state, TriggerState::Qualifying);
    assert_eq!(
        remounted.entry_window.transition,
        WindowTransition::Restarted(ResetCause::IdentityChanged)
    );
}

#[test]
fn unusable_capacity_is_blocked_and_never_a_safe_level() {
    type Change = Box<dyn Fn(&mut VolumeEvidence)>;
    let unusable: [(Change, ReasonDetail); 6] = [
        (
            Box::new(|evidence| {
                evidence.available.reading =
                    Reading::Unavailable(UnavailableReason::PermissionDenied);
            }),
            ReasonDetail::ObservationUnavailable,
        ),
        (
            Box::new(|evidence| {
                evidence.available.reading =
                    Reading::Unrecognized(crate::encoding::UnrecognizedText::new("estimated"));
            }),
            ReasonDetail::ObservationUnrecognized,
        ),
        (
            Box::new(|evidence| evidence.available.unit = Unit::Page),
            ReasonDetail::UnitMismatch,
        ),
        (
            Box::new(|evidence| evidence.available.coverage = Coverage::Partial),
            ReasonDetail::CoverageIncomplete,
        ),
        (
            Box::new(|evidence| {
                evidence.available.metric_id = crate::observation::metric::DISK_FREE_BYTES;
            }),
            ReasonDetail::MetricMismatch,
        ),
        (
            Box::new(|evidence| {
                evidence.available.scope =
                    crate::observation::Scope::volume(VolumeId::new("vol_other").unwrap());
            }),
            ReasonDetail::ScopeMismatch,
        ),
    ];
    for (change, detail) in unusable {
        let mut harness: Harness = Harness::new();
        harness.disk_hold(0, 25, 9 * GIB);
        // A measured zero would be an emergency. No value is not a zero and
        // not a normal level.
        let mut snapshot: DiskSnapshot = disk_snapshot(0, 30);
        change(&mut snapshot.volumes[0]);
        let trigger: VolumeTrigger = harness.disk(30, &snapshot).volumes.remove(0);
        assert_eq!(trigger.state, TriggerState::Blocked, "{detail:?}");
        assert_eq!(trigger.level, CapacityLevel::Unknown);
        assert_eq!(trigger.available, None);
        assert_eq!(trigger.evidence.value, None);
        assert_eq!(
            trigger.reasons,
            [explanation(DecisionReason::MetricUnavailable, detail)]
        );
        assert!(!trigger.entry_window.qualified);
        assert_eq!(harness.disk.incidents, []);
    }
}

#[test]
fn a_selector_with_no_volume_or_two_volumes_is_blocked() {
    let mut harness: Harness = Harness::new();
    let none: VolumeTrigger = harness.disk(0, &DiskSnapshot::default()).volumes.remove(0);
    assert_eq!(none.state, TriggerState::Blocked);
    assert_eq!(none.reasons[0].detail, ReasonDetail::SelectorUnresolved);

    let mut two: DiskSnapshot = disk_snapshot(9 * GIB, 0);
    two.volumes.push(volume_evidence(
        "startup-data",
        volume("other", CapacityDomainMembership::Exclusive),
        9 * GIB,
        0,
    ));
    let ambiguous: VolumeTrigger = harness.disk(0, &two).volumes.remove(0);
    assert_eq!(ambiguous.state, TriggerState::Blocked);
    assert_eq!(ambiguous.reasons[0].detail, ReasonDetail::SelectorAmbiguous);
}

#[test]
fn the_emergency_threshold_shortens_the_wait() {
    let mut harness: Harness = Harness::new();
    assert_eq!(harness.disk_at(0, GIB).state, TriggerState::Qualifying);
    let ready: VolumeTrigger = harness.disk_at(5, GIB);
    assert_eq!(ready.state, TriggerState::Ready);
    assert!(ready.emergency_window.qualified);
    assert!(!ready.entry_window.qualified);

    // Exactly at the emergency threshold the shorter wait does not apply.
    let mut harness: Harness = Harness::new();
    harness.disk_at(0, 2 * GIB);
    assert_eq!(harness.disk_at(5, 2 * GIB).state, TriggerState::Qualifying);
}

#[test]
fn recovery_needs_the_higher_target_for_the_stable_interval() {
    let mut harness: Harness = Harness::new();
    assert_eq!(harness.disk_hold(0, 30, 9 * GIB).state, TriggerState::Ready);
    // The executor charged the incident. The evaluation must keep the
    // usage through each later step.
    let charged: WorkUsage = WorkUsage {
        consumed_bytes: Bytes::new(3 * GIB),
        reserved_bytes: Bytes::ZERO,
        consumed_items: EntryCount::new(100),
        reserved_items: EntryCount::ZERO,
    };
    harness.disk.incidents[0].usage = charged;

    // Above the reclaim threshold and below the recovery target: the same
    // incident continues.
    let continuing: VolumeTrigger = harness.disk_at(35, 15 * GIB);
    assert_eq!(continuing.state, TriggerState::Ready);
    assert_eq!(continuing.level, CapacityLevel::Warning);
    assert!(continuing.incident_open);

    // At the recovery target: new dispatch stops and the stable window
    // starts.
    let recovering: VolumeTrigger = harness.disk_hold(40, 90, 25 * GIB);
    assert_eq!(recovering.state, TriggerState::Recovering);
    assert!(!recovering.recovery_window.qualified);
    assert_eq!(
        recovering.reasons,
        [explanation(
            DecisionReason::TriggerCleared,
            ReasonDetail::RecoveryInProgress
        )]
    );

    // A drop before stability: the incident and its usage stay, and the
    // continuation must qualify again.
    let dropped: VolumeTrigger = harness.disk_at(95, 25 * GIB - 1);
    assert_eq!(dropped.state, TriggerState::Qualifying);
    assert!(dropped.incident_open);
    assert_eq!(
        dropped.recovery_window.transition,
        WindowTransition::Reset(ResetCause::Contradicted)
    );
    assert_eq!(
        harness.disk_hold(100, 120, 24 * GIB).state,
        TriggerState::Qualifying
    );
    assert_eq!(harness.disk_at(125, 24 * GIB).state, TriggerState::Ready);
    assert_eq!(harness.disk.incidents[0].usage, charged);

    // The target for the full stable interval closes the incident.
    assert_eq!(
        harness.disk_hold(130, 185, 26 * GIB).state,
        TriggerState::Recovering
    );
    assert_eq!(harness.disk.incidents.len(), 1);
    let recovered: VolumeTrigger = harness.disk_at(190, 26 * GIB);
    assert_eq!(recovered.state, TriggerState::Normal);
    assert!(recovered.recovery_window.qualified);
    assert!(!recovered.incident_open);
    assert_eq!(harness.disk.incidents, []);

    // After the incident, the entry predicate applies again: 15 GiB is a
    // warning and not a continuation.
    assert_eq!(harness.disk_at(195, 15 * GIB).state, TriggerState::Advisory);
}

#[test]
fn a_gap_during_an_incident_needs_requalification_and_keeps_the_incident() {
    let mut harness: Harness = Harness::new();
    harness.disk_hold(0, 30, 9 * GIB);
    harness.disk.incidents[0].usage.consumed_bytes = Bytes::new(GIB);
    let after_gap: VolumeTrigger = harness.disk_at(100, 9 * GIB);
    assert_eq!(after_gap.state, TriggerState::Qualifying);
    assert!(after_gap.incident_open);
    assert_eq!(
        harness.disk.incidents[0].usage.consumed_bytes,
        Bytes::new(GIB)
    );
    assert_eq!(
        harness.disk_hold(105, 130, 9 * GIB).state,
        TriggerState::Ready
    );

    // The shorter wait applies during an incident only below the emergency
    // threshold.
    harness.continuity += 1;
    assert_eq!(harness.disk_at(135, GIB).state, TriggerState::Qualifying);
    assert_eq!(harness.disk_at(140, GIB).state, TriggerState::Ready);
}

#[test]
fn missing_evidence_cannot_recover_an_incident() {
    let mut harness: Harness = Harness::new();
    harness.disk_hold(0, 30, 9 * GIB);
    for seconds in (35..=200).step_by(5) {
        let mut snapshot: DiskSnapshot = disk_snapshot(30 * GIB, seconds);
        snapshot.volumes[0].available.reading =
            Reading::Unavailable(UnavailableReason::TransientFailure);
        let trigger: VolumeTrigger = harness.disk(seconds, &snapshot).volumes.remove(0);
        assert_eq!(trigger.state, TriggerState::Blocked);
        assert!(trigger.incident_open);
    }
    assert_eq!(harness.disk.incidents.len(), 1);
    assert_eq!(harness.disk.incidents[0].unrecovered.len(), 1);
}

#[test]
fn an_outstanding_operation_keeps_the_incident_open() {
    let mut harness: Harness = Harness::new();
    harness.disk_hold(0, 30, 9 * GIB);
    harness.disk.incidents[0].outstanding_operation = true;
    let acting: VolumeTrigger = harness.disk_at(35, 9 * GIB);
    assert_eq!(acting.state, TriggerState::Acting);
    harness.disk_hold(40, 100, 26 * GIB);
    assert_eq!(harness.disk.incidents.len(), 1);
    harness.disk.incidents[0].outstanding_operation = false;
    harness.disk_at(105, 26 * GIB);
    assert_eq!(harness.disk.incidents, []);
}

#[test]
fn volumes_of_one_domain_are_counted_once_and_unverified_ones_are_not_summed() {
    let text: String = BASE_CONFIG.replace(
        r#"volumes = ["startup-data"]"#,
        r#"volumes = ["startup-data", "system", "external", "unverified"]"#,
    );
    let mut harness: Harness = Harness::with_config(&text);
    let snapshot: DiskSnapshot = DiskSnapshot {
        volumes: vec![
            volume_evidence(
                "startup-data",
                volume("data", shared("domain_disk3")),
                40 * GIB,
                0,
            ),
            volume_evidence(
                "system",
                volume("system", shared("domain_disk3")),
                39 * GIB,
                0,
            ),
            volume_evidence(
                "external",
                volume("external", CapacityDomainMembership::Exclusive),
                100 * GIB,
                0,
            ),
            volume_evidence(
                "unverified",
                volume("unverified", CapacityDomainMembership::Unknown),
                500 * GIB,
                0,
            ),
        ],
        candidates: Vec::new(),
    };
    let evaluation: DiskEvaluation = harness.disk(0, &snapshot);
    let capacity = &evaluation.capacity;
    assert_eq!(capacity.domains.len(), 2);
    assert_eq!(capacity.domains[0].available, Bytes::new(39 * GIB));
    assert_eq!(capacity.domains[0].selectors, ["startup-data", "system"]);
    assert_eq!(capacity.domains[1].available, Bytes::new(100 * GIB));
    assert_eq!(capacity.not_summed, ["unverified"]);
    // 39 GiB and 100 GiB: not 40 + 39, and not the 500 GiB of the volume
    // whose membership is not verified.
    assert_eq!(capacity.total_available, Some(Bytes::new(139 * GIB)));
    assert!(!evaluation.volumes[3].domain_verified);
    assert_eq!(evaluation.volumes[3].domain, None);
}

#[test]
fn a_volume_with_unverified_membership_opens_no_incident() {
    let mut harness: Harness = Harness::new();
    let mut last: Option<VolumeTrigger> = None;
    for seconds in (0..=30).step_by(5) {
        let mut snapshot: DiskSnapshot = disk_snapshot(9 * GIB, seconds);
        snapshot.volumes[0].identity.capacity_domain = CapacityDomainMembership::Unrecognized;
        last = Some(harness.disk(seconds, &snapshot).volumes.remove(0));
    }
    let trigger: VolumeTrigger = last.unwrap();
    assert_eq!(trigger.state, TriggerState::Ready);
    assert_eq!(
        trigger.reasons,
        [explanation(
            DecisionReason::MetricUnavailable,
            ReasonDetail::CapacityDomainUnverified
        )]
    );
    assert!(!trigger.incident_open);
    assert_eq!(harness.disk.incidents, []);
}

#[test]
fn two_volumes_of_one_domain_share_one_incident() {
    let text: String = BASE_CONFIG.replace(
        r#"volumes = ["startup-data"]"#,
        r#"volumes = ["startup-data", "system"]"#,
    );
    let mut harness: Harness = Harness::with_config(&text);
    for seconds in (0..=35).step_by(5) {
        let snapshot: DiskSnapshot = DiskSnapshot {
            volumes: vec![
                volume_evidence(
                    "startup-data",
                    volume("data", shared("domain_disk3")),
                    9 * GIB,
                    seconds,
                ),
                volume_evidence(
                    "system",
                    volume("system", shared("domain_disk3")),
                    9 * GIB,
                    seconds,
                ),
            ],
            candidates: Vec::new(),
        };
        harness.disk(seconds, &snapshot);
    }
    assert_eq!(harness.disk.incidents.len(), 1);
    assert_eq!(
        harness.disk.incidents[0].domain,
        CapacityDomainKey::Domain(crate::id::CapacityDomainId::new("domain_disk3").unwrap())
    );
    assert_eq!(harness.disk.incidents[0].unrecovered.len(), 2);
}

fn candidate(id: &str, rule: &str, work: u64, items: u64) -> CleanupCandidate {
    CleanupCandidate {
        target_id: TargetId::new(id).unwrap(),
        rule_id: RuleId::new(rule).unwrap(),
        volume_id: VolumeId::new("vol_data").unwrap(),
        path: LosslessPath::from_bytes(format!("/Users/tester/Library/Caches/{id}")).unwrap(),
        work_bytes: Some(Bytes::new(work)),
        item_count: Some(EntryCount::new(items)),
        estimated_reclaimable_bytes: Some(Bytes::new(work)),
        facts: CleanupFacts {
            rule_readiness: RuleReadiness::Ready,
            hard_protection: ProtectionFact::NotProtected,
            protected_classes: Vec::new(),
            owner: OwnerFact::RequestingUser,
            activity: ActivityFact::Inactive {
                inactive_for: Nanoseconds::new(3600 * SECOND),
            },
            rebuild_cost: RebuildCost::Low,
        },
    }
}

fn temporary(id: &str, work: u64, items: u64) -> CleanupCandidate {
    candidate(id, "svalnir.expired-temporary", work, items)
}

/// Evaluates the guard at `seconds` with a fresh 9 GiB sample and plans the
/// cleanup of the candidates.
fn plan_at(harness: &mut Harness, seconds: u64, candidates: Vec<CleanupCandidate>) -> CleanupPlan {
    let mut snapshot: DiskSnapshot = disk_snapshot(9 * GIB, seconds);
    snapshot.candidates = candidates;
    let evaluation: DiskEvaluation = harness.disk(seconds, &snapshot);
    let clock: EvaluationClock = harness.clock(seconds);
    plan_cleanup(&harness.context(&clock), &evaluation, &snapshot)
}

fn decide(change: impl FnOnce(&mut CleanupCandidate)) -> CleanupDecision {
    let mut harness: Harness = Harness::new();
    let mut one: CleanupCandidate = temporary("target_1", MIB, 10);
    change(&mut one);
    plan_at(&mut harness, 0, vec![one]).decisions.remove(0)
}

fn path(text: &str) -> LosslessPath {
    LosslessPath::from_bytes(text).unwrap()
}

#[test]
#[expect(clippy::too_many_lines, reason = "the test is one table of cases")]
fn each_eligibility_fact_gives_its_decision_and_reason() {
    use CandidateDecision::{Protected, Skipped};
    use DecisionReason as Reason;
    use ReasonDetail as Detail;
    type Change = Box<dyn FnOnce(&mut CleanupCandidate)>;
    let cases: Vec<(&str, Change, CandidateDecision, Reason, Detail)> = vec![
        (
            "rule not approved",
            Box::new(|one| one.rule_id = RuleId::new("homebrew.cache").unwrap()),
            Skipped,
            Reason::ActionNotGranted,
            Detail::RuleNotApproved,
        ),
        (
            "rule not ready",
            Box::new(|one| one.facts.rule_readiness = RuleReadiness::NotReady),
            Skipped,
            Reason::RuleNotReady,
            Detail::RuleNotReady,
        ),
        (
            "rule version",
            Box::new(|one| one.facts.rule_readiness = RuleReadiness::VersionUnapproved),
            Skipped,
            Reason::RuleVersionUnapproved,
            Detail::RuleVersionUnapproved,
        ),
        (
            "hard protected",
            Box::new(|one| one.facts.hard_protection = ProtectionFact::Protected),
            Protected,
            Reason::HardProtected,
            Detail::ProductProtection,
        ),
        (
            "protection unknown",
            Box::new(|one| one.facts.hard_protection = ProtectionFact::Unknown),
            Skipped,
            Reason::MetricUnavailable,
            Detail::ProtectionUnknown,
        ),
        (
            "database",
            Box::new(|one| one.facts.protected_classes = vec![ProtectedDataClass::Database]),
            Protected,
            Reason::HardProtected,
            Detail::ProtectedDataClass,
        ),
        (
            "inside an excluded path",
            Box::new(|one| one.path = path("/Users/tester/Documents/project/build")),
            Protected,
            Reason::UserExcluded,
            Detail::ExcludedPath,
        ),
        (
            "excluded path, different case",
            Box::new(|one| one.path = path("/users/TESTER/documents/x")),
            Protected,
            Reason::UserExcluded,
            Detail::ExcludedPath,
        ),
        (
            "contains an excluded path",
            Box::new(|one| one.path = path("/Users/tester")),
            Protected,
            Reason::UserExcluded,
            Detail::ExcludedPath,
        ),
        (
            "other user",
            Box::new(|one| one.facts.owner = OwnerFact::OtherUser),
            Skipped,
            Reason::TargetNotEligible,
            Detail::OtherUser,
        ),
        (
            "owner unknown",
            Box::new(|one| one.facts.owner = OwnerFact::Unknown),
            Skipped,
            Reason::MetricUnavailable,
            Detail::OwnerUnknown,
        ),
        (
            "active",
            Box::new(|one| one.facts.activity = ActivityFact::Active),
            Skipped,
            Reason::TargetNotEligible,
            Detail::TargetActive,
        ),
        (
            "activity unknown",
            Box::new(|one| {
                one.facts.activity = ActivityFact::Unknown;
                one.estimated_reclaimable_bytes = Some(Bytes::new(500 * GIB));
            }),
            Skipped,
            Reason::MetricUnavailable,
            Detail::ActivityUnknown,
        ),
        (
            "charge unknown",
            Box::new(|one| one.work_bytes = None),
            Skipped,
            Reason::MetricUnavailable,
            Detail::WorkChargeUnknown,
        ),
        (
            "entry count unknown",
            Box::new(|one| one.item_count = None),
            Skipped,
            Reason::MetricUnavailable,
            Detail::WorkChargeUnknown,
        ),
        (
            "other volume",
            Box::new(|one| one.volume_id = VolumeId::new("vol_other").unwrap()),
            Skipped,
            Reason::TargetNotEligible,
            Detail::VolumeNotSelected,
        ),
    ];
    for (name, change, decision, reason, detail) in cases {
        let decided: CleanupDecision = decide(change);
        assert_eq!(decided.decision, decision, "{name}");
        assert_eq!(decided.reasons[0], explanation(reason, detail), "{name}");
        assert_eq!(decided.rank, None, "{name}");
        assert!(!decided.in_first_batch, "{name}");
    }

    let eligible: CleanupDecision = decide(|_| {});
    assert_eq!(eligible.decision, CandidateDecision::Eligible);
    assert_eq!(eligible.reasons, []);
    assert_eq!(eligible.rank, Some(1));
    assert!(eligible.in_first_batch);
}

#[test]
fn a_decision_has_each_reason_with_the_protection_first() {
    let decided: CleanupDecision = decide(|one| {
        one.rule_id = RuleId::new("homebrew.cache").unwrap();
        one.facts.activity = ActivityFact::Unknown;
        one.facts.hard_protection = ProtectionFact::Protected;
    });
    assert_eq!(decided.decision, CandidateDecision::Protected);
    assert_eq!(
        decided.reasons,
        [
            explanation(
                DecisionReason::HardProtected,
                ReasonDetail::ProductProtection
            ),
            explanation(
                DecisionReason::ActionNotGranted,
                ReasonDetail::RuleNotApproved
            ),
            explanation(
                DecisionReason::MetricUnavailable,
                ReasonDetail::ActivityUnknown
            ),
        ]
    );
}

#[test]
fn a_home_path_with_no_home_directory_skips_each_candidate() {
    let mut harness: Harness = Harness::new();
    harness.home = None;
    let plan: CleanupPlan = plan_at(&mut harness, 0, vec![temporary("target_1", MIB, 10)]);
    assert_eq!(plan.decisions[0].decision, CandidateDecision::Skipped);
    assert_eq!(
        plan.decisions[0].reasons,
        [explanation(
            DecisionReason::MetricUnavailable,
            ReasonDetail::HomeDirectoryUnknown
        )]
    );
}

#[test]
fn eligible_candidates_are_ranked_in_the_sequence_of_the_specification() {
    let inactive = |seconds: u64| ActivityFact::Inactive {
        inactive_for: Nanoseconds::new(seconds * SECOND),
    };
    let mut second_rule: CleanupCandidate = candidate("a", "xcode.inactive-derived-data", MIB, 1);
    second_rule.facts.activity = inactive(10_000);
    let mut high_cost: CleanupCandidate = temporary("b", MIB, 1);
    high_cost.facts.rebuild_cost = RebuildCost::High;
    let mut unknown_cost: CleanupCandidate = temporary("f", MIB, 1);
    unknown_cost.facts.rebuild_cost = RebuildCost::Unknown;
    let mut short_inactivity: CleanupCandidate = temporary("c", MIB, 1);
    short_inactivity.facts.activity = inactive(10);
    let mut long_inactivity: CleanupCandidate = temporary("e", MIB, 1);
    long_inactivity.facts.activity = inactive(100);
    let mut same_as_e: CleanupCandidate = temporary("d", MIB, 1);
    same_as_e.facts.activity = inactive(100);
    // A large estimate has no effect on the rank.
    second_rule.estimated_reclaimable_bytes = Some(Bytes::new(900 * GIB));

    let expected: [&str; 6] = ["d", "e", "c", "b", "f", "a"];
    let forward: Vec<CleanupCandidate> = vec![
        second_rule,
        high_cost,
        unknown_cost,
        short_inactivity,
        long_inactivity,
        same_as_e,
    ];
    let mut backward: Vec<CleanupCandidate> = forward.clone();
    backward.reverse();
    // The sequence of the input has no effect.
    for candidates in [forward, backward] {
        let plan: CleanupPlan = plan_at(&mut Harness::new(), 0, candidates);
        let order: Vec<&str> = plan
            .decisions
            .iter()
            .map(|decision| decision.target_id.as_str())
            .collect();
        assert_eq!(order, expected);
        let ranks: Vec<Option<u32>> = plan
            .decisions
            .iter()
            .map(|decision| decision.rank)
            .collect();
        assert_eq!(
            ranks,
            [Some(1), Some(2), Some(3), Some(4), Some(5), Some(6)]
        );
        assert_eq!(plan.first_batches[0].targets.len(), 6);
    }
}

#[test]
fn the_batch_ceilings_admit_the_exact_limit_and_skip_one_more() {
    // The batch ceilings are 1 GiB and 256 entries.
    let plan: CleanupPlan = plan_at(
        &mut Harness::new(),
        0,
        vec![
            temporary("a_exact", GIB, 256),
            temporary("b_bytes_over", GIB + 1, 1),
            temporary("c_items_over", 1, 257),
        ],
    );
    let exact: &CleanupDecision = &plan.decisions[0];
    assert_eq!(exact.decision, CandidateDecision::Eligible);
    assert!(exact.in_first_batch);
    for over in &plan.decisions[1..] {
        assert_eq!(over.decision, CandidateDecision::Skipped);
        assert_eq!(
            over.reasons,
            [explanation(
                DecisionReason::BudgetExhausted,
                ReasonDetail::ExceedsBatchLimit
            )]
        );
        assert!(!over.in_first_batch);
        assert!(over.rank.is_some());
    }
    let batch = &plan.first_batches[0];
    assert_eq!(batch.work_bytes, Bytes::new(GIB));
    assert_eq!(batch.item_count, EntryCount::new(256));
    assert_eq!(batch.targets, [TargetId::new("a_exact").unwrap()]);
}

#[test]
fn a_candidate_that_does_not_fit_the_rest_of_the_batch_waits_for_a_later_batch() {
    let plan: CleanupPlan = plan_at(
        &mut Harness::new(),
        0,
        vec![
            temporary("a", 600 * MIB, 100),
            temporary("b", 600 * MIB, 100),
            temporary("c", 424 * MIB, 100),
            temporary("d", 0, 57),
        ],
    );
    let in_batch: Vec<bool> = plan
        .decisions
        .iter()
        .map(|decision| decision.in_first_batch)
        .collect();
    // 600 MiB + 424 MiB is the 1 GiB ceiling. The 256-entry ceiling then
    // has 56 entries left, and the last candidate has 57.
    assert_eq!(in_batch, [true, false, true, false]);
    // A candidate that waits for a later batch is skipped for this one.
    for waiting in [&plan.decisions[1], &plan.decisions[3]] {
        assert_eq!(waiting.decision, CandidateDecision::Skipped);
        assert_eq!(
            waiting.reasons,
            [explanation(
                DecisionReason::BudgetExhausted,
                ReasonDetail::BatchFull
            )]
        );
    }

    assert_eq!(plan.first_batches[0].work_bytes, Bytes::new(GIB));
    assert_eq!(plan.first_batches[0].item_count, EntryCount::new(200));
    assert_eq!(
        plan.first_batches[0].estimated_reclaimable_bytes,
        Some(Bytes::new(GIB))
    );
}

/// A harness with an open incident, at 30 s.
fn with_incident() -> Harness {
    let mut harness: Harness = Harness::new();
    assert_eq!(harness.disk_hold(0, 30, 9 * GIB).state, TriggerState::Ready);
    harness
}

#[test]
fn the_pass_and_incident_allowances_are_exact_at_their_limits() {
    // The incident ceiling is 16 GiB: 512 MiB are left.
    let mut harness: Harness = with_incident();
    harness.disk.incidents[0].usage.consumed_bytes = Bytes::new(15 * GIB);
    harness.disk.incidents[0].usage.reserved_bytes = Bytes::new(512 * MIB);
    let plan: CleanupPlan = plan_at(
        &mut harness,
        35,
        vec![
            temporary("a_exact", 512 * MIB, 1),
            temporary("b_over", 512 * MIB + 1, 1),
        ],
    );
    assert!(plan.decisions[0].in_first_batch);
    assert_eq!(
        plan.decisions[1].reasons,
        [explanation(
            DecisionReason::BudgetExhausted,
            ReasonDetail::ExceedsIncidentLimit
        )]
    );
    assert_eq!(
        plan.first_batches[0].allowance.incident_remaining,
        Bytes::new(512 * MIB)
    );
    assert!(plan.first_batches[0].admissible_now);

    // The pass ceiling is 8 GiB: 100 MiB are left in the pass in progress.
    let mut harness: Harness = with_incident();
    harness.disk.incidents[0].passes_started = 1;
    harness.disk.incidents[0].current_pass = Some(WorkUsage {
        consumed_bytes: Bytes::new(8 * GIB - 100 * MIB),
        ..WorkUsage::default()
    });
    let plan: CleanupPlan = plan_at(
        &mut harness,
        35,
        vec![
            temporary("a_exact", 100 * MIB, 1),
            temporary("b_over", 100 * MIB + 1, 1),
        ],
    );
    assert!(plan.decisions[0].in_first_batch);
    assert_eq!(
        plan.decisions[1].reasons,
        [explanation(
            DecisionReason::BudgetExhausted,
            ReasonDetail::ExceedsPassLimit
        )]
    );
    assert_eq!(plan.first_batches[0].allowance.passes_remaining, 2);

    // The entry ceiling of the incident is 4096.
    let mut harness: Harness = with_incident();
    harness.disk.incidents[0].usage.consumed_items = EntryCount::new(4000);
    let plan: CleanupPlan = plan_at(
        &mut harness,
        35,
        vec![temporary("a_exact", 1, 96), temporary("b_over", 1, 97)],
    );
    assert!(plan.decisions[0].in_first_batch);
    assert_eq!(
        plan.decisions[1].reasons,
        [explanation(
            DecisionReason::BudgetExhausted,
            ReasonDetail::ExceedsIncidentLimit
        )]
    );
}

#[test]
fn usage_above_a_lowered_limit_leaves_no_allowance() {
    let mut harness: Harness = with_incident();
    // The consumed usage is larger than the ceiling, as after a policy
    // change that lowers the limit.
    harness.disk.incidents[0].usage.consumed_bytes = Bytes::new(20 * GIB);
    harness.disk.incidents[0].usage.reserved_bytes = Bytes::MAX;
    let plan: CleanupPlan = plan_at(&mut harness, 35, vec![temporary("a", 1, 1)]);
    let batch = &plan.first_batches[0];
    assert_eq!(batch.allowance.incident_remaining, Bytes::ZERO);
    assert_eq!(batch.targets, []);
    assert!(!batch.admissible_now);
    assert!(batch.blocked_by.contains(&explanation(
        DecisionReason::BudgetExhausted,
        ReasonDetail::ExceedsIncidentLimit
    )));
    assert_eq!(plan.decisions[0].decision, CandidateDecision::Skipped);
    assert_eq!(
        harness.disk.incidents[0].usage.consumed_bytes,
        Bytes::new(20 * GIB)
    );
    assert_eq!(harness.disk_at(40, 9 * GIB).state, TriggerState::Exhausted);
}

#[test]
fn an_incident_with_no_pass_left_is_exhausted() {
    let mut harness: Harness = with_incident();
    harness.disk.incidents[0].passes_started = 2;
    let plan: CleanupPlan = plan_at(&mut harness, 35, vec![temporary("a", 1, 1)]);
    assert_eq!(plan.first_batches[0].allowance.passes_remaining, 0);
    assert_eq!(
        plan.decisions[0].reasons,
        [explanation(
            DecisionReason::BudgetExhausted,
            ReasonDetail::PassCountExhausted
        )]
    );
    assert_eq!(harness.disk_at(40, 9 * GIB).state, TriggerState::Exhausted);

    // One pass before the limit, a new pass can start.
    let mut harness: Harness = with_incident();
    harness.disk.incidents[0].passes_started = 1;
    let plan: CleanupPlan = plan_at(&mut harness, 35, vec![temporary("a", 1, 1)]);
    assert_eq!(plan.first_batches[0].allowance.passes_remaining, 1);
    assert!(plan.first_batches[0].admissible_now);
}

#[test]
fn a_cooldown_inhibits_the_next_pass_until_its_end() {
    let cooldown = |until: u64, boot: &str| Cooldown {
        cause: CooldownCause::PassPacing,
        until: super::monotonic(until),
        clock_domain: ClockDomainId::new("clock_main").unwrap(),
        boot_id: BootId::new(boot).unwrap(),
    };
    // (end of the cooldown, boot, evaluation time, state, reason)
    let cases: [(u64, &str, u64, TriggerState, Option<ReasonDetail>); 4] = [
        (
            100,
            "boot_1",
            35,
            TriggerState::Cooldown,
            Some(ReasonDetail::PassCooldown),
        ),
        (
            36,
            "boot_1",
            35,
            TriggerState::Cooldown,
            Some(ReasonDetail::PassCooldown),
        ),
        (35, "boot_1", 35, TriggerState::Ready, None),
        // The end of a cooldown of an earlier boot is not known.
        (
            1,
            "boot_0",
            35,
            TriggerState::Cooldown,
            Some(ReasonDetail::CooldownClockUnknown),
        ),
    ];
    for (until, boot, seconds, state, detail) in cases {
        let mut harness: Harness = with_incident();
        harness.disk.incidents[0].cooldown = Some(cooldown(until, boot));
        let plan: CleanupPlan = plan_at(&mut harness, seconds, vec![temporary("a", 1, 1)]);
        let trigger: VolumeTrigger = harness.disk_at(seconds, 9 * GIB);
        assert_eq!(trigger.state, state, "until {until}");
        let expected: Vec<Explanation> = detail
            .map(|detail| explanation(DecisionReason::CooldownActive, detail))
            .into_iter()
            .collect();
        assert_eq!(plan.first_batches[0].blocked_by, expected, "until {until}");
        assert_eq!(plan.first_batches[0].admissible_now, detail.is_none());
    }
}

#[test]
fn the_first_batch_tells_why_it_is_not_admissible() {
    use DecisionReason as Reason;
    use ReasonDetail as Detail;
    let one = || vec![temporary("a", MIB, 1)];

    // The trigger is not sustained.
    let plan: CleanupPlan = plan_at(&mut Harness::new(), 0, one());
    assert_eq!(
        plan.first_batches[0].blocked_by,
        [explanation(
            Reason::TriggerNotSustained,
            Detail::WindowNotQualified
        )]
    );
    assert_eq!(plan.first_batches[0].targets.len(), 1);

    // The trigger is ready: admissible.
    let plan: CleanupPlan = plan_at(&mut with_incident(), 35, one());
    assert!(plan.first_batches[0].admissible_now);
    assert_eq!(plan.first_batches[0].blocked_by, []);

    // No grant.
    let mut harness: Harness = with_incident();
    harness.grants = AssumedGrants::none(GrantBasis::Recorded);
    let plan: CleanupPlan = plan_at(&mut harness, 35, one());
    assert_eq!(
        plan.first_batches[0].blocked_by,
        [explanation(
            Reason::ActionNotGranted,
            Detail::GrantNotAssumed
        )]
    );

    // The guard is disabled, and the profile is `observe`.
    let text: String = BASE_CONFIG
        .replacen("enabled = true", "enabled = false", 1)
        .replace(r#"profile = "balanced""#, r#"profile = "observe""#);
    let mut harness: Harness = Harness::with_config(&text);
    harness.disk_hold(0, 30, 9 * GIB);
    let plan: CleanupPlan = plan_at(&mut harness, 35, one());
    assert_eq!(
        plan.first_batches[0].blocked_by,
        [
            explanation(Reason::ActionNotGranted, Detail::GuardDisabled),
            explanation(Reason::ActionNotGranted, Detail::ObserveProfile),
        ]
    );

    // No eligible candidate.
    let plan: CleanupPlan = plan_at(&mut with_incident(), 35, Vec::new());
    assert_eq!(
        plan.first_batches[0].blocked_by,
        [explanation(
            Reason::TargetNotEligible,
            Detail::NoEligibleCandidate
        )]
    );
}

#[test]
fn a_snapshot_above_its_limits_is_rejected() {
    let harness: Harness = Harness::new();
    let mut snapshot: DiskSnapshot = disk_snapshot(9 * GIB, 0);
    snapshot.candidates = vec![temporary("a", 1, 1); MAX_CLEANUP_CANDIDATES + 1];
    let clock: EvaluationClock = harness.clock(0);
    let error: PolicyInputError =
        evaluate_disk_guard(&harness.context(&clock), &harness.disk, &snapshot).unwrap_err();
    assert_eq!(
        error,
        PolicyInputError::TooManyEntries {
            list: "cleanup candidates",
            count: MAX_CLEANUP_CANDIDATES + 1,
            limit: MAX_CLEANUP_CANDIDATES,
        }
    );
    snapshot.candidates.pop();
    assert!(evaluate_disk_guard(&harness.context(&clock), &harness.disk, &snapshot).is_ok());
}

#[test]
fn equal_inputs_give_an_equal_disk_evaluation() {
    let identity = volume("data", shared("domain_disk3"));
    let reading = capacity_reading(&identity, Reading::Available(Bytes::new(9 * GIB)), 0);
    let evidence: VolumeEvidence = VolumeEvidence {
        selector: VolumeSelector::new("startup-data").unwrap(),
        identity,
        available: reading,
    };
    let snapshot: DiskSnapshot = DiskSnapshot {
        volumes: vec![evidence],
        candidates: Vec::new(),
    };
    let mut harness: Harness = Harness::new();
    let first: DiskEvaluation = harness.disk(0, &snapshot);
    let again: DiskEvaluation = Harness::new().disk(0, &snapshot);
    assert_eq!(first, again);
}

#[test]
fn a_sample_from_before_a_wake_is_not_usable() {
    let mut harness: Harness = Harness::new();
    harness.disk_hold(0, 10, 9 * GIB);
    // The host woke at 12 s. The evaluation at 15 s reads the sample of
    // 10 s again: its age is 5 seconds, and it is from before the wake.
    harness.continuity += 1;
    harness.last_discontinuity = Some(12);
    let cached: VolumeTrigger = harness
        .disk(15, &disk_snapshot(9 * GIB, 10))
        .volumes
        .remove(0);
    assert_eq!(cached.state, TriggerState::Blocked);
    assert_eq!(
        cached.reasons,
        [explanation(
            DecisionReason::MetricStale,
            ReasonDetail::SampleBeforeDiscontinuity
        )]
    );
    // The window starts at the first sample after the wake.
    assert_eq!(
        harness.disk_hold(15, 40, 9 * GIB).state,
        TriggerState::Qualifying
    );
    assert_eq!(harness.disk_at(45, 9 * GIB).state, TriggerState::Ready);
}

#[test]
fn a_path_that_is_not_canonical_skips_the_candidate() {
    let paths: [&str; 3] = [
        // The components show a cache; the file is in an excluded directory.
        "/Users/tester/Library/Caches/x/../../../Documents/f",
        "Users/tester/Library/Caches/x",
        "/Users/tester/./Library/Caches/x",
    ];
    for text in paths {
        let decided: CleanupDecision = decide(|one| one.path = path(text));
        assert_eq!(decided.decision, CandidateDecision::Skipped, "{text}");
        assert_eq!(
            decided.reasons,
            [explanation(
                DecisionReason::MetricUnavailable,
                ReasonDetail::PathNotCanonical
            )],
            "{text}"
        );
        assert!(!decided.in_first_batch);
    }
}

#[test]
fn a_domain_change_or_unusable_evidence_does_not_close_or_reset_an_incident() {
    let mut harness: Harness = with_incident();
    harness.disk.incidents[0].usage.consumed_bytes = Bytes::new(16 * GIB);
    let moved = |bytes: u64, seconds: u64| {
        let mut snapshot: DiskSnapshot = disk_snapshot(bytes, seconds);
        snapshot.volumes[0].identity.capacity_domain = CapacityDomainMembership::Exclusive;
        snapshot
    };
    // The volume reports a different capacity domain, and its capacity is
    // not available.
    let mut unusable: DiskSnapshot = moved(30 * GIB, 35);
    unusable.volumes[0].available.reading =
        Reading::Unavailable(UnavailableReason::TransientFailure);
    let blocked: VolumeTrigger = harness.disk(35, &unusable).volumes.remove(0);
    assert_eq!(blocked.state, TriggerState::Blocked);
    assert!(blocked.incident_open);
    assert_eq!(harness.disk.incidents.len(), 1);

    // With usable capacity, the volume stays in its incident: no new
    // incident with a new allowance opens for the new domain.
    let mut last: Option<VolumeTrigger> = None;
    for seconds in (40..=70).step_by(5) {
        last = Some(
            harness
                .disk(seconds, &moved(5 * GIB, seconds))
                .volumes
                .remove(0),
        );
    }
    assert_eq!(last.unwrap().state, TriggerState::Exhausted);
    assert_eq!(harness.disk.incidents.len(), 1);
    assert_eq!(
        harness.disk.incidents[0].usage.consumed_bytes,
        Bytes::new(16 * GIB)
    );
}

#[test]
fn a_new_selector_for_the_same_volume_keeps_the_incident() {
    let mut harness: Harness = with_incident();
    harness.disk.incidents[0].usage.consumed_bytes = Bytes::new(GIB);
    harness.config = super::config_from(&BASE_CONFIG.replace("startup-data", "data-by-uuid"));
    let mut snapshot: DiskSnapshot = disk_snapshot(9 * GIB, 35);
    snapshot.volumes[0].selector = VolumeSelector::new("data-by-uuid").unwrap();
    let trigger: VolumeTrigger = harness.disk(35, &snapshot).volumes.remove(0);
    assert_eq!(trigger.selector, "data-by-uuid");
    assert_eq!(trigger.state, TriggerState::Qualifying);
    assert!(trigger.incident_open);
    assert_eq!(harness.disk.incidents.len(), 1);
    assert_eq!(
        harness.disk.incidents[0].usage.consumed_bytes,
        Bytes::new(GIB)
    );
}

fn two_volumes(data: u64, system: u64, seconds: u64) -> DiskSnapshot {
    DiskSnapshot {
        volumes: vec![
            volume_evidence(
                "startup-data",
                volume("data", shared("domain_disk3")),
                data,
                seconds,
            ),
            volume_evidence(
                "system",
                volume("system", shared("domain_disk3")),
                system,
                seconds,
            ),
        ],
        candidates: Vec::new(),
    }
}

fn two_volume_harness() -> Harness {
    Harness::with_config(&BASE_CONFIG.replace(
        r#"volumes = ["startup-data"]"#,
        r#"volumes = ["startup-data", "system"]"#,
    ))
}

#[test]
fn a_continuation_window_does_not_qualify_the_entry_predicate() {
    let mut harness: Harness = two_volume_harness();
    for seconds in (0..=30).step_by(5) {
        harness.disk(seconds, &two_volumes(9 * GIB, 26 * GIB, seconds));
    }
    assert_eq!(harness.disk.incidents.len(), 1);
    // The first volume recovers from 35 s to 95 s. The second volume is
    // below the recovery target from 80 s: a continuation window.
    for seconds in (35..=95).step_by(5) {
        let system: u64 = if seconds < 80 { 26 * GIB } else { 15 * GIB };
        harness.disk(seconds, &two_volumes(26 * GIB, system, seconds));
    }
    assert_eq!(harness.disk.incidents, []);
    // The second volume goes below the reclaim threshold at 100 s. The
    // entry needs 30 seconds from there, not from 80 s.
    for seconds in (100..=125).step_by(5) {
        let evaluation: DiskEvaluation =
            harness.disk(seconds, &two_volumes(26 * GIB, 9 * GIB, seconds));
        assert_eq!(
            evaluation.volumes[1].state,
            TriggerState::Qualifying,
            "{seconds}"
        );
    }
    let evaluation: DiskEvaluation = harness.disk(130, &two_volumes(26 * GIB, 9 * GIB, 130));
    assert_eq!(evaluation.volumes[1].state, TriggerState::Ready);
}

#[test]
fn the_volumes_of_one_domain_share_one_allowance_in_a_plan() {
    let mut harness: Harness = two_volume_harness();
    for seconds in (0..=35).step_by(5) {
        harness.disk(seconds, &two_volumes(9 * GIB, 9 * GIB, seconds));
    }
    // 1 GiB of the incident ceiling is left.
    harness.disk.incidents[0].usage.consumed_bytes = Bytes::new(15 * GIB);
    let mut on_system: CleanupCandidate = temporary("b_system", GIB, 1);
    on_system.volume_id = VolumeId::new("vol_system").unwrap();
    let mut snapshot: DiskSnapshot = two_volumes(9 * GIB, 9 * GIB, 40);
    snapshot.candidates = vec![temporary("a_data", GIB, 1), on_system];
    let evaluation: DiskEvaluation = harness.disk(40, &snapshot);
    let clock: EvaluationClock = harness.clock(40);
    let plan: CleanupPlan = plan_cleanup(&harness.context(&clock), &evaluation, &snapshot);
    assert!(plan.first_batches[0].admissible_now);
    assert_eq!(plan.first_batches[0].work_bytes, Bytes::new(GIB));
    assert_eq!(
        plan.first_batches[1].allowance.incident_remaining,
        Bytes::ZERO
    );
    assert_eq!(plan.first_batches[1].targets, []);
    assert!(!plan.first_batches[1].admissible_now);
    assert_eq!(
        plan.decisions[1].reasons,
        [explanation(
            DecisionReason::BudgetExhausted,
            ReasonDetail::ExceedsIncidentLimit
        )]
    );
}

#[test]
fn a_full_pass_admits_no_candidate_also_with_a_charge_of_zero() {
    let mut harness: Harness = with_incident();
    harness.disk.incidents[0].passes_started = 1;
    harness.disk.incidents[0].current_pass = Some(WorkUsage {
        consumed_bytes: Bytes::new(8 * GIB),
        ..WorkUsage::default()
    });
    let plan: CleanupPlan = plan_at(&mut harness, 35, vec![temporary("a", 0, 0)]);
    assert_eq!(plan.first_batches[0].targets, []);
    assert!(!plan.first_batches[0].admissible_now);
    assert_eq!(
        plan.first_batches[0].blocked_by,
        [
            explanation(
                DecisionReason::BudgetExhausted,
                ReasonDetail::ExceedsPassLimit
            ),
            explanation(
                DecisionReason::TargetNotEligible,
                ReasonDetail::NoEligibleCandidate
            ),
        ]
    );
}
