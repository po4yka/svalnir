//! Tests of the explanation of a plan.

use super::{
    BUILT_AT, Fixture, LIFETIME, SECOND, charge, clock_at, entry, modes, path, request, rule,
    rule_reference, trash,
};
use crate::action::{ActionClass, WorkCharge};
use crate::plan::{
    CleanupEntry, CleanupMode, Consequence, ESTIMATE_STATEMENT, OmissionReason, PlanExplanation,
    PlanMode, PlanOutcome, StopKind, TargetExplanation, build_cleanup_plan, explain,
};
use crate::policy::ProtectionFact;
use crate::quantity::{Bytes, Nanoseconds};
use crate::rule::Rule;
use crate::time::MonotonicNanos;

/// The explanation of a plan of each mode for two entries of 100 and 300
/// bytes and one protected entry.
fn explanations() -> Vec<PlanExplanation> {
    let fixture: Fixture = Fixture::new();
    let rule: Rule = rule();
    let mut protected: CleanupEntry = entry("c", 100);
    protected.hard_protection = ProtectionFact::Protected;
    let entries: [CleanupEntry; 3] = [entry("b", 300), protected, entry("a", 100)];
    modes(&rule)
        .into_iter()
        .map(|selection| {
            let outcome: PlanOutcome =
                build_cleanup_plan(&fixture.context(), &request(selection, &entries)).unwrap();
            explain(&outcome, &clock_at(BUILT_AT + 60))
        })
        .collect()
}

#[test]
fn each_mode_states_its_consequence() {
    let [trash, permanent, evict] = <[PlanExplanation; 3]>::try_from(explanations()).unwrap();

    assert_eq!(trash.mode, PlanMode::Cleanup(CleanupMode::Trash));
    assert_eq!(trash.consequence, Consequence::TrashNotReclaimed);
    assert!(
        trash
            .consequence_statement
            .contains("not reclaimed capacity")
    );
    assert!(!trash.counts_as_reclaimed_capacity);
    assert!(!trash.consequence.is_irreversible());
    // A move to Trash has no estimate of reclaimed bytes, also when each
    // entry has one.
    assert_eq!(trash.totals.estimated_reclaimable_bytes, None);
    assert_eq!(trash.totals.estimated_logical_bytes, Some(Bytes::new(400)));

    assert_eq!(permanent.consequence, Consequence::PermanentNoUndo);
    assert!(permanent.consequence_statement.contains("has no undo"));
    assert!(permanent.counts_as_reclaimed_capacity);
    assert!(permanent.consequence.is_irreversible());
    assert_eq!(
        permanent.totals.estimated_reclaimable_bytes,
        Some(Bytes::new(200))
    );

    assert_eq!(evict.consequence, Consequence::EvictionNoUndo);
    assert!(evict.consequence_statement.contains("has no undo"));
    assert!(evict.consequence_statement.contains("make the data again"));
    assert!(evict.consequence.is_irreversible());

    for explanation in [&trash, &permanent, &evict] {
        assert_eq!(explanation.estimate_statement, ESTIMATE_STATEMENT);
        assert_eq!(
            explanation.consequence_statement,
            explanation.consequence.statement()
        );
    }
    assert_eq!(
        Consequence::of(PlanMode::Stop(StopKind::Graceful)),
        Consequence::GracefulExit
    );
    assert!(!Consequence::GracefulExit.is_irreversible());
    assert!(Consequence::ForceAfterGrace.is_irreversible());
    assert!(Consequence::ImmediateForce.is_irreversible());
}

#[test]
fn the_explanation_shows_what_an_approval_covers() {
    let explanation: PlanExplanation = explanations().remove(2);
    let summary = explanation.plan.as_ref().unwrap();
    assert_eq!(summary.plan_id.as_str(), "plan_1");
    assert!(summary.digest.as_str().starts_with("sha256:"));
    assert_eq!(summary.action_classes, [ActionClass::EvictRegenerableData]);
    assert_eq!(
        summary.revisions.authority.policy_revision.as_str(),
        "policy_1"
    );
    assert_eq!(summary.revisions.rules, [rule_reference("r1")]);
    assert_eq!(summary.grace, None);
    assert_eq!(summary.execution_deadline, Nanoseconds::new(300 * SECOND));

    // The expiry, one minute after the plan was built.
    let expiry = &summary.expiry;
    assert_eq!(expiry.created_at, MonotonicNanos::new(BUILT_AT * SECOND));
    assert_eq!(expiry.lifetime, Some(LIFETIME));
    assert!(!expiry.expired);
    assert_eq!(expiry.remaining, Some(Nanoseconds::new(540 * SECOND)));

    // The targets of the plan, with the charge apart from the estimates.
    assert_eq!(explanation.totals.targets, 2);
    assert_eq!(explanation.totals.admission_charge, Some(charge(400, 20)));
    let [first, second] = explanation.targets.as_slice() else {
        panic!("the plan has two targets");
    };
    let TargetExplanation::File {
        target_id,
        path: display_path,
        relative_entry,
        rule,
        admission_charge,
        estimate,
        has_object_evidence,
        ..
    } = first
    else {
        panic!("a cleanup plan has file targets");
    };
    assert_eq!(target_id.as_str(), "target_a");
    assert_eq!(display_path, &Some(path("/Users/a/Library/Caches/a")));
    assert_eq!(relative_entry, &path("a"));
    assert_eq!(rule, &Some(rule_reference("r1")));
    assert_eq!(admission_charge, &charge(100, 10));
    assert_eq!(estimate.logical_bytes, Some(Bytes::new(100)));
    assert_eq!(estimate.estimated_reclaimable_bytes, Some(Bytes::new(50)));
    assert!(has_object_evidence);
    assert!(matches!(second, TargetExplanation::File { target_id, .. }
        if target_id.as_str() == "target_b"));

    // The entry that was left out, with its reason.
    let [omission] = explanation.omitted.as_slice() else {
        panic!("one entry was left out");
    };
    assert_eq!(omission.target_id.as_str(), "target_c");
    assert_eq!(omission.reasons, [OmissionReason::HardProtected]);
    assert_eq!(explanation.batches.len(), 1);
    assert_eq!(explanation.preset, None);
}

#[test]
fn an_estimate_that_is_absent_gives_no_sum() {
    let fixture: Fixture = Fixture::new();
    let mut no_estimate: CleanupEntry = entry("b", 300);
    no_estimate.estimate.estimated_reclaimable_bytes = None;
    let entries: [CleanupEntry; 2] = [entry("a", 100), no_estimate];
    let outcome: PlanOutcome = build_cleanup_plan(
        &fixture.context(),
        &request(crate::plan::ModeSelection::Permanent, &entries),
    )
    .unwrap();
    let explanation: PlanExplanation = explain(&outcome, &clock_at(BUILT_AT));
    // An absent estimate is not zero.
    assert_eq!(explanation.totals.estimated_reclaimable_bytes, None);
    assert_eq!(
        explanation.totals.estimated_logical_bytes,
        Some(Bytes::new(400))
    );

    // A sum that overflows is not a sum.
    let mut huge: [CleanupEntry; 2] = [entry("a", 100), entry("b", 100)];
    for entry in &mut huge {
        entry.estimate.logical_bytes = Some(Bytes::MAX);
    }
    let explanation: PlanExplanation = explain(&trash(&huge), &clock_at(BUILT_AT));
    assert_eq!(explanation.totals.estimated_logical_bytes, None);
    assert_eq!(
        explanation.totals.admission_charge,
        Some(WorkCharge::new(
            Bytes::new(200),
            crate::quantity::EntryCount::new(20)
        ))
    );
}

#[test]
fn an_empty_plan_is_explained() {
    let mut protected: CleanupEntry = entry("a", 100);
    protected.hard_protection = ProtectionFact::Unknown;
    let outcome: PlanOutcome = trash(&[protected]);
    let explanation: PlanExplanation = explain(&outcome, &clock_at(BUILT_AT));
    assert_eq!(explanation.plan, None);
    assert_eq!(explanation.targets, []);
    assert_eq!(explanation.totals.targets, 0);
    assert_eq!(explanation.totals.admission_charge, None);
    assert_eq!(explanation.totals.estimated_logical_bytes, None);
    assert_eq!(explanation.consequence, Consequence::TrashNotReclaimed);
    assert_eq!(
        explanation.omitted[0].reasons,
        [OmissionReason::ProtectionUnknown]
    );
}

#[test]
fn the_explanation_shows_an_expired_plan_as_expired() {
    let outcome: PlanOutcome = trash(&[entry("a", 100)]);
    let at_expiry: PlanExplanation = explain(&outcome, &clock_at(BUILT_AT + 600));
    let expiry = &at_expiry.plan.as_ref().unwrap().expiry;
    assert!(expiry.expired);
    assert_eq!(expiry.remaining, None);

    let mut other_boot = clock_at(BUILT_AT + 1);
    other_boot.boot_id = crate::id::BootId::new("boot_2").unwrap();
    let after_restart: PlanExplanation = explain(&outcome, &other_boot);
    let expiry = &after_restart.plan.as_ref().unwrap().expiry;
    assert!(expiry.expired);
    assert_eq!(expiry.remaining, None);
}

#[test]
fn the_json_of_an_explanation_names_each_estimate_as_an_estimate() {
    let explanation: PlanExplanation = explanations().remove(1);
    let value: serde_json::Value = serde_json::to_value(&explanation).unwrap();
    assert_eq!(value["consequence"], "permanent_no_undo");
    assert_eq!(value["counts_as_reclaimed_capacity"], true);
    assert_eq!(value["totals"]["estimated_reclaimable_bytes"], "200");
    let target = &value["targets"][0];
    assert_eq!(target["kind"], "file");
    assert_eq!(target["admission_charge"]["work_bytes"], "100");
    assert_eq!(target["estimate"]["estimated_reclaimable_bytes"], "50");
    assert_eq!(
        value["omitted"][0]["reasons"][0]["reason"],
        "hard_protected"
    );
    assert_eq!(value["plan"]["expiry"]["expired"], false);
}

#[test]
fn the_mode_of_an_explanation_comes_from_the_sealed_plan() {
    use crate::action::{Escalation, PlanContent};
    use crate::plan::mode_of;
    let fixture: Fixture = Fixture::new();
    let entries: [CleanupEntry; 1] = [entry("a", 100)];
    let mut outcome: PlanOutcome = build_cleanup_plan(
        &fixture.context(),
        &request(crate::plan::ModeSelection::Permanent, &entries),
    )
    .unwrap();
    // A stored record with a different mode does not change what the
    // reviewer of the digest reads.
    outcome.mode = PlanMode::Cleanup(CleanupMode::Trash);
    let explanation: PlanExplanation = explain(&outcome, &clock_at(BUILT_AT));
    assert_eq!(explanation.mode, PlanMode::Cleanup(CleanupMode::Permanent));
    assert_eq!(explanation.consequence, Consequence::PermanentNoUndo);
    assert!(explanation.counts_as_reclaimed_capacity);

    // Content whose steps do not agree with its force strategy has no
    // mode.
    let mut content: PlanContent = PlanContent::clone(outcome.plan.as_ref().unwrap());
    assert_eq!(
        mode_of(&content),
        Some(PlanMode::Cleanup(CleanupMode::Permanent))
    );
    content.steps[0].action_class = ActionClass::RequestApplicationExit;
    content.limits.escalation = Escalation::ImmediateForce;
    assert_eq!(mode_of(&content), None);
    content.limits.escalation = Escalation::None;
    assert_eq!(mode_of(&content), Some(PlanMode::Stop(StopKind::Graceful)));
    content.steps.clear();
    assert_eq!(mode_of(&content), None);
}
