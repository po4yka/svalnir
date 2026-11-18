//! Regression tests of the review of Milestone 2. Each test fails without
//! the check that it names.

use super::{
    BUILT_AT, Fixture, charge, clock_at, declaration, entry, manual_validated, path, planned,
    request, rule, trash,
};
use crate::action::Checked;
use crate::id::{RootId, VolumeId};
use crate::plan::{
    CleanupEntry, ModeSelection, OmissionReason, PlanExplanation, PlanOutcome, TargetExplanation,
    build_cleanup_plan, explain,
};
use crate::policy::ProtectionFact;
use crate::quantity::Bytes;
use crate::rule::Rule;

fn reasons(outcome: &PlanOutcome, name: &str) -> Vec<OmissionReason> {
    let target_id: String = format!("target_{name}");
    outcome
        .preview
        .omitted
        .iter()
        .find(|omission| omission.target_id.as_str() == target_id)
        .map_or_default(|omission| omission.reasons.clone())
}

#[test]
fn the_evict_mode_charges_no_more_than_one_pass_of_the_rule() {
    let fixture: Fixture = Fixture::new();
    let mut declaration = declaration(manual_validated());
    declaration.budget.per_candidate = charge(200, 100);
    declaration.budget.per_pass = charge(250, 1_000);
    let rule: Rule = Checked::new(declaration).unwrap();
    // The ceiling of the request is larger than the pass ceiling of the
    // rule.
    let entries: [CleanupEntry; 3] = [entry("a", 100), entry("b", 200), entry("c", 50)];

    let selection = ModeSelection::Evict { rule: Ok(&rule) };
    let outcome: PlanOutcome =
        build_cleanup_plan(&fixture.context(), &request(selection, &entries)).unwrap();
    assert_eq!(planned(&outcome), ["target_a", "target_c"]);
    assert_eq!(reasons(&outcome, "b"), [OmissionReason::ExceedsPlanLimit]);
    assert_eq!(
        outcome.plan.as_ref().unwrap().limits.work,
        Some(charge(150, 20))
    );

    // A mode with no rule has the ceiling of the request only.
    let outcome: PlanOutcome = trash(&entries);
    assert_eq!(planned(&outcome), ["target_a", "target_b", "target_c"]);
}

/// The entry `id` with the name `name` in the root of the tests. A target
/// identity is ASCII, and a name is not.
fn named(id: &str, name: &str) -> CleanupEntry {
    let mut entry: CleanupEntry = entry(id, 100);
    entry.path = path(&format!("/Users/a/Library/Caches/{name}"));
    entry.relative_entry = path(name);
    entry
}

#[test]
fn two_entries_with_names_that_are_not_ascii_are_two_entries() {
    // Two files of one directory, and two entries of different directories.
    let entries: [CleanupEntry; 4] = [
        named("a", "фото1.jpg"),
        named("b", "фото2.jpg"),
        named("c", "é"),
        named("d", "b/c"),
    ];
    let outcome: PlanOutcome = trash(&entries);
    assert_eq!(outcome.preview.omitted, []);
    assert_eq!(
        planned(&outcome),
        ["target_a", "target_b", "target_c", "target_d"]
    );

    // An entry inside a selected entry is left out, with a name that is
    // not ASCII and with a different case.
    let entries: [CleanupEntry; 3] = [
        named("a", "Фото"),
        named("b", "фото/2026"),
        named("c", "фото2"),
    ];
    let outcome: PlanOutcome = trash(&entries);
    assert_eq!(planned(&outcome), ["target_a", "target_c"]);
    assert_eq!(
        reasons(&outcome, "b"),
        [OmissionReason::OverlapsSelectedEntry]
    );
}

#[test]
fn one_object_with_two_names_has_one_step_and_one_charge() {
    // The same volume and the same native identifiers: one object.
    let first: CleanupEntry = entry("a", 100);
    let mut alias: CleanupEntry = entry("b", 100);
    alias.object = first.object;
    let entries: [CleanupEntry; 2] = [alias.clone(), first.clone()];
    let outcome: PlanOutcome = trash(&entries);
    assert_eq!(planned(&outcome), ["target_a"]);
    assert_eq!(
        reasons(&outcome, "b"),
        [OmissionReason::OverlapsSelectedEntry]
    );
    assert_eq!(
        outcome.plan.as_ref().unwrap().limits.work,
        Some(charge(100, 10))
    );

    // The same identifiers on a different volume are a different object.
    let mut other_volume: CleanupEntry = alias.clone();
    other_volume.volume_id = VolumeId::new("volume_other").unwrap();
    let outcome: PlanOutcome = trash(&[first.clone(), other_volume]);
    assert_eq!(planned(&outcome), ["target_a", "target_b"]);

    // Absent identifiers are not equal identifiers.
    let mut unknown_first: CleanupEntry = first;
    unknown_first.object = None;
    let mut unknown_second: CleanupEntry = alias;
    unknown_second.object = None;
    let outcome: PlanOutcome = trash(&[unknown_first, unknown_second]);
    assert_eq!(planned(&outcome), ["target_a", "target_b"]);
}

#[test]
fn an_entry_inside_a_repeated_object_is_left_out() {
    // Two roots are one directory. `b` is the object of `a` through the
    // second root, which has a longer path, and `c` is inside `b`. The path
    // of `c` is not inside the path of `a`.
    let in_alias = |id: &str, name: &str| {
        let mut entry: CleanupEntry = entry(id, 100);
        entry.root_id = RootId::new("root_alias").unwrap();
        entry.root_path = path("/Users/a/Library/Saved/Alias");
        entry.path = path(&format!("/Users/a/Library/Saved/Alias/{name}"));
        entry.relative_entry = path(name);
        entry
    };
    let first: CleanupEntry = named("a", "d");
    let mut alias: CleanupEntry = in_alias("b", "d");
    alias.object = first.object;
    let inside: CleanupEntry = in_alias("c", "d/e");
    let outcome: PlanOutcome = trash(&[inside, alias, first]);
    assert_eq!(planned(&outcome), ["target_a"]);
    for name in ["b", "c"] {
        assert_eq!(
            reasons(&outcome, name),
            [OmissionReason::OverlapsSelectedEntry],
            "{name}"
        );
    }
}

#[test]
fn a_target_of_a_trash_plan_has_no_estimate_of_reclaimable_bytes() {
    let fixture: Fixture = Fixture::new();
    let rule: Rule = rule();
    let mut protected: CleanupEntry = entry("b", 100);
    protected.hard_protection = ProtectionFact::Protected;
    let entries: [CleanupEntry; 2] = [entry("a", 100), protected];
    let reclaimable = |selection: ModeSelection<'_>| {
        let outcome: PlanOutcome =
            build_cleanup_plan(&fixture.context(), &request(selection, &entries)).unwrap();
        let explanation: PlanExplanation = explain(&outcome, &clock_at(BUILT_AT + 60));
        // An entry that was left out has the estimate of its mode also.
        let [omission] = explanation.omitted.as_slice() else {
            panic!("one entry was left out");
        };
        let of_target = match explanation.targets.as_slice() {
            [TargetExplanation::File { estimate, .. }] => estimate.estimated_reclaimable_bytes,
            _ => panic!("the plan has one file target"),
        };
        assert_eq!(omission.estimate.estimated_reclaimable_bytes, of_target);
        let [TargetExplanation::File { estimate, .. }] = explanation.targets.as_slice() else {
            panic!("the plan has one file target");
        };
        assert_eq!(estimate.logical_bytes, Some(Bytes::new(100)));
        estimate.estimated_reclaimable_bytes
    };
    assert_eq!(reclaimable(ModeSelection::Trash), None);
    assert_eq!(reclaimable(ModeSelection::Permanent), Some(Bytes::new(50)));
    assert_eq!(
        reclaimable(ModeSelection::Evict { rule: Ok(&rule) }),
        Some(Bytes::new(50))
    );
}
