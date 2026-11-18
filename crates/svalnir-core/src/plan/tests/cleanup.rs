//! Tests of the cleanup plan builder: modes, rules, protections, overlap,
//! limits, batches, and the digest.

use std::collections::BTreeSet;

use super::{
    Fixture, LAYOUT, LIFETIME, SECOND, USER, charge, clock_at, declaration, entry, limits,
    manual_validated, modes, path, planned, request, rule, rule_reference, rule_with, satisfied,
    trash,
};
use crate::action::{
    ActionClass, Checked, ClientRole, ErrorFamily, Escalation, ExecutorRole, FileObjectType,
    PlanError, TargetBinding, TriggerClass, WorkCharge,
};
use crate::authority::{ActionGrantRef, Generation, PrivilegeGrantRef};
use crate::digest::ContentDigest;
use crate::file::{DeviceNumber, FileObjectEvidence, InodeNumber};
use crate::id::{
    ActionGrantId, MountId, PlanId, PolicyRevisionId, PrivilegeGrantId, RootId, RuleId, StepId,
    TargetId, VolumeId,
};
use crate::plan::OmissionReason as Reason;
use crate::plan::{
    BatchError, CleanupEntry, CleanupLimits, CleanupMode, CleanupRequest, MAX_SELECTED_ENTRIES,
    ModeSelection, OmissionReason, PlanBuildError, PlanContext, PlanMode, PlanOutcome,
    RuleEvidence, SelectionPreset, build_cleanup_plan, mode_of, split_batches,
};
use crate::policy::ProtectionFact;
use crate::process::Uid;
use crate::quantity::{Bytes, Nanoseconds};
use crate::rule::{EligibilityPredicate, Fact, LifecycleState, Rule, RuleRefusal};

/// The reasons of the entry `name` in the list of the entries that were
/// left out. Empty when the entry is in the plan.
fn reasons(outcome: &PlanOutcome, name: &str) -> Vec<OmissionReason> {
    let target_id: String = format!("target_{name}");
    outcome
        .preview
        .omitted
        .iter()
        .find(|omission| omission.target_id.as_str() == target_id)
        .map_or_default(|omission| omission.reasons.clone())
}

fn digest_of(outcome: &PlanOutcome) -> ContentDigest {
    outcome.plan.as_ref().unwrap().digest().clone()
}

#[test]
fn each_mode_gives_a_plan_of_its_action_class() {
    let fixture: Fixture = Fixture::new();
    let rule: Rule = rule();
    let entries: [CleanupEntry; 2] = [entry("b", 300), entry("a", 200)];
    let expected: [(CleanupMode, ActionClass); 3] = [
        (CleanupMode::Trash, ActionClass::MoveToTrash),
        (CleanupMode::Permanent, ActionClass::DeleteSelectedFiles),
        (CleanupMode::Evict, ActionClass::EvictRegenerableData),
    ];
    for (selection, (mode, class)) in modes(&rule).into_iter().zip(expected) {
        let outcome: PlanOutcome =
            build_cleanup_plan(&fixture.context(), &request(selection, &entries)).unwrap();
        let plan = outcome.plan.as_ref().unwrap();
        assert_eq!(outcome.mode, PlanMode::Cleanup(mode));
        assert_eq!(mode_of(plan), Some(PlanMode::Cleanup(mode)));
        assert_eq!(mode.action_class(), class);
        assert_eq!(outcome.preview.omitted, []);
        // The targets and the steps have the sequence of the target
        // identities, one step for each target.
        assert_eq!(planned(&outcome), ["target_a", "target_b"]);
        let steps: Vec<(&str, &str)> = plan
            .steps
            .iter()
            .map(|step| (step.step_id.as_str(), step.target_id.as_str()))
            .collect();
        assert_eq!(steps, [("step_a", "target_a"), ("step_b", "target_b")]);
        assert!(plan.steps.iter().all(|step| step.action_class == class));

        assert_eq!(plan.trigger.class, TriggerClass::Manual);
        assert_eq!(plan.executor, ExecutorRole::User);
        assert_eq!(plan.limits.work, Some(charge(500, 20)));
        assert_eq!(plan.limits.escalation, Escalation::None);
        assert_eq!(plan.limits.grace, None);
        assert_eq!(plan.validity.created_at, fixture.clock.now);
        assert_eq!(
            plan.validity.expires_at,
            fixture.clock.now.checked_add(LIFETIME).unwrap()
        );
        // Only the `evict` mode binds a rule revision.
        for target in &plan.targets {
            let TargetBinding::File(file) = &target.binding else {
                panic!("a cleanup plan has file targets only");
            };
            let bound = (mode == CleanupMode::Evict).then(|| rule_reference("r1"));
            assert_eq!(file.rule, bound);
            assert_eq!(file.owner, USER);
        }
    }
}

#[test]
fn the_spelling_of_each_mode_is_the_one_of_the_command() {
    for (mode, text) in CleanupMode::ALL
        .into_iter()
        .zip(["trash", "permanent", "evict"])
    {
        assert_eq!(mode.as_str(), text);
        assert_eq!(mode.to_string(), text);
        assert_eq!(CleanupMode::from_text(text), Some(mode));
    }
    assert_eq!(CleanupMode::from_text("Trash"), None);
    assert_eq!(CleanupMode::from_text("delete"), None);
}

#[test]
fn the_evict_mode_with_no_exact_rule_gives_no_plan() {
    let fixture: Fixture = Fixture::new();
    let entries: [CleanupEntry; 1] = [entry("a", 100)];
    for refusal in [
        RuleRefusal::UnknownRule,
        RuleRefusal::UnknownRevision,
        RuleRefusal::UnknownLayout,
        RuleRefusal::ModeNotValidated,
    ] {
        let selection = ModeSelection::Evict { rule: Err(refusal) };
        let error: PlanBuildError =
            build_cleanup_plan(&fixture.context(), &request(selection, &entries)).unwrap_err();
        assert_eq!(error, PlanBuildError::Rule(refusal));
        assert_eq!(error.family(), ErrorFamily::Eligibility);
    }

    // A rule of the helper executor has no manual plan.
    let mut helper = declaration(manual_validated());
    helper.executor = ExecutorRole::Helper;
    let helper: Rule = Checked::new(helper).unwrap();
    let selection = ModeSelection::Evict { rule: Ok(&helper) };
    assert_eq!(
        build_cleanup_plan(&fixture.context(), &request(selection, &entries)),
        Err(PlanBuildError::UnsupportedExecutor)
    );
}

#[test]
fn the_evict_mode_takes_only_candidates_of_the_exact_validated_revision() {
    let fixture: Fixture = Fixture::new();
    // `keep` is a protected descendant of this rule.
    let mut with_exclusion = declaration(manual_validated());
    with_exclusion.exclusions.descendants = vec![path("keep")];
    let rule: Rule = Checked::new(with_exclusion).unwrap();

    let mut other_revision: CleanupEntry = entry("other_revision", 100);
    other_revision.rule.as_mut().unwrap().rule = rule_reference("r2");
    let mut other_rule: CleanupEntry = entry("other_rule", 100);
    other_rule.rule.as_mut().unwrap().rule.id = RuleId::new("xcode.inactive-derived-data").unwrap();
    let mut no_rule: CleanupEntry = entry("no_rule", 100);
    no_rule.rule = None;
    let mut other_layout: CleanupEntry = entry("other_layout", 100);
    other_layout.rule.as_mut().unwrap().layout = "temporary-v2".to_owned();
    let mut link: CleanupEntry = entry("link", 100);
    link.object_type = FileObjectType::SymbolicLink;
    let mut over_ceiling: CleanupEntry = entry("over_ceiling", 1_000_001);
    over_ceiling.estimate.estimated_reclaimable_bytes = None;
    let at_ceiling: CleanupEntry = entry("at_ceiling", 1_000_000);
    let excluded: CleanupEntry = entry("keep", 100);
    let mut inside_excluded: CleanupEntry = entry("inside", 100);
    inside_excluded.path = path("/Users/a/Library/Caches/KEEP/inside");
    inside_excluded.relative_entry = path("KEEP/inside");

    let entries: [CleanupEntry; 9] = [
        other_revision,
        other_rule,
        no_rule,
        other_layout,
        link,
        over_ceiling,
        at_ceiling,
        excluded,
        inside_excluded,
    ];
    let selection = ModeSelection::Evict { rule: Ok(&rule) };
    let outcome: PlanOutcome =
        build_cleanup_plan(&fixture.context(), &request(selection, &entries)).unwrap();

    assert_eq!(planned(&outcome), ["target_at_ceiling"]);
    assert_eq!(
        reasons(&outcome, "other_revision"),
        [Reason::RuleNotSelected]
    );
    assert_eq!(reasons(&outcome, "other_rule"), [Reason::RuleNotSelected]);
    assert_eq!(reasons(&outcome, "no_rule"), [Reason::RuleNotSelected]);
    assert_eq!(
        reasons(&outcome, "other_layout"),
        [Reason::LayoutNotSupported]
    );
    assert_eq!(reasons(&outcome, "link"), [Reason::ObjectTypeNotSupported]);
    assert_eq!(
        reasons(&outcome, "over_ceiling"),
        [Reason::ExceedsCandidateCeiling]
    );
    assert_eq!(reasons(&outcome, "keep"), [Reason::RuleExclusion]);
    assert_eq!(reasons(&outcome, "inside"), [Reason::RuleExclusion]);

    // The rule of an entry and the exclusions of that rule apply only when
    // the rule executes: a `trash` plan has the same entries. Only the
    // entry inside a different selected entry is left out.
    let trash_outcome: PlanOutcome =
        build_cleanup_plan(&fixture.context(), &request(ModeSelection::Trash, &entries)).unwrap();
    assert_eq!(trash_outcome.preview.omitted.len(), 1);
    assert_eq!(
        reasons(&trash_outcome, "inside"),
        [Reason::OverlapsSelectedEntry]
    );
}

#[test]
fn a_rule_that_is_not_validated_for_manual_eviction_gives_an_empty_plan() {
    let fixture: Fixture = Fixture::new();
    let entries: [CleanupEntry; 1] = [entry("a", 100)];
    let inspection_only = LifecycleState::InspectionValidated {
        evidence: crate::rule::PromotionEvidence {
            record: "VAL-07/record".to_owned(),
        },
    };
    for lifecycle in [
        LifecycleState::Proposed,
        inspection_only,
        LifecycleState::Disabled {
            inspection_permitted: true,
        },
        LifecycleState::Retired,
    ] {
        let rule: Rule = rule_with(lifecycle);
        let selection = ModeSelection::Evict { rule: Ok(&rule) };
        let outcome: PlanOutcome =
            build_cleanup_plan(&fixture.context(), &request(selection, &entries)).unwrap();
        assert_eq!(outcome.plan, None);
        assert_eq!(reasons(&outcome, "a"), [OmissionReason::ModeNotValidated]);
    }
}

#[test]
fn each_eligibility_predicate_must_be_satisfied_for_the_evict_mode() {
    let fixture: Fixture = Fixture::new();
    let rule: Rule = rule();
    let selection = ModeSelection::Evict { rule: Ok(&rule) };
    let set: [fn(&mut crate::rule::CandidateEligibility, Fact); 10] = [
        |evidence, fact| evidence.rule_supports_layout = fact,
        |evidence, fact| evidence.identity_matches = fact,
        |evidence, fact| evidence.within_authorized_scope = fact,
        |evidence, fact| evidence.regenerable = fact,
        |evidence, fact| evidence.age_and_inactivity = fact,
        |evidence, fact| evidence.protocols_valid = fact,
        |evidence, fact| evidence.no_exclusion_overlap = fact,
        |evidence, fact| evidence.unit_and_charge_known = fact,
        |evidence, fact| evidence.resources_available = fact,
        |evidence, fact| evidence.fresh_check = fact,
    ];
    let predicates: Vec<EligibilityPredicate> = satisfied()
        .facts()
        .iter()
        .map(|(predicate, _)| *predicate)
        .collect();
    for (set, predicate) in set.into_iter().zip(predicates) {
        let cases: [(Fact, OmissionReason, ErrorFamily); 3] = [
            (
                Fact::NotSatisfied,
                OmissionReason::EligibilityNotSatisfied { predicate },
                ErrorFamily::Eligibility,
            ),
            (
                Fact::Unknown,
                OmissionReason::EligibilityUnknown { predicate },
                ErrorFamily::Evidence,
            ),
            (
                Fact::from_wire("probably"),
                OmissionReason::EligibilityUnknown { predicate },
                ErrorFamily::Evidence,
            ),
        ];
        for (fact, reason, family) in cases {
            let mut one: CleanupEntry = entry("a", 100);
            set(&mut one.rule.as_mut().unwrap().eligibility, fact);
            let entries: [CleanupEntry; 1] = [one];
            let outcome: PlanOutcome =
                build_cleanup_plan(&fixture.context(), &request(selection, &entries)).unwrap();
            assert_eq!(outcome.plan, None, "{predicate:?}");
            assert_eq!(reasons(&outcome, "a"), [reason]);
            assert_eq!(reason.family(), family);
        }
    }

    // An entry that no check examined has ten unknown predicates.
    let mut unexamined: CleanupEntry = entry("a", 100);
    unexamined.rule.as_mut().unwrap().eligibility = crate::rule::CandidateEligibility::unknown();
    let entries: [CleanupEntry; 1] = [unexamined];
    let outcome: PlanOutcome =
        build_cleanup_plan(&fixture.context(), &request(selection, &entries)).unwrap();
    assert_eq!(reasons(&outcome, "a").len(), 10);
}

/// One change of an entry and the reasons that it gives.
type EntryCase = (&'static str, fn(&mut CleanupEntry), Vec<OmissionReason>);

fn entry_cases() -> Vec<EntryCase> {
    let mut cases: Vec<EntryCase> = fact_cases();
    cases.extend(path_cases());
    cases
}

/// The cases of a path, a root path, and a relative entry that do not name
/// one canonical object.
fn path_cases() -> Vec<EntryCase> {
    vec![
        (
            "relative path",
            |entry| entry.path = path("Users/a/Library/Caches/a"),
            vec![Reason::PathNotCanonical],
        ),
        (
            "parent component",
            |entry| entry.path = path("/Users/a/Library/../Library/Caches/a"),
            vec![Reason::PathNotCanonical],
        ),
        (
            "absolute relative entry",
            |entry| entry.relative_entry = path("/a"),
            vec![Reason::PathNotCanonical],
        ),
        (
            "parent component in the relative entry",
            |entry| entry.relative_entry = path("../a"),
            vec![Reason::PathNotCanonical],
        ),
        (
            "relative entry of a different object",
            |entry| entry.relative_entry = path("b"),
            vec![Reason::PathNotCanonical],
        ),
        (
            "relative entry that differs in case",
            |entry| entry.relative_entry = path("A"),
            vec![Reason::PathNotCanonical],
        ),
        (
            "path below a subdirectory of the root",
            |entry| entry.path = path("/Users/a/Library/Caches/sub/a"),
            vec![Reason::PathNotCanonical],
        ),
        (
            "root path of a different directory",
            |entry| {
                entry.root_id = RootId::new("root_documents").unwrap();
                entry.root_path = path("/Users/a/Documents");
            },
            vec![Reason::PathNotCanonical],
        ),
        (
            "root path that is not canonical",
            |entry| {
                entry.root_id = RootId::new("root_relative").unwrap();
                entry.root_path = path("Users/a/Library/Caches");
            },
            vec![Reason::PathNotCanonical],
        ),
    ]
}

/// The cases of a protection, an owner, a charge, and an object type.
fn fact_cases() -> Vec<EntryCase> {
    vec![
        (
            "hard protection",
            |entry| entry.hard_protection = ProtectionFact::Protected,
            vec![Reason::HardProtected],
        ),
        (
            "unknown protection",
            |entry| entry.hard_protection = ProtectionFact::Unknown,
            vec![Reason::ProtectionUnknown],
        ),
        (
            "unknown owner",
            |entry| entry.owner = None,
            vec![Reason::OwnerUnknown],
        ),
        (
            "other user",
            |entry| entry.owner = Some(Uid::new(502)),
            vec![Reason::OtherUser],
        ),
        (
            "root",
            |entry| entry.owner = Some(Uid::new(0)),
            vec![Reason::OtherUser],
        ),
        (
            "unknown charge",
            |entry| entry.charge = None,
            vec![Reason::WorkChargeUnknown],
        ),
        (
            "no item",
            |entry| entry.charge = Some(charge(100, 0)),
            vec![Reason::NoItems],
        ),
        (
            "unrecognized object type",
            |entry| entry.object_type = FileObjectType::from_wire("socket"),
            vec![Reason::ObjectTypeNotSupported],
        ),
        (
            "each unknown fact",
            |entry| {
                entry.hard_protection = ProtectionFact::Unknown;
                entry.owner = None;
                entry.charge = None;
            },
            vec![
                Reason::ProtectionUnknown,
                Reason::OwnerUnknown,
                Reason::WorkChargeUnknown,
            ],
        ),
    ]
}

#[test]
fn no_mode_includes_an_entry_with_a_protection_or_an_unknown_fact() {
    let fixture: Fixture = Fixture::new();
    let rule: Rule = rule();
    for selection in modes(&rule) {
        for (name, change, expected) in entry_cases() {
            let mut changed: CleanupEntry = entry("a", 100);
            change(&mut changed);
            let entries: [CleanupEntry; 2] = [changed, entry("b", 100)];
            let outcome: PlanOutcome =
                build_cleanup_plan(&fixture.context(), &request(selection, &entries)).unwrap();
            assert_eq!(planned(&outcome), ["target_b"], "{name}");
            assert_eq!(reasons(&outcome, "a"), expected, "{name}");
        }
    }
}

#[test]
fn an_absent_object_identifier_stays_absent_in_the_binding() {
    let mut one: CleanupEntry = entry("a", 100);
    one.object = None;
    let outcome: PlanOutcome = trash(&[one]);
    let plan = outcome.plan.as_ref().unwrap();
    let TargetBinding::File(file) = &plan.targets[0].binding else {
        panic!("a cleanup plan has file targets only");
    };
    assert_eq!(file.object, None);
}

/// Builds a plan of each mode for one entry at `entry_path` with the
/// `[protections]` lines `protections`, and returns the reasons of the
/// entry. Each mode must give the same reasons.
fn excluded_reasons(
    protections: &str,
    home: Option<&str>,
    entry_path: &str,
) -> Vec<OmissionReason> {
    let mut fixture: Fixture = Fixture::with_protections(protections);
    fixture.home = home.map(path);
    let rule: Rule = rule();
    let mut one: CleanupEntry = entry("a", 100);
    let (root, name) = entry_path.rsplit_once('/').unwrap();
    one.path = path(entry_path);
    one.root_path = path(if root.is_empty() { "/" } else { root });
    one.relative_entry = path(name);
    let entries: [CleanupEntry; 1] = [one];
    let mut results: Vec<Vec<OmissionReason>> = modes(&rule)
        .into_iter()
        .map(|selection| {
            let outcome: PlanOutcome =
                build_cleanup_plan(&fixture.context(), &request(selection, &entries)).unwrap();
            reasons(&outcome, "a")
        })
        .collect();
    results.dedup();
    assert_eq!(results.len(), 1, "the modes disagree for {entry_path}");
    results.remove(0)
}

#[test]
fn a_path_of_the_protections_table_excludes_the_entry_in_each_mode() {
    use OmissionReason::ExcludedPath;
    let home: Option<&str> = Some("/Users/a");
    let list: &str = "excluded_paths = [\"~/Documents\", \"/Volumes/Work/keep\"]";
    let excluded: [&str; 8] = [
        // The entry is the path, is inside it, or contains it.
        "/Users/a/Documents",
        "/Users/a/Documents/taxes/2026",
        "/Users/a",
        "/Volumes/Work/keep/cache",
        "/Volumes/Work",
        // The default volume ignores case.
        "/users/A/DOCUMENTS/x",
        // A name with a non-ASCII character can be the same name in a
        // different normalization form.
        "/Users/a/Dокументы",
        "/Volumes/Work/kéep",
    ];
    for entry_path in excluded {
        assert_eq!(
            excluded_reasons(list, home, entry_path),
            [ExcludedPath],
            "{entry_path}"
        );
    }
    let included: [&str; 4] = [
        "/Users/a/Library/Caches/x",
        // A prefix of the text is not a parent directory.
        "/Users/a/Documents2",
        "/Volumes/Work/keeper",
        "/Users/b/Documents",
    ];
    for entry_path in included {
        assert_eq!(excluded_reasons(list, home, entry_path), [], "{entry_path}");
    }
    // With no list, nothing is excluded.
    assert_eq!(excluded_reasons("", home, "/Users/a/Documents"), []);
}

#[test]
fn a_home_directory_that_is_not_usable_leaves_each_entry_out() {
    use OmissionReason::HomeDirectoryUnknown;
    let list: &str = "excluded_paths = [\"~/Documents\"]";
    let entry_path: &str = "/Users/a/Library/Caches/x";
    for home in [
        None,
        Some("Users/a"),
        Some("/"),
        Some("/Users/a/"),
        Some("/Users//a"),
        Some("/Users/./a"),
        Some("/Users/a/.."),
    ] {
        assert_eq!(
            excluded_reasons(list, home, entry_path),
            [HomeDirectoryUnknown],
            "{home:?}"
        );
    }
    // A path from the root needs no home directory.
    assert_eq!(
        excluded_reasons("excluded_paths = [\"/Volumes/Work\"]", None, entry_path),
        []
    );
}

#[test]
fn a_preset_only_filters() {
    let fixture: Fixture = Fixture::with_protections("excluded_paths = [\"~/Documents\"]");
    let mut protected: CleanupEntry = entry("protected", 100);
    protected.hard_protection = ProtectionFact::Protected;
    let mut document: CleanupEntry = entry("document", 100);
    document.path = path("/Users/a/Documents/document");
    document.root_id = RootId::new("root_documents").unwrap();
    document.root_path = path("/Users/a/Documents");
    let mut unknown: CleanupEntry = entry("unknown", 100);
    unknown.charge = None;
    let mut other_root: CleanupEntry = entry("other_root", 100);
    other_root.root_id = RootId::new("root_other").unwrap();
    let mut no_rule: CleanupEntry = entry("no_rule", 100);
    no_rule.rule = None;
    let entries: [CleanupEntry; 6] = [
        entry("a", 100),
        protected,
        document,
        unknown,
        other_root,
        no_rule,
    ];

    // A preset that includes each entry changes no decision.
    let everything: SelectionPreset = SelectionPreset {
        name: "everything".to_owned(),
        rules: None,
        roots: None,
    };
    let plain: PlanOutcome =
        build_cleanup_plan(&fixture.context(), &request(ModeSelection::Trash, &entries)).unwrap();
    let mut with_preset: CleanupRequest<'_> = request(ModeSelection::Trash, &entries);
    with_preset.preset = Some(&everything);
    let filtered: PlanOutcome = build_cleanup_plan(&fixture.context(), &with_preset).unwrap();
    assert_eq!(filtered.plan, plain.plan);
    assert_eq!(filtered.preview.omitted, plain.preview.omitted);
    assert_eq!(filtered.preview.preset.as_deref(), Some("everything"));
    assert_eq!(
        planned(&plain),
        ["target_a", "target_no_rule", "target_other_root"]
    );

    // A narrower preset leaves more out, and it never includes an entry
    // that a protection leaves out.
    let developer: SelectionPreset = SelectionPreset {
        name: "developer".to_owned(),
        rules: Some(vec![RuleId::new("svalnir.expired-temporary").unwrap()]),
        roots: Some(vec![RootId::new("root_caches").unwrap()]),
    };
    with_preset.preset = Some(&developer);
    let narrow: PlanOutcome = build_cleanup_plan(&fixture.context(), &with_preset).unwrap();
    assert_eq!(planned(&narrow), ["target_a"]);
    assert_eq!(reasons(&narrow, "other_root"), [Reason::NotInPreset]);
    assert_eq!(reasons(&narrow, "no_rule"), [Reason::NotInPreset]);
    assert_eq!(reasons(&narrow, "protected"), [Reason::HardProtected]);
    assert_eq!(
        reasons(&narrow, "document"),
        [Reason::ExcludedPath, Reason::NotInPreset]
    );
    assert_eq!(reasons(&narrow, "unknown"), [Reason::WorkChargeUnknown]);
    // The preset is not in the plan: the digest covers the targets.
    let only_a: PlanOutcome = build_cleanup_plan(
        &fixture.context(),
        &request(ModeSelection::Trash, &entries[..1]),
    )
    .unwrap();
    assert_eq!(digest_of(&narrow), digest_of(&only_a));
}

#[test]
fn a_parent_and_its_descendant_are_not_two_removals() {
    use OmissionReason::{ExcludedPath, OverlapsSelectedEntry};
    let parent: CleanupEntry = entry("p", 100);
    let mut child: CleanupEntry = entry("a_child", 100);
    child.path = path("/Users/a/Library/Caches/P/child");
    child.relative_entry = path("P/child");
    let mut grandchild: CleanupEntry = entry("a_grandchild", 100);
    grandchild.path = path("/Users/a/Library/Caches/p/child/deep");
    grandchild.relative_entry = path("p/child/deep");
    // The same path with a different target identity.
    let mut twin: CleanupEntry = entry("z_twin", 100);
    twin.path = parent.path.clone();
    twin.relative_entry = parent.relative_entry.clone();
    let sibling: CleanupEntry = entry("q", 100);

    let entries: [CleanupEntry; 5] = [grandchild, child, twin, sibling, parent];
    let outcome: PlanOutcome = trash(&entries);
    assert_eq!(planned(&outcome), ["target_p", "target_q"]);
    for name in ["a_child", "a_grandchild", "z_twin"] {
        assert_eq!(reasons(&outcome, name), [OverlapsSelectedEntry], "{name}");
    }

    // A parent that contains an excluded path is left out, and its other
    // children can then be selected one by one.
    let fixture: Fixture = Fixture::with_protections("excluded_paths = [\"~/Projects/keep\"]");
    let mut projects: CleanupEntry = entry("projects", 100);
    projects.root_id = RootId::new("root_home").unwrap();
    projects.root_path = path("/Users/a");
    projects.path = path("/Users/a/Projects");
    projects.relative_entry = path("Projects");
    let mut build: CleanupEntry = entry("build", 100);
    build.root_id = RootId::new("root_home").unwrap();
    build.root_path = path("/Users/a");
    build.path = path("/Users/a/Projects/build");
    build.relative_entry = path("Projects/build");
    let mut keep: CleanupEntry = entry("keep", 100);
    keep.root_id = RootId::new("root_home").unwrap();
    keep.root_path = path("/Users/a");
    keep.path = path("/Users/a/Projects/keep");
    keep.relative_entry = path("Projects/keep");
    let entries: [CleanupEntry; 3] = [projects, build, keep];
    let outcome: PlanOutcome = build_cleanup_plan(
        &fixture.context(),
        &request(ModeSelection::Permanent, &entries),
    )
    .unwrap();
    assert_eq!(planned(&outcome), ["target_build"]);
    assert_eq!(reasons(&outcome, "projects"), [ExcludedPath]);
    assert_eq!(reasons(&outcome, "keep"), [ExcludedPath]);
}

fn with_limits(entries: &[CleanupEntry], limits: CleanupLimits) -> PlanOutcome {
    let fixture: Fixture = Fixture::new();
    let mut request: CleanupRequest<'_> = request(ModeSelection::Trash, entries);
    request.limits = limits;
    build_cleanup_plan(&fixture.context(), &request).unwrap()
}

#[test]
fn the_plan_ceiling_is_exact_at_the_boundary() {
    use OmissionReason::ExceedsPlanLimit;
    // Three entries of ten items: 100, 200, and 50 bytes.
    let entries: [CleanupEntry; 3] = [entry("a", 100), entry("b", 200), entry("c", 50)];

    let mut exact: CleanupLimits = limits();
    exact.plan = charge(350, 30);
    let outcome: PlanOutcome = with_limits(&entries, exact);
    assert_eq!(planned(&outcome), ["target_a", "target_b", "target_c"]);
    assert_eq!(
        outcome.plan.as_ref().unwrap().limits.work,
        Some(charge(350, 30))
    );

    // One byte less: `c` does not fit after `a` and `b`.
    let mut one_short: CleanupLimits = limits();
    one_short.plan = charge(349, 30);
    let outcome: PlanOutcome = with_limits(&entries, one_short);
    assert_eq!(planned(&outcome), ["target_a", "target_b"]);
    assert_eq!(reasons(&outcome, "c"), [ExceedsPlanLimit]);

    // `b` does not fit after `a`, and the smaller `c` does.
    let mut bytes_short: CleanupLimits = limits();
    bytes_short.plan = charge(299, 30);
    let outcome: PlanOutcome = with_limits(&entries, bytes_short);
    assert_eq!(planned(&outcome), ["target_a", "target_c"]);
    assert_eq!(reasons(&outcome, "b"), [ExceedsPlanLimit]);
    assert_eq!(
        outcome.plan.as_ref().unwrap().limits.work,
        Some(charge(150, 20))
    );

    // One item less: the item ceiling applies independently.
    let mut items_short: CleanupLimits = limits();
    items_short.plan = charge(1_000, 29);
    let outcome: PlanOutcome = with_limits(&entries, items_short);
    assert_eq!(planned(&outcome), ["target_a", "target_b"]);
    assert_eq!(reasons(&outcome, "c"), [ExceedsPlanLimit]);

    // A ceiling of zero admits nothing: the result is an empty plan.
    let mut nothing: CleanupLimits = limits();
    nothing.plan = WorkCharge::ZERO;
    let outcome: PlanOutcome = with_limits(&entries, nothing);
    assert_eq!(outcome.plan, None);
    assert_eq!(outcome.preview.omitted.len(), 3);
    assert_eq!(ExceedsPlanLimit.family(), ErrorFamily::Limits);
}

#[test]
fn an_indivisible_entry_that_is_larger_than_a_batch_is_left_out() {
    use OmissionReason::ExceedsBatchLimit;
    let entries: [CleanupEntry; 3] = [entry("a", 100), entry("b", 101), entry("c", 100)];
    let mut one_batch: CleanupLimits = limits();
    one_batch.batch = charge(100, 10);
    let outcome: PlanOutcome = with_limits(&entries, one_batch);
    assert_eq!(planned(&outcome), ["target_a", "target_c"]);
    assert_eq!(reasons(&outcome, "b"), [ExceedsBatchLimit]);
    // Each entry fills one batch exactly.
    let batches: Vec<(Vec<&str>, WorkCharge)> = outcome
        .preview
        .batches
        .iter()
        .map(|batch| {
            (
                batch.steps.iter().map(StepId::as_str).collect(),
                batch.charge,
            )
        })
        .collect();
    assert_eq!(
        batches,
        [
            (vec!["step_a"], charge(100, 10)),
            (vec!["step_c"], charge(100, 10))
        ]
    );

    // The item ceiling of a batch applies independently.
    let mut few_items: CleanupLimits = limits();
    few_items.batch = charge(1_000, 9);
    let outcome: PlanOutcome = with_limits(&entries, few_items);
    assert_eq!(outcome.plan, None);
    assert_eq!(reasons(&outcome, "a"), [ExceedsBatchLimit]);
}

#[test]
fn the_steps_are_split_into_consecutive_batches_under_the_ceiling() {
    let entries: [CleanupEntry; 5] = [
        entry("a", 40),
        entry("b", 60),
        entry("c", 1),
        entry("d", 99),
        entry("e", 100),
    ];
    let mut small_batches: CleanupLimits = limits();
    small_batches.batch = charge(100, 20);
    let outcome: PlanOutcome = with_limits(&entries, small_batches);
    let plan = outcome.plan.as_ref().unwrap();
    let steps = |names: &[&str]| -> Vec<StepId> {
        names
            .iter()
            .map(|name| StepId::new(format!("step_{name}")).unwrap())
            .collect()
    };
    // `a` and `b` are 100 bytes exactly. `c` and `d` are 100 bytes exactly.
    let expected: Vec<(Vec<StepId>, WorkCharge)> = vec![
        (steps(&["a", "b"]), charge(100, 20)),
        (steps(&["c", "d"]), charge(100, 20)),
        (steps(&["e"]), charge(100, 10)),
    ];
    let actual: Vec<(Vec<StepId>, WorkCharge)> = outcome
        .preview
        .batches
        .iter()
        .map(|batch| (batch.steps.clone(), batch.charge))
        .collect();
    assert_eq!(actual, expected);
    // The stored plan and the same ceiling give the same batches.
    assert_eq!(
        split_batches(plan, &small_batches.batch).unwrap(),
        outcome.preview.batches
    );
    // The item ceiling starts a new batch also.
    let by_items: Vec<usize> = split_batches(plan, &charge(1_000, 10))
        .unwrap()
        .iter()
        .map(|batch| batch.steps.len())
        .collect();
    assert_eq!(by_items, [1, 1, 1, 1, 1]);
    // A smaller ceiling than one target is an error, not a partial list.
    let error: BatchError = split_batches(plan, &charge(99, 20)).unwrap_err();
    assert_eq!(error, BatchError::ExceedsBatch);
    assert_eq!(error.family(), ErrorFamily::Limits);
}

#[test]
fn a_charge_sum_that_overflows_leaves_the_entry_out() {
    let mut first: CleanupEntry = entry("a", u64::MAX);
    first.estimate.estimated_reclaimable_bytes = None;
    let second: CleanupEntry = entry("b", u64::MAX);
    let third: CleanupEntry = entry("c", 1);
    let mut unlimited: CleanupLimits = limits();
    unlimited.plan = WorkCharge::new(Bytes::MAX, crate::quantity::EntryCount::MAX);
    unlimited.batch = unlimited.plan;
    let outcome: PlanOutcome = with_limits(&[first, second, third], unlimited);
    assert_eq!(planned(&outcome), ["target_a"]);
    assert_eq!(reasons(&outcome, "b"), [OmissionReason::ExceedsPlanLimit]);
    assert_eq!(reasons(&outcome, "c"), [OmissionReason::ExceedsPlanLimit]);
    assert_eq!(
        outcome.plan.as_ref().unwrap().limits.work,
        Some(charge(u64::MAX, 10))
    );
}

#[test]
fn a_plan_with_no_target_is_a_valid_result() {
    // No entry was selected.
    let outcome: PlanOutcome = trash(&[]);
    assert_eq!(outcome.plan, None);
    assert_eq!(outcome.preview.omitted, []);
    assert_eq!(outcome.preview.targets, []);
    assert_eq!(outcome.preview.batches, []);
    assert_eq!(outcome.mode, PlanMode::Cleanup(CleanupMode::Trash));

    // Each entry was left out, and each one is explained.
    let mut protected: CleanupEntry = entry("a", 100);
    protected.hard_protection = ProtectionFact::Protected;
    let mut unknown: CleanupEntry = entry("b", 100);
    unknown.owner = None;
    let outcome: PlanOutcome = trash(&[unknown, protected]);
    assert_eq!(outcome.plan, None);
    let omitted: Vec<(&str, &[OmissionReason])> = outcome
        .preview
        .omitted
        .iter()
        .map(|omission| (omission.target_id.as_str(), omission.reasons.as_slice()))
        .collect();
    assert_eq!(
        omitted,
        [
            ("target_a", [OmissionReason::HardProtected].as_slice()),
            ("target_b", [OmissionReason::OwnerUnknown].as_slice()),
        ]
    );
    // The omission keeps the display path, the charge, and the estimate.
    let first = &outcome.preview.omitted[0];
    assert_eq!(first.path, Some(path("/Users/a/Library/Caches/a")));
    assert_eq!(first.charge, Some(charge(100, 10)));
    assert_eq!(first.estimate.logical_bytes, Some(Bytes::new(100)));
}

#[test]
fn equal_inputs_in_any_sequence_give_the_same_plan_and_digest() {
    let rule: Rule = rule();
    let mut protected: CleanupEntry = entry("d", 100);
    protected.hard_protection = ProtectionFact::Protected;
    let mut child: CleanupEntry = entry("e", 100);
    child.path = path("/Users/a/Library/Caches/a/e");
    child.relative_entry = path("a/e");
    let mut entries: Vec<CleanupEntry> = vec![
        entry("a", 100),
        entry("b", 200),
        entry("c", 300),
        protected,
        child,
    ];
    let grant = |name: &str, generation: u64| ActionGrantRef {
        grant_id: ActionGrantId::new(name).unwrap(),
        generation: Generation::new(generation),
    };
    let fixture: Fixture = Fixture::new();
    let mut context: PlanContext<'_> = fixture.context();
    context.authority.action_grants = vec![grant("grant_b", 2), grant("grant_a", 7)];
    let mut tight: CleanupLimits = limits();
    tight.plan = charge(450, 100);
    tight.batch = charge(250, 100);

    for selection in modes(&rule) {
        let mut request: CleanupRequest<'_> = request(selection, &entries);
        request.limits = tight;
        let first: PlanOutcome = build_cleanup_plan(&context, &request).unwrap();
        // Equal inputs give an equal result.
        assert_eq!(build_cleanup_plan(&context, &request).unwrap(), first);

        // The reverse sequence of the entries and of the grants.
        let mut reversed: Vec<CleanupEntry> = entries.clone();
        reversed.reverse();
        let mut reversed_context: PlanContext<'_> = fixture.context();
        reversed_context.authority.action_grants = vec![grant("grant_a", 7), grant("grant_b", 2)];
        // A repeated reference is the same reference.
        reversed_context
            .authority
            .action_grants
            .push(grant("grant_b", 2));
        let mut reversed_request: CleanupRequest<'_> = request;
        reversed_request.entries = &reversed;
        let second: PlanOutcome = build_cleanup_plan(&reversed_context, &reversed_request).unwrap();
        assert_eq!(second, first);
        assert_eq!(digest_of(&second), digest_of(&first));
        // `a` and `b` fit the ceilings, `c` does not, and `b` starts the
        // second batch.
        assert_eq!(planned(&first), ["target_a", "target_b"]);
        assert_eq!(first.preview.batches.len(), 2);
    }
    entries.rotate_left(2);
    let rotated: PlanOutcome =
        build_cleanup_plan(&context, &request(ModeSelection::Permanent, &entries)).unwrap();
    entries.rotate_right(1);
    assert_eq!(
        build_cleanup_plan(&context, &request(ModeSelection::Permanent, &entries)).unwrap(),
        rotated
    );
}

/// The digest of an `evict` plan of `a` and `b` after one change of the
/// context, the request, or the entries.
fn changed_digest(
    change_context: impl FnOnce(&mut PlanContext<'_>),
    change_limits: impl FnOnce(&mut CleanupLimits),
    change_entries: impl FnOnce(&mut Vec<CleanupEntry>),
    selection: Option<ModeSelection<'_>>,
) -> ContentDigest {
    changed_digest_at(
        clock_at(super::BUILT_AT),
        change_context,
        change_limits,
        change_entries,
        selection,
    )
}

/// The same as [`changed_digest`], with the plan built at `clock`.
fn changed_digest_at(
    clock: crate::policy::EvaluationClock,
    change_context: impl FnOnce(&mut PlanContext<'_>),
    change_limits: impl FnOnce(&mut CleanupLimits),
    change_entries: impl FnOnce(&mut Vec<CleanupEntry>),
    selection: Option<ModeSelection<'_>>,
) -> ContentDigest {
    let rule: Rule = rule();
    let mut fixture: Fixture = Fixture::new();
    fixture.clock = clock;
    let mut context: PlanContext<'_> = fixture.context();
    context.authority.action_grants = vec![ActionGrantRef {
        grant_id: ActionGrantId::new("grant_a").unwrap(),
        generation: Generation::new(1),
    }];
    change_context(&mut context);
    let mut entries: Vec<CleanupEntry> = vec![entry("a", 100), entry("b", 200)];
    change_entries(&mut entries);
    let selection: ModeSelection<'_> =
        selection.unwrap_or(ModeSelection::Evict { rule: Ok(&rule) });
    let mut request: CleanupRequest<'_> = request(selection, &entries);
    change_limits(&mut request.limits);
    digest_of(&build_cleanup_plan(&context, &request).unwrap())
}

fn keep_context(_: &mut PlanContext<'_>) {}
fn keep_limits(_: &mut CleanupLimits) {}
fn keep_entries(_: &mut Vec<CleanupEntry>) {}

/// A named change of one input of a plan.
type Change<T> = (&'static str, fn(&mut T));

/// A named change of the context. The change applies to a context of each
/// lifetime.
type ContextChange = (&'static str, fn(&mut PlanContext<'_>));

/// One change of each field of the context that a plan has.
fn context_changes() -> Vec<ContextChange> {
    vec![
        ("plan identity", |context| {
            context.plan_id = PlanId::new("plan_2").unwrap();
        }),
        ("policy revision", |context| {
            context.authority.policy_revision = PolicyRevisionId::new("policy_2").unwrap();
        }),
        ("grant generation", |context| {
            context.authority.action_grants[0].generation = Generation::new(2);
        }),
        ("grant identity", |context| {
            context.authority.action_grants[0].grant_id = ActionGrantId::new("grant_b").unwrap();
        }),
        ("no grant", |context| {
            context.authority.action_grants.clear();
        }),
        ("expiry", |context| {
            context.lifetime = Nanoseconds::new(LIFETIME.get() + 1);
        }),
        ("client role", |context| {
            context.principal.role = ClientRole::Gui;
        }),
        ("session", |context| {
            context.principal.session = Some(crate::id::SessionId::new("session_1").unwrap());
        }),
    ]
}

/// One change of each duration of the limits.
fn limit_changes() -> Vec<Change<CleanupLimits>> {
    vec![
        ("execution deadline", |limits| {
            limits.execution_deadline = Nanoseconds::new(301 * SECOND);
        }),
        ("verification window", |limits| {
            limits.verification_window = Nanoseconds::new(6 * SECOND);
        }),
    ]
}

/// One change of the target set and of each field of a target binding.
fn entry_changes() -> Vec<Change<Vec<CleanupEntry>>> {
    vec![
        ("target set", |entries| {
            entries.pop();
        }),
        ("one more target", |entries| entries.push(entry("c", 1))),
        ("target identity", |entries| {
            entries[0].target_id = TargetId::new("target_a2").unwrap();
        }),
        ("step identity", |entries| {
            entries[0].step_id = StepId::new("step_a2").unwrap();
        }),
        ("root", |entries| {
            entries[0].root_id = RootId::new("root_other").unwrap();
        }),
        ("relative entry", |entries| {
            entries[0].path = path("/Users/a/Library/Caches/a2");
            entries[0].relative_entry = path("a2");
        }),
        ("volume", |entries| {
            entries[0].volume_id = VolumeId::new("volume_other").unwrap();
        }),
        ("mount generation", |entries| {
            entries[0].mount_id = MountId::new("mount_2").unwrap();
        }),
        ("object type", |entries| {
            entries[0].object_type = FileObjectType::RegularFile;
        }),
        ("object identifier", |entries| {
            entries[0].object = Some(FileObjectEvidence {
                device: DeviceNumber::new(1),
                inode: InodeNumber::new(43),
            });
        }),
        ("device", |entries| {
            entries[0].object = Some(FileObjectEvidence {
                device: DeviceNumber::new(2),
                inode: InodeNumber::new(42),
            });
        }),
        ("absent object identifier", |entries| {
            entries[0].object = None;
        }),
        ("charge bytes", |entries| {
            entries[0].charge = Some(charge(101, 10));
        }),
        ("charge items", |entries| {
            entries[0].charge = Some(charge(100, 11));
        }),
    ]
}

/// The digest after a change of the mode, of the rule revision, or of the
/// time and the boot of the plan.
fn mode_and_clock_digests() -> Vec<(&'static str, ContentDigest)> {
    let later: crate::policy::EvaluationClock = clock_at(super::BUILT_AT + 1);
    let other_boot: crate::policy::EvaluationClock = crate::policy::EvaluationClock {
        boot_id: crate::id::BootId::new("boot_2").unwrap(),
        ..clock_at(super::BUILT_AT)
    };
    let mut digests: Vec<(&'static str, ContentDigest)> = Vec::new();
    for (name, clock) in [("creation time", later), ("boot", other_boot)] {
        digests.push((
            name,
            changed_digest_at(clock, keep_context, keep_limits, keep_entries, None),
        ));
    }
    for (name, selection) in [
        ("trash mode", ModeSelection::Trash),
        ("permanent mode", ModeSelection::Permanent),
    ] {
        digests.push((
            name,
            changed_digest(keep_context, keep_limits, keep_entries, Some(selection)),
        ));
    }
    let mut next_revision = declaration(manual_validated());
    next_revision.reference = rule_reference("r2");
    let next_revision: Rule = Checked::new(next_revision).unwrap();
    digests.push((
        "rule revision",
        changed_digest(
            keep_context,
            keep_limits,
            |entries| {
                for entry in entries {
                    entry.rule = Some(RuleEvidence {
                        rule: rule_reference("r2"),
                        layout: LAYOUT.to_owned(),
                        eligibility: satisfied(),
                    });
                }
            },
            Some(ModeSelection::Evict {
                rule: Ok(&next_revision),
            }),
        ),
    ));
    digests
}

#[test]
fn a_change_of_each_covered_field_changes_the_digest() {
    let base: ContentDigest = changed_digest(keep_context, keep_limits, keep_entries, None);
    assert_eq!(
        changed_digest(keep_context, keep_limits, keep_entries, None),
        base
    );

    let mut digests: Vec<(&'static str, ContentDigest)> = mode_and_clock_digests();
    for (name, change) in context_changes() {
        digests.push((
            name,
            changed_digest(change, keep_limits, keep_entries, None),
        ));
    }
    for (name, change) in limit_changes() {
        digests.push((
            name,
            changed_digest(keep_context, change, keep_entries, None),
        ));
    }
    for (name, change) in entry_changes() {
        digests.push((
            name,
            changed_digest(keep_context, keep_limits, change, None),
        ));
    }
    assert_eq!(digests.len(), 29);

    let distinct: BTreeSet<&ContentDigest> = digests.iter().map(|(_, digest)| digest).collect();
    for (name, digest) in &digests {
        assert_ne!(digest, &base, "{name} is not in the digest");
    }
    assert_eq!(distinct.len(), digests.len(), "two changes give one digest");

    // A plan ceiling that leaves `b` out gives the plan of a selection with
    // no `b`: the digest covers the targets, not how they were selected.
    let by_ceiling: ContentDigest = changed_digest(
        keep_context,
        |limits| limits.plan = charge(100, 10),
        keep_entries,
        None,
    );
    let by_selection: ContentDigest = changed_digest(
        keep_context,
        keep_limits,
        |entries| {
            entries.pop();
        },
        None,
    );
    assert_eq!(by_ceiling, by_selection);
    assert_ne!(by_ceiling, base);
}

#[test]
fn a_change_that_an_approval_does_not_cover_keeps_the_digest() {
    let base: ContentDigest = changed_digest(keep_context, keep_limits, keep_entries, None);
    // The size estimates are display data. The charge is in the digest.
    let estimates: ContentDigest = changed_digest(
        keep_context,
        keep_limits,
        |entries| {
            entries[0].estimate.logical_bytes = Some(Bytes::new(1));
            entries[0].estimate.estimated_reclaimable_bytes = None;
        },
        None,
    );
    assert_eq!(estimates, base);
    // A ceiling that leaves no entry out does not change the plan.
    let ceiling: ContentDigest = changed_digest(
        keep_context,
        |limits| {
            limits.plan = charge(300, 20);
            limits.batch = charge(200, 10);
        },
        |_| {},
        None,
    );
    assert_eq!(ceiling, base);
}

#[test]
fn a_request_that_a_plan_cannot_express_is_an_error() {
    let fixture: Fixture = Fixture::new();
    let entries: [CleanupEntry; 2] = [entry("a", 100), entry("b", 100)];
    let build = |context: &PlanContext<'_>, request: &CleanupRequest<'_>| {
        build_cleanup_plan(context, request).unwrap_err()
    };
    let base: CleanupRequest<'_> = request(ModeSelection::Trash, &entries);

    // Two entries with one target identity, or with one step identity.
    let mut same_target: [CleanupEntry; 2] = entries.clone();
    same_target[1].target_id = same_target[0].target_id.clone();
    let mut same_step: [CleanupEntry; 2] = entries.clone();
    same_step[1].step_id = same_step[0].step_id.clone();
    for duplicate in [&same_target, &same_step] {
        let error: PlanBuildError = build(
            &fixture.context(),
            &request(ModeSelection::Trash, duplicate),
        );
        assert_eq!(error, PlanBuildError::DuplicateIdentity);
        assert_eq!(error.family(), ErrorFamily::Request);
    }

    // One root identity with two root paths: the exclusion check of an
    // entry would not be for the object that the plan binds.
    let mut two_roots: [CleanupEntry; 2] = entries.clone();
    two_roots[1].root_path = path("/Users/a/Documents");
    two_roots[1].path = path("/Users/a/Documents/b");
    let error: PlanBuildError = build(
        &fixture.context(),
        &request(ModeSelection::Trash, &two_roots),
    );
    assert_eq!(error, PlanBuildError::RootPath);
    assert_eq!(error.family(), ErrorFamily::Request);

    // A duration of zero.
    for change in [
        (|limits| limits.execution_deadline = Nanoseconds::ZERO) as fn(&mut CleanupLimits),
        |limits| limits.verification_window = Nanoseconds::ZERO,
    ] {
        let mut zero: CleanupRequest<'_> = base;
        change(&mut zero.limits);
        let error: PlanBuildError = build(&fixture.context(), &zero);
        assert_eq!(error, PlanBuildError::Limits);
        assert_eq!(error.family(), ErrorFamily::Limits);
    }
    // The same error with no entry: an empty plan does not hide it.
    let mut zero_empty: CleanupRequest<'_> = request(ModeSelection::Trash, &[]);
    zero_empty.limits.execution_deadline = Nanoseconds::ZERO;
    assert_eq!(
        build(&fixture.context(), &zero_empty),
        PlanBuildError::Limits
    );

    // A lifetime of zero, and an expiry that is not a monotonic time.
    let mut no_lifetime: PlanContext<'_> = fixture.context();
    no_lifetime.lifetime = Nanoseconds::ZERO;
    assert_eq!(build(&no_lifetime, &base), PlanBuildError::Lifetime);
    let mut overflow: PlanContext<'_> = fixture.context();
    overflow.lifetime = Nanoseconds::MAX;
    let error: PlanBuildError = build(&overflow, &base);
    assert_eq!(error, PlanBuildError::Lifetime);
    assert_eq!(error.family(), ErrorFamily::Limits);

    // A privilege grant, and one action grant with two generations.
    let mut privileged: PlanContext<'_> = fixture.context();
    privileged.authority.privilege_grant = Some(PrivilegeGrantRef {
        grant_id: PrivilegeGrantId::new("privilege_1").unwrap(),
        generation: Generation::new(1),
    });
    let error: PlanBuildError = build(&privileged, &base);
    assert_eq!(error, PlanBuildError::Authority);
    assert_eq!(error.family(), ErrorFamily::Authority);
    let mut two_generations: PlanContext<'_> = fixture.context();
    two_generations.authority.action_grants = [1, 2]
        .map(|generation| ActionGrantRef {
            grant_id: ActionGrantId::new("grant_a").unwrap(),
            generation: Generation::new(generation),
        })
        .to_vec();
    assert_eq!(build(&two_generations, &base), PlanBuildError::Authority);

    // The check of the foundation applies: a role that this build does not
    // recognize is rejected.
    let mut unknown_role: PlanContext<'_> = fixture.context();
    unknown_role.principal.role = ClientRole::from_wire("watch");
    let error: PlanBuildError = build(&unknown_role, &base);
    assert_eq!(error, PlanBuildError::Plan(PlanError::Unrecognized));
    assert_eq!(error.family(), ErrorFamily::Request);
}

#[test]
fn a_selection_that_is_larger_than_a_plan_is_rejected() {
    let fixture: Fixture = Fixture::new();
    let entries: Vec<CleanupEntry> = (0..=MAX_SELECTED_ENTRIES)
        .map(|index| entry(&format!("e{index}"), 1))
        .collect();
    let error: PlanBuildError =
        build_cleanup_plan(&fixture.context(), &request(ModeSelection::Trash, &entries))
            .unwrap_err();
    assert_eq!(
        error,
        PlanBuildError::TooManyEntries {
            count: MAX_SELECTED_ENTRIES + 1,
            limit: MAX_SELECTED_ENTRIES
        }
    );
    assert_eq!(error.family(), ErrorFamily::Limits);

    // The largest selection gives a plan with the largest number of
    // targets.
    let mut largest: CleanupRequest<'_> =
        request(ModeSelection::Trash, &entries[..MAX_SELECTED_ENTRIES]);
    largest.limits.plan = charge(u64::MAX, u64::MAX);
    let outcome: PlanOutcome = build_cleanup_plan(&fixture.context(), &largest).unwrap();
    assert_eq!(
        outcome.plan.as_ref().unwrap().targets.len(),
        MAX_SELECTED_ENTRIES
    );
    assert_eq!(outcome.preview.omitted, []);
}

#[test]
fn the_outcome_has_one_json_encoding_and_reads_back() {
    let mut protected: CleanupEntry = entry("b", 100);
    protected.hard_protection = ProtectionFact::Protected;
    let outcome: PlanOutcome = trash(&[entry("a", 100), protected]);
    let json: String = serde_json::to_string(&outcome).unwrap();
    let decoded: PlanOutcome = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, outcome);
    assert_eq!(serde_json::to_string(&decoded).unwrap(), json);
    assert!(json.contains(r#""mode":{"kind":"cleanup","mode":"trash"}"#));
    assert!(json.contains(r#""reasons":[{"reason":"hard_protected"}]"#));
}
