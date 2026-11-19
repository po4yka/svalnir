//! Tests of the scope of a configuration and of the scope difference.

use super::super::{
    AffectedGuards, PolicyScope, ProtectionTable, ScopeChange, ScopeDifference,
    ScopeDifferenceKind, ScopeEffect, ScopeError, ScopeSubject, difference, effect_on,
};
use super::{
    DERIVED_DATA, Registry, TEMPORARY, automatic, base_config, config, declaration, registry, rule,
    rule_ref,
};
use crate::action::{ActionClass, Checked, Escalation};
use crate::config::ValidatedConfig;
use crate::policy::PolicyId;
use crate::rule::{LifecycleState, RuleMode};

fn scope(config: &ValidatedConfig) -> PolicyScope {
    PolicyScope::of(config, &registry()).unwrap()
}

/// The differences from the base configuration to the base configuration
/// with `changes`.
fn changed(changes: &[(&str, &str)]) -> Vec<ScopeDifference> {
    difference(&scope(&base_config()), &scope(&config(changes)))
}

/// The one difference of `differences`.
fn only(differences: &[ScopeDifference]) -> &ScopeDifference {
    assert_eq!(differences.len(), 1, "{differences:#?}");
    &differences[0]
}

fn threshold(key: &str) -> ScopeSubject {
    ScopeSubject::Threshold {
        key: key.to_owned(),
    }
}

#[test]
fn a_scope_is_a_deterministic_function_of_the_configuration() {
    let first = scope(&base_config());
    let second = scope(&base_config());
    assert_eq!(first, second);
    assert_eq!(difference(&first, &second), []);
    // The sequence of a list in the document has no effect.
    let reordered = scope(&config(&[(
        r#"["svalnir.expired-temporary", "xcode.inactive-derived-data"]"#,
        r#"["xcode.inactive-derived-data", "svalnir.expired-temporary"]"#,
    )]));
    assert_eq!(first, reordered);
    // The record round-trips.
    let json = serde_json::to_string(&first).unwrap();
    assert_eq!(serde_json::from_str::<PolicyScope>(&json).unwrap(), first);
    // Two computations of one difference are equal, entry by entry.
    let changes = [("allow_force_quit = true", "allow_force_quit = false")];
    assert_eq!(changed(&changes), changed(&changes));
}

#[test]
fn the_scope_has_the_classes_that_the_configuration_can_use() {
    let base = scope(&base_config());
    assert_eq!(
        base.action_classes(PolicyId::DiskGuard),
        [ActionClass::EvictRegenerableData]
    );
    assert_eq!(
        base.action_classes(PolicyId::MemoryGuard),
        [
            ActionClass::RequestApplicationExit,
            ActionClass::ForceApplicationExit
        ]
    );
    assert_eq!(
        base.escalations(PolicyId::MemoryGuard),
        [Escalation::ForceAfterGrace]
    );
    assert_eq!(
        base.rules(PolicyId::DiskGuard),
        [rule_ref(TEMPORARY, "r1"), rule_ref(DERIVED_DATA, "r1")]
    );
    let graceful = scope(&config(&[(
        "allow_force_quit = true",
        "allow_force_quit = false",
    )]));
    assert_eq!(
        graceful.action_classes(PolicyId::MemoryGuard),
        [ActionClass::RequestApplicationExit]
    );
    assert_eq!(graceful.escalations(PolicyId::MemoryGuard), []);
    // A guard that the configuration does not request can use no class.
    let off = scope(&config(&[(
        "[disk_guard]\nenabled = true",
        "[disk_guard]\nenabled = false",
    )]));
    assert_eq!(off.action_classes(PolicyId::DiskGuard), []);
    assert!(!off.requests(PolicyId::DiskGuard));
    assert!(off.requests(PolicyId::MemoryGuard));
}

#[test]
fn a_rule_that_the_registry_cannot_resolve_gives_no_scope() {
    let config = base_config();
    let one_rule = Registry(vec![rule(TEMPORARY, "r1", automatic())]);
    assert_eq!(
        PolicyScope::of(&config, &one_rule),
        Err(ScopeError::UnknownRule {
            rule: rule_ref(DERIVED_DATA, "r1").id
        })
    );
    let two_revisions = Registry(vec![
        rule(TEMPORARY, "r1", automatic()),
        rule(TEMPORARY, "r2", automatic()),
        rule(DERIVED_DATA, "r1", automatic()),
    ]);
    assert_eq!(
        PolicyScope::of(&config, &two_revisions),
        Err(ScopeError::AmbiguousRule {
            rule: rule_ref(TEMPORARY, "r1").id
        })
    );
    let mut inspection_only = declaration(TEMPORARY, "r1", LifecycleState::Proposed);
    inspection_only.modes = vec![RuleMode::Inspection];
    let no_automatic_mode = Registry(vec![
        Checked::new(inspection_only).unwrap(),
        rule(DERIVED_DATA, "r1", automatic()),
    ]);
    assert_eq!(
        PolicyScope::of(&config, &no_automatic_mode),
        Err(ScopeError::NoAutomaticMode {
            rule: rule_ref(TEMPORARY, "r1")
        })
    );
    // A rule that is only proposed can be in a scope. The authorization
    // refuses its automatic use.
    let proposed = super::registry_with(&LifecycleState::Proposed);
    assert_eq!(PolicyScope::of(&config, &proposed).unwrap(), scope(&config));
}

#[test]
fn an_eligible_root_is_widening_when_added_and_narrowing_when_removed() {
    let added = changed(&[(
        r#"volumes = ["startup-data"]"#,
        r#"volumes = ["startup-data", "external-data"]"#,
    )]);
    let one = only(&added);
    assert_eq!(one.kind, ScopeDifferenceKind::EligibleRoot);
    assert_eq!(one.guards, AffectedGuards::DiskGuard);
    assert_eq!(
        one.subject,
        ScopeSubject::Volume {
            selector: "external-data".to_owned()
        }
    );
    assert_eq!(one.change, ScopeChange::Added);
    assert_eq!(one.effect, ScopeEffect::Widening);
    assert_eq!(
        effect_on(&added, PolicyId::DiskGuard),
        ScopeEffect::Widening
    );
    assert_eq!(
        effect_on(&added, PolicyId::MemoryGuard),
        ScopeEffect::Neutral
    );

    let removed = changed(&[(
        r#"["background-user-applications", "managed-jobs"]"#,
        r#"["managed-jobs"]"#,
    )]);
    let one = only(&removed);
    assert_eq!(one.kind, ScopeDifferenceKind::EligibleRoot);
    assert_eq!(one.guards, AffectedGuards::MemoryGuard);
    assert_eq!(one.change, ScopeChange::Removed);
    assert_eq!(one.effect, ScopeEffect::Narrowing);
    assert_eq!(
        effect_on(&removed, PolicyId::MemoryGuard),
        ScopeEffect::Narrowing
    );

    // A new application budget is a new target of the budget trigger. Its
    // thresholds are not listed again.
    let budget = changed(&[(
        "restart = \"never\"\n",
        "restart = \"never\"\n\n[[memory_guard.app_budgets]]\nid = \"render\"\n\
         bundle_id = \"com.example.Render\"\nfootprint_soft = \"1GiB\"\n\
         footprint_stop = \"2GiB\"\nover_limit_for = \"30s\"\ncooldown = \"10m\"\n",
    )]);
    let one = only(&budget);
    assert_eq!(
        one.subject,
        ScopeSubject::AppBudget {
            budget: "render=com.example.Render".to_owned()
        }
    );
    assert_eq!(one.effect, ScopeEffect::Widening);
}

#[test]
fn an_approved_rule_is_widening_when_added_or_when_its_revision_changes() {
    let removed = changed(&[(
        r#"["svalnir.expired-temporary", "xcode.inactive-derived-data"]"#,
        r#"["svalnir.expired-temporary"]"#,
    )]);
    // The rule and its root are removed.
    assert_eq!(removed.len(), 2);
    assert!(
        removed
            .iter()
            .all(|one| one.effect == ScopeEffect::Narrowing
                && one.change == ScopeChange::Removed
                && one.guards == AffectedGuards::DiskGuard)
    );
    assert!(
        removed
            .iter()
            .any(|one| one.kind == ScopeDifferenceKind::ApprovedRule
                && one.subject
                    == ScopeSubject::ApprovedRule {
                        rule: rule_ref(DERIVED_DATA, "r1")
                    })
    );
    assert!(
        removed
            .iter()
            .any(|one| one.kind == ScopeDifferenceKind::EligibleRoot)
    );

    // The same rule identity with a later implementation revision: the
    // approval of the identity does not approve the revision.
    let later = Registry(vec![
        rule(TEMPORARY, "r2", automatic()),
        rule(DERIVED_DATA, "r1", automatic()),
    ]);
    let base = scope(&base_config());
    let updated = PolicyScope::of(&base_config(), &later).unwrap();
    let differences = difference(&base, &updated);
    assert!(
        differences
            .iter()
            .any(|one| one.kind == ScopeDifferenceKind::ApprovedRule
                && one.change == ScopeChange::Added
                && one.effect == ScopeEffect::Widening
                && one.subject
                    == ScopeSubject::ApprovedRule {
                        rule: rule_ref(TEMPORARY, "r2")
                    })
    );
    assert_eq!(
        effect_on(&differences, PolicyId::DiskGuard),
        ScopeEffect::Widening
    );
    // The opposite direction is widening also.
    assert_eq!(
        effect_on(&difference(&updated, &base), PolicyId::DiskGuard),
        ScopeEffect::Widening
    );
}

#[test]
fn an_action_class_is_widening_when_added_and_narrowing_when_removed() {
    let no_force = changed(&[("allow_force_quit = true", "allow_force_quit = false")]);
    assert_eq!(no_force.len(), 2);
    assert!(
        no_force
            .iter()
            .all(|one| one.kind == ScopeDifferenceKind::ActionClass
                && one.guards == AffectedGuards::MemoryGuard
                && one.change == ScopeChange::Removed
                && one.effect == ScopeEffect::Narrowing)
    );
    assert_eq!(
        no_force[0].subject,
        ScopeSubject::ActionClass {
            class: ActionClass::ForceApplicationExit
        }
    );
    assert_eq!(
        no_force[1].subject,
        ScopeSubject::Escalation {
            escalation: Escalation::ForceAfterGrace
        }
    );

    // The opposite direction adds the class and the force strategy.
    let base = scope(&base_config());
    let graceful = scope(&config(&[(
        "allow_force_quit = true",
        "allow_force_quit = false",
    )]));
    let with_force = difference(&graceful, &base);
    assert!(
        with_force
            .iter()
            .all(|one| one.change == ScopeChange::Added && one.effect == ScopeEffect::Widening)
    );
    assert_eq!(with_force.len(), 2);

    // A guard that the configuration requests for the first time gets its
    // classes.
    let off = scope(&config(&[(
        "[disk_guard]\nenabled = true",
        "[disk_guard]\nenabled = false",
    )]));
    let requested = difference(&off, &base);
    let one = only(&requested);
    assert_eq!(
        one.subject,
        ScopeSubject::ActionClass {
            class: ActionClass::EvictRegenerableData
        }
    );
    assert_eq!(one.effect, ScopeEffect::Widening);
    assert_eq!(
        effect_on(&difference(&base, &off), PolicyId::DiskGuard),
        ScopeEffect::Narrowing
    );
}

#[test]
fn the_critical_memory_exception_is_its_own_widening_difference() {
    let differences = changed(&[(
        "allow_volatile_journal_on_critical = false",
        "allow_volatile_journal_on_critical = true",
    )]);
    let one = only(&differences);
    assert_eq!(one.kind, ScopeDifferenceKind::RecordingException);
    assert_eq!(one.subject, ScopeSubject::VolatileJournalOnCritical);
    assert_eq!(one.guards, AffectedGuards::MemoryGuard);
    assert_eq!(one.effect, ScopeEffect::Widening);
    assert_eq!(
        effect_on(&differences, PolicyId::DiskGuard),
        ScopeEffect::Neutral
    );
}

#[test]
fn a_removed_protection_is_a_widening_exception() {
    let removed = changed(&[(r#"paths = ["~/Documents"]"#, "paths = []")]);
    let one = only(&removed);
    assert_eq!(one.kind, ScopeDifferenceKind::ProtectedTargetException);
    assert_eq!(
        one.subject,
        ScopeSubject::ExcludedPath {
            table: ProtectionTable::DiskGuardExclusions,
            path: "~/Documents".to_owned()
        }
    );
    assert_eq!(one.change, ScopeChange::Removed);
    assert_eq!(one.effect, ScopeEffect::Widening);
    assert_eq!(one.guards, AffectedGuards::DiskGuard);

    let added = changed(&[(
        r#"excluded_paths = ["~/Keep"]"#,
        r#"excluded_paths = ["~/Keep", "~/Projects"]"#,
    )]);
    let one = only(&added);
    assert_eq!(
        one.subject,
        ScopeSubject::ExcludedPath {
            table: ProtectionTable::Protections,
            path: "~/Projects".to_owned()
        }
    );
    assert_eq!(one.change, ScopeChange::Added);
    assert_eq!(one.effect, ScopeEffect::Narrowing);

    // A protected application of the memory guard.
    let bundle = changed(&[(
        r#"protected_bundle_ids = ["com.example.Protected"]"#,
        "protected_bundle_ids = []",
    )]);
    let one = only(&bundle);
    assert_eq!(one.guards, AffectedGuards::MemoryGuard);
    assert_eq!(one.effect, ScopeEffect::Widening);
    let executable = changed(&[(
        r#"protected_executable_paths = ["/Applications/Keep.app"]"#,
        r#"protected_executable_paths = ["/Applications/Keep.app", "/Applications/Other.app"]"#,
    )]);
    assert_eq!(only(&executable).effect, ScopeEffect::Narrowing);

    // The foreground application becomes eligible.
    let foreground = changed(&[("protect_foreground = true", "protect_foreground = false")]);
    let one = only(&foreground);
    assert_eq!(one.subject, ScopeSubject::ForegroundProtection);
    assert_eq!(one.kind, ScopeDifferenceKind::ProtectedTargetException);
    assert_eq!(one.effect, ScopeEffect::Widening);

    // An entry that is written differently is a removal and an addition,
    // so the result is widening.
    let rewritten = changed(&[(r#"paths = ["~/Documents"]"#, r#"paths = ["~/documents"]"#)]);
    assert_eq!(rewritten.len(), 2);
    assert_eq!(
        effect_on(&rewritten, PolicyId::DiskGuard),
        ScopeEffect::Widening
    );
}

#[test]
fn a_threshold_has_the_effect_of_its_direction() {
    let cases: [(&str, &str, &str, ScopeEffect, AffectedGuards); 11] = [
        // An incident can start with more available capacity.
        (
            r#"reclaim_below = "10GiB""#,
            r#"reclaim_below = "12GiB""#,
            "disk_guard.reclaim_below",
            ScopeEffect::Widening,
            AffectedGuards::DiskGuard,
        ),
        (
            r#"reclaim_below = "10GiB""#,
            r#"reclaim_below = "8GiB""#,
            "disk_guard.reclaim_below",
            ScopeEffect::Narrowing,
            AffectedGuards::DiskGuard,
        ),
        // A larger ceiling.
        (
            r#"incident_limit = "16GiB""#,
            r#"incident_limit = "32GiB""#,
            "disk_guard.incident_limit",
            ScopeEffect::Widening,
            AffectedGuards::DiskGuard,
        ),
        (
            "max_passes_per_incident = 2",
            "max_passes_per_incident = 1",
            "disk_guard.max_passes_per_incident",
            ScopeEffect::Narrowing,
            AffectedGuards::DiskGuard,
        ),
        // A shorter qualification window.
        (
            "[disk_guard]\nenabled = true\nvolumes = [\"startup-data\"]\nwarn_below = \"20GiB\"\n\
             reclaim_below = \"10GiB\"\nemergency_below = \"2GiB\"\nrecover_above = \"25GiB\"\n\
             sustain_for = \"30s\"",
            "[disk_guard]\nenabled = true\nvolumes = [\"startup-data\"]\nwarn_below = \"20GiB\"\n\
             reclaim_below = \"10GiB\"\nemergency_below = \"2GiB\"\nrecover_above = \"25GiB\"\n\
             sustain_for = \"20s\"",
            "disk_guard.sustain_for",
            ScopeEffect::Widening,
            AffectedGuards::DiskGuard,
        ),
        // The warning threshold starts no action.
        (
            r#"warn_below = "20GiB""#,
            r#"warn_below = "22GiB""#,
            "disk_guard.warn_below",
            ScopeEffect::Neutral,
            AffectedGuards::DiskGuard,
        ),
        // A shorter grace period forces sooner.
        (
            r#"grace_period = "10s""#,
            r#"grace_period = "5s""#,
            "memory_guard.grace_period",
            ScopeEffect::Widening,
            AffectedGuards::MemoryGuard,
        ),
        (
            "max_applications_per_incident = 3",
            "max_applications_per_incident = 2",
            "memory_guard.max_applications_per_incident",
            ScopeEffect::Narrowing,
            AffectedGuards::MemoryGuard,
        ),
        // A lower stop threshold of an application budget.
        (
            r#"footprint_stop = "6GiB""#,
            r#"footprint_stop = "5GiB""#,
            "memory_guard.app_budgets[build-worker].footprint_stop",
            ScopeEffect::Widening,
            AffectedGuards::MemoryGuard,
        ),
        // The effect of the recovery threshold is not ordered, so each
        // change is widening.
        (
            r#"footprint_recover = "3GiB""#,
            r#"footprint_recover = "2GiB""#,
            "memory_guard.app_budgets[build-worker].footprint_recover",
            ScopeEffect::Widening,
            AffectedGuards::MemoryGuard,
        ),
        // A time of the agent applies to the two guards.
        (
            r#"plan_ttl = "30s""#,
            r#"plan_ttl = "20s""#,
            "agent.plan_ttl",
            ScopeEffect::Narrowing,
            AffectedGuards::Both,
        ),
    ];
    for (from, to, key, effect, guards) in cases {
        let differences = changed(&[(from, to)]);
        let one = only(&differences);
        assert_eq!(one.kind, ScopeDifferenceKind::Threshold, "{key}");
        assert_eq!(one.subject, threshold(key));
        assert_eq!(one.effect, effect, "{key}");
        assert_eq!(one.guards, guards, "{key}");
        assert!(matches!(one.change, ScopeChange::Changed { .. }), "{key}");
    }
    let differences = changed(&[(r#"reclaim_below = "10GiB""#, r#"reclaim_below = "12GiB""#)]);
    assert_eq!(
        only(&differences).change,
        ScopeChange::Changed {
            from: (10_u64 << 30).to_string(),
            to: (12_u64 << 30).to_string()
        }
    );
}

#[test]
fn a_threshold_that_only_one_scope_has_is_widening() {
    let base = scope(&base_config());
    let mut other = base.clone();
    other
        .disk
        .thresholds
        .retain(|one| one.key != "disk_guard.batch_limit");
    for (old, new, change) in [
        (&base, &other, ScopeChange::Removed),
        (&other, &base, ScopeChange::Added),
    ] {
        let differences = difference(old, new);
        let one = only(&differences);
        assert_eq!(one.subject, threshold("disk_guard.batch_limit"));
        assert_eq!(one.change, change);
        assert_eq!(one.effect, ScopeEffect::Widening);
    }
    // A key that this build does not know is widening for each change.
    let mut unknown = base.clone();
    unknown.disk.thresholds[0].key = "disk_guard.later_key".to_owned();
    let mut changed_value = unknown.clone();
    changed_value.disk.thresholds[0].value += 1;
    let differences = difference(&unknown, &changed_value);
    assert_eq!(only(&differences).effect, ScopeEffect::Widening);
}

#[test]
fn a_setting_with_one_value_in_this_schema_is_widening_for_each_difference() {
    let base = scope(&base_config());
    let keys: Vec<&str> = base
        .fixed_settings
        .iter()
        .map(|setting| setting.key.as_str())
        .collect();
    assert_eq!(
        keys,
        [
            "disk_guard.automatic_mode",
            "disk_guard.exclusions.protect_archives",
            "disk_guard.exclusions.protect_backups",
            "disk_guard.exclusions.protect_databases",
            "disk_guard.exclusions.protect_model_weights",
            "memory_guard.app_budgets[build-worker].restart",
            "memory_guard.global_trigger",
        ]
    );
    // A record of a later schema with another value.
    for index in 0..base.fixed_settings.len() {
        let mut later = base.clone();
        later.fixed_settings[index].value = "later".to_owned();
        for (old, new) in [(&base, &later), (&later, &base)] {
            let differences = difference(old, new);
            let one = only(&differences);
            assert_eq!(one.subject, threshold(&base.fixed_settings[index].key));
            assert_eq!(one.effect, ScopeEffect::Widening);
        }
    }
    // A setting that only one record has.
    let mut shorter = base.clone();
    shorter.fixed_settings.remove(0);
    assert_eq!(
        only(&difference(&shorter, &base)).effect,
        ScopeEffect::Widening
    );
    assert_eq!(
        only(&difference(&base, &shorter)).effect,
        ScopeEffect::Widening
    );
}

#[test]
fn a_profile_change_has_an_effect_only_to_or_from_observe() {
    let aggressive = changed(&[(r#"profile = "balanced""#, r#"profile = "aggressive""#)]);
    let one = only(&aggressive);
    assert_eq!(one.kind, ScopeDifferenceKind::Profile);
    assert_eq!(one.guards, AffectedGuards::Both);
    assert_eq!(one.effect, ScopeEffect::Neutral);
    assert_eq!(
        one.change,
        ScopeChange::Changed {
            from: "balanced".to_owned(),
            to: "aggressive".to_owned()
        }
    );

    let observe = changed(&[(r#"profile = "balanced""#, r#"profile = "observe""#)]);
    assert_eq!(only(&observe).effect, ScopeEffect::Narrowing);

    let base = scope(&base_config());
    let observing = scope(&config(&[(
        r#"profile = "balanced""#,
        r#"profile = "observe""#,
    )]));
    assert_eq!(
        only(&difference(&observing, &base)).effect,
        ScopeEffect::Widening
    );
    assert!(base.profile_permits_intervention());
    assert!(!observing.profile_permits_intervention());
    // A profile text that this build does not know permits nothing.
    let mut unknown = base;
    unknown.profile = "later".to_owned();
    assert!(!unknown.profile_permits_intervention());
}

#[test]
fn the_effect_on_a_guard_is_the_widest_effect_that_applies_to_it() {
    let differences = changed(&[
        // Narrowing for the disk guard.
        (r#"reclaim_below = "10GiB""#, r#"reclaim_below = "8GiB""#),
        // Widening for the disk guard.
        (r#"paths = ["~/Documents"]"#, "paths = []"),
        // Narrowing for the memory guard.
        ("allow_force_quit = true", "allow_force_quit = false"),
    ]);
    assert_eq!(
        effect_on(&differences, PolicyId::DiskGuard),
        ScopeEffect::Widening
    );
    assert_eq!(
        effect_on(&differences, PolicyId::MemoryGuard),
        ScopeEffect::Narrowing
    );
    assert_eq!(effect_on(&[], PolicyId::DiskGuard), ScopeEffect::Neutral);
    // Each difference has the JSON form of its tags.
    let exception = differences
        .iter()
        .find(|one| one.kind == ScopeDifferenceKind::ProtectedTargetException)
        .unwrap();
    let json = serde_json::to_value(exception).unwrap();
    assert_eq!(json["kind"], "protected_target_exception");
    assert_eq!(json["guards"], "disk_guard");
    assert_eq!(json["effect"], "widening");
    assert_eq!(json["change"]["change"], "removed");
    assert_eq!(json["subject"]["subject"], "excluded_path");
    assert_eq!(
        serde_json::from_value::<ScopeDifference>(json).unwrap(),
        *exception
    );
}

/// The differences from the base configuration with `changes` to the base
/// configuration: the opposite direction of [`changed`].
fn reversed(changes: &[(&str, &str)]) -> Vec<ScopeDifference> {
    difference(&scope(&config(changes)), &scope(&base_config()))
}

#[test]
fn a_difference_in_the_opposite_direction_has_the_opposite_effect() {
    let groups = reversed(&[(
        r#"["background-user-applications", "managed-jobs"]"#,
        r#"["managed-jobs"]"#,
    )]);
    let one = only(&groups);
    assert_eq!(one.kind, ScopeDifferenceKind::EligibleRoot);
    assert_eq!(one.change, ScopeChange::Added);
    assert_eq!(one.effect, ScopeEffect::Widening);

    let budget = reversed(&[(
        "restart = \"never\"\n",
        "restart = \"never\"\n\n[[memory_guard.app_budgets]]\nid = \"render\"\n\
         bundle_id = \"com.example.Render\"\nfootprint_soft = \"1GiB\"\n\
         footprint_stop = \"2GiB\"\nover_limit_for = \"30s\"\ncooldown = \"10m\"\n",
    )]);
    let one = only(&budget);
    assert_eq!(
        one.subject,
        ScopeSubject::AppBudget {
            budget: "render=com.example.Render".to_owned()
        }
    );
    assert_eq!(one.change, ScopeChange::Removed);
    assert_eq!(one.effect, ScopeEffect::Narrowing);
}

#[test]
fn a_protection_that_is_added_narrows_and_a_protection_that_is_removed_widens() {
    let bundle = changed(&[(
        r#"protected_bundle_ids = ["com.example.Protected"]"#,
        r#"protected_bundle_ids = ["com.example.Protected", "com.example.Other"]"#,
    )]);
    let one = only(&bundle);
    assert_eq!(one.change, ScopeChange::Added);
    assert_eq!(one.effect, ScopeEffect::Narrowing);
    assert_eq!(one.guards, AffectedGuards::MemoryGuard);

    let executable = changed(&[(
        r#"protected_executable_paths = ["/Applications/Keep.app"]"#,
        "protected_executable_paths = []",
    )]);
    let one = only(&executable);
    assert_eq!(one.change, ScopeChange::Removed);
    assert_eq!(one.effect, ScopeEffect::Widening);
    assert_eq!(one.guards, AffectedGuards::MemoryGuard);

    let foreground = reversed(&[("protect_foreground = true", "protect_foreground = false")]);
    let one = only(&foreground);
    assert_eq!(one.subject, ScopeSubject::ForegroundProtection);
    assert_eq!(one.effect, ScopeEffect::Narrowing);
}

#[test]
fn the_critical_memory_exception_that_is_removed_is_narrowing() {
    let differences = reversed(&[(
        "allow_volatile_journal_on_critical = false",
        "allow_volatile_journal_on_critical = true",
    )]);
    let one = only(&differences);
    assert_eq!(one.kind, ScopeDifferenceKind::RecordingException);
    assert_eq!(one.subject, ScopeSubject::VolatileJournalOnCritical);
    assert_eq!(one.effect, ScopeEffect::Narrowing);
}

#[test]
fn a_larger_recovery_threshold_is_widening_like_a_smaller_one() {
    let differences = changed(&[(
        r#"footprint_recover = "3GiB""#,
        r#"footprint_recover = "4GiB""#,
    )]);
    let one = only(&differences);
    assert_eq!(
        one.subject,
        threshold("memory_guard.app_budgets[build-worker].footprint_recover")
    );
    assert_eq!(one.effect, ScopeEffect::Widening);
}

#[test]
fn two_scopes_of_no_configuration_have_no_difference() {
    assert_eq!(difference(&PolicyScope::none(), &PolicyScope::none()), []);
}

#[test]
fn each_threshold_of_a_scope_has_a_unit() {
    use super::super::{Threshold, ThresholdUnit};
    let scope: PolicyScope = scope(&base_config());
    let thresholds: Vec<&Threshold> = scope
        .agent_thresholds
        .iter()
        .chain(&scope.disk.thresholds)
        .chain(&scope.memory.thresholds)
        .collect();
    assert!(thresholds.len() > 20);
    for threshold in &thresholds {
        assert!(threshold.unit().is_some(), "{} has no unit", threshold.key);
    }
    let unit = |key: &str| {
        thresholds
            .iter()
            .find(|threshold| threshold.key == key)
            .and_then(|threshold| threshold.unit())
    };
    assert_eq!(unit("disk_guard.reclaim_below"), Some(ThresholdUnit::Bytes));
    assert_eq!(unit("disk_guard.batch_limit"), Some(ThresholdUnit::Bytes));
    assert_eq!(
        unit("disk_guard.batch_item_limit"),
        Some(ThresholdUnit::Count)
    );
    assert_eq!(unit("agent.plan_ttl"), Some(ThresholdUnit::Nanoseconds));
    assert_eq!(
        unit("memory_guard.app_budgets[build-worker].footprint_stop"),
        Some(ThresholdUnit::Bytes)
    );
    assert_eq!(
        unit("memory_guard.app_budgets[build-worker].cooldown"),
        Some(ThresholdUnit::Nanoseconds)
    );
    assert_eq!(
        unit("memory_guard.max_applications_per_incident"),
        Some(ThresholdUnit::Count)
    );
}

#[test]
fn a_key_that_this_build_does_not_make_has_no_unit() {
    use super::super::threshold_unit;
    for key in [
        "",
        "cooldown",
        "disk_guard",
        "disk_guard.unknown_field",
        "protections.cooldown",
        // A budget identifier with a `.` does not change the field.
        "memory_guard.app_budgets[a.cooldown].unknown",
        // A field of a different table.
        "disk_guard.cooldown",
        "agent.batch_limit",
        "memory_guard.footprint_stop",
        "memory_guard.app_budgets[x].sample_interval",
        "memory_guard.app_budgets[x]cooldown",
        "disk_guard.sustain_for.extra",
    ] {
        assert_eq!(threshold_unit(key), None, "{key}");
    }
}

#[test]
fn a_threshold_value_has_the_text_of_the_configuration_grammar() {
    use super::super::{Threshold, ThresholdValue};
    use crate::byte_size::parse_byte_size;
    use crate::duration::parse_duration;
    use crate::quantity::{Bytes, Nanoseconds};
    const GIB: u64 = 1024 * 1024 * 1024;
    const SECOND: u64 = 1_000_000_000;

    let value = |key: &str, value: u64| {
        Threshold {
            key: key.to_owned(),
            value,
        }
        .typed_value()
        .unwrap()
    };
    assert_eq!(
        value("disk_guard.reclaim_below", 25 * GIB),
        ThresholdValue::Bytes(Bytes::new(25 * GIB))
    );
    assert_eq!(
        value("disk_guard.reclaim_below", 25 * GIB).to_string(),
        "25GiB"
    );
    assert_eq!(
        value("disk_guard.batch_limit", 1536 * 1024 * 1024).to_string(),
        "1536MiB"
    );
    assert_eq!(value("disk_guard.batch_limit", 1000).to_string(), "1000B");
    assert_eq!(value("disk_guard.batch_limit", 0).to_string(), "0B");
    assert_eq!(
        value("disk_guard.sustain_for", 120 * SECOND).to_string(),
        "2m"
    );
    assert_eq!(
        value("disk_guard.sustain_for", 90 * SECOND).to_string(),
        "90s"
    );
    assert_eq!(
        value("disk_guard.sustain_for", 250_000_000).to_string(),
        "250ms"
    );
    assert_eq!(value("disk_guard.sustain_for", 0).to_string(), "0s");
    assert_eq!(value("disk_guard.sustain_for", 7).to_string(), "7ns");
    assert_eq!(value("agent.plan_ttl", 86_400 * SECOND).to_string(), "1d");
    assert_eq!(
        value("disk_guard.pass_item_limit", 5000).to_string(),
        "5000"
    );
    assert_eq!(
        value("disk_guard.sustain_for", 7),
        ThresholdValue::Nanoseconds(Nanoseconds::new(7))
    );

    // The text of each value of the base scope reads back to the value.
    let scope: PolicyScope = scope(&base_config());
    for threshold in scope
        .agent_thresholds
        .iter()
        .chain(&scope.disk.thresholds)
        .chain(&scope.memory.thresholds)
    {
        let text: String = threshold.typed_value().unwrap().to_string();
        match threshold.typed_value().unwrap() {
            ThresholdValue::Bytes(size) => assert_eq!(parse_byte_size(&text), Ok(size), "{text}"),
            ThresholdValue::Nanoseconds(time) => assert_eq!(
                u64::try_from(parse_duration(&text).unwrap().as_nanos()).unwrap(),
                time.get(),
                "{text}"
            ),
            ThresholdValue::Count(count) => assert_eq!(text, count.to_string()),
        }
    }
    assert_eq!(
        Threshold {
            key: "disk_guard.unknown".to_owned(),
            value: 1
        }
        .typed_value(),
        None
    );
}
