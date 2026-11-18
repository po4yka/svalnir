//! Tests of activation, enablement, disablement, and revocation.

use super::super::{
    Acceptance, AcknowledgementLevel, ActivationRefusal, AuthorityState, ControlRefusal,
    DisableRequest, EnableRefusal, GuardStanding, InhibitedGuard, InhibitionCause,
    InstanceInhibition, Persistence, RevokeRequest, ScopeDifferenceKind, ScopeEffect, ScopeError,
    activate, disable, guard_standing, revoke,
};
use super::{
    DERIVED_DATA, Registry, TEMPORARY, USER, activated, activation, active_state, automatic,
    base_config, config, durable, enable, enable_request, enabled, enabled_state, grant, grant_id,
    registry, registry_with, revision_id, rule, rule_ref, wall,
};
use crate::action::{ActionClass, Escalation};
use crate::authority::Generation;
use crate::policy::PolicyId;
use crate::process::Uid;
use crate::rule::LifecycleState;

const DISK: PolicyId = PolicyId::DiskGuard;
const MEMORY: PolicyId = PolicyId::MemoryGuard;

fn standing(state: &AuthorityState, policy: PolicyId) -> GuardStanding {
    guard_standing(state, &InstanceInhibition::default(), policy, wall(30))
}

fn none() -> InstanceInhibition {
    InstanceInhibition::default()
}

// Activation.

#[test]
fn the_first_activation_makes_a_revision_and_no_grant() {
    let state = AuthorityState::new(USER);
    let config = base_config();
    let request = activation(&state, &config, "policy_1");
    let change = activate(&state, &request, &registry()).unwrap();
    assert!(change.needs_persistence());
    let acknowledged = durable(change);
    assert_eq!(acknowledged.level, AcknowledgementLevel::DurablyApplied);
    let report = &acknowledged.report;
    assert_eq!(report.revision.revision_id, revision_id("policy_1"));
    assert_eq!(report.revision.content, request.content);
    assert_eq!(report.revision.schema_version, 1);
    assert_eq!(report.revision.activated_at, wall(10));
    assert_eq!(report.previous, None);
    assert!(!report.unchanged);
    assert!(report.invalidates_unconsumed_plans);
    assert_eq!(report.rules_not_validated, []);
    // The thresholds of a first activation are not listed.
    assert_ne!(report.differences, []);
    assert!(
        report
            .differences
            .iter()
            .all(|one| one.kind != ScopeDifferenceKind::Threshold)
    );
    // An activation enables nothing and grants nothing.
    let state = &acknowledged.state;
    assert_eq!(state.guards, []);
    for guard in &report.guards {
        assert_eq!(guard.standing, GuardStanding::Disabled);
        assert_eq!(guard.effect, ScopeEffect::Widening);
    }
    assert_eq!(standing(state, DISK), GuardStanding::Disabled);
}

#[test]
fn a_profile_name_grants_nothing() {
    let config = config(&[(r#"profile = "balanced""#, r#"profile = "aggressive""#)]);
    let state = active_state(&config);
    assert_eq!(state.guards, []);
    assert_eq!(standing(&state, DISK), GuardStanding::Disabled);
    assert_eq!(standing(&state, MEMORY), GuardStanding::Disabled);
}

#[test]
fn an_activation_reports_the_rules_that_are_only_proposed() {
    let state = AuthorityState::new(USER);
    let config = base_config();
    let proposed = registry_with(&LifecycleState::Proposed);
    let change = activate(&state, &activation(&state, &config, "policy_1"), &proposed).unwrap();
    assert_eq!(
        change.report.rules_not_validated,
        [rule_ref(TEMPORARY, "r1"), rule_ref(DERIVED_DATA, "r1")]
    );
}

#[test]
fn a_stale_expected_revision_is_a_conflict_and_overwrites_nothing() {
    let config = base_config();
    let state = active_state(&config);
    let narrower = config_without_force();

    // The client expects no revision, and one is in effect.
    let mut request = activation(&state, &narrower, "policy_2");
    request.expected_revision = None;
    assert_eq!(
        activate(&state, &request, &registry()),
        Err(ActivationRefusal::RevisionConflict {
            expected: None,
            active: Some(revision_id("policy_1")),
            content_is_active: false,
        })
    );
    // The client expects an earlier revision.
    request.expected_revision = Some(revision_id("policy_0"));
    assert!(matches!(
        activate(&state, &request, &registry()),
        Err(ActivationRefusal::RevisionConflict {
            content_is_active: false,
            ..
        })
    ));
    // A client that lost the reply of its apply sees that its content is
    // in effect.
    let mut retry = activation(&state, &config, "policy_2");
    retry.expected_revision = None;
    assert!(matches!(
        activate(&state, &retry, &registry()),
        Err(ActivationRefusal::RevisionConflict {
            content_is_active: true,
            ..
        })
    ));
    // A client expects a revision, and none is in effect.
    let empty = AuthorityState::new(USER);
    let mut request = activation(&empty, &config, "policy_1");
    request.expected_revision = Some(revision_id("policy_1"));
    assert!(matches!(
        activate(&empty, &request, &registry()),
        Err(ActivationRefusal::RevisionConflict { active: None, .. })
    ));
}

#[test]
fn an_activation_with_the_content_in_effect_makes_no_revision() {
    let config = base_config();
    let state = enabled_state();
    let change = activate(
        &state,
        &activation(&state, &config, "policy_2"),
        &registry(),
    )
    .unwrap();
    assert!(!change.needs_persistence());
    assert!(change.report.unchanged);
    assert!(!change.report.invalidates_unconsumed_plans);
    assert_eq!(change.report.revision.revision_id, revision_id("policy_1"));
    assert_eq!(change.next, state);
    // With nothing to write, a failed store has no effect.
    let acknowledged = change.acknowledge(&none(), Persistence::Failed);
    assert_eq!(acknowledged.level, AcknowledgementLevel::DurablyApplied);
    assert_eq!(acknowledged.state, state);
}

#[test]
fn an_activation_is_refused_for_another_user_or_a_bad_request() {
    let config = base_config();
    let state = active_state(&config);
    let narrower = config_without_force();
    let mut request = activation(&state, &narrower, "policy_2");
    request.principal = Uid::new(502);
    assert_eq!(
        activate(&state, &request, &registry()),
        Err(ActivationRefusal::WrongPrincipal)
    );
    let reused = activation(&state, &narrower, "policy_1");
    assert_eq!(
        activate(&state, &reused, &registry()),
        Err(ActivationRefusal::RevisionIdInUse)
    );
    let one_rule = Registry(vec![rule(TEMPORARY, "r1", automatic())]);
    let request = activation(&state, &narrower, "policy_2");
    assert_eq!(
        activate(&state, &request, &one_rule),
        Err(ActivationRefusal::Scope(ScopeError::UnknownRule {
            rule: rule_ref(DERIVED_DATA, "r1").id
        }))
    );
}

fn config_without_force() -> crate::config::ValidatedConfig {
    config(&[("allow_force_quit = true", "allow_force_quit = false")])
}

#[test]
fn a_narrowing_activation_carries_the_grant_to_the_new_revision() {
    let state = enabled_state();
    let before = grant(&state, MEMORY).clone();
    assert_eq!(before.generation, Generation::new(1));
    let (next, report) = activated(&state, &config_without_force(), "policy_2");

    let memory = &report.guards[1];
    assert_eq!(memory.policy, MEMORY);
    assert_eq!(memory.effect, ScopeEffect::Narrowing);
    assert_eq!(memory.standing, GuardStanding::Active);
    assert_eq!(memory.uncovered, []);
    let after = grant(&next, MEMORY);
    assert_eq!(after.grant_id, before.grant_id);
    assert_eq!(after.generation, Generation::new(2));
    assert_eq!(after.policy_revision, revision_id("policy_2"));
    // The grant loses what the new scope does not use.
    assert_eq!(after.action_classes, [ActionClass::RequestApplicationExit]);
    assert_eq!(after.escalations, []);

    // A neutral change for the disk guard carries its grant also.
    let disk = &report.guards[0];
    assert_eq!(disk.effect, ScopeEffect::Neutral);
    assert_eq!(disk.standing, GuardStanding::Active);
    assert_eq!(grant(&next, DISK).generation, Generation::new(2));
    assert_eq!(grant(&next, DISK).policy_revision, revision_id("policy_2"));
    assert!(report.invalidates_unconsumed_plans);
}

#[test]
fn a_widening_activation_needs_a_new_acceptance() {
    let state = enabled_state();
    let before = grant(&state, DISK).clone();
    let wider = config(&[(
        r#"volumes = ["startup-data"]"#,
        r#"volumes = ["startup-data", "external-data"]"#,
    )]);
    let (next, report) = activated(&state, &wider, "policy_2");

    let disk = &report.guards[0];
    assert_eq!(disk.effect, ScopeEffect::Widening);
    assert_eq!(disk.standing, GuardStanding::AcceptanceRequired);
    assert_eq!(disk.uncovered.len(), 1);
    assert_eq!(disk.uncovered[0].kind, ScopeDifferenceKind::EligibleRoot);
    // The grant did not change: it stays bound to the earlier revision.
    assert_eq!(grant(&next, DISK), &before);
    assert_eq!(standing(&next, DISK), GuardStanding::AcceptanceRequired);
    // The other guard is not affected.
    assert_eq!(report.guards[1].standing, GuardStanding::Active);

    // The acceptance of the new revision makes the guard active again.
    let accepted = enabled(&next, DISK, &[Acceptance::PermanentEviction]);
    assert_eq!(standing(&accepted, DISK), GuardStanding::Active);
    let after = grant(&accepted, DISK);
    assert_eq!(after.grant_id, before.grant_id);
    assert_eq!(after.generation, Generation::new(2));
    assert_eq!(after.policy_revision, revision_id("policy_2"));
}

#[test]
fn each_kind_of_widening_leaves_the_grant_of_its_guard_uncovered() {
    let cases: [(&str, &str, PolicyId); 5] = [
        // A new action class.
        (
            "allow_volatile_journal_on_critical = false",
            "allow_volatile_journal_on_critical = true",
            MEMORY,
        ),
        // A new exception of a protection.
        (r#"paths = ["~/Documents"]"#, "paths = []", DISK),
        (
            "protect_foreground = true",
            "protect_foreground = false",
            MEMORY,
        ),
        // A larger ceiling.
        (
            r#"incident_limit = "16GiB""#,
            r#"incident_limit = "32GiB""#,
            DISK,
        ),
        // A removed global exclusion.
        (
            r#"excluded_paths = ["~/Keep"]"#,
            "excluded_paths = []",
            DISK,
        ),
    ];
    for (from, to, policy) in cases {
        let state = enabled_state();
        let (next, report) = activated(&state, &config(&[(from, to)]), "policy_2");
        assert_eq!(
            standing(&next, policy),
            GuardStanding::AcceptanceRequired,
            "{from}"
        );
        let other = if policy == DISK { MEMORY } else { DISK };
        assert_eq!(standing(&next, other), GuardStanding::Active, "{from}");
        let guard = report
            .guards
            .iter()
            .find(|one| one.policy == policy)
            .unwrap();
        assert!(!guard.uncovered.is_empty(), "{from}");
    }
}

#[test]
fn a_grant_covers_the_scope_that_was_accepted_and_no_wider_scope() {
    let state = enabled_state();
    let wider = config(&[(r#"paths = ["~/Documents"]"#, "paths = []")]);
    // Wider, then the accepted scope again: the grant covers it, with no
    // new acceptance.
    let (widened, _) = activated(&state, &wider, "policy_2");
    assert_eq!(standing(&widened, DISK), GuardStanding::AcceptanceRequired);
    let (back, report) = activated(&widened, &base_config(), "policy_3");
    assert_eq!(standing(&back, DISK), GuardStanding::Active);
    assert_eq!(report.guards[0].effect, ScopeEffect::Narrowing);
    assert_eq!(grant(&back, DISK).policy_revision, revision_id("policy_3"));

    // Narrower, then the first scope again: the grant followed the
    // narrower scope, so the wider one needs an acceptance.
    let narrower = config(&[(
        r#"excluded_paths = ["~/Keep"]"#,
        r#"excluded_paths = ["~/Keep", "~/Projects"]"#,
    )]);
    let (restricted, _) = activated(&state, &narrower, "policy_2");
    assert_eq!(standing(&restricted, DISK), GuardStanding::Active);
    let (again, _) = activated(&restricted, &base_config(), "policy_3");
    assert_eq!(standing(&again, DISK), GuardStanding::AcceptanceRequired);
}

#[test]
fn an_activation_that_is_not_persisted_changes_no_revision() {
    let state = enabled_state();
    // A wider scope is an expansion: nothing changes.
    let wider = config(&[(r#"paths = ["~/Documents"]"#, "paths = []")]);
    let change = activate(&state, &activation(&state, &wider, "policy_2"), &registry()).unwrap();
    assert!(!change.is_restriction());
    let acknowledged = change.acknowledge(&none(), Persistence::Failed);
    assert_eq!(acknowledged.level, AcknowledgementLevel::NotApplied);
    assert_eq!(acknowledged.state, state);
    assert_eq!(acknowledged.inhibition, none());

    // A narrower scope is a restriction: the earlier revision stays, and
    // the running instance inhibits the guard that the request restricts.
    let narrower = config_without_force();
    let request = activation(&state, &narrower, "policy_2");
    let change = activate(&state, &request, &registry()).unwrap();
    assert!(change.is_restriction());
    let acknowledged = change.acknowledge(&none(), Persistence::Failed);
    assert_eq!(
        acknowledged.level,
        AcknowledgementLevel::CurrentInstanceInhibition
    );
    assert_eq!(acknowledged.state, state);
    let restricted = InhibitedGuard {
        policy: MEMORY,
        cause: InhibitionCause::Restriction,
    };
    assert_eq!(acknowledged.inhibition.guards, [restricted]);
    assert_eq!(
        guard_standing(&state, &acknowledged.inhibition, MEMORY, wall(30)),
        GuardStanding::Inhibited
    );
    assert_eq!(
        guard_standing(&state, &acknowledged.inhibition, DISK, wall(30)),
        GuardStanding::Active
    );

    // The same request with a durable write removes the inhibition.
    let change = activate(&state, &request, &registry()).unwrap();
    let durable = change.acknowledge(&acknowledged.inhibition, Persistence::Durable);
    assert_eq!(durable.level, AcknowledgementLevel::DurablyApplied);
    assert_eq!(durable.inhibition, none());
    assert_eq!(
        guard_standing(&durable.state, &durable.inhibition, MEMORY, wall(30)),
        GuardStanding::Active
    );
}

#[test]
fn a_mixed_activation_that_is_not_persisted_inhibits_the_guard_that_it_restricts() {
    let state = enabled_state();
    // Wider for the disk guard, narrower for the memory guard.
    let mixed = config(&[
        (r#"paths = ["~/Documents"]"#, "paths = []"),
        ("allow_force_quit = true", "allow_force_quit = false"),
    ]);
    let request = activation(&state, &mixed, "policy_2");
    let change = activate(&state, &request, &registry()).unwrap();
    assert_eq!(change.report.guards[0].effect, ScopeEffect::Widening);
    assert_eq!(change.report.guards[1].effect, ScopeEffect::Narrowing);
    let acknowledged = change.acknowledge(&none(), Persistence::Failed);
    assert_eq!(
        acknowledged.level,
        AcknowledgementLevel::CurrentInstanceInhibition
    );
    // The earlier revision stays: the wider scope does not apply.
    assert_eq!(acknowledged.state, state);
    assert_eq!(
        acknowledged.inhibition.guards,
        [InhibitedGuard {
            policy: MEMORY,
            cause: InhibitionCause::Restriction,
        }]
    );
    // An enable does not remove the inhibition of an activation: only a
    // durable activation changes the scope.
    let enabled = super::super::enable(
        &state,
        &acknowledged.inhibition,
        &enable_request(&state, MEMORY, &[Acceptance::ForceQuit]),
    )
    .unwrap()
    .acknowledge(&acknowledged.inhibition, Persistence::Durable);
    assert_eq!(enabled.inhibition, acknowledged.inhibition);
    assert_eq!(
        guard_standing(&enabled.state, &enabled.inhibition, MEMORY, wall(30)),
        GuardStanding::Inhibited
    );
}

#[test]
fn a_revision_identity_that_is_used_again_gives_no_authority() {
    let state = enabled_state();
    let wider = config(&[(
        r#"volumes = ["startup-data"]"#,
        r#"volumes = ["startup-data", "external-data"]"#,
    )]);
    let (widened, _) = activated(&state, &wider, "policy_2");
    assert_eq!(standing(&widened, DISK), GuardStanding::AcceptanceRequired);
    // A later revision with the wider scope and the identity that the
    // grant is bound to.
    let commented = config(&[
        (
            r#"volumes = ["startup-data"]"#,
            r#"volumes = ["startup-data", "external-data"]"#,
        ),
        (r#"warn_below = "20GiB""#, r#"warn_below = "21GiB""#),
    ]);
    let (reused, _) = activated(&widened, &commented, "policy_1");
    assert_eq!(
        grant(&reused, DISK).policy_revision,
        revision_id("policy_1")
    );
    assert_eq!(standing(&reused, DISK), GuardStanding::AcceptanceRequired);
}

// Enablement.

#[test]
fn a_guard_is_enabled_only_with_exactly_its_action_classes() {
    use ActionClass::{EvictRegenerableData, ForceApplicationExit, RequestApplicationExit};
    let state = active_state(&base_config());
    let refusal = |policy: PolicyId, acceptances: &[Acceptance]| {
        enable(&state, &enable_request(&state, policy, acceptances)).unwrap_err()
    };
    let mismatch =
        |missing: &[ActionClass], excess: &[ActionClass]| EnableRefusal::AcceptanceMismatch {
            missing: missing.to_vec(),
            excess: excess.to_vec(),
        };
    // Missing.
    assert_eq!(refusal(DISK, &[]), mismatch(&[EvictRegenerableData], &[]));
    assert_eq!(
        refusal(MEMORY, &[Acceptance::ApplicationExit]),
        mismatch(&[ForceApplicationExit], &[])
    );
    // Excess.
    assert_eq!(
        refusal(
            DISK,
            &[Acceptance::PermanentEviction, Acceptance::ForceQuit]
        ),
        mismatch(&[], &[RequestApplicationExit, ForceApplicationExit])
    );
    // Missing and excess.
    assert_eq!(
        refusal(MEMORY, &[Acceptance::PermanentEviction]),
        mismatch(
            &[RequestApplicationExit, ForceApplicationExit],
            &[EvictRegenerableData]
        )
    );
    // A class that this build does not know is an excess.
    let mut request = enable_request(&state, DISK, &[Acceptance::PermanentEviction]);
    request.accepted.push(ActionClass::from_wire("EmptyTrash"));
    assert_eq!(
        enable(&state, &request).unwrap_err(),
        mismatch(&[], &[ActionClass::from_wire("EmptyTrash")])
    );
    assert_eq!(state.guards, []);

    // Exact.
    let change = enable(
        &state,
        &enable_request(&state, DISK, &[Acceptance::PermanentEviction]),
    )
    .unwrap();
    assert!(!change.report.unchanged);
    assert_eq!(change.report.action_classes, [EvictRegenerableData]);
    let next = durable(change).state;
    assert_eq!(standing(&next, DISK), GuardStanding::Active);
    assert_eq!(standing(&next, MEMORY), GuardStanding::Disabled);
    let disk = grant(&next, DISK);
    assert_eq!(disk.grant_id, grant_id("grant_disk"));
    assert_eq!(disk.generation, Generation::new(1));
    assert_eq!(disk.principal, USER);
    assert_eq!(disk.policy_revision, revision_id("policy_1"));
    assert_eq!(
        disk.rules,
        [rule_ref(TEMPORARY, "r1"), rule_ref(DERIVED_DATA, "r1")]
    );
    assert_eq!(disk.escalations, []);
    assert!(!disk.allow_volatile_journal_on_critical);
    assert_eq!(disk.granted_at, wall(20));
    assert_eq!(disk.expires_at, None);

    // The two acceptances of the memory guard name the same classes as
    // the force-quit acceptance alone.
    let both = enabled(
        &next,
        MEMORY,
        &[Acceptance::ApplicationExit, Acceptance::ForceQuit],
    );
    let memory = grant(&both, MEMORY);
    assert_eq!(
        memory.action_classes,
        [RequestApplicationExit, ForceApplicationExit]
    );
    assert_eq!(memory.escalations, [Escalation::ForceAfterGrace]);
    assert_eq!(memory.rules, []);
}

#[test]
fn a_guard_with_no_force_quit_refuses_the_force_quit_acceptance() {
    let state = active_state(&config_without_force());
    assert_eq!(
        enable(
            &state,
            &enable_request(&state, MEMORY, &[Acceptance::ForceQuit])
        )
        .unwrap_err(),
        EnableRefusal::AcceptanceMismatch {
            missing: Vec::new(),
            excess: vec![ActionClass::ForceApplicationExit],
        }
    );
    let next = enabled(&state, MEMORY, &[Acceptance::ApplicationExit]);
    assert_eq!(standing(&next, MEMORY), GuardStanding::Active);
    assert_eq!(
        grant(&next, MEMORY).action_classes,
        [ActionClass::RequestApplicationExit]
    );
}

#[test]
fn the_grant_records_the_critical_memory_exception_of_the_reviewed_revision() {
    let volatile = config(&[(
        "allow_volatile_journal_on_critical = false",
        "allow_volatile_journal_on_critical = true",
    )]);
    let state = active_state(&volatile);
    let next = enabled(&state, MEMORY, &[Acceptance::ForceQuit]);
    assert!(grant(&next, MEMORY).allow_volatile_journal_on_critical);
    // The disk grant never has the exception.
    let next = enabled(&next, DISK, &[Acceptance::PermanentEviction]);
    assert!(!grant(&next, DISK).allow_volatile_journal_on_critical);
    // A narrowing activation removes it from the grant.
    let (narrowed, _) = activated(&next, &base_config(), "policy_2");
    assert_eq!(standing(&narrowed, MEMORY), GuardStanding::Active);
    assert!(!grant(&narrowed, MEMORY).allow_volatile_journal_on_critical);
}

#[test]
fn an_enable_must_name_the_reviewed_revision() {
    let state = active_state(&base_config());
    // A request that names no revision binds nothing: the revision in
    // effect is not used in its place, also not for a client with a terminal.
    let mut request = enable_request(&state, DISK, &[Acceptance::PermanentEviction]);
    request.reviewed_revision = None;
    assert_eq!(
        enable(&state, &request).unwrap_err(),
        EnableRefusal::ReviewedRevisionRequired
    );
    // The revision that the client showed is the revision of the grant.
    request.reviewed_revision = Some(revision_id("policy_1"));
    let next = durable(enable(&state, &request).unwrap()).state;
    assert_eq!(grant(&next, DISK).policy_revision, revision_id("policy_1"));

    // A reviewed revision that is not in effect is a conflict.
    let mut request = enable_request(&state, DISK, &[Acceptance::PermanentEviction]);
    request.reviewed_revision = Some(revision_id("policy_0"));
    assert_eq!(
        enable(&state, &request).unwrap_err(),
        EnableRefusal::RevisionConflict {
            reviewed: revision_id("policy_0"),
            active: revision_id("policy_1"),
        }
    );
}

#[test]
fn an_enable_is_refused_without_a_usable_revision() {
    let accept = [Acceptance::PermanentEviction];
    let empty = AuthorityState::new(USER);
    let request = enable_request(&empty, DISK, &accept);
    assert_eq!(
        enable(&empty, &request).unwrap_err(),
        EnableRefusal::NoActiveRevision
    );

    let state = active_state(&base_config());
    let mut request = enable_request(&state, DISK, &accept);
    request.principal = Uid::new(502);
    assert_eq!(
        enable(&state, &request).unwrap_err(),
        EnableRefusal::WrongPrincipal
    );

    let observing = active_state(&config(&[(
        r#"profile = "balanced""#,
        r#"profile = "observe""#,
    )]));
    assert_eq!(
        enable(&observing, &enable_request(&observing, DISK, &accept)).unwrap_err(),
        EnableRefusal::ObserveProfile
    );

    let off = active_state(&config(&[(
        "[disk_guard]\nenabled = true",
        "[disk_guard]\nenabled = false",
    )]));
    assert_eq!(
        enable(&off, &enable_request(&off, DISK, &accept)).unwrap_err(),
        EnableRefusal::GuardNotRequested
    );
    assert_eq!(standing(&off, DISK), GuardStanding::NotRequested);
    assert_eq!(standing(&observing, DISK), GuardStanding::ObserveProfile);
    assert_eq!(standing(&empty, DISK), GuardStanding::NoActiveRevision);
}

#[test]
fn a_new_grant_does_not_take_the_identity_of_a_grant_of_the_record() {
    let state = active_state(&base_config());
    let state = enabled(&state, DISK, &[Acceptance::PermanentEviction]);
    let mut request = enable_request(&state, MEMORY, &[Acceptance::ForceQuit]);
    request.grant_id = grant_id("grant_disk");
    assert_eq!(
        enable(&state, &request).unwrap_err(),
        EnableRefusal::GrantIdInUse
    );
    // A grant whose generation cannot become larger starts again with a
    // new identity, and not with its own.
    let mut exhausted = state;
    exhausted.guards[0].grant.as_mut().unwrap().generation = Generation::MAX;
    exhausted.guards[0].enabled = false;
    let mut request = enable_request(&exhausted, DISK, &[Acceptance::PermanentEviction]);
    assert_eq!(
        enable(&exhausted, &request).unwrap_err(),
        EnableRefusal::GrantIdInUse
    );
    request.grant_id = grant_id("grant_disk_2");
    let next = durable(enable(&exhausted, &request).unwrap()).state;
    assert_eq!(grant(&next, DISK).grant_id, grant_id("grant_disk_2"));
    assert_eq!(grant(&next, DISK).generation, Generation::new(1));
}

#[test]
fn a_repeated_enable_makes_no_new_generation() {
    let state = enabled_state();
    let change = enable(
        &state,
        &enable_request(&state, DISK, &[Acceptance::PermanentEviction]),
    )
    .unwrap();
    assert!(change.report.unchanged);
    assert!(!change.needs_persistence());
    assert_eq!(change.report.grant.generation, Generation::new(1));
    assert_eq!(change.next, state);
}

#[test]
fn an_enable_that_is_not_persisted_grants_nothing() {
    let state = active_state(&base_config());
    let change = enable(
        &state,
        &enable_request(&state, DISK, &[Acceptance::PermanentEviction]),
    )
    .unwrap();
    assert!(!change.is_restriction());
    let acknowledged = change.acknowledge(&none(), Persistence::Failed);
    assert_eq!(acknowledged.level, AcknowledgementLevel::NotApplied);
    assert_eq!(acknowledged.state, state);
    assert_eq!(standing(&acknowledged.state, DISK), GuardStanding::Disabled);
}

// Disable and revoke.

fn disable_request(policy: PolicyId) -> DisableRequest {
    DisableRequest {
        principal: USER,
        policy,
    }
}

#[test]
fn a_durable_disable_stops_the_guard_and_changes_the_generation() {
    let state = enabled_state();
    let change = disable(&state, &disable_request(DISK)).unwrap();
    assert!(change.is_restriction());
    assert!(change.needs_persistence());
    // The restriction applies before the write.
    let now = change.inhibit_now(&none());
    assert_eq!(
        guard_standing(&state, &now, DISK, wall(30)),
        GuardStanding::Inhibited
    );
    let acknowledged = change.acknowledge(&now, Persistence::Durable);
    assert_eq!(acknowledged.level, AcknowledgementLevel::DurablyApplied);
    assert_eq!(acknowledged.inhibition, none());
    assert!(!acknowledged.report.unchanged);
    let next = acknowledged.state;
    assert_eq!(standing(&next, DISK), GuardStanding::Disabled);
    assert_eq!(standing(&next, MEMORY), GuardStanding::Active);
    // The grant stays, with a larger generation.
    assert_eq!(grant(&next, DISK).generation, Generation::new(2));
    assert!(!grant(&next, DISK).revoked);
    assert_eq!(
        acknowledged.report.grant.unwrap().generation,
        Generation::new(2)
    );

    // A new enable gives another generation, so a plan of the first
    // generation does not become valid again.
    let again = enabled(&next, DISK, &[Acceptance::PermanentEviction]);
    assert_eq!(standing(&again, DISK), GuardStanding::Active);
    assert_eq!(grant(&again, DISK).generation, Generation::new(3));

    // A second disable changes nothing.
    let repeated = disable(&next, &disable_request(DISK)).unwrap();
    assert!(repeated.report.unchanged);
    assert!(!repeated.needs_persistence());
}

#[test]
fn a_disable_that_is_not_persisted_inhibits_the_running_instance_only() {
    let state = enabled_state();
    let change = disable(&state, &disable_request(MEMORY)).unwrap();
    let acknowledged = change.acknowledge(&none(), Persistence::Failed);
    assert_eq!(
        acknowledged.level,
        AcknowledgementLevel::CurrentInstanceInhibition
    );
    // The durable record did not change: after a restart the guard is
    // active again.
    assert_eq!(acknowledged.state, state);
    assert_eq!(standing(&acknowledged.state, MEMORY), GuardStanding::Active);
    // The running instance inhibits the guard.
    let inhibited = InhibitedGuard {
        policy: MEMORY,
        cause: InhibitionCause::Disable,
    };
    assert_eq!(acknowledged.inhibition.guards, [inhibited]);
    assert_eq!(
        guard_standing(&state, &acknowledged.inhibition, MEMORY, wall(30)),
        GuardStanding::Inhibited
    );
    // A second failed disable adds no second entry.
    let again = disable(&state, &disable_request(MEMORY))
        .unwrap()
        .acknowledge(&acknowledged.inhibition, Persistence::Failed);
    assert_eq!(again.inhibition.guards, [inhibited]);

    // An activation does not remove the inhibition of a disable.
    let narrower = config_without_force();
    let change = activate(
        &state,
        &activation(&state, &narrower, "policy_2"),
        &registry(),
    )
    .unwrap();
    let activated = change.acknowledge(&acknowledged.inhibition, Persistence::Durable);
    assert_eq!(activated.inhibition.guards, [inhibited]);

    // A new enable of the user removes it. The enable is a new acceptance:
    // the grant gets a larger generation, so a plan from before the disable
    // stays invalid.
    let change = super::super::enable(
        &state,
        &acknowledged.inhibition,
        &enable_request(&state, MEMORY, &[Acceptance::ForceQuit]),
    )
    .unwrap();
    assert!(!change.report.unchanged);
    assert!(change.needs_persistence());
    let enabled = change.acknowledge(&acknowledged.inhibition, Persistence::Durable);
    assert_eq!(enabled.inhibition, none());
    assert_eq!(grant(&enabled.state, MEMORY).generation, Generation::new(2));
    // When that enable is not persisted, the inhibition stays.
    let failed = super::super::enable(
        &state,
        &acknowledged.inhibition,
        &enable_request(&state, MEMORY, &[Acceptance::ForceQuit]),
    )
    .unwrap()
    .acknowledge(&acknowledged.inhibition, Persistence::Failed);
    assert_eq!(failed.level, AcknowledgementLevel::NotApplied);
    assert_eq!(failed.inhibition.guards, [inhibited]);
}

#[test]
fn a_disable_is_refused_for_another_user() {
    let state = enabled_state();
    let request = DisableRequest {
        principal: Uid::new(502),
        policy: DISK,
    };
    assert_eq!(
        disable(&state, &request).unwrap_err(),
        ControlRefusal::WrongPrincipal
    );
}

fn revoke_request(grant: &str) -> RevokeRequest {
    RevokeRequest {
        principal: USER,
        grant_id: grant_id(grant),
    }
}

#[test]
fn a_durable_revocation_ends_the_grant() {
    let state = enabled_state();
    let change = revoke(&state, &revoke_request("grant_disk")).unwrap();
    assert!(change.is_restriction());
    let acknowledged = durable(change);
    assert_eq!(acknowledged.level, AcknowledgementLevel::DurablyApplied);
    assert_eq!(acknowledged.report.policy, DISK);
    let next = acknowledged.state;
    assert!(grant(&next, DISK).revoked);
    assert_eq!(grant(&next, DISK).generation, Generation::new(2));
    assert_eq!(standing(&next, DISK), GuardStanding::GrantRevoked);
    assert_eq!(standing(&next, MEMORY), GuardStanding::Active);
    for class in &ActionClass::ALL {
        assert!(!grant(&next, DISK).covers_class(class, wall(30)));
    }
    // A second revocation changes nothing.
    let repeated = revoke(&next, &revoke_request("grant_disk")).unwrap();
    assert!(repeated.report.unchanged);
    assert!(!repeated.needs_persistence());
    // A narrowing activation does not bring a revoked grant back.
    let (activated, _) = activated(&next, &config_without_force(), "policy_2");
    assert_eq!(standing(&activated, DISK), GuardStanding::GrantRevoked);
    // A new acceptance does, with a larger generation.
    let accepted = enabled(&next, DISK, &[Acceptance::PermanentEviction]);
    assert_eq!(standing(&accepted, DISK), GuardStanding::Active);
    assert_eq!(grant(&accepted, DISK).generation, Generation::new(3));
    assert!(!grant(&accepted, DISK).revoked);
}

#[test]
fn a_revocation_that_is_not_persisted_inhibits_the_running_instance_only() {
    let state = enabled_state();
    let change = revoke(&state, &revoke_request("grant_memory")).unwrap();
    let acknowledged = change.acknowledge(&none(), Persistence::Failed);
    assert_eq!(
        acknowledged.level,
        AcknowledgementLevel::CurrentInstanceInhibition
    );
    assert_eq!(acknowledged.state, state);
    assert!(!grant(&acknowledged.state, MEMORY).revoked);
    assert_eq!(
        acknowledged.inhibition.guards,
        [InhibitedGuard {
            policy: MEMORY,
            cause: InhibitionCause::Revoke,
        }]
    );
    assert_eq!(
        guard_standing(&state, &acknowledged.inhibition, MEMORY, wall(30)),
        GuardStanding::Inhibited
    );
    assert_eq!(
        guard_standing(&state, &acknowledged.inhibition, DISK, wall(30)),
        GuardStanding::Active
    );
}

#[test]
fn a_revocation_is_refused_for_another_user_or_an_unknown_grant() {
    let state = enabled_state();
    assert_eq!(
        revoke(&state, &revoke_request("grant_other")).unwrap_err(),
        ControlRefusal::UnknownGrant {
            grant_id: grant_id("grant_other")
        }
    );
    let request = RevokeRequest {
        principal: Uid::new(502),
        grant_id: grant_id("grant_disk"),
    };
    assert_eq!(
        revoke(&state, &request).unwrap_err(),
        ControlRefusal::WrongPrincipal
    );
}

#[test]
fn a_record_that_does_not_agree_with_itself_gives_no_authority() {
    let mut state = enabled_state();
    let duplicate = state.guard(DISK).unwrap().clone();
    state.guards.push(duplicate);
    assert!(state.guard(DISK).is_none());
    assert_eq!(standing(&state, DISK), GuardStanding::Disabled);
    // A grant of another user covers nothing.
    let mut state = enabled_state();
    state.guards[0].grant.as_mut().unwrap().principal = Uid::new(502);
    assert_eq!(standing(&state, DISK), GuardStanding::AcceptanceRequired);
    // An expired grant.
    let mut state = enabled_state();
    state.guards[0].grant.as_mut().unwrap().expires_at = Some(wall(30));
    assert_eq!(standing(&state, DISK), GuardStanding::GrantExpired);
    // An enabled guard with no grant.
    let mut state = enabled_state();
    state.guards[0].grant = None;
    assert_eq!(standing(&state, DISK), GuardStanding::NoGrant);
}

#[test]
fn the_authority_record_round_trips_and_each_transition_is_deterministic() {
    let state = enabled_state();
    let json = serde_json::to_string(&state).unwrap();
    assert_eq!(
        serde_json::from_str::<AuthorityState>(&json).unwrap(),
        state
    );
    assert_eq!(state, enabled_state());
    let value = serde_json::to_value(&state).unwrap();
    assert_eq!(value["guards"][0]["policy"], "disk-guard");
    assert_eq!(value["guards"][1]["policy"], "memory-guard");
    // A policy name that this build does not know is rejected.
    let mut unknown = value;
    unknown["guards"][0]["policy"] = "cpu-guard".into();
    assert!(serde_json::from_value::<AuthorityState>(unknown).is_err());

    let narrower = config_without_force();
    let request = activation(&state, &narrower, "policy_2");
    assert_eq!(
        activate(&state, &request, &registry()),
        activate(&state, &request, &registry())
    );
    assert_eq!(
        disable(&state, &disable_request(DISK)),
        disable(&state, &disable_request(DISK))
    );
}

#[test]
fn a_restriction_of_a_guard_that_the_same_request_also_widens_inhibits_when_not_persisted() {
    let state = enabled_state();
    // The two differences are for the memory guard: the force quit is
    // removed (narrower) and a protected application is removed (wider).
    let mixed = config(&[
        ("allow_force_quit = true", "allow_force_quit = false"),
        (
            r#"protected_bundle_ids = ["com.example.Protected"]"#,
            "protected_bundle_ids = []",
        ),
    ]);
    let request = activation(&state, &mixed, "policy_2");
    let change = activate(&state, &request, &registry()).unwrap();
    let memory = &change.report.differences;
    assert!(
        memory
            .iter()
            .any(|difference| difference.effect == ScopeEffect::Narrowing
                && difference.guards.includes(MEMORY))
    );
    // The combined effect is widening, and the restriction is not lost.
    assert_eq!(change.report.guards[1].effect, ScopeEffect::Widening);
    assert!(change.is_restriction());
    let acknowledged = change.acknowledge(&none(), Persistence::Failed);
    assert_eq!(
        acknowledged.level,
        AcknowledgementLevel::CurrentInstanceInhibition
    );
    assert_eq!(acknowledged.state, state);
    assert!(acknowledged.inhibition.guards.contains(&InhibitedGuard {
        policy: MEMORY,
        cause: InhibitionCause::Restriction,
    }));
}

#[test]
fn the_durable_record_refuses_an_unknown_key_and_an_absent_optional_key() {
    let state = enabled_state();
    let encoded = serde_json::to_value(&state).unwrap();
    let decoded: AuthorityState = serde_json::from_value(encoded.clone()).unwrap();
    assert_eq!(decoded, state);

    // A key of a later build can restrict authority. This build does not
    // drop it silently.
    let mut unknown = encoded.clone();
    unknown["only_while_on_power"] = serde_json::json!(true);
    assert!(serde_json::from_value::<AuthorityState>(unknown).is_err());
    let mut unknown_grant = encoded.clone();
    unknown_grant["guards"][0]["grant"]["limit"] = serde_json::json!(1);
    assert!(serde_json::from_value::<AuthorityState>(unknown_grant).is_err());
    let mut unknown_scope = encoded.clone();
    unknown_scope["active"]["scope"]["memory"]["extra"] = serde_json::json!(1);
    assert!(serde_json::from_value::<AuthorityState>(unknown_scope).is_err());

    // An absent key is not "no pause" and not "no expiry".
    let mut no_pause = encoded.clone();
    assert!(no_pause.as_object_mut().unwrap().remove("pause").is_some());
    assert!(serde_json::from_value::<AuthorityState>(no_pause).is_err());
    let mut no_expiry = encoded;
    assert!(
        no_expiry["guards"][0]["grant"]
            .as_object_mut()
            .unwrap()
            .remove("expires_at")
            .is_some()
    );
    assert!(serde_json::from_value::<AuthorityState>(no_expiry).is_err());
}
