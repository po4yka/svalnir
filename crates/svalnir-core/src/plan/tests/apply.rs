//! Tests of the checks before an apply: approval, expiry, and revisions.

use super::{
    BUILT_AT, Fixture, LIFETIME, SECOND, clock_at, entry, modes, request, rule, rule_reference,
    trash,
};
use crate::action::{ErrorFamily, Plan, PlanApproval};
use crate::authority::{ActionGrantRef, Generation, PrivilegeGrantRef};
use crate::digest::ContentDigest;
use crate::id::{ActionGrantId, BootId, ClockDomainId, PlanId, PolicyRevisionId, PrivilegeGrantId};
use crate::plan::{
    ApplyRefusal, ApprovalMismatch, BoundRevisions, CleanupMode, CurrentRevisions, ExpiryCause,
    ModeSelection, PlanContext, PlanMode, RevisionChange, StopKind, bound_revisions,
    build_cleanup_plan, check_apply, check_approval, check_expiry, check_revisions,
};
use crate::policy::EvaluationClock;
use crate::quantity::Nanoseconds;
use crate::rule::{Rule, RuleRef};
use crate::time::MonotonicNanos;

fn trash_plan() -> Plan {
    trash(&[entry("a", 100), entry("b", 200)]).plan.unwrap()
}

fn approval_of(plan: &Plan) -> PlanApproval {
    PlanApproval {
        plan_id: plan.plan_id.clone(),
        digest: plan.digest().clone(),
    }
}

const TRASH: PlanMode = PlanMode::Cleanup(CleanupMode::Trash);

#[test]
fn an_approval_is_bound_to_the_plan_identity_the_digest_and_the_mode() {
    let plan: Plan = trash_plan();
    let approval: PlanApproval = approval_of(&plan);
    assert_eq!(check_approval(&plan, &approval, TRASH), Ok(()));

    let other_plan: PlanApproval = PlanApproval {
        plan_id: PlanId::new("plan_2").unwrap(),
        ..approval.clone()
    };
    assert_eq!(
        check_approval(&plan, &other_plan, TRASH),
        Err(ApprovalMismatch::PlanId)
    );

    // The digest of a plan with a different target set.
    let smaller: Plan = trash(&[entry("a", 100)]).plan.unwrap();
    assert_eq!(smaller.plan_id, plan.plan_id);
    let other_digest: PlanApproval = PlanApproval {
        digest: smaller.digest().clone(),
        ..approval.clone()
    };
    assert_eq!(
        check_approval(&plan, &other_digest, TRASH),
        Err(ApprovalMismatch::Digest)
    );
    let no_content: PlanApproval = PlanApproval {
        digest: ContentDigest::of_bytes(b""),
        ..approval.clone()
    };
    assert_eq!(
        check_approval(&plan, &no_content, TRASH),
        Err(ApprovalMismatch::Digest)
    );

    // A wrong identity and a wrong digest together: the identity is
    // compared first, also with a wrong mode.
    let both: PlanApproval = PlanApproval {
        plan_id: PlanId::new("plan_2").unwrap(),
        digest: ContentDigest::of_bytes(b""),
    };
    for mode in [TRASH, PlanMode::Cleanup(CleanupMode::Permanent)] {
        assert_eq!(
            check_approval(&plan, &both, mode),
            Err(ApprovalMismatch::PlanId)
        );
    }

    // An approval of one mode does not apply a plan of a different mode.
    for mode in [
        PlanMode::Cleanup(CleanupMode::Permanent),
        PlanMode::Cleanup(CleanupMode::Evict),
        PlanMode::Stop(StopKind::Graceful),
        PlanMode::Stop(StopKind::ForceAfterGrace),
        PlanMode::Stop(StopKind::ImmediateForce),
    ] {
        assert_eq!(
            check_approval(&plan, &approval, mode),
            Err(ApprovalMismatch::Mode)
        );
    }
    for mismatch in [
        ApprovalMismatch::PlanId,
        ApprovalMismatch::Digest,
        ApprovalMismatch::Mode,
    ] {
        assert_eq!(mismatch.family(), ErrorFamily::Authority);
    }
}

#[test]
fn the_approval_of_each_mode_matches_only_the_plan_of_that_mode() {
    let fixture: Fixture = Fixture::new();
    let rule: Rule = rule();
    let entries = [entry("a", 100)];
    let plans: Vec<Plan> = modes(&rule)
        .into_iter()
        .map(|selection| {
            build_cleanup_plan(&fixture.context(), &request(selection, &entries))
                .unwrap()
                .plan
                .unwrap()
        })
        .collect();
    for (index, plan) in plans.iter().enumerate() {
        for (other, mode) in CleanupMode::ALL.into_iter().enumerate() {
            let result = check_approval(plan, &approval_of(plan), PlanMode::Cleanup(mode));
            assert_eq!(result.is_ok(), index == other);
        }
        // The approval of a different mode has a different digest.
        for (other, other_plan) in plans.iter().enumerate() {
            let result = check_approval(plan, &approval_of(other_plan), TRASH);
            if index != other {
                assert_eq!(result, Err(ApprovalMismatch::Digest));
            }
        }
    }
}

#[test]
fn a_plan_is_expired_at_its_expiry_time() {
    let plan: Plan = trash_plan();
    let expiry: u64 = BUILT_AT * SECOND + LIFETIME.get();
    let at = |nanoseconds: u64| EvaluationClock {
        now: MonotonicNanos::new(nanoseconds),
        ..clock_at(0)
    };
    assert_eq!(plan.validity.expires_at, MonotonicNanos::new(expiry));

    assert_eq!(check_expiry(&plan, &at(BUILT_AT * SECOND)), Ok(()));
    assert_eq!(check_expiry(&plan, &at(expiry - 1)), Ok(()));
    assert_eq!(check_expiry(&plan, &at(expiry)), Err(ExpiryCause::Expired));
    assert_eq!(
        check_expiry(&plan, &at(expiry + 1)),
        Err(ExpiryCause::Expired)
    );
    assert_eq!(
        check_expiry(&plan, &at(u64::MAX)),
        Err(ExpiryCause::Expired)
    );
    assert_eq!(
        check_expiry(&plan, &at(BUILT_AT * SECOND - 1)),
        Err(ExpiryCause::BeforeCreation)
    );

    // A time of a different boot or clock domain is not comparable, also
    // when its number is inside the validity.
    let other_boot: EvaluationClock = EvaluationClock {
        boot_id: BootId::new("boot_2").unwrap(),
        ..at(expiry - 1)
    };
    let other_domain: EvaluationClock = EvaluationClock {
        clock_domain: ClockDomainId::new("clock_other").unwrap(),
        ..at(expiry - 1)
    };
    for clock in [other_boot, other_domain] {
        assert_eq!(
            check_expiry(&plan, &clock),
            Err(ExpiryCause::ClockNotComparable)
        );
        assert!(plan.is_expired(&clock));
    }
    for cause in [
        ExpiryCause::Expired,
        ExpiryCause::ClockNotComparable,
        ExpiryCause::BeforeCreation,
    ] {
        assert_eq!(cause.family(), ErrorFamily::Limits);
    }
}

fn grant(name: &str, generation: u64) -> ActionGrantRef {
    ActionGrantRef {
        grant_id: ActionGrantId::new(name).unwrap(),
        generation: Generation::new(generation),
    }
}

/// An `evict` plan that binds the policy revision `policy_1`, the grants
/// `grant_a` generation 3 and `grant_b` generation 1, and the rule
/// revision `r1`.
fn evict_plan() -> Plan {
    let fixture: Fixture = Fixture::new();
    let rule: Rule = rule();
    let mut context: PlanContext<'_> = fixture.context();
    context.authority.action_grants = vec![grant("grant_b", 1), grant("grant_a", 3)];
    let entries = [entry("a", 100), entry("b", 100)];
    build_cleanup_plan(
        &context,
        &request(ModeSelection::Evict { rule: Ok(&rule) }, &entries),
    )
    .unwrap()
    .plan
    .unwrap()
}

#[test]
fn the_bound_revisions_of_a_plan_are_its_policy_grants_and_rules() {
    let bound: BoundRevisions = bound_revisions(&evict_plan());
    assert_eq!(bound.authority.policy_revision.as_str(), "policy_1");
    assert_eq!(
        bound.authority.action_grants,
        [grant("grant_a", 3), grant("grant_b", 1)]
    );
    assert_eq!(bound.authority.privilege_grant, None);
    // Two targets of one rule revision bind it one time.
    assert_eq!(bound.rules, [rule_reference("r1")]);
    // A `trash` plan binds no rule.
    assert_eq!(bound_revisions(&trash_plan()).rules, []);
}

#[test]
fn a_change_of_each_bound_revision_stops_the_plan() {
    let plan: Plan = evict_plan();
    let policy: PolicyRevisionId = PolicyRevisionId::new("policy_1").unwrap();
    let grants: [ActionGrantRef; 3] = [
        grant("grant_a", 3),
        grant("grant_b", 1),
        grant("grant_c", 9),
    ];
    let rules: [RuleRef; 2] = [rule_reference("r1"), rule_reference("r2")];
    let current: CurrentRevisions<'_> = CurrentRevisions {
        policy_revision: &policy,
        action_grants: &grants,
        privilege_grant: None,
        rules: &rules,
    };
    assert_eq!(check_revisions(&plan, &current), Ok(()));

    // A privilege grant that the plan does not name does not stop it.
    let privilege: PrivilegeGrantRef = PrivilegeGrantRef {
        grant_id: PrivilegeGrantId::new("privilege_1").unwrap(),
        generation: Generation::new(1),
    };
    let with_privilege: CurrentRevisions<'_> = CurrentRevisions {
        privilege_grant: Some(&privilege),
        ..current
    };
    assert_eq!(check_revisions(&plan, &with_privilege), Ok(()));

    let next_policy: PolicyRevisionId = PolicyRevisionId::new("policy_2").unwrap();
    let change: RevisionChange = check_revisions(
        &plan,
        &CurrentRevisions {
            policy_revision: &next_policy,
            ..current
        },
    )
    .unwrap_err();
    assert_eq!(change, RevisionChange::PolicyRevision);
    assert_eq!(change.family(), ErrorFamily::Authority);

    // A grant with a later generation, an earlier generation, or no
    // record: the grant was changed or revoked.
    for changed in [
        vec![grant("grant_a", 4), grant("grant_b", 1)],
        vec![grant("grant_a", 2), grant("grant_b", 1)],
        vec![grant("grant_b", 1)],
    ] {
        let change: RevisionChange = check_revisions(
            &plan,
            &CurrentRevisions {
                action_grants: &changed,
                ..current
            },
        )
        .unwrap_err();
        assert_eq!(
            change,
            RevisionChange::ActionGrant(ActionGrantId::new("grant_a").unwrap())
        );
        assert_eq!(change.family(), ErrorFamily::Authority);
    }
    assert_eq!(
        check_revisions(
            &plan,
            &CurrentRevisions {
                action_grants: &[grant("grant_a", 3)],
                ..current
            }
        ),
        Err(RevisionChange::ActionGrant(
            ActionGrantId::new("grant_b").unwrap()
        ))
    );

    // The registry has a different revision of the rule only. No other
    // revision takes the place of the one in the plan.
    let change: RevisionChange = check_revisions(
        &plan,
        &CurrentRevisions {
            rules: &[rule_reference("r2")],
            ..current
        },
    )
    .unwrap_err();
    assert_eq!(change, RevisionChange::Rule(rule_reference("r1")));
    assert_eq!(change.family(), ErrorFamily::Eligibility);
    assert_eq!(
        change.to_string(),
        "the rule revision svalnir.expired-temporary r1 is not registered for the mode"
    );

    // A plan that binds no grant and no rule needs none.
    let nothing: CurrentRevisions<'_> = CurrentRevisions {
        policy_revision: &policy,
        action_grants: &[],
        privilege_grant: None,
        rules: &[],
    };
    assert_eq!(check_revisions(&trash_plan(), &nothing), Ok(()));
    assert_eq!(
        check_revisions(&plan, &nothing),
        Err(RevisionChange::ActionGrant(
            ActionGrantId::new("grant_a").unwrap()
        ))
    );
}

#[test]
fn the_apply_check_gives_the_first_refusal() {
    let plan: Plan = trash_plan();
    let approval: PlanApproval = approval_of(&plan);
    let policy: PolicyRevisionId = PolicyRevisionId::new("policy_1").unwrap();
    let next_policy: PolicyRevisionId = PolicyRevisionId::new("policy_2").unwrap();
    let current = |policy_revision| CurrentRevisions {
        policy_revision,
        action_grants: &[],
        privilege_grant: None,
        rules: &[],
    };
    let now: EvaluationClock = clock_at(BUILT_AT + 1);
    let late: EvaluationClock = clock_at(BUILT_AT + 601);
    let wrong: PlanApproval = PlanApproval {
        digest: ContentDigest::of_bytes(b"other"),
        ..approval.clone()
    };

    assert_eq!(
        check_apply(&plan, &approval, TRASH, &now, &current(&policy)),
        Ok(())
    );
    // The approval is checked first, then the expiry, then the revisions.
    let refusal: ApplyRefusal =
        check_apply(&plan, &wrong, TRASH, &late, &current(&next_policy)).unwrap_err();
    assert_eq!(refusal, ApplyRefusal::Approval(ApprovalMismatch::Digest));
    assert_eq!(refusal.family(), ErrorFamily::Authority);
    let refusal: ApplyRefusal = check_apply(
        &plan,
        &approval,
        PlanMode::Cleanup(CleanupMode::Permanent),
        &late,
        &current(&next_policy),
    )
    .unwrap_err();
    assert_eq!(refusal, ApplyRefusal::Approval(ApprovalMismatch::Mode));
    assert_eq!(refusal.family(), ErrorFamily::Authority);
    // A clock of a different boot is not comparable; the expiry is checked
    // before the revisions.
    let other_boot: EvaluationClock = EvaluationClock {
        boot_id: BootId::new("boot_2").unwrap(),
        ..clock_at(BUILT_AT + 1)
    };
    let refusal: ApplyRefusal =
        check_apply(&plan, &approval, TRASH, &other_boot, &current(&next_policy)).unwrap_err();
    assert_eq!(
        refusal,
        ApplyRefusal::Expiry(ExpiryCause::ClockNotComparable)
    );
    assert_eq!(refusal.family(), ErrorFamily::Limits);
    let refusal: ApplyRefusal =
        check_apply(&plan, &approval, TRASH, &late, &current(&next_policy)).unwrap_err();
    assert_eq!(refusal, ApplyRefusal::Expiry(ExpiryCause::Expired));
    assert_eq!(refusal.family(), ErrorFamily::Limits);
    assert_eq!(refusal.to_string(), "the plan is expired");
    let refusal: ApplyRefusal =
        check_apply(&plan, &approval, TRASH, &now, &current(&next_policy)).unwrap_err();
    assert_eq!(
        refusal,
        ApplyRefusal::Revision(RevisionChange::PolicyRevision)
    );
    assert_eq!(refusal.family(), ErrorFamily::Authority);

    // A plan with a longer lifetime is current at the same time.
    let fixture: Fixture = Fixture::new();
    let mut context: PlanContext<'_> = fixture.context();
    context.lifetime = Nanoseconds::new(602 * SECOND);
    let entries = [entry("a", 100)];
    let longer: Plan = build_cleanup_plan(&context, &request(ModeSelection::Trash, &entries))
        .unwrap()
        .plan
        .unwrap();
    assert_eq!(
        check_apply(
            &longer,
            &approval_of(&longer),
            TRASH,
            &late,
            &current(&policy)
        ),
        Ok(())
    );
}
