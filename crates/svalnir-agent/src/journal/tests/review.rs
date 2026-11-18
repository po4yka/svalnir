//! Tests of the cross-area changes of the Milestone 2 review: the
//! comparison of an intent with the stored plan, and the rejection that
//! names a different digest.

use svalnir_core::action::{
    Checked, DispatchState, EnvelopeContent, ErrorFamily, Escalation, Journal as _, JournalError,
    PlanApproval, TargetBinding, TriggerClass,
};
use svalnir_core::digest::ContentDigest;
use svalnir_core::file::LosslessPath;
use svalnir_core::id::{DecisionId, PolicyRevisionId};
use svalnir_core::quantity::Nanoseconds;

use super::{
    Fixture, admit, application_plan, approval, envelope, envelope_content, failure, file_plan,
    new_operation, other_principal, principal,
};
use svalnir_core::action::Durability;

/// Each envelope of `changes` has one field that is not the field of the
/// stored plan. The journal refuses each one, records no intent, and then
/// takes the envelope of the plan.
fn refuses_each(
    plan: &svalnir_core::action::Plan,
    step: &str,
    changes: Vec<(&str, Box<dyn Fn(&mut EnvelopeContent)>)>,
) {
    let fixture = Fixture::new();
    let mut journal = fixture.open();
    let operation = admit(&mut journal, plan, "operation_1", "epoch_1");
    for (name, change) in changes {
        let mut content: EnvelopeContent = envelope_content(plan, &operation, step);
        change(&mut content);
        let changed = Checked::new(content).unwrap_or_else(|error| {
            panic!("the changed envelope `{name}` is not a valid envelope: {error}")
        });
        assert_eq!(
            journal.commit_intent(&changed),
            Err(JournalError::Conflict),
            "{name}"
        );
    }
    // No refused envelope fixed the content of the step.
    journal
        .commit_intent(&envelope(plan, &operation, step))
        .unwrap();
}

#[test]
fn an_intent_with_a_file_target_that_is_not_the_target_of_the_plan_is_refused() {
    let plan = file_plan("plan_1", 2);
    refuses_each(
        &plan,
        "s0",
        vec![
            (
                "relative entry",
                Box::new(|content| {
                    let TargetBinding::File(file) = &mut content.target.binding else {
                        panic!("the fixture has a file target");
                    };
                    file.relative_entry = LosslessPath::from_bytes("other").unwrap();
                }),
            ),
            (
                "principal",
                Box::new(|content| content.principal = other_principal()),
            ),
            (
                "authority",
                Box::new(|content| {
                    content.authority.policy_revision = PolicyRevisionId::new("policy_2").unwrap();
                }),
            ),
        ],
    );
}

#[test]
fn an_intent_with_a_member_list_or_limits_that_are_not_those_of_the_plan_is_refused() {
    let plan = application_plan(
        "plan_1",
        TriggerClass::ApplicationBudget,
        Escalation::ForceAfterGrace,
    );
    refuses_each(
        &plan,
        "graceful",
        vec![
            (
                "member list",
                Box::new(|content| {
                    let TargetBinding::Application(application) = &mut content.target.binding
                    else {
                        panic!("the fixture has an application target");
                    };
                    application.members[0].pid = svalnir_core::process::Pid::new(4343).unwrap();
                }),
            ),
            (
                "trigger",
                Box::new(|content| {
                    content.trigger.decision_id = Some(DecisionId::new("decision_2").unwrap());
                }),
            ),
            (
                "grace",
                Box::new(|content| {
                    content.limits.grace = Some(Nanoseconds::new(1));
                }),
            ),
            (
                "escalation",
                Box::new(|content| {
                    content.limits.escalation = Escalation::None;
                    content.limits.grace = None;
                }),
            ),
        ],
    );
}

#[test]
fn a_rejection_for_a_digest_that_is_not_the_stored_digest_records_nothing() {
    let fixture = Fixture::new();
    let mut journal = fixture.open();
    let plan = file_plan("plan_1", 1);
    journal.record_plan(&plan).unwrap();
    let rejection = failure(ErrorFamily::Authority, DispatchState::NotSubmitted);
    let wrong = PlanApproval {
        plan_id: plan.plan_id.clone(),
        digest: ContentDigest::of_bytes(b"a different plan"),
    };
    assert_eq!(
        journal.record_rejection(&wrong, &principal(), &rejection),
        Err(JournalError::Conflict)
    );
    // The plan is not consumed: an apply with the stored digest is
    // admitted and is not the rejection.
    let operation = new_operation(&plan, "operation_1", "epoch_1", Durability::Durable);
    assert_eq!(
        journal.admit(&approval(&plan), &principal(), &operation),
        Ok(svalnir_core::action::Admission::Admitted)
    );
}
