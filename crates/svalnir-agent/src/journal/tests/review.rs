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

/// Each envelope of `edits` has one field that is not the field of the
/// stored plan. The journal refuses each one, records no intent, and then
/// takes the envelope of the plan.
/// A named change of the content of an envelope.
type Edit = (&'static str, Box<dyn Fn(&mut EnvelopeContent)>);

fn refuses_each(plan: &svalnir_core::action::Plan, step: &str, edits: Vec<Edit>) {
    let fixture = Fixture::new();
    let mut journal = fixture.open();
    let operation = admit(&mut journal, plan, "operation_1", "epoch_1");
    for (name, edit) in edits {
        let mut content: EnvelopeContent = envelope_content(plan, &operation, step);
        edit(&mut content);
        let refused = Checked::new(content).unwrap_or_else(|error| {
            panic!("the changed envelope `{name}` is not a valid envelope: {error}")
        });
        assert_eq!(
            journal.commit_intent(&refused),
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

#[test]
fn a_journal_of_an_earlier_version_is_refused_and_not_changed() {
    use super::super::{JOURNAL_VERSION, OperationJournal, OperationJournalError};
    use super::options;

    let fixture = Fixture::new();
    drop(fixture.open());
    // The journal has no migration: a file of an earlier version, which
    // has a different schema, is not opened.
    let raw = rusqlite::Connection::open(fixture.path()).unwrap();
    raw.pragma_update(None, "user_version", JOURNAL_VERSION - 1)
        .unwrap();
    let objects = |raw: &rusqlite::Connection| -> i64 {
        raw.query_row("SELECT count(*) FROM sqlite_schema", [], |row| row.get(0))
            .unwrap()
    };
    let before: i64 = objects(&raw);

    let error = OperationJournal::open(&fixture.path(), &options()).unwrap_err();
    assert!(matches!(
        error,
        OperationJournalError::OlderVersion { found, supported }
            if found == JOURNAL_VERSION - 1 && supported == JOURNAL_VERSION
    ));
    assert_eq!(error.to_journal_error(), JournalError::Unavailable);
    let version: i64 = raw
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(version, i64::from(JOURNAL_VERSION - 1));
    assert_eq!(objects(&raw), before);
}

#[test]
fn the_observations_of_an_operation_are_recorded_and_go_with_it() {
    use svalnir_core::action::ResourceEffect;

    use super::super::coordination::CoordinatorLock;
    use super::super::{CoordinatorRole, OperationJournalError, SequenceViolation};
    use super::{complete, dispatch, epoch, operation_id, wall};

    let fixture = Fixture::new();
    let mut journal = fixture.open();
    let lock = CoordinatorLock::try_acquire(&fixture.path(), CoordinatorRole::Client).unwrap();
    journal
        .begin_coordination(&lock, &epoch("epoch_1"), wall(0))
        .unwrap();
    let plan = file_plan("plan_1", 1);
    let mut operation = admit(&mut journal, &plan, "operation_1", "epoch_1");
    let id = operation.operation_id().clone();
    // No record is not a measurement.
    assert_eq!(journal.resource_effects(&id).unwrap(), Vec::new());
    assert!(matches!(
        journal.record_resource_effects(&operation_id("operation_9"), &[]),
        Err(OperationJournalError::NotFound)
    ));

    // The coordinator tests record real observations. A value that this
    // build does not recognize is sufficient for the storage rules.
    let first = vec![ResourceEffect::Unrecognized];
    journal.record_resource_effects(&id, &first).unwrap();
    assert_eq!(journal.resource_effects(&id).unwrap(), first);
    // The last measurement replaces the record.
    let second = vec![ResourceEffect::Unrecognized, ResourceEffect::Unrecognized];
    journal.record_resource_effects(&id, &second).unwrap();
    assert_eq!(journal.resource_effects(&id).unwrap(), second);
    // A second connection reads the record, as a different client does.
    assert_eq!(fixture.open().resource_effects(&id).unwrap(), second);

    dispatch(&mut journal, &plan, &mut operation, "s0");
    complete(&mut journal, &mut operation, "s0", "t0");
    operation.settle().unwrap();
    journal.record_operation(&operation).unwrap();
    // A coordinator that is not the registered one writes nothing.
    journal.end_coordination(&epoch("epoch_1")).unwrap();
    assert!(matches!(
        journal.record_resource_effects(&id, &first),
        Err(OperationJournalError::Sequence(
            SequenceViolation::ExecutorEpoch
        ))
    ));
    assert_eq!(journal.resource_effects(&id).unwrap(), second);

    // The retention removes the record with its operation.
    let report = journal.prune(wall(1_000_000), 16, &[]).unwrap();
    assert_eq!(report.operations, 1);
    assert_eq!(journal.resource_effects(&id).unwrap(), Vec::new());
    let rows: i64 = rusqlite::Connection::open(fixture.path())
        .unwrap()
        .query_row("SELECT count(*) FROM operation_effect", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(rows, 0);
}

/// A stored plan of a different schema version is refused with its own
/// error before a field of it is read, and a plan of this version reads
/// back unchanged.
#[test]
fn a_stored_plan_of_a_different_schema_version_is_refused_by_its_version() {
    use super::super::OperationJournalError;
    use svalnir_core::action::PLAN_SCHEMA_VERSION;

    let fixture = Fixture::new();
    let mut journal = fixture.open();
    let plan = file_plan("plan_1", 1);
    journal.record_plan(&plan).unwrap();
    assert_eq!(journal.try_plan(&plan.plan_id).unwrap(), Some(plan.clone()));

    for version in [1, 2, PLAN_SCHEMA_VERSION + 1] {
        // A plan of version 1 has no root path and no budget generation:
        // the field is removed, so only the number refuses it.
        journal
            .connection
            .execute(
                "UPDATE plan SET content = json_remove(json_set(content, \
                 '$.content.schema_version', ?1), '$.content.trigger.budget_generation')",
                [version],
            )
            .unwrap();
        assert!(
            matches!(
                journal.try_plan(&plan.plan_id),
                Err(OperationJournalError::PlanVersion { found, supported })
                    if found == version && supported == PLAN_SCHEMA_VERSION
            ),
            "{version}"
        );
        assert_eq!(journal.plan(&plan.plan_id), Err(JournalError::Corrupt));
    }
}
