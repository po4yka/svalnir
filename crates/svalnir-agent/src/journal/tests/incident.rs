//! The usage row of an incident: the charge at the dispatch consumption,
//! the read after a restart, and the retention.

use svalnir_core::action::{
    ClientRole, DispatchState, Durability, Escalation, Journal as _, Operation, Plan, PlanContent,
    Principal, StepState, TargetEffect, Trigger, TriggerClass,
};
use svalnir_core::authority::{ActionGrantRef, AuthorityBinding, Generation};
use svalnir_core::id::{ActionGrantId, DecisionId, IncidentId};

use super::super::{IncidentUsage, OperationJournal};
use super::{
    Fixture, admit, application_plan, charge, complete, dispatch, file_content, incident,
    principal, result, step_id, wall,
};

/// An automatic eviction plan of the incident `incident_1` with `count`
/// targets.
fn disk_plan(plan: &str, count: u64) -> Plan {
    let base: PlanContent = file_content(plan, count);
    Plan::seal(PlanContent {
        principal: Principal {
            role: ClientRole::Agent,
            ..principal()
        },
        trigger: Trigger {
            class: TriggerClass::DiskPressure,
            incident_id: Some(incident()),
            decision_id: Some(DecisionId::new("decision_1").unwrap()),
        },
        authority: AuthorityBinding {
            action_grants: vec![ActionGrantRef {
                grant_id: ActionGrantId::new("grant_1").unwrap(),
                generation: Generation::new(1),
            }],
            ..base.authority.clone()
        },
        ..base
    })
    .unwrap()
}

/// Dispatches and completes each step of a disk plan, and settles the
/// operation.
fn run_disk_plan(journal: &mut OperationJournal, plan: &Plan, id: &str) -> Operation {
    let mut operation: Operation = admit(journal, plan, id, "epoch_1");
    for (index, planned) in plan.steps.clone().iter().enumerate() {
        dispatch(journal, plan, &mut operation, planned.step_id.as_str());
        complete(
            journal,
            &mut operation,
            planned.step_id.as_str(),
            &format!("t{index}"),
        );
    }
    operation.settle().unwrap();
    journal.record_operation(&operation).unwrap();
    operation
}

#[test]
fn the_consumption_of_a_dispatch_charges_the_incident_and_a_restart_reads_it() {
    let fixture = Fixture::new();
    let mut journal = fixture.open();
    assert_eq!(journal.incident_usage(&incident()).unwrap(), None);
    let plan = disk_plan("plan_1", 2);
    let mut operation = admit(&mut journal, &plan, "operation_1", "epoch_1");
    // The consumption of the first step charges its work.
    dispatch(&mut journal, &plan, &mut operation, "s0");
    assert_eq!(
        journal.incident_usage(&incident()).unwrap(),
        Some(IncidentUsage {
            slots: 0,
            work: charge(10, 1),
        })
    );
    dispatch(&mut journal, &plan, &mut operation, "s1");
    // A repeated consumption is not a second charge.
    journal
        .consume_dispatch(operation.operation_id(), &step_id("s1"))
        .unwrap();

    // A new handle on the same file, as after a restart, reads the usage.
    drop(journal);
    let journal: OperationJournal = fixture.open();
    assert_eq!(
        journal.incident_usage(&incident()).unwrap(),
        Some(IncidentUsage {
            slots: 0,
            work: charge(20, 2),
        })
    );
    let other = IncidentId::new("incident_2").unwrap();
    assert_eq!(journal.incident_usage(&other).unwrap(), None);
    // A manual operation has no incident and charges none.
    let mut journal = journal;
    let manual = super::file_plan("plan_manual", 1);
    let mut manual_operation = admit(&mut journal, &manual, "operation_manual", "epoch_1");
    dispatch(&mut journal, &manual, &mut manual_operation, "s0");
    assert_eq!(
        journal.incident_usage(&incident()).unwrap(),
        Some(IncidentUsage {
            slots: 0,
            work: charge(20, 2),
        })
    );
}

#[test]
fn a_graceful_step_and_its_force_step_use_one_slot() {
    let fixture = Fixture::new();
    let mut journal = fixture.open();
    let plan = application_plan(
        "plan_1",
        TriggerClass::ApplicationBudget,
        Escalation::ForceAfterGrace,
    );
    let mut operation = admit(&mut journal, &plan, "operation_1", "epoch_1");
    let graceful = step_id("graceful");
    dispatch(&mut journal, &plan, &mut operation, "graceful");
    operation
        .advance_step(
            &graceful,
            StepState::Verifying,
            DispatchState::Submitted,
            Durability::Durable,
        )
        .unwrap();
    journal
        .record_step(operation.operation_id(), operation.step(&graceful).unwrap())
        .unwrap();
    operation
        .settle_step(
            &graceful,
            vec![result(
                "app",
                TargetEffect::StillRunning,
                Durability::Durable,
            )],
            Durability::Durable,
        )
        .unwrap();
    journal
        .record_step(operation.operation_id(), operation.step(&graceful).unwrap())
        .unwrap();
    assert_eq!(
        journal.incident_usage(&incident()).unwrap().unwrap().slots,
        1
    );
    dispatch(&mut journal, &plan, &mut operation, "force");
    assert_eq!(
        journal.incident_usage(&incident()).unwrap(),
        Some(IncidentUsage {
            slots: 1,
            work: charge(0, 0),
        })
    );

    // A second operation of the incident uses a second slot.
    let second = application_plan("plan_2", TriggerClass::ApplicationBudget, Escalation::None);
    let mut second_operation = admit(&mut journal, &second, "operation_2", "epoch_1");
    dispatch(&mut journal, &second, &mut second_operation, "graceful");
    assert_eq!(
        journal.incident_usage(&incident()).unwrap().unwrap().slots,
        2
    );
}

#[test]
fn a_prune_keeps_the_usage_of_an_open_incident_and_removes_that_of_a_closed_one() {
    let fixture = Fixture::new();
    let mut journal = fixture.open();
    let plan = disk_plan("plan_1", 1);
    let operation = run_disk_plan(&mut journal, &plan, "operation_1");
    let used = Some(IncidentUsage {
        slots: 0,
        work: charge(10, 1),
    });

    // The prune removes the settled operation of the open incident, and
    // the budget of the incident stays.
    let report = journal.prune(wall(100), 16, &[incident()]).unwrap();
    assert_eq!((report.operations, report.incident_usage), (1, 0));
    assert_eq!(journal.operation(operation.operation_id()), Ok(None));
    assert_eq!(journal.incident_usage(&incident()).unwrap(), used);
    // After a restart the usage is the same, with no operation of the
    // incident in the journal.
    drop(journal);
    let mut journal: OperationJournal = fixture.open();
    assert_eq!(journal.incident_usage(&incident()).unwrap(), used);

    // A cutoff before the latest admission of the incident keeps the row
    // of a closed incident.
    assert_eq!(journal.prune(wall(0), 16, &[]).unwrap().incident_usage, 0);
    assert_eq!(journal.incident_usage(&incident()).unwrap(), used);
    // The row of a closed incident goes after the cutoff.
    assert_eq!(journal.prune(wall(100), 16, &[]).unwrap().incident_usage, 1);
    assert_eq!(journal.incident_usage(&incident()).unwrap(), None);
}
