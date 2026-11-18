//! A rearm request of the queue reaches the controller of the agent.

use svalnir_core::authority::Generation;
use svalnir_core::grant::AuthorityState;
use svalnir_core::id::{IncidentId, RequestId};
use svalnir_core::policy::PolicyId;
use svalnir_core::state::PressureState;

use super::{
    Bench, GIBIBYTE, SAMPLE, TestClock, TestIdle, journal_path, paused, user, validated_registry,
    wall,
};
use crate::journal::{
    AgentRecord, JournalOptions, OperationJournal, QueuedRequest, RequestBody, RequestCompletion,
    RequestStatus,
};

fn rearm_request(
    id: &str,
    incident_id: &IncidentId,
    generation: Generation,
    now: u64,
) -> QueuedRequest {
    QueuedRequest {
        request_id: RequestId::new(id).unwrap(),
        principal: svalnir_core::action::Principal {
            uid: user(),
            session: None,
            role: svalnir_core::action::ClientRole::Cli,
        },
        body: RequestBody::Rearm {
            policy: PolicyId::MemoryGuard,
            incident_id: incident_id.clone(),
            generation,
        },
        enqueued_at: wall(now),
    }
}

fn completion(bench: &Bench, id: &str) -> RequestCompletion {
    match bench
        .journal()
        .request_status(&RequestId::new(id).unwrap())
        .unwrap()
    {
        Some(RequestStatus::Completed { completion }) => completion,
        other => panic!("the request is not complete: {other:?}"),
    }
}

#[test]
fn a_queued_rearm_gives_a_new_generation_and_a_refused_one_changes_nothing() {
    let mut bench = Bench::new(TestClock::fixed(), validated_registry());
    let active: AuthorityState = bench.seed_authority();
    let mut driver = bench.start();
    // Sustained critical pressure opens a memory incident. No application
    // is a candidate, so the controller makes no plan.
    for _ in 0..40 {
        driver.tick(Some(bench.sample(
            100 * GIBIBYTE,
            PressureState::Critical,
            Vec::new(),
        )));
        if driver.controller_state().memory_incident.is_some() {
            break;
        }
        bench.clock.advance(SAMPLE);
    }
    let record = driver
        .controller_state()
        .memory_incident
        .clone()
        .expect("a memory incident opened");
    assert_eq!(record.budget.generation, Generation::new(1));

    // A client queues a rearm of the current generation.
    bench
        .journal()
        .enqueue_request(&rearm_request(
            "request-rearm-1",
            &record.incident_id,
            Generation::new(1),
            bench.clock.now(),
        ))
        .unwrap();
    bench.clock.advance(SAMPLE);
    driver.tick(Some(bench.sample(
        100 * GIBIBYTE,
        PressureState::Critical,
        Vec::new(),
    )));
    assert_eq!(
        completion(&bench, "request-rearm-1"),
        RequestCompletion::Rearmed {
            incident_id: record.incident_id.clone(),
            previous_generation: Generation::new(1),
            new_generation: Generation::new(2),
        }
    );
    let generation = |state: &crate::controller::ControllerState| {
        state.memory_incident.as_ref().unwrap().budget.generation
    };
    assert_eq!(generation(driver.controller_state()), Generation::new(2));
    // The controller record of the journal has the new generation.
    assert_eq!(generation(&bench.controller_record()), Generation::new(2));

    // A pause is in effect: the next rearm is refused, and the generation
    // does not change.
    bench.write_authority(&paused(&active, bench.clock.now()));
    bench
        .journal()
        .enqueue_request(&rearm_request(
            "request-rearm-2",
            &record.incident_id,
            Generation::new(2),
            bench.clock.now(),
        ))
        .unwrap();
    bench.clock.advance(SAMPLE);
    driver.tick(Some(bench.sample(
        100 * GIBIBYTE,
        PressureState::Critical,
        Vec::new(),
    )));
    match completion(&bench, "request-rearm-2") {
        RequestCompletion::Rejected { error } => {
            assert_eq!(error.code.as_str(), "automation_paused");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(generation(driver.controller_state()), Generation::new(2));
    assert_eq!(generation(&bench.controller_record()), Generation::new(2));
    assert!(driver.shutdown(&mut TestIdle(bench.clock.clone())).clean);
}

#[test]
fn a_pause_that_the_journal_has_before_the_claim_of_a_rearm_refuses_it() {
    let mut bench = Bench::new(TestClock::fixed(), validated_registry());
    let active: AuthorityState = bench.seed_authority();
    let mut driver = bench.start();
    for _ in 0..40 {
        driver.tick(Some(bench.sample(
            100 * GIBIBYTE,
            PressureState::Critical,
            Vec::new(),
        )));
        if driver.controller_state().memory_incident.is_some() {
            break;
        }
        bench.clock.advance(SAMPLE);
    }
    let record = driver
        .controller_state()
        .memory_incident
        .clone()
        .expect("a memory incident opened");
    bench
        .journal()
        .enqueue_request(&rearm_request(
            "request-rearm-1",
            &record.incident_id,
            Generation::new(1),
            bench.clock.now(),
        ))
        .unwrap();
    // A client pauses the agent after the tick read the authority record
    // and before the coordinator claims the rearm request.
    let pause: AuthorityState = paused(&active, bench.clock.now());
    let path = journal_path(&bench.state);
    let at = wall(bench.clock.now());
    bench.footprint_hook.set(move || {
        let options = JournalOptions {
            full_fsync: false,
            ..JournalOptions::default()
        };
        OperationJournal::open(&path, &options)
            .unwrap()
            .put_agent_record(AgentRecord::Authority, &pause, None, at)
            .unwrap();
    });
    bench.clock.advance(SAMPLE);
    driver.tick(Some(bench.sample(
        100 * GIBIBYTE,
        PressureState::Critical,
        Vec::new(),
    )));
    match completion(&bench, "request-rearm-1") {
        RequestCompletion::Rejected { error } => {
            assert_eq!(error.code.as_str(), "automation_paused");
        }
        other => panic!("{other:?}"),
    }
    let generation = driver
        .controller_state()
        .memory_incident
        .as_ref()
        .unwrap()
        .budget
        .generation;
    assert_eq!(generation, Generation::new(1));
    assert!(driver.shutdown(&mut TestIdle(bench.clock.clone())).clean);
}
