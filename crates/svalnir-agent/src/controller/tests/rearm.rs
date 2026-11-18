//! The rearm of an incident by the controller (`policy rearm`).

use svalnir_core::authority::Generation;
use svalnir_core::grant::{
    AuthorityState, ControlClock, DisableRequest, InstanceInhibition, Persistence, RearmRequest,
    disable,
};
use svalnir_core::policy::PolicyId;
use svalnir_core::state::PressureState;

use super::super::{ApplyReport, ControllerState, Guard, GuardPhase, OperationResult};
use super::support::{SECOND, memory_grant_revoked, paused, time, user, validated_registry};
use super::{Bench, SAMPLE, critical, guard, two_jobs};
use crate::coordinator::TimeReading;

/// The result of an application plan: the application exited, and the
/// pressure is still critical.
fn finished(plan_id: svalnir_core::id::PlanId) -> ApplyReport {
    ApplyReport::Finished {
        plan_id,
        result: OperationResult {
            state: "Completed".to_owned(),
            completed: true,
            possibly_submitted: true,
            unknown_outcome: false,
            capacity_gain: None,
            pressure_after: Some(PressureState::Critical),
            cooldown_until: None,
        },
    }
}

/// A bench whose memory incident used its one application slot.
fn exhausted() -> Bench {
    let mut bench = Bench::with(
        validated_registry(),
        &[(
            "max_applications_per_incident = 2",
            "max_applications_per_incident = 1",
        )],
    );
    bench.run(20 * SECOND, critical(two_jobs));
    let first = bench.state.outstanding.clone().unwrap();
    assert_eq!(first.application.as_deref(), Some("com.example.alpha"));
    bench.advance(SAMPLE);
    bench.step(&critical(two_jobs)(bench.now), &[finished(first.plan_id)]);
    let output = bench.run(120 * SECOND, critical(two_jobs));
    assert!(bench.state.outstanding.is_none());
    assert_eq!(guard(&output, Guard::Memory).phase, GuardPhase::Exhausted);
    bench
}

/// The rearm request of the open memory incident of `bench`.
fn request(bench: &Bench) -> RearmRequest {
    let record = bench.state.memory_incident.as_ref().unwrap();
    RearmRequest {
        principal: user(),
        policy: PolicyId::MemoryGuard,
        incident_id: record.incident_id.clone(),
        generation: record.budget.generation,
    }
}

/// Rearms the memory incident of `bench` with the authority `authority`.
fn rearm(
    bench: &mut Bench,
    authority: &AuthorityState,
) -> Result<svalnir_core::grant::Rearm, super::super::RearmFailure> {
    let request: RearmRequest = request(bench);
    let reading: TimeReading = time(bench.now);
    let control = ControlClock {
        clock: &reading.clock,
        wall: reading.wall,
    };
    let inhibition: InstanceInhibition = bench.inhibition.clone();
    let epoch = bench.epoch.clone();
    bench
        .state
        .rearm(authority, &inhibition, &request, &control, &epoch)
}

#[test]
fn a_rearm_gives_a_new_generation_and_one_more_application_within_its_ceiling() {
    let mut bench = exhausted();
    let authority: AuthorityState = bench.authority.clone().unwrap();
    let rearmed = rearm(&mut bench, &authority).unwrap();
    assert_eq!(rearmed.previous_generation, Generation::new(1));
    assert_eq!(rearmed.new_generation, Generation::new(2));
    let record = bench.state.memory_incident.clone().unwrap();
    assert_eq!(record.budget.generation, Generation::new(2));
    assert_eq!(record.budget.history.len(), 2);
    // The new generation starts with no usage; the history keeps the
    // usage of the first one.
    assert_eq!(
        bench.state.policy.memory.incident.unwrap().consumed_slots,
        0
    );
    assert_eq!(
        record.budget.history[0].final_usage,
        Some(svalnir_core::grant::IncidentUsage::Memory {
            consumed_slots: 1,
            reserved_slots: 0,
        })
    );
}

#[test]
fn a_repeated_rearm_request_gives_one_generation() {
    let mut bench = exhausted();
    let authority: AuthorityState = bench.authority.clone().unwrap();
    let stale: RearmRequest = request(&bench);
    rearm(&mut bench, &authority).unwrap();
    let reading: TimeReading = time(bench.now);
    let control = ControlClock {
        clock: &reading.clock,
        wall: reading.wall,
    };
    let epoch = bench.epoch.clone();
    let failure = bench
        .state
        .rearm(
            &authority,
            &InstanceInhibition::default(),
            &stale,
            &control,
            &epoch,
        )
        .unwrap_err();
    assert_eq!(failure.code(), "generation_conflict");
    assert_eq!(
        bench
            .state
            .memory_incident
            .as_ref()
            .unwrap()
            .budget
            .generation,
        Generation::new(2)
    );
}

#[test]
fn an_automatic_action_is_possible_again_within_the_new_budget_only() {
    let mut bench = exhausted();
    let authority: AuthorityState = bench.authority.clone().unwrap();
    rearm(&mut bench, &authority).unwrap();
    // One more application, of the new generation.
    bench.run(120 * SECOND, critical(two_jobs));
    // The plan is of the incident and of the new generation. The relaunch
    // cooldown of the first application ended in the time of the test, so
    // the application of the plan is not tested.
    let second = bench.state.outstanding.clone().unwrap();
    let record = bench.state.memory_incident.clone().unwrap();
    assert_eq!(second.incident_id, record.incident_id);
    assert_eq!(record.budget.generation, Generation::new(2));
    // Its result uses the one slot of the new generation: the incident is
    // exhausted again, and no third application is selected.
    bench.advance(SAMPLE);
    bench.step(&critical(two_jobs)(bench.now), &[finished(second.plan_id)]);
    let output = bench.run(300 * SECOND, critical(two_jobs));
    assert!(bench.state.outstanding.is_none());
    assert_eq!(guard(&output, Guard::Memory).phase, GuardPhase::Exhausted);
    let incident = guard(&output, Guard::Memory).incidents[0].clone();
    assert_eq!(incident.slots_remaining, Some(0));
    assert_eq!(incident.slots_used, Some(1));
}

#[test]
fn a_rearm_of_a_disabled_revoked_or_paused_guard_leaves_the_generation_unchanged() {
    let bench = exhausted();
    let active: AuthorityState = bench.authority.clone().unwrap();
    let none = InstanceInhibition::default();
    let disabled: AuthorityState = disable(
        &active,
        &DisableRequest {
            principal: user(),
            policy: PolicyId::MemoryGuard,
        },
    )
    .unwrap()
    .acknowledge(&none, Persistence::Durable)
    .state;
    let cases: [(AuthorityState, &str); 3] = [
        (disabled, "guard_disabled"),
        (memory_grant_revoked(&active), "action_grant_revoked"),
        (paused(&active, bench.now), "automation_paused"),
    ];
    for (authority, code) in cases {
        let mut bench = exhausted();
        let before: ControllerState = bench.state.clone();
        let failure = rearm(&mut bench, &authority).unwrap_err();
        assert_eq!(failure.code(), code);
        assert_eq!(
            failure.family(),
            svalnir_core::action::ErrorFamily::Authority
        );
        assert_eq!(bench.state, before, "{code}");
        assert_eq!(
            bench
                .state
                .memory_incident
                .as_ref()
                .unwrap()
                .budget
                .generation,
            Generation::new(1)
        );
    }
}

#[test]
fn a_restart_restores_the_rearmed_generation_from_the_durable_record() {
    let mut bench = exhausted();
    let authority: AuthorityState = bench.authority.clone().unwrap();
    rearm(&mut bench, &authority).unwrap();
    // The record that the journal has, read by the next lifetime.
    let stored: ControllerState = bench.state.durable_view();
    let restored = ControllerState::restore(super::super::PriorState::Recorded(Box::new(stored)));
    let record = restored.memory_incident.clone().unwrap();
    assert_eq!(record.budget.generation, Generation::new(2));
    assert_eq!(record.budget.history.len(), 2);
    assert_eq!(restored.policy.memory.incident.unwrap().consumed_slots, 0);
}
