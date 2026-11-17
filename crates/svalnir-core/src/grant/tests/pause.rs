//! Tests of pause and resume.

use super::super::{
    AcknowledgementLevel, AuthorityState, InstanceInhibition, MeasurementFloor, Pause, PauseBasis,
    PauseRefusal, PauseRequest, PauseStatus, Persistence, ResumeRefusal, ResumeRequest, pause,
    pause_status, resume,
};
use super::{SECOND, USER, clock, clock_in, control, durable, enabled_state, monotonic, wall};
use crate::process::Uid;
use crate::quantity::Nanoseconds;
use crate::time::MonotonicNanos;

const HOUR: u64 = 3_600;

fn pause_for(seconds: Option<u64>) -> PauseRequest {
    PauseRequest {
        principal: USER,
        duration: seconds.map(|seconds| Nanoseconds::new(seconds * SECOND)),
    }
}

fn resume_request() -> ResumeRequest {
    ResumeRequest { principal: USER }
}

/// A record that was paused for one hour at second 100.
fn paused_for_an_hour() -> AuthorityState {
    let state = enabled_state();
    let at = clock(100);
    durable(pause(&state, &pause_for(Some(HOUR)), &control(&at, 100)).unwrap()).state
}

fn status_at(state: &AuthorityState, seconds: u64) -> PauseStatus {
    let at = clock(seconds);
    pause_status(state.pause.as_ref(), &control(&at, seconds))
}

#[test]
fn a_timed_pause_records_its_expiry_on_the_two_clocks() {
    let state = enabled_state();
    let at = clock(100);
    let change = pause(&state, &pause_for(Some(HOUR)), &control(&at, 100)).unwrap();
    assert!(change.is_restriction());
    assert!(change.needs_persistence());
    assert_eq!(change.report.replaced, None);
    let acknowledged = durable(change);
    assert_eq!(acknowledged.level, AcknowledgementLevel::DurablyApplied);
    let recorded: &Pause = acknowledged.state.pause.as_ref().unwrap();
    assert_eq!(recorded.started_wall, wall(100));
    let deadline = recorded.deadline.as_ref().unwrap();
    assert_eq!(deadline.monotonic, monotonic(100 + HOUR));
    assert_eq!(deadline.wall, wall(100 + HOUR));
    assert_eq!(deadline.boot_id, at.boot_id);
    assert_eq!(deadline.clock_domain, at.clock_domain);
    // The pause changes no grant and no guard.
    assert_eq!(acknowledged.state.guards, state.guards);
    assert_eq!(acknowledged.state.active, state.active);
}

#[test]
fn a_timed_pause_ends_at_its_expiry() {
    let state = paused_for_an_hour();
    assert_eq!(
        status_at(&state, 100),
        PauseStatus::Paused {
            remaining: Some(Nanoseconds::new(HOUR * SECOND)),
            until: Some(wall(100 + HOUR)),
            basis: PauseBasis::Monotonic,
        }
    );
    // One nanosecond before the expiry.
    let before = super::EvaluationClock {
        now: MonotonicNanos::new((100 + HOUR) * SECOND - 1),
        ..clock(0)
    };
    let status = pause_status(state.pause.as_ref(), &control(&before, 100 + HOUR));
    assert_eq!(
        status,
        PauseStatus::Paused {
            remaining: Some(Nanoseconds::new(1)),
            until: Some(wall(100 + HOUR)),
            basis: PauseBasis::Monotonic,
        }
    );
    assert!(status.is_paused());
    // At the expiry and after it.
    for seconds in [100 + HOUR, 100 + HOUR + 1, 100 + 10 * HOUR] {
        let status = status_at(&state, seconds);
        assert_eq!(
            status,
            PauseStatus::Expired {
                floor: Some(monotonic(100 + HOUR)),
                basis: PauseBasis::Monotonic,
            }
        );
        assert!(!status.is_paused());
    }
}

#[test]
fn the_wall_clock_does_not_end_a_pause_of_the_same_boot() {
    let state = paused_for_an_hour();
    // The wall clock jumps one day; the monotonic time is at second 200.
    let at = clock(200);
    let status = pause_status(state.pause.as_ref(), &control(&at, 100 + 24 * HOUR));
    assert!(status.is_paused());
    // The wall clock goes back; the monotonic time is after the expiry.
    let at = clock(100 + HOUR);
    let status = pause_status(state.pause.as_ref(), &control(&at, 0));
    assert!(!status.is_paused());
}

#[test]
fn a_pause_survives_a_restart_and_then_ends_on_the_wall_clock() {
    let state = paused_for_an_hour();
    // The record is what a client reads after a restart.
    let json = serde_json::to_string(&state).unwrap();
    let restored: AuthorityState = serde_json::from_str(&json).unwrap();
    assert_eq!(restored, state);

    // A new boot: the monotonic time starts again, so it cannot show that
    // the pause ended. The wall clock is 10 minutes after the request.
    let rebooted = clock_in("boot_2", 5);
    let status = pause_status(restored.pause.as_ref(), &control(&rebooted, 100 + 600));
    assert_eq!(
        status,
        PauseStatus::Paused {
            remaining: Some(Nanoseconds::new((HOUR - 600) * SECOND)),
            until: Some(wall(100 + HOUR)),
            basis: PauseBasis::WallClock,
        }
    );
    // A monotonic time after the recorded expiry has no meaning in the new
    // boot.
    let late = clock_in("boot_2", 100 + 2 * HOUR);
    assert!(pause_status(restored.pause.as_ref(), &control(&late, 100 + 600)).is_paused());
    // The wall clock is at the recorded expiry: the pause ends now, at
    // second 5 of the new boot.
    assert_eq!(
        pause_status(restored.pause.as_ref(), &control(&rebooted, 100 + HOUR)),
        PauseStatus::Expired {
            floor: Some(monotonic(5)),
            basis: PauseBasis::WallClock,
        }
    );
    // Two seconds after the expiry, the pause ended at second 3.
    assert_eq!(
        pause_status(restored.pause.as_ref(), &control(&rebooted, 102 + HOUR)),
        PauseStatus::Expired {
            floor: Some(monotonic(3)),
            basis: PauseBasis::WallClock,
        }
    );
    // The pause ended before the new boot started.
    assert_eq!(
        pause_status(restored.pause.as_ref(), &control(&rebooted, 200 + HOUR)),
        PauseStatus::Expired {
            floor: None,
            basis: PauseBasis::WallClock,
        }
    );
}

#[test]
fn the_longer_of_two_volatile_pauses_is_decided_on_the_monotonic_timeline() {
    let state = enabled_state();
    let none = InstanceInhibition::default();
    // Two hours from second 0, with the wall clock at second 0.
    let first_clock = clock(0);
    let first = pause(
        &state,
        &pause_for(Some(2 * HOUR)),
        &control(&first_clock, 0),
    )
    .unwrap()
    .acknowledge(&none, Persistence::Failed);
    // The wall clock goes three hours forward. Ten minutes from second 60.
    let second_clock = clock(60);
    let second = pause(
        &state,
        &pause_for(Some(600)),
        &control(&second_clock, 3 * HOUR + 60),
    )
    .unwrap()
    .acknowledge(&first.inhibition, Persistence::Failed);
    // The first pause ends later on the monotonic timeline, so it stays.
    assert_eq!(second.inhibition.pause, first.inhibition.pause);
    assert_eq!(
        second.inhibition.pause.unwrap().deadline.unwrap().monotonic,
        monotonic(2 * HOUR)
    );
}

#[test]
fn a_pause_with_no_expiry_stays_until_a_resume() {
    let state = enabled_state();
    let at = clock(100);
    let paused = durable(pause(&state, &pause_for(None), &control(&at, 100)).unwrap()).state;
    let indefinite = PauseStatus::Paused {
        remaining: None,
        until: None,
        basis: PauseBasis::Indefinite,
    };
    assert_eq!(status_at(&paused, 100), indefinite);
    assert_eq!(status_at(&paused, 100 + 1_000 * HOUR), indefinite);
    let rebooted = clock_in("boot_2", 1);
    assert_eq!(
        pause_status(
            paused.pause.as_ref(),
            &control(&rebooted, 100 + 1_000 * HOUR)
        ),
        indefinite
    );
    assert_eq!(status_at(&state, 100), PauseStatus::NotPaused);
}

#[test]
fn a_pause_request_is_checked() {
    let state = enabled_state();
    let at = clock(100);
    let now = control(&at, 100);
    assert_eq!(
        pause(&state, &pause_for(Some(0)), &now).unwrap_err(),
        PauseRefusal::ZeroDuration
    );
    let other = PauseRequest {
        principal: Uid::new(502),
        duration: None,
    };
    assert_eq!(
        pause(&state, &other, &now).unwrap_err(),
        PauseRefusal::WrongPrincipal
    );
    let endless = PauseRequest {
        principal: USER,
        duration: Some(Nanoseconds::MAX),
    };
    assert_eq!(
        pause(&state, &endless, &now).unwrap_err(),
        PauseRefusal::DeadlineOutOfRange
    );
    // A new pause replaces the earlier one.
    let paused = paused_for_an_hour();
    let later = clock(200);
    let change = pause(&paused, &pause_for(Some(60)), &control(&later, 200)).unwrap();
    assert_eq!(change.report.replaced, paused.pause);
    assert_eq!(
        change.next.pause.unwrap().deadline.unwrap().monotonic,
        monotonic(260)
    );
}

#[test]
fn a_pause_that_is_not_persisted_inhibits_the_running_instance_only() {
    let state = enabled_state();
    let at = clock(100);
    let change = pause(&state, &pause_for(Some(HOUR)), &control(&at, 100)).unwrap();
    let requested: Pause = change.report.pause.clone();
    // The pause applies before the write.
    let now = change.inhibit_now(&InstanceInhibition::default());
    assert_eq!(now.pause.as_ref(), Some(&requested));
    let acknowledged = change.acknowledge(&now, Persistence::Failed);
    assert_eq!(
        acknowledged.level,
        AcknowledgementLevel::CurrentInstanceInhibition
    );
    // The durable record has no pause: a restart loses it.
    assert_eq!(acknowledged.state, state);
    assert_eq!(acknowledged.state.pause, None);
    assert_eq!(acknowledged.inhibition.pause.as_ref(), Some(&requested));
    let later = clock(200);
    assert!(
        pause_status(
            acknowledged.inhibition.pause.as_ref(),
            &control(&later, 200)
        )
        .is_paused()
    );

    // A shorter pause that is not persisted does not shorten the volatile
    // pause.
    let shorter = pause(&state, &pause_for(Some(60)), &control(&later, 200))
        .unwrap()
        .acknowledge(&acknowledged.inhibition, Persistence::Failed);
    assert_eq!(shorter.inhibition.pause.as_ref(), Some(&requested));
    // A pause with no expiry is the longer one.
    let endless = pause(&state, &pause_for(None), &control(&later, 200))
        .unwrap()
        .acknowledge(&acknowledged.inhibition, Persistence::Failed);
    assert_eq!(endless.inhibition.pause.unwrap().deadline, None);

    // A durable pause is the latest request: the volatile pause goes.
    let durable = pause(&state, &pause_for(Some(60)), &control(&later, 200))
        .unwrap()
        .acknowledge(&acknowledged.inhibition, Persistence::Durable);
    assert_eq!(durable.level, AcknowledgementLevel::DurablyApplied);
    assert_eq!(durable.inhibition.pause, None);
    assert!(durable.state.pause.is_some());
}

#[test]
fn a_resume_removes_the_pause_and_requires_a_fresh_measurement() {
    let state = paused_for_an_hour();
    let at = clock(500);
    let none = InstanceInhibition::default();
    let change = resume(&state, &none, &resume_request(), &control(&at, 500)).unwrap();
    assert!(!change.is_restriction());
    assert!(change.needs_persistence());
    let report = change.report.clone();
    assert!(report.requires_fresh_measurement);
    assert_eq!(report.durable_pause, state.pause);
    assert_eq!(report.volatile_pause, None);
    let floor = MeasurementFloor {
        at: monotonic(500),
        clock_domain: at.clock_domain.clone(),
        boot_id: at.boot_id.clone(),
    };
    assert_eq!(report.measurement_floor, floor);

    let acknowledged = change.acknowledge(&none, Persistence::Durable);
    assert_eq!(acknowledged.level, AcknowledgementLevel::DurablyApplied);
    assert_eq!(acknowledged.state.pause, None);
    assert_eq!(acknowledged.inhibition.measurement_floor, Some(floor));
    assert_eq!(status_at(&acknowledged.state, 500), PauseStatus::NotPaused);
    // The resume changes no grant.
    assert_eq!(acknowledged.state.guards, state.guards);
}

#[test]
fn a_resume_that_is_not_persisted_leaves_the_durable_pause() {
    let state = paused_for_an_hour();
    let at = clock(500);
    let none = InstanceInhibition::default();
    let change = resume(&state, &none, &resume_request(), &control(&at, 500)).unwrap();
    let acknowledged = change.acknowledge(&none, Persistence::Failed);
    assert_eq!(acknowledged.level, AcknowledgementLevel::NotApplied);
    assert_eq!(acknowledged.state, state);
    assert_eq!(acknowledged.inhibition, none);
    assert!(status_at(&acknowledged.state, 500).is_paused());
}

#[test]
fn a_resume_removes_a_pause_that_only_the_instance_has() {
    let state = enabled_state();
    let at = clock(100);
    let failed = pause(&state, &pause_for(None), &control(&at, 100))
        .unwrap()
        .acknowledge(&InstanceInhibition::default(), Persistence::Failed);
    assert!(failed.inhibition.pause.is_some());
    let later = clock(200);
    let change = resume(
        &failed.state,
        &failed.inhibition,
        &resume_request(),
        &control(&later, 200),
    )
    .unwrap();
    // The durable record has no pause, so there is nothing to write, and a
    // store that does not work cannot keep the instance paused.
    assert!(!change.needs_persistence());
    assert_eq!(change.report.volatile_pause, failed.inhibition.pause);
    let acknowledged = change.acknowledge(&failed.inhibition, Persistence::Failed);
    assert_eq!(acknowledged.level, AcknowledgementLevel::DurablyApplied);
    assert_eq!(acknowledged.inhibition.pause, None);
    assert_eq!(
        acknowledged.inhibition.measurement_floor.unwrap().at,
        monotonic(200)
    );
}

#[test]
fn a_resume_is_refused_for_another_user() {
    let state = paused_for_an_hour();
    let at = clock(500);
    let request = ResumeRequest {
        principal: Uid::new(502),
    };
    assert_eq!(
        resume(
            &state,
            &InstanceInhibition::default(),
            &request,
            &control(&at, 500)
        )
        .unwrap_err(),
        ResumeRefusal::WrongPrincipal
    );
}
