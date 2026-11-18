//! A journal that a different process holds locked when the controller
//! records its state before an automatic admission.

use std::time::{Duration, Instant};

use svalnir_core::state::PressureState;

use super::{
    Bench, SAMPLE, SECOND, TestClock, TestIdle, child_identity, child_sample, config_text,
    journal_path, spawn_child, validated_registry,
};
use crate::coordinator::code;

/// A lock of the journal is a refusal of the attempt, and not a storage
/// failure: no operation, no signal, no volatile record, no pacing wait,
/// and the journal is not reported as unavailable. `exception` is true
/// when the configuration and the grant permit the critical-memory
/// exception.
fn a_locked_journal_refuses_the_plan_and_the_next_evaluation_plans_again(exception: bool) {
    let mut bench = Bench::new(TestClock::host(), validated_registry());
    if exception {
        bench.text = config_text(&[(
            "allow_volatile_journal_on_critical = false",
            "allow_volatile_journal_on_critical = true",
        )]);
    }
    bench.busy_timeout = Some(Duration::from_millis(50));
    bench.seed_authority();
    let mut child = spawn_child(false);
    let member = child_identity(child.pid());
    let mut driver = bench.start();

    // A second connection holds the write lock for the time of each tick,
    // until the controller has a plan.
    let mut planned: bool = false;
    for _ in 0..40 {
        let other = rusqlite::Connection::open(journal_path(&bench.state)).unwrap();
        other.execute_batch("BEGIN IMMEDIATE").unwrap();
        driver.tick(Some(child_sample(&bench, &member)));
        other.execute_batch("ROLLBACK").unwrap();
        drop(other);
        if driver.controller_state().outstanding.is_some() {
            planned = true;
            break;
        }
        bench.clock.advance(SAMPLE);
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(
        planned,
        "{exception}: no plan: {:?}",
        driver.controller_status()
    );
    let outstanding = driver.controller_state().outstanding.clone().unwrap();
    assert_eq!(outstanding.operation_id, None, "{exception}");
    assert!(child.0.try_wait().unwrap().is_none(), "{exception}");
    assert_eq!(bench.journal().unsettled_operation_count().unwrap(), 0);

    // The lock is released. The next evaluation reads the refusal and
    // plans again at once.
    bench.clock.advance(SAMPLE);
    driver.tick(Some(child_sample(&bench, &member)));
    let status = driver.controller_status().unwrap();
    assert!(
        !status
            .degraded
            .iter()
            .any(|reason| reason == "journal_unavailable"),
        "{exception}: {status:?}"
    );
    let incident = driver.controller_state().memory_incident.clone().unwrap();
    assert_eq!(
        incident.last_refusal.as_deref(),
        Some(code::ADMISSION_NOT_RECORDED),
        "{exception}"
    );
    assert_eq!(incident.refusals, 0, "{exception}");
    let admitted = driver
        .controller_state()
        .outstanding
        .as_ref()
        .and_then(|outstanding| outstanding.operation_id.clone());
    assert!(admitted.is_some(), "{exception}: {status:?}");

    // The operation ends the child of the test.
    let limit: Instant = Instant::now() + Duration::from_secs(20);
    while child.0.try_wait().unwrap().is_none() {
        assert!(Instant::now() < limit, "the child did not end");
        std::thread::sleep(Duration::from_millis(20));
        bench.clock.advance(SECOND / 100);
        driver.tick(None);
    }
    while driver.controller_state().outstanding.is_some() {
        assert!(Instant::now() < limit, "the operation did not finish");
        bench.clock.advance(SECOND);
        std::thread::sleep(Duration::from_millis(20));
        *bench.pressure.lock().unwrap() = PressureState::Normal;
        driver.tick(None);
    }
    assert!(driver.shutdown(&mut TestIdle(bench.clock.clone())).clean);
}

#[test]
fn a_locked_journal_is_a_refusal_with_no_pacing_wait() {
    a_locked_journal_refuses_the_plan_and_the_next_evaluation_plans_again(false);
}

#[test]
fn a_locked_journal_does_not_start_the_critical_memory_exception() {
    a_locked_journal_refuses_the_plan_and_the_next_evaluation_plans_again(true);
}
