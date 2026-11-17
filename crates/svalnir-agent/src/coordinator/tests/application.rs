//! Application stops with the synthetic process host: the graceful exit,
//! the force escalation, the target that is gone, and the wait that does
//! not block a query.

use std::time::Duration;

use svalnir_core::action::{
    DispatchState, Escalation, OperationState, ResourceEffect, StepState, StopReason, TargetEffect,
};
use svalnir_core::time::MonotonicNanos;

use super::super::{Phase, StopAcknowledgement, WaitOutcome};
use super::support::{
    Bench, GRACE, NativeCall, SECOND, START, admitted, run, stop_plan, stored_request,
};
use crate::executor::process::{GracefulSignal, ProcessSignal};

fn term(process: i32) -> NativeCall {
    NativeCall::Signal(process, ProcessSignal::Graceful(GracefulSignal::default()))
}

fn kill(process: i32) -> NativeCall {
    NativeCall::Signal(process, ProcessSignal::Kill)
}

#[test]
fn a_graceful_request_completes_only_after_the_exit_is_observed() {
    let mut bench = Bench::new();
    let member = bench.host.spawn(4242);
    bench.measurements.0.lock().unwrap().pressure = ["critical", "warning"].into();
    let plan = stop_plan("plan_1", vec![member], Escalation::None, bench.clock.now());
    bench.store(&plan);
    let mut coordinator = bench.start();
    let operation_id = admitted(&mut coordinator, stored_request(&plan));

    // The request is submitted, and the process runs: the step waits for
    // the observation. A submitted request is not a verified exit.
    let progress = coordinator.step();
    assert_eq!(bench.host.calls(), vec![term(4242)]);
    let view = coordinator.operation(&operation_id).unwrap().unwrap();
    assert!(matches!(view.phase, Phase::Observing { .. }));
    assert_eq!(view.operation.state(), &OperationState::Admitted);
    assert_eq!(
        view.operation.steps()[0].progress().state(),
        &StepState::Verifying
    );
    assert_eq!(view.operation.steps()[0].results().len(), 0);
    assert!(progress.wake_at.is_some());

    // The process exits later.
    bench.clock.advance(2 * SECOND);
    bench.host.world().processes.remove(&4242);
    let view = run(&mut coordinator, &bench.clock, &operation_id);
    assert_eq!(view.operation.state(), &OperationState::Completed);
    let result = &view.operation.steps()[0].results()[0];
    assert_eq!(result.effect, TargetEffect::ExitVerified);
    assert_eq!(result.dispatch, DispatchState::Submitted);
    // The pressure before and after is an observation of the host.
    let [ResourceEffect::MemoryPressure { before, after }] = view.resource_effects.as_slice()
    else {
        panic!("the operation has no pressure effect");
    };
    assert_ne!(before.value(), after.value());
}

#[test]
fn a_force_step_follows_the_grace_period_when_the_target_runs() {
    let mut bench = Bench::new();
    let member = bench.host.spawn(4242);
    let plan = stop_plan(
        "plan_1",
        vec![member],
        Escalation::ForceAfterGrace,
        bench.clock.now(),
    );
    bench.store(&plan);
    let mut coordinator = bench.start();
    let operation_id = admitted(&mut coordinator, stored_request(&plan));
    coordinator.step();
    assert_eq!(bench.host.calls(), vec![term(4242)]);
    // No force call before the end of the grace period.
    bench.clock.set(START + GRACE - SECOND);
    for _ in 0..5 {
        coordinator.step();
    }
    assert_eq!(bench.host.calls(), vec![term(4242)]);
    let view = run(&mut coordinator, &bench.clock, &operation_id);
    assert_eq!(bench.host.calls(), vec![term(4242), kill(4242)]);
    assert!(bench.clock.now() >= START + GRACE);
    assert_eq!(view.operation.state(), &OperationState::Completed);
    let steps = view.operation.steps();
    assert_eq!(steps[0].progress().state(), &StepState::Incomplete);
    assert_eq!(steps[0].results()[0].effect, TargetEffect::StillRunning);
    assert_eq!(steps[1].progress().state(), &StepState::Completed);
    assert_eq!(steps[1].results()[0].effect, TargetEffect::ExitVerified);
}

#[test]
fn a_force_step_is_not_dispatched_when_the_graceful_request_was_enough() {
    let mut bench = Bench::new();
    let member = bench.host.spawn(4242);
    bench.host.world().exits_on_term.insert(4242);
    let plan = stop_plan(
        "plan_1",
        vec![member],
        Escalation::ForceAfterGrace,
        bench.clock.now(),
    );
    bench.store(&plan);
    let mut coordinator = bench.start();
    let operation_id = admitted(&mut coordinator, stored_request(&plan));
    let view = run(&mut coordinator, &bench.clock, &operation_id);
    assert_eq!(bench.host.calls(), vec![term(4242)]);
    assert_eq!(view.operation.state(), &OperationState::Completed);
    let force = &view.operation.steps()[1];
    assert_eq!(force.progress().state(), &StepState::NoAction);
    assert_eq!(force.results()[0].effect, TargetEffect::AlreadyExited);
    assert_eq!(force.results()[0].dispatch, DispatchState::NotSubmitted);
    // The force step had no intent and no dispatch.
    assert_eq!(bench.intents(), 1);
}

#[test]
fn a_target_that_is_gone_or_replaced_gets_no_call() {
    let mut bench = Bench::new();
    // The process of the first plan exited before the apply.
    let gone = super::support::member(4242);
    // The PID of the second plan has a process with a different start
    // time: a replacement, which is a different target.
    let replaced = bench.host.spawn(4343);
    bench.host.world().processes.insert(4343, 2_000);
    let now = bench.clock.now();
    let first = stop_plan("plan_1", vec![gone], Escalation::ImmediateForce, now);
    let second = stop_plan("plan_2", vec![replaced], Escalation::ImmediateForce, now);
    bench.store(&first);
    bench.store(&second);
    let mut coordinator = bench.start();

    let operation_id = admitted(&mut coordinator, stored_request(&first));
    let view = run(&mut coordinator, &bench.clock, &operation_id);
    assert_eq!(view.operation.state(), &OperationState::NoAction);
    let result = &view.operation.steps()[0].results()[0];
    assert_eq!(result.effect, TargetEffect::AlreadyExited);
    assert_eq!(result.dispatch, DispatchState::NotSubmitted);

    let operation_id = admitted(&mut coordinator, stored_request(&second));
    let view = run(&mut coordinator, &bench.clock, &operation_id);
    assert_eq!(view.operation.state(), &OperationState::NoAction);
    let result = &view.operation.steps()[0].results()[0];
    assert_eq!(result.effect, TargetEffect::Skipped);
    assert_eq!(result.stop_reason, StopReason::TargetSkipped);
    assert_eq!(
        result.failure.as_ref().unwrap().code.as_str(),
        "process_replaced"
    );
    // The replacement runs, and no signal was sent.
    assert_eq!(bench.host.calls(), Vec::new());
    assert!(bench.host.world().processes.contains_key(&4343));
}

#[test]
fn a_status_query_and_a_cancel_are_answered_during_a_grace_period() {
    let mut bench = Bench::new();
    let member = bench.host.spawn(4242);
    let plan = stop_plan(
        "plan_1",
        vec![member],
        Escalation::ForceAfterGrace,
        bench.clock.now(),
    );
    bench.store(&plan);
    let mut coordinator = bench.start();
    let operation_id = admitted(&mut coordinator, stored_request(&plan));
    let progress = coordinator.step();
    // The driver returned: the grace period is a time in the result and
    // not a wait inside the call.
    assert!(!progress.worked);
    assert!(progress.wake_at.unwrap() > MonotonicNanos::new(START));

    // A different thread reads the status and requests the stop while
    // the grace period runs. Neither call needs the driver.
    let handle = coordinator.handle();
    let id = operation_id.clone();
    let (view, acknowledgement, waited) = std::thread::spawn(move || {
        let view = handle.operation(&id).unwrap();
        let waited = handle.wait(&id, Duration::from_millis(5));
        let acknowledgement = handle.cancel(&id).unwrap();
        (view, acknowledgement, waited)
    })
    .join()
    .unwrap();
    assert!(matches!(view.phase, Phase::Observing { .. }));
    // The timeout of the client ended and canceled nothing.
    assert!(matches!(waited, WaitOutcome::TimedOut(_)));
    assert_eq!(acknowledgement, StopAcknowledgement::Received);

    // The driver reads the request at its next call and writes the
    // durable fence. The observation ends, and no force step follows.
    let view = run(&mut coordinator, &bench.clock, &operation_id);
    assert_eq!(bench.host.calls(), vec![term(4242)]);
    assert!(bench.clock.now() < START + GRACE);
    // The graceful request was submitted and the target runs: the result
    // is `Incomplete` with the cancellation, not a failure and not a
    // claim that nothing was dispatched.
    assert_eq!(view.operation.state(), &OperationState::Incomplete);
    assert_eq!(view.operation.dispatch(), DispatchState::Submitted);
    let steps = view.operation.steps();
    assert_eq!(steps[0].results()[0].effect, TargetEffect::StillRunning);
    assert_eq!(steps[1].results()[0].effect, TargetEffect::Skipped);
    assert_eq!(steps[1].results()[0].stop_reason, StopReason::Canceled);
    let stop = view.stop.unwrap();
    assert_eq!(stop.acknowledgement, StopAcknowledgement::Settled);
    assert!(
        coordinator
            .journal()
            .inner
            .try_has_stop_fence(&operation_id)
            .unwrap()
    );
}

#[test]
fn the_end_of_a_client_wait_cancels_nothing() {
    let mut bench = Bench::new();
    let member = bench.host.spawn(4242);
    let plan = stop_plan(
        "plan_1",
        vec![member],
        Escalation::ForceAfterGrace,
        bench.clock.now(),
    );
    bench.store(&plan);
    let mut coordinator = bench.start();
    let operation_id = admitted(&mut coordinator, stored_request(&plan));
    let mut idle = bench.clock.clone();
    let give_up = MonotonicNanos::new(START + 3 * SECOND);
    let outcome = coordinator.run_until_finished(&operation_id, give_up, &mut idle);
    let WaitOutcome::TimedOut(view) = outcome else {
        panic!("the wait did not end at the time of the client");
    };
    assert!(matches!(view.phase, Phase::Observing { .. }));
    assert!(view.stop.is_none());
    // The operation continues and escalates as planned.
    let give_up = MonotonicNanos::new(START + 60 * SECOND);
    let outcome = coordinator.run_until_finished(&operation_id, give_up, &mut idle);
    let WaitOutcome::Finished(view) = outcome else {
        panic!("the operation did not finish");
    };
    assert_eq!(view.operation.state(), &OperationState::Completed);
    assert_eq!(bench.host.calls(), vec![term(4242), kill(4242)]);
}
