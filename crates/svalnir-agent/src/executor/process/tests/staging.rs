//! The staging and identity logic, with a synthetic host and a clock that
//! the test advances. No test in this file has a live process.

use svalnir_core::action::{
    ActionClass, Attribution, Checked, DispatchConsumption, DispatchReceipt, DispatchState,
    Durability, ErrorFamily, Escalation, NativeResult, RecordingRefusal, RequestEnvelope,
    StepState, StopReason, TargetEffect, TargetResult, aggregate_step,
};
use svalnir_core::file::LosslessPath;
use svalnir_core::id::{BootId, ExecutorEpochId};
use svalnir_core::policy::ProtectionFact;
use svalnir_core::process::{AttributionMethod, ProcessAssociation, ProcessIdentity};
use svalnir_core::time::MonotonicNanos;

use super::super::{
    ApplicationCallResult, ApplicationRequest, ExecutorConfig, ExecutorError, GenerationState,
    GracefulRecord, GracefulSignal, MAX_CLOCK_FAILURES, NextStep, Observation, ProcessExecutor,
    ProcessSignal, SignalResult, StepInput, StepReport, StepRun, StopRequest, code,
};
use super::fake::{
    BUNDLE, GRACE, Host, NativeCall, OWN_PID, PARENT_PID, START, USER, WINDOW, application,
    content, context, force, graceful, helper, instance, job, member, receipt,
};
use crate::platform::process::{
    ProcessSource, QueryFailure, RawProcessInfo, RawUsage, RunningApplication, Timebase,
};
use svalnir_core::file::FileObjectEvidence;
use svalnir_core::observation::UnavailableReason;
use svalnir_core::process::{Pid, Uid};
use svalnir_core::quantity::Nanoseconds;
use svalnir_core::time::WallTime;

const TERM: ProcessSignal = ProcessSignal::Graceful(GracefulSignal::Terminate);

fn input<'a>(envelope: &'a RequestEnvelope, receipt: &'a DispatchReceipt) -> StepInput<'a> {
    StepInput {
        envelope,
        receipt,
        protection: ProtectionFact::NotProtected,
        graceful: None,
        stop: None,
    }
}

/// A receipt that lives for the rest of the test process.
fn durable() -> &'static DispatchReceipt {
    Box::leak(Box::new(receipt()))
}

fn begin(host: &Host, envelope: &RequestEnvelope) -> StepRun {
    host.executor().begin(input(envelope, &receipt())).unwrap()
}

fn finished(run: StepRun) -> StepReport {
    match run {
        StepRun::Finished(report) => report,
        StepRun::Observing(_) => panic!("the step is not finished"),
    }
}

fn observing(run: StepRun) -> Observation {
    match run {
        StepRun::Observing(observation) => *observation,
        StepRun::Finished(report) => panic!("the step is finished: {report:?}"),
    }
}

fn poll(host: &Host, observation: Observation, stop: Option<StopRequest>) -> StepRun {
    observation.poll(&host.executor(), stop).unwrap()
}

fn code_of(result: &TargetResult) -> &str {
    result.failure.as_ref().unwrap().code.as_str()
}

fn family_of(result: &TargetResult) -> &ErrorFamily {
    &result.failure.as_ref().unwrap().family
}

/// Asserts that each member was skipped with `code` and that the executor
/// issued no call.
fn assert_all_skipped(host: &Host, report: &StepReport, code: &str, family: &ErrorFamily) {
    assert_ne!(report.members, Vec::new());
    for outcome in &report.members {
        let result: &TargetResult = &outcome.result;
        assert_eq!(result.effect, TargetEffect::Skipped);
        assert_eq!(result.dispatch, DispatchState::NotSubmitted);
        assert_eq!(result.stop_reason, StopReason::TargetSkipped);
        assert_eq!(result.evidence.native, NativeResult::NotCalled);
        assert_eq!(code_of(result), code);
        assert_eq!(family_of(result), family);
    }
    assert_eq!(host.calls(), Vec::new());
    assert_eq!(report.submitted_at, None);
    assert_eq!(report.next, NextStep::None);
    assert_eq!(
        aggregate_step(&report.results()).unwrap(),
        StepState::NoAction
    );
}

// Identity before the call.

#[test]
fn a_pid_that_another_generation_has_is_skipped() {
    // The plan has the start time 10. The PID was used again.
    let host: Host = Host::new().with_process(100, 20);
    let report = finished(begin(
        &host,
        &graceful(Escalation::None, vec![member(100, 10, job())]),
    ));
    assert_all_skipped(
        &host,
        &report,
        code::PROCESS_REPLACED,
        &ErrorFamily::Evidence,
    );
    assert_eq!(report.members[0].state, Some(GenerationState::Replaced));
}

#[test]
fn an_absent_process_and_a_zombie_are_already_exited_and_get_no_call() {
    let absent: Host = Host::new();
    let zombie: Host = Host::new().with_process(100, 10);
    zombie.change(|world| world.processes.get_mut(&100).unwrap().zombie = true);
    for host in [absent, zombie] {
        for envelope in [
            graceful(Escalation::None, vec![member(100, 10, job())]),
            force(Escalation::ImmediateForce, vec![member(100, 10, job())]),
        ] {
            let report = finished(begin(&host, &envelope));
            let result: &TargetResult = &report.members[0].result;
            assert_eq!(result.effect, TargetEffect::AlreadyExited);
            assert_eq!(result.dispatch, DispatchState::NotSubmitted);
            assert_eq!(result.attribution, Attribution::NotApplicable);
            assert_eq!(result.stop_reason, StopReason::Completed);
            assert_eq!(result.failure, None);
            assert_eq!(report.members[0].state, Some(GenerationState::Exited));
            assert_eq!(report.next, NextStep::None);
            assert_eq!(
                aggregate_step(&report.results()).unwrap(),
                StepState::NoAction
            );
        }
        assert_eq!(host.calls(), Vec::new());
    }
}

#[test]
fn evidence_that_does_not_agree_is_skipped_with_its_reason() {
    type Change = fn(&Host) -> ProcessIdentity;
    let cases: [(Change, &str); 8] = [
        (
            |host| {
                host.change(|world| world.processes.get_mut(&100).unwrap().effective_uid = 0);
                member(100, 10, job())
            },
            code::PROCESS_OWNER_CHANGED,
        ),
        (
            |host| {
                host.change(|world| world.processes.get_mut(&100).unwrap().real_uid = 502);
                member(100, 10, job())
            },
            code::PROCESS_OWNER_CHANGED,
        ),
        (
            |host| {
                host.change(|world| {
                    world.processes.get_mut(&100).unwrap().path = "/opt/other".to_owned();
                });
                member(100, 10, job())
            },
            code::PROCESS_EXECUTABLE_CHANGED,
        ),
        (
            |host| {
                host.change(|world| world.processes.get_mut(&100).unwrap().inode = 7);
                member(100, 10, job())
            },
            code::PROCESS_EXECUTABLE_CHANGED,
        ),
        (
            |host| {
                host.change(|world| {
                    world.path_failures.insert(100, QueryFailure::Failed(5));
                });
                member(100, 10, job())
            },
            code::PROCESS_EVIDENCE_MISSING,
        ),
        (
            |_| {
                let mut planned = member(100, 10, job());
                planned.executable.as_mut().unwrap().file = None;
                planned
            },
            code::PROCESS_EVIDENCE_MISSING,
        ),
        (
            |host| {
                host.change(|world| {
                    world
                        .info_failures
                        .insert(100, QueryFailure::PermissionDenied);
                });
                member(100, 10, job())
            },
            code::PROCESS_QUERY_DENIED,
        ),
        (
            |host| {
                host.change(|world| {
                    world.info_failures.insert(100, QueryFailure::Failed(5));
                });
                member(100, 10, job())
            },
            code::PROCESS_QUERY_FAILED,
        ),
    ];
    for (change, expected) in cases {
        let host: Host = Host::new().with_process(100, 10);
        let planned: ProcessIdentity = change(&host);
        for envelope in [
            graceful(Escalation::None, vec![planned.clone()]),
            force(Escalation::ImmediateForce, vec![planned.clone()]),
        ] {
            let report = finished(begin(&host, &envelope));
            assert_all_skipped(&host, &report, expected, &ErrorFamily::Evidence);
        }
    }
}

#[test]
fn a_member_whose_plan_has_a_code_signature_gets_no_call() {
    // The executor cannot read a signature again, so evidence that it
    // cannot compare is evidence that is missing.
    let host: Host = Host::new().with_process(100, 10);
    let mut planned: ProcessIdentity = member(100, 10, job());
    planned.executable.as_mut().unwrap().code_signature =
        Some(svalnir_core::process::CodeSignatureEvidence {
            signing_identifier: "com.example.job".to_owned(),
            team_identifier: Some("TEAM123456".to_owned()),
        });
    for envelope in [
        graceful(Escalation::None, vec![planned.clone()]),
        force(Escalation::ImmediateForce, vec![planned.clone()]),
    ] {
        let report = finished(begin(&host, &envelope));
        assert_all_skipped(
            &host,
            &report,
            code::PROCESS_EVIDENCE_MISSING,
            &ErrorFamily::Evidence,
        );
    }
}

#[test]
fn the_grace_period_starts_at_the_request_that_was_sent() {
    // The call for the first member finds no process. It is not a request
    // that was sent, so it does not start the grace period.
    const CALL: u64 = 1_000_000;
    let host: Host = Host::new().with_process(100, 10).with_process(101, 10);
    host.change(|world| {
        world.call_duration = CALL;
        world
            .signal_results
            .insert(100, SignalResult::NoSuchProcess);
    });
    let members = vec![member(100, 10, job()), member(101, 10, job())];
    let envelope = graceful(Escalation::ForceAfterGrace, members);
    let observation = observing(begin(&host, &envelope));
    assert_eq!(
        observation.submitted_at(),
        Some(MonotonicNanos::new(START + 2 * CALL))
    );
    host.advance(GRACE);
    let report = finished(poll(&host, observation, None));
    assert_eq!(report.members[0].result.effect, TargetEffect::AlreadyExited);
    assert_eq!(report.members[1].result.effect, TargetEffect::StillRunning);
    assert_eq!(
        report.next,
        NextStep::Force {
            not_before: MonotonicNanos::new(START + 2 * CALL + GRACE)
        }
    );

    // When no member was possibly running, no time is recorded.
    let host: Host = Host::new().with_process(100, 10);
    host.change(|world| {
        world
            .signal_results
            .insert(100, SignalResult::NoSuchProcess);
    });
    let envelope = graceful(Escalation::ForceAfterGrace, vec![member(100, 10, job())]);
    assert_eq!(finished(begin(&host, &envelope)).submitted_at, None);
}

#[test]
fn a_helper_that_exits_after_the_application_request_is_a_covered_member() {
    let host: Host = Host::new().with_process(100, 10).with_process(101, 10);
    let members = vec![member(101, 10, helper()), member(100, 10, application())];
    let envelope = graceful(Escalation::ForceAfterGrace, members);
    let observation = observing(begin(&host, &envelope));
    host.exit(100);
    host.exit(101);
    let report = finished(poll(&host, observation, None));
    let helper_result: &TargetResult = &report.members[0].result;
    assert_eq!(helper_result.effect, TargetEffect::ExitVerified);
    assert_eq!(helper_result.attribution, Attribution::Established);
    assert_eq!(
        helper_result.evidence.native,
        NativeResult::CoveredByApplicationRequest
    );
    assert!(helper_result.evidence.source.is_some());
    assert_eq!(
        report.members[1].result.evidence.native,
        NativeResult::Succeeded
    );
}

#[test]
fn a_covered_helper_that_cannot_be_read_at_the_end_is_an_unknown_outcome() {
    let host: Host = Host::new().with_process(100, 10).with_process(101, 10);
    let members = vec![member(101, 10, helper()), member(100, 10, application())];
    let envelope = graceful(Escalation::ForceAfterGrace, members);
    let observation = observing(begin(&host, &envelope));
    host.exit(100);
    host.change(|world| {
        world.info_failures.insert(101, QueryFailure::Failed(5));
    });
    host.advance(GRACE);
    let report = finished(poll(&host, observation, None));
    let helper_result: &TargetResult = &report.members[0].result;
    assert_eq!(helper_result.effect, TargetEffect::UnknownOutcome);
    assert_eq!(
        helper_result.evidence.native,
        NativeResult::CoveredByApplicationRequest
    );
    assert_eq!(report.next, NextStep::Reconcile);
}

#[test]
fn a_plan_with_no_executable_evidence_gets_no_call() {
    let host: Host = Host::new().with_process(100, 10);
    let mut planned: ProcessIdentity = member(100, 10, job());
    planned.executable = None;
    let report = finished(begin(&host, &graceful(Escalation::None, vec![planned])));
    assert_all_skipped(
        &host,
        &report,
        code::PROCESS_EVIDENCE_MISSING,
        &ErrorFamily::Evidence,
    );
}

// The graceful step and the grace period.

#[test]
fn an_exit_in_the_grace_period_is_verified_and_permits_no_force_step() {
    let host: Host = Host::new().with_process(100, 10);
    let envelope = graceful(Escalation::ForceAfterGrace, vec![member(100, 10, job())]);
    let observation = observing(begin(&host, &envelope));
    assert_eq!(host.calls(), vec![NativeCall::Signal(100, TERM)]);
    assert_eq!(observation.submitted_at(), Some(MonotonicNanos::new(START)));
    assert_eq!(
        observation.window_ends_at(),
        MonotonicNanos::new(START + GRACE)
    );
    assert_eq!(observation.waiting(), 1);

    // The call returned success, and the process is running: no result.
    host.advance(100);
    let observation = observing(poll(&host, observation, None));

    host.exit(100);
    host.advance(100);
    let report = finished(poll(&host, observation, None));
    let result: &TargetResult = &report.members[0].result;
    assert_eq!(result.effect, TargetEffect::ExitVerified);
    assert_eq!(result.dispatch, DispatchState::Submitted);
    assert_eq!(result.attribution, Attribution::Established);
    assert_eq!(result.evidence.native, NativeResult::Succeeded);
    assert_eq!(result.stop_reason, StopReason::Completed);
    assert_eq!(result.durability, Durability::Durable);
    assert!(result.evidence.source.is_some());
    assert_eq!(report.members[0].state, Some(GenerationState::Exited));
    assert_eq!(report.submitted_at, Some(MonotonicNanos::new(START)));
    assert_eq!(report.next, NextStep::None);
    assert_eq!(
        aggregate_step(&report.results()).unwrap(),
        StepState::Completed
    );
    // One signal only.
    assert_eq!(host.calls().len(), 1);
}

#[test]
fn a_replacement_generation_after_the_call_is_the_exit_of_the_planned_one() {
    let host: Host = Host::new().with_process(100, 10);
    let envelope = graceful(Escalation::None, vec![member(100, 10, job())]);
    let observation = observing(begin(&host, &envelope));
    // The planned generation exited and a new process has its PID.
    host.change(|world| world.processes.get_mut(&100).unwrap().start_seconds = 30);
    let report = finished(poll(&host, observation, None));
    let result: &TargetResult = &report.members[0].result;
    assert_eq!(result.effect, TargetEffect::ExitVerified);
    assert_eq!(result.attribution, Attribution::Possible);
    assert_eq!(report.members[0].state, Some(GenerationState::Replaced));
    // The new generation gets no call.
    assert_eq!(host.calls(), vec![NativeCall::Signal(100, TERM)]);
}

#[test]
fn a_process_that_runs_at_the_end_of_the_window_permits_force_only_with_the_strategy() {
    // `force_after_grace`: the window is the grace period.
    let host: Host = Host::new().with_process(100, 10);
    let envelope = graceful(Escalation::ForceAfterGrace, vec![member(100, 10, job())]);
    let observation = observing(begin(&host, &envelope));
    host.advance(GRACE - 1);
    let observation = observing(poll(&host, observation, None));
    host.advance(1);
    let report = finished(poll(&host, observation, None));
    let result: &TargetResult = &report.members[0].result;
    assert_eq!(result.effect, TargetEffect::StillRunning);
    assert_eq!(result.dispatch, DispatchState::Submitted);
    assert_eq!(result.attribution, Attribution::NotApplicable);
    assert_eq!(result.stop_reason, StopReason::Completed);
    assert_eq!(report.members[0].state, Some(GenerationState::Running));
    assert_eq!(
        report.next,
        NextStep::Force {
            not_before: MonotonicNanos::new(START + GRACE)
        }
    );
    assert_eq!(
        aggregate_step(&report.results()).unwrap(),
        StepState::Incomplete
    );

    // `none`: the window is the verification window, and no force step
    // follows.
    let host: Host = Host::new().with_process(100, 10);
    let envelope = graceful(Escalation::None, vec![member(100, 10, job())]);
    let observation = observing(begin(&host, &envelope));
    assert_eq!(
        observation.window_ends_at(),
        MonotonicNanos::new(START + WINDOW)
    );
    host.advance(WINDOW);
    let report = finished(poll(&host, observation, None));
    assert_eq!(report.members[0].result.effect, TargetEffect::StillRunning);
    assert_eq!(report.next, NextStep::ForceNotPermitted);
    assert_eq!(host.calls(), vec![NativeCall::Signal(100, TERM)]);
}

#[test]
fn the_configured_graceful_signal_is_sent() {
    let host: Host = Host::new().with_process(100, 10);
    let executor = ProcessExecutor::new(
        host.clone(),
        host.clone(),
        host.clone(),
        context(),
        ExecutorConfig {
            graceful_signal: GracefulSignal::Interrupt,
        },
    );
    let envelope = graceful(Escalation::None, vec![member(100, 10, job())]);
    let _run = executor.begin(input(&envelope, &receipt())).unwrap();
    assert_eq!(
        host.calls(),
        vec![NativeCall::Signal(
            100,
            ProcessSignal::Graceful(GracefulSignal::Interrupt)
        )]
    );
}

// The force step.

/// Runs a graceful step of `force_after_grace` to the end of the grace
/// period with each process running.
fn graceful_step_to_the_end(host: &Host, members: Vec<ProcessIdentity>) -> StepReport {
    let envelope = graceful(Escalation::ForceAfterGrace, members);
    match begin(host, &envelope) {
        StepRun::Finished(report) => report,
        StepRun::Observing(observation) => {
            host.advance(GRACE);
            finished(poll(host, *observation, None))
        }
    }
}

fn force_input<'a>(
    envelope: &'a RequestEnvelope,
    receipt: &'a DispatchReceipt,
    report: &StepReport,
    results: &'a [TargetResult],
) -> StepInput<'a> {
    StepInput {
        graceful: Some(GracefulRecord {
            submitted_at: report.submitted_at.unwrap(),
            operation_id: &super::fake::OPERATION,
            step_id: &super::fake::GRACEFUL_STEP,
            results,
        }),
        ..input(envelope, receipt)
    }
}

#[test]
fn a_force_step_needs_the_record_of_its_graceful_step_and_no_other_step_has_one() {
    let host: Host = Host::new().with_process(100, 10);
    let members = vec![member(100, 10, job())];
    let executor = host.executor();
    let after_grace = force(Escalation::ForceAfterGrace, members.clone());
    assert_eq!(
        executor.begin(input(&after_grace, &receipt())).unwrap_err(),
        ExecutorError::GracefulRecord
    );
    let record = GracefulRecord {
        submitted_at: MonotonicNanos::new(START),
        operation_id: &super::fake::OPERATION,
        step_id: &super::fake::GRACEFUL_STEP,
        results: &[],
    };
    for envelope in [
        force(Escalation::ImmediateForce, members.clone()),
        graceful(Escalation::ForceAfterGrace, members.clone()),
        graceful(Escalation::None, members),
    ] {
        let with_record = StepInput {
            graceful: Some(record),
            ..input(&envelope, durable())
        };
        assert_eq!(
            executor.begin(with_record).unwrap_err(),
            ExecutorError::GracefulRecord
        );
    }
    assert_eq!(host.calls(), Vec::new());
}

#[test]
fn a_force_step_waits_for_the_end_of_the_grace_period() {
    let host: Host = Host::new().with_process(100, 10);
    let members = vec![member(100, 10, job())];
    let envelope = graceful(Escalation::ForceAfterGrace, members.clone());
    let observation = observing(begin(&host, &envelope));
    // A stop ends the graceful step early. The grace period does not end.
    host.advance(GRACE / 2);
    let stopped = finished(poll(&host, observation, Some(StopRequest::Paused)));
    assert_eq!(stopped.next, NextStep::Stopped(StopRequest::Paused));
    let results = stopped.results();
    let after_grace = force(Escalation::ForceAfterGrace, members);
    let receipt = receipt();
    let early = finished(
        host.executor()
            .begin(force_input(&after_grace, &receipt, &stopped, &results))
            .unwrap(),
    );
    for outcome in &early.members {
        assert_eq!(outcome.result.effect, TargetEffect::Skipped);
        assert_eq!(code_of(&outcome.result), code::GRACE_NOT_EXPIRED);
        assert_eq!(family_of(&outcome.result), &ErrorFamily::Limits);
    }
    assert_eq!(host.calls(), vec![NativeCall::Signal(100, TERM)]);
}

#[test]
fn a_force_step_after_the_grace_period_kills_and_verifies() {
    let host: Host = Host::new().with_process(100, 10);
    let members = vec![member(100, 10, job())];
    let report = graceful_step_to_the_end(&host, members.clone());
    let results = report.results();
    let envelope = force(Escalation::ForceAfterGrace, members);
    let receipt = receipt();
    host.change(|world| {
        world.exits_on_call.insert(100);
    });
    let observation = observing(
        host.executor()
            .begin(force_input(&envelope, &receipt, &report, &results))
            .unwrap(),
    );
    assert_eq!(
        host.calls(),
        vec![
            NativeCall::Signal(100, TERM),
            NativeCall::Signal(100, ProcessSignal::Kill)
        ]
    );
    // The return value of `kill` is not the result: the step waits for a
    // reading.
    assert_eq!(observation.waiting(), 1);
    assert_eq!(
        observation.window_ends_at(),
        MonotonicNanos::new(START + GRACE + WINDOW)
    );
    let forced = finished(poll(&host, observation, None));
    assert_eq!(forced.members[0].result.effect, TargetEffect::ExitVerified);
    assert_eq!(forced.next, NextStep::None);
    let mut all = results;
    all.extend(forced.results());
    assert_eq!(aggregate_step(&all).unwrap(), StepState::Completed);
}

#[test]
fn a_graceful_record_of_a_different_operation_or_of_the_force_step_permits_no_force_step() {
    let host: Host = Host::new().with_process(100, 10);
    let members = vec![member(100, 10, job())];
    let report = graceful_step_to_the_end(&host, members.clone());
    let results = report.results();
    let envelope = force(Escalation::ForceAfterGrace, members);
    let receipt = receipt();
    let other_operation = svalnir_core::id::OperationId::new("operation_2").unwrap();
    let force_step = envelope.correlation.step_id.clone();
    let correct = force_input(&envelope, &receipt, &report, &results);
    let record = correct.graceful.unwrap();
    for wrong in [
        GracefulRecord {
            operation_id: &other_operation,
            ..record
        },
        GracefulRecord {
            step_id: &force_step,
            ..record
        },
    ] {
        let input = StepInput {
            graceful: Some(wrong),
            ..correct
        };
        assert_eq!(
            host.executor().begin(input).unwrap_err(),
            ExecutorError::GracefulRecord
        );
    }
    // No force call was issued for either record.
    assert_eq!(host.calls(), vec![NativeCall::Signal(100, TERM)]);
    // The record of the operation of the envelope permits the step.
    host.executor().begin(correct).unwrap();
    assert_eq!(
        host.calls(),
        vec![
            NativeCall::Signal(100, TERM),
            NativeCall::Signal(100, ProcessSignal::Kill)
        ]
    );
}

#[test]
fn a_force_step_checks_the_identity_again() {
    let host: Host = Host::new().with_process(100, 10);
    let members = vec![member(100, 10, job())];
    let report = graceful_step_to_the_end(&host, members.clone());
    let results = report.results();
    // The process exited after the grace period and its PID was used again.
    host.change(|world| world.processes.get_mut(&100).unwrap().start_seconds = 40);
    let envelope = force(Escalation::ForceAfterGrace, members);
    let receipt = receipt();
    let forced = finished(
        host.executor()
            .begin(force_input(&envelope, &receipt, &report, &results))
            .unwrap(),
    );
    assert_eq!(forced.members[0].result.effect, TargetEffect::Skipped);
    assert_eq!(code_of(&forced.members[0].result), code::PROCESS_REPLACED);
    assert_eq!(host.calls(), vec![NativeCall::Signal(100, TERM)]);
}

#[test]
fn a_force_step_acts_only_on_a_member_that_a_request_left_running() {
    // 100 exits in the grace period, 101 runs, and 102 was replaced before
    // the graceful request.
    let host: Host = Host::new()
        .with_process(100, 10)
        .with_process(101, 10)
        .with_process(102, 99);
    let members = vec![
        member(100, 10, job()),
        member(101, 10, job()),
        member(102, 10, job()),
    ];
    host.change(|world| {
        world.exits_on_call.insert(100);
    });
    let report = graceful_step_to_the_end(&host, members.clone());
    let effects: Vec<TargetEffect> = report
        .members
        .iter()
        .map(|outcome| outcome.result.effect.clone())
        .collect();
    assert_eq!(
        effects,
        vec![
            TargetEffect::ExitVerified,
            TargetEffect::StillRunning,
            TargetEffect::Skipped
        ]
    );
    assert_eq!(
        aggregate_step(&report.results()).unwrap(),
        StepState::Partial
    );
    let results = report.results();
    let envelope = force(Escalation::ForceAfterGrace, members);
    let receipt = receipt();
    let observation = observing(
        host.executor()
            .begin(force_input(&envelope, &receipt, &report, &results))
            .unwrap(),
    );
    host.exit(101);
    let forced = finished(poll(&host, observation, None));
    let first: &TargetResult = &forced.members[0].result;
    assert_eq!(first.effect, TargetEffect::AlreadyExited);
    assert_eq!(first.dispatch, DispatchState::NotSubmitted);
    assert_eq!(forced.members[1].result.effect, TargetEffect::ExitVerified);
    let third: &TargetResult = &forced.members[2].result;
    assert_eq!(third.effect, TargetEffect::Skipped);
    assert_eq!(code_of(third), code::GRACEFUL_REQUEST_NOT_SUBMITTED);
    assert_eq!(family_of(third), &ErrorFamily::Eligibility);
    assert_eq!(
        host.calls(),
        vec![
            NativeCall::Signal(100, TERM),
            NativeCall::Signal(101, TERM),
            NativeCall::Signal(101, ProcessSignal::Kill)
        ]
    );
}

#[test]
fn a_record_of_a_different_target_is_rejected() {
    let host: Host = Host::new().with_process(100, 10);
    let members = vec![member(100, 10, job())];
    let report = graceful_step_to_the_end(&host, members.clone());
    let mut record = report.members[0].result.clone().into_inner();
    record.target_id = svalnir_core::id::TargetId::new("other").unwrap();
    let results = vec![Checked::new(record).unwrap()];
    let envelope = force(Escalation::ForceAfterGrace, members);
    let receipt = receipt();
    assert_eq!(
        host.executor()
            .begin(force_input(&envelope, &receipt, &report, &results))
            .unwrap_err(),
        ExecutorError::GracefulRecord
    );
}

// Stop requests.

#[test]
fn a_stop_before_the_first_call_gives_a_result_with_no_call() {
    let host: Host = Host::new().with_process(100, 10);
    for envelope in [
        graceful(Escalation::ForceAfterGrace, vec![member(100, 10, job())]),
        force(Escalation::ImmediateForce, vec![member(100, 10, job())]),
    ] {
        let stopped = StepInput {
            stop: Some(StopRequest::Canceled),
            ..input(&envelope, durable())
        };
        let report = finished(host.executor().begin(stopped).unwrap());
        let result: &TargetResult = &report.members[0].result;
        assert_eq!(result.effect, TargetEffect::Skipped);
        assert_eq!(result.dispatch, DispatchState::NotSubmitted);
        assert_eq!(result.stop_reason, StopReason::Canceled);
        assert_eq!(result.failure, None);
        assert_eq!(result.evidence.source, None);
        assert_eq!(report.members[0].state, None);
        assert_eq!(report.next, NextStep::None);
        assert_eq!(
            aggregate_step(&report.results()).unwrap(),
            StepState::NoAction
        );
    }
    assert_eq!(host.calls(), Vec::new());
    // The executor did not read the process.
    assert_eq!(host.0.borrow().info_queries, 0);
}

#[test]
fn a_stop_in_the_grace_period_stops_the_escalation_and_keeps_the_submission() {
    let host: Host = Host::new().with_process(100, 10);
    let envelope = graceful(Escalation::ForceAfterGrace, vec![member(100, 10, job())]);
    let observation = observing(begin(&host, &envelope));
    host.advance(10);
    let report = finished(poll(&host, observation, Some(StopRequest::Canceled)));
    let result: &TargetResult = &report.members[0].result;
    assert_eq!(result.effect, TargetEffect::StillRunning);
    assert_eq!(result.dispatch, DispatchState::Submitted);
    assert_eq!(result.evidence.native, NativeResult::Succeeded);
    assert_eq!(result.stop_reason, StopReason::Canceled);
    assert_eq!(report.submitted_at, Some(MonotonicNanos::new(START)));
    assert_eq!(report.next, NextStep::Stopped(StopRequest::Canceled));
    assert_eq!(
        aggregate_step(&report.results()).unwrap(),
        StepState::Incomplete
    );
    assert_eq!(host.calls(), vec![NativeCall::Signal(100, TERM)]);
}

#[test]
fn a_stop_with_an_exit_in_the_same_poll_records_the_exit() {
    let host: Host = Host::new().with_process(100, 10);
    let envelope = graceful(Escalation::ForceAfterGrace, vec![member(100, 10, job())]);
    let observation = observing(begin(&host, &envelope));
    host.exit(100);
    let report = finished(poll(&host, observation, Some(StopRequest::Canceled)));
    assert_eq!(report.members[0].result.effect, TargetEffect::ExitVerified);
    assert_eq!(report.next, NextStep::None);
}

#[test]
fn a_stop_before_the_escalation_issues_no_force_call() {
    let host: Host = Host::new().with_process(100, 10);
    let members = vec![member(100, 10, job())];
    let report = graceful_step_to_the_end(&host, members.clone());
    let results = report.results();
    let envelope = force(Escalation::ForceAfterGrace, members);
    let receipt = receipt();
    let stopped = StepInput {
        stop: Some(StopRequest::TriggerCleared),
        ..force_input(&envelope, &receipt, &report, &results)
    };
    let forced = finished(host.executor().begin(stopped).unwrap());
    let result: &TargetResult = &forced.members[0].result;
    assert_eq!(result.effect, TargetEffect::Skipped);
    assert_eq!(result.stop_reason, StopReason::TriggerCleared);
    assert_eq!(host.calls(), vec![NativeCall::Signal(100, TERM)]);
    // The graceful request stays recorded as submitted.
    let mut all = results;
    all.extend(forced.results());
    assert_eq!(aggregate_step(&all).unwrap(), StepState::Incomplete);
}

#[test]
fn a_stop_in_the_force_verification_keeps_the_submission() {
    let host: Host = Host::new().with_process(100, 10);
    let envelope = force(Escalation::ImmediateForce, vec![member(100, 10, job())]);
    let observation = observing(begin(&host, &envelope));
    let report = finished(poll(&host, observation, Some(StopRequest::Paused)));
    let result: &TargetResult = &report.members[0].result;
    assert_eq!(result.effect, TargetEffect::StillRunning);
    assert_eq!(result.dispatch, DispatchState::Submitted);
    assert_eq!(result.stop_reason, StopReason::Paused);
    assert_eq!(report.next, NextStep::None);
    assert_eq!(
        host.calls(),
        vec![NativeCall::Signal(100, ProcessSignal::Kill)]
    );
}

// Hard refusals.

#[test]
fn the_protection_fact_of_the_caller_is_necessary() {
    for (fact, expected) in [
        (ProtectionFact::Protected, code::TARGET_PROTECTED),
        (ProtectionFact::Unknown, code::TARGET_PROTECTION_UNKNOWN),
    ] {
        let host: Host = Host::new().with_process(100, 10);
        for envelope in [
            graceful(Escalation::None, vec![member(100, 10, job())]),
            force(Escalation::ImmediateForce, vec![member(100, 10, job())]),
        ] {
            let protected = StepInput {
                protection: fact,
                ..input(&envelope, durable())
            };
            let report = finished(host.executor().begin(protected).unwrap());
            assert_all_skipped(&host, &report, expected, &ErrorFamily::Eligibility);
        }
    }
}

#[test]
fn the_executor_refuses_protected_processes_for_each_plan() {
    type Setup = fn(&Host) -> Vec<ProcessIdentity>;
    let cases: [(Setup, &str); 9] = [
        // `launchd`.
        (|_| vec![member(1, 10, job())], code::TARGET_PROTECTED),
        // The executor and its parent.
        (
            |_| vec![member(OWN_PID, 10, job())],
            code::TARGET_IS_CONTROL_PLANE,
        ),
        (
            |_| vec![member(100, 10, job()), member(PARENT_PID, 10, job())],
            code::TARGET_IS_CONTROL_PLANE,
        ),
        // The executor cannot establish its own process.
        (
            |host| {
                host.change(|world| world.own = None);
                vec![member(100, 10, job())]
            },
            code::CONTROL_PLANE_UNKNOWN,
        ),
        (
            |host| {
                host.change(|world| world.parent = None);
                vec![member(100, 10, job())]
            },
            code::CONTROL_PLANE_UNKNOWN,
        ),
        // The executor runs for a different user than the principal and
        // the members.
        (
            |host| {
                host.change(|world| world.effective_uid = 502);
                vec![member(100, 10, job())]
            },
            code::TARGET_OTHER_USER,
        ),
        // A system executable.
        (
            |_| {
                let mut planned = member(100, 10, job());
                planned.executable.as_mut().unwrap().path =
                    LosslessPath::from_bytes("/usr/libexec/example").unwrap();
                vec![planned]
            },
            code::TARGET_PROTECTED,
        ),
        // A session application.
        (
            |_| {
                let association = ProcessAssociation::Application {
                    instance_id: instance(),
                    bundle_identifier: "com.apple.finder".to_owned(),
                    attribution: AttributionMethod::LaunchServices,
                };
                vec![member(100, 10, association)]
            },
            code::TARGET_PROTECTED,
        ),
        // A Svalnir executable.
        (
            |_| {
                let mut planned = member(100, 10, job());
                planned.executable.as_mut().unwrap().path =
                    LosslessPath::from_bytes("/opt/bin/svalnir-agent").unwrap();
                vec![planned]
            },
            code::TARGET_PROTECTED,
        ),
    ];
    for (setup, expected) in cases {
        let host: Host = Host::new()
            .with_process(1, 10)
            .with_process(100, 10)
            .with_process(OWN_PID, 10)
            .with_process(PARENT_PID, 10);
        let members: Vec<ProcessIdentity> = setup(&host);
        for envelope in [
            graceful(Escalation::None, members.clone()),
            graceful(Escalation::ForceAfterGrace, members.clone()),
            force(Escalation::ImmediateForce, members.clone()),
        ] {
            let report = finished(begin(&host, &envelope));
            assert_all_skipped(&host, &report, expected, &ErrorFamily::Eligibility);
        }
    }
}

#[test]
fn a_root_principal_and_a_member_of_another_boot_are_refused() {
    // Each member and the principal are root, and the executor runs as
    // root: the initial surface has no root target.
    let host: Host = Host::new().with_process(100, 10);
    host.change(|world| world.effective_uid = 0);
    let mut planned: ProcessIdentity = member(100, 10, job());
    planned.uid = Uid::new(0);
    let root: RequestEnvelope = Checked::new(content(
        ActionClass::RequestApplicationExit,
        Escalation::None,
        vec![planned],
        0,
    ))
    .unwrap();
    let report = finished(begin(&host, &root));
    assert_all_skipped(
        &host,
        &report,
        code::TARGET_OTHER_USER,
        &ErrorFamily::Eligibility,
    );

    let host: Host = Host::new().with_process(100, 10);
    let mut planned: ProcessIdentity = member(100, 10, job());
    planned.boot_id = BootId::new("boot_0").unwrap();
    let report = finished(begin(&host, &graceful(Escalation::None, vec![planned])));
    assert_all_skipped(
        &host,
        &report,
        code::EXECUTOR_CONTEXT_CHANGED,
        &ErrorFamily::Evidence,
    );
}

// Verification.

#[test]
fn a_failed_verification_query_is_an_unknown_outcome() {
    let host: Host = Host::new().with_process(100, 10);
    let envelope = graceful(Escalation::ForceAfterGrace, vec![member(100, 10, job())]);
    let observation = observing(begin(&host, &envelope));
    host.change(|world| {
        world.info_failures.insert(100, QueryFailure::Failed(5));
    });
    host.advance(10);
    // A failed query in the window is not a result.
    let observation = observing(poll(&host, observation, None));
    host.advance(GRACE);
    let report = finished(poll(&host, observation, None));
    let result: &TargetResult = &report.members[0].result;
    assert_eq!(result.effect, TargetEffect::UnknownOutcome);
    assert_eq!(result.dispatch, DispatchState::Submitted);
    assert_eq!(result.attribution, Attribution::Possible);
    assert_eq!(result.stop_reason, StopReason::Failed);
    assert_eq!(code_of(result), code::EXIT_NOT_VERIFIABLE);
    assert_eq!(family_of(result), &ErrorFamily::Outcome);
    assert_eq!(
        report.members[0].state,
        Some(GenerationState::Unknown(QueryFailure::Failed(5)))
    );
    // No force step follows an effect that is not known.
    assert_eq!(report.next, NextStep::Reconcile);
    assert_eq!(
        aggregate_step(&report.results()).unwrap(),
        StepState::UnknownOutcome
    );
}

#[test]
fn a_graceful_step_with_an_unknown_member_permits_no_force_call_for_another_member() {
    // 100 runs at the end of the grace period. The condition of 101 is not
    // known: its query fails.
    let host: Host = Host::new().with_process(100, 10).with_process(101, 10);
    let members = vec![member(100, 10, job()), member(101, 10, job())];
    let envelope = graceful(Escalation::ForceAfterGrace, members.clone());
    let observation = observing(begin(&host, &envelope));
    host.change(|world| {
        world.info_failures.insert(101, QueryFailure::Failed(5));
    });
    host.advance(GRACE);
    let report = finished(poll(&host, observation, None));
    assert_eq!(report.members[0].result.effect, TargetEffect::StillRunning);
    assert_eq!(
        report.members[1].result.effect,
        TargetEffect::UnknownOutcome
    );
    assert_eq!(report.next, NextStep::Reconcile);
    // A caller that submits the force step in spite of that gets no call.
    host.change(|world| {
        world.info_failures.clear();
    });
    let results = report.results();
    let after_grace = force(Escalation::ForceAfterGrace, members);
    let receipt = receipt();
    assert_eq!(
        host.executor()
            .begin(force_input(&after_grace, &receipt, &report, &results))
            .unwrap_err(),
        ExecutorError::GracefulRecord
    );
    assert_eq!(
        host.calls(),
        vec![NativeCall::Signal(100, TERM), NativeCall::Signal(101, TERM)]
    );
}

#[test]
fn a_query_that_fails_and_then_succeeds_gives_the_observed_result() {
    let host: Host = Host::new().with_process(100, 10);
    let envelope = graceful(Escalation::None, vec![member(100, 10, job())]);
    let observation = observing(begin(&host, &envelope));
    host.change(|world| {
        world.info_failures.insert(100, QueryFailure::Failed(5));
    });
    let observation = observing(poll(&host, observation, None));
    host.change(|world| {
        world.info_failures.clear();
        world.processes.remove(&100);
    });
    let report = finished(poll(&host, observation, None));
    assert_eq!(report.members[0].result.effect, TargetEffect::ExitVerified);
}

#[test]
fn an_observation_ends_when_the_clock_gives_no_value() {
    let host: Host = Host::new().with_process(100, 10);
    let envelope = graceful(Escalation::None, vec![member(100, 10, job())]);
    let mut observation = observing(begin(&host, &envelope));
    host.change(|world| world.clock_fails = true);
    for _ in 1..MAX_CLOCK_FAILURES {
        observation = observing(poll(&host, observation, None));
    }
    let report = finished(poll(&host, observation, None));
    // The last reading showed the process: it is running, and no exit is
    // reported.
    assert_eq!(report.members[0].result.effect, TargetEffect::StillRunning);
    assert_eq!(report.members[0].result.stop_reason, StopReason::Completed);
    assert_eq!(report.next, NextStep::ForceNotPermitted);

    // With no clock value at the start, no call is issued.
    let host: Host = Host::new().with_process(100, 10);
    host.change(|world| world.clock_fails = true);
    let report = finished(begin(&host, &envelope));
    assert_all_skipped(
        &host,
        &report,
        code::CLOCK_UNAVAILABLE,
        &ErrorFamily::Evidence,
    );
}

// The native results.

#[test]
fn each_signal_result_has_its_own_record() {
    // `ESRCH`: the process exited between the check and the call.
    let host: Host = Host::new().with_process(100, 10);
    host.change(|world| {
        world
            .signal_results
            .insert(100, SignalResult::NoSuchProcess);
    });
    let envelope = graceful(Escalation::ForceAfterGrace, vec![member(100, 10, job())]);
    let report = finished(begin(&host, &envelope));
    let result: &TargetResult = &report.members[0].result;
    assert_eq!(result.effect, TargetEffect::AlreadyExited);
    assert_eq!(result.dispatch, DispatchState::Submitted);
    assert_eq!(result.attribution, Attribution::Possible);
    assert_eq!(
        result.evidence.native,
        NativeResult::Errno { errno: libc::ESRCH }
    );
    assert_eq!(result.failure, None);
    assert_eq!(report.next, NextStep::None);
    // The member is not signaled again.
    assert_eq!(host.calls().len(), 1);

    for (native, errno, expected) in [
        (
            SignalResult::NotPermitted,
            libc::EPERM,
            code::SIGNAL_NOT_PERMITTED,
        ),
        (
            SignalResult::Failed(libc::EINVAL),
            libc::EINVAL,
            code::SIGNAL_FAILED,
        ),
    ] {
        let host: Host = Host::new().with_process(100, 10);
        host.change(|world| {
            world.signal_results.insert(100, native);
        });
        let report = finished(begin(&host, &envelope));
        let result: &TargetResult = &report.members[0].result;
        assert_eq!(result.effect, TargetEffect::Refused);
        assert_eq!(result.dispatch, DispatchState::Submitted);
        assert_eq!(result.evidence.native, NativeResult::Errno { errno });
        assert_eq!(result.stop_reason, StopReason::Failed);
        assert_eq!(code_of(result), expected);
        assert_eq!(family_of(result), &ErrorFamily::Native);
        assert_eq!(
            result.failure.as_ref().unwrap().dispatch,
            DispatchState::Submitted
        );
        assert_eq!(report.submitted_at, Some(MonotonicNanos::new(START)));
        assert_eq!(
            aggregate_step(&report.results()).unwrap(),
            StepState::Failed
        );
    }

    // The native layer issued no call.
    let host: Host = Host::new().with_process(100, 10);
    host.change(|world| {
        world
            .signal_results
            .insert(100, SignalResult::InvalidTarget);
    });
    let report = finished(begin(&host, &envelope));
    let result: &TargetResult = &report.members[0].result;
    assert_eq!(result.effect, TargetEffect::Skipped);
    assert_eq!(code_of(result), code::TARGET_PROTECTED);
    assert_eq!(result.dispatch, DispatchState::NotSubmitted);
    assert_eq!(result.evidence.native, NativeResult::NotCalled);
    // The fake records the call that the native layer refuses.
    assert_eq!(host.calls().len(), 1);
    assert_eq!(report.submitted_at, None);
}

#[test]
fn each_application_result_has_its_own_record() {
    let envelope = graceful(Escalation::None, vec![member(100, 10, application())]);

    // `false` for a running application is a refusal.
    let host: Host = Host::new().with_process(100, 10);
    host.change(|world| {
        world
            .application_results
            .insert(100, ApplicationCallResult::Declined);
    });
    let report = finished(begin(&host, &envelope));
    let result: &TargetResult = &report.members[0].result;
    assert_eq!(result.effect, TargetEffect::Refused);
    assert_eq!(result.dispatch, DispatchState::Submitted);
    assert_eq!(result.evidence.native, NativeResult::Refused);
    assert_eq!(code_of(result), code::APPLICATION_DECLINED_REQUEST);
    assert_eq!(family_of(result), &ErrorFamily::Native);

    // `false` for an application that exited before the call is not a
    // refusal.
    let host: Host = Host::new().with_process(100, 10);
    host.change(|world| {
        world
            .application_results
            .insert(100, ApplicationCallResult::Declined);
        world.exits_on_call.insert(100);
    });
    let report = finished(begin(&host, &envelope));
    let result: &TargetResult = &report.members[0].result;
    assert_eq!(result.effect, TargetEffect::AlreadyExited);
    assert_eq!(result.dispatch, DispatchState::Submitted);
    assert_eq!(result.attribution, Attribution::Possible);
    assert_eq!(result.evidence.native, NativeResult::Refused);
    assert_eq!(result.failure, None);

    for (native, expected, family) in [
        (
            ApplicationCallResult::NotRegistered,
            code::APPLICATION_NOT_REGISTERED,
            ErrorFamily::Evidence,
        ),
        (
            ApplicationCallResult::IdentityMismatch,
            code::APPLICATION_IDENTITY_MISMATCH,
            ErrorFamily::Evidence,
        ),
        (
            ApplicationCallResult::Terminated,
            code::APPLICATION_TERMINATED,
            ErrorFamily::Evidence,
        ),
        (
            ApplicationCallResult::Unsupported,
            code::BACKEND_UNSUPPORTED,
            ErrorFamily::Native,
        ),
    ] {
        let host: Host = Host::new().with_process(100, 10);
        host.change(|world| {
            world.application_results.insert(100, native);
        });
        let report = finished(begin(&host, &envelope));
        let result: &TargetResult = &report.members[0].result;
        assert_eq!(result.effect, TargetEffect::Skipped);
        assert_eq!(result.dispatch, DispatchState::NotSubmitted);
        assert_eq!(result.evidence.native, NativeResult::NotCalled);
        assert_eq!(code_of(result), expected);
        assert_eq!(family_of(result), &family);
        assert_eq!(report.submitted_at, None);
    }
}

// The application path.

fn application_call(request: ApplicationRequest) -> NativeCall {
    NativeCall::Application(
        100,
        request,
        BUNDLE.to_owned(),
        b"/Applications/Example.app/Contents/MacOS/Example100".to_vec(),
    )
}

#[test]
fn a_graceful_step_sends_one_request_to_the_application_and_observes_each_member() {
    let host: Host = Host::new().with_process(100, 10).with_process(101, 10);
    let members = vec![member(101, 10, helper()), member(100, 10, application())];
    let envelope = graceful(Escalation::ForceAfterGrace, members.clone());
    let observation = observing(begin(&host, &envelope));
    // The helper gets no call.
    assert_eq!(
        host.calls(),
        vec![application_call(ApplicationRequest::Terminate)]
    );
    assert_eq!(observation.waiting(), 2);
    host.exit(100);
    host.advance(GRACE);
    let report = finished(poll(&host, observation, None));
    let helper_result: &TargetResult = &report.members[0].result;
    assert_eq!(helper_result.effect, TargetEffect::StillRunning);
    assert_eq!(helper_result.dispatch, DispatchState::Submitted);
    // The helper got no call of its own: the request to the application
    // covers it. The force step below still follows it.
    assert_eq!(
        helper_result.evidence.native,
        NativeResult::CoveredByApplicationRequest
    );
    assert_eq!(report.members[1].result.effect, TargetEffect::ExitVerified);
    assert_eq!(
        report.members[1].result.evidence.native,
        NativeResult::Succeeded
    );
    assert_eq!(
        aggregate_step(&report.results()).unwrap(),
        StepState::Partial
    );
    assert_eq!(
        report.next,
        NextStep::Force {
            not_before: MonotonicNanos::new(START + GRACE)
        }
    );

    // The force step kills the listed helper that runs, and it sends no
    // request to the application that exited.
    let results = report.results();
    let after_grace = force(Escalation::ForceAfterGrace, members);
    let receipt = receipt();
    host.change(|world| {
        world.exits_on_call.insert(101);
    });
    let observation = observing(
        host.executor()
            .begin(force_input(&after_grace, &receipt, &report, &results))
            .unwrap(),
    );
    let forced = finished(poll(&host, observation, None));
    assert_eq!(forced.members[0].result.effect, TargetEffect::ExitVerified);
    assert_eq!(forced.members[1].result.effect, TargetEffect::AlreadyExited);
    assert_eq!(
        host.calls(),
        vec![
            application_call(ApplicationRequest::Terminate),
            NativeCall::Signal(101, ProcessSignal::Kill)
        ]
    );
    let mut all = results;
    all.extend(forced.results());
    assert_eq!(aggregate_step(&all).unwrap(), StepState::Completed);
}

#[test]
fn an_immediate_force_step_addresses_the_application_first_and_then_each_listed_helper() {
    let host: Host = Host::new().with_process(100, 10).with_process(101, 10);
    host.change(|world| {
        world.exits_on_call.insert(100);
        world.exits_on_call.insert(101);
    });
    let members = vec![member(101, 10, helper()), member(100, 10, application())];
    let envelope = force(Escalation::ImmediateForce, members);
    let observation = observing(begin(&host, &envelope));
    assert_eq!(
        host.calls(),
        vec![
            application_call(ApplicationRequest::ForceTerminate),
            NativeCall::Signal(101, ProcessSignal::Kill)
        ]
    );
    let report = finished(poll(&host, observation, None));
    for outcome in &report.members {
        assert_eq!(outcome.result.effect, TargetEffect::ExitVerified);
        assert_eq!(outcome.result.attribution, Attribution::Established);
    }
}

#[test]
fn a_helper_gets_no_result_of_a_request_that_was_not_sent() {
    let host: Host = Host::new().with_process(100, 10).with_process(101, 10);
    host.change(|world| {
        world
            .application_results
            .insert(100, ApplicationCallResult::NotRegistered);
    });
    let members = vec![
        member(100, 10, application()),
        member(101, 10, helper()),
        member(102, 10, helper()),
    ];
    let report = finished(begin(&host, &graceful(Escalation::None, members)));
    // The fake records the request before it answers: one call for the
    // application, and no call for a helper.
    assert_eq!(
        host.calls(),
        vec![application_call(ApplicationRequest::Terminate)]
    );
    let running: &TargetResult = &report.members[1].result;
    assert_eq!(running.effect, TargetEffect::Skipped);
    assert_eq!(code_of(running), code::APPLICATION_REQUEST_NOT_SUBMITTED);
    // A helper that does not exist is in its final condition.
    let absent: &TargetResult = &report.members[2].result;
    assert_eq!(absent.effect, TargetEffect::AlreadyExited);
    assert_eq!(absent.dispatch, DispatchState::NotSubmitted);
    assert_eq!(
        aggregate_step(&report.results()).unwrap(),
        StepState::NoAction
    );
}

#[test]
fn an_envelope_rejects_a_membership_that_is_not_verified() {
    // The envelope check rejects such a member, so the executor cannot get
    // one in a checked envelope, so the executor does not run.
    let mut planned: ProcessIdentity = member(100, 10, job());
    planned.association = ProcessAssociation::ManagedJob {
        instance_id: instance(),
        label: "job".to_owned(),
        attribution: AttributionMethod::LaunchServices,
    };
    assert!(
        Checked::new(content(
            ActionClass::RequestApplicationExit,
            Escalation::None,
            vec![planned],
            USER
        ))
        .is_err()
    );
}

// The receipt and the limits.

#[test]
fn a_receipt_that_does_not_permit_a_submission_gives_no_call() {
    let host: Host = Host::new().with_process(100, 10);
    let envelope = graceful(Escalation::None, vec![member(100, 10, job())]);
    for consumption in [
        DispatchConsumption::AlreadyConsumed,
        DispatchConsumption::Fenced,
    ] {
        let receipt = DispatchReceipt {
            consumption,
            durability: Durability::Durable,
        };
        assert_eq!(
            host.executor()
                .begin(input(&envelope, &receipt))
                .unwrap_err(),
            ExecutorError::DispatchNotConsumed(consumption)
        );
    }
    for (durability, refusal) in [
        (Durability::Volatile, RecordingRefusal::DurableRequired),
        (Durability::PersistenceFailed, RecordingRefusal::NoRecord),
    ] {
        let receipt = DispatchReceipt {
            consumption: DispatchConsumption::Consumed,
            durability,
        };
        assert_eq!(
            host.executor()
                .begin(input(&envelope, &receipt))
                .unwrap_err(),
            ExecutorError::Recording(refusal)
        );
    }
    assert_eq!(host.calls(), Vec::new());
    assert_eq!(host.0.borrow().info_queries, 0);
}

#[test]
fn the_limits_of_the_step_are_checked_before_a_call() {
    let members = || vec![member(100, 10, job())];
    let envelope = graceful(Escalation::None, members());

    // At the deadline.
    let host: Host = Host::new().with_process(100, 10);
    host.change(|world| world.now = 800_000_000);
    let report = finished(begin(&host, &envelope));
    let result: &TargetResult = &report.members[0].result;
    assert_eq!(result.effect, TargetEffect::Skipped);
    assert_eq!(result.stop_reason, StopReason::DeadlineExpired);
    assert_eq!(result.failure, None);
    assert_eq!(host.calls(), Vec::new());

    // Before the observation of the evidence.
    let host: Host = Host::new().with_process(100, 10);
    host.change(|world| world.now = 999);
    let report = finished(begin(&host, &envelope));
    assert_all_skipped(
        &host,
        &report,
        code::EVIDENCE_EXPIRED,
        &ErrorFamily::Evidence,
    );

    // After the validity of the evidence.
    let mut expired = content(
        ActionClass::RequestApplicationExit,
        Escalation::None,
        members(),
        USER,
    );
    expired.evidence.valid_until = MonotonicNanos::new(START);
    let host: Host = Host::new().with_process(100, 10);
    let report = finished(begin(&host, &Checked::new(expired).unwrap()));
    assert_all_skipped(
        &host,
        &report,
        code::EVIDENCE_EXPIRED,
        &ErrorFamily::Evidence,
    );

    // An expired lease.
    let mut leased = content(
        ActionClass::RequestApplicationExit,
        Escalation::None,
        members(),
        USER,
    );
    leased.leases[0].expires_at = MonotonicNanos::new(START);
    let host: Host = Host::new().with_process(100, 10);
    let report = finished(begin(&host, &Checked::new(leased).unwrap()));
    assert_all_skipped(&host, &report, code::LEASE_EXPIRED, &ErrorFamily::Limits);

    // A window that has no representable end.
    let mut endless = content(
        ActionClass::RequestApplicationExit,
        Escalation::None,
        members(),
        USER,
    );
    endless.limits.verification_window = Nanoseconds::new(u64::MAX);
    let host: Host = Host::new().with_process(100, 10);
    let report = finished(begin(&host, &Checked::new(endless).unwrap()));
    assert_all_skipped(&host, &report, code::WINDOW_OVERFLOW, &ErrorFamily::Limits);
}

#[test]
fn a_request_of_a_different_executor_lifetime_is_not_executed() {
    let host: Host = Host::new().with_process(100, 10);
    let mut other = context();
    other.executor_epoch = ExecutorEpochId::new("epoch_2").unwrap();
    let executor = ProcessExecutor::new(
        host.clone(),
        host.clone(),
        host.clone(),
        other,
        ExecutorConfig::default(),
    );
    let envelope = graceful(Escalation::None, vec![member(100, 10, job())]);
    let report = finished(executor.begin(input(&envelope, &receipt())).unwrap());
    assert_all_skipped(
        &host,
        &report,
        code::EXECUTOR_CONTEXT_CHANGED,
        &ErrorFamily::Evidence,
    );
}

// Regression tests of the review findings.

#[test]
fn a_process_that_runs_after_a_force_request_is_a_failure() {
    let host: Host = Host::new().with_process(100, 10);
    let envelope = force(Escalation::ImmediateForce, vec![member(100, 10, job())]);
    let observation = observing(begin(&host, &envelope));
    host.advance(WINDOW);
    let report = finished(poll(&host, observation, None));
    let result: &TargetResult = &report.members[0].result;
    assert_eq!(result.effect, TargetEffect::StillRunning);
    assert_eq!(result.dispatch, DispatchState::Submitted);
    assert_eq!(result.stop_reason, StopReason::Failed);
    assert_eq!(code_of(result), code::EXIT_NOT_OBSERVED);
    assert_eq!(family_of(result), &ErrorFamily::Outcome);
    assert_eq!(
        aggregate_step(&report.results()).unwrap(),
        StepState::Failed
    );
}

#[test]
fn a_declined_request_applies_to_each_helper_and_a_force_step_can_follow() {
    let host: Host = Host::new().with_process(100, 10).with_process(101, 10);
    host.change(|world| {
        world
            .application_results
            .insert(100, ApplicationCallResult::Declined);
    });
    let members = vec![member(100, 10, application()), member(101, 10, helper())];
    let envelope = graceful(Escalation::ForceAfterGrace, members.clone());
    let report = finished(begin(&host, &envelope));
    for (outcome, native) in report.members.iter().zip([
        NativeResult::Refused,
        NativeResult::CoveredByApplicationRequest,
    ]) {
        assert_eq!(outcome.result.effect, TargetEffect::Refused);
        assert_eq!(outcome.result.evidence.native, native);
        assert_eq!(code_of(&outcome.result), code::APPLICATION_DECLINED_REQUEST);
        assert_eq!(outcome.state, Some(GenerationState::Running));
    }
    assert_eq!(
        report.next,
        NextStep::Force {
            not_before: MonotonicNanos::new(START + GRACE)
        }
    );
    host.advance(GRACE);
    host.change(|world| {
        world.application_results.clear();
        world.exits_on_call.insert(100);
        world.exits_on_call.insert(101);
    });
    let results = report.results();
    let after_grace = force(Escalation::ForceAfterGrace, members);
    let receipt = receipt();
    let observation = observing(
        host.executor()
            .begin(force_input(&after_grace, &receipt, &report, &results))
            .unwrap(),
    );
    assert_eq!(
        host.calls(),
        vec![
            application_call(ApplicationRequest::Terminate),
            application_call(ApplicationRequest::ForceTerminate),
            NativeCall::Signal(101, ProcessSignal::Kill)
        ]
    );
    let forced = finished(poll(&host, observation, None));
    for outcome in &forced.members {
        assert_eq!(outcome.result.effect, TargetEffect::ExitVerified);
    }
}

#[test]
fn a_declined_request_with_a_failed_reading_records_that_the_process_was_not_read() {
    let host: Host = Host::new().with_process(100, 10);
    host.change(|world| {
        world
            .application_results
            .insert(100, ApplicationCallResult::Declined);
    });
    // The identity check succeeds, and the reading after the call fails.
    let source = FailingAfter {
        host: host.clone(),
        successes: std::cell::Cell::new(2),
    };
    let executor = ProcessExecutor::new(
        source,
        host.clone(),
        host.clone(),
        context(),
        ExecutorConfig::default(),
    );
    let envelope = graceful(Escalation::None, vec![member(100, 10, application())]);
    let report = finished(executor.begin(input(&envelope, &receipt())).unwrap());
    assert_eq!(report.members[0].result.effect, TargetEffect::Refused);
    assert_eq!(
        report.members[0].state,
        Some(GenerationState::Unknown(QueryFailure::Failed(5)))
    );
}

#[test]
fn the_limits_are_checked_again_before_the_call_of_each_member() {
    // Each call takes more time than the step has before its deadline.
    let host: Host = Host::new().with_process(100, 10).with_process(101, 10);
    host.change(|world| world.call_duration = 800_000_000);
    let members = vec![member(100, 10, job()), member(101, 10, job())];
    let observation = observing(begin(&host, &graceful(Escalation::None, members)));
    assert_eq!(host.calls(), vec![NativeCall::Signal(100, TERM)]);
    host.exit(100);
    let report = finished(poll(&host, observation, None));
    assert_eq!(report.members[0].result.effect, TargetEffect::ExitVerified);
    let late: &TargetResult = &report.members[1].result;
    assert_eq!(late.effect, TargetEffect::Skipped);
    assert_eq!(late.dispatch, DispatchState::NotSubmitted);
    assert_eq!(late.stop_reason, StopReason::DeadlineExpired);
}

#[test]
fn a_submission_time_is_never_earlier_than_the_call() {
    let host: Host = Host::new().with_process(100, 10);
    host.change(|world| world.clock_fails_after_call = true);
    let envelope = graceful(Escalation::ForceAfterGrace, vec![member(100, 10, job())]);
    let observation = observing(begin(&host, &envelope));
    // The clock gave no value after the call: the time is not known, and
    // the time of the check before the call is not used.
    assert_eq!(observation.submitted_at(), None);
    assert_eq!(observation.window_ends_at(), MonotonicNanos::new(u64::MAX));
    host.change(|world| {
        world.clock_fails_after_call = false;
        world.clock_fails = false;
        world.now = START + 700;
    });
    let observation = observing(poll(&host, observation, None));
    assert_eq!(
        observation.submitted_at(),
        Some(MonotonicNanos::new(START + 700))
    );
    host.advance(GRACE);
    let report = finished(poll(&host, observation, None));
    assert_eq!(
        report.next,
        NextStep::Force {
            not_before: MonotonicNanos::new(START + 700 + GRACE)
        }
    );

    // With no clock value to the end, the report has no submission time
    // and permits no force step.
    let host: Host = Host::new().with_process(100, 10);
    host.change(|world| world.clock_fails_after_call = true);
    let mut observation = observing(begin(&host, &envelope));
    for _ in 1..MAX_CLOCK_FAILURES {
        observation = observing(poll(&host, observation, None));
    }
    let report = finished(poll(&host, observation, None));
    assert_eq!(report.members[0].result.effect, TargetEffect::StillRunning);
    assert_eq!(report.submitted_at, None);
    assert_eq!(report.next, NextStep::ForceNotPermitted);
}

#[test]
fn a_graceful_record_with_an_unrecognized_value_permits_no_force_call() {
    let host: Host = Host::new().with_process(100, 10);
    let members = vec![member(100, 10, job())];
    let report = graceful_step_to_the_end(&host, members.clone());
    let mut record = report.members[0].result.clone().into_inner();
    record.dispatch = DispatchState::from_wire("queued");
    let results = vec![Checked::new(record).unwrap()];
    let envelope = force(Escalation::ForceAfterGrace, members);
    let receipt = receipt();
    // An unrecognized field is an effect that is not known: the step as a
    // whole is refused before the first call.
    assert_eq!(
        host.executor()
            .begin(force_input(&envelope, &receipt, &report, &results))
            .unwrap_err(),
        ExecutorError::GracefulRecord
    );
    assert_eq!(host.calls(), vec![NativeCall::Signal(100, TERM)]);
}

#[test]
fn an_exec_between_the_two_identity_readings_is_detected() {
    // Each identity reading agrees. The path query shows another
    // executable after the first reading.
    let host: Host = Host::new().with_process(100, 10);
    let source = ChangingPath {
        host: host.clone(),
        readings: std::cell::Cell::new(0),
    };
    let executor = ProcessExecutor::new(
        source,
        host.clone(),
        host.clone(),
        context(),
        ExecutorConfig::default(),
    );
    let envelope = graceful(Escalation::None, vec![member(100, 10, job())]);
    let report = finished(executor.begin(input(&envelope, &receipt())).unwrap());
    assert_eq!(report.members[0].result.effect, TargetEffect::Skipped);
    assert_eq!(
        code_of(&report.members[0].result),
        code::PROCESS_EXECUTABLE_CHANGED
    );
    assert_eq!(host.calls(), Vec::new());
}

#[test]
fn an_owner_that_changes_between_the_two_identity_readings_is_detected() {
    // The path query shows the planned executable, and the process then
    // gets a different owner before the last identity reading.
    let host: Host = Host::new().with_process(100, 10);
    let source = ChangingOwner {
        host: host.clone(),
        readings: std::cell::Cell::new(0),
    };
    let executor = ProcessExecutor::new(
        source,
        host.clone(),
        host.clone(),
        context(),
        ExecutorConfig::default(),
    );
    let envelope = graceful(Escalation::None, vec![member(100, 10, job())]);
    let report = finished(executor.begin(input(&envelope, &receipt())).unwrap());
    assert_eq!(report.members[0].result.effect, TargetEffect::Skipped);
    assert_eq!(
        code_of(&report.members[0].result),
        code::PROCESS_OWNER_CHANGED
    );
    assert_eq!(host.calls(), Vec::new());
}

/// A source whose identity query fails after a number of successes.
#[derive(Debug)]
struct FailingAfter {
    host: Host,
    successes: std::cell::Cell<u32>,
}

/// A source whose second and later identity readings show another owner.
#[derive(Debug)]
struct ChangingOwner {
    host: Host,
    readings: std::cell::Cell<u32>,
}

macro_rules! delegate_source {
    ($name:ident, |$self:ident, $pid:ident| $info:block) => {
        delegate_source!($name, |$self, $pid| $info, |$self, $pid| {
            $self.host.executable_path($pid)
        });
    };
    (
        $name:ident,
        |$self:ident, $pid:ident| $info:block,
        |$pself:ident, $ppid:ident| $path:block
    ) => {
        impl ProcessSource for $name {
            fn effective_uid(&self) -> Uid {
                self.host.effective_uid()
            }
            fn list_pids(&self) -> Result<Vec<Pid>, QueryFailure> {
                self.host.list_pids()
            }
            fn process_info(&$self, $pid: Pid) -> Result<RawProcessInfo, QueryFailure> $info
            fn executable_path(&$pself, $ppid: Pid) -> Result<LosslessPath, QueryFailure> $path
            fn file_evidence(
                &self,
                path: &LosslessPath,
            ) -> Result<FileObjectEvidence, QueryFailure> {
                self.host.file_evidence(path)
            }
            fn usage(&self, pid: Pid) -> Result<RawUsage, QueryFailure> {
                self.host.usage(pid)
            }
            fn responsible_pid(&self, pid: Pid) -> Result<Pid, QueryFailure> {
                self.host.responsible_pid(pid)
            }
            fn application_list_current(&self) -> bool {
                true
            }
            fn running_applications(&self) -> Result<Vec<RunningApplication>, QueryFailure> {
                self.host.running_applications()
            }
            fn timebase(&self) -> Result<Timebase, QueryFailure> {
                self.host.timebase()
            }
            fn monotonic_now(&self) -> Result<MonotonicNanos, QueryFailure> {
                ProcessSource::monotonic_now(&self.host)
            }
            fn sleep_time(&self) -> Result<Nanoseconds, UnavailableReason> {
                self.host.sleep_time()
            }
            fn wall_now(&self) -> Result<WallTime, QueryFailure> {
                ProcessSource::wall_now(&self.host)
            }
        }
    };
}

delegate_source!(FailingAfter, |self, pid| {
    let left: u32 = self.successes.get();
    if left == 0 {
        return Err(QueryFailure::Failed(5));
    }
    self.successes.set(left - 1);
    self.host.process_info(pid)
});

/// A source whose path query shows another executable once an identity
/// reading was made, while each identity reading agrees: an exec between
/// the first identity reading and the path query.
#[derive(Debug)]
struct ChangingPath {
    host: Host,
    readings: std::cell::Cell<u32>,
}

delegate_source!(
    ChangingPath,
    |self, pid| {
        self.readings.set(self.readings.get() + 1);
        self.host.process_info(pid)
    },
    |self, pid| {
        if self.readings.get() > 0 {
            return Ok(LosslessPath::from_bytes(b"/opt/other".to_vec()).unwrap());
        }
        self.host.executable_path(pid)
    }
);

delegate_source!(ChangingOwner, |self, pid| {
    let reading: u32 = self.readings.get();
    self.readings.set(reading + 1);
    let mut info: RawProcessInfo = self.host.process_info(pid)?;
    if reading > 0 {
        info.effective_uid = Uid::new(502);
    }
    Ok(info)
});

// A target of one process with no verified membership.

/// The envelope of a step on the one process `process`, which gets the
/// association `Unattributed`.
fn process_envelope(
    class: ActionClass,
    escalation: Escalation,
    mut process: ProcessIdentity,
) -> RequestEnvelope {
    use svalnir_core::action::{ProcessBinding, TargetBinding};
    let is_force: bool = class == ActionClass::ForceApplicationExit;
    let mut content = content(class, escalation, vec![process.clone()], USER);
    if is_force {
        content.correlation.step_id = svalnir_core::id::StepId::new("step_2").unwrap();
    }
    process.association = ProcessAssociation::Unattributed;
    content.target.binding = TargetBinding::Process(ProcessBinding { process });
    Checked::new(content).unwrap()
}

fn process_graceful(escalation: Escalation, process: ProcessIdentity) -> RequestEnvelope {
    process_envelope(ActionClass::RequestApplicationExit, escalation, process)
}

fn process_force(escalation: Escalation, process: ProcessIdentity) -> RequestEnvelope {
    process_envelope(ActionClass::ForceApplicationExit, escalation, process)
}

#[test]
fn one_process_with_no_membership_gets_one_signal_and_its_exit_is_observed() {
    let host: Host = Host::new().with_process(100, 10);
    let envelope = process_graceful(Escalation::None, member(100, 10, job()));
    let observation = observing(begin(&host, &envelope));
    // One signal to the one process ID: no application request, and no
    // call to a different process.
    assert_eq!(host.calls(), vec![NativeCall::Signal(100, TERM)]);
    assert_eq!(observation.waiting(), 1);
    // The return value of the signal is not the result.
    host.exit(100);
    let report = finished(poll(&host, observation, None));
    let [outcome] = report.members.as_slice() else {
        panic!("a process target has one result");
    };
    assert_eq!(outcome.result.effect, TargetEffect::ExitVerified);
    assert_eq!(outcome.result.dispatch, DispatchState::Submitted);
    assert_eq!(outcome.result.attribution, Attribution::Established);
    assert_eq!(
        outcome.result.member.as_ref(),
        Some(&member(100, 10, job()).generation_id)
    );
    assert_eq!(report.next, NextStep::None);
    assert_eq!(
        aggregate_step(&report.results()).unwrap(),
        StepState::Completed
    );
}

#[test]
fn the_identity_of_one_process_is_checked_immediately_before_each_signal() {
    type Change = fn(&Host);
    let cases: [(Change, &str); 4] = [
        // The PID has a different generation.
        (
            |host| host.change(|world| world.processes.get_mut(&100).unwrap().start_seconds = 20),
            code::PROCESS_REPLACED,
        ),
        // The process replaced its program image.
        (
            |host| {
                host.change(|world| {
                    world.processes.get_mut(&100).unwrap().path = "/opt/other".to_owned();
                });
            },
            code::PROCESS_EXECUTABLE_CHANGED,
        ),
        (
            |host| host.change(|world| world.processes.get_mut(&100).unwrap().inode = 7),
            code::PROCESS_EXECUTABLE_CHANGED,
        ),
        (
            |host| host.change(|world| world.processes.get_mut(&100).unwrap().effective_uid = 0),
            code::PROCESS_OWNER_CHANGED,
        ),
    ];
    for (change, expected) in cases {
        for (class, escalation) in [
            (ActionClass::RequestApplicationExit, Escalation::None),
            (
                ActionClass::ForceApplicationExit,
                Escalation::ImmediateForce,
            ),
        ] {
            let host: Host = Host::new().with_process(100, 10);
            let envelope = process_envelope(class, escalation, member(100, 10, job()));
            change(&host);
            let report = finished(begin(&host, &envelope));
            assert_all_skipped(&host, &report, expected, &ErrorFamily::Evidence);
        }
    }
    // A plan with no executable evidence is not a sealed plan of a process
    // target: the check of the envelope refuses it.
    let mut process: ProcessIdentity = member(100, 10, job());
    process.executable = None;
    let mut bare = content(
        ActionClass::RequestApplicationExit,
        Escalation::None,
        vec![process.clone()],
        USER,
    );
    process.association = ProcessAssociation::Unattributed;
    bare.target.binding =
        svalnir_core::action::TargetBinding::Process(svalnir_core::action::ProcessBinding {
            process,
        });
    assert!(Checked::new(bare).is_err());
}

#[test]
fn a_force_step_of_one_process_follows_its_graceful_step_and_checks_the_identity_again() {
    let host: Host = Host::new().with_process(100, 10);
    let process: ProcessIdentity = member(100, 10, job());
    let envelope = process_graceful(Escalation::ForceAfterGrace, process.clone());
    let observation = observing(begin(&host, &envelope));
    host.advance(GRACE);
    let report = finished(poll(&host, observation, None));
    assert_eq!(report.members[0].result.effect, TargetEffect::StillRunning);
    assert!(matches!(report.next, NextStep::Force { .. }));
    let results = report.results();
    let force_envelope = process_force(Escalation::ForceAfterGrace, process.clone());
    let receipt = receipt();

    // A different generation has the PID at the force step: no signal.
    let replaced: Host = Host::new().with_process(100, 20);
    replaced.change(|world| world.now = host.0.borrow().now);
    let skipped = finished(
        replaced
            .executor()
            .begin(force_input(&force_envelope, &receipt, &report, &results))
            .unwrap(),
    );
    assert_all_skipped(
        &replaced,
        &skipped,
        code::PROCESS_REPLACED,
        &ErrorFamily::Evidence,
    );

    // The planned generation runs: one force signal, and the exit is
    // observed.
    host.change(|world| {
        world.exits_on_call.insert(100);
    });
    let observation = observing(
        host.executor()
            .begin(force_input(&force_envelope, &receipt, &report, &results))
            .unwrap(),
    );
    assert_eq!(
        host.calls(),
        vec![
            NativeCall::Signal(100, TERM),
            NativeCall::Signal(100, ProcessSignal::Kill)
        ]
    );
    let forced = finished(poll(&host, observation, None));
    assert_eq!(forced.members[0].result.effect, TargetEffect::ExitVerified);
    assert_eq!(forced.next, NextStep::None);
}

#[test]
fn a_process_target_with_an_association_is_not_an_envelope_and_gets_no_signal() {
    use svalnir_core::action::{ProcessBinding, TargetBinding};
    // A member of a job, an association kind that this build does not
    // recognize, and an attribution method that it does not recognize:
    // none is a process with no application or job evidence.
    let unknown_method = ProcessAssociation::Application {
        instance_id: instance(),
        bundle_identifier: BUNDLE.to_owned(),
        attribution: AttributionMethod::from_wire("parent_process"),
    };
    for association in [job(), ProcessAssociation::Unrecognized, unknown_method] {
        let mut process: ProcessIdentity = member(100, 10, job());
        let mut content = content(
            ActionClass::ForceApplicationExit,
            Escalation::ImmediateForce,
            vec![process.clone()],
            USER,
        );
        process.association = association;
        content.target.binding = TargetBinding::Process(ProcessBinding { process });
        assert!(Checked::new(content).is_err());
    }
}

#[test]
fn the_hard_refusals_apply_to_a_target_of_one_process() {
    type Setup = fn(&Host) -> ProcessIdentity;
    let cases: [(Setup, &str); 5] = [
        (
            |_| member(OWN_PID, 10, job()),
            code::TARGET_IS_CONTROL_PLANE,
        ),
        (
            |_| member(PARENT_PID, 10, job()),
            code::TARGET_IS_CONTROL_PLANE,
        ),
        (
            |host| {
                host.change(|world| world.own = None);
                member(100, 10, job())
            },
            code::CONTROL_PLANE_UNKNOWN,
        ),
        (
            |_| {
                let mut planned = member(100, 10, job());
                planned.executable.as_mut().unwrap().path =
                    LosslessPath::from_bytes("/bin/sleep").unwrap();
                planned
            },
            code::TARGET_PROTECTED,
        ),
        (
            |_| {
                let mut planned = member(100, 10, job());
                planned.executable.as_mut().unwrap().path =
                    LosslessPath::from_bytes("/opt/bin/svalnir").unwrap();
                planned
            },
            code::TARGET_PROTECTED,
        ),
    ];
    for (setup, expected) in cases {
        let host: Host = Host::new()
            .with_process(100, 10)
            .with_process(OWN_PID, 10)
            .with_process(PARENT_PID, 10);
        let process: ProcessIdentity = setup(&host);
        for envelope in [
            process_graceful(Escalation::None, process.clone()),
            process_graceful(Escalation::ForceAfterGrace, process.clone()),
            process_force(Escalation::ImmediateForce, process.clone()),
        ] {
            let report = finished(begin(&host, &envelope));
            assert_all_skipped(&host, &report, expected, &ErrorFamily::Eligibility);
        }
    }
    // The protection fact of the caller is necessary also.
    for (fact, expected) in [
        (ProtectionFact::Protected, code::TARGET_PROTECTED),
        (ProtectionFact::Unknown, code::TARGET_PROTECTION_UNKNOWN),
    ] {
        let host: Host = Host::new().with_process(100, 10);
        let envelope = process_force(Escalation::ImmediateForce, member(100, 10, job()));
        let protected = StepInput {
            protection: fact,
            ..input(&envelope, durable())
        };
        let report = finished(host.executor().begin(protected).unwrap());
        assert_all_skipped(&host, &report, expected, &ErrorFamily::Eligibility);
    }
}
