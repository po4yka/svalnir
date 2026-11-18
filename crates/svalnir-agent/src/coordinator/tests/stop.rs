//! Cancellation, pause, revocation, and a cleared trigger at each stage
//! of an operation.

use svalnir_core::action::{
    ActionClass, DispatchState, Escalation, Journal as _, OperationState, StepState, StopReason,
    TargetEffect, TriggerClass,
};

use svalnir_core::quantity::EntryCount;

use super::super::{Phase, StopAcknowledgement};
use super::support::{
    Bench, FailPoint, GRACE, START, admitted, allowance, automatic_request, automatic_stop_plan,
    cleanup_plan, incident_id, open_journal, run, stop_plan, stored_request,
};

/// A bench with a running process, an open memory incident, and an
/// automatic force-after-grace plan that is admitted and whose graceful
/// request is submitted.
fn waiting_for_grace() -> (
    Bench,
    Box<super::support::TestCoordinator>,
    svalnir_core::id::OperationId,
) {
    let mut bench = Bench::new();
    let member = bench.host.spawn(4242);
    let incident = incident_id("incident_1");
    bench.authority.open_incident(&incident, bench.clock.now());
    let plan = automatic_stop_plan(
        "plan_1",
        &bench.authority,
        &incident,
        TriggerClass::GlobalCriticalMemory,
        vec![member],
        Escalation::ForceAfterGrace,
        bench.clock.now(),
    );
    let mut coordinator = bench.start();
    let request = automatic_request(&plan, allowance(&incident, coordinator.executor_epoch(), 3));
    let operation_id = admitted(&mut coordinator, request);
    coordinator.step();
    assert_eq!(bench.host.calls().len(), 1);
    (bench, coordinator, operation_id)
}

/// Asserts the result of a graceful request that was submitted, with a
/// target that runs and a force step that `reason` stopped.
fn assert_incomplete(view: &super::super::OperationView, reason: &StopReason) {
    assert_eq!(view.operation.state(), &OperationState::Incomplete);
    assert_eq!(view.operation.dispatch(), DispatchState::Submitted);
    let steps = view.operation.steps();
    assert_eq!(steps[0].progress().state(), &StepState::Incomplete);
    assert_eq!(steps[0].results()[0].effect, TargetEffect::StillRunning);
    assert_eq!(steps[1].progress().state(), &StepState::NoAction);
    assert_eq!(steps[1].results()[0].effect, TargetEffect::Skipped);
    assert_eq!(&steps[1].results()[0].stop_reason, reason);
    assert!(steps[1].results()[0].failure.is_none());
}

#[test]
fn a_pause_during_the_graceful_wait_stops_the_force_step() {
    let (bench, mut coordinator, operation_id) = waiting_for_grace();
    bench.authority.pause(bench.clock.now());
    let view = run(&mut coordinator, &bench.clock, &operation_id);
    // The observation ran to the end of the grace period, and the pause
    // was read at the boundary of the force step.
    assert!(bench.clock.now() >= START + GRACE);
    assert_eq!(bench.host.calls().len(), 1);
    assert_incomplete(&view, &StopReason::Paused);
    assert_eq!(view.stop.unwrap().reason, StopReason::Paused);
    // The slot of the submitted request stays consumed.
    assert_eq!(
        coordinator.remaining_slots(&incident_id("incident_1")),
        Some(2)
    );
}

#[test]
fn a_revoked_grant_during_the_graceful_wait_stops_the_force_step() {
    let (bench, mut coordinator, operation_id) = waiting_for_grace();
    bench.authority.revoke_memory_grant();
    let view = run(&mut coordinator, &bench.clock, &operation_id);
    assert_eq!(bench.host.calls().len(), 1);
    assert_incomplete(&view, &StopReason::AuthorityMissing); // The slot of the submitted graceful request stays consumed.
    assert_eq!(
        coordinator.remaining_slots(&incident_id("incident_1")),
        Some(2)
    );
}

#[test]
fn a_cleared_trigger_before_the_force_step_stops_the_escalation() {
    let (bench, mut coordinator, operation_id) = waiting_for_grace();
    // The incident stays open, and the qualified predicate does not hold.
    bench.authority.records().trigger_holds = Some(false);
    let view = run(&mut coordinator, &bench.clock, &operation_id);
    assert_eq!(bench.host.calls().len(), 1);
    assert_incomplete(&view, &StopReason::TriggerCleared); // The slot of the submitted graceful request stays consumed.
    assert_eq!(
        coordinator.remaining_slots(&incident_id("incident_1")),
        Some(2)
    );
}

#[test]
fn a_grant_change_after_the_intent_and_before_the_call_submits_nothing() {
    let mut bench = Bench::new();
    let member = bench.host.spawn(4242);
    let incident = incident_id("incident_1");
    bench.authority.open_incident(&incident, bench.clock.now());
    let plan = automatic_stop_plan(
        "plan_1",
        &bench.authority,
        &incident,
        TriggerClass::GlobalCriticalMemory,
        vec![member],
        Escalation::None,
        bench.clock.now(),
    );
    let mut coordinator = bench.start();
    let request = automatic_request(&plan, allowance(&incident, coordinator.executor_epoch(), 3));
    let operation_id = admitted(&mut coordinator, request);
    // The grant is revoked after the intent and the dispatch consumption
    // are recorded, and before the final check.
    let authority = bench.authority.clone();
    bench.after_consume(move || authority.revoke_memory_grant());
    let view = run(&mut coordinator, &bench.clock, &operation_id);
    assert_eq!(bench.host.calls(), Vec::new());
    assert_eq!(view.operation.state(), &OperationState::NoAction);
    let step = &view.operation.steps()[0];
    assert_eq!(step.progress().dispatch(), &DispatchState::NotSubmitted);
    assert_eq!(step.results()[0].stop_reason, StopReason::AuthorityMissing);
    // The step stays consumed, and the charge that no call used is not
    // counted against the incident.
    assert_eq!(bench.intents(), 1);
    assert_eq!(coordinator.remaining_slots(&incident), Some(3));
}

#[test]
fn a_cancel_before_the_first_step_settles_with_no_effect() {
    let mut bench = Bench::new();
    let first = bench.tree.file("a");
    let second = bench.tree.file("b");
    let now = bench.clock.now();
    let member = bench.host.spawn(4242);
    let waiting = stop_plan("plan_app", vec![member], Escalation::None, now);
    let plan = cleanup_plan(
        "plan_1",
        &bench.tree,
        &ActionClass::DeleteSelectedFiles,
        &["a", "b"],
        now,
    );
    bench.store(&plan);
    bench.store(&waiting);
    let mut coordinator = bench.start();
    let operation_id = admitted(&mut coordinator, stored_request(&plan));
    let waiting_id = admitted(&mut coordinator, stored_request(&waiting));

    // An operation that waits is settled at once.
    let level = coordinator.cancel(&waiting_id).unwrap();
    assert_eq!(level, StopAcknowledgement::Settled);
    let view = coordinator.operation(&waiting_id).unwrap().unwrap();
    assert_eq!(view.operation.state(), &OperationState::NoAction);
    assert_eq!(bench.host.calls(), Vec::new());

    // The active operation gets a durable fence and settles at its next
    // boundary.
    let level = coordinator.cancel(&operation_id).unwrap();
    assert_eq!(level, StopAcknowledgement::DurableFence);
    let view = run(&mut coordinator, &bench.clock, &operation_id);
    assert_eq!(view.operation.state(), &OperationState::NoAction);
    assert_eq!(
        view.stop.unwrap().acknowledgement,
        StopAcknowledgement::Settled
    );
    assert!(first.exists() && second.exists());
    assert_eq!(bench.intents(), 0);
    for step in view.operation.steps() {
        assert_eq!(step.results()[0].stop_reason, StopReason::Canceled);
    }
    assert!(coordinator.shutdown().is_ok());
}

#[test]
fn a_cancel_after_a_verified_removal_is_a_partial_result() {
    let mut bench = Bench::new();
    let first = bench.tree.file("a");
    let second = bench.tree.file("b");
    let plan = cleanup_plan(
        "plan_1",
        &bench.tree,
        &ActionClass::DeleteSelectedFiles,
        &["a", "b"],
        bench.clock.now(),
    );
    bench.store(&plan);
    let mut coordinator = bench.start();
    let operation_id = admitted(&mut coordinator, stored_request(&plan));
    coordinator.step();
    assert!(!first.exists());
    assert_eq!(
        coordinator.cancel(&operation_id).unwrap(),
        StopAcknowledgement::DurableFence
    );
    let view = run(&mut coordinator, &bench.clock, &operation_id);
    // The removal that was done is not rewritten as not done.
    assert_eq!(view.operation.state(), &OperationState::Partial);
    let steps = view.operation.steps();
    assert_eq!(steps[0].results()[0].effect, TargetEffect::Removed);
    assert_eq!(steps[1].results()[0].effect, TargetEffect::Skipped);
    assert_eq!(steps[1].results()[0].stop_reason, StopReason::Canceled);
    assert!(second.exists());
}

#[test]
fn a_cancel_after_the_intent_and_before_the_call_issues_no_call() {
    let mut bench = Bench::new();
    let file = bench.tree.file("a");
    let plan = cleanup_plan(
        "plan_1",
        &bench.tree,
        &ActionClass::DeleteSelectedFiles,
        &["a"],
        bench.clock.now(),
    );
    bench.store(&plan);
    let mut coordinator = bench.start();
    let operation_id = admitted(&mut coordinator, stored_request(&plan));
    // A different thread requests the stop while the driver is between
    // the dispatch consumption and the call.
    let handle = coordinator.handle();
    let id = operation_id.clone();
    bench.after_consume(move || {
        assert_eq!(handle.cancel(&id), Some(StopAcknowledgement::Received));
    });
    let view = run(&mut coordinator, &bench.clock, &operation_id);
    assert!(file.exists());
    assert_eq!(view.operation.state(), &OperationState::NoAction);
    let step = &view.operation.steps()[0];
    assert_eq!(step.progress().state(), &StepState::NoAction);
    assert_eq!(step.results()[0].stop_reason, StopReason::Canceled);
    // The consumed step stays consumed in the journal.
    assert_eq!(bench.intents(), 1);
}

#[test]
fn a_fence_that_is_not_durable_is_reported_as_a_stop_of_this_instance() {
    let mut bench = Bench::new();
    let file = bench.tree.file("a");
    let plan = cleanup_plan(
        "plan_1",
        &bench.tree,
        &ActionClass::DeleteSelectedFiles,
        &["a"],
        bench.clock.now(),
    );
    bench.store(&plan);
    let mut coordinator = bench.start();
    let operation_id = admitted(&mut coordinator, stored_request(&plan));
    bench.fail(FailPoint::SetStopFence);
    let level = coordinator.cancel(&operation_id).unwrap();
    assert_eq!(level, StopAcknowledgement::CurrentInstance);
    let view = coordinator.operation(&operation_id).unwrap().unwrap();
    assert_eq!(view.phase, Phase::Running);
    assert_eq!(
        view.stop.unwrap().acknowledgement,
        StopAcknowledgement::CurrentInstance
    );
    // The running instance dispatches nothing.
    let view = run(&mut coordinator, &bench.clock, &operation_id);
    assert!(file.exists());
    assert_eq!(view.operation.state(), &OperationState::NoAction);
}

#[test]
fn a_fence_of_a_different_process_stops_the_dispatch() {
    let mut bench = Bench::new();
    let file = bench.tree.file("a");
    let plan = cleanup_plan(
        "plan_1",
        &bench.tree,
        &ActionClass::DeleteSelectedFiles,
        &["a"],
        bench.clock.now(),
    );
    bench.store(&plan);
    let mut coordinator = bench.start();
    let operation_id = admitted(&mut coordinator, stored_request(&plan));
    // A client writes the fence with its own connection.
    open_journal(&bench.tree.database)
        .set_stop_fence(&operation_id)
        .unwrap();
    let view = run(&mut coordinator, &bench.clock, &operation_id);
    assert!(file.exists());
    assert_eq!(view.operation.state(), &OperationState::NoAction);
    assert_eq!(
        view.operation.steps()[0].results()[0].stop_reason,
        StopReason::Canceled
    );
    let stop = view.stop.unwrap();
    assert_eq!(stop.acknowledgement, StopAcknowledgement::Settled);
}

#[test]
fn a_deadline_that_passes_between_two_targets_stops_the_later_target() {
    let mut bench = Bench::new();
    let first = bench.tree.file("a");
    let second = bench.tree.file("b");
    let plan = cleanup_plan(
        "plan_1",
        &bench.tree,
        &ActionClass::DeleteSelectedFiles,
        &["a", "b"],
        bench.clock.now(),
    );
    bench.store(&plan);
    let mut coordinator = bench.start();
    let operation_id = admitted(&mut coordinator, stored_request(&plan));
    coordinator.step();
    assert!(!first.exists());
    // The execution deadline of the plan is 60 seconds after admission.
    bench.clock.advance(61 * super::support::SECOND);
    let view = run(&mut coordinator, &bench.clock, &operation_id);
    assert!(second.exists());
    assert_eq!(view.operation.state(), &OperationState::Partial);
    assert_eq!(
        view.operation.steps()[1].results()[0].stop_reason,
        StopReason::DeadlineExpired
    );
}

/// A filesystem executor that waits inside its call until the test
/// releases it.
#[derive(Debug)]
struct Gate {
    inner: crate::executor::fs::FsExecutor,
    entered: std::sync::Mutex<std::sync::mpsc::Sender<()>>,
    release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
}

impl super::super::FilesystemExecutor for Gate {
    fn execute(
        &self,
        roots: &crate::executor::fs::ApprovedRoots,
        step: crate::executor::fs::AdmittedStep<'_>,
        signal: &dyn crate::executor::fs::StopSignal,
    ) -> crate::executor::fs::StepOutcome {
        self.entered.lock().unwrap().send(()).unwrap();
        self.release.lock().unwrap().recv().unwrap();
        self.inner.execute_step_until(roots, step, signal)
    }
}

#[test]
fn a_query_and_a_cancel_are_answered_while_an_executor_call_runs() {
    let mut bench = Bench::new();
    let first = bench.tree.file("a");
    let second = bench.tree.file("b");
    let plan = cleanup_plan(
        "plan_1",
        &bench.tree,
        &ActionClass::DeleteSelectedFiles,
        &["a", "b"],
        bench.clock.now(),
    );
    bench.store(&plan);
    let (entered_sender, entered) = std::sync::mpsc::channel();
    let (release, release_receiver) = std::sync::mpsc::channel();
    let inner = bench.tree.executor(super::support::TrashMode::Move);
    let started = bench.start_with(|dependencies, _| {
        dependencies.filesystem = Box::new(Gate {
            inner,
            entered: std::sync::Mutex::new(entered_sender),
            release: std::sync::Mutex::new(release_receiver),
        });
    });
    let super::super::Start::Coordinating(mut coordinator) = started else {
        panic!("a different coordinator holds the lock");
    };
    let operation_id = admitted(&mut coordinator, stored_request(&plan));
    let handle = coordinator.handle();
    let clock = bench.clock.clone();
    let id = operation_id.clone();
    // The driver thread goes into the executor call of the first target
    // and stays there.
    let driver = std::thread::spawn(move || run(&mut coordinator, &clock, &id));
    entered.recv().unwrap();
    // The call is in progress. The status and the stop request do not
    // wait for it.
    let view = handle.operation(&operation_id).unwrap();
    assert_eq!(view.phase, Phase::Running);
    assert_eq!(
        handle.cancel(&operation_id),
        Some(StopAcknowledgement::Received)
    );
    assert!(first.exists());
    release.send(()).unwrap();
    // A second executor call then gets no release and does not wait: a
    // cancel that the driver ignored fails the test and does not hang it.
    drop(release);
    let view = driver.join().unwrap();
    // The call that was issued ended with its real result, and the next
    // target was not dispatched.
    assert!(!first.exists());
    assert!(second.exists());
    assert_eq!(view.operation.state(), &OperationState::Partial);
    assert_eq!(
        view.operation.steps()[1].results()[0].stop_reason,
        StopReason::Canceled
    );
    assert_eq!(bench.intents(), 1);
}

/// Makes the directory `name` below the root of `bench`, with one file in
/// each of the directories `children` below it.
fn directory_with(bench: &Bench, name: &str, children: &[&str]) -> Vec<std::path::PathBuf> {
    children
        .iter()
        .map(|child| {
            let directory = bench.tree.root.join(name).join(child);
            std::fs::create_dir_all(&directory).unwrap();
            let file = directory.join("file");
            std::fs::write(&file, b"content").unwrap();
            file
        })
        .collect()
}

#[test]
fn a_cancel_during_the_call_of_a_directory_target_stops_before_its_first_entry() {
    let mut bench = Bench::new();
    let files = directory_with(&bench, "d", &["sub"]);
    let later = bench.tree.file("z");
    let plan = cleanup_plan(
        "plan_1",
        &bench.tree,
        &ActionClass::DeleteSelectedFiles,
        &["d", "z"],
        bench.clock.now(),
    );
    bench.store(&plan);
    let (entered_sender, entered) = std::sync::mpsc::channel();
    let (release, release_receiver) = std::sync::mpsc::channel();
    let inner = bench.tree.executor(super::support::TrashMode::Move);
    let started = bench.start_with(|dependencies, _| {
        dependencies.filesystem = Box::new(Gate {
            inner,
            entered: std::sync::Mutex::new(entered_sender),
            release: std::sync::Mutex::new(release_receiver),
        });
    });
    let super::super::Start::Coordinating(mut coordinator) = started else {
        panic!("a different coordinator holds the lock");
    };
    let operation_id = admitted(&mut coordinator, stored_request(&plan));
    let handle = coordinator.handle();
    let clock = bench.clock.clone();
    let id = operation_id.clone();
    let driver = std::thread::spawn(move || run(&mut coordinator, &clock, &id));
    entered.recv().unwrap();
    // The final check of the step passed. The cancel arrives while the
    // executor call is in progress, before the first entry of the tree.
    assert_eq!(
        handle.cancel(&operation_id),
        Some(StopAcknowledgement::Received)
    );
    release.send(()).unwrap();
    drop(release);
    let view = driver.join().unwrap();
    // The executor read the stop signal before the directory `sub` and
    // issued no call.
    assert!(files[0].exists());
    assert!(later.exists());
    let result = &view.operation.steps()[0].results()[0];
    assert_eq!(result.effect, TargetEffect::Skipped);
    assert_eq!(result.dispatch, DispatchState::NotSubmitted);
    assert_eq!(result.stop_reason, StopReason::Canceled);
    assert_eq!(
        view.operation.steps()[1].results()[0].stop_reason,
        StopReason::Canceled
    );
    assert_eq!(view.operation.state(), &OperationState::NoAction);
    assert_eq!(bench.intents(), 1);
}

/// A filesystem executor whose stop signal gets a cancel of the operation
/// immediately before its second reading.
#[derive(Debug)]
struct CancelInside {
    inner: crate::executor::fs::FsExecutor,
    cancel: std::sync::Arc<
        std::sync::Mutex<
            Option<(
                super::super::CoordinatorHandle,
                svalnir_core::id::OperationId,
            )>,
        >,
    >,
    readings: std::sync::atomic::AtomicUsize,
}

impl super::super::FilesystemExecutor for CancelInside {
    fn execute(
        &self,
        roots: &crate::executor::fs::ApprovedRoots,
        step: crate::executor::fs::AdmittedStep<'_>,
        inner_signal: &dyn crate::executor::fs::StopSignal,
    ) -> crate::executor::fs::StepOutcome {
        let signal = || {
            let reading = self
                .readings
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if reading == 1
                && let Some((handle, operation_id)) = self.cancel.lock().unwrap().as_ref()
            {
                handle.cancel(operation_id);
            }
            inner_signal.check()
        };
        self.inner.execute_step_until(roots, step, &signal)
    }
}

#[test]
fn a_cancel_between_two_entries_of_a_directory_target_leaves_the_rest_of_the_tree() {
    let mut bench = Bench::new();
    let files = directory_with(&bench, "d", &["one", "two"]);
    let later = bench.tree.file("z");
    let plan = cleanup_plan(
        "plan_1",
        &bench.tree,
        &ActionClass::DeleteSelectedFiles,
        &["d", "z"],
        bench.clock.now(),
    );
    bench.store(&plan);
    let cancel = std::sync::Arc::new(std::sync::Mutex::new(None));
    let inner = bench.tree.executor(super::support::TrashMode::Move);
    let shared = std::sync::Arc::clone(&cancel);
    let started = bench.start_with(|dependencies, _| {
        dependencies.filesystem = Box::new(CancelInside {
            inner,
            cancel: shared,
            readings: std::sync::atomic::AtomicUsize::new(0),
        });
    });
    let super::super::Start::Coordinating(mut coordinator) = started else {
        panic!("a different coordinator holds the lock");
    };
    let operation_id = admitted(&mut coordinator, stored_request(&plan));
    let handle = coordinator.handle();
    *cancel.lock().unwrap() = Some((handle, operation_id.clone()));
    let view = run(&mut coordinator, &bench.clock, &operation_id);
    // The executor removed the first directory of the tree, read the
    // stop, and issued no further call.
    assert_eq!(files.iter().filter(|file| file.exists()).count(), 1);
    assert!(bench.tree.root.join("d").exists());
    assert!(later.exists());
    let result = &view.operation.steps()[0].results()[0];
    assert_eq!(result.effect, TargetEffect::UnknownOutcome);
    assert_eq!(result.dispatch, DispatchState::Submitted);
    assert_eq!(result.stop_reason, StopReason::Canceled);
    assert!(result.failure.is_none());
    // The later target got no dispatch.
    assert_eq!(
        view.operation.steps()[1].results()[0].stop_reason,
        StopReason::Canceled
    );
    assert_eq!(view.operation.state(), &OperationState::UnknownOutcome);
    assert_eq!(bench.intents(), 1);
    // The work of the removed part stays in the totals.
    assert!(view.work.removed_entries > EntryCount::ZERO);
}
