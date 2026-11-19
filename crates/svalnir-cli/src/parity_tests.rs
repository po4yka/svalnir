//! End-to-end tests of the two behaviors that the CLI shares with the
//! GPUI client: the stop of a group with a verified membership
//! (`processes stop --group`), and the cancel through the request queue
//! of the journal (`operations cancel`).
//!
//! A child of a test has no application and no job membership on the
//! host. A test gives disposable children of its own a verified managed-job
//! membership with the `process_reading` seam, so the plan binds them as
//! the members of one instance; the executor then signals each of them
//! directly, after it checks the identity of each one again. A stop
//! signals only children that the test started. A cancel test uses a
//! test thread in the place of the agent; it changes only the journal of
//! the test.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use svalnir_agent::journal::{
    CoordinatorLock, CoordinatorRole, JournalOptions, OperationJournal, RequestBody,
    RequestCompletion, RequestStatus,
};
use svalnir_agent::platform::process::{ProcessSnapshot, generation_id};
use svalnir_core::action::{
    ActionError, ActionStage, ClientRole, DispatchState, ErrorCode, ErrorFamily, Journal as _,
    StopFence, TargetBinding,
};
use svalnir_core::id::{ApplicationInstanceId, OperationId, PlanId, RequestId};
use svalnir_core::process::{AttributionMethod, Pid, ProcessAssociation, ProcessStartTime};

use crate::environment::Environment;
use crate::intervention_tests::{
    ChildGuard, Outcome, World, json, run, serve_one_rearm, spawn_child, world_for_stop,
};
use crate::output::ExitStatus;
use crate::seams::{ProcessReading, WhileAsked};

/// Gives the processes `members` a verified managed-job membership in the
/// instance `instance` in each process reading of `processes stop`. The
/// reading of `replaced`, when it is given, has a different start time, as
/// for a process that the host replaced at the same PID after the reading.
fn give_membership(
    environment: &mut Environment,
    instance: &str,
    members: Vec<Pid>,
    replaced: Option<Pid>,
) {
    let instance: ApplicationInstanceId = ApplicationInstanceId::new(instance).unwrap();
    environment.seams.test.process_reading = Some(ProcessReading(Arc::new(
        move |snapshot: &mut ProcessSnapshot| {
            for record in &mut snapshot.records {
                let identity = &mut record.identity;
                if !members.contains(&identity.pid) {
                    continue;
                }
                identity.association = ProcessAssociation::ManagedJob {
                    instance_id: instance.clone(),
                    label: "dev.po4yka.svalnir.test-group".to_owned(),
                    attribution: AttributionMethod::LaunchdJob,
                };
                if Some(identity.pid) == replaced {
                    identity.start_time = ProcessStartTime::new(identity.start_time.get() + 1);
                    identity.generation_id =
                        generation_id(identity.pid, identity.start_time).unwrap();
                }
            }
        },
    )));
}

fn instance_of(child: &ChildGuard) -> String {
    format!("job-test-{}", child.pid().get())
}

fn this_process() -> Pid {
    Pid::new(i32::try_from(std::process::id()).unwrap()).unwrap()
}

fn stop_group(environment: &Environment, instance: &str, more: &[&str]) -> Outcome {
    let mut arguments: Vec<&str> = vec!["processes", "stop", "--group", instance];
    arguments.extend_from_slice(more);
    json(environment, &arguments)
}

/// The members of the target results, with their effects.
fn effects(outcome: &Outcome) -> Vec<(String, String)> {
    let mut effects: Vec<(String, String)> = outcome.result()["operation"]["target_results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|result| {
            (
                result["member"].as_str().unwrap_or_default().to_owned(),
                result["effect"].as_str().unwrap_or_default().to_owned(),
            )
        })
        .collect();
    effects.sort();
    effects
}

#[test]
fn a_group_stop_binds_each_verified_member_and_no_process_of_the_same_name() {
    let mut world: World = world_for_stop();
    let mut first: ChildGuard = spawn_child(false);
    let mut second: ChildGuard = spawn_child(false);
    // The same executable and the same name, with no membership.
    let mut other: ChildGuard = spawn_child(false);
    let instance: String = instance_of(&first);
    let (first_target, second_target) = (first.target(), second.target());
    give_membership(
        &mut world.environment,
        &instance,
        vec![first.pid(), second.pid()],
        None,
    );
    let stop = stop_group(&world.environment, &instance, &["--grace", "10s", "--yes"]);
    assert_eq!(
        stop.status,
        ExitStatus::Success,
        "{} {}",
        stop.stdout,
        stop.stderr
    );
    let result = stop.result();
    assert_eq!(result["wait"], "finished");
    assert_eq!(result["operation"]["state"], "Completed", "{}", stop.stdout);
    assert_eq!(result["operation"]["effects"]["exit_verified"], 2);
    let mut expected = vec![
        (first_target, "ExitVerified".to_owned()),
        (second_target, "ExitVerified".to_owned()),
    ];
    expected.sort();
    assert_eq!(effects(&stop), expected);
    assert!(first.has_exited());
    assert!(second.has_exited());
    assert!(!other.has_exited());

    // The plan has one application target with the two members.
    let journal = crate::commands::session::open_journal(&world.environment)
        .ok()
        .unwrap();
    let plan_id = PlanId::new(result["plan_id"].as_str().unwrap()).unwrap();
    let plan = journal.plan(&plan_id).unwrap().unwrap();
    let [bound] = plan.targets.as_slice() else {
        panic!("a stop plan has one target");
    };
    let TargetBinding::Application(binding) = &bound.binding else {
        panic!("the group is not an application target");
    };
    assert_eq!(binding.instance_id.as_str(), instance);
    assert_eq!(binding.members.len(), 2);
    drop(journal);

    // The operation is settled, so a repeated request reads the group
    // again. Its members are gone: no second plan and no second signal.
    let again = stop_group(&world.environment, &instance, &["--grace", "10s", "--yes"]);
    assert_eq!(again.error_code(), "group_not_found", "{}", again.stdout);
    let history = json(&world.environment, &["history"]);
    assert_eq!(history.result()["records"].as_array().unwrap().len(), 1);
}

#[test]
fn a_member_that_joins_after_a_settled_group_stop_is_in_the_next_plan() {
    let mut world: World = world_for_stop();
    // The first member ignores the request to exit, so the graceful stop
    // settles with the member still running.
    let mut first: ChildGuard = spawn_child(true);
    let mut later: ChildGuard = spawn_child(false);
    let instance: String = instance_of(&first);
    let later_target: String = later.target();
    give_membership(&mut world.environment, &instance, vec![first.pid()], None);
    let stop = stop_group(&world.environment, &instance, &["--grace", "1s", "--yes"]);
    assert_eq!(stop.status, ExitStatus::Partial, "{}", stop.stdout);
    assert_eq!(stop.result()["operation"]["state"], "Incomplete");
    let first_plan = stop.result()["plan_id"].clone();

    // A second process joins the instance. The same request makes a new
    // plan from a new reading, with both members.
    give_membership(
        &mut world.environment,
        &instance,
        vec![first.pid(), later.pid()],
        None,
    );
    let again = stop_group(&world.environment, &instance, &["--grace", "1s", "--yes"]);
    let result = again.result();
    assert_ne!(result["plan_id"], first_plan, "{}", again.stdout);
    assert_eq!(result["existing_operation"], false);
    assert!(
        effects(&again)
            .iter()
            .any(|(member, effect)| member == &later_target && effect == "ExitVerified"),
        "{}",
        again.stdout
    );
    assert!(later.has_exited());
    assert!(!first.has_exited());
}

#[test]
fn a_group_stop_has_a_text_form_and_a_question_that_name_the_group() {
    let mut world: World = world_for_stop();
    let mut first: ChildGuard = spawn_child(false);
    let target: String = first.target();
    let instance: String = instance_of(&first);
    give_membership(&mut world.environment, &instance, vec![first.pid()], None);
    // The question names the group and each bound process. A "no" sends
    // no signal.
    world.environment.seams.test.answers =
        Some(Arc::new(Mutex::new(std::collections::VecDeque::from([
            "no".to_owned(),
        ]))));
    let declined = run(
        &world.environment,
        &["processes", "stop", "--group", &instance, "--grace", "10s"],
    );
    assert_ne!(declined.status, ExitStatus::Success, "{}", declined.stderr);
    assert!(
        declined.stderr.contains(&format!("instance {instance}")),
        "{}",
        declined.stderr
    );
    assert!(declined.stderr.contains(&target), "{}", declined.stderr);
    assert!(!first.has_exited());
    world.environment.seams.test.answers = None;
    let stop = run(
        &world.environment,
        &[
            "processes",
            "stop",
            "--group",
            &instance,
            "--grace",
            "10s",
            "--yes",
        ],
    );
    assert_eq!(stop.status, ExitStatus::Success, "{}", stop.stderr);
    assert!(stop.stdout.contains("): Completed"), "{}", stop.stdout);
    assert!(stop.stdout.contains(&target), "{}", stop.stdout);
    assert!(first.has_exited());
}

#[test]
fn a_member_that_exits_before_the_signal_is_recorded_as_already_exited() {
    let mut world: World = world_for_stop();
    let mut first: ChildGuard = spawn_child(false);
    let second: ChildGuard = spawn_child(false);
    let first_target: String = first.target();
    let second_target: String = second.target();
    let instance: String = instance_of(&first);
    give_membership(
        &mut world.environment,
        &instance,
        vec![first.pid(), second.pid()],
        None,
    );
    // The second member exits after the plan and before the approval.
    let held: Arc<Mutex<Option<ChildGuard>>> = Arc::new(Mutex::new(Some(second)));
    world.environment.seams.test.answers =
        Some(Arc::new(Mutex::new(std::collections::VecDeque::from([
            "yes".to_owned(),
        ]))));
    world.environment.seams.test.while_asked = Some(WhileAsked(Arc::new({
        let held = Arc::clone(&held);
        move || drop(held.lock().unwrap().take())
    })));
    let stop = stop_group(&world.environment, &instance, &["--grace", "10s"]);
    assert!(held.lock().unwrap().is_none(), "the question was not asked");
    assert_eq!(
        stop.status,
        ExitStatus::Success,
        "{} {}",
        stop.stdout,
        stop.stderr
    );
    let mut expected = vec![
        (first_target, "ExitVerified".to_owned()),
        (second_target, "AlreadyExited".to_owned()),
    ];
    expected.sort();
    assert_eq!(effects(&stop), expected, "{}", stop.stdout);
    assert!(first.has_exited());
}

#[test]
fn a_member_whose_identity_changed_after_the_plan_gets_no_signal() {
    let mut world: World = world_for_stop();
    let mut first: ChildGuard = spawn_child(false);
    let mut second: ChildGuard = spawn_child(false);
    let instance: String = instance_of(&first);
    let first_target: String = first.target();
    // The plan binds a generation of the second PID that the host does
    // not have at the signal.
    give_membership(
        &mut world.environment,
        &instance,
        vec![first.pid(), second.pid()],
        Some(second.pid()),
    );
    let stop = stop_group(&world.environment, &instance, &["--grace", "2s", "--yes"]);
    let result = stop.result();
    let results = result["operation"]["target_results"].as_array().unwrap();
    let replaced = results
        .iter()
        .find(|result| result["member"] != first_target.as_str())
        .unwrap();
    // The check before the call found a different generation: no call.
    assert_eq!(replaced["effect"], "Skipped", "{}", stop.stdout);
    assert_eq!(replaced["failure"]["code"], "process_replaced");
    assert_eq!(replaced["dispatch"], "not_submitted");
    assert_eq!(replaced["evidence"]["native"]["kind"], "not_called");
    // The process at the PID is not the planned generation: it stays.
    assert!(!second.has_exited(), "{}", stop.stdout);
    assert!(first.has_exited(), "{}", stop.stdout);
    assert_eq!(stop.status, ExitStatus::Partial, "{}", stop.stdout);
}

#[test]
fn a_plan_that_expires_while_the_question_waits_signals_no_member() {
    let mut world: World = World::new();
    world.activate(
        "schema_version = 1\n\n[agent]\nmanual_plan_ttl = \"1s\"\n",
        "none",
    );
    let mut first: ChildGuard = spawn_child(false);
    let instance: String = instance_of(&first);
    give_membership(&mut world.environment, &instance, vec![first.pid()], None);
    world.environment.seams.test.answers =
        Some(Arc::new(Mutex::new(std::collections::VecDeque::from([
            "yes".to_owned(),
        ]))));
    world.environment.seams.test.while_asked = Some(WhileAsked(Arc::new(|| {
        std::thread::sleep(Duration::from_millis(1500));
    })));
    let stop = stop_group(&world.environment, &instance, &["--grace", "10s"]);
    assert_eq!(stop.error_code(), "plan_expired", "{}", stop.stdout);
    assert_eq!(stop.status, ExitStatus::Conflict);
    let expired: String = stop.envelope()["error"]["plan_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(!first.has_exited());
    let history = json(&world.environment, &["history"]);
    assert_eq!(history.result()["records"], serde_json::json!([]));

    // The expired plan was never applied, so a new request makes a new
    // plan and does not use the stale one.
    world.environment.seams.test.while_asked = None;
    world.environment.seams.test.answers = None;
    let again = stop_group(&world.environment, &instance, &["--grace", "10s", "--yes"]);
    assert_eq!(again.status, ExitStatus::Success, "{}", again.stdout);
    assert_ne!(again.result()["plan_id"], expired.as_str());
    assert_eq!(again.result()["existing_operation"], false);
    assert!(first.has_exited());
}

#[test]
fn a_group_with_no_verified_member_and_a_protected_group_are_refused() {
    let mut world: World = world_for_stop();
    let mut first: ChildGuard = spawn_child(false);
    let instance: String = instance_of(&first);
    // With no membership evidence, a process of the same name is no group.
    let absent = stop_group(&world.environment, &instance, &["--yes"]);
    assert_eq!(absent.error_code(), "group_not_found", "{}", absent.stdout);
    assert_eq!(absent.status, ExitStatus::Conflict);
    assert_eq!(absent.envelope()["error"]["fields"][0], "group");

    // A group with this client in it is protected as a whole.
    give_membership(
        &mut world.environment,
        &instance,
        vec![first.pid(), this_process()],
        None,
    );
    let protected = stop_group(&world.environment, &instance, &["--force", "--yes"]);
    assert_eq!(
        protected.error_code(),
        "target_protected",
        "{}",
        protected.stdout
    );
    assert!(!first.has_exited());
}

/// A world with one operation that is not settled: a move to the Trash
/// whose effect is not known, so the operation is `UnknownOutcome`.
fn unsettled_operation() -> (World, String, PathBuf) {
    let (mut world, _tree, plan) = World::with_plan("trash");
    world.environment.seams.test.trash_gives_no_result = true;
    let apply = json(
        &world.environment,
        &["clean", "apply", "--plan", &plan, "--yes"],
    );
    let operation: String = apply.result()["operation"]["operation_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(apply.result()["operation"]["state"], "UnknownOutcome");
    let journal: PathBuf = world.path("state").join("operations.sqlite");
    (world, operation, journal)
}

fn request_status(journal: &Path, request: &str) -> Option<RequestStatus> {
    OperationJournal::open(journal, &JournalOptions::default())
        .unwrap()
        .request_status(&RequestId::new(request).unwrap())
        .unwrap()
}

fn cancel(environment: &Environment, operation: &str, more: &[&str]) -> Outcome {
    let mut arguments: Vec<&str> = vec!["operations", "cancel", "--operation", operation];
    arguments.extend_from_slice(more);
    json(environment, &arguments)
}

#[test]
fn a_cancel_with_an_agent_goes_to_the_queue_and_the_agent_decides_it() {
    let (world, operation, journal) = unsettled_operation();
    let (claimed, handle) = serve_one_rearm(
        journal,
        RequestCompletion::Stopped {
            fence: StopFence::Durable,
        },
    );
    let outcome = cancel(&world.environment, &operation, &[]);
    handle.join().unwrap();
    let request = claimed.recv().unwrap();
    assert_eq!(outcome.status, ExitStatus::Success, "{}", outcome.stdout);
    let result = outcome.result();
    assert_eq!(result["path"], "request_queue");
    assert_eq!(result["fence_written"], true);
    assert_eq!(result["acknowledgement"], "durable_stop_fence");
    assert_eq!(result["request_id"], request.request_id.as_str());
    assert_eq!(request.principal.role, ClientRole::Cli);
    assert_eq!(
        request.body,
        RequestBody::Cancel {
            operation_id: OperationId::new(operation.as_str()).unwrap(),
        }
    );
}

#[test]
fn a_cancel_that_the_agent_stops_only_in_its_executor_is_not_durable() {
    let (world, operation, journal) = unsettled_operation();
    let (_claimed, handle) = serve_one_rearm(
        journal,
        RequestCompletion::Stopped {
            fence: StopFence::CurrentInstance,
        },
    );
    let outcome = cancel(&world.environment, &operation, &[]);
    handle.join().unwrap();
    assert_eq!(outcome.status, ExitStatus::Success, "{}", outcome.stdout);
    let result = outcome.result();
    assert_eq!(result["acknowledgement"], "current_instance");
    assert_eq!(result["fence_written"], false);
    let text = run(
        &world.environment,
        &["operations", "show", "--operation", &operation],
    );
    assert_eq!(text.status, ExitStatus::Success);
}

#[test]
fn a_cancel_that_the_agent_refuses_reports_the_code_of_the_agent() {
    let (world, operation, journal) = unsettled_operation();
    let (_claimed, handle) = serve_one_rearm(
        journal,
        RequestCompletion::Rejected {
            error: ActionError {
                code: ErrorCode::new("principal_mismatch").unwrap(),
                family: ErrorFamily::Authority,
                stage: ActionStage::Admission,
                dispatch: DispatchState::NotSubmitted,
                plan_id: None,
                operation_id: None,
                step_id: None,
            },
        },
    );
    let outcome = cancel(&world.environment, &operation, &[]);
    handle.join().unwrap();
    assert_eq!(
        outcome.error_code(),
        "principal_mismatch",
        "{}",
        outcome.stdout
    );
    assert_ne!(outcome.status, ExitStatus::Success);
    assert_eq!(outcome.envelope()["error"]["operation_id"], operation);
    // The refused request wrote no fence.
    let show = json(
        &world.environment,
        &["operations", "show", "--operation", &operation],
    );
    assert_eq!(
        show.result()["operation"]["stop"]["durable_stop_fence"],
        false,
        "{}",
        show.stdout
    );
}

#[test]
fn a_cancel_that_the_agent_does_not_answer_in_the_wait_writes_the_fence() {
    let (world, operation, journal) = unsettled_operation();
    // A holder of the lock that serves no request, in place of an agent.
    let lock = CoordinatorLock::try_acquire(&journal, CoordinatorRole::Agent).unwrap();
    let started: Instant = Instant::now();
    let outcome = cancel(&world.environment, &operation, &["--timeout", "1s"]);
    assert!(started.elapsed() < Duration::from_secs(8));
    assert_eq!(outcome.status, ExitStatus::Success, "{}", outcome.stdout);
    // `--timeout` applies to the command.
    assert_eq!(outcome.envelope()["warnings"], serde_json::json!([]));
    let result = outcome.result();
    assert_eq!(result["path"], "stop_fence");
    assert_eq!(result["fence_written"], true);
    assert_eq!(result["acknowledgement"], "durable_stop_fence");
    let request: String = result["request_id"].as_str().unwrap().to_owned();
    assert!(
        result["notes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|note| note.as_str().unwrap().contains("did not serve")),
        "{result}"
    );
    // The request stays in the queue for the agent.
    assert_eq!(
        request_status(&journal, &request),
        Some(RequestStatus::Queued)
    );
    drop(lock);
    let show = json(
        &world.environment,
        &["operations", "show", "--operation", &operation],
    );
    assert_eq!(
        show.result()["operation"]["stop"]["durable_stop_fence"],
        true
    );
}

#[test]
fn a_cancel_with_no_agent_writes_the_fence_and_no_request() {
    let (world, operation, journal) = unsettled_operation();
    let outcome = cancel(&world.environment, &operation, &[]);
    assert_eq!(outcome.status, ExitStatus::Success, "{}", outcome.stdout);
    let result = outcome.result();
    assert_eq!(result["path"], "stop_fence");
    assert_eq!(result["fence_written"], true);
    assert!(result["request_id"].is_null());
    assert_eq!(result["coordinator"], "not_running");

    // A client that holds the lock is not an agent: the client writes the
    // fence, and the queue gets no request.
    let lock = CoordinatorLock::try_acquire(&journal, CoordinatorRole::Client).unwrap();
    let again = cancel(&world.environment, &operation, &[]);
    assert_eq!(again.status, ExitStatus::Success, "{}", again.stdout);
    assert_eq!(again.result()["path"], "stop_fence");
    assert!(again.result()["request_id"].is_null());
    let request: String = again.envelope()["request_id"].as_str().unwrap().to_owned();
    assert_eq!(request_status(&journal, &request), None);
    drop(lock);
}

#[test]
fn a_cancel_of_a_completed_operation_sends_nothing_also_with_an_agent() {
    let (world, _tree, plan) = World::with_plan("permanent");
    let apply = json(
        &world.environment,
        &["clean", "apply", "--plan", &plan, "--yes"],
    );
    let operation: String = apply.result()["operation"]["operation_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let journal: PathBuf = world.path("state").join("operations.sqlite");
    let lock = CoordinatorLock::try_acquire(&journal, CoordinatorRole::Agent).unwrap();
    let started: Instant = Instant::now();
    let outcome = cancel(&world.environment, &operation, &[]);
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(outcome.status, ExitStatus::Success, "{}", outcome.stdout);
    let result = outcome.result();
    assert_eq!(result["acknowledgement"], "settled");
    assert_eq!(result["path"], "none");
    assert_eq!(result["fence_written"], false);
    assert!(result["request_id"].is_null());
    let request: String = outcome.envelope()["request_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(request_status(&journal, &request), None);
    drop(lock);
}
