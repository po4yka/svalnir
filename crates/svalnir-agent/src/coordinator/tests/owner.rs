//! The owner operation through the coordinator (`docs/ACTION_CONTRACTS.md`
//! section 7, the subsection of `RunOwnerOperation`).
//!
//! The producer of each test is a shell script that the test writes in its
//! temporary directory, with the owner and the mode that the owner
//! executor accepts. The script changes only the scope root below that
//! directory and a file of runs in the home directory of the tree. No test
//! runs a real producer tool.

use std::fs;
use std::path::{Path, PathBuf};

use svalnir_core::action::{
    ActionClass, ClientRole, OperationState, OwnerOperationBinding, OwnerOperationKind, Plan,
    PlanError, PlanTarget, PlannedStep, ResourceEffect, TargetBinding, TargetEffect, Trigger,
    TriggerClass,
};
use svalnir_core::authority::Generation;
use svalnir_core::id::{DecisionId, IncidentId, OperationId, RootId, StepId, TargetId};
use svalnir_core::quantity::{ByteDelta, Nanoseconds};
use svalnir_core::rule::owner::OwnerOperation;

use super::super::{ApplyOutcome, OperationView, code};
use super::support::{
    Bench, FailPoint, NoRules, ROOT_ID, SECOND, admitted, base_content, cleanup_plan, open_journal,
    refusal, stored_request,
};
use crate::executor::fs::ApprovedRoot;
use crate::executor::owner::{ScopeLimits, code as owner_code};
use crate::rules::fixture::{
    manual_action_validated, owner_fixture_declaration, owner_fixture_rule, write_owner_script,
};
use crate::rules::in_use::UnitUse;
use crate::rules::owner_operation::{OwnerBindError, OwnerBindRequest, bind_owner_operation};
use crate::scan::{CancellationToken, WallScanClock};
use svalnir_core::action::Journal as _;

/// The script of a producer that records its run and removes the package
/// entries of its scope.
const PRUNE: &str = "echo \"$1\" >> \"$HOME/runs\"\nrm -f \"$2\"/pkg/*\necho \"pruned in $HOME\"";

/// A bench whose registry has the fixture rule of an owner operation with a
/// lifecycle state that permits a manual action, a scope root with three
/// package entries, and the producer script `body`.
fn owner_bench(body: &str) -> (Bench, PathBuf) {
    owner_bench_with(body, 30 * SECOND)
}

/// [`owner_bench`] with the command deadline `deadline` in the reviewed
/// declaration of the registry, which admission compares with the plan.
/// The protected locations name the home directory of the tree, which the
/// coordinator uses to make the command again.
fn owner_bench_with(body: &str, deadline: u64) -> (Bench, PathBuf) {
    let bench: Bench = Bench::new();
    let package: PathBuf = bench.tree.root.join("pkg");
    fs::create_dir(&package).unwrap();
    for name in ["a", "b", "c"] {
        fs::write(package.join(name), vec![7_u8; 9_000]).unwrap();
    }
    let tools: PathBuf = bench.tree.base().join("tools");
    fs::create_dir(&tools).unwrap();
    let script: PathBuf = write_owner_script(&tools, "producer", body).unwrap();
    {
        let mut records = bench.authority.records();
        records.registry = NoRules(
            None,
            vec![owner_fixture_rule(manual_action_validated()).unwrap()],
            vec![declaration(&script, deadline)],
        );
        records.locations = crate::protection::ProtectedLocations::from_resolved(
            Some(bench.tree.home().to_path_buf()),
            Some(PathBuf::from("/svalnir-test-no-state")),
        );
    }
    (bench, script)
}

/// Runs the coordinator until the operation is finished. The worker of an
/// owner step runs in real time, so each turn waits 5 ms and moves the
/// clock of the test by the same time.
fn run_owner(
    coordinator: &mut super::support::TestCoordinator,
    bench: &Bench,
    operation_id: &OperationId,
) -> OperationView {
    for _ in 0..12_000 {
        let view: OperationView = coordinator.operation(operation_id).unwrap().unwrap();
        if view.phase == super::super::Phase::Finished {
            return view;
        }
        let progress = coordinator.step();
        if !progress.worked {
            std::thread::sleep(std::time::Duration::from_millis(5));
            bench.clock.advance(SECOND / 200);
        }
    }
    panic!("the operation did not finish");
}

fn declaration(script: &Path, deadline: u64) -> OwnerOperation {
    owner_fixture_declaration(script, Nanoseconds::new(deadline)).unwrap()
}

/// The binding of the scope root of the tree for `kind`.
fn binding(
    bench: &Bench,
    declaration: &OwnerOperation,
    kind: OwnerOperationKind,
) -> Result<OwnerOperationBinding, OwnerBindError> {
    let roots = bench.tree.roots();
    let scope: &ApprovedRoot = roots.root(&RootId::new(ROOT_ID).unwrap()).unwrap();
    bind_owner_operation(
        &OwnerBindRequest {
            declaration,
            kind,
            clear_opt_in: matches!(kind, OwnerOperationKind::Clear),
            scope,
            layout: crate::rules::fixture::OWNER_FIXTURE_LAYOUT,
            home_directory: bench.tree.home(),
            principal: super::support::user(),
            max_executable_bytes: 1 << 20,
            scope_limits: ScopeLimits::default(),
        },
        &CancellationToken::new(),
        &WallScanClock,
    )
}

/// A manual plan with one owner operation, stored in the journal.
fn owner_plan(bench: &Bench, plan: &str, owner: OwnerOperationBinding) -> Plan {
    let mut content = base_content(plan, bench.clock.now());
    let target_id = TargetId::new(format!("{plan}_scope")).unwrap();
    content.limits.work = Some(owner.charge);
    content.steps = vec![PlannedStep {
        step_id: StepId::new(format!("{plan}_step")).unwrap(),
        action_class: ActionClass::RunOwnerOperation,
        target_id: target_id.clone(),
    }];
    content.targets = vec![PlanTarget {
        target_id,
        binding: TargetBinding::OwnerOperation(Box::new(owner)),
    }];
    let plan: Plan = Plan::seal(content).unwrap();
    bench.store(&plan);
    plan
}

/// The number of runs of the script.
fn runs(bench: &Bench) -> usize {
    fs::read_to_string(bench.tree.home().join("runs")).map_or(0, |text| text.lines().count())
}

fn effect(view: &OperationView) -> TargetEffect {
    view.operation.steps()[0].results()[0].effect.clone()
}

fn failure_code(view: &OperationView) -> Option<String> {
    view.operation.steps()[0].results()[0]
        .failure
        .as_ref()
        .map(|failure| failure.code.as_str().to_owned())
}

/// A plan of a file below the same root, which conflicts with the cleanup
/// root lease of an owner operation.
fn conflicting(bench: &Bench, plan: &str) -> Plan {
    bench.tree.file("other");
    let plan: Plan = cleanup_plan(
        plan,
        &bench.tree,
        &ActionClass::DeleteSelectedFiles,
        &["other"],
        bench.clock.now(),
    );
    bench.store(&plan);
    plan
}

#[test]
fn a_prune_runs_the_command_one_time_and_measures_the_scope_again() {
    let (mut bench, script) = owner_bench(PRUNE);
    let owner = binding(
        &bench,
        &declaration(&script, 30 * SECOND),
        OwnerOperationKind::Prune,
    )
    .unwrap();
    assert_eq!(owner.arguments[0], "prune");
    assert!(owner.measured.complete);
    // The producer is a script: the interpreter and the script are bound
    // apart, and the interpreter is the declared `/bin/sh`.
    let interpreter = owner.interpreter.clone().unwrap();
    assert_eq!(
        interpreter.executable.path.to_path_buf(),
        fs::canonicalize("/bin/sh").unwrap()
    );
    assert_eq!(owner.executable.path.to_path_buf(), script);
    let plan: Plan = owner_plan(&bench, "plan_owner", owner);
    let mut coordinator = bench.start();
    let operation_id: OperationId = admitted(&mut coordinator, stored_request(&plan));
    let view = run_owner(&mut coordinator, &bench, &operation_id);
    assert_eq!(view.operation.state(), &OperationState::Completed);
    assert_eq!(effect(&view), TargetEffect::OperationCompleted);
    assert_eq!(runs(&bench), 1);
    // The journal recorded the process of the command before it ran.
    let processes = open_journal(&bench.tree.database)
        .owner_processes(&operation_id)
        .unwrap();
    assert_eq!(processes.len(), 1);
    assert_eq!(processes[0].group, processes[0].pid);
    assert_eq!(
        fs::read_dir(bench.tree.root.join("pkg")).unwrap().count(),
        0
    );
    // The use check is for the scope root.
    let checks = bench.authority.records().use_checks.lock().unwrap().clone();
    assert_eq!(checks, vec![bench.tree.root.clone()]);
    // The measurement after the command shows the decrease of the scope.
    let scope = view
        .resource_effects
        .iter()
        .find_map(|effect| match effect {
            ResourceEffect::ScopeAllocation(scope) => Some(scope.clone()),
            _ => None,
        })
        .unwrap();
    let after = scope.after().unwrap();
    assert!(after.complete);
    assert!(after.allocated_bytes < scope.before().allocated_bytes);
    if let Some(delta) = scope.delta() {
        assert!(delta < ByteDelta::ZERO);
    }
    // The journal has the observation, and a repeated apply makes no
    // second run.
    let effects = open_journal(&bench.tree.database)
        .resource_effects(&operation_id)
        .unwrap();
    assert!(
        effects
            .iter()
            .any(|effect| matches!(effect, ResourceEffect::ScopeAllocation(_)))
    );
    assert!(matches!(
        coordinator.apply(stored_request(&plan)),
        ApplyOutcome::Existing { .. }
    ));
    coordinator.step();
    assert_eq!(runs(&bench), 1);
    // The lease is released: a plan of the same root is admitted.
    let second = conflicting(&bench, "plan_second");
    admitted(&mut coordinator, stored_request(&second));
}

#[test]
fn a_manual_clear_runs_its_own_command() {
    let (mut bench, script) = owner_bench(PRUNE);
    let owner = binding(
        &bench,
        &declaration(&script, 30 * SECOND),
        OwnerOperationKind::Clear,
    )
    .unwrap();
    assert!(owner.clear_opt_in);
    let plan: Plan = owner_plan(&bench, "plan_clear", owner);
    let mut coordinator = bench.start();
    let operation_id = admitted(&mut coordinator, stored_request(&plan));
    let view = run_owner(&mut coordinator, &bench, &operation_id);
    assert_eq!(view.operation.state(), &OperationState::Completed);
    assert_eq!(
        fs::read_to_string(bench.tree.home().join("runs")).unwrap(),
        "clear\n"
    );
}

#[test]
fn a_clear_needs_the_consent_and_is_never_automatic() {
    let (bench, script) = owner_bench(PRUNE);
    let declaration = declaration(&script, 30 * SECOND);
    let roots = bench.tree.roots();
    let scope: &ApprovedRoot = roots.root(&RootId::new(ROOT_ID).unwrap()).unwrap();
    let request = OwnerBindRequest {
        declaration: &declaration,
        kind: OwnerOperationKind::Clear,
        clear_opt_in: false,
        scope,
        layout: crate::rules::fixture::OWNER_FIXTURE_LAYOUT,
        home_directory: bench.tree.home(),
        principal: super::support::user(),
        max_executable_bytes: 1 << 20,
        scope_limits: ScopeLimits::default(),
    };
    assert_eq!(
        bind_owner_operation(&request, &CancellationToken::new(), &WallScanClock),
        Err(OwnerBindError::ClearNotConfirmed)
    );
    // An automatic plan with a clear operation is refused when it is
    // sealed, so no stored form of it reaches the coordinator.
    let owner = binding(&bench, &declaration, OwnerOperationKind::Clear).unwrap();
    let manual: Plan = owner_plan(&bench, "plan_manual_clear", owner);
    let mut content = (*manual).clone();
    content.trigger = Trigger {
        class: TriggerClass::DiskPressure,
        incident_id: Some(IncidentId::new("incident_disk").unwrap()),
        decision_id: Some(DecisionId::new("decision_disk").unwrap()),
        budget_generation: Some(Generation::new(1)),
    };
    content.principal.role = ClientRole::Agent;
    content.authority.action_grants = vec![bench.authority.memory_grant()];
    assert_eq!(Plan::seal(content.clone()), Err(PlanError::Trigger));
    let mut value = serde_json::to_value(&manual).unwrap();
    value["content"] = serde_json::to_value(&content).unwrap();
    assert!(serde_json::from_value::<Plan>(value).is_err());
}

#[test]
fn a_failed_command_is_unknown_and_keeps_the_lease() {
    let (mut bench, script) =
        owner_bench("echo \"$1\" >> \"$HOME/runs\"\necho \"failure below $HOME\" >&2\nexit 3");
    let owner = binding(
        &bench,
        &declaration(&script, 30 * SECOND),
        OwnerOperationKind::Prune,
    )
    .unwrap();
    let plan: Plan = owner_plan(&bench, "plan_fail", owner);
    let mut coordinator = bench.start();
    let operation_id = admitted(&mut coordinator, stored_request(&plan));
    let view = run_owner(&mut coordinator, &bench, &operation_id);
    assert_eq!(view.operation.state(), &OperationState::UnknownOutcome);
    assert_eq!(effect(&view), TargetEffect::UnknownOutcome);
    assert_eq!(
        failure_code(&view).as_deref(),
        Some(owner_code::OWNER_OPERATION_FAILED)
    );
    assert_eq!(
        view.operation.steps()[0].results()[0].evidence.native,
        svalnir_core::action::NativeResult::ExitStatus { status: 3 }
    );
    assert_eq!(runs(&bench), 1);
    let second = conflicting(&bench, "plan_second");
    assert_eq!(
        refusal(&mut coordinator, stored_request(&second))
            .code
            .as_str(),
        code::LEASE_UNAVAILABLE
    );
    // The acknowledgment releases the lease; the command does not run
    // again.
    coordinator
        .acknowledge(&operation_id, &super::support::principal())
        .unwrap();
    admitted(&mut coordinator, stored_request(&second));
    assert_eq!(runs(&bench), 1);
}

#[test]
fn a_command_past_its_deadline_has_its_group_stopped_and_keeps_the_lease() {
    let (mut bench, script) = owner_bench_with(
        "echo \"$1\" >> \"$HOME/runs\"\nsleep 30 &\nsleep 30\necho late >> \"$HOME/runs\"",
        SECOND,
    );
    let owner = binding(
        &bench,
        &declaration(&script, SECOND),
        OwnerOperationKind::Prune,
    )
    .unwrap();
    let plan: Plan = owner_plan(&bench, "plan_deadline", owner);
    let mut coordinator = bench.start();
    let operation_id = admitted(&mut coordinator, stored_request(&plan));
    let started = std::time::Instant::now();
    let view = run_owner(&mut coordinator, &bench, &operation_id);
    assert!(started.elapsed() < std::time::Duration::from_secs(20));
    assert_eq!(view.operation.state(), &OperationState::UnknownOutcome);
    assert_eq!(
        failure_code(&view).as_deref(),
        Some(owner_code::OWNER_OPERATION_DEADLINE)
    );
    assert_eq!(runs(&bench), 1);
    let second = conflicting(&bench, "plan_second");
    assert_eq!(
        refusal(&mut coordinator, stored_request(&second))
            .code
            .as_str(),
        code::LEASE_UNAVAILABLE
    );
}

#[test]
fn a_child_that_stays_after_the_exit_makes_the_effect_unknown() {
    let (mut bench, script) = owner_bench("echo \"$1\" >> \"$HOME/runs\"\nsleep 30 &\nexit 0");
    let owner = binding(
        &bench,
        &declaration(&script, 30 * SECOND),
        OwnerOperationKind::Prune,
    )
    .unwrap();
    let plan: Plan = owner_plan(&bench, "plan_child", owner);
    let mut coordinator = bench.start();
    let operation_id = admitted(&mut coordinator, stored_request(&plan));
    let view = run_owner(&mut coordinator, &bench, &operation_id);
    assert_eq!(view.operation.state(), &OperationState::UnknownOutcome);
    assert_eq!(
        failure_code(&view).as_deref(),
        Some(owner_code::OWNER_OPERATION_CHILDREN_REMAINED)
    );
}

#[test]
fn a_replaced_executable_starts_no_command() {
    let (mut bench, script) = owner_bench(PRUNE);
    let owner = binding(
        &bench,
        &declaration(&script, 30 * SECOND),
        OwnerOperationKind::Prune,
    )
    .unwrap();
    let plan: Plan = owner_plan(&bench, "plan_replaced", owner);
    // The same name, a different content.
    write_owner_script(
        script.parent().unwrap(),
        "producer",
        "echo replaced >> \"$HOME/runs\"",
    )
    .unwrap();
    let mut coordinator = bench.start();
    let operation_id = admitted(&mut coordinator, stored_request(&plan));
    let view = run_owner(&mut coordinator, &bench, &operation_id);
    assert_eq!(view.operation.state(), &OperationState::NoAction);
    assert_eq!(effect(&view), TargetEffect::Skipped);
    assert_eq!(
        failure_code(&view).as_deref(),
        Some(owner_code::OWNER_EXECUTABLE_CHANGED)
    );
    assert_eq!(runs(&bench), 0);
    assert_eq!(
        fs::read_dir(bench.tree.root.join("pkg")).unwrap().count(),
        3
    );
}

#[test]
fn an_executable_that_the_group_can_change_starts_no_command() {
    use std::os::unix::fs::PermissionsExt as _;
    let (mut bench, script) = owner_bench(PRUNE);
    let owner = binding(
        &bench,
        &declaration(&script, 30 * SECOND),
        OwnerOperationKind::Prune,
    )
    .unwrap();
    let plan: Plan = owner_plan(&bench, "plan_writable", owner);
    let tools: &Path = script.parent().unwrap();
    fs::set_permissions(tools, fs::Permissions::from_mode(0o775)).unwrap();
    let mut coordinator = bench.start();
    let operation_id = admitted(&mut coordinator, stored_request(&plan));
    let view = run_owner(&mut coordinator, &bench, &operation_id);
    assert_eq!(effect(&view), TargetEffect::Skipped);
    assert_eq!(
        failure_code(&view).as_deref(),
        Some(owner_code::OWNER_EXECUTABLE_NOT_TRUSTED)
    );
    assert_eq!(runs(&bench), 0);
}

#[test]
fn a_replaced_scope_root_starts_no_command() {
    let (mut bench, script) = owner_bench(PRUNE);
    let owner = binding(
        &bench,
        &declaration(&script, 30 * SECOND),
        OwnerOperationKind::Prune,
    )
    .unwrap();
    let plan: Plan = owner_plan(&bench, "plan_root", owner);
    let mut coordinator = bench.start();
    let operation_id = admitted(&mut coordinator, stored_request(&plan));
    // A different directory at the name of the root.
    fs::rename(&bench.tree.root, bench.tree.base().join("root_old")).unwrap();
    fs::create_dir(&bench.tree.root).unwrap();
    let view = run_owner(&mut coordinator, &bench, &operation_id);
    assert_eq!(effect(&view), TargetEffect::Skipped);
    assert_eq!(
        failure_code(&view).as_deref(),
        Some(owner_code::SCOPE_ROOT_CHANGED)
    );
    assert_eq!(runs(&bench), 0);
}

#[test]
fn a_scope_that_grew_after_the_plan_starts_no_command() {
    let (mut bench, script) = owner_bench(PRUNE);
    let owner = binding(
        &bench,
        &declaration(&script, 30 * SECOND),
        OwnerOperationKind::Prune,
    )
    .unwrap();
    let plan: Plan = owner_plan(&bench, "plan_grew", owner);
    fs::write(bench.tree.root.join("pkg/d"), vec![1_u8; 64_000]).unwrap();
    let mut coordinator = bench.start();
    let operation_id = admitted(&mut coordinator, stored_request(&plan));
    let view = run_owner(&mut coordinator, &bench, &operation_id);
    assert_eq!(
        failure_code(&view).as_deref(),
        Some(owner_code::TARGET_GREW)
    );
    assert_eq!(runs(&bench), 0);
}

#[test]
fn a_scope_in_use_is_skipped_with_no_command() {
    let cases = [
        (
            UnitUse::InUse {
                uses: Vec::new(),
                omitted: 1,
            },
            code::UNIT_IN_USE,
        ),
        (
            UnitUse::Unknown {
                reason: "process_not_readable",
                processes: Vec::new(),
                omitted: 1,
            },
            code::UNIT_USE_UNKNOWN,
        ),
    ];
    for (unit_use, expected) in cases {
        let (mut bench, script) = owner_bench(PRUNE);
        let owner = binding(
            &bench,
            &declaration(&script, 30 * SECOND),
            OwnerOperationKind::Prune,
        )
        .unwrap();
        let plan: Plan = owner_plan(&bench, "plan_in_use", owner);
        bench.authority.records().unit_use = unit_use;
        let mut coordinator = bench.start();
        let operation_id = admitted(&mut coordinator, stored_request(&plan));
        let view = run_owner(&mut coordinator, &bench, &operation_id);
        assert_eq!(view.operation.state(), &OperationState::NoAction);
        assert_eq!(effect(&view), TargetEffect::Skipped);
        assert_eq!(failure_code(&view).as_deref(), Some(expected));
        assert_eq!(runs(&bench), 0);
    }
}

#[test]
fn an_active_producer_is_skipped_with_no_command() {
    let (mut bench, script) = owner_bench(PRUNE);
    let owner = binding(
        &bench,
        &declaration(&script, 30 * SECOND),
        OwnerOperationKind::Prune,
    )
    .unwrap();
    let plan: Plan = owner_plan(&bench, "plan_active", owner);
    bench.authority.records().activity = crate::rules::ProducerActivity::Active;
    let mut coordinator = bench.start();
    let operation_id = admitted(&mut coordinator, stored_request(&plan));
    let view = run_owner(&mut coordinator, &bench, &operation_id);
    assert_eq!(failure_code(&view).as_deref(), Some(code::PRODUCER_ACTIVE));
    assert_eq!(runs(&bench), 0);
}

#[test]
fn a_proposed_layout_permits_no_owner_operation() {
    let (mut bench, script) = owner_bench(PRUNE);
    let owner = binding(
        &bench,
        &declaration(&script, 30 * SECOND),
        OwnerOperationKind::Prune,
    )
    .unwrap();
    let plan: Plan = owner_plan(&bench, "plan_proposed", owner);
    bench.authority.records().registry = NoRules(
        None,
        vec![owner_fixture_rule(svalnir_core::rule::LifecycleState::Proposed).unwrap()],
        vec![declaration(&script, 30 * SECOND)],
    );
    let mut coordinator = bench.start();
    let error = refusal(&mut coordinator, stored_request(&plan));
    assert_eq!(error.code.as_str(), "rule_mode_not_validated");
    coordinator.step();
    assert_eq!(runs(&bench), 0);
}

#[test]
fn a_restart_after_the_consumption_does_not_run_the_command_again() {
    let (mut bench, script) = owner_bench(PRUNE);
    let owner = binding(
        &bench,
        &declaration(&script, 30 * SECOND),
        OwnerOperationKind::Prune,
    )
    .unwrap();
    let plan: Plan = owner_plan(&bench, "plan_restart", owner);
    // The journal records the intent and the consumption and no result of
    // the step, as after a crash after the command.
    bench.fail(FailPoint::RecordStep);
    let operation_id: OperationId = {
        let mut coordinator = bench.start();
        let operation_id = admitted(&mut coordinator, stored_request(&plan));
        run_owner(&mut coordinator, &bench, &operation_id);
        operation_id
    };
    assert_eq!(runs(&bench), 1);
    bench.heal();
    let mut coordinator = bench.start();
    coordinator.step();
    let stored = open_journal(&bench.tree.database)
        .operation(&operation_id)
        .unwrap()
        .unwrap();
    assert_eq!(stored.state(), &OperationState::UnknownOutcome);
    // The single-use plan gives no new operation, and the command does not
    // run again.
    assert!(!matches!(
        coordinator.apply(stored_request(&plan)),
        ApplyOutcome::Admitted { .. }
    ));
    coordinator.step();
    assert_eq!(runs(&bench), 1);
    let second = conflicting(&bench, "plan_second");
    assert_eq!(
        refusal(&mut coordinator, stored_request(&second))
            .code
            .as_str(),
        code::LEASE_UNAVAILABLE
    );
}

/// A copy of `plan` with its binding changed by `change`, sealed again
/// and stored, as a different process could store it in the journal.
fn crafted(
    bench: &Bench,
    plan: &str,
    owner: &OwnerOperationBinding,
    change: impl FnOnce(&mut OwnerOperationBinding),
) -> Plan {
    let mut owner: OwnerOperationBinding = owner.clone();
    change(&mut owner);
    owner_plan(bench, plan, owner)
}

#[test]
fn admission_refuses_a_binding_that_is_not_the_reviewed_command() {
    let (mut bench, script) = owner_bench(PRUNE);
    let owner = binding(
        &bench,
        &declaration(&script, 30 * SECOND),
        OwnerOperationKind::Prune,
    )
    .unwrap();
    let remove = crate::executor::owner::examine_executable(
        &fs::canonicalize("/bin/rm").unwrap(),
        super::support::user(),
        1 << 24,
    )
    .unwrap();
    let plans: Vec<Plan> = vec![
        crafted(&bench, "plan_rm", &owner, |owner| {
            owner.executable = remove;
            owner.interpreter = None;
            owner.arguments = vec!["-rf".to_owned(), owner.root_path.display_label()];
        }),
        crafted(&bench, "plan_env", &owner, |owner| {
            owner
                .environment
                .push(svalnir_core::action::EnvironmentEntry {
                    name: "EXTRA".to_owned(),
                    value: "1".to_owned(),
                });
        }),
        crafted(&bench, "plan_arguments", &owner, |owner| {
            owner.arguments.push("--all".to_owned());
        }),
        crafted(&bench, "plan_effect", &owner, |owner| {
            owner.expected_effect = "A different statement.".to_owned();
        }),
        crafted(&bench, "plan_directory", &owner, |owner| {
            owner.working_directory = owner.root_path.clone();
        }),
    ];
    let mut coordinator = bench.start();
    for plan in &plans {
        assert_eq!(
            refusal(&mut coordinator, stored_request(plan))
                .code
                .as_str(),
            code::OWNER_BINDING_MISMATCH,
            "{}",
            plan.plan_id
        );
    }
    coordinator.step();
    assert_eq!(runs(&bench), 0);
    // A rule with no declaration has no command.
    bench.authority.records().registry.2.clear();
    let unknown: Plan = owner_plan(&bench, "plan_no_declaration", owner);
    assert_eq!(
        refusal(&mut coordinator, stored_request(&unknown))
            .code
            .as_str(),
        code::OWNER_BINDING_MISMATCH
    );
}

#[test]
fn admission_refuses_a_command_deadline_after_the_expiry_of_the_plan() {
    let (mut bench, script) = owner_bench(PRUNE);
    let owner = binding(
        &bench,
        &declaration(&script, 30 * SECOND),
        OwnerOperationKind::Prune,
    )
    .unwrap();
    let mut content = base_content("plan_short", bench.clock.now());
    content.validity.expires_at =
        svalnir_core::time::MonotonicNanos::new(bench.clock.now() + 10 * SECOND);
    let target_id = TargetId::new("plan_short_scope").unwrap();
    content.limits.work = Some(owner.charge);
    content.steps = vec![PlannedStep {
        step_id: StepId::new("plan_short_step").unwrap(),
        action_class: ActionClass::RunOwnerOperation,
        target_id: target_id.clone(),
    }];
    content.targets = vec![PlanTarget {
        target_id,
        binding: TargetBinding::OwnerOperation(Box::new(owner)),
    }];
    let plan: Plan = Plan::seal(content).unwrap();
    bench.store(&plan);
    let mut coordinator = bench.start();
    assert_eq!(
        refusal(&mut coordinator, stored_request(&plan))
            .code
            .as_str(),
        code::OWNER_DEADLINE_BEYOND_PLAN
    );
}

#[test]
fn no_command_starts_without_the_responsibility_disclaim() {
    let (mut bench, script) = owner_bench(PRUNE);
    let owner = binding(
        &bench,
        &declaration(&script, 30 * SECOND),
        OwnerOperationKind::Prune,
    )
    .unwrap();
    let plan: Plan = owner_plan(&bench, "plan_disclaim", owner);
    let home: PathBuf = bench.tree.home().to_path_buf();
    let start = bench.start_with(|dependencies, _| {
        let mut config = crate::executor::owner::OwnerExecutorConfig::new(
            svalnir_core::id::AdapterId::new("svalnir.owner-operation").unwrap(),
            svalnir_core::file::LosslessPath::from_path(&home).unwrap(),
        );
        config.responsibility = crate::executor::owner::ResponsibilitySymbols {
            disclaim: c"svalnir_test_no_such_function",
            ..crate::executor::owner::ResponsibilitySymbols::default()
        };
        dependencies.owner = Box::new(crate::executor::owner::OwnerExecutor::new(config));
    });
    let super::super::Start::Coordinating(mut coordinator) = start else {
        panic!("the lock is held");
    };
    let operation_id = admitted(&mut coordinator, stored_request(&plan));
    let view = run_owner(&mut coordinator, &bench, &operation_id);
    assert_eq!(view.operation.state(), &OperationState::NoAction);
    assert_eq!(effect(&view), TargetEffect::Skipped);
    assert_eq!(
        failure_code(&view).as_deref(),
        Some(owner_code::OWNER_DISCLAIM_UNAVAILABLE)
    );
    assert_eq!(runs(&bench), 0);
}

#[test]
fn a_process_that_the_journal_does_not_record_never_runs() {
    let (mut bench, script) = owner_bench(PRUNE);
    let owner = binding(
        &bench,
        &declaration(&script, 30 * SECOND),
        OwnerOperationKind::Prune,
    )
    .unwrap();
    let plan: Plan = owner_plan(&bench, "plan_unrecorded", owner);
    bench.fail(FailPoint::RecordOwnerProcess);
    let mut coordinator = bench.start();
    let operation_id = admitted(&mut coordinator, stored_request(&plan));
    let view = run_owner(&mut coordinator, &bench, &operation_id);
    assert_eq!(effect(&view), TargetEffect::Skipped);
    assert_eq!(
        failure_code(&view).as_deref(),
        Some(owner_code::OWNER_PROCESS_NOT_RECORDED)
    );
    assert_eq!(runs(&bench), 0);
}

/// Steps the coordinator until the script wrote its run.
fn until_running(coordinator: &mut super::support::TestCoordinator, bench: &Bench) {
    for _ in 0..4000 {
        if runs(bench) > 0 {
            return;
        }
        coordinator.step();
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    panic!("the command did not start");
}

#[test]
fn a_stop_of_the_agent_stops_a_running_command_and_keeps_its_lease() {
    let (mut bench, script) = owner_bench("echo \"$1\" >> \"$HOME/runs\"\nsleep 30");
    let owner = binding(
        &bench,
        &declaration(&script, 30 * SECOND),
        OwnerOperationKind::Prune,
    )
    .unwrap();
    let plan: Plan = owner_plan(&bench, "plan_stop", owner);
    let mut coordinator = bench.start();
    let operation_id = admitted(&mut coordinator, stored_request(&plan));
    until_running(&mut coordinator, &bench);
    // The tick of the agent continues while the command runs: a query of
    // the operation answers at once.
    assert_eq!(
        coordinator.operation(&operation_id).unwrap().unwrap().phase,
        super::super::Phase::Running
    );
    let started = std::time::Instant::now();
    coordinator.stop_claims();
    let stopped = coordinator.cancel_active();
    assert_eq!(stopped, vec![operation_id.clone()]);
    let view = run_owner(&mut coordinator, &bench, &operation_id);
    assert!(started.elapsed() < std::time::Duration::from_secs(10));
    assert_eq!(view.operation.state(), &OperationState::UnknownOutcome);
    assert_eq!(
        view.operation.steps()[0].results()[0].stop_reason,
        svalnir_core::action::StopReason::Canceled
    );
    // The process of the command is gone, so an acknowledgment is
    // accepted and releases the lease.
    coordinator
        .acknowledge(&operation_id, &super::support::principal())
        .unwrap();
}

#[test]
fn a_plan_that_expires_while_its_command_runs_does_not_stop_the_command() {
    let (mut bench, script) =
        owner_bench("echo \"$1\" >> \"$HOME/runs\"\nsleep 1\necho done >> \"$HOME/runs\"");
    let owner = binding(
        &bench,
        &declaration(&script, 30 * SECOND),
        OwnerOperationKind::Prune,
    )
    .unwrap();
    let mut content = base_content("plan_expiring", bench.clock.now());
    content.validity.expires_at =
        svalnir_core::time::MonotonicNanos::new(bench.clock.now() + 40 * SECOND);
    let target_id = TargetId::new("plan_expiring_scope").unwrap();
    content.limits.work = Some(owner.charge);
    content.steps = vec![PlannedStep {
        step_id: StepId::new("plan_expiring_step").unwrap(),
        action_class: ActionClass::RunOwnerOperation,
        target_id: target_id.clone(),
    }];
    content.targets = vec![PlanTarget {
        target_id,
        binding: TargetBinding::OwnerOperation(Box::new(owner)),
    }];
    let plan: Plan = Plan::seal(content).unwrap();
    bench.store(&plan);
    let mut coordinator = bench.start();
    let operation_id = admitted(&mut coordinator, stored_request(&plan));
    until_running(&mut coordinator, &bench);
    // The plan expires; the lease (the execution deadline) does not.
    bench.clock.advance(45 * SECOND);
    let view = run_owner(&mut coordinator, &bench, &operation_id);
    assert_eq!(view.operation.state(), &OperationState::Completed);
    assert_eq!(runs(&bench), 2);
}

#[test]
fn the_trigger_and_the_plan_expiry_do_not_stop_a_running_command() {
    use super::super::dispatch::stops_running_command;
    use svalnir_core::grant::RefusalReason;
    for reason in [
        RefusalReason::PlanExpired,
        RefusalReason::TriggerEvidenceMissing,
        RefusalReason::TriggerEvidenceStale,
        RefusalReason::MeasurementBeforeResume,
    ] {
        assert!(!stops_running_command(reason), "{reason:?}");
    }
    for reason in [
        RefusalReason::AutomationPaused,
        RefusalReason::ActionGrantRevoked,
        RefusalReason::GuardDisabled,
        RefusalReason::PolicyRevisionMismatch,
    ] {
        assert!(stops_running_command(reason), "{reason:?}");
    }
}

#[test]
fn an_acknowledgment_is_refused_while_a_recorded_process_lives() {
    use std::os::unix::process::CommandExt as _;
    let (mut bench, script) = owner_bench("echo \"$1\" >> \"$HOME/runs\"\nexit 3");
    let owner = binding(
        &bench,
        &declaration(&script, 30 * SECOND),
        OwnerOperationKind::Prune,
    )
    .unwrap();
    let plan: Plan = owner_plan(&bench, "plan_alive", owner);
    let mut coordinator = bench.start();
    let operation_id = admitted(&mut coordinator, stored_request(&plan));
    let view = run_owner(&mut coordinator, &bench, &operation_id);
    assert_eq!(view.operation.state(), &OperationState::UnknownOutcome);
    // A process of the test in the place of a command that still runs.
    let mut child = std::process::Command::new("/bin/sleep")
        .arg("30")
        .process_group(0)
        .spawn()
        .unwrap();
    let pid = i32::try_from(child.id()).unwrap();
    let record = crate::executor::owner::process_record_of(pid).unwrap();
    open_journal(&bench.tree.database)
        .record_owner_process(
            &operation_id,
            &StepId::new("plan_alive_step").unwrap(),
            &record,
        )
        .unwrap();
    let error = coordinator
        .acknowledge(&operation_id, &super::support::principal())
        .unwrap_err();
    assert_eq!(error.code.as_str(), code::OWNER_PROCESS_ALIVE);
    child.kill().unwrap();
    child.wait().unwrap();
    coordinator
        .acknowledge(&operation_id, &super::support::principal())
        .unwrap();
}

#[test]
fn admission_refuses_an_interpreter_argument_that_the_declaration_does_not_permit() {
    let (mut bench, script) = owner_bench(PRUNE);
    let owner = binding(
        &bench,
        &declaration(&script, 30 * SECOND),
        OwnerOperationKind::Prune,
    )
    .unwrap();
    let plans: Vec<Plan> = vec![
        crafted(&bench, "plan_eval", &owner, |owner| {
            if let Some(interpreter) = owner.interpreter.as_mut() {
                interpreter.arguments = vec!["--eval=1".to_owned()];
            }
        }),
        // An argument where the declaration permits none. Two arguments
        // are refused when the plan is sealed.
        crafted(&bench, "plan_extra", &owner, |owner| {
            if let Some(interpreter) = owner.interpreter.as_mut() {
                interpreter.arguments = vec!["-x".to_owned()];
            }
        }),
        crafted(&bench, "plan_no_interpreter", &owner, |owner| {
            owner.interpreter = None;
        }),
    ];
    let mut coordinator = bench.start();
    for plan in &plans {
        assert_eq!(
            refusal(&mut coordinator, stored_request(plan))
                .code
                .as_str(),
            code::OWNER_BINDING_MISMATCH,
            "{}",
            plan.plan_id
        );
    }
    assert_eq!(runs(&bench), 0);
}

#[test]
fn the_journal_keeps_each_descendant_that_the_worker_finds() {
    let (mut bench, script) = owner_bench("echo \"$1\" >> \"$HOME/runs\"\nsleep 1 &\nsleep 1");
    let owner = binding(
        &bench,
        &declaration(&script, 30 * SECOND),
        OwnerOperationKind::Prune,
    )
    .unwrap();
    let plan: Plan = owner_plan(&bench, "plan_descendants", owner);
    let mut coordinator = bench.start();
    let operation_id = admitted(&mut coordinator, stored_request(&plan));
    run_owner(&mut coordinator, &bench, &operation_id);
    let processes = open_journal(&bench.tree.database)
        .owner_processes(&operation_id)
        .unwrap();
    assert_eq!(processes.len(), 1);
    assert_ne!(processes[0].descendants, Vec::new());
    assert!(
        processes[0]
            .descendants
            .iter()
            .all(|descendant| descendant.pid != processes[0].pid)
    );
}

#[test]
fn a_stop_during_the_checks_before_the_start_ends_at_once() {
    let (mut bench, script) = owner_bench(PRUNE);
    // A scope whose measurement takes long enough for the stop to arrive
    // during it.
    let many: PathBuf = bench.tree.root.join("many");
    fs::create_dir(&many).unwrap();
    for index in 0..20_000 {
        fs::write(many.join(format!("f{index}")), b"").unwrap();
    }
    let owner = binding(
        &bench,
        &declaration(&script, 30 * SECOND),
        OwnerOperationKind::Prune,
    )
    .unwrap();
    let plan: Plan = owner_plan(&bench, "plan_early_stop", owner);
    let mut coordinator = bench.start();
    let operation_id = admitted(&mut coordinator, stored_request(&plan));
    for _ in 0..100 {
        coordinator.step();
        if coordinator
            .active
            .as_ref()
            .is_some_and(|active| active.owner_run.is_some())
        {
            break;
        }
    }
    let started = std::time::Instant::now();
    drop(coordinator.cancel(&operation_id));
    let view = run_owner(&mut coordinator, &bench, &operation_id);
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
    assert_eq!(runs(&bench), 0);
    assert_eq!(effect(&view), TargetEffect::Skipped);
    assert_eq!(
        view.operation.steps()[0].results()[0].stop_reason,
        svalnir_core::action::StopReason::Canceled
    );
}

/// Leaves the worker of the running owner step with no coordinator, as a
/// crash of the agent leaves its command: the handle is not dropped, so
/// the command is not stopped.
fn crash(mut coordinator: Box<super::support::TestCoordinator>) {
    let run = coordinator
        .active
        .as_mut()
        .and_then(|active| active.owner_run.take());
    let _leaked = Box::leak(Box::new(run));
    drop(coordinator);
}

#[test]
fn a_restart_stops_a_command_that_runs_and_then_accepts_the_acknowledgment() {
    let (mut bench, script) = owner_bench("echo \"$1\" >> \"$HOME/runs\"\nsleep 30");
    let owner = binding(
        &bench,
        &declaration(&script, 30 * SECOND),
        OwnerOperationKind::Prune,
    )
    .unwrap();
    let plan: Plan = owner_plan(&bench, "plan_crash_running", owner);
    let mut coordinator = bench.start();
    let operation_id = admitted(&mut coordinator, stored_request(&plan));
    until_running(&mut coordinator, &bench);
    crash(coordinator);
    let processes = open_journal(&bench.tree.database)
        .owner_processes(&operation_id)
        .unwrap();
    assert!(crate::executor::owner::process_lives(&processes[0]));
    let mut coordinator = bench.start();
    coordinator.step();
    assert!(!crate::executor::owner::process_lives(&processes[0]));
    let stored = open_journal(&bench.tree.database)
        .operation(&operation_id)
        .unwrap()
        .unwrap();
    assert_eq!(stored.state(), &OperationState::UnknownOutcome);
    coordinator
        .acknowledge(&operation_id, &super::support::principal())
        .unwrap();
    assert_eq!(runs(&bench), 1);
}

#[test]
fn a_restart_stops_a_suspended_command_that_never_ran() {
    let (mut bench, script) = owner_bench(PRUNE);
    let owner = binding(
        &bench,
        &declaration(&script, 30 * SECOND),
        OwnerOperationKind::Prune,
    )
    .unwrap();
    let plan: Plan = owner_plan(&bench, "plan_crash_suspended", owner);
    let mut coordinator = bench.start();
    let operation_id = admitted(&mut coordinator, stored_request(&plan));
    for _ in 0..100 {
        coordinator.step();
        if coordinator
            .active
            .as_ref()
            .is_some_and(|active| active.owner_run.is_some())
        {
            break;
        }
    }
    // The handle leaves the coordinator, so nothing answers the start: the
    // command stays suspended, as at a crash before the resume.
    let mut run = coordinator
        .active
        .as_mut()
        .and_then(|active| active.owner_run.take())
        .unwrap()
        .run;
    let process = loop {
        if let crate::executor::owner::OwnerPoll::Started(process) = run.poll() {
            break process;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    };
    open_journal(&bench.tree.database)
        .record_owner_process(
            &operation_id,
            &StepId::new("plan_crash_suspended_step").unwrap(),
            &process,
        )
        .unwrap();
    let _leaked = Box::leak(Box::new(run));
    drop(coordinator);
    // This test process is the parent of the command; after a crash of the
    // agent, `launchd` collects it.
    let pid = process.pid;
    let reaper = std::thread::spawn(move || {
        let mut status: libc::c_int = 0;
        // SAFETY: `status` is a valid pointer for the call.
        unsafe { libc::waitpid(pid, &raw mut status, 0) };
    });
    let started = std::time::Instant::now();
    let mut coordinator = bench.start();
    coordinator.step();
    reaper.join().unwrap();
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
    assert!(!crate::executor::owner::process_lives(&process));
    assert_eq!(runs(&bench), 0);
    coordinator
        .acknowledge(&operation_id, &super::support::principal())
        .unwrap();
}

#[test]
fn a_set_of_descendants_that_overflows_is_unknown_and_refuses_the_acknowledgment() {
    let (mut bench, script) = owner_bench(
        "echo \"$1\" >> \"$HOME/runs\"\nsleep 1 &\nsleep 1 &\nsleep 1 &\nsleep 1 &\nwait\nexit 0",
    );
    let owner = binding(
        &bench,
        &declaration(&script, 30 * SECOND),
        OwnerOperationKind::Prune,
    )
    .unwrap();
    let plan: Plan = owner_plan(&bench, "plan_overflow", owner);
    let home: PathBuf = bench.tree.home().to_path_buf();
    let start = bench.start_with(|dependencies, _| {
        let mut config = crate::executor::owner::OwnerExecutorConfig::new(
            svalnir_core::id::AdapterId::new("svalnir.owner-operation").unwrap(),
            svalnir_core::file::LosslessPath::from_path(&home).unwrap(),
        );
        config.max_descendants = 2;
        dependencies.owner = Box::new(crate::executor::owner::OwnerExecutor::new(config));
    });
    let super::super::Start::Coordinating(mut coordinator) = start else {
        panic!("the lock is held");
    };
    let operation_id = admitted(&mut coordinator, stored_request(&plan));
    let view = run_owner(&mut coordinator, &bench, &operation_id);
    assert_eq!(view.operation.state(), &OperationState::UnknownOutcome);
    assert_eq!(effect(&view), TargetEffect::UnknownOutcome);
    assert_eq!(
        failure_code(&view).as_deref(),
        Some(owner_code::OWNER_DESCENDANTS_TRUNCATED)
    );
    let processes = open_journal(&bench.tree.database)
        .owner_processes(&operation_id)
        .unwrap();
    assert_eq!(processes.len(), 1);
    assert!(processes[0].truncated);
    // Each process of the command ended, but the record is truncated.
    let error = coordinator
        .acknowledge(&operation_id, &super::support::principal())
        .unwrap_err();
    assert_eq!(error.code.as_str(), code::OWNER_PROCESS_ALIVE);
}

#[test]
fn a_descendant_record_that_fails_is_unknown_and_refuses_the_acknowledgment() {
    let (mut bench, script) = owner_bench("echo \"$1\" >> \"$HOME/runs\"\nsleep 1 &\nwait\nexit 0");
    let owner = binding(
        &bench,
        &declaration(&script, 30 * SECOND),
        OwnerOperationKind::Prune,
    )
    .unwrap();
    let plan: Plan = owner_plan(&bench, "plan_lost", owner);
    bench.fail(FailPoint::RecordOwnerDescendants);
    let mut coordinator = bench.start();
    let operation_id = admitted(&mut coordinator, stored_request(&plan));
    let view = run_owner(&mut coordinator, &bench, &operation_id);
    assert_eq!(view.operation.state(), &OperationState::UnknownOutcome);
    assert_eq!(effect(&view), TargetEffect::UnknownOutcome);
    assert_eq!(
        failure_code(&view).as_deref(),
        Some(owner_code::OWNER_DESCENDANTS_NOT_RECORDED)
    );
    let processes = open_journal(&bench.tree.database)
        .owner_processes(&operation_id)
        .unwrap();
    assert!(processes[0].truncated);
    let error = coordinator
        .acknowledge(&operation_id, &super::support::principal())
        .unwrap_err();
    assert_eq!(error.code.as_str(), code::OWNER_PROCESS_ALIVE);
}

#[test]
fn a_truncated_record_refuses_the_acknowledgment_with_no_live_process() {
    let (mut bench, script) = owner_bench("echo \"$1\" >> \"$HOME/runs\"\nexit 3");
    let owner = binding(
        &bench,
        &declaration(&script, 30 * SECOND),
        OwnerOperationKind::Prune,
    )
    .unwrap();
    let plan: Plan = owner_plan(&bench, "plan_truncated", owner);
    let mut coordinator = bench.start();
    let operation_id = admitted(&mut coordinator, stored_request(&plan));
    let view = run_owner(&mut coordinator, &bench, &operation_id);
    assert_eq!(view.operation.state(), &OperationState::UnknownOutcome);
    let step_id = StepId::new("plan_truncated_step").unwrap();
    let mut journal = open_journal(&bench.tree.database);
    let mut record = journal.owner_processes(&operation_id).unwrap().remove(0);
    record.truncated = true;
    journal
        .record_owner_process(&operation_id, &step_id, &record)
        .unwrap();
    let error = coordinator
        .acknowledge(&operation_id, &super::support::principal())
        .unwrap_err();
    assert_eq!(error.code.as_str(), code::OWNER_PROCESS_ALIVE);
    // The same record with a complete set permits the acknowledgment.
    record.truncated = false;
    journal
        .record_owner_process(&operation_id, &step_id, &record)
        .unwrap();
    coordinator
        .acknowledge(&operation_id, &super::support::principal())
        .unwrap();
}
