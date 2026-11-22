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
    refusal, run, stored_request,
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
    let bench: Bench = Bench::new();
    bench.authority.records().registry = NoRules(
        None,
        vec![owner_fixture_rule(manual_action_validated()).unwrap()],
    );
    let package: PathBuf = bench.tree.root.join("pkg");
    fs::create_dir(&package).unwrap();
    for name in ["a", "b", "c"] {
        fs::write(package.join(name), vec![7_u8; 9_000]).unwrap();
    }
    let tools: PathBuf = bench.tree.base().join("tools");
    fs::create_dir(&tools).unwrap();
    let script: PathBuf = write_owner_script(&tools, "producer", body).unwrap();
    (bench, script)
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
        binding: TargetBinding::OwnerOperation(owner),
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
    let plan: Plan = owner_plan(&bench, "plan_owner", owner);
    let mut coordinator = bench.start();
    let operation_id: OperationId = admitted(&mut coordinator, stored_request(&plan));
    let view = run(&mut coordinator, &bench.clock, &operation_id);
    assert_eq!(view.operation.state(), &OperationState::Completed);
    assert_eq!(effect(&view), TargetEffect::OperationCompleted);
    assert_eq!(runs(&bench), 1);
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
    let view = run(&mut coordinator, &bench.clock, &operation_id);
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
    let view = run(&mut coordinator, &bench.clock, &operation_id);
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
    let (mut bench, script) = owner_bench(
        "echo \"$1\" >> \"$HOME/runs\"\nsleep 30 &\nsleep 30\necho late >> \"$HOME/runs\"",
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
    let view = run(&mut coordinator, &bench.clock, &operation_id);
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
    let view = run(&mut coordinator, &bench.clock, &operation_id);
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
    let view = run(&mut coordinator, &bench.clock, &operation_id);
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
    let view = run(&mut coordinator, &bench.clock, &operation_id);
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
    let view = run(&mut coordinator, &bench.clock, &operation_id);
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
    let view = run(&mut coordinator, &bench.clock, &operation_id);
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
        let view = run(&mut coordinator, &bench.clock, &operation_id);
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
    let view = run(&mut coordinator, &bench.clock, &operation_id);
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
        run(&mut coordinator, &bench.clock, &operation_id);
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
