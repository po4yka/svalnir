//! Admission: the refusals, the single coordinator, and the duplicates.

use svalnir_core::action::{
    ActionClass, ErrorFamily, Escalation, ExecutorRole, Journal as _, OperationState,
    PermittedNextStep, Plan, PlanContent, TargetBinding,
};
use svalnir_core::digest::ContentDigest;
use svalnir_core::id::{PolicyRevisionId, RuleId, RuleRevisionId};
use svalnir_core::policy::ProtectionFact;
use svalnir_core::rule::RuleRef;

use super::super::{ApplyOutcome, ApplyRequest, Start, code};
use super::support::{
    Bench, NoRules, SECOND, admitted, approval, cleanup_content, cleanup_plan, open_journal,
    principal, queued, refusal, run, stop_content, stop_plan, stored_request,
};
use crate::journal::{RequestBody, RequestCompletion, RequestStatus};
use crate::rules::{EXPIRED_TEMPORARY_REVISION, EXPIRED_TEMPORARY_RULE_ID, ReviewedRules};

/// A bench with one file `a` and a stored permanent-removal plan for it.
fn bench_with_plan() -> (Bench, Plan, std::path::PathBuf) {
    let bench = Bench::new();
    let file = bench.tree.file("a");
    let plan = cleanup_plan(
        "plan_1",
        &bench.tree,
        &ActionClass::DeleteSelectedFiles,
        &["a"],
        bench.clock.now(),
    );
    bench.store(&plan);
    (bench, plan, file)
}

/// Asserts that a refusal left no operation, no intent, and no effect.
fn assert_nothing_changed(bench: &Bench, file: &std::path::Path) {
    assert!(file.exists());
    assert_eq!(bench.intents(), 0);
    let journal = open_journal(&bench.tree.database);
    assert_eq!(journal.unsettled_operation_count().unwrap(), 0);
}

#[test]
fn an_expired_plan_is_refused_and_changes_nothing() {
    let (mut bench, plan, file) = bench_with_plan();
    let mut coordinator = bench.start();
    bench.clock.advance(121 * SECOND);
    let error = refusal(&mut coordinator, stored_request(&plan));
    assert_eq!(error.code.as_str(), code::PLAN_EXPIRED);
    assert_eq!(error.family, ErrorFamily::Limits);
    assert_eq!(
        error.permitted_next_step(),
        PermittedNextStep::RespectLimits
    );
    assert_nothing_changed(&bench, &file);
    // A refusal is not recorded: the journal has no consumption of the
    // plan, and the plan is expired for each later apply also.
    let error = refusal(&mut coordinator, stored_request(&plan));
    assert_eq!(error.code.as_str(), code::PLAN_EXPIRED);
}

#[test]
fn an_approval_for_a_different_digest_is_refused() {
    let (mut bench, plan, file) = bench_with_plan();
    let mut coordinator = bench.start();
    let mut request = stored_request(&plan);
    request.approval.digest = ContentDigest::of_bytes(b"a different plan");
    let error = refusal(&mut coordinator, request);
    assert_eq!(error.code.as_str(), code::APPROVAL_MISMATCH);
    assert_eq!(error.family, ErrorFamily::Authority);
    assert_nothing_changed(&bench, &file);
}

#[test]
fn a_plan_of_a_different_policy_revision_is_refused() {
    let bench = Bench::new();
    let file = bench.tree.file("a");
    let mut content: PlanContent = cleanup_content(
        "plan_1",
        &bench.tree,
        &ActionClass::DeleteSelectedFiles,
        &["a"],
        bench.clock.now(),
    );
    content.authority.policy_revision = PolicyRevisionId::new("policy_0").unwrap();
    let plan = Plan::seal(content).unwrap();
    bench.store(&plan);
    let mut bench = bench;
    let mut coordinator = bench.start();
    let error = refusal(&mut coordinator, stored_request(&plan));
    assert_eq!(error.code.as_str(), code::POLICY_REVISION_CHANGED);
    assert_eq!(error.family, ErrorFamily::Authority);
    assert_nothing_changed(&bench, &file);
}

#[test]
fn a_plan_that_the_journal_does_not_have_is_refused() {
    let mut bench = Bench::new();
    let file = bench.tree.file("a");
    let plan = cleanup_plan(
        "plan_1",
        &bench.tree,
        &ActionClass::DeleteSelectedFiles,
        &["a"],
        bench.clock.now(),
    );
    let mut coordinator = bench.start();
    let error = refusal(&mut coordinator, stored_request(&plan));
    assert_eq!(error.code.as_str(), code::PLAN_NOT_FOUND);
    assert_eq!(error.family, ErrorFamily::Request);
    assert_nothing_changed(&bench, &file);
}

#[test]
fn a_plan_for_the_helper_and_a_protected_target_are_refused() {
    let mut bench = Bench::new();
    let member = bench.host.spawn(4242);
    let plan = stop_plan(
        "plan_1",
        vec![member.clone()],
        Escalation::None,
        bench.clock.now(),
    );
    bench.store(&plan);
    let mut coordinator = bench.start();
    bench.authority.records().protection = ProtectionFact::Protected;
    let error = refusal(&mut coordinator, stored_request(&plan));
    assert_eq!(error.code.as_str(), code::TARGET_PROTECTED);
    assert_eq!(error.family, ErrorFamily::Eligibility);
    // An unknown protection permits nothing.
    bench.authority.records().protection = ProtectionFact::Unknown;
    let error = refusal(&mut coordinator, stored_request(&plan));
    assert_eq!(error.code.as_str(), code::TARGET_PROTECTED);
    assert_eq!(bench.host.calls(), Vec::new());

    bench.authority.records().protection = ProtectionFact::NotProtected;
    let file = bench.tree.file("a");
    let mut content: PlanContent = cleanup_content(
        "plan_2",
        &bench.tree,
        &ActionClass::DeleteSelectedFiles,
        &["a"],
        bench.clock.now(),
    );
    content.executor = ExecutorRole::Helper;
    // A helper plan is not sealed without a privilege grant, so the test
    // gives the content to the coordinator through a sealed user plan
    // only when the seal accepts it.
    if let Ok(plan) = Plan::seal(content) {
        bench.store(&plan);
        let error = refusal(&mut coordinator, stored_request(&plan));
        assert_eq!(error.code.as_str(), code::HELPER_NOT_AVAILABLE);
    }
    assert!(file.exists());
}

#[test]
fn a_manual_eviction_with_a_proposed_rule_is_refused_and_the_trash_mode_is_not() {
    let bench = Bench::new();
    bench.authority.records().registry = NoRules(Some(ReviewedRules::new().unwrap()));
    let file = bench.tree.file("a");
    let trashed = bench.tree.file("b");
    let mut content: PlanContent = cleanup_content(
        "plan_1",
        &bench.tree,
        &ActionClass::EvictRegenerableData,
        &["a"],
        bench.clock.now(),
    );
    for target in &mut content.targets {
        if let TargetBinding::File(binding) = &mut target.binding {
            binding.rule = Some(RuleRef {
                id: RuleId::new(EXPIRED_TEMPORARY_RULE_ID).unwrap(),
                revision: RuleRevisionId::new(EXPIRED_TEMPORARY_REVISION).unwrap(),
            });
        }
    }
    let evict = Plan::seal(content).unwrap();
    let trash = cleanup_plan(
        "plan_2",
        &bench.tree,
        &ActionClass::MoveToTrash,
        &["b"],
        bench.clock.now(),
    );
    bench.store(&evict);
    bench.store(&trash);
    let mut bench = bench;
    let mut coordinator = bench.start();
    // The layout of the rule is in the proposed state, which permits no
    // mode: the eviction is refused also for a manual plan.
    let error = refusal(&mut coordinator, stored_request(&evict));
    assert_eq!(error.code.as_str(), "rule_mode_not_validated");
    assert_eq!(error.family, ErrorFamily::Eligibility);
    assert!(file.exists());
    // A Trash plan binds no rule, so the state of the rule does not
    // change it.
    let operation_id = admitted(&mut coordinator, stored_request(&trash));
    let view = run(&mut coordinator, &bench.clock, &operation_id);
    assert_eq!(view.operation.state(), &OperationState::Completed);
    assert!(!trashed.exists());
}

#[test]
fn a_second_coordinator_is_told_to_enqueue_and_the_first_one_serves_the_request() {
    let (mut bench, plan, file) = bench_with_plan();
    let mut first = bench.start();
    // The second process does not get the lock.
    let Start::Busy { journal, .. } = bench.try_start() else {
        panic!("two coordinators hold the lock");
    };
    let mut client = journal.inner;
    let request = queued(
        "request_1",
        RequestBody::Apply {
            approval: approval(&plan),
        },
        bench.clock.now(),
    );
    client.enqueue_request(&request).unwrap();
    assert_eq!(
        client.request_status(&request.request_id).unwrap(),
        Some(RequestStatus::Queued)
    );
    assert!(first.serve_queue());
    let Some(RequestStatus::Completed {
        completion: RequestCompletion::Operation { operation_id },
    }) = client.request_status(&request.request_id).unwrap()
    else {
        panic!("the request has no operation");
    };
    run(&mut first, &bench.clock, &operation_id);
    // The client reads the result by the operation identity.
    let stored = client.operation(&operation_id).unwrap().unwrap();
    assert_eq!(stored.state(), &OperationState::Completed);
    assert!(!file.exists());
}

#[test]
fn a_repeated_apply_returns_the_one_operation() {
    let (mut bench, plan, file) = bench_with_plan();
    let mut coordinator = bench.start();
    let operation_id = admitted(&mut coordinator, stored_request(&plan));
    // Before the first step.
    let ApplyOutcome::Existing { operation } = coordinator.apply(stored_request(&plan)) else {
        panic!("a second operation was made");
    };
    assert_eq!(operation.operation_id(), &operation_id);
    run(&mut coordinator, &bench.clock, &operation_id);
    assert!(!file.exists());
    assert_eq!(bench.intents(), 1);
    // After the end, and also after the plan expired.
    bench.clock.advance(500 * SECOND);
    let ApplyOutcome::Existing { operation } = coordinator.apply(stored_request(&plan)) else {
        panic!("a second operation was made");
    };
    assert_eq!(operation.state(), &OperationState::Completed);
    assert_eq!(bench.intents(), 1);
    // A different user gets a conflict and no status of the operation.
    let mut other = stored_request(&plan);
    other.principal.uid = svalnir_core::process::Uid::new(principal().uid.get() + 1);
    let error = refusal(&mut coordinator, other);
    assert_eq!(error.family, ErrorFamily::Request);
}

#[test]
fn two_clients_that_apply_one_plan_get_one_operation_and_one_dispatch() {
    let (mut bench, plan, file) = bench_with_plan();
    let mut client = open_journal(&bench.tree.database);
    for name in ["request_1", "request_2"] {
        let request = queued(
            name,
            RequestBody::Apply {
                approval: approval(&plan),
            },
            bench.clock.now(),
        );
        client.enqueue_request(&request).unwrap();
    }
    let mut coordinator = bench.start();
    for _ in 0..20 {
        coordinator.step();
    }
    let mut operations = Vec::new();
    for name in ["request_1", "request_2"] {
        let id = svalnir_core::id::RequestId::new(name).unwrap();
        let Some(RequestStatus::Completed {
            completion: RequestCompletion::Operation { operation_id },
        }) = client.request_status(&id).unwrap()
        else {
            panic!("the request {name} has no operation");
        };
        operations.push(operation_id);
    }
    assert_eq!(operations[0], operations[1]);
    assert_eq!(bench.intents(), 1);
    assert!(!file.exists());
}

#[test]
fn a_duplicate_plan_identity_with_different_targets_is_rejected() {
    let (mut bench, plan, file) = bench_with_plan();
    let other_file = bench.tree.file("b");
    let different = cleanup_plan(
        "plan_1",
        &bench.tree,
        &ActionClass::DeleteSelectedFiles,
        &["b"],
        bench.clock.now(),
    );
    assert_ne!(plan.digest(), different.digest());
    let mut coordinator = bench.start();
    let request = ApplyRequest {
        approval: approval(&different),
        principal: principal(),
        plan: Some(different),
        incident: None,
    };
    let error = refusal(&mut coordinator, request);
    assert_eq!(error.code.as_str(), code::PLAN_CONFLICT);
    assert_eq!(error.family, ErrorFamily::Request);
    assert!(other_file.exists());
    assert_nothing_changed(&bench, &file);
}

#[test]
fn a_second_operation_on_a_leased_resource_is_refused_until_the_first_one_is_settled() {
    let mut bench = Bench::new();
    bench.tree.file("a");
    bench.tree.file("b");
    let now = bench.clock.now();
    let class = ActionClass::DeleteSelectedFiles;
    let first = cleanup_plan("plan_1", &bench.tree, &class, &["a"], now);
    let second = cleanup_plan("plan_2", &bench.tree, &class, &["b"], now);
    bench.store(&first);
    bench.store(&second);
    let mut coordinator = bench.start();
    let operation_id = admitted(&mut coordinator, stored_request(&first));
    // The two plans have the same cleanup root.
    let error = refusal(&mut coordinator, stored_request(&second));
    assert_eq!(error.code.as_str(), code::LEASE_UNAVAILABLE);
    assert_eq!(error.family, ErrorFamily::Limits);
    assert!(bench.tree.root.join("b").exists());
    run(&mut coordinator, &bench.clock, &operation_id);
    // The refusal changed nothing, so the plan can be applied now.
    let operation_id = admitted(&mut coordinator, stored_request(&second));
    let view = run(&mut coordinator, &bench.clock, &operation_id);
    assert_eq!(view.operation.state(), &OperationState::Completed);
    assert!(!bench.tree.root.join("b").exists());
}

#[test]
fn two_operations_on_different_processes_wait_in_sequence() {
    let mut bench = Bench::new();
    let first_member = bench.host.spawn(4242);
    let second_member = bench.host.spawn(4343);
    bench.host.world().exits_on_term.extend([4242, 4343]);
    let now = bench.clock.now();
    let first = stop_plan("plan_1", vec![first_member.clone()], Escalation::None, now);
    let second = Plan::seal(stop_content(
        "plan_2",
        vec![second_member],
        Escalation::None,
        now,
    ))
    .unwrap();
    // The same generation in a third plan is a lease conflict.
    let third = stop_plan("plan_3", vec![first_member], Escalation::None, now);
    for plan in [&first, &second, &third] {
        bench.store(plan);
    }
    let mut coordinator = bench.start();
    let first_id = admitted(&mut coordinator, stored_request(&first));
    let second_id = admitted(&mut coordinator, stored_request(&second));
    let error = refusal(&mut coordinator, stored_request(&third));
    assert_eq!(error.code.as_str(), code::LEASE_UNAVAILABLE);
    // The second operation waits: one intervention action at a time.
    let waiting = coordinator.operation(&second_id).unwrap().unwrap();
    assert_eq!(waiting.phase, super::super::Phase::Waiting);
    let view = run(&mut coordinator, &bench.clock, &second_id);
    assert_eq!(view.operation.state(), &OperationState::Completed);
    let first_view = coordinator.operation(&first_id).unwrap().unwrap();
    assert_eq!(first_view.operation.state(), &OperationState::Completed);
}
