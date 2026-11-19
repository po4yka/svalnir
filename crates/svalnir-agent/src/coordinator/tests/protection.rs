//! The catalog of protected file locations at admission.

use std::path::PathBuf;

use svalnir_core::action::{ActionClass, ErrorFamily};

use super::super::code;
use super::support::{Bench, admitted, cleanup_plan, refusal, stored_request};
use crate::protection::ProtectedLocations;

/// The locations of a test: the home directory of the tree, and a state
/// directory in the temporary directory of the tree.
fn locations(bench: &Bench, state: &str) -> ProtectedLocations {
    let base: PathBuf = bench.tree.root.parent().unwrap().to_path_buf();
    let state: PathBuf = base.join(state);
    if !state.exists() {
        std::fs::create_dir(&state).unwrap();
    }
    ProtectedLocations::resolve(Some(&base.join("home")), Some(&state))
}

#[test]
fn a_target_in_the_state_directory_is_refused_at_admission() {
    let mut bench = Bench::new();
    let file = bench.tree.file("a");
    // The cleanup root of the plan is the state directory of this
    // coordinator: a plan that a different process built with a different
    // state directory.
    bench.authority.records().locations = locations(&bench, "root");
    for (plan_id, class) in [
        ("plan_1", ActionClass::DeleteSelectedFiles),
        ("plan_2", ActionClass::MoveToTrash),
    ] {
        let plan = cleanup_plan(plan_id, &bench.tree, &class, &["a"], bench.clock.now());
        bench.store(&plan);
        let mut coordinator = bench.start();
        let error = refusal(&mut coordinator, stored_request(&plan));
        assert_eq!(error.code.as_str(), code::TARGET_PROTECTED);
        assert_eq!(error.family, ErrorFamily::Eligibility);
        assert!(coordinator.shutdown().is_ok());
    }
    assert!(file.exists());
    assert_eq!(bench.intents(), 0);
}

#[test]
fn a_link_to_the_state_directory_is_refused_at_admission() {
    let mut bench = Bench::new();
    bench.authority.records().locations = locations(&bench, "state");
    let state = bench.tree.root.parent().unwrap().join("state");
    std::os::unix::fs::symlink(&state, bench.tree.root.join("link")).unwrap();
    let plan = cleanup_plan(
        "plan_1",
        &bench.tree,
        &ActionClass::DeleteSelectedFiles,
        &["link"],
        bench.clock.now(),
    );
    bench.store(&plan);
    let mut coordinator = bench.start();
    let error = refusal(&mut coordinator, stored_request(&plan));
    assert_eq!(error.code.as_str(), code::TARGET_PROTECTED);
    assert!(state.exists());
    assert!(bench.tree.root.join("link").exists());
}

#[test]
fn one_protected_target_refuses_the_plan_and_no_target_is_removed() {
    let mut bench = Bench::new();
    let ordinary = bench.tree.file("a");
    bench.authority.records().locations = locations(&bench, "state");
    let state = bench.tree.root.parent().unwrap().join("state");
    std::os::unix::fs::symlink(&state, bench.tree.root.join("link")).unwrap();
    let plan = cleanup_plan(
        "plan_1",
        &bench.tree,
        &ActionClass::DeleteSelectedFiles,
        &["a", "link"],
        bench.clock.now(),
    );
    bench.store(&plan);
    let mut coordinator = bench.start();
    let error = refusal(&mut coordinator, stored_request(&plan));
    assert_eq!(error.code.as_str(), code::TARGET_PROTECTED);
    assert!(ordinary.exists());
}

#[test]
fn a_location_that_is_not_known_refuses_the_plan() {
    let mut bench = Bench::new();
    let file = bench.tree.file("a");
    let base: PathBuf = bench.tree.root.parent().unwrap().to_path_buf();
    for unknown in [
        ProtectedLocations::default(),
        // A home directory with no state directory, and the reverse.
        ProtectedLocations::resolve(Some(&base.join("home")), None),
        ProtectedLocations::resolve(None, Some(&base.join("home"))),
    ] {
        bench.authority.records().locations = unknown;
        let plan = cleanup_plan(
            "plan_1",
            &bench.tree,
            &ActionClass::DeleteSelectedFiles,
            &["a"],
            bench.clock.now(),
        );
        bench.store(&plan);
        let mut coordinator = bench.start();
        let error = refusal(&mut coordinator, stored_request(&plan));
        assert_eq!(error.code.as_str(), code::TARGET_PROTECTION_UNKNOWN);
        assert_eq!(error.family, ErrorFamily::Evidence);
        assert!(coordinator.shutdown().is_ok());
    }
    assert!(file.exists());
}

#[test]
fn a_target_that_is_absent_at_admission_does_not_refuse_the_plan() {
    let mut bench = Bench::new();
    let present = bench.tree.file("a");
    let absent = bench.tree.file("b");
    bench.authority.records().locations = locations(&bench, "state");
    let plan = cleanup_plan(
        "plan_1",
        &bench.tree,
        &ActionClass::DeleteSelectedFiles,
        &["a", "b"],
        bench.clock.now(),
    );
    bench.store(&plan);
    std::fs::remove_file(&absent).unwrap();
    let mut coordinator = bench.start();
    // The plan is admitted: the entry that is absent gets no call, and the
    // other target is not held back.
    let operation_id = admitted(&mut coordinator, stored_request(&plan));
    let view = super::support::run(&mut coordinator, &bench.clock, &operation_id);
    assert!(!present.exists());
    assert_eq!(view.operation.steps().len(), 2);
}
