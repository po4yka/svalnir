//! Crash boundaries with a real process exit (`docs/VALIDATION.md`
//! section 7, VAL-07).
//!
//! Each test makes a file tree and a journal in its own temporary
//! directory and stores one manual cleanup plan. It then starts the test
//! binary again as a child process, which runs a coordinator on that
//! journal and ends itself with `SIGKILL` at one boundary. `SIGKILL`
//! gives no destructor, no clean close of the database, and no crash
//! report. The kernel releases the coordinator lock. The test then starts
//! a new executor lifetime on the same journal and checks the recovery
//! that `docs/ACTION_CONTRACTS.md` section 12 specifies.
//!
//! The boundaries are points in the code of the test journal and the test
//! filesystem executor (`support::FailingJournal`, [`CrashingFs`]). They
//! are in this test build only: a build that is not a test build has no
//! such point. The child removes entries only below the temporary
//! directory of its parent test, and a test signals only its own child
//! and the child only itself. A process exit is not a power failure: no
//! test here removes power or shows the durability of a commit on the
//! storage.

use std::fs;
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use svalnir_core::action::{
    ActionClass, Attribution, Journal as _, Operation, OperationState, Plan, TargetEffect,
};
use svalnir_core::id::{OperationId, PlanId};

use super::super::{ApplyOutcome, FilesystemExecutor, Start, code};
use super::support::{
    Bench, TestClock, TrashMode, Tree, admitted, cleanup_plan, open_journal, principal, refusal,
    run, stored_request,
};
use crate::executor::fs::{AdmittedStep, ApprovedRoots, FsExecutor, StepOutcome, StopSignal};
use crate::journal::{JournalOptions, OperationJournal};

const POINT_VARIABLE: &str = "SVALNIR_TEST_CRASH_POINT";
const BASE_VARIABLE: &str = "SVALNIR_TEST_CRASH_BASE";
const CHILD_TEST: &str = "coordinator::tests::crash::crash_child_entry";
/// The longest time that a child runs.
const CHILD_LIMIT: Duration = Duration::from_secs(60);
/// The reading of the stop signal at which the child ends during the call
/// of a directory target: after the executor removed at least one entry.
const DURING_CALL_CHECK: u32 = 3;
/// The number of entries of the directory target.
const DIRECTORY_ENTRIES: usize = 6;
const REPLACEMENT: &[u8] = b"replacement";

/// A point at which the child process ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CrashPoint {
    /// Before the journal call that commits the intent of a step.
    BeforeIntent,
    /// After the intent is committed, before the dispatch consumption.
    AfterIntent,
    /// After the dispatch consumption is committed, before the executor
    /// call.
    AfterConsume,
    /// In the executor call of a directory target, after a part of the
    /// entries was removed.
    DuringCall,
    /// After the executor call returned in the executor, before the
    /// coordinator has its result.
    BeforeReturn,
    /// Before the journal call that records the settled result of a step.
    BeforeStepResult,
    /// Before the journal call that records the settled operation.
    BeforeOperationResult,
}

impl CrashPoint {
    const ALL: [Self; 7] = [
        Self::BeforeIntent,
        Self::AfterIntent,
        Self::AfterConsume,
        Self::DuringCall,
        Self::BeforeReturn,
        Self::BeforeStepResult,
        Self::BeforeOperationResult,
    ];

    fn name(self) -> &'static str {
        match self {
            Self::BeforeIntent => "before_intent",
            Self::AfterIntent => "after_intent",
            Self::AfterConsume => "after_consume",
            Self::DuringCall => "during_call",
            Self::BeforeReturn => "before_return",
            Self::BeforeStepResult => "before_step_result",
            Self::BeforeOperationResult => "before_operation_result",
        }
    }
}

/// The boundary of this process: only in a child that a test of this
/// file started.
fn armed() -> Option<CrashPoint> {
    static ARMED: OnceLock<Option<CrashPoint>> = OnceLock::new();
    *ARMED.get_or_init(|| {
        let name = std::env::var(POINT_VARIABLE).ok()?;
        CrashPoint::ALL
            .into_iter()
            .find(|point| point.name() == name)
    })
}

/// Ends this process with `SIGKILL` when `point` is its boundary. In
/// each other process it does nothing.
pub(super) fn reach(point: CrashPoint) {
    if armed() != Some(point) {
        return;
    }
    let pid: libc::pid_t = libc::pid_t::try_from(std::process::id()).unwrap();
    // SAFETY: `kill` has no memory precondition, and the PID of this
    // process addresses only this process.
    unsafe {
        libc::kill(pid, libc::SIGKILL);
    }
    // The signal is delivered before the return to user code; this loop
    // is not reached.
    loop {
        std::thread::park();
    }
}

/// The filesystem executor of the child: the real executor, with the
/// boundaries in its call.
#[derive(Debug)]
struct CrashingFs(FsExecutor);

impl FilesystemExecutor for CrashingFs {
    fn execute(
        &self,
        roots: &ApprovedRoots,
        step: AdmittedStep<'_>,
        signal: &dyn StopSignal,
    ) -> StepOutcome {
        let checks = std::cell::Cell::new(0_u32);
        let counting = || {
            checks.set(checks.get() + 1);
            if checks.get() >= DURING_CALL_CHECK {
                reach(CrashPoint::DuringCall);
            }
            signal.check()
        };
        let outcome: StepOutcome = self.0.execute_step_until(roots, step, &counting);
        reach(CrashPoint::BeforeReturn);
        outcome
    }
}

/// The body of the child process. Without the variables, which only the
/// tests of this file set, it does nothing.
#[test]
#[ignore = "the entry of a child process that the tests of this file start"]
fn crash_child_entry() {
    if armed().is_none() {
        return;
    }
    let base: PathBuf = PathBuf::from(std::env::var_os(BASE_VARIABLE).unwrap());
    let mut bench = Bench::on(Tree::at(&base), false, TrashMode::Move, 0);
    let plan: Plan = open_journal(&bench.tree.database)
        .plan(&PlanId::new("plan_1").unwrap())
        .unwrap()
        .unwrap();
    let executor: FsExecutor = bench.tree.executor(bench.trash_mode);
    let mut coordinator = match bench.start_with(move |dependencies, _| {
        dependencies.filesystem = Box::new(CrashingFs(executor));
    }) {
        Start::Coordinating(coordinator) => coordinator,
        Start::Busy { .. } => panic!("a different coordinator holds the lock"),
    };
    let operation_id: OperationId = admitted(&mut coordinator, stored_request(&plan));
    run(&mut coordinator, &bench.clock, &operation_id);
    panic!("the operation ended and reached no boundary");
}

/// A child process that is killed and collected when the value is
/// dropped before it ended.
struct ChildGuard(Option<Child>);

impl ChildGuard {
    fn wait(&mut self) -> ExitStatus {
        let limit: Instant = Instant::now() + CHILD_LIMIT;
        let child: &mut Child = self.0.as_mut().unwrap();
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                self.0 = None;
                return status;
            }
            assert!(Instant::now() < limit, "the child did not end");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            // `Child::kill` addresses only the child of this value.
            if let Err(error) = child.kill() {
                eprintln!("the child was not killed: {error}");
            }
            if let Err(error) = child.wait() {
                eprintln!("the child was not collected: {error}");
            }
        }
    }
}

/// The state that a crashed child left: the bench of the next lifetime,
/// the plan, and the operation of the child.
struct Crashed {
    bench: Bench,
    plan: Plan,
    operation_id: OperationId,
}

/// Makes a tree with `prepare`, stores a plan for `names`, and runs a
/// child that ends at `point`.
fn crash_at(point: CrashPoint, names: &[&str], prepare: impl FnOnce(&Tree)) -> Crashed {
    let tree = Tree::new();
    prepare(&tree);
    let plan: Plan = cleanup_plan(
        "plan_1",
        &tree,
        &ActionClass::DeleteSelectedFiles,
        names,
        TestClock::new().now(),
    );
    open_journal(&tree.database).record_plan(&plan).unwrap();

    let program: PathBuf = std::env::current_exe().unwrap();
    let mut child = ChildGuard(Some(
        Command::new(program)
            .args(["--ignored", "--exact", CHILD_TEST, "--test-threads=1"])
            .env(POINT_VARIABLE, point.name())
            .env(BASE_VARIABLE, tree.base())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    ));
    let status: ExitStatus = child.wait();
    assert_eq!(
        status.signal(),
        Some(libc::SIGKILL),
        "the child did not end at {point:?}: {status:?}"
    );

    let unsettled: Vec<Operation> = open_journal(&tree.database)
        .unsettled_operations(10)
        .unwrap();
    assert_eq!(unsettled.len(), 1, "the crash left no unsettled operation");
    let operation_id: OperationId = unsettled[0].operation_id().clone();
    Crashed {
        bench: Bench::on(tree, false, TrashMode::Move, 1),
        plan,
        operation_id,
    }
}

fn stored(bench: &Bench, operation_id: &OperationId) -> Operation {
    open_journal(&bench.tree.database)
        .operation(operation_id)
        .unwrap()
        .unwrap()
}

/// The effects of the results of the one step of an operation.
fn effects(operation: &Operation) -> Vec<TargetEffect> {
    operation.steps()[0]
        .results()
        .iter()
        .map(|result| result.effect.clone())
        .collect()
}

/// A plan for the entry `name` below the same root, which conflicts with
/// the lease of the crashed operation.
fn conflicting(bench: &Bench, plan: &str, name: &str) -> Plan {
    bench.tree.file(name);
    let plan: Plan = cleanup_plan(
        plan,
        &bench.tree,
        &ActionClass::DeleteSelectedFiles,
        &[name],
        bench.clock.now(),
    );
    bench.store(&plan);
    plan
}

fn entries(path: &Path) -> usize {
    fs::read_dir(path).unwrap().count()
}

fn directory(tree: &Tree) {
    let path: PathBuf = tree.root.join("d");
    fs::create_dir(&path).unwrap();
    // The executor reads the stop signal before each directory below the
    // target, so each entry is a directory with one file.
    for index in 0..DIRECTORY_ENTRIES {
        let entry: PathBuf = path.join(format!("e{index}"));
        fs::create_dir(&entry).unwrap();
        fs::write(entry.join("f"), b"content").unwrap();
    }
}

/// A step that issued no call: the restart settles it as skipped, the
/// target stays, and the single-use plan does not give a new operation.
fn assert_not_started(crashed: Crashed) {
    let Crashed {
        mut bench,
        plan,
        operation_id,
    } = crashed;
    let target: PathBuf = bench.tree.root.join("a");
    let mut coordinator = bench.start();
    coordinator.step();
    assert!(!coordinator.reconciliation_pending());

    let operation: Operation = stored(&bench, &operation_id);
    assert!(operation.state().is_settled(), "{:?}", operation.state());
    assert_ne!(operation.state(), &OperationState::Completed);
    assert_ne!(operation.state(), &OperationState::UnknownOutcome);
    assert_eq!(effects(&operation), vec![TargetEffect::Skipped]);
    let step = &operation.steps()[0];
    assert!(!step.progress().dispatch().is_possibly_submitted());
    assert_eq!(fs::read(&target).unwrap(), b"content");

    // The old intent and the old approval do not authorize a new dispatch.
    assert!(!matches!(
        coordinator.apply(stored_request(&plan)),
        ApplyOutcome::Admitted { .. }
    ));
    coordinator.step();
    assert_eq!(fs::read(&target).unwrap(), b"content");
    // No lease stays: a different plan of the root is admitted.
    let second = conflicting(&bench, "plan_2", "c");
    admitted(&mut coordinator, stored_request(&second));
}

#[test]
fn a_crash_before_the_intent_commits_dispatches_nothing() {
    let crashed = crash_at(CrashPoint::BeforeIntent, &["a"], |tree| {
        tree.file("a");
    });
    let records = open_journal(&crashed.bench.tree.database)
        .recovery_records(10)
        .unwrap();
    assert!(records[0].unsettled_steps[0].intent.is_none());
    assert!(!records[0].unsettled_steps[0].dispatch_consumed);
    assert_not_started(crashed);
}

#[test]
fn a_crash_after_the_intent_and_before_the_consumption_dispatches_nothing() {
    let crashed = crash_at(CrashPoint::AfterIntent, &["a"], |tree| {
        tree.file("a");
    });
    let records = open_journal(&crashed.bench.tree.database)
        .recovery_records(10)
        .unwrap();
    assert!(records[0].unsettled_steps[0].intent.is_some());
    assert!(!records[0].unsettled_steps[0].dispatch_consumed);
    assert_not_started(crashed);
}

#[test]
fn a_crash_after_the_consumption_is_unknown_and_never_dispatched_again() {
    let Crashed {
        mut bench,
        plan,
        operation_id,
    } = crash_at(CrashPoint::AfterConsume, &["a"], |tree| {
        tree.file("a");
    });
    let target: PathBuf = bench.tree.root.join("a");
    let records = open_journal(&bench.tree.database)
        .recovery_records(10)
        .unwrap();
    assert!(records[0].unsettled_steps[0].dispatch_consumed);
    // The child issued no call.
    assert_eq!(fs::read(&target).unwrap(), b"content");

    let mut coordinator = bench.start();
    coordinator.step();
    assert!(!coordinator.reconciliation_pending());
    // A consumed dispatch with no outcome is unknown, also when the entry
    // is at its name: the journal has no proof that no call was issued.
    let operation: Operation = stored(&bench, &operation_id);
    assert_eq!(operation.state(), &OperationState::UnknownOutcome);
    assert_eq!(effects(&operation), vec![TargetEffect::UnknownOutcome]);
    assert_eq!(fs::read(&target).unwrap(), b"content");
    let second = conflicting(&bench, "plan_2", "c");
    assert_eq!(
        refusal(&mut coordinator, stored_request(&second))
            .code
            .as_str(),
        code::LEASE_UNAVAILABLE
    );
    assert!(!matches!(
        coordinator.apply(stored_request(&plan)),
        ApplyOutcome::Admitted { .. }
    ));

    // An acknowledgment releases the lease and keeps the unknown result.
    // The step is not dispatched again.
    coordinator
        .acknowledge(&operation_id, &principal())
        .unwrap();
    let operation_2: OperationId = admitted(&mut coordinator, stored_request(&second));
    run(&mut coordinator, &bench.clock, &operation_2);
    assert_eq!(
        stored(&bench, &operation_id).state(),
        &OperationState::UnknownOutcome
    );
    assert_eq!(fs::read(&target).unwrap(), b"content");
}

#[test]
fn a_crash_during_the_call_keeps_the_partial_effect_unknown_and_retries_nothing() {
    let Crashed {
        mut bench,
        operation_id,
        ..
    } = crash_at(CrashPoint::DuringCall, &["d"], directory);
    let path: PathBuf = bench.tree.root.join("d");
    let left: usize = entries(&path);
    assert!(
        left > 0 && left < DIRECTORY_ENTRIES,
        "the child removed {} of {DIRECTORY_ENTRIES} entries",
        DIRECTORY_ENTRIES - left
    );

    let mut coordinator = bench.start();
    coordinator.step();
    assert!(!coordinator.reconciliation_pending());
    let operation: Operation = stored(&bench, &operation_id);
    assert_eq!(operation.state(), &OperationState::UnknownOutcome);
    // No call was repeated: the entries that the child left stay.
    assert_eq!(entries(&path), left);
    let second = conflicting(&bench, "plan_2", "c");
    assert_eq!(
        refusal(&mut coordinator, stored_request(&second))
            .code
            .as_str(),
        code::LEASE_UNAVAILABLE
    );
    coordinator.step();
    assert_eq!(entries(&path), left);
}

#[test]
fn a_crash_before_the_call_returns_recovers_the_absence_as_evidence() {
    let Crashed {
        mut bench,
        operation_id,
        ..
    } = crash_at(CrashPoint::BeforeReturn, &["a"], |tree| {
        tree.file("a");
    });
    let target: PathBuf = bench.tree.root.join("a");
    assert!(!target.exists(), "the child did not remove the entry");

    let mut coordinator = bench.start();
    coordinator.step();
    assert!(!coordinator.reconciliation_pending());
    // The absence is the final condition. Who removed the entry is not
    // established.
    let operation: Operation = stored(&bench, &operation_id);
    assert_eq!(operation.state(), &OperationState::Completed);
    let results = operation.steps()[0].results();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].effect, TargetEffect::AlreadyAbsent);
    assert_eq!(results[0].attribution, Attribution::Possible);
    let second = conflicting(&bench, "plan_2", "c");
    admitted(&mut coordinator, stored_request(&second));
}

/// After a crash at `point` with the effect done, a different object at
/// the name of the target: the restart does not target it.
fn assert_replacement_kept(point: CrashPoint) {
    let Crashed {
        mut bench,
        operation_id,
        ..
    } = crash_at(point, &["a"], |tree| {
        tree.file("a");
    });
    let target: PathBuf = bench.tree.root.join("a");
    assert!(!target.exists(), "the child did not remove the entry");
    fs::write(&target, REPLACEMENT).unwrap();

    let mut coordinator = bench.start();
    coordinator.step();
    assert!(!coordinator.reconciliation_pending());
    let operation: Operation = stored(&bench, &operation_id);
    assert_eq!(operation.state(), &OperationState::UnknownOutcome);
    assert_eq!(effects(&operation), vec![TargetEffect::UnknownOutcome]);
    assert_eq!(fs::read(&target).unwrap(), REPLACEMENT);
    let second = conflicting(&bench, "plan_2", "c");
    assert_eq!(
        refusal(&mut coordinator, stored_request(&second))
            .code
            .as_str(),
        code::LEASE_UNAVAILABLE
    );
    coordinator.step();
    assert_eq!(fs::read(&target).unwrap(), REPLACEMENT);
}

#[test]
fn a_crash_before_the_call_returns_never_targets_a_replacement() {
    assert_replacement_kept(CrashPoint::BeforeReturn);
}

#[test]
fn a_crash_before_the_step_result_commits_never_targets_a_replacement() {
    assert_replacement_kept(CrashPoint::BeforeStepResult);
}

#[test]
fn a_crash_before_the_operation_result_commits_settles_from_the_step_records() {
    let Crashed {
        mut bench,
        operation_id,
        ..
    } = crash_at(CrashPoint::BeforeOperationResult, &["a"], |tree| {
        tree.file("a");
    });
    let target: PathBuf = bench.tree.root.join("a");
    let before: Operation = stored(&bench, &operation_id);
    assert!(!before.state().is_settled());
    assert_eq!(effects(&before), vec![TargetEffect::Removed]);
    fs::write(&target, REPLACEMENT).unwrap();

    let mut coordinator = bench.start();
    coordinator.step();
    assert!(!coordinator.reconciliation_pending());
    // The recorded step result settles the operation; the replacement is
    // not probed and not touched.
    let operation: Operation = stored(&bench, &operation_id);
    assert_eq!(operation.state(), &OperationState::Completed);
    assert_eq!(effects(&operation), vec![TargetEffect::Removed]);
    assert_eq!(fs::read(&target).unwrap(), REPLACEMENT);
    let second = conflicting(&bench, "plan_2", "c");
    admitted(&mut coordinator, stored_request(&second));
}

#[test]
fn a_journal_corrupted_after_a_crash_is_refused_and_nothing_is_dispatched() {
    let Crashed { bench, .. } = crash_at(CrashPoint::AfterConsume, &["a"], |tree| {
        tree.file("a");
    });
    let target: PathBuf = bench.tree.root.join("a");
    // The header of the database file is not a header of `SQLite`.
    let mut content: Vec<u8> = fs::read(&bench.tree.database).unwrap();
    content[..16].copy_from_slice(b"not a database\0\0");
    fs::write(&bench.tree.database, &content).unwrap();

    let options = JournalOptions {
        full_fsync: false,
        ..JournalOptions::default()
    };
    let error = OperationJournal::open(&bench.tree.database, &options).unwrap_err();
    assert!(error.is_storage_failure(), "{error:?}");
    // The open changed nothing, and no executor lifetime started.
    assert_eq!(fs::read(&bench.tree.database).unwrap(), content);
    assert_eq!(fs::read(&target).unwrap(), b"content");
}
