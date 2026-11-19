//! Tests of the filesystem executor. Each test uses a temporary directory
//! that it made, and the executor acts as the user of the test.

use std::fs;
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};

use svalnir_core::action::{
    ActionError, Attribution, DispatchState, ErrorFamily, FileObjectType, NativeResult, StopReason,
    TargetEffect,
};
use svalnir_core::authority::{Generation, PrivilegeGrantRef};
use svalnir_core::file::LosslessPath;
use svalnir_core::id::{PrivilegeGrantId, RootId};
use svalnir_core::time::{MonotonicNanos, WallTime};

use super::{EvictionExecutor as _, Execution, FsEvictor};
use crate::request::{EntryTarget, LoginSessionId};
use crate::response::EntryReport;
use crate::testing::{
    EXPIRES, Fixture, SESSION, assert_reports_agree, charge, correlation, entry_of,
    entry_of_absent, make_directory, replace_with_new_file, rule, session, step_key, wall,
};
use crate::validation::{ApprovedRoot, BoundedEntry, BoundedEviction, EntryPath, RefusalReason};

fn bounded(target: EntryTarget) -> BoundedEntry {
    BoundedEntry {
        path: EntryPath::parse(&target.relative_entry).unwrap(),
        object_type: target.object_type,
        object: target.object.unwrap(),
        limit: target.charge,
    }
}

/// The accepted eviction of `targets` below `root`, as the validation
/// gives it to the executor.
fn eviction_below(root: ApprovedRoot, targets: Vec<EntryTarget>) -> BoundedEviction {
    let entries: Vec<BoundedEntry> = targets.into_iter().map(bounded).collect();
    BoundedEviction {
        key: step_key("step-1"),
        login_session: LoginSessionId::new(session(SESSION)),
        correlation: correlation("step-1"),
        grant: PrivilegeGrantRef {
            grant_id: PrivilegeGrantId::new("grant-1").unwrap(),
            generation: Generation::new(3),
        },
        root,
        rule: rule(),
        limit: charge(0, 0),
        entries,
        deadline: MonotonicNanos::new(EXPIRES),
    }
}

fn eviction(fixture: &Fixture, targets: Vec<EntryTarget>) -> BoundedEviction {
    eviction_below(fixture.approved_root(), targets)
}

/// Runs the executor with a gate that permits each entry.
fn run(eviction: &BoundedEviction) -> Vec<EntryReport> {
    let mut gate = || -> Result<WallTime, RefusalReason> { Ok(wall(1_000)) };
    let execution: Execution = FsEvictor::new().evict(eviction, &mut gate);
    assert_eq!(execution.stopped, None);
    assert_eq!(execution.entries.len(), eviction.entries.len());
    assert_reports_agree(&execution.entries);
    execution.entries
}

fn failure_of(report: &EntryReport) -> (&str, &ErrorFamily) {
    let failure: &ActionError = report.failure.as_ref().expect("the report has an error");
    (failure.code.as_str(), &failure.family)
}

fn assert_skipped(report: &EntryReport, code: &str, family: &ErrorFamily) {
    assert_eq!(report.effect, TargetEffect::Skipped, "{report:?}");
    assert_eq!(report.dispatch, DispatchState::NotSubmitted);
    assert_eq!(report.evidence.native, NativeResult::NotCalled);
    assert_eq!(report.attribution, Attribution::NotApplicable);
    assert_eq!(report.stop_reason, StopReason::TargetSkipped);
    assert_eq!(failure_of(report), (code, family));
}

#[test]
fn a_file_a_link_and_an_empty_directory_are_removed() {
    let fixture: Fixture = Fixture::new();
    let file: PathBuf = fixture.file("cache/a.tmp");
    let empty: PathBuf = fixture.root.join("cache/empty");
    make_directory(&empty);
    let outside_file: PathBuf = fixture.outside.join("kept.txt");
    fs::write(&outside_file, b"personal").unwrap();
    let link: PathBuf = fixture.root.join("cache/link");
    symlink(&outside_file, &link).unwrap();

    let reports: Vec<EntryReport> = run(&eviction(
        &fixture,
        vec![
            fixture.entry("cache/a.tmp"),
            fixture.entry("cache/link"),
            fixture.entry("cache/empty"),
        ],
    ));

    for report in &reports {
        assert_eq!(report.effect, TargetEffect::Removed);
        assert_eq!(report.dispatch, DispatchState::Submitted);
        assert_eq!(report.attribution, Attribution::Possible);
        assert_eq!(report.stop_reason, StopReason::Completed);
        assert_eq!(report.evidence.observed_at, Some(wall(1_000)));
        assert!(report.evidence.source.is_some());
        assert_eq!(report.removed.items.get(), 1);
    }
    assert!(!file.exists());
    assert!(fs::symlink_metadata(&link).is_err());
    assert!(!empty.exists());
    // The link was removed and not followed.
    assert_eq!(fs::read(&outside_file).unwrap(), b"personal");
    assert!(fixture.root.join("cache").is_dir());
}

#[test]
fn a_replaced_object_is_not_removed() {
    let fixture: Fixture = Fixture::new();
    let file: PathBuf = fixture.file("a.tmp");
    let becomes_directory: PathBuf = fixture.file("b.tmp");
    let becomes_link: PathBuf = fixture.file("c.tmp");
    let outside_file: PathBuf = fixture.outside.join("kept.txt");
    fs::write(&outside_file, b"personal").unwrap();
    let planned: BoundedEviction = eviction(
        &fixture,
        vec![
            fixture.entry("a.tmp"),
            fixture.entry("b.tmp"),
            fixture.entry("c.tmp"),
        ],
    );
    // After the validation: another file, a directory, and a link to a
    // file outside the root get the three names.
    replace_with_new_file(&file);
    fs::remove_file(&becomes_directory).unwrap();
    make_directory(&becomes_directory);
    fs::remove_file(&becomes_link).unwrap();
    symlink(&outside_file, &becomes_link).unwrap();

    let reports: Vec<EntryReport> = run(&planned);

    for report in &reports {
        assert_skipped(report, "helper_target_changed", &ErrorFamily::Evidence);
    }
    assert_eq!(fs::read(&file).unwrap(), b"not the planned object");
    assert!(becomes_directory.is_dir());
    assert!(fs::symlink_metadata(&becomes_link).is_ok());
    assert_eq!(fs::read(&outside_file).unwrap(), b"personal");
}

#[test]
fn a_symbolic_link_in_the_path_is_not_followed() {
    let fixture: Fixture = Fixture::new();
    let outside_file: PathBuf = fixture.outside.join("victim.txt");
    fs::write(&outside_file, b"personal").unwrap();
    // `root/escape` is a link to the directory beside the root. The entry
    // names the file through the link, with the identifiers of the file.
    symlink(&fixture.outside, fixture.root.join("escape")).unwrap();
    let through_link: EntryTarget = entry_of(&outside_file, "escape/victim.txt");

    let reports: Vec<EntryReport> = run(&eviction(&fixture, vec![through_link]));

    assert_skipped(&reports[0], "helper_path_changed", &ErrorFamily::Evidence);
    assert_eq!(fs::read(&outside_file).unwrap(), b"personal");
}

#[test]
fn a_root_that_is_a_symbolic_link_is_not_opened() {
    let fixture: Fixture = Fixture::new();
    let outside_file: PathBuf = fixture.outside.join("victim.txt");
    fs::write(&outside_file, b"personal").unwrap();
    // The record has the path of a root that is now a link to another
    // directory.
    let link_root: PathBuf = fixture.root.parent().unwrap().join("moved-root");
    symlink(&fixture.outside, &link_root).unwrap();
    let root: ApprovedRoot = ApprovedRoot::new(
        RootId::new("root-a").unwrap(),
        &LosslessPath::from_path(&link_root).unwrap(),
        vec![rule()],
    )
    .unwrap();

    let reports: Vec<EntryReport> = run(&eviction_below(
        root,
        vec![entry_of(&outside_file, "victim.txt")],
    ));

    assert_skipped(
        &reports[0],
        "helper_root_unavailable",
        &ErrorFamily::Evidence,
    );
    assert!(outside_file.exists());
}

#[test]
fn a_directory_that_another_user_can_write_to_is_refused() {
    let fixture: Fixture = Fixture::new();
    let in_open_directory: PathBuf = fixture.file("open/a.tmp");
    let open: &Path = in_open_directory.parent().unwrap();
    fs::set_permissions(open, fs::Permissions::from_mode(0o777)).unwrap();
    let in_group_directory: PathBuf = fixture.file("group/b.tmp");
    fs::set_permissions(
        in_group_directory.parent().unwrap(),
        fs::Permissions::from_mode(0o775),
    )
    .unwrap();

    let reports: Vec<EntryReport> = run(&eviction(
        &fixture,
        vec![fixture.entry("open/a.tmp"), fixture.entry("group/b.tmp")],
    ));

    for report in &reports {
        assert_skipped(
            report,
            "helper_path_not_controlled",
            &ErrorFamily::Eligibility,
        );
    }
    assert!(in_open_directory.exists());
    assert!(in_group_directory.exists());

    // The same rule for the root: each entry is skipped.
    let file: PathBuf = fixture.file("c.tmp");
    fs::set_permissions(&fixture.root, fs::Permissions::from_mode(0o777)).unwrap();
    let reports: Vec<EntryReport> = run(&eviction(
        &fixture,
        vec![fixture.entry("c.tmp"), entry_of_absent("gone.tmp")],
    ));
    for report in &reports {
        assert_skipped(
            report,
            "helper_root_not_controlled",
            &ErrorFamily::Eligibility,
        );
    }
    assert!(file.exists());
    fs::set_permissions(&fixture.root, fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn a_hard_linked_file_is_not_removed() {
    let fixture: Fixture = Fixture::new();
    let file: PathBuf = fixture.file("a.tmp");
    let second_name: PathBuf = fixture.outside.join("second-name");
    fs::hard_link(&file, &second_name).unwrap();

    let reports: Vec<EntryReport> = run(&eviction(&fixture, vec![fixture.entry("a.tmp")]));

    assert_skipped(
        &reports[0],
        "helper_target_hard_linked",
        &ErrorFamily::Eligibility,
    );
    assert!(file.exists());
    assert!(second_name.exists());
}

#[test]
fn an_object_over_the_bound_of_its_entry_is_not_removed() {
    let fixture: Fixture = Fixture::new();
    let file: PathBuf = fixture.file("a.tmp");
    fs::write(&file, vec![1_u8; 64 * 1024]).unwrap();
    let mut target: EntryTarget = fixture.entry("a.tmp");
    target.charge = charge(4 * 1024, 1);

    let reports: Vec<EntryReport> = run(&eviction(&fixture, vec![target]));

    assert_skipped(
        &reports[0],
        "helper_target_over_bound",
        &ErrorFamily::Limits,
    );
    assert!(file.exists());
}

#[test]
fn a_directory_is_removed_only_when_it_is_empty() {
    let fixture: Fixture = Fixture::new();
    let inner: PathBuf = fixture.file("full/inner.tmp");
    let directory: PathBuf = fixture.root.join("full");

    let reports: Vec<EntryReport> = run(&eviction(&fixture, vec![fixture.entry("full")]));

    let report: &EntryReport = &reports[0];
    assert_eq!(report.effect, TargetEffect::Refused);
    assert_eq!(report.dispatch, DispatchState::Submitted);
    assert_eq!(report.stop_reason, StopReason::Failed);
    assert_eq!(
        report.evidence.native,
        NativeResult::Errno {
            errno: libc::ENOTEMPTY
        }
    );
    assert_eq!(
        failure_of(report),
        ("helper_directory_not_empty", &ErrorFamily::Native)
    );
    assert_eq!(
        report.failure.as_ref().unwrap().dispatch,
        DispatchState::Submitted
    );
    assert!(directory.is_dir());
    assert!(inner.exists());
}

#[test]
fn an_absent_entry_and_an_entry_of_an_absent_directory_are_already_absent() {
    let fixture: Fixture = Fixture::new();

    let reports: Vec<EntryReport> = run(&eviction(
        &fixture,
        vec![
            entry_of_absent("gone.tmp"),
            entry_of_absent("no-such-directory/gone.tmp"),
        ],
    ));

    for report in &reports {
        assert_eq!(report.effect, TargetEffect::AlreadyAbsent);
        assert_eq!(report.dispatch, DispatchState::NotSubmitted);
        assert_eq!(report.attribution, Attribution::NotApplicable);
        assert_eq!(report.evidence.native, NativeResult::NotCalled);
        assert_eq!(report.failure, None);
    }
}

#[test]
fn an_entry_whose_type_this_build_does_not_recognize_is_not_removed() {
    let fixture: Fixture = Fixture::new();
    let file: PathBuf = fixture.file("a.tmp");
    let mut target: EntryTarget = fixture.entry("a.tmp");
    target.object_type = FileObjectType::from_wire("a_later_type");

    let reports: Vec<EntryReport> = run(&eviction(&fixture, vec![target]));

    assert_skipped(&reports[0], "helper_target_changed", &ErrorFamily::Evidence);
    assert!(file.exists());
}

#[test]
fn a_gate_refusal_stops_the_step_before_the_entry() {
    let fixture: Fixture = Fixture::new();
    let first: PathBuf = fixture.file("a.tmp");
    let second: PathBuf = fixture.file("b.tmp");
    let third: PathBuf = fixture.file("c.tmp");
    let planned: BoundedEviction = eviction(
        &fixture,
        vec![
            fixture.entry("a.tmp"),
            fixture.entry("b.tmp"),
            fixture.entry("c.tmp"),
        ],
    );
    // The grant is revoked after the first entry.
    let mut calls: u32 = 0;
    let mut gate = || -> Result<WallTime, RefusalReason> {
        calls += 1;
        if calls == 1 {
            Ok(wall(1_000))
        } else {
            Err(RefusalReason::GrantRevoked)
        }
    };

    let execution: Execution = FsEvictor::new().evict(&planned, &mut gate);

    assert_eq!(execution.stopped, Some(RefusalReason::GrantRevoked));
    assert_reports_agree(&execution.entries);
    assert_eq!(execution.entries[0].effect, TargetEffect::Removed);
    for stopped in &execution.entries[1..] {
        assert_eq!(stopped.effect, TargetEffect::Skipped);
        assert_eq!(stopped.dispatch, DispatchState::NotSubmitted);
        assert_eq!(stopped.stop_reason, StopReason::AuthorityMissing);
        assert_eq!(stopped.failure, None);
    }
    // The gate is not asked again after it refused.
    assert_eq!(calls, 2);
    assert!(!first.exists());
    assert!(second.exists());
    assert!(third.exists());
}

#[test]
fn a_gate_that_refuses_the_first_entry_leaves_the_root_closed() {
    let fixture: Fixture = Fixture::new();
    let file: PathBuf = fixture.file("a.tmp");
    let planned: BoundedEviction = eviction(&fixture, vec![fixture.entry("a.tmp")]);
    let mut gate = || -> Result<WallTime, RefusalReason> { Err(RefusalReason::RequestExpired) };

    let execution: Execution = FsEvictor::new().evict(&planned, &mut gate);

    assert_eq!(execution.stopped, Some(RefusalReason::RequestExpired));
    assert_eq!(
        execution.entries[0].stop_reason,
        StopReason::DeadlineExpired
    );
    assert_eq!(execution.entries[0].dispatch, DispatchState::NotSubmitted);
    assert!(file.exists());
}

#[test]
fn a_root_below_a_directory_that_another_user_can_write_to_is_refused() {
    let fixture: Fixture = Fixture::new();
    let file: PathBuf = fixture.file("a.tmp");
    let above: &Path = fixture.root.parent().unwrap();
    // A user that can write to the directory above the root can put
    // another directory at the name of the root.
    fs::set_permissions(above, fs::Permissions::from_mode(0o777)).unwrap();

    let reports: Vec<EntryReport> = run(&eviction(&fixture, vec![fixture.entry("a.tmp")]));

    assert_skipped(
        &reports[0],
        "helper_root_not_controlled",
        &ErrorFamily::Eligibility,
    );
    assert!(file.exists());

    // With the sticky bit, a user can replace only its own entries there,
    // and the root has a controlling owner.
    fs::set_permissions(above, fs::Permissions::from_mode(0o1777)).unwrap();
    let reports: Vec<EntryReport> = run(&eviction(&fixture, vec![fixture.entry("a.tmp")]));
    assert_eq!(reports[0].effect, TargetEffect::Removed);
    fs::set_permissions(above, fs::Permissions::from_mode(0o700)).unwrap();
}
