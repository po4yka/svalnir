//! Fixture tests of the detection of repositories and of the exception for
//! the checkouts of Swift Package Manager. Each test makes its units and
//! its repositories in a temporary directory; no test reads or changes a
//! repository of the host.

use std::fs;
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use tempfile::TempDir;

use super::swiftpm::parse_pins;
use super::{
    Detection, DetectionLimits, DetectionProblem, FoundRepository, MarkerKind, RefusalReason,
    RepositoryRefusal, SwiftPmCheckouts, Verdict, check_unit, detect, is_marker,
};
use crate::rules::git::{GitTool, GitToolProblem};

/// A temporary directory with a canonical path, so that no component of a
/// unit path is a symbolic link.
struct Place {
    _directory: TempDir,
    path: PathBuf,
    git: GitTool,
}

impl Place {
    fn new() -> Self {
        let directory: TempDir = TempDir::new().unwrap();
        let path: PathBuf = fs::canonicalize(directory.path()).unwrap();
        Self {
            _directory: directory,
            path,
            git: GitTool::locate().expect("the developer tools of the host have Git"),
        }
    }

    fn join(&self, relative: &str) -> PathBuf {
        self.path.join(relative)
    }

    fn write(&self, relative: &str, content: &[u8]) -> PathBuf {
        let path: PathBuf = self.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, content).unwrap();
        path
    }

    /// Runs the Git of the test in `directory`, with no configuration of
    /// the host, and gives its standard output.
    fn git(&self, directory: &Path, arguments: &[&str]) -> String {
        let output = Command::new(self.git.executable())
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &self.path)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .current_dir(directory)
            .args([
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "-c",
                "init.defaultBranch=main",
            ])
            .args(arguments)
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .unwrap();
        assert!(output.status.success(), "git {arguments:?}");
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    /// A repository at `relative` with one commit of a file.
    fn repository(&self, relative: &str) -> PathBuf {
        let path: PathBuf = self.join(relative);
        fs::create_dir_all(&path).unwrap();
        fs::write(path.join("Sources.swift"), b"let value = 1\n").unwrap();
        self.git(&path, &["init", "-q"]);
        self.git(&path, &["add", "-A"]);
        self.git(&path, &["commit", "-q", "-m", "start"]);
        path
    }

    fn check(&self, unit: &Path, checkouts: Option<&SwiftPmCheckouts>) -> Verdict {
        check_unit(
            unit,
            checkouts,
            Ok(&self.git),
            &DetectionLimits::default(),
            None,
        )
    }
}

/// The work tree and the marker kind of each repository of a detection.
fn found(detection: &Detection) -> Vec<(PathBuf, MarkerKind)> {
    detection
        .repositories
        .iter()
        .map(|repository: &FoundRepository| (repository.work_tree.clone(), repository.marker))
        .collect()
}

fn refused(reason: RefusalReason, path: &str) -> Verdict {
    Verdict::Refused(RepositoryRefusal {
        reason,
        path: Some(PathBuf::from(path)),
    })
}

// ---------------------------------------------------------------------
// The walk.
// ---------------------------------------------------------------------

#[test]
fn the_marker_name_ignores_the_case_of_ascii_letters() {
    for name in [".git", ".GIT", ".Git"] {
        assert!(is_marker(name.as_bytes()), "{name}");
    }
    for name in ["git", ".gitignore", ".git2", "x.git", ""] {
        assert!(!is_marker(name.as_bytes()), "{name}");
    }
}

#[test]
fn a_unit_with_no_repository_is_clear() {
    let place = Place::new();
    place.write("unit/a/b/file.bin", b"data");
    place.write("unit/.gitignore", b"*\n");
    assert_eq!(place.check(&place.join("unit"), None), Verdict::Clear);
}

#[test]
fn a_repository_at_depth_three_refuses_the_unit() {
    let place = Place::new();
    place.write("unit/top.bin", b"data");
    place.repository("unit/a/b/c");

    let detection: Detection = detect(&place.join("unit"), &DetectionLimits::default(), None);
    assert_eq!(detection.problem, None);
    assert_eq!(
        found(&detection),
        [(PathBuf::from("a/b/c"), MarkerKind::Directory)]
    );
    assert_eq!(
        place.check(&place.join("unit"), None),
        refused(RefusalReason::NestedRepository, "a/b/c")
    );
}

#[test]
fn a_repository_at_the_top_of_the_unit_refuses_it() {
    let place = Place::new();
    place.repository("unit");
    assert_eq!(
        place.check(&place.join("unit"), None),
        refused(RefusalReason::NestedRepository, "")
    );
}

#[test]
fn a_git_file_of_a_submodule_or_a_worktree_refuses_the_unit() {
    let place = Place::new();
    place.write("unit/vendor/dep/.git", b"gitdir: ../../../elsewhere/.git\n");

    let detection: Detection = detect(&place.join("unit"), &DetectionLimits::default(), None);
    assert_eq!(
        found(&detection),
        [(PathBuf::from("vendor/dep"), MarkerKind::File)]
    );
    assert_eq!(
        place.check(&place.join("unit"), None),
        refused(RefusalReason::NestedRepository, "vendor/dep")
    );
}

#[test]
fn a_git_symbolic_link_refuses_the_unit_and_is_not_followed() {
    let place = Place::new();
    let outside: PathBuf = place.repository("outside");
    fs::create_dir_all(place.join("unit/dep")).unwrap();
    symlink(outside.join(".git"), place.join("unit/dep/.git")).unwrap();
    // A link to a directory with a repository is not entered.
    symlink(&outside, place.join("unit/link")).unwrap();

    let detection: Detection = detect(&place.join("unit"), &DetectionLimits::default(), None);
    assert_eq!(
        found(&detection),
        [(PathBuf::from("dep"), MarkerKind::Other)]
    );
}

#[test]
fn a_bare_repository_or_a_separate_git_directory_refuses_the_unit() {
    let place = Place::new();
    fs::create_dir_all(place.join("unit/vendor")).unwrap();
    place.git(
        &place.join("unit/vendor"),
        &["init", "-q", "--bare", "mirror.git"],
    );
    let detection: Detection = detect(&place.join("unit"), &DetectionLimits::default(), None);
    assert_eq!(
        found(&detection),
        [(PathBuf::from("vendor/mirror.git"), MarkerKind::Bare)]
    );
    assert_eq!(
        place.check(&place.join("unit"), None),
        refused(RefusalReason::NestedRepository, "vendor/mirror.git")
    );

    // A work tree outside the unit whose Git directory is in the unit.
    let other = Place::new();
    fs::create_dir_all(other.join("unit")).unwrap();
    fs::create_dir_all(other.join("work")).unwrap();
    let separate: PathBuf = other.join("unit/state");
    other.git(
        &other.join("work"),
        &[
            "init",
            "-q",
            "--separate-git-dir",
            separate.to_str().unwrap(),
        ],
    );
    assert_eq!(
        other.check(&other.join("unit"), None),
        refused(RefusalReason::NestedRepository, "state")
    );
}

#[test]
fn the_tracker_of_a_scan_finds_a_marker_and_a_git_directory() {
    use super::MarkerTracker;
    use crate::scan::EntryKind;
    let mut tracker = MarkerTracker::default();
    assert!(!tracker.note(Path::new("a/objects"), EntryKind::Directory));
    assert!(!tracker.note(Path::new("a/HEAD"), EntryKind::Directory));
    assert!(!tracker.note(Path::new("a/refs"), EntryKind::Directory));
    assert_eq!(tracker.first(), None);
    assert!(tracker.note(Path::new("a/HEAD"), EntryKind::File));
    assert_eq!(tracker.first(), Some(Path::new("a")));

    let mut tracker = MarkerTracker::default();
    assert!(tracker.note(Path::new("dep/.Git"), EntryKind::File));
    assert_eq!(tracker.first(), Some(Path::new("dep/.Git")));
}

#[test]
fn a_symbolic_link_to_a_repository_is_not_entered() {
    let place = Place::new();
    let outside: PathBuf = place.repository("outside");
    fs::create_dir_all(place.join("unit")).unwrap();
    symlink(&outside, place.join("unit/link")).unwrap();
    assert_eq!(place.check(&place.join("unit"), None), Verdict::Clear);
}

/// Gives the directory at `path` its permissions back when the test ends,
/// so that the temporary directory can be removed.
struct Unlocked(PathBuf);

impl Drop for Unlocked {
    fn drop(&mut self) {
        drop(fs::set_permissions(
            &self.0,
            fs::Permissions::from_mode(0o755),
        ));
    }
}

#[test]
fn a_directory_that_cannot_be_read_refuses_the_unit() {
    let place = Place::new();
    place.write("unit/open/file.bin", b"data");
    let locked: PathBuf = place.join("unit/open/locked");
    fs::create_dir_all(&locked).unwrap();
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
    let _unlocked = Unlocked(locked);

    assert_eq!(
        place.check(&place.join("unit"), None),
        refused(RefusalReason::UnreadableDirectory, "open/locked")
    );
}

#[test]
fn a_bound_of_the_walk_refuses_the_unit() {
    let place = Place::new();
    place.write("unit/a/b/c/d/file.bin", b"data");
    let shallow = DetectionLimits {
        max_depth: 2,
        ..DetectionLimits::default()
    };
    let detection: Detection = detect(&place.join("unit"), &shallow, None);
    assert_eq!(detection.problem, Some(DetectionProblem::DepthLimit));

    let few = DetectionLimits {
        max_entries: 3,
        ..DetectionLimits::default()
    };
    assert_eq!(
        check_unit(&place.join("unit"), None, Ok(&place.git), &few, None),
        Verdict::Refused(RepositoryRefusal {
            reason: RefusalReason::DetectionIncomplete,
            path: None,
        })
    );
}

#[test]
fn a_unit_path_with_a_symbolic_link_is_not_walked() {
    let place = Place::new();
    place.write("real/file.bin", b"data");
    symlink(place.join("real"), place.join("alias")).unwrap();
    assert_eq!(
        place.check(&place.join("alias"), None),
        Verdict::Refused(RepositoryRefusal {
            reason: RefusalReason::UnitUnavailable,
            path: None,
        })
    );
}

// ---------------------------------------------------------------------
// The pins.
// ---------------------------------------------------------------------

#[test]
fn the_pins_of_versions_one_two_and_three_are_read() {
    let version_one = br#"{
        "object": {"pins": [
            {"package": "Alamofire", "repositoryURL": "https://github.com/Alamofire/Alamofire.git",
             "state": {"branch": null, "revision": "ABC123", "version": "5.8.0"}}
        ]},
        "version": 1
    }"#;
    let pins = parse_pins(version_one).unwrap();
    assert_eq!(pins.len(), 1);
    assert_eq!(pins[0].identity, "alamofire");
    assert_eq!(
        pins[0].location,
        "https://github.com/Alamofire/Alamofire.git"
    );
    assert_eq!(pins[0].revision, "abc123");

    for version in [2, 3] {
        let text: String = format!(
            r#"{{"originHash": "x", "pins": [
                {{"identity": "Swift-Argument-Parser", "kind": "remoteSourceControl",
                  "location": "https://github.com/apple/swift-argument-parser",
                  "state": {{"revision": "41982a3", "version": "1.2.3"}}}},
                {{"identity": "registry-package", "kind": "registry",
                  "state": {{"version": "1.0.0"}}}}
            ], "version": {version}}}"#
        );
        let pins = parse_pins(text.as_bytes()).unwrap();
        assert_eq!(pins.len(), 1, "a pin with no revision is not a clone");
        assert_eq!(pins[0].identity, "swift-argument-parser");
        assert_eq!(pins[0].revision, "41982a3");
    }
}

#[test]
fn a_pin_file_of_another_version_or_form_is_invalid() {
    for text in [
        &br#"{"pins": [], "version": 4}"#[..],
        br#"{"pins": [], "version": 1}"#,
        br#"{"object": {"pins": []}, "version": 2}"#,
        b"not json",
    ] {
        assert!(parse_pins(text).is_err());
    }
}

#[test]
fn the_pins_of_an_xcode_project_are_in_its_workspace() {
    let project: &Path = Path::new("/D/App-abcdefghijklmnopqrstuvwxyzab");
    let of = |workspace: &str| SwiftPmCheckouts::of_xcode_project(project, Path::new(workspace));
    let workspace = of("/Code/App/App.xcworkspace").unwrap();
    assert_eq!(
        workspace.checkouts(),
        Path::new("/D/App-abcdefghijklmnopqrstuvwxyzab/SourcePackages/checkouts")
    );
    assert_eq!(
        workspace.resolved(),
        Path::new("/Code/App/App.xcworkspace/xcshareddata/swiftpm/Package.resolved")
    );
    assert_eq!(
        of("/Code/App/App.xcodeproj").unwrap().resolved(),
        Path::new(
            "/Code/App/App.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved"
        )
    );
    assert_eq!(
        of("/Code/Package").unwrap().resolved(),
        Path::new("/Code/Package/Package.resolved")
    );
    assert!(of("Code/App.xcodeproj").is_none());
}

// ---------------------------------------------------------------------
// The checkouts of Swift Package Manager.
// ---------------------------------------------------------------------

/// A package `pkg` with a build directory `.build` and one checkout
/// `checkouts/dep`, cloned from the repository `upstream`.
struct Package {
    place: Place,
    upstream: PathBuf,
    unit: PathBuf,
    checkout: PathBuf,
    /// The first commit of `upstream`, which the pin names.
    pinned: String,
}

impl Package {
    fn new() -> Self {
        let place = Place::new();
        let upstream: PathBuf = place.repository("upstream");
        let pinned: String = place.git(&upstream, &["rev-parse", "HEAD"]);
        place.write("pkg/Package.swift", b"// swift-tools-version:5.9\n");
        let unit: PathBuf = place.join("pkg/.build");
        fs::create_dir_all(unit.join("checkouts")).unwrap();
        place.write("pkg/.build/debug/output.o", b"object");
        place.git(
            &unit.join("checkouts"),
            &["clone", "-q", upstream.to_str().unwrap(), "dep"],
        );
        let checkout: PathBuf = unit.join("checkouts/dep");
        place.git(&checkout, &["checkout", "-q", "--detach", &pinned]);
        let package = Self {
            place,
            upstream,
            unit,
            checkout,
            pinned,
        };
        package.pin("dep", &package.pinned.clone());
        package
    }

    /// Writes `Package.resolved` with one pin of version 2.
    fn pin(&self, identity: &str, revision: &str) {
        let resolved = serde_json::json!({
            "pins": [{
                "identity": identity,
                "kind": "localSourceControl",
                "location": self.upstream.to_str().unwrap(),
                "state": {"revision": revision},
            }],
            "version": 2,
        });
        self.place.write(
            "pkg/Package.resolved",
            serde_json::to_vec(&resolved).unwrap().as_slice(),
        );
    }

    fn checkouts(&self) -> SwiftPmCheckouts {
        SwiftPmCheckouts::of_package_build(&self.unit).unwrap()
    }

    fn check(&self) -> Verdict {
        self.place.check(&self.unit, Some(&self.checkouts()))
    }

    fn git(&self, arguments: &[&str]) -> String {
        self.place.git(&self.checkout, arguments)
    }
}

fn checkout_refused(reason: RefusalReason) -> Verdict {
    refused(reason, "checkouts/dep")
}

#[test]
fn a_clean_checkout_at_its_pin_is_accepted() {
    let package = Package::new();
    assert_eq!(package.check(), Verdict::Clear);
}

#[test]
fn a_checkout_is_not_accepted_without_the_exception() {
    let package = Package::new();
    assert_eq!(
        package.place.check(&package.unit, None),
        checkout_refused(RefusalReason::NestedRepository)
    );
}

#[test]
fn a_checkout_is_refused_without_git() {
    let package = Package::new();
    assert_eq!(
        check_unit(
            &package.unit,
            Some(&package.checkouts()),
            Err(GitToolProblem::NotInstalled),
            &DetectionLimits::default(),
            None,
        ),
        checkout_refused(RefusalReason::GitUnavailable)
    );
}

#[test]
fn a_checkout_with_an_edit_is_refused() {
    let package = Package::new();
    fs::write(package.checkout.join("Sources.swift"), b"let value = 2\n").unwrap();
    assert_eq!(
        package.check(),
        checkout_refused(RefusalReason::ChangedWorkTree)
    );
}

#[test]
fn a_checkout_with_an_untracked_file_is_refused() {
    let package = Package::new();
    fs::write(package.checkout.join("Notes.txt"), b"mine\n").unwrap();
    assert_eq!(
        package.check(),
        checkout_refused(RefusalReason::ChangedWorkTree)
    );
}

#[test]
fn a_checkout_with_a_hidden_change_is_refused() {
    let package = Package::new();
    package.git(&["update-index", "--assume-unchanged", "Sources.swift"]);
    fs::write(package.checkout.join("Sources.swift"), b"let value = 3\n").unwrap();
    assert_eq!(
        package.check(),
        checkout_refused(RefusalReason::ChangedWorkTree)
    );
}

#[test]
fn a_checkout_with_a_local_commit_is_refused() {
    let package = Package::new();
    package.git(&["checkout", "-q", "-b", "work"]);
    fs::write(package.checkout.join("Sources.swift"), b"let value = 4\n").unwrap();
    package.git(&["commit", "-q", "-am", "local"]);
    // `HEAD` is at the pin again; the branch `work` keeps the commit.
    package.git(&["checkout", "-q", "--detach", &package.pinned]);
    assert_eq!(
        package.check(),
        checkout_refused(RefusalReason::LocalCommits)
    );
}

#[test]
fn a_checkout_at_another_revision_is_refused() {
    let package = Package::new();
    fs::write(package.checkout.join("Sources.swift"), b"let value = 5\n").unwrap();
    package.git(&["commit", "-q", "-am", "local"]);
    assert_eq!(
        package.check(),
        checkout_refused(RefusalReason::RevisionNotPinned)
    );
}

#[test]
fn a_checkout_with_no_pin_is_refused() {
    let package = Package::new();
    package.pin("other", &package.pinned);
    assert_eq!(package.check(), checkout_refused(RefusalReason::NotPinned));
}

#[test]
fn a_checkout_with_no_pin_file_is_refused() {
    let package = Package::new();
    fs::remove_file(package.place.join("pkg/Package.resolved")).unwrap();
    assert_eq!(
        package.check(),
        checkout_refused(RefusalReason::PinsUnavailable)
    );
}

#[test]
fn a_checkout_with_a_stash_is_refused() {
    let package = Package::new();
    fs::write(package.checkout.join("Sources.swift"), b"let value = 6\n").unwrap();
    package.git(&["stash", "-q"]);
    assert_eq!(package.check(), checkout_refused(RefusalReason::Stash));
}

#[test]
fn a_checkout_with_a_filter_driver_is_refused() {
    let package = Package::new();
    package.git(&["config", "filter.lfs.clean", "cat"]);
    assert_eq!(
        package.check(),
        checkout_refused(RefusalReason::FilterDriver)
    );
}

#[test]
fn a_checkout_with_another_remote_is_refused() {
    let package = Package::new();
    let other: PathBuf = package.place.repository("other");
    package.git(&["remote", "set-url", "origin", other.to_str().unwrap()]);
    assert_eq!(
        package.check(),
        checkout_refused(RefusalReason::LocationNotPinned)
    );
}

#[test]
fn a_repository_beside_the_checkouts_is_refused() {
    let package = Package::new();
    package.place.repository("pkg/.build/debug/vendored");
    assert_eq!(
        package.check(),
        refused(RefusalReason::NestedRepository, "debug/vendored")
    );
}

#[test]
fn a_checkout_cloned_from_a_mirror_of_its_pin_is_accepted() {
    let package = Package::new();
    let mirror: PathBuf = with_mirror(&package);
    assert_eq!(package.check(), Verdict::Clear);

    // A mirror whose remote is not the location of the pin is not
    // accepted.
    let other: PathBuf = package.place.repository("other");
    package.place.git(
        &mirror,
        &["remote", "set-url", "origin", other.to_str().unwrap()],
    );
    // The walk can reach the mirror or the checkout first; each one is
    // refused for its location.
    let Verdict::Refused(refusal) = package.check() else {
        panic!("the mirror was accepted");
    };
    assert_eq!(refusal.reason, RefusalReason::LocationNotPinned);
}

#[test]
fn a_checkout_whose_git_directory_was_replaced_is_refused() {
    let package = Package::new();
    let detection: Detection = detect(&package.unit, &DetectionLimits::default(), None);
    // After the walk, the name `.git` names another object: a link to the
    // directory that the walk measured.
    let git_dir: PathBuf = package.checkout.join(".git");
    fs::rename(&git_dir, package.checkout.join("moved")).unwrap();
    symlink("moved", &git_dir).unwrap();
    assert_eq!(
        super::judge(
            &package.unit,
            &detection,
            Some(&package.checkouts()),
            Ok(&package.place.git),
        ),
        checkout_refused(RefusalReason::IdentityChanged)
    );
}

#[test]
fn a_checkout_with_no_reflog_is_refused() {
    let package = Package::new();
    package.git(&["config", "core.logAllRefUpdates", "false"]);
    assert_eq!(
        package.check(),
        checkout_refused(RefusalReason::ReflogDisabled)
    );
}

#[test]
fn a_checkout_with_a_pushed_remote_tracking_reference_is_refused() {
    let package = Package::new();
    package.git(&[
        "update-ref",
        "-m",
        "update by push",
        "refs/remotes/origin/pushed",
        &package.pinned,
    ]);
    assert_eq!(
        package.check(),
        checkout_refused(RefusalReason::ReflogNotFetch)
    );
}

/// Makes the mirror `repositories/dep-1234` of the upstream repository and
/// makes it the remote of the checkout.
fn with_mirror(package: &Package) -> PathBuf {
    let repositories: PathBuf = package.unit.join("repositories");
    fs::create_dir_all(&repositories).unwrap();
    package.place.git(
        &repositories,
        &[
            "clone",
            "-q",
            "--mirror",
            package.upstream.to_str().unwrap(),
            "dep-1234",
        ],
    );
    let mirror: PathBuf = repositories.join("dep-1234");
    package.git(&["remote", "set-url", "origin", mirror.to_str().unwrap()]);
    package.git(&["fetch", "-q", "origin"]);
    mirror
}

#[test]
fn a_mirror_with_an_update_that_is_not_a_fetch_is_refused() {
    let package = Package::new();
    let mirror: PathBuf = with_mirror(&package);
    assert_eq!(package.check(), Verdict::Clear);
    package.place.git(
        &mirror,
        &[
            "-c",
            "core.logAllRefUpdates=always",
            "update-ref",
            "-m",
            "update by push",
            "refs/heads/extra",
            &package.pinned,
        ],
    );
    // The walk can reach the mirror or the checkout first; the checkout
    // checks its mirror too.
    let Verdict::Refused(refusal) = package.check() else {
        panic!("the mirror was accepted");
    };
    assert_eq!(refusal.reason, RefusalReason::ReflogNotFetch);
}

/// Writes an executable script at `path` that makes the file `marker`.
fn marker_program(path: &Path, marker: &Path) {
    fs::write(path, format!("#!/bin/sh\ntouch '{}'\n", marker.display())).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

/// Replaces `HEAD` of the repository at `repository` with a commit that
/// has a signature header of `kind` (`PGP` or `SSH`). The signature is not
/// valid; a verification only runs the program of the configuration.
fn signed_commit(place: &Place, repository: &Path, kind: &str) -> String {
    let tree: String = place.git(repository, &["rev-parse", "HEAD^{tree}"]);
    let parent: String = place.git(repository, &["rev-parse", "HEAD"]);
    let content: String = format!(
        "tree {tree}\nparent {parent}\nauthor Test <test@example.invalid> 1700000000 +0000\n\
         committer Test <test@example.invalid> 1700000000 +0000\n\
         gpgsig -----BEGIN {kind} SIGNATURE-----\n U0lH\n -----END {kind} SIGNATURE-----\n\nsigned\n"
    );
    let file: PathBuf = place.write("commit.txt", content.as_bytes());
    let commit: String = place.git(
        repository,
        &["hash-object", "-t", "commit", "-w", file.to_str().unwrap()],
    );
    place.git(repository, &["update-ref", "refs/heads/main", &commit]);
    place.git(repository, &["reset", "-q", "--hard", &commit]);
    commit
}

#[test]
fn the_checks_run_no_signature_program_of_the_configuration() {
    let place = Place::new();
    let upstream: PathBuf = place.repository("upstream");
    signed_commit(&place, &upstream, "PGP");
    let pinned: String = signed_commit(&place, &upstream, "SSH");
    place.write("pkg/Package.swift", b"// swift-tools-version:5.9\n");
    let unit: PathBuf = place.join("pkg/.build");
    fs::create_dir_all(unit.join("checkouts")).unwrap();
    place.git(
        &unit.join("checkouts"),
        &["clone", "-q", upstream.to_str().unwrap(), "dep"],
    );
    let checkout: PathBuf = unit.join("checkouts/dep");
    place.git(&checkout, &["checkout", "-q", "--detach", &pinned]);
    let package = Package {
        place,
        upstream,
        unit,
        checkout,
        pinned,
    };
    package.pin("dep", &package.pinned.clone());

    let pgp_marker: PathBuf = package.place.join("pgp-ran");
    let ssh_marker: PathBuf = package.place.join("ssh-ran");
    let pgp_program: PathBuf = package.place.join("pgp.sh");
    let ssh_program: PathBuf = package.place.join("ssh.sh");
    marker_program(&pgp_program, &pgp_marker);
    marker_program(&ssh_program, &ssh_marker);
    package.git(&["config", "log.showSignature", "true"]);
    package.git(&["config", "gpg.program", pgp_program.to_str().unwrap()]);
    package.git(&["config", "gpg.ssh.program", ssh_program.to_str().unwrap()]);
    package.git(&[
        "config",
        "gpg.ssh.allowedSignersFile",
        package.place.join("allowed").to_str().unwrap(),
    ]);
    // The fixture runs the programs for a plain `git log`.
    package.git(&["log", "--format=%h"]);
    assert!(pgp_marker.exists() && ssh_marker.exists());
    fs::remove_file(&pgp_marker).unwrap();
    fs::remove_file(&ssh_marker).unwrap();

    assert_eq!(package.check(), Verdict::Clear);
    assert!(!pgp_marker.exists(), "the checks ran gpg.program");
    assert!(!ssh_marker.exists(), "the checks ran gpg.ssh.program");
}
