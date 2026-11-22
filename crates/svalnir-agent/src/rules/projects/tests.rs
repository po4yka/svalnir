//! Fixture tests of `project.dependency-directory`. Each test makes a home
//! directory and disposable Git repositories in a temporary directory; no
//! test reads or changes a project of the host.

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use svalnir_core::process::Uid;
use svalnir_core::rule::{LifecycleState, RootBase, RuleMode, RuleRefusal, RuleRegistry};
use svalnir_core::time::MonotonicNanos;
use tempfile::TempDir;

use super::{
    BuildProcesses, NativeProcessEvidence, ProcessEvidence, ProjectActivity, ProjectHost,
    ProjectInspection, ProjectLimits, ProjectProcess, ProjectUnitOutcome, ProjectUnitReport,
    SearchCompletion, SearchRootOutcome, SearchRoots, VersionControl, is_build_process,
};
use crate::protection::ProtectedLocations;
use crate::rules::ReviewedRules;
use crate::rules::caches::ReclaimFigure;
use crate::rules::fixture::{automatic_eviction_validated, manual_action_validated};
use crate::rules::git::{GitTool, GitToolProblem};
use crate::rules::nested_git::{RefusalReason, RepositoryRefusal};
use crate::rules::resolve_roots;
use crate::scan::{CancellationToken, WallScanClock};

/// Process evidence that the test gives.
struct Fixed(BuildProcesses);

impl ProcessEvidence for Fixed {
    fn build_processes(&self, _principal: Uid) -> BuildProcesses {
        self.0.clone()
    }

    fn monotonic_now(&self) -> Option<MonotonicNanos> {
        self.0.observed_at
    }
}

/// A complete inventory with the processes `processes`.
fn inventory(processes: Vec<ProjectProcess>) -> Fixed {
    Fixed(BuildProcesses {
        processes,
        incomplete: None,
        observed_at: Some(MonotonicNanos::new(1_000)),
    })
}

/// A complete inventory with one process that is not a build process.
fn quiet() -> Fixed {
    inventory(vec![ProjectProcess {
        executable: PathBuf::from("/usr/bin/login"),
        working_directory: None,
    }])
}

/// A home directory with the search root `Code` in a temporary directory.
struct Home {
    _directory: TempDir,
    path: PathBuf,
    locations: ProtectedLocations,
    principal: Uid,
    git: GitTool,
}

impl Home {
    fn new() -> Self {
        let directory: TempDir = TempDir::new().unwrap();
        let path: PathBuf = fs::canonicalize(directory.path()).unwrap();
        let state: PathBuf = path.join("Library/Application Support/Svalnir");
        fs::create_dir_all(&state).unwrap();
        fs::create_dir_all(path.join("Code")).unwrap();
        let principal: Uid = Uid::new(fs::metadata(&path).unwrap().uid());
        Self {
            locations: ProtectedLocations::from_resolved(Some(path.clone()), Some(state)),
            _directory: directory,
            path,
            principal,
            git: GitTool::locate().expect("the developer tools of the host have Git"),
        }
    }

    fn write(&self, relative: &str, content: &[u8]) -> PathBuf {
        let path: PathBuf = self.path.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, content).unwrap();
        path
    }

    /// Runs the Git of the test in `directory`, with no configuration of
    /// the host.
    fn git(&self, directory: &str, arguments: &[&str]) {
        let status = Command::new(self.git.executable())
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &self.path)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .current_dir(self.path.join(directory))
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
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "git {arguments:?}");
    }

    /// A repository at `directory` with one commit of its files.
    fn repository(&self, directory: &str) {
        fs::create_dir_all(self.path.join(directory)).unwrap();
        self.git(directory, &["init", "-q"]);
        self.git(directory, &["add", "-A"]);
        self.git(directory, &["commit", "-q", "--allow-empty", "-m", "start"]);
    }

    /// A Node project at `Code/NAME` with an installed package, which Git
    /// ignores.
    fn node_project(&self, name: &str) -> PathBuf {
        let project: String = format!("Code/{name}");
        self.write(&format!("{project}/package.json"), b"{}");
        self.write(&format!("{project}/.gitignore"), b"node_modules/\n");
        self.repository(&project);
        self.write(
            &format!("{project}/node_modules/left-pad/index.js"),
            b"module.exports = 1;\n",
        );
        self.path.join(project)
    }

    fn inspect_with(
        &self,
        processes: &dyn ProcessEvidence,
        git: Result<&GitTool, GitToolProblem>,
        limits: ProjectLimits,
    ) -> ProjectInspection {
        let registry: ReviewedRules = ReviewedRules::new().unwrap();
        let host: ProjectHost<'_> = ProjectHost {
            principal: self.principal,
            locations: &self.locations,
            user_exclusions: &[],
            git,
            processes,
        };
        registry.projects().inspect(
            host,
            &SearchRoots::new(vec![PathBuf::from("Code")]).unwrap(),
            limits,
            &CancellationToken::new(),
            &WallScanClock,
        )
    }

    fn inspect(&self, processes: &dyn ProcessEvidence) -> ProjectInspection {
        self.inspect_with(processes, Ok(&self.git), ProjectLimits::default())
    }
}

/// The report of the unit at `path`.
fn unit<'a>(inspection: &'a ProjectInspection, path: &Path) -> &'a ProjectUnitReport {
    inspection
        .units
        .iter()
        .find(|unit| unit.path == path)
        .unwrap_or_else(|| panic!("no unit {}: {:#?}", path.display(), inspection.units))
}

fn refusal(report: &ProjectUnitReport) -> &'static str {
    match report.outcome {
        ProjectUnitOutcome::Refused { reason } => reason,
        ref other => panic!("the unit was not refused: {other:?}"),
    }
}

// ---------------------------------------------------------------------
// The registry.
// ---------------------------------------------------------------------

#[test]
fn the_rule_is_registered_proposed_with_the_inspection_mode_only() {
    let registry: ReviewedRules = ReviewedRules::new().unwrap();
    let rule = registry.projects().rule();
    assert_eq!(rule.reference.id.as_str(), "project.dependency-directory");
    assert_eq!(rule.modes, [RuleMode::Inspection]);
    let layouts: Vec<&str> = rule
        .layouts
        .iter()
        .map(|layout| layout.layout.as_str())
        .collect();
    assert_eq!(layouts, ["node-modules", "python-venv", "cocoapods-pods"]);
    for layout in &rule.layouts {
        assert_eq!(layout.lifecycle, LifecycleState::Proposed);
        for mode in RuleMode::ALL {
            assert_eq!(
                registry
                    .resolve(&rule.reference, &layout.layout, &mode)
                    .err(),
                Some(RuleRefusal::ModeNotValidated)
            );
        }
    }
    // Each root is in a project that the user selects, so the discovery
    // for an eviction has no path for it.
    assert!(
        rule.roots
            .iter()
            .all(|root| root.base == RootBase::UserSelected)
    );
    let home = Home::new();
    assert!(
        resolve_roots(rule, &home.locations)
            .iter()
            .all(Result::is_err)
    );
}

#[test]
fn a_fixture_lifecycle_does_not_change_the_rule() {
    for state in [manual_action_validated(), automatic_eviction_validated()] {
        let registry: ReviewedRules = ReviewedRules::with_fixture_lifecycle(&state).unwrap();
        for layout in &registry.projects().rule().layouts {
            assert_eq!(layout.lifecycle, LifecycleState::Proposed);
            assert!(!layout.lifecycle.permits(&RuleMode::ManualEviction));
            assert!(!layout.lifecycle.permits(&RuleMode::AutomaticEviction));
        }
    }
}

#[test]
fn a_search_root_is_a_plain_path_below_the_home_directory() {
    for path in ["", "/Users", "../other", "Code/../..", "./Code"] {
        assert!(
            SearchRoots::new(vec![PathBuf::from(path)]).is_err(),
            "{path}"
        );
    }
    assert!(SearchRoots::new(vec![PathBuf::from("Code"), PathBuf::from("Code")]).is_err());
    assert_eq!(SearchRoots::new(vec![PathBuf::from("Code"); 17]), Err(None));
    assert_eq!(
        SearchRoots::new(Vec::new()).unwrap().paths(),
        &[] as &[PathBuf]
    );
}

#[test]
fn no_search_root_examines_nothing() {
    let home = Home::new();
    home.node_project("app");
    let registry: ReviewedRules = ReviewedRules::new().unwrap();
    let processes = quiet();
    let inspection: ProjectInspection = registry.projects().inspect(
        ProjectHost {
            principal: home.principal,
            locations: &home.locations,
            user_exclusions: &[],
            git: Ok(&home.git),
            processes: &processes,
        },
        &SearchRoots::new(Vec::new()).unwrap(),
        ProjectLimits::default(),
        &CancellationToken::new(),
        &WallScanClock,
    );
    assert_eq!(inspection.roots, []);
    assert_eq!(inspection.units, []);
}

#[test]
fn a_search_root_with_the_state_directory_is_refused() {
    let home = Home::new();
    let registry: ReviewedRules = ReviewedRules::new().unwrap();
    let processes = quiet();
    let inspection: ProjectInspection = registry.projects().inspect(
        ProjectHost {
            principal: home.principal,
            locations: &home.locations,
            user_exclusions: &[],
            git: Ok(&home.git),
            processes: &processes,
        },
        &SearchRoots::new(vec![PathBuf::from("Library"), PathBuf::from("Absent")]).unwrap(),
        ProjectLimits::default(),
        &CancellationToken::new(),
        &WallScanClock,
    );
    assert_eq!(
        inspection.roots[0].outcome,
        SearchRootOutcome::Refused("root_protected")
    );
    assert_eq!(inspection.roots[1].outcome, SearchRootOutcome::Absent);
}

// ---------------------------------------------------------------------
// The units.
// ---------------------------------------------------------------------

#[test]
fn an_ignored_dependency_directory_of_a_project_is_measured() {
    let home = Home::new();
    let project: PathBuf = home.node_project("app");
    let inspection: ProjectInspection = home.inspect(&quiet());
    assert_eq!(
        inspection.roots[0].outcome,
        SearchRootOutcome::Examined(SearchCompletion::Complete)
    );
    let report = unit(&inspection, &project.join("node_modules"));
    assert_eq!(report.layout, "node-modules");
    assert_eq!(report.project, project);
    assert_eq!(report.version_control, Some(VersionControl::Ignored));
    assert_eq!(report.activity, Some(ProjectActivity::Inactive));
    let ProjectUnitOutcome::Measured(measurement) = &report.outcome else {
        panic!("not measured: {:?}", report.outcome);
    };
    assert_eq!(measurement.files.get(), 1);
    // Package managers can link the files from a store.
    assert_eq!(
        measurement.reclaim,
        ReclaimFigure::NotKnownLinkedIntoProjects
    );
    // The walk does not enter the unit, and the inspection changed
    // nothing.
    assert_eq!(inspection.units.len(), 1);
    assert!(project.join("node_modules/left-pad/index.js").exists());
}

#[test]
fn a_committed_directory_with_a_generic_name_is_not_a_candidate() {
    let home = Home::new();
    home.write("Code/vendored/package.json", b"{}");
    home.write("Code/vendored/.gitignore", b"node_modules/\n");
    home.write("Code/vendored/node_modules/patched/index.js", b"1;\n");
    fs::create_dir_all(home.path.join("Code/vendored")).unwrap();
    home.git("Code/vendored", &["init", "-q"]);
    // The project commits its dependency directory, although the ignore
    // file names it.
    home.git("Code/vendored", &["add", "-A"]);
    home.git("Code/vendored", &["add", "-f", "node_modules"]);
    home.git("Code/vendored", &["commit", "-q", "-m", "vendor"]);
    let inspection: ProjectInspection = home.inspect(&quiet());
    let report = unit(&inspection, &home.path.join("Code/vendored/node_modules"));
    assert_eq!(report.version_control, Some(VersionControl::Tracked));
    assert_eq!(refusal(report), "tracked_files");
}

#[test]
fn a_directory_that_git_does_not_ignore_is_not_a_candidate() {
    let home = Home::new();
    home.write("Code/plain/package.json", b"{}");
    home.repository("Code/plain");
    home.write("Code/plain/node_modules/a/index.js", b"1;\n");
    let inspection: ProjectInspection = home.inspect(&quiet());
    let report = unit(&inspection, &home.path.join("Code/plain/node_modules"));
    assert_eq!(report.version_control, Some(VersionControl::NotIgnored));
    assert_eq!(refusal(report), "not_ignored");
}

#[test]
fn a_directory_with_no_repository_is_not_a_candidate() {
    let home = Home::new();
    home.write("Code/loose/package.json", b"{}");
    home.write("Code/loose/node_modules/a/index.js", b"1;\n");
    let inspection: ProjectInspection = home.inspect(&quiet());
    let report = unit(&inspection, &home.path.join("Code/loose/node_modules"));
    assert_eq!(report.version_control, Some(VersionControl::NoRepository));
    assert_eq!(refusal(report), "no_repository");
}

#[test]
fn a_directory_with_no_project_marker_is_not_a_candidate() {
    let home = Home::new();
    home.write("Code/stray/.gitignore", b"node_modules/\n");
    home.repository("Code/stray");
    home.write("Code/stray/node_modules/a/index.js", b"1;\n");
    // A marker that is a directory is not a marker.
    fs::create_dir_all(home.path.join("Code/fake/package.json")).unwrap();
    home.write("Code/fake/node_modules/a/index.js", b"1;\n");
    let inspection: ProjectInspection = home.inspect(&quiet());
    for project in ["Code/stray", "Code/fake"] {
        let report = unit(&inspection, &home.path.join(project).join("node_modules"));
        assert_eq!(refusal(report), "project_marker_missing", "{project}");
        assert_eq!(report.version_control, None);
    }
}

#[test]
fn a_symbolic_link_is_not_followed() {
    let home = Home::new();
    let outside: PathBuf = home.node_project("app");
    // A unit that is a symbolic link to a real dependency directory.
    home.write("Code/linked/package.json", b"{}");
    home.write("Code/linked/.gitignore", b"node_modules\n");
    home.repository("Code/linked");
    symlink(
        outside.join("node_modules"),
        home.path.join("Code/linked/node_modules"),
    )
    .unwrap();
    // A directory of the search root that is a symbolic link to a project
    // outside it.
    home.write("Elsewhere/other/package.json", b"{}");
    home.write("Elsewhere/other/node_modules/a/index.js", b"1;\n");
    symlink(
        home.path.join("Elsewhere"),
        home.path.join("Code/elsewhere"),
    )
    .unwrap();
    let inspection: ProjectInspection = home.inspect(&quiet());
    let report = unit(&inspection, &home.path.join("Code/linked/node_modules"));
    assert_eq!(refusal(report), "unit_symbolic_link");
    assert!(inspection.units.iter().all(|unit| {
        !unit.path.starts_with(home.path.join("Code/elsewhere"))
            && !unit.path.starts_with(home.path.join("Elsewhere"))
    }));
}

/// A disposable process with the name `node` and the working directory
/// `directory`: a copy of `/bin/sleep`.
fn build_process(home: &Home, directory: &Path) -> Child {
    let tools: PathBuf = home.path.join("tools");
    fs::create_dir_all(&tools).unwrap();
    let node: PathBuf = tools.join("node");
    fs::copy("/bin/sleep", &node).unwrap();
    fs::set_permissions(&node, fs::Permissions::from_mode(0o755)).unwrap();
    Command::new(&node)
        .arg("30")
        .current_dir(directory)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}

#[test]
fn a_build_process_in_the_project_blocks_the_unit() {
    let home = Home::new();
    let project: PathBuf = home.node_project("app");
    let mut child: Child = build_process(&home, &project.join("node_modules"));
    let inspection: ProjectInspection = home.inspect(&NativeProcessEvidence);
    drop(child.kill());
    drop(child.wait());
    let report = unit(&inspection, &project.join("node_modules"));
    assert_eq!(refusal(report), "producer_active");
    assert_eq!(
        report.activity,
        Some(ProjectActivity::Active {
            executable: home.path.join("tools/node"),
        })
    );
}

#[test]
fn a_build_process_of_another_project_does_not_block_the_unit() {
    let home = Home::new();
    let project: PathBuf = home.node_project("app");
    let other: PathBuf = home.node_project("other");
    let evidence = inventory(vec![ProjectProcess {
        executable: PathBuf::from("/usr/local/bin/node"),
        working_directory: Some(other.clone()),
    }]);
    let inspection: ProjectInspection = home.inspect(&evidence);
    assert!(matches!(
        unit(&inspection, &project.join("node_modules")).outcome,
        ProjectUnitOutcome::Measured(_)
    ));
    assert_eq!(
        refusal(unit(&inspection, &other.join("node_modules"))),
        "producer_active"
    );
}

#[test]
fn an_executable_in_the_project_blocks_the_unit() {
    let home = Home::new();
    home.write("Code/py/pyproject.toml", b"[project]\nname = \"py\"\n");
    home.write("Code/py/.gitignore", b".venv/\n");
    home.repository("Code/py");
    home.write("Code/py/.venv/pyvenv.cfg", b"home = /usr/bin\n");
    home.write("Code/py/.venv/bin/python", b"");
    let evidence = inventory(vec![ProjectProcess {
        executable: home.path.join("Code/py/.venv/bin/python"),
        working_directory: Some(PathBuf::from("/")),
    }]);
    let inspection: ProjectInspection = home.inspect(&evidence);
    assert_eq!(
        refusal(unit(&inspection, &home.path.join("Code/py/.venv"))),
        "producer_active"
    );
}

#[test]
fn unknown_activity_is_not_inactivity() {
    let home = Home::new();
    let project: PathBuf = home.node_project("app");
    for evidence in [
        Fixed(BuildProcesses {
            processes: vec![ProjectProcess {
                executable: PathBuf::from("/usr/bin/login"),
                working_directory: None,
            }],
            incomplete: Some("working_directory_query_failed"),
            observed_at: Some(MonotonicNanos::new(1)),
        }),
        // No time: the age of the evidence is not known.
        Fixed(BuildProcesses {
            processes: Vec::new(),
            incomplete: None,
            observed_at: None,
        }),
    ] {
        let inspection: ProjectInspection = home.inspect(&evidence);
        let report = unit(&inspection, &project.join("node_modules"));
        assert_eq!(refusal(report), "activity_unknown");
        assert!(matches!(
            report.activity,
            Some(ProjectActivity::Unknown { .. })
        ));
    }
}

#[test]
fn with_no_trusted_git_the_version_control_is_unknown() {
    let home = Home::new();
    let project: PathBuf = home.node_project("app");
    let inspection: ProjectInspection = home.inspect_with(
        &quiet(),
        Err(GitToolProblem::NotTrusted),
        ProjectLimits::default(),
    );
    let report = unit(&inspection, &project.join("node_modules"));
    assert_eq!(refusal(report), "version_control_unknown");
    assert_eq!(
        report.version_control,
        Some(VersionControl::Unknown {
            reason: "git_not_available"
        })
    );
}

#[test]
fn a_virtual_environment_needs_its_marker_and_cocoapods_needs_its_manifest() {
    let home = Home::new();
    home.write("Code/py/pyproject.toml", b"[project]\nname = \"py\"\n");
    home.write("Code/py/.gitignore", b".venv/\n");
    home.repository("Code/py");
    home.write("Code/py/.venv/lib/site.py", b"");
    home.write("Code/ios/Podfile", b"platform :ios\n");
    home.write("Code/ios/.gitignore", b"Pods/\n");
    home.repository("Code/ios");
    home.write("Code/ios/Pods/Manifest.lock", b"PODS:\n");
    home.write("Code/ios/Pods/Alamofire/a.swift", b"//\n");
    let inspection: ProjectInspection = home.inspect(&quiet());
    assert_eq!(
        refusal(unit(&inspection, &home.path.join("Code/py/.venv"))),
        "unsupported_layout"
    );
    let pods = unit(&inspection, &home.path.join("Code/ios/Pods"));
    let ProjectUnitOutcome::Measured(measurement) = &pods.outcome else {
        panic!("not measured: {:?}", pods.outcome);
    };
    assert!(matches!(
        measurement.reclaim,
        ReclaimFigure::AllocatedUpperBound { .. }
    ));
    // With its marker, the environment is measured.
    home.write("Code/py/.venv/pyvenv.cfg", b"home = /usr/bin\n");
    let inspection: ProjectInspection = home.inspect(&quiet());
    assert!(matches!(
        unit(&inspection, &home.path.join("Code/py/.venv")).outcome,
        ProjectUnitOutcome::Measured(_)
    ));
}

#[test]
fn a_cargo_target_directory_belongs_to_the_cargo_rule() {
    let home = Home::new();
    home.write("Code/crate/Cargo.toml", b"[package]\n");
    home.write("Code/crate/target/debug/app", b"");
    // A directory named `target` with no manifest is an ordinary
    // directory, which the walk enters.
    home.write("Code/web/target/package.json", b"{}");
    home.write("Code/web/target/node_modules/a/index.js", b"1;\n");
    let inspection: ProjectInspection = home.inspect(&quiet());
    let report = unit(&inspection, &home.path.join("Code/crate/target"));
    assert_eq!(
        report.outcome,
        ProjectUnitOutcome::OwnedByOtherRule {
            rule: "cargo.build-output"
        }
    );
    assert_eq!(
        refusal(unit(
            &inspection,
            &home.path.join("Code/web/target/node_modules")
        )),
        "no_repository"
    );
}

#[test]
fn the_walk_stops_at_its_depth_bound() {
    let home = Home::new();
    home.node_project("a/b/c/d/deep");
    let limits = ProjectLimits {
        max_depth: 2,
        ..ProjectLimits::default()
    };
    let inspection: ProjectInspection = home.inspect_with(&quiet(), Ok(&home.git), limits);
    assert_eq!(
        inspection.roots[0].outcome,
        SearchRootOutcome::Examined(SearchCompletion::DepthLimitReached)
    );
    assert_eq!(inspection.units, []);
    let limits = ProjectLimits {
        max_directories: 2,
        ..ProjectLimits::default()
    };
    let inspection: ProjectInspection = home.inspect_with(&quiet(), Ok(&home.git), limits);
    assert_eq!(
        inspection.roots[0].outcome,
        SearchRootOutcome::Examined(SearchCompletion::DirectoryLimitReached)
    );
}

#[test]
fn a_linked_worktree_of_the_project_has_git_evidence() {
    let home = Home::new();
    home.node_project("app");
    home.git("Code/app", &["worktree", "add", "-q", "../app-feature"]);
    home.write("Code/app-feature/node_modules/a/index.js", b"1;\n");
    let inspection: ProjectInspection = home.inspect(&quiet());
    let report = unit(
        &inspection,
        &home.path.join("Code/app-feature/node_modules"),
    );
    assert_eq!(report.version_control, Some(VersionControl::Ignored));
}

#[test]
fn the_build_process_names() {
    for name in ["node", "pnpm", "python3", "python3.13", "pod", "xcodebuild"] {
        assert!(is_build_process(name), "{name}");
    }
    for name in ["zsh", "Finder", "nodejs-helper", "login"] {
        assert!(!is_build_process(name), "{name}");
    }
}

#[test]
fn a_build_process_above_the_project_makes_the_activity_unknown() {
    let home = Home::new();
    // A monorepo with a package below its root.
    home.write("Code/mono/package.json", b"{}");
    home.write("Code/mono/.gitignore", b"node_modules/\n");
    home.write("Code/mono/packages/app/package.json", b"{}");
    home.repository("Code/mono");
    home.write("Code/mono/node_modules/a/index.js", b"1;\n");
    home.write("Code/mono/packages/app/node_modules/b/index.js", b"1;\n");
    let app: PathBuf = home.path.join("Code/mono/packages/app/node_modules");
    // `pnpm install -r` at the root of the monorepo, and `make -C` from
    // the search root.
    for directory in [home.path.join("Code/mono"), home.path.join("Code")] {
        let evidence = inventory(vec![ProjectProcess {
            executable: PathBuf::from("/opt/homebrew/bin/pnpm"),
            working_directory: Some(directory.clone()),
        }]);
        let inspection: ProjectInspection = home.inspect(&evidence);
        let report = unit(&inspection, &app);
        assert_eq!(
            refusal(report),
            "activity_unknown",
            "{}",
            directory.display()
        );
        assert_eq!(
            report.activity,
            Some(ProjectActivity::Unknown {
                reason: "build_process_above_project"
            })
        );
    }
    // A build process above the search root is not seen; that is a
    // limit of the revision (docs/CLEANUP_RULES.md section 12).
    let evidence = inventory(vec![ProjectProcess {
        executable: PathBuf::from("/opt/homebrew/bin/npm"),
        working_directory: Some(home.path.clone()),
    }]);
    let inspection: ProjectInspection = home.inspect(&evidence);
    assert_eq!(
        unit(&inspection, &app).activity,
        Some(ProjectActivity::Inactive)
    );
}

#[test]
fn a_search_root_in_another_case_has_the_stored_names() {
    let home = Home::new();
    let project: PathBuf = home.node_project("app");
    // The temporary directory of a macOS host is on a volume that ignores
    // case, as the default volume is.
    assert!(
        home.path.join("code").exists(),
        "the test needs a volume that ignores case"
    );
    let registry: ReviewedRules = ReviewedRules::new().unwrap();
    let mut child: Child = build_process(&home, &project);
    let inspection: ProjectInspection = registry.projects().inspect(
        ProjectHost {
            principal: home.principal,
            locations: &home.locations,
            user_exclusions: &[],
            git: Ok(&home.git),
            processes: &NativeProcessEvidence,
        },
        &SearchRoots::new(vec![PathBuf::from("code")]).unwrap(),
        ProjectLimits::default(),
        &CancellationToken::new(),
        &WallScanClock,
    );
    drop(child.kill());
    drop(child.wait());
    assert_eq!(inspection.roots[0].path, Some(home.path.join("Code")));
    let report = unit(&inspection, &project.join("node_modules"));
    assert_eq!(refusal(report), "producer_active");
}

// ---------------------------------------------------------------------
// Repositories in a unit.
// ---------------------------------------------------------------------

#[test]
fn a_unit_that_holds_a_repository_is_refused_and_not_measured() {
    let home = Home::new();
    let project: PathBuf = home.node_project("app");
    // A dependency that a person cloned into the ignored directory.
    home.repository("Code/app/node_modules/forked-lib");

    let inspection: ProjectInspection = home.inspect(&quiet());
    let report = unit(&inspection, &project.join("node_modules"));
    assert_eq!(report.version_control, Some(VersionControl::Ignored));
    assert_eq!(
        report.outcome,
        ProjectUnitOutcome::RepositoryRefused(RepositoryRefusal {
            reason: RefusalReason::NestedRepository,
            path: Some(PathBuf::from("forked-lib")),
        })
    );
}
