//! End-to-end tests of the `evict` mode of `clean plan` and of its apply.
//!
//! Each test has its own temporary directory with the state directory, a
//! home directory, and a `DerivedData` root below that home directory. The
//! rule is `xcode.inactive-derived-data` with a lifecycle state that only
//! a test build can give: each reviewed rule of a build is `proposed`. The
//! process evidence comes from a fixture. A removal is only below the
//! temporary directory.

#![cfg(debug_assertions)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde_json::Value;
use svalnir_agent::rules::ProducerProcesses;
use svalnir_agent::rules::fixture::{
    FixtureEnvironment, automatic_eviction_validated, derived_data_root, manual_action_validated,
    write_project, write_workspace,
};
use svalnir_core::rule::LifecycleState;

use crate::environment::Environment;
use crate::output::ExitStatus;
use crate::run_in;
use crate::seams::TestEnvironment;
use crate::test_support::{TempDirectory, environment};

const RULE: &str = "xcode.inactive-derived-data";
const PROJECT: &str = "App-abcdefghijklmnopqrstuvwxyzab";
const UNITS: [&str; 3] = [
    "Build/Intermediates.noindex",
    "Build/Products",
    "Index.noindex",
];

struct Outcome {
    status: ExitStatus,
    stdout: String,
}

impl Outcome {
    fn envelope(&self) -> Value {
        assert_eq!(self.stdout.lines().count(), 1, "{}", self.stdout);
        serde_json::from_str(&self.stdout).unwrap()
    }

    fn result(&self) -> Value {
        let envelope = self.envelope();
        assert!(envelope["error"].is_null(), "{}", self.stdout);
        envelope["result"].clone()
    }

    fn error_code(&self) -> String {
        self.envelope()["error"]["code"]
            .as_str()
            .unwrap_or_default()
            .to_owned()
    }
}

static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn run(environment: &Environment, arguments: &[&str]) -> Outcome {
    let mut stdout: Vec<u8> = Vec::new();
    let mut stderr: Vec<u8> = Vec::new();
    let request_id = svalnir_core::id::RequestId::new(format!(
        "request_evict_{}",
        NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    ))
    .unwrap();
    let status = run_in(
        std::iter::once("svalnir").chain(arguments.iter().copied()),
        request_id,
        environment,
        &mut stdout,
        &mut stderr,
    );
    Outcome {
        status,
        stdout: String::from_utf8(stdout).unwrap(),
    }
}

fn json(environment: &Environment, arguments: &[&str]) -> Outcome {
    let mut machine: Vec<&str> = arguments.to_vec();
    machine.extend(["--format", "json"]);
    run(environment, &machine)
}

/// One temporary world with a project in the `DerivedData` root of its
/// home directory.
struct World {
    environment: Environment,
    directory: TempDirectory,
    evidence: FixtureEnvironment,
    project: PathBuf,
}

impl World {
    /// A world whose rules have `lifecycle`, or the state of the build.
    fn new(lifecycle: Option<LifecycleState>) -> Self {
        let (mut environment, directory) = environment();
        // The fixture is 30 days old for the discovery.
        let evidence = FixtureEnvironment::days_later(30);
        environment.seams.test.rule_lifecycle = lifecycle;
        environment.seams.test.discovery_environment =
            Some(TestEnvironment(Arc::new(evidence.clone())));
        let home: PathBuf = std::fs::canonicalize(environment.home.as_ref().unwrap()).unwrap();
        let root: PathBuf = derived_data_root(&home);
        std::fs::create_dir_all(&root).unwrap();
        let workspace: PathBuf = write_workspace(&directory.path().join("src"), "App").unwrap();
        let project: PathBuf = write_project(&root, PROJECT, &workspace).unwrap();
        let world = Self {
            environment,
            directory,
            evidence,
            project,
        };
        world.activate();
        world
    }

    fn manual() -> Self {
        Self::new(Some(manual_action_validated()))
    }

    fn activate(&self) {
        let config: PathBuf = self.directory.path().join("config.toml");
        std::fs::write(&config, "schema_version = 1\n").unwrap();
        let outcome = json(
            &self.environment,
            &[
                "config",
                "apply",
                "--config",
                config.to_str().unwrap(),
                "--expected-revision",
                "none",
            ],
        );
        assert_eq!(outcome.status, ExitStatus::Success, "{}", outcome.stdout);
    }

    fn plan(&self, extra: &[&str]) -> Outcome {
        let mut arguments: Vec<&str> = vec!["clean", "plan", "--mode", "evict", "--rule", RULE];
        arguments.extend_from_slice(extra);
        json(&self.environment, &arguments)
    }

    /// Makes a plan and returns its identity.
    fn planned(&self) -> String {
        let outcome = self.plan(&[]);
        assert_eq!(outcome.status, ExitStatus::Success, "{}", outcome.stdout);
        outcome.result()["explanation"]["plan"]["plan_id"]
            .as_str()
            .unwrap_or_else(|| panic!("no plan: {}", outcome.stdout))
            .to_owned()
    }

    fn apply(&self, plan: &str) -> Outcome {
        json(
            &self.environment,
            &["clean", "apply", "--plan", plan, "--yes"],
        )
    }

    fn remaining(&self) -> Vec<&'static str> {
        UNITS
            .iter()
            .copied()
            .filter(|unit| self.project.join(unit).exists())
            .collect()
    }

    fn state_has_plans(&self) -> bool {
        self.directory.path().join("state/plans").exists()
    }
}

fn target_paths(result: &Value) -> Vec<String> {
    let mut paths: Vec<String> = result["explanation"]["targets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|target| target["path"]["value"].as_str().unwrap().to_owned())
        .collect();
    paths.sort();
    paths
}

fn unit_paths(project: &Path) -> Vec<String> {
    UNITS
        .iter()
        .map(|unit| project.join(unit).to_str().unwrap().to_owned())
        .collect()
}

#[test]
fn a_rule_of_the_build_is_proposed_and_the_evict_mode_is_refused() {
    let world = World::new(None);
    let outcome = world.plan(&[]);
    assert_eq!(
        outcome.status,
        ExitStatus::Unavailable,
        "{}",
        outcome.stdout
    );
    assert_eq!(outcome.error_code(), "rule_mode_not_validated");
    // No directory was read for a plan, and nothing was written.
    assert!(!world.state_has_plans());
    assert_eq!(world.remaining().len(), 3);
    // A rule that the registry does not have.
    let unknown = json(
        &world.environment,
        &["clean", "plan", "--mode", "evict", "--rule", "all.caches"],
    );
    assert_eq!(unknown.status, ExitStatus::Usage, "{}", unknown.stdout);
    assert_eq!(unknown.error_code(), "unknown_rule");
}

#[test]
fn the_evict_mode_refuses_each_inspection_rule_also_with_a_fixture_lifecycle() {
    // The registry of this world gives the other rules a state that is
    // validated for manual eviction. A cache rule has the inspection mode
    // only, so it keeps its `proposed` state.
    let world = World::manual();
    let home: PathBuf = std::fs::canonicalize(world.environment.home.as_ref().unwrap()).unwrap();
    // A fixture cache at the default location of each rule.
    for directory in [
        "Library/pnpm/store/v10/files",
        "Library/Caches/Yarn/v6",
        "Library/Caches/go-build",
        ".cache/uv",
        "Library/Caches/Homebrew/downloads",
        "Library/Caches/CocoaPods/Pods",
    ] {
        std::fs::create_dir_all(home.join(directory)).unwrap();
        std::fs::write(home.join(directory).join("entry"), b"cache").unwrap();
    }
    for rule in [
        "pnpm.content-store",
        "yarn.cache",
        "go.build-cache",
        "uv.cache",
        "homebrew.download-cache",
        "cocoapods.cache",
        // The rules of the owner tools.
        "simulator.devices",
        "container.build-cache",
        "homebrew.cleanup",
        // The rule of the linked Git worktrees is manual only by its
        // specification and has the inspection mode only.
        "git.linked-worktree",
    ] {
        let outcome = json(
            &world.environment,
            &["clean", "plan", "--mode", "evict", "--rule", rule],
        );
        assert_eq!(
            outcome.status,
            ExitStatus::Unavailable,
            "{rule}: {}",
            outcome.stdout
        );
        assert_eq!(outcome.error_code(), "rule_mode_not_validated", "{rule}");
    }
    assert!(!world.state_has_plans());
    assert!(
        home.join("Library/Caches/Homebrew/downloads/entry")
            .exists()
    );
}

#[test]
fn an_evict_plan_has_the_units_of_the_rule_and_its_apply_removes_them() {
    let world = World::manual();
    let outcome = world.plan(&[]);
    assert_eq!(outcome.status, ExitStatus::Success, "{}", outcome.stdout);
    let result = outcome.result();
    // The plan has the three units, and the command removed nothing.
    assert_eq!(target_paths(&result), unit_paths(&world.project));
    assert_eq!(world.remaining().len(), 3);
    let root: PathBuf = world.project.parent().unwrap().to_path_buf();
    assert_eq!(
        result["cleanup_roots"][0]["value"],
        root.to_str().unwrap(),
        "{result}"
    );
    assert_eq!(result["plan_document"], "used");
    assert!(result["scan_id"].is_null());
    let discovery = &result["discovery"];
    assert_eq!(discovery["rule"]["id"], RULE);
    assert_eq!(discovery["complete"], true);
    assert_eq!(discovery["candidates"], 3);
    assert_eq!(discovery["roots"][0]["result"], "examined");
    assert_eq!(discovery["roots"][0]["completion"], "finished");
    let plan_id: String = result["explanation"]["plan"]["plan_id"]
        .as_str()
        .unwrap()
        .to_owned();
    // The stored plan is an eviction of the exact rule revision.
    let shown = json(&world.environment, &["clean", "show", "--plan", &plan_id]);
    assert_eq!(shown.status, ExitStatus::Success, "{}", shown.stdout);
    assert_eq!(target_paths(&shown.result()), unit_paths(&world.project));
    assert_eq!(shown.result()["plan_document"], "used");
    assert!(shown.result().get("discovery").is_none());
    // The text output names the rule and the root.
    let text = run(
        &world.environment,
        &["clean", "plan", "--mode", "evict", "--rule", RULE],
    );
    assert_eq!(text.status, ExitStatus::Success, "{}", text.stdout);
    assert!(
        text.stdout
            .contains("Rule discovery: xcode.inactive-derived-data"),
        "{}",
        text.stdout
    );

    let applied = world.apply(&plan_id);
    assert_eq!(applied.status, ExitStatus::Success, "{}", applied.stdout);
    assert_eq!(world.remaining(), Vec::<&str>::new());
    // What is not a unit of the rule stays.
    assert!(world.project.join("info.plist").exists());
    assert!(world.project.join("Logs/Build/1.xcactivitylog").exists());
    assert!(
        world
            .directory
            .path()
            .join("src/App/App.xcodeproj/project.pbxproj")
            .exists()
    );
    let history = json(&world.environment, &["history"]);
    assert_eq!(history.status, ExitStatus::Success, "{}", history.stdout);
    let record = &history.result()["records"][0];
    assert_eq!(record["effects"]["permanently_removed"], 3, "{record}");
    assert_eq!(record["effects"]["moved_to_trash"], 0, "{record}");
}

#[test]
fn an_orphan_project_directory_is_planned_as_one_target_and_removed() {
    let world = World::manual();
    // The project of `WorkspacePath` is gone.
    std::fs::remove_dir_all(world.directory.path().join("src")).unwrap();
    let outcome = world.plan(&[]);
    assert_eq!(outcome.status, ExitStatus::Success, "{}", outcome.stdout);
    let result = outcome.result();
    assert_eq!(
        target_paths(&result),
        [world.project.to_str().unwrap().to_owned()]
    );
    let plan: String = result["explanation"]["plan"]["plan_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let applied = world.apply(&plan);
    assert_eq!(applied.status, ExitStatus::Success, "{}", applied.stdout);
    assert!(!world.project.exists());
    // The root of the rule stays.
    assert!(world.project.parent().unwrap().exists());
}

#[test]
fn an_orphan_whose_project_is_back_is_skipped_at_its_step() {
    let world = World::manual();
    let sources: PathBuf = world.directory.path().join("src");
    std::fs::remove_dir_all(&sources).unwrap();
    let plan: String = world.planned();
    // The project is back after the plan.
    write_workspace(&sources, "App").unwrap();
    let applied = world.apply(&plan);
    assert!(
        applied.stdout.contains("workspace_present"),
        "{}",
        applied.stdout
    );
    assert!(world.project.exists());
}

#[test]
fn a_session_with_no_terminal_needs_the_approval_of_the_eviction() {
    let world = World::manual();
    let plan_id: String = world.planned();
    let refused = json(&world.environment, &["clean", "apply", "--plan", &plan_id]);
    assert_eq!(
        refused.status,
        ExitStatus::Unavailable,
        "{}",
        refused.stdout
    );
    assert_eq!(refused.error_code(), "approval_required");
    assert_eq!(world.remaining().len(), 3);
}

#[test]
fn the_evict_mode_takes_no_entry_and_the_other_modes_need_a_scan() {
    let world = World::manual();
    let with_entry = world.plan(&["--entry", world.project.to_str().unwrap()]);
    assert_eq!(
        with_entry.status,
        ExitStatus::Usage,
        "{}",
        with_entry.stdout
    );
    assert_eq!(with_entry.error_code(), "entry_not_accepted");
    for mode in ["trash", "permanent"] {
        let no_scan = json(&world.environment, &["clean", "plan", "--mode", mode]);
        assert_eq!(no_scan.status, ExitStatus::Usage, "{}", no_scan.stdout);
        assert_eq!(no_scan.error_code(), "scan_required");
    }
    assert!(!world.state_has_plans());
}

#[test]
fn the_developer_preset_filters_and_an_unknown_preset_is_refused() {
    let world = World::manual();
    let unknown = world.plan(&["--profile", "everything"]);
    assert_eq!(unknown.status, ExitStatus::Usage, "{}", unknown.stdout);
    assert_eq!(unknown.error_code(), "unknown_profile");
    assert!(!world.state_has_plans());
    // The preset includes the rule of the fixture: the plan is the same,
    // and the explanation names the preset.
    let outcome = world.plan(&["--profile", "developer"]);
    assert_eq!(outcome.status, ExitStatus::Success, "{}", outcome.stdout);
    let result = outcome.result();
    assert_eq!(target_paths(&result), unit_paths(&world.project));
    assert_eq!(result["explanation"]["preset"], "developer");

    // An entry of a scan has no rule, so the preset leaves it out: no
    // plan is made, and the explanation has the reason.
    let tree: PathBuf = world.directory.path().join("tree");
    std::fs::create_dir_all(tree.join("cache")).unwrap();
    std::fs::write(tree.join("cache/c.bin"), vec![3_u8; 20_000]).unwrap();
    let scanned = json(
        &world.environment,
        &["scan", tree.to_str().unwrap(), "--save"],
    );
    assert_eq!(scanned.status, ExitStatus::Success, "{}", scanned.stdout);
    let scan: String = scanned.result()["scan"]["scan_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let cache: PathBuf = std::fs::canonicalize(tree.join("cache")).unwrap();
    let filtered = json(
        &world.environment,
        &[
            "clean",
            "plan",
            "--scan",
            &scan,
            "--mode",
            "trash",
            "--profile",
            "developer",
            "--entry",
            cache.to_str().unwrap(),
        ],
    );
    assert_eq!(filtered.status, ExitStatus::Success, "{}", filtered.stdout);
    let result = filtered.result();
    assert!(result["explanation"]["plan"].is_null(), "{result}");
    assert!(
        filtered.stdout.contains("not_in_preset"),
        "{}",
        filtered.stdout
    );
    assert!(cache.exists());
}

#[test]
fn an_interrupted_discovery_makes_no_plan() {
    let mut world = World::manual();
    let (interrupt, flag) = crate::interrupt::Interrupt::manual();
    world.environment.interrupt = interrupt;
    flag.store(true, std::sync::atomic::Ordering::SeqCst);
    let outcome = world.plan(&[]);
    assert_eq!(
        outcome.status,
        ExitStatus::Interrupted,
        "{}",
        outcome.stdout
    );
    let result = outcome.result();
    assert!(result["explanation"]["plan"].is_null(), "{result}");
    assert_eq!(result["plan_document"], "absent");
    assert!(
        result["note"].as_str().unwrap().contains("interrupted"),
        "{result}"
    );
    assert!(!world.state_has_plans());
    assert_eq!(world.remaining().len(), 3);
}

#[test]
fn a_running_producer_gives_no_plan() {
    let world = World::manual();
    world.evidence.set_producer(ProducerProcesses::Running);
    let outcome = world.plan(&[]);
    assert_eq!(outcome.status, ExitStatus::Success, "{}", outcome.stdout);
    let result = outcome.result();
    assert!(result["explanation"]["plan"].is_null(), "{result}");
    assert_eq!(result["plan_document"], "absent");
    // The result has the reason of the rule for each unit.
    let blocked = result["discovery"]["blocked"].as_array().unwrap().clone();
    assert_eq!(blocked.len(), 3, "{result}");
    for unit in &blocked {
        assert_eq!(unit["reasons"][0], "active_producer", "{unit}");
    }
    assert!(!world.state_has_plans());
    assert_eq!(world.remaining().len(), 3);
}

#[test]
fn a_producer_that_starts_after_the_plan_inhibits_the_apply() {
    let world = World::manual();
    let plan_id: String = world.planned();
    // A build starts between the plan and its apply.
    world.evidence.set_producer(ProducerProcesses::Running);
    let applied = world.apply(&plan_id);
    // The fresh check before each step skipped each target: the operation
    // did nothing, and nothing stopped the producer.
    assert_eq!(world.remaining().len(), 3);
    let operation = applied.result()["operation"].clone();
    assert_eq!(operation["state"], "NoAction", "{operation}");
    assert_eq!(operation["dispatch"], "not_submitted", "{operation}");
    assert_eq!(operation["effects"]["skipped"], 3, "{operation}");
    assert_eq!(
        operation["effects"]["permanently_removed"], 0,
        "{operation}"
    );
    assert!(
        applied.stdout.contains("producer_active"),
        "{}",
        applied.stdout
    );
    // The plan was consumed: a second apply reports the same operation and
    // removes nothing.
    world.evidence.set_producer(ProducerProcesses::NotRunning);
    let again = world.apply(&plan_id);
    assert_eq!(
        again.result()["existing_operation"],
        true,
        "{}",
        again.stdout
    );
    assert_eq!(world.remaining().len(), 3);
}

#[test]
fn a_unit_that_is_replaced_after_the_plan_is_not_removed() {
    let world = World::manual();
    let plan_id: String = world.planned();
    let unit: PathBuf = world.project.join("Build/Products");
    let moved: PathBuf = world.directory.path().join("moved-products");
    std::fs::rename(&unit, &moved).unwrap();
    std::fs::create_dir(&unit).unwrap();
    std::fs::write(unit.join("precious.txt"), b"a file of the user").unwrap();
    let applied = world.apply(&plan_id);
    // The other targets are removed. The replaced unit is a different
    // object than the plan binds, so it gets no call.
    assert_ne!(applied.status, ExitStatus::Success, "{}", applied.stdout);
    assert_eq!(world.remaining(), vec!["Build/Products"]);
    assert!(unit.join("precious.txt").exists());
    assert!(moved.join("Debug/App.app/App").exists());
}

#[test]
fn a_rule_that_is_validated_for_automatic_eviction_also_permits_a_manual_plan() {
    let world = World::new(Some(automatic_eviction_validated()));
    let outcome = world.plan(&[]);
    assert_eq!(outcome.status, ExitStatus::Success, "{}", outcome.stdout);
    assert_eq!(target_paths(&outcome.result()), unit_paths(&world.project));
    assert!(
        outcome.result()["explanation"]["plan"]["plan_id"].is_string(),
        "{}",
        outcome.stdout
    );
}

#[test]
fn a_state_directory_in_the_root_gives_no_plan() {
    let (mut environment, directory) = environment();
    let home: PathBuf = std::fs::canonicalize(environment.home.as_ref().unwrap()).unwrap();
    let root: PathBuf = derived_data_root(&home);
    std::fs::create_dir_all(&root).unwrap();
    // The state directory of this user is inside the `DerivedData` root.
    environment.state_directory_override = Some(root.join("state").into_os_string());
    environment.seams.test.rule_lifecycle = Some(manual_action_validated());
    environment.seams.test.discovery_environment = Some(TestEnvironment(Arc::new(
        FixtureEnvironment::days_later(30),
    )));
    let workspace: PathBuf = write_workspace(&directory.path().join("src"), "App").unwrap();
    let project: PathBuf = write_project(&root, PROJECT, &workspace).unwrap();
    let config: PathBuf = directory.path().join("config.toml");
    std::fs::write(&config, "schema_version = 1\n").unwrap();
    let activated = json(
        &environment,
        &[
            "config",
            "apply",
            "--config",
            config.to_str().unwrap(),
            "--expected-revision",
            "none",
        ],
    );
    assert_eq!(
        activated.status,
        ExitStatus::Success,
        "{}",
        activated.stdout
    );
    let outcome = json(
        &environment,
        &["clean", "plan", "--mode", "evict", "--rule", RULE],
    );
    assert_eq!(outcome.status, ExitStatus::Success, "{}", outcome.stdout);
    let result = outcome.result();
    assert!(result["explanation"]["plan"].is_null(), "{result}");
    assert_eq!(result["discovery"]["roots"][0]["result"], "refused");
    assert_eq!(
        result["discovery"]["roots"][0]["reason"],
        "root_overlaps_protected"
    );
    assert!(project.join("Build/Products").exists());
}

impl World {
    /// A repository `upstream` with one commit, and a clone of it in
    /// `SourcePackages/checkouts/dep` of the project directory.
    fn source_package_checkout(&self) -> PathBuf {
        use crate::test_support::fixture_git;

        let home: PathBuf = std::fs::canonicalize(self.environment.home.as_ref().unwrap()).unwrap();
        let upstream: PathBuf = self.directory.path().join("upstream");
        std::fs::create_dir_all(&upstream).unwrap();
        std::fs::write(upstream.join("Sources.swift"), b"let value = 1\n").unwrap();
        fixture_git(&home, &upstream, &["init", "-q"]);
        fixture_git(&home, &upstream, &["add", "-A"]);
        fixture_git(&home, &upstream, &["commit", "-q", "-m", "start"]);
        let checkouts: PathBuf = self.project.join("SourcePackages/checkouts");
        std::fs::create_dir_all(&checkouts).unwrap();
        fixture_git(
            &home,
            &checkouts,
            &[
                "clone",
                "-q",
                "--no-hardlinks",
                upstream.to_str().unwrap(),
                "dep",
            ],
        );
        // A checkout of Swift Package Manager has a remote URL as its
        // origin; the commit stays in the remote-tracking references.
        fixture_git(
            &home,
            &checkouts.join("dep"),
            &[
                "remote",
                "set-url",
                "origin",
                "https://example.invalid/org/dep.git",
            ],
        );
        checkouts.join("dep")
    }
}

#[test]
fn an_orphan_with_a_swift_clone_that_gets_a_commit_after_the_plan_skips_the_step() {
    use crate::test_support::fixture_git;

    let world = World::manual();
    let checkout: PathBuf = world.source_package_checkout();
    std::fs::remove_dir_all(world.directory.path().join("src")).unwrap();
    let home: PathBuf = std::fs::canonicalize(world.environment.home.as_ref().unwrap()).unwrap();
    // A commit after the plan: the step keeps the project directory.
    let plan: String = world.planned();
    fixture_git(
        &home,
        &checkout,
        &["commit", "-q", "--allow-empty", "-m", "mine"],
    );
    let applied = world.apply(&plan);
    assert!(
        applied.stdout.contains("repository_changed"),
        "{}",
        applied.stdout
    );
    assert!(checkout.join(".git").exists());
    // A new plan is refused for the local commit: no target.
    let outcome = world.plan(&[]);
    assert_eq!(outcome.status, ExitStatus::Success, "{}", outcome.stdout);
    assert!(
        target_paths(&outcome.result()).is_empty(),
        "{}",
        outcome.stdout
    );
}

#[test]
fn an_orphan_with_a_clean_swift_clone_is_planned_and_removed() {
    let world = World::manual();
    let checkout: PathBuf = world.source_package_checkout();
    std::fs::remove_dir_all(world.directory.path().join("src")).unwrap();
    let plan: String = world.planned();
    let applied = world.apply(&plan);
    assert_eq!(applied.status, ExitStatus::Success, "{}", applied.stdout);
    assert!(!checkout.exists());
    assert!(!world.project.exists());
}
