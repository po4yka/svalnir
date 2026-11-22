//! End-to-end tests of the commands that change state.
//!
//! Each test has its own temporary directory with the state directory, a
//! home directory, a tree of files, and a directory that takes the place
//! of the Trash. A cleanup removes or moves only entries of that tree. A
//! stop signals only a child process that the test started. No test
//! registers a service: the service commands use a host that records its
//! calls.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::Value;
use svalnir_agent::journal::CoordinatorLock;
use svalnir_agent::platform::process::{DarwinProcessSource, ProcessSource, generation_id};
use svalnir_core::process::Pid;

use crate::environment::Environment;
use crate::output::ExitStatus;
use crate::run_in;
use crate::seams::{ProgramProblem, ServiceFailure, ServiceHost};
use crate::test_support::{TempDirectory, environment};

const CHILD_VARIABLE: &str = "SVALNIR_TEST_CLI_CHILD";
const CHILD_TEST: &str = "intervention_tests::child_entry";
const CHILD_LIFE: Duration = Duration::from_secs(60);

const BALANCED_CONFIG: &str = "schema_version = 1\n\n[agent]\nprofile = \"balanced\"\n\n[disk_guard]\nenabled = true\nvolumes = [\"startup-data\"]\n\n[memory_guard]\nenabled = true\neligible_groups = [\"background-user-applications\"]\n";

pub(super) struct Outcome {
    pub(super) status: ExitStatus,
    pub(super) stdout: String,
    pub(super) stderr: String,
}

impl Outcome {
    pub(super) fn envelope(&self) -> Value {
        assert_eq!(self.stdout.lines().count(), 1, "{}", self.stdout);
        serde_json::from_str(&self.stdout).unwrap()
    }

    pub(super) fn result(&self) -> Value {
        let envelope = self.envelope();
        assert!(envelope["error"].is_null(), "{}", self.stdout);
        envelope["result"].clone()
    }

    pub(super) fn error_code(&self) -> String {
        self.envelope()["error"]["code"]
            .as_str()
            .unwrap_or_default()
            .to_owned()
    }
}

/// The counter of the request identities of this test binary.
static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub(super) fn run(environment: &Environment, arguments: &[&str]) -> Outcome {
    let mut stdout: Vec<u8> = Vec::new();
    let mut stderr: Vec<u8> = Vec::new();
    // Each invocation has its own request identity, as each process has.
    let request_id = svalnir_core::id::RequestId::new(format!(
        "request_test_{}",
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
        stderr: String::from_utf8(stderr).unwrap(),
    }
}

pub(super) fn json(environment: &Environment, arguments: &[&str]) -> Outcome {
    let mut machine: Vec<&str> = arguments.to_vec();
    machine.extend(["--format", "json"]);
    run(environment, &machine)
}

/// One temporary world.
pub(super) struct World {
    pub(super) environment: Environment,
    directory: TempDirectory,
}

impl World {
    pub(super) fn new() -> Self {
        let (mut environment, directory) = environment();
        let trash: PathBuf = directory.path().join("trash");
        std::fs::create_dir_all(&trash).unwrap();
        environment.seams.test.trash_directory = Some(trash);
        Self {
            environment,
            directory,
        }
    }

    pub(super) fn path(&self, name: &str) -> PathBuf {
        self.directory.path().join(name)
    }

    /// Makes `tree/` with two directories and one file.
    pub(super) fn tree(&self) -> PathBuf {
        let tree: PathBuf = self.path("tree");
        std::fs::create_dir_all(tree.join("build/objects")).unwrap();
        std::fs::create_dir_all(tree.join("cache")).unwrap();
        std::fs::write(tree.join("build/objects/a.o"), vec![1_u8; 70_000]).unwrap();
        std::fs::write(tree.join("build/b.bin"), vec![2_u8; 30_000]).unwrap();
        std::fs::write(tree.join("cache/c.bin"), vec![3_u8; 20_000]).unwrap();
        std::fs::write(tree.join("notes.txt"), b"notes").unwrap();
        tree
    }

    /// Activates a configuration and returns its revision.
    pub(super) fn activate(&self, text: &str, expected: &str) -> String {
        let config: PathBuf = self.path("config.toml");
        std::fs::write(&config, text).unwrap();
        let outcome = json(
            &self.environment,
            &[
                "config",
                "apply",
                "--config",
                config.to_str().unwrap(),
                "--expected-revision",
                expected,
            ],
        );
        assert_eq!(outcome.status, ExitStatus::Success, "{}", outcome.stdout);
        let result = outcome.result();
        assert_eq!(result["acknowledgement"], "durably_applied");
        assert_eq!(result["durable"], true);
        result["report"]["revision"]["revision_id"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    fn scan(&self, tree: &Path) -> String {
        let outcome = json(
            &self.environment,
            &["scan", tree.to_str().unwrap(), "--save"],
        );
        assert_eq!(outcome.status, ExitStatus::Success, "{}", outcome.stdout);
        outcome.result()["scan"]["scan_id"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    /// The paths of the candidates of a scan: `clean plan` with no entry.
    fn candidates(&self, scan: &str, mode: &str) -> Vec<String> {
        let listed = json(
            &self.environment,
            &["clean", "plan", "--scan", scan, "--mode", mode],
        );
        assert_eq!(listed.status, ExitStatus::Usage, "{}", listed.stdout);
        listed.result()["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .map(|candidate| candidate["path"]["value"].as_str().unwrap().to_owned())
            .collect()
    }

    /// Prepares a plan that names each candidate of the scan, and returns
    /// its identity.
    fn plan(&self, scan: &str, mode: &str) -> String {
        let candidates: Vec<String> = self.candidates(scan, mode);
        let mut arguments: Vec<&str> = vec!["clean", "plan", "--scan", scan, "--mode", mode];
        for candidate in &candidates {
            arguments.extend(["--entry", candidate.as_str()]);
        }
        let outcome = json(&self.environment, &arguments);
        assert_eq!(outcome.status, ExitStatus::Success, "{}", outcome.stdout);
        outcome.result()["explanation"]["plan"]["plan_id"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    /// A world with an active template configuration, a tree, and a plan.
    pub(super) fn with_plan(mode: &str) -> (Self, PathBuf, String) {
        let world = Self::new();
        world.activate("schema_version = 1\n", "none");
        let tree: PathBuf = world.tree();
        let scan: String = world.scan(&tree);
        let plan: String = world.plan(&scan, mode);
        (world, tree, plan)
    }
}

fn entries(directory: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

/// The bytes of each file of the state directory, by name.
fn state_files(world: &World) -> std::collections::BTreeMap<PathBuf, Vec<u8>> {
    let mut files = std::collections::BTreeMap::new();
    let mut directories: Vec<PathBuf> = vec![world.path("state")];
    while let Some(directory) = directories.pop() {
        for entry in std::fs::read_dir(&directory).unwrap() {
            let path: PathBuf = entry.unwrap().path();
            if path.is_dir() {
                directories.push(path);
            } else {
                files.insert(path.clone(), std::fs::read(&path).unwrap());
            }
        }
    }
    files
}

/// `clean plan` with the arguments and each `--entry`.
fn plan_with(world: &World, scan: &str, mode: &str, entries: &[&Path]) -> Outcome {
    let mut arguments: Vec<&str> = vec!["clean", "plan", "--scan", scan, "--mode", mode];
    for entry in entries {
        arguments.extend(["--entry", entry.to_str().unwrap()]);
    }
    json(&world.environment, &arguments)
}

#[test]
fn a_plan_with_no_entry_lists_the_candidates_and_makes_no_plan() {
    let world = World::new();
    world.activate("schema_version = 1\n", "none");
    let tree: PathBuf = world.tree();
    let scan: String = world.scan(&tree);
    let before = state_files(&world);
    for mode in ["trash", "permanent"] {
        let listed = plan_with(&world, &scan, mode, &[]);
        assert_eq!(listed.status, ExitStatus::Usage, "{}", listed.stdout);
        assert_eq!(listed.envelope()["kind"], "report");
        assert_eq!(listed.envelope()["schema_version"], 1);
        let result = listed.result();
        assert_eq!(result["mode"], mode);
        assert_eq!(result["selection"], "entries_required");
        assert!(result.get("explanation").is_none(), "{result}");
        let paths: Vec<&str> = result["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .map(|candidate| candidate["path"]["value"].as_str().unwrap())
            .collect();
        assert!(
            paths.contains(&tree.join("build").to_str().unwrap()),
            "{paths:?}"
        );
        assert!(result["note"].as_str().unwrap().contains("--entry PATH"));
        let text = run(
            &world.environment,
            &["clean", "plan", "--scan", &scan, "--mode", mode],
        );
        assert_eq!(text.status, ExitStatus::Usage);
        assert!(
            text.stdout.starts_with("Candidates of scan "),
            "{}",
            text.stdout
        );
    }
    // No plan, no plan document, and no change of the journal.
    assert_eq!(state_files(&world), before);
    assert!(!world.path("state").join("plans").exists());
    assert_eq!(entries(&tree).len(), 3);
}

#[test]
fn a_manual_plan_warns_about_a_selected_tree_with_a_repository() {
    let world = World::new();
    world.activate("schema_version = 1\n", "none");
    let tree: PathBuf = world.tree();
    std::fs::create_dir_all(tree.join("build/vendor/dep/.git")).unwrap();
    std::fs::write(
        tree.join("build/vendor/dep/.git/HEAD"),
        b"ref: refs/heads/main\n",
    )
    .unwrap();
    let scan: String = world.scan(&tree);
    let build: PathBuf = tree.join("build");
    let cache: PathBuf = tree.join("cache");
    for mode in ["trash", "permanent"] {
        let planned = plan_with(&world, &scan, mode, &[&build, &cache]);
        assert_eq!(planned.status, ExitStatus::Success, "{}", planned.stdout);
        let warnings = planned.result()["repository_warnings"].clone();
        let warnings = warnings.as_array().unwrap();
        // The tree with no repository has no warning.
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert_eq!(warnings[0]["code"], "nested_repository");
        assert_eq!(warnings[0]["entry"]["value"], build.to_str().unwrap());
        assert_eq!(warnings[0]["path"]["value"], "vendor/dep");
        // The plan still has both entries.
        assert_eq!(planned.result()["explanation"]["totals"]["targets"], 2);

        let text = run(
            &world.environment,
            &[
                "clean",
                "plan",
                "--scan",
                &scan,
                "--mode",
                mode,
                "--entry",
                build.to_str().unwrap(),
            ],
        );
        assert_eq!(text.status, ExitStatus::Success, "{}", text.stdout);
        assert!(
            text.stdout
                .contains("Warning: 1 selected entries hold a Git repository"),
            "{}",
            text.stdout
        );
        assert!(text.stdout.contains("nested_repository"), "{}", text.stdout);
        assert!(text.stdout.contains("(at vendor/dep)"), "{}", text.stdout);
    }
    // A plan with no repository has no warning list.
    let planned = plan_with(&world, &scan, "permanent", &[&cache]);
    assert!(planned.result().get("repository_warnings").is_none());
}

#[test]
fn a_named_entry_is_the_only_target_and_an_entry_not_in_the_scan_is_refused() {
    let world = World::new();
    world.activate("schema_version = 1\n", "none");
    let tree: PathBuf = world.tree();
    let scan: String = world.scan(&tree);
    let cache: PathBuf = tree.join("cache");
    for mode in ["trash", "permanent"] {
        let planned = plan_with(&world, &scan, mode, &[&cache]);
        assert_eq!(planned.status, ExitStatus::Success, "{}", planned.stdout);
        let targets = planned.result()["explanation"]["targets"].clone();
        let targets = targets.as_array().unwrap();
        assert_eq!(targets.len(), 1, "{targets:?}");
        assert_eq!(targets[0]["path"]["value"], cache.to_str().unwrap());
        assert_eq!(planned.result()["explanation"]["totals"]["targets"], 1);
    }
    // A path of the tree that the scan record does not name, a path that
    // does not exist, and a prefix of a recorded entry.
    let before = state_files(&world);
    for absent in [
        tree.join("cache/c.bin/x"),
        tree.join("missing"),
        tree.join("cac"),
        tree.clone(),
    ] {
        let refused = plan_with(&world, &scan, "permanent", &[&cache, &absent]);
        assert_eq!(refused.status, ExitStatus::Usage, "{}", refused.stdout);
        assert_eq!(refused.error_code(), "entry_not_in_scan", "{absent:?}");
    }
    assert_eq!(state_files(&world), before);
    // The `evict` mode takes no entry and is otherwise unchanged.
    let evict = json(
        &world.environment,
        &[
            "clean",
            "plan",
            "--scan",
            &scan,
            "--mode",
            "evict",
            "--rule",
            "svalnir.expired-temporary",
            "--entry",
            cache.to_str().unwrap(),
        ],
    );
    assert_eq!(evict.status, ExitStatus::Usage, "{}", evict.stdout);
    assert_eq!(evict.error_code(), "entry_not_accepted");
    let evict = json(
        &world.environment,
        &[
            "clean",
            "plan",
            "--scan",
            &scan,
            "--mode",
            "evict",
            "--rule",
            "svalnir.expired-temporary",
        ],
    );
    assert_eq!(evict.status, ExitStatus::Unavailable, "{}", evict.stdout);
    assert_eq!(evict.error_code(), "rule_mode_not_validated");
    assert_eq!(state_files(&world), before);
}

/// The default `[protections]` table covers the personal folders of the
/// home directory. A configuration whose `excluded_paths` does not name
/// the folder permits a manual plan inside it.
#[test]
fn an_entry_in_a_personal_folder_is_protected_until_the_configuration_permits_it() {
    let world = World::new();
    let revision: String = world.activate("schema_version = 1\n", "none");
    let documents: PathBuf = world.path("home").join("Documents");
    std::fs::create_dir_all(documents.join("drafts")).unwrap();
    std::fs::write(documents.join("drafts/a.txt"), vec![1_u8; 4096]).unwrap();
    std::fs::write(documents.join("taxes.pdf"), vec![2_u8; 8192]).unwrap();
    let documents: PathBuf = std::fs::canonicalize(&documents).unwrap();
    let scan: String = world.scan(&documents);
    let drafts: PathBuf = documents.join("drafts");
    let before = state_files(&world);
    let refused = plan_with(&world, &scan, "permanent", &[&drafts]);
    assert_eq!(
        refused.status,
        ExitStatus::Unavailable,
        "{}",
        refused.stdout
    );
    assert_eq!(refused.error_code(), "target_protected");
    assert!(
        refused.envelope()["error"]["message"]
            .as_str()
            .unwrap()
            .contains("excluded_paths"),
        "{}",
        refused.stdout
    );
    assert_eq!(state_files(&world), before);

    // The user replaces the list: only `~/Desktop` and `~/Pictures` stay
    // protected. The activation names each default folder that the list
    // does not protect.
    let config: PathBuf = world.path("config.toml");
    std::fs::write(
        &config,
        "schema_version = 1\n[protections]\nexcluded_paths = [\"~/Desktop\", \"~/Pictures\"]\n",
    )
    .unwrap();
    let arguments = [
        "config",
        "apply",
        "--config",
        config.to_str().unwrap(),
        "--expected-revision",
        &revision,
    ];
    let applied = json(&world.environment, &arguments);
    assert_eq!(applied.status, ExitStatus::Success, "{}", applied.stdout);
    let warnings: Vec<String> = applied.envelope()["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|warning| warning["code"] == "personal_folder_not_protected")
        .map(|warning| warning["message"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(warnings.len(), 7, "{warnings:?}");
    for folder in ["~/Documents", "~/Downloads", "~/Library/CloudStorage"] {
        assert!(
            warnings
                .iter()
                .any(|warning| warning.contains(&format!("`{folder}`"))),
            "{folder}: {warnings:?}"
        );
    }
    assert!(
        !warnings
            .iter()
            .any(|warning| warning.contains("`~/Desktop`"))
    );
    let planned = plan_with(&world, &scan, "permanent", &[&drafts]);
    assert_eq!(planned.status, ExitStatus::Success, "{}", planned.stdout);
    let targets = planned.result()["explanation"]["targets"].clone();
    assert_eq!(targets.as_array().unwrap().len(), 1, "{targets}");
    assert_eq!(targets[0]["path"]["value"], drafts.to_str().unwrap());
}

/// The `[protections]` list applies to the resolved location of an entry
/// too: a scan root that reaches a personal folder through a symbolic-link
/// component does not make its entries look outside the folder.
#[test]
fn an_entry_reached_through_a_link_component_has_the_protection_of_its_location() {
    let world = World::new();
    world.activate("schema_version = 1\n", "none");
    let home: PathBuf = std::fs::canonicalize(world.path("home")).unwrap();
    std::fs::create_dir_all(home.join("Documents/drafts")).unwrap();
    std::fs::write(home.join("Documents/drafts/a.txt"), vec![1_u8; 4096]).unwrap();
    let link: PathBuf = std::fs::canonicalize(world.path("")).unwrap().join("link");
    std::os::unix::fs::symlink(&home, &link).unwrap();
    let root: PathBuf = link.join("Documents");
    let scan: String = world.scan(&root);
    let drafts: PathBuf = root.join("drafts");
    let before = state_files(&world);
    let refused = plan_with(&world, &scan, "permanent", &[&drafts]);
    assert_eq!(
        refused.status,
        ExitStatus::Unavailable,
        "{}",
        refused.stdout
    );
    assert_eq!(refused.error_code(), "target_protected");
    assert_eq!(state_files(&world), before);
}

#[test]
fn the_list_of_the_candidates_escapes_a_name() {
    let world = World::new();
    world.activate("schema_version = 1\n", "none");
    let tree: PathBuf = world.path("tree");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::write(tree.join("a\u{1b}[31mb\nOperation fake: Completed"), b"x").unwrap();
    let scan: String = world.scan(&tree);
    let listed = run(
        &world.environment,
        &["clean", "plan", "--scan", &scan, "--mode", "trash"],
    );
    assert_eq!(listed.status, ExitStatus::Usage, "{}", listed.stderr);
    assert!(!listed.stdout.contains('\u{1b}'), "{}", listed.stdout);
    assert!(
        !listed.stdout.contains("\nOperation fake"),
        "{}",
        listed.stdout
    );
    assert!(listed.stdout.contains("--entry PATH"), "{}", listed.stdout);
}

#[test]
fn a_plan_and_its_view_change_no_file() {
    let (world, tree, plan) = World::with_plan("permanent");
    let before: Vec<String> = entries(&tree);
    let show = json(&world.environment, &["clean", "show", "--plan", &plan]);
    assert_eq!(show.status, ExitStatus::Success, "{}", show.stdout);
    let result = show.result();
    assert_eq!(show.envelope()["kind"], "report");
    assert_eq!(result["explanation"]["mode"]["mode"], "permanent");
    assert_eq!(result["explanation"]["consequence"], "permanent_no_undo");
    assert_eq!(result["explanation"]["totals"]["targets"], 3);
    assert!(result["operation_id"].is_null());
    // The entries below a selected directory are left out with a reason.
    let omitted = result["explanation"]["omitted"].as_array().unwrap();
    assert!(
        omitted
            .iter()
            .all(|entry| entry["reasons"][0]["reason"] == "overlaps_selected_entry"),
        "{omitted:?}"
    );
    assert_ne!(omitted.len(), 0);
    let text = run(&world.environment, &["clean", "show", "--plan", &plan]);
    assert!(
        text.stdout.contains("Mode: cleanup: permanent"),
        "{}",
        text.stdout
    );
    assert!(
        text.stdout.contains("Permanent removal has no undo"),
        "{}",
        text.stdout
    );
    assert!(text.stdout.contains("directory"), "{}", text.stdout);
    assert_eq!(entries(&tree), before);
}

#[test]
fn a_permanent_plan_removes_the_selected_entries() {
    let (world, tree, plan) = World::with_plan("permanent");
    let apply = json(
        &world.environment,
        &["clean", "apply", "--plan", &plan, "--yes"],
    );
    assert_eq!(apply.status, ExitStatus::Success, "{}", apply.stdout);
    assert_eq!(apply.envelope()["kind"], "operation");
    let result = apply.result();
    assert_eq!(result["wait"], "finished");
    assert_eq!(result["existing_operation"], false);
    assert_eq!(result["executor"], "transient_coordinator");
    let operation = &result["operation"];
    assert_eq!(operation["state"], "Completed");
    assert_eq!(operation["settled"], true);
    assert_eq!(operation["effects"]["permanently_removed"], 3);
    assert_eq!(operation["effects"]["moved_to_trash"], 0);
    assert_eq!(operation["work"]["trashed_entries"], "0");
    // The observed capacity change is a list of its own, with a note.
    assert!(operation["resource_effects"].is_array());
    assert_eq!(entries(&tree), Vec::<String>::new());
    assert_eq!(entries(&world.path("trash")), Vec::<String>::new());

    // The history has the estimate, the removals, and the observation
    // as separate values.
    let history = json(&world.environment, &["history"]);
    assert_eq!(history.status, ExitStatus::Success);
    let record = &history.result()["records"][0];
    assert_eq!(record["state"], "Completed");
    assert_eq!(record["mode"]["mode"], "permanent");
    assert_eq!(record["effects"]["permanently_removed"], 3);
    assert_eq!(record["estimate"]["targets"], 3);
    assert!(record["estimate"]["estimated_reclaimable_bytes"].is_string());
    assert!(record["work"]["removed_entries"].is_string());
    let text = run(&world.environment, &["history", "--limit", "5"]);
    assert!(
        text.stdout.contains("3 permanently removed"),
        "{}",
        text.stdout
    );
    assert!(
        text.stdout.contains("Estimate of the plan"),
        "{}",
        text.stdout
    );
    // Each removal has the attribution `possible`, so the removed counts
    // are an estimate.
    assert!(
        text.stdout.contains("Permanently removed (estimate):"),
        "{}",
        text.stdout
    );
    let show = run(
        &world.environment,
        &[
            "operations",
            "show",
            "--operation",
            operation["operation_id"].as_str().unwrap(),
        ],
    );
    assert!(
        show.stdout
            .contains("(an estimate: the sizes that the executor measured before each call)"),
        "{}",
        show.stdout
    );
}

#[test]
fn a_trash_plan_moves_the_entries_and_claims_no_capacity() {
    let (world, tree, plan) = World::with_plan("trash");
    let apply = run(
        &world.environment,
        &["clean", "apply", "--plan", &plan, "--yes"],
    );
    assert_eq!(apply.status, ExitStatus::Success, "{}", apply.stderr);
    assert!(
        apply.stdout.contains("3 moved to Trash"),
        "{}",
        apply.stdout
    );
    assert!(
        apply
            .stdout
            .contains("A move to Trash is not reclaimed capacity"),
        "{}",
        apply.stdout
    );
    assert!(
        !apply.stdout.contains("Permanently removed:"),
        "{}",
        apply.stdout
    );
    assert_eq!(entries(&tree), Vec::<String>::new());
    assert_eq!(entries(&world.path("trash")).len(), 3);

    let history = json(&world.environment, &["history"]);
    let record = &history.result()["records"][0];
    assert_eq!(record["effects"]["moved_to_trash"], 3);
    assert_eq!(record["effects"]["permanently_removed"], 0);
    // A move to Trash has no estimate of reclaimable bytes.
    assert!(record["estimate"]["estimated_reclaimable_bytes"].is_null());
    assert_eq!(record["work"]["removed_entries"], "0");
    assert_eq!(record["work"]["trashed_entries"], "3");
}

#[test]
fn a_second_apply_reports_the_existing_operation() {
    let (world, _tree, plan) = World::with_plan("permanent");
    let first = json(
        &world.environment,
        &["clean", "apply", "--plan", &plan, "--yes"],
    );
    let second = json(
        &world.environment,
        &["clean", "apply", "--plan", &plan, "--yes"],
    );
    assert_eq!(second.status, ExitStatus::Success, "{}", second.stdout);
    let (first, second) = (first.result(), second.result());
    assert_eq!(second["existing_operation"], true);
    assert_eq!(
        second["operation"]["operation_id"],
        first["operation"]["operation_id"]
    );
    assert_eq!(second["operation"]["state"], "Completed");
    let history = json(&world.environment, &["history"]);
    assert_eq!(history.result()["records"].as_array().unwrap().len(), 1);
    // The view of the plan names its operation.
    let show = json(&world.environment, &["clean", "show", "--plan", &plan]);
    assert_eq!(
        show.result()["operation_id"],
        first["operation"]["operation_id"]
    );
}

#[test]
fn an_apply_needs_an_approval_that_yes_or_a_terminal_gives() {
    let (mut world, tree, plan) = World::with_plan("permanent");
    // No terminal and no `--yes`.
    let refused = json(&world.environment, &["clean", "apply", "--plan", &plan]);
    assert_eq!(refused.status, ExitStatus::Unavailable);
    assert_eq!(refused.error_code(), "approval_required");
    // A terminal, and the user does not approve.
    let answers = Arc::new(Mutex::new(VecDeque::from(["n".to_owned()])));
    world.environment.seams.test.answers = Some(Arc::clone(&answers));
    let declined = json(&world.environment, &["clean", "apply", "--plan", &plan]);
    assert_eq!(declined.status, ExitStatus::Unavailable);
    assert_eq!(declined.error_code(), "approval_declined");
    // The question has the scope and the consequence, on stderr.
    assert!(
        declined.stderr.contains("Permanent removal has no undo"),
        "{}",
        declined.stderr
    );
    assert!(
        declined.stderr.contains(&format!("Apply plan {plan}?")),
        "{}",
        declined.stderr
    );
    assert_eq!(entries(&tree).len(), 3);
    // The user approves.
    answers.lock().unwrap().push_back("yes".to_owned());
    let approved = json(&world.environment, &["clean", "apply", "--plan", &plan]);
    assert_eq!(approved.status, ExitStatus::Success, "{}", approved.stdout);
    assert_eq!(entries(&tree), Vec::<String>::new());
}

#[test]
fn an_expired_plan_is_refused_also_with_yes() {
    let world = World::new();
    world.activate(
        "schema_version = 1\n\n[agent]\nmanual_plan_ttl = \"1s\"\n",
        "none",
    );
    let tree: PathBuf = world.tree();
    let scan: String = world.scan(&tree);
    let plan: String = world.plan(&scan, "permanent");
    std::thread::sleep(Duration::from_millis(1200));
    let apply = json(
        &world.environment,
        &["clean", "apply", "--plan", &plan, "--yes"],
    );
    assert_eq!(apply.status, ExitStatus::Conflict, "{}", apply.stdout);
    let envelope = apply.envelope();
    assert_eq!(envelope["error"]["code"], "plan_expired");
    assert_eq!(envelope["error"]["family"], "limits");
    assert_eq!(envelope["error"]["plan_id"], plan);
    assert_eq!(envelope["error"]["next_action"], "prepare_new_plan");
    assert_eq!(entries(&tree).len(), 3);
    let show = json(&world.environment, &["clean", "show", "--plan", &plan]);
    assert_eq!(
        show.result()["explanation"]["plan"]["expiry"]["expired"],
        true
    );
}

#[test]
fn a_plan_of_an_earlier_revision_is_refused() {
    let (world, tree, plan) = World::with_plan("permanent");
    let revision: String = json(&world.environment, &["config", "show", "--effective"]).result()
        ["revision"]["revision_id"]
        .as_str()
        .unwrap()
        .to_owned();
    world.activate(BALANCED_CONFIG, &revision);
    let apply = json(
        &world.environment,
        &["clean", "apply", "--plan", &plan, "--yes"],
    );
    assert_eq!(apply.status, ExitStatus::Unavailable, "{}", apply.stdout);
    assert_eq!(apply.error_code(), "policy_revision_changed");
    assert_eq!(apply.envelope()["error"]["next_action"], "prepare_new_plan");
    assert_eq!(entries(&tree).len(), 3);
}

/// A different client changes the policy revision while the approval
/// question waits. The admission reads the authority record again, so the
/// approved plan of the earlier revision is refused and no file changes.
#[test]
fn a_revision_that_changes_while_the_question_waits_refuses_the_plan() {
    let (mut world, tree, plan) = World::with_plan("permanent");
    let revision: String = json(&world.environment, &["config", "show", "--effective"]).result()
        ["revision"]["revision_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let config: PathBuf = world.path("later.toml");
    std::fs::write(&config, BALANCED_CONFIG).unwrap();
    let other_client: Environment = world.environment.clone();
    world.environment.seams.test.answers =
        Some(Arc::new(Mutex::new(VecDeque::from(["yes".to_owned()]))));
    world.environment.seams.test.while_asked =
        Some(crate::seams::WhileAsked(Arc::new(move || {
            let outcome = json(
                &other_client,
                &[
                    "config",
                    "apply",
                    "--config",
                    config.to_str().unwrap(),
                    "--expected-revision",
                    &revision,
                ],
            );
            assert_eq!(outcome.status, ExitStatus::Success, "{}", outcome.stdout);
        })));
    let apply = json(&world.environment, &["clean", "apply", "--plan", &plan]);
    assert_eq!(apply.status, ExitStatus::Unavailable, "{}", apply.stdout);
    assert_eq!(apply.error_code(), "policy_revision_changed");
    assert_eq!(entries(&tree).len(), 3);
}

#[test]
fn no_wait_gives_the_operation_and_the_queries_read_it() {
    let (world, tree, plan) = World::with_plan("permanent");
    let accepted = json(
        &world.environment,
        &["clean", "apply", "--plan", &plan, "--yes", "--no-wait"],
    );
    assert_eq!(accepted.status, ExitStatus::Success, "{}", accepted.stdout);
    assert_eq!(accepted.envelope()["kind"], "accepted");
    let result = accepted.result();
    assert_eq!(result["plan_id"], plan);
    assert_eq!(result["acknowledgement"], "operation_admitted");
    assert_eq!(result["executor"], "transient_coordinator");
    let operation: String = result["operation_id"].as_str().unwrap().to_owned();
    // The client process is the executor: the operation ended before the
    // invocation returned.
    assert_eq!(entries(&tree), Vec::<String>::new());

    let show = json(
        &world.environment,
        &["operations", "show", "--operation", &operation],
    );
    assert_eq!(show.status, ExitStatus::Success);
    assert_eq!(show.envelope()["kind"], "operation");
    assert_eq!(show.result()["operation"]["state"], "Completed");
    assert_eq!(show.result()["coordinator"], "not_running");
    // The plan document of this client has the measurements.
    assert!(show.result()["operation"]["resource_effects"].is_array());

    let wait = json(
        &world.environment,
        &[
            "operations",
            "wait",
            "--operation",
            &operation,
            "--timeout",
            "5s",
        ],
    );
    assert_eq!(wait.status, ExitStatus::Success, "{}", wait.stdout);
    assert_eq!(wait.result()["wait"], "finished");
    let text = run(
        &world.environment,
        &["operations", "show", "--operation", &operation],
    );
    assert!(text.stdout.contains("): Completed"), "{}", text.stdout);

    // A cancel of a settled operation changes nothing and says so.
    let cancel = json(
        &world.environment,
        &["operations", "cancel", "--operation", &operation],
    );
    assert_eq!(cancel.status, ExitStatus::Success);
    assert_eq!(cancel.result()["acknowledgement"], "settled");
    assert_eq!(cancel.result()["fence_written"], false);
}

#[test]
fn a_held_coordinator_lock_sends_the_request_to_the_queue() {
    let (world, tree, plan) = World::with_plan("permanent");
    let journal: PathBuf = world.path("state").join("operations.sqlite");
    // A holder of the lock that serves no request, in place of an agent.
    let lock =
        CoordinatorLock::try_acquire(&journal, svalnir_agent::journal::CoordinatorRole::Agent)
            .unwrap();
    let accepted = json(
        &world.environment,
        &[
            "clean",
            "apply",
            "--plan",
            &plan,
            "--yes",
            "--no-wait",
            "--timeout",
            "1s",
        ],
    );
    assert_eq!(accepted.status, ExitStatus::Success, "{}", accepted.stdout);
    let result = accepted.result();
    assert_eq!(accepted.envelope()["kind"], "accepted");
    assert_eq!(result["executor"], "queued_for_coordinator");
    assert_eq!(result["state"], "queued");
    assert_eq!(result["acknowledgement"], "request_queued");
    assert!(result["operation_id"].is_null());
    assert!(
        result["request_id"]
            .as_str()
            .unwrap()
            .starts_with("request_test_")
    );

    // A waited request ends with no final result: exit 5, and nothing is
    // canceled or executed.
    let waited = json(
        &world.environment,
        &[
            "clean",
            "apply",
            "--plan",
            &plan,
            "--yes",
            "--timeout",
            "1s",
        ],
    );
    assert_eq!(waited.status, ExitStatus::Conflict, "{}", waited.stdout);
    assert_eq!(waited.result()["wait"], "timed_out");
    assert!(waited.result()["operation"].is_null());
    assert_eq!(entries(&tree).len(), 3);
    let status = json(&world.environment, &["agent", "status"]);
    assert_eq!(status.result()["coordinator"], "running");

    // With no holder, the client executes the plan one time.
    drop(lock);
    let applied = json(
        &world.environment,
        &["clean", "apply", "--plan", &plan, "--yes"],
    );
    assert_eq!(applied.status, ExitStatus::Success, "{}", applied.stdout);
    assert_eq!(applied.result()["operation"]["state"], "Completed");
    assert_eq!(entries(&tree), Vec::<String>::new());
    let history = json(&world.environment, &["history"]);
    assert_eq!(history.result()["records"].as_array().unwrap().len(), 1);
}

#[test]
fn an_activation_compares_the_expected_revision() {
    let world = World::new();
    let first: String = world.activate("schema_version = 1\n", "none");
    let config: PathBuf = world.path("other.toml");
    std::fs::write(&config, BALANCED_CONFIG).unwrap();
    let apply = |expected: &str| {
        json(
            &world.environment,
            &[
                "config",
                "apply",
                "--config",
                config.to_str().unwrap(),
                "--expected-revision",
                expected,
            ],
        )
    };
    for stale in ["none", "rev_stale"] {
        let refused = apply(stale);
        assert_eq!(refused.status, ExitStatus::Conflict, "{}", refused.stdout);
        assert_eq!(refused.error_code(), "revision_conflict");
        assert_eq!(
            refused.envelope()["error"]["fields"][0],
            "expected_revision"
        );
    }
    let effective = json(&world.environment, &["config", "show", "--effective"]);
    assert_eq!(effective.result()["revision"]["revision_id"], first);
    assert_eq!(effective.result()["active"], true);

    let second = apply(&first);
    assert_eq!(second.status, ExitStatus::Success, "{}", second.stdout);
    let report = &second.result()["report"];
    assert_eq!(report["previous"], first);
    assert_eq!(report["invalidates_unconsumed_plans"], true);
    assert_eq!(report["activation_makes_no_grant"], true);
    // An activation enables no guard.
    let status = json(&world.environment, &["agent", "status"]);
    let guards = status.result()["authority"]["guards"].clone();
    assert!(
        guards
            .as_array()
            .unwrap()
            .iter()
            .all(|guard| guard["standing"] != "active"),
        "{guards}"
    );
    let text = run(&world.environment, &["config", "show", "--effective"]);
    assert!(
        text.stdout.starts_with("Effective configuration"),
        "{}",
        text.stdout
    );
}

#[test]
fn a_guard_is_enabled_only_with_its_acceptance_and_its_revision() {
    let world = World::new();
    let revision: String = world.activate(BALANCED_CONFIG, "none");
    // No acceptance of permanent eviction.
    let missing = json(
        &world.environment,
        &[
            "policy",
            "enable",
            "disk-guard",
            "--expected-revision",
            &revision,
        ],
    );
    assert_eq!(
        missing.status,
        ExitStatus::Unavailable,
        "{}",
        missing.stdout
    );
    assert_eq!(missing.error_code(), "acceptance_mismatch");
    assert!(
        missing.envelope()["error"]["message"]
            .as_str()
            .unwrap()
            .contains("EvictRegenerableData"),
        "{}",
        missing.stdout
    );
    // An acceptance that the guard does not have.
    let excess = json(
        &world.environment,
        &[
            "policy",
            "enable",
            "disk-guard",
            "--accept-permanent-eviction",
            "--accept-force-quit",
            "--expected-revision",
            &revision,
        ],
    );
    assert_eq!(excess.error_code(), "acceptance_mismatch");
    // No terminal and no reviewed revision.
    let unbound = json(
        &world.environment,
        &[
            "policy",
            "enable",
            "disk-guard",
            "--accept-permanent-eviction",
        ],
    );
    assert_eq!(unbound.status, ExitStatus::Unavailable);
    assert_eq!(unbound.error_code(), "reviewed_revision_required");
    // A revision that is not the one in effect.
    let stale = json(
        &world.environment,
        &[
            "policy",
            "enable",
            "disk-guard",
            "--accept-permanent-eviction",
            "--expected-revision",
            "rev_stale",
        ],
    );
    assert_eq!(stale.status, ExitStatus::Conflict);
    assert_eq!(stale.error_code(), "revision_conflict");

    let enabled = json(
        &world.environment,
        &[
            "policy",
            "enable",
            "disk-guard",
            "--accept-permanent-eviction",
            "--expected-revision",
            &revision,
        ],
    );
    assert_eq!(enabled.status, ExitStatus::Success, "{}", enabled.stdout);
    let result = enabled.result();
    assert_eq!(result["acknowledgement"], "durably_applied");
    assert_eq!(result["report"]["standing"], "active");
    assert_eq!(
        result["report"]["action_classes"][0],
        "EvictRegenerableData"
    );
    assert_eq!(result["coordinator"], "not_running");
}

/// An interactive enable names no revision in its arguments. The request
/// binds the revision that the question showed.
#[test]
fn an_interactive_enable_binds_the_revision_that_the_question_showed() {
    let mut world = World::new();
    let revision: String = world.activate(BALANCED_CONFIG, "none");
    world.environment.seams.test.answers =
        Some(Arc::new(Mutex::new(VecDeque::from(["yes".to_owned()]))));
    let enabled = json(
        &world.environment,
        &[
            "policy",
            "enable",
            "disk-guard",
            "--accept-permanent-eviction",
        ],
    );
    assert_eq!(enabled.status, ExitStatus::Success, "{}", enabled.stdout);
    assert!(enabled.stderr.contains(&revision), "{}", enabled.stderr);
    let result = enabled.result();
    assert_eq!(result["report"]["policy_revision"], revision);
    assert_eq!(result["report"]["standing"], "active");
}

/// A different client activates a new revision while the question of an
/// interactive enable waits. The user saw the earlier revision, so the
/// enable binds nothing and no guard gets a grant.
#[test]
fn a_revision_that_changes_while_the_question_waits_refuses_the_enable() {
    let mut world = World::new();
    let revision: String = world.activate(BALANCED_CONFIG, "none");
    let config: PathBuf = world.path("later.toml");
    std::fs::write(&config, BALANCED_CONFIG.replace("balanced", "aggressive")).unwrap();
    let other_client: Environment = world.environment.clone();
    world.environment.seams.test.answers =
        Some(Arc::new(Mutex::new(VecDeque::from(["yes".to_owned()]))));
    world.environment.seams.test.while_asked =
        Some(crate::seams::WhileAsked(Arc::new(move || {
            let outcome = json(
                &other_client,
                &[
                    "config",
                    "apply",
                    "--config",
                    config.to_str().unwrap(),
                    "--expected-revision",
                    &revision,
                ],
            );
            assert_eq!(outcome.status, ExitStatus::Success, "{}", outcome.stdout);
        })));
    let enabled = json(
        &world.environment,
        &[
            "policy",
            "enable",
            "disk-guard",
            "--accept-permanent-eviction",
        ],
    );
    assert_eq!(enabled.status, ExitStatus::Conflict, "{}", enabled.stdout);
    assert_eq!(enabled.error_code(), "authority_record_changed");
    world.environment.seams.test.while_asked = None;
    let status = json(&world.environment, &["agent", "status"]);
    let guard = &status.result()["authority"]["guards"][0];
    assert_eq!(guard["policy"], "disk-guard");
    assert_eq!(guard["grant"], Value::Null, "{}", status.stdout);
}

#[test]
fn an_enabled_guard_is_in_the_status_and_a_disable_removes_its_standing() {
    let world = World::new();
    let revision: String = world.activate(BALANCED_CONFIG, "none");
    let enable = |flags: &[&str]| {
        let mut arguments: Vec<&str> = vec!["policy", "enable", "memory-guard"];
        arguments.extend_from_slice(flags);
        arguments.extend(["--expected-revision", revision.as_str()]);
        json(&world.environment, &arguments)
    };
    // No acceptance flag accepts no class, and a force quit is not in this
    // configuration: each is refused and changes nothing.
    for flags in [&[][..], &["--accept-force-quit"][..]] {
        let refused = enable(flags);
        assert_eq!(
            refused.status,
            ExitStatus::Unavailable,
            "{}",
            refused.stdout
        );
        assert_eq!(refused.error_code(), "acceptance_mismatch", "{flags:?}");
        let status = json(&world.environment, &["agent", "status"]);
        assert_eq!(
            status.result()["authority"]["guards"][1]["grant"],
            Value::Null,
            "{}",
            status.stdout
        );
    }
    let enabled = enable(&["--accept-application-exit"]);
    assert_eq!(enabled.status, ExitStatus::Success, "{}", enabled.stdout);
    // The configuration does not allow a force quit, so the grant has
    // only the request for an exit.
    assert_eq!(
        enabled.result()["report"]["action_classes"],
        serde_json::json!(["RequestApplicationExit"])
    );
    assert_eq!(
        enabled.result()["report"]["acceptances"],
        serde_json::json!(["application_exit"])
    );
    let status = json(&world.environment, &["status"]);
    let policies = &status.result()["policies"];
    assert_eq!(policies["state"], "active");
    assert!(
        policies["note"].as_str().unwrap().contains("no agent runs"),
        "{policies}"
    );

    let disabled = json(&world.environment, &["policy", "disable", "memory-guard"]);
    assert_eq!(disabled.status, ExitStatus::Success, "{}", disabled.stdout);
    assert_eq!(disabled.result()["acknowledgement"], "durably_applied");
    let status = json(&world.environment, &["agent", "status"]);
    assert_eq!(
        status.result()["authority"]["guards"][1]["standing"],
        "disabled"
    );
    let text = run(&world.environment, &["policy", "disable", "memory-guard"]);
    assert!(
        text.stdout
            .starts_with("svalnir policy disable: durably_applied"),
        "{}",
        text.stdout
    );
}

#[test]
fn a_pause_and_a_resume_are_in_the_authority_record() {
    let world = World::new();
    let paused = json(&world.environment, &["agent", "pause", "--for", "1h"]);
    assert_eq!(paused.status, ExitStatus::Success, "{}", paused.stdout);
    let result = paused.result();
    assert_eq!(result["acknowledgement"], "durably_applied");
    assert_eq!(result["record_changed"], true);
    assert_eq!(result["report"]["status"]["status"], "paused");
    let status = json(&world.environment, &["agent", "status"]);
    let summary = status.result();
    assert_eq!(status.envelope()["kind"], "snapshot");
    assert_eq!(summary["authority"]["pause"]["status"], "paused");
    assert_eq!(summary["coordinator"], "not_running");
    assert_eq!(summary["lock_holder"], "none");
    let text = run(&world.environment, &["agent", "status"]);
    assert!(
        text.stdout
            .contains("No agent process holds the coordinator lock"),
        "{}",
        text.stdout
    );
    assert!(text.stdout.contains("paused until"), "{}", text.stdout);

    let resumed = json(&world.environment, &["agent", "resume"]);
    assert_eq!(resumed.status, ExitStatus::Success, "{}", resumed.stdout);
    assert_eq!(resumed.result()["report"]["status"]["status"], "not_paused");
    let again = json(&world.environment, &["agent", "resume"]);
    assert_eq!(again.result()["record_changed"], false);
    let status = json(&world.environment, &["agent", "status"]);
    assert_eq!(
        status.result()["authority"]["pause"]["status"],
        "not_paused"
    );
}

/// A timed pause of an earlier boot cannot be shown to have ended: the
/// status keeps it with the reason `retained`, and a resume ends it.
#[test]
fn a_timed_pause_of_an_earlier_boot_is_shown_as_retained_until_a_resume() {
    use svalnir_agent::journal::{AgentRecord, JournalOptions, OperationJournal};
    use svalnir_core::grant::AuthorityState;

    let world = World::new();
    let paused = json(&world.environment, &["agent", "pause", "--for", "1m"]);
    assert_eq!(paused.status, ExitStatus::Success, "{}", paused.stdout);
    // The record as an earlier boot left it.
    let path: PathBuf = world.path("state").join("operations.sqlite");
    let mut journal = OperationJournal::open(&path, &JournalOptions::default()).unwrap();
    let stored = journal
        .agent_record::<AuthorityState>(AgentRecord::Authority)
        .unwrap()
        .unwrap();
    let mut record: AuthorityState = stored.record;
    let deadline = record.pause.as_mut().unwrap().deadline.as_mut().unwrap();
    deadline.boot_id = svalnir_core::id::BootId::new("boot_of_an_earlier_start").unwrap();
    // The recorded expiry is long past on the wall clock.
    deadline.wall = svalnir_core::time::WallTime::from_unix(1_000_000_000, 0).unwrap();
    journal
        .put_agent_record(
            AgentRecord::Authority,
            &record,
            Some(stored.revision),
            svalnir_core::time::WallTime::from_unix(1_000_000_000, 0).unwrap(),
        )
        .unwrap();
    drop(journal);

    let status = json(&world.environment, &["agent", "status"]);
    let pause = status.result()["authority"]["pause"].clone();
    assert_eq!(pause["status"], "paused", "{}", status.stdout);
    assert_eq!(pause["basis"], "retained");
    assert_eq!(pause["until"], Value::Null);
    let text = run(&world.environment, &["agent", "status"]);
    assert!(text.stdout.contains("earlier boot"), "{}", text.stdout);

    let resumed = json(&world.environment, &["agent", "resume"]);
    assert_eq!(resumed.status, ExitStatus::Success, "{}", resumed.stdout);
    assert_eq!(resumed.result()["report"]["status"]["status"], "not_paused");
}

/// A pause whose write fails is not in effect, so the command reports an
/// error and no pause: a pause report of a change that is not durable would
/// show an end time that no record has.
#[test]
fn a_pause_that_is_not_written_reports_an_error_and_no_pause() {
    use std::os::unix::fs::PermissionsExt;

    let world = World::new();
    world.activate("schema_version = 1\n", "none");
    let state: PathBuf = world.environment.state_directory().unwrap();
    let files: Vec<PathBuf> = std::fs::read_dir(&state)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_file())
        .collect();
    let set_mode = |mode: u32| {
        for file in &files {
            std::fs::set_permissions(file, std::fs::Permissions::from_mode(mode)).unwrap();
        }
    };
    set_mode(0o400);
    let paused = json(&world.environment, &["agent", "pause", "--for", "1h"]);
    set_mode(0o600);
    assert_ne!(paused.status, ExitStatus::Success, "{}", paused.stdout);
    let envelope = paused.envelope();
    assert_eq!(envelope["result"], Value::Null, "{}", paused.stdout);
    assert!(!paused.stdout.contains("\"until\""), "{}", paused.stdout);
    assert!(
        envelope["error"]["message"]
            .as_str()
            .unwrap()
            .contains("NOT in effect"),
        "{}",
        paused.stdout
    );
    let status = json(&world.environment, &["agent", "status"]);
    assert_eq!(
        status.result()["authority"]["pause"]["status"],
        "not_paused",
        "{}",
        status.stdout
    );
}

/// A service host that records its calls and changes only a temporary
/// directory.
#[derive(Debug)]
struct RecordingHost {
    program: Option<PathBuf>,
    /// The problem that the host reports when it has no program.
    problem: ProgramProblem,
    calls: Mutex<Vec<String>>,
    fail_load: bool,
    /// The log directory is refused, as for a directory that this user
    /// cannot write.
    fail_log_directory: bool,
    /// The number of queries after an unload that still find the service,
    /// as the service manager of the host does for a short time. `None`:
    /// the service is never removed.
    late_removal: Option<u32>,
    /// The queries since the last unload.
    queries: Mutex<u32>,
}

impl Default for RecordingHost {
    fn default() -> Self {
        Self {
            program: None,
            problem: ProgramProblem::NotFound,
            calls: Mutex::new(Vec::new()),
            fail_load: false,
            fail_log_directory: false,
            late_removal: Some(0),
            queries: Mutex::new(0),
        }
    }
}

impl ServiceHost for RecordingHost {
    fn agent_program(&self) -> Result<PathBuf, ProgramProblem> {
        self.program.clone().ok_or(self.problem)
    }

    fn definition_exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn prepare_log_directory(&self, path: &Path) -> Result<(), ServiceFailure> {
        self.calls.lock().unwrap().push("log_directory".to_owned());
        if self.fail_log_directory {
            return Err(ServiceFailure {
                step: "log_directory",
                detail: "this user does not own the log directory or cannot write to it".to_owned(),
            });
        }
        std::fs::create_dir_all(path).unwrap();
        Ok(())
    }

    fn write_definition(&self, path: &Path, text: &str) -> Result<(), ServiceFailure> {
        self.calls.lock().unwrap().push("write".to_owned());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
        Ok(())
    }

    fn remove_definition(&self, path: &Path) -> Result<(), ServiceFailure> {
        self.calls.lock().unwrap().push("remove".to_owned());
        drop(std::fs::remove_file(path));
        Ok(())
    }

    fn load(&self, _uid: u32, _path: &Path) -> Result<(), ServiceFailure> {
        self.calls.lock().unwrap().push("load".to_owned());
        if self.fail_load {
            return Err(ServiceFailure {
                step: "load",
                detail: "the service manager refused the definition (status 5)".to_owned(),
            });
        }
        Ok(())
    }

    fn unload(&self, _uid: u32, label: &str) -> Result<(), ServiceFailure> {
        self.calls.lock().unwrap().push(format!("unload {label}"));
        *self.queries.lock().unwrap() = 0;
        Ok(())
    }

    fn is_loaded(&self, _uid: u32, _label: &str) -> Result<bool, ServiceFailure> {
        let mut queries = self.queries.lock().unwrap();
        *queries += 1;
        Ok(self.late_removal.is_none_or(|late| *queries <= late))
    }

    fn pause(&self, _interval: Duration) {
        self.calls.lock().unwrap().push("pause".to_owned());
    }
}

fn world_with_host(host: RecordingHost) -> (World, Arc<RecordingHost>) {
    let mut world = World::new();
    let host = Arc::new(host);
    world.environment.seams.test.service_host = Some(Arc::clone(&host) as Arc<dyn ServiceHost>);
    (world, host)
}

#[test]
fn an_install_registers_an_observation_agent_through_the_service_host() {
    let (world, host) = world_with_host(RecordingHost {
        program: Some(PathBuf::from("/opt/svalnir/bin/svalnir-agent")),
        ..RecordingHost::default()
    });
    let definition: PathBuf = world
        .path("home")
        .join("Library/LaunchAgents/dev.po4yka.svalnir.agent.plist");
    // No terminal and no `--yes`: no host effect.
    let refused = json(&world.environment, &["agent", "install"]);
    assert_eq!(refused.status, ExitStatus::Unavailable);
    assert_eq!(refused.error_code(), "approval_required");
    assert!(host.calls.lock().unwrap().is_empty());
    assert!(!definition.exists());

    let installed = json(&world.environment, &["agent", "install", "--yes"]);
    assert_eq!(
        installed.status,
        ExitStatus::Success,
        "{}",
        installed.stdout
    );
    let result = installed.result();
    assert_eq!(result["mode"], "observation");
    assert_eq!(result["guards_enabled"], serde_json::json!([]));
    assert_eq!(result["service_manager"], "loaded");
    assert_eq!(
        *host.calls.lock().unwrap(),
        [
            "log_directory",
            "write",
            "unload dev.po4yka.svalnir.agent",
            "load"
        ]
    );
    let text: String = std::fs::read_to_string(&definition).unwrap();
    assert!(
        text.contains("<string>/opt/svalnir/bin/svalnir-agent</string>"),
        "{text}"
    );
    assert!(text.contains("<string>--foreground</string>"), "{text}");
    assert!(text.contains("<string>--state-dir</string>"), "{text}");
    // The definition gives no configuration and enables no guard.
    assert!(!text.contains("--config"), "{text}");
    // The log is in the log directory of the home directory, not in the
    // state directory, and the directory exists before the service loads.
    let log: PathBuf = world.path("home").join("Library/Logs/Svalnir/agent.log");
    let log_text: String = format!(
        "<key>StandardErrorPath</key>\n\t<string>{}</string>",
        log.display()
    );
    assert!(text.contains(&log_text), "{text}");
    assert!(log.parent().unwrap().is_dir());
    assert_eq!(result["log"]["value"], log.display().to_string());
    let status = json(&world.environment, &["agent", "status"]);
    assert_eq!(status.result()["service"]["definition_present"], true);
    assert_eq!(
        status.result()["service"]["log"]["value"],
        log.display().to_string()
    );
    // The install made no authority record.
    assert!(status.result()["authority"].is_null());
}

/// An install on a state directory whose authority record has an enabled
/// guard does not say that the agent makes no automatic intervention.
#[test]
fn an_install_names_a_guard_that_the_authority_record_has_enabled() {
    let (mut world, _host) = world_with_host(RecordingHost {
        program: Some(PathBuf::from("/opt/svalnir/bin/svalnir-agent")),
        ..RecordingHost::default()
    });
    let revision: String = world.activate(BALANCED_CONFIG, "none");
    let enabled = json(
        &world.environment,
        &[
            "policy",
            "enable",
            "memory-guard",
            "--accept-application-exit",
            "--expected-revision",
            &revision,
        ],
    );
    assert_eq!(enabled.status, ExitStatus::Success, "{}", enabled.stdout);

    // The question names the guard and the stop of a running agent.
    world.environment.seams.test.answers =
        Some(Arc::new(Mutex::new(VecDeque::from(["n".to_owned()]))));
    let declined = json(&world.environment, &["agent", "install"]);
    assert_eq!(declined.error_code(), "approval_declined");
    assert!(
        declined.stderr.contains("memory-guard"),
        "{}",
        declined.stderr
    );
    assert!(
        declined.stderr.contains("is stopped and started again"),
        "{}",
        declined.stderr
    );
    assert!(
        !declined.stderr.contains("observation mode"),
        "{}",
        declined.stderr
    );

    let installed = json(&world.environment, &["agent", "install", "--yes"]);
    assert_eq!(
        installed.status,
        ExitStatus::Success,
        "{}",
        installed.stdout
    );
    let result = installed.result();
    assert_eq!(result["mode"], "standing_guards");
    assert_eq!(
        result["standing_guards"],
        serde_json::json!(["memory-guard"])
    );
    assert_eq!(result["guards_enabled"], serde_json::json!([]));
    assert!(
        !result["note"]
            .as_str()
            .unwrap()
            .contains("no automatic intervention"),
        "{result}"
    );
}

/// A state directory that other users can read is refused, and so is a
/// state directory that is a symbolic link.
#[test]
fn a_state_directory_that_is_not_private_is_refused() {
    use std::os::unix::fs::PermissionsExt as _;
    let world = World::new();
    let state: PathBuf = world.path("state");
    std::fs::create_dir_all(&state).unwrap();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o755)).unwrap();
    let config: PathBuf = world.path("config.toml");
    std::fs::write(&config, "schema_version = 1\n").unwrap();
    let arguments = [
        "config",
        "apply",
        "--config",
        config.to_str().unwrap(),
        "--expected-revision",
        "none",
    ];
    let refused = json(&world.environment, &arguments);
    assert_eq!(
        refused.status,
        ExitStatus::Unavailable,
        "{}",
        refused.stdout
    );
    assert_eq!(refused.error_code(), "state_directory_not_private");
    assert_eq!(entries(&state), Vec::<String>::new());

    // A link to a private directory is also not the state directory.
    std::fs::remove_dir(&state).unwrap();
    let real: PathBuf = world.path("real-state");
    std::fs::create_dir_all(&real).unwrap();
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::os::unix::fs::symlink(&real, &state).unwrap();
    let refused = json(&world.environment, &arguments);
    assert_eq!(refused.error_code(), "state_directory_not_private");
    assert_eq!(entries(&real), Vec::<String>::new());

    // A private directory is accepted.
    std::fs::remove_file(&state).unwrap();
    std::fs::create_dir_all(&state).unwrap();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
    let applied = json(&world.environment, &arguments);
    assert_eq!(applied.status, ExitStatus::Success, "{}", applied.stdout);
}

/// The removal of old documents keeps each lock file: a client can hold
/// the lock of an old file.
#[test]
fn the_removal_of_old_documents_keeps_the_lock_files() {
    let (world, _tree, plan) = World::with_plan("permanent");
    let plans: PathBuf = world.path("state").join("plans");
    let old: std::time::SystemTime = std::time::SystemTime::now() - Duration::from_hours(720);
    let lock: PathBuf = plans.join("stop-pg_old.lock");
    let record: PathBuf = plans.join("stop-pg_old.json");
    for path in [&lock, &record] {
        std::fs::write(path, b"{}").unwrap();
        std::fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(old)
            .unwrap();
    }
    crate::commands::plan_store::prune(&world.environment);
    assert!(lock.exists());
    assert!(!record.exists());
    assert!(document_path(&world, &plan).exists());
}

/// `--expected-revision none` cannot enable a guard, and the error says
/// that the revisions do not agree.
/// A guard whose revision permits a force quit needs `--accept-force-quit`;
/// `--accept-application-exit` alone is refused. With the two flags, the
/// accepted classes are those of `--accept-force-quit`.
#[test]
fn a_guard_that_permits_a_force_quit_needs_the_force_quit_acceptance() {
    let world = World::new();
    let config: String = BALANCED_CONFIG.replace(
        "[memory_guard]\nenabled = true\n",
        "[memory_guard]\nenabled = true\nallow_force_quit = true\n",
    );
    assert_ne!(config, BALANCED_CONFIG);
    let revision: String = world.activate(&config, "none");
    let enable = |flags: &[&str]| {
        let mut arguments: Vec<&str> = vec!["policy", "enable", "memory-guard"];
        arguments.extend_from_slice(flags);
        arguments.extend(["--expected-revision", revision.as_str()]);
        json(&world.environment, &arguments)
    };
    let refused = enable(&["--accept-application-exit"]);
    assert_eq!(
        refused.status,
        ExitStatus::Unavailable,
        "{}",
        refused.stdout
    );
    assert_eq!(refused.error_code(), "acceptance_mismatch");
    let enabled = enable(&["--accept-application-exit", "--accept-force-quit"]);
    assert_eq!(enabled.status, ExitStatus::Success, "{}", enabled.stdout);
    assert_eq!(
        enabled.result()["report"]["action_classes"],
        serde_json::json!(["RequestApplicationExit", "ForceApplicationExit"])
    );
    assert_eq!(
        enabled.result()["report"]["acceptances"],
        serde_json::json!(["force_quit"])
    );
    let text = run(
        &world.environment,
        &[
            "policy",
            "enable",
            "memory-guard",
            "--accept-force-quit",
            "--expected-revision",
            &revision,
        ],
    );
    assert!(text.stdout.contains("force_quit"), "{}", text.stdout);
}

#[test]
fn an_enable_that_expects_no_revision_is_a_revision_conflict() {
    let world = World::new();
    world.activate(BALANCED_CONFIG, "none");
    let refused = json(
        &world.environment,
        &[
            "policy",
            "enable",
            "memory-guard",
            "--expected-revision",
            "none",
        ],
    );
    assert_eq!(refused.status, ExitStatus::Conflict, "{}", refused.stdout);
    assert_eq!(refused.error_code(), "revision_conflict");
}

#[test]
fn an_uninstall_unloads_the_service_and_removes_the_definition() {
    let (world, host) = world_with_host(RecordingHost {
        program: Some(PathBuf::from("/opt/svalnir/bin/svalnir-agent")),
        ..RecordingHost::default()
    });
    let definition: PathBuf = world
        .path("home")
        .join("Library/LaunchAgents/dev.po4yka.svalnir.agent.plist");
    let installed = json(&world.environment, &["agent", "install", "--yes"]);
    assert_eq!(
        installed.status,
        ExitStatus::Success,
        "{}",
        installed.stdout
    );
    assert!(definition.exists());
    let removed = run(&world.environment, &["agent", "uninstall", "--yes"]);
    assert_eq!(removed.status, ExitStatus::Success, "{}", removed.stderr);
    assert!(
        removed
            .stdout
            .starts_with("svalnir agent uninstall: unloaded"),
        "{}",
        removed.stdout
    );
    assert_eq!(
        host.calls.lock().unwrap()[4..],
        ["unload dev.po4yka.svalnir.agent", "remove"]
    );
    assert!(!definition.exists());
    // The records of the state directory stay, and so does the log.
    assert!(world.path("state").exists());
    assert!(
        world.path("home").join("Library/Logs/Svalnir").is_dir(),
        "the uninstall removed the log directory"
    );
    assert!(
        removed.stdout.contains("The log of the agent stays"),
        "{}",
        removed.stdout
    );
    assert!(removed.stdout.contains("Library/Logs/Svalnir/agent.log"));
}

#[test]
fn an_install_with_a_log_directory_that_is_not_writable_changes_no_registration() {
    let (world, host) = world_with_host(RecordingHost {
        program: Some(PathBuf::from("/opt/svalnir/bin/svalnir-agent")),
        fail_log_directory: true,
        ..RecordingHost::default()
    });
    let definition: PathBuf = world
        .path("home")
        .join("Library/LaunchAgents/dev.po4yka.svalnir.agent.plist");
    let refused = json(&world.environment, &["agent", "install", "--yes"]);
    assert_eq!(
        refused.status,
        ExitStatus::Unavailable,
        "{}",
        refused.stdout
    );
    assert_eq!(refused.error_code(), "service_change_failed");
    let message: String = refused.envelope()["error"]["message"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(message.contains("changed no registration"), "{message}");
    assert!(message.contains("log directory"), "{message}");
    // No definition and no service-manager call.
    assert_eq!(*host.calls.lock().unwrap(), ["log_directory"]);
    assert!(!definition.exists());
}

#[test]
fn an_install_reports_a_missing_program_and_a_refused_load() {
    let (world, host) = world_with_host(RecordingHost::default());
    let missing = json(&world.environment, &["agent", "install", "--yes"]);
    assert_eq!(missing.status, ExitStatus::Unavailable);
    assert_eq!(missing.error_code(), "agent_program_not_found");
    assert!(host.calls.lock().unwrap().is_empty());

    // A program that a different user can change is refused before each
    // host effect.
    let (world, host) = world_with_host(RecordingHost {
        problem: ProgramProblem::NotTrusted,
        ..RecordingHost::default()
    });
    let untrusted = json(&world.environment, &["agent", "install", "--yes"]);
    assert_eq!(untrusted.status, ExitStatus::Unavailable);
    assert_eq!(untrusted.error_code(), "agent_program_not_trusted");
    assert!(host.calls.lock().unwrap().is_empty());

    let (world, host) = world_with_host(RecordingHost {
        program: Some(PathBuf::from("/opt/svalnir/bin/svalnir-agent")),
        fail_load: true,
        ..RecordingHost::default()
    });
    let refused = json(&world.environment, &["agent", "install", "--yes"]);
    assert_eq!(refused.status, ExitStatus::Unavailable);
    assert_eq!(refused.error_code(), "service_change_failed");
    // The error says what stays on the host.
    assert!(
        refused.envelope()["error"]["message"]
            .as_str()
            .unwrap()
            .contains("the definition file is written"),
        "{}",
        refused.stdout
    );
    assert_eq!(
        *host.calls.lock().unwrap(),
        [
            "log_directory",
            "write",
            "unload dev.po4yka.svalnir.agent",
            "load"
        ]
    );
}

/// The service manager removes a service some time after the unload
/// request returns, and it refuses a load in that time. A reinstall waits
/// until the service is absent, and then loads the new definition.
#[test]
fn a_reinstall_waits_until_the_service_manager_removed_the_service() {
    let (world, host) = world_with_host(RecordingHost {
        program: Some(PathBuf::from("/opt/svalnir/bin/svalnir-agent")),
        late_removal: Some(3),
        ..RecordingHost::default()
    });
    let installed = json(&world.environment, &["agent", "install", "--yes"]);
    assert_eq!(
        installed.status,
        ExitStatus::Success,
        "{}",
        installed.stdout
    );
    assert_eq!(
        *host.calls.lock().unwrap(),
        [
            "log_directory",
            "write",
            "unload dev.po4yka.svalnir.agent",
            "pause",
            "pause",
            "pause",
            "load"
        ]
    );
}

/// A service that the service manager keeps is not loaded again: the
/// wait has a bound, and the error has its own code.
#[test]
fn a_reinstall_reports_a_service_that_the_service_manager_keeps() {
    let (world, host) = world_with_host(RecordingHost {
        program: Some(PathBuf::from("/opt/svalnir/bin/svalnir-agent")),
        late_removal: None,
        ..RecordingHost::default()
    });
    let refused = json(&world.environment, &["agent", "install", "--yes"]);
    assert_eq!(
        refused.status,
        ExitStatus::Unavailable,
        "{}",
        refused.stdout
    );
    assert_eq!(refused.error_code(), "service_unload_timeout");
    let calls = host.calls.lock().unwrap();
    assert!(!calls.iter().any(|call| call == "load"), "{calls:?}");
    assert_eq!(calls.iter().filter(|call| *call == "pause").count(), 49);
}

/// The body of a child process. Without the variable, which only the
/// tests of this file set, it does nothing.
#[test]
#[ignore = "the entry of a child process that the tests of this file start"]
fn child_entry() {
    if std::env::var_os(CHILD_VARIABLE).is_none() {
        return;
    }
    let parent: u32 = std::os::unix::process::parent_id();
    let end: Instant = Instant::now() + CHILD_LIFE;
    while Instant::now() < end && std::os::unix::process::parent_id() == parent {
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// A child process that is killed and collected when the value is
/// dropped.
pub(super) struct ChildGuard(Child);

impl ChildGuard {
    pub(super) fn pid(&self) -> Pid {
        Pid::new(i32::try_from(self.0.id()).unwrap()).unwrap()
    }

    /// The target ID of the child: its process generation.
    pub(super) fn target(&self) -> String {
        let info = DarwinProcessSource::new().process_info(self.pid()).unwrap();
        generation_id(self.pid(), info.start_time)
            .unwrap()
            .to_string()
    }

    pub(super) fn has_exited(&mut self) -> bool {
        self.0.try_wait().unwrap().is_some()
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        // `Child::kill` addresses only the child of this value.
        drop(self.0.kill());
        drop(self.0.wait());
    }
}

/// Starts a child of this test. With `ignores_term`, the shell sets the
/// disposition of `SIGTERM` and replaces itself with the test binary.
pub(super) fn spawn_child(ignores_term: bool) -> ChildGuard {
    let program = std::env::current_exe().unwrap();
    let arguments = ["--ignored", "--exact", CHILD_TEST];
    let configure = |command: &mut Command| {
        command
            .env(CHILD_VARIABLE, "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
    };
    let guard: ChildGuard = if ignores_term {
        let mut command = Command::new("/bin/sh");
        configure(&mut command);
        ChildGuard(
            command
                .args(["-c", "trap '' TERM; exec \"$0\" \"$@\""])
                .arg(&program)
                .args(arguments)
                .spawn()
                .unwrap(),
        )
    } else {
        let mut command = Command::new(&program);
        configure(&mut command);
        ChildGuard(command.args(arguments).spawn().unwrap())
    };
    // The child is the test binary, not the shell, before it is a target.
    let source = DarwinProcessSource::new();
    let limit: Instant = Instant::now() + Duration::from_secs(10);
    loop {
        let ready: bool = source
            .executable_path(guard.pid())
            .is_ok_and(|path| !path.as_bytes().starts_with(b"/bin/"));
        if ready {
            return guard;
        }
        assert!(Instant::now() < limit, "the child did not start");
        std::thread::sleep(Duration::from_millis(10));
    }
}

pub(super) fn world_for_stop() -> World {
    let world = World::new();
    world.activate("schema_version = 1\n", "none");
    world
}

#[test]
fn a_graceful_stop_reports_the_observed_exit_of_the_child() {
    let world = world_for_stop();
    let mut child: ChildGuard = spawn_child(false);
    let target: String = child.target();
    let stop = json(
        &world.environment,
        &[
            "processes",
            "stop",
            "--target",
            &target,
            "--grace",
            "10s",
            "--yes",
        ],
    );
    assert_eq!(
        stop.status,
        ExitStatus::Success,
        "{} {}",
        stop.stdout,
        stop.stderr
    );
    let result = stop.result();
    assert_eq!(result["wait"], "finished");
    let operation = &result["operation"];
    assert_eq!(operation["state"], "Completed");
    assert_eq!(operation["effects"]["exit_verified"], 1);
    // The record names the process generation that was observed gone.
    assert_eq!(operation["target_results"][0]["member"], target);
    assert_eq!(operation["target_results"][0]["effect"], "ExitVerified");
    assert!(child.has_exited());
    // The inventory finds no application and no job for a child of the
    // test, as for a process that a shell started. The plan binds it as
    // a target of one process, with no synthetic membership.
    {
        use svalnir_core::action::{Journal as _, TargetBinding};
        let journal = crate::commands::session::open_journal(&world.environment)
            .ok()
            .unwrap();
        let plan_id = svalnir_core::id::PlanId::new(result["plan_id"].as_str().unwrap()).unwrap();
        let plan = journal.plan(&plan_id).unwrap().unwrap();
        let [bound] = plan.targets.as_slice() else {
            panic!("a stop plan has one target");
        };
        let TargetBinding::Process(binding) = &bound.binding else {
            panic!("the child is not a target of one process");
        };
        assert_eq!(binding.process.generation_id.as_str(), target);
    }

    // A repeated request finds the plan and the operation of the first
    // one: it makes no second plan and sends no second signal.
    let again = json(
        &world.environment,
        &[
            "processes",
            "stop",
            "--target",
            &target,
            "--grace",
            "10s",
            "--yes",
        ],
    );
    assert_eq!(again.status, ExitStatus::Success, "{}", again.stdout);
    assert_eq!(again.result()["existing_operation"], true);
    assert_eq!(again.result()["plan_id"], result["plan_id"]);
    assert_eq!(
        again.result()["operation"]["operation_id"],
        operation["operation_id"]
    );
    let other = json(
        &world.environment,
        &["processes", "stop", "--target", &target, "--force", "--yes"],
    );
    // The first operation is settled, so this is a new request. The
    // process is gone: the request makes no plan.
    assert_eq!(other.status, ExitStatus::Conflict, "{}", other.stdout);
    assert_eq!(other.error_code(), "target_not_found");
    let history = json(&world.environment, &["history"]);
    assert_eq!(history.result()["records"].as_array().unwrap().len(), 1);
    assert_eq!(
        history.result()["records"][0]["effects"]["exit_verified"],
        1
    );
}

#[test]
fn a_child_that_ignores_the_request_is_forced_after_the_grace_period() {
    let world = world_for_stop();
    let mut child: ChildGuard = spawn_child(true);
    let target: String = child.target();
    let stop = run(
        &world.environment,
        &[
            "processes",
            "stop",
            "--target",
            &target,
            "--grace",
            "1s",
            "--force-after-timeout",
            "--yes",
        ],
    );
    assert_eq!(
        stop.status,
        ExitStatus::Success,
        "{} {}",
        stop.stdout,
        stop.stderr
    );
    assert!(stop.stdout.contains("): Completed"), "{}", stop.stdout);
    assert!(stop.stdout.contains("exit observed"), "{}", stop.stdout);
    assert!(child.has_exited());
}

#[test]
fn a_graceful_stop_of_a_child_that_stays_is_incomplete() {
    let world = world_for_stop();
    let mut child: ChildGuard = spawn_child(true);
    let target: String = child.target();
    // The request has no force step, so the child stays.
    let stop = json(
        &world.environment,
        &[
            "processes",
            "stop",
            "--target",
            &target,
            "--grace",
            "1s",
            "--yes",
        ],
    );
    assert_eq!(
        stop.status,
        ExitStatus::Partial,
        "{} {}",
        stop.stdout,
        stop.stderr
    );
    let operation = &stop.result()["operation"];
    assert_eq!(operation["state"], "Incomplete");
    assert_eq!(operation["effects"]["still_running"], 1);
    assert_eq!(operation["effects"]["exit_verified"], 0);
    assert!(!child.has_exited());
}

#[test]
fn a_cancel_stops_the_force_step_of_a_stop() {
    let world = world_for_stop();
    let mut child: ChildGuard = spawn_child(true);
    let target: String = child.target();
    let environment: Environment = world.environment.clone();
    let stopper = std::thread::spawn({
        let target = target.clone();
        move || {
            json(
                &environment,
                &[
                    "processes",
                    "stop",
                    "--target",
                    &target,
                    "--grace",
                    "3s",
                    "--force-after-timeout",
                    "--yes",
                ],
            )
        }
    });
    // The cancel is sent after the graceful request was submitted, so that
    // it stops the force step and not the first step.
    let limit: Instant = Instant::now() + Duration::from_secs(10);
    let operation: String = loop {
        let history = json(&world.environment, &["history"]);
        let submitted: Option<String> = history.result()["records"][0]["operation_id"]
            .as_str()
            .map(str::to_owned)
            .filter(|operation| {
                let show = json(
                    &world.environment,
                    &["operations", "show", "--operation", operation],
                );
                show.result()["operation"]["dispatch"] == "submitted"
            });
        if let Some(operation) = submitted {
            break operation;
        }
        assert!(Instant::now() < limit, "the request was not submitted");
        std::thread::sleep(Duration::from_millis(50));
    };
    let cancel = json(
        &world.environment,
        &["operations", "cancel", "--operation", &operation],
    );
    assert_eq!(cancel.status, ExitStatus::Success, "{}", cancel.stdout);
    let result = cancel.result();
    assert_eq!(result["fence_written"], true);
    assert!(
        result["acknowledgement"] == "durable_stop_fence" || result["acknowledgement"] == "settled",
        "{result}"
    );
    assert_eq!(result["coordinator"], "running");

    let stop = stopper.join().unwrap();
    // The graceful request was submitted and the force step was not: the
    // child stays, and the result is not NoAction.
    let outcome = stop.result();
    assert_eq!(
        outcome["operation"]["state"], "Incomplete",
        "{}",
        stop.stdout
    );
    assert_eq!(stop.status, ExitStatus::Partial);
    assert!(!child.has_exited());
    let show = json(
        &world.environment,
        &["operations", "show", "--operation", &operation],
    );
    assert_eq!(
        show.result()["operation"]["stop"]["durable_stop_fence"],
        true
    );
}

/// A stop signal of a transient coordinator stops it as the agent stops:
/// the operation gets the stop at the next safe point, no force step is
/// dispatched, the result is recorded, the coordinator is released, and
/// the exit status is `128` plus the number of the signal.
#[test]
fn a_stop_signal_stops_a_transient_coordinator_before_the_force_step() {
    let mut world = world_for_stop();
    let (interrupt, _flag, signal) = crate::interrupt::Interrupt::manual_with_stop_signal();
    world.environment.interrupt = interrupt;
    let mut child: ChildGuard = spawn_child(true);
    let target: String = child.target();
    let environment: Environment = world.environment.clone();
    let stopper = std::thread::spawn({
        let target = target.clone();
        move || {
            json(
                &environment,
                &[
                    "processes",
                    "stop",
                    "--target",
                    &target,
                    "--grace",
                    "3s",
                    "--force-after-timeout",
                    "--yes",
                ],
            )
        }
    });
    let limit: Instant = Instant::now() + Duration::from_secs(10);
    let operation: String = loop {
        let history = json(&world.environment, &["history"]);
        let submitted: Option<String> = history.result()["records"][0]["operation_id"]
            .as_str()
            .map(str::to_owned)
            .filter(|operation| {
                let show = json(
                    &world.environment,
                    &["operations", "show", "--operation", operation],
                );
                show.result()["operation"]["dispatch"] == "submitted"
            });
        if let Some(operation) = submitted {
            break operation;
        }
        assert!(Instant::now() < limit, "the request was not submitted");
        std::thread::sleep(Duration::from_millis(50));
    };
    // The graceful request was submitted. The stop signal comes before
    // the end of the grace period.
    signal.store(libc::SIGTERM, std::sync::atomic::Ordering::SeqCst);

    let stop = stopper.join().unwrap();
    assert_eq!(stop.status, ExitStatus::Terminated, "{}", stop.stdout);
    assert_eq!(ExitStatus::Terminated.code(), 143);
    let result = stop.result();
    assert_eq!(result["wait"], "stopped_by_sigterm", "{}", stop.stdout);
    assert_eq!(result["executor"], "transient_coordinator");
    assert_eq!(
        result["operation"]["state"], "Incomplete",
        "{}",
        stop.stdout
    );
    // No force step: the child that ignores `SIGTERM` stays.
    assert!(!child.has_exited());
    let show = json(
        &world.environment,
        &["operations", "show", "--operation", &operation],
    );
    assert_eq!(show.result()["operation"]["state"], "Incomplete");
    assert_eq!(
        show.result()["operation"]["stop"]["durable_stop_fence"],
        true
    );
    // The coordinator released its lock and its registration: the next
    // coordinator has no reconciliation.
    let status = json(&world.environment, &["agent", "status"]);
    assert_eq!(status.result()["lock_holder"], "none", "{}", status.stdout);
}

/// A stop signal that the transient coordinator records before the
/// admission admits no operation: no step, no operation record, and the
/// exit status of the signal.
#[test]
fn a_stop_signal_before_the_admission_admits_no_operation() {
    let mut world = world_for_stop();
    let (interrupt, _flag, signal) = crate::interrupt::Interrupt::manual_with_stop_signal();
    world.environment.interrupt = interrupt;
    let mut child: ChildGuard = spawn_child(false);
    let target: String = child.target();
    // The signal is in the flag when the coordinator holds the lock.
    signal.store(libc::SIGTERM, std::sync::atomic::Ordering::SeqCst);
    let stop = json(
        &world.environment,
        &["processes", "stop", "--target", &target, "--yes"],
    );
    assert_eq!(stop.status, ExitStatus::Terminated, "{}", stop.stdout);
    assert_eq!(stop.error_code(), "stopped_by_signal", "{}", stop.stdout);
    assert!(!child.has_exited());
    let history = json(&world.environment, &["history"]);
    assert_eq!(history.result()["records"], serde_json::json!([]));
    let status = json(&world.environment, &["agent", "status"]);
    assert_eq!(status.result()["lock_holder"], "none", "{}", status.stdout);
}

#[test]
fn a_stop_refuses_a_protected_process_and_a_process_that_is_absent() {
    let world = world_for_stop();
    // The test process is the client: it is in its own control plane.
    let own = Pid::new(i32::try_from(std::process::id()).unwrap()).unwrap();
    let info = DarwinProcessSource::new().process_info(own).unwrap();
    let target: String = generation_id(own, info.start_time).unwrap().to_string();
    let refused = json(
        &world.environment,
        &["processes", "stop", "--target", &target, "--force", "--yes"],
    );
    assert_eq!(
        refused.status,
        ExitStatus::Unavailable,
        "{}",
        refused.stdout
    );
    assert_eq!(refused.error_code(), "target_protected");
    let absent = json(
        &world.environment,
        &["processes", "stop", "--target", "pg-999999-1", "--yes"],
    );
    assert_eq!(absent.status, ExitStatus::Conflict);
    assert_eq!(absent.error_code(), "target_not_found");
    let history = json(&world.environment, &["history"]);
    assert_eq!(history.result()["records"], serde_json::json!([]));
}

#[test]
fn a_manual_request_needs_a_revision_in_effect() {
    let world = World::new();
    let tree: PathBuf = world.tree();
    let scan: String = world.scan(&tree);
    let entry: PathBuf = tree.join("build");
    let plan = json(
        &world.environment,
        &[
            "clean",
            "plan",
            "--scan",
            &scan,
            "--mode",
            "trash",
            "--entry",
            entry.to_str().unwrap(),
        ],
    );
    assert_eq!(plan.status, ExitStatus::Unavailable, "{}", plan.stdout);
    assert_eq!(plan.error_code(), "no_active_policy_revision");
    let child: ChildGuard = spawn_child(false);
    let stop = json(
        &world.environment,
        &["processes", "stop", "--target", &child.target(), "--yes"],
    );
    assert_eq!(stop.error_code(), "no_active_policy_revision");
}

#[test]
fn the_status_has_the_agent_the_policies_and_the_latest_intervention() {
    let (world, _tree, plan) = World::with_plan("trash");
    let before = json(&world.environment, &["status"]);
    let result = before.result();
    assert_eq!(result["agent"]["state"], "not_running");
    assert_eq!(result["policies"]["state"], "none_active");
    assert!(result["latest_intervention"].is_null());
    json(
        &world.environment,
        &["clean", "apply", "--plan", &plan, "--yes"],
    );
    let after = json(&world.environment, &["status"]);
    let latest = &after.result()["latest_intervention"];
    assert_eq!(latest["plan_id"], plan);
    assert_eq!(latest["effects"]["moved_to_trash"], 3);
    let text = run(&world.environment, &["status"]);
    assert!(
        text.stdout.contains("Latest intervention:"),
        "{}",
        text.stdout
    );
    assert!(text.stdout.contains("3 moved to Trash"), "{}", text.stdout);
}

#[test]
fn the_text_forms_escape_a_name_and_keep_machine_output_clean() {
    let world = World::new();
    let config: PathBuf = world.path("config.toml");
    std::fs::write(&config, "schema_version = 1\n").unwrap();
    let activation = run(
        &world.environment,
        &[
            "config",
            "apply",
            "--config",
            config.to_str().unwrap(),
            "--expected-revision",
            "none",
        ],
    );
    assert!(
        activation
            .stdout
            .starts_with("svalnir config apply: durably_applied"),
        "{}",
        activation.stdout
    );
    assert!(
        activation.stdout.contains("no restart is necessary"),
        "{}",
        activation.stdout
    );
    let tree: PathBuf = world.path("tree");
    std::fs::create_dir_all(&tree).unwrap();
    // A name with a terminal escape sequence and a line break.
    let name: PathBuf = tree.join("a\u{1b}[31mb\nOperation fake: Completed");
    std::fs::write(&name, b"x").unwrap();
    let scan: String = world.scan(&tree);
    let entry: &str = name.to_str().unwrap();
    let arguments = [
        "clean", "plan", "--scan", &scan, "--mode", "trash", "--entry", entry,
    ];
    let plan = run(&world.environment, &arguments);
    assert_eq!(plan.status, ExitStatus::Success, "{}", plan.stderr);
    assert!(!plan.stdout.contains('\u{1b}'), "{}", plan.stdout);
    assert!(!plan.stdout.contains("\nOperation fake"), "{}", plan.stdout);
    assert!(plan.stdout.contains("move to Trash"), "{}", plan.stdout);
    assert!(
        plan.stdout.contains("This command changed no file"),
        "{}",
        plan.stdout
    );
    let plan_id: String = plan
        .stdout
        .lines()
        .next()
        .and_then(|line| line.strip_prefix("Plan "))
        .unwrap()
        .to_owned();
    let accepted = run(
        &world.environment,
        &["clean", "apply", "--plan", &plan_id, "--yes", "--no-wait"],
    );
    assert_eq!(accepted.status, ExitStatus::Success, "{}", accepted.stderr);
    assert!(
        accepted.stdout.starts_with("Accepted: operation "),
        "{}",
        accepted.stdout
    );
    assert!(
        accepted.stdout.contains("not the completion"),
        "{}",
        accepted.stdout
    );
    let history = json(&world.environment, &["history"]);
    let operation: String = history.result()["records"][0]["operation_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let show = run(
        &world.environment,
        &["operations", "show", "--operation", &operation],
    );
    assert!(!show.stdout.contains('\u{1b}'), "{}", show.stdout);
    assert!(!show.stdout.contains("\nOperation fake"), "{}", show.stdout);
    assert!(
        show.stdout.contains("Trashed  COMPLETED"),
        "{}",
        show.stdout
    );
    let cancel = run(
        &world.environment,
        &["operations", "cancel", "--operation", &operation],
    );
    assert!(
        cancel.stdout.contains("settled; no step is executing"),
        "{}",
        cancel.stdout
    );
    // A machine response is one line of JSON with no diagnostic text.
    let machine = json(
        &world.environment,
        &["operations", "show", "--operation", &operation],
    );
    assert_eq!(machine.stderr, "");
    assert!(!machine.stdout.contains('\u{1b}'));
    machine.envelope();
}

#[test]
fn a_pause_has_a_text_form_that_states_its_effect() {
    let world = World::new();
    let pause = run(&world.environment, &["agent", "pause"]);
    assert!(
        pause
            .stdout
            .starts_with("svalnir agent pause: durably_applied"),
        "{}",
        pause.stdout
    );
    assert!(
        pause
            .stdout
            .contains("A pause stops new automatic interventions"),
        "{}",
        pause.stdout
    );
}

#[test]
fn a_timeout_is_a_warning_only_for_a_command_with_no_wait() {
    let world = World::new();
    let history = json(&world.environment, &["history", "--timeout", "5s"]);
    assert_eq!(
        history.envelope()["warnings"][0]["code"],
        "timeout_not_applied"
    );
    let wait = json(
        &world.environment,
        &[
            "operations",
            "wait",
            "--operation",
            "operation_1",
            "--timeout",
            "5s",
        ],
    );
    assert_eq!(wait.envelope()["warnings"], serde_json::json!([]));
}

#[test]
fn a_plan_document_that_names_a_different_root_is_not_used() {
    let (world, tree, plan) = World::with_plan("permanent");
    let other: PathBuf = world.path("other");
    std::fs::create_dir_all(other.join("build")).unwrap();
    // A different directory in place of the cleanup root of the plan.
    let document: PathBuf = world
        .path("state")
        .join("plans")
        .join(format!("plan-{plan}.json"));
    // Only the root record of the document changes. The sealed plan in
    // the document binds the path of its root, and it stays as it is.
    let text: String = std::fs::read_to_string(&document).unwrap();
    let mut value: Value = serde_json::from_str(&text).unwrap();
    let path = |directory: &Path| {
        serde_json::to_value(svalnir_core::file::LosslessPath::from_path(directory).unwrap())
            .unwrap()
    };
    assert_eq!(value["roots"][0]["path"], path(&tree));
    value["roots"][0]["path"] = path(&other);
    std::fs::write(&document, serde_json::to_string(&value).unwrap()).unwrap();
    let apply = json(
        &world.environment,
        &["clean", "apply", "--plan", &plan, "--yes"],
    );
    assert_eq!(apply.status, ExitStatus::Conflict, "{}", apply.stdout);
    assert_eq!(apply.error_code(), "plan_document_not_usable");
    assert_eq!(entries(&tree).len(), 3);
    assert_eq!(entries(&other), ["build"]);
    // The view of the plan does not show the text of the document. Its
    // cleanup root is the root that the sealed plan binds.
    let show = json(&world.environment, &["clean", "show", "--plan", &plan]);
    assert_eq!(show.result()["has_plan_document"], false);
    assert_eq!(show.result()["plan_document"], "disagrees_with_plan");
    assert_eq!(
        show.result()["cleanup_roots"],
        serde_json::json!([path(&std::fs::canonicalize(&tree).unwrap())])
    );
    assert!(!show.stdout.contains("/other"), "{}", show.stdout);
}

/// A plan document of a different version is refused with a stable code,
/// and no field of it is read. A document of this version is used.
#[test]
fn a_plan_document_of_a_different_version_is_refused() {
    let (world, tree, plan) = World::with_plan("permanent");
    let show = json(&world.environment, &["clean", "show", "--plan", &plan]);
    assert_eq!(show.status, ExitStatus::Success, "{}", show.stdout);
    assert_eq!(show.result()["plan_document"], "used");
    let document: PathBuf = world
        .path("state")
        .join("plans")
        .join(format!("plan-{plan}.json"));
    // Version 1 had no cleanup roots: the field is removed, so only the
    // number refuses the document.
    let text: String = std::fs::read_to_string(&document).unwrap();
    let mut value: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(value["schema_version"], 3);
    value["schema_version"] = serde_json::json!(1);
    value.as_object_mut().unwrap().remove("roots");
    std::fs::write(&document, serde_json::to_string(&value).unwrap()).unwrap();
    for arguments in [
        &["clean", "show", "--plan", &plan][..],
        &["clean", "apply", "--plan", &plan, "--yes"][..],
    ] {
        let refused = json(&world.environment, arguments);
        assert_eq!(refused.status, ExitStatus::Usage, "{}", refused.stdout);
        assert_eq!(refused.error_code(), "plan_version_not_supported");
        assert_eq!(
            refused.envelope()["error"]["next_action"],
            "prepare_new_plan"
        );
        assert!(
            refused.envelope()["error"]["message"]
                .as_str()
                .unwrap()
                .contains("make a new plan"),
            "{}",
            refused.stdout
        );
    }
    assert_eq!(entries(&tree).len(), 3);
}

/// A stored plan of a different schema version in the journal has the
/// same code as a plan document of a different version.
#[test]
fn a_stored_plan_of_a_different_version_has_the_stable_code() {
    let error = crate::commands::session::journal_error(
        &svalnir_agent::journal::OperationJournalError::PlanVersion {
            found: 1,
            supported: svalnir_core::action::PLAN_SCHEMA_VERSION,
        },
    );
    assert_eq!(&*error.code, "plan_version_not_supported");
    assert!(error.message.contains("stored plan"), "{}", error.message);
    assert!(
        error.message.contains("make a new plan"),
        "{}",
        error.message
    );
}

/// A standard output whose reader closed the pipe.
struct ClosedPipe;

impl std::io::Write for ClosedPipe {
    fn write(&mut self, _bytes: &[u8]) -> std::io::Result<usize> {
        Err(std::io::ErrorKind::BrokenPipe.into())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Err(std::io::ErrorKind::BrokenPipe.into())
    }
}

/// The exit status of an invocation whose reader closed the pipe.
fn status_with_a_closed_pipe(environment: &Environment, arguments: &[&str]) -> ExitStatus {
    let mut stderr: Vec<u8> = Vec::new();
    let request_id = svalnir_core::id::RequestId::new(format!(
        "request_test_{}",
        NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    ))
    .unwrap();
    run_in(
        std::iter::once("svalnir").chain(arguments.iter().copied()),
        request_id,
        environment,
        &mut ClosedPipe,
        &mut stderr,
    )
}

/// A reader that closes the pipe does not turn the result of an operation
/// that did not complete into exit status 0.
#[test]
fn a_closed_pipe_keeps_the_exit_status_of_the_operation() {
    let (world, tree, plan) = World::with_plan("permanent");
    // One target is a different object than the plan binds, so the
    // executor refuses it and the operation is not complete.
    std::fs::remove_dir_all(tree.join("cache")).unwrap();
    std::fs::create_dir_all(tree.join("cache")).unwrap();
    let status: ExitStatus = status_with_a_closed_pipe(
        &world.environment,
        &[
            "clean", "apply", "--plan", &plan, "--yes", "--format", "json",
        ],
    );
    // The operation was executed to its end, and the journal has it.
    let shown = json(&world.environment, &["clean", "apply", "--plan", &plan]);
    assert_eq!(shown.result()["existing_operation"], true);
    assert_ne!(shown.status, ExitStatus::Success, "{}", shown.stdout);
    assert_eq!(status, shown.status);
    assert_eq!(
        status_with_a_closed_pipe(&world.environment, &["clean", "apply", "--plan", &plan]),
        shown.status
    );
    let operation: String = shown.result()["operation"]["operation_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        status_with_a_closed_pipe(
            &world.environment,
            &["operations", "wait", "--operation", &operation]
        ),
        shown.status
    );
    // A query keeps its success status.
    assert_eq!(
        status_with_a_closed_pipe(
            &world.environment,
            &["operations", "show", "--operation", &operation]
        ),
        ExitStatus::Success
    );
}

fn document_path(world: &World, plan: &str) -> PathBuf {
    world
        .path("state")
        .join("plans")
        .join(format!("plan-{plan}.json"))
}

/// A client that did not execute an operation has no plan document with
/// its measurements. It reads the resource observations of the operation
/// from the journal.
#[test]
fn a_client_with_no_plan_document_reads_the_observations_from_the_journal() {
    let (world, _tree, plan) = World::with_plan("permanent");
    let apply = json(
        &world.environment,
        &["clean", "apply", "--plan", &plan, "--yes"],
    );
    assert_eq!(apply.status, ExitStatus::Success, "{}", apply.stdout);
    let executed = apply.result()["operation"].clone();
    let operation_id: String = executed["operation_id"].as_str().unwrap().to_owned();
    assert!(
        !executed["resource_effects"].as_array().unwrap().is_empty(),
        "{}",
        apply.stdout
    );
    // The state of a different client: the plan document is absent.
    std::fs::remove_file(document_path(&world, &plan)).unwrap();

    let show = json(
        &world.environment,
        &["operations", "show", "--operation", &operation_id],
    );
    assert_eq!(show.status, ExitStatus::Success, "{}", show.stdout);
    let shown = &show.result()["operation"];
    assert_eq!(shown["resource_effects"], executed["resource_effects"]);
    // The journal has the observations and not the work totals.
    assert_eq!(shown["work"], Value::Null);
    let notes: String = shown["notes"].to_string();
    assert!(notes.contains("observed capacity change"), "{notes}");
    assert!(!notes.contains("no resource observation"), "{notes}");

    let history = json(&world.environment, &["history"]);
    assert_eq!(history.status, ExitStatus::Success, "{}", history.stdout);
    let record = &history.result()["records"][0];
    assert_eq!(record["operation_id"], operation_id.as_str());
    assert_eq!(record["resource_effects"], executed["resource_effects"]);
    let text = run(&world.environment, &["history"]);
    assert!(
        !text
            .stdout
            .contains("Observed capacity change: not in this view"),
        "{}",
        text.stdout
    );
}

/// A client that has no plan document, as a client that did not prepare
/// the plan, applies the plan under the roots that the sealed plan binds.
/// The plan document gives the executor no root.
#[test]
fn an_apply_with_no_plan_document_acts_under_the_roots_of_the_sealed_plan() {
    let (world, tree, plan) = World::with_plan("permanent");
    std::fs::remove_file(document_path(&world, &plan)).unwrap();
    let apply = json(
        &world.environment,
        &["clean", "apply", "--plan", &plan, "--yes"],
    );
    assert_eq!(apply.status, ExitStatus::Success, "{}", apply.stdout);
    let operation = &apply.result()["operation"];
    assert_eq!(operation["state"], "Completed", "{}", apply.stdout);
    assert_eq!(operation["effects"]["permanently_removed"], 3);
    // The volume of the capacity observations is that of the root of the
    // plan, so the operation has its observations with no document.
    assert!(
        !operation["resource_effects"].as_array().unwrap().is_empty(),
        "{}",
        apply.stdout
    );
    assert_eq!(entries(&tree), Vec::<String>::new());
    // Only the scanned tree changed.
    assert!(world.path("config.toml").exists());

    // The view of a client with no document has each path and the root.
    let (world, tree, plan) = World::with_plan("permanent");
    std::fs::remove_file(document_path(&world, &plan)).unwrap();
    let show = json(&world.environment, &["clean", "show", "--plan", &plan]);
    assert_eq!(show.status, ExitStatus::Success, "{}", show.stdout);
    let result = show.result();
    assert_eq!(result["plan_document"], "absent");
    assert_eq!(result["cleanup_roots"].as_array().unwrap().len(), 1);
    let root: String = std::fs::canonicalize(&tree)
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    assert_eq!(result["cleanup_roots"][0]["value"], root.as_str());
    let text = run(&world.environment, &["clean", "show", "--plan", &plan]);
    assert!(
        text.stdout.contains(&format!("{root}/build")),
        "{}",
        text.stdout
    );
}

/// A plan document with a second cleanup root, which no target of the
/// plan binds, gives the executor no root.
#[test]
fn a_plan_document_with_a_root_that_no_target_binds_is_not_used() {
    let (world, tree, plan) = World::with_plan("permanent");
    // A second plan of the same client gives a root record whose identity
    // agrees with its own values.
    let other: PathBuf = world.path("other");
    std::fs::create_dir_all(other.join("build")).unwrap();
    std::fs::write(other.join("build/a.bin"), vec![1_u8; 9_000]).unwrap();
    let other_plan: String = world.plan(&world.scan(&other), "permanent");
    let read = |plan: &str| -> Value {
        serde_json::from_str(&std::fs::read_to_string(document_path(&world, plan)).unwrap())
            .unwrap()
    };
    let extra: Value = read(&other_plan)["roots"][0].clone();
    let mut document: Value = read(&plan);
    document["roots"].as_array_mut().unwrap().push(extra);
    std::fs::write(
        document_path(&world, &plan),
        serde_json::to_string(&document).unwrap(),
    )
    .unwrap();

    let show = json(&world.environment, &["clean", "show", "--plan", &plan]);
    assert_eq!(show.result()["plan_document"], "disagrees_with_plan");
    let apply = json(
        &world.environment,
        &["clean", "apply", "--plan", &plan, "--yes"],
    );
    assert_eq!(apply.status, ExitStatus::Conflict, "{}", apply.stdout);
    assert_eq!(apply.error_code(), "plan_document_not_usable");
    assert_eq!(entries(&tree).len(), 3);
    assert_eq!(entries(&other), ["build"]);
}

/// The plan view and the approval question name the cleanup root, and the
/// question has each target, also when the list is long.
#[test]
fn the_question_has_the_cleanup_root_and_each_target() {
    let mut world = World::new();
    world.activate("schema_version = 1\n", "none");
    let tree: PathBuf = world.path("many");
    std::fs::create_dir_all(&tree).unwrap();
    for index in 0..45_usize {
        std::fs::write(
            tree.join(format!("file-{index:02}.bin")),
            vec![7_u8; 1_000 + index],
        )
        .unwrap();
    }
    let plan: String = world.plan(&world.scan(&tree), "permanent");
    let show = json(&world.environment, &["clean", "show", "--plan", &plan]);
    let targets: usize = show.result()["explanation"]["targets"]
        .as_array()
        .unwrap()
        .len();
    assert!(
        targets > crate::commands::plan_view::TEXT_LIST_LIMIT,
        "{targets}"
    );
    assert_eq!(
        show.result()["cleanup_roots"][0]["value"],
        std::fs::canonicalize(&tree).unwrap().to_str().unwrap()
    );
    let text = run(&world.environment, &["clean", "show", "--plan", &plan]);
    assert!(text.stdout.contains("Cleanup root:"), "{}", text.stdout);
    assert!(
        text.stdout.contains("more; `--format json`"),
        "{}",
        text.stdout
    );

    world.environment.seams.test.answers =
        Some(Arc::new(Mutex::new(VecDeque::from(["n".to_owned()]))));
    let declined = json(&world.environment, &["clean", "apply", "--plan", &plan]);
    assert_eq!(declined.error_code(), "approval_declined");
    assert!(
        declined.stderr.contains("Cleanup root:"),
        "{}",
        declined.stderr
    );
    assert!(
        !declined.stderr.contains("more; `--format json`"),
        "{}",
        declined.stderr
    );
    assert_eq!(
        declined.stderr.matches("file-").count(),
        targets,
        "{}",
        declined.stderr
    );
    assert_eq!(entries(&tree).len(), 45);
}

/// The path of a target in the result is the root and the relative entry
/// that the stored plan binds, not the path text of the plan document.
#[test]
fn the_result_has_the_bound_path_and_not_the_text_of_the_document() {
    let (world, tree, plan) = World::with_plan("permanent");
    let path: PathBuf = document_path(&world, &plan);
    let text: String = std::fs::read_to_string(&path).unwrap();
    let changed: String = text.replace("/tree/cache\"", "/tree/elsewhere\"");
    assert_ne!(changed, text);
    std::fs::write(&path, changed).unwrap();
    let apply = json(
        &world.environment,
        &["clean", "apply", "--plan", &plan, "--yes"],
    );
    assert_eq!(apply.status, ExitStatus::Success, "{}", apply.stdout);
    assert!(!apply.stdout.contains("elsewhere"), "{}", apply.stdout);
    assert!(apply.stdout.contains("/tree/cache\""), "{}", apply.stdout);
    assert!(!tree.join("cache").exists());
    for query in [
        vec!["history"],
        vec![
            "operations",
            "show",
            "--operation",
            apply.result()["operation"]["operation_id"]
                .as_str()
                .unwrap(),
        ],
    ] {
        let outcome = json(&world.environment, &query);
        assert!(!outcome.stdout.contains("elsewhere"), "{}", outcome.stdout);
    }
}

/// A plan document that cannot be decoded does not hide the plan and the
/// operation that the journal has.
#[test]
fn a_plan_document_that_cannot_be_read_keeps_the_view_and_the_existing_operation() {
    let (world, tree, plan) = World::with_plan("permanent");
    let first = json(
        &world.environment,
        &["clean", "apply", "--plan", &plan, "--yes"],
    );
    assert_eq!(first.status, ExitStatus::Success, "{}", first.stdout);
    std::fs::write(document_path(&world, &plan), b"{ not a document").unwrap();

    let show = json(&world.environment, &["clean", "show", "--plan", &plan]);
    assert_eq!(show.status, ExitStatus::Success, "{}", show.stdout);
    assert_eq!(show.result()["plan_document"], "not_readable");
    assert_eq!(
        show.result()["operation_id"],
        first.result()["operation"]["operation_id"]
    );
    let again = json(
        &world.environment,
        &["clean", "apply", "--plan", &plan, "--yes"],
    );
    assert_eq!(again.status, ExitStatus::Success, "{}", again.stdout);
    assert_eq!(again.result()["existing_operation"], true);

    // A plan that was not applied gets no root from such a document.
    let other: String = world.plan(&world.scan(&world.tree()), "permanent");
    std::fs::write(document_path(&world, &other), b"{ not a document").unwrap();
    let refused = json(
        &world.environment,
        &["clean", "apply", "--plan", &other, "--yes"],
    );
    assert_eq!(refused.status, ExitStatus::Conflict, "{}", refused.stdout);
    assert_eq!(refused.error_code(), "plan_document_not_usable");
    assert_eq!(entries(&tree).len(), 3);
}

#[test]
fn a_force_quit_after_a_settled_graceful_request_is_a_new_plan() {
    let world = world_for_stop();
    let mut child: ChildGuard = spawn_child(true);
    let target: String = child.target();
    let graceful = json(
        &world.environment,
        &[
            "processes",
            "stop",
            "--target",
            &target,
            "--grace",
            "1s",
            "--yes",
        ],
    );
    assert_eq!(graceful.result()["operation"]["state"], "Incomplete");
    assert!(!child.has_exited());
    // The same request again reports the first operation.
    let again = json(
        &world.environment,
        &[
            "processes",
            "stop",
            "--target",
            &target,
            "--grace",
            "1s",
            "--yes",
        ],
    );
    assert_eq!(again.result()["existing_operation"], true);
    assert_eq!(again.status, ExitStatus::Partial);
    assert!(!child.has_exited());
    // A different grace period is a different request, as a force is.
    let forced = json(
        &world.environment,
        &["processes", "stop", "--target", &target, "--force", "--yes"],
    );
    assert_eq!(forced.status, ExitStatus::Success, "{}", forced.stdout);
    assert_eq!(forced.result()["existing_operation"], false);
    assert_ne!(forced.result()["plan_id"], graceful.result()["plan_id"]);
    assert_eq!(forced.result()["operation"]["state"], "Completed");
    assert!(child.has_exited());
    let history = json(&world.environment, &["history"]);
    assert_eq!(history.result()["records"].as_array().unwrap().len(), 2);
}

#[test]
fn an_acknowledgment_releases_the_leases_of_an_unknown_operation_and_keeps_its_result() {
    let (mut world, tree, plan) = World::with_plan("trash");
    // The Trash gives no result: the outcome of the move is not known.
    world.environment.seams.test.trash_gives_no_result = true;
    let apply = json(
        &world.environment,
        &["clean", "apply", "--plan", &plan, "--yes"],
    );
    let operation: String = apply.result()["operation"]["operation_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        apply.result()["operation"]["state"],
        "UnknownOutcome",
        "{}",
        apply.stdout
    );
    world.environment.seams.test.trash_gives_no_result = false;

    // A new plan for the same tree is refused while the unknown operation
    // holds its leases.
    let scan: String = world.scan(&tree);
    let second: String = world.plan(&scan, "trash");
    let refused = json(
        &world.environment,
        &["clean", "apply", "--plan", &second, "--yes"],
    );
    assert_eq!(
        refused.error_code(),
        "lease_unavailable",
        "{}",
        refused.stdout
    );

    // The acknowledgment, in this process as a transient coordinator.
    let first = json(
        &world.environment,
        &["operations", "acknowledge", "--operation", &operation],
    );
    assert_eq!(first.status, ExitStatus::Success, "{}", first.stdout);
    let result = first.result();
    assert_eq!(result["repeated"], false);
    assert_eq!(result["executor"], "transient_coordinator");
    assert_eq!(result["operation"]["state"], "UnknownOutcome");
    assert!(!result["acknowledged_at"].is_null());
    // A repeated acknowledgment is the first one.
    let again = json(
        &world.environment,
        &["operations", "acknowledge", "--operation", &operation],
    );
    assert_eq!(again.result()["repeated"], true);
    assert_eq!(again.result()["acknowledged_at"], result["acknowledged_at"]);
    // The history keeps the unknown result, with the acknowledgment.
    let show = json(
        &world.environment,
        &["operations", "show", "--operation", &operation],
    );
    assert_eq!(show.result()["operation"]["state"], "UnknownOutcome");
    assert_eq!(
        show.result()["operation"]["acknowledged_at"],
        result["acknowledged_at"]
    );
    let history = json(&world.environment, &["history"]);
    let record = history.result()["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|record| record["operation_id"] == operation.as_str())
        .unwrap()
        .clone();
    assert_eq!(record["state"], "UnknownOutcome");
    assert_eq!(record["acknowledged_at"], result["acknowledged_at"]);
    let text = run(
        &world.environment,
        &["operations", "show", "--operation", &operation],
    );
    assert!(text.stdout.contains("Acknowledged: "), "{}", text.stdout);

    // The leases are released: the new plan is admitted.
    let admitted = json(
        &world.environment,
        &["clean", "apply", "--plan", &second, "--yes"],
    );
    assert_eq!(admitted.status, ExitStatus::Success, "{}", admitted.stdout);
    let settled: String = admitted.result()["operation"]["operation_id"]
        .as_str()
        .unwrap()
        .to_owned();

    // An operation that is not `UnknownOutcome` and an operation that
    // the journal does not have are refused with their codes.
    let not_unknown = json(
        &world.environment,
        &["operations", "acknowledge", "--operation", &settled],
    );
    assert_eq!(not_unknown.status, ExitStatus::Usage);
    assert_eq!(not_unknown.error_code(), "operation_not_unknown_outcome");
    let absent = json(
        &world.environment,
        &["operations", "acknowledge", "--operation", "operation_none"],
    );
    assert_eq!(absent.error_code(), "operation_not_found");
}

#[test]
fn a_held_coordinator_lock_sends_the_acknowledgment_to_the_queue() {
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
    let journal: PathBuf = world.path("state").join("operations.sqlite");
    // A holder of the lock that serves no request, in place of an agent.
    let lock =
        CoordinatorLock::try_acquire(&journal, svalnir_agent::journal::CoordinatorRole::Agent)
            .unwrap();
    let pending = json(
        &world.environment,
        &[
            "operations",
            "acknowledge",
            "--operation",
            &operation,
            "--timeout",
            "1s",
        ],
    );
    assert_eq!(
        pending.error_code(),
        "acknowledgment_pending",
        "{}",
        pending.stdout
    );
    assert_eq!(pending.envelope()["warnings"], serde_json::json!([]));
    drop(lock);
    // The request stays in the queue; with no holder, the client records
    // the acknowledgment itself.
    let recorded = json(
        &world.environment,
        &["operations", "acknowledge", "--operation", &operation],
    );
    assert_eq!(recorded.result()["executor"], "transient_coordinator");
    assert_eq!(recorded.result()["operation"]["state"], "UnknownOutcome");
}

/// The arguments of a rearm of the memory incident `incident_1`.
const REARM: [&str; 7] = [
    "policy",
    "rearm",
    "memory-guard",
    "--incident",
    "incident_1",
    "--generation",
    "1",
];

/// A process of the test in the place of an agent: it holds the
/// coordinator lock with the role of an agent, claims one request of the
/// queue, and completes it with `completion`. It changes only the journal
/// of the test.
pub(super) fn serve_one_rearm(
    journal: PathBuf,
    completion: svalnir_agent::journal::RequestCompletion,
) -> (
    std::sync::mpsc::Receiver<svalnir_agent::journal::QueuedRequest>,
    std::thread::JoinHandle<()>,
) {
    use svalnir_agent::journal::{CoordinatorRole, JournalOptions, OperationJournal};

    let (ready_send, ready) = std::sync::mpsc::channel::<()>();
    let (claimed_send, claimed) = std::sync::mpsc::channel();
    let handle = std::thread::spawn(move || {
        let lock = CoordinatorLock::try_acquire(&journal, CoordinatorRole::Agent).unwrap();
        let mut database = OperationJournal::open(&journal, &JournalOptions::default()).unwrap();
        let epoch = svalnir_core::id::ExecutorEpochId::new("epoch_test_agent").unwrap();
        database
            .begin_coordination(
                &lock,
                &epoch,
                svalnir_core::time::WallTime::from_unix(1_000_000_000, 0).unwrap(),
            )
            .unwrap();
        ready_send.send(()).unwrap();
        let limit = Instant::now() + Duration::from_secs(20);
        loop {
            assert!(Instant::now() < limit, "no request reached the queue");
            if let Some(request) = database.claim_next_request(&epoch).unwrap() {
                database
                    .complete_request(&request.request.request_id, &epoch, &completion)
                    .unwrap();
                claimed_send.send(request.request).unwrap();
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        drop(lock);
    });
    ready.recv().unwrap();
    (claimed, handle)
}

#[test]
fn a_rearm_with_no_agent_is_refused_and_changes_nothing() {
    let world = World::new();
    let refused = json(&world.environment, &REARM);
    assert_eq!(
        refused.error_code(),
        "agent_not_running",
        "{}",
        refused.stdout
    );
    assert_eq!(refused.status.code(), 5);
    // A client that holds the lock is not an agent.
    world.activate("schema_version = 1\n", "none");
    let journal: PathBuf = world.path("state").join("operations.sqlite");
    let lock =
        CoordinatorLock::try_acquire(&journal, svalnir_agent::journal::CoordinatorRole::Client)
            .unwrap();
    let refused = json(&world.environment, &REARM);
    assert_eq!(
        refused.error_code(),
        "agent_not_running",
        "{}",
        refused.stdout
    );
    drop(lock);
}

#[test]
fn a_rearm_that_the_agent_does_not_serve_in_time_stays_in_the_queue() {
    let world = World::new();
    world.activate("schema_version = 1\n", "none");
    let journal: PathBuf = world.path("state").join("operations.sqlite");
    // A holder of the lock that serves no request, in place of an agent.
    let lock =
        CoordinatorLock::try_acquire(&journal, svalnir_agent::journal::CoordinatorRole::Agent)
            .unwrap();
    let mut arguments: Vec<&str> = REARM.to_vec();
    arguments.extend(["--timeout", "1s"]);
    let pending = json(&world.environment, &arguments);
    assert_eq!(pending.error_code(), "rearm_pending", "{}", pending.stdout);
    // `--timeout` applies to the command.
    assert_eq!(pending.envelope()["warnings"], serde_json::json!([]));
    drop(lock);
}

#[test]
fn a_rearm_that_the_agent_accepts_reports_the_new_generation() {
    use svalnir_core::authority::Generation;
    use svalnir_core::id::IncidentId;

    let world = World::new();
    world.activate("schema_version = 1\n", "none");
    let journal: PathBuf = world.path("state").join("operations.sqlite");
    let (claimed, agent) = serve_one_rearm(
        journal,
        svalnir_agent::journal::RequestCompletion::Rearmed {
            incident_id: IncidentId::new("incident_1").unwrap(),
            previous_generation: Generation::new(1),
            new_generation: Generation::new(2),
        },
    );
    let accepted = json(&world.environment, &REARM);
    agent.join().unwrap();
    assert_eq!(accepted.status, ExitStatus::Success, "{}", accepted.stdout);
    let result = accepted.result();
    assert_eq!(result["previous_generation"], "1");
    assert_eq!(result["new_generation"], "2");
    assert_eq!(result["executor"], "queued_for_coordinator");
    // The queued request named the guard, the incident, and the
    // generation of the command.
    let request = claimed.recv().unwrap();
    assert_eq!(
        request.body,
        svalnir_agent::journal::RequestBody::Rearm {
            policy: svalnir_core::policy::PolicyId::MemoryGuard,
            incident_id: IncidentId::new("incident_1").unwrap(),
            generation: Generation::new(1),
        }
    );
}

#[test]
fn a_rearm_that_the_agent_refuses_reports_the_reason_of_the_standing() {
    let world = World::new();
    world.activate("schema_version = 1\n", "none");
    let journal: PathBuf = world.path("state").join("operations.sqlite");
    let (_claimed, agent) = serve_one_rearm(
        journal,
        svalnir_agent::journal::RequestCompletion::Rejected {
            error: svalnir_agent::coordinator::rearm_rejection(
                "guard_disabled",
                svalnir_core::action::ErrorFamily::Authority,
            ),
        },
    );
    let refused = json(&world.environment, &REARM);
    agent.join().unwrap();
    assert_eq!(refused.error_code(), "guard_disabled", "{}", refused.stdout);
    assert_eq!(refused.status.code(), 3);
}

/// A resume writes the durable resume floor into the authority record,
/// and a record of the earlier format, with no floor, gives no authority.
#[test]
fn a_resume_writes_the_floor_and_an_old_authority_record_is_refused() {
    use svalnir_agent::journal::{AgentRecord, JournalOptions, OperationJournal};

    let world = World::new();
    world.activate("schema_version = 1\n", "none");
    let paused = json(&world.environment, &["agent", "pause"]);
    assert_eq!(paused.status, ExitStatus::Success, "{}", paused.stdout);
    let resumed = json(&world.environment, &["agent", "resume"]);
    assert_eq!(resumed.status, ExitStatus::Success, "{}", resumed.stdout);
    let path: PathBuf = world.path("state").join("operations.sqlite");
    let mut journal = OperationJournal::open(&path, &JournalOptions::default()).unwrap();
    let stored = journal
        .agent_record::<Value>(AgentRecord::Authority)
        .unwrap()
        .unwrap();
    let mut record: Value = stored.record;
    assert!(!record["resume_floor"]["at"].is_null(), "{record}");
    assert!(record["resume_floor"]["boot_id"].is_string(), "{record}");

    // The record as an earlier build wrote it.
    record.as_object_mut().unwrap().remove("resume_floor");
    journal
        .put_agent_record(
            AgentRecord::Authority,
            &record,
            Some(stored.revision),
            svalnir_core::time::WallTime::from_unix(1_000_000_000, 0).unwrap(),
        )
        .unwrap();
    drop(journal);
    for arguments in [
        &["agent", "resume"][..],
        &["agent", "pause"][..],
        &["policy", "disable", "memory-guard"][..],
    ] {
        let refused = json(&world.environment, arguments);
        assert_eq!(
            refused.error_code(),
            "authority_record_not_readable",
            "{arguments:?}: {}",
            refused.stdout
        );
        assert_eq!(refused.status.code(), 1);
    }
}

/// The row `agent_catalog_watch` of `doctor` for the status record of
/// [`doctor_shows_the_notification_capability_of_the_agent`].
fn assert_catalog_watch_row(row: &Value, text: &str) {
    assert_eq!(row["reading"], "recorded", "{row}");
    assert_eq!(row["state"], "available", "{row}");
    assert_eq!(row["roots"], 2, "{row}");
    assert_eq!(
        row["counts"]["last_reconcile_reason"], "events_dropped",
        "{row}"
    );
    assert!(text.contains("agent.catalog_watch"), "{}", text);
    assert!(
        text.contains("7 events, 0 dirty regions, 1 full reconciliations (latest: events_dropped)"),
        "{}",
        text
    );
}

/// A running status record of the agent for the rows of `doctor`.
fn doctor_status(
    now: svalnir_core::time::WallTime,
    notifications: Option<svalnir_agent::notify::NotificationStatus>,
    catalog_watch: Option<svalnir_agent::runtime::invalidation::CatalogWatchStatus>,
) -> svalnir_agent::runtime::AgentStatus {
    use svalnir_agent::runtime::{
        AGENT_STATUS_VERSION, AgentStatus, CapabilitySummary, PolicySource, RunState, SelfLimits,
    };
    AgentStatus {
        schema_version: AGENT_STATUS_VERSION,
        executor_epoch: svalnir_core::id::ExecutorEpochId::new("epoch_1").unwrap(),
        process_id: 4242,
        started_at: now,
        written_at: now,
        state: RunState::Running,
        controller: None,
        policy: PolicySource {
            revision: None,
            problem: None,
        },
        capabilities: Some(CapabilitySummary {
            verdict: "ready".to_owned(),
            required_not_available: Vec::new(),
            probed_at: Some(now),
            lines: Vec::new(),
            notifications,
            catalog_watch,
        }),
        limits: SelfLimits {
            footprint_bytes: None,
            budget_bytes: 64 * 1024 * 1024,
            over_budget: false,
            optional_work_reduced: false,
        },
        degraded: Vec::new(),
        unclean_stops: 0,
        restart_backoff: false,
    }
}

/// The notification capability and the catalog invalidation capability of
/// the agent are rows of `doctor`: a denied center or a refused event
/// stream is a reported state, not a failure of the command.
#[test]
fn doctor_shows_the_notification_capability_of_the_agent() {
    use svalnir_agent::journal::{AgentRecord, JournalOptions, OperationJournal};
    use svalnir_agent::notify::{CenterAuthorization, NotificationCounts, NotificationStatus};
    use svalnir_agent::runtime::AgentStatus;
    use svalnir_agent::runtime::invalidation::{
        CatalogWatchState, CatalogWatchStatus, InvalidationCounts, ReconcileReason,
    };
    use svalnir_core::state::CapabilityState;
    use svalnir_core::time::WallTime;

    let world = World::new();
    std::fs::create_dir_all(world.path("state")).unwrap();
    let path: PathBuf = world.path("state").join("operations.sqlite");
    let mut journal = OperationJournal::open(&path, &JournalOptions::default()).unwrap();
    let now: WallTime = WallTime::try_from(std::time::SystemTime::now()).unwrap();
    let status = |notifications: Option<NotificationStatus>,
                  catalog_watch: Option<CatalogWatchStatus>| {
        doctor_status(now, notifications, catalog_watch)
    };
    // A status record with a summary and no notification capability.
    journal
        .put_agent_record(AgentRecord::Status, &status(None, None), None, now)
        .unwrap();
    let outcome = json(&world.environment, &["doctor"]);
    assert_eq!(outcome.status, ExitStatus::Success, "{}", outcome.stdout);
    assert_eq!(
        outcome.result()["agent_notifications"]["reading"],
        "not_recorded",
        "{}",
        outcome.stdout
    );
    assert_eq!(
        outcome.result()["agent_catalog_watch"]["reading"],
        "not_recorded",
        "{}",
        outcome.stdout
    );

    let revision: u64 = journal
        .agent_record::<AgentStatus>(AgentRecord::Status)
        .unwrap()
        .unwrap()
        .revision;
    let denied = NotificationStatus {
        state: CapabilityState::Denied,
        authorization: CenterAuthorization::Denied,
        detail: "The user turned the notifications off.".to_owned(),
        counts: NotificationCounts {
            not_authorized: 3,
            ..NotificationCounts::default()
        },
    };
    let watch = CatalogWatchStatus {
        state: CatalogWatchState::Available,
        detail: "FSEvents marks the approved roots dirty.".to_owned(),
        roots: 2,
        counts: InvalidationCounts {
            events: 7,
            reconciliations: 1,
            last_reconcile_reason: Some(ReconcileReason::EventsDropped),
            ..InvalidationCounts::default()
        },
    };
    journal
        .put_agent_record(
            AgentRecord::Status,
            &status(Some(denied), Some(watch)),
            Some(revision),
            now,
        )
        .unwrap();
    drop(journal);
    let outcome = json(&world.environment, &["doctor"]);
    assert_eq!(outcome.status, ExitStatus::Success, "{}", outcome.stdout);
    let row = &outcome.result()["agent_notifications"];
    assert_eq!(row["reading"], "recorded", "{row}");
    assert_eq!(row["state"], "denied", "{row}");
    assert_eq!(row["authorization"], "denied", "{row}");
    assert_eq!(row["counts"]["not_authorized"], 3, "{row}");
    assert_eq!(row["freshness"]["freshness"], "current", "{row}");
    let text = run(&world.environment, &["doctor"]);
    assert_eq!(text.status, ExitStatus::Success);
    assert!(
        text.stdout.contains("agent.notifications"),
        "{}",
        text.stdout
    );
    assert!(text.stdout.contains("State: denied"), "{}", text.stdout);
    assert!(text.stdout.contains("3 not authorized"), "{}", text.stdout);
    assert_catalog_watch_row(&outcome.result()["agent_catalog_watch"], &text.stdout);
}
