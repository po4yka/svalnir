//! End-to-end tests of the `owner` mode of `clean plan`, of its apply, and
//! of the owner part of `clean inspect`.
//!
//! Each test has its own temporary directory with the state directory, a
//! home directory, and a directory of test scripts. The rules have a
//! lifecycle state that only a test build can give, and each executable is
//! a script of `/bin/sh` in the directory of the test
//! (`ReviewedRules::with_owner_fixture_executables`), so no test runs a
//! producer tool or changes a cache of the host. A script records each run
//! in the home directory and removes only the files `stale-*` of the
//! scope root of the test.

#![cfg(debug_assertions)]

use std::path::{Path, PathBuf};

use serde_json::Value;
use std::sync::Arc;

use svalnir_agent::rules::ProducerProcesses;
use svalnir_agent::rules::fixture::{
    FixtureEnvironment, manual_action_validated, write_owner_script,
};
use svalnir_core::rule::LifecycleState;

use crate::environment::Environment;
use crate::output::ExitStatus;
use crate::run_in;
use crate::seams::TestEnvironment;
use crate::test_support::{TempDirectory, environment};

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

fn json(environment: &Environment, arguments: &[&str]) -> Outcome {
    let mut stdout: Vec<u8> = Vec::new();
    let mut stderr: Vec<u8> = Vec::new();
    let request_id = svalnir_core::id::RequestId::new(format!(
        "request_owner_{}",
        NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    ))
    .unwrap();
    let status = run_in(
        std::iter::once("svalnir")
            .chain(arguments.iter().copied())
            .chain(["--format", "json"]),
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

/// The script of a producer: it records its arguments and removes the
/// files `stale-*` of the directory that its last argument or `$GOCACHE`
/// names.
const PRODUCER: &str = "echo \"$*\" >> \"$HOME/runs\"\nfor last; do :; done\nroot=\"${GOCACHE:-$last}\"\nrm -f \"$root\"/stale-*";

/// One temporary world with a home directory and a directory of scripts.
struct World {
    environment: Environment,
    directory: TempDirectory,
    home: PathBuf,
    evidence: FixtureEnvironment,
}

impl World {
    fn new(lifecycle: Option<LifecycleState>) -> Self {
        let (mut environment, directory) = environment();
        let tools: PathBuf = std::fs::canonicalize(directory.path())
            .unwrap()
            .join("tools");
        std::fs::create_dir(&tools).unwrap();
        for name in ["uv", "go", "mise", "pnpm"] {
            write_owner_script(&tools, name, PRODUCER).unwrap();
        }
        environment.seams.test.rule_lifecycle = lifecycle;
        environment.seams.test.owner_executables = Some(tools);
        // The process evidence of the producer: no producer runs, and no
        // process uses the scope root.
        let evidence = FixtureEnvironment::days_later(0);
        environment.seams.test.discovery_environment =
            Some(TestEnvironment(Arc::new(evidence.clone())));
        let home: PathBuf = std::fs::canonicalize(environment.home.as_ref().unwrap()).unwrap();
        let world = Self {
            environment,
            directory,
            home,
            evidence,
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

    /// A cache below the home directory with two stale files and one file
    /// that the producer keeps.
    fn cache(&self, relative: &str) -> PathBuf {
        let root: PathBuf = self.home.join(relative);
        std::fs::create_dir_all(&root).unwrap();
        for name in ["stale-a", "stale-b", "kept"] {
            std::fs::write(root.join(name), vec![3_u8; 8192]).unwrap();
        }
        root
    }

    fn plan(&self, rule: &str, extra: &[&str]) -> Outcome {
        let mut arguments: Vec<&str> = vec!["clean", "plan", "--mode", "owner", "--rule", rule];
        arguments.extend_from_slice(extra);
        json(&self.environment, &arguments)
    }

    fn planned(&self, rule: &str, extra: &[&str]) -> (String, Value) {
        let outcome = self.plan(rule, extra);
        assert_eq!(outcome.status, ExitStatus::Success, "{}", outcome.stdout);
        let result: Value = outcome.result();
        let plan: String = result["explanation"]["plan"]["plan_id"]
            .as_str()
            .unwrap_or_else(|| panic!("no plan: {}", outcome.stdout))
            .to_owned();
        (plan, result)
    }

    fn apply(&self, plan: &str) -> Outcome {
        json(
            &self.environment,
            &["clean", "apply", "--plan", plan, "--yes"],
        )
    }

    fn runs(&self) -> Vec<String> {
        std::fs::read_to_string(self.home.join("runs")).map_or_else(
            |_| Vec::new(),
            |text| text.lines().map(str::to_owned).collect(),
        )
    }

    fn state_has_plans(&self) -> bool {
        self.directory.path().join("state/plans").exists()
    }
}

fn stale(root: &Path) -> usize {
    std::fs::read_dir(root)
        .unwrap()
        .filter(|entry| {
            entry
                .as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("stale-")
        })
        .count()
}

#[test]
fn a_rule_of_the_build_is_proposed_and_the_owner_mode_is_refused() {
    let world = World::new(None);
    world.cache(".cache/uv");
    let outcome = world.plan("uv.cache", &[]);
    assert_eq!(
        outcome.status,
        ExitStatus::Unavailable,
        "{}",
        outcome.stdout
    );
    assert_eq!(outcome.error_code(), "rule_mode_not_validated");
    assert!(!world.state_has_plans());
    assert_eq!(world.runs(), Vec::<String>::new());
}

#[test]
fn the_owner_mode_refuses_a_rule_with_no_owner_operation() {
    let world = World::manual();
    let unknown = world.plan("all.caches", &[]);
    assert_eq!(unknown.status, ExitStatus::Usage, "{}", unknown.stdout);
    assert_eq!(unknown.error_code(), "unknown_rule");
    let inspection_only = world.plan("cocoapods.cache", &[]);
    assert_eq!(inspection_only.status, ExitStatus::Usage);
    assert_eq!(
        inspection_only.error_code(),
        "owner_operation_not_available"
    );
    // The `owner` mode takes no entry and no scan.
    let entry = world.plan("uv.cache", &["--entry", "/tmp/x"]);
    assert_eq!(
        entry.error_code(),
        "option_not_accepted",
        "{}",
        entry.stdout
    );
    // `--include-clear` is an option of the `owner` mode only.
    let evict = json(
        &world.environment,
        &[
            "clean",
            "plan",
            "--mode",
            "evict",
            "--rule",
            "uv.cache",
            "--include-clear",
        ],
    );
    assert_eq!(evict.error_code(), "unsupported_rule_selection");
    // The `evict` mode does not take the layout of the scope root of an
    // owner operation.
    world.cache(".cache/uv");
    let evict = json(
        &world.environment,
        &["clean", "plan", "--mode", "evict", "--rule", "uv.cache"],
    );
    assert_eq!(evict.error_code(), "rule_mode_not_validated");
    assert_eq!(world.runs(), Vec::<String>::new());
}

#[test]
fn a_prune_plan_binds_the_command_and_the_apply_runs_it_one_time() {
    let world = World::manual();
    let root: PathBuf = world.cache(".cache/uv");
    let (plan, result) = world.planned("uv.cache", &[]);
    // The plan names the scope root, the command, and its kind, and the
    // planning ran nothing.
    assert_eq!(world.runs(), Vec::<String>::new());
    let target: &Value = &result["explanation"]["targets"][0];
    assert_eq!(target["operation"], "prune", "{result}");
    assert_eq!(target["bound"], "within_scope");
    assert_eq!(
        target["arguments"],
        serde_json::json!([
            "cache",
            "prune",
            "--no-config",
            "--cache-dir",
            root.to_str().unwrap()
        ])
    );
    assert_eq!(result["owner"]["whole_cache"], true);
    assert_eq!(
        result["cleanup_roots"][0]["value"].as_str(),
        root.to_str(),
        "{result}"
    );
    // `clean show` has the same scope root.
    let show = json(&world.environment, &["clean", "show", "--plan", &plan]);
    assert_eq!(show.status, ExitStatus::Success, "{}", show.stdout);
    assert_eq!(
        show.result()["cleanup_roots"][0]["value"].as_str(),
        root.to_str()
    );
    // The apply runs the command one time; the producer removes its stale
    // files and keeps the other.
    let applied = world.apply(&plan);
    assert_eq!(applied.status, ExitStatus::Success, "{}", applied.stdout);
    assert_eq!(world.runs().len(), 1, "{}", applied.stdout);
    assert!(world.runs()[0].starts_with("cache prune --no-config --cache-dir "));
    assert_eq!(stale(&root), 0);
    assert!(root.join("kept").exists());
    // A second apply of the same plan reports the operation and runs
    // nothing again.
    let again = world.apply(&plan);
    assert_eq!(world.runs().len(), 1, "{}", again.stdout);
}

#[test]
fn a_clear_plan_needs_include_clear_and_names_the_root_in_the_environment() {
    let world = World::manual();
    let root: PathBuf = world.cache("Library/Caches/go-build");
    let refused = world.plan("go.build-cache", &[]);
    assert_eq!(refused.status, ExitStatus::Usage, "{}", refused.stdout);
    assert_eq!(refused.error_code(), "clear_not_included");
    assert!(!world.state_has_plans());
    let (plan, result) = world.planned("go.build-cache", &["--include-clear"]);
    assert_eq!(result["explanation"]["targets"][0]["operation"], "clear");
    let environment: &Value = &result["owner"]["environment"];
    assert!(
        environment
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["name"] == "GOCACHE" && entry["value"].as_str() == root.to_str()),
        "{result}"
    );
    let applied = world.apply(&plan);
    assert_eq!(applied.status, ExitStatus::Success, "{}", applied.stdout);
    assert_eq!(world.runs(), ["clean -cache"]);
    assert_eq!(stale(&root), 0);
}

#[test]
fn a_running_producer_inhibits_the_command() {
    let world = World::manual();
    let root: PathBuf = world.cache(".cache/uv");
    let (plan, _) = world.planned("uv.cache", &[]);
    world.evidence.set_producer(ProducerProcesses::Running);
    let applied = world.apply(&plan);
    let result: Value = applied.result();
    assert_eq!(
        result["operation"]["target_results"][0]["failure"]["code"], "producer_active",
        "{}",
        applied.stdout
    );
    assert_eq!(world.runs(), Vec::<String>::new());
    assert_eq!(stale(&root), 2);
}

#[test]
fn a_scope_root_that_is_absent_gives_no_plan() {
    let world = World::manual();
    let outcome = world.plan("mise.cache", &[]);
    assert_eq!(
        outcome.error_code(),
        "owner_scope_unavailable",
        "{}",
        outcome.stdout
    );
    assert!(!world.state_has_plans());
}

#[test]
fn the_inspection_shows_the_owner_operation_and_runs_nothing() {
    let world = World::manual();
    let root: PathBuf = world.cache("Library/pnpm/store");
    let outcome = json(
        &world.environment,
        &["clean", "inspect", "--rule", "pnpm.content-store"],
    );
    assert_eq!(outcome.status, ExitStatus::Success, "{}", outcome.stdout);
    let result: Value = outcome.result();
    assert_eq!(result["kind"], "cache");
    let owner: &Value = &result["owner"];
    assert_eq!(owner["kind"], "prune");
    assert_eq!(owner["whole_cache"], true);
    assert_eq!(owner["scope"]["path"].as_str(), root.to_str());
    assert!(
        owner["program"]["executable"]["value"]
            .as_str()
            .is_some_and(|path| path.ends_with("/tools/pnpm")),
        "{owner}"
    );
    assert_eq!(
        owner["arguments"],
        serde_json::json!(["store", "prune", "--store-dir", root.to_str().unwrap()])
    );
    assert_ne!(owner["measured"]["allocated_bytes"], "0", "{owner}");
    assert_eq!(owner["measured"]["complete"], true);
    // A rule with its own declaration is of the kind `owner`.
    let mise = json(
        &world.environment,
        &["clean", "inspect", "--rule", "mise.cache"],
    );
    assert_eq!(mise.status, ExitStatus::Success, "{}", mise.stdout);
    assert_eq!(mise.result()["kind"], "owner");
    assert_eq!(world.runs(), Vec::<String>::new());
}
