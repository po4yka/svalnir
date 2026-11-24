//! End-to-end tests of `clean inspect` and of the `evict` mode of
//! `clean plan` for `project.dependency-directory`, and of its apply.
//!
//! Each test has its own temporary directory with the state directory and
//! a home directory with disposable Git repositories. The rule has a
//! lifecycle state that only a test build can give: each reviewed rule of a
//! build is `proposed`. The process evidence comes from a fixture. A removal
//! is only below the temporary directory.

#![cfg(debug_assertions)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;

use serde_json::Value;
use svalnir_agent::rules::fixture::{FixtureEnvironment, manual_action_validated};
use svalnir_agent::rules::git::GitTool;
use svalnir_core::rule::LifecycleState;

use crate::environment::Environment;
use crate::output::ExitStatus;
use crate::run_in;
use crate::seams::TestEnvironment;
use crate::test_support::{TempDirectory, environment};

const RULE: &str = "project.dependency-directory";

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
        "request_projects_{}",
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

/// One temporary world with a home directory and the search root `Code`.
struct World {
    environment: Environment,
    directory: TempDirectory,
    evidence: FixtureEnvironment,
    home: PathBuf,
    git: GitTool,
}

impl World {
    fn new(lifecycle: Option<LifecycleState>) -> Self {
        Self::with_config(lifecycle, "schema_version = 1\n")
    }

    /// A world whose configuration in effect is `document`.
    fn with_config(lifecycle: Option<LifecycleState>, document: &str) -> Self {
        let (mut environment, directory) = environment();
        // The fixture is 30 days old for the discovery.
        let evidence = FixtureEnvironment::days_later(30);
        environment.seams.test.rule_lifecycle = lifecycle;
        environment.seams.test.discovery_environment =
            Some(TestEnvironment(Arc::new(evidence.clone())));
        let home: PathBuf = std::fs::canonicalize(environment.home.as_ref().unwrap()).unwrap();
        std::fs::create_dir_all(home.join("Code")).unwrap();
        let world = Self {
            environment,
            directory,
            evidence,
            home,
            git: GitTool::locate().expect("the developer tools of the host have Git"),
        };
        world.activate(document);
        world
    }

    fn manual() -> Self {
        Self::new(Some(manual_action_validated()))
    }

    fn activate(&self, document: &str) {
        let config: PathBuf = self.directory.path().join("config.toml");
        std::fs::write(&config, document).unwrap();
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

    fn write(&self, relative: &str, content: &[u8]) {
        let path: PathBuf = self.home.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }

    /// A repository at `relative` with one commit of its files, with no
    /// configuration of the host.
    fn repository(&self, relative: &str) {
        for arguments in [
            &["init", "-q"][..],
            &["add", "-A"][..],
            &["commit", "-q", "--allow-empty", "-m", "start"][..],
        ] {
            let status = Command::new(self.git.executable())
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("HOME", &self.home)
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .current_dir(self.home.join(relative))
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
    }

    /// A Node project at `Code/NAME` with an installed package that Git
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
        self.home.join(project)
    }

    /// A Mix project at `Code/NAME` with a `_build` directory that Git
    /// ignores.
    fn mix_project(&self, name: &str) -> PathBuf {
        let project: String = format!("Code/{name}");
        self.write(
            &format!("{project}/mix.exs"),
            b"defmodule App.MixProject do end\n",
        );
        self.write(&format!("{project}/.gitignore"), b"/_build/\n");
        self.repository(&project);
        self.write(
            &format!("{project}/_build/dev/lib/app/ebin/a.beam"),
            b"beam",
        );
        self.home.join(project)
    }

    fn root(&self) -> String {
        self.home.join("Code").to_str().unwrap().to_owned()
    }

    fn plan(&self, extra: &[&str]) -> Outcome {
        let mut arguments: Vec<&str> = vec!["clean", "plan", "--mode", "evict", "--rule", RULE];
        arguments.extend_from_slice(extra);
        json(&self.environment, &arguments)
    }

    fn planned(&self) -> (String, Value) {
        let root: String = self.root();
        let outcome = self.plan(&["--root", &root, "--no-mise"]);
        assert_eq!(outcome.status, ExitStatus::Success, "{}", outcome.stdout);
        let result: Value = outcome.result();
        let plan_id: String = result["explanation"]["plan"]["plan_id"]
            .as_str()
            .unwrap_or_else(|| panic!("no plan: {}", outcome.stdout))
            .to_owned();
        (plan_id, result)
    }

    fn apply(&self, plan: &str) -> Outcome {
        json(
            &self.environment,
            &["clean", "apply", "--plan", plan, "--yes"],
        )
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

fn text(path: &Path) -> String {
    path.to_str().unwrap().to_owned()
}

#[test]
fn the_rule_of_a_build_is_proposed_and_its_evict_mode_is_refused() {
    let world = World::new(None);
    world.node_project("app");
    let root: String = world.root();
    let outcome = world.plan(&["--root", &root]);
    assert_eq!(
        outcome.status,
        ExitStatus::Unavailable,
        "{}",
        outcome.stdout
    );
    assert_eq!(outcome.error_code(), "rule_mode_not_validated");
    assert!(world.home.join("Code/app/node_modules").exists());
}

#[test]
fn an_evict_plan_has_the_eligible_units_and_its_apply_removes_only_them() {
    let world = World::manual();
    let app: PathBuf = world.node_project("app");
    let mix: PathBuf = world.mix_project("mix");
    // A release of Mix in a second project: its unit is refused.
    let release: PathBuf = world.mix_project("release");
    world.write("Code/release/_build/dev/rel/app/bin/app", b"#!/bin/sh\n");
    let (plan_id, result) = world.planned();
    assert_eq!(
        target_paths(&result),
        [text(&app.join("node_modules")), text(&mix.join("_build"))]
    );
    let discovery = &result["discovery"];
    assert_eq!(discovery["rule"]["id"], RULE);
    assert_eq!(discovery["rule"]["revision"], "r6");
    assert_eq!(discovery["complete"], true, "{discovery}");
    assert_eq!(discovery["project_roots"][0]["kind"], "search");
    assert_eq!(discovery["project_roots"][0]["source"]["kind"], "argument");
    assert_eq!(discovery["mise"]["state"]["kind"], "off");
    let skipped = &discovery["roots"][0]["skipped"];
    assert_eq!(
        skipped[0]["relative_entry"]["value"], "release/_build",
        "{discovery}"
    );
    assert_eq!(skipped[0]["reasons"][0], "protected_data");
    assert_eq!(result["cleanup_roots"][0]["value"], world.root());

    let applied = world.apply(&plan_id);
    assert_eq!(applied.status, ExitStatus::Success, "{}", applied.stdout);
    assert!(!app.join("node_modules").exists());
    assert!(!mix.join("_build").exists());
    // The sources, the refused unit, and its release stay.
    assert!(app.join("package.json").exists());
    assert!(mix.join("mix.exs").exists());
    assert!(release.join("_build/dev/rel/app/bin/app").exists());
    let history = json(&world.environment, &["history"]);
    let record = &history.result()["records"][0];
    assert_eq!(record["effects"]["permanently_removed"], 2, "{record}");
}

#[test]
fn the_step_checks_the_layout_and_the_protected_children_again() {
    let world = World::manual();
    let app: PathBuf = world.node_project("app");
    let mix: PathBuf = world.mix_project("mix");
    let crate_dir: PathBuf = world.home.join("Code/crate");
    world.write("Code/crate/Cargo.toml", b"[package]\n");
    world.write("Code/crate/.gitignore", b"/target/\n");
    world.repository("Code/crate");
    world.write(
        "Code/crate/target/CACHEDIR.TAG",
        b"Signature: 8a477f597d28d172789f06886806bc55",
    );
    world.write("Code/crate/target/debug/app", b"binary");
    let (plan_id, result) = world.planned();
    assert_eq!(target_paths(&result).len(), 3, "{result}");
    // After the plan: the project marker of one unit is gone, a protected
    // child appears in another, and the third keeps its layout.
    std::fs::remove_file(app.join("package.json")).unwrap();
    world.write("Code/mix/_build/dev/rel/app/bin/app", b"#!/bin/sh\n");
    let applied = world.apply(&plan_id);
    // Two of the three targets are skipped.
    assert_eq!(applied.status, ExitStatus::Partial, "{}", applied.stdout);
    let output: &str = &applied.stdout;
    assert!(output.contains("project_marker_missing"), "{output}");
    assert!(output.contains("protected_child"), "{output}");
    assert!(app.join("node_modules/left-pad/index.js").exists());
    assert!(mix.join("_build/dev/rel/app/bin/app").exists());
    assert!(!crate_dir.join("target").exists());
}

#[test]
fn a_unit_of_a_layout_of_the_configuration_is_planned_and_checked_with_that_layout() {
    let world = World::with_config(
        Some(manual_action_validated()),
        "schema_version = 1\n\n[[cleanup.projects.layouts]]\ndirectory = \"builddir\"\nmarkers = [\"meson.build\"]\n",
    );
    world.write("Code/meson/meson.build", b"project('a')\n");
    world.write("Code/meson/.gitignore", b"/builddir/\n");
    world.repository("Code/meson");
    world.write("Code/meson/builddir/build.ninja", b"rule cc\n");
    let (plan_id, result) = world.planned();
    let out: PathBuf = world.home.join("Code/meson/builddir");
    assert_eq!(target_paths(&result), [text(&out)]);
    let applied = world.apply(&plan_id);
    assert_eq!(applied.status, ExitStatus::Success, "{}", applied.stdout);
    assert!(!out.exists());
    assert!(world.home.join("Code/meson/meson.build").exists());
}

#[test]
fn a_symbolic_link_in_a_unit_is_removed_and_its_target_stays() {
    let world = World::manual();
    let app: PathBuf = world.node_project("app");
    world.write(
        "Code/app/node_modules/tool/cli.js",
        b"#!/usr/bin/env node\n",
    );
    std::fs::create_dir_all(app.join("node_modules/.bin")).unwrap();
    std::os::unix::fs::symlink("../tool/cli.js", app.join("node_modules/.bin/tool")).unwrap();
    // A link to a directory outside the home directory.
    let outside: PathBuf = world.directory.path().join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("keep.txt"), b"keep").unwrap();
    std::os::unix::fs::symlink(&outside, app.join("node_modules/linked")).unwrap();
    let (plan_id, result) = world.planned();
    assert_eq!(target_paths(&result), [text(&app.join("node_modules"))]);
    let applied = world.apply(&plan_id);
    assert_eq!(applied.status, ExitStatus::Success, "{}", applied.stdout);
    assert!(!app.join("node_modules").exists());
    assert!(std::fs::symlink_metadata(app.join("node_modules")).is_err());
    // The target of the link outside the unit stays with its content.
    assert_eq!(std::fs::read(outside.join("keep.txt")).unwrap(), b"keep");
}

#[test]
fn a_unit_that_is_gone_at_its_step_is_already_absent_and_not_skipped() {
    let world = World::manual();
    let app: PathBuf = world.node_project("app");
    let (plan_id, _) = world.planned();
    std::fs::remove_dir_all(app.join("node_modules")).unwrap();
    let applied = world.apply(&plan_id);
    assert_eq!(applied.status, ExitStatus::Success, "{}", applied.stdout);
    assert!(
        !applied.stdout.contains("unit_absent"),
        "{}",
        applied.stdout
    );
    assert!(
        applied.stdout.contains("AlreadyAbsent"),
        "{}",
        applied.stdout
    );
}

#[test]
fn a_build_process_after_the_plan_skips_the_step() {
    let world = World::manual();
    let app: PathBuf = world.node_project("app");
    let (plan_id, _) = world.planned();
    world.evidence.set_build_process(Some(app.clone()));
    let applied = world.apply(&plan_id);
    assert_eq!(applied.status, ExitStatus::Success, "{}", applied.stdout);
    assert!(
        applied.stdout.contains("producer_active"),
        "{}",
        applied.stdout
    );
    assert!(app.join("node_modules/left-pad/index.js").exists());
}

#[test]
fn min_size_leaves_out_the_small_candidates() {
    let world = World::manual();
    let app: PathBuf = world.node_project("app");
    let root: String = world.root();
    let outcome = world.plan(&["--root", &root, "--no-mise", "--min-size", "1GiB"]);
    assert_eq!(outcome.status, ExitStatus::Success, "{}", outcome.stdout);
    let result: Value = outcome.result();
    assert!(result["explanation"]["plan"].is_null(), "{result}");
    assert_eq!(
        result["discovery"]["below_minimum_size"][0]["value"],
        text(&app.join("node_modules"))
    );
}

#[test]
fn the_roots_come_from_the_configuration_and_from_mise() {
    let mut world = World::with_config(
        Some(manual_action_validated()),
        "schema_version = 1\n[cleanup.projects]\nsearch_roots = [\"Code\"]\n",
    );
    let app: PathBuf = world.node_project("app");
    // A project that mise records, outside the search root.
    let other: PathBuf = world.home.join("Other/tool");
    world.write("Other/tool/package.json", b"{}");
    world.write("Other/tool/.gitignore", b"node_modules/\nmise.toml\n");
    world.write("Other/tool/mise.toml", b"[tools]\n");
    world.repository("Other/tool");
    world.write("Other/tool/node_modules/a/index.js", b"1");
    let state_home: PathBuf = world.home.join(".local/state-x");
    let tracked: PathBuf = state_home.join("mise/tracked-configs");
    std::fs::create_dir_all(&tracked).unwrap();
    std::os::unix::fs::symlink(other.join("mise.toml"), tracked.join("abc")).unwrap();
    world.environment.xdg_state_home = Some(state_home.into_os_string());
    let outcome = world.plan(&[]);
    assert_eq!(outcome.status, ExitStatus::Success, "{}", outcome.stdout);
    let result: Value = outcome.result();
    assert_eq!(
        target_paths(&result),
        [
            text(&app.join("node_modules")),
            text(&other.join("node_modules"))
        ]
    );
    let roots = &result["discovery"]["project_roots"];
    assert_eq!(roots[0]["source"]["kind"], "configuration");
    assert_eq!(roots[1]["kind"], "project");
    assert_eq!(roots[1]["source"]["kind"], "mise");
    assert_eq!(roots[1]["source"]["config"], text(&other.join("mise.toml")));
    // `--no-mise` leaves the project of mise out.
    let without = world.plan(&["--no-mise"]);
    assert_eq!(
        target_paths(&without.result()),
        [text(&app.join("node_modules"))]
    );
}

#[test]
fn the_project_options_are_checked_before_a_directory_is_read() {
    let world = World::manual();
    let outside: String = world
        .directory
        .path()
        .join("outside")
        .to_str()
        .unwrap()
        .to_owned();
    std::fs::create_dir_all(&outside).unwrap();
    let missing: String = world.home.join("Code/missing").to_str().unwrap().to_owned();
    // A `..` component is refused, also when the text stays below home.
    let parent: String = world.home.join("Code/../Code").to_str().unwrap().to_owned();
    let cases: [(&[&str], ExitStatus, &str); 5] = [
        (
            &["--root", &parent],
            ExitStatus::Usage,
            "invalid_search_root",
        ),
        (
            &["--root", &outside],
            ExitStatus::Usage,
            "invalid_search_root",
        ),
        (
            &["--root", &missing],
            ExitStatus::Usage,
            "search_root_not_found",
        ),
        (&["--no-mise"], ExitStatus::Usage, "no_search_roots"),
        (&["--root", "home/Code"], ExitStatus::Success, ""),
    ];
    for (extra, status, code) in cases {
        let outcome = world.plan(extra);
        assert_eq!(outcome.status, status, "{extra:?}: {}", outcome.stdout);
        if !code.is_empty() {
            assert_eq!(outcome.error_code(), code, "{extra:?}");
        }
    }
    // The options of the rule with another rule or another mode.
    for arguments in [
        &[
            "clean",
            "plan",
            "--mode",
            "evict",
            "--rule",
            "xcode.inactive-derived-data",
            "--no-mise",
        ][..],
        &["clean", "plan", "--scan", "s", "--include-active"][..],
    ] {
        let outcome = json(&world.environment, arguments);
        assert_eq!(outcome.status, ExitStatus::Usage, "{}", outcome.stdout);
        assert_eq!(outcome.error_code(), "option_not_accepted");
    }
}

#[test]
fn clean_inspect_reports_the_units_of_the_rules_that_have_an_inspection() {
    let world = World::new(None);
    let app: PathBuf = world.node_project("app");
    let root: String = world.root();
    let outcome = json(
        &world.environment,
        &[
            "clean",
            "inspect",
            "--rule",
            RULE,
            "--root",
            &root,
            "--no-mise",
        ],
    );
    assert_eq!(outcome.status, ExitStatus::Success, "{}", outcome.stdout);
    let result: Value = outcome.result();
    assert_eq!(result["kind"], "project");
    let unit = &result["projects"]["units"][0];
    assert_eq!(unit["path"], text(&app.join("node_modules")));
    assert_eq!(unit["outcome"]["kind"], "measured", "{unit}");
    assert_eq!(result["projects"]["roots"][0]["source"]["kind"], "argument");
    let shown = run(
        &world.environment,
        &[
            "clean",
            "inspect",
            "--rule",
            RULE,
            "--root",
            &root,
            "--no-mise",
        ],
    );
    assert_eq!(shown.status, ExitStatus::Success);
    assert!(
        shown
            .stdout
            .contains("Inspection: project.dependency-directory"),
        "{}",
        shown.stdout
    );
    assert!(shown.stdout.contains("node-modules"), "{}", shown.stdout);
    // A cache rule and the worktrees.
    let cache = json(
        &world.environment,
        &["clean", "inspect", "--rule", "uv.cache"],
    );
    assert_eq!(cache.status, ExitStatus::Success, "{}", cache.stdout);
    assert_eq!(cache.result()["kind"], "cache");
    let worktrees = json(
        &world.environment,
        &[
            "clean",
            "inspect",
            "--rule",
            "git.linked-worktree",
            "--root",
            &root,
        ],
    );
    assert_eq!(
        worktrees.status,
        ExitStatus::Success,
        "{}",
        worktrees.stdout
    );
    assert_eq!(worktrees.result()["kind"], "worktree");
    // A rule with no inspection command, and a rule that does not exist.
    for (rule, code) in [
        ("xcode.inactive-derived-data", "inspection_not_available"),
        ("all.caches", "unknown_rule"),
    ] {
        let outcome = json(&world.environment, &["clean", "inspect", "--rule", rule]);
        assert_eq!(outcome.status, ExitStatus::Usage, "{}", outcome.stdout);
        assert_eq!(outcome.error_code(), code);
    }
    // The inspection removed nothing.
    assert!(app.join("node_modules/left-pad/index.js").exists());
}

#[test]
fn clean_inspect_shows_an_unmarked_directory_only_with_allow_unmarked() {
    let world = World::new(None);
    world.write("Code/scripts/.gitignore", b"/.venv/\n");
    world.repository("Code/scripts");
    world.write("Code/scripts/.venv/pyvenv.cfg", b"home = /usr/bin\n");
    let venv: PathBuf = world.home.join("Code/scripts/.venv");
    let root: String = world.root();
    let inspect = |extra: &[&str]| {
        let mut arguments: Vec<&str> = vec![
            "clean",
            "inspect",
            "--rule",
            RULE,
            "--root",
            &root,
            "--no-mise",
        ];
        arguments.extend_from_slice(extra);
        json(&world.environment, &arguments)
    };
    let unit_of = |result: &Value| {
        result["projects"]["units"]
            .as_array()
            .unwrap()
            .iter()
            .find(|unit| unit["path"] == text(&venv))
            .cloned()
            .unwrap()
    };
    let plain = inspect(&[]);
    assert_eq!(plain.status, ExitStatus::Success, "{}", plain.stdout);
    let unit: Value = unit_of(&plain.result());
    assert_eq!(unit["layout"], "python-venv");
    assert_eq!(
        unit["outcome"]["reason"], "project_marker_missing",
        "{unit}"
    );
    assert_eq!(unit["marker_allowance"], Value::Null);
    let allowed = inspect(&["--allow-unmarked"]);
    assert_eq!(allowed.status, ExitStatus::Success, "{}", allowed.stdout);
    let unit: Value = unit_of(&allowed.result());
    assert_eq!(unit["layout"], "python-venv+unmarked");
    assert_eq!(unit["marker_allowance"], "project_marker_absent_allowed");
    assert_eq!(unit["outcome"]["kind"], "measured", "{unit}");
    // The option with another rule or another mode.
    for arguments in [
        &[
            "clean",
            "inspect",
            "--rule",
            "go.build-cache",
            "--allow-unmarked",
        ][..],
        &[
            "clean",
            "plan",
            "--mode",
            "evict",
            "--rule",
            "xcode.inactive-derived-data",
            "--allow-unmarked",
        ][..],
        &["clean", "plan", "--scan", "s", "--allow-unmarked"][..],
    ] {
        let outcome = json(&world.environment, arguments);
        assert_eq!(outcome.status, ExitStatus::Usage, "{}", outcome.stdout);
        assert_eq!(outcome.error_code(), "option_not_accepted");
    }
}

// ---------------------------------------------------------------------
// The clean clones of Swift Package Manager (`docs/CLEANUP_RULES.md`
// section 6).
// ---------------------------------------------------------------------

impl World {
    fn git_in(&self, relative: &str, arguments: &[&str]) -> String {
        crate::test_support::fixture_git(&self.home, &self.home.join(relative), arguments)
    }

    /// The upstream repository `Upstream/dep` and its commit.
    fn upstream(&self) -> (PathBuf, String) {
        self.write("Upstream/dep/Sources.swift", b"let value = 1\n");
        self.repository("Upstream/dep");
        let commit: String = self.git_in("Upstream/dep", &["rev-parse", "HEAD"]);
        (self.home.join("Upstream/dep"), commit)
    }

    /// The pin file with one pin of version 2.
    fn pin(&self, relative: &str, upstream: &Path, commit: &str) {
        let resolved = serde_json::json!({
            "pins": [{
                "identity": "dep",
                "kind": "localSourceControl",
                "location": upstream.to_str().unwrap(),
                "state": {"revision": commit},
            }],
            "version": 2,
        });
        self.write(relative, serde_json::to_vec(&resolved).unwrap().as_slice());
    }

    /// A package `Code/NAME` with a `.build` directory that Git ignores and
    /// a clone of `Upstream/dep` at the pin in `.build/checkouts/dep`.
    fn swift_package(&self, name: &str) -> PathBuf {
        let (upstream, commit) = self.upstream();
        let project: String = format!("Code/{name}");
        self.write(&format!("{project}/Package.swift"), b"// tools 5.9\n");
        self.write(&format!("{project}/.gitignore"), b"/.build/\n");
        self.pin(&format!("{project}/Package.resolved"), &upstream, &commit);
        self.repository(&project);
        self.write(&format!("{project}/.build/workspace-state.json"), b"{}");
        self.write(&format!("{project}/.build/debug/out.o"), b"object");
        let checkouts: String = format!("{project}/.build/checkouts");
        std::fs::create_dir_all(self.home.join(&checkouts)).unwrap();
        self.git_in(
            &checkouts,
            &[
                "clone",
                "-q",
                "--no-hardlinks",
                upstream.to_str().unwrap(),
                "dep",
            ],
        );
        self.git_in(
            &format!("{checkouts}/dep"),
            &["checkout", "-q", "--detach", &commit],
        );
        self.home.join(project)
    }

    /// A project `Code/NAME` with `App.xcodeproj` and a `DerivedData`
    /// directory with a clone of `Upstream/dep` at the pin in
    /// `SourcePackages/checkouts/dep`.
    fn xcode_project(&self, name: &str) -> PathBuf {
        let (upstream, commit) = self.upstream();
        let project: String = format!("Code/{name}");
        self.write(&format!("{project}/App.xcodeproj/project.pbxproj"), b"{}");
        self.write(&format!("{project}/.gitignore"), b"/DerivedData/\n");
        self.pin(
            &format!(
                "{project}/App.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved"
            ),
            &upstream,
            &commit,
        );
        self.repository(&project);
        self.write(
            &format!("{project}/DerivedData/Build/Products/a.o"),
            b"object",
        );
        let checkouts: String = format!("{project}/DerivedData/SourcePackages/checkouts");
        std::fs::create_dir_all(self.home.join(&checkouts)).unwrap();
        self.git_in(
            &checkouts,
            &[
                "clone",
                "-q",
                "--no-hardlinks",
                upstream.to_str().unwrap(),
                "dep",
            ],
        );
        self.git_in(
            &format!("{checkouts}/dep"),
            &["checkout", "-q", "--detach", &commit],
        );
        self.home.join(project)
    }
}

#[test]
fn a_clean_swift_checkout_is_removed_with_its_build_directory() {
    let world = World::manual();
    let package: PathBuf = world.swift_package("sp");
    let (plan_id, result) = world.planned();
    assert_eq!(target_paths(&result), [text(&package.join(".build"))]);
    let applied = world.apply(&plan_id);
    assert_eq!(applied.status, ExitStatus::Success, "{}", applied.stdout);
    assert!(!package.join(".build").exists());
    assert!(package.join("Package.swift").exists());
    assert!(world.home.join("Upstream/dep/Sources.swift").exists());
}

#[test]
fn a_clean_swift_checkout_of_an_xcode_project_is_removed_with_its_derived_data() {
    let world = World::manual();
    let project: PathBuf = world.xcode_project("xp");
    let (plan_id, result) = world.planned();
    assert_eq!(target_paths(&result), [text(&project.join("DerivedData"))]);
    let applied = world.apply(&plan_id);
    assert_eq!(applied.status, ExitStatus::Success, "{}", applied.stdout);
    assert!(!project.join("DerivedData").exists());
    assert!(project.join("App.xcodeproj/project.pbxproj").exists());
}

#[test]
fn a_swift_checkout_with_no_pin_file_keeps_its_build_directory() {
    let world = World::manual();
    let package: PathBuf = world.swift_package("sp");
    std::fs::remove_file(package.join("Package.resolved")).unwrap();
    let root: String = world.root();
    let outcome = world.plan(&["--root", &root, "--no-mise"]);
    assert_eq!(outcome.status, ExitStatus::Success, "{}", outcome.stdout);
    assert!(
        target_paths(&outcome.result()).is_empty(),
        "{}",
        outcome.stdout
    );
    assert!(package.join(".build/checkouts/dep/.git").exists());
}

#[test]
fn a_new_commit_in_an_admitted_checkout_skips_the_step() {
    let world = World::manual();
    let package: PathBuf = world.swift_package("sp");
    let (plan_id, result) = world.planned();
    assert_eq!(target_paths(&result), [text(&package.join(".build"))]);
    world.git_in(
        "Code/sp/.build/checkouts/dep",
        &["commit", "-q", "--allow-empty", "-m", "mine"],
    );
    let applied = world.apply(&plan_id);
    assert!(
        applied.stdout.contains("repository_changed"),
        "{}",
        applied.stdout
    );
    assert!(package.join(".build/checkouts/dep/.git").exists());
    assert!(package.join(".build/debug/out.o").exists());
}

#[test]
fn a_repository_that_the_plan_does_not_list_skips_the_step() {
    let world = World::manual();
    let package: PathBuf = world.swift_package("sp");
    let (plan_id, _) = world.planned();
    world.write("Code/sp/.build/extra/a.txt", b"mine\n");
    world.repository("Code/sp/.build/extra");
    let applied = world.apply(&plan_id);
    assert!(
        applied.stdout.contains("repository_changed"),
        "{}",
        applied.stdout
    );
    assert!(package.join(".build/extra/.git").exists());
    assert!(package.join(".build/checkouts/dep/.git").exists());
}
