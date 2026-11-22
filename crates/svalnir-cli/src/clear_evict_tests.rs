//! End-to-end tests of `clean inspect` and of the `evict` mode of
//! `clean plan` for the clear rules, and of the apply of their plans.
//!
//! Each test has its own temporary directory with the state directory and
//! a home directory with fixture caches. A plan needs a lifecycle state
//! that only a test build can give: each clear rule of a build is
//! `proposed`. The process evidence comes from a fixture. A removal is only
//! below the temporary directory; no test reads a real cache or runs a
//! producer tool.

#![cfg(debug_assertions)]

use std::path::PathBuf;
use std::sync::Arc;

use serde_json::Value;
use svalnir_agent::rules::fixture::{FixtureEnvironment, manual_action_validated};
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
        "request_clear_{}",
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

/// One temporary world with a home directory and a policy revision in
/// effect.
struct World {
    environment: Environment,
    _directory: TempDirectory,
    home: PathBuf,
}

impl World {
    fn new(lifecycle: Option<LifecycleState>) -> Self {
        let (mut environment, directory) = environment();
        // The fixture is 30 days old for the discovery.
        let evidence = FixtureEnvironment::days_later(30);
        environment.seams.test.rule_lifecycle = lifecycle;
        environment.seams.test.discovery_environment = Some(TestEnvironment(Arc::new(evidence)));
        let home: PathBuf = std::fs::canonicalize(environment.home.as_ref().unwrap()).unwrap();
        let config: PathBuf = directory.path().join("config.toml");
        std::fs::write(&config, "schema_version = 1\n").unwrap();
        let world = Self {
            environment,
            _directory: directory,
            home,
        };
        let outcome = json(
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
        assert_eq!(outcome.status, ExitStatus::Success, "{}", outcome.stdout);
        world
    }

    fn manual() -> Self {
        Self::new(Some(manual_action_validated()))
    }

    fn write(&self, relative: &str, content: &[u8]) -> PathBuf {
        let path: PathBuf = self.home.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, content).unwrap();
        path
    }

    fn plan(&self, rule: &str, extra: &[&str]) -> Outcome {
        let mut arguments: Vec<&str> = vec!["clean", "plan", "--mode", "evict", "--rule", rule];
        arguments.extend_from_slice(extra);
        json(&self.environment, &arguments)
    }

    /// The plan of `rule` with the consent, and its result.
    fn planned(&self, rule: &str) -> (String, Value) {
        let outcome = self.plan(rule, &["--include-clear"]);
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

    fn exists(&self, relative: &str) -> bool {
        std::fs::symlink_metadata(self.home.join(relative)).is_ok()
    }
}

/// The target paths of a plan result, relative to the home directory.
fn targets(world: &World, result: &Value) -> Vec<String> {
    let mut paths: Vec<String> = result["explanation"]["targets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|target| {
            PathBuf::from(target["path"]["value"].as_str().unwrap())
                .strip_prefix(&world.home)
                .unwrap()
                .to_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    paths.sort();
    paths
}

#[test]
fn a_clear_rule_of_a_build_is_proposed_and_its_evict_mode_is_refused() {
    let world = World::new(None);
    world.write(
        ".cargo/registry/cache/index.crates.io-1/a-1.0.0.crate",
        b"crate",
    );
    let outcome = world.plan("cargo.registry-cache", &["--include-clear"]);
    assert_eq!(
        outcome.status,
        ExitStatus::Unavailable,
        "{}",
        outcome.stdout
    );
    assert_eq!(outcome.error_code(), "rule_mode_not_validated");
    assert!(world.exists(".cargo/registry/cache/index.crates.io-1/a-1.0.0.crate"));
}

#[test]
fn a_clear_rule_needs_the_consent_and_the_flag_needs_a_clear_rule() {
    let world = World::manual();
    world.write(".gradle/caches/modules-2/a.jar", b"jar");
    // No consent: no plan, and nothing is read or changed.
    let outcome = world.plan("gradle.caches", &[]);
    assert_eq!(outcome.status, ExitStatus::Usage, "{}", outcome.stdout);
    assert_eq!(outcome.error_code(), "clear_not_included");
    assert!(world.exists(".gradle/caches/modules-2/a.jar"));
    // The flag with a rule that is not a clear rule, or with another mode.
    for arguments in [
        &[
            "clean",
            "plan",
            "--mode",
            "evict",
            "--rule",
            "xcode.inactive-derived-data",
            "--include-clear",
        ][..],
        &["clean", "plan", "--scan", "s", "--include-clear"][..],
    ] {
        let outcome = json(&world.environment, arguments);
        assert_eq!(outcome.status, ExitStatus::Usage, "{}", outcome.stdout);
        assert_eq!(outcome.error_code(), "unsupported_rule_selection");
    }
}

#[test]
fn a_maven_plan_removes_only_the_eligible_groups_and_keeps_the_settings() {
    let world = World::manual();
    world.write(".m2/repository/org/lib/1.0/lib-1.0.jar", b"jar");
    world.write(".m2/repository/io/x/1/x.pom", b"<project/>");
    world.write(
        ".m2/repository/com/me/app/1.0/maven-metadata-local.xml",
        b"<metadata/>",
    );
    world.write(".m2/settings.xml", b"<settings/>");
    let (plan_id, result) = world.planned("maven.repository");
    assert_eq!(
        targets(&world, &result),
        [".m2/repository/io", ".m2/repository/org"]
    );
    let discovery = &result["discovery"];
    assert_eq!(discovery["rule"]["id"], "maven.repository");
    assert_eq!(discovery["complete"], true, "{discovery}");
    let skipped = &discovery["roots"][0]["skipped"];
    assert_eq!(skipped[0]["relative_entry"]["value"], "com", "{discovery}");
    assert_eq!(skipped[0]["reasons"][0], "protected_data");

    let applied = world.apply(&plan_id);
    assert_eq!(applied.status, ExitStatus::Success, "{}", applied.stdout);
    assert!(!world.exists(".m2/repository/org"));
    assert!(!world.exists(".m2/repository/io"));
    // The root, the local install, and the settings stay.
    assert!(world.exists(".m2/repository"));
    assert!(world.exists(".m2/repository/com/me/app/1.0/maven-metadata-local.xml"));
    assert!(world.exists(".m2/settings.xml"));
}

#[test]
fn a_cargo_plan_keeps_the_checkouts_the_binaries_and_the_index() {
    let world = World::manual();
    world.write(
        ".cargo/registry/cache/index.crates.io-1/a-1.0.0.crate",
        b"crate",
    );
    world.write(
        ".cargo/registry/src/index.crates.io-1/a-1.0.0/src/lib.rs",
        b"//",
    );
    world.write(".cargo/registry/index/index.crates.io-1/config.json", b"{}");
    world.write(".cargo/git/checkouts/tool-1/abc/src/main.rs", b"// edited");
    world.write(".cargo/bin/tool", b"binary");
    let (plan_id, result) = world.planned("cargo.registry-cache");
    assert_eq!(
        targets(&world, &result),
        [
            ".cargo/registry/cache/index.crates.io-1",
            ".cargo/registry/src/index.crates.io-1"
        ]
    );
    let applied = world.apply(&plan_id);
    assert_eq!(applied.status, ExitStatus::Success, "{}", applied.stdout);
    assert!(!world.exists(".cargo/registry/cache/index.crates.io-1"));
    assert!(!world.exists(".cargo/registry/src/index.crates.io-1"));
    assert!(world.exists(".cargo/registry/cache"));
    assert!(world.exists(".cargo/registry/index/index.crates.io-1/config.json"));
    assert!(world.exists(".cargo/git/checkouts/tool-1/abc/src/main.rs"));
    assert!(world.exists(".cargo/bin/tool"));
}

#[test]
fn a_rubygems_plan_removes_the_gem_files_and_keeps_bundler() {
    let world = World::manual();
    world.write(".gem/ruby/3.3.0/cache/rake-13.0.gem", b"gem");
    world.write(".gem/ruby/3.3.0/cache/bundler/git/tool-1/HEAD", b"ref: x");
    world.write(".gem/ruby/3.3.0/gems/rake-13.0/lib/rake.rb", b"#");
    let (plan_id, result) = world.planned("rubygems.cache");
    assert_eq!(
        targets(&world, &result),
        [".gem/ruby/3.3.0/cache/rake-13.0.gem"]
    );
    let applied = world.apply(&plan_id);
    assert_eq!(applied.status, ExitStatus::Success, "{}", applied.stdout);
    assert!(!world.exists(".gem/ruby/3.3.0/cache/rake-13.0.gem"));
    assert!(world.exists(".gem/ruby/3.3.0/cache/bundler/git/tool-1/HEAD"));
    assert!(world.exists(".gem/ruby/3.3.0/gems/rake-13.0/lib/rake.rb"));
}

#[test]
fn a_deno_plan_keeps_the_local_storage_and_the_history() {
    let world = World::manual();
    world.write("Library/Caches/deno/remote/https/deno.land/a", b"js");
    world.write("Library/Caches/deno/location_data/a/local_storage", b"db");
    world.write("Library/Caches/deno/deno_history.txt", b"1 + 1");
    let (plan_id, result) = world.planned("deno.remote");
    assert_eq!(
        targets(&world, &result),
        ["Library/Caches/deno/remote/https"]
    );
    let applied = world.apply(&plan_id);
    assert_eq!(applied.status, ExitStatus::Success, "{}", applied.stdout);
    assert!(!world.exists("Library/Caches/deno/remote/https"));
    assert!(world.exists("Library/Caches/deno/location_data/a/local_storage"));
    assert!(world.exists("Library/Caches/deno/deno_history.txt"));
}

#[test]
fn the_step_checks_a_local_install_and_a_repository_again() {
    let world = World::manual();
    world.write(".m2/repository/org/lib/1.0/lib-1.0.jar", b"jar");
    world.write(".m2/repository/io/x/1/x.pom", b"<project/>");
    let (plan_id, result) = world.planned("maven.repository");
    assert_eq!(targets(&world, &result).len(), 2, "{result}");
    // After the plan: a local install in one unit, and a Git repository in
    // the other.
    world.write(
        ".m2/repository/org/me/1.0/maven-metadata-local.xml",
        b"<metadata/>",
    );
    world.write(".m2/repository/io/work/.git/HEAD", b"ref: x");
    let applied = world.apply(&plan_id);
    // Each target is skipped, so the operation took no action.
    assert!(applied.stdout.contains("NoAction"), "{}", applied.stdout);
    for code in ["protected_child", "nested_repository"] {
        assert!(applied.stdout.contains(code), "{code}: {}", applied.stdout);
    }
    assert!(world.exists(".m2/repository/org/lib/1.0/lib-1.0.jar"));
    assert!(world.exists(".m2/repository/io/work/.git/HEAD"));
}

#[test]
fn clean_inspect_reports_the_units_of_a_proposed_clear_rule() {
    let world = World::new(None);
    world.write(".hex/packages/hexpm/jason-1.4.tar", b"tar");
    world.write(".hex/hex.config", b"api_key");
    let outcome = json(
        &world.environment,
        &["clean", "inspect", "--rule", "hex.packages"],
    );
    assert_eq!(outcome.status, ExitStatus::Success, "{}", outcome.stdout);
    let result: Value = outcome.result();
    assert_eq!(result["kind"], "clear");
    let clear = &result["clear"];
    assert_eq!(
        clear["resolved_roots"][0]["source"]["pattern"],
        ".hex/packages"
    );
    let unit = clear["units"][0]["path"]["value"].as_str().unwrap();
    assert!(unit.ends_with(".hex/packages/hexpm"), "{clear}");
    assert!(clear["kept"].as_str().unwrap().contains("hex.config"));
    // The inspection removes nothing.
    assert!(world.exists(".hex/packages/hexpm/jason-1.4.tar"));
    assert!(world.exists(".hex/hex.config"));
}
