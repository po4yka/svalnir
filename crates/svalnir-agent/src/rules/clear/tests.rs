//! Tests of the clear rules.
//!
//! Each test makes a home directory with fixture caches in a temporary
//! directory that it created. No test reads a real cache, runs a producer
//! tool, or reads the process table: the process evidence comes from a
//! fixture.

use std::fs;
use std::path::{Path, PathBuf};

use svalnir_core::id::RuleId;
use svalnir_core::process::Uid;
use svalnir_core::rule::{LifecycleState, RuleMode, RuleRegistry as _};
use tempfile::TempDir;

use super::{
    CLEAR_SPECS, Configured, GRADLE_CACHES, MAVEN_REPOSITORY, RUBYGEMS_CACHE, is_clear_rule,
    local_repository_of, recheck_unit, resolve,
};
use crate::protection::ProtectedLocations;
use crate::rules::eviction::{
    DiscoveryEnvironment as _, DiscoveryHost, EvictionDiscovery, EvictionRequest, ProducerActivity,
    RootResult, automatic_roots,
};
use crate::rules::fixture::{
    FixtureEnvironment, FixtureUse, automatic_eviction_validated, manual_action_validated,
};
use crate::rules::model::{DiscoveryLimits, SkipReason};
use crate::rules::projects::UnitRecheck;
use crate::rules::registry::ReviewedRules;
use crate::rules::xcode::ProducerProcesses;
use crate::scan::CancellationToken;

/// A home directory and a state directory in a temporary directory.
struct Home {
    _directory: TempDir,
    path: PathBuf,
    state: PathBuf,
    principal: Uid,
}

impl Home {
    fn new() -> Self {
        use std::os::unix::fs::MetadataExt as _;

        let directory: TempDir = tempfile::tempdir().unwrap();
        // The temporary directory of macOS is below a symbolic link.
        let base: PathBuf = fs::canonicalize(directory.path()).unwrap();
        let home: PathBuf = base.join("home");
        let state: PathBuf = home.join("Library/Application Support/Svalnir");
        fs::create_dir_all(&state).unwrap();
        let principal: Uid = Uid::new(fs::metadata(&home).unwrap().uid());
        Self {
            _directory: directory,
            path: home,
            state,
            principal,
        }
    }

    fn write(&self, relative: &str, content: &[u8]) -> PathBuf {
        let path: PathBuf = self.path.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, content).unwrap();
        path
    }

    fn host(&self) -> DiscoveryHost {
        DiscoveryHost {
            principal: self.principal,
            locations: ProtectedLocations::resolve(Some(&self.path), Some(&self.state)),
            user_exclusions: Vec::new(),
        }
    }
}

fn manual_registry() -> ReviewedRules {
    ReviewedRules::with_fixture_lifecycle(&manual_action_validated()).unwrap()
}

/// An environment 30 days after the time of the host: each fixture unit is
/// then older than the quiet time of the rules.
fn month_later() -> FixtureEnvironment {
    FixtureEnvironment::days_later(30)
}

fn discover(
    registry: &ReviewedRules,
    home: &Home,
    rule: &str,
    purpose: &RuleMode,
    environment: &FixtureEnvironment,
) -> EvictionDiscovery {
    let cancel = CancellationToken::new();
    let host: DiscoveryHost = home.host();
    registry.discover_for_eviction(
        &EvictionRequest {
            host: &host,
            purpose,
            rules: Some(&[RuleId::new(rule).unwrap()]),
            volumes: None,
            known: None,
            limits: DiscoveryLimits::default(),
            cancel: &cancel,
            projects: None,
        },
        environment,
    )
}

fn manual(home: &Home, rule: &str) -> EvictionDiscovery {
    discover(
        &manual_registry(),
        home,
        rule,
        &RuleMode::ManualEviction,
        &month_later(),
    )
}

/// The candidate paths of a discovery, relative to the home directory.
fn candidates(home: &Home, discovery: &EvictionDiscovery) -> Vec<String> {
    let mut paths: Vec<String> = discovery
        .candidates
        .iter()
        .filter(|candidate| candidate.discovered.blockers.is_empty())
        .map(|candidate| {
            candidate
                .candidate
                .candidate
                .path
                .to_path_buf()
                .strip_prefix(&home.path)
                .unwrap()
                .to_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    paths.sort();
    paths
}

/// The reasons of the skipped unit `relative` of the root `root`.
fn skip_reasons(discovery: &EvictionDiscovery, root: &Path, relative: &str) -> Vec<SkipReason> {
    discovery
        .roots
        .iter()
        .filter(|report| report.path.as_deref() == Some(root))
        .find_map(|report| match &report.result {
            RootResult::Examined { skipped, .. } => skipped
                .iter()
                .find(|unit| unit.relative_entry.as_utf8() == Some(relative))
                .map(|unit| unit.reasons.clone()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no skipped unit {relative}: {discovery:?}"))
}

// ---------------------------------------------------------------------
// Registry and modes
// ---------------------------------------------------------------------

#[test]
fn each_clear_rule_is_proposed_and_has_no_automatic_mode() {
    let registry: ReviewedRules = ReviewedRules::new().unwrap();
    assert_eq!(registry.clear().all().len(), CLEAR_SPECS.len());
    for spec in &CLEAR_SPECS {
        let rule = registry.clear_rule(spec.id).unwrap().rule();
        assert!(is_clear_rule(spec.id));
        assert!(
            !rule.modes.contains(&RuleMode::AutomaticEviction),
            "{}",
            spec.id
        );
        assert!(
            rule.modes.contains(&RuleMode::ManualEviction),
            "{}",
            spec.id
        );
        assert!(
            rule.layouts
                .iter()
                .all(|layout| layout.lifecycle == LifecycleState::Proposed),
            "{}",
            spec.id
        );
        // The registry lists the rule.
        assert!(
            registry
                .rules()
                .iter()
                .any(|known| known.reference.id.as_str() == spec.id)
        );
    }
}

#[test]
fn a_fixture_lifecycle_gives_a_clear_rule_at_most_the_manual_state() {
    let registry: ReviewedRules =
        ReviewedRules::with_fixture_lifecycle(&automatic_eviction_validated()).unwrap();
    for status in registry.statuses() {
        if !is_clear_rule(status.reference.id.as_str()) {
            continue;
        }
        assert!(
            matches!(
                status.lifecycle,
                LifecycleState::ManualActionValidated { .. }
            ),
            "{status:?}"
        );
        assert!(
            !status
                .permitted_modes
                .contains(&RuleMode::AutomaticEviction)
        );
        assert!(status.permitted_modes.contains(&RuleMode::ManualEviction));
    }
}

#[test]
fn a_clear_rule_is_never_examined_for_an_automatic_operation() {
    let home = Home::new();
    home.write(
        ".cargo/registry/cache/index.crates.io-1/foo-1.0.0.crate",
        b"crate",
    );
    let registry: ReviewedRules =
        ReviewedRules::with_fixture_lifecycle(&automatic_eviction_validated()).unwrap();
    let rule: RuleId = RuleId::new(GRADLE_CACHES.id).unwrap();
    let cargo: RuleId = RuleId::new(super::CARGO_REGISTRY.id).unwrap();
    // The approved roots of an automatic operation have no root of a clear
    // rule, also when the guard approves the rule.
    let roots = automatic_roots(&registry, &[rule, cargo], &home.host().locations);
    assert!(roots.is_empty(), "{roots:?}");
    // The discovery for an automatic eviction does not examine the rule.
    let discovery: EvictionDiscovery = discover(
        &registry,
        &home,
        super::CARGO_REGISTRY.id,
        &RuleMode::AutomaticEviction,
        &month_later(),
    );
    assert_eq!(discovery.candidates.len(), 0);
    assert!(discovery.roots.is_empty(), "{:?}", discovery.roots);
}

#[test]
fn a_proposed_clear_rule_is_not_examined_for_a_manual_eviction() {
    let home = Home::new();
    home.write(
        ".cargo/registry/cache/index.crates.io-1/foo-1.0.0.crate",
        b"crate",
    );
    let discovery: EvictionDiscovery = discover(
        &ReviewedRules::new().unwrap(),
        &home,
        super::CARGO_REGISTRY.id,
        &RuleMode::ManualEviction,
        &month_later(),
    );
    assert_eq!(discovery.candidates.len(), 0);
    assert_eq!(discovery.roots.len(), 0);
}

// ---------------------------------------------------------------------
// Families
// ---------------------------------------------------------------------

#[test]
fn cargo_clears_the_archives_and_the_sources_and_keeps_git_bin_and_index() {
    let home = Home::new();
    home.write(
        ".cargo/registry/cache/index.crates.io-1/foo-1.0.0.crate",
        b"crate",
    );
    home.write(
        ".cargo/registry/src/index.crates.io-1/foo-1.0.0/src/lib.rs",
        b"//",
    );
    home.write(".cargo/registry/index/index.crates.io-1/config.json", b"{}");
    home.write(".cargo/git/checkouts/tool-1/abc/.git", b"gitdir: x");
    home.write(".cargo/bin/tool", b"binary");
    let discovery: EvictionDiscovery = manual(&home, super::CARGO_REGISTRY.id);
    assert_eq!(
        candidates(&home, &discovery),
        [
            ".cargo/registry/cache/index.crates.io-1",
            ".cargo/registry/src/index.crates.io-1"
        ]
    );
    assert!(discovery.complete, "{discovery:?}");
    assert_eq!(discovery.roots.len(), 2);
}

#[test]
fn maven_refuses_an_artifact_with_a_local_install_and_reads_settings() {
    let home = Home::new();
    home.write(".m2/repository/org/lib/1.0/lib-1.0.jar", b"jar");
    home.write(
        ".m2/repository/org/lib/1.0/_remote.repositories",
        b"#NOTE: internal\nlib-1.0.jar>central=\nlib-1.0.pom>central=\n",
    );
    // Two artifacts of one group: only the installed one is refused.
    home.write(".m2/repository/com/me/app/1.0/app-1.0.pom", b"<project/>");
    home.write(
        ".m2/repository/com/me/app/maven-metadata-local.xml",
        b"<metadata/>",
    );
    home.write(".m2/repository/com/me/tool/2.0/tool-2.0.jar", b"jar");
    home.write(".m2/repository/com/me/cli/3.0/cli-3.0.jar", b"jar");
    home.write(
        ".m2/repository/com/me/cli/3.0/_remote.repositories",
        b"cli-3.0.jar>=\n",
    );
    // An entry in no artifact directory is not a unit.
    home.write(".m2/repository/org/stray.lastUpdated", b"x");
    home.write(".m2/settings.xml", b"<settings/>");
    let root: PathBuf = home.path.join(".m2/repository");
    let discovery: EvictionDiscovery = manual(&home, MAVEN_REPOSITORY.id);
    assert_eq!(
        candidates(&home, &discovery),
        [".m2/repository/com/me/tool", ".m2/repository/org/lib"]
    );
    for refused in ["com/me/app", "com/me/cli"] {
        assert_eq!(
            skip_reasons(&discovery, &root, refused),
            [SkipReason::ProtectedData],
            "{refused}"
        );
    }
    assert!(discovery.complete, "{discovery:?}");

    // A `localRepository` of the settings replaces the default root.
    home.write(
        ".m2/settings.xml",
        b"<settings><!-- <localRepository>/nowhere</localRepository> -->\n  <localRepository>${user.home}/maven-repo</localRepository>\n</settings>",
    );
    home.write("maven-repo/io/x/1/x-1.pom", b"<project/>");
    let discovery: EvictionDiscovery = manual(&home, MAVEN_REPOSITORY.id);
    assert_eq!(candidates(&home, &discovery), ["maven-repo/io/x"]);

    // A value outside the home directory gives no root.
    home.write(
        ".m2/settings.xml",
        b"<settings><localRepository>/tmp/repo</localRepository></settings>",
    );
    let discovery: EvictionDiscovery = manual(&home, MAVEN_REPOSITORY.id);
    assert_eq!(discovery.candidates.len(), 0);
    assert!(!discovery.complete);
    assert_eq!(
        discovery.roots[0].result,
        RootResult::Refused("configuration_outside_home")
    );
}

#[test]
fn the_settings_reader_takes_one_plain_value_below_the_home_directory() {
    let home: &Path = Path::new("/Users/test");
    let read = |text: &str| local_repository_of(text, home);
    assert_eq!(read("<settings/>"), Configured::Unset);
    assert_eq!(
        read("<localRepository> /Users/test/r </localRepository>"),
        Configured::Path(PathBuf::from("/Users/test/r"))
    );
    assert_eq!(
        read("<!-- a --><localRepository>${user.home}/r</localRepository>"),
        Configured::Path(PathBuf::from("/Users/test/r"))
    );
    for (text, problem) in [
        (
            "<localRepository>a</localRepository><localRepository>b</localRepository>",
            "configuration_conflicting",
        ),
        (
            "<localRepository>${env.HOME}/r</localRepository>",
            "configuration_not_resolved",
        ),
        (
            "<localRepository>/Users/test/a&amp;b</localRepository>",
            "configuration_not_resolved",
        ),
        (
            "<localRepository>repo</localRepository>",
            "configuration_not_absolute",
        ),
        (
            "<localRepository>/Users/test/../r</localRepository>",
            "configuration_not_absolute",
        ),
        (
            "<localRepository>/Users/test</localRepository>",
            "configuration_outside_home",
        ),
        ("<localRepository>/Users/test/r", "configuration_not_valid"),
        ("<!-- <localRepository>", "configuration_not_valid"),
    ] {
        assert_eq!(read(text), Configured::Problem(problem), "{text}");
    }
}

#[test]
fn gradle_refuses_a_unit_with_a_repository_and_clears_a_file_unit() {
    let home = Home::new();
    home.write(".gradle/caches/modules-2/files-2.1/g/a/1/a.jar", b"jar");
    home.write(".gradle/caches/user-id.txt", b"id");
    home.write(".gradle/caches/transforms-4/work/.git/HEAD", b"ref: x");
    home.write(".gradle/gradle.properties", b"token=secret");
    home.write(".gradle/wrapper/dists/gradle-8/x.zip", b"zip");
    let root: PathBuf = home.path.join(".gradle/caches");
    let discovery: EvictionDiscovery = manual(&home, GRADLE_CACHES.id);
    assert_eq!(
        candidates(&home, &discovery),
        [".gradle/caches/modules-2", ".gradle/caches/user-id.txt"]
    );
    assert_eq!(
        skip_reasons(&discovery, &root, "transforms-4"),
        [SkipReason::NestedRepository]
    );
}

#[test]
fn deno_clears_its_three_caches_and_keeps_the_local_storage() {
    let home = Home::new();
    home.write("Library/Caches/deno/remote/https/deno.land/abc", b"js");
    home.write(
        "Library/Caches/deno/npm/registry.npmjs.org/x/1/index.js",
        b"js",
    );
    home.write("Library/Caches/deno/gen/file/a.js", b"js");
    home.write("Library/Caches/deno/location_data/abc/local_storage", b"db");
    home.write("Library/Caches/deno/deno_history.txt", b"1 + 1");
    for (rule, expected) in [
        (super::DENO_REMOTE.id, "Library/Caches/deno/remote/https"),
        (
            super::DENO_NPM.id,
            "Library/Caches/deno/npm/registry.npmjs.org",
        ),
        (super::DENO_GEN.id, "Library/Caches/deno/gen/file"),
    ] {
        let discovery: EvictionDiscovery = manual(&home, rule);
        assert_eq!(candidates(&home, &discovery), [expected], "{rule}");
        let paths: Vec<String> = candidates(&home, &discovery);
        assert!(paths.iter().all(|path| !path.contains("location_data")));
    }
}

#[test]
fn rubygems_clears_gem_files_and_keeps_bundler_and_other_children() {
    let home = Home::new();
    home.write(".gem/ruby/3.3.0/cache/rake-13.0.gem", b"gem");
    home.write(".gem/ruby/3.3.0/cache/notes.txt", b"note");
    home.write(".gem/ruby/3.3.0/cache/bundler/git/tool-1/HEAD", b"ref: x");
    home.write(".gem/ruby/3.3.0/gems/rake-13.0/lib/rake.rb", b"#");
    home.write(
        ".rbenv/versions/3.2.2/lib/ruby/gems/3.2.0/cache/json-2.gem",
        b"gem",
    );
    let root: PathBuf = home.path.join(".gem/ruby/3.3.0/cache");
    let discovery: EvictionDiscovery = manual(&home, RUBYGEMS_CACHE.id);
    assert_eq!(
        candidates(&home, &discovery),
        [
            ".gem/ruby/3.3.0/cache/rake-13.0.gem",
            ".rbenv/versions/3.2.2/lib/ruby/gems/3.2.0/cache/json-2.gem"
        ]
    );
    assert_eq!(
        skip_reasons(&discovery, &root, "bundler"),
        [SkipReason::ProtectedData]
    );
    assert_eq!(
        skip_reasons(&discovery, &root, "notes.txt"),
        [SkipReason::UnsupportedLayout]
    );
}

#[test]
fn the_expansion_of_a_root_pattern_is_bounded_and_skips_links() {
    let home = Home::new();
    for index in 0..40 {
        home.write(&format!(".gem/ruby/{index:02}/cache/a.gem"), b"gem");
    }
    fs::create_dir_all(home.path.join("elsewhere/cache")).unwrap();
    std::os::unix::fs::symlink(
        home.path.join("elsewhere"),
        home.path.join(".gem/ruby/linked"),
    )
    .unwrap();
    let (roots, complete) = resolve(&RUBYGEMS_CACHE, &home.path);
    assert!(!complete);
    assert_eq!(roots.len(), super::MAX_EXPANDED_ROOTS);
    assert!(roots.iter().all(|root| {
        root.path
            .as_ref()
            .is_some_and(|path| !path.to_str().unwrap().contains("linked"))
    }));
}

#[test]
fn each_default_root_of_each_rule_is_below_the_home_directory() {
    for spec in &CLEAR_SPECS {
        let (roots, _) = resolve(spec, Path::new("/Users/test"));
        for root in roots {
            let path: PathBuf = root.path.unwrap();
            assert!(path.starts_with("/Users/test/"), "{}", spec.id);
            assert!(!path.to_str().unwrap().contains('*'), "{}", spec.id);
        }
    }
}

// ---------------------------------------------------------------------
// Activity and use
// ---------------------------------------------------------------------

#[test]
fn a_running_producer_blocks_each_unit_and_each_step() {
    let home = Home::new();
    home.write(".hex/packages/hexpm/jason-1.4.tar", b"tar");
    let environment: FixtureEnvironment = month_later();
    environment.set_producer(ProducerProcesses::Running);
    let discovery: EvictionDiscovery = discover(
        &manual_registry(),
        &home,
        super::HEX_PACKAGES.id,
        &RuleMode::ManualEviction,
        &environment,
    );
    assert_eq!(discovery.candidates.len(), 1);
    assert_eq!(
        discovery.candidates[0].discovered.blockers,
        [SkipReason::ActiveProducer]
    );
    let rule: RuleId = RuleId::new(super::HEX_PACKAGES.id).unwrap();
    assert_eq!(
        environment.producer_activity(&rule, home.principal),
        ProducerActivity::Active
    );
    environment.set_producer(ProducerProcesses::NotRunning);
    assert_eq!(
        environment.producer_activity(&rule, home.principal),
        ProducerActivity::Inactive
    );
}

#[test]
fn a_unit_whose_use_is_not_known_is_skipped() {
    let home = Home::new();
    home.write(".bun/install/cache/left-pad@1.3.0/index.js", b"js");
    home.write(".bun/install/cache/links/x", b"link");
    let environment: FixtureEnvironment = month_later();
    // A process of the user that cannot be read can use each unit.
    environment.set_use(FixtureUse::Unknown);
    let root: PathBuf = home.path.join(".bun/install/cache");
    let discovery: EvictionDiscovery = discover(
        &manual_registry(),
        &home,
        super::BUN_CACHE.id,
        &RuleMode::ManualEviction,
        &environment,
    );
    assert_eq!(discovery.candidates.len(), 0);
    assert_eq!(
        skip_reasons(&discovery, &root, "left-pad@1.3.0"),
        [SkipReason::UnitUseUnknown]
    );
    assert_eq!(
        skip_reasons(&discovery, &root, "links"),
        [SkipReason::ProtectedData]
    );
}

#[test]
fn a_unit_changed_within_the_quiet_time_is_blocked() {
    let home = Home::new();
    let file: PathBuf = home.write(".cache/zig/o/abc/main.o", b"o");
    // The clock of the discovery is 30 days later; the file changed five
    // minutes before that time.
    let modified = std::time::SystemTime::now() + std::time::Duration::from_mins(30 * 24 * 60 - 5);
    fs::File::options()
        .write(true)
        .open(&file)
        .unwrap()
        .set_modified(modified)
        .unwrap();
    let discovery: EvictionDiscovery = manual(&home, super::ZIG_GLOBAL_CACHE.id);
    assert_eq!(discovery.candidates.len(), 1);
    assert_eq!(
        discovery.candidates[0].discovered.blockers,
        [SkipReason::RetentionNotElapsed]
    );
}

// ---------------------------------------------------------------------
// Check before a step
// ---------------------------------------------------------------------

#[test]
fn the_check_before_a_step_examines_the_form_and_the_refused_names_again() {
    let home = Home::new();
    let root: PathBuf = home.path.join(".m2/repository");
    home.write(".m2/repository/org/lib/1.0/lib-1.0.jar", b"jar");
    let unit: PathBuf = root.join("org/lib");
    let check = |path: &Path| recheck_unit(&MAVEN_REPOSITORY, home.principal, &root, path);
    assert_eq!(check(&unit), UnitRecheck::Passed);
    // A local install in the unit after the plan.
    home.write(
        ".m2/repository/org/lib/2.0/_remote.repositories",
        b"lib-2.0.jar>=\n",
    );
    assert_eq!(check(&unit), UnitRecheck::Refused("protected_child"));
    home.write(
        ".m2/repository/org/lib/2.0/_remote.repositories",
        b"lib-2.0.jar>central=\n",
    );
    assert_eq!(check(&unit), UnitRecheck::Passed);
    home.write(
        ".m2/repository/org/lib/maven-metadata-local.xml",
        b"<metadata/>",
    );
    assert_eq!(check(&unit), UnitRecheck::Refused("protected_child"));
    // A group directory is not an artifact directory.
    assert_eq!(
        check(&root.join("org")),
        UnitRecheck::Refused("unit_layout_changed")
    );
    assert_eq!(check(&root.join("gone")), UnitRecheck::Absent);

    // A kept child and a child of another form.
    let gems: PathBuf = home.path.join(".gem/ruby/3.3.0/cache");
    home.write(".gem/ruby/3.3.0/cache/bundler/x", b"x");
    home.write(".gem/ruby/3.3.0/cache/a.txt", b"x");
    let check = |path: &Path| recheck_unit(&RUBYGEMS_CACHE, home.principal, &gems, path);
    assert_eq!(
        check(&gems.join("bundler")),
        UnitRecheck::Refused("unit_layout_changed")
    );
    assert_eq!(
        check(&gems.join("a.txt")),
        UnitRecheck::Refused("unit_layout_changed")
    );
    // The environment applies the check for a clear rule.
    let environment: FixtureEnvironment = month_later();
    let reference = manual_registry()
        .clear_rule(MAVEN_REPOSITORY.id)
        .unwrap()
        .rule()
        .reference
        .clone();
    assert_eq!(
        environment.unit_recheck(home.principal, &reference, None, &root, &unit, &[]),
        UnitRecheck::Refused("protected_child")
    );
}

#[test]
fn the_inspection_reports_the_roots_and_the_units_of_a_proposed_rule() {
    let home = Home::new();
    home.write(".nuget/packages/newtonsoft.json/13.0.1/lib.dll", b"dll");
    let registry: ReviewedRules = ReviewedRules::new().unwrap();
    let host: DiscoveryHost = home.host();
    let cancel = CancellationToken::new();
    let (discovery, roots) = registry
        .inspect_clear(
            super::NUGET_PACKAGES.id,
            &EvictionRequest {
                host: &host,
                purpose: &RuleMode::Inspection,
                rules: None,
                volumes: None,
                known: None,
                limits: DiscoveryLimits::default(),
                cancel: &cancel,
                projects: None,
            },
            &month_later(),
        )
        .unwrap();
    assert_eq!(roots.len(), 1);
    assert_eq!(
        candidates(&home, &discovery),
        [".nuget/packages/newtonsoft.json"]
    );
    assert!(
        registry
            .inspect_clear(
                "xcode.inactive-derived-data",
                &EvictionRequest {
                    host: &host,
                    purpose: &RuleMode::Inspection,
                    rules: None,
                    volumes: None,
                    known: None,
                    limits: DiscoveryLimits::default(),
                    cancel: &cancel,
                    projects: None,
                },
                &month_later(),
            )
            .is_none()
    );
}
