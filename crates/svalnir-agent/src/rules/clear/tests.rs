//! Tests of the clear rules.
//!
//! Each test makes a home directory with fixture caches in a temporary
//! directory that it created. No test reads a real cache, runs a producer
//! tool, or reads the process table: the process evidence comes from a
//! fixture.

use std::fs;
use std::os::unix::fs::PermissionsExt;
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
            cache_locations: Vec::new(),
            system_root: self.path.join("system"),
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
fn maven_clears_only_the_artifacts_that_a_record_attributes_to_a_remote() {
    let home = Home::new();
    home.write(".m2/repository/org/lib/1.0/lib-1.0.jar", b"jar");
    home.write(".m2/repository/org/lib/1.0/lib-1.0.pom", b"<project/>");
    home.write(
        ".m2/repository/org/lib/1.0/_remote.repositories",
        b"#NOTE: internal\nlib-1.0.jar>central=\nlib-1.0.pom>central=\n",
    );
    // A local install: the metadata of the install, and a record with no
    // repository.
    home.write(".m2/repository/com/me/app/1.0/app-1.0.pom", b"<project/>");
    home.write(
        ".m2/repository/com/me/app/1.0/_remote.repositories",
        b"app-1.0.pom>central=\n",
    );
    home.write(
        ".m2/repository/com/me/app/maven-metadata-local.xml",
        b"<metadata/>",
    );
    home.write(".m2/repository/com/me/cli/3.0/cli-3.0.jar", b"jar");
    home.write(
        ".m2/repository/com/me/cli/3.0/_remote.repositories",
        b"cli-3.0.jar>=\n",
    );
    // A hand-copied driver: a `.jar` and a `.pom` with no record.
    home.write(
        ".m2/repository/com/oracle/ojdbc8/19.3/ojdbc8-19.3.jar",
        b"jar",
    );
    home.write(
        ".m2/repository/com/oracle/ojdbc8/19.3/ojdbc8-19.3.pom",
        b"<project/>",
    );
    // A record that names the `.jar` and not the `.pom`.
    home.write(".m2/repository/io/half/1/half-1.jar", b"jar");
    home.write(".m2/repository/io/half/1/half-1.pom", b"<project/>");
    home.write(
        ".m2/repository/io/half/1/_remote.repositories",
        b"half-1.jar>central=\n",
    );
    // An entry in no artifact directory is not a unit.
    home.write(".m2/repository/org/stray.lastUpdated", b"x");
    home.write(".m2/settings.xml", b"<settings/>");
    let root: PathBuf = home.path.join(".m2/repository");
    let discovery: EvictionDiscovery = manual(&home, MAVEN_REPOSITORY.id);
    assert_eq!(candidates(&home, &discovery), [".m2/repository/org/lib"]);
    for refused in ["com/me/app", "com/me/cli", "com/oracle/ojdbc8", "io/half"] {
        assert_eq!(
            skip_reasons(&discovery, &root, refused),
            [SkipReason::ProtectedData],
            "{refused}"
        );
    }
    assert!(discovery.complete, "{discovery:?}");
}

#[test]
fn maven_reads_the_settings_and_refuses_a_root_in_a_work_tree() {
    let home = Home::new();
    let downloaded = |relative: &str| {
        home.write(&format!("{relative}/x/1/x-1.pom"), b"<project/>");
        home.write(
            &format!("{relative}/x/1/_remote.repositories"),
            b"x-1.pom>central=\n",
        );
    };
    // A `localRepository` of the settings replaces the default root.
    home.write(
        ".m2/settings.xml",
        b"<settings><!-- <localRepository>/nowhere</localRepository> -->\n  <localRepository>${user.home}/maven-repo</localRepository>\n</settings>",
    );
    downloaded("maven-repo/io");
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

    // A root in a Git work tree, for example a folder of a project.
    home.write(
        ".m2/settings.xml",
        b"<settings><localRepository>${user.home}/Code/app/repo</localRepository></settings>",
    );
    home.write("Code/app/.git/HEAD", b"ref: refs/heads/main");
    downloaded("Code/app/repo/io");
    let discovery: EvictionDiscovery = manual(&home, MAVEN_REPOSITORY.id);
    assert_eq!(discovery.candidates.len(), 0);
    assert_eq!(
        discovery.roots[0].result,
        RootResult::Refused("configuration_in_work_tree")
    );

    // With no user settings, the global settings of a Maven of SDKMAN!.
    fs::remove_file(home.path.join(".m2/settings.xml")).unwrap();
    home.write(
        ".sdkman/candidates/maven/current/conf/settings.xml",
        b"<settings><localRepository>${user.home}/sdk-repo</localRepository></settings>",
    );
    downloaded("sdk-repo/io");
    let (roots, _) = resolve(
        &MAVEN_REPOSITORY,
        &home.path,
        &home.path.join("system"),
        &[],
    );
    assert_eq!(roots.len(), 1);
    assert_eq!(
        roots[0].path.as_deref(),
        Some(home.path.join("sdk-repo").as_path())
    );
    assert_eq!(
        roots[0].source,
        super::RootSource::Configuration {
            file: ".sdkman/candidates/maven/current/conf/settings.xml"
        }
    );
}

#[test]
fn nuget_refuses_a_package_with_a_local_or_unknown_source() {
    let home = Home::new();
    let metadata = |relative: &str, source: &str| {
        home.write(
            &format!(".nuget/packages/{relative}/.nupkg.metadata"),
            format!("{{\"version\": 2, \"contentHash\": \"x\", \"source\": \"{source}\"}}")
                .as_bytes(),
        );
    };
    metadata(
        "newtonsoft.json/13.0.1",
        "https://api.nuget.org/v3/index.json",
    );
    metadata("local.tool/1.0.0", "/Users/me/feed");
    // One version from the registry and one with no record.
    metadata("mixed/1.0.0", "https://api.nuget.org/v3/index.json");
    home.write(".nuget/packages/mixed/2.0.0/mixed.nuspec", b"<package/>");
    home.write(".nuget/packages/broken/1.0.0/.nupkg.metadata", b"not json");
    let root: PathBuf = home.path.join(".nuget/packages");
    let discovery: EvictionDiscovery = manual(&home, super::NUGET_PACKAGES.id);
    assert_eq!(
        candidates(&home, &discovery),
        [".nuget/packages/newtonsoft.json"]
    );
    for refused in ["local.tool", "mixed", "broken"] {
        assert_eq!(
            skip_reasons(&discovery, &root, refused),
            [SkipReason::ProtectedData],
            "{refused}"
        );
    }
}

#[test]
fn a_root_with_no_marker_of_its_producer_is_not_bound() {
    let home = Home::new();
    // `registry/cache` with no `registry/index` beside it.
    home.write(
        ".cargo/registry/cache/index.crates.io-1/a-1.0.0.crate",
        b"crate",
    );
    // A Zig cache with none of `h`, `o`, and `z`.
    home.write(".cache/zig/notes.txt", b"x");
    for (rule, root) in [
        (super::CARGO_REGISTRY.id, ".cargo/registry/cache"),
        (super::ZIG_GLOBAL_CACHE.id, ".cache/zig"),
    ] {
        let discovery: EvictionDiscovery = manual(&home, rule);
        assert_eq!(discovery.candidates.len(), 0, "{rule}");
        let report = discovery
            .roots
            .iter()
            .find(|report| report.path.as_deref() == Some(home.path.join(root).as_path()))
            .unwrap();
        assert_eq!(
            report.result,
            RootResult::Refused("clear_root_unmarked"),
            "{rule}"
        );
        assert!(!discovery.complete);
    }
}

#[test]
fn the_markers_of_each_rule_are_checked() {
    use super::{RootMarker, has_marker};
    let home = Home::new();
    let root: PathBuf = home.path.join("root");
    fs::create_dir_all(&root).unwrap();
    assert!(has_marker(RootMarker::None, &root));
    assert!(!has_marker(RootMarker::Sibling("index"), &root));
    fs::create_dir_all(home.path.join("index")).unwrap();
    assert!(has_marker(RootMarker::Sibling("index"), &root));
    assert!(!has_marker(RootMarker::AnyChild(&["h", "o"]), &root));
    home.write("root/o/a", b"x");
    assert!(has_marker(RootMarker::AnyChild(&["h", "o"]), &root));
    assert!(!has_marker(RootMarker::ChildNameContains("@"), &root));
    home.write("root/left-pad@1.3.0/index.js", b"x");
    assert!(has_marker(RootMarker::ChildNameContains("@"), &root));
    assert!(!has_marker(RootMarker::NuGetPackage, &root));
    home.write("root/pkg/1.0.0/.nupkg.metadata", b"{}");
    assert!(has_marker(RootMarker::NuGetPackage, &root));
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
    home.write(".gem/ruby/3.3.0/specifications/rake-13.0.gemspec", b"#");
    home.write(
        ".rbenv/versions/3.2.2/lib/ruby/gems/3.2.0/cache/json-2.gem",
        b"gem",
    );
    home.write(
        ".rbenv/versions/3.2.2/lib/ruby/gems/3.2.0/specifications/json-2.gemspec",
        b"#",
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
    let (roots, complete) = resolve(&RUBYGEMS_CACHE, &home.path, &home.path.join("system"), &[]);
    assert!(!complete);
    assert_eq!(roots.len(), super::MAX_EXPANDED_ROOTS);
    // The cut keeps the first versions in name order.
    let expected: Vec<PathBuf> = (0..super::MAX_EXPANDED_ROOTS)
        .map(|index| home.path.join(format!(".gem/ruby/{index:02}/cache")))
        .collect();
    let found: Vec<PathBuf> = roots.iter().filter_map(|root| root.path.clone()).collect();
    assert_eq!(found, expected);
    assert!(roots.iter().all(|root| {
        root.path
            .as_ref()
            .is_some_and(|path| !path.to_str().unwrap().contains("linked"))
    }));
}

#[test]
fn each_default_root_of_each_rule_is_below_the_home_directory() {
    for spec in &CLEAR_SPECS {
        let (roots, _) = resolve(
            spec,
            Path::new("/Users/test"),
            Path::new("/nonexistent-svalnir-system-root"),
            &[],
        );
        for root in roots {
            let path: PathBuf = root.path.unwrap();
            // The Ruby of Homebrew is the one default outside the home
            // directory.
            let homebrew: bool = spec.id == "rubygems.cache"
                && (path.starts_with("/opt/homebrew/lib/ruby/gems")
                    || path.starts_with("/usr/local/lib/ruby/gems"));
            assert!(homebrew || path.starts_with("/Users/test/"), "{}", spec.id);
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
    home.write(
        ".m2/repository/org/lib/1.0/_remote.repositories",
        b"lib-1.0.jar>central=\n",
    );
    let unit: PathBuf = root.join("org/lib");
    let check = |path: &Path| recheck_unit(&MAVEN_REPOSITORY, home.principal, &root, path);
    assert_eq!(check(&unit), UnitRecheck::Passed);
    // A local install in the unit after the plan.
    home.write(".m2/repository/org/lib/2.0/lib-2.0.jar", b"jar");
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
    home.write(
        ".nuget/packages/newtonsoft.json/13.0.1/.nupkg.metadata",
        b"{\"version\": 2, \"source\": \"https://api.nuget.org/v3/index.json\"}",
    );
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

// ---------------------------------------------------------------------
// Configured cache locations and the global cache of Yarn 2 and later
// ---------------------------------------------------------------------

/// The result of the root `root` in `discovery`.
fn root_result<'a>(discovery: &'a EvictionDiscovery, root: &Path) -> &'a RootResult {
    discovery
        .roots
        .iter()
        .find(|report| report.path.as_deref() == Some(root))
        .map_or_else(
            || panic!("no report of {}: {discovery:?}", root.display()),
            |report| &report.result,
        )
}

/// A manual discovery of `rule` with the configured locations `locations`.
fn manual_with(home: &Home, rule: &str, locations: &[PathBuf]) -> EvictionDiscovery {
    let mut host: DiscoveryHost = home.host();
    host.cache_locations = locations
        .iter()
        .map(|path| crate::rules::caches::CacheLocationEntry {
            rule: rule.to_owned(),
            path: path.clone(),
        })
        .collect();
    let cancel = CancellationToken::new();
    manual_registry().discover_for_eviction(
        &EvictionRequest {
            host: &host,
            purpose: &RuleMode::ManualEviction,
            rules: Some(&[RuleId::new(rule).unwrap()]),
            volumes: None,
            known: None,
            limits: DiscoveryLimits::default(),
            cancel: &cancel,
            projects: None,
        },
        &month_later(),
    )
}

#[test]
fn a_configured_location_adds_its_roots_beside_the_default() {
    let home = Home::new();
    home.write(".hex/packages/hexpm/jason-1.4.tar", b"tar");
    home.write("dev/hex/packages/hexpm/plug-1.0.tar", b"tar");
    let discovery: EvictionDiscovery =
        manual_with(&home, "hex.packages", &[home.path.join("dev/hex")]);
    // The path names the Hex home: the root is `packages` below it.
    assert_eq!(
        candidates(&home, &discovery),
        [".hex/packages/hexpm", "dev/hex/packages/hexpm"]
    );
    // Each root is reported, the default one too.
    for root in [".hex/packages", "dev/hex/packages"] {
        assert!(matches!(
            root_result(&discovery, &home.path.join(root)),
            RootResult::Examined { .. }
        ));
    }
    // Without the location only the default root has a candidate.
    assert_eq!(
        candidates(&home, &manual(&home, "hex.packages")),
        [".hex/packages/hexpm"]
    );
    // A rule with a list of roots below the location: Cargo home.
    home.write("cargo-home/registry/index/x/f", b"i");
    home.write("cargo-home/registry/cache/x/a.crate", b"c");
    home.write("cargo-home/registry/src/x/a-1/lib.rs", b"s");
    let discovery: EvictionDiscovery = manual_with(
        &home,
        "cargo.registry-cache",
        &[home.path.join("cargo-home")],
    );
    assert_eq!(
        candidates(&home, &discovery),
        ["cargo-home/registry/cache/x", "cargo-home/registry/src/x"]
    );
}

#[test]
fn a_configured_root_has_the_checks_of_a_default_root() {
    let home = Home::new();
    let location = |relative: &str| vec![home.path.join(relative)];
    // No marker of the producer.
    home.write("dev/hex/packages/other/file", b"x");
    let root: PathBuf = home.path.join("dev/hex/packages");
    let discovery = manual_with(&home, "hex.packages", &location("dev/hex"));
    assert_eq!(
        root_result(&discovery, &root),
        &RootResult::Refused("clear_root_unmarked")
    );
    assert!(!discovery.complete);
    assert_eq!(candidates(&home, &discovery), Vec::<String>::new());
    // A root that is a symbolic link is not bound.
    fs::create_dir_all(home.path.join("real/packages/hexpm")).unwrap();
    fs::create_dir(home.path.join("linked")).unwrap();
    std::os::unix::fs::symlink(
        home.path.join("real/packages"),
        home.path.join("linked/packages"),
    )
    .unwrap();
    let discovery = manual_with(&home, "hex.packages", &location("linked"));
    assert!(matches!(
        root_result(&discovery, &home.path.join("linked/packages")),
        RootResult::NotBound(_)
    ));
    // A location in a Git work tree gives no root.
    home.write("work/app/hex/packages/hexpm/a.tar", b"tar");
    fs::create_dir(home.path.join("work/app/.git")).unwrap();
    let discovery = manual_with(&home, "hex.packages", &location("work/app/hex"));
    assert_eq!(
        root_result(&discovery, &home.path.join("work/app/hex/packages")),
        &RootResult::Refused("configuration_in_work_tree")
    );
    assert_eq!(candidates(&home, &discovery), Vec::<String>::new());
    // A location outside the home directory under a directory that the
    // group can write.
    let outside: TempDir = TempDir::new().unwrap();
    let base: PathBuf = fs::canonicalize(outside.path()).unwrap();
    fs::create_dir_all(base.join("shared/hex/packages/hexpm")).unwrap();
    fs::write(base.join("shared/hex/packages/hexpm/a.tar"), b"tar").unwrap();
    let set_mode = |relative: &str, bits: u32| {
        fs::set_permissions(base.join(relative), fs::Permissions::from_mode(bits)).unwrap();
    };
    set_mode("", 0o755);
    set_mode("shared", 0o775);
    let discovery = manual_with(&home, "hex.packages", &[base.join("shared/hex")]);
    assert_eq!(
        root_result(&discovery, &base.join("shared/hex/packages")),
        &RootResult::Refused("root_ancestor_writable")
    );
    assert_eq!(candidates(&home, &discovery), Vec::<String>::new());
    // With the mode 0755 the root is examined.
    set_mode("shared", 0o755);
    let discovery = manual_with(&home, "hex.packages", &[base.join("shared/hex")]);
    assert!(matches!(
        root_result(&discovery, &base.join("shared/hex/packages")),
        RootResult::Examined { .. }
    ));
    // A location in the folder of a project with no Git.
    home.write("proj/hex/packages/hexpm/a.tar", b"tar");
    home.write("proj/Package.swift", b"");
    let discovery = manual_with(&home, "hex.packages", &location("proj/hex"));
    assert_eq!(
        root_result(&discovery, &home.path.join("proj/hex/packages")),
        &RootResult::Refused("root_in_project")
    );
    assert_eq!(candidates(&home, &discovery), Vec::<String>::new());
    // The home directory, a directory above it, and a protected location.
    // The catalog protects the home directory first, so its code is the
    // code of a protected location.
    for refused in [home.path.clone(), home.path.parent().unwrap().to_path_buf()] {
        let discovery = manual_with(&home, "bun.cache", std::slice::from_ref(&refused));
        assert!(matches!(
            root_result(&discovery, &refused),
            RootResult::Refused("root_protected" | "root_contains_home")
        ));
    }
    // The state directory of Svalnir is protected.
    let discovery = manual_with(&home, "bun.cache", std::slice::from_ref(&home.state));
    assert_eq!(
        root_result(&discovery, &home.state),
        &RootResult::Refused("root_protected")
    );
}

#[test]
fn a_rule_with_no_location_form_ignores_a_configured_location() {
    let home = Home::new();
    home.write("elsewhere/repositories/x/f", b"x");
    let discovery = manual_with(&home, "swiftpm.cache", &[home.path.join("elsewhere")]);
    assert!(
        discovery.roots.iter().all(|report| {
            report.path.as_deref() != Some(home.path.join("elsewhere").as_path())
        })
    );
}

#[test]
fn the_location_table_of_the_configuration_agrees_with_the_rules() {
    use svalnir_core::config::CACHE_LOCATION_RULES;

    let registry: ReviewedRules = ReviewedRules::new().unwrap();
    for (id, limit) in CACHE_LOCATION_RULES {
        let accepted: bool = match super::spec_of(id) {
            Some(spec) => spec.location != super::LocationForm::NotAccepted,
            None => registry
                .producer(id)
                .is_some_and(|rule| rule.spec().location != super::LocationForm::NotAccepted),
        };
        assert!(accepted, "{id}");
        // A rule with an owner operation acts on one scope root.
        assert_eq!(limit == 1, super::spec_of(id).is_none(), "{id}");
    }
    for spec in &CLEAR_SPECS {
        let listed: bool = CACHE_LOCATION_RULES.iter().any(|(id, _)| *id == spec.id);
        assert_eq!(
            listed,
            spec.location != super::LocationForm::NotAccepted,
            "{}",
            spec.id
        );
    }
    for producer in registry.producers() {
        let listed: bool = CACHE_LOCATION_RULES
            .iter()
            .any(|(id, _)| *id == producer.spec().id);
        assert_eq!(
            listed,
            producer.spec().location != super::LocationForm::NotAccepted,
            "{}",
            producer.spec().id
        );
    }
}

/// The root of the global cache of Yarn 2 and later, with the folders that
/// mark it.
fn berry_home() -> Home {
    let home = Home::new();
    fs::create_dir_all(home.path.join(".yarn/berry/index")).unwrap();
    fs::create_dir_all(home.path.join(".yarn/berry/metadata")).unwrap();
    home
}

#[test]
fn the_global_cache_of_yarn_berry_has_the_zip_files_as_units() {
    let home = berry_home();
    let root: PathBuf = home.path.join(".yarn/berry/cache");
    home.write(".yarn/berry/cache/left-pad-npm-1.3.0-abc-10.zip", b"zip");
    home.write(".yarn/berry/cache/@scope-pkg-npm-2.0.0-def-10.zip", b"zip");
    home.write(".yarn/berry/cache/notes.txt", b"text");
    fs::create_dir(root.join("folder.zip")).unwrap();
    std::os::unix::fs::symlink(home.path.join("outside.zip"), root.join("link.zip")).unwrap();
    let discovery: EvictionDiscovery = manual(&home, "yarn.berry-cache");
    assert_eq!(
        candidates(&home, &discovery),
        [
            ".yarn/berry/cache/@scope-pkg-npm-2.0.0-def-10.zip",
            ".yarn/berry/cache/left-pad-npm-1.3.0-abc-10.zip"
        ]
    );
    assert_eq!(
        skip_reasons(&discovery, &root, "link.zip"),
        [SkipReason::SymbolicLink]
    );
    assert_eq!(
        skip_reasons(&discovery, &root, "folder.zip"),
        [SkipReason::UnsupportedLayout]
    );
    assert_eq!(
        skip_reasons(&discovery, &root, "notes.txt"),
        [SkipReason::UnsupportedLayout]
    );
    // The folders beside the root stay: they are not in the root.
    assert!(home.path.join(".yarn/berry/index").is_dir());
}

#[test]
fn the_global_cache_of_yarn_berry_needs_both_folders_beside_it() {
    let home = berry_home();
    home.write(".yarn/berry/cache/a-npm-1.0.0-abc-10.zip", b"zip");
    fs::remove_dir(home.path.join(".yarn/berry/metadata")).unwrap();
    let root: PathBuf = home.path.join(".yarn/berry/cache");
    let discovery: EvictionDiscovery = manual(&home, "yarn.berry-cache");
    assert_eq!(
        root_result(&discovery, &root),
        &RootResult::Refused("clear_root_unmarked")
    );
    assert_eq!(candidates(&home, &discovery), Vec::<String>::new());
    // A Yarn global folder in another place, from the configuration.
    home.write("yarn-home/cache/b-npm-1.0.0-abc-10.zip", b"zip");
    fs::create_dir_all(home.path.join("yarn-home/index")).unwrap();
    fs::create_dir_all(home.path.join("yarn-home/metadata")).unwrap();
    let discovery = manual_with(&home, "yarn.berry-cache", &[home.path.join("yarn-home")]);
    assert_eq!(
        candidates(&home, &discovery),
        ["yarn-home/cache/b-npm-1.0.0-abc-10.zip"]
    );
}

#[test]
fn a_component_star_of_an_absolute_pattern_expands_below_the_root() {
    let home = Home::new();
    let base: PathBuf = home.path.join("prefix/lib/ruby/gems");
    fs::create_dir_all(base.join("4.0.0/cache")).unwrap();
    fs::create_dir_all(base.join("3.4.0")).unwrap();
    let pattern: String = format!("{}/*/cache", base.display());
    let (paths, complete) =
        super::expand(Path::new("/nonexistent-home"), Path::new("/"), &pattern, 8);
    assert!(complete);
    assert_eq!(paths, [base.join("4.0.0/cache")]);
}

#[test]
fn a_homebrew_gem_cache_has_regular_gem_files_only_as_units() {
    // The default root of the Ruby of Homebrew is below the system root,
    // which is a directory of the fixture here. Its cache has `.gem` files,
    // and symbolic links into the Cellar for the default gems.
    let home = Home::new();
    let gems: PathBuf = home.path.join("system/opt/homebrew/lib/ruby/gems/4.0.0");
    fs::create_dir_all(gems.join("specifications")).unwrap();
    fs::create_dir_all(gems.join("cache")).unwrap();
    fs::write(gems.join("cache/ffi-1.17.2.gem"), b"gem").unwrap();
    std::os::unix::fs::symlink(
        home.path.join("Cellar/ruby/cache/abbrev-0.1.2.gem"),
        gems.join("cache/abbrev-0.1.2.gem"),
    )
    .unwrap();
    let discovery = manual(&home, "rubygems.cache");
    assert_eq!(
        candidates(&home, &discovery),
        ["system/opt/homebrew/lib/ruby/gems/4.0.0/cache/ffi-1.17.2.gem"]
    );
    assert_eq!(
        skip_reasons(&discovery, &gems.join("cache"), "abbrev-0.1.2.gem"),
        [SkipReason::SymbolicLink]
    );
    // The same root with no `specifications` beside it is not a gem cache.
    fs::remove_dir(gems.join("specifications")).unwrap();
    let discovery = manual(&home, "rubygems.cache");
    assert_eq!(
        root_result(&discovery, &gems.join("cache")),
        &RootResult::Refused("clear_root_unmarked")
    );
}
