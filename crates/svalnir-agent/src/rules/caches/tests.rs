//! Fixture tests of the cache rules. Each test makes a home directory in
//! a temporary directory; no test reads or changes a cache of the host.

use std::fs;
use std::os::unix::fs::{MetadataExt, symlink};
use std::path::{Path, PathBuf};

use svalnir_core::process::Uid;
use svalnir_core::quantity::Bytes;
use svalnir_core::rule::{LifecycleState, RuleMode, RuleRefusal, RuleRegistry};
use tempfile::TempDir;

use super::config::{ConfigFormat, ConfigProblem, find_values};
use super::{
    CACHE_SPECS, CacheInspection, InspectionHost, InspectionLimits, ReclaimFigure, RootOutcome,
    RootResolution, UnitOutcome,
};
use crate::protection::ProtectedLocations;
use crate::rules::ReviewedRules;
use crate::rules::fixture::{automatic_eviction_validated, manual_action_validated};
use crate::scan::{CancellationToken, ScanCompletion, WallScanClock};

/// A home directory in a temporary directory.
struct Home {
    _directory: TempDir,
    path: PathBuf,
    locations: ProtectedLocations,
    principal: Uid,
}

impl Home {
    fn new() -> Self {
        let directory: TempDir = TempDir::new().unwrap();
        let path: PathBuf = fs::canonicalize(directory.path()).unwrap();
        let state: PathBuf = path.join("Library/Application Support/Svalnir");
        fs::create_dir_all(&state).unwrap();
        let principal: Uid = Uid::new(fs::metadata(&path).unwrap().uid());
        Self {
            locations: ProtectedLocations::from_resolved(Some(path.clone()), Some(state)),
            _directory: directory,
            path,
            principal,
        }
    }

    fn write(&self, relative: &str, content: &[u8]) -> PathBuf {
        let path: PathBuf = self.path.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, content).unwrap();
        path
    }

    fn directory(&self, relative: &str) -> PathBuf {
        let path: PathBuf = self.path.join(relative);
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn inspect_with(&self, id: &str, exclusions: &[PathBuf]) -> CacheInspection {
        let registry: ReviewedRules = ReviewedRules::new().unwrap();
        let host: InspectionHost<'_> = InspectionHost {
            principal: self.principal,
            locations: &self.locations,
            user_exclusions: exclusions,
        };
        registry.cache(id).unwrap().inspect(
            host,
            InspectionLimits::default(),
            &CancellationToken::new(),
            &WallScanClock,
        )
    }

    fn inspect(&self, id: &str) -> CacheInspection {
        self.inspect_with(id, &[])
    }
}

fn measured(outcome: &UnitOutcome) -> &super::CacheMeasurement {
    match outcome {
        UnitOutcome::Measured(measurement) => measurement,
        other => panic!("the unit was not measured: {other:?}"),
    }
}

const GO_README: &[u8] =
    b"This directory holds cached build artifacts from the Go build system.\nRun \"go clean -cache\" if the directory is getting too large.\n";
const UV_TAG: &[u8] =
    b"Signature: 8a477f597d28d172789f06886806bc55\n# This file is a cache directory tag.\n";

// ---------------------------------------------------------------------
// The registry.
// ---------------------------------------------------------------------

#[test]
fn each_cache_rule_is_registered_proposed_with_the_inspection_mode_only() {
    let registry: ReviewedRules = ReviewedRules::new().unwrap();
    assert_eq!(registry.caches().len(), 6);
    let ids: Vec<&str> = registry
        .caches()
        .iter()
        .map(|cache| cache.rule().reference.id.as_str())
        .collect();
    assert_eq!(
        ids,
        [
            "pnpm.content-store",
            "yarn.cache",
            "go.build-cache",
            "uv.cache",
            "homebrew.download-cache",
            "cocoapods.cache",
        ]
    );
    for cache in registry.caches() {
        let rule = cache.rule();
        assert_eq!(rule.modes, [RuleMode::Inspection]);
        assert!(registry.lookup(&rule.reference).is_ok());
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
    }
}

#[test]
fn a_fixture_lifecycle_does_not_change_a_cache_rule() {
    for state in [manual_action_validated(), automatic_eviction_validated()] {
        let registry: ReviewedRules = ReviewedRules::with_fixture_lifecycle(&state).unwrap();
        for cache in registry.caches() {
            for layout in &cache.rule().layouts {
                assert_eq!(layout.lifecycle, LifecycleState::Proposed);
                for mode in [RuleMode::ManualEviction, RuleMode::AutomaticEviction] {
                    assert!(!layout.lifecycle.permits(&mode));
                }
            }
        }
        // The other rules have the fixture state, so the registry of the
        // test is a registry of a fixture.
        assert!(
            registry
                .rules()
                .iter()
                .any(|rule| rule.layouts.iter().any(|layout| layout.lifecycle == state))
        );
    }
}

// ---------------------------------------------------------------------
// The configuration files.
// ---------------------------------------------------------------------

fn one(text: &str, format: ConfigFormat, key: &str) -> Vec<String> {
    find_values(text, format, key)
}

#[test]
fn each_format_gives_the_top_level_values_of_its_key() {
    let ini = "\u{feff}; comment\nstore-dir = ~/a ; moved\nstore-dir=\"~/b;c\"\n[section]\nstore-dir=~/c\n";
    assert_eq!(one(ini, ConfigFormat::Ini, "store-dir"), ["~/a", "~/b;c"]);
    let yarnrc = "# yarn\n\"cache-folder\" \"/caches/yarn\"\nlastUpdateCheck 1\n";
    assert_eq!(
        one(yarnrc, ConfigFormat::SpaceSeparated, "cache-folder"),
        ["/caches/yarn"]
    );
    let yaml = "npmScopes:\n  globalFolder: /nested\nglobalFolder: /berry\t# comment\n";
    assert_eq!(
        one(yaml, ConfigFormat::YamlTopLevel, "globalFolder"),
        ["/berry"]
    );
    let toml = "\"cache-dir\" = \"/caches/uv\" # comment\n[pip]\ncache-dir = \"/other\"\n";
    assert_eq!(
        one(toml, ConfigFormat::TomlTopLevel, "cache-dir"),
        ["/caches/uv"]
    );
    let env = "GOPROXY=direct\nGOCACHE=/caches/go\n";
    assert_eq!(
        one(env, ConfigFormat::Assignment, "GOCACHE"),
        ["/caches/go"]
    );
    assert_eq!(
        one(env, ConfigFormat::Assignment, "GOMODCACHE"),
        Vec::<String>::new()
    );
}

#[test]
fn a_key_with_two_different_values_in_one_file_gives_no_root() {
    let home = Home::new();
    home.write(
        "Library/Application Support/go/env",
        b"GOCACHE=/caches/one\nGOCACHE=/caches/two\n",
    );
    let root = &home.inspect("go.build-cache").roots[0];
    assert_eq!(
        root.resolution,
        RootResolution::NotResolved {
            file: home.path.join("Library/Application Support/go/env"),
            key: "GOCACHE",
            problem: ConfigProblem::Conflicting,
        }
    );
}

#[test]
fn an_empty_gopath_is_the_default_and_does_not_refuse_the_root() {
    let home = Home::new();
    home.write("Library/Application Support/go/env", b"GOPATH=\n");
    home.write("Library/Caches/go-build/README", GO_README);
    let root = &home.inspect("go.build-cache").roots[0];
    assert_eq!(root.outcome, RootOutcome::Examined);
}

#[test]
fn a_configuration_file_below_a_symbolic_link_is_not_read() {
    let home = Home::new();
    home.write("dotfiles/uv/uv.toml", b"cache-dir = \"~/elsewhere\"\n");
    symlink(home.path.join("dotfiles"), home.path.join(".config")).unwrap();
    let root = &home.inspect("uv.cache").roots[0];
    assert_eq!(
        root.resolution,
        RootResolution::NotResolved {
            file: home.path.join(".config/uv/uv.toml"),
            key: "cache-dir",
            problem: ConfigProblem::FileNotReadable,
        }
    );
    assert_eq!(root.outcome, RootOutcome::NoPath);
}

#[test]
fn a_tool_that_is_not_installed_has_its_default_root_absent() {
    let home = Home::new();
    for spec in &CACHE_SPECS {
        let inspection = home.inspect(spec.id);
        for layout in &inspection.layouts {
            assert_eq!(layout.lifecycle, LifecycleState::Proposed);
        }
        assert_ne!(inspection.owner_workflow, "");
        for (report, root) in inspection.roots.iter().zip(spec.roots) {
            assert_eq!(report.resolution, RootResolution::Default, "{}", spec.id);
            assert_eq!(
                report.path.as_deref(),
                Some(home.path.join(root.default).as_path())
            );
            assert_eq!(report.outcome, RootOutcome::Absent, "{}", spec.id);
            assert_eq!(report.units, []);
        }
    }
}

#[test]
fn a_configured_pnpm_store_is_measured_with_no_reclaim_figure() {
    let home = Home::new();
    home.write(
        ".npmrc",
        b"registry=https://registry.example\nstore-dir=~/stores/pnpm\n",
    );
    home.write("stores/pnpm/v10/files/00/content", &[7_u8; 4096]);
    home.directory("stores/pnpm/v10/index");
    let inspection = home.inspect("pnpm.content-store");
    let root = &inspection.roots[0];
    assert_eq!(
        root.resolution,
        RootResolution::Configured {
            file: home.path.join(".npmrc"),
            key: "store-dir",
        }
    );
    assert_eq!(
        root.path.as_deref(),
        Some(home.path.join("stores/pnpm").as_path())
    );
    assert_eq!(root.outcome, RootOutcome::Examined);
    let v10 = measured(&root.units[0].outcome);
    assert_eq!(root.units[0].layout, "pnpm-store-v10");
    assert_eq!(v10.files.get(), 1);
    assert_eq!(v10.logical_bytes, Bytes::new(4096));
    assert_eq!(v10.completion, ScanCompletion::Finished);
    // Hard links and clones into projects: the logical size and the
    // allocated size are not a reclaim figure.
    assert_eq!(v10.reclaim, ReclaimFigure::NotKnownLinkedIntoProjects);
    // The store of version 3 is not there.
    assert_eq!(root.units[1].outcome, UnitOutcome::Absent);
}

#[test]
fn a_pnpm_unit_with_no_marker_is_not_measured() {
    let home = Home::new();
    home.write("Library/pnpm/store/v10/other", b"x");
    let inspection = home.inspect("pnpm.content-store");
    assert_eq!(inspection.roots[0].outcome, RootOutcome::Examined);
    assert_eq!(
        inspection.roots[0].units[0].outcome,
        UnitOutcome::UnsupportedLayout
    );
}

#[test]
fn two_configuration_files_with_different_locations_give_no_root() {
    let home = Home::new();
    home.write("Library/Preferences/pnpm/rc", b"store-dir=~/one\n");
    home.write(".npmrc", b"store-dir=~/two\n");
    home.directory("Library/pnpm/store/v10/files");
    let root = &home.inspect("pnpm.content-store").roots[0];
    assert_eq!(
        root.resolution,
        RootResolution::NotResolved {
            file: home.path.join("Library/Preferences/pnpm/rc"),
            key: "store-dir",
            problem: ConfigProblem::Conflicting,
        }
    );
    // The default is not used in place of a configured location.
    assert_eq!(root.path, None);
    assert_eq!(root.outcome, RootOutcome::NoPath);
}

#[test]
fn a_value_with_a_substitution_or_a_relative_path_is_not_supported() {
    for value in [
        "$HOME/store",
        "${XDG_DATA_HOME}/pnpm",
        "`whoami`",
        "relative/store",
        "~/../x",
    ] {
        let home = Home::new();
        home.write(".npmrc", format!("store-dir={value}\n").as_bytes());
        let root = &home.inspect("pnpm.content-store").roots[0];
        assert_eq!(
            root.resolution,
            RootResolution::NotResolved {
                file: home.path.join(".npmrc"),
                key: "store-dir",
                problem: ConfigProblem::ValueNotSupported,
            },
            "{value}"
        );
        assert_eq!(root.outcome, RootOutcome::NoPath);
    }
}

#[test]
fn a_configuration_file_that_is_a_symbolic_link_is_not_read() {
    let home = Home::new();
    let target: PathBuf = home.write("dotfiles/npmrc", b"store-dir=~/stores/pnpm\n");
    symlink(&target, home.path.join(".npmrc")).unwrap();
    let root = &home.inspect("pnpm.content-store").roots[0];
    assert_eq!(
        root.resolution,
        RootResolution::NotResolved {
            file: home.path.join(".npmrc"),
            key: "store-dir",
            problem: ConfigProblem::FileNotReadable,
        }
    );
}

// ---------------------------------------------------------------------
// The roots.
// ---------------------------------------------------------------------

#[test]
fn a_root_that_is_a_symbolic_link_is_refused() {
    let home = Home::new();
    let elsewhere: PathBuf = home.directory("elsewhere/Homebrew");
    fs::create_dir_all(elsewhere.join("downloads")).unwrap();
    home.directory("Library/Caches");
    symlink(&elsewhere, home.path.join("Library/Caches/Homebrew")).unwrap();
    let root = &home.inspect("homebrew.download-cache").roots[0];
    assert_eq!(root.outcome, RootOutcome::Refused("root_not_directory"));
    assert_eq!(root.units, []);
}

#[test]
fn a_root_below_a_symbolic_link_is_refused() {
    let home = Home::new();
    home.directory("real/caches/CocoaPods/Pods");
    symlink(home.path.join("real/caches"), home.path.join("linked")).unwrap();
    home.write(
        ".cocoapods/config.yaml",
        b"cache_root: ~/linked/CocoaPods\n",
    );
    let root = &home.inspect("cocoapods.cache").roots[0];
    assert_eq!(root.outcome, RootOutcome::Refused("root_path_not_plain"));
}

#[test]
fn the_go_build_cache_is_measured_and_the_cache_off_has_no_root() {
    let home = Home::new();
    home.write("Library/Caches/go-build/README", GO_README);
    home.write("Library/Caches/go-build/ab/abcdef-a", &[1_u8; 2048]);
    let inspection = home.inspect("go.build-cache");
    let root = &inspection.roots[0];
    assert_eq!(root.resolution, RootResolution::Default);
    let unit = measured(&root.units[0].outcome);
    assert_eq!(unit.files.get(), 2);
    assert!(matches!(
        unit.reclaim,
        ReclaimFigure::AllocatedUpperBound { .. }
    ));

    home.write("Library/Application Support/go/env", b"GOCACHE=off\n");
    let root = &home.inspect("go.build-cache").roots[0];
    assert_eq!(
        root.resolution,
        RootResolution::Disabled {
            file: home.path.join("Library/Application Support/go/env"),
            key: "GOCACHE",
        }
    );
    assert_eq!(root.outcome, RootOutcome::NoPath);
}

#[test]
fn a_go_cache_with_no_readme_has_no_supported_layout() {
    let home = Home::new();
    home.write("Library/Caches/go-build/README", b"Something else.\n");
    let root = &home.inspect("go.build-cache").roots[0];
    assert_eq!(root.units[0].outcome, UnitOutcome::UnsupportedLayout);
}

#[test]
fn a_go_cache_in_the_module_cache_or_gopath_is_refused() {
    let home = Home::new();
    let env: &str = "Library/Application Support/go/env";
    // Go does not expand `~`.
    home.write(env, b"GOCACHE=~/go-build\n");
    assert_eq!(
        home.inspect("go.build-cache").roots[0].resolution,
        RootResolution::NotResolved {
            file: home.path.join(env),
            key: "GOCACHE",
            problem: ConfigProblem::ValueNotSupported,
        }
    );
    // In the default module cache.
    let in_modules: PathBuf = home.path.join("go/pkg/mod/cache/build");
    home.write(
        env,
        format!("GOCACHE={}\n", in_modules.display()).as_bytes(),
    );
    home.write("go/pkg/mod/cache/build/README", GO_README);
    assert_eq!(
        home.inspect("go.build-cache").roots[0].outcome,
        RootOutcome::Refused("root_overlaps_excluded")
    );
    // A GOPATH entry of a list that contains the cache.
    let gopath: PathBuf = home.path.join("work");
    let cache: PathBuf = gopath.join("src");
    home.write(
        env,
        format!(
            "GOPATH=/nonexistent/gopath:{}\nGOCACHE={}\n",
            gopath.display(),
            cache.display()
        )
        .as_bytes(),
    );
    home.write("work/src/README", GO_README);
    assert_eq!(
        home.inspect("go.build-cache").roots[0].outcome,
        RootOutcome::Refused("root_overlaps_excluded")
    );
    // A configured module cache that the cache contains.
    let modules: PathBuf = home.path.join("caches/go/mod");
    home.write(
        env,
        format!(
            "GOMODCACHE={}\nGOCACHE={}\n",
            modules.display(),
            home.path.join("caches/go").display()
        )
        .as_bytes(),
    );
    home.write("caches/go/README", GO_README);
    assert_eq!(
        home.inspect("go.build-cache").roots[0].outcome,
        RootOutcome::Refused("root_overlaps_excluded")
    );
}

#[test]
fn a_yarn_cache_in_a_project_is_refused() {
    let home = Home::new();
    home.write("projects/app/package.json", b"{}");
    home.directory("projects/app/.yarn/cache");
    home.write(
        ".yarnrc.yml",
        format!(
            "globalFolder: {}\n",
            home.path.join("projects/app/.yarn").display()
        )
        .as_bytes(),
    );
    let inspection = home.inspect("yarn.cache");
    // The root of Yarn 1 is the default and is absent.
    assert_eq!(inspection.roots[0].outcome, RootOutcome::Absent);
    assert_eq!(
        inspection.roots[1].outcome,
        RootOutcome::Refused("root_in_project")
    );
}

#[test]
fn the_two_yarn_caches_are_measured_with_their_layouts() {
    let home = Home::new();
    home.write(
        "Library/Caches/Yarn/v6/npm-left-pad-1.3.0/package.json",
        b"{}",
    );
    home.write(".yarn/berry/cache/left-pad-npm-1.3.0-abc.zip", &[0_u8; 512]);
    let inspection = home.inspect("yarn.cache");
    assert_eq!(inspection.roots[0].units[0].layout, "yarn-classic-v6");
    assert_eq!(
        measured(&inspection.roots[0].units[0].outcome).files.get(),
        1
    );
    assert_eq!(
        inspection.roots[1].units[0].layout,
        "yarn-berry-global-cache"
    );
    let berry = measured(&inspection.roots[1].units[0].outcome);
    assert_eq!(berry.logical_bytes, Bytes::new(512));
}

#[test]
fn a_yarn_unit_with_a_project_marker_is_refused() {
    let home = Home::new();
    // A package below the unit is cache content; a marker in the unit
    // itself shows a project.
    home.write("Library/Caches/Yarn/v6/package.json", b"{}");
    let inspection = home.inspect("yarn.cache");
    assert_eq!(
        inspection.roots[0].units[0].outcome,
        UnitOutcome::Refused {
            reason: "unit_in_project"
        }
    );
}

#[test]
fn the_homebrew_rule_measures_the_downloads_only() {
    let home = Home::new();
    home.write(
        "Library/Caches/Homebrew/downloads/abc--wget-1.0.bottle.tar.gz",
        &[2_u8; 1024],
    );
    home.write(
        "Library/Caches/Homebrew/api/formula.jws.json",
        &[3_u8; 8192],
    );
    let root = &home.inspect("homebrew.download-cache").roots[0];
    let downloads = measured(&root.units[0].outcome);
    assert_eq!(
        root.units[0].path,
        home.path.join("Library/Caches/Homebrew/downloads")
    );
    assert_eq!(downloads.files.get(), 1);
    assert_eq!(downloads.logical_bytes, Bytes::new(1024));
}

#[test]
fn a_homebrew_cache_in_a_prefix_is_refused_before_a_call_on_it() {
    let home = Home::new();
    for cache in [
        "/usr/local",
        "/usr/local/Homebrew/cache",
        "/opt/homebrew/cache",
    ] {
        home.write(
            ".homebrew/brew.env",
            format!("HOMEBREW_CACHE={cache}\n").as_bytes(),
        );
        assert_eq!(
            home.inspect("homebrew.download-cache").roots[0].outcome,
            RootOutcome::Refused("root_overlaps_excluded"),
            "{cache}"
        );
    }
}

#[test]
fn a_cocoapods_cache_in_the_cocoapods_home_is_refused() {
    let home = Home::new();
    home.directory(".cocoapods/repos/trunk");
    home.directory(".cocoapods/cache/Pods");
    home.write(
        ".cocoapods/config.yaml",
        b"cache_root: ~/.cocoapods/cache\n",
    );
    assert_eq!(
        home.inspect("cocoapods.cache").roots[0].outcome,
        RootOutcome::Refused("root_overlaps_excluded")
    );
}

#[test]
fn the_uv_cache_is_measured_with_no_reclaim_figure() {
    let home = Home::new();
    home.write(".cache/uv/CACHEDIR.TAG", UV_TAG);
    let wheel: PathBuf = home.write(".cache/uv/archive-v0/abc/pkg/__init__.py", &[4_u8; 1000]);
    // An environment that has a hard link to the cache file.
    let environment: PathBuf = home.directory("project/.venv/lib");
    fs::hard_link(&wheel, environment.join("__init__.py")).unwrap();
    let root = &home.inspect("uv.cache").roots[0];
    let unit = measured(&root.units[0].outcome);
    assert_eq!(unit.reclaim, ReclaimFigure::NotKnownLinkedIntoProjects);
    assert!(unit.logical_bytes.get() >= 1000);
}

#[test]
fn a_uv_cache_that_holds_the_managed_pythons_is_refused() {
    let home = Home::new();
    home.write(".config/uv/uv.toml", b"cache-dir = \"~/.local/share/uv\"\n");
    home.write(".local/share/uv/CACHEDIR.TAG", UV_TAG);
    assert_eq!(
        home.inspect("uv.cache").roots[0].outcome,
        RootOutcome::Refused("root_overlaps_excluded")
    );
}

#[test]
fn a_root_that_contains_the_state_directory_or_the_home_is_refused() {
    let home = Home::new();
    // The home directory itself.
    home.write(
        ".config/uv/uv.toml",
        format!("cache-dir = \"{}\"\n", home.path.display()).as_bytes(),
    );
    assert_eq!(
        home.inspect("uv.cache").roots[0].outcome,
        RootOutcome::Refused("root_protected")
    );
    // A root that contains the state directory of Svalnir.
    home.write(
        ".config/uv/uv.toml",
        b"cache-dir = \"~/Library/Application Support\"\n",
    );
    assert_eq!(
        home.inspect("uv.cache").roots[0].outcome,
        RootOutcome::Refused("root_protected")
    );
}

#[test]
fn a_user_exclusion_keeps_a_unit_from_the_measurement() {
    let home = Home::new();
    let downloads: PathBuf = home.directory("Library/Caches/Homebrew/downloads");
    let inspection = home.inspect_with("homebrew.download-cache", &[downloads]);
    assert_eq!(
        inspection.roots[0].units[0].outcome,
        UnitOutcome::Refused {
            reason: "unit_excluded"
        }
    );
}

#[test]
fn an_unknown_home_directory_gives_no_root() {
    let registry: ReviewedRules = ReviewedRules::new().unwrap();
    let locations: ProtectedLocations = ProtectedLocations::default();
    let host: InspectionHost<'_> = InspectionHost {
        principal: Uid::new(0),
        locations: &locations,
        user_exclusions: &[],
    };
    for cache in registry.caches() {
        let inspection = cache.inspect(
            host,
            InspectionLimits::default(),
            &CancellationToken::new(),
            &WallScanClock,
        );
        for root in &inspection.roots {
            assert_eq!(root.resolution, RootResolution::HomeUnknown);
            assert_eq!(root.outcome, RootOutcome::NoPath);
        }
    }
}

#[test]
fn the_inspection_changes_nothing_in_the_home_directory() {
    let home = Home::new();
    home.write(".cache/uv/CACHEDIR.TAG", UV_TAG);
    home.write("Library/Caches/go-build/README", GO_README);
    home.write("Library/Caches/Homebrew/downloads/a", b"a");
    let before: Vec<(PathBuf, u64, i64)> = listing(&home.path);
    for spec in &CACHE_SPECS {
        home.inspect(spec.id);
    }
    assert_eq!(listing(&home.path), before);
}

/// Each path below `root` with its size and its modification time.
fn listing(root: &Path) -> Vec<(PathBuf, u64, i64)> {
    let mut entries: Vec<(PathBuf, u64, i64)> = Vec::new();
    let mut pending: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).unwrap() {
            let path: PathBuf = entry.unwrap().path();
            let metadata = fs::symlink_metadata(&path).unwrap();
            if metadata.is_dir() {
                pending.push(path.clone());
            }
            entries.push((path, metadata.size(), metadata.mtime()));
        }
    }
    entries.sort();
    entries
}
