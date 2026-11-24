//! Fixture tests of the rules with an owner operation. Each test makes a
//! home directory in a temporary directory. No test runs a producer tool
//! or reads a cache of the host: the executable of a binding is a test
//! script of `/bin/sh` that the test writes.

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use svalnir_core::action::{Check, OwnerOperationBound, OwnerOperationKind, is_denied_environment};
use svalnir_core::process::Uid;
use svalnir_core::rule::owner::ParameterPart;
use svalnir_core::rule::{LifecycleState, RuleMode, RuleRegistry};
use tempfile::TempDir;

use super::{
    EXTENDED_RULE_REVISION, GuardOutcome, HOMEBREW_ENV_OVERRIDES, OWN_RULE_REVISION,
    OWNER_SCOPE_UNMARKED, PRODUCER_SPECS, Part, ProducerBindError, ProducerBindRequest,
    ProducerRule, homebrew_system_env, mise_tracked_configs, scope_evidence,
};
use crate::executor::owner::{ScopeLimits, examine_program};
use crate::protection::ProtectedLocations;
use crate::rules::ReviewedRules;
use crate::rules::caches::{CacheLocationEntry, InspectionHost, RootOutcome, RootResolution};
use crate::rules::fixture::{manual_action_validated, write_owner_script};
use crate::rules::owner_operation::{OwnerBindError, binding_agrees};
use crate::rules::owner_operation::{canonical_interpreters, canonical_locations};
use crate::scan::{CancellationToken, WallScanClock};

/// A home directory in a temporary directory, with a directory of test
/// scripts beside it.
struct Home {
    _directory: TempDir,
    path: PathBuf,
    tools: PathBuf,
    locations: ProtectedLocations,
    principal: Uid,
}

impl Home {
    fn new() -> Self {
        let directory: TempDir = TempDir::new().unwrap();
        let base: PathBuf = fs::canonicalize(directory.path()).unwrap();
        let path: PathBuf = base.join("home");
        let state: PathBuf = path.join("Library/Application Support/Svalnir");
        fs::create_dir_all(&state).unwrap();
        let tools: PathBuf = base.join("tools");
        fs::create_dir(&tools).unwrap();
        let principal: Uid = Uid::new(fs::metadata(&path).unwrap().uid());
        Self {
            locations: ProtectedLocations::from_resolved(Some(path.clone()), Some(state)),
            _directory: directory,
            path,
            tools,
            principal,
        }
    }

    fn write(&self, relative: &str, content: &[u8]) -> PathBuf {
        let path: PathBuf = self.path.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, content).unwrap();
        path
    }

    fn host(&self) -> InspectionHost<'_> {
        InspectionHost {
            principal: self.principal,
            locations: &self.locations,
            user_exclusions: &[],
            cache_locations: &[],
        }
    }

    /// The host with the configured location `path` of the rule `rule`.
    fn host_with<'a>(&'a self, entries: &'a [CacheLocationEntry]) -> InspectionHost<'a> {
        InspectionHost {
            cache_locations: entries,
            ..self.host()
        }
    }

    /// A registry whose rules with an owner operation have the test
    /// scripts of this home and a lifecycle state that permits a manual
    /// action.
    fn registry(&self) -> ReviewedRules {
        ReviewedRules::with_fixture_lifecycle(&manual_action_validated())
            .unwrap()
            .with_owner_fixture_executables(&self.tools)
            .unwrap()
    }

    fn request(&self, include_clear: bool) -> ProducerBindRequest<'_> {
        ProducerBindRequest {
            host: self.host(),
            include_clear,
            max_executable_bytes: 1 << 20,
            scope_limits: ScopeLimits::default(),
        }
    }
}

fn bind(
    rule: &ProducerRule,
    home: &Home,
    include_clear: bool,
) -> Result<super::ProducerBinding, ProducerBindError> {
    rule.bind(
        &home.request(include_clear),
        &CancellationToken::new(),
        &WallScanClock,
    )
}

#[test]
fn each_declaration_is_complete_and_has_fixed_arguments() {
    let registry: ReviewedRules = ReviewedRules::new().unwrap();
    assert_eq!(registry.producers().len(), PRODUCER_SPECS.len());
    for producer in registry.producers() {
        let spec = producer.spec();
        let operation = producer.operation();
        assert_eq!(operation.check(), Ok(()), "{}", spec.id);
        assert_eq!(operation.rule, producer.rule().reference, "{}", spec.id);
        // One command of the kind of the rule, with the bound of the
        // review.
        assert_eq!(operation.commands.len(), 1, "{}", spec.id);
        let command = operation.command(spec.kind).unwrap();
        assert_eq!(command.bound, spec.bound, "{}", spec.id);
        // Each argument is literal text or the scope root: no value of
        // user input and no home directory in the argument vector.
        assert!(
            command
                .arguments
                .iter()
                .all(|part| matches!(part, ParameterPart::Literal(_) | ParameterPart::ScopeRoot)),
            "{}",
            spec.id
        );
        // No environment name changes the code that a process loads, and
        // each command has `HOME` and the fixed `PATH`.
        for entry in &operation.environment {
            assert!(!is_denied_environment(&entry.name), "{}", spec.id);
        }
        let names: Vec<&str> = operation
            .environment
            .iter()
            .map(|entry| entry.name.as_str())
            .collect();
        assert!(
            names.contains(&"HOME") && names.contains(&"PATH"),
            "{}",
            spec.id
        );
        // The registry gives the declaration of the exact revision.
        assert_eq!(
            registry.owner_operation(&producer.rule().reference),
            Some(operation),
            "{}",
            spec.id
        );
        // The layout of the scope root is `proposed`, and the rule has the
        // mode of an owner operation and no automatic mode.
        assert_eq!(
            producer.layout().unwrap().lifecycle,
            LifecycleState::Proposed,
            "{}",
            spec.id
        );
        assert!(producer.rule().modes.contains(&RuleMode::ManualEviction));
        assert!(!producer.rule().modes.contains(&RuleMode::AutomaticEviction));
        let revision: &str = if producer.extends() {
            EXTENDED_RULE_REVISION
        } else {
            OWN_RULE_REVISION
        };
        assert_eq!(producer.rule().reference.revision.as_str(), revision);
        // Only `prune` can have the bound of an automatic plan, and only
        // `uv.cache` has it in this build.
        if spec.bound == OwnerOperationBound::WithinScope {
            assert_eq!(spec.kind, OwnerOperationKind::Prune);
            assert_eq!(spec.id, "uv.cache");
        }
    }
}

#[test]
fn one_identity_has_one_revision_and_the_cache_rules_have_the_new_revision() {
    let registry: ReviewedRules = ReviewedRules::new().unwrap();
    let rules = registry.rules();
    for producer in registry.producers() {
        let id: &str = producer.spec().id;
        let found: Vec<_> = rules
            .iter()
            .filter(|rule| rule.reference.id.as_str() == id)
            .collect();
        assert_eq!(found.len(), 1, "{id}");
        assert_eq!(found[0].reference, producer.rule().reference, "{id}");
    }
    // The inspection of a cache rule reads the new revision.
    let uv = registry.cache("uv.cache").unwrap();
    assert_eq!(
        uv.rule().reference.revision.as_str(),
        EXTENDED_RULE_REVISION
    );
    assert!(
        uv.rule()
            .layouts
            .iter()
            .any(|layout| layout.layout == "uv-cache")
    );
    assert!(
        uv.rule()
            .layouts
            .iter()
            .any(|layout| layout.layout == "uv-cache-root")
    );
    assert_eq!(
        registry
            .owner_tools()
            .homebrew()
            .reference
            .revision
            .as_str(),
        EXTENDED_RULE_REVISION
    );
}

#[test]
fn a_fixture_lifecycle_permits_only_the_manual_owner_operation() {
    let registry: ReviewedRules = ReviewedRules::with_fixture_lifecycle(
        &crate::rules::fixture::automatic_eviction_validated(),
    )
    .unwrap();
    for producer in registry.producers() {
        let layout = producer.layout().unwrap();
        assert!(
            layout.permits(&RuleMode::ManualEviction),
            "{}",
            layout.layout
        );
        assert!(!layout.permits(&RuleMode::AutomaticEviction));
        // The other layouts of a cache rule keep their state.
        for other in &producer.rule().layouts {
            if other.layout != layout.layout {
                assert_eq!(other.lifecycle, LifecycleState::Proposed);
            }
        }
    }
    // The cache module has the same declaration.
    let uv = registry.cache("uv.cache").unwrap().rule();
    assert_eq!(uv, registry.producer("uv.cache").unwrap().rule());
}

#[test]
fn the_scope_root_comes_from_the_configuration_of_the_producer() {
    let home = Home::new();
    let registry: ReviewedRules = ReviewedRules::new().unwrap();
    let uv = registry.producer("uv.cache").unwrap();
    // No file names a location: the root is the default, and it is absent.
    let report = uv.scope(&home.host());
    assert_eq!(report.resolution, RootResolution::Default);
    assert_eq!(report.path, Some(home.path.join(".cache/uv")));
    assert_eq!(report.outcome, RootOutcome::Absent);
    // The configuration names another location.
    home.write(".config/uv/uv.toml", b"cache-dir = \"~/uv-cache\"\n");
    fs::create_dir(home.path.join("uv-cache")).unwrap();
    // With no marker of uv, the directory is not a scope.
    assert_eq!(
        uv.scope(&home.host()).outcome,
        RootOutcome::Refused(OWNER_SCOPE_UNMARKED)
    );
    home.write(
        "uv-cache/CACHEDIR.TAG",
        b"Signature: 8a477f597d28d172789f06886806bc55\n",
    );
    let report = uv.scope(&home.host());
    assert!(matches!(
        report.resolution,
        RootResolution::Configured { .. }
    ));
    assert_eq!(report.path, Some(home.path.join("uv-cache")));
    assert_eq!(report.outcome, RootOutcome::Examined);
    assert!(report.bound.is_some());
    // A root that is a symbolic link is refused.
    fs::remove_dir_all(home.path.join("uv-cache")).unwrap();
    fs::create_dir(home.path.join("elsewhere")).unwrap();
    symlink(home.path.join("elsewhere"), home.path.join("uv-cache")).unwrap();
    assert!(matches!(
        uv.scope(&home.host()).outcome,
        RootOutcome::Refused(_)
    ));
}

#[test]
fn a_scope_root_in_a_project_or_at_the_home_directory_is_refused() {
    let home = Home::new();
    let registry: ReviewedRules = ReviewedRules::new().unwrap();
    let npm = registry.producer("npm.content-cache").unwrap();
    fs::create_dir_all(home.path.join("work/app/cache")).unwrap();
    fs::create_dir(home.path.join("work/app/.git")).unwrap();
    home.write(".npmrc", b"cache=~/work/app/cache\n");
    assert_eq!(
        npm.scope(&home.host()).outcome,
        RootOutcome::Refused("root_in_project")
    );
    home.write(".npmrc", b"cache=~/\n");
    assert!(matches!(
        npm.scope(&home.host()).outcome,
        RootOutcome::Refused(_) | RootOutcome::NoPath
    ));
}

#[test]
fn the_guard_of_mise_reads_each_tracked_configuration() {
    let home = Home::new();
    // No tracked-configs directory: mise tracks no file.
    assert_eq!(
        mise_tracked_configs(&home.path, home.principal),
        GuardOutcome::Passed { files: 0 }
    );
    let tracked: PathBuf = home.path.join(".local/state/mise/tracked-configs");
    fs::create_dir_all(&tracked).unwrap();
    let good: PathBuf = home.write("work/a/mise.toml", b"[tools]\nnode = \"22\"\n");
    let versions: PathBuf = home.write("work/b/.tool-versions", b"node 22\n");
    symlink(&good, tracked.join("a")).unwrap();
    symlink(&versions, tracked.join("b")).unwrap();
    // A link to a file that is absent in a directory that exists: mise
    // leaves the file of a removed project out.
    fs::create_dir_all(home.path.join("work/gone")).unwrap();
    symlink(home.path.join("work/gone/mise.toml"), tracked.join("c")).unwrap();
    assert_eq!(
        mise_tracked_configs(&home.path, home.principal),
        GuardOutcome::Passed { files: 2 }
    );
    // A file whose directory is absent can be on a volume that is not
    // mounted, so mise cannot load it: the guard refuses.
    let unmounted: PathBuf = PathBuf::from("/Volumes/svalnir-test-absent/app/mise.toml");
    symlink(&unmounted, tracked.join("v")).unwrap();
    assert_eq!(
        mise_tracked_configs(&home.path, home.principal),
        GuardOutcome::Refused {
            reason: "tracked_config_volume_absent",
            path: unmounted,
        }
    );
    fs::remove_file(tracked.join("v")).unwrap();
    // A file that does not parse protects no version, so the guard
    // refuses.
    let broken: PathBuf = home.write("work/d/mise.toml", b"[tools\nnode = 22\n");
    symlink(&broken, tracked.join("d")).unwrap();
    assert_eq!(
        mise_tracked_configs(&home.path, home.principal),
        GuardOutcome::Refused {
            reason: "tracked_config_not_loadable",
            path: broken,
        }
    );
}

#[test]
fn a_guard_that_refuses_gives_no_binding() {
    let home = Home::new();
    let registry: ReviewedRules = home.registry();
    write_owner_script(&home.tools, "mise", "exit 0").unwrap();
    fs::create_dir_all(home.path.join(".local/share/mise/installs/node/22")).unwrap();
    home.write(
        ".local/share/mise/installs/.mise-installs.toml",
        b"[node]\nshort = \"node\"\n",
    );
    let tracked: PathBuf = home.path.join(".local/state/mise/tracked-configs");
    fs::create_dir_all(&tracked).unwrap();
    let broken: PathBuf = home.write("work/mise.toml", b"tools = [\n");
    symlink(&broken, tracked.join("x")).unwrap();
    let installs = registry.producer("mise.installs").unwrap();
    assert!(matches!(
        bind(installs, &home, false),
        Err(ProducerBindError::Guard(GuardOutcome::Refused { .. }))
    ));
    fs::remove_file(tracked.join("x")).unwrap();
    let bound = bind(installs, &home, false).unwrap();
    assert_eq!(bound.binding.arguments, ["prune", "--tools", "--yes"]);
}

#[test]
fn a_binding_names_the_measured_root_and_admission_makes_it_again() {
    let home = Home::new();
    let registry: ReviewedRules = home.registry();
    let script: PathBuf = write_owner_script(&home.tools, "uv", "exit 0").unwrap();
    let root: PathBuf = home.path.join(".cache/uv");
    fs::create_dir_all(root.join("wheels-v5")).unwrap();
    fs::write(
        root.join("CACHEDIR.TAG"),
        b"Signature: 8a477f597d28d172789f06886806bc55\n",
    )
    .unwrap();
    fs::write(root.join("wheels-v5/pkg"), vec![1_u8; 4096]).unwrap();
    let uv = registry.producer("uv.cache").unwrap();
    let bound = bind(uv, &home, false).unwrap();
    let binding = bound.binding;
    assert_eq!(binding.executable.path.to_path_buf(), script);
    assert_eq!(
        binding.arguments,
        [
            "cache",
            "prune",
            "--no-config",
            "--cache-dir",
            root.to_str().unwrap()
        ]
    );
    assert_eq!(binding.layout, "uv-cache-root");
    assert_eq!(binding.bound, OwnerOperationBound::WithinScope);
    assert!(binding.measured.complete);
    assert!(binding.measured.entries.get() >= 2);
    assert_eq!(binding.working_directory.to_path_buf(), home.path);
    // The check of the coordinator at admission makes the same command
    // from the declaration of the registry.
    assert!(binding_agrees(&binding, uv.operation(), &home.path));
    // The declaration of a released build has other paths, so it does not
    // agree with the binding of the fixture script.
    let released: ReviewedRules = ReviewedRules::new().unwrap();
    assert!(!binding_agrees(
        &binding,
        released.producer("uv.cache").unwrap().operation(),
        &home.path
    ));
}

#[test]
fn a_clear_command_needs_include_clear() {
    let home = Home::new();
    let registry: ReviewedRules = home.registry();
    write_owner_script(&home.tools, "go", "exit 0").unwrap();
    let root: PathBuf = home.path.join("Library/Caches/go-build");
    fs::create_dir_all(&root).unwrap();
    fs::write(
        root.join("README"),
        b"This directory holds cached build artifacts from the Go build system.\n",
    )
    .unwrap();
    let go = registry.producer("go.build-cache").unwrap();
    assert_eq!(
        bind(go, &home, false),
        Err(ProducerBindError::ClearNotIncluded)
    );
    let bound = bind(go, &home, true).unwrap();
    assert!(bound.binding.clear_opt_in);
    assert_eq!(bound.binding.operation, OwnerOperationKind::Clear);
    assert!(
        bound
            .binding
            .environment
            .iter()
            .any(|entry| entry.name == "GOCACHE" && Path::new(&entry.value) == root)
    );
    assert!(
        bound
            .binding
            .environment
            .iter()
            .any(|entry| entry.name == "GOENV" && entry.value == "off")
    );
}

#[test]
fn a_missing_executable_or_an_absent_root_gives_no_binding() {
    let home = Home::new();
    let registry: ReviewedRules = home.registry();
    let pip = registry.producer("pip.cache").unwrap();
    // The root is absent.
    assert!(matches!(
        bind(pip, &home, true),
        Err(ProducerBindError::NoScope(report)) if report.outcome == RootOutcome::Absent
    ));
    fs::create_dir_all(home.path.join("Library/Caches/pip/http")).unwrap();
    // No executable is at the declared path.
    assert_eq!(
        bind(pip, &home, true),
        Err(ProducerBindError::Bind(OwnerBindError::ExecutableNotFound))
    );
    // A script whose interpreter is not declared is refused.
    let path: PathBuf = home.tools.join("pip3");
    fs::write(&path, "#!/bin/zsh\nexit 0\n").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        bind(pip, &home, true),
        Err(ProducerBindError::Bind(
            OwnerBindError::InterpreterNotDeclared
        ))
    );
}

#[test]
fn the_inspection_reports_the_executable_the_command_and_the_measurement() {
    let home = Home::new();
    let registry: ReviewedRules = home.registry();
    let script: PathBuf = write_owner_script(&home.tools, "pnpm", "exit 0").unwrap();
    let store: PathBuf = home.path.join("Library/pnpm/store");
    fs::create_dir_all(store.join("v10/files")).unwrap();
    fs::write(store.join("v10/files/a"), vec![2_u8; 8192]).unwrap();
    let pnpm = registry.producer("pnpm.content-store").unwrap();
    let inspection = pnpm.inspect(
        &home.host(),
        1 << 20,
        &CancellationToken::new(),
        &WallScanClock,
    );
    assert_eq!(inspection.program.executable.unwrap().to_path_buf(), script);
    assert!(inspection.program.interpreter.is_some());
    assert_eq!(inspection.scope.outcome, RootOutcome::Examined);
    assert_eq!(
        inspection.arguments,
        ["store", "prune", "--store-dir", store.to_str().unwrap()]
    );
    assert!(inspection.whole_cache);
    assert!(!inspection.needs_include_clear);
    assert!(inspection.measured.unwrap().complete);
    // A rule whose root is absent has the text of the parameter.
    let mise = registry.producer("mise.cache").unwrap().inspect(
        &home.host(),
        1 << 20,
        &CancellationToken::new(),
        &WallScanClock,
    );
    assert_eq!(mise.scope.outcome, RootOutcome::Absent);
    assert_eq!(mise.program.problem, Some("executable_not_found"));
    assert!(mise.measured.is_none());
    assert!(
        mise.environment
            .iter()
            .any(|entry| entry.name == "MISE_CACHE_DIR")
    );
}

#[test]
fn each_spec_names_the_scope_root_to_its_producer() {
    // The producer acts on the measured root only when the command names
    // it: in an argument or in the environment.
    for spec in PRODUCER_SPECS {
        let in_arguments: bool = spec.arguments.contains(&Part::ScopeRoot);
        let in_environment: bool = spec
            .environment
            .iter()
            .any(|(_, value)| *value == Part::ScopeRoot);
        // `mise.installs` acts on the default data directory of mise,
        // which is its root with the fixed environment.
        assert!(
            in_arguments || in_environment || spec.id == "mise.installs",
            "{}",
            spec.id
        );
    }
}

#[test]
fn the_owner_of_a_home_is_the_principal_of_the_fixture() {
    let home = Home::new();
    assert_eq!(
        fs::metadata(&home.path).unwrap().uid(),
        home.principal.get()
    );
}

#[test]
fn a_root_with_a_typing_error_is_never_a_scope() {
    // A configuration value names a directory of the user: the producer
    // command would empty it. With no marker of uv, no plan binds it.
    let home = Home::new();
    let registry: ReviewedRules = home.registry();
    write_owner_script(&home.tools, "uv", "exit 0").unwrap();
    home.write(".config/uv/uv.toml", b"cache-dir = \"~/code\"\n");
    let work: PathBuf = home.write("code/app/main.rs", b"fn main() {}\n");
    let uv = registry.producer("uv.cache").unwrap();
    assert!(matches!(
        bind(uv, &home, false),
        Err(ProducerBindError::NoScope(report))
            if report.outcome == RootOutcome::Refused(OWNER_SCOPE_UNMARKED)
    ));
    // The same for each other rule whose root is a plain directory.
    let go = registry.producer("go.module-cache").unwrap();
    fs::create_dir_all(home.path.join("go/pkg/mod/github.com")).unwrap();
    write_owner_script(&home.tools, "go", "exit 0").unwrap();
    assert!(matches!(
        bind(go, &home, true),
        Err(ProducerBindError::NoScope(report))
            if report.outcome == RootOutcome::Refused(OWNER_SCOPE_UNMARKED)
    ));
    assert!(work.exists());
    // The rule `mise.cache` needs the `.auto_prune` of mise in its root.
    fs::create_dir_all(home.path.join("Library/Caches/mise/node")).unwrap();
    let mise = registry.producer("mise.cache").unwrap();
    assert_eq!(
        mise.scope(&home.host()).outcome,
        RootOutcome::Refused(OWNER_SCOPE_UNMARKED)
    );
    // The directory form, as one host has it.
    fs::create_dir(home.path.join("Library/Caches/mise/.auto_prune")).unwrap();
    assert_eq!(mise.scope(&home.host()).outcome, RootOutcome::Examined);
    // The file form.
    fs::remove_dir(home.path.join("Library/Caches/mise/.auto_prune")).unwrap();
    home.write("Library/Caches/mise/.auto_prune", b"");
    assert_eq!(mise.scope(&home.host()).outcome, RootOutcome::Examined);
    // A symbolic link of that name is no marker.
    fs::remove_file(home.path.join("Library/Caches/mise/.auto_prune")).unwrap();
    symlink(
        &home.path,
        home.path.join("Library/Caches/mise/.auto_prune"),
    )
    .unwrap();
    assert_eq!(
        mise.scope(&home.host()).outcome,
        RootOutcome::Refused(OWNER_SCOPE_UNMARKED)
    );
}

/// A Mach-O executable that the checks of the owner executor accept.
fn native_program(home: &Home, relative: &str) -> PathBuf {
    let path: PathBuf = home.path.join(relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::copy("/bin/sh", &path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    path
}

#[test]
fn the_latest_installs_of_mise_are_executable_locations() {
    let home = Home::new();
    let registry: ReviewedRules = ReviewedRules::new().unwrap();
    let installs: PathBuf = home.path.join(".local/share/mise/installs");
    let link = |tool: &str| {
        symlink("1.0.0", installs.join(tool).join("latest")).unwrap();
    };
    // `npm` of the `latest` node: the script `npm-cli.js` with the `node`
    // of the same install as its interpreter.
    let node: PathBuf = native_program(&home, ".local/share/mise/installs/node/1.0.0/bin/node");
    let npm: PathBuf = home.write(
        ".local/share/mise/installs/node/1.0.0/lib/node_modules/npm/bin/npm-cli.js",
        b"#!/usr/bin/env node\nrequire('../lib/cli.js')\n",
    );
    fs::set_permissions(&npm, fs::Permissions::from_mode(0o755)).unwrap();
    link("node");
    let operation = registry.producer("npm.content-cache").unwrap().operation();
    // The host can have its own Node.js, which comes first in the sequence,
    // so the test reads the declared locations and binds the files directly.
    let located = canonical_locations(&operation.executables, &home.path);
    assert!(located.contains(&fs::canonicalize(&npm).unwrap()));
    let interpreters = canonical_interpreters(&operation.interpreters, &home.path);
    assert!(interpreters.contains(&(fs::canonicalize(&node).unwrap(), Vec::new())));
    // Another `node` comes first in the declared sequence, as the `node` of
    // Homebrew does: the script runs with the `node` of its own install.
    let other: PathBuf = native_program(&home, "other/bin/node");
    let mut declared = vec![(fs::canonicalize(&other).unwrap(), Vec::new())];
    declared.extend(interpreters.iter().cloned());
    let (executable, interpreter) = examine_program(
        &fs::canonicalize(&npm).unwrap(),
        &declared,
        home.principal,
        1 << 28,
    )
    .unwrap();
    assert_eq!(
        executable.path.to_path_buf(),
        fs::canonicalize(&npm).unwrap()
    );
    assert_eq!(
        interpreter.unwrap().executable.path.to_path_buf(),
        fs::canonicalize(&node).unwrap()
    );
    // With the real declared sequence, the binding is the same.
    let (_, interpreter) = examine_program(
        &fs::canonicalize(&npm).unwrap(),
        &interpreters,
        home.principal,
        1 << 28,
    )
    .unwrap();
    assert_eq!(
        interpreter.unwrap().executable.path.to_path_buf(),
        fs::canonicalize(&node).unwrap()
    );
    // The Bash wrapper `bin/npm` of that install is not a location.
    let wrapper: PathBuf = home.write(
        ".local/share/mise/installs/node/1.0.0/bin/npm",
        b"#!/usr/bin/env bash\nexit 0\n",
    );
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o755)).unwrap();
    for spec in PRODUCER_SPECS {
        for location in spec.executables {
            assert!(
                !matches!(location, crate::rules::caches::Location::Home(path) if path.ends_with("latest/bin/npm")
                    || path.ends_with("latest/bin/pip3")),
                "{}",
                spec.id
            );
        }
    }
    // `uv` of the `latest` install of mise is in the directory of its
    // archive.
    let uv: PathBuf = native_program(
        &home,
        ".local/share/mise/installs/uv/1.0.0/uv-aarch64-apple-darwin/uv",
    );
    link("uv");
    let operation = registry.producer("uv.cache").unwrap().operation();
    let located = canonical_locations(&operation.executables, &home.path);
    assert!(located.contains(&fs::canonicalize(&uv).unwrap()));
    let (_, interpreter) = examine_program(
        &fs::canonicalize(&uv).unwrap(),
        &[],
        home.principal,
        1 << 28,
    )
    .unwrap();
    assert!(interpreter.is_none());
}

#[test]
fn the_checks_at_admission_read_the_marker_and_the_guards_again() {
    let home = Home::new();
    let registry: ReviewedRules = home.registry();
    let root: PathBuf = home.path.join(".cache/uv");
    fs::create_dir_all(&root).unwrap();
    fs::write(
        root.join("CACHEDIR.TAG"),
        b"Signature: 8a477f597d28d172789f06886806bc55\n",
    )
    .unwrap();
    let rule = registry
        .producer("uv.cache")
        .unwrap()
        .rule()
        .reference
        .clone();
    assert_eq!(
        scope_evidence(&rule, &root, &home.path, home.principal),
        Ok(())
    );
    fs::remove_file(root.join("CACHEDIR.TAG")).unwrap();
    assert_eq!(
        scope_evidence(&rule, &root, &home.path, home.principal),
        Err(OWNER_SCOPE_UNMARKED)
    );
    // A rule that is not of this module, as the fixture rule, passes.
    let other = registry
        .cache("cocoapods.cache")
        .unwrap()
        .rule()
        .reference
        .clone();
    assert_eq!(
        scope_evidence(&other, &root, &home.path, home.principal),
        Ok(())
    );
}

#[test]
fn the_module_cache_is_below_the_first_path_of_gopath() {
    let home = Home::new();
    let registry: ReviewedRules = ReviewedRules::new().unwrap();
    let go = registry.producer("go.module-cache").unwrap();
    assert_eq!(
        go.scope(&home.host()).path,
        Some(home.path.join("go/pkg/mod"))
    );
    let first: PathBuf = home.path.join("work/gopath");
    let text: String = format!(
        "GOPATH={}:{}\n",
        first.display(),
        home.path.join("other").display()
    );
    home.write("Library/Application Support/go/env", text.as_bytes());
    let report = go.scope(&home.host());
    assert_eq!(report.path, Some(first.join("pkg/mod")));
    assert!(matches!(
        report.resolution,
        RootResolution::Configured { .. }
    ));
    // `GOMODCACHE` takes priority over `GOPATH`.
    let named: PathBuf = home.path.join("mods");
    home.write(
        "Library/Application Support/go/env",
        format!("{text}GOMODCACHE={}\n", named.display()).as_bytes(),
    );
    assert_eq!(go.scope(&home.host()).path, Some(named));
}

#[test]
fn a_system_brew_env_that_changes_the_effect_refuses_homebrew() {
    let home = Home::new();
    let absent: PathBuf = home.path.join("etc/absent/brew.env");
    assert_eq!(
        homebrew_system_env(std::slice::from_ref(&absent)),
        GuardOutcome::Passed { files: 0 }
    );
    let quiet: PathBuf = home.write("etc/quiet/brew.env", b"HOMEBREW_NO_EMOJI=1\n");
    assert_eq!(
        homebrew_system_env(&[absent.clone(), quiet.clone()]),
        GuardOutcome::Passed { files: 1 }
    );
    for line in [
        "HOMEBREW_CACHE=/tmp/elsewhere",
        "HOMEBREW_SYSTEM_ENV_TAKES_PRIORITY=1",
        "HOMEBREW_NO_INSTALL_CLEANUP=",
        "HOMEBREW_AUTOREMOVE=1",
    ] {
        let file: PathBuf = home.write("etc/loud/brew.env", format!("{line}\n").as_bytes());
        assert_eq!(
            homebrew_system_env(&[quiet.clone(), file.clone()]),
            GuardOutcome::Refused {
                reason: HOMEBREW_ENV_OVERRIDES,
                path: file,
            },
            "{line}"
        );
    }
    // The declaration has the fixed value that stops the autoremove.
    let registry: ReviewedRules = ReviewedRules::new().unwrap();
    let brew = registry.producer("homebrew.cleanup").unwrap().operation();
    assert!(
        brew.environment
            .iter()
            .any(|entry| entry.name == "HOMEBREW_NO_AUTOREMOVE")
    );
}

fn entry(rule: &str, path: PathBuf) -> CacheLocationEntry {
    CacheLocationEntry {
        rule: rule.to_owned(),
        path,
    }
}

#[test]
fn a_configured_location_is_the_scope_root_of_an_owner_rule() {
    let home = Home::new();
    let registry: ReviewedRules = home.registry();
    write_owner_script(&home.tools, "uv", "exit 0").unwrap();
    let uv = registry.producer("uv.cache").unwrap();
    // The default root exists and has its marker, and a configured location
    // takes its place as the scope root.
    let default: PathBuf = home.path.join(".cache/uv");
    fs::create_dir_all(&default).unwrap();
    let tag: &[u8] = b"Signature: 8a477f597d28d172789f06886806bc55\n";
    fs::write(default.join("CACHEDIR.TAG"), tag).unwrap();
    let configured: PathBuf = home.path.join("caches/uv");
    let entries = [entry("uv.cache", configured.clone())];
    // No marker: the existing code.
    fs::create_dir_all(&configured).unwrap();
    let report = uv.scope(&home.host_with(&entries));
    assert_eq!(report.resolution, RootResolution::ConfiguredLocation);
    assert_eq!(report.path, Some(configured.clone()));
    assert_eq!(report.outcome, RootOutcome::Refused(OWNER_SCOPE_UNMARKED));
    // With the marker, and the command names the configured root.
    fs::write(configured.join("CACHEDIR.TAG"), tag).unwrap();
    let request = ProducerBindRequest {
        host: home.host_with(&entries),
        include_clear: false,
        max_executable_bytes: 1 << 20,
        scope_limits: ScopeLimits::default(),
    };
    let bound = uv
        .bind(&request, &CancellationToken::new(), &WallScanClock)
        .unwrap();
    assert_eq!(bound.scope.outcome, RootOutcome::Examined);
    assert_eq!(
        bound.binding.arguments.last().unwrap(),
        configured.to_str().unwrap()
    );
    // The inspection shows the source.
    let inspection = uv.inspect(
        &home.host_with(&entries),
        1 << 20,
        &CancellationToken::new(),
        &WallScanClock,
    );
    assert_eq!(
        inspection.scope.resolution,
        RootResolution::ConfiguredLocation
    );
    // Without the entry the root is the default again.
    assert_eq!(uv.scope(&home.host()).path, Some(default));
}

#[test]
fn a_configured_location_of_an_owner_rule_has_each_check_of_a_root() {
    let home = Home::new();
    let registry: ReviewedRules = ReviewedRules::new().unwrap();
    let mise = registry.producer("mise.cache").unwrap();
    let scope = |path: &Path| {
        let entries = [entry("mise.cache", path.to_path_buf())];
        mise.scope(&home.host_with(&entries))
    };
    // A symbolic link.
    fs::create_dir_all(home.path.join("real/.auto_prune")).unwrap();
    symlink(home.path.join("real"), home.path.join("linked")).unwrap();
    assert_eq!(
        scope(&home.path.join("linked")).outcome,
        RootOutcome::Refused("root_not_directory")
    );
    // A Git work tree.
    fs::create_dir_all(home.path.join("work/app/cache/.auto_prune")).unwrap();
    fs::create_dir(home.path.join("work/app/.git")).unwrap();
    assert_eq!(
        scope(&home.path.join("work/app/cache")).outcome,
        RootOutcome::Refused("configuration_in_work_tree")
    );
    // A project folder with no Git.
    fs::create_dir_all(home.path.join("proj/cache/.auto_prune")).unwrap();
    fs::write(home.path.join("proj/package.json"), b"{}").unwrap();
    assert_eq!(
        scope(&home.path.join("proj/cache")).outcome,
        RootOutcome::Refused("root_in_project")
    );
    // A location outside the home directory under a directory that the
    // group can write.
    let outside: TempDir = TempDir::new().unwrap();
    let base: PathBuf = fs::canonicalize(outside.path()).unwrap();
    fs::create_dir_all(base.join("shared/cache/.auto_prune")).unwrap();
    fs::set_permissions(&base, fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(base.join("shared"), fs::Permissions::from_mode(0o775)).unwrap();
    assert_eq!(
        scope(&base.join("shared/cache")).outcome,
        RootOutcome::Refused("root_ancestor_writable")
    );
    fs::set_permissions(base.join("shared"), fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        scope(&base.join("shared/cache")).outcome,
        RootOutcome::Examined
    );
    // The home directory.
    assert!(matches!(
        scope(&home.path).outcome,
        RootOutcome::Refused("root_protected" | "root_contains_home")
    ));
    // A root that is absent is no error.
    assert_eq!(
        scope(&home.path.join("absent")).outcome,
        RootOutcome::Absent
    );
    // A rule whose command names no root takes no location.
    let installs = registry.producer("mise.installs").unwrap();
    let entries = [entry("mise.installs", home.path.join("real"))];
    assert_eq!(
        installs.scope(&home.host_with(&entries)).path,
        Some(home.path.join(".local/share/mise/installs"))
    );
}
