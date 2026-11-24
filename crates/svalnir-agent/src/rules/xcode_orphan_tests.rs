//! Tests of the layout `derived-data-orphan-v1` of
//! `xcode.inactive-derived-data`: a project directory whose project is
//! gone.
//!
//! Each test makes its files in a temporary directory that it created. The
//! process evidence comes from a fixture; no test reads a real
//! `DerivedData` root.

use std::fs;
use std::path::{Path, PathBuf};

use svalnir_core::id::RuleId;
use svalnir_core::process::Uid;
use svalnir_core::rule::{LifecycleState, RuleMode};
use tempfile::TempDir;

use super::eviction::{
    DiscoveryEnvironment as _, DiscoveryHost, EvictionDiscovery, EvictionRequest, RootResult,
};
use super::fixture::{
    FixtureEnvironment, automatic_eviction_validated, derived_data_root, manual_action_validated,
    write_project, write_workspace,
};
use super::model::{DiscoveryLimits, SkipReason};
use super::projects::UnitRecheck;
use super::registry::ReviewedRules;
use super::xcode::{
    UNIT_PATHS, XCODE_DERIVED_DATA_LAYOUT, XCODE_DERIVED_DATA_RULE_ID, XCODE_ORPHAN_LAYOUT,
    recheck_orphan,
};
use crate::protection::ProtectedLocations;
use crate::scan::CancellationToken;

const PROJECT: &str = "App-abcdefghijklmnopqrstuvwxyzab";

struct Tree {
    _directory: TempDir,
    base: PathBuf,
    home: PathBuf,
    state: PathBuf,
    root: PathBuf,
    principal: Uid,
}

impl Tree {
    fn new() -> Self {
        use std::os::unix::fs::MetadataExt as _;

        let directory: TempDir = tempfile::tempdir().unwrap();
        let base: PathBuf = fs::canonicalize(directory.path()).unwrap();
        let home: PathBuf = base.join("home");
        let state: PathBuf = home.join("Library/Application Support/Svalnir");
        let root: PathBuf = derived_data_root(&home);
        fs::create_dir_all(&state).unwrap();
        fs::create_dir_all(&root).unwrap();
        let principal: Uid = Uid::new(fs::metadata(&root).unwrap().uid());
        Self {
            _directory: directory,
            base,
            home,
            state,
            root,
            principal,
        }
    }

    /// A project directory whose workspace was made and then removed.
    fn orphan(&self) -> PathBuf {
        let workspace: PathBuf = write_workspace(&self.base.join("src"), "App").unwrap();
        let project: PathBuf = write_project(&self.root, PROJECT, &workspace).unwrap();
        fs::remove_dir_all(self.base.join("src")).unwrap();
        project
    }

    fn host(&self) -> DiscoveryHost {
        DiscoveryHost {
            principal: self.principal,
            locations: ProtectedLocations::resolve(Some(&self.home), Some(&self.state)),
            user_exclusions: Vec::new(),
            cache_locations: Vec::new(),
            system_root: PathBuf::from("/nonexistent-svalnir-system-root"),
        }
    }

    fn discover(&self, registry: &ReviewedRules, purpose: &RuleMode) -> EvictionDiscovery {
        let cancel = CancellationToken::new();
        let host: DiscoveryHost = self.host();
        registry.discover_for_eviction(
            &EvictionRequest {
                host: &host,
                purpose,
                rules: Some(&[RuleId::new(XCODE_DERIVED_DATA_RULE_ID).unwrap()]),
                volumes: None,
                known: None,
                limits: DiscoveryLimits::default(),
                cancel: &cancel,
                projects: None,
            },
            &FixtureEnvironment::days_later(30),
        )
    }
}

fn manual_registry() -> ReviewedRules {
    ReviewedRules::with_fixture_lifecycle(&manual_action_validated()).unwrap()
}

fn skipped(discovery: &EvictionDiscovery) -> Vec<(String, Option<String>, Vec<SkipReason>)> {
    discovery
        .roots
        .iter()
        .flat_map(|report| match &report.result {
            RootResult::Examined { skipped, .. } => skipped.clone(),
            _ => Vec::new(),
        })
        .map(|unit| {
            (
                unit.relative_entry.as_utf8().unwrap().to_owned(),
                unit.layout,
                unit.reasons,
            )
        })
        .collect()
}

#[test]
fn a_project_directory_whose_project_is_gone_is_one_orphan_candidate() {
    let tree = Tree::new();
    tree.orphan();
    let discovery: EvictionDiscovery = tree.discover(&manual_registry(), &RuleMode::ManualEviction);
    assert_eq!(discovery.candidates.len(), 1, "{discovery:?}");
    let candidate = &discovery.candidates[0];
    assert_eq!(candidate.candidate.layout, XCODE_ORPHAN_LAYOUT);
    assert_eq!(
        candidate.discovered.evidence.relative_entry.as_utf8(),
        Some(PROJECT)
    );
    assert!(candidate.discovered.blockers.is_empty(), "{candidate:?}");
    // The units of the other layout keep their result.
    let skipped = skipped(&discovery);
    for unit in UNIT_PATHS {
        let relative: String = format!("{PROJECT}/{unit}");
        assert!(
            skipped
                .iter()
                .any(|(path, layout, reasons)| *path == relative
                    && layout.as_deref() == Some(XCODE_DERIVED_DATA_LAYOUT)
                    && *reasons == [SkipReason::NotRegenerable]),
            "{skipped:?}"
        );
    }
}

#[test]
fn an_orphan_is_never_examined_for_an_automatic_eviction() {
    let tree = Tree::new();
    tree.orphan();
    let registry: ReviewedRules =
        ReviewedRules::with_fixture_lifecycle(&automatic_eviction_validated()).unwrap();
    let discovery: EvictionDiscovery = registry_discover(&tree, &registry);
    assert_eq!(discovery.candidates.len(), 0);
    assert!(
        skipped(&discovery)
            .iter()
            .all(|(_, layout, _)| layout.as_deref() != Some(XCODE_ORPHAN_LAYOUT))
    );
    // The fixture state of the orphan layout permits a manual mode only.
    let status = registry
        .statuses()
        .into_iter()
        .find(|status| status.layout == XCODE_ORPHAN_LAYOUT)
        .unwrap();
    assert!(matches!(
        status.lifecycle,
        LifecycleState::ManualActionValidated { .. }
    ));
    assert!(
        !status
            .permitted_modes
            .contains(&RuleMode::AutomaticEviction)
    );
}

fn registry_discover(tree: &Tree, registry: &ReviewedRules) -> EvictionDiscovery {
    tree.discover(registry, &RuleMode::AutomaticEviction)
}

#[test]
fn an_orphan_with_a_repository_is_refused() {
    let tree = Tree::new();
    let project: PathBuf = tree.orphan();
    let checkout: PathBuf = project.join("SourcePackages/checkouts/lib");
    fs::create_dir_all(checkout.join(".git")).unwrap();
    fs::write(checkout.join(".git/HEAD"), b"ref: refs/heads/main").unwrap();
    fs::write(checkout.join("edited.swift"), b"// local edit").unwrap();
    let discovery: EvictionDiscovery = tree.discover(&manual_registry(), &RuleMode::ManualEviction);
    assert_eq!(discovery.candidates.len(), 0);
    assert!(
        skipped(&discovery)
            .iter()
            .any(|(path, layout, reasons)| path == PROJECT
                && layout.as_deref() == Some(XCODE_ORPHAN_LAYOUT)
                && reasons.contains(&SkipReason::NestedRepository)),
        "{:?}",
        skipped(&discovery)
    );
}

#[test]
fn a_project_on_a_volume_that_is_not_mounted_is_not_gone() {
    let tree = Tree::new();
    let workspace: &Path = Path::new("/Volumes/svalnir-absent-test-volume/App/App.xcodeproj");
    write_project(&tree.root, PROJECT, workspace).unwrap();
    let discovery: EvictionDiscovery = tree.discover(&manual_registry(), &RuleMode::ManualEviction);
    assert_eq!(discovery.candidates.len(), 0, "{discovery:?}");
    assert!(
        skipped(&discovery)
            .iter()
            .all(|(_, layout, _)| layout.as_deref() != Some(XCODE_ORPHAN_LAYOUT))
    );
}

#[test]
fn a_deny_listed_entry_refuses_an_orphan() {
    let tree = Tree::new();
    let project: PathBuf = tree.orphan();
    fs::create_dir_all(project.join("Build/Products/Debug/App.app.dSYM")).unwrap();
    let discovery: EvictionDiscovery = tree.discover(&manual_registry(), &RuleMode::ManualEviction);
    assert_eq!(discovery.candidates.len(), 0);
    assert!(
        skipped(&discovery)
            .iter()
            .any(|(path, layout, reasons)| path == PROJECT
                && layout.as_deref() == Some(XCODE_ORPHAN_LAYOUT)
                && reasons.contains(&SkipReason::ProtectedData))
    );
}

#[test]
fn the_check_before_a_step_examines_the_workspace_again() {
    let tree = Tree::new();
    let project: PathBuf = tree.orphan();
    let check = || recheck_orphan(tree.principal, &tree.root, &project, &[]);
    assert_eq!(check(), UnitRecheck::Passed);
    // The environment applies the check for the orphan layout.
    let registry: ReviewedRules = manual_registry();
    let reference = registry.xcode_derived_data().rule().reference.clone();
    assert_eq!(
        FixtureEnvironment::days_later(30).unit_recheck(
            tree.principal,
            &reference,
            Some(XCODE_ORPHAN_LAYOUT),
            &tree.root,
            &project,
            &[],
            &[],
        ),
        UnitRecheck::Passed
    );
    // The project is back.
    write_workspace(&tree.base.join("src"), "App").unwrap();
    assert_eq!(check(), UnitRecheck::Refused("workspace_present"));
    assert_eq!(
        recheck_orphan(tree.principal, &tree.root, &project.join("Build"), &[]),
        UnitRecheck::Refused("unit_layout_changed")
    );
    fs::remove_dir_all(&project).unwrap();
    assert_eq!(check(), UnitRecheck::Absent);
}
