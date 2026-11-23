//! Fixture tests of the roots of a request, of mise, of the discovery for a
//! manual eviction, and of the checks before a step of
//! `project.dependency-directory`. Each test makes a home directory and
//! disposable Git repositories in a temporary directory; no test reads or
//! changes a project or a mise directory of the host.

use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use svalnir_core::id::RuleId;
use svalnir_core::rule::{Fact, RuleMode};
use svalnir_core::time::WallTime;

use super::inspect::recheck_unit_in;
use super::tests::{DAY, Home, NoActivity};
use super::{
    AgentListing, AgentStatus, ArgumentRootError, BuildProcesses, DirectoryName, GitHeadActivity,
    HeadActivity, MarkerKind, MiseLocations, MiseState, PROJECT_RULE_ID, PackageCheckouts,
    ProjectLayout, ProjectLimits, ProjectMarker, ProjectProcess, ProjectRequest, RecencyHost,
    RecheckInput, RootKind, RootSource, SearchRootEntry, SearchRoots, SourceReading, UnitRecheck,
    Unmarked, argument_root, project_root, recheck_unit, tracked_projects,
};
use crate::rules::caches::ReclaimBasis;
use crate::rules::fixture::{
    FixtureEnvironment, automatic_eviction_validated, manual_action_validated,
};
use crate::rules::git::Repository;
use crate::rules::{
    DiscoveryEnvironment, DiscoveryHost, DiscoveryLimits, EvictionDiscovery, EvictionRequest,
    ReviewedRules, RootResult, SkipReason, automatic_roots,
};
use crate::scan::{CancellationToken, ScanClock as _};
use svalnir_core::rule::RuleRegistry as _;

// ---------------------------------------------------------------------
// The roots of a request.
// ---------------------------------------------------------------------

#[test]
fn an_argument_root_is_an_existing_directory_below_the_home_directory() {
    let home = Home::new();
    fs::create_dir_all(home.path.join("Code/app")).unwrap();
    home.write("Code/file", b"x");
    assert_eq!(
        argument_root(&home.path.join("Code/app"), &home.path),
        Ok(PathBuf::from("Code/app"))
    );
    // A `.` is removed; a `..` is refused, also when the text stays below
    // the home directory.
    assert_eq!(
        argument_root(&home.path.join("Code/./app"), &home.path),
        Ok(PathBuf::from("Code/app"))
    );
    assert_eq!(
        argument_root(&home.path.join("Code/app/../app"), &home.path),
        Err(ArgumentRootError::NotPlain)
    );
    assert_eq!(
        argument_root(Path::new("Code"), &home.path),
        Err(ArgumentRootError::NotAbsolute)
    );
    assert_eq!(
        argument_root(&home.path, &home.path),
        Err(ArgumentRootError::NotBelowHome)
    );
    assert_eq!(
        argument_root(&home.path.join("Code/.."), &home.path),
        Err(ArgumentRootError::NotPlain)
    );
    assert_eq!(
        argument_root(Path::new("/usr"), &home.path),
        Err(ArgumentRootError::NotBelowHome)
    );
    assert_eq!(
        argument_root(&home.path.join("Code/missing"), &home.path),
        Err(ArgumentRootError::NotFound)
    );
    assert_eq!(
        argument_root(&home.path.join("Code/file"), &home.path),
        Err(ArgumentRootError::NotDirectory)
    );
    // A symbolic link is not a directory.
    symlink(home.path.join("Code/app"), home.path.join("Code/link")).unwrap();
    assert_eq!(
        argument_root(&home.path.join("Code/link"), &home.path),
        Err(ArgumentRootError::NotDirectory)
    );
}

fn entry(relative: &str, kind: RootKind, source: RootSource) -> SearchRootEntry {
    SearchRootEntry {
        relative: PathBuf::from(relative),
        kind,
        source,
    }
}

#[test]
fn the_roots_of_a_request_have_no_repeated_root_and_no_covered_project_root() {
    let mise = |config: &str| RootSource::Mise {
        config: PathBuf::from(config),
    };
    let roots = SearchRoots::with_entries(vec![
        entry("Code", RootKind::Search, RootSource::Configuration),
        entry("Code", RootKind::Search, RootSource::Argument),
        entry("Code/app", RootKind::Project, mise("/h/Code/app/mise.toml")),
        entry(
            "Other/app",
            RootKind::Project,
            mise("/h/Other/app/mise.toml"),
        ),
        entry(
            "Other/app",
            RootKind::Project,
            mise("/h/Other/app/.mise.toml"),
        ),
    ])
    .unwrap();
    let kept: Vec<(&Path, RootKind, &RootSource)> = roots
        .entries()
        .iter()
        .map(|entry| (entry.relative.as_path(), entry.kind, &entry.source))
        .collect();
    assert_eq!(
        kept,
        [
            (
                Path::new("Code"),
                RootKind::Search,
                &RootSource::Configuration
            ),
            (
                Path::new("Other/app"),
                RootKind::Project,
                &mise("/h/Other/app/mise.toml")
            ),
        ]
    );
    assert_eq!(
        SearchRoots::with_entries(vec![entry("../x", RootKind::Search, RootSource::Argument)]),
        Err(Some(PathBuf::from("../x")))
    );
    let many: Vec<SearchRootEntry> = (0..17)
        .map(|index| entry(&format!("r{index}"), RootKind::Search, RootSource::Argument))
        .collect();
    assert_eq!(SearchRoots::with_entries(many), Err(None));
    let reasons: Vec<(&Path, &str)> = roots
        .dropped()
        .iter()
        .map(|(entry, reason)| (entry.relative.as_path(), *reason))
        .collect();
    assert_eq!(
        reasons,
        [
            (Path::new("Code"), super::REPEATED_ROOT),
            (Path::new("Code/app"), super::IN_SEARCH_ROOT),
            (Path::new("Other/app"), super::REPEATED_ROOT),
        ]
    );
}

#[test]
fn a_search_root_in_another_search_root_is_left_out_in_each_order() {
    for order in [["Code", "code/app"], ["Code/app", "Code"]] {
        let roots = SearchRoots::with_entries(
            order
                .iter()
                .map(|path| entry(path, RootKind::Search, RootSource::Argument))
                .collect(),
        )
        .unwrap();
        let kept: Vec<&Path> = roots
            .entries()
            .iter()
            .map(|entry| entry.relative.as_path())
            .collect();
        assert_eq!(kept, [Path::new("Code")], "{order:?}");
        assert_eq!(roots.dropped()[0].1, super::IN_SEARCH_ROOT);
    }
    // The walk of the kept root finds each unit one time, and the report
    // names the root that was left out.
    let world = World::new();
    world.home.node_project("app");
    let roots = SearchRoots::with_entries(vec![
        entry("Code/app", RootKind::Search, RootSource::Argument),
        entry("Code", RootKind::Search, RootSource::Configuration),
    ])
    .unwrap();
    let head = GitHeadActivity::new(Ok(&world.home.git));
    let discovery =
        world.discover_with(&roots, false, &head, &NoActivity, &RuleMode::ManualEviction);
    assert_eq!(eligible(&discovery).len(), 1);
    assert!(discovery.complete);
    assert_eq!(
        discovery.project_roots[1].outcome,
        super::SearchRootOutcome::Covered(super::IN_SEARCH_ROOT)
    );
}

#[test]
fn an_excluded_location_refuses_a_root_whose_case_differs() {
    let world = World::new();
    world.home.node_project("app");
    fs::create_dir_all(world.home.path.join("Documents/work")).unwrap();
    let mut host = world.host();
    host.user_exclusions = vec![world.home.path.join("Documents")];
    let head = GitHeadActivity::new(Ok(&world.home.git));
    let request = ProjectRequest {
        roots: &SearchRoots::new(vec![PathBuf::from("documents/work"), PathBuf::from("Code")])
            .unwrap(),
        git: Ok(&world.home.git),
        recency: RecencyHost {
            quiet_period: DAY,
            head: &head,
            transcripts: &NoActivity,
            agents: &NoActivity,
        },
        layouts: &[],
        include_active: false,
        allow_unmarked: false,
        limits: ProjectLimits::default(),
    };
    let discovery = world.registry.discover_for_eviction(
        &EvictionRequest {
            host: &host,
            purpose: &RuleMode::ManualEviction,
            rules: None,
            volumes: None,
            known: None,
            limits: DiscoveryLimits::default(),
            cancel: &CancellationToken::new(),
            projects: Some(&request),
        },
        &world.evidence,
    );
    assert_eq!(
        discovery.project_roots[0].outcome,
        super::SearchRootOutcome::Refused("root_excluded")
    );
    assert_eq!(eligible(&discovery).len(), 1);
}

// ---------------------------------------------------------------------
// mise.
// ---------------------------------------------------------------------

#[test]
fn the_project_root_of_a_configuration_file_is_the_directory_of_mise() {
    let root = |file: &str| project_root(Path::new(file));
    assert_eq!(root("/h/app/mise.toml"), PathBuf::from("/h/app"));
    assert_eq!(root("/h/app/.mise.toml"), PathBuf::from("/h/app"));
    assert_eq!(root("/h/app/.tool-versions"), PathBuf::from("/h/app"));
    assert_eq!(root("/h/app/.config/mise.toml"), PathBuf::from("/h/app"));
    assert_eq!(
        root("/h/app/.config/mise/config.toml"),
        PathBuf::from("/h/app")
    );
    assert_eq!(
        root("/h/app/.config/mise/conf.d/a.toml"),
        PathBuf::from("/h/app")
    );
    assert_eq!(root("/h/app/mise/config.toml"), PathBuf::from("/h/app"));
    assert_eq!(root("/h/app/.mise/config.toml"), PathBuf::from("/h/app"));
    // A project with the name `mise` and `mise.toml` at its top stays.
    assert_eq!(root("/h/mise/mise.toml"), PathBuf::from("/h/mise"));
}

#[test]
fn the_tracked_configs_of_mise_give_project_roots_below_the_home_directory_only() {
    let home = Home::new();
    let locations = MiseLocations::resolve(&home.path, None, None);
    assert_eq!(
        locations.tracked_configs,
        home.path.join(".local/state/mise/tracked-configs")
    );
    // No directory: mise loaded nothing.
    assert_eq!(
        tracked_projects(&home.path, &locations, home.principal).state,
        MiseState::Absent
    );
    let tracked: &Path = &locations.tracked_configs;
    fs::create_dir_all(tracked).unwrap();
    let link = |name: &str, target: &Path| symlink(target, tracked.join(name)).unwrap();
    // A valid project, and a second link of the same project.
    let app: PathBuf = home.write("Code/app/mise.toml", b"[tools]\n");
    link("a1", &app);
    link("a2", &home.write("Code/app/.config/mise/config.toml", b""));
    // A dangling link.
    link("b", &home.path.join("Code/gone/mise.toml"));
    // The global configuration, and a file whose project root is home.
    link("c", &home.write(".config/mise/config.toml", b""));
    link("d", &home.write(".tool-versions", b""));
    // A target outside the home directory.
    link("e", Path::new("/etc/hosts"));
    // An entry that is not a link.
    fs::write(tracked.join("f"), b"").unwrap();
    // A relative target is relative to the directory of the link.
    link("g", Path::new("../../../../Code/rel/mise.toml"));
    home.write("Code/rel/mise.toml", b"");
    // A target with `..` is not a plain path.
    link("h", &home.path.join("Code/app/../app/mise.toml"));

    let found = tracked_projects(&home.path, &locations, home.principal);
    assert_eq!(found.state, MiseState::Read);
    let roots: Vec<&Path> = found
        .roots
        .iter()
        .map(|root| root.relative.as_path())
        .collect();
    assert_eq!(roots, [Path::new("Code/app")]);
    assert_eq!(found.roots[0].config, app);
    let ignored: Vec<(&str, &str)> = found
        .ignored
        .iter()
        .map(|link| (link.name.to_str().unwrap(), link.reason))
        .collect();
    assert_eq!(
        ignored,
        [
            ("b", "target_absent"),
            ("c", "global_config"),
            ("d", "global_config"),
            ("e", "target_outside_home"),
            ("f", "not_a_link"),
            ("g", "target_not_plain"),
            ("h", "target_not_plain"),
        ]
    );
    let entries = found.entries();
    assert_eq!(entries[0].kind, RootKind::Project);
    assert_eq!(entries[0].source, RootSource::Mise { config: app });
}

#[test]
fn the_tracked_configs_directory_follows_xdg_state_home_and_is_not_a_link() {
    let home = Home::new();
    let state: PathBuf = home.path.join("state-home");
    let locations = MiseLocations::resolve(
        &home.path,
        Some(state.as_os_str()),
        Some(std::ffi::OsStr::new("relative/config")),
    );
    assert_eq!(
        locations.tracked_configs,
        state.join("mise/tracked-configs")
    );
    // A value that is not absolute is not used.
    assert_eq!(locations.config_directory, home.path.join(".config/mise"));
    fs::create_dir_all(home.path.join("elsewhere")).unwrap();
    fs::create_dir_all(state.join("mise")).unwrap();
    symlink(home.path.join("elsewhere"), &locations.tracked_configs).unwrap();
    assert_eq!(
        tracked_projects(&home.path, &locations, home.principal).state,
        MiseState::Refused("tracked_configs_not_directory")
    );
}

// ---------------------------------------------------------------------
// The discovery for a manual eviction.
// ---------------------------------------------------------------------

/// A Git source that gives the time `at` for each repository.
struct RecentHead(WallTime);

impl HeadActivity for RecentHead {
    fn head_activity(&self, _repository: &Repository) -> SourceReading {
        SourceReading::Observed { at: self.0 }
    }
}

/// A Paseo source whose listing failed.
struct FailedListing;

impl AgentStatus for FailedListing {
    fn agent_listing(&self) -> AgentListing {
        AgentListing::Failed {
            reason: "paseo_failed",
        }
    }
}

struct World {
    home: Home,
    evidence: FixtureEnvironment,
    registry: ReviewedRules,
    /// The option `--allow-unmarked` of each request.
    allow_unmarked: bool,
}

impl World {
    /// A world whose clock is 30 days after the fixture, so each fixture is
    /// older than the minimum age of the rule.
    fn new() -> Self {
        Self::days_later(30)
    }

    fn days_later(days: i64) -> Self {
        Self {
            home: Home::new(),
            evidence: FixtureEnvironment::days_later(days),
            registry: ReviewedRules::with_fixture_lifecycle(&manual_action_validated()).unwrap(),
            allow_unmarked: false,
        }
    }

    fn host(&self) -> DiscoveryHost {
        DiscoveryHost {
            principal: self.home.principal,
            locations: self.home.locations.clone(),
            user_exclusions: Vec::new(),
        }
    }

    fn code() -> SearchRoots {
        SearchRoots::new(vec![PathBuf::from("Code")]).unwrap()
    }

    fn discover(&self, include_active: bool) -> EvictionDiscovery {
        let head = GitHeadActivity::new(Ok(&self.home.git));
        self.discover_with(
            &Self::code(),
            include_active,
            &head,
            &NoActivity,
            &RuleMode::ManualEviction,
        )
    }

    fn discover_with(
        &self,
        roots: &SearchRoots,
        include_active: bool,
        head: &dyn HeadActivity,
        agents: &dyn AgentStatus,
        purpose: &RuleMode,
    ) -> EvictionDiscovery {
        let request = ProjectRequest {
            roots,
            git: Ok(&self.home.git),
            recency: RecencyHost {
                quiet_period: DAY,
                head,
                transcripts: &NoActivity,
                agents,
            },
            layouts: &[],
            include_active,
            allow_unmarked: self.allow_unmarked,
            limits: ProjectLimits::default(),
        };
        let rules: [RuleId; 1] = [RuleId::new(PROJECT_RULE_ID).unwrap()];
        self.registry.discover_for_eviction(
            &EvictionRequest {
                host: &self.host(),
                purpose,
                rules: Some(&rules),
                volumes: None,
                known: None,
                limits: DiscoveryLimits::default(),
                cancel: &CancellationToken::new(),
                projects: Some(&request),
            },
            &self.evidence,
        )
    }
}

/// The paths of the candidates with no blocker.
fn eligible(discovery: &EvictionDiscovery) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = discovery
        .candidates
        .iter()
        .filter(|candidate| candidate.discovered.blockers.is_empty())
        .map(|candidate| candidate.candidate.candidate.path.to_path_buf())
        .collect();
    paths.sort();
    paths
}

/// The reasons of the unit `relative` (below the root `Code`): of a
/// skipped unit, or the blockers of a candidate.
fn reasons(discovery: &EvictionDiscovery, relative: &str) -> Vec<SkipReason> {
    for root in &discovery.roots {
        if let RootResult::Examined { skipped, .. } = &root.result
            && let Some(unit) = skipped
                .iter()
                .find(|unit| unit.relative_entry.to_path_buf() == Path::new(relative))
        {
            return unit.reasons.clone();
        }
    }
    discovery
        .candidates
        .iter()
        .find(|candidate| {
            candidate.discovered.evidence.relative_entry.to_path_buf() == Path::new(relative)
        })
        .map_or_else(Vec::new, |candidate| candidate.discovered.blockers.clone())
}

#[test]
fn an_ignored_unit_of_a_quiet_project_is_an_eligible_candidate_of_its_search_root() {
    let world = World::new();
    let project: PathBuf = world.home.node_project("app");
    let discovery = world.discover(false);
    assert!(discovery.complete, "{discovery:?}");
    assert_eq!(eligible(&discovery), [project.join("node_modules")]);
    let candidate = &discovery.candidates[0];
    assert!(candidate.candidate.eligibility.is_eligible());
    assert_eq!(
        candidate.candidate.eligibility.within_authorized_scope,
        Fact::Satisfied
    );
    assert_eq!(candidate.candidate.layout, "node-modules");
    // The approved root is the search root, bound to its object, its
    // volume, and its mount generation; the unit is relative to it.
    let binding = candidate.discovered.file_binding();
    assert_eq!(
        binding.root_path.to_path_buf(),
        world.home.path.join("Code")
    );
    assert_eq!(
        binding.relative_entry.to_path_buf(),
        PathBuf::from("app/node_modules")
    );
    assert_eq!(binding.layout.as_deref(), Some("node-modules"));
    assert!(
        discovery
            .bound_roots
            .iter()
            .any(|root| root.binding.root_id == binding.root_id)
    );
    // The report of the root has its kind and its source.
    assert_eq!(discovery.project_roots.len(), 1);
    assert_eq!(discovery.project_roots[0].kind, RootKind::Search);
    assert_eq!(discovery.project_roots[0].source, RootSource::Caller);
}

#[test]
fn each_check_of_the_inspection_refuses_a_unit_for_an_eviction() {
    let world = World::new();
    let home = &world.home;
    // Git does not ignore the directory.
    home.write("Code/plain/package.json", b"{}");
    home.repository("Code/plain");
    home.write("Code/plain/node_modules/a/index.js", b"1");
    // A committed directory.
    home.write("Code/committed/package.json", b"{}");
    home.write("Code/committed/node_modules/a/index.js", b"1");
    home.repository("Code/committed");
    // No repository.
    home.write("Code/loose/package.json", b"{}");
    home.write("Code/loose/node_modules/a/index.js", b"1");
    // A protected child: a release of Mix.
    home.write("Code/mix/mix.exs", b"");
    home.write("Code/mix/.gitignore", b"/_build/\n");
    home.repository("Code/mix");
    home.write("Code/mix/_build/dev/rel/app/bin/app", b"#!/bin/sh\n");
    // A cloned dependency with its own repository.
    home.node_project("clone");
    fs::create_dir_all(home.path.join("Code/clone/node_modules/dep/.git")).unwrap();
    let discovery = world.discover(false);
    assert_eq!(eligible(&discovery), Vec::<PathBuf>::new());
    assert_eq!(
        reasons(&discovery, "plain/node_modules"),
        [SkipReason::NotRegenerable]
    );
    assert_eq!(
        reasons(&discovery, "committed/node_modules"),
        [SkipReason::NotRegenerable]
    );
    assert_eq!(
        reasons(&discovery, "loose/node_modules"),
        [SkipReason::RegenerabilityUnknown]
    );
    assert_eq!(
        reasons(&discovery, "mix/_build"),
        [SkipReason::ProtectedData]
    );
    assert!(
        reasons(&discovery, "clone/node_modules").contains(&SkipReason::NestedRepository),
        "{:?}",
        reasons(&discovery, "clone/node_modules")
    );
}

#[test]
fn a_build_process_in_the_project_refuses_its_units() {
    let world = World::new();
    let project: PathBuf = world.home.node_project("app");
    world.evidence.set_build_process(Some(project));
    let discovery = world.discover(true);
    assert_eq!(eligible(&discovery), Vec::<PathBuf>::new());
    assert_eq!(
        reasons(&discovery, "app/node_modules"),
        [SkipReason::ActiveProducer]
    );
}

#[test]
fn an_active_project_is_eligible_only_with_include_active_and_a_busy_project_never() {
    let world = World::new();
    let project: PathBuf = world.home.node_project("app");
    let now: WallTime = world.evidence.now().wall.unwrap();
    let recent = RecentHead(now);
    let active = world.discover_with(
        &World::code(),
        false,
        &recent,
        &NoActivity,
        &RuleMode::ManualEviction,
    );
    assert_eq!(eligible(&active), Vec::<PathBuf>::new());
    assert_eq!(
        reasons(&active, "app/node_modules"),
        [SkipReason::RetentionNotElapsed]
    );
    let included = world.discover_with(
        &World::code(),
        true,
        &recent,
        &NoActivity,
        &RuleMode::ManualEviction,
    );
    assert_eq!(eligible(&included), [project.join("node_modules")]);
    // A busy project, also with `include_active`.
    let head = GitHeadActivity::new(Ok(&world.home.git));
    let busy = world.discover_with(
        &World::code(),
        true,
        &head,
        &FailedListing,
        &RuleMode::ManualEviction,
    );
    assert_eq!(eligible(&busy), Vec::<PathBuf>::new());
    assert_eq!(
        reasons(&busy, "app/node_modules"),
        [SkipReason::ActiveProducer]
    );
}

#[test]
fn include_active_does_not_waive_the_minimum_age() {
    // The clock is two days after the fixture: the content is younger than
    // the minimum age of seven days.
    let world = World::days_later(2);
    world.home.node_project("app");
    let discovery = world.discover(true);
    assert_eq!(eligible(&discovery), Vec::<PathBuf>::new());
    assert_eq!(
        reasons(&discovery, "app/node_modules"),
        [SkipReason::RetentionNotElapsed]
    );
}

#[test]
fn a_project_root_is_examined_without_a_walk_below_it() {
    let world = World::new();
    let project: PathBuf = world.home.node_project("app");
    // A nested project below the project root, which only a walk finds.
    world.home.write("Code/app/sub/package.json", b"{}");
    world
        .home
        .write("Code/app/sub/node_modules/b/index.js", b"1");
    world.home.write("Code/app/.gitignore", b"node_modules/\n");
    let roots = SearchRoots::with_entries(vec![entry(
        "Code/app",
        RootKind::Project,
        RootSource::Mise {
            config: project.join("mise.toml"),
        },
    )])
    .unwrap();
    let head = GitHeadActivity::new(Ok(&world.home.git));
    let discovery =
        world.discover_with(&roots, false, &head, &NoActivity, &RuleMode::ManualEviction);
    assert_eq!(eligible(&discovery), [project.join("node_modules")]);
    assert_eq!(discovery.project_roots[0].kind, RootKind::Project);
}

#[test]
fn the_rule_is_never_examined_for_an_automatic_eviction() {
    let mut world = World::new();
    world.registry =
        ReviewedRules::with_fixture_lifecycle(&automatic_eviction_validated()).unwrap();
    world.home.node_project("app");
    let head = GitHeadActivity::new(Ok(&world.home.git));
    let automatic = world.discover_with(
        &World::code(),
        true,
        &head,
        &NoActivity,
        &RuleMode::AutomaticEviction,
    );
    assert_eq!(automatic.candidates.len(), 0);
    assert_eq!(automatic.roots.len(), 0);
    assert_eq!(automatic.project_roots.len(), 0);
    // The manual discovery of the same registry finds the unit, and its
    // root is never an approved root of an automatic operation.
    let manual = world.discover(false);
    assert_eq!(eligible(&manual).len(), 1);
    let root_id = &manual.candidates[0].discovered.root.root_id;
    let approved = automatic_roots(
        &world.registry,
        &[RuleId::new(PROJECT_RULE_ID).unwrap()],
        &world.home.locations,
    );
    assert!(approved.root(root_id).is_none());
    // No layout of the rule permits an automatic eviction, also with the
    // fixture state of the registry.
    assert!(
        world
            .registry
            .projects()
            .rule()
            .layouts
            .iter()
            .all(|layout| !layout.permits(&RuleMode::AutomaticEviction))
    );
}

// ---------------------------------------------------------------------
// The checks before a step.
// ---------------------------------------------------------------------

fn complete(processes: Vec<ProjectProcess>, evidence: &FixtureEnvironment) -> BuildProcesses {
    BuildProcesses {
        processes,
        incomplete: None,
        observed_at: evidence.now().monotonic_ns,
    }
}

fn recheck(
    home: &Home,
    layout: &str,
    unit: &Path,
    processes: &BuildProcesses,
    evidence: &FixtureEnvironment,
) -> UnitRecheck {
    recheck_unit(&RecheckInput {
        principal: home.principal,
        layout,
        root: &home.path.join("Code"),
        unit,
        user_layouts: &[],
        processes,
        now: evidence.now().monotonic_ns,
        expiry: super::PROJECT_EVIDENCE_EXPIRY,
        git: Some(&home.git),
    })
}

#[test]
fn the_check_before_a_step_refuses_a_unit_that_changed_after_the_plan() {
    let home = Home::new();
    let evidence = FixtureEnvironment::days_later(0);
    let none: BuildProcesses = complete(Vec::new(), &evidence);
    // A Cargo target directory.
    home.write("Code/crate/Cargo.toml", b"[package]\n");
    home.write(
        "Code/crate/target/CACHEDIR.TAG",
        b"Signature: 8a477f597d28d172789f06886806bc55",
    );
    let target: PathBuf = home.path.join("Code/crate/target");
    assert_eq!(
        recheck(&home, "cargo-target", &target, &none, &evidence),
        UnitRecheck::Passed
    );
    // The layout that the plan binds does not fit the path.
    assert_eq!(
        recheck(&home, "node-modules", &target, &none, &evidence),
        UnitRecheck::Refused("unit_layout_changed")
    );
    // A build process in the project.
    let building = complete(
        vec![ProjectProcess {
            executable: PathBuf::from("/usr/local/bin/cargo"),
            working_directory: Some(home.path.join("Code/crate")),
        }],
        &evidence,
    );
    assert_eq!(
        recheck(&home, "cargo-target", &target, &building, &evidence),
        UnitRecheck::Refused("producer_active")
    );
    // An inventory that is not complete.
    let partial = BuildProcesses {
        incomplete: Some("process_query_failed"),
        ..none.clone()
    };
    assert_eq!(
        recheck(&home, "cargo-target", &target, &partial, &evidence),
        UnitRecheck::Unknown("activity_unknown")
    );
    // The inner marker is gone.
    fs::remove_file(target.join("CACHEDIR.TAG")).unwrap();
    assert_eq!(
        recheck(&home, "cargo-target", &target, &none, &evidence),
        UnitRecheck::Refused("unsupported_layout")
    );
    // The project marker is gone.
    home.write("Code/app/package.json", b"{}");
    home.write("Code/app/node_modules/a/index.js", b"1");
    let modules: PathBuf = home.path.join("Code/app/node_modules");
    assert_eq!(
        recheck(&home, "node-modules", &modules, &none, &evidence),
        UnitRecheck::Passed
    );
    fs::remove_file(home.path.join("Code/app/package.json")).unwrap();
    assert_eq!(
        recheck(&home, "node-modules", &modules, &none, &evidence),
        UnitRecheck::Refused("project_marker_missing")
    );
    // A protected child appears.
    home.write("Code/mix/mix.exs", b"");
    home.write("Code/mix/_build/dev/lib/app/ebin/a.beam", b"beam");
    let build: PathBuf = home.path.join("Code/mix/_build");
    assert_eq!(
        recheck(&home, "mix-build", &build, &none, &evidence),
        UnitRecheck::Passed
    );
    home.write("Code/mix/_build/dev/rel/app/bin/app", b"#!/bin/sh\n");
    assert_eq!(
        recheck(&home, "mix-build", &build, &none, &evidence),
        UnitRecheck::Refused("protected_child")
    );
    // An earlier layout of the same directory now has its marker.
    home.write("Code/java/pom.xml", b"<project/>");
    home.write("Code/java/target/classes/A.class", b"x");
    let java: PathBuf = home.path.join("Code/java/target");
    assert_eq!(
        recheck(&home, "maven-target", &java, &none, &evidence),
        UnitRecheck::Passed
    );
    home.write("Code/java/Cargo.toml", b"[package]\n");
    assert_eq!(
        recheck(&home, "maven-target", &java, &none, &evidence),
        UnitRecheck::Refused("unit_layout_changed")
    );
    // A layout of the configuration that the configuration in effect does
    // not have.
    home.write("Code/x/out/a", b"x");
    assert_eq!(
        recheck(
            &home,
            "user-configured",
            &home.path.join("Code/x/out"),
            &none,
            &evidence
        ),
        UnitRecheck::Unknown("unit_layout_unknown")
    );
}

#[test]
fn the_environment_checks_a_unit_of_the_rule_only() {
    let home = Home::new();
    let evidence = FixtureEnvironment::days_later(0);
    home.write("Code/app/package.json", b"{}");
    home.write("Code/app/node_modules/a/index.js", b"1");
    let modules: PathBuf = home.path.join("Code/app/node_modules");
    let project_rule = svalnir_core::rule::RuleRef {
        id: RuleId::new(PROJECT_RULE_ID).unwrap(),
        revision: svalnir_core::id::RuleRevisionId::new("r4").unwrap(),
    };
    let root: PathBuf = home.path.join("Code");
    assert_eq!(
        evidence.unit_recheck(
            home.principal,
            &project_rule,
            Some("node-modules"),
            &root,
            &modules,
            &[]
        ),
        UnitRecheck::Passed
    );
    evidence.set_build_process(Some(home.path.join("Code/app")));
    assert_eq!(
        evidence.unit_recheck(
            home.principal,
            &project_rule,
            Some("node-modules"),
            &root,
            &modules,
            &[]
        ),
        UnitRecheck::Refused("producer_active")
    );
    assert_eq!(
        evidence.unit_recheck(home.principal, &project_rule, None, &root, &modules, &[]),
        UnitRecheck::Unknown("unit_layout_unknown")
    );
    // A unit that is gone is absent, not refused.
    evidence.set_build_process(None);
    fs::remove_dir_all(&modules).unwrap();
    assert_eq!(
        evidence.unit_recheck(
            home.principal,
            &project_rule,
            Some("node-modules"),
            &root,
            &modules,
            &[]
        ),
        UnitRecheck::Absent
    );
    // Another rule has no such check.
    let xcode = svalnir_core::rule::RuleRef {
        id: RuleId::new(crate::rules::XCODE_DERIVED_DATA_RULE_ID).unwrap(),
        revision: svalnir_core::id::RuleRevisionId::new("r1").unwrap(),
    };
    assert_eq!(
        evidence.unit_recheck(home.principal, &xcode, Some("x"), &root, &modules, &[]),
        UnitRecheck::Passed
    );
}

// ---------------------------------------------------------------------
// Unmarked directories, and the checks before a step of the new
// capabilities of the walk.
// ---------------------------------------------------------------------

/// A project at `Code/NAME` with an environment `.venv` that Git ignores
/// and no project marker.
fn unmarked_venv(home: &Home, name: &str) -> PathBuf {
    home.project_files(
        name,
        &[],
        "/.venv/\n",
        &[".venv/pyvenv.cfg", ".venv/bin/python"],
    )
}

#[test]
fn an_unmarked_directory_is_a_candidate_of_a_manual_plan_only_with_the_option() {
    let mut world = World::new();
    let project: PathBuf = unmarked_venv(&world.home, "app");
    let discovery = world.discover(false);
    assert_eq!(eligible(&discovery), Vec::<PathBuf>::new());
    assert_eq!(
        reasons(&discovery, "app/.venv"),
        [SkipReason::UnsupportedLayout]
    );
    world.allow_unmarked = true;
    let discovery = world.discover(false);
    assert_eq!(eligible(&discovery), [project.join(".venv")]);
    let candidate = &discovery.candidates[0];
    // The layout name of the plan target shows that the unit has no
    // project marker.
    assert_eq!(candidate.candidate.layout, "python-venv+unmarked");
    assert_eq!(
        candidate.discovered.file_binding().layout.as_deref(),
        Some("python-venv+unmarked")
    );
    // The readiness of the candidate is never `ready`: no state of the
    // layout permits an automatic eviction.
    assert_eq!(
        candidate.candidate.candidate.facts.rule_readiness,
        svalnir_core::policy::RuleReadiness::NotReady
    );
}

#[test]
fn the_inner_marker_is_still_required_with_the_option() {
    let mut world = World::new();
    world.allow_unmarked = true;
    world
        .home
        .project_files("app", &[], "/.venv/\n", &[".venv/bin/python"]);
    let discovery = world.discover(false);
    assert_eq!(eligible(&discovery), Vec::<PathBuf>::new());
    assert_eq!(
        reasons(&discovery, "app/.venv"),
        [SkipReason::UnsupportedLayout]
    );
}

#[test]
fn no_automatic_path_binds_an_unmarked_unit() {
    let mut world = World::new();
    world.registry =
        ReviewedRules::with_fixture_lifecycle(&automatic_eviction_validated()).unwrap();
    world.allow_unmarked = true;
    unmarked_venv(&world.home, "app");
    // The discovery for an automatic eviction (the controller and the
    // candidate source of the agent) never examines the rule.
    let head = GitHeadActivity::new(Ok(&world.home.git));
    let automatic = world.discover_with(
        &World::code(),
        true,
        &head,
        &NoActivity,
        &RuleMode::AutomaticEviction,
    );
    assert_eq!(automatic.candidates.len(), 0);
    assert_eq!(automatic.roots.len(), 0);
    // The manual discovery of the same registry gives the unit; its root is
    // never an approved root of an automatic operation.
    let manual = world.discover(false);
    assert_eq!(eligible(&manual).len(), 1);
    let approved = automatic_roots(
        &world.registry,
        &[RuleId::new(PROJECT_RULE_ID).unwrap()],
        &world.home.locations,
    );
    assert!(
        approved
            .root(&manual.candidates[0].discovered.root.root_id)
            .is_none()
    );
    // The registry, which the readiness of a candidate, the controller, and
    // the authority checks ask, refuses the automatic mode for the layout.
    let rule = world.registry.projects().rule();
    let support = rule
        .layouts
        .iter()
        .find(|layout| layout.layout == "python-venv+unmarked")
        .unwrap();
    assert!(support.permits(&RuleMode::ManualEviction));
    assert!(!support.permits(&RuleMode::AutomaticEviction));
    assert_eq!(
        world
            .registry
            .resolve(
                &rule.reference,
                "python-venv+unmarked",
                &RuleMode::AutomaticEviction
            )
            .err(),
        Some(svalnir_core::rule::RuleRefusal::ModeNotValidated)
    );
    assert!(
        world
            .registry
            .resolve(
                &rule.reference,
                "python-venv+unmarked",
                &RuleMode::ManualEviction
            )
            .is_ok()
    );
    // The declaration check refuses the state "Automatic eviction
    // validated" for the layout, also if the rule had an automatic mode.
    let mut declaration: svalnir_core::rule::RuleDeclaration = (**rule).clone();
    declaration.modes.push(RuleMode::AutomaticEviction);
    for layout in &mut declaration.layouts {
        if layout.layout == "python-venv+unmarked" {
            layout.lifecycle = automatic_eviction_validated();
        }
    }
    assert!(
        svalnir_core::action::Checked::<svalnir_core::rule::RuleDeclaration>::new(declaration)
            .is_err()
    );
}

#[test]
fn the_check_before_a_step_of_an_unmarked_unit_keeps_each_check() {
    let home = Home::new();
    let evidence = FixtureEnvironment::days_later(0);
    let none: BuildProcesses = complete(Vec::new(), &evidence);
    let project: PathBuf = unmarked_venv(&home, "app");
    let venv: PathBuf = project.join(".venv");
    assert_eq!(
        recheck(&home, "python-venv+unmarked", &venv, &none, &evidence),
        UnitRecheck::Passed
    );
    // The layout with a marker refuses the unit, which has no marker.
    assert_eq!(
        recheck(&home, "python-venv", &venv, &none, &evidence),
        UnitRecheck::Refused("project_marker_missing")
    );
    // A layout name of unmarked units that no layout has.
    assert_eq!(
        recheck(&home, "pycache+unmarked", &venv, &none, &evidence),
        UnitRecheck::Refused("unit_layout_changed")
    );
    // The inner marker is gone.
    fs::rename(venv.join("pyvenv.cfg"), project.join("pyvenv.cfg")).unwrap();
    assert_eq!(
        recheck(&home, "python-venv+unmarked", &venv, &none, &evidence),
        UnitRecheck::Refused("unsupported_layout")
    );
    fs::rename(project.join("pyvenv.cfg"), venv.join("pyvenv.cfg")).unwrap();
    // A build process in the project.
    let building = complete(
        vec![ProjectProcess {
            executable: PathBuf::from("/usr/bin/python3"),
            working_directory: Some(project.clone()),
        }],
        &evidence,
    );
    assert_eq!(
        recheck(&home, "python-venv+unmarked", &venv, &building, &evidence),
        UnitRecheck::Refused("producer_active")
    );
    // A project marker appears: the unit is a different kind of directory
    // than at the plan.
    home.write("Code/app/pyproject.toml", b"[project]\n");
    assert_eq!(
        recheck(&home, "python-venv+unmarked", &venv, &none, &evidence),
        UnitRecheck::Refused("unit_layout_changed")
    );
}

static RECHECK_TABLE: [ProjectLayout; 2] = [
    ProjectLayout {
        directory: "*-cache",
        layout: "pattern-cache",
        project_markers: &[ProjectMarker {
            name: "conf/tool.cfg",
            kind: MarkerKind::File,
        }],
        inner_marker: None,
        project_file: None,
        protected: &[],
        name: DirectoryName::Generic,
        unmarked: Unmarked::Never,
        checkouts: PackageCheckouts::None,
        own_ignore_file: false,
        reclaim: ReclaimBasis::AllocatedBytes,
        owner_workflow: "A test layout.",
        rebuild_impact: "A test layout.",
    },
    ProjectLayout {
        directory: "a/b/c",
        layout: "three-names",
        project_markers: &[ProjectMarker {
            name: ".tool",
            kind: MarkerKind::Directory,
        }],
        inner_marker: None,
        project_file: None,
        protected: &[],
        name: DirectoryName::Generic,
        unmarked: Unmarked::Never,
        checkouts: PackageCheckouts::None,
        own_ignore_file: false,
        reclaim: ReclaimBasis::AllocatedBytes,
        owner_workflow: "A test layout.",
        rebuild_impact: "A test layout.",
    },
];

#[test]
fn the_check_before_a_step_matches_a_pattern_name_and_three_names() {
    let home = Home::new();
    let evidence = FixtureEnvironment::days_later(0);
    let none: BuildProcesses = complete(Vec::new(), &evidence);
    home.write("Code/p/conf/tool.cfg", b"x");
    home.write("Code/p/x-cache/a", b"x");
    home.write("Code/p/.tool/keep", b"x");
    home.write("Code/p/a/b/c/data", b"x");
    let check = |layout: &str, unit: &Path| {
        recheck_unit_in(
            &RECHECK_TABLE,
            &RecheckInput {
                principal: home.principal,
                layout,
                root: &home.path.join("Code"),
                unit,
                user_layouts: &[],
                processes: &none,
                now: evidence.now().monotonic_ns,
                expiry: super::PROJECT_EVIDENCE_EXPIRY,
                git: Some(&home.git),
            },
        )
    };
    let pattern: PathBuf = home.path.join("Code/p/x-cache");
    let three: PathBuf = home.path.join("Code/p/a/b/c");
    assert_eq!(check("pattern-cache", &pattern), UnitRecheck::Passed);
    assert_eq!(check("three-names", &three), UnitRecheck::Passed);
    // A name that the pattern does not match.
    home.write("Code/p/x-CACHE2/a", b"x");
    assert_eq!(
        check("pattern-cache", &home.path.join("Code/p/x-CACHE2")),
        UnitRecheck::Refused("unit_layout_changed")
    );
    // The directory on the way of the marker is now a symbolic link.
    fs::rename(
        home.path.join("Code/p/conf"),
        home.path.join("Code/p/conf2"),
    )
    .unwrap();
    symlink(
        home.path.join("Code/p/conf2"),
        home.path.join("Code/p/conf"),
    )
    .unwrap();
    assert_eq!(
        check("pattern-cache", &pattern),
        UnitRecheck::Refused("project_marker_missing")
    );
    // The middle name is now a symbolic link.
    fs::rename(home.path.join("Code/p/a/b"), home.path.join("Code/p/a/b2")).unwrap();
    symlink(home.path.join("Code/p/a/b2"), home.path.join("Code/p/a/b")).unwrap();
    assert_eq!(
        check("three-names", &three),
        UnitRecheck::Refused("unit_path_not_plain")
    );
}

#[test]
fn the_check_before_a_step_refuses_a_user_unit_when_a_table_marker_appears() {
    let home = Home::new();
    let evidence = FixtureEnvironment::days_later(0);
    let none: BuildProcesses = complete(Vec::new(), &evidence);
    home.write("Code/c/premake5.lua", b"project(c)\n");
    home.write("Code/c/build/a.o", b"x");
    let validation = svalnir_core::config::parse_and_validate(
        "schema_version = 1\n[[cleanup.projects.layouts]]\ndirectory = \"build\"\nmarkers = [\"premake5.lua\"]\n",
    );
    let layouts = validation
        .config()
        .unwrap()
        .cleanup()
        .projects
        .layouts
        .clone();
    let build: PathBuf = home.path.join("Code/c/build");
    let check = || {
        recheck_unit(&RecheckInput {
            principal: home.principal,
            layout: "user-configured",
            root: &home.path.join("Code"),
            unit: &build,
            user_layouts: &layouts,
            processes: &none,
            now: evidence.now().monotonic_ns,
            expiry: super::PROJECT_EVIDENCE_EXPIRY,
            git: Some(&home.git),
        })
    };
    assert_eq!(check(), UnitRecheck::Passed);
    home.write("Code/c/build.gradle", b"plugins {}\n");
    assert_eq!(check(), UnitRecheck::Refused("unit_layout_changed"));
}

#[test]
fn a_unit_of_a_pattern_name_of_a_synthetic_table_is_a_candidate() {
    let mut world = World::new();
    world.registry = ReviewedRules::new()
        .unwrap()
        .with_project_table(&RECHECK_TABLE, &manual_action_validated())
        .unwrap();
    let project: PathBuf = world.home.project_files(
        "p",
        &["conf/tool.cfg"],
        "*-cache/\n",
        &["build-cache/a.bin"],
    );
    let discovery = world.discover(false);
    assert_eq!(eligible(&discovery), [project.join("build-cache")]);
    assert_eq!(discovery.candidates[0].candidate.layout, "pattern-cache");
}
