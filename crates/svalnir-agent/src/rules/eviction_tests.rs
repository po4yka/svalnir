//! Tests of the discovery for an eviction.
//!
//! Each test makes its files in a temporary directory that it created. The
//! home directory and the state directory of a test are in that directory.
//! No test reads the process table of the host: the process evidence comes
//! from a fixture or from a synthetic process source.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::PathBuf;

use svalnir_core::file::{FileObjectEvidence, LosslessPath};
use svalnir_core::id::RuleId;
use svalnir_core::observation::UnavailableReason;
use svalnir_core::policy::{ProtectionFact, RuleReadiness};
use svalnir_core::process::{Pid, ProcessStartTime, Uid};
use svalnir_core::quantity::Nanoseconds;
use svalnir_core::rule::{EligibilityPredicate, LifecycleState, RuleMode};
use svalnir_core::time::{MonotonicNanos, WallTime};
use tempfile::TempDir;

use super::eviction::{
    DiscoveryEnvironment as _, DiscoveryHost, EvictionDiscovery, EvictionRequest, ProducerActivity,
    RootProblem, RootResult, automatic_roots, resolve_roots, xcode_evidence,
};
use super::fixture::{
    FixtureEnvironment, automatic_eviction_validated, derived_data_root, manual_action_validated,
    write_project, write_workspace,
};
use super::model::{DiscoveredCandidate, DiscoveryCompletion, DiscoveryLimits, SkipReason};
use super::registry::ReviewedRules;
use super::xcode::{ProducerProcesses, XCODE_DERIVED_DATA_RULE_ID};
use crate::platform::process::{
    ProcessSource, QueryFailure, RawProcessInfo, RawUsage, RunningApplication, Timebase,
};
use crate::protection::ProtectedLocations;
use crate::scan::CancellationToken;

const PROJECT: &str = "App-abcdefghijklmnopqrstuvwxyzab";
const OTHER_PROJECT: &str = "Tool-bcdefghijklmnopqrstuvwxyzabc";

/// A home directory with a `DerivedData` root and a state directory, in a
/// temporary directory.
struct UserTree {
    _directory: TempDir,
    base: PathBuf,
    home: PathBuf,
    state: PathBuf,
    root: PathBuf,
    principal: Uid,
}

impl UserTree {
    fn new() -> Self {
        use std::os::unix::fs::MetadataExt as _;

        let directory: TempDir = tempfile::tempdir().unwrap();
        // The temporary directory of macOS is below a symbolic link.
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

    /// A home directory with one project in its `DerivedData` root.
    fn with_project() -> Self {
        let home = Self::new();
        home.add_project(PROJECT, "App");
        home
    }

    fn add_project(&self, name: &str, workspace: &str) -> PathBuf {
        let workspace: PathBuf = write_workspace(&self.base.join("src"), workspace).unwrap();
        write_project(&self.root, name, &workspace).unwrap()
    }

    fn locations(&self) -> ProtectedLocations {
        ProtectedLocations::resolve(Some(&self.home), Some(&self.state))
    }

    fn host(&self) -> DiscoveryHost {
        DiscoveryHost {
            principal: self.principal,
            locations: self.locations(),
            user_exclusions: Vec::new(),
        }
    }
}

fn xcode_rule() -> RuleId {
    RuleId::new(XCODE_DERIVED_DATA_RULE_ID).unwrap()
}

/// An environment 30 days after the time of the host: each unit of a
/// fixture is then older than the minimum age of the rule.
fn month_later() -> FixtureEnvironment {
    FixtureEnvironment::days_later(30)
}

fn discover(
    registry: &ReviewedRules,
    host: &DiscoveryHost,
    purpose: &RuleMode,
    known: Option<&[DiscoveredCandidate]>,
    environment: &FixtureEnvironment,
) -> EvictionDiscovery {
    let cancel = CancellationToken::new();
    registry.discover_for_eviction(
        &EvictionRequest {
            host,
            purpose,
            rules: Some(&[xcode_rule()]),
            volumes: None,
            known,
            limits: DiscoveryLimits::default(),
            cancel: &cancel,
        },
        environment,
    )
}

fn manual_registry() -> ReviewedRules {
    ReviewedRules::with_fixture_lifecycle(&manual_action_validated()).unwrap()
}

fn automatic_registry() -> ReviewedRules {
    ReviewedRules::with_fixture_lifecycle(&automatic_eviction_validated()).unwrap()
}

fn relative_entries(discovery: &EvictionDiscovery) -> Vec<String> {
    let mut entries: Vec<String> = discovery
        .candidates
        .iter()
        .map(|candidate| {
            candidate
                .discovered
                .evidence
                .relative_entry
                .as_utf8()
                .unwrap()
                .to_owned()
        })
        .collect();
    entries.sort();
    entries
}

fn units(project: &str) -> Vec<String> {
    [
        "Build/Intermediates.noindex",
        "Build/Products",
        "Index.noindex",
    ]
    .iter()
    .map(|unit| format!("{project}/{unit}"))
    .collect()
}

// ---------------------------------------------------------------------
// The lifecycle state decides whether a rule is examined.
// ---------------------------------------------------------------------

#[test]
fn a_proposed_rule_is_not_examined_and_gives_no_candidate() {
    let home = UserTree::with_project();
    let registry = ReviewedRules::new().unwrap();
    for purpose in [RuleMode::ManualEviction, RuleMode::AutomaticEviction] {
        let discovery = discover(&registry, &home.host(), &purpose, None, &month_later());
        assert!(discovery.complete);
        assert_eq!(discovery.candidates.len(), 0);
        // No root was opened.
        assert_eq!(discovery.roots.len(), 0);
    }
    // The registry of a released build gives an automatic operation no
    // root.
    assert_eq!(
        automatic_roots(&registry, &[xcode_rule()], &home.locations()).len(),
        0
    );
}

#[test]
fn a_rule_that_is_validated_for_manual_action_is_not_examined_for_automatic_eviction() {
    let home = UserTree::with_project();
    let registry = manual_registry();
    let automatic = discover(
        &registry,
        &home.host(),
        &RuleMode::AutomaticEviction,
        None,
        &month_later(),
    );
    assert_eq!(automatic.candidates.len(), 0);
    assert_eq!(automatic.roots.len(), 0);
    assert_eq!(
        automatic_roots(&registry, &[xcode_rule()], &home.locations()).len(),
        0
    );
    let manual = discover(
        &registry,
        &home.host(),
        &RuleMode::ManualEviction,
        None,
        &month_later(),
    );
    assert_eq!(relative_entries(&manual), units(PROJECT));
    // A candidate of a manual discovery is not ready for automatic action.
    for candidate in &manual.candidates {
        assert_eq!(
            candidate.candidate.candidate.facts.rule_readiness,
            RuleReadiness::NotReady
        );
    }
}

// ---------------------------------------------------------------------
// The candidates and the facts of admission.
// ---------------------------------------------------------------------

#[test]
fn each_unit_of_an_inactive_project_is_an_eligible_candidate() {
    let home = UserTree::with_project();
    let discovery = discover(
        &automatic_registry(),
        &home.host(),
        &RuleMode::AutomaticEviction,
        None,
        &month_later(),
    );
    assert!(discovery.complete);
    assert_eq!(relative_entries(&discovery), units(PROJECT));
    assert_eq!(discovery.conflicts.len(), 0);
    assert_eq!(discovery.roots.len(), 1);
    assert!(matches!(
        discovery.roots[0].result,
        RootResult::Examined {
            completion: DiscoveryCompletion::Finished,
            ..
        }
    ));
    for candidate in &discovery.candidates {
        assert!(candidate.candidate.is_eligible(), "{candidate:?}");
        let policy = &candidate.candidate.candidate;
        assert_eq!(policy.facts.hard_protection, ProtectionFact::NotProtected);
        assert_eq!(policy.facts.rule_readiness, RuleReadiness::Ready);
        // The entry for the plan builder names the object that the rule
        // measured, below the root of the declaration.
        let entry = candidate.cleanup_entry("target-1".parse().unwrap(), "step-1".parse().unwrap());
        assert_eq!(entry.root_path.to_path_buf(), home.root);
        assert_eq!(
            entry.path.to_path_buf(),
            home.root.join(entry.relative_entry.to_path_buf())
        );
        assert_eq!(entry.owner, Some(home.principal));
        assert_eq!(entry.object, Some(candidate.discovered.evidence.object));
        assert_eq!(entry.charge, Some(candidate.charge()));
        assert!(entry.rule.is_some());
    }
    // The project directory, its logs, and its `info.plist` stay.
    assert!(!relative_entries(&discovery).contains(&PROJECT.to_owned()));
}

/// The skip reasons of each unit that the discovery of the one root did
/// not accept.
fn skip_reasons(discovery: &EvictionDiscovery) -> Vec<SkipReason> {
    let RootResult::Examined { skipped, .. } = &discovery.roots[0].result else {
        panic!("the root was not examined: {:?}", discovery.roots);
    };
    skipped
        .iter()
        .flat_map(|unit| unit.reasons.iter().copied())
        .collect()
}

#[test]
fn a_running_producer_and_unknown_evidence_give_no_eligible_candidate() {
    let home = UserTree::with_project();
    let registry = automatic_registry();
    for (producer, reason) in [
        (ProducerProcesses::Running, SkipReason::ActiveProducer),
        (ProducerProcesses::Unknown, SkipReason::ActivityUnknown),
    ] {
        let environment = month_later();
        environment.set_producer(producer);
        let discovery = discover(
            &registry,
            &home.host(),
            &RuleMode::AutomaticEviction,
            None,
            &environment,
        );
        assert!(
            discovery
                .candidates
                .iter()
                .all(|candidate| !candidate.candidate.is_eligible()),
            "{producer:?}"
        );
        let blockers: Vec<SkipReason> = discovery
            .candidates
            .iter()
            .flat_map(|candidate| candidate.discovered.blockers.iter().copied())
            .chain(skip_reasons(&discovery))
            .collect();
        assert!(blockers.contains(&reason), "{producer:?}: {blockers:?}");
    }
}

#[test]
fn a_unit_that_is_younger_than_the_minimum_age_is_not_eligible() {
    let home = UserTree::with_project();
    // One day after the fixture was written: less than the minimum age.
    let discovery = discover(
        &automatic_registry(),
        &home.host(),
        &RuleMode::AutomaticEviction,
        None,
        &FixtureEnvironment::days_later(1),
    );
    assert_eq!(discovery.candidates.len(), 3);
    for candidate in &discovery.candidates {
        assert!(!candidate.candidate.is_eligible());
        assert_eq!(
            candidate
                .candidate
                .eligibility
                .first_blocker()
                .map(|blocker| blocker.0),
            Some(EligibilityPredicate::AgeAndInactivity)
        );
        assert!(
            candidate
                .discovered
                .blockers
                .contains(&SkipReason::RetentionNotElapsed),
            "{:?}",
            candidate.discovered.blockers
        );
    }
}

#[test]
fn a_user_exclusion_removes_a_unit_from_the_candidates() {
    let home = UserTree::with_project();
    let mut host = home.host();
    host.user_exclusions = vec![home.root.join(PROJECT).join("Build/Products")];
    let discovery = discover(
        &automatic_registry(),
        &host,
        &RuleMode::AutomaticEviction,
        None,
        &month_later(),
    );
    assert!(!relative_entries(&discovery).contains(&format!("{PROJECT}/Build/Products")));
    assert_eq!(discovery.candidates.len(), 2);
}

// ---------------------------------------------------------------------
// The roots.
// ---------------------------------------------------------------------

#[test]
fn a_root_that_is_absent_gives_no_candidate_and_is_not_an_error() {
    let home = UserTree::new();
    fs::remove_dir(&home.root).unwrap();
    let registry = automatic_registry();
    let discovery = discover(
        &registry,
        &home.host(),
        &RuleMode::AutomaticEviction,
        None,
        &month_later(),
    );
    assert!(discovery.complete);
    assert_eq!(discovery.candidates.len(), 0);
    assert_eq!(
        discovery.roots[0].result,
        RootResult::NotBound(RootProblem::Absent)
    );
    assert_eq!(
        automatic_roots(&registry, &[xcode_rule()], &home.locations()).len(),
        0
    );
}

#[test]
fn a_root_that_is_a_symbolic_link_is_not_bound() {
    let home = UserTree::new();
    fs::remove_dir(&home.root).unwrap();
    let elsewhere: PathBuf = home.base.join("elsewhere");
    fs::create_dir(&elsewhere).unwrap();
    symlink(&elsewhere, &home.root).unwrap();
    let registry = automatic_registry();
    let rule = registry.xcode_derived_data().rule();
    assert_eq!(
        resolve_roots(rule, &home.locations()),
        vec![Err(RootProblem::NotDirectory)]
    );
    assert_eq!(
        automatic_roots(&registry, &[xcode_rule()], &home.locations()).len(),
        0
    );
}

#[test]
fn with_no_home_directory_or_no_state_directory_nothing_is_examined() {
    let home = UserTree::with_project();
    let registry = automatic_registry();
    let rule = registry.xcode_derived_data().rule();
    let no_home = ProtectedLocations::resolve(None, Some(&home.state));
    assert_eq!(
        resolve_roots(rule, &no_home),
        vec![Err(RootProblem::BaseUnknown)]
    );
    assert_eq!(
        automatic_roots(&registry, &[xcode_rule()], &no_home).len(),
        0
    );
    // With no state directory, the hard exclusion of the control-plane
    // state has no path: no rule is examined, and the result is not
    // complete.
    let host = DiscoveryHost {
        principal: home.principal,
        locations: ProtectedLocations::resolve(Some(&home.home), None),
        user_exclusions: Vec::new(),
    };
    let discovery = discover(
        &registry,
        &host,
        &RuleMode::AutomaticEviction,
        None,
        &month_later(),
    );
    assert!(!discovery.complete);
    assert_eq!(discovery.candidates.len(), 0);
    assert_eq!(discovery.roots.len(), 0);
}

#[test]
fn a_state_directory_in_the_root_refuses_the_root() {
    let home = UserTree::with_project();
    // The state directory of this user is inside the `DerivedData` root.
    let state: PathBuf = home.root.join("state");
    fs::create_dir(&state).unwrap();
    let host = DiscoveryHost {
        principal: home.principal,
        locations: ProtectedLocations::resolve(Some(&home.home), Some(&state)),
        user_exclusions: Vec::new(),
    };
    let discovery = discover(
        &automatic_registry(),
        &host,
        &RuleMode::AutomaticEviction,
        None,
        &month_later(),
    );
    assert_eq!(discovery.candidates.len(), 0);
    assert_eq!(
        discovery.roots[0].result,
        RootResult::Refused("root_overlaps_protected")
    );
    // A root that exists and that was not examined: the result is not
    // complete, so it supports no automatic plan.
    assert!(!discovery.complete);
}

#[test]
fn the_approved_roots_are_those_of_the_approved_rules_that_permit_automatic_eviction() {
    let home = UserTree::with_project();
    let registry = automatic_registry();
    // A rule that the configuration does not approve gives no root.
    assert_eq!(automatic_roots(&registry, &[], &home.locations()).len(), 0);
    let other = RuleId::new("npm.content-cache").unwrap();
    assert_eq!(
        automatic_roots(&registry, &[other], &home.locations()).len(),
        0
    );
    let roots = automatic_roots(&registry, &[xcode_rule()], &home.locations());
    assert_eq!(roots.len(), 1);
    // The root record is the one that a discovery binds its candidates to.
    let discovery = discover(
        &registry,
        &home.host(),
        &RuleMode::AutomaticEviction,
        None,
        &month_later(),
    );
    let bound = &discovery.candidates[0].discovered.root;
    let record = roots.root(&bound.root_id).unwrap();
    assert_eq!(record.path, LosslessPath::from_path(&home.root).unwrap());
    assert_eq!(record.object, bound.object);
    // A root that was replaced by a different directory has a different
    // identity: the earlier record does not name it.
    let moved: PathBuf = home.base.join("moved");
    fs::rename(&home.root, &moved).unwrap();
    fs::create_dir(&home.root).unwrap();
    let replaced = automatic_roots(&registry, &[xcode_rule()], &home.locations());
    assert_eq!(replaced.len(), 1);
    assert!(replaced.root(&bound.root_id).is_none());
}

// ---------------------------------------------------------------------
// Known candidates only.
// ---------------------------------------------------------------------

fn known_of(discovery: &EvictionDiscovery) -> Vec<DiscoveredCandidate> {
    discovery
        .candidates
        .iter()
        .map(|candidate| candidate.discovered.clone())
        .collect()
}

#[test]
fn known_candidates_are_examined_again_and_no_new_unit_is_found() {
    let home = UserTree::with_project();
    let registry = automatic_registry();
    let environment = month_later();
    let full = discover(
        &registry,
        &home.host(),
        &RuleMode::AutomaticEviction,
        None,
        &environment,
    );
    let known = known_of(&full);
    assert_eq!(known.len(), 3);
    // A project that appears after the discovery is not listed.
    home.add_project(OTHER_PROJECT, "Tool");
    let again = discover(
        &registry,
        &home.host(),
        &RuleMode::AutomaticEviction,
        Some(&known),
        &environment,
    );
    assert!(again.complete);
    assert_eq!(relative_entries(&again), units(PROJECT));
    assert!(again.candidates.iter().all(|c| c.candidate.is_eligible()));
    // A producer that started after the discovery blocks each candidate.
    environment.set_producer(ProducerProcesses::Running);
    let blocked = discover(
        &registry,
        &home.host(),
        &RuleMode::AutomaticEviction,
        Some(&known),
        &environment,
    );
    assert_eq!(blocked.candidates.len(), 3);
    assert!(
        blocked
            .candidates
            .iter()
            .all(|c| !c.candidate.is_eligible())
    );
}

#[test]
fn with_nothing_known_the_root_is_not_opened() {
    let home = UserTree::with_project();
    let discovery = discover(
        &automatic_registry(),
        &home.host(),
        &RuleMode::AutomaticEviction,
        Some(&[]),
        &month_later(),
    );
    assert!(discovery.complete);
    assert_eq!(discovery.candidates.len(), 0);
    assert_eq!(discovery.roots[0].result, RootResult::NothingKnown);
}

#[test]
fn a_known_unit_that_was_replaced_is_not_a_candidate() {
    let home = UserTree::with_project();
    let registry = automatic_registry();
    let environment = month_later();
    let known = known_of(&discover(
        &registry,
        &home.host(),
        &RuleMode::AutomaticEviction,
        None,
        &environment,
    ));
    // A different directory takes the name of one unit.
    let unit: PathBuf = home.root.join(PROJECT).join("Build/Products");
    fs::rename(&unit, home.base.join("moved-products")).unwrap();
    fs::create_dir(&unit).unwrap();
    fs::write(unit.join("precious.txt"), b"a file of the user").unwrap();
    let again = discover(
        &registry,
        &home.host(),
        &RuleMode::AutomaticEviction,
        Some(&known),
        &environment,
    );
    assert!(!relative_entries(&again).contains(&format!("{PROJECT}/Build/Products")));
    assert!(unit.join("precious.txt").exists());
}

#[test]
fn a_known_candidate_of_a_root_that_was_replaced_is_not_known_at_the_new_root() {
    let home = UserTree::with_project();
    let registry = automatic_registry();
    let environment = month_later();
    let known = known_of(&discover(
        &registry,
        &home.host(),
        &RuleMode::AutomaticEviction,
        None,
        &environment,
    ));
    let moved: PathBuf = home.base.join("moved");
    fs::rename(&home.root, &moved).unwrap();
    fs::create_dir(&home.root).unwrap();
    let again = discover(
        &registry,
        &home.host(),
        &RuleMode::AutomaticEviction,
        Some(&known),
        &environment,
    );
    assert_eq!(again.candidates.len(), 0);
    assert_eq!(again.roots[0].result, RootResult::NothingKnown);
}

#[test]
fn a_cancelled_discovery_is_not_complete() {
    let home = UserTree::with_project();
    let cancel = CancellationToken::new();
    cancel.cancel();
    let host = home.host();
    let discovery = automatic_registry().discover_for_eviction(
        &EvictionRequest {
            host: &host,
            purpose: &RuleMode::AutomaticEviction,
            rules: None,
            volumes: None,
            known: None,
            limits: DiscoveryLimits::default(),
            cancel: &cancel,
        },
        &month_later(),
    );
    assert!(!discovery.complete);
    assert_eq!(discovery.candidates.len(), 0);
}

#[test]
fn a_root_on_a_volume_that_the_request_does_not_name_is_not_examined() {
    let home = UserTree::with_project();
    let cancel = CancellationToken::new();
    let host = home.host();
    let other = [svalnir_core::id::VolumeId::new("volume-other").unwrap()];
    let discovery = automatic_registry().discover_for_eviction(
        &EvictionRequest {
            host: &host,
            purpose: &RuleMode::AutomaticEviction,
            rules: Some(&[xcode_rule()]),
            volumes: Some(&other),
            known: None,
            limits: DiscoveryLimits::default(),
            cancel: &cancel,
        },
        &month_later(),
    );
    assert_eq!(discovery.candidates.len(), 0);
    assert_eq!(discovery.roots[0].result, RootResult::OtherVolume);
}

#[test]
fn the_expired_temporary_rule_gives_no_eligible_candidate_without_a_lease_record() {
    use super::expired_temporary::EXPIRED_TEMPORARY_RULE_ID;

    let home = UserTree::new();
    let registry = automatic_registry();
    let cancel = CancellationToken::new();
    let host = home.host();
    let rules = [RuleId::new(EXPIRED_TEMPORARY_RULE_ID).unwrap()];
    // The namespace does not exist: the root is absent.
    let discovery = registry.discover_for_eviction(
        &EvictionRequest {
            host: &host,
            purpose: &RuleMode::AutomaticEviction,
            rules: Some(&rules),
            volumes: None,
            known: None,
            limits: DiscoveryLimits::default(),
            cancel: &cancel,
        },
        &month_later(),
    );
    assert_eq!(discovery.candidates.len(), 0);
    assert_eq!(
        discovery.roots[0].result,
        RootResult::NotBound(RootProblem::Absent)
    );
    assert_eq!(
        month_later().producer_activity(&rules[0], home.principal),
        ProducerActivity::Unknown
    );
}

// ---------------------------------------------------------------------
// The process evidence.
// ---------------------------------------------------------------------

const USER: Uid = Uid::new(501);
const OTHER_USER: Uid = Uid::new(502);

/// The answers of the identity query and of the path query of one process.
type Answers = (
    Result<Uid, QueryFailure>,
    Result<&'static str, QueryFailure>,
);

/// A process table with fixed answers.
#[derive(Debug, Default)]
struct Table {
    list_fails: bool,
    clock_fails: bool,
    processes: BTreeMap<i32, Answers>,
    /// The answer of the owner query of each PID; no entry is a failure.
    owners: BTreeMap<i32, Uid>,
    /// The PIDs whose code is Apple platform code.
    platform: Vec<i32>,
}

impl Table {
    fn with(mut self, pid: i32, uid: Uid, path: &'static str) -> Self {
        self.processes.insert(pid, (Ok(uid), Ok(path)));
        self
    }

    fn with_answers(
        mut self,
        pid: i32,
        info: Result<Uid, QueryFailure>,
        path: Result<&'static str, QueryFailure>,
    ) -> Self {
        self.processes.insert(pid, (info, path));
        self
    }
}

impl ProcessSource for Table {
    fn effective_uid(&self) -> Uid {
        USER
    }

    fn list_pids(&self) -> Result<Vec<Pid>, QueryFailure> {
        if self.list_fails {
            return Err(QueryFailure::Failed(5));
        }
        Ok(self
            .processes
            .keys()
            .map(|pid| Pid::new(*pid).unwrap())
            .collect())
    }

    fn process_info(&self, pid: Pid) -> Result<RawProcessInfo, QueryFailure> {
        let (info, _) = self.processes.get(&pid.get()).ok_or(QueryFailure::Gone)?;
        let uid: Uid = (*info)?;
        Ok(RawProcessInfo {
            pid,
            parent_pid: None,
            effective_uid: uid,
            real_uid: uid,
            start_time: ProcessStartTime::from_timeval(1_000, 0).unwrap(),
            zombie: false,
        })
    }

    fn executable_path(&self, pid: Pid) -> Result<LosslessPath, QueryFailure> {
        let (_, path) = self.processes.get(&pid.get()).ok_or(QueryFailure::Gone)?;
        Ok(LosslessPath::from_bytes((*path)?).unwrap())
    }

    fn process_owner(&self, pid: Pid) -> Result<(Uid, Uid), QueryFailure> {
        let owner: Uid = *self.owners.get(&pid.get()).ok_or(QueryFailure::Failed(5))?;
        Ok((owner, owner))
    }

    fn apple_platform_code(&self, pid: Pid) -> Result<bool, QueryFailure> {
        Ok(self.platform.contains(&pid.get()))
    }

    fn file_evidence(&self, _path: &LosslessPath) -> Result<FileObjectEvidence, QueryFailure> {
        Err(QueryFailure::Unsupported)
    }

    fn usage(&self, _pid: Pid) -> Result<RawUsage, QueryFailure> {
        Err(QueryFailure::Unsupported)
    }

    fn responsible_pid(&self, _pid: Pid) -> Result<Pid, QueryFailure> {
        Err(QueryFailure::Unsupported)
    }

    fn application_list_current(&self) -> bool {
        false
    }

    fn running_applications(&self) -> Result<Vec<RunningApplication>, QueryFailure> {
        Err(QueryFailure::Unsupported)
    }

    fn timebase(&self) -> Result<Timebase, QueryFailure> {
        Err(QueryFailure::Unsupported)
    }

    fn monotonic_now(&self) -> Result<MonotonicNanos, QueryFailure> {
        if self.clock_fails {
            Err(QueryFailure::Failed(5))
        } else {
            Ok(MonotonicNanos::new(7_000))
        }
    }

    fn sleep_time(&self) -> Result<Nanoseconds, UnavailableReason> {
        Err(UnavailableReason::Unsupported)
    }

    fn wall_now(&self) -> Result<WallTime, QueryFailure> {
        Err(QueryFailure::Unsupported)
    }
}

fn shell_and(table: Table) -> Table {
    table.with(100, USER, "/bin/zsh")
}

#[test]
fn a_complete_inventory_with_no_producer_shows_inactivity_at_its_time() {
    let evidence = xcode_evidence(&shell_and(Table::default()), USER);
    assert_eq!(evidence.producer_processes, ProducerProcesses::NotRunning);
    assert_eq!(evidence.observed_at, MonotonicNanos::new(7_000));
}

#[test]
fn a_producer_process_of_the_user_is_found_by_its_executable_name() {
    for path in [
        "/Applications/Xcode.app/Contents/MacOS/Xcode",
        "/Applications/Xcode.app/Contents/Developer/usr/bin/xcodebuild",
    ] {
        let table = shell_and(Table::default()).with(200, USER, path);
        assert_eq!(
            xcode_evidence(&table, USER).producer_processes,
            ProducerProcesses::Running,
            "{path}"
        );
    }
    // A producer process of a different user does not act on the data of
    // this user.
    let table = shell_and(Table::default()).with(
        200,
        OTHER_USER,
        "/Applications/Xcode.app/Contents/MacOS/Xcode",
    );
    assert_eq!(
        xcode_evidence(&table, USER).producer_processes,
        ProducerProcesses::NotRunning
    );
}

#[test]
fn an_inventory_that_is_not_complete_does_not_show_inactivity() {
    // The process list failed.
    let table = Table {
        list_fails: true,
        ..shell_and(Table::default())
    };
    assert_eq!(
        xcode_evidence(&table, USER).producer_processes,
        ProducerProcesses::Unknown
    );
    // No process at all is a failed query.
    assert_eq!(
        xcode_evidence(&Table::default(), USER).producer_processes,
        ProducerProcesses::Unknown
    );
    // The clock gave no time.
    let table = Table {
        clock_fails: true,
        ..shell_and(Table::default())
    };
    assert_eq!(
        xcode_evidence(&table, USER).producer_processes,
        ProducerProcesses::Unknown
    );
    // An identity query, or a path query of a process of the user, failed
    // for a cause that is not an exit: that process can be the producer.
    for table in [
        shell_and(Table::default()).with_answers(
            200,
            Err(QueryFailure::Failed(5)),
            Ok("/usr/bin/true"),
        ),
        shell_and(Table::default()).with_answers(200, Ok(USER), Err(QueryFailure::Failed(5))),
        shell_and(Table::default()).with_answers(
            200,
            Ok(USER),
            Err(QueryFailure::PermissionDenied),
        ),
    ] {
        assert_eq!(
            xcode_evidence(&table, USER).producer_processes,
            ProducerProcesses::Unknown
        );
    }
}

#[test]
fn a_denied_process_of_the_user_is_out_of_the_inventory_only_through_the_platform_gate() {
    let denied = |failure: QueryFailure, path: &'static str, platform: bool| Table {
        owners: BTreeMap::from([(202, USER)]),
        platform: if platform { vec![202] } else { Vec::new() },
        ..shell_and(Table::default()).with_answers(202, Err(failure), Ok(path))
    };
    // `login`: Apple platform code on the sealed system volume.
    assert_eq!(
        xcode_evidence(
            &denied(QueryFailure::PermissionDenied, "/usr/bin/login", true),
            USER
        )
        .producer_processes,
        ProducerProcesses::NotRunning
    );
    // With no owner answer, the gate still decides.
    let no_owner: Table = Table {
        owners: BTreeMap::new(),
        ..denied(QueryFailure::PermissionDenied, "/usr/bin/login", true)
    };
    assert_eq!(
        xcode_evidence(&no_owner, USER).producer_processes,
        ProducerProcesses::NotRunning
    );
    // Each other denied process of the user can be the producer.
    for table in [
        denied(QueryFailure::PermissionDenied, "/usr/bin/login", false),
        denied(QueryFailure::PermissionDenied, "/Users/u/bin/tool", true),
        denied(QueryFailure::AccessDenied, "/usr/bin/login", true),
    ] {
        assert_eq!(
            xcode_evidence(&table, USER).producer_processes,
            ProducerProcesses::Unknown
        );
    }
}

#[test]
fn a_process_that_exited_and_a_process_of_a_different_user_keep_the_inventory_complete() {
    let table = shell_and(Table::default())
        .with_answers(200, Err(QueryFailure::Gone), Ok("/usr/bin/true"))
        .with_answers(201, Ok(USER), Err(QueryFailure::Gone))
        .with_answers(
            202,
            Err(QueryFailure::PermissionDenied),
            Ok("/usr/bin/true"),
        )
        .with_answers(203, Ok(OTHER_USER), Err(QueryFailure::Failed(5)));
    // The owner query of the denied process gives a different user.
    let table = Table {
        owners: BTreeMap::from([(202, OTHER_USER)]),
        ..table
    };
    assert_eq!(
        xcode_evidence(&table, USER).producer_processes,
        ProducerProcesses::NotRunning
    );
}

#[test]
fn the_fresh_activity_check_reads_the_producer_state_now() {
    let environment = month_later();
    assert_eq!(
        environment.producer_activity(&xcode_rule(), USER),
        ProducerActivity::Inactive
    );
    environment.set_producer(ProducerProcesses::Running);
    assert_eq!(
        environment.producer_activity(&xcode_rule(), USER),
        ProducerActivity::Active
    );
    environment.set_producer(ProducerProcesses::Unknown);
    assert_eq!(
        environment.producer_activity(&xcode_rule(), USER),
        ProducerActivity::Unknown
    );
    // A rule that this build does not know.
    assert_eq!(
        month_later().producer_activity(&RuleId::new("npm.content-cache").unwrap(), USER),
        ProducerActivity::Unknown
    );
}

#[test]
fn the_fixture_lifecycle_names_no_validation_record() {
    for state in [manual_action_validated(), automatic_eviction_validated()] {
        let (LifecycleState::ManualActionValidated { evidence }
        | LifecycleState::AutomaticEvictionValidated { evidence }) = state
        else {
            panic!("the state is not a validated state");
        };
        assert!(evidence.record.starts_with("test-fixture/"));
    }
    // The registry of a build has each layout in the proposed state.
    for status in ReviewedRules::new().unwrap().statuses() {
        assert_eq!(status.lifecycle, LifecycleState::Proposed);
    }
}

// ---------------------------------------------------------------------
// The use check of a running process (`docs/CLEANUP_RULES.md` section 6).
// ---------------------------------------------------------------------

/// A fixture environment whose path-use inventory the test gives.
struct WithUses {
    inner: FixtureEnvironment,
    inventory: crate::platform::process::PathInventory,
    scopes: std::sync::Mutex<Vec<PathBuf>>,
}

impl crate::scan::ScanClock for WithUses {
    fn now(&self) -> crate::scan::ScanTimestamp {
        self.inner.now()
    }
}

impl super::eviction::DiscoveryEnvironment for WithUses {
    fn xcode_evidence(&self, principal: Uid) -> super::xcode::XcodeEvidence {
        self.inner.xcode_evidence(principal)
    }

    fn path_uses(
        &self,
        _principal: Uid,
        scopes: &[super::in_use::UnitScope],
    ) -> crate::platform::process::PathInventory {
        self.scopes
            .lock()
            .unwrap()
            .extend(scopes.iter().map(|scope| scope.path().to_path_buf()));
        self.inventory.clone()
    }
}

fn discover_with(
    home: &UserTree,
    inventory: crate::platform::process::PathInventory,
) -> (EvictionDiscovery, Vec<PathBuf>) {
    let environment = WithUses {
        inner: month_later(),
        inventory,
        scopes: std::sync::Mutex::default(),
    };
    let cancel = CancellationToken::new();
    let discovery = automatic_registry().discover_for_eviction(
        &EvictionRequest {
            host: &home.host(),
            purpose: &RuleMode::AutomaticEviction,
            rules: Some(&[xcode_rule()]),
            volumes: None,
            known: None,
            limits: DiscoveryLimits::default(),
            cancel: &cancel,
        },
        &environment,
    );
    let scopes = environment.scopes.into_inner().unwrap();
    (discovery, scopes)
}

#[test]
fn a_unit_that_a_process_uses_is_skipped_and_the_others_stay_candidates() {
    use crate::platform::process::{PathInventory, PathUseKind, ProcessPathUse, ProcessUses};

    let home = UserTree::with_project();
    let used: PathBuf = home.root.join(PROJECT).join("Build/Products/Debug");
    let inventory = PathInventory {
        processes: vec![ProcessUses {
            pid: Pid::new(77).unwrap(),
            name: "lldb".to_owned(),
            uses: vec![ProcessPathUse {
                kind: PathUseKind::WorkingDirectory,
                path: used,
            }],
        }],
        ..PathInventory::default()
    };
    let (discovery, scopes) = discover_with(&home, inventory);
    // The scope of the inventory is the bound root.
    assert_eq!(scopes, vec![home.root.clone()]);
    let mut expected: Vec<String> = units(PROJECT);
    expected.retain(|unit| !unit.ends_with("Build/Products"));
    assert_eq!(relative_entries(&discovery), expected);
    assert_eq!(skip_reasons(&discovery), vec![SkipReason::UnitInUse]);
    let RootResult::Examined { skipped, .. } = &discovery.roots[0].result else {
        panic!("{:?}", discovery.roots);
    };
    assert_eq!(
        skipped[0].relative_entry.as_utf8().unwrap(),
        format!("{PROJECT}/Build/Products")
    );
    assert_eq!(
        skipped[0].eligibility.protocols_valid,
        svalnir_core::rule::Fact::NotSatisfied
    );
    assert!(discovery.complete);
}

#[test]
fn an_unknown_process_or_an_incomplete_inventory_gives_no_candidate() {
    use crate::platform::process::{InventoryGap, PathInventory, UnknownProcess};

    let home = UserTree::with_project();
    let unknown = PathInventory {
        unknown: vec![UnknownProcess {
            pid: Pid::new(9).unwrap(),
            name: "dmd".to_owned(),
            reason: InventoryGap::ProcessQueryDenied,
        }],
        ..PathInventory::default()
    };
    let gap = PathInventory::incomplete(InventoryGap::ProcessListUnavailable, None);
    for inventory in [unknown, gap] {
        let (discovery, _) = discover_with(&home, inventory);
        assert_eq!(discovery.candidates.len(), 0);
        assert_eq!(
            skip_reasons(&discovery),
            vec![SkipReason::UnitUseUnknown; 3]
        );
        let RootResult::Examined { skipped, .. } = &discovery.roots[0].result else {
            panic!("{:?}", discovery.roots);
        };
        assert_eq!(
            skipped[0].eligibility.protocols_valid,
            svalnir_core::rule::Fact::Unknown
        );
    }
}
