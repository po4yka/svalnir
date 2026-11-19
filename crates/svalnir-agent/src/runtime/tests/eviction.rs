//! The disk guard with the discovery of a reviewed rule, end to end.
//!
//! Each test has a home directory, a state directory, and a `DerivedData`
//! root in a temporary directory that it made. The rule is
//! `xcode.inactive-derived-data` with a lifecycle state that only a test
//! build can give ([`ReviewedRules::with_fixture_lifecycle`]). The process
//! evidence comes from a fixture: no test reads the process table for it.
//! A file is removed only below the temporary directory.

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use svalnir_core::action::{Journal as _, OperationState, TargetEffect};
use svalnir_core::grant::AuthorityState;
use svalnir_core::id::{AdapterId, ExecutorEpochId, OperationId, VolumeId};
use svalnir_core::observation::{Observation, Scope};
use svalnir_core::policy::VolumeEvidence;
use svalnir_core::quantity::{Bytes, Nanoseconds};
use svalnir_core::state::PressureState;
use svalnir_core::volume::VolumeIdentity;
use tempfile::TempDir;

use super::{
    Footprint, Hook, Notes, SAMPLE, TempTrash, TestClock, TestIdle, TestIds, blocked, phase,
};
use crate::controller::tests::support::{
    GIBIBYTE, SECOND, boot, capacity, clock_domain, config, config_text, enabled, memory, user,
    volume, wall,
};
use crate::controller::{
    BlockedReason, CandidateSet, ControllerState, Guard, GuardPhase, Notification, Observations,
    PreparationMode,
};
use crate::coordinator::{CoordinatorConfig, Measurements, SystemProbe};
use crate::executor::fs::{ApprovedRoots, ExecutorLimits, FsExecutor, FsExecutorConfig};
use crate::executor::process::{
    DarwinProcessControl, ExecutorConfig, ExecutorContext, ProcessExecutor,
};
use crate::journal::{AgentRecord, CoordinatorRole, JournalOptions, OperationJournal};
use crate::platform::process::DarwinProcessSource;
use crate::platform::volume::volume_at;
use crate::protection::ProtectedLocations;
use crate::rules::fixture::{
    FixtureEnvironment, automatic_eviction_validated, derived_data_root, write_project,
    write_workspace,
};
use crate::rules::{DiscoveryLimits, ProducerProcesses, ReviewedRules};
use crate::runtime::{
    CandidateSource, Driver, DriverParts, DriverSettings, DriverStart, Preparation,
    RuleCandidateSource, Sample, journal_path,
};

const PROJECT: &str = "App-abcdefghijklmnopqrstuvwxyzab";
const OTHER_PROJECT: &str = "Tool-bcdefghijklmnopqrstuvwxyzabc";
const UNITS: [&str; 3] = [
    "Build/Intermediates.noindex",
    "Build/Products",
    "Index.noindex",
];
const RULE_LINE: &str = "approved_rules = [\"test.cache\"]";
const XCODE_RULE_LINE: &str = "approved_rules = [\"xcode.inactive-derived-data\"]";

/// The capacity of the advisory band of the test configuration: below
/// `warn_below` and above `reclaim_below`.
const ADVISORY: u64 = 15 * GIBIBYTE;
/// A capacity below `reclaim_below` and above `emergency_below`.
const LOW: u64 = 5 * GIBIBYTE;

/// The candidate source of the agent, with a discovery that is complete
/// when the request returns. The worker thread still runs the discovery.
struct Synchronous {
    source: RuleCandidateSource,
    modes: Arc<Mutex<Vec<PreparationMode>>>,
}

impl CandidateSource for Synchronous {
    fn prepare(&mut self, request: &Preparation<'_>) -> Option<CandidateSet> {
        self.modes.lock().unwrap().push(request.mode);
        let set: Option<CandidateSet> = self.source.prepare(request);
        if request.mode == PreparationMode::Refresh {
            return self.source.wait_for_discovery();
        }
        set
    }

    fn cancel(&mut self) {
        self.source.cancel();
    }
}

/// The measurements of a test: the available capacity is `LOW`, plus a
/// gain for each unit that does not exist when the removals help.
#[derive(Debug, Clone)]
struct UnitMeasurements {
    clock: TestClock,
    units: Vec<PathBuf>,
    volume_id: VolumeId,
    gain: Arc<AtomicU64>,
}

impl UnitMeasurements {
    fn available(&self) -> u64 {
        let removed: u64 = self.units.iter().filter(|unit| !unit.exists()).count() as u64;
        LOW + removed * self.gain.load(Ordering::SeqCst)
    }
}

impl Measurements for UnitMeasurements {
    fn capacity(&mut self, _volume: &VolumeId) -> Observation<Bytes> {
        let mut observation = capacity(Some(self.available()), self.clock.now());
        observation.scope = Scope::volume(self.volume_id.clone());
        observation
    }

    fn memory_pressure(&mut self) -> Observation<PressureState> {
        super::pressure(Some(PressureState::Normal), self.clock.now())
    }
}

struct Bench {
    _temp: TempDir,
    base: PathBuf,
    home: PathBuf,
    state: PathBuf,
    project: PathBuf,
    /// The units of the fixture, as absolute paths.
    units: Vec<PathBuf>,
    trash: PathBuf,
    clock: TestClock,
    registry: ReviewedRules,
    environment: FixtureEnvironment,
    text: String,
    volume: VolumeIdentity,
    /// The capacity gain of each removed unit.
    gain: Arc<AtomicU64>,
    modes: Arc<Mutex<Vec<PreparationMode>>>,
    notes: Notes,
    coordinator_units: u32,
    lifetimes: u32,
}

impl Bench {
    fn new(registry: ReviewedRules, changes: &[(&str, &str)]) -> Self {
        let temp: TempDir = tempfile::tempdir().unwrap();
        let base: PathBuf = fs::canonicalize(temp.path()).unwrap();
        let home: PathBuf = base.join("home");
        let state: PathBuf = home.join("Library/Application Support/Svalnir");
        let root: PathBuf = derived_data_root(&home);
        let trash: PathBuf = base.join("trash");
        for directory in [&state, &root, &trash] {
            fs::create_dir_all(directory).unwrap();
        }
        let workspace: PathBuf = write_workspace(&base.join("src"), "App").unwrap();
        let project: PathBuf = write_project(&root, PROJECT, &workspace).unwrap();
        let mut all: Vec<(&str, &str)> = vec![(RULE_LINE, XCODE_RULE_LINE)];
        all.extend_from_slice(changes);
        let volume: VolumeIdentity = volume_at(&root).unwrap().identity;
        Self {
            _temp: temp,
            base,
            home,
            state,
            units: UNITS.iter().map(|unit| project.join(unit)).collect(),
            project,
            trash,
            clock: TestClock::fixed(),
            registry,
            environment: FixtureEnvironment::days_later(30),
            text: config_text(&all),
            volume,
            // Each removed unit gives 10 GiB: with the three units removed,
            // the capacity is above `recover_above`.
            gain: Arc::new(AtomicU64::new(10 * GIBIBYTE)),
            modes: Arc::new(Mutex::new(Vec::new())),
            notes: Notes::default(),
            coordinator_units: 8,
            lifetimes: 0,
        }
    }

    fn validated(changes: &[(&str, &str)]) -> Self {
        Self::new(
            ReviewedRules::with_fixture_lifecycle(&automatic_eviction_validated()).unwrap(),
            changes,
        )
    }

    /// A bench with two projects that have one unit each, the
    /// intermediates with the build database, and with one unit for each
    /// batch (a unit has 5 names).
    ///
    /// The rule examines the lock of the build database of a project for
    /// each of its units. After the intermediates of a project are
    /// removed, its other units thus have an unknown activity and are not
    /// candidates. A test of more than one batch uses units of different
    /// projects, so that a later batch does not depend on that property.
    fn two_single_unit_projects(changes: &[(&str, &str)]) -> Self {
        let mut all: Vec<(&str, &str)> = vec![("batch_item_limit = 256", "batch_item_limit = 6")];
        all.extend_from_slice(changes);
        let mut bench = Self::validated(&all);
        let workspace: PathBuf = write_workspace(&bench.base.join("src"), "Tool").unwrap();
        let other: PathBuf =
            write_project(&derived_data_root(&bench.home), OTHER_PROJECT, &workspace).unwrap();
        for project in [&bench.project, &other] {
            fs::remove_dir_all(project.join("Build/Products")).unwrap();
            fs::remove_dir_all(project.join("Index.noindex")).unwrap();
        }
        bench.units = vec![bench.project.join(UNITS[0]), other.join(UNITS[0])];
        bench
    }

    fn journal(&self) -> OperationJournal {
        let options = JournalOptions {
            full_fsync: false,
            ..JournalOptions::default()
        };
        OperationJournal::open(&journal_path(&self.state), &options).unwrap()
    }

    /// Writes the authority record as an activation and the enable
    /// commands of a client do.
    fn seed_authority(&self) {
        let state: AuthorityState = enabled(&self.text, &self.registry);
        let mut journal = self.journal();
        journal
            .record_policy_revision(&state.active.as_ref().unwrap().revision, Some(&self.text))
            .unwrap();
        journal
            .put_agent_record(AgentRecord::Authority, &state, None, wall(self.clock.now()))
            .unwrap();
    }

    fn measurements(&self) -> UnitMeasurements {
        UnitMeasurements {
            clock: self.clock.clone(),
            units: self.units.clone(),
            volume_id: self.volume.volume_id.clone(),
            gain: Arc::clone(&self.gain),
        }
    }

    fn locations(&self) -> ProtectedLocations {
        ProtectedLocations::resolve(Some(&self.home), Some(&self.state))
    }

    fn settings(&self) -> DriverSettings {
        DriverSettings {
            principal: user(),
            home_directory: Some(svalnir_core::file::LosslessPath::from_path(&self.home).unwrap()),
            proposal: config(&[]),
            coordinator: CoordinatorConfig {
                filesystem_adapter: AdapterId::new("svalnir.filesystem").unwrap(),
                process_adapter: AdapterId::new("macos.process").unwrap(),
                batch_targets: 8,
                poll_interval: Nanoseconds::new(SECOND),
                volatile_capacity: 8,
                role: CoordinatorRole::Agent,
            },
            journal: JournalOptions {
                full_fsync: false,
                ..JournalOptions::default()
            },
            status_interval: Nanoseconds::new(30 * SECOND),
            maintenance_interval: Nanoseconds::new(3_600 * SECOND),
            self_budget: Bytes::new(64 * 1024 * 1024),
            shutdown_bound: Nanoseconds::new(3 * SECOND),
            coordinator_units: self.coordinator_units,
            sample_stale_after: Nanoseconds::new(180 * SECOND),
        }
    }

    fn parts(&self, epoch: &ExecutorEpochId) -> DriverParts {
        let filesystem = FsExecutor::new(
            &FsExecutorConfig {
                home_directory: svalnir_core::file::LosslessPath::from_path(&self.home).unwrap(),
                limits: ExecutorLimits::default(),
            },
            Box::new(TempTrash(self.trash.clone())),
        )
        .unwrap();
        DriverParts {
            clock: Arc::new(self.clock.clone()),
            registry: Box::new(self.registry.clone()),
            measurements: Box::new(self.measurements()),
            ids: Box::new(TestIds(epoch.as_str().to_owned(), 0)),
            filesystem: Box::new(filesystem),
            // The process has no fixed root: the driver resolves the roots
            // of an automatic operation from the rule declarations.
            roots: ApprovedRoots::default(),
            application: Box::new(ProcessExecutor::new(
                DarwinProcessSource::new(),
                DarwinProcessControl,
                self.clock.clone(),
                ExecutorContext {
                    boot_id: boot(),
                    clock_domain: clock_domain(),
                    executor_epoch: epoch.clone(),
                },
                ExecutorConfig::default(),
            )),
            probe: Box::new(SystemProbe::new(
                ApprovedRoots::default(),
                DarwinProcessSource::new(),
            )),
            candidates: Box::new(Synchronous {
                source: RuleCandidateSource::new(
                    self.registry.clone(),
                    user(),
                    self.locations(),
                    Arc::new(self.environment.clone()),
                    DiscoveryLimits::default(),
                ),
                modes: Arc::clone(&self.modes),
            }),
            environment: Arc::new(self.environment.clone()),
            notifier: Box::new(self.notes.clone()),
            footprint: Box::new(Footprint(
                Arc::new(AtomicU64::new(10 * 1024 * 1024)),
                Hook::default(),
            )),
            store: None,
            capabilities: None,
        }
    }

    fn start(&mut self) -> Box<Driver> {
        for _ in 0..200 {
            self.lifetimes += 1;
            let epoch = ExecutorEpochId::new(format!("epoch_{}", self.lifetimes)).unwrap();
            match Driver::start(
                &self.state,
                epoch.clone(),
                self.settings(),
                self.parts(&epoch),
            )
            .unwrap()
            {
                DriverStart::Running(driver) => return driver,
                DriverStart::Busy { .. } => {
                    self.lifetimes -= 1;
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
            }
        }
        panic!("a different coordinator holds the lock");
    }

    /// A sample at the time of the clock with `available` bytes on the
    /// volume of the `DerivedData` root.
    fn sample(&self, available: u64) -> Sample {
        let at: u64 = self.clock.now();
        let mut evidence: VolumeEvidence = volume(Some(available), at);
        evidence.identity.volume_id = self.volume.volume_id.clone();
        evidence.identity.mount_id = self.volume.mount_id.clone();
        evidence.available.scope = Scope::volume(self.volume.volume_id.clone());
        Sample {
            observations: Observations {
                volumes: vec![evidence],
                memory: memory(Some(PressureState::Normal), at, Vec::new()),
                candidates: None,
            },
            woke: false,
            control_plane: Some(Vec::new()),
            degraded: Vec::new(),
        }
    }

    /// Ticks with the capacity of the advisory band until the source ran
    /// one discovery.
    fn discover(&self, driver: &mut Driver) {
        for _ in 0..12 {
            driver.tick(Some(self.sample(ADVISORY)));
            self.clock.advance(SAMPLE);
            if self
                .modes
                .lock()
                .unwrap()
                .contains(&PreparationMode::Refresh)
            {
                return;
            }
        }
        panic!("no discovery started: {:?}", blocked(driver, Guard::Disk));
    }

    /// Ticks `count` times with the capacity that the measurements give
    /// now, and returns each blocked reason of the disk guard that a tick
    /// showed.
    fn run_low(&self, driver: &mut Driver, count: u32) -> Vec<BlockedReason> {
        let mut reasons: Vec<BlockedReason> = Vec::new();
        for _ in 0..count {
            driver.tick(Some(self.sample(self.measurements().available())));
            for reason in blocked(driver, Guard::Disk) {
                if !reasons.contains(&reason) {
                    reasons.push(reason);
                }
            }
            self.clock.advance(SAMPLE);
        }
        reasons
    }

    fn unit(&self, unit: &str) -> PathBuf {
        self.project.join(unit)
    }

    /// The units of the fixture that exist, relative to the project of
    /// each one.
    fn remaining(&self) -> Vec<String> {
        self.units
            .iter()
            .filter(|unit| unit.exists())
            .map(|unit| {
                let project: &std::path::Path = unit.ancestors().nth(2).unwrap_or(unit);
                let relative = if unit.ends_with("Index.noindex") {
                    unit.strip_prefix(unit.parent().unwrap()).unwrap()
                } else {
                    unit.strip_prefix(project).unwrap()
                };
                relative.to_str().unwrap().to_owned()
            })
            .collect()
    }

    fn finished(&self) -> Vec<(String, bool)> {
        self.notes
            .0
            .lock()
            .unwrap()
            .iter()
            .filter_map(|note| match note {
                Notification::Finished {
                    guard: Guard::Disk,
                    state,
                    low_benefit,
                    ..
                } => Some((state.clone(), *low_benefit)),
                _ => None,
            })
            .collect()
    }

    fn operations(&self) -> Vec<svalnir_core::action::Operation> {
        self.journal().recent_operations(16).unwrap()
    }
}

fn stop(bench: &Bench, driver: Box<Driver>) {
    assert!(driver.shutdown(&mut TestIdle(bench.clock.clone())).clean);
}

#[test]
fn a_disk_incident_evicts_the_units_of_the_rule_and_the_capacity_recovers() {
    let mut bench = Bench::validated(&[]);
    bench.seed_authority();
    let mut driver = bench.start();

    // The advisory band: one bounded discovery, and no removal.
    bench.discover(&mut driver);
    assert_eq!(bench.remaining().len(), 3);
    assert_eq!(bench.operations().len(), 0);

    // Below the reclaim threshold for the sustain time: the guard examines
    // the known candidates again, and evicts them.
    let mut reasons: Vec<BlockedReason> = Vec::new();
    for _ in 0..30 {
        if bench.remaining().is_empty() {
            break;
        }
        reasons.extend(bench.run_low(&mut driver, 1));
    }
    assert_eq!(bench.remaining(), Vec::<String>::new(), "{reasons:?}");
    // The tick after the last removal reads the result of the operation.
    bench.run_low(&mut driver, 1);
    let modes: Vec<PreparationMode> = bench.modes.lock().unwrap().clone();
    // One discovery, in the advisory band. Each later request was for the
    // known candidates.
    assert_eq!(
        modes
            .iter()
            .filter(|mode| **mode == PreparationMode::Refresh)
            .count(),
        1,
        "{modes:?}"
    );
    assert!(modes.contains(&PreparationMode::KnownOnly));

    // What is not a unit of the rule stays: the project directory, its
    // logs, its record, and the source of the project.
    assert!(bench.project.join("info.plist").exists());
    assert!(bench.project.join("Logs/Build/1.xcactivitylog").exists());
    assert!(bench.project.join("Build").is_dir());
    assert!(
        bench
            .base
            .join("src/App/App.xcodeproj/project.pbxproj")
            .exists()
    );
    // An eviction is a removal, not a move to the Trash.
    assert_eq!(fs::read_dir(&bench.trash).unwrap().count(), 0);

    // The journal has the settled operation with each removal, and the
    // charge is in the incident.
    let operations = bench.operations();
    assert_ne!(operations.len(), 0);
    for operation in &operations {
        assert_eq!(operation.state(), &OperationState::Completed);
        for step in operation.steps() {
            assert_eq!(step.results()[0].effect, TargetEffect::Removed);
        }
    }
    assert_eq!(
        operations
            .iter()
            .map(|operation| operation.steps().len())
            .sum::<usize>(),
        3
    );
    let finished = bench.finished();
    assert_ne!(finished.len(), 0);
    assert!(
        finished
            .iter()
            .all(|(state, low_benefit)| state == "Completed" && !low_benefit),
        "{finished:?}"
    );
    let state: &ControllerState = driver.controller_state();
    assert!(state.outstanding.is_none());
    assert!(state.policy.disk.incidents[0].usage.consumed_items.get() >= 3);
    assert_eq!(bench.journal().unsettled_operation_count().unwrap(), 0);
    stop(&bench, driver);
}

#[test]
fn the_rules_of_a_released_build_are_proposed_and_nothing_is_removed() {
    // The registry of a build: each layout is `proposed`.
    let mut bench = Bench::new(ReviewedRules::new().unwrap(), &[]);
    // The activation of the configuration is refused for a guard whose
    // approved rule permits no automatic eviction, so the authority record
    // comes from the registry of a test, as a record of an earlier build
    // would.
    let validated = ReviewedRules::with_fixture_lifecycle(&automatic_eviction_validated()).unwrap();
    let state: AuthorityState = enabled(&bench.text, &validated);
    let mut journal = bench.journal();
    journal
        .record_policy_revision(&state.active.as_ref().unwrap().revision, Some(&bench.text))
        .unwrap();
    journal
        .put_agent_record(
            AgentRecord::Authority,
            &state,
            None,
            wall(bench.clock.now()),
        )
        .unwrap();
    drop(journal);
    let mut driver = bench.start();
    for _ in 0..4 {
        driver.tick(Some(bench.sample(ADVISORY)));
        bench.clock.advance(SAMPLE);
    }
    let reasons = bench.run_low(&mut driver, 20);
    assert_eq!(bench.remaining().len(), 3);
    assert_eq!(bench.operations().len(), 0);
    assert!(
        reasons.contains(&BlockedReason::RuleNotValidated {
            rule: "xcode.inactive-derived-data".to_owned()
        }),
        "{reasons:?}"
    );
    // No discovery ran: the source examines no rule that is `proposed`.
    assert!(
        !bench
            .modes
            .lock()
            .unwrap()
            .contains(&PreparationMode::Refresh)
    );
    stop(&bench, driver);
}

#[test]
fn with_no_discovery_before_the_incident_nothing_is_evicted() {
    let mut bench = Bench::validated(&[]);
    bench.seed_authority();
    let mut driver = bench.start();
    // The capacity is below the reclaim threshold from the first sample:
    // the guard asks only for the known candidates, and none is known. A
    // resource emergency starts no discovery.
    let reasons = bench.run_low(&mut driver, 20);
    assert_eq!(bench.remaining().len(), 3);
    assert_eq!(bench.operations().len(), 0);
    let modes: Vec<PreparationMode> = bench.modes.lock().unwrap().clone();
    assert!(!modes.contains(&PreparationMode::Refresh), "{modes:?}");
    assert!(modes.contains(&PreparationMode::KnownOnly));
    assert!(
        reasons.contains(&BlockedReason::NoEligibleTarget),
        "{reasons:?}"
    );
    stop(&bench, driver);
}

#[test]
fn a_producer_that_starts_after_the_discovery_inhibits_the_eviction() {
    let mut bench = Bench::validated(&[]);
    bench.seed_authority();
    let mut driver = bench.start();
    bench.discover(&mut driver);
    // A build starts. The examination of the known candidates reads the
    // process evidence again.
    bench.environment.set_producer(ProducerProcesses::Running);
    let reasons = bench.run_low(&mut driver, 20);
    assert_eq!(bench.remaining().len(), 3, "{reasons:?}");
    assert_eq!(bench.operations().len(), 0);
    // The build ends, and the guard acts.
    bench
        .environment
        .set_producer(ProducerProcesses::NotRunning);
    bench.run_low(&mut driver, 20);
    assert_eq!(bench.remaining(), Vec::<String>::new());
    stop(&bench, driver);
}

#[test]
fn a_producer_that_starts_after_the_admission_inhibits_each_later_step() {
    let mut bench = Bench::validated(&[]);
    // One unit of coordinator work for each tick, so that the producer
    // can start between two steps of one operation.
    bench.coordinator_units = 1;
    bench.gain.store(GIBIBYTE, Ordering::SeqCst);
    bench.seed_authority();
    let mut driver = bench.start();
    bench.discover(&mut driver);
    let mut operation_id: Option<OperationId> = None;
    for _ in 0..40 {
        driver.tick(Some(bench.sample(bench.measurements().available())));
        bench.clock.advance(SAMPLE);
        operation_id = driver
            .controller_state()
            .outstanding
            .as_ref()
            .and_then(|outstanding| outstanding.operation_id.clone());
        if operation_id.is_some() {
            break;
        }
    }
    let operation_id: OperationId = operation_id.expect("an operation was admitted");
    // A build starts after the plan was admitted. The plan has the three
    // units; the fresh check of each later step reads the process
    // evidence again.
    let before: usize = bench.remaining().len();
    assert!(
        before >= 2,
        "the operation ended in the tick of its admission"
    );
    bench.environment.set_producer(ProducerProcesses::Running);
    bench.run_low(&mut driver, 20);
    assert_eq!(bench.remaining().len(), before);
    let operation = bench.journal().operation(&operation_id).unwrap().unwrap();
    let skipped: Vec<String> = operation
        .steps()
        .iter()
        .flat_map(svalnir_core::action::Step::results)
        .filter(|result| result.effect == TargetEffect::Skipped)
        .filter_map(|result| result.failure.as_ref())
        .map(|failure| failure.code.as_str().to_owned())
        .collect();
    assert_eq!(skipped.len(), before, "{:?}", operation.steps());
    assert!(
        skipped.iter().all(|code| code == "producer_active"),
        "{skipped:?}"
    );
    // The producer was not stopped, and the operation is settled.
    assert_ne!(operation.state(), &OperationState::Completed);
    assert_eq!(bench.journal().unsettled_operation_count().unwrap(), 0);
    stop(&bench, driver);
}

#[test]
fn a_unit_that_is_replaced_after_the_discovery_is_not_removed() {
    let mut bench = Bench::validated(&[]);
    bench.seed_authority();
    let mut driver = bench.start();
    bench.discover(&mut driver);
    // A different directory with a file of the user takes the name of one
    // unit.
    let unit: PathBuf = bench.unit("Build/Products");
    fs::rename(&unit, bench.base.join("moved-products")).unwrap();
    fs::create_dir(&unit).unwrap();
    fs::write(unit.join("precious.txt"), b"a file of the user").unwrap();
    bench.run_low(&mut driver, 30);
    assert_eq!(bench.remaining(), vec!["Build/Products".to_owned()]);
    assert!(unit.join("precious.txt").exists());
    // The directory that was moved away is not a target.
    assert!(bench.base.join("moved-products/Debug/App.app/App").exists());
    stop(&bench, driver);
}

#[test]
fn a_unit_that_cannot_be_read_stays_and_the_other_units_are_removed() {
    let mut bench = Bench::validated(&[]);
    bench.seed_authority();
    let mut driver = bench.start();
    bench.discover(&mut driver);
    // A directory below one unit loses each permission after the
    // discovery. The times of the unit directory do not change, so the
    // unit stays a known candidate, and the executor finds the failure.
    let closed: PathBuf = bench.unit("Build/Products/Debug/App.app");
    fs::set_permissions(&closed, fs::Permissions::from_mode(0o000)).unwrap();
    let reasons = bench.run_low(&mut driver, 30);
    fs::set_permissions(&closed, fs::Permissions::from_mode(0o700)).unwrap();
    // The superuser can read each directory.
    if user().get() == 0 {
        return;
    }
    assert_eq!(
        bench.remaining(),
        vec!["Build/Products".to_owned()],
        "{reasons:?}"
    );
    assert!(closed.join("App").exists());
    // The operation is not `Completed`: one target has no removal. There
    // is no retry as a different user.
    let operations = bench.operations();
    let states: Vec<&OperationState> = operations
        .iter()
        .map(svalnir_core::action::Operation::state)
        .collect();
    assert!(
        states
            .iter()
            .any(|state| **state != OperationState::Completed),
        "{states:?}"
    );
    let effects: Vec<TargetEffect> = operations
        .iter()
        .flat_map(svalnir_core::action::Operation::steps)
        .flat_map(|step| step.results().iter().map(|result| result.effect.clone()))
        .collect();
    assert_eq!(
        effects
            .iter()
            .filter(|effect| **effect == TargetEffect::Removed)
            .count(),
        2,
        "{effects:?}"
    );
    assert_eq!(bench.journal().unsettled_operation_count().unwrap(), 0);
    stop(&bench, driver);
}

#[test]
fn a_removal_with_no_capacity_gain_starts_the_backoff() {
    let mut bench = Bench::two_single_unit_projects(&[]);
    // The removals do not change the measured capacity.
    bench.gain.store(0, Ordering::SeqCst);
    bench.seed_authority();
    let mut driver = bench.start();
    bench.discover(&mut driver);
    // 200 seconds of low capacity: less than the backoff of 15 minutes.
    let reasons = bench.run_low(&mut driver, 40);
    // One batch ran. The guard measured no gain and does not remove more
    // to try again.
    assert_eq!(bench.remaining().len(), 1, "{reasons:?}");
    let finished = bench.finished();
    assert_eq!(finished, vec![("Completed".to_owned(), true)]);
    assert_eq!(bench.operations().len(), 1);
    // The incident has the backoff, and the status shows it.
    let record = &driver.controller_state().disk_incidents[0];
    assert!(record.observe_until.is_some(), "{record:?}");
    assert_eq!(
        phase(&driver, Guard::Disk),
        GuardPhase::Cooldown,
        "{reasons:?}"
    );
    stop(&bench, driver);
}

/// Runs 300 seconds of low capacity with one unit for each batch and a
/// small gain for each removal, so that the capacity stays below the
/// reclaim threshold. Returns the bench, the driver, and the reasons.
fn run_small_batches(changes: &[(&str, &str)]) -> (Bench, Box<Driver>, Vec<BlockedReason>) {
    let mut bench = Bench::two_single_unit_projects(changes);
    bench.gain.store(GIBIBYTE, Ordering::SeqCst);
    bench.seed_authority();
    let mut driver = bench.start();
    bench.discover(&mut driver);
    let reasons = bench.run_low(&mut driver, 60);
    (bench, driver, reasons)
}

#[test]
fn the_incident_budget_stops_the_eviction() {
    // With the ceilings of the test configuration, the batches continue
    // while the capacity is low: each unit is removed, and the guard
    // measures the capacity again after each batch.
    let (bench, driver, reasons) = run_small_batches(&[]);
    assert_eq!(bench.remaining(), Vec::<String>::new(), "{reasons:?}");
    assert_eq!(bench.operations().len(), 2);
    assert_eq!(
        bench.finished(),
        vec![
            ("Completed".to_owned(), false),
            ("Completed".to_owned(), false)
        ]
    );
    stop(&bench, driver);

    // An item ceiling of the pass and of the incident with room for one
    // unit: the other unit stays, with the capacity still low.
    let (bench, driver, reasons) = run_small_batches(&[
        ("pass_item_limit = 2048", "pass_item_limit = 6"),
        ("incident_item_limit = 4096", "incident_item_limit = 6"),
    ]);
    assert_eq!(bench.remaining().len(), 1, "{reasons:?}");
    assert_eq!(bench.operations().len(), 1);
    let state: &ControllerState = driver.controller_state();
    let usage = &state.policy.disk.incidents[0].usage;
    assert_eq!(usage.consumed_items.get(), 5, "{usage:?}");
    stop(&bench, driver);
}

#[test]
fn the_other_units_of_a_project_are_not_evicted_after_its_intermediates() {
    // One unit for each batch, and one project with its three units.
    let mut bench = Bench::validated(&[("batch_item_limit = 256", "batch_item_limit = 6")]);
    bench.gain.store(GIBIBYTE, Ordering::SeqCst);
    bench.seed_authority();
    let mut driver = bench.start();
    bench.discover(&mut driver);
    let reasons = bench.run_low(&mut driver, 60);
    // The first batch removed one unit. When it was the intermediates,
    // the project has no build database, the lock check of the rule has
    // no result, and the other units are not candidates: they stay. When
    // it was a different unit, the batches continue to the intermediates.
    let remaining = bench.remaining();
    assert!(
        !remaining.contains(&"Build/Intermediates.noindex".to_owned()),
        "{reasons:?}"
    );
    for operation in bench.operations() {
        assert_eq!(operation.state(), &OperationState::Completed);
    }
    assert_eq!(bench.operations().len(), 3 - remaining.len());
    stop(&bench, driver);
}

#[test]
fn a_restart_during_an_automatic_eviction_does_not_evict_again() {
    let mut bench = Bench::two_single_unit_projects(&[]);
    // One unit of coordinator work for each tick, so that the crash is
    // between the admission and the end of the operation.
    bench.coordinator_units = 1;
    bench.gain.store(GIBIBYTE, Ordering::SeqCst);
    bench.seed_authority();
    let mut driver = bench.start();
    bench.discover(&mut driver);
    let mut operation_id: Option<OperationId> = None;
    for _ in 0..40 {
        driver.tick(Some(bench.sample(bench.measurements().available())));
        bench.clock.advance(SAMPLE);
        operation_id = driver
            .controller_state()
            .outstanding
            .as_ref()
            .and_then(|outstanding| outstanding.operation_id.clone());
        if operation_id.is_some() {
            break;
        }
    }
    let operation_id: OperationId = operation_id.expect("an operation was admitted");
    // The crash: the process ends with no record of a stop.
    drop(driver);
    let remaining_at_crash: usize = bench.remaining().len();

    let mut driver = bench.start();
    // The operation of the lifetime before this one was reconciled before
    // anything else, and it is never dispatched again.
    let operation = bench.journal().operation(&operation_id).unwrap().unwrap();
    assert_eq!(operation.executor_epoch().as_str(), "epoch_1");
    assert_ne!(operation.state(), &OperationState::Admitted);
    assert_eq!(bench.journal().unsettled_operation_count().unwrap(), 0);
    let state: &ControllerState = driver.controller_state();
    assert!(state.outstanding.is_none());
    assert!(!state.disk_incidents[0].established);

    // The capacity stays low. The incident of before the crash is not
    // established, so the new lifetime removes nothing.
    let reasons = bench.run_low(&mut driver, 30);
    assert_eq!(bench.remaining().len(), remaining_at_crash, "{reasons:?}");
    assert!(
        reasons.contains(&BlockedReason::IncidentStateNotEstablished),
        "{reasons:?}"
    );
    assert_eq!(bench.operations().len(), 1);
    stop(&bench, driver);
}

#[test]
fn a_changed_configuration_removes_the_root_of_a_rule_that_is_not_approved() {
    // The source and the roots follow the configuration in effect: with a
    // different approved rule, the rule of the fixture is not examined.
    let mut bench = Bench::validated(&[(
        XCODE_RULE_LINE,
        "approved_rules = [\"svalnir.expired-temporary\"]",
    )]);
    bench.seed_authority();
    let mut driver = bench.start();
    for _ in 0..6 {
        driver.tick(Some(bench.sample(ADVISORY)));
        bench.clock.advance(SAMPLE);
    }
    bench.run_low(&mut driver, 20);
    assert_eq!(bench.remaining().len(), 3);
    assert_eq!(bench.operations().len(), 0);
    stop(&bench, driver);
}
