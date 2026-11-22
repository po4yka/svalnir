//! The candidate source of the agent: the discovery of the reviewed rules.
//!
//! Owning specifications: `docs/POLICY_SPEC.md` section 9 and
//! `docs/CLEANUP_RULES.md` sections 6 and 11.
//!
//! The source runs the discovery of each rule that the disk guard of the
//! configuration in effect approves and that the registry permits for
//! automatic eviction ([`ReviewedRules::discover_for_eviction`]).
//!
//! - [`PreparationMode::Refresh`] starts one bounded discovery on a worker
//!   thread and returns at once, so the driver thread does not wait for a
//!   directory listing or a tree measurement: the controller continues to
//!   evaluate the memory guard. A later request takes the finished result.
//!   [`CandidateSource::cancel`] stops the worker at its next name.
//! - [`PreparationMode::KnownOnly`] examines the candidates of the latest
//!   discovery again on the calling thread. It lists no directory and
//!   measures no tree, and it has a short time bound. This is the only
//!   work of the source in a resource emergency. With no earlier
//!   discovery, the set is empty.
//!
//! - The `FSEvents` invalidation ([`super::invalidation`]): before each
//!   discovery, the source watches the approved roots that the discovery
//!   examines, so the discovery after a start of the stream is its full
//!   reconciliation. [`CandidateSource::invalidated`] reads the events; a
//!   change that is due marks the set as invalidated until a complete
//!   discovery that started after the change. The flag only makes the
//!   disk guard ask for a discovery again in the warning band. An event
//!   makes no candidate.
//!
//! The source changes no file.

use std::path::PathBuf;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use svalnir_core::id::{RuleId, VolumeId};
use svalnir_core::process::Uid;
use svalnir_core::quantity::EntryCount;
use svalnir_core::rule::RuleMode;
use svalnir_core::time::MonotonicNanos;

use super::invalidation::{CatalogWatch, CatalogWatchStatus};
use super::ports::{CandidateSource, Preparation};
use crate::controller::{
    CandidateSet, MAX_PREPARED_CANDIDATES, PreparationMode, PreparedCandidate,
};
use crate::platform::fsevents::{EventStream, UnsupportedStream};
use crate::protection::ProtectedLocations;
use crate::rules::{
    DiscoveredCandidate, DiscoveryHost, DiscoveryLimits, EvictionCandidate, EvictionDiscovery,
    EvictionRequest, ReviewedRules, SharedEnvironment, automatic_roots,
};
use crate::scan::CancellationToken;

/// The time bound of one examination of the known candidates. The
/// examination runs on the driver thread.
const KNOWN_ONLY_DURATION: Duration = Duration::from_secs(2);

/// A discovery that runs on a worker thread.
struct Worker {
    cancel: CancellationToken,
    handle: JoinHandle<EvictionDiscovery>,
    /// The time of the request that started the discovery. The candidates
    /// of the discovery are not newer than this time.
    started_at: MonotonicNanos,
    /// The rules and the exclusions of the request that started the
    /// discovery.
    scope: Scope,
}

/// The part of the configuration that a discovery depends on: the approved
/// rules and the exclusions. A result of a different scope is not used.
type Scope = (Vec<RuleId>, Vec<PathBuf>);

/// The candidate source of the agent.
pub struct RuleCandidateSource {
    registry: ReviewedRules,
    principal: Uid,
    locations: ProtectedLocations,
    environment: SharedEnvironment,
    limits: DiscoveryLimits,
    /// The candidates of the latest discovery or examination, for the next
    /// examination of known candidates.
    known: Vec<DiscoveredCandidate>,
    /// The latest set.
    latest: Option<CandidateSet>,
    /// The rules and the exclusions of the latest request.
    scope: Option<Scope>,
    worker: Option<Worker>,
    /// The event stream on the approved roots.
    watch: CatalogWatch,
    /// The time of the latest invalidation that no complete discovery
    /// covers: a discovery covers each invalidation when it started at
    /// this time or later. The latest time, not the earliest: a change
    /// during a discovery must not be covered by that discovery.
    invalidated_at: Option<MonotonicNanos>,
}

impl std::fmt::Debug for RuleCandidateSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuleCandidateSource")
            .field("principal", &self.principal)
            .field("known", &self.known.len())
            .field("discovery_runs", &self.worker.is_some())
            .field("invalidated_at", &self.invalidated_at)
            .finish_non_exhaustive()
    }
}

/// The prepared candidate of the controller for a candidate of a
/// discovery.
fn prepared(candidate: EvictionCandidate) -> PreparedCandidate {
    let estimate = candidate.estimate();
    let charge = candidate.charge();
    let EvictionCandidate {
        discovered,
        candidate,
    } = candidate;
    PreparedCandidate {
        candidate,
        root_id: discovered.root.root_id,
        root_path: discovered.root.path,
        root_object: discovered.root.object,
        relative_entry: discovered.evidence.relative_entry,
        mount_id: discovered.root.mount_id,
        object_type: discovered.evidence.object_type,
        owner: Some(discovered.evidence.owner),
        object: Some(discovered.evidence.object),
        link_count: Some(EntryCount::new(discovered.evidence.link_count)),
        charge: Some(charge),
        estimate,
    }
}

impl RuleCandidateSource {
    /// The source for the rules of `registry`, the user `principal`, and
    /// the locations of the agent.
    #[must_use]
    pub fn new(
        registry: ReviewedRules,
        principal: Uid,
        locations: ProtectedLocations,
        environment: SharedEnvironment,
        limits: DiscoveryLimits,
    ) -> Self {
        Self {
            registry,
            principal,
            locations,
            environment,
            limits,
            known: Vec::new(),
            latest: None,
            scope: None,
            worker: None,
            watch: CatalogWatch::new(Box::new(UnsupportedStream)),
            invalidated_at: None,
        }
    }

    /// The source with `stream` as its event stream on the approved roots.
    /// With no stream, the candidates are refreshed by age only.
    #[must_use]
    pub fn with_event_stream(mut self, stream: Box<dyn EventStream>) -> Self {
        self.watch = CatalogWatch::new(stream);
        self
    }

    /// The paths of the approved roots of `rules` that a discovery for an
    /// automatic eviction examines, as they are on the host now.
    fn watched_roots(&self, rules: &[RuleId]) -> Vec<PathBuf> {
        automatic_roots(&self.registry, rules, &self.locations)
            .iter()
            .map(|root| root.path.to_path_buf())
            .collect()
    }

    /// Records the result of a discovery (`full`) or of an examination
    /// of the known candidates that started at `at`.
    ///
    /// A result that is not complete (a discovery that was cancelled, that
    /// stopped at a bound, or that ended with no result) does not replace
    /// the known candidates: the candidates of the earlier complete result
    /// stay for the next examination, which examines each of them again.
    /// Only a complete discovery covers an invalidation, and only one that
    /// started at the time of the invalidation or later; an examination of
    /// the known candidates lists no directory and covers none.
    fn record(&mut self, discovery: EvictionDiscovery, at: MonotonicNanos, full: bool) {
        if full && discovery.complete && self.invalidated_at.is_some_and(|since| since <= at) {
            self.invalidated_at = None;
        }
        if discovery.complete {
            self.known = discovery
                .candidates
                .iter()
                .map(|candidate| candidate.discovered.clone())
                .collect();
        }
        // A set that the controller cannot use in full supports no plan.
        let complete: bool =
            discovery.complete && discovery.candidates.len() <= MAX_PREPARED_CANDIDATES;
        self.latest = Some(CandidateSet {
            prepared_at: at,
            complete,
            candidates: discovery
                .candidates
                .into_iter()
                .take(MAX_PREPARED_CANDIDATES)
                .map(prepared)
                .collect(),
            invalidated: self.invalidated_at.is_some(),
        });
    }

    /// Waits for a discovery that runs now and gives the latest set. A
    /// test uses it to make the result of a discovery a part of its
    /// sequence.
    #[cfg(test)]
    pub(crate) fn wait_for_discovery(&mut self) -> Option<CandidateSet> {
        if let Some(worker) = self.worker.take() {
            let discovery: EvictionDiscovery = worker.handle.join().unwrap_or_default();
            self.record(discovery, worker.started_at, true);
        }
        self.latest.clone()
    }

    /// Takes the result of the worker when it finished. A worker that
    /// ended with no result (a defect) gives a set that is not complete.
    /// The result of a discovery that started with different approved
    /// rules or exclusions than `scope` is discarded: the configuration
    /// changed, and the controller asks again when its set is old.
    fn take_finished(&mut self, scope: &Scope) {
        if !self
            .worker
            .as_ref()
            .is_some_and(|worker| worker.handle.is_finished())
        {
            return;
        }
        let Some(worker) = self.worker.take() else {
            return;
        };
        let discovery: EvictionDiscovery = worker.handle.join().unwrap_or_default();
        if &worker.scope == scope {
            self.record(discovery, worker.started_at, true);
        }
    }

    fn start(&mut self, host: DiscoveryHost, rules: Vec<RuleId>, request: &Preparation<'_>) {
        // The stream runs before the discovery starts, so each change after
        // the start of the discovery has an event, and the discovery is
        // the reconciliation of a new stream.
        let roots: Vec<PathBuf> = self.watched_roots(&rules);
        self.watch.watch(roots);
        let cancel: CancellationToken = CancellationToken::new();
        let registry: ReviewedRules = self.registry.clone();
        let environment: SharedEnvironment = Arc::clone(&self.environment);
        let limits: DiscoveryLimits = self.limits;
        let volumes: Vec<VolumeId> = request.volumes.to_vec();
        let token: CancellationToken = cancel.clone();
        let scope: Scope = (rules.clone(), host.user_exclusions.clone());
        let spawned = std::thread::Builder::new()
            .name("svalnir-rule-discovery".to_owned())
            .spawn(move || {
                registry.discover_for_eviction(
                    &EvictionRequest {
                        host: &host,
                        purpose: &RuleMode::AutomaticEviction,
                        rules: Some(&rules),
                        volumes: Some(&volumes),
                        known: None,
                        limits,
                        cancel: &token,
                        // An automatic operation never examines the rule of
                        // the project directories.
                        projects: None,
                    },
                    environment.as_ref(),
                )
            });
        // With no thread, no discovery runs. The controller asks again
        // when its set is old.
        if let Ok(handle) = spawned {
            self.worker = Some(Worker {
                cancel,
                handle,
                started_at: request.time.clock.now,
                scope,
            });
        }
    }
}

impl CandidateSource for RuleCandidateSource {
    fn prepare(&mut self, request: &Preparation<'_>) -> Option<CandidateSet> {
        let rules: Vec<RuleId> = request.config.disk_guard().approved_rules.clone();
        let host: DiscoveryHost =
            DiscoveryHost::automatic(self.principal, self.locations.clone(), request.config);
        let scope: Scope = (rules.clone(), host.user_exclusions.clone());
        // A set of a different configuration supports no plan.
        if self.scope.as_ref().is_some_and(|known| known != &scope) {
            self.latest = None;
        }
        self.scope = Some(scope.clone());
        self.take_finished(&scope);
        match request.mode {
            PreparationMode::Refresh => {
                if self.worker.is_none() {
                    self.start(host, rules, request);
                }
            }
            PreparationMode::KnownOnly => {
                let cancel: CancellationToken = CancellationToken::new();
                let discovery: EvictionDiscovery = self.registry.discover_for_eviction(
                    &EvictionRequest {
                        host: &host,
                        purpose: &RuleMode::AutomaticEviction,
                        rules: Some(&rules),
                        volumes: Some(request.volumes),
                        known: Some(&self.known),
                        limits: DiscoveryLimits {
                            max_duration: KNOWN_ONLY_DURATION.min(self.limits.max_duration),
                            ..self.limits
                        },
                        cancel: &cancel,
                        projects: None,
                    },
                    self.environment.as_ref(),
                );
                self.record(discovery, request.time.clock.now, false);
            }
        }
        self.latest.clone()
    }

    fn cancel(&mut self) {
        if let Some(worker) = &self.worker {
            worker.cancel.cancel();
        }
    }

    fn invalidated(&mut self, at: MonotonicNanos) -> bool {
        if self.watch.poll(at) {
            // Monotonic: the latest time of an invalidation.
            self.invalidated_at = Some(self.invalidated_at.map_or(at, |earlier| earlier.max(at)));
        }
        let invalidated: bool = self.invalidated_at.is_some();
        if let Some(set) = &mut self.latest {
            set.invalidated = invalidated;
        }
        invalidated
    }

    fn watch_status(&self) -> Option<CatalogWatchStatus> {
        Some(self.watch.status())
    }
}

impl Drop for RuleCandidateSource {
    fn drop(&mut self) {
        // The worker reads the flag before each name, so the wait is
        // short.
        if let Some(worker) = self.worker.take() {
            worker.cancel.cancel();
            drop(worker.handle.join());
        }
        self.watch.stop();
    }
}

#[cfg(test)]
#[cfg(target_os = "macos")]
mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;

    use svalnir_core::config::ValidatedConfig;
    use svalnir_core::id::VolumeId;

    use svalnir_core::time::MonotonicNanos;

    use super::RuleCandidateSource;
    use crate::controller::PreparationMode;
    use crate::controller::tests::support::{config, time, user};
    use crate::platform::fsevents::{RawEvent, WatchError};
    use crate::platform::volume::volume_at;
    use crate::protection::ProtectedLocations;
    use crate::rules::fixture::{
        FixtureEnvironment, automatic_eviction_validated, derived_data_root, write_project,
        write_workspace,
    };
    use crate::rules::{DiscoveryLimits, ReviewedRules};
    use crate::runtime::invalidation::CatalogWatchState;
    use crate::runtime::invalidation::tests::FakeStream;
    use crate::runtime::{CandidateSource as _, Preparation};

    const RULE_LINE: &str = "approved_rules = [\"test.cache\"]";
    const XCODE_RULE_LINE: &str = "approved_rules = [\"xcode.inactive-derived-data\"]";

    /// A source for a home directory with one project, in a temporary
    /// directory, and the volume of that directory.
    fn source() -> (tempfile::TempDir, RuleCandidateSource, VolumeId) {
        let directory = tempfile::tempdir().unwrap();
        let base: PathBuf = std::fs::canonicalize(directory.path()).unwrap();
        let home: PathBuf = base.join("home");
        let state: PathBuf = home.join("state");
        let root: PathBuf = derived_data_root(&home);
        std::fs::create_dir_all(&state).unwrap();
        std::fs::create_dir_all(&root).unwrap();
        let workspace = write_workspace(&base.join("src"), "App").unwrap();
        write_project(&root, "App-abcdefghijklmnopqrstuvwxyzab", &workspace).unwrap();
        let volume: VolumeId = volume_at(&root).unwrap().identity.volume_id;
        let source = RuleCandidateSource::new(
            ReviewedRules::with_fixture_lifecycle(&automatic_eviction_validated()).unwrap(),
            user(),
            ProtectedLocations::resolve(Some(&home), Some(&state)),
            Arc::new(FixtureEnvironment::days_later(30)),
            DiscoveryLimits::default(),
        );
        (directory, source, volume)
    }

    fn approved() -> ValidatedConfig {
        config(&[(RULE_LINE, XCODE_RULE_LINE)])
    }

    fn count(
        source: &mut RuleCandidateSource,
        mode: PreparationMode,
        volume: &VolumeId,
        config: &ValidatedConfig,
        now: u64,
    ) -> Option<(bool, usize)> {
        let time = time(now);
        source
            .prepare(&Preparation {
                volumes: std::slice::from_ref(volume),
                mode,
                time: &time,
                config,
            })
            .map(|set| (set.complete, set.candidates.len()))
    }

    #[test]
    fn a_discovery_gives_the_known_candidates_of_a_later_examination() {
        let (_directory, mut source, volume) = source();
        let config = approved();
        // With no discovery, nothing is known.
        assert_eq!(
            count(&mut source, PreparationMode::KnownOnly, &volume, &config, 1),
            Some((true, 0))
        );
        count(&mut source, PreparationMode::Refresh, &volume, &config, 2);
        let found = source.wait_for_discovery().unwrap();
        assert!(found.complete);
        assert_eq!(found.candidates.len(), 3);
        assert_eq!(
            count(&mut source, PreparationMode::KnownOnly, &volume, &config, 3),
            Some((true, 3))
        );
    }

    #[test]
    fn a_cancelled_discovery_keeps_the_known_candidates() {
        let (_directory, mut source, volume) = source();
        let config = approved();
        count(&mut source, PreparationMode::Refresh, &volume, &config, 1);
        assert_eq!(source.wait_for_discovery().unwrap().candidates.len(), 3);
        // A second discovery is cancelled before it ends, as it is when
        // optional work is reduced. A discovery that was cancelled before
        // its first name has no candidate.
        let cancelled = super::EvictionDiscovery::default();
        assert!(!cancelled.complete);
        source.record(cancelled, time(2).clock.now, true);
        assert!(!source.latest.as_ref().unwrap().complete);
        // The emergency still examines the candidates of the complete
        // discovery.
        assert_eq!(
            count(&mut source, PreparationMode::KnownOnly, &volume, &config, 3),
            Some((true, 3))
        );
    }

    #[test]
    fn a_changed_configuration_discards_the_set_and_the_running_discovery() {
        let (_directory, mut source, volume) = source();
        let config = approved();
        count(&mut source, PreparationMode::Refresh, &volume, &config, 1);
        assert_eq!(source.wait_for_discovery().unwrap().candidates.len(), 3);
        // A discovery starts with the approved rule. Before its result is
        // taken, the configuration approves a different rule.
        count(&mut source, PreparationMode::Refresh, &volume, &config, 2);
        while !source.worker.as_ref().unwrap().handle.is_finished() {
            std::thread::yield_now();
        }
        let other = config_with_other_rule();
        // The set of the earlier configuration is not given, the result of
        // the discovery is discarded, and the rule that is not approved is
        // not examined.
        assert_eq!(
            count(&mut source, PreparationMode::KnownOnly, &volume, &other, 3),
            Some((true, 0))
        );
    }

    const SECOND: u64 = 1_000_000_000;

    /// A source as [`source`] with a fake event stream, and the derived
    /// data root of the fixture.
    fn watched_source() -> (
        tempfile::TempDir,
        RuleCandidateSource,
        VolumeId,
        FakeStream,
        PathBuf,
    ) {
        let (directory, source, volume) = source();
        let fake = FakeStream::default();
        let source = source.with_event_stream(Box::new(fake.clone()));
        let base: PathBuf = std::fs::canonicalize(directory.path()).unwrap();
        let root: PathBuf = derived_data_root(&base.join("home"));
        (directory, source, volume, fake, root)
    }

    fn change_below(root: &std::path::Path) -> RawEvent {
        RawEvent {
            path: root.join("App-abcdefghijklmnopqrstuvwxyzab"),
            flags: 0,
            id: 42,
        }
    }

    #[test]
    fn a_discovery_starts_the_stream_on_the_approved_roots_first() {
        let (_directory, mut source, volume, fake, root) = watched_source();
        let config = approved();
        assert_eq!(
            source.watch_status().unwrap().state,
            CatalogWatchState::NotStarted
        );
        count(
            &mut source,
            PreparationMode::Refresh,
            &volume,
            &config,
            SECOND,
        );
        // The stream started before the discovery, on the root of each
        // approved rule that exists.
        let starts = fake.0.lock().unwrap().starts.clone();
        assert_eq!(starts.len(), 1);
        assert!(starts[0].contains(&root), "{starts:?}");
        assert_eq!(
            source.watch_status().unwrap().state,
            CatalogWatchState::Available
        );
        assert!(!source.wait_for_discovery().unwrap().invalidated);
        // An examination of the known candidates in an emergency starts no
        // stream and changes none.
        count(
            &mut source,
            PreparationMode::KnownOnly,
            &volume,
            &config,
            2 * SECOND,
        );
        assert_eq!(fake.0.lock().unwrap().starts.len(), 1);
    }

    #[test]
    fn an_event_invalidates_the_set_until_a_later_complete_discovery() {
        let (_directory, mut source, volume, fake, root) = watched_source();
        let config = approved();
        count(
            &mut source,
            PreparationMode::Refresh,
            &volume,
            &config,
            SECOND,
        );
        assert_eq!(source.wait_for_discovery().unwrap().candidates.len(), 3);
        fake.inject(vec![change_below(&root)]);
        // The debounce holds the change.
        assert!(!source.invalidated(MonotonicNanos::new(10 * SECOND)));
        assert!(source.invalidated(MonotonicNanos::new(15 * SECOND)));
        // The event made no candidate: the examination of the known
        // candidates gives the same three, and the set stays invalidated,
        // because an examination lists no directory.
        assert_eq!(
            count(
                &mut source,
                PreparationMode::KnownOnly,
                &volume,
                &config,
                16 * SECOND
            ),
            Some((true, 3))
        );
        assert!(source.latest.as_ref().unwrap().invalidated);
        assert!(source.invalidated(MonotonicNanos::new(17 * SECOND)));
        // A complete discovery that started after the change covers it.
        count(
            &mut source,
            PreparationMode::Refresh,
            &volume,
            &config,
            18 * SECOND,
        );
        let set = source.wait_for_discovery().unwrap();
        assert!(set.complete);
        assert!(!set.invalidated);
        assert!(!source.invalidated(MonotonicNanos::new(19 * SECOND)));
        // The same roots keep the stream.
        assert_eq!(fake.0.lock().unwrap().starts.len(), 1);
    }

    #[test]
    fn a_discovery_that_started_before_the_change_does_not_cover_it() {
        let (_directory, mut source, volume, fake, root) = watched_source();
        let config = approved();
        count(
            &mut source,
            PreparationMode::Refresh,
            &volume,
            &config,
            SECOND,
        );
        // The change is due while the discovery of second 1 runs.
        fake.inject(vec![change_below(&root)]);
        assert!(!source.invalidated(MonotonicNanos::new(2 * SECOND)));
        assert!(source.invalidated(MonotonicNanos::new(7 * SECOND)));
        let set = source.wait_for_discovery().unwrap();
        assert!(set.invalidated);
        assert!(source.invalidated(MonotonicNanos::new(8 * SECOND)));
    }

    #[test]
    fn a_change_during_a_discovery_is_not_covered_by_it() {
        let (_directory, mut source, volume, fake, root) = watched_source();
        let config = approved();
        count(
            &mut source,
            PreparationMode::Refresh,
            &volume,
            &config,
            SECOND,
        );
        drop(source.wait_for_discovery());
        // A first change is due at second 15.
        fake.inject(vec![change_below(&root)]);
        assert!(!source.invalidated(MonotonicNanos::new(10 * SECOND)));
        assert!(source.invalidated(MonotonicNanos::new(15 * SECOND)));
        // A discovery starts at second 16, after the first change.
        count(
            &mut source,
            PreparationMode::Refresh,
            &volume,
            &config,
            16 * SECOND,
        );
        // A second change arrives while it runs and is due at second 25,
        // before the result is taken.
        fake.inject(vec![change_below(&root)]);
        assert!(source.invalidated(MonotonicNanos::new(20 * SECOND)));
        assert!(source.invalidated(MonotonicNanos::new(25 * SECOND)));
        // The discovery covers the first change only: the set stays
        // invalidated.
        let set = source.wait_for_discovery().unwrap();
        assert!(set.complete);
        assert!(set.invalidated);
    }

    #[test]
    fn changes_held_at_the_start_of_a_discovery_are_covered_by_it() {
        let (_directory, mut source, volume, fake, root) = watched_source();
        let config = approved();
        count(
            &mut source,
            PreparationMode::Refresh,
            &volume,
            &config,
            SECOND,
        );
        drop(source.wait_for_discovery());
        // A change is read but still held in the debounce when the next
        // discovery starts, which covers it.
        fake.inject(vec![change_below(&root)]);
        assert!(!source.invalidated(MonotonicNanos::new(10 * SECOND)));
        count(
            &mut source,
            PreparationMode::Refresh,
            &volume,
            &config,
            12 * SECOND,
        );
        assert!(!source.invalidated(MonotonicNanos::new(20 * SECOND)));
        assert!(!source.wait_for_discovery().unwrap().invalidated);
    }

    #[test]
    fn a_lost_event_invalidates_the_set() {
        let (_directory, mut source, volume, fake, _root) = watched_source();
        let config = approved();
        count(
            &mut source,
            PreparationMode::Refresh,
            &volume,
            &config,
            SECOND,
        );
        drop(source.wait_for_discovery());
        fake.0
            .lock()
            .unwrap()
            .batches
            .push_back(crate::platform::fsevents::EventBatch {
                events: Vec::new(),
                lost: true,
            });
        assert!(!source.invalidated(MonotonicNanos::new(2 * SECOND)));
        assert!(source.invalidated(MonotonicNanos::new(7 * SECOND)));
        assert_eq!(
            source.watch_status().unwrap().counts.last_reconcile_reason,
            Some(crate::runtime::invalidation::ReconcileReason::EventsLost)
        );
    }

    #[test]
    fn a_refused_stream_leaves_the_refresh_by_age() {
        let (_directory, mut source, volume, fake, root) = watched_source();
        fake.0.lock().unwrap().refusal = Some(WatchError::Refused("FSEventStreamStart"));
        let config = approved();
        count(
            &mut source,
            PreparationMode::Refresh,
            &volume,
            &config,
            SECOND,
        );
        assert_eq!(
            source.watch_status().unwrap().state,
            CatalogWatchState::Denied
        );
        // The discovery runs, and an event of no stream invalidates
        // nothing.
        assert_eq!(source.wait_for_discovery().unwrap().candidates.len(), 3);
        fake.inject(vec![change_below(&root)]);
        assert!(!source.invalidated(MonotonicNanos::new(30 * SECOND)));
    }

    fn config_with_other_rule() -> ValidatedConfig {
        config(&[(
            RULE_LINE,
            "approved_rules = [\"svalnir.expired-temporary\"]",
        )])
    }
}
