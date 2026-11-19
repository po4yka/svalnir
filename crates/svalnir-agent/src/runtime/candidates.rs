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
//! The source changes no file.

use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use svalnir_core::id::{RuleId, VolumeId};
use svalnir_core::process::Uid;
use svalnir_core::quantity::EntryCount;
use svalnir_core::rule::RuleMode;
use svalnir_core::time::MonotonicNanos;

use super::ports::{CandidateSource, Preparation};
use crate::controller::{
    CandidateSet, MAX_PREPARED_CANDIDATES, PreparationMode, PreparedCandidate,
};
use crate::protection::ProtectedLocations;
use crate::rules::{
    DiscoveredCandidate, DiscoveryHost, DiscoveryLimits, EvictionCandidate, EvictionDiscovery,
    EvictionRequest, ReviewedRules, SharedEnvironment,
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
}

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
    worker: Option<Worker>,
}

impl std::fmt::Debug for RuleCandidateSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuleCandidateSource")
            .field("principal", &self.principal)
            .field("known", &self.known.len())
            .field("discovery_runs", &self.worker.is_some())
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
            worker: None,
        }
    }

    /// Records the result of a discovery or of an examination that
    /// started at `at`.
    fn record(&mut self, discovery: EvictionDiscovery, at: MonotonicNanos) {
        self.known = discovery
            .candidates
            .iter()
            .map(|candidate| candidate.discovered.clone())
            .collect();
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
        });
    }

    /// Waits for a discovery that runs now and gives the latest set. A
    /// test uses it to make the result of a discovery a part of its
    /// sequence.
    #[cfg(test)]
    pub(crate) fn wait_for_discovery(&mut self) -> Option<CandidateSet> {
        if let Some(worker) = self.worker.take() {
            let discovery: EvictionDiscovery = worker.handle.join().unwrap_or_default();
            self.record(discovery, worker.started_at);
        }
        self.latest.clone()
    }

    /// Takes the result of the worker when it finished. A worker that
    /// ended with no result (a defect) gives a set that is not complete.
    fn take_finished(&mut self) {
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
        self.record(discovery, worker.started_at);
    }

    fn start(&mut self, host: DiscoveryHost, rules: Vec<RuleId>, request: &Preparation<'_>) {
        let cancel: CancellationToken = CancellationToken::new();
        let registry: ReviewedRules = self.registry.clone();
        let environment: SharedEnvironment = Arc::clone(&self.environment);
        let limits: DiscoveryLimits = self.limits;
        let volumes: Vec<VolumeId> = request.volumes.to_vec();
        let token: CancellationToken = cancel.clone();
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
            });
        }
    }
}

impl CandidateSource for RuleCandidateSource {
    fn prepare(&mut self, request: &Preparation<'_>) -> Option<CandidateSet> {
        self.take_finished();
        let rules: Vec<RuleId> = request.config.disk_guard().approved_rules.clone();
        let host: DiscoveryHost =
            DiscoveryHost::automatic(self.principal, self.locations.clone(), request.config);
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
                    },
                    self.environment.as_ref(),
                );
                self.record(discovery, request.time.clock.now);
            }
        }
        self.latest.clone()
    }

    fn cancel(&mut self) {
        if let Some(worker) = &self.worker {
            worker.cancel.cancel();
        }
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
    }
}
