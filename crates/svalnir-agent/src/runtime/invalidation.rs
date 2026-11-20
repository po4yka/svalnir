//! The invalidation of the candidate catalog from `FSEvents`.
//!
//! Owning specification: `docs/ARCHITECTURE.md` section 5 ("Disk and
//! filesystem state"). `FSEvents` marks catalog regions dirty; it is not a
//! complete audit log.
//!
//! [`CatalogInvalidation`] reads the events of the stream on the approved
//! roots ([`crate::platform::fsevents`]) and keeps, for each root, either a
//! bounded set of dirty regions or a full reconciliation:
//!
//! - An ordinary event marks the directory of the event as a dirty region
//!   of the root that contains it.
//! - A coalesced event that asks for a scan of the subdirectories, a
//!   dropped event in the kernel or in the client, an event identifier
//!   that wrapped or went back, a changed root, a mount or an unmount, an
//!   event that no root contains, a loss in the inbox of the adapter, and
//!   a region set over its bound each give a full reconciliation of each
//!   affected root. The consumer never assumes that the events it did not
//!   get changed nothing.
//!
//! [`CatalogInvalidation::take_due`] gives the changes after a debounce: a
//! quiet interval after the last event, or a longest hold after the first
//! one, so a burst gives one invalidation and a long burst does not delay
//! it without bound.
//!
//! A change makes no candidate and authorizes no action. The candidate
//! source runs its bounded discovery again; each action still needs the
//! fresh checks of its targets at admission.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use svalnir_core::quantity::Nanoseconds;
use svalnir_core::time::MonotonicNanos;

use crate::platform::fsevents::{EventBatch, EventStream, RawEvent, WatchError, flags};

/// The largest number of dirty regions of one root. One more region makes
/// the root a full reconciliation.
pub const MAX_DIRTY_REGIONS: usize = 32;

/// The quiet interval after the last change, before the changes are due.
pub const QUIET_INTERVAL: Nanoseconds = Nanoseconds::new(5_000_000_000);

/// The longest hold of a change: after this interval from the first change,
/// the changes are due, also while events continue.
pub const MAX_HOLD: Nanoseconds = Nanoseconds::new(60_000_000_000);

/// Why a root needs a full reconciliation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconcileReason {
    /// Events were coalesced hierarchically
    /// (`kFSEventStreamEventFlagMustScanSubDirs`).
    MustScanSubdirectories,
    /// Events were dropped in the kernel or in the client
    /// (`kFSEventStreamEventFlagKernelDropped`,
    /// `kFSEventStreamEventFlagUserDropped`).
    EventsDropped,
    /// The event identifier wrapped
    /// (`kFSEventStreamEventFlagEventIdsWrapped`) or went back.
    EventIdsWrapped,
    /// A directory on the path to the root changed
    /// (`kFSEventStreamEventFlagRootChanged`).
    RootChanged,
    /// A volume was mounted below the root.
    Mount,
    /// A volume was unmounted below the root.
    Unmount,
    /// An event that no root contains.
    Unattributed,
    /// The inbox of the adapter lost events.
    EventsLost,
    /// The root had more dirty regions than [`MAX_DIRTY_REGIONS`].
    RegionLimit,
}

impl ReconcileReason {
    /// The stable name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MustScanSubdirectories => "must_scan_subdirectories",
            Self::EventsDropped => "events_dropped",
            Self::EventIdsWrapped => "event_ids_wrapped",
            Self::RootChanged => "root_changed",
            Self::Mount => "mount",
            Self::Unmount => "unmount",
            Self::Unattributed => "unattributed",
            Self::EventsLost => "events_lost",
            Self::RegionLimit => "region_limit",
        }
    }
}

/// What changed in one root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootChange {
    /// The dirty regions, relative to the root. An empty path is the root
    /// directory itself. At most [`MAX_DIRTY_REGIONS`], and no region is
    /// below another one.
    Regions(Vec<PathBuf>),
    /// The root needs a full reconciliation.
    Reconcile(ReconcileReason),
}

/// The changes of one root that are due.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DueChange {
    /// The root.
    pub root: PathBuf,
    /// What changed.
    pub change: RootChange,
}

/// The counts of the consumer in one stream lifetime.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvalidationCounts {
    /// The events that the consumer read.
    pub events: u64,
    /// The dirty regions that the consumer marked.
    pub regions: u64,
    /// The full reconciliations of a root that the consumer asked for.
    pub reconciliations: u64,
    /// The invalidations that were due.
    pub invalidations: u64,
    /// The reason of the latest full reconciliation.
    pub last_reconcile_reason: Option<ReconcileReason>,
}

#[derive(Debug, Clone)]
struct RootState {
    path: PathBuf,
    regions: Vec<PathBuf>,
    reconcile: Option<ReconcileReason>,
}

impl RootState {
    fn changed(&self) -> bool {
        self.reconcile.is_some() || !self.regions.is_empty()
    }
}

/// The consumer of the events of one stream on a set of roots.
#[derive(Debug, Clone)]
pub struct CatalogInvalidation {
    roots: Vec<RootState>,
    last_event_id: Option<u64>,
    first_change_at: Option<MonotonicNanos>,
    last_change_at: Option<MonotonicNanos>,
    counts: InvalidationCounts,
}

impl CatalogInvalidation {
    /// The consumer of a stream that started now on `roots`, with no
    /// change. The owner reconciles each root after the start, so the
    /// start itself is not a change.
    #[must_use]
    pub fn new(roots: Vec<PathBuf>) -> Self {
        Self {
            roots: roots
                .into_iter()
                .map(|path| RootState {
                    path,
                    regions: Vec::new(),
                    reconcile: None,
                })
                .collect(),
            last_event_id: None,
            first_change_at: None,
            last_change_at: None,
            counts: InvalidationCounts::default(),
        }
    }

    /// The watched roots.
    pub fn roots(&self) -> impl Iterator<Item = &Path> {
        self.roots.iter().map(|root| root.path.as_path())
    }

    /// The counts of this stream lifetime.
    #[must_use]
    pub const fn counts(&self) -> InvalidationCounts {
        self.counts
    }

    /// True when a change is held for the debounce.
    #[must_use]
    pub fn pending(&self) -> bool {
        self.roots.iter().any(RootState::changed)
    }

    /// Drops each change that is held, as after a full discovery that
    /// starts now and covers them.
    pub fn discard_pending(&mut self) {
        for root in &mut self.roots {
            root.regions.clear();
            root.reconcile = None;
        }
        self.first_change_at = None;
        self.last_change_at = None;
    }

    /// Reads the events of one drain at `at`.
    pub fn apply(&mut self, batch: EventBatch, at: MonotonicNanos) {
        let mut changed: bool = false;
        if batch.lost {
            changed |= self.reconcile_all(ReconcileReason::EventsLost);
        }
        for event in batch.events {
            self.counts.events = self.counts.events.saturating_add(1);
            changed |= self.apply_event(&event);
        }
        if changed {
            self.first_change_at.get_or_insert(at);
            self.last_change_at = Some(at);
        }
    }

    fn apply_event(&mut self, event: &RawEvent) -> bool {
        let flags: u32 = event.flags;
        // The path of the sentinel of the historical events has no
        // meaning. A stream of this build starts at "now" and gives none.
        if flags & flags::HISTORY_DONE != 0 {
            return false;
        }
        let mut changed: bool = false;
        // An identifier that wrapped, or that went back, makes each earlier
        // identifier not valid: the sequence of the stream is not known.
        // A root change has the identifier zero, which is no position.
        let went_back: bool =
            event.id != 0 && self.last_event_id.is_some_and(|last: u64| event.id < last);
        if flags & flags::EVENT_IDS_WRAPPED != 0 || went_back {
            changed |= self.reconcile_all(ReconcileReason::EventIdsWrapped);
        }
        if event.id != 0 {
            self.last_event_id = Some(event.id);
        }
        // A dropped event asks for a full scan of each watched root, as
        // `FSEvents.h` states.
        if flags & (flags::USER_DROPPED | flags::KERNEL_DROPPED) != 0 {
            return self.reconcile_all(ReconcileReason::EventsDropped) || changed;
        }
        let reason: Option<ReconcileReason> = if flags & flags::ROOT_CHANGED != 0 {
            Some(ReconcileReason::RootChanged)
        } else if flags & flags::MOUNT != 0 {
            Some(ReconcileReason::Mount)
        } else if flags & flags::UNMOUNT != 0 {
            Some(ReconcileReason::Unmount)
        } else if flags & flags::MUST_SCAN_SUBDIRS != 0 {
            Some(ReconcileReason::MustScanSubdirectories)
        } else {
            None
        };
        changed
            | match reason {
                Some(reason) => self.reconcile_affected(&event.path, reason),
                None => self.mark(&event.path),
            }
    }

    /// Marks the region of `path` in the root that contains it. A path
    /// that no root contains reconciles each root below it, or each root
    /// when no root is below it.
    fn mark(&mut self, path: &Path) -> bool {
        let Some(index) = self.containing(path) else {
            return self.reconcile_affected(path, ReconcileReason::Unattributed);
        };
        let root: &mut RootState = &mut self.roots[index];
        if root.reconcile.is_some() {
            return true;
        }
        let Ok(relative) = path.strip_prefix(&root.path) else {
            return self.reconcile_affected(path, ReconcileReason::Unattributed);
        };
        let relative: PathBuf = relative.to_path_buf();
        if root
            .regions
            .iter()
            .any(|region| relative.starts_with(region))
        {
            return true;
        }
        root.regions.retain(|region| !region.starts_with(&relative));
        root.regions.push(relative);
        self.counts.regions = self.counts.regions.saturating_add(1);
        if self.roots[index].regions.len() > MAX_DIRTY_REGIONS {
            self.reconcile(index, ReconcileReason::RegionLimit);
        }
        true
    }

    /// The index of the root that contains `path`: the longest root that
    /// is a prefix of it.
    fn containing(&self, path: &Path) -> Option<usize> {
        self.roots
            .iter()
            .enumerate()
            .filter(|(_, root)| path.starts_with(&root.path))
            .max_by_key(|(_, root)| root.path.components().count())
            .map(|(index, _)| index)
    }

    /// Reconciles each root that contains `path` or that is below it. With
    /// no such root, the attribution of the event is not known, and each
    /// root is reconciled.
    fn reconcile_affected(&mut self, path: &Path, reason: ReconcileReason) -> bool {
        let affected: Vec<usize> = self
            .roots
            .iter()
            .enumerate()
            .filter(|(_, root)| path.starts_with(&root.path) || root.path.starts_with(path))
            .map(|(index, _)| index)
            .collect();
        if affected.is_empty() {
            return self.reconcile_all(reason);
        }
        for index in affected {
            self.reconcile(index, reason);
        }
        true
    }

    fn reconcile_all(&mut self, reason: ReconcileReason) -> bool {
        for index in 0..self.roots.len() {
            self.reconcile(index, reason);
        }
        !self.roots.is_empty()
    }

    fn reconcile(&mut self, index: usize, reason: ReconcileReason) {
        let root: &mut RootState = &mut self.roots[index];
        root.regions.clear();
        // The first reason of a root stays: it is the earliest evidence.
        if root.reconcile.is_none() {
            root.reconcile = Some(reason);
            self.counts.reconciliations = self.counts.reconciliations.saturating_add(1);
            self.counts.last_reconcile_reason = Some(reason);
        }
    }

    /// Takes the changes when they are due at `now`: after
    /// [`QUIET_INTERVAL`] with no change, or [`MAX_HOLD`] after the first
    /// change. A clock reading before the first change is not due.
    pub fn take_due(&mut self, now: MonotonicNanos) -> Option<Vec<DueChange>> {
        if !self.pending() {
            return None;
        }
        let (Some(first), Some(last)) = (self.first_change_at, self.last_change_at) else {
            return None;
        };
        let quiet: bool = now
            .checked_duration_since(last)
            .is_some_and(|age| age >= QUIET_INTERVAL);
        let held: bool = now
            .checked_duration_since(first)
            .is_some_and(|age| age >= MAX_HOLD);
        if !quiet && !held {
            return None;
        }
        let changes: Vec<DueChange> = self
            .roots
            .iter_mut()
            .filter(|root| root.changed())
            .map(|root| DueChange {
                root: root.path.clone(),
                change: match root.reconcile.take() {
                    Some(reason) => {
                        root.regions.clear();
                        RootChange::Reconcile(reason)
                    }
                    None => RootChange::Regions(std::mem::take(&mut root.regions)),
                },
            })
            .collect();
        self.first_change_at = None;
        self.last_change_at = None;
        self.counts.invalidations = self.counts.invalidations.saturating_add(1);
        Some(changes)
    }
}

/// The state of the event stream of the candidate source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CatalogWatchState {
    /// A stream runs on the approved roots.
    Available,
    /// The platform refused the stream. `FSEvents` gives no reason, so a
    /// refusal for privacy and each other refusal have this one state.
    Denied,
    /// This platform has no `FSEvents`, or a root path has no `CFString`.
    Unsupported,
    /// No stream was started: no discovery ran in this agent lifetime, or
    /// no approved rule permits automatic eviction for a root that exists.
    NotStarted,
}

impl CatalogWatchState {
    /// The stable name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Denied => "denied",
            Self::Unsupported => "unsupported",
            Self::NotStarted => "not_started",
        }
    }
}

/// The catalog invalidation capability of the agent, as the status record
/// keeps it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogWatchStatus {
    /// The state of the stream.
    pub state: CatalogWatchState,
    /// One line that says what the state means for the candidates. It
    /// names no path.
    pub detail: String,
    /// The number of watched roots.
    pub roots: u32,
    /// The counts of the current stream lifetime. All zero with no stream.
    pub counts: InvalidationCounts,
}

/// The event stream of the candidate source, its consumer, and its state.
#[derive(Debug)]
pub struct CatalogWatch {
    stream: Box<dyn EventStream>,
    consumer: Option<CatalogInvalidation>,
    state: CatalogWatchState,
    detail: String,
}

const NO_DISCOVERY: &str =
    "No event stream: no discovery of the candidates ran in this agent lifetime";
const NO_ROOT: &str = "No event stream: no approved rule permits automatic eviction for a root that exists; the candidates are refreshed by age";
const AVAILABLE: &str = "FSEvents marks the approved roots dirty, and a dirty root gets the bounded discovery again; a lost, dropped, or coalesced event reconciles the root. A root that did not exist at the start of the latest discovery is not watched until a later discovery. An event authorizes no action";

impl CatalogWatch {
    /// The watch of `stream`, before its first start.
    #[must_use]
    pub fn new(stream: Box<dyn EventStream>) -> Self {
        Self {
            stream,
            consumer: None,
            state: CatalogWatchState::NotStarted,
            detail: NO_DISCOVERY.to_owned(),
        }
    }

    /// Watches `roots`. The caller starts a full discovery of each root
    /// after the call, which is the reconciliation of a new stream.
    ///
    /// A stream that runs on the same roots continues. A different set
    /// starts a new stream, and an empty set stops the stream. A stream
    /// that did not start is tried again at the next call.
    pub fn watch(&mut self, roots: Vec<PathBuf>) {
        if roots.is_empty() {
            self.stop();
            self.state = CatalogWatchState::NotStarted;
            NO_ROOT.clone_into(&mut self.detail);
            return;
        }
        let same: bool = self
            .consumer
            .as_ref()
            .is_some_and(|consumer| consumer.roots().eq(roots.iter().map(PathBuf::as_path)));
        if same {
            // The discovery that follows the call covers each change that
            // arrived before it: those changes are taken now and dropped,
            // so they do not invalidate the result of that discovery. A
            // change that FSEvents still holds arrives later and
            // invalidates it again, which is conservative.
            if let Some(consumer) = &mut self.consumer {
                consumer.apply(self.stream.drain(), MonotonicNanos::new(0));
                consumer.discard_pending();
            }
            return;
        }
        self.consumer = None;
        match self.stream.start(&roots) {
            Ok(()) => {
                self.consumer = Some(CatalogInvalidation::new(roots));
                self.state = CatalogWatchState::Available;
                AVAILABLE.clone_into(&mut self.detail);
            }
            Err(error) => {
                self.state = match error {
                    WatchError::Refused(_) => CatalogWatchState::Denied,
                    WatchError::Unsupported | WatchError::PathNotUnicode => {
                        CatalogWatchState::Unsupported
                    }
                };
                self.detail =
                    format!("No event stream: {error}; the candidates are refreshed by age");
            }
        }
    }

    /// Stops the stream. The state stays until the next call of
    /// [`Self::watch`].
    pub fn stop(&mut self) {
        self.stream.stop();
        self.consumer = None;
    }

    /// Reads the events since the last call at `now`. Returns true when an
    /// invalidation is due: the latest discovery does not show the roots
    /// as they are now.
    pub fn poll(&mut self, now: MonotonicNanos) -> bool {
        let batch: EventBatch = self.stream.drain();
        let Some(consumer) = &mut self.consumer else {
            return false;
        };
        consumer.apply(batch, now);
        consumer.take_due(now).is_some()
    }

    /// The capability for the status record.
    #[must_use]
    pub fn status(&self) -> CatalogWatchStatus {
        CatalogWatchStatus {
            state: self.state,
            detail: self.detail.clone(),
            roots: self.consumer.as_ref().map_or(0, |consumer| {
                u32::try_from(consumer.roots().count()).unwrap_or(u32::MAX)
            }),
            counts: self
                .consumer
                .as_ref()
                .map_or(InvalidationCounts::default(), CatalogInvalidation::counts),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;
