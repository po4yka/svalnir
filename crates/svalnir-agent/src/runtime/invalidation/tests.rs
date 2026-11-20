//! The consumer and the watch with injected event sequences. No test
//! starts a native stream: the stream is a fake.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use svalnir_core::time::MonotonicNanos;

use super::{
    CatalogInvalidation, CatalogWatch, CatalogWatchState, DueChange, MAX_DIRTY_REGIONS, MAX_HOLD,
    QUIET_INTERVAL, ReconcileReason, RootChange,
};
use crate::platform::fsevents::{EventBatch, EventStream, RawEvent, WatchError, flags};

const SECOND: u64 = 1_000_000_000;

fn at(seconds: u64) -> MonotonicNanos {
    MonotonicNanos::new(seconds * SECOND)
}

fn roots() -> Vec<PathBuf> {
    vec![
        PathBuf::from("/home/Library/Developer/Xcode/DerivedData"),
        PathBuf::from("/home/Library/Caches/Svalnir"),
    ]
}

fn event(path: &str, flags: u32, id: u64) -> RawEvent {
    RawEvent {
        path: PathBuf::from(path),
        flags,
        id,
    }
}

fn batch(events: Vec<RawEvent>) -> EventBatch {
    EventBatch {
        events,
        lost: false,
    }
}

/// The consumer after `events` at second 10, taken after the quiet
/// interval.
fn due_after(events: Vec<RawEvent>) -> Vec<DueChange> {
    let mut consumer = CatalogInvalidation::new(roots());
    consumer.apply(batch(events), at(10));
    consumer.take_due(at(10 + 5)).unwrap_or_default()
}

fn reconcile(root: &str, reason: ReconcileReason) -> DueChange {
    DueChange {
        root: PathBuf::from(root),
        change: RootChange::Reconcile(reason),
    }
}

fn reconcile_all(reason: ReconcileReason) -> Vec<DueChange> {
    roots()
        .iter()
        .map(|root| reconcile(root.to_str().unwrap(), reason))
        .collect()
}

const XCODE: &str = "/home/Library/Developer/Xcode/DerivedData";

#[test]
fn an_event_marks_a_region_after_the_quiet_interval() {
    let mut consumer = CatalogInvalidation::new(roots());
    // A new stream has no change: the discovery after the start is its
    // reconciliation.
    assert!(!consumer.pending());
    assert_eq!(consumer.take_due(at(100)), None);
    consumer.apply(
        batch(vec![
            event(&format!("{XCODE}/App-abc/Build/"), 0, 10),
            // A region below a dirty region adds nothing.
            event(&format!("{XCODE}/App-abc/Build/Products/"), 0, 11),
        ]),
        at(10),
    );
    assert!(consumer.pending());
    // Not due before the quiet interval.
    assert_eq!(consumer.take_due(at(14)), None);
    let due = consumer.take_due(at(15)).unwrap();
    assert_eq!(
        due,
        vec![DueChange {
            root: PathBuf::from(XCODE),
            change: RootChange::Regions(vec![PathBuf::from("App-abc/Build")]),
        }]
    );
    // The changes were taken.
    assert!(!consumer.pending());
    assert_eq!(consumer.counts().invalidations, 1);
    assert_eq!(consumer.counts().events, 2);
}

#[test]
fn a_region_above_dirty_regions_replaces_them() {
    let due = due_after(vec![
        event(&format!("{XCODE}/A/x/"), 0, 1),
        event(&format!("{XCODE}/A/y/"), 0, 2),
        event(&format!("{XCODE}/A/"), 0, 3),
    ]);
    assert_eq!(
        due,
        vec![DueChange {
            root: PathBuf::from(XCODE),
            change: RootChange::Regions(vec![PathBuf::from("A")]),
        }]
    );
}

#[test]
fn a_coalesced_event_reconciles_the_root_that_contains_it() {
    let due = due_after(vec![event(
        &format!("{XCODE}/App-abc/"),
        flags::MUST_SCAN_SUBDIRS,
        5,
    )]);
    // Only the affected root: the other root has no change.
    assert_eq!(
        due,
        vec![reconcile(XCODE, ReconcileReason::MustScanSubdirectories)]
    );
}

#[test]
fn a_coalesced_event_above_the_roots_reconciles_each_root_below_it() {
    // FSEvents can coalesce events of two directories into their parent.
    let due = due_after(vec![event("/home/Library/", flags::MUST_SCAN_SUBDIRS, 5)]);
    assert_eq!(due, reconcile_all(ReconcileReason::MustScanSubdirectories));
}

#[test]
fn a_dropped_event_reconciles_each_root() {
    for dropped in [flags::USER_DROPPED, flags::KERNEL_DROPPED] {
        // The path of a dropped event names one directory, but the events
        // of each root can be lost.
        let due = due_after(vec![event(
            &format!("{XCODE}/App-abc/"),
            flags::MUST_SCAN_SUBDIRS | dropped,
            5,
        )]);
        assert_eq!(due, reconcile_all(ReconcileReason::EventsDropped));
    }
}

#[test]
fn a_wrapped_event_identifier_reconciles_each_root() {
    let due = due_after(vec![event(
        &format!("{XCODE}/App-abc/"),
        flags::EVENT_IDS_WRAPPED,
        1,
    )]);
    assert_eq!(due, reconcile_all(ReconcileReason::EventIdsWrapped));
}

#[test]
fn an_event_identifier_that_goes_back_reconciles_each_root() {
    let mut consumer = CatalogInvalidation::new(roots());
    consumer.apply(batch(vec![event(&format!("{XCODE}/A/"), 0, 900)]), at(10));
    drop(consumer.take_due(at(20)));
    // An identifier lower than the last one, with no flag: the sequence
    // of the stream is not known.
    consumer.apply(batch(vec![event(&format!("{XCODE}/B/"), 0, 3)]), at(30));
    assert_eq!(
        consumer.take_due(at(35)).unwrap(),
        reconcile_all(ReconcileReason::EventIdsWrapped)
    );
    // A root change has the identifier zero, which is no position.
    consumer.apply(batch(vec![event(XCODE, flags::ROOT_CHANGED, 0)]), at(40));
    assert_eq!(
        consumer.take_due(at(45)).unwrap(),
        vec![reconcile(XCODE, ReconcileReason::RootChanged)]
    );
}

#[test]
fn a_changed_root_is_reconciled() {
    let due = due_after(vec![event(XCODE, flags::ROOT_CHANGED, 0)]);
    assert_eq!(due, vec![reconcile(XCODE, ReconcileReason::RootChanged)]);
}

#[test]
fn a_mount_or_an_unmount_reconciles_the_root() {
    let due = due_after(vec![event(&format!("{XCODE}/Volume/"), flags::MOUNT, 7)]);
    assert_eq!(due, vec![reconcile(XCODE, ReconcileReason::Mount)]);
    let due = due_after(vec![event(&format!("{XCODE}/Volume/"), flags::UNMOUNT, 7)]);
    assert_eq!(due, vec![reconcile(XCODE, ReconcileReason::Unmount)]);
}

#[test]
fn a_loss_in_the_inbox_reconciles_each_root() {
    let mut consumer = CatalogInvalidation::new(roots());
    consumer.apply(
        EventBatch {
            events: Vec::new(),
            lost: true,
        },
        at(10),
    );
    assert_eq!(
        consumer.take_due(at(15)).unwrap(),
        reconcile_all(ReconcileReason::EventsLost)
    );
}

#[test]
fn an_event_that_no_root_contains_reconciles_each_root() {
    let due = due_after(vec![event("/elsewhere/", 0, 4)]);
    assert_eq!(due, reconcile_all(ReconcileReason::Unattributed));
}

#[test]
fn the_sentinel_of_the_history_is_no_change() {
    let mut consumer = CatalogInvalidation::new(roots());
    consumer.apply(batch(vec![event("/", flags::HISTORY_DONE, 0)]), at(10));
    assert!(!consumer.pending());
}

#[test]
fn more_regions_than_the_bound_reconcile_the_root() {
    let events: Vec<RawEvent> = (0..=MAX_DIRTY_REGIONS)
        .map(|index| event(&format!("{XCODE}/P{index}/"), 0, 1 + index as u64))
        .collect();
    let due = due_after(events);
    assert_eq!(due, vec![reconcile(XCODE, ReconcileReason::RegionLimit)]);
}

#[test]
fn a_reconciliation_keeps_its_first_reason() {
    let due = due_after(vec![
        event(XCODE, flags::ROOT_CHANGED, 0),
        event(&format!("{XCODE}/A/"), flags::MUST_SCAN_SUBDIRS, 9),
        event(&format!("{XCODE}/B/"), 0, 10),
    ]);
    assert_eq!(due, vec![reconcile(XCODE, ReconcileReason::RootChanged)]);
}

#[test]
fn continuous_events_are_due_after_the_longest_hold() {
    let mut consumer = CatalogInvalidation::new(roots());
    let quiet_seconds: u64 = QUIET_INTERVAL.get() / SECOND;
    let hold_seconds: u64 = MAX_HOLD.get() / SECOND;
    // One event each second: the quiet interval never ends.
    for second in 0..hold_seconds {
        consumer.apply(
            batch(vec![event(&format!("{XCODE}/A/"), 0, second + 1)]),
            at(100 + second),
        );
        assert_eq!(consumer.take_due(at(100 + second)), None);
    }
    assert!(quiet_seconds < hold_seconds);
    assert!(consumer.take_due(at(100 + hold_seconds)).is_some());
}

/// The state of a fake stream, shared with the test.
#[derive(Debug, Default)]
pub(crate) struct FakeState {
    /// The roots of each start, in sequence.
    pub(crate) starts: Vec<Vec<PathBuf>>,
    /// The number of stops.
    pub(crate) stops: usize,
    /// The result of the next starts.
    pub(crate) refusal: Option<WatchError>,
    /// The batches of the next drains.
    pub(crate) batches: VecDeque<EventBatch>,
}

/// A stream that gives injected batches.
#[derive(Debug, Default, Clone)]
pub(crate) struct FakeStream(pub(crate) Arc<Mutex<FakeState>>);

impl FakeStream {
    pub(crate) fn inject(&self, events: Vec<RawEvent>) {
        self.0.lock().unwrap().batches.push_back(batch(events));
    }
}

impl EventStream for FakeStream {
    fn start(&mut self, roots: &[PathBuf]) -> Result<(), WatchError> {
        let mut state = self.0.lock().unwrap();
        state.starts.push(roots.to_vec());
        state.batches.clear();
        match &state.refusal {
            Some(error) => Err(error.clone()),
            None => Ok(()),
        }
    }

    fn stop(&mut self) {
        self.0.lock().unwrap().stops += 1;
    }

    fn drain(&mut self) -> EventBatch {
        self.0
            .lock()
            .unwrap()
            .batches
            .pop_front()
            .unwrap_or_default()
    }
}

#[test]
fn the_watch_reports_each_state() {
    let fake = FakeStream::default();
    let mut watch = CatalogWatch::new(Box::new(fake.clone()));
    assert_eq!(watch.status().state, CatalogWatchState::NotStarted);
    // With no stream, events are discarded and nothing is due.
    fake.inject(vec![event(&format!("{XCODE}/A/"), 0, 1)]);
    assert!(!watch.poll(at(100)));

    watch.watch(roots());
    let status = watch.status();
    assert_eq!(status.state, CatalogWatchState::Available);
    assert_eq!(status.roots, 2);
    // The same roots keep the stream.
    watch.watch(roots());
    assert_eq!(fake.0.lock().unwrap().starts.len(), 1);
    // A different set starts a new stream.
    watch.watch(vec![PathBuf::from(XCODE)]);
    assert_eq!(fake.0.lock().unwrap().starts.len(), 2);
    assert_eq!(watch.status().roots, 1);
    // No root: no stream.
    watch.watch(Vec::new());
    let status = watch.status();
    assert_eq!(status.state, CatalogWatchState::NotStarted);
    assert_eq!(status.roots, 0);
    assert!(fake.0.lock().unwrap().stops >= 1);

    // A refusal of the platform is `denied`, and the next call tries
    // again.
    fake.0.lock().unwrap().refusal = Some(WatchError::Refused("FSEventStreamStart"));
    watch.watch(roots());
    let status = watch.status();
    assert_eq!(status.state, CatalogWatchState::Denied);
    assert!(status.detail.contains("refreshed by age"));
    fake.0.lock().unwrap().refusal = None;
    watch.watch(roots());
    assert_eq!(watch.status().state, CatalogWatchState::Available);

    fake.0.lock().unwrap().refusal = Some(WatchError::Unsupported);
    watch.watch(vec![PathBuf::from("/other")]);
    assert_eq!(watch.status().state, CatalogWatchState::Unsupported);
}

#[test]
fn the_watch_is_due_after_the_debounce() {
    let fake = FakeStream::default();
    let mut watch = CatalogWatch::new(Box::new(fake.clone()));
    watch.watch(roots());
    fake.inject(vec![event(&format!("{XCODE}/A/"), 0, 1)]);
    assert!(!watch.poll(at(10)));
    assert!(!watch.poll(at(12)));
    assert!(watch.poll(at(15)));
    // Taken: nothing more is due.
    assert!(!watch.poll(at(30)));
    let counts = watch.status().counts;
    assert_eq!(counts.events, 1);
    assert_eq!(counts.regions, 1);
    assert_eq!(counts.invalidations, 1);
    // A loss is a reconciliation in the counts.
    fake.0.lock().unwrap().batches.push_back(EventBatch {
        events: Vec::new(),
        lost: true,
    });
    assert!(!watch.poll(at(40)));
    assert!(watch.poll(at(45)));
    assert_eq!(
        watch.status().counts.last_reconcile_reason,
        Some(ReconcileReason::EventsLost)
    );
}

#[test]
fn the_status_names_no_path() {
    let fake = FakeStream::default();
    let mut watch = CatalogWatch::new(Box::new(fake));
    watch.watch(roots());
    let text: String = serde_json::to_string(&watch.status()).unwrap();
    assert!(!text.contains("/home"), "{text}");
    assert!(text.contains("\"state\":\"available\""), "{text}");
}
