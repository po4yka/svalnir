//! Tests of the history query against a temporary store, of the sleep
//! evidence of a series, and of the report entries with injected
//! observations. The estimate has its own tests in `estimate.rs`.

use svalnir_core::file::{DeviceNumber, FileObjectEvidence, InodeNumber, LosslessPath};
use svalnir_core::id::{ScanId, VolumeId};
use svalnir_core::observation::{
    Coverage, MetricKind, Observation, Reading, Sample, Scope, ScopeKind, UnavailableReason, Unit,
    metric,
};
use svalnir_core::quantity::{ByteDelta, Bytes, EntryCount, Nanoseconds};
use svalnir_core::time::{MonotonicNanos, WallTime};
use svalnir_core::volume::VolumeIdentity;

use super::estimate::{EstimateLimits, NoEstimateReason, TimeToThreshold, forecast};
use super::history::{CapacityHistory, capacity_history, series_points};
use super::report::{
    NO_SCAN_DETAIL, NO_SCAN_VOLUME_DETAIL, OTHER_VOLUME_DETAIL, SCAN_EXCEEDS_USED_DETAIL,
    SNAPSHOT_LIST_DETAIL, capacity_report,
};
use crate::platform::memory::context::{CollectionContext, testing};
use crate::platform::volume::identity::testing::apfs_mount;
use crate::platform::volume::identity::{ContainerLookup, mounted_volume};
use crate::platform::volume::raw::{RawFoundationCapacity, RawMount};
use crate::platform::volume::{
    FoundationCapacity, VolumeCapacity, capacity_observations, foundation_capacity_observations,
};
use crate::scan::{
    ScanCompletion, ScanLimits, ScanResult, ScanTimestamp, ScanTotals, ScanVolumeEvidence,
    SharedStorageEvidence,
};
use crate::store::{QueryLimit, Store, StoreOptions};

const MINUTE: u64 = 60_000_000_000;
const GIB: u64 = 1 << 30;
/// The start of the series on the wall clock.
const EPOCH_SECONDS: i64 = 1_800_000_000;

fn wall(minute: u64) -> WallTime {
    WallTime::from_unix(EPOCH_SECONDS + i64::try_from(minute * 60).unwrap(), 0).unwrap()
}

/// A sample of `context` at `minute` on its manual timeline.
fn sample_at_minute(context: &CollectionContext, minute: u64, offset_ns: u64) -> Sample {
    let mut sample: Sample =
        testing::sample_at(context, 1_000_000_000 + minute * MINUTE + offset_ns);
    sample.captured_at = wall(minute);
    sample
}

fn available(
    context: &CollectionContext,
    volume: &str,
    minute: u64,
    bytes: Option<u64>,
) -> Observation<Bytes> {
    let mut observation: Observation<Bytes> = Observation {
        metric_id: metric::DISK_AVAILABLE_BYTES,
        scope: Scope::volume(VolumeId::new(volume).unwrap()),
        reading: bytes.map_or(
            Reading::Unavailable(UnavailableReason::TransientFailure),
            |bytes| Reading::Available(Bytes::new(bytes)),
        ),
        unit: Unit::Byte,
        kind: MetricKind::Gauge,
        coverage: Coverage::Complete,
        source: context.sleep_time_observation().unwrap().source,
        sample: sample_at_minute(context, minute, 2_000_000),
    };
    observation.source.adapter_id = svalnir_core::id::AdapterId::new("macos.statfs").unwrap();
    observation
}

/// A stored sleep reading of the tick at `minute`, taken before the
/// capacity collection of that tick, as the collector of the agent does.
fn sleep(context: &CollectionContext, minute: u64, slept: u64) -> Observation<Nanoseconds> {
    let mut observation: Observation<Nanoseconds> = context.sleep_time_observation().unwrap();
    observation.reading = Reading::Available(Nanoseconds::new(slept));
    observation.sample = sample_at_minute(context, minute, 0);
    observation
}

fn host(context: &CollectionContext) -> Scope {
    context.host_scope()
}

fn store() -> Store {
    Store::open_in_memory(&StoreOptions::default()).unwrap()
}

/// A store with `minutes` ticks of `vol_a` that fall by 1 GiB a minute,
/// one tick of `vol_b`, and a sleep reading before each tick.
fn falling_store(context: &CollectionContext, minutes: u64) -> Store {
    let mut store: Store = store();
    for minute in 0..minutes {
        store.insert_sample(&sleep(context, minute, 5)).unwrap();
        store
            .insert_sample(&available(
                context,
                "vol_a",
                minute,
                Some((60 - minute) * GIB),
            ))
            .unwrap();
    }
    store
        .insert_sample(&available(context, "vol_b", 3, Some(GIB)))
        .unwrap();
    store
}

fn history(store: &Store, context: &CollectionContext, from: u64, limit: u32) -> CapacityHistory {
    capacity_history(
        store,
        &VolumeId::new("vol_a").unwrap(),
        &host(context),
        wall(from),
        None,
        QueryLimit::new(limit).unwrap(),
        Nanoseconds::new(3 * MINUTE),
    )
    .unwrap()
}

#[test]
fn the_history_has_the_samples_of_one_volume_in_the_window_the_oldest_first() {
    let (context, _clock) = testing::context();
    let store: Store = falling_store(&context, 20);
    let history: CapacityHistory = history(&store, &context, 5, 100);
    assert_eq!(history.metric_id, metric::DISK_AVAILABLE_BYTES);
    assert_eq!(history.scope.identity_id.as_str(), "vol_a");
    assert_eq!(history.samples.len(), 15);
    assert!(!history.limit_reached);
    assert_eq!(history.unreadable, EntryCount::new(0));
    assert_eq!(history.samples[0].sample.captured_at, wall(5));
    assert_eq!(history.samples[14].value(), Some(&Bytes::new(41 * GIB)));
    assert!(
        history
            .samples
            .iter()
            .all(|sample| sample.scope.identity_id.as_str() == "vol_a")
    );
    // The sleep readings start before the window, so the oldest sample has
    // one before it.
    assert_eq!(history.sleep.first().unwrap().sample.captured_at, wall(2));
}

#[test]
fn a_history_with_more_samples_than_the_limit_keeps_the_newest_ones() {
    let (context, _clock) = testing::context();
    let store: Store = falling_store(&context, 20);
    let history: CapacityHistory = history(&store, &context, 0, 4);
    assert!(history.limit_reached);
    assert_eq!(history.samples.len(), 4);
    assert_eq!(history.samples[0].sample.captured_at, wall(16));
    assert_eq!(history.samples[3].sample.captured_at, wall(19));
}

#[test]
fn an_unavailable_sample_stays_unavailable_and_is_not_a_point_of_the_estimate() {
    let (context, _clock) = testing::context();
    let mut store: Store = store();
    store
        .insert_sample(&available(&context, "vol_a", 1, None))
        .unwrap();
    store
        .insert_sample(&available(&context, "vol_a", 2, Some(GIB)))
        .unwrap();
    let history: CapacityHistory = history(&store, &context, 0, 10);
    assert_eq!(history.samples.len(), 2);
    assert_eq!(
        history.samples[0].reason(),
        Some(&UnavailableReason::TransientFailure)
    );
    assert_eq!(history.samples[0].value(), None);
    assert_eq!(series_points(&history, None).len(), 1);
}

#[test]
fn the_sleep_readings_around_each_sample_are_its_evidence() {
    let (context, _clock) = testing::context();
    let store: Store = falling_store(&context, 20);
    let history: CapacityHistory = history(&store, &context, 0, 100);
    let points = series_points(&history, None);
    assert_eq!(points.len(), 20);
    assert_eq!(points[0].sleep_before, Some(Nanoseconds::new(5)));
    assert_eq!(points[0].sleep_after, Some(Nanoseconds::new(5)));
    // The agent has not written the reading after the newest sample yet.
    assert_eq!(points[19].sleep_after, None);
    let current: Observation<Nanoseconds> = sleep(&context, 20, 5);
    let points = series_points(&history, Some(&current));
    assert_eq!(points[19].sleep_after, Some(Nanoseconds::new(5)));

    let limits = EstimateLimits::for_sample_interval(Nanoseconds::new(MINUTE));
    let forecast = forecast(&points, Bytes::new(20 * GIB), limits);
    let TimeToThreshold::Estimate(estimate) = forecast.result else {
        panic!("no estimate: {:?}", forecast.result);
    };
    assert_eq!(estimate.series_break, None);
    assert_eq!(estimate.sample_count, EntryCount::new(20));
}

#[test]
fn a_reading_of_another_boot_is_no_evidence() {
    let (context, _clock) = testing::context();
    let store: Store = falling_store(&context, 10);
    let history: CapacityHistory = history(&store, &context, 0, 100);
    let (other, _clock) =
        testing::context_with(testing::identity("boot_other", "epoch_test", "clock_test"));
    let current: Observation<Nanoseconds> = sleep(&other, 20, 5);
    let points = series_points(&history, Some(&current));
    assert_eq!(points[9].sleep_after, None);
    let limits = EstimateLimits::for_sample_interval(Nanoseconds::new(MINUTE));
    assert_eq!(
        forecast(&points, Bytes::new(0), limits).result,
        TimeToThreshold::NoEstimate {
            reason: NoEstimateReason::NoSleepEvidence
        }
    );
}

#[test]
fn the_sleep_time_observation_is_a_host_counter_in_nanoseconds() {
    let (context, clock) = testing::context();
    clock.set_slept(42);
    let observation: Observation<Nanoseconds> = context.sleep_time_observation().unwrap();
    assert_eq!(observation.metric_id, metric::HOST_SLEEP_TIME_NS);
    assert_eq!(observation.scope.kind, ScopeKind::Host);
    assert_eq!(observation.unit, Unit::Nanosecond);
    assert_eq!(observation.kind, MetricKind::Counter);
    assert_eq!(observation.value(), Some(&Nanoseconds::new(42)));
    assert_eq!(observation.source.adapter_id.as_str(), "macos.clock_sleep");
}

fn volume() -> (RawMount, VolumeIdentity) {
    let raw: RawMount = apfs_mount("disk3s5", "/System/Volumes/Data", 16_777_234);
    let identity: VolumeIdentity = mounted_volume(&raw, None, ContainerLookup::NotExamined)
        .unwrap()
        .identity;
    (raw, identity)
}

/// The capacity of the test volume: `4_096_000_000` total, `1_638_400_000`
/// free, and `1_228_800_000` available, so `2_457_600_000` used.
fn readings(
    context: &CollectionContext,
    raw: Result<RawMount, UnavailableReason>,
    important: Result<u64, UnavailableReason>,
) -> (VolumeIdentity, VolumeCapacity, FoundationCapacity) {
    let (_, identity) = volume();
    let sample: Sample = testing::sample_at(context, 10);
    let capacity: VolumeCapacity = capacity_observations(context, &identity, raw, &sample);
    let foundation: FoundationCapacity = foundation_capacity_observations(
        context,
        &identity,
        Ok(RawFoundationCapacity {
            important,
            opportunistic: Ok(0),
        }),
        &sample,
    );
    (identity, capacity, foundation)
}

fn scan_of(identity: Option<VolumeIdentity>, allocated: u64, coverage: Coverage) -> ScanResult {
    let object = |inode: u64| FileObjectEvidence {
        device: DeviceNumber::new(16_777_234),
        inode: InodeNumber::new(inode),
    };
    let path = |text: &[u8]| LosslessPath::from_bytes(text.to_vec()).unwrap();
    ScanResult {
        schema_version: 1,
        scan_id: ScanId::new("scan_test").unwrap(),
        root: path(b"/System/Volumes/Data/project"),
        volume: ScanVolumeEvidence {
            device: DeviceNumber::new(16_777_234),
            root_object: object(2),
            filesystem_type: Some("apfs".to_owned()),
            mount_point: Some(path(b"/System/Volumes/Data")),
            identity,
        },
        started: ScanTimestamp {
            wall: Some(wall(0)),
            monotonic_ns: Some(MonotonicNanos::new(1)),
        },
        finished: ScanTimestamp {
            wall: Some(wall(1)),
            monotonic_ns: Some(MonotonicNanos::new(2)),
        },
        elapsed: Some(Nanoseconds::new(1)),
        completion: ScanCompletion::Finished,
        coverage,
        limits: ScanLimits::default(),
        entries_examined: EntryCount::new(1),
        totals: ScanTotals {
            logical_bytes: Bytes::new(allocated),
            allocated_bytes: Bytes::new(allocated),
            entries: EntryCount::new(1),
            files: EntryCount::new(1),
            directories: EntryCount::new(0),
            symlinks: EntryCount::new(0),
            other_entries: EntryCount::new(0),
        },
        shared_storage: SharedStorageEvidence {
            hard_linked_objects: EntryCount::new(0),
            hard_link_names_not_counted_again: EntryCount::new(0),
            hard_link_names_not_tracked: EntryCount::new(0),
            compressed_files: EntryCount::new(0),
            files_allocated_below_logical: EntryCount::new(0),
        },
        private_allocation: crate::scan::PrivateAllocation::unavailable(
            crate::scan::PrivateSizeUnavailable::NotReported,
        ),
        largest_files: Vec::new(),
        largest_directories: Vec::new(),
        boundaries: Vec::new(),
        boundaries_omitted: EntryCount::new(0),
        regions: Vec::new(),
        regions_omitted: EntryCount::new(0),
    }
}

#[test]
fn the_report_has_separate_entries_from_the_injected_readings() {
    let (context, _clock) = testing::context();
    let (raw, _) = volume();
    let (identity, capacity, foundation) = readings(&context, Ok(raw), Ok(1_500_000_000));
    let scan: ScanResult = scan_of(Some(identity.clone()), 457_600_000, Coverage::Complete);
    let report = capacity_report(&context, &identity, &capacity, &foundation, Some(&scan)).unwrap();

    let explained = &report.explained_by_scan.observation;
    assert_eq!(explained.metric_id, metric::DISK_SCAN_EXPLAINED_BYTES);
    assert_eq!(explained.value(), Some(&Bytes::new(457_600_000)));
    assert_eq!(explained.coverage, Coverage::Complete);
    let unexplained = &report.not_explained_by_scan.observation;
    assert_eq!(unexplained.metric_id, metric::DISK_SCAN_UNEXPLAINED_BYTES);
    assert_eq!(unexplained.kind, MetricKind::Estimate);
    assert_eq!(unexplained.value(), Some(&Bytes::new(2_000_000_000)));
    let difference = &report.important_minus_available.observation;
    assert_eq!(
        difference.metric_id,
        metric::DISK_IMPORTANT_MINUS_AVAILABLE_BYTES
    );
    assert_eq!(
        difference.value(),
        Some(&ByteDelta::new(271_200_000).unwrap())
    );
    assert_eq!(difference.kind, MetricKind::Estimate);
    for observation in [explained, unexplained] {
        assert_eq!(observation.scope, Scope::volume(identity.volume_id.clone()));
        assert_eq!(
            observation.source.adapter_id.as_str(),
            "svalnir.capacity_report"
        );
    }
    assert_eq!(report.scan.as_ref().unwrap().scan_id.as_str(), "scan_test");
    // The entries do not change the available capacity.
    assert_eq!(capacity.available.value(), Some(&Bytes::new(1_228_800_000)));
}

#[test]
fn the_local_snapshots_are_unavailable_with_a_named_reason_and_are_not_zero() {
    let (context, _clock) = testing::context();
    let (raw, _) = volume();
    let (identity, capacity, foundation) = readings(&context, Ok(raw), Ok(0));
    let report = capacity_report(&context, &identity, &capacity, &foundation, None).unwrap();
    let snapshots = &report.local_snapshots;
    assert_eq!(
        snapshots.observation.metric_id,
        metric::DISK_LOCAL_SNAPSHOT_COUNT
    );
    assert_eq!(snapshots.observation.unit, Unit::Entry);
    assert_eq!(snapshots.observation.value(), None);
    assert_eq!(
        snapshots.observation.reason(),
        Some(&UnavailableReason::Unsupported)
    );
    assert_eq!(snapshots.detail, Some(SNAPSHOT_LIST_DETAIL));
    assert_eq!(snapshots.observation.source.native_api, "fs_snapshot_list");
}

#[test]
fn with_no_scan_the_scan_entries_are_not_collected() {
    let (context, _clock) = testing::context();
    let (raw, _) = volume();
    let (identity, capacity, foundation) = readings(&context, Ok(raw), Ok(0));
    let report = capacity_report(&context, &identity, &capacity, &foundation, None).unwrap();
    for entry in [&report.explained_by_scan, &report.not_explained_by_scan] {
        assert_eq!(
            entry.observation.reason(),
            Some(&UnavailableReason::NotCollected)
        );
        assert_eq!(entry.detail, Some(NO_SCAN_DETAIL));
    }
    assert!(report.scan.is_none());
    // A Foundation value of zero is a measured value, so the difference is
    // available and negative.
    assert_eq!(
        report.important_minus_available.observation.value(),
        Some(&ByteDelta::new(-1_228_800_000).unwrap())
    );
}

#[test]
fn a_scan_of_another_volume_explains_nothing_of_this_one() {
    let (context, _clock) = testing::context();
    let (raw, _) = volume();
    let (identity, capacity, foundation) = readings(&context, Ok(raw), Ok(0));
    let mut other: VolumeIdentity = identity.clone();
    other.volume_id = VolumeId::new("vol_other").unwrap();
    for (scanned, detail) in [
        (Some(other), OTHER_VOLUME_DETAIL),
        (None, NO_SCAN_VOLUME_DETAIL),
    ] {
        let scan: ScanResult = scan_of(scanned, 1, Coverage::Complete);
        let report =
            capacity_report(&context, &identity, &capacity, &foundation, Some(&scan)).unwrap();
        for entry in [&report.explained_by_scan, &report.not_explained_by_scan] {
            assert_eq!(
                entry.observation.reason(),
                Some(&UnavailableReason::IdentityChanged)
            );
            assert_eq!(entry.detail, Some(detail));
        }
    }
}

#[test]
fn a_partial_scan_gives_partial_entries() {
    let (context, _clock) = testing::context();
    let (raw, _) = volume();
    let (identity, capacity, foundation) = readings(&context, Ok(raw), Ok(0));
    let scan: ScanResult = scan_of(Some(identity.clone()), 1_000, Coverage::Partial);
    let report = capacity_report(&context, &identity, &capacity, &foundation, Some(&scan)).unwrap();
    assert_eq!(
        report.explained_by_scan.observation.coverage,
        Coverage::Partial
    );
    assert_eq!(
        report.not_explained_by_scan.observation.coverage,
        Coverage::Partial
    );
    assert_eq!(report.scan.unwrap().coverage, Coverage::Partial);
}

#[test]
fn a_scan_larger_than_the_used_capacity_gives_no_unexplained_value() {
    let (context, _clock) = testing::context();
    let (raw, _) = volume();
    let (identity, capacity, foundation) = readings(&context, Ok(raw), Ok(0));
    let scan: ScanResult = scan_of(Some(identity.clone()), 3_000_000_000, Coverage::Complete);
    let report = capacity_report(&context, &identity, &capacity, &foundation, Some(&scan)).unwrap();
    assert!(report.explained_by_scan.observation.is_available());
    let unexplained = &report.not_explained_by_scan;
    assert_eq!(
        unexplained.observation.reason(),
        Some(&UnavailableReason::InconsistentData)
    );
    assert_eq!(unexplained.detail, Some(SCAN_EXCEEDS_USED_DETAIL));
}

#[test]
fn a_failed_capacity_query_makes_the_derived_entries_unavailable_and_not_zero() {
    let (context, _clock) = testing::context();
    let (identity, capacity, foundation) = readings(
        &context,
        Err(UnavailableReason::PermissionDenied),
        Err(UnavailableReason::TransientFailure),
    );
    let scan: ScanResult = scan_of(Some(identity.clone()), 1_000, Coverage::Complete);
    let report = capacity_report(&context, &identity, &capacity, &foundation, Some(&scan)).unwrap();
    assert!(report.explained_by_scan.observation.is_available());
    assert_eq!(
        report.not_explained_by_scan.observation.reason(),
        Some(&UnavailableReason::PermissionDenied)
    );
    assert_eq!(report.not_explained_by_scan.detail, None);
    assert_eq!(
        report.important_minus_available.observation.reason(),
        Some(&UnavailableReason::TransientFailure)
    );
    // The Foundation value with no `statfs` value: the reason of `statfs`.
    let (identity, capacity, foundation) =
        readings(&context, Err(UnavailableReason::ResourceGone), Ok(7));
    let report = capacity_report(&context, &identity, &capacity, &foundation, None).unwrap();
    assert_eq!(
        report.important_minus_available.observation.reason(),
        Some(&UnavailableReason::ResourceGone)
    );
}

#[test]
fn the_report_serializes_each_entry_as_a_canonical_observation() {
    let (context, _clock) = testing::context();
    let (raw, _) = volume();
    let (identity, capacity, foundation) = readings(&context, Ok(raw), Ok(1_500_000_000));
    let report = capacity_report(&context, &identity, &capacity, &foundation, None).unwrap();
    let value = serde_json::to_value(&report).unwrap();
    for (entry, id) in [
        ("explained_by_scan", "disk.scan_explained_bytes"),
        ("not_explained_by_scan", "disk.scan_unexplained_bytes"),
        ("local_snapshots", "disk.local_snapshot_count"),
        (
            "important_minus_available",
            "disk.important_minus_available_bytes",
        ),
    ] {
        assert!(value[entry]["label"].is_string(), "{entry}");
        assert_eq!(value[entry]["observation"]["metric_id"], id);
        for field in [
            "value",
            "unit",
            "kind",
            "availability",
            "reason",
            "coverage",
            "source",
            "sample",
        ] {
            assert!(
                value[entry]["observation"].get(field).is_some(),
                "{entry}.{field}"
            );
        }
    }
    assert_eq!(
        value["important_minus_available"]["observation"]["value"],
        "271200000"
    );
    assert_eq!(
        value["local_snapshots"]["observation"]["value"],
        serde_json::Value::Null
    );
    assert_eq!(
        value["local_snapshots"]["observation"]["reason"],
        "unsupported"
    );
    assert_eq!(value["local_snapshots"]["detail"], SNAPSHOT_LIST_DETAIL);
    assert!(value["note"].as_str().unwrap().contains("Do not add"));
}
