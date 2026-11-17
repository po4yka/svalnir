//! Tests of the state store. Each test uses a database in memory or in its
//! own temporary directory.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use rusqlite::Connection;
use serde::Serialize;
use svalnir_core::file::LosslessPath;
use svalnir_core::id::{
    AdapterId, BootId, ClockDomainId, CollectorEpochId, IdentityId, SampleId, ScanId, VolumeId,
    WorkerId,
};
use svalnir_core::observation::{
    Coverage, MetricId, MetricKind, Observation, ObservationValue, Reading, Sample, Scope,
    ScopeKind, Source, UnavailableReason, Unit, metric,
};
use svalnir_core::quantity::{ByteDelta, Bytes, CounterValue, EntryCount, PageCount};
use svalnir_core::state::PressureState;
use svalnir_core::time::{MonotonicNanos, WallTime};

use super::migration::{APPLICATION_ID, MIGRATIONS, Migration};
use super::{
    EncodedSample, MAX_SAMPLE_BATCH, MAX_SCAN_RESULT_BYTES, QueryLimit, RetentionPolicy,
    STATE_STORE_VERSION, SampleQuery, ScanQuery, ScanRecord, Store, StoreError, StoreOptions,
    TimeOrder, TimeRange,
};

/// A directory under the system temporary directory, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let path: PathBuf = std::env::temp_dir().join(format!(
            "svalnir-store-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn database(&self) -> PathBuf {
        self.0.join("state.sqlite")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        drop(fs::remove_dir_all(&self.0));
    }
}

fn options() -> StoreOptions {
    StoreOptions::default()
}

fn memory() -> Store {
    Store::open_in_memory(&options()).unwrap()
}

fn at(seconds: i64) -> WallTime {
    WallTime::from_unix(seconds, 0).unwrap()
}

fn host() -> Scope {
    Scope {
        kind: ScopeKind::Host,
        identity_id: IdentityId::new("host_boot-1").unwrap(),
    }
}

fn observation<T>(
    metric_id: MetricId,
    scope: Scope,
    reading: Reading<T>,
    unit: Unit,
    captured_at: WallTime,
) -> Observation<T> {
    Observation {
        metric_id,
        scope,
        reading,
        unit,
        kind: MetricKind::Gauge,
        coverage: Coverage::Complete,
        source: Source {
            adapter_id: AdapterId::new("test-adapter").unwrap(),
            adapter_revision: "1".to_owned(),
            native_api: "test_api".to_owned(),
            native_field: "test_field".to_owned(),
            worker_id: WorkerId::new("worker-1").unwrap(),
        },
        sample: Sample {
            sample_id: SampleId::new("sample-1").unwrap(),
            clock_domain: ClockDomainId::new("clock-1").unwrap(),
            boot_id: BootId::new("boot-1").unwrap(),
            collector_epoch: CollectorEpochId::new("epoch-1").unwrap(),
            started_monotonic_ns: MonotonicNanos::new(10),
            finished_monotonic_ns: MonotonicNanos::new(20),
            captured_at,
        },
    }
}

/// A sample of free disk bytes for the host at `seconds`.
fn free_bytes(seconds: i64) -> Observation<Bytes> {
    observation(
        metric::DISK_FREE_BYTES,
        host(),
        Reading::Available(Bytes::new(u64::try_from(seconds).unwrap())),
        Unit::Byte,
        at(seconds),
    )
}

fn insert_series(store: &mut Store, seconds: std::ops::Range<i64>) {
    let batch: Vec<EncodedSample> = seconds
        .map(|second| EncodedSample::encode(&free_bytes(second)).unwrap())
        .collect();
    store.insert_samples(&batch).unwrap();
}

fn all_samples() -> SampleQuery {
    SampleQuery {
        order: TimeOrder::OldestFirst,
        ..SampleQuery::newest(QueryLimit::new(QueryLimit::MAX).unwrap())
    }
}

fn scan_record(id: &str, started: i64) -> ScanRecord {
    ScanRecord {
        scan_id: ScanId::new(id).unwrap(),
        root: LosslessPath::from_path(Path::new("/Users/example/Library/Caches")).unwrap(),
        started_at: at(started),
        finished_at: at(started + 5),
        result_json: r#"{"entries":"3","allocated_bytes":"18446744073709551615"}"#.to_owned(),
    }
}

fn user_version(path: &Path) -> i64 {
    Connection::open(path)
        .unwrap()
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap()
}

fn round_trip<T>(store: &mut Store, observation: &Observation<T>) -> Observation<T>
where
    T: Serialize + serde::de::DeserializeOwned + ObservationValue,
{
    store.delete_all_samples().unwrap();
    store.insert_sample(observation).unwrap();
    let rows = store.samples(&all_samples()).unwrap();
    assert_eq!(rows.len(), 1);
    rows[0].sample.decode::<T>().unwrap()
}

#[test]
fn the_migration_list_ends_at_the_state_store_version() {
    assert_eq!(MIGRATIONS.last().unwrap().version, STATE_STORE_VERSION);
}

#[test]
fn an_empty_file_is_migrated_to_the_current_version() {
    let directory = TempDir::new();
    let store = Store::open(&directory.database(), &options()).unwrap();
    assert_eq!(store.version().unwrap(), STATE_STORE_VERSION);
    assert_eq!(store.sample_count().unwrap(), EntryCount::ZERO);
    assert_eq!(store.scan_count().unwrap(), EntryCount::ZERO);

    let mode: String = store
        .connection
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .unwrap();
    assert_eq!(mode, "wal");
    let application_id: i64 = store
        .connection
        .pragma_query_value(None, "application_id", |row| row.get(0))
        .unwrap();
    assert_eq!(application_id, APPLICATION_ID);
    let foreign_keys: i64 = store
        .connection
        .pragma_query_value(None, "foreign_keys", |row| row.get(0))
        .unwrap();
    assert_eq!(foreign_keys, 1);
}

#[test]
fn a_reopened_store_keeps_its_version_and_rows() {
    let directory = TempDir::new();
    {
        let mut store = Store::open(&directory.database(), &options()).unwrap();
        insert_series(&mut store, 0..3);
        store.insert_scan(&scan_record("scan-1", 100)).unwrap();
    }
    let store = Store::open(&directory.database(), &options()).unwrap();
    assert_eq!(store.version().unwrap(), STATE_STORE_VERSION);
    assert_eq!(store.sample_count().unwrap(), EntryCount::new(3));
    assert_eq!(
        store.scan(&ScanId::new("scan-1").unwrap()).unwrap(),
        Some(scan_record("scan-1", 100))
    );
}

#[test]
fn a_database_of_a_newer_version_is_refused_and_not_changed() {
    let directory = TempDir::new();
    let path = directory.database();
    {
        let connection = Connection::open(&path).unwrap();
        connection
            .pragma_update(None, "application_id", APPLICATION_ID)
            .unwrap();
        connection
            .pragma_update(None, "user_version", STATE_STORE_VERSION + 1)
            .unwrap();
        connection
            .execute_batch("CREATE TABLE future (a INTEGER)")
            .unwrap();
    }
    let before: Vec<u8> = fs::read(&path).unwrap();

    let error = Store::open(&path, &options()).unwrap_err();
    assert!(matches!(
        error,
        StoreError::NewerVersion { found, supported }
            if found == STATE_STORE_VERSION + 1 && supported == STATE_STORE_VERSION
    ));
    assert!(!error.recording_failed());
    assert_eq!(fs::read(&path).unwrap(), before);
}

#[test]
fn a_database_of_a_different_application_is_refused_and_not_changed() {
    let directory = TempDir::new();
    let path = directory.database();
    Connection::open(&path)
        .unwrap()
        .execute_batch("CREATE TABLE notes (text TEXT)")
        .unwrap();
    let before: Vec<u8> = fs::read(&path).unwrap();

    let error = Store::open(&path, &options()).unwrap_err();
    assert!(matches!(error, StoreError::NotAStateStore));
    assert_eq!(fs::read(&path).unwrap(), before);
}

#[test]
fn a_failed_migration_rolls_back_to_the_previous_version() {
    const FAILING: &[Migration] = &[
        MIGRATIONS[0],
        Migration {
            version: 2,
            sql: "CREATE TABLE extra (a INTEGER) STRICT; \
                  INSERT INTO extra VALUES (1); \
                  INSERT INTO no_such_table VALUES (1);",
        },
    ];
    let directory = TempDir::new();
    let path = directory.database();
    {
        let mut store = Store::open(&path, &options()).unwrap();
        insert_series(&mut store, 0..2);
    }

    let error = Store::open_with_migrations(&path, &options(), FAILING).unwrap_err();
    assert!(matches!(
        &error,
        StoreError::Migration { version: 2, source } if matches!(**source, StoreError::Sqlite(_))
    ));
    assert_eq!(user_version(&path), 1);
    let extra_tables: i64 = Connection::open(&path)
        .unwrap()
        .query_row(
            "SELECT count(*) FROM sqlite_schema WHERE name = 'extra'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(extra_tables, 0);

    let store = Store::open(&path, &options()).unwrap();
    assert_eq!(store.version().unwrap(), 1);
    assert_eq!(store.sample_count().unwrap(), EntryCount::new(2));
}

#[test]
fn a_failed_migration_of_a_new_database_keeps_the_steps_before_it() {
    const FAILING: &[Migration] = &[
        MIGRATIONS[0],
        Migration {
            version: 2,
            sql: "CREATE TABLE extra (a INTEGER) STRICT; SELECT * FROM no_such_table;",
        },
    ];
    let directory = TempDir::new();
    let path = directory.database();
    let error = Store::open_with_migrations(&path, &options(), FAILING).unwrap_err();
    assert!(matches!(error, StoreError::Migration { version: 2, .. }));
    assert_eq!(user_version(&path), 1);
}

#[test]
fn a_later_migration_runs_on_an_existing_store_and_an_older_build_refuses_it() {
    const NEXT: &[Migration] = &[
        MIGRATIONS[0],
        Migration {
            version: 2,
            sql: "CREATE TABLE extra (a INTEGER) STRICT;",
        },
    ];
    let directory = TempDir::new();
    let path = directory.database();
    {
        let mut store = Store::open(&path, &options()).unwrap();
        insert_series(&mut store, 0..2);
    }
    {
        let store = Store::open_with_migrations(&path, &options(), NEXT).unwrap();
        assert_eq!(store.version().unwrap(), 2);
        assert_eq!(store.sample_count().unwrap(), EntryCount::new(2));
    }
    let error = Store::open(&path, &options()).unwrap_err();
    assert!(matches!(
        error,
        StoreError::NewerVersion {
            found: 2,
            supported: 1
        }
    ));
}

#[test]
fn a_migration_list_that_is_out_of_order_is_refused() {
    const UNORDERED: &[Migration] = &[
        MIGRATIONS[0],
        Migration {
            version: 3,
            sql: "CREATE TABLE extra (a INTEGER) STRICT;",
        },
    ];
    let directory = TempDir::new();
    let path = directory.database();
    let error = Store::open_with_migrations(&path, &options(), UNORDERED).unwrap_err();
    assert!(matches!(error, StoreError::MigrationOrder { version: 3 }));
    // The refusal comes before the store opens the file.
    assert!(!path.exists());
}

#[test]
fn quantities_round_trip_with_no_loss() {
    let mut store = memory();

    let bytes = observation(
        metric::DISK_TOTAL_BYTES,
        Scope::volume(VolumeId::new("vol_1").unwrap()),
        Reading::Available(Bytes::MAX),
        Unit::Byte,
        WallTime::from_unix(1_800_000_000, 999_999_999).unwrap(),
    );
    assert_eq!(round_trip(&mut store, &bytes), bytes);
    let stored: String = store
        .connection
        .query_row("SELECT observation FROM metric_sample", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert!(stored.contains(r#""value":"18446744073709551615""#));

    let counter = observation(
        metric::MEMORY_VM_PAGEINS_TOTAL,
        host(),
        Reading::Available(CounterValue::MAX),
        Unit::Page,
        at(1),
    );
    assert_eq!(round_trip(&mut store, &counter), counter);

    let pages = observation(
        metric::MEMORY_VM_FREE_PAGES,
        host(),
        Reading::Available(PageCount::ZERO),
        Unit::Page,
        at(2),
    );
    assert_eq!(round_trip(&mut store, &pages), pages);

    let delta = observation(
        MetricId::new("test.byte_delta").unwrap(),
        host(),
        Reading::Available(ByteDelta::MIN),
        Unit::Byte,
        at(3),
    );
    assert_eq!(round_trip(&mut store, &delta), delta);

    let pressure = observation(
        metric::MEMORY_PRESSURE,
        host(),
        Reading::Available(PressureState::Critical),
        Unit::State,
        at(4),
    );
    assert_eq!(round_trip(&mut store, &pressure), pressure);
}

#[test]
fn an_unavailable_observation_keeps_its_reason_and_has_no_value() {
    let mut store = memory();
    let denied: Observation<Bytes> = observation(
        metric::PROCESS_FOOTPRINT_BYTES,
        host(),
        Reading::Unavailable(UnavailableReason::PermissionDenied),
        Unit::Byte,
        at(7),
    );
    assert_eq!(round_trip(&mut store, &denied), denied);

    let rows = store.samples(&all_samples()).unwrap();
    assert_eq!(
        rows[0].sample.availability(),
        &Reading::Unavailable(UnavailableReason::PermissionDenied)
    );
    let (availability, reason, value_is_null): (String, Option<String>, bool) = store
        .connection
        .query_row(
            "SELECT availability, reason, json_extract(observation, '$.value') IS NULL \
             FROM metric_sample",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(availability, "unavailable");
    assert_eq!(reason.as_deref(), Some("permission_denied"));
    assert!(value_is_null);

    // A reason of a newer build stays as its text.
    let newer: Observation<Bytes> = observation(
        metric::PROCESS_FOOTPRINT_BYTES,
        host(),
        Reading::Unavailable(UnavailableReason::from_wire("reason_of_a_newer_build")),
        Unit::Byte,
        at(8),
    );
    assert_eq!(round_trip(&mut store, &newer), newer);
}

#[test]
fn an_unknown_availability_round_trips_as_unknown() {
    let mut store = memory();
    let denied: Observation<Bytes> = observation(
        metric::DISK_FREE_BYTES,
        host(),
        Reading::Unavailable(UnavailableReason::Unsupported),
        Unit::Byte,
        at(9),
    );
    let json: String = serde_json::to_string(&denied)
        .unwrap()
        .replace(
            r#""availability":"unavailable""#,
            r#""availability":"partial""#,
        )
        .replace(r#""reason":"unsupported""#, r#""reason":null"#);
    let unknown: Observation<Bytes> = serde_json::from_str(&json).unwrap();
    assert!(matches!(unknown.reading, Reading::Unrecognized(_)));

    assert_eq!(round_trip(&mut store, &unknown), unknown);
    let rows = store.samples(&all_samples()).unwrap();
    assert!(matches!(
        rows[0].sample.availability(),
        Reading::Unrecognized(text) if text.as_str() == "partial"
    ));
}

#[test]
fn an_observation_that_cannot_be_read_back_is_refused() {
    let mut store = memory();
    let wrong_unit = observation(
        metric::DISK_FREE_BYTES,
        host(),
        Reading::Available(Bytes::new(1)),
        Unit::Page,
        at(1),
    );
    assert!(matches!(
        store.insert_sample(&wrong_unit).unwrap_err(),
        StoreError::Observation(_)
    ));

    let mut backwards = free_bytes(1);
    backwards.sample.finished_monotonic_ns = MonotonicNanos::new(1);
    assert!(matches!(
        store.insert_sample(&backwards).unwrap_err(),
        StoreError::Encode(_)
    ));
    assert_eq!(store.sample_count().unwrap(), EntryCount::ZERO);
}

#[test]
fn a_stored_sample_does_not_decode_as_a_different_value_type() {
    let mut store = memory();
    store.insert_sample(&free_bytes(5)).unwrap();
    let rows = store.samples(&all_samples()).unwrap();
    assert!(matches!(
        rows[0].sample.decode::<PageCount>().unwrap_err(),
        StoreError::Decode(_)
    ));
}

#[test]
fn sample_queries_are_bounded_by_metric_scope_time_and_limit() {
    let mut store = memory();
    insert_series(&mut store, 0..100);
    let volume = Scope::volume(VolumeId::new("vol_1").unwrap());
    store
        .insert_sample(&observation(
            metric::DISK_FREE_BYTES,
            volume.clone(),
            Reading::Available(Bytes::new(1)),
            Unit::Byte,
            at(50),
        ))
        .unwrap();
    store
        .insert_sample(&observation(
            metric::MEMORY_PHYSICAL_BYTES,
            host(),
            Reading::Available(Bytes::new(2)),
            Unit::Byte,
            at(50),
        ))
        .unwrap();

    let seconds = |query: &SampleQuery| -> Vec<i64> {
        store
            .samples(query)
            .unwrap()
            .iter()
            .map(|row| row.sample.captured_at().unix_seconds())
            .collect()
    };
    let limit = |rows: u32| QueryLimit::new(rows).unwrap();

    // The newest rows are first by default, and the limit keeps the newest.
    let newest = SampleQuery {
        metric_id: Some(metric::DISK_FREE_BYTES),
        scope: Some(host()),
        ..SampleQuery::newest(limit(3))
    };
    assert_eq!(seconds(&newest), [99, 98, 97]);

    // The start of the range is inclusive and the end is exclusive.
    let range = SampleQuery {
        metric_id: Some(metric::DISK_FREE_BYTES),
        scope: Some(host()),
        range: TimeRange {
            from: Some(at(10)),
            until: Some(at(13)),
        },
        order: TimeOrder::OldestFirst,
        limit: limit(10),
    };
    assert_eq!(seconds(&range), [10, 11, 12]);

    let by_scope = SampleQuery {
        scope: Some(volume),
        ..SampleQuery::newest(limit(10))
    };
    assert_eq!(seconds(&by_scope), [50]);

    let by_metric = SampleQuery {
        metric_id: Some(metric::MEMORY_PHYSICAL_BYTES),
        ..SampleQuery::newest(limit(10))
    };
    let rows = store.samples(&by_metric).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].sample.metric_id(), &metric::MEMORY_PHYSICAL_BYTES);
    assert_eq!(rows[0].sample.scope(), &host());

    // The time comparison uses the nanosecond column.
    let mut fraction = free_bytes(200);
    fraction.sample.captured_at = WallTime::from_unix(200, 500).unwrap();
    store.insert_sample(&fraction).unwrap();
    let after = SampleQuery {
        range: TimeRange {
            from: Some(WallTime::from_unix(200, 501).unwrap()),
            until: None,
        },
        ..SampleQuery::newest(limit(10))
    };
    assert_eq!(store.samples(&after).unwrap(), []);
    let at_or_after = SampleQuery {
        range: TimeRange {
            from: Some(WallTime::from_unix(200, 500).unwrap()),
            until: None,
        },
        ..SampleQuery::newest(limit(10))
    };
    assert_eq!(store.samples(&at_or_after).unwrap().len(), 1);

    assert_eq!(store.samples(&all_samples()).unwrap().len(), 103);
}

#[test]
fn a_query_limit_is_1_to_the_maximum() {
    assert!(matches!(
        QueryLimit::new(0),
        Err(StoreError::InvalidLimit { limit: 0, .. })
    ));
    assert!(QueryLimit::new(QueryLimit::MAX + 1).is_err());
    assert_eq!(QueryLimit::new(QueryLimit::MAX).unwrap().get(), 10_000);
}

#[test]
fn a_batch_larger_than_the_limit_is_refused() {
    let mut store = memory();
    let sample = EncodedSample::encode(&free_bytes(1)).unwrap();
    let batch: Vec<EncodedSample> = vec![sample; MAX_SAMPLE_BATCH + 1];
    assert!(matches!(
        store.insert_samples(&batch).unwrap_err(),
        StoreError::BatchTooLarge { .. }
    ));
    assert_eq!(store.sample_count().unwrap(), EntryCount::ZERO);
}

#[test]
fn scan_records_round_trip_and_are_listed_in_bounds() {
    let mut store = memory();
    let mut raw_root = scan_record("scan-raw", 300);
    raw_root.root = LosslessPath::from_bytes(b"/tmp/\xff\xfe/cache".to_vec()).unwrap();
    for record in [
        scan_record("scan-a", 100),
        scan_record("scan-b", 200),
        raw_root.clone(),
    ] {
        store.insert_scan(&record).unwrap();
    }

    assert_eq!(
        store.scan(&ScanId::new("scan-raw").unwrap()).unwrap(),
        Some(raw_root)
    );
    assert_eq!(store.scan(&ScanId::new("absent").unwrap()).unwrap(), None);
    assert_eq!(store.scan_count().unwrap(), EntryCount::new(3));

    let newest = store
        .scans(&ScanQuery::newest(QueryLimit::new(2).unwrap()))
        .unwrap();
    let ids: Vec<&str> = newest.iter().map(|scan| scan.scan_id.as_str()).collect();
    assert_eq!(ids, ["scan-raw", "scan-b"]);
    assert_eq!(
        newest[1].result_size,
        Bytes::new(u64::try_from(scan_record("scan-b", 200).result_json.len()).unwrap())
    );
    assert_eq!(newest[1].finished_at, at(205));

    let range = ScanQuery {
        range: TimeRange {
            from: Some(at(100)),
            until: Some(at(200)),
        },
        order: TimeOrder::OldestFirst,
        limit: QueryLimit::new(10).unwrap(),
    };
    let ids: Vec<String> = store
        .scans(&range)
        .unwrap()
        .into_iter()
        .map(|scan| scan.scan_id.as_str().to_owned())
        .collect();
    assert_eq!(ids, ["scan-a"]);

    assert!(store.delete_scan(&ScanId::new("scan-a").unwrap()).unwrap());
    assert!(!store.delete_scan(&ScanId::new("scan-a").unwrap()).unwrap());
    assert_eq!(store.scan_count().unwrap(), EntryCount::new(2));
}

#[test]
fn a_scan_record_that_is_not_valid_is_refused() {
    let mut store = memory();
    store.insert_scan(&scan_record("scan-a", 100)).unwrap();

    let mut duplicate = scan_record("scan-a", 900);
    duplicate.result_json = "{}".to_owned();
    assert!(matches!(
        store.insert_scan(&duplicate).unwrap_err(),
        StoreError::DuplicateScan(id) if id.as_str() == "scan-a"
    ));
    assert_eq!(
        store.scan(&ScanId::new("scan-a").unwrap()).unwrap(),
        Some(scan_record("scan-a", 100))
    );

    let mut not_json = scan_record("scan-b", 100);
    not_json.result_json = "{not json".to_owned();
    assert!(matches!(
        store.insert_scan(&not_json).unwrap_err(),
        StoreError::InvalidScanResult(_)
    ));

    let mut large = scan_record("scan-c", 100);
    large.result_json = format!("\"{}\"", "a".repeat(MAX_SCAN_RESULT_BYTES));
    assert!(matches!(
        store.insert_scan(&large).unwrap_err(),
        StoreError::ScanResultTooLarge { .. }
    ));
    assert_eq!(store.scan_count().unwrap(), EntryCount::new(1));
}

#[test]
fn retention_by_age_deletes_only_the_older_samples() {
    let mut store = memory();
    insert_series(&mut store, 0..1200);
    store.insert_scan(&scan_record("scan-old", 0)).unwrap();

    // The cutoff is 1000.5 s - 400.75 s = 599.75 s.
    let now = WallTime::from_unix(1000, 500_000_000).unwrap();
    let policy = RetentionPolicy {
        max_age: Some(Duration::new(400, 750_000_000)),
        max_used_size: None,
        ..RetentionPolicy::default()
    };
    let report = store.apply_retention(now, &policy).unwrap();
    assert_eq!(report.samples_deleted_by_age, EntryCount::new(600));
    assert_eq!(report.samples_deleted_by_size, EntryCount::ZERO);
    assert_eq!(report.scans_deleted_by_size, EntryCount::ZERO);
    assert!(report.size_target_met);

    let rows = store.samples(&all_samples()).unwrap();
    assert_eq!(rows.len(), 600);
    assert_eq!(rows[0].sample.captured_at(), at(600));
    // The age rule does not delete a scan record.
    assert_eq!(store.scan_count().unwrap(), EntryCount::new(1));

    // An age that is longer than the range of the wall time deletes nothing.
    let policy = RetentionPolicy {
        max_age: Some(Duration::MAX),
        max_used_size: None,
        ..RetentionPolicy::default()
    };
    let report = store.apply_retention(now, &policy).unwrap();
    assert_eq!(report.samples_deleted_by_age, EntryCount::ZERO);
}

#[test]
fn retention_by_size_deletes_the_oldest_samples_before_scan_records() {
    let mut store = memory();
    store.insert_scan(&scan_record("scan-old", 0)).unwrap();
    insert_series(&mut store, 0..3000);
    store.insert_scan(&scan_record("scan-new", 5000)).unwrap();
    let before = store.size().unwrap();

    let target = Bytes::new(before.used.get() / 2);
    let policy = RetentionPolicy {
        max_age: None,
        max_used_size: Some(target),
        ..RetentionPolicy::default()
    };
    let report = store.apply_retention(at(5000), &policy).unwrap();
    assert!(report.size_target_met);
    assert!(report.used_size <= target);
    assert_eq!(report.scans_deleted_by_size, EntryCount::ZERO);
    let deleted: u64 = report.samples_deleted_by_size.get();
    assert!(deleted > 0 && deleted < 3000);

    // The samples that remain are the newest ones.
    let rows = store.samples(&all_samples()).unwrap();
    assert_eq!(u64::try_from(rows.len()).unwrap(), 3000 - deleted);
    assert_eq!(
        rows[0].sample.captured_at(),
        at(i64::try_from(deleted).unwrap())
    );
    assert_eq!(store.scan_count().unwrap(), EntryCount::new(2));

    // Retention does not compact: the file keeps its size.
    let after = store.size().unwrap();
    assert_eq!(after.file, before.file);
    assert!(after.free > Bytes::ZERO);

    // A target that the store cannot reach deletes all history and tells so.
    let policy = RetentionPolicy {
        max_age: None,
        max_used_size: Some(before.page_size),
        ..RetentionPolicy::default()
    };
    let report = store.apply_retention(at(5000), &policy).unwrap();
    assert!(!report.size_target_met);
    assert_eq!(report.scans_deleted_by_size, EntryCount::new(2));
    assert_eq!(store.sample_count().unwrap(), EntryCount::ZERO);
    assert_eq!(store.scan_count().unwrap(), EntryCount::ZERO);
}

#[test]
fn the_history_policy_keeps_free_space_below_the_hard_limit() {
    let policy = RetentionPolicy::for_history(Duration::from_secs(60), Bytes::new(1005));
    assert_eq!(policy.max_age, Some(Duration::from_secs(60)));
    assert_eq!(policy.max_used_size, Some(Bytes::new(905)));
}

#[test]
fn a_full_store_gives_the_full_error_and_no_partial_row() {
    let directory = TempDir::new();
    let limited = StoreOptions {
        max_database_size: Some(Bytes::new(48 * 4096)),
        ..options()
    };
    let mut store = Store::open(&directory.database(), &limited).unwrap();
    assert_eq!(store.size().unwrap().limit, Some(Bytes::new(48 * 4096)));

    let mut written: u64 = 0;
    let error: StoreError = loop {
        assert!(written < 100_000, "the size limit had no effect");
        match store.insert_sample(&free_bytes(i64::try_from(written).unwrap())) {
            Ok(()) => written += 1,
            Err(error) => break error,
        }
    };
    assert!(matches!(error, StoreError::Full(_)));
    assert!(error.recording_failed());
    assert!(written > 0);
    assert_eq!(store.sample_count().unwrap(), EntryCount::new(written));

    // A batch that does not fit leaves none of its rows.
    let batch: Vec<EncodedSample> = (0..200)
        .map(|second| EncodedSample::encode(&free_bytes(1_000_000 + second)).unwrap())
        .collect();
    assert!(matches!(
        store.insert_samples(&batch).unwrap_err(),
        StoreError::Full(_)
    ));
    assert_eq!(store.sample_count().unwrap(), EntryCount::new(written));
    let size = store.size().unwrap();
    assert!(size.file <= Bytes::new(48 * 4096));

    // A scan record is refused in the same way.
    let mut large = scan_record("scan-large", 1);
    large.result_json = format!("\"{}\"", "a".repeat(64 * 4096));
    assert!(matches!(
        store.insert_scan(&large).unwrap_err(),
        StoreError::Full(_)
    ));
    assert_eq!(store.scan_count().unwrap(), EntryCount::ZERO);

    // Retention frees pages, and the store accepts writes again.
    let policy = RetentionPolicy {
        max_age: None,
        max_used_size: Some(Bytes::new(size.used.get() / 2)),
        ..RetentionPolicy::default()
    };
    let report = store.apply_retention(at(0), &policy).unwrap();
    assert!(report.size_target_met);
    store.insert_sample(&free_bytes(2_000_000)).unwrap();
    assert!(store.size().unwrap().file <= Bytes::new(48 * 4096));
}

#[test]
fn a_lock_of_a_different_connection_gives_the_busy_error() {
    let directory = TempDir::new();
    let path = directory.database();
    let short = StoreOptions {
        busy_timeout: Duration::from_millis(50),
        ..options()
    };
    let mut store = Store::open(&path, &short).unwrap();
    store.insert_sample(&free_bytes(1)).unwrap();

    let holder = Connection::open(&path).unwrap();
    holder.execute_batch("BEGIN IMMEDIATE").unwrap();

    let error = store.insert_sample(&free_bytes(2)).unwrap_err();
    assert!(matches!(error, StoreError::Busy(_)));
    assert!(error.recording_failed());
    assert!(matches!(
        store.insert_scan(&scan_record("scan-a", 1)).unwrap_err(),
        StoreError::Busy(_)
    ));
    // A reader is not blocked in the write-ahead log mode.
    assert_eq!(store.sample_count().unwrap(), EntryCount::new(1));
    // A second store can open, because the open does not write.
    let second = Store::open(&path, &short).unwrap();
    assert_eq!(second.sample_count().unwrap(), EntryCount::new(1));

    holder.execute_batch("ROLLBACK").unwrap();
    store.insert_sample(&free_bytes(2)).unwrap();
    assert_eq!(store.sample_count().unwrap(), EntryCount::new(2));
}

#[test]
fn a_file_that_is_not_a_database_gives_the_corrupt_error() {
    let directory = TempDir::new();
    let path = directory.database();
    fs::write(&path, vec![0x5a_u8; 8192]).unwrap();
    let error = Store::open(&path, &options()).unwrap_err();
    assert!(matches!(error, StoreError::Corrupt(_)));
    assert!(error.recording_failed());
    assert_eq!(fs::read(&path).unwrap(), vec![0x5a_u8; 8192]);
}

#[test]
fn a_path_that_cannot_be_opened_gives_the_io_error() {
    let directory = TempDir::new();
    // The store does not make the directory of the database.
    let path = directory.0.join("absent").join("state.sqlite");
    let error = Store::open(&path, &options()).unwrap_err();
    assert!(matches!(error, StoreError::Io(_)));
    assert!(error.recording_failed());
    assert!(!directory.0.join("absent").exists());
}

#[test]
fn history_deletion_removes_the_rows_and_compaction_is_a_separate_call() {
    let directory = TempDir::new();
    let path = directory.database();
    let mut store = Store::open(&path, &options()).unwrap();
    insert_series(&mut store, 0..2000);
    store.insert_scan(&scan_record("scan-a", 1)).unwrap();
    store.insert_scan(&scan_record("scan-b", 2)).unwrap();

    assert_eq!(store.delete_all_samples().unwrap(), EntryCount::new(2000));
    assert_eq!(store.scan_count().unwrap(), EntryCount::new(2));
    assert_eq!(store.delete_all_scans().unwrap(), EntryCount::new(2));

    insert_series(&mut store, 0..2000);
    store.insert_scan(&scan_record("scan-c", 3)).unwrap();
    let full = store.size().unwrap();
    assert_eq!(
        store.delete_all_history().unwrap(),
        (EntryCount::new(2000), EntryCount::new(1))
    );
    assert_eq!(store.sample_count().unwrap(), EntryCount::ZERO);
    assert_eq!(store.scan_count().unwrap(), EntryCount::ZERO);

    // The deletion does not compact.
    let deleted = store.size().unwrap();
    assert_eq!(deleted.file, full.file);
    assert!(deleted.used < full.used);

    assert!(store.compact().unwrap());
    let compacted = store.size().unwrap();
    assert!(compacted.file < full.file);
    assert_eq!(compacted.free, Bytes::ZERO);

    assert!(store.checkpoint().unwrap());
    let file_length: u64 = fs::metadata(&path).unwrap().len();
    assert_eq!(Bytes::new(file_length), compacted.file);
    assert_eq!(store.version().unwrap(), STATE_STORE_VERSION);
}

#[test]
fn an_open_that_cannot_get_the_lock_for_a_migration_gives_the_busy_error() {
    let directory = TempDir::new();
    let path = directory.database();
    let holder = Connection::open(&path).unwrap();
    holder
        .execute_batch("PRAGMA journal_mode = WAL; BEGIN IMMEDIATE; CREATE TABLE held (a INTEGER)")
        .unwrap();

    let short = StoreOptions {
        busy_timeout: Duration::from_millis(50),
        ..options()
    };
    let error = Store::open(&path, &short).unwrap_err();
    assert!(matches!(error, StoreError::Busy(_)), "{error:?}");

    holder.execute_batch("ROLLBACK").unwrap();
    drop(holder);
    let store = Store::open(&path, &short).unwrap();
    assert_eq!(store.version().unwrap(), STATE_STORE_VERSION);
}

#[test]
fn retention_stops_at_the_batch_budget_and_the_next_call_continues() {
    let mut store = memory();
    insert_series(&mut store, 0..1200);
    let policy = RetentionPolicy {
        max_age: Some(Duration::from_secs(1)),
        max_used_size: None,
        max_batches: 1,
    };
    let now = at(10_000);
    let first = store.apply_retention(now, &policy).unwrap();
    assert_eq!(first.samples_deleted_by_age, EntryCount::new(500));
    assert!(first.work_remaining);
    assert_eq!(store.sample_count().unwrap(), EntryCount::new(700));

    let more = RetentionPolicy {
        max_batches: 10,
        ..policy
    };
    let second = store.apply_retention(now, &more).unwrap();
    assert_eq!(second.samples_deleted_by_age, EntryCount::new(700));
    assert!(!second.work_remaining);
    assert_eq!(store.sample_count().unwrap(), EntryCount::ZERO);
}

#[test]
fn the_size_rule_obeys_the_batch_budget_and_keeps_scan_records() {
    let mut store = memory();
    store.insert_scan(&scan_record("scan-old", 0)).unwrap();
    insert_series(&mut store, 0..3000);
    let policy = RetentionPolicy {
        max_age: None,
        max_used_size: Some(Bytes::new(4096)),
        max_batches: 2,
    };
    let report = store.apply_retention(at(5000), &policy).unwrap();
    assert!(report.work_remaining);
    assert!(!report.size_target_met);
    assert_eq!(report.samples_deleted_by_size, EntryCount::new(1000));
    assert_eq!(report.scans_deleted_by_size, EntryCount::ZERO);
    assert_eq!(store.scan_count().unwrap(), EntryCount::new(1));
}

#[test]
fn open_refuses_an_empty_path_and_the_memory_name() {
    for name in ["", ":memory:"] {
        let error = Store::open(Path::new(name), &options()).unwrap_err();
        assert!(matches!(error, StoreError::InvalidPath(_)), "{name}");
        assert!(!error.recording_failed());
    }
}

#[test]
fn a_file_without_wal_takes_full_synchronous() {
    assert_eq!(super::synchronous_for("wal", true), "NORMAL");
    assert_eq!(super::synchronous_for("memory", false), "NORMAL");
    assert_eq!(super::synchronous_for("delete", true), "FULL");
    assert_eq!(super::synchronous_for("memory", true), "FULL");

    let directory = TempDir::new();
    let store = Store::open(&directory.database(), &options()).unwrap();
    let mode: String = store
        .connection
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .unwrap();
    assert_eq!(mode, "wal");
    let synchronous: i64 = store
        .connection
        .pragma_query_value(None, "synchronous", |row| row.get(0))
        .unwrap();
    assert_eq!(synchronous, 1);
}

#[test]
fn recording_failed_is_true_for_every_failed_write_variant() {
    use rusqlite::ffi;
    for code in [
        ffi::SQLITE_NOMEM,
        ffi::SQLITE_PROTOCOL,
        ffi::SQLITE_INTERRUPT,
        ffi::SQLITE_CONSTRAINT,
    ] {
        let error: StoreError = rusqlite::Error::SqliteFailure(ffi::Error::new(code), None).into();
        assert!(matches!(error, StoreError::Sqlite(_)), "code {code}");
        assert!(error.recording_failed(), "code {code}");
    }
    let migration = StoreError::Migration {
        version: 2,
        source: Box::new(StoreError::Sqlite(rusqlite::Error::QueryReturnedNoRows)),
    };
    assert!(migration.recording_failed());
    let refused = StoreError::BatchTooLarge { size: 2, limit: 1 };
    assert!(!refused.recording_failed());
}
