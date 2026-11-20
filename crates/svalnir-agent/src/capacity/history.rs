//! The history of `disk.available_bytes` of one volume from the stored
//! samples.
//!
//! The agent writes one `disk.available_bytes` sample of each selected volume
//! and one `host.sleep_time_ns` sample at each tick to the catalog store; the
//! retention of the store bounds both series. A history query reads one
//! window with a row limit, so its memory is bounded. It reads no other
//! metric and it changes nothing in the store.

use std::collections::HashMap;

use serde::Serialize;
use svalnir_core::id::{BootId, ClockDomainId, VolumeId};
use svalnir_core::observation::{MetricId, Observation, Sample, Scope, metric};
use svalnir_core::quantity::{Bytes, EntryCount, Nanoseconds};
use svalnir_core::time::{MonotonicNanos, WallTime};

use super::estimate::SeriesPoint;
use crate::store::{QueryLimit, SampleQuery, SampleRow, Store, StoreError, TimeOrder, TimeRange};

/// The default number of samples of a history query.
pub const DEFAULT_HISTORY_LIMIT: u32 = 2_000;

/// The samples of `disk.available_bytes` of one volume in one window.
#[derive(Debug, Clone, Serialize)]
pub struct CapacityHistory {
    /// Always `disk.available_bytes`.
    pub metric_id: MetricId,
    /// The volume.
    pub scope: Scope,
    /// The first instant of the window (inclusive).
    pub from: WallTime,
    /// The first instant after the window (exclusive). `None`: no end.
    pub until: Option<WallTime>,
    /// The row limit of the query.
    pub limit: u32,
    /// True when the query returned `limit` rows: the window can have more
    /// samples, and the history then has the newest ones.
    pub limit_reached: bool,
    /// The stored samples, the oldest first. An unavailable sample is a
    /// failed collection, not a capacity of zero.
    pub samples: Vec<Observation<Bytes>>,
    /// The rows that this build cannot decode. They are not in `samples`.
    pub unreadable: EntryCount,
    /// The stored sleep readings of the host around the window, the oldest
    /// first. They are evidence for the estimate and are not output.
    #[serde(skip)]
    pub sleep: Vec<Observation<Nanoseconds>>,
}

/// The rows of one metric and scope in a range, the oldest first.
fn rows(
    store: &Store,
    metric_id: &MetricId,
    scope: &Scope,
    range: TimeRange,
    limit: QueryLimit,
) -> Result<Vec<SampleRow>, StoreError> {
    let mut rows: Vec<SampleRow> = store.samples(&SampleQuery {
        metric_id: Some(metric_id.clone()),
        scope: Some(scope.clone()),
        range,
        // With a limit, the newest rows of the window are kept.
        order: TimeOrder::NewestFirst,
        limit,
    })?;
    rows.reverse();
    Ok(rows)
}

/// The wall-clock time `margin` before `time`, or `time` when the result is
/// not a valid time.
fn earlier_by(time: WallTime, margin: Nanoseconds) -> WallTime {
    let seconds: i64 = i64::try_from(margin.get() / 1_000_000_000).unwrap_or(i64::MAX);
    time.unix_seconds()
        .checked_sub(seconds)
        .and_then(|seconds| WallTime::from_unix(seconds, time.subsecond_nanoseconds()).ok())
        .unwrap_or(time)
}

/// The wall-clock time `margin` after `time`, or `time` when the result is
/// not a valid time.
fn later_by(time: WallTime, margin: Nanoseconds) -> WallTime {
    let seconds: i64 = i64::try_from(margin.get() / 1_000_000_000).unwrap_or(i64::MAX);
    time.unix_seconds()
        .checked_add(seconds)
        .and_then(|seconds| WallTime::from_unix(seconds, time.subsecond_nanoseconds()).ok())
        .unwrap_or(time)
}

/// Reads the history of `disk.available_bytes` of `volume` in the window
/// that starts at `from` and ends before `until`.
///
/// The sleep readings of `host` are read from `sleep_margin` before the
/// window, so that the oldest sample of the window has a reading before
/// it, with a limit of two times `limit` rows. When that limit is reached,
/// the oldest samples have no reading before them, and the estimate does
/// not use them.
///
/// # Errors
///
/// Returns a storage error of [`Store::samples`].
pub fn capacity_history(
    store: &Store,
    volume: &VolumeId,
    host: &Scope,
    from: WallTime,
    until: Option<WallTime>,
    limit: QueryLimit,
    sleep_margin: Nanoseconds,
) -> Result<CapacityHistory, StoreError> {
    let scope: Scope = Scope::volume(volume.clone());
    let range = TimeRange {
        from: Some(from),
        until,
    };
    let capacity: Vec<SampleRow> =
        rows(store, &metric::DISK_AVAILABLE_BYTES, &scope, range, limit)?;
    let limit_reached: bool = capacity.len() == usize::try_from(limit.get()).unwrap_or(usize::MAX);
    let mut unreadable: u64 = 0;
    let mut samples: Vec<Observation<Bytes>> = Vec::with_capacity(capacity.len());
    for row in &capacity {
        match row.sample.decode::<Bytes>() {
            Ok(observation) => samples.push(observation),
            Err(_) => unreadable += 1,
        }
    }
    let sleep_from: WallTime = samples.first().map_or(from, |first| {
        earlier_by(first.sample.captured_at, sleep_margin)
    });
    let sleep: Vec<Observation<Nanoseconds>> = rows(
        store,
        &metric::HOST_SLEEP_TIME_NS,
        host,
        TimeRange {
            from: Some(sleep_from),
            until: until.map(|until| later_by(until, sleep_margin)),
        },
        QueryLimit::new(limit.get().saturating_mul(2).min(QueryLimit::MAX))?,
    )?
    .iter()
    .filter_map(|row| row.sample.decode::<Nanoseconds>().ok())
    .collect();
    Ok(CapacityHistory {
        metric_id: metric::DISK_AVAILABLE_BYTES,
        scope,
        from,
        until,
        limit: limit.get(),
        limit_reached,
        samples,
        unreadable: EntryCount::new(unreadable),
        sleep,
    })
}

/// The sleep readings of one boot and clock domain, by acquisition start.
type Timeline = Vec<(MonotonicNanos, MonotonicNanos, Nanoseconds)>;

/// The series of the estimate: each available sample with the sleep
/// readings that bracket it.
///
/// The reading before a sample is the newest one that finished at or
/// before the start of its acquisition; the reading after it is the oldest
/// one that started at or after its end. Each is of the boot and the clock
/// domain of the sample. `current_sleep` is a reading of the caller after
/// the query, for the newest sample, whose next stored reading the agent
/// has not written yet. An unavailable sample is left out: the time to its
/// neighbors is then a longer interval, which the estimate can find to be a
/// gap.
#[must_use]
pub fn series_points(
    history: &CapacityHistory,
    current_sleep: Option<&Observation<Nanoseconds>>,
) -> Vec<SeriesPoint> {
    let mut timelines: HashMap<(&BootId, &ClockDomainId), Timeline> = HashMap::new();
    for reading in history.sleep.iter().chain(current_sleep) {
        if let Some(value) = reading.value() {
            timelines
                .entry((&reading.sample.boot_id, &reading.sample.clock_domain))
                .or_default()
                .push((
                    reading.sample.started_monotonic_ns,
                    reading.sample.finished_monotonic_ns,
                    *value,
                ));
        }
    }
    for timeline in timelines.values_mut() {
        timeline.sort_unstable();
    }
    history
        .samples
        .iter()
        .filter_map(|observation| {
            let available: Bytes = *observation.value()?;
            let sample: &Sample = &observation.sample;
            let timeline: &[(MonotonicNanos, MonotonicNanos, Nanoseconds)] = timelines
                .get(&(&sample.boot_id, &sample.clock_domain))
                .map_or(&[], Vec::as_slice);
            // The readings do not overlap, so the order by start is also the
            // order by end.
            let before: usize = timeline
                .partition_point(|(_, finished, _)| *finished <= sample.started_monotonic_ns);
            let after: usize =
                timeline.partition_point(|(started, _, _)| *started < sample.finished_monotonic_ns);
            Some(SeriesPoint {
                sample: sample.clone(),
                available,
                sleep_before: before
                    .checked_sub(1)
                    .and_then(|index| timeline.get(index))
                    .map(|(_, _, value)| *value),
                sleep_after: timeline.get(after).map(|(_, _, value)| *value),
            })
        })
        .collect()
}
