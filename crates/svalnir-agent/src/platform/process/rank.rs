//! The order of processes for `processes top`.
//!
//! A process with no value for the selected metric stays in the result,
//! after each process that has a value. It is never ranked as a zero.

use std::cmp::Ordering;

use svalnir_core::observation::{Observation, Reading, UnavailableReason};
use svalnir_core::quantity::{ByteDelta, Bytes};

use super::derived::{CpuUsage, DerivedMetrics, DerivedUnavailable, checked_reading};
use super::inventory::ProcessRecord;

/// The metric that orders the result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RankMetric {
    /// `process.footprint_bytes`, the largest value first.
    Footprint,
    /// `process.resident_bytes`, the largest value first.
    Resident,
    /// The footprint growth from [`DerivedMetrics`], the largest increase
    /// first. A decrease ranks after no change.
    FootprintGrowth,
    /// The CPU use from [`DerivedMetrics`], the largest ratio first.
    Cpu,
}

/// The value that gave a process its position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RankValue {
    /// A byte gauge.
    Bytes(Bytes),
    /// A footprint growth.
    Growth(ByteDelta),
    /// A CPU use.
    Cpu(CpuUsage),
}

/// One process in a ranking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RankedProcess<'a> {
    /// The position, from 1.
    pub position: usize,
    /// The process.
    pub record: &'a ProcessRecord,
    /// The value of the selected metric, or the reason there is no value.
    pub value: Reading<RankValue>,
}

/// The result of [`rank_processes`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ranking<'a> {
    /// The processes in order: each process with a value, then each process
    /// with no value.
    pub entries: Vec<RankedProcess<'a>>,
    /// The number of processes with a value that the limit removed.
    pub omitted_available: usize,
    /// The number of processes with no value that the limit removed. Show
    /// this count, so that these processes are not read as absent.
    pub omitted_unavailable: usize,
}

fn gauge(observation: &Observation<Bytes>) -> Reading<RankValue> {
    checked_reading(observation).map(RankValue::Bytes)
}

fn derived<T>(
    entry: Option<&Result<T, DerivedUnavailable>>,
    convert: fn(&T) -> RankValue,
) -> Reading<RankValue> {
    match entry {
        Some(Ok(value)) => Reading::Available(convert(value)),
        Some(Err(unavailable)) => Reading::Unavailable(unavailable.reason()),
        // No earlier sample of this generation was supplied.
        None => Reading::Unavailable(UnavailableReason::NotInitialized),
    }
}

fn rank_value(
    record: &ProcessRecord,
    metric: RankMetric,
    derived_metrics: Option<&DerivedMetrics>,
) -> Reading<RankValue> {
    let generation_id = &record.identity.generation_id;
    match metric {
        RankMetric::Footprint => gauge(&record.metrics.footprint),
        RankMetric::Resident => gauge(&record.metrics.resident),
        RankMetric::FootprintGrowth => derived(
            derived_metrics.and_then(|metrics| metrics.growth.get(generation_id)),
            |growth| RankValue::Growth(growth.delta),
        ),
        RankMetric::Cpu => derived(
            derived_metrics.and_then(|metrics| metrics.cpu.get(generation_id)),
            |usage| RankValue::Cpu(usage.clone()),
        ),
    }
}

/// The order of two values of one metric, the larger value first.
fn descending(left: &RankValue, right: &RankValue) -> Ordering {
    match (left, right) {
        (RankValue::Bytes(left), RankValue::Bytes(right)) => right.cmp(left),
        (RankValue::Growth(left), RankValue::Growth(right)) => right.cmp(left),
        (RankValue::Cpu(left), RankValue::Cpu(right)) => right.cmp_ratio(left),
        // One metric gives one kind of value, so this arm is not reached.
        _ => Ordering::Equal,
    }
}

/// Ranks `records` by `metric`.
///
/// Processes with a value come first, the largest value first. Processes
/// with no value come after them. Equal positions are in PID order, so the
/// result is deterministic. `derived_metrics` supplies the growth and the
/// CPU use; without it, those two metrics have no value for each process.
///
/// `limit` is the maximum number of entries. The counts of the processes
/// that it removed are in the result.
pub fn rank_processes<'a>(
    records: &'a [ProcessRecord],
    metric: RankMetric,
    derived_metrics: Option<&DerivedMetrics>,
    limit: Option<usize>,
) -> Ranking<'a> {
    let mut valued: Vec<(&ProcessRecord, Reading<RankValue>)> = records
        .iter()
        .map(|record| (record, rank_value(record, metric, derived_metrics)))
        .collect();
    valued.sort_by(|(left_record, left), (right_record, right)| {
        let by_value: Ordering = match (left.value(), right.value()) {
            (Some(left), Some(right)) => descending(left, right),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => Ordering::Equal,
        };
        by_value.then_with(|| left_record.identity.pid.cmp(&right_record.identity.pid))
    });

    let kept: usize = limit.map_or(valued.len(), |limit| limit.min(valued.len()));
    let omitted_available: usize = valued
        .iter()
        .skip(kept)
        .filter(|(_, value)| value.is_available())
        .count();
    let omitted_unavailable: usize = valued.len() - kept - omitted_available;
    Ranking {
        entries: valued
            .into_iter()
            .take(kept)
            .enumerate()
            .map(|(index, (record, value))| RankedProcess {
                position: index + 1,
                record,
                value,
            })
            .collect(),
        omitted_available,
        omitted_unavailable,
    }
}
