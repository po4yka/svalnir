//! Values that are derived from two or more samples of one process
//! generation: footprint growth and CPU use.
//!
//! Each function is pure. It reads injected samples and no live process. A
//! series belongs to one process generation, so a restarted process (the
//! same PID with a new start time) does not continue the series of its
//! predecessor.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use svalnir_core::id::{ClockDomainId, ProcessGenerationId, SampleId};
use svalnir_core::observation::{Observation, ObservationValue, Reading, UnavailableReason};
use svalnir_core::quantity::{ByteDelta, Bytes, CounterValue, Nanoseconds};
use svalnir_core::time::MonotonicNanos;
use thiserror::Error;

use super::inventory::{ProcessRecord, ProcessSnapshot};

/// The reason a derived value has no result.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DerivedUnavailable {
    /// The window has no sample of the process generation.
    #[error("the window has no sample of the process generation")]
    NoSamples,
    /// The window has fewer than two available samples at different times.
    #[error("the window has fewer than two available samples at different times")]
    InsufficientSamples,
    /// The samples are not from the same process generation.
    #[error("the samples are not from the same process generation")]
    GenerationMismatch,
    /// The samples are not from the same clock domain.
    #[error("the samples are not from the same clock domain")]
    ClockDomainMismatch,
    /// The later sample is not after the earlier sample.
    #[error("the later sample is not after the earlier sample")]
    NotOrdered,
    /// The cumulative counter decreased. The result is a reset, not a
    /// negative activity.
    #[error("the cumulative counter decreased")]
    CounterReset,
    /// A sample is unavailable with this reason.
    #[error("a sample is unavailable")]
    SampleUnavailable(UnavailableReason),
    /// A sample has an availability that this build does not recognize.
    #[error("a sample has an availability that is not recognized")]
    SampleUnrecognized,
}

impl DerivedUnavailable {
    /// The stable reason for an unavailable reading.
    pub fn reason(&self) -> UnavailableReason {
        match self {
            Self::NoSamples => UnavailableReason::NotCollected,
            Self::InsufficientSamples => UnavailableReason::NotInitialized,
            Self::GenerationMismatch => UnavailableReason::IdentityChanged,
            Self::ClockDomainMismatch => UnavailableReason::ClockDiscontinuity,
            Self::NotOrdered | Self::CounterReset | Self::SampleUnrecognized => {
                UnavailableReason::InconsistentData
            }
            Self::SampleUnavailable(reason) => reason.clone(),
        }
    }
}

/// The reading of an observation, with the unit check of
/// [`Observation::value`]. A value whose unit the value type does not accept
/// has no known meaning, so it is unavailable.
pub(super) fn checked_reading<T: ObservationValue + Clone>(
    observation: &Observation<T>,
) -> Reading<T> {
    match &observation.reading {
        Reading::Available(_) => observation.value().map_or(
            Reading::Unavailable(UnavailableReason::InconsistentData),
            |value| Reading::Available(value.clone()),
        ),
        other => other.clone(),
    }
}

/// One footprint measurement of one process generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FootprintSample {
    /// The process generation.
    pub generation_id: ProcessGenerationId,
    /// The acquisition that gave the value.
    pub sample_id: SampleId,
    /// The clock domain of `at`.
    pub clock_domain: ClockDomainId,
    /// When the measurement finished.
    pub at: MonotonicNanos,
    /// The physical footprint, or the reason there is no value.
    pub footprint: Reading<Bytes>,
}

impl FootprintSample {
    /// The footprint sample of a record.
    pub fn from_record(record: &ProcessRecord) -> Self {
        Self {
            generation_id: record.identity.generation_id.clone(),
            sample_id: record.metrics.sample().sample_id.clone(),
            clock_domain: record.metrics.sample().clock_domain.clone(),
            at: record.metrics.sample().finished_monotonic_ns,
            footprint: checked_reading(&record.metrics.footprint),
        }
    }
}

/// The time interval that a growth value covers: the `length` that ends at
/// `end`, both limits included.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrowthWindow {
    /// The end of the window.
    pub end: MonotonicNanos,
    /// The length of the window.
    pub length: Nanoseconds,
}

impl GrowthWindow {
    fn contains(self, at: MonotonicNanos) -> bool {
        let start: u64 = self.end.get().saturating_sub(self.length.get());
        at.get() >= start && at <= self.end
    }
}

/// The change of the physical footprint of one process generation over a
/// window.
///
/// The value is a signed gauge difference. Growth can show a workload trend;
/// it does not show a leak.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FootprintGrowth {
    /// The last available footprint minus the first available footprint.
    pub delta: ByteDelta,
    /// The time between the two samples.
    pub elapsed: Nanoseconds,
    /// The time of the first available sample in the window.
    pub first_at: MonotonicNanos,
    /// The time of the last available sample in the window.
    pub last_at: MonotonicNanos,
    /// The acquisition of the first available sample.
    pub first_sample_id: SampleId,
    /// The acquisition of the last available sample.
    pub last_sample_id: SampleId,
    /// The number of available samples in the interval.
    pub available_samples: usize,
    /// The number of samples in the interval that have no value. A gap is
    /// not evidence of steady growth.
    pub gaps: usize,
}

/// The footprint growth of `generation_id` over `window`.
///
/// The function uses only the samples of that generation in `clock_domain`.
/// A sample of a different generation is ignored, also when it has the same
/// PID. The order of `samples` has no effect.
///
/// # Errors
///
/// Returns a [`DerivedUnavailable`] when the window has no sample of the
/// generation, has a sample of the generation from a different clock
/// domain, or has fewer than two available samples at different times.
pub fn footprint_growth(
    samples: &[FootprintSample],
    generation_id: &ProcessGenerationId,
    clock_domain: &ClockDomainId,
    window: GrowthWindow,
) -> Result<FootprintGrowth, DerivedUnavailable> {
    let mut in_window: Vec<&FootprintSample> = samples
        .iter()
        .filter(|sample| &sample.generation_id == generation_id && window.contains(sample.at))
        .collect();
    if in_window.is_empty() {
        return Err(DerivedUnavailable::NoSamples);
    }
    if in_window
        .iter()
        .any(|sample| &sample.clock_domain != clock_domain)
    {
        return Err(DerivedUnavailable::ClockDomainMismatch);
    }
    in_window.sort_by_key(|sample| sample.at);

    let available = |sample: &&FootprintSample| -> Option<(MonotonicNanos, Bytes, SampleId)> {
        sample
            .footprint
            .value()
            .map(|value| (sample.at, *value, sample.sample_id.clone()))
    };
    let (Some((first_at, first, first_sample_id)), Some((last_at, last, last_sample_id))) = (
        in_window.iter().find_map(available),
        in_window.iter().rev().find_map(available),
    ) else {
        return Err(DerivedUnavailable::InsufficientSamples);
    };
    let elapsed: Nanoseconds = match last_at.checked_duration_since(first_at) {
        Some(elapsed) if elapsed > Nanoseconds::ZERO => elapsed,
        _ => return Err(DerivedUnavailable::InsufficientSamples),
    };
    let interval = in_window
        .iter()
        .filter(|sample| sample.at >= first_at && sample.at <= last_at);
    let available_samples: usize = interval
        .clone()
        .filter(|sample| sample.footprint.is_available())
        .count();
    Ok(FootprintGrowth {
        delta: last.delta_from(first),
        elapsed,
        first_at,
        last_at,
        first_sample_id,
        last_sample_id,
        available_samples,
        gaps: interval.count() - available_samples,
    })
}

/// One cumulative CPU time measurement of one process generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpuSample {
    /// The process generation.
    pub generation_id: ProcessGenerationId,
    /// The acquisition that gave the value.
    pub sample_id: SampleId,
    /// The clock domain of `at`.
    pub clock_domain: ClockDomainId,
    /// When the measurement finished.
    pub at: MonotonicNanos,
    /// The cumulative CPU time in nanoseconds, or the reason there is no
    /// value.
    pub cpu_time: Reading<CounterValue>,
}

impl CpuSample {
    /// The CPU sample of a record.
    pub fn from_record(record: &ProcessRecord) -> Self {
        Self {
            generation_id: record.identity.generation_id.clone(),
            sample_id: record.metrics.sample().sample_id.clone(),
            clock_domain: record.metrics.sample().clock_domain.clone(),
            at: record.metrics.sample().finished_monotonic_ns,
            cpu_time: checked_reading(&record.metrics.cpu_time),
        }
    }
}

/// The CPU time that one process generation used in an interval.
///
/// `process.cpu_core_equivalent_percent` is `100 * cpu_delta / elapsed`. It
/// can be more than 100 when the process uses more than one core. The order
/// of two values is the order of that ratio.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpuUsage {
    /// The increase of the cumulative CPU time.
    pub cpu_delta: Nanoseconds,
    /// The length of the interval. It is more than zero.
    pub elapsed: Nanoseconds,
    /// The acquisition of the earlier sample.
    pub earlier_sample_id: SampleId,
    /// The acquisition of the later sample.
    pub later_sample_id: SampleId,
}

impl CpuUsage {
    /// The percentage of one core, for display.
    #[expect(
        clippy::cast_precision_loss,
        reason = "the value is a finite approximation for display"
    )]
    pub fn core_equivalent_percent(&self) -> f64 {
        100.0 * self.cpu_delta.get() as f64 / self.elapsed.get() as f64
    }

    /// Compares the ratios `cpu_delta / elapsed` with integer arithmetic.
    pub fn cmp_ratio(&self, other: &Self) -> Ordering {
        let left: u128 = u128::from(self.cpu_delta.get()) * u128::from(other.elapsed.get());
        let right: u128 = u128::from(other.cpu_delta.get()) * u128::from(self.elapsed.get());
        left.cmp(&right)
    }
}

fn counter_value(reading: &Reading<CounterValue>) -> Result<CounterValue, DerivedUnavailable> {
    match reading {
        Reading::Available(value) => Ok(*value),
        Reading::Unavailable(reason) => Err(DerivedUnavailable::SampleUnavailable(reason.clone())),
        Reading::Unrecognized(_) => Err(DerivedUnavailable::SampleUnrecognized),
    }
}

/// The CPU use of one process generation between two samples.
///
/// # Errors
///
/// Returns a [`DerivedUnavailable`] when the samples are not from the same
/// generation and clock domain, `later` is not after `earlier`, a sample
/// has no value, or the counter decreased.
pub fn cpu_usage(earlier: &CpuSample, later: &CpuSample) -> Result<CpuUsage, DerivedUnavailable> {
    if earlier.generation_id != later.generation_id {
        return Err(DerivedUnavailable::GenerationMismatch);
    }
    if earlier.clock_domain != later.clock_domain {
        return Err(DerivedUnavailable::ClockDomainMismatch);
    }
    let elapsed: Nanoseconds = match later.at.checked_duration_since(earlier.at) {
        Some(elapsed) if elapsed > Nanoseconds::ZERO => elapsed,
        _ => return Err(DerivedUnavailable::NotOrdered),
    };
    let before: CounterValue = counter_value(&earlier.cpu_time)?;
    let after: CounterValue = counter_value(&later.cpu_time)?;
    let increase: u64 = after
        .increase_since(before)
        .map_err(|_| DerivedUnavailable::CounterReset)?;
    Ok(CpuUsage {
        cpu_delta: Nanoseconds::new(increase),
        elapsed,
        earlier_sample_id: earlier.sample_id.clone(),
        later_sample_id: later.sample_id.clone(),
    })
}

/// The derived values of the process generations of a snapshot.
///
/// A generation with no entry has no earlier sample, for example a process
/// that started after the earlier snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DerivedMetrics {
    /// The footprint growth of each generation.
    pub growth: BTreeMap<ProcessGenerationId, Result<FootprintGrowth, DerivedUnavailable>>,
    /// The CPU use of each generation.
    pub cpu: BTreeMap<ProcessGenerationId, Result<CpuUsage, DerivedUnavailable>>,
}

/// The footprint growth and the CPU use of each process generation that is
/// in the two snapshots.
///
/// A process that restarted between the snapshots has a new generation, so
/// it gets no value from the data of its predecessor.
pub fn derive_between(earlier: &ProcessSnapshot, later: &ProcessSnapshot) -> DerivedMetrics {
    let mut derived: DerivedMetrics = DerivedMetrics::default();
    for record in &later.records {
        let generation_id: &ProcessGenerationId = &record.identity.generation_id;
        let Some(previous) = earlier.find_generation(generation_id) else {
            continue;
        };
        let samples: [FootprintSample; 2] = [
            FootprintSample::from_record(previous),
            FootprintSample::from_record(record),
        ];
        let window: GrowthWindow = GrowthWindow {
            end: samples[1].at.max(samples[0].at),
            length: Nanoseconds::MAX,
        };
        derived.growth.insert(
            generation_id.clone(),
            footprint_growth(&samples, generation_id, &samples[1].clock_domain, window),
        );
        derived.cpu.insert(
            generation_id.clone(),
            cpu_usage(
                &CpuSample::from_record(previous),
                &CpuSample::from_record(record),
            ),
        );
    }
    derived
}
