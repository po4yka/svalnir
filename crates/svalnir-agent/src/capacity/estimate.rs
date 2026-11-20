//! The estimate of the time until the available capacity of a volume falls
//! to a threshold.
//!
//! The estimate is a pure function of stored samples. It prepares work: it
//! authorizes no action, and no guard or policy reads it as a trigger
//! (`docs/POLICY_SPEC.md` section 1, `docs/RESOURCE_MODEL.md` sections 6
//! and 7). The function is in the agent library and not in `svalnir-core`,
//! so the policy evaluation of `svalnir-core` cannot depend on it.
//!
//! The model is a least-squares line through the newest part of one series
//! with no break. A break is an interval between two consecutive samples
//! that is longer than the permitted gap, that crosses a boot or a change
//! of clock domain, or that the sleep evidence shows to contain a sleep or
//! does not cover (`docs/RESOURCE_MODEL.md` sections 5 and 6). The samples
//! before the newest break do not count. The series gives no estimate when
//! the part after the break has too few samples or too short a span, when
//! the capacity does not fall, or when it is already at the threshold.

use serde::Serialize;
use svalnir_core::id::SampleId;
use svalnir_core::observation::{Reading, Sample};
use svalnir_core::quantity::{Bytes, EntryCount, Nanoseconds};
use svalnir_core::time::WallTime;

use crate::platform::sleep::{SleepBoundary, sleep_between};

/// The name of the model of the estimate.
pub const ESTIMATE_MODEL: &str = "least_squares_linear";

/// The statement of each estimate about authority.
pub const ESTIMATE_NOTE: &str =
    "This is an estimate from stored samples. It authorizes no action, and no guard reads it.";

const NANOSECONDS_PER_SECOND: f64 = 1_000_000_000.0;

/// One stored `disk.available_bytes` sample with the sleep evidence around
/// its acquisition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeriesPoint {
    /// The acquisition of the sample.
    pub sample: Sample,
    /// The available capacity that the sample measured.
    pub available: Bytes,
    /// The cumulative sleep time of the host, read at or before the start
    /// of the acquisition in the same boot and clock domain. `None` when no
    /// such reading exists.
    pub sleep_before: Option<Nanoseconds>,
    /// The cumulative sleep time of the host, read at or after the end of
    /// the acquisition in the same boot and clock domain. `None` when no
    /// such reading exists.
    pub sleep_after: Option<Nanoseconds>,
}

/// The bounds of a series that can give an estimate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct EstimateLimits {
    /// The smallest number of samples. At least 2.
    pub min_samples: usize,
    /// The shortest time from the first sample to the last one.
    pub min_span: Nanoseconds,
    /// The longest permitted time between two consecutive samples. A longer
    /// interval is a gap in the series.
    pub max_gap: Nanoseconds,
}

impl EstimateLimits {
    /// The limits for samples that the agent takes at `interval`: at least
    /// 5 samples over at least 10 minutes, and a gap longer than three
    /// intervals.
    #[must_use]
    pub fn for_sample_interval(interval: Nanoseconds) -> Self {
        Self {
            min_samples: 5,
            min_span: Nanoseconds::new(600 * 1_000_000_000),
            max_gap: Nanoseconds::new(interval.get().saturating_mul(3)),
        }
    }
}

/// The reason a series gives no estimate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NoEstimateReason {
    /// The series has fewer samples than the limit.
    TooFewSamples,
    /// The available capacity of the newest sample is at the threshold or
    /// below it.
    AtOrBelowThreshold,
    /// A sample is of a different boot or clock domain than the newest
    /// one: their monotonic times cannot be compared.
    BootChanged,
    /// The monotonic times of the samples do not increase.
    TimeNotIncreasing,
    /// The interval between two consecutive samples is longer than the
    /// permitted gap.
    Gap,
    /// The sleep time of the host changed between two consecutive samples.
    SleepInSeries,
    /// No sleep reading brackets two consecutive samples, so there is no
    /// evidence that the host did not sleep between them.
    NoSleepEvidence,
    /// The time from the first sample to the last one is shorter than the
    /// limit.
    SpanTooShort,
    /// The fitted capacity does not fall: it rises or stays the same.
    CapacityNotFalling,
    /// The projected time is outside the range of a duration.
    OutOfRange,
}

impl NoEstimateReason {
    /// The wire spelling of the reason.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TooFewSamples => "too_few_samples",
            Self::AtOrBelowThreshold => "at_or_below_threshold",
            Self::BootChanged => "boot_changed",
            Self::TimeNotIncreasing => "time_not_increasing",
            Self::Gap => "gap",
            Self::SleepInSeries => "sleep_in_series",
            Self::NoSleepEvidence => "no_sleep_evidence",
            Self::SpanTooShort => "span_too_short",
            Self::CapacityNotFalling => "capacity_not_falling",
            Self::OutOfRange => "out_of_range",
        }
    }
}

/// An estimate of the time to the threshold.
///
/// The values are approximate. `remaining_ns` counts from the acquisition
/// start of the newest sample.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ThresholdEstimate {
    /// The estimated time from the newest sample until the available
    /// capacity is at the threshold.
    pub remaining_ns: Nanoseconds,
    /// The fitted change of the available capacity, in bytes per second.
    /// Negative: the capacity falls.
    pub slope_bytes_per_second: f64,
    /// The root mean square of the distances of the samples from the line,
    /// in bytes. The uncertainty of the model.
    pub residual_rms_bytes: f64,
    /// The number of samples of the fit.
    pub sample_count: EntryCount,
    /// The time from the first sample to the newest one.
    pub span_ns: Nanoseconds,
    /// The first sample of the fit.
    pub first_sample_id: SampleId,
    /// The newest sample of the fit.
    pub newest_sample_id: SampleId,
    /// The wall-clock time of the newest sample, for display.
    pub newest_captured_at: WallTime,
    /// The available capacity of the newest sample.
    pub newest_available: Bytes,
    /// Why the samples before the first sample of the fit do not count:
    /// a gap, a sleep, a boot change, or no sleep evidence. `None` when the
    /// fit uses each sample of the series.
    pub series_break: Option<NoEstimateReason>,
}

/// The result of the estimate.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum TimeToThreshold {
    /// The series gives an estimate.
    Estimate(ThresholdEstimate),
    /// The series gives no estimate.
    NoEstimate {
        /// Why.
        reason: NoEstimateReason,
    },
}

/// The estimate with its label, its model, and its threshold.
///
/// `kind` is always `estimate` and `authorizes_action` is always false, so
/// a consumer of the structured output cannot read the value as a
/// measurement or as a permission.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ThresholdForecast {
    /// Always `estimate`.
    pub kind: &'static str,
    /// Always false.
    pub authorizes_action: bool,
    /// [`ESTIMATE_MODEL`].
    pub model: &'static str,
    /// The threshold of available capacity.
    pub threshold_bytes: Bytes,
    /// The limits of the series.
    pub limits: EstimateLimits,
    /// The estimate or the reason there is none.
    pub result: TimeToThreshold,
    /// [`ESTIMATE_NOTE`].
    pub note: &'static str,
}

/// Checks the interval between two consecutive samples.
fn check_interval(
    earlier: &SeriesPoint,
    later: &SeriesPoint,
    limits: &EstimateLimits,
) -> Result<(), NoEstimateReason> {
    if earlier.sample.boot_id != later.sample.boot_id
        || earlier.sample.clock_domain != later.sample.clock_domain
    {
        return Err(NoEstimateReason::BootChanged);
    }
    let interval: Nanoseconds = later
        .sample
        .started_monotonic_ns
        .checked_duration_since(earlier.sample.finished_monotonic_ns)
        .filter(|_| later.sample.started_monotonic_ns > earlier.sample.started_monotonic_ns)
        .ok_or(NoEstimateReason::TimeNotIncreasing)?;
    if interval > limits.max_gap {
        return Err(NoEstimateReason::Gap);
    }
    // Cumulative sleep times before the earlier acquisition and after the
    // later one that agree within the read tolerance of the clocks show
    // that the host did not sleep between the two samples.
    let (Some(before), Some(after)) = (earlier.sleep_before, later.sleep_after) else {
        return Err(NoEstimateReason::NoSleepEvidence);
    };
    match sleep_between(&Reading::Available(before), &Reading::Available(after)) {
        Ok(()) => Ok(()),
        Err(SleepBoundary::Slept | SleepBoundary::Decreased) => {
            Err(NoEstimateReason::SleepInSeries)
        }
        Err(SleepBoundary::Unavailable(_) | SleepBoundary::Unrecognized) => {
            Err(NoEstimateReason::NoSleepEvidence)
        }
    }
}

/// The least-squares slope in bytes per second and the root mean square of
/// the residuals in bytes. `None` when the values are not finite.
#[expect(
    clippy::cast_precision_loss,
    reason = "the fit is an approximation; a byte count below 2^53 is exact, and a larger one loses less than one part in 2^52"
)]
fn fit(points: &[SeriesPoint]) -> Option<(f64, f64)> {
    let first = points.first()?.sample.started_monotonic_ns;
    let coordinates: Vec<(f64, f64)> = points
        .iter()
        .map(|point| {
            let seconds: f64 = point
                .sample
                .started_monotonic_ns
                .checked_duration_since(first)
                .map_or(0.0, |elapsed| elapsed.get() as f64 / NANOSECONDS_PER_SECOND);
            (seconds, point.available.get() as f64)
        })
        .collect();
    let count: f64 = coordinates.len() as f64;
    let mean_x: f64 = coordinates.iter().map(|(x, _)| x).sum::<f64>() / count;
    let mean_y: f64 = coordinates.iter().map(|(_, y)| y).sum::<f64>() / count;
    let (sxx, sxy): (f64, f64) = coordinates.iter().fold((0.0, 0.0), |(sxx, sxy), (x, y)| {
        let dx: f64 = x - mean_x;
        (dx.mul_add(dx, sxx), dx.mul_add(y - mean_y, sxy))
    });
    let slope: f64 = sxy / sxx;
    let squares: f64 = coordinates.iter().fold(0.0, |sum, (x, y)| {
        let residual: f64 = y - slope.mul_add(x - mean_x, mean_y);
        residual.mul_add(residual, sum)
    });
    let residual: f64 = (squares / count).sqrt();
    (slope.is_finite() && residual.is_finite()).then_some((slope, residual))
}

/// Converts a finite nonnegative number of seconds to nanoseconds.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    reason = "the value is checked to be finite, nonnegative, and below the largest duration before the conversion"
)]
fn seconds_to_nanoseconds(seconds: f64) -> Option<Nanoseconds> {
    let nanoseconds: f64 = seconds * NANOSECONDS_PER_SECOND;
    (nanoseconds.is_finite() && nanoseconds >= 0.0 && nanoseconds < u64::MAX as f64)
        .then(|| Nanoseconds::new(nanoseconds as u64))
}

/// Estimates the time until the available capacity falls to `threshold`.
///
/// `points` are the samples of one volume, the oldest first. The function
/// reads no clock: the times are those of the samples.
#[must_use]
pub fn estimate_time_to_threshold(
    points: &[SeriesPoint],
    threshold: Bytes,
    limits: &EstimateLimits,
) -> TimeToThreshold {
    match estimate(points, threshold, limits) {
        Ok(estimate) => TimeToThreshold::Estimate(estimate),
        Err(reason) => TimeToThreshold::NoEstimate { reason },
    }
}

/// The estimate with its label, its model, and its threshold.
#[must_use]
pub fn forecast(
    points: &[SeriesPoint],
    threshold: Bytes,
    limits: EstimateLimits,
) -> ThresholdForecast {
    ThresholdForecast {
        kind: "estimate",
        authorizes_action: false,
        model: ESTIMATE_MODEL,
        threshold_bytes: threshold,
        result: estimate_time_to_threshold(points, threshold, &limits),
        limits,
        note: ESTIMATE_NOTE,
    }
}

fn estimate(
    points: &[SeriesPoint],
    threshold: Bytes,
    limits: &EstimateLimits,
) -> Result<ThresholdEstimate, NoEstimateReason> {
    let Some(newest) = points.last() else {
        return Err(NoEstimateReason::TooFewSamples);
    };
    if newest.available <= threshold {
        return Err(NoEstimateReason::AtOrBelowThreshold);
    }
    // The fit uses the newest part of the series with no break: the
    // samples before a gap, a sleep, or a boot change do not count.
    let mut start: usize = points.len() - 1;
    let mut series_break: Option<NoEstimateReason> = None;
    while let Some(earlier_index) = start.checked_sub(1) {
        match check_interval(&points[earlier_index], &points[start], limits) {
            Ok(()) => start = earlier_index,
            Err(reason) => {
                series_break = Some(reason);
                break;
            }
        }
    }
    let segment: &[SeriesPoint] = &points[start..];
    if segment.len() < limits.min_samples.max(2) {
        return Err(series_break.unwrap_or(NoEstimateReason::TooFewSamples));
    }
    let first: &SeriesPoint = &segment[0];
    let span: Nanoseconds = newest
        .sample
        .started_monotonic_ns
        .checked_duration_since(first.sample.started_monotonic_ns)
        .ok_or(NoEstimateReason::TimeNotIncreasing)?;
    if span < limits.min_span {
        return Err(series_break.unwrap_or(NoEstimateReason::SpanTooShort));
    }
    let (slope, residual) = fit(segment).ok_or(NoEstimateReason::OutOfRange)?;
    if slope >= 0.0 {
        return Err(NoEstimateReason::CapacityNotFalling);
    }
    let margin: u64 = newest.available.get() - threshold.get();
    #[expect(
        clippy::cast_precision_loss,
        reason = "the projection is an approximation"
    )]
    let remaining: Nanoseconds =
        seconds_to_nanoseconds(margin as f64 / -slope).ok_or(NoEstimateReason::OutOfRange)?;
    Ok(ThresholdEstimate {
        remaining_ns: remaining,
        slope_bytes_per_second: slope,
        residual_rms_bytes: residual,
        sample_count: EntryCount::new(u64::try_from(segment.len()).unwrap_or(u64::MAX)),
        span_ns: span,
        first_sample_id: first.sample.sample_id.clone(),
        newest_sample_id: newest.sample.sample_id.clone(),
        newest_captured_at: newest.sample.captured_at,
        newest_available: newest.available,
        series_break,
    })
}

#[cfg(test)]
mod tests {
    use svalnir_core::id::{BootId, ClockDomainId, CollectorEpochId, SampleId};
    use svalnir_core::observation::Sample;
    use svalnir_core::quantity::{Bytes, Nanoseconds};
    use svalnir_core::time::{MonotonicNanos, WallTime};

    use super::{
        EstimateLimits, NoEstimateReason, SeriesPoint, TimeToThreshold, estimate_time_to_threshold,
        forecast,
    };

    const MINUTE: u64 = 60_000_000_000;
    const GIB: u64 = 1 << 30;

    /// A point at `minute` with the boot `boot` and no sleep.
    fn point(minute: u64, available: u64, boot: &str) -> SeriesPoint {
        let started: u64 = 1_000_000_000 + minute * MINUTE;
        SeriesPoint {
            sample: Sample {
                sample_id: SampleId::new(format!("sample_{minute}")).unwrap(),
                clock_domain: ClockDomainId::new("clock_test").unwrap(),
                boot_id: BootId::new(boot).unwrap(),
                collector_epoch: CollectorEpochId::new("epoch_test").unwrap(),
                started_monotonic_ns: MonotonicNanos::new(started),
                finished_monotonic_ns: MonotonicNanos::new(started + 1_000_000),
                captured_at: WallTime::from_unix(
                    1_800_000_000 + i64::try_from(minute * 60).unwrap(),
                    0,
                )
                .unwrap(),
            },
            available: Bytes::new(available),
            sleep_before: Some(Nanoseconds::new(7)),
            sleep_after: Some(Nanoseconds::new(7)),
        }
    }

    /// Twelve samples one minute apart that fall by 1 GiB each minute,
    /// from 50 GiB to 39 GiB.
    fn falling() -> Vec<SeriesPoint> {
        (0..12)
            .map(|minute| point(minute, (50 - minute) * GIB, "boot_a"))
            .collect()
    }

    fn limits() -> EstimateLimits {
        EstimateLimits::for_sample_interval(Nanoseconds::new(MINUTE))
    }

    fn reason(points: &[SeriesPoint], threshold: u64) -> NoEstimateReason {
        match estimate_time_to_threshold(points, Bytes::new(threshold), &limits()) {
            TimeToThreshold::NoEstimate { reason } => reason,
            TimeToThreshold::Estimate(estimate) => panic!("an estimate: {estimate:?}"),
        }
    }

    #[test]
    fn a_falling_series_gives_the_time_to_the_threshold() {
        let TimeToThreshold::Estimate(estimate) =
            estimate_time_to_threshold(&falling(), Bytes::new(20 * GIB), &limits())
        else {
            panic!("no estimate");
        };
        // 39 GiB at the newest sample, 1 GiB a minute: 19 minutes to 20 GiB.
        let remaining: u64 = estimate.remaining_ns.get();
        assert!(
            remaining.abs_diff(19 * MINUTE) < 1_000_000_000,
            "{remaining}"
        );
        assert!(estimate.slope_bytes_per_second < 0.0);
        assert!(estimate.residual_rms_bytes < 1.0);
        assert_eq!(estimate.sample_count.get(), 12);
        assert_eq!(estimate.span_ns.get(), 11 * MINUTE);
        assert_eq!(estimate.newest_sample_id.as_str(), "sample_11");
        assert_eq!(estimate.newest_available, Bytes::new(39 * GIB));
        assert_eq!(estimate.series_break, None);
    }

    #[test]
    fn too_few_samples_give_no_estimate() {
        assert_eq!(reason(&[], 0), NoEstimateReason::TooFewSamples);
        assert_eq!(reason(&falling()[..4], 0), NoEstimateReason::TooFewSamples);
    }

    #[test]
    fn a_short_span_gives_no_estimate() {
        let points: Vec<SeriesPoint> = (0..6)
            .map(|step| {
                let mut point = point(0, (50 - step) * GIB, "boot_a");
                let started: u64 = point.sample.started_monotonic_ns.get() + step * 10_000_000_000;
                point.sample.started_monotonic_ns = MonotonicNanos::new(started);
                point.sample.finished_monotonic_ns = MonotonicNanos::new(started + 1_000_000);
                point
            })
            .collect();
        assert_eq!(reason(&points, 0), NoEstimateReason::SpanTooShort);
    }

    #[test]
    fn rising_or_flat_capacity_gives_no_estimate() {
        let rising: Vec<SeriesPoint> = (0..12)
            .map(|minute| point(minute, (40 + minute) * GIB, "boot_a"))
            .collect();
        assert_eq!(
            reason(&rising, 20 * GIB),
            NoEstimateReason::CapacityNotFalling
        );
        let flat: Vec<SeriesPoint> = (0..12)
            .map(|minute| point(minute, 40 * GIB, "boot_a"))
            .collect();
        assert_eq!(
            reason(&flat, 20 * GIB),
            NoEstimateReason::CapacityNotFalling
        );
    }

    #[test]
    fn capacity_at_the_threshold_gives_no_estimate() {
        assert_eq!(
            reason(&falling(), 39 * GIB),
            NoEstimateReason::AtOrBelowThreshold
        );
        assert_eq!(
            reason(&falling(), 60 * GIB),
            NoEstimateReason::AtOrBelowThreshold
        );
    }

    #[test]
    fn a_gap_in_the_series_gives_no_estimate() {
        let mut points: Vec<SeriesPoint> = falling();
        // The agent took no sample for ten minutes before the newest one.
        let newest = points.pop().unwrap();
        points.push(point(21, newest.available.get(), "boot_a"));
        assert_eq!(reason(&points, 0), NoEstimateReason::Gap);
    }

    #[test]
    fn a_boot_or_clock_change_gives_no_estimate() {
        let mut points: Vec<SeriesPoint> = falling();
        points[5] = point(5, 45 * GIB, "boot_b");
        assert_eq!(reason(&points, 0), NoEstimateReason::BootChanged);
        let mut points: Vec<SeriesPoint> = falling();
        points[3].sample.clock_domain = ClockDomainId::new("clock_other").unwrap();
        assert_eq!(reason(&points, 0), NoEstimateReason::BootChanged);
    }

    #[test]
    fn a_sleep_or_no_sleep_evidence_gives_no_estimate() {
        let mut slept: Vec<SeriesPoint> = falling();
        // The host slept after sample 4: the readings after it are larger.
        for point in &mut slept[5..] {
            point.sleep_before = Some(Nanoseconds::new(7 + MINUTE));
            point.sleep_after = Some(Nanoseconds::new(7 + MINUTE));
        }
        assert_eq!(reason(&slept, 0), NoEstimateReason::SleepInSeries);
        let mut unknown: Vec<SeriesPoint> = falling();
        unknown[6].sleep_after = None;
        assert_eq!(reason(&unknown, 0), NoEstimateReason::NoSleepEvidence);
    }

    #[test]
    fn the_samples_before_a_break_do_not_count() {
        let mut points: Vec<SeriesPoint> = (0..20)
            .map(|minute| point(minute, (60 - minute) * GIB, "boot_a"))
            .collect();
        points[0] = point(0, 5 * GIB, "boot_b");
        let TimeToThreshold::Estimate(estimate) =
            estimate_time_to_threshold(&points, Bytes::new(20 * GIB), &limits())
        else {
            panic!("no estimate");
        };
        assert_eq!(estimate.series_break, Some(NoEstimateReason::BootChanged));
        assert_eq!(estimate.sample_count.get(), 19);
        assert_eq!(estimate.first_sample_id.as_str(), "sample_1");
        // The sample of the other boot does not bend the line.
        assert!(estimate.residual_rms_bytes < 1.0);
    }

    #[test]
    fn a_sleep_time_that_changes_within_the_read_tolerance_is_no_sleep() {
        // Two reads of the same sleep time differ by the read error of the
        // clocks, which is at most one millisecond.
        let mut points: Vec<SeriesPoint> = falling();
        for (index, point) in points.iter_mut().enumerate() {
            let jitter: u64 = 7 + u64::try_from(index).unwrap() * 1_000;
            point.sleep_before = Some(Nanoseconds::new(jitter));
            point.sleep_after = Some(Nanoseconds::new(jitter + 400_000));
        }
        assert!(matches!(
            estimate_time_to_threshold(&points, Bytes::new(20 * GIB), &limits()),
            TimeToThreshold::Estimate(_)
        ));
        // A change of more than 10 ms is a sleep.
        for point in &mut points[6..] {
            point.sleep_before = point
                .sleep_before
                .map(|value| Nanoseconds::new(value.get() + 20_000_000));
            point.sleep_after = point
                .sleep_after
                .map(|value| Nanoseconds::new(value.get() + 20_000_000));
        }
        assert_eq!(reason(&points, 0), NoEstimateReason::SleepInSeries);
    }

    #[test]
    fn times_that_do_not_increase_give_no_estimate() {
        let mut points: Vec<SeriesPoint> = falling();
        points.swap(2, 3);
        assert_eq!(reason(&points, 0), NoEstimateReason::TimeNotIncreasing);
    }

    #[test]
    fn the_forecast_is_labeled_an_estimate_that_authorizes_nothing() {
        let value =
            serde_json::to_value(forecast(&falling(), Bytes::new(20 * GIB), limits())).unwrap();
        assert_eq!(value["kind"], "estimate");
        assert_eq!(value["authorizes_action"], false);
        assert_eq!(value["model"], "least_squares_linear");
        assert_eq!(value["threshold_bytes"], (20 * GIB).to_string());
        assert_eq!(value["result"]["outcome"], "estimate");
        assert!(value["result"]["remaining_ns"].is_string());
        let none =
            serde_json::to_value(forecast(&falling()[..2], Bytes::new(0), limits())).unwrap();
        assert_eq!(none["kind"], "estimate");
        assert_eq!(none["result"]["outcome"], "no_estimate");
        assert_eq!(none["result"]["reason"], "too_few_samples");
    }
}
