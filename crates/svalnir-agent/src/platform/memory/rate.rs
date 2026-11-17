//! Rates from cumulative counters.
//!
//! `docs/RESOURCE_MODEL.md` section 6 owns the rule. A rate is the checked
//! increase of a counter over a monotonic interval. Each function here is
//! pure: it reads two recorded observations and no clock.
//!
//! An interval that is not valid gives a typed reason and no number. A
//! counter that decreased is a reset. It is not negative activity, and it is
//! not a zero.

use svalnir_core::id::SampleId;
use svalnir_core::observation::{MetricKind, Observation, Reading, UnavailableReason};
use svalnir_core::quantity::{Bytes, CounterValue, Nanoseconds};
use thiserror::Error;

use super::host::VmStatistics;
use crate::platform::sleep::{SleepBoundary, sleep_between};

const NANOSECONDS_PER_SECOND: f64 = 1_000_000_000.0;

/// The increase of one counter over one valid interval.
///
/// The record keeps the two sample identities and the interval, so a
/// consumer can show how the rate was derived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CounterRate {
    /// The checked increase of the counter, in the unit of the counter.
    pub increase: u64,
    /// The time from the start of the earlier acquisition to the start of
    /// the later acquisition. It is larger than zero.
    pub interval: Nanoseconds,
    /// The sample of the earlier reading.
    pub earlier_sample: SampleId,
    /// The sample of the later reading.
    pub later_sample: SampleId,
}

impl CounterRate {
    /// The rate in counter units for each second: a finite approximation.
    #[expect(
        clippy::cast_precision_loss,
        reason = "a rate is a finite approximation; the exact increase and interval stay in the record"
    )]
    pub fn per_second(&self) -> f64 {
        // The interval is larger than zero, so the quotient is finite.
        self.increase as f64 / (self.interval.get() as f64 / NANOSECONDS_PER_SECOND)
    }
}

/// The reason two counter readings give no rate.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RateUnavailable {
    /// There is no earlier reading: this is the first sample.
    #[error("there is no earlier sample")]
    FirstSample,
    /// One of the two readings has no value.
    #[error("a counter reading is unavailable: {}", .0.as_str())]
    InputUnavailable(UnavailableReason),
    /// One of the two readings has an availability or a unit that this build
    /// does not recognize.
    #[error("a counter reading is not recognized")]
    InputUnrecognized,
    /// The two readings are not the same counter metric, unit, or scope.
    #[error("the two readings are not the same metric of the same scope")]
    DefinitionMismatch,
    /// The readings are from two boots. The counter was reset between them.
    #[error("the readings are from two boots")]
    BootChanged,
    /// The readings are from two collector lifetimes. The specification
    /// permits no join across a collector restart.
    #[error("the readings are from two collector lifetimes")]
    CollectorRestarted,
    /// The readings are on two clock domains: there is no interval.
    #[error("the readings are on two clock domains")]
    ClockDomainChanged,
    /// The later acquisition did not start after the earlier one finished,
    /// or the two readings are one sample.
    #[error("the two samples are not distinct and ordered")]
    NotOrdered,
    /// The interval is longer than the permitted maximum: a gap or a sleep.
    #[error("the interval is longer than the permitted maximum")]
    IntervalTooLong,
    /// The interval is shorter than the permitted minimum. The kernel can
    /// return the counters of an earlier call for a call that is too soon, so
    /// the later counters can be old values with a new sample time.
    #[error("the interval is shorter than the permitted minimum")]
    IntervalTooShort,
    /// The counter decreased: it was reset.
    #[error("the counter decreased; it was reset")]
    CounterReset,
    /// The runtime page size changed between the two samples.
    #[error("the page size changed between the samples")]
    PageSizeChanged,
    /// The runtime page size of one sample is not known.
    #[error("the page size of a sample is unavailable: {}", .0.as_str())]
    PageSizeUnavailable(UnavailableReason),
    /// The host slept between the two samples.
    #[error("the host slept in the interval")]
    SleepInInterval,
    /// The sleep time of the host decreased between the two samples.
    #[error("the sleep time of the host decreased between the samples")]
    SleepTimeDecreased,
    /// The sleep time of one sample is not known, so there is no evidence
    /// that the host did not sleep.
    #[error("the sleep time of a sample is unavailable: {}", .0.as_str())]
    SleepTimeUnavailable(UnavailableReason),
}

impl From<SleepBoundary> for RateUnavailable {
    fn from(boundary: SleepBoundary) -> Self {
        match boundary {
            SleepBoundary::Slept => Self::SleepInInterval,
            SleepBoundary::Decreased => Self::SleepTimeDecreased,
            SleepBoundary::Unavailable(reason) => Self::SleepTimeUnavailable(reason),
            SleepBoundary::Unrecognized => Self::InputUnrecognized,
        }
    }
}

impl RateUnavailable {
    /// The stable reason for an unavailable rate reading.
    pub fn reason(&self) -> UnavailableReason {
        match self {
            // A new collector lifetime has no baseline measurement.
            Self::FirstSample | Self::CollectorRestarted => UnavailableReason::NotInitialized,
            Self::InputUnavailable(reason)
            | Self::PageSizeUnavailable(reason)
            | Self::SleepTimeUnavailable(reason) => reason.clone(),
            Self::InputUnrecognized
            | Self::DefinitionMismatch
            | Self::CounterReset
            | Self::PageSizeChanged
            | Self::SleepTimeDecreased => UnavailableReason::InconsistentData,
            // The counters of the later sample are possibly not new values.
            Self::IntervalTooShort => UnavailableReason::NotCollected,
            Self::BootChanged
            | Self::ClockDomainChanged
            | Self::NotOrdered
            | Self::IntervalTooLong
            | Self::SleepInInterval => UnavailableReason::ClockDiscontinuity,
        }
    }
}

/// The limits of a valid rate interval.
///
/// There is no default maximum: the caller states the longest interval that is
/// one continuous observation. [`RateLimits::DEFAULT_MIN_INTERVAL`] is the
/// default minimum. The monotonic clock of the host continues during
/// sleep, so a sleep that is longer than the limit shows as a gap. The limits
/// do not show a sleep that is shorter: [`swap_activity`] rejects such an
/// interval from the sleep times of the two samples. A caller of
/// [`counter_rate`] makes that check with
/// [`sleep_between`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimits {
    /// The longest permitted interval. A longer interval is a gap: the host
    /// slept or the collector missed samples.
    pub max_interval: Nanoseconds,
    /// The shortest permitted interval. A shorter interval gives no rate.
    ///
    /// The kernel can answer a process that calls `host_statistics64` too
    /// often with the values of an earlier call and `KERN_SUCCESS`. This
    /// build does not verify the length of that window. The minimum is a
    /// conservative bound that keeps such a repeated value from becoming a
    /// measured rate of zero or an inflated rate.
    pub min_interval: Nanoseconds,
}

impl RateLimits {
    /// The default minimum interval: one second.
    pub const DEFAULT_MIN_INTERVAL: Nanoseconds = Nanoseconds::new(1_000_000_000);

    /// Limits with `max_interval` and the default minimum interval.
    pub const fn with_max_interval(max_interval: Nanoseconds) -> Self {
        Self {
            max_interval,
            min_interval: Self::DEFAULT_MIN_INTERVAL,
        }
    }
}

fn counter_value(observation: &Observation<CounterValue>) -> Result<CounterValue, RateUnavailable> {
    match &observation.reading {
        Reading::Available(_) => observation
            .value()
            .copied()
            .ok_or(RateUnavailable::InputUnrecognized),
        Reading::Unavailable(reason) => Err(RateUnavailable::InputUnavailable(reason.clone())),
        Reading::Unrecognized(_) => Err(RateUnavailable::InputUnrecognized),
    }
}

/// The rate of one counter between two readings.
///
/// `earlier` is `None` for the first sample.
///
/// # Errors
///
/// Returns a [`RateUnavailable`] when the two readings do not make a valid
/// interval: a first sample, a reading with no value, two different metrics
/// or scopes, two boots, two collector lifetimes, two clock domains, samples
/// that are not distinct and ordered, an interval shorter than the minimum
/// or longer than the maximum, or
/// a counter that decreased.
///
/// An observation has no sleep time, so this function does not reject an
/// interval with a sleep that is shorter than the maximum. The caller makes
/// that check with [`sleep_between`].
pub fn counter_rate(
    earlier: Option<&Observation<CounterValue>>,
    later: &Observation<CounterValue>,
    limits: RateLimits,
) -> Result<CounterRate, RateUnavailable> {
    let earlier: &Observation<CounterValue> = earlier.ok_or(RateUnavailable::FirstSample)?;
    if earlier.metric_id != later.metric_id
        || earlier.unit != later.unit
        || earlier.kind != MetricKind::Counter
        || later.kind != MetricKind::Counter
        || earlier.scope != later.scope
    {
        return Err(RateUnavailable::DefinitionMismatch);
    }
    if earlier.sample.boot_id != later.sample.boot_id {
        return Err(RateUnavailable::BootChanged);
    }
    if earlier.sample.collector_epoch != later.sample.collector_epoch {
        return Err(RateUnavailable::CollectorRestarted);
    }
    if earlier.sample.clock_domain != later.sample.clock_domain {
        return Err(RateUnavailable::ClockDomainChanged);
    }
    let earlier_value: CounterValue = counter_value(earlier)?;
    let later_value: CounterValue = counter_value(later)?;

    if earlier.sample.sample_id == later.sample.sample_id
        || later.sample.started_monotonic_ns < earlier.sample.finished_monotonic_ns
    {
        return Err(RateUnavailable::NotOrdered);
    }
    let interval: Nanoseconds = later
        .sample
        .started_monotonic_ns
        .checked_duration_since(earlier.sample.started_monotonic_ns)
        .filter(|interval| *interval > Nanoseconds::ZERO)
        .ok_or(RateUnavailable::NotOrdered)?;
    if interval < limits.min_interval {
        return Err(RateUnavailable::IntervalTooShort);
    }
    if interval > limits.max_interval {
        return Err(RateUnavailable::IntervalTooLong);
    }
    let increase: u64 = later_value
        .increase_since(earlier_value)
        .map_err(|_| RateUnavailable::CounterReset)?;
    Ok(CounterRate {
        increase,
        interval,
        earlier_sample: earlier.sample.sample_id.clone(),
        later_sample: later.sample.sample_id.clone(),
    })
}

/// A rate of a page counter with the page size of its interval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageRate {
    /// The increase of the page counter over the interval.
    pub rate: CounterRate,
    /// The runtime page size, which is the same in the two samples.
    pub page_size: Bytes,
}

impl PageRate {
    /// Pages for each second.
    pub fn pages_per_second(&self) -> f64 {
        self.rate.per_second()
    }

    /// The page-equivalent bytes for each second.
    ///
    /// This is the page rate multiplied by the page size. It is not the
    /// write traffic of the storage device: compression, metadata, and other
    /// I/O are not in this value.
    #[expect(
        clippy::cast_precision_loss,
        reason = "a rate is a finite approximation; the exact page size stays in the record"
    )]
    pub fn page_equivalent_bytes_per_second(&self) -> f64 {
        self.rate.per_second() * self.page_size.get() as f64
    }
}

/// The swap activity of the host between two VM samples.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwapActivity {
    /// The rate of `memory.swap.swapins_total`.
    pub swapins: Result<PageRate, RateUnavailable>,
    /// The rate of `memory.swap.swapouts_total`.
    pub swapouts: Result<PageRate, RateUnavailable>,
}

fn stable_page_size(
    earlier: &VmStatistics,
    later: &VmStatistics,
) -> Result<Bytes, RateUnavailable> {
    let page_size = |statistics: &VmStatistics| match &statistics.page_size {
        Reading::Available(page_size) => Ok(*page_size),
        Reading::Unavailable(reason) => Err(RateUnavailable::PageSizeUnavailable(reason.clone())),
        Reading::Unrecognized(_) => Err(RateUnavailable::InputUnrecognized),
    };
    let earlier_size: Bytes = page_size(earlier)?;
    let later_size: Bytes = page_size(later)?;
    if earlier_size == later_size {
        Ok(later_size)
    } else {
        Err(RateUnavailable::PageSizeChanged)
    }
}

/// The swap-in and swap-out rates between two VM samples.
///
/// The rates use the explicit swap counters. The page-in and page-out
/// counters are different activity and are not used. `earlier` is `None` for
/// the first sample. An interval in which the host slept gives no rate: the
/// sleep times of the two samples must agree.
pub fn swap_activity(
    earlier: Option<&VmStatistics>,
    later: &VmStatistics,
    limits: RateLimits,
) -> SwapActivity {
    let Some(earlier) = earlier else {
        return SwapActivity {
            swapins: Err(RateUnavailable::FirstSample),
            swapouts: Err(RateUnavailable::FirstSample),
        };
    };
    let page_rate = |earlier_counter: &Observation<CounterValue>,
                     later_counter: &Observation<CounterValue>| {
        let rate: CounterRate = counter_rate(Some(earlier_counter), later_counter, limits)?;
        sleep_between(&earlier.sleep_time, &later.sleep_time)?;
        let page_size: Bytes = stable_page_size(earlier, later)?;
        Ok(PageRate { rate, page_size })
    };
    SwapActivity {
        swapins: page_rate(&earlier.swapins, &later.swapins),
        swapouts: page_rate(&earlier.swapouts, &later.swapouts),
    }
}

#[cfg(test)]
mod tests {
    use svalnir_core::observation::UnavailableReason;
    use svalnir_core::quantity::{Bytes, Nanoseconds};

    use super::super::context::{CollectionContext, testing};
    use super::super::host::{VmStatistics, vm_statistics};
    use super::super::raw::{RawVmStatistics, RawVmStatisticsRevision1};
    use super::{RateLimits, RateUnavailable, counter_rate, swap_activity};

    const SECOND: u64 = 1_000_000_000;
    /// A limit that is longer than each interval of these tests.
    const LIMITS: RateLimits = RateLimits::with_max_interval(Nanoseconds::new(3_600 * SECOND));
    const PAGE_16K: u64 = 16_384;

    fn raw(swapins: u64, swapouts: u64) -> RawVmStatistics {
        RawVmStatistics {
            free_count: 1,
            active_count: 1,
            inactive_count: 1,
            wire_count: 1,
            speculative_count: 0,
            pageins: 1_000_000,
            pageouts: 2_000_000,
            revision_1: Some(RawVmStatisticsRevision1 {
                decompressions: 0,
                compressions: 0,
                swapins,
                swapouts,
                compressor_page_count: 0,
                external_page_count: 0,
                internal_page_count: 0,
                total_uncompressed_pages_in_compressor: 0,
            }),
        }
    }

    /// A VM sample of `context` that starts at `started` nanoseconds.
    fn vm_at(
        context: &CollectionContext,
        started: u64,
        swapins: u64,
        swapouts: u64,
    ) -> VmStatistics {
        let sample = testing::sample_at(context, started);
        vm_statistics(context, Ok(raw(swapins, swapouts)), Ok(PAGE_16K), &sample)
    }

    #[test]
    fn two_ordered_samples_give_the_increase_over_the_interval() {
        let (context, _clock) = testing::context();
        let earlier = vm_at(&context, 10 * SECOND, 1_000, 5_000);
        let later = vm_at(&context, 12 * SECOND, 1_300, 5_000);
        let activity = swap_activity(Some(&earlier), &later, LIMITS);

        let swapins = activity.swapins.unwrap();
        assert_eq!(swapins.rate.increase, 300);
        assert_eq!(swapins.rate.interval, Nanoseconds::new(2 * SECOND));
        assert_eq!(swapins.rate.earlier_sample, earlier.sample.sample_id);
        assert_eq!(swapins.rate.later_sample, later.sample.sample_id);
        assert_eq!(swapins.page_size, Bytes::new(PAGE_16K));
        assert!((swapins.pages_per_second() - 150.0).abs() < 1e-9);
        assert!((swapins.page_equivalent_bytes_per_second() - 2_457_600.0).abs() < 1e-6);

        // No swap-out in the interval is a measured rate of zero.
        let swapouts = activity.swapouts.unwrap();
        assert_eq!(swapouts.rate.increase, 0);
        assert!(swapouts.pages_per_second().abs() < f64::EPSILON);
    }

    #[test]
    fn the_rate_uses_the_swap_counters_and_not_the_paging_counters() {
        let (context, _clock) = testing::context();
        let earlier = vm_at(&context, 10 * SECOND, 100, 100);
        let mut later = vm_at(&context, 11 * SECOND, 100, 100);
        // The paging counters of `later` are the same as in `earlier`, so a
        // rate from them is zero. Change only the swap counters.
        later = {
            let sample = later.sample.clone();
            vm_statistics(&context, Ok(raw(160, 100)), Ok(PAGE_16K), &sample)
        };
        let activity = swap_activity(Some(&earlier), &later, LIMITS);
        assert_eq!(activity.swapins.unwrap().rate.increase, 60);
    }

    #[test]
    fn a_first_sample_gives_no_rate() {
        let (context, _clock) = testing::context();
        let later = vm_at(&context, 10 * SECOND, 1_000, 5_000);
        let activity = swap_activity(None, &later, LIMITS);
        assert_eq!(activity.swapins, Err(RateUnavailable::FirstSample));
        assert_eq!(activity.swapouts, Err(RateUnavailable::FirstSample));
        assert_eq!(
            RateUnavailable::FirstSample.reason(),
            UnavailableReason::NotInitialized
        );
        assert_eq!(
            counter_rate(None, &later.swapins, LIMITS),
            Err(RateUnavailable::FirstSample)
        );
    }

    #[test]
    fn a_counter_that_decreased_is_a_reset_and_not_a_negative_or_zero_rate() {
        let (context, _clock) = testing::context();
        let earlier = vm_at(&context, 10 * SECOND, 1_000, 5_000);
        let later = vm_at(&context, 12 * SECOND, 20, 5_100);
        let activity = swap_activity(Some(&earlier), &later, LIMITS);
        assert_eq!(activity.swapins, Err(RateUnavailable::CounterReset));
        assert_eq!(
            RateUnavailable::CounterReset.reason(),
            UnavailableReason::InconsistentData
        );
        // The other counter of the same samples has its own result.
        assert_eq!(activity.swapouts.unwrap().rate.increase, 100);
    }

    #[test]
    fn samples_that_are_not_distinct_and_ordered_give_no_rate() {
        let (context, _clock) = testing::context();
        let earlier = vm_at(&context, 10 * SECOND, 1_000, 5_000);

        // The same sample two times.
        assert_eq!(
            swap_activity(Some(&earlier), &earlier, LIMITS).swapins,
            Err(RateUnavailable::NotOrdered)
        );
        // The same start time: no elapsed time.
        let same_time = vm_at(&context, 10 * SECOND, 1_100, 5_000);
        assert_eq!(
            swap_activity(Some(&earlier), &same_time, LIMITS).swapins,
            Err(RateUnavailable::NotOrdered)
        );
        // The later sample starts before the earlier one finishes.
        let overlapping = vm_at(&context, 10 * SECOND + 500_000, 1_100, 5_000);
        assert_eq!(
            swap_activity(Some(&earlier), &overlapping, LIMITS).swapins,
            Err(RateUnavailable::NotOrdered)
        );
        // The samples are in the opposite order.
        let before = vm_at(&context, 5 * SECOND, 900, 5_000);
        assert_eq!(
            swap_activity(Some(&earlier), &before, LIMITS).swapins,
            Err(RateUnavailable::NotOrdered)
        );
        assert_eq!(
            RateUnavailable::NotOrdered.reason(),
            UnavailableReason::ClockDiscontinuity
        );
    }

    #[test]
    fn a_clock_that_is_not_continuous_gives_no_rate() {
        let (first_boot, _clock) = testing::context();
        let earlier = vm_at(&first_boot, 10 * SECOND, 1_000, 5_000);

        let (second_boot, _clock) =
            testing::context_with(testing::identity("boot_other", "epoch_test", "clock_test"));
        let later = vm_at(&second_boot, 12 * SECOND, 1_300, 5_000);
        let activity = swap_activity(Some(&earlier), &later, LIMITS);
        assert_eq!(activity.swapins, Err(RateUnavailable::BootChanged));
        assert_eq!(
            RateUnavailable::BootChanged.reason(),
            UnavailableReason::ClockDiscontinuity
        );

        let (other_clock, _clock) =
            testing::context_with(testing::identity("boot_test", "epoch_test", "clock_other"));
        let later = vm_at(&other_clock, 12 * SECOND, 1_300, 5_000);
        let activity = swap_activity(Some(&earlier), &later, LIMITS);
        assert_eq!(activity.swapins, Err(RateUnavailable::ClockDomainChanged));
        assert_eq!(
            RateUnavailable::ClockDomainChanged.reason(),
            UnavailableReason::ClockDiscontinuity
        );

        let (restarted, _clock) =
            testing::context_with(testing::identity("boot_test", "epoch_other", "clock_test"));
        let later = vm_at(&restarted, 12 * SECOND, 1_300, 5_000);
        let activity = swap_activity(Some(&earlier), &later, LIMITS);
        assert_eq!(activity.swapins, Err(RateUnavailable::CollectorRestarted));
        assert_eq!(
            RateUnavailable::CollectorRestarted.reason(),
            UnavailableReason::NotInitialized
        );
    }

    #[test]
    fn a_sleep_in_the_interval_gives_no_rate() {
        let (context, clock) = testing::context();
        clock.set_slept(40 * SECOND);
        let earlier = vm_at(&context, 10 * SECOND, 1_000, 5_000);
        // The host slept for three seconds. The interval is shorter than the
        // limit, so only the sleep time shows the sleep.
        clock.set_slept(43 * SECOND);
        let later = vm_at(&context, 15 * SECOND, 1_300, 5_100);
        let activity = swap_activity(Some(&earlier), &later, LIMITS);
        assert_eq!(activity.swapins, Err(RateUnavailable::SleepInInterval));
        assert_eq!(activity.swapouts, Err(RateUnavailable::SleepInInterval));
        assert_eq!(
            RateUnavailable::SleepInInterval.reason(),
            UnavailableReason::ClockDiscontinuity
        );

        // A sleep time that decreased is not consistent.
        clock.set_slept(39 * SECOND);
        let decreased = vm_at(&context, 16 * SECOND, 1_300, 5_100);
        assert_eq!(
            swap_activity(Some(&earlier), &decreased, LIMITS).swapins,
            Err(RateUnavailable::SleepTimeDecreased)
        );

        // The next interval, with no sleep, gives a rate again.
        clock.set_slept(43 * SECOND);
        let next = vm_at(&context, 17 * SECOND, 1_400, 5_100);
        let swapins = swap_activity(Some(&later), &next, LIMITS).swapins.unwrap();
        assert_eq!(swapins.rate.increase, 100);
    }

    #[test]
    fn a_sample_with_no_sleep_time_gives_no_rate() {
        let (context, _clock) = testing::context();
        let earlier = vm_at(&context, 10 * SECOND, 1_000, 5_000);
        let mut later = vm_at(&context, 12 * SECOND, 1_300, 5_000);
        later.sleep_time =
            svalnir_core::observation::Reading::Unavailable(UnavailableReason::Unsupported);
        let activity = swap_activity(Some(&earlier), &later, LIMITS);
        assert_eq!(
            activity.swapins,
            Err(RateUnavailable::SleepTimeUnavailable(
                UnavailableReason::Unsupported
            ))
        );
        assert_eq!(
            activity.swapins.unwrap_err().reason(),
            UnavailableReason::Unsupported
        );
    }

    #[test]
    fn an_interval_longer_than_the_limit_is_a_gap() {
        let (context, _clock) = testing::context();
        let limits = RateLimits::with_max_interval(Nanoseconds::new(30 * SECOND));
        let earlier = vm_at(&context, 10 * SECOND, 1_000, 5_000);
        let at_limit = vm_at(&context, 40 * SECOND, 1_300, 5_000);
        assert_eq!(
            swap_activity(Some(&earlier), &at_limit, limits)
                .swapins
                .unwrap()
                .rate
                .interval,
            Nanoseconds::new(30 * SECOND)
        );
        let after_sleep = vm_at(&context, 40 * SECOND + 1, 1_300, 5_000);
        assert_eq!(
            swap_activity(Some(&earlier), &after_sleep, limits).swapins,
            Err(RateUnavailable::IntervalTooLong)
        );
        assert_eq!(
            RateUnavailable::IntervalTooLong.reason(),
            UnavailableReason::ClockDiscontinuity
        );
    }

    #[test]
    fn an_interval_shorter_than_the_minimum_gives_no_rate() {
        let (context, _clock) = testing::context();
        let earlier = vm_at(&context, 10 * SECOND, 1_000, 5_000);
        // The kernel can give the earlier values to a call that is too soon.
        let too_soon = vm_at(&context, 10 * SECOND + 999_999_999, 1_000, 5_000);
        let activity = swap_activity(Some(&earlier), &too_soon, LIMITS);
        assert_eq!(activity.swapins, Err(RateUnavailable::IntervalTooShort));
        assert_eq!(activity.swapouts, Err(RateUnavailable::IntervalTooShort));
        assert_eq!(
            RateUnavailable::IntervalTooShort.reason(),
            UnavailableReason::NotCollected
        );
        // The minimum itself is a valid interval.
        let at_minimum = vm_at(&context, 11 * SECOND, 1_300, 5_000);
        assert_eq!(
            swap_activity(Some(&earlier), &at_minimum, LIMITS)
                .swapins
                .unwrap()
                .rate
                .interval,
            RateLimits::DEFAULT_MIN_INTERVAL
        );
    }

    #[test]
    fn an_unavailable_counter_gives_its_reason_and_not_a_rate() {
        let (context, _clock) = testing::context();
        let earlier = vm_at(&context, 10 * SECOND, 1_000, 5_000);
        let sample = testing::sample_at(&context, 12 * SECOND);
        let failed = vm_statistics(
            &context,
            Err(UnavailableReason::TransientFailure),
            Ok(PAGE_16K),
            &sample,
        );
        let expected = RateUnavailable::InputUnavailable(UnavailableReason::TransientFailure);
        assert_eq!(
            swap_activity(Some(&earlier), &failed, LIMITS).swapins,
            Err(expected.clone())
        );
        assert_eq!(
            swap_activity(Some(&failed), &earlier, LIMITS).swapouts,
            Err(expected.clone())
        );
        assert_eq!(expected.reason(), UnavailableReason::TransientFailure);
    }

    #[test]
    fn a_page_size_that_changed_or_is_not_known_gives_no_rate() {
        let (context, _clock) = testing::context();
        let earlier = vm_at(&context, 10 * SECOND, 1_000, 5_000);

        let sample = testing::sample_at(&context, 12 * SECOND);
        let other_size = vm_statistics(&context, Ok(raw(1_300, 5_000)), Ok(4_096), &sample);
        assert_eq!(
            swap_activity(Some(&earlier), &other_size, LIMITS).swapins,
            Err(RateUnavailable::PageSizeChanged)
        );

        let sample = testing::sample_at(&context, 14 * SECOND);
        let no_size = vm_statistics(
            &context,
            Ok(raw(1_300, 5_000)),
            Err(UnavailableReason::TransientFailure),
            &sample,
        );
        assert_eq!(
            swap_activity(Some(&earlier), &no_size, LIMITS).swapins,
            Err(RateUnavailable::PageSizeUnavailable(
                UnavailableReason::TransientFailure
            ))
        );
    }

    #[test]
    fn two_different_counters_give_no_rate() {
        let (context, _clock) = testing::context();
        let earlier = vm_at(&context, 10 * SECOND, 1_000, 5_000);
        let later = vm_at(&context, 12 * SECOND, 1_300, 5_000);
        assert_eq!(
            counter_rate(Some(&earlier.pageins), &later.swapins, LIMITS),
            Err(RateUnavailable::DefinitionMismatch)
        );
        assert_eq!(
            counter_rate(Some(&earlier.swapins), &later.swapouts, LIMITS),
            Err(RateUnavailable::DefinitionMismatch)
        );
    }

    #[test]
    fn two_readings_that_are_not_counters_give_no_rate() {
        let (context, _clock) = testing::context();
        let mut earlier = vm_at(&context, 10 * SECOND, 1_000, 5_000).swapins;
        let mut later = vm_at(&context, 12 * SECOND, 1_300, 5_000).swapins;
        earlier.kind = svalnir_core::observation::MetricKind::Gauge;
        later.kind = svalnir_core::observation::MetricKind::Gauge;
        assert_eq!(
            counter_rate(Some(&earlier), &later, LIMITS),
            Err(RateUnavailable::DefinitionMismatch)
        );
    }

    #[test]
    fn the_largest_increase_gives_a_finite_rate() {
        let (context, _clock) = testing::context();
        let earlier = vm_at(&context, 10 * SECOND, 0, 0);
        let later = vm_at(&context, 11 * SECOND + 1, u64::MAX, 0);
        let rate = swap_activity(Some(&earlier), &later, LIMITS)
            .swapins
            .unwrap();
        assert_eq!(rate.rate.increase, u64::MAX);
        assert!(rate.pages_per_second().is_finite());
        assert!(rate.page_equivalent_bytes_per_second().is_finite());
    }
}
