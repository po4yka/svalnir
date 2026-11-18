//! The sleep time of the host, as evidence for a rate interval.
//!
//! `docs/RESOURCE_MODEL.md` section 6 permits no sleep boundary in a rate
//! interval. The monotonic clock of the collectors continues while the host
//! sleeps, so a short sleep does not show as a gap. The sleep time is the
//! cumulative time that the host slept in the current boot. It increases only
//! while the host sleeps, so two samples with different sleep times have a
//! sleep between them.
//!
//! On macOS the sleep time is `CLOCK_MONOTONIC_RAW` minus `CLOCK_UPTIME_RAW`:
//! the first clock continues during sleep and the second clock stops. The
//! read needs no run loop and no notification.

use svalnir_core::observation::{Reading, UnavailableReason};
use svalnir_core::quantity::Nanoseconds;

/// The largest difference of two sleep times that is not a sleep.
///
/// The two clocks are not read at one instant, so each sleep time has a read
/// error of at most one millisecond. A sleep of the host is much longer
/// than this tolerance.
pub const SLEEP_TOLERANCE: Nanoseconds = Nanoseconds::new(10_000_000);

/// The longest time between the two reads of the continuous clock that
/// bracket the read of the uptime clock.
#[cfg(target_os = "macos")]
const MAX_READ_WINDOW: u64 = 1_000_000;

/// The number of attempts to read the two clocks in one millisecond.
#[cfg(target_os = "macos")]
const READ_ATTEMPTS: u32 = 4;

/// The reason two sleep times do not show an interval with no sleep.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SleepBoundary {
    /// The sleep time increased: the host slept in the interval.
    Slept,
    /// The sleep time decreased. The two values are not consistent.
    Decreased,
    /// One of the two sleep times has no value.
    Unavailable(UnavailableReason),
    /// One of the two sleep times has an availability that this build does
    /// not recognize.
    Unrecognized,
}

fn sleep_value(reading: &Reading<Nanoseconds>) -> Result<Nanoseconds, SleepBoundary> {
    match reading {
        Reading::Available(value) => Ok(*value),
        Reading::Unavailable(reason) => Err(SleepBoundary::Unavailable(reason.clone())),
        Reading::Unrecognized(_) => Err(SleepBoundary::Unrecognized),
    }
}

/// Checks that the host did not sleep between two samples.
///
/// `earlier` and `later` are the sleep times of the two samples. A sleep time
/// with no value is not evidence of an interval with no sleep.
///
/// # Errors
///
/// Returns a [`SleepBoundary`] when the sleep time changed by more than
/// [`SLEEP_TOLERANCE`], or when one of the two sleep times has no value.
pub fn sleep_between(
    earlier: &Reading<Nanoseconds>,
    later: &Reading<Nanoseconds>,
) -> Result<(), SleepBoundary> {
    let earlier: u64 = sleep_value(earlier)?.get();
    let later: u64 = sleep_value(later)?.get();
    if later.abs_diff(earlier) <= SLEEP_TOLERANCE.get() {
        Ok(())
    } else if later > earlier {
        Err(SleepBoundary::Slept)
    } else {
        Err(SleepBoundary::Decreased)
    }
}

/// The reading of a sleep-time query.
pub(crate) fn sleep_reading(
    result: Result<Nanoseconds, UnavailableReason>,
) -> Reading<Nanoseconds> {
    match result {
        Ok(value) => Reading::Available(value),
        Err(reason) => Reading::Unavailable(reason),
    }
}

/// The sleep time of one acquisition from a read before it and a read after
/// it.
///
/// The result has a value only when the two reads agree: then the host did
/// not sleep during the acquisition, and each value that the acquisition
/// read has this sleep time. A sleep during the acquisition gives
/// `clock_discontinuity`, so no interval that ends or starts at this
/// acquisition gives a rate.
pub(crate) fn bracketed_sleep_reading(
    before: &Reading<Nanoseconds>,
    after: Reading<Nanoseconds>,
) -> Reading<Nanoseconds> {
    match sleep_between(before, &after) {
        Ok(()) => after,
        Err(SleepBoundary::Slept | SleepBoundary::Decreased) => {
            Reading::Unavailable(UnavailableReason::ClockDiscontinuity)
        }
        Err(SleepBoundary::Unavailable(reason)) => Reading::Unavailable(reason),
        Err(SleepBoundary::Unrecognized) => {
            Reading::Unavailable(UnavailableReason::InconsistentData)
        }
    }
}

#[cfg(target_os = "macos")]
fn clock_nanoseconds(clock: libc::clockid_t) -> Option<u64> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `time` is a live, writable `timespec` for the duration of the
    // call. The kernel writes the clock value into it.
    let status: libc::c_int = unsafe { libc::clock_gettime(clock, &raw mut time) };
    if status != 0 {
        return None;
    }
    let seconds: u64 = u64::try_from(time.tv_sec).ok()?;
    let nanoseconds: u64 = u64::try_from(time.tv_nsec).ok()?;
    seconds.checked_mul(1_000_000_000)?.checked_add(nanoseconds)
}

/// The sleep time from one read of the continuous clock, the uptime clock,
/// and the continuous clock again, in that order.
///
/// `None` means that the two continuous reads are more than
/// [`MAX_READ_WINDOW`] apart, so the caller reads the clocks again.
///
/// The sleep time is `after` minus `uptime`. The continuous clock is never
/// behind the uptime clock, and `after` is read later than `uptime`, so the
/// difference is not negative on a host that did not sleep in the current
/// boot. `before` minus `uptime` is negative on such a host, by the time
/// between the two reads.
#[cfg(target_os = "macos")]
fn sleep_time_from_reads(
    before: u64,
    uptime: u64,
    after: u64,
) -> Option<Result<Nanoseconds, UnavailableReason>> {
    let window: u64 = after.checked_sub(before)?;
    if window > MAX_READ_WINDOW {
        return None;
    }
    Some(
        after
            .checked_sub(uptime)
            .map(Nanoseconds::new)
            .ok_or(UnavailableReason::InconsistentData),
    )
}

/// The cumulative time that the host slept in the current boot.
///
/// The function reads the continuous clock, the uptime clock, and the
/// continuous clock again. It accepts the values when the two continuous
/// reads are at most one millisecond apart, so the result has an error of at
/// most that time.
///
/// # Errors
///
/// Returns `inconsistent_data` when a clock gives no value, the uptime is
/// larger than the continuous time that was read after it, or each attempt
/// was interrupted for longer than the permitted window.
#[cfg(target_os = "macos")]
pub(crate) fn native_sleep_time() -> Result<Nanoseconds, UnavailableReason> {
    for _ in 0..READ_ATTEMPTS {
        let read = || -> Option<(u64, u64, u64)> {
            Some((
                clock_nanoseconds(libc::CLOCK_MONOTONIC_RAW)?,
                clock_nanoseconds(libc::CLOCK_UPTIME_RAW)?,
                clock_nanoseconds(libc::CLOCK_MONOTONIC_RAW)?,
            ))
        };
        let (before, uptime, after) = read().ok_or(UnavailableReason::InconsistentData)?;
        if let Some(result) = sleep_time_from_reads(before, uptime, after) {
            return result;
        }
    }
    Err(UnavailableReason::InconsistentData)
}

/// No sleep time is read on this host.
#[cfg(not(target_os = "macos"))]
pub(crate) fn native_sleep_time() -> Result<Nanoseconds, UnavailableReason> {
    Err(UnavailableReason::Unsupported)
}

#[cfg(test)]
mod tests {
    use svalnir_core::observation::{Reading, UnavailableReason};
    use svalnir_core::quantity::Nanoseconds;

    use super::{SLEEP_TOLERANCE, SleepBoundary, bracketed_sleep_reading, sleep_between};

    fn slept(nanoseconds: u64) -> Reading<Nanoseconds> {
        Reading::Available(Nanoseconds::new(nanoseconds))
    }

    #[test]
    fn equal_sleep_times_and_a_read_error_are_no_sleep() {
        assert_eq!(sleep_between(&slept(0), &slept(0)), Ok(()));
        let base: u64 = 7_000_000_000;
        let tolerance: u64 = SLEEP_TOLERANCE.get();
        assert_eq!(
            sleep_between(&slept(base), &slept(base + tolerance)),
            Ok(())
        );
        assert_eq!(
            sleep_between(&slept(base), &slept(base - tolerance)),
            Ok(())
        );
    }

    #[test]
    fn a_larger_sleep_time_is_a_sleep_and_a_smaller_one_is_inconsistent() {
        let base: u64 = 7_000_000_000;
        let step: u64 = SLEEP_TOLERANCE.get() + 1;
        assert_eq!(
            sleep_between(&slept(base), &slept(base + step)),
            Err(SleepBoundary::Slept)
        );
        assert_eq!(
            sleep_between(&slept(base), &slept(base - step)),
            Err(SleepBoundary::Decreased)
        );
    }

    #[test]
    fn a_sleep_time_with_no_value_is_not_evidence_of_no_sleep() {
        let unavailable: Reading<Nanoseconds> =
            Reading::Unavailable(UnavailableReason::Unsupported);
        assert_eq!(
            sleep_between(&unavailable, &slept(0)),
            Err(SleepBoundary::Unavailable(UnavailableReason::Unsupported))
        );
        assert_eq!(
            sleep_between(&slept(0), &unavailable),
            Err(SleepBoundary::Unavailable(UnavailableReason::Unsupported))
        );
    }

    #[test]
    fn a_sleep_during_an_acquisition_gives_no_sleep_time() {
        // The two reads agree: the acquisition has the later value.
        assert_eq!(bracketed_sleep_reading(&slept(5), slept(6)), slept(6));
        // The host slept between the two reads.
        let after_sleep: u64 = SLEEP_TOLERANCE.get() + 6;
        assert_eq!(
            bracketed_sleep_reading(&slept(5), slept(after_sleep)),
            Reading::Unavailable(UnavailableReason::ClockDiscontinuity)
        );
        // A read with no value keeps its reason.
        assert_eq!(
            bracketed_sleep_reading(
                &Reading::Unavailable(UnavailableReason::Unsupported),
                slept(6)
            ),
            Reading::Unavailable(UnavailableReason::Unsupported)
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_host_that_did_not_sleep_has_a_sleep_time() {
        use super::{MAX_READ_WINDOW, sleep_time_from_reads};

        // The two clocks are equal on a host that did not sleep, so the
        // uptime read is between the two continuous reads.
        assert_eq!(
            sleep_time_from_reads(1_000, 1_040, 1_090),
            Some(Ok(Nanoseconds::new(50)))
        );
        // The host slept for seven seconds before the reads.
        assert_eq!(
            sleep_time_from_reads(7_000_001_000, 1_040, 7_000_001_090),
            Some(Ok(Nanoseconds::new(7_000_000_050)))
        );
        // The uptime is larger than the continuous time read after it.
        assert_eq!(
            sleep_time_from_reads(1_000, 1_100, 1_090),
            Some(Err(UnavailableReason::InconsistentData))
        );
        // The reads are too far apart, or the continuous clock went back.
        assert_eq!(
            sleep_time_from_reads(1_000, 1_040, 1_001 + MAX_READ_WINDOW),
            None
        );
        assert_eq!(sleep_time_from_reads(1_090, 1_040, 1_000), None);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_host_sleep_time_does_not_change_while_the_host_is_awake() {
        let first = super::native_sleep_time().unwrap();
        let second = super::native_sleep_time().unwrap();
        assert_eq!(
            sleep_between(&Reading::Available(first), &Reading::Available(second)),
            Ok(())
        );
    }
}
