//! The runway: an estimate of the time until the available space of the
//! startup volume is 0, if the trend of this session continues
//! (`DESIGN.md` section 5, "Runway").
//!
//! The functions are pure. A value that is unavailable never enters the fit
//! and is never read as zero. Every text of a runway starts with "≈", except
//! "more than 7 d" and "steady", which are also estimates and are always
//! shown with the word "runway" or in the "Runway" row.

use crate::data::model::HostSample;
use std::time::SystemTime;

/// The newest readings that the fit looks at.
pub const WINDOW: usize = 60;
/// The fewest measured readings that the fit needs.
pub const MIN_READINGS: usize = 12;
/// The shortest span of the measured readings, in seconds.
pub const MIN_SPAN_SECS: f64 = 60.0;
/// The part of the volume that the fall over the readings must reach, as a
/// fraction (0.05%).
pub const MIN_FALL_SHARE: f64 = 0.0005;
/// The seconds of one hour, for the "next hour" dots of the dial.
pub const HOUR_SECS: f64 = 3_600.0;
/// The longest runway that has its own value, in seconds (7 days).
const MAX_SECS: f64 = 7.0 * 86_400.0;

/// A least-squares line through the measured readings.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Trend {
    /// The change of the available space, in bytes a second. Below 0 the
    /// space falls.
    pub slope: f64,
    /// The value of the line at `newest_at`, in bytes.
    pub fit_at_newest: f64,
    /// The time of the newest measured reading in the fit.
    pub newest_at: SystemTime,
    /// The number of measured readings in the fit.
    pub readings: usize,
    /// The seconds from the first to the newest measured reading.
    pub span_secs: f64,
}

impl Trend {
    /// The value of the line at `at`, in bytes. It can be below 0 or above
    /// the volume; the caller clamps it to what it draws.
    #[must_use]
    pub fn value_at(&self, at: SystemTime) -> f64 {
        self.fit_at_newest + self.slope * signed_secs(self.newest_at, at)
    }

    /// The bytes that the line takes in one hour; 0 when it does not fall.
    #[must_use]
    pub fn taken_in_hour(&self) -> f64 {
        if self.slope < 0.0 {
            -self.slope * HOUR_SECS
        } else {
            0.0
        }
    }
}

/// What the trend says about the available space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Runway {
    /// The space falls and is 0 after `seconds`.
    Falling {
        /// The seconds until the available space is 0.
        seconds: u64,
    },
    /// The line is level, rises, or falls too little to count.
    Steady,
}

/// The seconds from `from` to `to`; negative when `to` is earlier.
fn signed_secs(from: SystemTime, to: SystemTime) -> f64 {
    match to.duration_since(from) {
        Ok(d) => d.as_secs_f64(),
        Err(e) => -e.duration().as_secs_f64(),
    }
}

/// The fit through the measured readings among the newest [`WINDOW`]
/// readings, or `None` when the readings are too few, span too little time,
/// or have too many gaps (more than one third unavailable).
#[must_use]
pub fn trend(samples: &[HostSample]) -> Option<Trend> {
    let window: &[HostSample] = &samples[samples.len().saturating_sub(WINDOW)..];
    let points: Vec<(SystemTime, u64)> = window
        .iter()
        .filter_map(|s| s.disk_available.value().map(|v| (s.at, *v)))
        .collect();
    let missing: usize = window.len() - points.len();
    if points.len() < MIN_READINGS || missing * 3 > window.len() {
        return None;
    }
    let first_at: SystemTime = points.first()?.0;
    let newest_at: SystemTime = points.last()?.0;
    let span_secs: f64 = signed_secs(first_at, newest_at);
    if span_secs < MIN_SPAN_SECS {
        return None;
    }
    let xs: Vec<f64> = points
        .iter()
        .map(|(at, _)| signed_secs(first_at, *at))
        .collect();
    #[expect(
        clippy::cast_precision_loss,
        reason = "a value of the fit needs no exact bytes"
    )]
    let ys: Vec<f64> = points.iter().map(|(_, v)| *v as f64).collect();
    #[expect(
        clippy::cast_precision_loss,
        reason = "the count is at most 60, so the conversion is exact"
    )]
    let n: f64 = points.len() as f64;
    let mean_x: f64 = xs.iter().sum::<f64>() / n;
    let mean_y: f64 = ys.iter().sum::<f64>() / n;
    let sxx: f64 = xs.iter().map(|x| (x - mean_x).powi(2)).sum();
    let sxy: f64 = xs
        .iter()
        .zip(&ys)
        .map(|(x, y)| (x - mean_x) * (y - mean_y))
        .sum();
    // Identical timestamps have no variance: no line.
    if !sxx.is_finite() || sxx <= f64::EPSILON {
        return None;
    }
    let slope: f64 = sxy / sxx;
    let fit_at_newest: f64 = mean_y + slope * (span_secs - mean_x);
    if !slope.is_finite() || !fit_at_newest.is_finite() {
        return None;
    }
    Some(Trend {
        slope,
        fit_at_newest,
        newest_at,
        readings: points.len(),
        span_secs,
    })
}

/// A non-negative float as whole seconds, saturating.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "the value is clamped to 0 and 10^18 first"
)]
fn whole_secs(value: f64) -> u64 {
    value.clamp(0.0, 1e18) as u64
}

/// The runway of `trend`. It needs the newest reading of the available space
/// and the size of the volume; without either there is no runway. It is
/// `Falling` only when the line falls and the fall over the readings is
/// [`MIN_FALL_SHARE`] of the volume or more.
#[must_use]
pub fn runway(
    trend: &Trend,
    newest_available: Option<u64>,
    disk_total: Option<u64>,
) -> Option<Runway> {
    let available: u64 = newest_available?;
    let total: u64 = disk_total.filter(|t| *t > 0)?;
    #[expect(
        clippy::cast_precision_loss,
        reason = "an estimate needs no exact bytes"
    )]
    let (available, total): (f64, f64) = (available as f64, total as f64);
    let fall: f64 = -trend.slope * trend.span_secs;
    if trend.slope < 0.0 && fall >= total * MIN_FALL_SHARE {
        Some(Runway::Falling {
            seconds: whole_secs(available / -trend.slope),
        })
    } else {
        Some(Runway::Steady)
    }
}

/// The text of a runway, with one unit: "≈ 40 min", "≈ 3 h", "≈ 2 d",
/// "more than 7 d", or "steady".
#[must_use]
pub fn runway_text(runway: Runway) -> String {
    let Runway::Falling { seconds } = runway else {
        return "steady".to_owned();
    };
    #[expect(
        clippy::cast_precision_loss,
        reason = "an estimate of seconds needs no exact value"
    )]
    let secs: f64 = seconds as f64;
    if secs > MAX_SECS {
        return "more than 7 d".to_owned();
    }
    let minutes: u64 = whole_secs((secs / 60.0).round()).max(1);
    if minutes < 60 {
        return format!("≈ {minutes} min");
    }
    let hours: u64 = whole_secs((secs / 3_600.0).round());
    if hours < 24 {
        return format!("≈ {hours} h");
    }
    format!("≈ {} d", whole_secs((secs / 86_400.0).round()).max(1))
}

/// The runway of a session, with the trend and the readings behind it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Estimate {
    /// The line.
    pub trend: Trend,
    /// The runway.
    pub runway: Runway,
}

impl Estimate {
    /// The text of the runway.
    #[must_use]
    pub fn text(&self) -> String {
        runway_text(self.runway)
    }

    /// The number of measured readings behind the estimate.
    #[must_use]
    pub const fn readings(&self) -> usize {
        self.trend.readings
    }
}

/// The estimate of the newest readings of `samples`. The volume size is the
/// used plus the available space of the newest reading; an unavailable newest
/// reading gives no estimate.
#[must_use]
pub fn estimate(samples: &[HostSample]) -> Option<Estimate> {
    let newest: &HostSample = samples.last()?;
    let available: Option<u64> = newest.disk_available.value().copied();
    let total: Option<u64> = newest
        .disk_used
        .value()
        .zip(available.as_ref())
        .map(|(used, free)| used.saturating_add(*free));
    let trend: Trend = trend(samples)?;
    let runway: Runway = runway(&trend, available, total)?;
    Some(Estimate { trend, runway })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::model::{Measured, PressureLevel};
    use std::time::Duration;

    const GB: u64 = 1_000_000_000;

    /// Whether two instants are `gap` apart or less.
    fn near(a: SystemTime, b: SystemTime, gap: Duration) -> bool {
        a.duration_since(b).unwrap_or_else(|e| e.duration()) <= gap
    }

    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000 + secs)
    }

    fn sample(secs: u64, available: Option<u64>, total: u64) -> HostSample {
        HostSample {
            at: at(secs),
            pressure: Measured::Value(PressureLevel::Normal),
            swap_used: Measured::Value(0),
            disk_available: available
                .map_or_else(|| Measured::Unavailable("none".to_owned()), Measured::Value),
            disk_used: available.map_or_else(
                || Measured::Unavailable("none".to_owned()),
                |a| Measured::Value(total - a),
            ),
            utc_offset: None,
        }
    }

    /// `count` readings, 10 s apart, with `step` bytes added each time.
    fn line(count: u64, start: u64, step: i64) -> Vec<HostSample> {
        (0..count)
            .map(|i| {
                let value: i64 =
                    i64::try_from(start).unwrap_or(0) + step * i64::try_from(i).unwrap_or(0);
                sample(i * 10, Some(u64::try_from(value).unwrap_or(0)), 500 * GB)
            })
            .collect()
    }

    #[test]
    fn too_few_readings_give_no_trend() {
        assert!(trend(&[]).is_none());
        assert!(trend(&line(11, 300 * GB, -400_000_000)).is_none());
        assert!(trend(&line(12, 300 * GB, -400_000_000)).is_some());
    }

    #[test]
    fn a_short_span_gives_no_trend() {
        let short: Vec<HostSample> = (0..20)
            .map(|i| sample(i * 2, Some(300 * GB - i * 1_000_000), 500 * GB))
            .collect();
        assert!(trend(&short).is_none(), "38 s is below 60 s");
    }

    #[test]
    fn too_many_unavailable_readings_give_no_trend() {
        let mut samples: Vec<HostSample> = line(24, 300 * GB, -400_000_000);
        for index in 0..9 {
            samples[index * 2 + 1] = sample(
                u64::try_from(index * 2 + 1).unwrap_or(0) * 10,
                None,
                500 * GB,
            );
        }
        // 9 of 24 are unavailable: more than a third.
        assert!(trend(&samples).is_none());
        samples[1] = sample(10, Some(300 * GB), 500 * GB);
        // 8 of 24: exactly a third, and 16 measured readings.
        assert!(trend(&samples).is_some());
    }

    #[test]
    fn an_unavailable_reading_never_enters_the_fit() {
        let mut samples: Vec<HostSample> = line(20, 300 * GB, -400_000_000);
        samples[5] = sample(50, None, 500 * GB);
        let Some(t) = trend(&samples) else {
            panic!("a trend is expected")
        };
        assert_eq!(t.readings, 19);
        // A zero would bend the line; the fit stays on the exact line.
        assert!((t.slope + 40_000_000.0).abs() < 1.0, "{}", t.slope);
    }

    #[test]
    fn a_level_line_is_steady() {
        let samples: Vec<HostSample> = line(20, 300 * GB, 0);
        let Some(t) = trend(&samples) else {
            panic!("a trend is expected")
        };
        let r = runway(&t, Some(300 * GB), Some(500 * GB));
        assert_eq!(r, Some(Runway::Steady));
        assert_eq!(runway_text(Runway::Steady), "steady");
    }

    #[test]
    fn a_rising_line_is_steady() {
        let samples: Vec<HostSample> = line(20, 300 * GB, 400_000_000);
        let Some(t) = trend(&samples) else {
            panic!("a trend is expected")
        };
        assert_eq!(
            runway(&t, Some(300 * GB), Some(500 * GB)),
            Some(Runway::Steady)
        );
        assert!(t.taken_in_hour() < 1.0);
    }

    #[test]
    fn the_fall_threshold_is_a_share_of_the_volume() {
        // 0.05% of 500 GB is 250 MB. 20 readings have 19 steps.
        let above: Vec<HostSample> = line(20, 300 * GB, -14_000_000);
        let below: Vec<HostSample> = line(20, 300 * GB, -12_000_000);
        let run = |samples: &[HostSample]| {
            trend(samples).and_then(|t| runway(&t, Some(300 * GB), Some(500 * GB)))
        };
        assert!(matches!(run(&above), Some(Runway::Falling { .. })));
        assert_eq!(run(&below), Some(Runway::Steady));
    }

    #[test]
    fn a_small_fall_is_steady() {
        // 1 MB over 190 s is far below 0.05% of 500 GB.
        let samples: Vec<HostSample> = line(20, 300 * GB, -52_632);
        let Some(t) = trend(&samples) else {
            panic!("a trend is expected")
        };
        assert_eq!(
            runway(&t, Some(300 * GB), Some(500 * GB)),
            Some(Runway::Steady)
        );
    }

    #[test]
    fn a_falling_line_has_an_exact_text() {
        // 40 MB a second from 300 GB: 7500 s, 2.08 h.
        let samples: Vec<HostSample> = line(20, 300 * GB, -400_000_000);
        let Some(t) = trend(&samples) else {
            panic!("a trend is expected")
        };
        let newest: u64 = 300 * GB - 19 * 400_000_000;
        let r = runway(&t, Some(newest), Some(500 * GB));
        let Some(Runway::Falling { seconds }) = r else {
            panic!("a fall is expected, got {r:?}")
        };
        assert!(seconds.abs_diff(newest / 40_000_000) <= 1, "{seconds}");
        assert_eq!(runway_text(Runway::Falling { seconds }), "≈ 2 h");
        let hour: f64 = t.taken_in_hour();
        assert!((hour - 144.0e9).abs() < 1.0e6, "{hour}");
        assert!(near(t.newest_at, at(190), Duration::from_secs(1)));
    }

    #[test]
    fn the_text_has_one_unit() {
        let text = |seconds: u64| runway_text(Runway::Falling { seconds });
        assert_eq!(text(0), "≈ 1 min");
        assert_eq!(text(40 * 60), "≈ 40 min");
        assert_eq!(text(59 * 60 + 40), "≈ 1 h");
        assert_eq!(text(3 * 3_600), "≈ 3 h");
        assert_eq!(text(23 * 3_600 + 20 * 60), "≈ 23 h");
        assert_eq!(text(2 * 86_400), "≈ 2 d");
        assert_eq!(text(7 * 86_400), "≈ 7 d");
        assert_eq!(text(7 * 86_400 + 1), "more than 7 d");
        assert_eq!(text(u64::MAX), "more than 7 d");
    }

    #[test]
    fn huge_values_stay_finite() {
        let samples: Vec<HostSample> = (0..20)
            .map(|i| HostSample {
                at: at(i * 10),
                pressure: Measured::Value(PressureLevel::Normal),
                swap_used: Measured::Value(0),
                disk_available: Measured::Value(u64::MAX - i * 1_000_000_000_000),
                disk_used: Measured::Value(0),
                utc_offset: None,
            })
            .collect();
        let Some(t) = trend(&samples) else {
            panic!("a trend is expected")
        };
        assert!(t.slope.is_finite() && t.fit_at_newest.is_finite());
        let r = runway(&t, Some(u64::MAX), Some(u64::MAX));
        // The fall of these readings is below 0.05% of a volume of this size.
        assert_eq!(r, Some(Runway::Steady));
    }

    #[test]
    fn identical_timestamps_give_no_trend() {
        let samples: Vec<HostSample> = (0..20)
            .map(|i| sample(0, Some(300 * GB - i * GB), 500 * GB))
            .collect();
        assert!(trend(&samples).is_none());
    }

    #[test]
    fn an_unavailable_newest_reading_gives_no_runway() {
        let mut samples: Vec<HostSample> = line(20, 300 * GB, -400_000_000);
        samples.push(sample(200, None, 500 * GB));
        assert!(trend(&samples).is_some(), "the fit has enough readings");
        assert!(estimate(&samples).is_none());
        let Some(t) = trend(&samples) else {
            panic!("a trend is expected")
        };
        assert_eq!(runway(&t, None, Some(500 * GB)), None);
        assert_eq!(runway(&t, Some(GB), None), None);
        assert_eq!(runway(&t, Some(GB), Some(0)), None);
    }

    #[test]
    fn the_estimate_names_the_total_from_the_newest_reading() {
        let samples: Vec<HostSample> = line(20, 300 * GB, -400_000_000);
        let Some(e) = estimate(&samples) else {
            panic!("an estimate is expected")
        };
        assert_eq!(e.readings(), 20);
        assert_eq!(e.text(), "≈ 2 h");
    }

    #[test]
    fn only_the_newest_sixty_readings_count() {
        let mut samples: Vec<HostSample> = line(40, 400 * GB, 400_000_000);
        samples.extend(
            (40..100).map(|i| sample(i * 10, Some(300 * GB - (i - 40) * 400_000_000), 500 * GB)),
        );
        let Some(t) = trend(&samples) else {
            panic!("a trend is expected")
        };
        assert_eq!(t.readings, 60);
        assert!(t.slope < 0.0, "the older rise is not in the fit");
    }

    #[test]
    fn the_drift_fixture_has_a_falling_runway() {
        use crate::data::fixture::{DriftReading, drift_step};
        let samples: Vec<HostSample> = (0..100)
            .map(|step| match drift_step(step) {
                DriftReading::Values { available, .. } => sample(
                    u64::try_from(step).unwrap_or(0) * 10,
                    Some(available),
                    512 * GB,
                ),
                DriftReading::Unavailable => {
                    sample(u64::try_from(step).unwrap_or(0) * 10, None, 512 * GB)
                }
            })
            .collect();
        let Some(e) = estimate(&samples) else {
            panic!("an estimate is expected")
        };
        assert!(e.text().starts_with('\u{2248}'), "{}", e.text());
    }
}
