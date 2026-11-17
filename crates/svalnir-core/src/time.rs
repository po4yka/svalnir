//! Monotonic and wall-clock timestamps.
//!
//! `docs/RESOURCE_MODEL.md` sections 3 and 5 own the time model. The two
//! timestamps are distinct types. A monotonic timestamp orders measurements
//! in one clock domain and one boot. A wall-clock timestamp is for display
//! and history; it does not establish freshness, a sustain period, or a
//! cooldown.

use std::fmt;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use crate::encoding::unsigned_quantity;
use crate::quantity::Nanoseconds;

unsigned_quantity! {
    /// Nanoseconds on the monotonic timeline of one clock domain.
    ///
    /// Two values are comparable only when their clock domain and boot
    /// identity are the same. The value is not a process-local `Instant`.
    MonotonicNanos
}

impl MonotonicNanos {
    /// The time from `earlier` to this timestamp. Returns `None` when
    /// `earlier` is later than this timestamp.
    #[must_use]
    pub const fn checked_duration_since(self, earlier: Self) -> Option<Nanoseconds> {
        match self.get().checked_sub(earlier.get()) {
            Some(elapsed) => Some(Nanoseconds::new(elapsed)),
            None => None,
        }
    }

    /// The timestamp `duration` after this timestamp. Returns `None` on
    /// overflow.
    #[must_use]
    pub const fn checked_add(self, duration: Nanoseconds) -> Option<Self> {
        match self.get().checked_add(duration.get()) {
            Some(value) => Some(Self::new(value)),
            None => None,
        }
    }
}

/// The reason a wall-clock timestamp was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum WallTimeError {
    /// The text is not an RFC 3339 timestamp with the `Z` offset.
    #[error("the timestamp is not an RFC 3339 UTC timestamp such as `2026-11-16T12:00:00.003Z`")]
    Malformed,
    /// A date or time field has a value that does not exist.
    #[error("the timestamp has a date or time field that is out of range")]
    FieldOutOfRange,
    /// The time is outside the years 0000 to 9999.
    #[error("the timestamp is outside the years 0000 to 9999")]
    OutOfRange,
}

const NANOSECONDS_PER_SECOND: u32 = 1_000_000_000;
const SECONDS_PER_DAY: i64 = 86_400;
/// `0000-01-01T00:00:00Z`.
const MIN_UNIX_SECONDS: i64 = -62_167_219_200;
/// `9999-12-31T23:59:59Z`.
const MAX_UNIX_SECONDS: i64 = 253_402_300_799;

/// A UTC wall-clock time with nanosecond resolution.
///
/// JSON encodes it as an RFC 3339 string with the `Z` offset. The fraction
/// has zero, three, six, or nine digits: the smallest of these that is exact.
/// Decoding accepts a fraction of one to nine digits and only the uppercase
/// `T` and `Z`. A leap second (`:60`) is rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WallTime {
    unix_seconds: i64,
    subsecond_nanoseconds: u32,
}

impl WallTime {
    /// `1970-01-01T00:00:00Z`.
    pub const UNIX_EPOCH: Self = Self {
        unix_seconds: 0,
        subsecond_nanoseconds: 0,
    };

    /// Makes a time from seconds since the Unix epoch and a fraction.
    ///
    /// # Errors
    ///
    /// Returns [`WallTimeError::FieldOutOfRange`] when the fraction is one
    /// second or more, and [`WallTimeError::OutOfRange`] when the time is
    /// outside the years 0000 to 9999.
    pub const fn from_unix(
        unix_seconds: i64,
        subsecond_nanoseconds: u32,
    ) -> Result<Self, WallTimeError> {
        if subsecond_nanoseconds >= NANOSECONDS_PER_SECOND {
            return Err(WallTimeError::FieldOutOfRange);
        }
        if unix_seconds < MIN_UNIX_SECONDS || unix_seconds > MAX_UNIX_SECONDS {
            return Err(WallTimeError::OutOfRange);
        }
        Ok(Self {
            unix_seconds,
            subsecond_nanoseconds,
        })
    }

    /// Whole seconds since the Unix epoch. The value is negative before 1970.
    pub const fn unix_seconds(self) -> i64 {
        self.unix_seconds
    }

    /// The fraction of the second, in nanoseconds.
    pub const fn subsecond_nanoseconds(self) -> u32 {
        self.subsecond_nanoseconds
    }
}

impl TryFrom<SystemTime> for WallTime {
    type Error = WallTimeError;

    fn try_from(time: SystemTime) -> Result<Self, Self::Error> {
        match time.duration_since(UNIX_EPOCH) {
            Ok(after) => {
                let seconds: i64 =
                    i64::try_from(after.as_secs()).map_err(|_| WallTimeError::OutOfRange)?;
                Self::from_unix(seconds, after.subsec_nanos())
            }
            Err(error) => {
                let before = error.duration();
                let whole: i64 =
                    i64::try_from(before.as_secs()).map_err(|_| WallTimeError::OutOfRange)?;
                if before.subsec_nanos() == 0 {
                    Self::from_unix(-whole, 0)
                } else {
                    // Round the seconds down and keep a positive fraction.
                    Self::from_unix(-whole - 1, NANOSECONDS_PER_SECOND - before.subsec_nanos())
                }
            }
        }
    }
}

/// Days from 1970-01-01 to the given date of the proleptic Gregorian
/// calendar. `month` is 1 to 12 and `day` is 1 to 31.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let shifted_year: i64 = if month <= 2 { year - 1 } else { year };
    let era: i64 = shifted_year.div_euclid(400);
    let year_of_era: i64 = shifted_year.rem_euclid(400);
    let shifted_month: i64 = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year: i64 = (153 * shifted_month + 2) / 5 + day - 1;
    let day_of_era: i64 = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// The year, month, and day of the given count of days from 1970-01-01.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let shifted: i64 = days + 719_468;
    let era: i64 = shifted.div_euclid(146_097);
    let day_of_era: i64 = shifted.rem_euclid(146_097);
    let year_of_era: i64 =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year: i64 = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month: i64 = (5 * day_of_year + 2) / 153;
    let day: i64 = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month: i64 = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year: i64 = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

fn days_in_month(year: i64, month: i64) -> i64 {
    let is_leap_year: bool = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    match month {
        2 if is_leap_year => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

impl fmt::Display for WallTime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let days: i64 = self.unix_seconds.div_euclid(SECONDS_PER_DAY);
        let second_of_day: i64 = self.unix_seconds.rem_euclid(SECONDS_PER_DAY);
        let (year, month, day) = civil_from_days(days);
        let (hour, minute, second) = (
            second_of_day / 3_600,
            second_of_day % 3_600 / 60,
            second_of_day % 60,
        );
        write!(
            formatter,
            "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}"
        )?;
        let fraction: u32 = self.subsecond_nanoseconds;
        if fraction == 0 {
            // No fraction.
        } else if fraction.is_multiple_of(1_000_000) {
            write!(formatter, ".{:03}", fraction / 1_000_000)?;
        } else if fraction.is_multiple_of(1_000) {
            write!(formatter, ".{:06}", fraction / 1_000)?;
        } else {
            write!(formatter, ".{fraction:09}")?;
        }
        formatter.write_str("Z")
    }
}

/// Reads `text` as a decimal number of ASCII digits only.
fn parse_digits(text: &str) -> Result<i64, WallTimeError> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(WallTimeError::Malformed);
    }
    text.parse().map_err(|_| WallTimeError::Malformed)
}

impl FromStr for WallTime {
    type Err = WallTimeError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        // `YYYY-MM-DDTHH:MM:SS`, an optional fraction, and `Z`.
        const SEPARATORS: [(usize, u8); 5] =
            [(4, b'-'), (7, b'-'), (10, b'T'), (13, b':'), (16, b':')];
        const DATE_TIME_LENGTH: usize = 19;

        let bytes: &[u8] = text.as_bytes();
        if !text.is_ascii() || bytes.len() <= DATE_TIME_LENGTH {
            return Err(WallTimeError::Malformed);
        }
        if SEPARATORS
            .iter()
            .any(|&(index, separator)| bytes[index] != separator)
        {
            return Err(WallTimeError::Malformed);
        }
        let year: i64 = parse_digits(&text[0..4])?;
        let month: i64 = parse_digits(&text[5..7])?;
        let day: i64 = parse_digits(&text[8..10])?;
        let hour: i64 = parse_digits(&text[11..13])?;
        let minute: i64 = parse_digits(&text[14..16])?;
        let second: i64 = parse_digits(&text[17..19])?;

        let tail: &str = text[DATE_TIME_LENGTH..]
            .strip_suffix('Z')
            .ok_or(WallTimeError::Malformed)?;
        let subsecond_nanoseconds: u32 = if tail.is_empty() {
            0
        } else {
            let digits: &str = tail.strip_prefix('.').ok_or(WallTimeError::Malformed)?;
            if digits.is_empty() || digits.len() > 9 {
                return Err(WallTimeError::Malformed);
            }
            let padded: String = format!("{digits:0<9}");
            u32::try_from(parse_digits(&padded)?).map_err(|_| WallTimeError::Malformed)?
        };

        if !(1..=12).contains(&month)
            || !(1..=days_in_month(year, month)).contains(&day)
            || hour > 23
            || minute > 59
            || second > 59
        {
            return Err(WallTimeError::FieldOutOfRange);
        }
        let unix_seconds: i64 = days_from_civil(year, month, day) * SECONDS_PER_DAY
            + hour * 3_600
            + minute * 60
            + second;
        Self::from_unix(unix_seconds, subsecond_nanoseconds)
    }
}

impl Serialize for WallTime {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for WallTime {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text: String = Deserialize::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use super::{MonotonicNanos, WallTime, WallTimeError};
    use crate::quantity::Nanoseconds;

    #[test]
    fn monotonic_timestamps_encode_as_canonical_strings() {
        let timestamp = MonotonicNanos::new(120_003_000_000);
        let json: String = serde_json::to_string(&timestamp).unwrap();
        assert_eq!(json, "\"120003000000\"");
        assert_eq!(
            serde_json::from_str::<MonotonicNanos>(&json).unwrap(),
            timestamp
        );
        assert!(serde_json::from_str::<MonotonicNanos>("120003000000").is_err());
        assert!(serde_json::from_str::<MonotonicNanos>("\"0120\"").is_err());
    }

    #[test]
    fn monotonic_arithmetic_is_checked() {
        let start = MonotonicNanos::new(120_000_000_000);
        let finish = MonotonicNanos::new(120_003_000_000);
        assert_eq!(
            finish.checked_duration_since(start),
            Some(Nanoseconds::new(3_000_000))
        );
        assert_eq!(start.checked_duration_since(finish), None);
        assert_eq!(start.checked_add(Nanoseconds::new(3_000_000)), Some(finish));
        assert_eq!(MonotonicNanos::MAX.checked_add(Nanoseconds::new(1)), None);
    }

    #[test]
    fn wall_time_round_trips() {
        for (text, seconds, nanoseconds) in [
            ("1970-01-01T00:00:00Z", 0, 0),
            ("2026-11-16T12:00:00.003Z", 1_794_830_400, 3_000_000),
            ("2026-11-16T12:00:00.000250Z", 1_794_830_400, 250_000),
            ("2026-11-16T12:00:00.000000001Z", 1_794_830_400, 1),
            ("2024-02-29T23:59:59Z", 1_709_251_199, 0),
            ("1969-12-31T23:59:59.500Z", -1, 500_000_000),
            ("0000-01-01T00:00:00Z", -62_167_219_200, 0),
            (
                "9999-12-31T23:59:59.999999999Z",
                253_402_300_799,
                999_999_999,
            ),
        ] {
            let time: WallTime = text.parse().unwrap();
            assert_eq!(
                (time.unix_seconds(), time.subsecond_nanoseconds()),
                (seconds, nanoseconds),
                "{text}"
            );
            assert_eq!(time.to_string(), text);
            let json: String = serde_json::to_string(&time).unwrap();
            assert_eq!(json, format!("\"{text}\""));
            assert_eq!(serde_json::from_str::<WallTime>(&json).unwrap(), time);
        }
    }

    #[test]
    fn wall_time_accepts_a_short_fraction_and_writes_the_canonical_one() {
        let time: WallTime = "2026-11-16T12:00:00.5Z".parse().unwrap();
        assert_eq!(time.subsecond_nanoseconds(), 500_000_000);
        assert_eq!(time.to_string(), "2026-11-16T12:00:00.500Z");
    }

    #[test]
    fn wall_time_rejects_text_outside_the_grammar() {
        for text in [
            "",
            "2026-11-16",
            "2026-11-16T12:00:00",
            "2026-11-16T12:00:00+00:00",
            "2026-11-16T12:00:00.003+00:00",
            "2026-11-16t12:00:00Z",
            "2026-11-16T12:00:00z",
            "2026-11-16 12:00:00Z",
            "2026-11-16T12:00:00.Z",
            "2026-11-16T12:00:00.0000000001Z",
            "2026-11-16T12:00:00,003Z",
            "2026-11-16T12:00:+0Z",
            "+026-11-16T12:00:00Z",
            "12026-11-16T12:00:00Z",
            "2026-11-16T12:00:00Zé",
        ] {
            assert_eq!(
                text.parse::<WallTime>(),
                Err(WallTimeError::Malformed),
                "{text}"
            );
        }
        for text in [
            "2026-00-16T12:00:00Z",
            "2026-13-16T12:00:00Z",
            "2026-02-29T12:00:00Z",
            "2026-04-31T12:00:00Z",
            "2026-11-00T12:00:00Z",
            "2026-11-16T24:00:00Z",
            "2026-11-16T12:60:00Z",
            "2026-11-16T23:59:60Z",
        ] {
            assert_eq!(
                text.parse::<WallTime>(),
                Err(WallTimeError::FieldOutOfRange),
                "{text}"
            );
        }
        assert!(serde_json::from_str::<WallTime>("1794830400").is_err());
    }

    #[test]
    fn wall_time_range_is_checked() {
        assert_eq!(
            WallTime::from_unix(0, 1_000_000_000),
            Err(WallTimeError::FieldOutOfRange)
        );
        assert_eq!(
            WallTime::from_unix(253_402_300_800, 0),
            Err(WallTimeError::OutOfRange)
        );
        assert_eq!(
            WallTime::from_unix(-62_167_219_201, 0),
            Err(WallTimeError::OutOfRange)
        );
    }

    #[test]
    fn wall_time_converts_from_system_time() {
        assert_eq!(WallTime::try_from(UNIX_EPOCH), Ok(WallTime::UNIX_EPOCH));
        let after = UNIX_EPOCH + Duration::new(1_794_830_400, 3_000_000);
        assert_eq!(
            WallTime::try_from(after).unwrap().to_string(),
            "2026-11-16T12:00:00.003Z"
        );
        let before = UNIX_EPOCH - Duration::new(0, 500_000_000);
        assert_eq!(
            WallTime::try_from(before).unwrap().to_string(),
            "1969-12-31T23:59:59.500Z"
        );
    }
}
