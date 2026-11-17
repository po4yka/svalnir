//! Text grammar for durations in configuration values and CLI options.
//!
//! A duration is a canonical base-10 integer and one unit, for example `30s`,
//! `15m`, or `30d`. The grammar has no fractions, signs, spaces, or compound
//! values.

use std::time::Duration;

use thiserror::Error;

/// The reason a duration text was rejected.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DurationParseError {
    /// The text is empty.
    #[error("the duration is empty; give an integer and a unit, for example `30s`")]
    Empty,
    /// The text does not start with an integer.
    #[error("the duration `{0}` does not start with an integer")]
    MissingValue(String),
    /// The integer has a leading zero.
    #[error("the duration `{0}` has an integer with a leading zero")]
    NonCanonical(String),
    /// The text has no unit.
    #[error("the duration `{0}` has no unit; use `ms`, `s`, `m`, `h`, or `d`")]
    MissingUnit(String),
    /// The unit is not one of the supported units.
    #[error("the duration `{0}` has an unknown unit; use `ms`, `s`, `m`, `h`, or `d`")]
    UnknownUnit(String),
    /// The value does not fit the supported range.
    #[error("the duration `{0}` is out of range")]
    OutOfRange(String),
}

const SECONDS_PER_MINUTE: u64 = 60;
const SECONDS_PER_HOUR: u64 = 60 * SECONDS_PER_MINUTE;
const SECONDS_PER_DAY: u64 = 24 * SECONDS_PER_HOUR;

/// Parses a duration such as `250ms`, `30s`, `15m`, `1h`, or `30d`.
///
/// # Errors
///
/// Returns a [`DurationParseError`] when the text is empty, has no canonical
/// integer, has no supported unit, or is out of range.
pub fn parse_duration(text: &str) -> Result<Duration, DurationParseError> {
    if text.is_empty() {
        return Err(DurationParseError::Empty);
    }
    let unit_start: usize = text
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(text.len());
    let (digits, unit) = text.split_at(unit_start);
    if digits.is_empty() {
        return Err(DurationParseError::MissingValue(text.to_owned()));
    }
    if digits.len() > 1 && digits.starts_with('0') {
        return Err(DurationParseError::NonCanonical(text.to_owned()));
    }
    if unit.is_empty() {
        return Err(DurationParseError::MissingUnit(text.to_owned()));
    }
    let out_of_range = || DurationParseError::OutOfRange(text.to_owned());
    let value: u64 = digits.parse().map_err(|_| out_of_range())?;
    let seconds = |factor: u64| -> Result<Duration, DurationParseError> {
        value
            .checked_mul(factor)
            .map(Duration::from_secs)
            .ok_or_else(out_of_range)
    };
    match unit {
        "ms" => Ok(Duration::from_millis(value)),
        "s" => seconds(1),
        "m" => seconds(SECONDS_PER_MINUTE),
        "h" => seconds(SECONDS_PER_HOUR),
        "d" => seconds(SECONDS_PER_DAY),
        _ => Err(DurationParseError::UnknownUnit(text.to_owned())),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{DurationParseError, parse_duration};

    #[test]
    fn parses_each_unit() {
        assert_eq!(parse_duration("250ms"), Ok(Duration::from_millis(250)));
        assert_eq!(parse_duration("0s"), Ok(Duration::ZERO));
        assert_eq!(parse_duration("30s"), Ok(Duration::from_secs(30)));
        assert_eq!(parse_duration("15m"), Ok(Duration::from_mins(15)));
        assert_eq!(parse_duration("1h"), Ok(Duration::from_hours(1)));
        assert_eq!(parse_duration("30d"), Ok(Duration::from_hours(720)));
    }

    #[test]
    fn rejects_text_outside_the_grammar() {
        assert_eq!(parse_duration(""), Err(DurationParseError::Empty));
        assert!(matches!(
            parse_duration("s"),
            Err(DurationParseError::MissingValue(_))
        ));
        assert!(matches!(
            parse_duration("-5s"),
            Err(DurationParseError::MissingValue(_))
        ));
        assert!(matches!(
            parse_duration("010s"),
            Err(DurationParseError::NonCanonical(_))
        ));
        assert!(matches!(
            parse_duration("10"),
            Err(DurationParseError::MissingUnit(_))
        ));
        assert!(matches!(
            parse_duration("1.5h"),
            Err(DurationParseError::UnknownUnit(_))
        ));
        assert!(matches!(
            parse_duration("10 s"),
            Err(DurationParseError::UnknownUnit(_))
        ));
        assert!(matches!(
            parse_duration("1h30m"),
            Err(DurationParseError::UnknownUnit(_))
        ));
    }

    #[test]
    fn rejects_values_that_overflow() {
        assert!(matches!(
            parse_duration("99999999999999999999s"),
            Err(DurationParseError::OutOfRange(_))
        ));
        assert!(matches!(
            parse_duration("18446744073709551615d"),
            Err(DurationParseError::OutOfRange(_))
        ));
    }
}
