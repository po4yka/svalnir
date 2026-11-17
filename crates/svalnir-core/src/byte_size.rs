//! Text grammar for byte sizes in configuration values.
//!
//! A size is a canonical base-10 integer and one unit, for example `512B`,
//! `256MiB`, or `20GiB`. The units are `B`, `KiB`, `MiB`, `GiB`, and `TiB`.
//! The grammar has no fractions, signs, spaces, or decimal units.
//! `docs/POLICY_SPEC.md` section 3 owns the grammar.

use thiserror::Error;

use crate::quantity::Bytes;

/// The reason a byte-size text was rejected.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ByteSizeParseError {
    /// The text is empty.
    #[error("the size is empty; give an integer and a unit, for example `20GiB`")]
    Empty,
    /// The text does not start with an integer.
    #[error("the size `{0}` does not start with an integer")]
    MissingValue(String),
    /// The integer has a leading zero.
    #[error("the size `{0}` has an integer with a leading zero")]
    NonCanonical(String),
    /// The text has no unit.
    #[error("the size `{0}` has no unit; use `B`, `KiB`, `MiB`, `GiB`, or `TiB`")]
    MissingUnit(String),
    /// The unit is not one of the supported units.
    #[error("the size `{0}` has an unknown unit; use `B`, `KiB`, `MiB`, `GiB`, or `TiB`")]
    UnknownUnit(String),
    /// The value does not fit the supported range.
    #[error("the size `{0}` is out of range")]
    OutOfRange(String),
}

const KIBIBYTE: u64 = 1024;
const MEBIBYTE: u64 = 1024 * KIBIBYTE;
const GIBIBYTE: u64 = 1024 * MEBIBYTE;
const TEBIBYTE: u64 = 1024 * GIBIBYTE;

/// Parses a byte size such as `512B`, `64KiB`, `256MiB`, `20GiB`, or `1TiB`.
///
/// # Errors
///
/// Returns a [`ByteSizeParseError`] when the text is empty, has no canonical
/// integer, has no supported unit, or is out of range.
pub fn parse_byte_size(text: &str) -> Result<Bytes, ByteSizeParseError> {
    if text.is_empty() {
        return Err(ByteSizeParseError::Empty);
    }
    let unit_start: usize = text
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(text.len());
    let (digits, unit) = text.split_at(unit_start);
    if digits.is_empty() {
        return Err(ByteSizeParseError::MissingValue(text.to_owned()));
    }
    if digits.len() > 1 && digits.starts_with('0') {
        return Err(ByteSizeParseError::NonCanonical(text.to_owned()));
    }
    if unit.is_empty() {
        return Err(ByteSizeParseError::MissingUnit(text.to_owned()));
    }
    let factor: u64 = match unit {
        "B" => 1,
        "KiB" => KIBIBYTE,
        "MiB" => MEBIBYTE,
        "GiB" => GIBIBYTE,
        "TiB" => TEBIBYTE,
        _ => return Err(ByteSizeParseError::UnknownUnit(text.to_owned())),
    };
    let out_of_range = || ByteSizeParseError::OutOfRange(text.to_owned());
    let value: u64 = digits.parse().map_err(|_| out_of_range())?;
    Bytes::new(value)
        .checked_mul(factor)
        .ok_or_else(out_of_range)
}

#[cfg(test)]
mod tests {
    use super::{ByteSizeParseError, parse_byte_size};
    use crate::quantity::Bytes;

    #[test]
    fn parses_each_unit() {
        assert_eq!(parse_byte_size("0B"), Ok(Bytes::ZERO));
        assert_eq!(parse_byte_size("512B"), Ok(Bytes::new(512)));
        assert_eq!(parse_byte_size("64KiB"), Ok(Bytes::new(65_536)));
        assert_eq!(parse_byte_size("256MiB"), Ok(Bytes::new(268_435_456)));
        assert_eq!(parse_byte_size("20GiB"), Ok(Bytes::new(21_474_836_480)));
        assert_eq!(parse_byte_size("1TiB"), Ok(Bytes::new(1_099_511_627_776)));
        assert_eq!(parse_byte_size("18446744073709551615B"), Ok(Bytes::MAX));
    }

    #[test]
    fn rejects_text_outside_the_grammar() {
        assert_eq!(parse_byte_size(""), Err(ByteSizeParseError::Empty));
        assert!(matches!(
            parse_byte_size("GiB"),
            Err(ByteSizeParseError::MissingValue(_))
        ));
        assert!(matches!(
            parse_byte_size("-5GiB"),
            Err(ByteSizeParseError::MissingValue(_))
        ));
        assert!(matches!(
            parse_byte_size("020GiB"),
            Err(ByteSizeParseError::NonCanonical(_))
        ));
        assert!(matches!(
            parse_byte_size("20"),
            Err(ByteSizeParseError::MissingUnit(_))
        ));
        for text in [
            "20GB",
            "20G",
            "20gib",
            "20 GiB",
            "1.5GiB",
            "20GiB ",
            "1GiB512MiB",
            "20b",
            "20PiB",
        ] {
            assert!(
                matches!(
                    parse_byte_size(text),
                    Err(ByteSizeParseError::UnknownUnit(_))
                ),
                "{text}"
            );
        }
    }

    #[test]
    fn rejects_values_that_overflow() {
        assert!(matches!(
            parse_byte_size("99999999999999999999B"),
            Err(ByteSizeParseError::OutOfRange(_))
        ));
        assert!(matches!(
            parse_byte_size("16777216TiB"),
            Err(ByteSizeParseError::OutOfRange(_))
        ));
        assert_eq!(
            parse_byte_size("16777215TiB"),
            Ok(Bytes::new(16_777_215 << 40))
        );
    }
}
