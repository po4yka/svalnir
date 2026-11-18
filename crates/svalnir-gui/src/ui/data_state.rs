//! Pure helpers that present snapshot values.

use crate::data::model::Measured;
use std::time::Duration;

/// The text for a value that is not available: an em dash.
pub const UNAVAILABLE_TEXT: &str = "\u{2014}";

const UNITS: [&str; 6] = ["B", "KB", "MB", "GB", "TB", "PB"];

/// Splits `bytes` into a value with one fraction digit and a decimal unit.
/// The unit is chosen after rounding: 999,950 B is "1.0 MB", not "1000.0 KB".
#[must_use]
pub fn format_bytes(bytes: u64) -> (String, &'static str) {
    let bytes: u128 = u128::from(bytes);
    let mut unit: usize = 0;
    let mut divisor: u128 = 1;
    loop {
        // Tenths of the unit, computed with integers to avoid float rounding.
        let tenths: u128 = (bytes * 10 + divisor / 2) / divisor;
        let at_top: bool = unit + 1 >= UNITS.len();
        if unit == 0 && bytes < 1000 {
            return (bytes.to_string(), "B");
        }
        if at_top || tenths < 10_000 {
            let text: String = format!("{}.{}", tenths / 10, tenths % 10);
            return (text, UNITS.get(unit).copied().unwrap_or("B"));
        }
        divisor *= 1000;
        unit += 1;
    }
}

/// The used capacity: total minus available. An available capacity larger
/// than the total is a contradiction and is reported as unavailable.
#[must_use]
pub fn used_capacity(total: &Measured<u64>, available: &Measured<u64>) -> Measured<u64> {
    match (total, available) {
        (Measured::Value(total), Measured::Value(available)) => {
            total.checked_sub(*available).map_or_else(
                || {
                    Measured::Unavailable(
                        "the available capacity is larger than the total capacity".to_owned(),
                    )
                },
                Measured::Value,
            )
        }
        (Measured::Unavailable(reason), _) | (_, Measured::Unavailable(reason)) => {
            Measured::Unavailable(reason.clone())
        }
    }
}

/// The age as "just now", "N s ago", or "N min ago" (hours as minutes).
#[must_use]
pub fn format_age(age: Duration) -> String {
    let seconds: u64 = age.as_secs();
    if seconds < 3 {
        "just now".to_owned()
    } else if seconds < 60 {
        format!("{seconds} s ago")
    } else {
        format!("{} min ago", seconds / 60)
    }
}

/// "185.5 GB" for a value, an em dash for an unavailable value.
#[must_use]
pub fn measured_text(measured: &Measured<u64>) -> String {
    match measured {
        Measured::Value(bytes) => {
            let (value, unit) = format_bytes(*bytes);
            format!("{value} {unit}")
        }
        Measured::Unavailable(_) => UNAVAILABLE_TEXT.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_use_decimal_units() {
        assert_eq!(format_bytes(185_500_000_000), ("185.5".to_owned(), "GB"));
        assert_eq!(format_bytes(0), ("0".to_owned(), "B"));
        assert_eq!(format_bytes(999), ("999".to_owned(), "B"));
        assert_eq!(format_bytes(1_000), ("1.0".to_owned(), "KB"));
        assert_eq!(format_bytes(512_000_000_000), ("512.0".to_owned(), "GB"));
        assert_eq!(format_bytes(u64::MAX).1, "PB");
    }

    #[test]
    fn unit_is_chosen_after_rounding() {
        assert_eq!(format_bytes(999_950_000), ("1.0".to_owned(), "GB"));
        assert_eq!(format_bytes(999_950), ("1.0".to_owned(), "MB"));
        assert_eq!(format_bytes(999_949), ("999.9".to_owned(), "KB"));
        assert_eq!(format_bytes(999_949_999), ("999.9".to_owned(), "MB"));
    }

    #[test]
    fn used_is_unavailable_when_available_exceeds_total() {
        assert_eq!(
            used_capacity(&Measured::Value(10), &Measured::Value(4)),
            Measured::Value(6)
        );
        assert!(matches!(
            used_capacity(&Measured::Value(10), &Measured::Value(11)),
            Measured::Unavailable(_)
        ));
        assert!(matches!(
            used_capacity(&Measured::Unavailable("x".into()), &Measured::Value(1)),
            Measured::Unavailable(_)
        ));
    }

    #[test]
    fn age_text() {
        assert_eq!(format_age(Duration::from_secs(1)), "just now");
        assert_eq!(format_age(Duration::from_secs(12)), "12 s ago");
        assert_eq!(format_age(Duration::from_secs(125)), "2 min ago");
    }

    #[test]
    fn unavailable_is_a_dash_not_zero() {
        assert_eq!(
            measured_text(&Measured::Unavailable("x".into())),
            "\u{2014}"
        );
        assert_eq!(measured_text(&Measured::Value(0)), "0 B");
        assert_eq!(measured_text(&Measured::Value(185_500_000_000)), "185.5 GB");
    }
}
