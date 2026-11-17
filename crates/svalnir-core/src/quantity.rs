//! Checked integer quantities.
//!
//! `docs/RESOURCE_MODEL.md` section 3 owns the units. Each unit is a distinct
//! type, so a byte count cannot be used as a page count. Arithmetic is
//! checked. JSON encodes each quantity as a canonical base-10 string
//! (`docs/INTERFACES.md` section 3).

use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::encoding::{QuantityError, checked_arithmetic, parse_canonical_i128, unsigned_quantity};

unsigned_quantity! {
    /// A number of bytes.
    Bytes
}
checked_arithmetic!(Bytes);

impl Bytes {
    /// Multiplies the value by `factor`. Returns `None` on overflow.
    #[must_use]
    pub const fn checked_mul(self, factor: u64) -> Option<Self> {
        match self.get().checked_mul(factor) {
            Some(value) => Some(Self::new(value)),
            None => None,
        }
    }

    /// The signed change from `earlier` to this value.
    #[must_use]
    pub fn delta_from(self, earlier: Self) -> ByteDelta {
        ByteDelta(i128::from(self.get()) - i128::from(earlier.get()))
    }

    /// Applies a signed change. Returns `None` when the result is negative or
    /// too large.
    #[must_use]
    pub fn checked_add_delta(self, delta: ByteDelta) -> Option<Self> {
        let sum: i128 = i128::from(self.get()).checked_add(delta.0)?;
        u64::try_from(sum).ok().map(Self::new)
    }
}

unsigned_quantity! {
    /// A number of virtual-memory pages.
    ///
    /// The page size is not part of the value. Keep the runtime page size
    /// with the measurement and convert with [`PageCount::to_bytes`].
    PageCount
}
checked_arithmetic!(PageCount);

impl PageCount {
    /// The byte representation of this count for the given runtime page size.
    /// Returns `None` on overflow.
    #[must_use]
    pub const fn to_bytes(self, page_size: Bytes) -> Option<Bytes> {
        page_size.checked_mul(self.get())
    }
}

unsigned_quantity! {
    /// A number of filesystem entries or objects.
    EntryCount
}
checked_arithmetic!(EntryCount);

unsigned_quantity! {
    /// The value of a cumulative counter.
    ///
    /// The value is comparable only with a value from the same reset domain.
    CounterValue
}

/// A later counter value is smaller than an earlier one.
///
/// The counter was reset or the two values are not comparable. This is not
/// negative activity and not a wraparound.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the counter decreased; it was reset or the samples are not comparable")]
pub struct CounterReset;

impl CounterValue {
    /// The increase from `earlier` to this value.
    ///
    /// # Errors
    ///
    /// Returns [`CounterReset`] when this value is smaller than `earlier`.
    pub const fn increase_since(self, earlier: Self) -> Result<u64, CounterReset> {
        match self.get().checked_sub(earlier.get()) {
            Some(increase) => Ok(increase),
            None => Err(CounterReset),
        }
    }
}

unsigned_quantity! {
    /// An exact duration in nanoseconds.
    Nanoseconds
}
checked_arithmetic!(Nanoseconds);

impl From<Nanoseconds> for Duration {
    fn from(value: Nanoseconds) -> Self {
        Self::from_nanos(value.get())
    }
}

impl TryFrom<Duration> for Nanoseconds {
    type Error = QuantityError;

    fn try_from(value: Duration) -> Result<Self, Self::Error> {
        u64::try_from(value.as_nanos())
            .map(Self::new)
            .map_err(|_| QuantityError::OutOfRange)
    }
}

/// A signed difference between two byte quantities, for example an observed
/// capacity change.
///
/// The range is the full difference of two [`Bytes`] values:
/// `-18446744073709551615..=18446744073709551615`. A negative value is valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct ByteDelta(i128);

impl ByteDelta {
    /// No change.
    pub const ZERO: Self = Self(0);
    /// The largest increase.
    pub const MAX: Self = Self(u64::MAX as i128);
    /// The largest decrease.
    pub const MIN: Self = Self(-(u64::MAX as i128));

    /// Makes a delta.
    ///
    /// # Errors
    ///
    /// Returns [`QuantityError::OutOfRange`] when the value is not the
    /// difference of two byte quantities.
    pub const fn new(value: i128) -> Result<Self, QuantityError> {
        if value < Self::MIN.0 || value > Self::MAX.0 {
            return Err(QuantityError::OutOfRange);
        }
        Ok(Self(value))
    }

    /// The integer value.
    pub const fn get(self) -> i128 {
        self.0
    }

    /// Adds the two deltas. Returns `None` when the sum is out of range.
    #[must_use]
    pub fn checked_add(self, other: Self) -> Option<Self> {
        Self::new(self.0.checked_add(other.0)?).ok()
    }

    /// The size of the change without its direction.
    #[must_use]
    pub fn magnitude(self) -> Bytes {
        // The range of the type keeps the magnitude in 64 bits.
        Bytes::new(u64::try_from(self.0.unsigned_abs()).unwrap_or(u64::MAX))
    }
}

impl fmt::Display for ByteDelta {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, formatter)
    }
}

impl FromStr for ByteDelta {
    type Err = QuantityError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::new(parse_canonical_i128(text)?)
    }
}

impl Serialize for ByteDelta {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ByteDelta {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text: String = Deserialize::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{ByteDelta, Bytes, CounterReset, CounterValue, EntryCount, Nanoseconds, PageCount};
    use crate::encoding::QuantityError;

    #[test]
    fn unsigned_quantities_round_trip_as_canonical_strings() {
        for value in [0, 1, 8_589_934_592, u64::MAX] {
            let bytes = Bytes::new(value);
            let json: String = serde_json::to_string(&bytes).unwrap();
            assert_eq!(json, format!("\"{value}\""));
            assert_eq!(serde_json::from_str::<Bytes>(&json).unwrap(), bytes);
        }
        let counter: CounterValue = serde_json::from_str("\"18446744073709551615\"").unwrap();
        assert_eq!(counter, CounterValue::MAX);
        assert_eq!(serde_json::to_string(&PageCount::new(7)).unwrap(), "\"7\"");
        assert_eq!(serde_json::to_string(&EntryCount::ZERO).unwrap(), "\"0\"");
        assert_eq!(
            serde_json::to_string(&Nanoseconds::new(3_000_000)).unwrap(),
            "\"3000000\""
        );
    }

    #[test]
    fn unsigned_decoding_rejects_non_canonical_and_out_of_range_text() {
        for json in [
            "\"\"",
            "\"00\"",
            "\"007\"",
            "\"+7\"",
            "\"-7\"",
            "\"-0\"",
            "\"7 \"",
            "\"1e3\"",
            "\"1.5\"",
            "\"1_000\"",
            "\"18446744073709551616\"",
            "\"99999999999999999999999999\"",
            // An exact quantity is a string. A JSON number is not accepted.
            "7",
            "7.0",
            "null",
        ] {
            assert!(serde_json::from_str::<Bytes>(json).is_err(), "{json}");
        }
        assert_eq!(
            "18446744073709551616".parse::<Bytes>(),
            Err(QuantityError::OutOfRange)
        );
        assert_eq!("01".parse::<Bytes>(), Err(QuantityError::NonCanonical));
    }

    #[test]
    fn byte_arithmetic_is_checked() {
        assert_eq!(
            Bytes::new(2).checked_add(Bytes::new(3)),
            Some(Bytes::new(5))
        );
        assert_eq!(Bytes::MAX.checked_add(Bytes::new(1)), None);
        assert_eq!(Bytes::new(2).checked_sub(Bytes::new(3)), None);
        assert_eq!(Bytes::new(4096).checked_mul(3), Some(Bytes::new(12_288)));
        assert_eq!(Bytes::MAX.checked_mul(2), None);
        assert_eq!(
            PageCount::new(3).to_bytes(Bytes::new(16_384)),
            Some(Bytes::new(49_152))
        );
        assert_eq!(PageCount::MAX.to_bytes(Bytes::new(16_384)), None);
    }

    #[test]
    fn byte_delta_covers_the_full_difference() {
        assert_eq!(Bytes::MAX.delta_from(Bytes::ZERO), ByteDelta::MAX);
        assert_eq!(Bytes::ZERO.delta_from(Bytes::MAX), ByteDelta::MIN);
        assert_eq!(Bytes::new(5).delta_from(Bytes::new(8)).get(), -3);
        assert_eq!(ByteDelta::MIN.magnitude(), Bytes::MAX);
        assert_eq!(ByteDelta::MAX.checked_add(ByteDelta::new(1).unwrap()), None);
        assert_eq!(
            Bytes::new(8).checked_add_delta(ByteDelta::new(-3).unwrap()),
            Some(Bytes::new(5))
        );
        assert_eq!(
            Bytes::new(2).checked_add_delta(ByteDelta::new(-3).unwrap()),
            None
        );
        assert_eq!(
            Bytes::MAX.checked_add_delta(ByteDelta::new(1).unwrap()),
            None
        );
    }

    #[test]
    fn byte_delta_round_trips_and_rejects_bad_text() {
        for (value, text) in [
            (0_i128, "\"0\""),
            (-1, "\"-1\""),
            (1024, "\"1024\""),
            (ByteDelta::MAX.get(), "\"18446744073709551615\""),
            (ByteDelta::MIN.get(), "\"-18446744073709551615\""),
        ] {
            let delta = ByteDelta::new(value).unwrap();
            assert_eq!(serde_json::to_string(&delta).unwrap(), text);
            assert_eq!(serde_json::from_str::<ByteDelta>(text).unwrap(), delta);
        }
        for json in [
            "\"-0\"",
            "\"+1\"",
            "\"-01\"",
            "\"\"",
            "\"-\"",
            "\"18446744073709551616\"",
            "\"-18446744073709551616\"",
            "-1",
        ] {
            assert!(serde_json::from_str::<ByteDelta>(json).is_err(), "{json}");
        }
        assert_eq!(ByteDelta::new(i128::MAX), Err(QuantityError::OutOfRange));
    }

    #[test]
    fn a_counter_decrease_is_a_reset() {
        assert_eq!(
            CounterValue::new(9).increase_since(CounterValue::new(4)),
            Ok(5)
        );
        assert_eq!(
            CounterValue::new(4).increase_since(CounterValue::new(4)),
            Ok(0)
        );
        assert_eq!(
            CounterValue::new(3).increase_since(CounterValue::new(4)),
            Err(CounterReset)
        );
    }

    #[test]
    fn nanoseconds_convert_to_and_from_a_duration() {
        assert_eq!(
            Duration::from(Nanoseconds::new(1_500)),
            Duration::from_nanos(1_500)
        );
        assert_eq!(
            Nanoseconds::try_from(Duration::from_secs(2)),
            Ok(Nanoseconds::new(2_000_000_000))
        );
        assert_eq!(
            Nanoseconds::try_from(Duration::MAX),
            Err(QuantityError::OutOfRange)
        );
    }
}
