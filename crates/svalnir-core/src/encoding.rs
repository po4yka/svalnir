//! Shared rules of the JSON encoding.
//!
//! `docs/INTERFACES.md` section 3 owns the encoding. Exact integers are
//! canonical base-10 strings. An enumeration value that this build does not
//! know stays visible as an unrecognized value.

use std::fmt;

use thiserror::Error;

/// The reason an exact integer text was rejected.
///
/// The error does not repeat the rejected text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum QuantityError {
    /// The text is empty.
    #[error("the quantity is empty")]
    Empty,
    /// The text is not a canonical base-10 integer.
    #[error("the quantity is not a canonical base-10 integer")]
    NonCanonical,
    /// The integer is outside the range of the field.
    #[error("the quantity is out of range")]
    OutOfRange,
}

/// Parses text that matches `0|[1-9][0-9]*` into the unsigned 64-bit range.
pub(crate) fn parse_canonical_u64(text: &str) -> Result<u64, QuantityError> {
    check_canonical_digits(text)?;
    text.parse().map_err(|_| QuantityError::OutOfRange)
}

/// Parses a canonical signed integer: `0`, or an optional `-` and a nonzero
/// canonical integer.
pub(crate) fn parse_canonical_i128(text: &str) -> Result<i128, QuantityError> {
    let digits: &str = match text.strip_prefix('-') {
        Some("0" | "") => return Err(QuantityError::NonCanonical),
        Some(rest) => rest,
        None => text,
    };
    check_canonical_digits(digits)?;
    text.parse().map_err(|_| QuantityError::OutOfRange)
}

fn check_canonical_digits(digits: &str) -> Result<(), QuantityError> {
    if digits.is_empty() {
        return Err(QuantityError::Empty);
    }
    let has_leading_zero: bool = digits.len() > 1 && digits.starts_with('0');
    if has_leading_zero || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(QuantityError::NonCanonical);
    }
    Ok(())
}

/// The text of an enumeration value that this build does not recognize.
///
/// Only decoding makes this value, so it is never equal to a known spelling.
/// A consumer shows it as unsupported or unknown. A consumer must not map it
/// to a known value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UnrecognizedText(String);

impl UnrecognizedText {
    pub(crate) fn new(text: &str) -> Self {
        Self(text.to_owned())
    }

    /// The text as it was received.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for UnrecognizedText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Defines an unsigned 64-bit quantity that JSON encodes as a canonical
/// base-10 string.
macro_rules! unsigned_quantity {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
        pub struct $name(u64);

        impl $name {
            /// The value zero.
            pub const ZERO: Self = Self(0);
            /// The largest value.
            pub const MAX: Self = Self(u64::MAX);

            /// Makes the value from its integer.
            pub const fn new(value: u64) -> Self {
                Self(value)
            }

            /// The integer value.
            pub const fn get(self) -> u64 {
                self.0
            }
        }

        impl From<u64> for $name {
            fn from(value: u64) -> Self {
                Self(value)
            }
        }

        impl From<$name> for u64 {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl ::std::fmt::Display for $name {
            fn fmt(&self, formatter: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                ::std::fmt::Display::fmt(&self.0, formatter)
            }
        }

        impl ::std::str::FromStr for $name {
            type Err = $crate::encoding::QuantityError;

            fn from_str(text: &str) -> Result<Self, Self::Err> {
                $crate::encoding::parse_canonical_u64(text).map(Self)
            }
        }

        impl ::serde::Serialize for $name {
            fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_str(&self.0)
            }
        }

        impl<'de> ::serde::Deserialize<'de> for $name {
            fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let text: String = ::serde::Deserialize::deserialize(deserializer)?;
                text.parse().map_err(::serde::de::Error::custom)
            }
        }
    };
}
pub(crate) use unsigned_quantity;

/// Adds checked addition and subtraction to an unsigned quantity.
macro_rules! checked_arithmetic {
    ($name:ident) => {
        impl $name {
            /// Adds the two values. Returns `None` on overflow.
            #[must_use]
            pub const fn checked_add(self, other: Self) -> Option<Self> {
                match self.0.checked_add(other.0) {
                    Some(value) => Some(Self(value)),
                    None => None,
                }
            }

            /// Subtracts `other`. Returns `None` when `other` is larger.
            #[must_use]
            pub const fn checked_sub(self, other: Self) -> Option<Self> {
                match self.0.checked_sub(other.0) {
                    Some(value) => Some(Self(value)),
                    None => None,
                }
            }
        }
    };
}
pub(crate) use checked_arithmetic;

/// Defines an enumeration that JSON encodes as a string and that keeps a
/// value it does not know in an `Unrecognized` variant.
macro_rules! wire_enum {
    (
        $(#[$meta:meta])*
        $name:ident {
            $($(#[$variant_meta:meta])* $variant:ident => $text:literal,)+
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub enum $name {
            $($(#[$variant_meta])* $variant,)+
            /// A value that this build does not recognize. It has no known
            /// meaning and is not a default.
            Unrecognized($crate::encoding::UnrecognizedText),
        }

        impl $name {
            /// The serialized spelling.
            pub fn as_str(&self) -> &str {
                match self {
                    $(Self::$variant => $text,)+
                    Self::Unrecognized(text) => text.as_str(),
                }
            }

            /// Decodes a serialized spelling. An unknown spelling becomes
            /// `Unrecognized`.
            pub fn from_wire(text: &str) -> Self {
                match text {
                    $($text => Self::$variant,)+
                    other => Self::Unrecognized($crate::encoding::UnrecognizedText::new(other)),
                }
            }

            /// Whether this build knows the value.
            pub fn is_recognized(&self) -> bool {
                !matches!(self, Self::Unrecognized(_))
            }
        }

        impl ::std::fmt::Display for $name {
            fn fmt(&self, formatter: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                formatter.write_str(self.as_str())
            }
        }

        impl ::serde::Serialize for $name {
            fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> ::serde::Deserialize<'de> for $name {
            fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let text: String = ::serde::Deserialize::deserialize(deserializer)?;
                Ok(Self::from_wire(&text))
            }
        }
    };
}
pub(crate) use wire_enum;

#[cfg(test)]
mod tests {
    use super::{QuantityError, parse_canonical_i128, parse_canonical_u64};

    #[test]
    fn unsigned_text_is_canonical_and_in_range() {
        assert_eq!(parse_canonical_u64("0"), Ok(0));
        assert_eq!(parse_canonical_u64("18446744073709551615"), Ok(u64::MAX));
        assert_eq!(parse_canonical_u64(""), Err(QuantityError::Empty));
        for text in [
            "00", "01", "+1", "-1", "1 ", " 1", "1_000", "1,000", "1e3", "1.0", "0x10", "١",
        ] {
            assert_eq!(
                parse_canonical_u64(text),
                Err(QuantityError::NonCanonical),
                "{text}"
            );
        }
        assert_eq!(
            parse_canonical_u64("18446744073709551616"),
            Err(QuantityError::OutOfRange)
        );
    }

    #[test]
    fn signed_text_has_a_minus_only_on_a_nonzero_value() {
        assert_eq!(parse_canonical_i128("0"), Ok(0));
        assert_eq!(parse_canonical_i128("-1"), Ok(-1));
        assert_eq!(parse_canonical_i128("42"), Ok(42));
        assert_eq!(parse_canonical_i128("-0"), Err(QuantityError::NonCanonical));
        assert_eq!(
            parse_canonical_i128("-01"),
            Err(QuantityError::NonCanonical)
        );
        assert_eq!(parse_canonical_i128("+1"), Err(QuantityError::NonCanonical));
        assert_eq!(
            parse_canonical_i128("--1"),
            Err(QuantityError::NonCanonical)
        );
        assert_eq!(parse_canonical_i128("-"), Err(QuantityError::NonCanonical));
        assert_eq!(
            parse_canonical_i128("999999999999999999999999999999999999999999"),
            Err(QuantityError::OutOfRange)
        );
    }
}
