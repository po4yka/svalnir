//! A value that passed its consistency check and cannot change after it.

use std::ops::Deref;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A record that has a consistency rule.
pub trait Check {
    /// The reason a record does not agree with its rule.
    type Error: std::fmt::Display;

    /// Checks the record.
    ///
    /// # Errors
    ///
    /// Returns the first rule that the record does not agree with.
    fn check(&self) -> Result<(), Self::Error>;
}

/// A record that passed [`Check::check`].
///
/// The record is read through `Deref`. There is no mutable access: a
/// change needs a new record and a new check. JSON encodes the record
/// itself, and decoding runs the check again.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Checked<T>(T);

impl<T: Check> Checked<T> {
    /// Checks the record and keeps it.
    ///
    /// # Errors
    ///
    /// Returns the error of [`Check::check`].
    pub fn new(record: T) -> Result<Self, T::Error> {
        record.check()?;
        Ok(Self(record))
    }
}

impl<T> Checked<T> {
    /// The record. A changed record needs a new check.
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> Deref for Checked<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T: Serialize> Serialize for Checked<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de, T: Check + Deserialize<'de>> Deserialize<'de> for Checked<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let record: T = T::deserialize(deserializer)?;
        Self::new(record).map_err(serde::de::Error::custom)
    }
}
