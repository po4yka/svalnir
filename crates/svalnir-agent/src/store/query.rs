//! Bounds that each history query has: a time range, an order, and a limit.

use rusqlite::types::Value;
use svalnir_core::time::WallTime;

use super::error::StoreError;

/// The maximum number of rows that one query returns.
///
/// Each query has a limit. The maximum bounds the memory of one result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct QueryLimit(u32);

impl QueryLimit {
    /// The largest limit.
    pub const MAX: u32 = 10_000;

    /// Makes a limit of 1 to [`QueryLimit::MAX`] rows.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidLimit`] for 0 or a larger number.
    pub const fn new(limit: u32) -> Result<Self, StoreError> {
        if limit == 0 || limit > Self::MAX {
            return Err(StoreError::InvalidLimit {
                limit,
                maximum: Self::MAX,
            });
        }
        Ok(Self(limit))
    }

    /// The number of rows.
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// A range of wall-clock time. An absent bound does not filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TimeRange {
    /// The first instant in the range (inclusive).
    pub from: Option<WallTime>,
    /// The first instant after the range (exclusive).
    pub until: Option<WallTime>,
}

impl TimeRange {
    /// The range that does not filter.
    pub const ALL: Self = Self {
        from: None,
        until: None,
    };
}

/// The order of the rows of a query result, by wall-clock time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TimeOrder {
    /// The newest row is first. With a limit, the result has the newest rows.
    #[default]
    NewestFirst,
    /// The oldest row is first. With a limit, the result has the oldest rows.
    OldestFirst,
}

impl TimeOrder {
    pub(super) const fn sql(self) -> &'static str {
        match self {
            Self::NewestFirst => "DESC",
            Self::OldestFirst => "ASC",
        }
    }
}

/// The two stored columns of a timestamp: the Unix second and the nanosecond
/// in the second.
pub(super) fn wall_parts(time: WallTime) -> (i64, i64) {
    (time.unix_seconds(), i64::from(time.subsecond_nanoseconds()))
}

/// Reads a timestamp from its two stored columns.
pub(super) fn wall_from_parts(
    seconds: i64,
    nanoseconds: i64,
    table: &'static str,
    column: &'static str,
) -> Result<WallTime, StoreError> {
    u32::try_from(nanoseconds)
        .ok()
        .and_then(|nanoseconds| WallTime::from_unix(seconds, nanoseconds).ok())
        .ok_or(StoreError::InvalidRow { table, column })
}

/// Adds the conditions of `range` on the column pair `prefix_unix_s`,
/// `prefix_subsec_ns` to a `WHERE` clause and its parameters.
pub(super) fn push_range(
    sql: &mut String,
    parameters: &mut Vec<Value>,
    prefix: &str,
    range: TimeRange,
) {
    for (bound, operator) in [(range.from, ">="), (range.until, "<")] {
        if let Some(bound) = bound {
            let (seconds, nanoseconds) = wall_parts(bound);
            sql.push_str(" AND (");
            sql.push_str(prefix);
            sql.push_str("_unix_s, ");
            sql.push_str(prefix);
            sql.push_str("_subsec_ns) ");
            sql.push_str(operator);
            sql.push_str(" (?, ?)");
            parameters.push(Value::Integer(seconds));
            parameters.push(Value::Integer(nanoseconds));
        }
    }
}
