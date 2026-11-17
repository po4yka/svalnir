//! Bounded retention of history.
//!
//! The caller starts retention; the store does not run it on a timer or in
//! an insert. Retention deletes rows in small batches, one transaction for
//! each batch, and does not compact the file.

use std::time::Duration;

use rusqlite::params;
use svalnir_core::quantity::{Bytes, EntryCount};
use svalnir_core::time::WallTime;

use super::Store;
use super::error::StoreError;
use super::query::wall_parts;

/// The number of samples that one retention transaction deletes.
const SAMPLE_BATCH: u32 = 500;

/// The default of [`RetentionPolicy::max_batches`]: about 50 000 samples.
pub const DEFAULT_MAX_BATCHES: u32 = 100;

/// What the caller wants retention to keep.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionPolicy {
    /// Delete each metric sample that is older than this duration before
    /// `now`. `None` does not delete by age. The age rule does not delete
    /// scan records.
    pub max_age: Option<Duration>,
    /// Delete the oldest rows until the used size of the database is not
    /// larger than this size. `None` does not delete by size. See
    /// [`Store::size`] for the used size.
    pub max_used_size: Option<Bytes>,
    /// The most delete statements, one transaction each, that one call runs
    /// for all rules together. When the budget ends first,
    /// [`RetentionReport::work_remaining`] is `true`, and the caller calls
    /// again later. Zero runs no deletion.
    pub max_batches: u32,
}

impl Default for RetentionPolicy {
    /// No age rule, no size rule, and [`DEFAULT_MAX_BATCHES`].
    fn default() -> Self {
        Self {
            max_age: None,
            max_used_size: None,
            max_batches: DEFAULT_MAX_BATCHES,
        }
    }
}

impl RetentionPolicy {
    /// The policy for the `[history]` configuration: `retention` and
    /// `max_database_size`.
    ///
    /// The size target is 90% of the hard limit, so that inserts between
    /// two retention runs have free space before the database is full.
    pub fn for_history(retention: Duration, max_database_size: Bytes) -> Self {
        let limit: u64 = max_database_size.get();
        Self {
            max_age: Some(retention),
            max_used_size: Some(Bytes::new(limit - limit / 10)),
            max_batches: DEFAULT_MAX_BATCHES,
        }
    }
}

/// What one retention run did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionReport {
    /// The samples that the age rule deleted.
    pub samples_deleted_by_age: EntryCount,
    /// The samples that the size rule deleted.
    pub samples_deleted_by_size: EntryCount,
    /// The scan records that the size rule deleted. The size rule deletes a
    /// scan record only when no sample remains.
    pub scans_deleted_by_size: EntryCount,
    /// The used size of the database after the run.
    pub used_size: Bytes,
    /// `false` when the used size is larger than the size target. Either the
    /// store cannot get below the target after the deletion of all history,
    /// or `work_remaining` is `true`.
    pub size_target_met: bool,
    /// `true` when the batch budget ended before the age rule and the size
    /// rule had finished. The caller calls retention again later.
    pub work_remaining: bool,
}

impl Store {
    /// Applies the retention policy at the wall-clock time `now`.
    ///
    /// The age rule runs first. The size rule then deletes the oldest metric
    /// samples, and deletes the oldest scan records only when no sample
    /// remains. Retention is best effort: the hard limit of
    /// `StoreOptions::max_database_size` stays in effect when retention
    /// does not run or cannot reach its target.
    ///
    /// One call runs at most [`RetentionPolicy::max_batches`] delete
    /// statements, so that it does not hold the write lock for a long time
    /// after a long stop. [`RetentionReport::work_remaining`] tells the
    /// caller to call again later.
    ///
    /// The run does not compact the file; freed pages are used again by
    /// later inserts. [`Store::compact`] is the separate, explicit call.
    ///
    /// # Errors
    ///
    /// Returns a storage error. The batches that were deleted before the
    /// error stay deleted.
    pub fn apply_retention(
        &mut self,
        now: WallTime,
        policy: &RetentionPolicy,
    ) -> Result<RetentionReport, StoreError> {
        let mut budget: u32 = policy.max_batches;
        let mut work_remaining: bool = false;

        let mut samples_by_age: u64 = 0;
        if let Some(cutoff) = policy.max_age.and_then(|age| cutoff(now, age)) {
            let (seconds, nanoseconds) = wall_parts(cutoff);
            loop {
                if budget == 0 {
                    work_remaining = true;
                    break;
                }
                budget -= 1;
                let deleted: usize = self
                    .connection
                    .prepare_cached(
                        "DELETE FROM metric_sample WHERE id IN (\
                     SELECT id FROM metric_sample \
                     WHERE (captured_unix_s, captured_subsec_ns) < (?1, ?2) \
                     ORDER BY captured_unix_s, captured_subsec_ns, id LIMIT ?3)",
                    )?
                    .execute(params![seconds, nanoseconds, SAMPLE_BATCH])?;
                samples_by_age = add(samples_by_age, deleted);
                // A short batch means that no older sample remains.
                if deleted < batch_len() {
                    break;
                }
            }
        }

        let mut samples_by_size: u64 = 0;
        let mut scans_by_size: u64 = 0;
        let mut used_size: Bytes = self.size()?.used;
        let mut size_target_met: bool = true;
        if let Some(target) = policy.max_used_size {
            // Metric samples go before scan records. The scan loop runs only
            // when no sample remains (the sample loop ended with `break`).
            let mut samples_left: bool = true;
            while used_size > target {
                if budget == 0 {
                    work_remaining = true;
                    break;
                }
                budget -= 1;
                let deleted: usize = self
                    .connection
                    .prepare_cached(
                        "DELETE FROM metric_sample WHERE id IN (\
                     SELECT id FROM metric_sample \
                     ORDER BY captured_unix_s, captured_subsec_ns, id LIMIT ?1)",
                    )?
                    .execute(params![SAMPLE_BATCH])?;
                if deleted == 0 {
                    samples_left = false;
                    break;
                }
                samples_by_size = add(samples_by_size, deleted);
                used_size = self.size()?.used;
            }
            while !samples_left && used_size > target {
                if budget == 0 {
                    work_remaining = true;
                    break;
                }
                budget -= 1;
                let deleted: usize = self
                    .connection
                    .prepare_cached(
                        "DELETE FROM scan_record WHERE scan_id IN (\
                     SELECT scan_id FROM scan_record \
                     ORDER BY started_unix_s, started_subsec_ns, scan_id LIMIT 1)",
                    )?
                    .execute([])?;
                if deleted == 0 {
                    break;
                }
                scans_by_size = add(scans_by_size, deleted);
                used_size = self.size()?.used;
            }
            size_target_met = used_size <= target;
        }

        Ok(RetentionReport {
            samples_deleted_by_age: EntryCount::new(samples_by_age),
            samples_deleted_by_size: EntryCount::new(samples_by_size),
            scans_deleted_by_size: EntryCount::new(scans_by_size),
            used_size,
            size_target_met,
            work_remaining,
        })
    }
}

fn batch_len() -> usize {
    usize::try_from(SAMPLE_BATCH).unwrap_or(usize::MAX)
}

fn add(total: u64, deleted: usize) -> u64 {
    total.saturating_add(u64::try_from(deleted).unwrap_or(u64::MAX))
}

/// The instant `age` before `now`. `None` when it is before the range of
/// the core wall time; no sample can then be older.
fn cutoff(now: WallTime, age: Duration) -> Option<WallTime> {
    let age_seconds: i64 = i64::try_from(age.as_secs()).ok()?;
    let mut seconds: i64 = now.unix_seconds().checked_sub(age_seconds)?;
    let mut nanoseconds: u32 = now.subsecond_nanoseconds();
    if nanoseconds < age.subsec_nanos() {
        seconds = seconds.checked_sub(1)?;
        nanoseconds += 1_000_000_000;
    }
    WallTime::from_unix(seconds, nanoseconds - age.subsec_nanos()).ok()
}
