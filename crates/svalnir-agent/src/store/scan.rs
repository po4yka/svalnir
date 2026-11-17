//! Saved scan records.
//!
//! The result of a scan is JSON text that the caller supplies. The store
//! does not read its fields, so that it does not depend on the scanner
//! types.

use rusqlite::types::Value;
use rusqlite::{OptionalExtension, params, params_from_iter};
use serde::de::IgnoredAny;
use svalnir_core::file::LosslessPath;
use svalnir_core::id::ScanId;
use svalnir_core::quantity::{Bytes, EntryCount};
use svalnir_core::time::WallTime;

use super::Store;
use super::error::StoreError;
use super::query::{QueryLimit, TimeOrder, TimeRange, push_range, wall_from_parts, wall_parts};

/// The maximum size of the result text of one scan record, in bytes.
pub const MAX_SCAN_RESULT_BYTES: usize = 16 * 1024 * 1024;

const TABLE: &str = "scan_record";

/// One saved scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanRecord {
    /// The identifier of the scan.
    pub scan_id: ScanId,
    /// The root of the scan, with each byte of the path.
    pub root: LosslessPath,
    /// The wall-clock time at which the scan started.
    pub started_at: WallTime,
    /// The wall-clock time at which the scan finished or stopped.
    pub finished_at: WallTime,
    /// The serialized result: JSON text that the store does not interpret.
    pub result_json: String,
}

/// A saved scan without its result text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanSummary {
    /// The identifier of the scan.
    pub scan_id: ScanId,
    /// The root of the scan.
    pub root: LosslessPath,
    /// The wall-clock time at which the scan started.
    pub started_at: WallTime,
    /// The wall-clock time at which the scan finished or stopped.
    pub finished_at: WallTime,
    /// The size of the result text.
    pub result_size: Bytes,
}

/// A bounded query of saved scans.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanQuery {
    /// The range of the start time.
    pub range: TimeRange,
    /// The order of the result, by start time.
    pub order: TimeOrder,
    /// The maximum number of rows.
    pub limit: QueryLimit,
}

impl ScanQuery {
    /// A query of the newest scans, up to `limit` rows.
    pub const fn newest(limit: QueryLimit) -> Self {
        Self {
            range: TimeRange::ALL,
            order: TimeOrder::NewestFirst,
            limit,
        }
    }
}

impl Store {
    /// Saves one scan record.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidScanResult`] when the result is not
    /// JSON, [`StoreError::ScanResultTooLarge`] when it is larger than
    /// [`MAX_SCAN_RESULT_BYTES`], and [`StoreError::DuplicateScan`] when a
    /// record with the identifier is in the store. Returns a storage error,
    /// for example [`StoreError::Full`], when the record was not written.
    pub fn insert_scan(&mut self, record: &ScanRecord) -> Result<(), StoreError> {
        if record.result_json.len() > MAX_SCAN_RESULT_BYTES {
            return Err(StoreError::ScanResultTooLarge {
                size: record.result_json.len(),
                limit: MAX_SCAN_RESULT_BYTES,
            });
        }
        serde_json::from_str::<IgnoredAny>(&record.result_json)
            .map_err(StoreError::InvalidScanResult)?;
        let started: (i64, i64) = wall_parts(record.started_at);
        let finished: (i64, i64) = wall_parts(record.finished_at);
        let inserted: usize = self.connection.execute(
            "INSERT INTO scan_record (scan_id, root, started_unix_s, started_subsec_ns, \
             finished_unix_s, finished_subsec_ns, result, result_size) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) ON CONFLICT (scan_id) DO NOTHING",
            params![
                record.scan_id.as_str(),
                record.root.as_bytes(),
                started.0,
                started.1,
                finished.0,
                finished.1,
                record.result_json,
                i64::try_from(record.result_json.len()).unwrap_or(i64::MAX),
            ],
        )?;
        if inserted == 0 {
            return Err(StoreError::DuplicateScan(record.scan_id.clone()));
        }
        Ok(())
    }

    /// Reads one scan record with its result. Returns `None` when the store
    /// has no record with the identifier.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidRow`] when a stored field is outside the
    /// range of its core type, or a storage error.
    pub fn scan(&self, scan_id: &ScanId) -> Result<Option<ScanRecord>, StoreError> {
        let row: Option<ScanColumns> = self
            .connection
            .query_row(
                "SELECT root, started_unix_s, started_subsec_ns, finished_unix_s, \
                 finished_subsec_ns, result FROM scan_record WHERE scan_id = ?1",
                params![scan_id.as_str()],
                |row| {
                    Ok((
                        row.get(0)?,
                        (row.get(1)?, row.get(2)?),
                        (row.get(3)?, row.get(4)?),
                        row.get(5)?,
                    ))
                },
            )
            .optional()?;
        let Some((root, started, finished, result_json)) = row else {
            return Ok(None);
        };
        Ok(Some(ScanRecord {
            scan_id: scan_id.clone(),
            root: root_from_bytes(root)?,
            started_at: wall_from_parts(started.0, started.1, TABLE, "started_at")?,
            finished_at: wall_from_parts(finished.0, finished.1, TABLE, "finished_at")?,
            result_json,
        }))
    }

    /// Lists the saved scans that agree with `query`, without the result
    /// text, up to its limit.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidRow`] when a stored field is outside the
    /// range of its core type, or a storage error.
    pub fn scans(&self, query: &ScanQuery) -> Result<Vec<ScanSummary>, StoreError> {
        let mut sql: String = String::from(
            "SELECT scan_id, root, started_unix_s, started_subsec_ns, finished_unix_s, \
             finished_subsec_ns, result_size FROM scan_record WHERE 1",
        );
        let mut parameters: Vec<Value> = Vec::new();
        push_range(&mut sql, &mut parameters, "started", query.range);
        let order: &str = query.order.sql();
        sql.push_str(" ORDER BY started_unix_s ");
        sql.push_str(order);
        sql.push_str(", started_subsec_ns ");
        sql.push_str(order);
        sql.push_str(", scan_id ");
        sql.push_str(order);
        sql.push_str(" LIMIT ?");
        parameters.push(Value::Integer(i64::from(query.limit.get())));

        let mut statement = self.connection.prepare_cached(&sql)?;
        let mut rows = statement.query(params_from_iter(parameters))?;
        let mut result: Vec<ScanSummary> = Vec::new();
        while let Some(row) = rows.next()? {
            let scan_id: String = row.get(0)?;
            let result_size: i64 = row.get(6)?;
            let invalid = |column: &'static str| StoreError::InvalidRow {
                table: TABLE,
                column,
            };
            result.push(ScanSummary {
                scan_id: ScanId::new(scan_id).map_err(|_| invalid("scan_id"))?,
                root: root_from_bytes(row.get(1)?)?,
                started_at: wall_from_parts(row.get(2)?, row.get(3)?, TABLE, "started_at")?,
                finished_at: wall_from_parts(row.get(4)?, row.get(5)?, TABLE, "finished_at")?,
                result_size: Bytes::new(u64::try_from(result_size).map_err(|_| invalid("result"))?),
            });
        }
        Ok(result)
    }

    /// Counts the saved scans.
    ///
    /// # Errors
    ///
    /// Returns a storage error.
    pub fn scan_count(&self) -> Result<EntryCount, StoreError> {
        self.count_rows("SELECT count(*) FROM scan_record", TABLE)
    }

    /// Deletes one scan record. Returns `true` when the record was in the
    /// store.
    ///
    /// # Errors
    ///
    /// Returns a storage error; the store then keeps the record.
    pub fn delete_scan(&mut self, scan_id: &ScanId) -> Result<bool, StoreError> {
        let deleted: usize = self.connection.execute(
            "DELETE FROM scan_record WHERE scan_id = ?1",
            params![scan_id.as_str()],
        )?;
        Ok(deleted > 0)
    }

    /// Deletes all scan records: the history-deletion operation for scans.
    /// Returns the number of deleted records.
    ///
    /// The file keeps its size. [`Store::compact`] returns the space, and
    /// [`Store::checkpoint`] removes the write-ahead log.
    ///
    /// # Errors
    ///
    /// Returns a storage error; the store then keeps each record.
    pub fn delete_all_scans(&mut self) -> Result<EntryCount, StoreError> {
        let deleted: usize = self.connection.execute("DELETE FROM scan_record", [])?;
        Ok(EntryCount::new(u64::try_from(deleted).unwrap_or(u64::MAX)))
    }
}

/// The columns of one scan row: the root, the start time, the finish time,
/// and the result text. A time is its second and nanosecond columns.
type ScanColumns = (Vec<u8>, (i64, i64), (i64, i64), String);

fn root_from_bytes(bytes: Vec<u8>) -> Result<LosslessPath, StoreError> {
    LosslessPath::from_bytes(bytes).map_err(|_| StoreError::InvalidRow {
        table: TABLE,
        column: "root",
    })
}
