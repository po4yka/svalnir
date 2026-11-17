//! Metric history samples.
//!
//! A sample is one core `Observation`. The store keeps its canonical JSON
//! text, so that each quantity is the base-10 string of the core encoding
//! and reads back with no loss. An unavailable observation keeps its reason
//! and has no value.

use rusqlite::types::Value;
use rusqlite::{TransactionBehavior, params, params_from_iter};
use serde::Serialize;
use serde::de::DeserializeOwned;
use svalnir_core::id::IdentityId;
use svalnir_core::observation::{
    Availability, MetricId, Observation, ObservationError, ObservationValue, Reading, Scope,
    ScopeKind, UnavailableReason,
};
use svalnir_core::quantity::EntryCount;
use svalnir_core::time::WallTime;

use super::Store;
use super::error::StoreError;
use super::query::{QueryLimit, TimeOrder, TimeRange, push_range, wall_from_parts, wall_parts};

/// The maximum number of samples in one [`Store::insert_samples`] call.
///
/// The limit bounds the size of one write transaction.
pub const MAX_SAMPLE_BATCH: usize = 10_000;

const TABLE: &str = "metric_sample";

/// One observation in its stored form: the canonical JSON text and the
/// fields that the store uses for filters.
///
/// The form does not depend on the value type, so that one batch can hold
/// observations of bytes, pages, counters, and states.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedSample {
    metric_id: MetricId,
    scope: Scope,
    captured_at: WallTime,
    availability: Reading<()>,
    observation_json: String,
}

impl EncodedSample {
    /// Encodes an observation for the store.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Observation`] when the observation has a value
    /// and a known unit that the value type does not accept, and
    /// [`StoreError::Encode`] when the core encoding refuses the observation
    /// (for example, a sample that finishes before it starts).
    pub fn encode<T>(observation: &Observation<T>) -> Result<Self, StoreError>
    where
        T: Serialize + ObservationValue,
    {
        if observation.reading.is_available()
            && observation.unit.is_recognized()
            && !T::accepts_unit(&observation.unit)
        {
            return Err(StoreError::Observation(ObservationError::UnitIncompatible));
        }
        let observation_json: String =
            serde_json::to_string(observation).map_err(StoreError::Encode)?;
        Ok(Self {
            metric_id: observation.metric_id.clone(),
            scope: observation.scope.clone(),
            captured_at: observation.sample.captured_at,
            availability: match &observation.reading {
                Reading::Available(_) => Reading::Available(()),
                Reading::Unavailable(reason) => Reading::Unavailable(reason.clone()),
                Reading::Unrecognized(text) => Reading::Unrecognized(text.clone()),
            },
            observation_json,
        })
    }

    /// Decodes the observation with the value type `T`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Decode`] when the stored text is not an
    /// observation of `T`.
    pub fn decode<T>(&self) -> Result<Observation<T>, StoreError>
    where
        T: DeserializeOwned + ObservationValue,
    {
        serde_json::from_str(&self.observation_json).map_err(StoreError::Decode)
    }

    /// The metric of the observation.
    pub fn metric_id(&self) -> &MetricId {
        &self.metric_id
    }

    /// The scope of the observation.
    pub fn scope(&self) -> &Scope {
        &self.scope
    }

    /// The wall-clock time of the sample.
    pub fn captured_at(&self) -> WallTime {
        self.captured_at
    }

    /// The availability of the observation, with the reason of an
    /// unavailable one. The value itself is in the encoded observation.
    pub fn availability(&self) -> &Reading<()> {
        &self.availability
    }

    /// The canonical JSON text of the observation.
    pub fn observation_json(&self) -> &str {
        &self.observation_json
    }
}

/// One stored sample.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SampleRow {
    /// The row identifier in the store. It is not stable after a deletion
    /// of all samples.
    pub row_id: i64,
    /// The sample.
    pub sample: EncodedSample,
}

/// A bounded query of metric samples.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SampleQuery {
    /// Keep only this metric. `None` keeps each metric.
    pub metric_id: Option<MetricId>,
    /// Keep only this scope. `None` keeps each scope.
    pub scope: Option<Scope>,
    /// The range of the sample time.
    pub range: TimeRange,
    /// The order of the result.
    pub order: TimeOrder,
    /// The maximum number of rows.
    pub limit: QueryLimit,
}

impl SampleQuery {
    /// A query of the newest samples of all metrics, up to `limit` rows.
    pub const fn newest(limit: QueryLimit) -> Self {
        Self {
            metric_id: None,
            scope: None,
            range: TimeRange::ALL,
            order: TimeOrder::NewestFirst,
            limit,
        }
    }
}

impl Store {
    /// Writes one observation.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`EncodedSample::encode`] and of
    /// [`Store::insert_samples`].
    pub fn insert_sample<T>(&mut self, observation: &Observation<T>) -> Result<(), StoreError>
    where
        T: Serialize + ObservationValue,
    {
        let sample: EncodedSample = EncodedSample::encode(observation)?;
        self.insert_samples(std::slice::from_ref(&sample))
    }

    /// Writes a batch of samples in one transaction: all of them or none.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::BatchTooLarge`] for more than
    /// [`MAX_SAMPLE_BATCH`] samples. Returns a storage error, for example
    /// [`StoreError::Full`] or [`StoreError::Busy`], when the transaction
    /// did not commit; the store then has no row of the batch.
    pub fn insert_samples(&mut self, samples: &[EncodedSample]) -> Result<(), StoreError> {
        if samples.len() > MAX_SAMPLE_BATCH {
            return Err(StoreError::BatchTooLarge {
                size: samples.len(),
                limit: MAX_SAMPLE_BATCH,
            });
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        {
            let mut statement = transaction.prepare_cached(
                "INSERT INTO metric_sample (metric_id, scope_kind, scope_identity, \
                 captured_unix_s, captured_subsec_ns, availability, reason, observation) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )?;
            for sample in samples {
                let (seconds, nanoseconds) = wall_parts(sample.captured_at);
                let (availability, reason): (&str, Option<&str>) = match &sample.availability {
                    Reading::Available(()) => (Availability::Available.as_str(), None),
                    Reading::Unavailable(reason) => {
                        (Availability::Unavailable.as_str(), Some(reason.as_str()))
                    }
                    Reading::Unrecognized(text) => (text.as_str(), None),
                };
                statement.execute(params![
                    sample.metric_id.as_str(),
                    sample.scope.kind.as_str(),
                    sample.scope.identity_id.as_str(),
                    seconds,
                    nanoseconds,
                    availability,
                    reason,
                    sample.observation_json,
                ])?;
            }
        }
        transaction.commit()?;
        Ok(())
    }

    /// Reads the samples that agree with `query`, up to its limit.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidRow`] when a stored field is outside the
    /// range of its core type, or a storage error.
    pub fn samples(&self, query: &SampleQuery) -> Result<Vec<SampleRow>, StoreError> {
        let mut sql: String = String::from(
            "SELECT id, metric_id, scope_kind, scope_identity, captured_unix_s, \
             captured_subsec_ns, availability, reason, observation \
             FROM metric_sample WHERE 1",
        );
        let mut parameters: Vec<Value> = Vec::new();
        if let Some(metric_id) = &query.metric_id {
            sql.push_str(" AND metric_id = ?");
            parameters.push(Value::Text(metric_id.as_str().to_owned()));
        }
        if let Some(scope) = &query.scope {
            sql.push_str(" AND scope_kind = ? AND scope_identity = ?");
            parameters.push(Value::Text(scope.kind.as_str().to_owned()));
            parameters.push(Value::Text(scope.identity_id.as_str().to_owned()));
        }
        push_range(&mut sql, &mut parameters, "captured", query.range);
        let order: &str = query.order.sql();
        sql.push_str(" ORDER BY captured_unix_s ");
        sql.push_str(order);
        sql.push_str(", captured_subsec_ns ");
        sql.push_str(order);
        sql.push_str(", id ");
        sql.push_str(order);
        sql.push_str(" LIMIT ?");
        parameters.push(Value::Integer(i64::from(query.limit.get())));

        let mut statement = self.connection.prepare_cached(&sql)?;
        let mut rows = statement.query(params_from_iter(parameters))?;
        let mut result: Vec<SampleRow> = Vec::new();
        while let Some(row) = rows.next()? {
            let metric_id: String = row.get(1)?;
            let scope_kind: String = row.get(2)?;
            let scope_identity: String = row.get(3)?;
            let availability: String = row.get(6)?;
            let reason: Option<String> = row.get(7)?;
            let invalid = |column: &'static str| StoreError::InvalidRow {
                table: TABLE,
                column,
            };
            let availability: Reading<()> = match (Availability::from_wire(&availability), reason) {
                (Availability::Available, None) => Reading::Available(()),
                (Availability::Unavailable, Some(reason)) => {
                    Reading::Unavailable(UnavailableReason::from_wire(&reason))
                }
                (Availability::Unrecognized(text), None) => Reading::Unrecognized(text),
                _ => return Err(invalid("reason")),
            };
            result.push(SampleRow {
                row_id: row.get(0)?,
                sample: EncodedSample {
                    metric_id: MetricId::new(metric_id).map_err(|_| invalid("metric_id"))?,
                    scope: Scope {
                        kind: ScopeKind::from_wire(&scope_kind),
                        identity_id: IdentityId::new(scope_identity)
                            .map_err(|_| invalid("scope_identity"))?,
                    },
                    captured_at: wall_from_parts(row.get(4)?, row.get(5)?, TABLE, "captured_at")?,
                    availability,
                    observation_json: row.get(8)?,
                },
            });
        }
        Ok(result)
    }

    /// Counts the stored samples.
    ///
    /// # Errors
    ///
    /// Returns a storage error.
    pub fn sample_count(&self) -> Result<EntryCount, StoreError> {
        self.count_rows("SELECT count(*) FROM metric_sample", TABLE)
    }

    /// Deletes all metric samples: the history-deletion operation for
    /// metrics. Returns the number of deleted samples.
    ///
    /// The file keeps its size. [`Store::compact`] returns the space, and
    /// [`Store::checkpoint`] removes the write-ahead log.
    ///
    /// # Errors
    ///
    /// Returns a storage error; the store then keeps each sample.
    pub fn delete_all_samples(&mut self) -> Result<EntryCount, StoreError> {
        let deleted: usize = self.connection.execute("DELETE FROM metric_sample", [])?;
        Ok(EntryCount::new(u64::try_from(deleted).unwrap_or(u64::MAX)))
    }
}
