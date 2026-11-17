//! The canonical observation envelope.
//!
//! `docs/RESOURCE_MODEL.md` section 4 owns the contract. An observation is a
//! measurement of one identified scope with its unit, source, coverage, and
//! time context. An unavailable measurement has no value and has a reason; it
//! cannot be read as an available zero.

use std::borrow::Cow;
use std::fmt;

use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use crate::encoding::{UnrecognizedText, wire_enum};
use crate::id::{
    AdapterId, BootId, ClockDomainId, CollectorEpochId, IdentityId, SampleId, WorkerId,
};
use crate::quantity::Nanoseconds;
use crate::time::{MonotonicNanos, WallTime};

/// The largest length of a metric name, in bytes.
pub const MAX_METRIC_ID_LENGTH: usize = 128;

/// The reason a metric name was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum MetricIdError {
    /// The name is empty or longer than [`MAX_METRIC_ID_LENGTH`].
    #[error("the metric name is empty or longer than 128 bytes")]
    Length,
    /// The name is not dot-separated segments of `a-z`, `0-9`, and `_`.
    #[error("the metric name is not dot-separated segments of lowercase letters, digits, and `_`")]
    Malformed,
}

/// The stable name of a metric, for example `disk.available_bytes`.
///
/// A name has one documented meaning. The [`metric`] module has the names
/// that `docs/RESOURCE_MODEL.md` registers.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MetricId(Cow<'static, str>);

impl MetricId {
    /// Makes a metric name from text.
    ///
    /// # Errors
    ///
    /// Returns a [`MetricIdError`] when the text is not a metric name.
    pub fn new(name: impl Into<String>) -> Result<Self, MetricIdError> {
        let name: String = name.into();
        validate_metric_id(&name)?;
        Ok(Self(Cow::Owned(name)))
    }

    /// A name from the registry in this file. A test validates each name.
    const fn registered(name: &'static str) -> Self {
        Self(Cow::Borrowed(name))
    }

    /// The text of the name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn validate_metric_id(name: &str) -> Result<(), MetricIdError> {
    if name.is_empty() || name.len() > MAX_METRIC_ID_LENGTH {
        return Err(MetricIdError::Length);
    }
    let is_segment = |segment: &str| {
        !segment.is_empty()
            && segment
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    };
    if !name.split('.').all(is_segment) {
        return Err(MetricIdError::Malformed);
    }
    Ok(())
}

impl fmt::Display for MetricId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Serialize for MetricId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for MetricId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let name: String = Deserialize::deserialize(deserializer)?;
        Self::new(name).map_err(serde::de::Error::custom)
    }
}

/// The metric names that `docs/RESOURCE_MODEL.md` registers.
pub mod metric {
    use super::MetricId;

    macro_rules! metrics {
        ($($(#[$meta:meta])* $name:ident => $text:literal,)+) => {
            $($(#[$meta])* pub const $name: MetricId = MetricId::registered($text);)+

            /// Each registered metric name.
            pub const ALL: &[MetricId] = &[$($name,)+];
        };
    }

    metrics! {
        /// Valid `f_blocks * f_bsize` of the volume.
        DISK_TOTAL_BYTES => "disk.total_bytes",
        /// Valid `f_bfree * f_bsize` of the volume.
        DISK_FREE_BYTES => "disk.free_bytes",
        /// Valid `f_bavail * f_bsize` of the volume. The baseline policy input.
        DISK_AVAILABLE_BYTES => "disk.available_bytes",
        /// Foundation capacity for important usage.
        DISK_IMPORTANT_AVAILABLE_BYTES => "disk.important_available_bytes",
        /// Foundation capacity for opportunistic usage.
        DISK_OPPORTUNISTIC_AVAILABLE_BYTES => "disk.opportunistic_available_bytes",

        /// Physical memory of the host.
        MEMORY_PHYSICAL_BYTES => "memory.physical_bytes",
        /// Native memory-pressure state of the host.
        MEMORY_PRESSURE => "memory.pressure",
        /// Free pages. Speculative pages are a subset of this count.
        MEMORY_VM_FREE_PAGES => "memory.vm.free_pages",
        /// Active pages.
        MEMORY_VM_ACTIVE_PAGES => "memory.vm.active_pages",
        /// Inactive pages.
        MEMORY_VM_INACTIVE_PAGES => "memory.vm.inactive_pages",
        /// Wired pages.
        MEMORY_VM_WIRED_PAGES => "memory.vm.wired_pages",
        /// Speculative pages. Do not add them to the free pages.
        MEMORY_VM_SPECULATIVE_PAGES => "memory.vm.speculative_pages",
        /// Anonymous pages. Not a disjoint slice.
        MEMORY_VM_INTERNAL_PAGES => "memory.vm.internal_pages",
        /// File-backed pages. Not a disjoint slice.
        MEMORY_VM_EXTERNAL_PAGES => "memory.vm.external_pages",
        /// Cumulative page-ins.
        MEMORY_VM_PAGEINS_TOTAL => "memory.vm.pageins_total",
        /// Cumulative page-outs.
        MEMORY_VM_PAGEOUTS_TOTAL => "memory.vm.pageouts_total",
        /// Pages that compressed data physically occupies.
        MEMORY_COMPRESSOR_PHYSICAL_PAGES => "memory.compressor.physical_pages",
        /// Logical page content that the compressor represents.
        MEMORY_COMPRESSOR_UNCOMPRESSED_PAGES => "memory.compressor.uncompressed_pages",
        /// Cumulative page compressions.
        MEMORY_COMPRESSOR_COMPRESSIONS_TOTAL => "memory.compressor.compressions_total",
        /// Cumulative page decompressions.
        MEMORY_COMPRESSOR_DECOMPRESSIONS_TOTAL => "memory.compressor.decompressions_total",
        /// Cumulative swap-ins.
        MEMORY_SWAP_SWAPINS_TOTAL => "memory.swap.swapins_total",
        /// Cumulative swap-outs.
        MEMORY_SWAP_SWAPOUTS_TOTAL => "memory.swap.swapouts_total",
        /// Allocated swap space.
        MEMORY_SWAP_ALLOCATED_BYTES => "memory.swap.allocated_bytes",
        /// Used swap space.
        MEMORY_SWAP_USED_BYTES => "memory.swap.used_bytes",
        /// Available swap space.
        MEMORY_SWAP_AVAILABLE_BYTES => "memory.swap.available_bytes",

        /// Resident size of a process. Not exclusive physical ownership.
        PROCESS_RESIDENT_BYTES => "process.resident_bytes",
        /// Native charged footprint of a process.
        PROCESS_FOOTPRINT_BYTES => "process.footprint_bytes",
        /// Virtual address-space size of a process. Not committed memory.
        PROCESS_VIRTUAL_BYTES => "process.virtual_bytes",
        /// Peak footprint of a process over the lifetime that the source states.
        PROCESS_PEAK_FOOTPRINT_BYTES => "process.peak_footprint_bytes",
        /// Cumulative CPU time of a process, in nanoseconds.
        PROCESS_CPU_TIME_NS => "process.cpu_time_ns",
        /// CPU use of a process as a percentage of one core.
        PROCESS_CPU_CORE_EQUIVALENT_PERCENT => "process.cpu_core_equivalent_percent",

        /// Checked sum of the process footprints of a membership snapshot.
        APPLICATION_ATTRIBUTED_FOOTPRINT_BYTES => "application.attributed_footprint_bytes",
    }
}

wire_enum! {
    /// The kind of subject that an observation measures.
    ScopeKind {
        /// The host in its recorded boot.
        Host => "host",
        /// One mounted volume.
        Volume => "volume",
        /// One verified shared-capacity domain, such as an APFS container.
        CapacityDomain => "capacity_domain",
        /// One process generation.
        Process => "process",
        /// One application membership snapshot.
        Application => "application",
        /// One scan and its recorded inventory.
        Scan => "scan",
    }
}

/// The measured subject of an observation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Scope {
    /// The kind of subject.
    pub kind: ScopeKind,
    /// The identity record of the subject.
    pub identity_id: IdentityId,
}

wire_enum! {
    /// The registered unit of an observation value.
    ///
    /// A consumer must understand the unit before arithmetic.
    Unit {
        /// Integer bytes.
        Byte => "byte",
        /// Virtual-memory pages of the runtime page size.
        Page => "page",
        /// Filesystem entries or objects.
        Entry => "entry",
        /// Integer nanoseconds.
        Nanosecond => "nanosecond",
        /// A percentage. The metric defines the denominator.
        Percent => "percent",
        /// A value of a defined enumeration.
        State => "state",
    }
}

wire_enum! {
    /// How the value of a metric behaves over time.
    MetricKind {
        /// A value at one time.
        Gauge => "gauge",
        /// A cumulative count with a reset identity.
        Counter => "counter",
        /// A finite approximation over an interval.
        Rate => "rate",
        /// A value of a defined enumeration.
        State => "state",
        /// A value with explicit limitations.
        Estimate => "estimate",
    }
}

wire_enum! {
    /// How much of the declared scope a measurement covers.
    ///
    /// Coverage is independent of availability.
    Coverage {
        /// Complete for the recorded scope and collection method.
        Complete => "complete",
        /// A part of the scope was not measured.
        Partial => "partial",
        /// The coverage is not known.
        Unknown => "unknown",
    }
}

wire_enum! {
    /// The stable reason a measurement is unavailable.
    UnavailableReason {
        /// The worker has no permission for the query.
        PermissionDenied => "permission_denied",
        /// The source does not support the metric.
        Unsupported => "unsupported",
        /// The measured subject no longer exists.
        ResourceGone => "resource_gone",
        /// The collector has not made its first measurement.
        NotInitialized => "not_initialized",
        /// The query failed and can succeed later.
        TransientFailure => "transient_failure",
        /// The subject changed its identity during the measurement.
        IdentityChanged => "identity_changed",
        /// The source returned data that is not consistent.
        InconsistentData => "inconsistent_data",
        /// The clock is not continuous across the measurement.
        ClockDiscontinuity => "clock_discontinuity",
        /// A checked conversion overflowed.
        Overflow => "overflow",
        /// The metric was not collected.
        NotCollected => "not_collected",
    }
}

wire_enum! {
    /// Whether an observation has a value.
    Availability {
        /// The observation has a value.
        Available => "available",
        /// The observation has no value and has a reason.
        Unavailable => "unavailable",
    }
}

/// The provenance of a measurement.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Source {
    /// The collection adapter.
    pub adapter_id: AdapterId,
    /// The revision of the adapter.
    pub adapter_revision: String,
    /// The native API that the adapter called.
    pub native_api: String,
    /// The native field or expression that gives the value.
    pub native_field: String,
    /// The process that collected the measurement.
    pub worker_id: WorkerId,
}

/// The acquisition identity and time context of a measurement.
///
/// A replayed or redisplayed observation keeps its sample. Decoding rejects a
/// sample that finishes before it starts, and encoding fails for one.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
#[serde(try_from = "SampleWire")]
pub struct Sample {
    /// The unique identity of the acquisition.
    pub sample_id: SampleId,
    /// The clock domain of the monotonic timestamps.
    pub clock_domain: ClockDomainId,
    /// The boot in which the measurement was made.
    pub boot_id: BootId,
    /// The collector lifetime in which the measurement was made.
    pub collector_epoch: CollectorEpochId,
    /// When the acquisition started.
    pub started_monotonic_ns: MonotonicNanos,
    /// When the acquisition finished.
    pub finished_monotonic_ns: MonotonicNanos,
    /// The wall-clock time of the acquisition, for display and history.
    pub captured_at: WallTime,
}

impl Sample {
    /// The time that the acquisition took. Returns `None` when the sample
    /// finishes before it starts.
    #[must_use]
    pub fn acquisition_duration(&self) -> Option<Nanoseconds> {
        self.finished_monotonic_ns
            .checked_duration_since(self.started_monotonic_ns)
    }
}

impl Serialize for Sample {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if self.acquisition_duration().is_none() {
            return Err(serde::ser::Error::custom(
                ObservationError::SampleFinishesBeforeStart,
            ));
        }
        let mut fields = serializer.serialize_struct("Sample", 7)?;
        fields.serialize_field("sample_id", &self.sample_id)?;
        fields.serialize_field("clock_domain", &self.clock_domain)?;
        fields.serialize_field("boot_id", &self.boot_id)?;
        fields.serialize_field("collector_epoch", &self.collector_epoch)?;
        fields.serialize_field("started_monotonic_ns", &self.started_monotonic_ns)?;
        fields.serialize_field("finished_monotonic_ns", &self.finished_monotonic_ns)?;
        fields.serialize_field("captured_at", &self.captured_at)?;
        fields.end()
    }
}

#[derive(Deserialize)]
struct SampleWire {
    sample_id: SampleId,
    clock_domain: ClockDomainId,
    boot_id: BootId,
    collector_epoch: CollectorEpochId,
    started_monotonic_ns: MonotonicNanos,
    finished_monotonic_ns: MonotonicNanos,
    captured_at: WallTime,
}

impl TryFrom<SampleWire> for Sample {
    type Error = ObservationError;

    fn try_from(wire: SampleWire) -> Result<Self, Self::Error> {
        let sample = Self {
            sample_id: wire.sample_id,
            clock_domain: wire.clock_domain,
            boot_id: wire.boot_id,
            collector_epoch: wire.collector_epoch,
            started_monotonic_ns: wire.started_monotonic_ns,
            finished_monotonic_ns: wire.finished_monotonic_ns,
            captured_at: wire.captured_at,
        };
        if sample.acquisition_duration().is_none() {
            return Err(ObservationError::SampleFinishesBeforeStart);
        }
        Ok(sample)
    }
}

/// The result of one measurement: a value, or the reason there is no value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Reading<T> {
    /// The measurement succeeded. A zero is a measured zero.
    Available(T),
    /// The measurement has no value.
    Unavailable(UnavailableReason),
    /// The `availability` text is one that this build does not recognize.
    /// The reading has no usable value and no usable reason. It is not
    /// available and it is not a known unavailable condition.
    Unrecognized(UnrecognizedText),
}

impl<T> Reading<T> {
    /// The value of an available reading.
    pub fn value(&self) -> Option<&T> {
        match self {
            Self::Available(value) => Some(value),
            Self::Unavailable(_) | Self::Unrecognized(_) => None,
        }
    }

    /// The reason of an unavailable reading.
    pub fn reason(&self) -> Option<&UnavailableReason> {
        match self {
            Self::Available(_) | Self::Unrecognized(_) => None,
            Self::Unavailable(reason) => Some(reason),
        }
    }

    /// Whether the reading has a value.
    pub fn is_available(&self) -> bool {
        matches!(self, Self::Available(_))
    }

    /// Converts the value of an available reading.
    pub fn map<U>(self, convert: impl FnOnce(T) -> U) -> Reading<U> {
        match self {
            Self::Available(value) => Reading::Available(convert(value)),
            Self::Unavailable(reason) => Reading::Unavailable(reason),
            Self::Unrecognized(text) => Reading::Unrecognized(text),
        }
    }
}

/// The reason a serialized observation was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ObservationError {
    /// `availability` is `available` and `value` is `null`.
    #[error("the observation is available and has no value")]
    AvailableWithoutValue,
    /// `availability` is `available` and `reason` is not `null`.
    #[error("the observation is available and has a reason")]
    AvailableWithReason,
    /// `availability` is `unavailable` and `value` is not `null`.
    #[error("the observation is unavailable and has a value")]
    UnavailableWithValue,
    /// `availability` is `unavailable` and `reason` is `null`.
    #[error("the observation is unavailable and has no reason")]
    UnavailableWithoutReason,
    /// The sample finishes before it starts.
    #[error("the sample finishes before it starts")]
    SampleFinishesBeforeStart,
}

/// One measurement of one scope.
///
/// `T` is the value type that the metric definition registers, for example
/// [`Bytes`](crate::quantity::Bytes) or
/// [`PressureState`](crate::state::PressureState). `T` must not encode to
/// JSON `null`.
///
/// JSON has the fields `metric_id`, `scope`, `value`, `unit`, `kind`,
/// `availability`, `reason`, `coverage`, `source`, and `sample`. The
/// [`Reading`] gives `value`, `availability`, and `reason`. Decoding needs
/// each field and rejects a combination that is not consistent. An
/// `availability` that this build does not recognize decodes to
/// [`Reading::Unrecognized`]; its `value` and `reason` are not kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation<T> {
    /// The metric that the value belongs to.
    pub metric_id: MetricId,
    /// The measured subject.
    pub scope: Scope,
    /// The value, or the reason there is no value.
    pub reading: Reading<T>,
    /// The unit of the value.
    pub unit: Unit,
    /// How the value behaves over time.
    pub kind: MetricKind,
    /// How much of the scope the measurement covers.
    pub coverage: Coverage,
    /// The provenance of the measurement.
    pub source: Source,
    /// The acquisition identity and time context.
    pub sample: Sample,
}

impl<T> Observation<T> {
    /// The value of an available observation.
    pub fn value(&self) -> Option<&T> {
        self.reading.value()
    }

    /// The reason of an unavailable observation.
    pub fn reason(&self) -> Option<&UnavailableReason> {
        self.reading.reason()
    }

    /// Whether the observation has a value.
    pub fn is_available(&self) -> bool {
        self.reading.is_available()
    }
}

impl<T: Serialize> Serialize for Observation<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut fields = serializer.serialize_struct("Observation", 10)?;
        fields.serialize_field("metric_id", &self.metric_id)?;
        fields.serialize_field("scope", &self.scope)?;
        fields.serialize_field("value", &self.reading.value())?;
        fields.serialize_field("unit", &self.unit)?;
        fields.serialize_field("kind", &self.kind)?;
        let availability: Availability = match &self.reading {
            Reading::Available(_) => Availability::Available,
            Reading::Unavailable(_) => Availability::Unavailable,
            Reading::Unrecognized(text) => Availability::Unrecognized(text.clone()),
        };
        fields.serialize_field("availability", &availability)?;
        fields.serialize_field("reason", &self.reading.reason())?;
        fields.serialize_field("coverage", &self.coverage)?;
        fields.serialize_field("source", &self.source)?;
        fields.serialize_field("sample", &self.sample)?;
        fields.end()
    }
}

/// Decodes a field that can be `null` and that must be present.
fn required_nullable<'de, D, V>(deserializer: D) -> Result<Option<V>, D::Error>
where
    D: Deserializer<'de>,
    V: Deserialize<'de>,
{
    Option::<V>::deserialize(deserializer)
}

#[derive(Deserialize)]
#[serde(bound(deserialize = "T: Deserialize<'de>"))]
struct ObservationWire<T> {
    metric_id: MetricId,
    scope: Scope,
    #[serde(deserialize_with = "required_nullable")]
    value: Option<T>,
    unit: Unit,
    kind: MetricKind,
    availability: Availability,
    #[serde(deserialize_with = "required_nullable")]
    reason: Option<UnavailableReason>,
    coverage: Coverage,
    source: Source,
    sample: Sample,
}

impl<T> TryFrom<ObservationWire<T>> for Observation<T> {
    type Error = ObservationError;

    fn try_from(wire: ObservationWire<T>) -> Result<Self, Self::Error> {
        let reading: Reading<T> = match (wire.availability, wire.value, wire.reason) {
            (Availability::Available, Some(value), None) => Reading::Available(value),
            (Availability::Available, None, _) => {
                return Err(ObservationError::AvailableWithoutValue);
            }
            (Availability::Available, Some(_), Some(_)) => {
                return Err(ObservationError::AvailableWithReason);
            }
            (Availability::Unavailable, None, Some(reason)) => Reading::Unavailable(reason),
            (Availability::Unavailable, Some(_), _) => {
                return Err(ObservationError::UnavailableWithValue);
            }
            (Availability::Unavailable, None, None) => {
                return Err(ObservationError::UnavailableWithoutReason);
            }
            (Availability::Unrecognized(text), _, _) => Reading::Unrecognized(text),
        };
        Ok(Self {
            metric_id: wire.metric_id,
            scope: wire.scope,
            reading,
            unit: wire.unit,
            kind: wire.kind,
            coverage: wire.coverage,
            source: wire.source,
            sample: wire.sample,
        })
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Observation<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire: ObservationWire<T> = ObservationWire::deserialize(deserializer)?;
        Self::try_from(wire).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::{
        Coverage, MetricId, MetricIdError, MetricKind, Observation, Reading, Sample, Scope,
        ScopeKind, Source, UnavailableReason, Unit, metric,
    };
    use crate::id::{
        AdapterId, BootId, ClockDomainId, CollectorEpochId, IdentityId, SampleId, WorkerId,
    };
    use crate::quantity::{Bytes, Nanoseconds};
    use crate::state::PressureState;
    use crate::time::MonotonicNanos;

    /// The serialized example of `docs/RESOURCE_MODEL.md` section 4.
    fn specification_example() -> Value {
        json!({
            "metric_id": "disk.available_bytes",
            "scope": { "kind": "volume", "identity_id": "vol_example" },
            "value": "8589934592",
            "unit": "byte",
            "kind": "gauge",
            "availability": "available",
            "reason": null,
            "coverage": "complete",
            "source": {
                "adapter_id": "macos.statfs",
                "adapter_revision": "1",
                "native_api": "statfs",
                "native_field": "f_bavail * f_bsize",
                "worker_id": "worker_example"
            },
            "sample": {
                "sample_id": "sample_example",
                "clock_domain": "clock_example",
                "boot_id": "boot_example",
                "collector_epoch": "collector_example",
                "started_monotonic_ns": "120000000000",
                "finished_monotonic_ns": "120003000000",
                "captured_at": "2026-11-16T12:00:00.003Z"
            }
        })
    }

    fn example_observation(reading: Reading<Bytes>) -> Observation<Bytes> {
        Observation {
            metric_id: metric::DISK_AVAILABLE_BYTES,
            scope: Scope {
                kind: ScopeKind::Volume,
                identity_id: IdentityId::new("vol_example").unwrap(),
            },
            reading,
            unit: Unit::Byte,
            kind: MetricKind::Gauge,
            coverage: Coverage::Complete,
            source: Source {
                adapter_id: AdapterId::new("macos.statfs").unwrap(),
                adapter_revision: "1".to_owned(),
                native_api: "statfs".to_owned(),
                native_field: "f_bavail * f_bsize".to_owned(),
                worker_id: WorkerId::new("worker_example").unwrap(),
            },
            sample: Sample {
                sample_id: SampleId::new("sample_example").unwrap(),
                clock_domain: ClockDomainId::new("clock_example").unwrap(),
                boot_id: BootId::new("boot_example").unwrap(),
                collector_epoch: CollectorEpochId::new("collector_example").unwrap(),
                started_monotonic_ns: MonotonicNanos::new(120_000_000_000),
                finished_monotonic_ns: MonotonicNanos::new(120_003_000_000),
                captured_at: "2026-11-16T12:00:00.003Z".parse().unwrap(),
            },
        }
    }

    fn decode(value: Value) -> Result<Observation<Bytes>, serde_json::Error> {
        serde_json::from_value(value)
    }

    #[test]
    fn the_specification_example_round_trips() {
        let observation: Observation<Bytes> = decode(specification_example()).unwrap();
        assert_eq!(
            observation,
            example_observation(Reading::Available(Bytes::new(8_589_934_592)))
        );
        assert_eq!(
            serde_json::to_value(&observation).unwrap(),
            specification_example()
        );
        assert_eq!(
            observation.sample.acquisition_duration(),
            Some(Nanoseconds::new(3_000_000))
        );
    }

    #[test]
    fn the_fields_are_written_in_the_order_of_the_specification() {
        let text: String =
            serde_json::to_string(&example_observation(Reading::Available(Bytes::ZERO))).unwrap();
        let positions: Vec<usize> = [
            "\"metric_id\"",
            "\"scope\"",
            "\"value\"",
            "\"unit\"",
            "\"availability\"",
            "\"reason\"",
            "\"coverage\"",
            "\"source\"",
            "\"sample\"",
        ]
        .iter()
        .map(|field| text.find(field).unwrap())
        .collect();
        assert!(positions.is_sorted());
    }

    #[test]
    fn an_unavailable_observation_is_not_an_available_zero() {
        let zero = example_observation(Reading::Available(Bytes::ZERO));
        let unavailable =
            example_observation(Reading::Unavailable(UnavailableReason::PermissionDenied));
        assert_ne!(zero, unavailable);

        let zero_json: Value = serde_json::to_value(&zero).unwrap();
        assert_eq!(zero_json["value"], json!("0"));
        assert_eq!(zero_json["availability"], json!("available"));
        assert_eq!(zero_json["reason"], Value::Null);
        assert_eq!(decode(zero_json).unwrap(), zero);
        assert_eq!(zero.value(), Some(&Bytes::ZERO));
        assert!(zero.is_available());

        let unavailable_json: Value = serde_json::to_value(&unavailable).unwrap();
        assert_eq!(unavailable_json["value"], Value::Null);
        assert_eq!(unavailable_json["availability"], json!("unavailable"));
        assert_eq!(unavailable_json["reason"], json!("permission_denied"));
        assert_eq!(decode(unavailable_json).unwrap(), unavailable);
        assert_eq!(unavailable.value(), None);
        assert_eq!(
            unavailable.reason(),
            Some(&UnavailableReason::PermissionDenied)
        );
        assert!(!unavailable.is_available());
    }

    #[test]
    fn decoding_rejects_a_combination_that_is_not_consistent() {
        let mut available_without_value: Value = specification_example();
        available_without_value["value"] = Value::Null;
        let mut available_with_reason: Value = specification_example();
        available_with_reason["reason"] = json!("overflow");
        let mut unavailable_with_value: Value = specification_example();
        unavailable_with_value["availability"] = json!("unavailable");
        unavailable_with_value["reason"] = json!("overflow");
        let mut unavailable_without_reason: Value = specification_example();
        unavailable_without_reason["availability"] = json!("unavailable");
        unavailable_without_reason["value"] = Value::Null;

        for (value, message) in [
            (available_without_value, "available and has no value"),
            (available_with_reason, "available and has a reason"),
            (unavailable_with_value, "unavailable and has a value"),
            (unavailable_without_reason, "unavailable and has no reason"),
        ] {
            let error: String = decode(value).unwrap_err().to_string();
            assert!(error.contains(message), "{error}");
        }
    }

    #[test]
    fn an_unknown_availability_is_not_available_and_has_no_value() {
        let mut value: Value = specification_example();
        value["availability"] = json!("stale");
        let observation: Observation<Bytes> = decode(value).unwrap();
        let Reading::Unrecognized(text) = &observation.reading else {
            panic!("the reading is recognized");
        };
        assert_eq!(text.as_str(), "stale");
        assert!(!observation.is_available());
        assert_eq!(observation.value(), None);
        assert_eq!(observation.reason(), None);

        // The value and the reason of an unknown availability are not kept.
        let encoded: Value = serde_json::to_value(&observation).unwrap();
        assert_eq!(encoded["availability"], json!("stale"));
        assert_eq!(encoded["value"], Value::Null);
        assert_eq!(encoded["reason"], Value::Null);
        assert_eq!(decode(encoded).unwrap(), observation);
    }

    #[test]
    fn decoding_needs_each_field() {
        for field in [
            "metric_id",
            "scope",
            "value",
            "unit",
            "kind",
            "availability",
            "reason",
            "coverage",
            "source",
            "sample",
        ] {
            let mut value: Value = specification_example();
            value.as_object_mut().unwrap().remove(field);
            let error: String = decode(value).unwrap_err().to_string();
            assert!(error.contains(field), "{field}: {error}");
        }
    }

    #[test]
    fn decoding_rejects_a_value_that_is_not_canonical() {
        for value in [
            json!(8_589_934_592_u64),
            json!("08"),
            json!("-1"),
            json!("18446744073709551616"),
        ] {
            let mut example: Value = specification_example();
            example["value"] = value;
            assert!(decode(example).is_err());
        }
    }

    #[test]
    fn decoding_rejects_a_sample_that_finishes_before_it_starts() {
        let mut value: Value = specification_example();
        value["sample"]["finished_monotonic_ns"] = json!("119999999999");
        let error: String = decode(value).unwrap_err().to_string();
        assert!(error.contains("finishes before it starts"), "{error}");
    }

    #[test]
    fn encoding_rejects_a_sample_that_finishes_before_it_starts() {
        let mut observation = example_observation(Reading::Available(Bytes::ZERO));
        observation.sample.finished_monotonic_ns = MonotonicNanos::new(1);
        assert_eq!(observation.sample.acquisition_duration(), None);
        let error: String = serde_json::to_string(&observation).unwrap_err().to_string();
        assert!(error.contains("finishes before it starts"), "{error}");
    }

    #[test]
    fn an_unknown_field_is_ignored() {
        let mut value: Value = specification_example();
        value["added_later"] = json!(true);
        assert!(decode(value).is_ok());
    }

    #[test]
    fn an_unknown_enumeration_value_stays_unrecognized() {
        let mut value: Value = specification_example();
        value["unit"] = json!("block");
        value["kind"] = json!("histogram");
        value["coverage"] = json!("sampled");
        value["scope"]["kind"] = json!("container_group");
        let observation: Observation<Bytes> = decode(value.clone()).unwrap();

        assert!(!observation.unit.is_recognized());
        assert_eq!(observation.unit.as_str(), "block");
        assert_ne!(observation.unit, Unit::Byte);
        assert!(!observation.kind.is_recognized());
        assert_ne!(observation.kind, MetricKind::Gauge);
        assert!(!observation.coverage.is_recognized());
        assert_ne!(observation.coverage, Coverage::Unknown);
        assert_ne!(observation.coverage, Coverage::Complete);
        assert!(!observation.scope.kind.is_recognized());
        // The value is written again as it was received.
        assert_eq!(serde_json::to_value(&observation).unwrap(), value);
    }

    #[test]
    fn an_unknown_reason_stays_unrecognized() {
        let mut value: Value = specification_example();
        value["availability"] = json!("unavailable");
        value["value"] = Value::Null;
        value["reason"] = json!("quota_exceeded");
        let observation: Observation<Bytes> = decode(value).unwrap();
        let reason: &UnavailableReason = observation.reason().unwrap();
        assert!(!reason.is_recognized());
        assert_eq!(reason.as_str(), "quota_exceeded");
        assert_eq!(
            UnavailableReason::from_wire("overflow"),
            UnavailableReason::Overflow
        );
    }

    #[test]
    fn an_unknown_state_value_is_not_normal() {
        let mut value: Value = specification_example();
        value["metric_id"] = json!("memory.pressure");
        value["scope"]["kind"] = json!("host");
        value["unit"] = json!("state");
        value["kind"] = json!("state");
        value["value"] = json!("urgent");
        let observation: Observation<PressureState> = serde_json::from_value(value).unwrap();
        let state: &PressureState = observation.value().unwrap();
        assert!(!state.is_recognized());
        assert_ne!(*state, PressureState::Normal);
        assert_eq!(observation.metric_id, metric::MEMORY_PRESSURE);
    }

    #[test]
    fn a_reading_maps_its_value_and_keeps_its_reason() {
        let doubled: Reading<u64> = Reading::Available(Bytes::new(4)).map(|bytes| bytes.get() * 2);
        assert_eq!(doubled, Reading::Available(8));
        let unavailable: Reading<u64> =
            Reading::<Bytes>::Unavailable(UnavailableReason::Unsupported).map(Bytes::get);
        assert_eq!(
            unavailable,
            Reading::Unavailable(UnavailableReason::Unsupported)
        );
    }

    #[test]
    fn each_registered_metric_name_is_valid_and_unique() {
        let mut names: Vec<&str> = Vec::new();
        for id in metric::ALL {
            assert_eq!(MetricId::new(id.as_str()).as_ref(), Ok(id));
            assert!(!names.contains(&id.as_str()), "{id}");
            names.push(id.as_str());
        }
    }

    #[test]
    fn a_metric_name_outside_the_grammar_is_rejected() {
        assert_eq!(MetricId::new(""), Err(MetricIdError::Length));
        assert_eq!(MetricId::new("a".repeat(129)), Err(MetricIdError::Length));
        for name in [
            "Disk.total",
            "disk..total",
            ".disk",
            "disk.",
            "disk total",
            "disk-total",
        ] {
            assert_eq!(MetricId::new(name), Err(MetricIdError::Malformed), "{name}");
        }
        assert!(serde_json::from_str::<MetricId>("\"disk.Total\"").is_err());
    }
}
