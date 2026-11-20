//! The capacity part of `report`: the capacity of the startup data volume
//! that the saved scan does not explain, the history of
//! `disk.available_bytes`, and the estimate of the time to a threshold.
//!
//! Each part is read-only. The part reads the host capacity and the catalog
//! store, and writes nothing. The estimate is labeled an estimate and
//! authorizes no action. `docs/RESOURCE_MODEL.md` section 7 owns the
//! entries.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde::Serialize;
use svalnir_agent::capacity::{
    CapacityEntry, CapacityHistory, CapacityReport, EstimateLimits, NoEstimateReason, SeriesPoint,
    ThresholdForecast, TimeToThreshold, capacity_history, capacity_report, forecast, series_points,
};
use svalnir_agent::observe::{self, DiskReading};
use svalnir_agent::platform::memory::CollectionContext;
use svalnir_agent::scan::ScanResult;
use svalnir_agent::store::{QueryLimit, ScanQuery, ScanSummary, Store};
use svalnir_core::config;
use svalnir_core::observation::{Observation, ObservationValue};
use svalnir_core::quantity::{Bytes, Nanoseconds};
use svalnir_core::time::WallTime;
use svalnir_core::volume::VolumeIdentity;

use crate::host::Host;
use crate::text::{
    escape, field, human_byte_delta, human_bytes, human_duration, observed, put_line,
};

/// The version of the field set of the capacity part.
pub(crate) const CAPACITY_SCHEMA_VERSION: u32 = 1;

/// The number of the newest saved scans that a report examines for a scan
/// of the startup data volume.
const SCAN_SEARCH_LIMIT: u32 = 20;

/// The width of the labels of the text form.
const LABEL_WIDTH: usize = 22;

/// Where the threshold of the estimate comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ThresholdSource {
    /// `--threshold`.
    Argument,
    /// `disk_guard.warn_below` of the configuration template.
    ConfigurationTemplate,
}

/// Why the capacity history has no value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HistoryUnavailable {
    /// The state directory has no catalog store: no agent and no saved scan
    /// wrote one.
    NoCatalogStore,
    /// The startup data volume has no identity.
    VolumeNotResolved,
    /// The catalog store gave an error.
    CatalogStoreError,
    /// The host gave no collection context, so nothing was read.
    CollectorUnavailable,
    /// The wall clock gave no start of the window.
    ClockUnavailable,
}

/// The capacity part of `report`.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct CapacityView {
    /// [`CAPACITY_SCHEMA_VERSION`].
    schema_version: u32,
    /// The logical selector of the volume.
    selector: &'static str,
    /// The four labeled entries. `null` when the volume has no capacity
    /// reading; `report_unavailable` then says why.
    report: Option<CapacityReport>,
    report_unavailable: Option<String>,
    /// The stored samples of `disk.available_bytes` in the window. `null`
    /// when there are none to read; `history_unavailable` then says why.
    history: Option<CapacityHistory>,
    history_unavailable: Option<HistoryUnavailable>,
    history_detail: Option<String>,
    /// The window of the history.
    window_ns: Nanoseconds,
    /// The estimate of the time to the threshold, labeled an estimate.
    /// `null` when the volume has no identity.
    time_to_threshold: Option<ThresholdForecast>,
    threshold_source: ThresholdSource,
}

/// The inputs of the capacity part, so that a test can give each one.
pub(crate) struct CapacityInputs<'a> {
    pub(crate) context: &'a CollectionContext,
    pub(crate) disk: &'a DiskReading,
    pub(crate) scan: Option<&'a ScanResult>,
    pub(crate) history: Result<CapacityHistory, (HistoryUnavailable, Option<String>)>,
    pub(crate) current_sleep: Option<Observation<Nanoseconds>>,
    pub(crate) window: Nanoseconds,
    pub(crate) threshold: Bytes,
    pub(crate) threshold_source: ThresholdSource,
    pub(crate) limits: EstimateLimits,
}

/// The volume of a disk reading.
fn identity_of(disk: &DiskReading) -> Option<&VolumeIdentity> {
    match disk {
        DiskReading::Measured { identity, .. }
        | DiskReading::CapacityUnavailable { identity, .. } => Some(identity),
        DiskReading::Unresolved(_) => None,
    }
}

/// Makes the capacity part from its inputs.
pub(crate) fn assemble(inputs: CapacityInputs<'_>) -> CapacityView {
    let (report, report_unavailable): (Option<CapacityReport>, Option<String>) = match inputs.disk {
        DiskReading::Measured {
            identity,
            capacity,
            foundation,
        } => match capacity_report(inputs.context, identity, capacity, foundation, inputs.scan) {
            Ok(report) => (Some(report), None),
            Err(error) => (None, Some(error.to_string())),
        },
        DiskReading::CapacityUnavailable { reason, .. } | DiskReading::Unresolved(reason) => {
            (None, Some(reason.clone()))
        }
    };
    let (history, history_unavailable, history_detail) = match inputs.history {
        Ok(history) => (Some(history), None, None),
        Err((reason, detail)) => (None, Some(reason), detail),
    };
    let time_to_threshold: Option<ThresholdForecast> = identity_of(inputs.disk).map(|_| {
        let points: Vec<SeriesPoint> = history.as_ref().map_or_else(Vec::new, |history| {
            series_points(history, inputs.current_sleep.as_ref())
        });
        forecast(&points, inputs.threshold, inputs.limits)
    });
    CapacityView {
        schema_version: CAPACITY_SCHEMA_VERSION,
        selector: "startup-data",
        report,
        report_unavailable,
        history,
        history_unavailable,
        history_detail,
        window_ns: inputs.window,
        time_to_threshold,
        threshold_source: inputs.threshold_source,
    }
}

/// The threshold and the sample interval of the configuration template.
/// This build has no effective configuration revision for a read-only
/// command, as for `scan --save`.
fn template_values() -> (Option<Bytes>, Duration) {
    let template = config::parse_and_validate("schema_version = 1\n");
    match template.config() {
        Some(config) => (
            Some(config.disk_guard().warn_below),
            config.agent().sample_interval,
        ),
        None => (None, Duration::from_secs(60)),
    }
}

/// The wall-clock time `window` before now.
fn window_start(window: Nanoseconds) -> Option<WallTime> {
    let now: WallTime = WallTime::try_from(SystemTime::now()).ok()?;
    let seconds: i64 = i64::try_from(window.get() / 1_000_000_000).ok()?;
    WallTime::from_unix(
        now.unix_seconds().checked_sub(seconds)?,
        now.subsecond_nanoseconds(),
    )
    .ok()
}

/// The newest saved scan of `volume`, from the newest saved scans.
fn newest_scan_of(store: &Store, volume: &VolumeIdentity) -> Option<ScanResult> {
    let summaries: Vec<ScanSummary> = store
        .scans(&ScanQuery::newest(QueryLimit::new(SCAN_SEARCH_LIMIT).ok()?))
        .ok()?;
    summaries.iter().find_map(|summary| {
        let record = store.scan(&summary.scan_id).ok()??;
        let result: ScanResult = serde_json::from_str(&record.result_json).ok()?;
        result
            .volume
            .identity
            .as_ref()
            .is_some_and(|scanned| scanned.volume_id == volume.volume_id)
            .then_some(result)
    })
}

/// Opens the catalog store when it exists. A report never creates it.
fn existing_catalog(path: &Path) -> Result<Store, (HistoryUnavailable, Option<String>)> {
    match std::fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => {}
        Ok(_) => return Err((HistoryUnavailable::NoCatalogStore, None)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err((HistoryUnavailable::NoCatalogStore, None));
        }
        Err(error) => {
            return Err((
                HistoryUnavailable::CatalogStoreError,
                Some(error.kind().to_string()),
            ));
        }
    }
    let (options, _) = super::scan::catalog_limits();
    Store::open(path, &options).map_err(|error| {
        (
            HistoryUnavailable::CatalogStoreError,
            Some(error.to_string()),
        )
    })
}

/// The arguments of the capacity part.
pub(crate) struct CapacityRequest {
    pub(crate) window: Duration,
    pub(crate) limit: u32,
    pub(crate) threshold: Option<Bytes>,
}

/// Reads the host and the catalog store and makes the capacity part.
///
/// `scan` is the scan that `--scan` named. Without it, the part uses the
/// newest saved scan of the startup data volume.
pub(crate) fn collect(
    request: &CapacityRequest,
    scan: Option<&ScanResult>,
    catalog: Result<PathBuf, String>,
) -> CapacityView {
    let window: Nanoseconds =
        Nanoseconds::try_from(request.window).unwrap_or(Nanoseconds::new(u64::MAX));
    let (template_threshold, sample_interval) = template_values();
    let (threshold, threshold_source): (Bytes, ThresholdSource) = match request.threshold {
        Some(threshold) => (threshold, ThresholdSource::Argument),
        None => (
            template_threshold.unwrap_or(Bytes::new(0)),
            ThresholdSource::ConfigurationTemplate,
        ),
    };
    let limits: EstimateLimits = EstimateLimits::for_sample_interval(
        Nanoseconds::try_from(sample_interval).unwrap_or(Nanoseconds::new(60_000_000_000)),
    );
    let host: Host = match Host::open() {
        Ok(host) => host,
        Err(error) => {
            return CapacityView {
                schema_version: CAPACITY_SCHEMA_VERSION,
                selector: "startup-data",
                report: None,
                report_unavailable: Some(error.message),
                history: None,
                history_unavailable: Some(HistoryUnavailable::CollectorUnavailable),
                history_detail: None,
                window_ns: window,
                time_to_threshold: None,
                threshold_source,
            };
        }
    };
    let disk: DiskReading = observe::collect_disk(host.observed());
    let store: Result<Store, (HistoryUnavailable, Option<String>)> = catalog
        .map_err(|detail| (HistoryUnavailable::CatalogStoreError, Some(detail)))
        .and_then(|path| existing_catalog(&path));
    let newest: Option<ScanResult> = match (scan, identity_of(&disk), &store) {
        (None, Some(identity), Ok(store)) => newest_scan_of(store, identity),
        _ => None,
    };
    let history: Result<CapacityHistory, (HistoryUnavailable, Option<String>)> =
        match (identity_of(&disk), &store) {
            (None, _) => Err((HistoryUnavailable::VolumeNotResolved, None)),
            (Some(_), Err(error)) => Err(error.clone()),
            (Some(identity), Ok(store)) => {
                let from: Option<WallTime> = window_start(window);
                let queried = from.map(|from| {
                    QueryLimit::new(request.limit).and_then(|limit| {
                        capacity_history(
                            store,
                            &identity.volume_id,
                            &host.context().host_scope(),
                            from,
                            None,
                            limit,
                            limits.max_gap,
                        )
                    })
                });
                match queried {
                    None => Err((HistoryUnavailable::ClockUnavailable, None)),
                    Some(result) => result.map_err(|error| {
                        (
                            HistoryUnavailable::CatalogStoreError,
                            Some(error.to_string()),
                        )
                    }),
                }
            }
        };
    assemble(CapacityInputs {
        context: host.context(),
        disk: &disk,
        scan: scan.or(newest.as_ref()),
        history,
        current_sleep: host.context().sleep_time_observation().ok(),
        window,
        threshold,
        threshold_source,
        limits,
    })
}

fn entry_text<T: ObservationValue>(
    out: &mut String,
    label: &str,
    entry: &CapacityEntry<T>,
    show: impl FnOnce(&T) -> String,
) {
    let mut value: String = observed(&entry.observation, show);
    if let Some(detail) = entry.detail {
        value.push_str(" [");
        value.push_str(&escape(detail));
        value.push(']');
    }
    field(out, label, LABEL_WIDTH, &value);
}

fn no_estimate_text(reason: NoEstimateReason) -> &'static str {
    match reason {
        NoEstimateReason::TooFewSamples => "too few stored samples",
        NoEstimateReason::AtOrBelowThreshold => {
            "the available capacity is at the threshold or below it"
        }
        NoEstimateReason::BootChanged => "the newest samples cross a restart of the host",
        NoEstimateReason::TimeNotIncreasing => "the sample times do not increase",
        NoEstimateReason::Gap => "the newest samples have a gap",
        NoEstimateReason::SleepInSeries => "the host slept between the newest samples",
        NoEstimateReason::NoSleepEvidence => {
            "no stored sleep reading shows that the host did not sleep"
        }
        NoEstimateReason::SpanTooShort => "the stored samples cover too short a time",
        NoEstimateReason::CapacityNotFalling => "the available capacity does not fall",
        NoEstimateReason::OutOfRange => "the projection is out of range",
    }
}

/// The text of the four entries.
fn render_report(out: &mut String, report: &CapacityReport) {
    field(
        out,
        "Volume",
        LABEL_WIDTH,
        &report.volume.mount_point.display_label(),
    );
    let scan_text: String = report.scan.as_ref().map_or_else(
        || "none of this volume".to_owned(),
        |scan| {
            let finished: String = scan
                .finished_at
                .map_or_else(String::new, |finished| format!(", finished {finished}"));
            format!(
                "{} of {} ({} coverage{finished})",
                scan.scan_id,
                escape(&scan.root),
                escape(scan.coverage.as_str()),
            )
        },
    );
    field(out, "Saved scan", LABEL_WIDTH, &scan_text);
    entry_text(
        out,
        "Explained by the scan",
        &report.explained_by_scan,
        |bytes| human_bytes(bytes.get()),
    );
    entry_text(
        out,
        "Not explained (est.)",
        &report.not_explained_by_scan,
        |bytes| human_bytes(bytes.get()),
    );
    entry_text(
        out,
        "Local snapshots",
        &report.local_snapshots,
        ToString::to_string,
    );
    entry_text(
        out,
        "Important - available",
        &report.important_minus_available,
        |delta| format!("{} (estimate)", human_byte_delta(delta.get())),
    );
    put_line!(
        out,
        "  The unexplained capacity includes the other volumes of the container, local snapshots, and files outside the scan root. It is not reclaimable capacity."
    );
    put_line!(out, "  {}", report.note);
}

/// The text of the estimate.
fn render_forecast(out: &mut String, forecast: &ThresholdForecast) {
    put_line!(
        out,
        "\nTime until {} available (estimate)",
        human_bytes(forecast.threshold_bytes.get())
    );
    match &forecast.result {
        TimeToThreshold::Estimate(estimate) => {
            field(
                out,
                "Estimate",
                LABEL_WIDTH,
                &format!(
                    "about {} after {}",
                    human_duration(estimate.remaining_ns),
                    estimate.newest_captured_at
                ),
            );
            field(
                out,
                "Model",
                LABEL_WIDTH,
                &format!(
                    "{}, {} samples over {}, {} per hour, residual {}",
                    forecast.model,
                    estimate.sample_count,
                    human_duration(estimate.span_ns),
                    per_hour(estimate.slope_bytes_per_second),
                    human_bytes(rounded(estimate.residual_rms_bytes)),
                ),
            );
            if let Some(reason) = estimate.series_break {
                field(
                    out,
                    "Older samples",
                    LABEL_WIDTH,
                    &format!("not used: {}", no_estimate_text(reason)),
                );
            }
        }
        TimeToThreshold::NoEstimate { reason } => {
            field(
                out,
                "Estimate",
                LABEL_WIDTH,
                &format!("none: {}", no_estimate_text(*reason)),
            );
        }
    }
    put_line!(out, "  {}", forecast.note);
}

/// The text of the history.
fn render_history(out: &mut String, history: &CapacityHistory) {
    let available: Vec<(WallTime, u64)> = history
        .samples
        .iter()
        .filter_map(|sample| {
            sample
                .value()
                .map(|value| (sample.sample.captured_at, value.get()))
        })
        .collect();
    let unavailable: usize = history.samples.len() - available.len();
    let mut counts: String = format!(
        "{} stored, {unavailable} unavailable",
        history.samples.len()
    );
    if history.limit_reached {
        counts.push_str("; the limit of ");
        counts.push_str(&history.limit.to_string());
        counts.push_str(" kept the newest");
    }
    if history.unreadable.get() > 0 {
        counts.push_str("; ");
        counts.push_str(&history.unreadable.to_string());
        counts.push_str(" not readable");
    }
    field(out, "Samples", LABEL_WIDTH, &counts);
    if let (Some((first_at, first)), Some((newest_at, newest))) =
        (available.first(), available.last())
    {
        field(
            out,
            "Oldest",
            LABEL_WIDTH,
            &format!("{} at {first_at}", human_bytes(*first)),
        );
        field(
            out,
            "Newest",
            LABEL_WIDTH,
            &format!("{} at {newest_at}", human_bytes(*newest)),
        );
        let lowest: u64 = available.iter().map(|(_, value)| *value).min().unwrap_or(0);
        let highest: u64 = available.iter().map(|(_, value)| *value).max().unwrap_or(0);
        field(
            out,
            "Range",
            LABEL_WIDTH,
            &format!("{} to {}", human_bytes(lowest), human_bytes(highest)),
        );
    }
}

impl CapacityView {
    /// The text form.
    pub(crate) fn render(&self, out: &mut String) {
        put_line!(out, "Capacity of the startup data volume");
        if let Some(report) = &self.report {
            render_report(out, report);
        } else {
            field(
                out,
                "Report",
                LABEL_WIDTH,
                &format!(
                    "unavailable ({})",
                    escape(self.report_unavailable.as_deref().unwrap_or("unknown"))
                ),
            );
        }
        put_line!(
            out,
            "\nHistory of disk.available_bytes, the last {}",
            human_duration(self.window_ns)
        );
        if let Some(history) = &self.history {
            render_history(out, history);
        } else {
            let reason: &str = match self.history_unavailable {
                Some(HistoryUnavailable::NoCatalogStore) => "no catalog store",
                Some(HistoryUnavailable::VolumeNotResolved) => "the volume has no identity",
                Some(HistoryUnavailable::CatalogStoreError) => "catalog store error",
                Some(HistoryUnavailable::CollectorUnavailable) => "the host gave no collector",
                Some(HistoryUnavailable::ClockUnavailable) => "the wall clock gave no time",
                None => "not read",
            };
            let detail: String = self
                .history_detail
                .as_deref()
                .map_or_else(String::new, |detail| format!(": {}", escape(detail)));
            field(
                out,
                "Samples",
                LABEL_WIDTH,
                &format!("unavailable ({reason}{detail})"),
            );
        }
        if let Some(forecast) = &self.time_to_threshold {
            render_forecast(out, forecast);
        }
    }
}

/// A finite nonnegative number of bytes, rounded to an integer.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "the value is display text; it is clamped to the range of u64 first"
)]
fn rounded(bytes: f64) -> u64 {
    if bytes.is_finite() && bytes > 0.0 {
        bytes.min(1.8e19).round() as u64
    } else {
        0
    }
}

/// The text of a signed rate in bytes per second, as a change per hour.
fn per_hour(bytes_per_second: f64) -> String {
    let magnitude: u64 = rounded((bytes_per_second * 3600.0).abs());
    let sign: &str = if bytes_per_second < 0.0 { "-" } else { "+" };
    format!("{sign}{}", human_bytes(magnitude))
}

#[cfg(test)]
pub(crate) mod tests {
    use svalnir_agent::capacity::{CapacityHistory, EstimateLimits};
    use svalnir_agent::observe::DiskReading;
    use svalnir_agent::platform::memory::CollectionContext;
    use svalnir_core::observation::{Observation, metric};
    use svalnir_core::quantity::{Bytes, EntryCount, Nanoseconds};
    use svalnir_core::time::WallTime;

    use super::{CapacityInputs, CapacityView, HistoryUnavailable, ThresholdSource, assemble};
    use crate::test_support::{available_sample, collection_context, scan_result, volume_capacity};

    const GIB: u64 = 1 << 30;
    const MINUTE: u64 = 60_000_000_000;

    fn measured() -> DiskReading {
        let (identity, capacity, foundation) = volume_capacity();
        DiskReading::Measured {
            identity,
            capacity,
            foundation,
        }
    }

    /// Twenty samples one minute apart that fall by 1 GiB a minute, with a
    /// sleep reading of zero before each one.
    fn history(context: &CollectionContext) -> CapacityHistory {
        let samples: Vec<Observation<Bytes>> = (0..20)
            .map(|minute| available_sample(minute, (120 - minute) * GIB))
            .collect();
        let sleep: Vec<Observation<Nanoseconds>> = samples
            .iter()
            .map(|sample| {
                let mut reading = context.sleep_time_observation().unwrap();
                reading.sample = sample.sample.clone();
                reading.sample.finished_monotonic_ns = sample.sample.started_monotonic_ns;
                reading
            })
            .collect();
        CapacityHistory {
            metric_id: metric::DISK_AVAILABLE_BYTES,
            scope: samples[0].scope.clone(),
            from: WallTime::UNIX_EPOCH,
            until: None,
            limit: 2_000,
            limit_reached: false,
            samples,
            unreadable: EntryCount::new(0),
            sleep,
        }
    }

    fn inputs<'a>(
        context: &'a CollectionContext,
        disk: &'a DiskReading,
        history: Result<CapacityHistory, (HistoryUnavailable, Option<String>)>,
    ) -> CapacityInputs<'a> {
        let mut current = context.sleep_time_observation().unwrap();
        current.sample.started_monotonic_ns = svalnir_core::time::MonotonicNanos::new(u64::MAX / 2);
        current.sample.finished_monotonic_ns = current.sample.started_monotonic_ns;
        CapacityInputs {
            context,
            disk,
            scan: None,
            history,
            current_sleep: Some(current),
            window: Nanoseconds::new(24 * 60 * MINUTE),
            threshold: Bytes::new(20 * GIB),
            threshold_source: ThresholdSource::ConfigurationTemplate,
            limits: EstimateLimits::for_sample_interval(Nanoseconds::new(MINUTE)),
        }
    }

    /// A capacity part with each entry, a history, and an estimate.
    pub(crate) fn view() -> CapacityView {
        let context: CollectionContext = collection_context();
        let disk: DiskReading = measured();
        let history = history(&context);
        assemble(inputs(&context, &disk, Ok(history)))
    }

    #[test]
    fn the_structured_output_has_a_versioned_field_set() {
        let value = serde_json::to_value(view()).unwrap();
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["selector"], "startup-data");
        assert_eq!(value["window_ns"], "86400000000000");
        assert_eq!(value["threshold_source"], "configuration_template");
        let report = &value["report"];
        for (entry, id) in [
            ("explained_by_scan", "disk.scan_explained_bytes"),
            ("not_explained_by_scan", "disk.scan_unexplained_bytes"),
            ("local_snapshots", "disk.local_snapshot_count"),
            (
                "important_minus_available",
                "disk.important_minus_available_bytes",
            ),
        ] {
            assert_eq!(report[entry]["observation"]["metric_id"], id, "{entry}");
        }
        // 130 GiB important minus 100 GiB available.
        assert_eq!(
            report["important_minus_available"]["observation"]["value"],
            (30 * GIB).to_string()
        );
        assert_eq!(
            report["explained_by_scan"]["observation"]["reason"],
            "not_collected"
        );
        assert_eq!(
            report["local_snapshots"]["observation"]["reason"],
            "unsupported"
        );
        assert_eq!(value["history"]["metric_id"], "disk.available_bytes");
        assert_eq!(value["history"]["samples"].as_array().unwrap().len(), 20);
        assert!(value["history"].get("sleep").is_none());
        let estimate = &value["time_to_threshold"];
        assert_eq!(estimate["kind"], "estimate");
        assert_eq!(estimate["authorizes_action"], false);
        assert_eq!(estimate["result"]["outcome"], "estimate", "{estimate}");
        assert!(estimate["result"]["remaining_ns"].is_string());
    }

    #[test]
    fn the_text_names_each_entry_and_labels_the_estimate() {
        let mut text = String::new();
        view().render(&mut text);
        for expected in [
            "Explained by the scan",
            "unavailable (not_collected) [no_saved_scan_of_the_volume]",
            "unavailable (unsupported) [snapshot_list_needs_superuser_and_entitlement]",
            "+30.0 GiB (estimate)",
            "20 stored, 0 unavailable",
            "Time until 20.0 GiB available (estimate)",
            "about ",
            "least_squares_linear, 20 samples",
            "It authorizes no action",
        ] {
            assert!(text.contains(expected), "{expected}: {text}");
        }
        assert!(!text.contains('\u{1b}'));
    }

    #[test]
    fn an_unresolved_volume_has_no_entries_no_history_and_no_estimate() {
        let context: CollectionContext = collection_context();
        let disk = DiskReading::Unresolved("the mount table is not readable".to_owned());
        let view = assemble(inputs(
            &context,
            &disk,
            Err((HistoryUnavailable::VolumeNotResolved, None)),
        ));
        let value = serde_json::to_value(&view).unwrap();
        assert!(value["report"].is_null());
        assert_eq!(
            value["report_unavailable"],
            "the mount table is not readable"
        );
        assert!(value["history"].is_null());
        assert_eq!(value["history_unavailable"], "volume_not_resolved");
        assert!(value["time_to_threshold"].is_null());
        let mut text = String::new();
        view.render(&mut text);
        assert!(
            text.contains("unavailable (the mount table is not readable)"),
            "{text}"
        );
        assert!(
            text.contains("unavailable (the volume has no identity)"),
            "{text}"
        );
    }

    #[test]
    fn no_catalog_store_gives_no_history_and_no_estimate_from_too_few_samples() {
        let context: CollectionContext = collection_context();
        let disk = measured();
        let view = assemble(inputs(
            &context,
            &disk,
            Err((HistoryUnavailable::NoCatalogStore, None)),
        ));
        let value = serde_json::to_value(&view).unwrap();
        assert!(value["history"].is_null());
        assert_eq!(value["history_unavailable"], "no_catalog_store");
        assert_eq!(
            value["time_to_threshold"]["result"]["outcome"],
            "no_estimate"
        );
        assert_eq!(
            value["time_to_threshold"]["result"]["reason"],
            "too_few_samples"
        );
        assert!(value["report"]["explained_by_scan"].is_object());
    }

    #[test]
    fn a_scan_of_the_volume_explains_a_part_of_the_used_capacity() {
        let context: CollectionContext = collection_context();
        let disk = measured();
        let (identity, _, _) = volume_capacity();
        let mut scan = scan_result(false);
        scan.volume.identity = Some(identity);
        let mut inputs = inputs(
            &context,
            &disk,
            Err((HistoryUnavailable::NoCatalogStore, None)),
        );
        inputs.scan = Some(&scan);
        let value = serde_json::to_value(assemble(inputs)).unwrap();
        let report = &value["report"];
        assert_eq!(report["scan"]["scan_id"], "scan_test");
        // 4 MiB allocated; 390 GiB used (500 GiB total minus 110 GiB free).
        assert_eq!(
            report["explained_by_scan"]["observation"]["value"],
            (4u64 << 20).to_string()
        );
        assert_eq!(
            report["not_explained_by_scan"]["observation"]["value"],
            (390 * GIB - (4 << 20)).to_string()
        );
    }
}
