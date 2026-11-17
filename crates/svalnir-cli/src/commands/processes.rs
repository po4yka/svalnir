//! `processes top` and `processes show`.
//!
//! The commands read the process inventory of the current user in this
//! process. They send no signal. The output never has process arguments or
//! environment variables: a process label is the last component of the
//! executable path.
//!
//! # Target ID
//!
//! A target ID is the text of a process generation identity,
//! `pg-<pid>-<start time in microseconds>`. It names one generation of a
//! process, not a PID. No server holds identity evidence,
//! so each invocation resolves the ID against a new snapshot: the ID resolves
//! while that generation runs and gives `target_not_found` after it exits.
//! A target ID is never permission to act on the process.

use serde::Serialize;
use svalnir_agent::platform::process::{
    DerivedMetrics, ForegroundState, Omissions, ProcessRecord, ProcessSnapshot, RankMetric,
    RankValue, Ranking, rank_processes,
};
use svalnir_core::id::{ApplicationInstanceId, ProcessGenerationId};
use svalnir_core::observation::{Observation, Reading};
use svalnir_core::process::{Pid, ProcessAssociation, ProcessIdentity, Uid, VerifiedMembership};
use svalnir_core::quantity::{Bytes, CounterValue, Nanoseconds};
use svalnir_core::time::WallTime;

use super::{CommandFailure, Invocation};
use crate::cli::{ProcessSort, ProcessesTopArgs, TargetRef};
use crate::host::ScopeCoverage;
use crate::output::{ErrorBody, ErrorFamily, ErrorStage, ExitStatus, Kind, NextAction};
use crate::text::{
    escape, field, human_byte_delta, human_bytes, human_duration, observed, observed_bytes,
    put_line, table, unavailable,
};

/// The number of entries of `processes top` when `--limit` is not given.
pub(crate) const DEFAULT_TOP_LIMIT: usize = 20;

/// The time between the two snapshots that `--sort growth` and `--sort cpu`
/// compare.
#[cfg(target_os = "macos")]
const DERIVED_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// The statement about target IDs in each result.
const TARGET_NOTE: &str = "A target ID names one process generation (PID and start time). No server holds identity evidence, so each invocation resolves the ID against a new snapshot. A target ID is not permission to act on the process.";

/// The statement about policy eligibility in `processes show`.
const ELIGIBILITY_NOTE: &str =
    "Policy eligibility needs the grants of the background agent. This build does not evaluate it.";

/// The value that orders a ranking, or the reason there is none.
#[derive(Debug, Clone, Serialize)]
struct RankValueView {
    /// The quantity of the value.
    quantity: &'static str,
    /// Bytes as a base-10 string, or a percentage as a number.
    value: Option<serde_json::Value>,
    unit: &'static str,
    availability: &'static str,
    reason: Option<String>,
    /// The CPU time in the interval, for a CPU value.
    cpu_delta_ns: Option<Nanoseconds>,
    /// The length of the interval, for a CPU value.
    elapsed_ns: Option<Nanoseconds>,
    /// The text form of the value. Not serialized.
    #[serde(skip)]
    text: String,
}

impl RankValueView {
    fn new(metric: RankMetric, value: &Reading<RankValue>) -> Self {
        let (quantity, unit): (&'static str, &'static str) = match metric {
            RankMetric::Footprint => ("process.footprint_bytes", "byte"),
            RankMetric::Resident => ("process.resident_bytes", "byte"),
            RankMetric::FootprintGrowth => ("footprint_growth_bytes", "byte"),
            RankMetric::Cpu => ("process.cpu_core_equivalent_percent", "percent"),
        };
        let mut view = Self {
            quantity,
            value: None,
            unit,
            availability: "unavailable",
            reason: None,
            cpu_delta_ns: None,
            elapsed_ns: None,
            text: unavailable(value),
        };
        match value {
            Reading::Available(RankValue::Bytes(bytes)) => {
                view.value = Some(serde_json::Value::String(bytes.to_string()));
                view.text = human_bytes(bytes.get());
            }
            Reading::Available(RankValue::Growth(delta)) => {
                view.value = Some(serde_json::Value::String(delta.to_string()));
                view.text = human_byte_delta(delta.get());
            }
            Reading::Available(RankValue::Cpu(usage)) => {
                let percent: f64 = usage.core_equivalent_percent();
                if let Some(number) = serde_json::Number::from_f64(percent) {
                    view.value = Some(serde_json::Value::Number(number));
                    view.cpu_delta_ns = Some(usage.cpu_delta);
                    view.elapsed_ns = Some(usage.elapsed);
                    view.text = format!("{percent:.1} %");
                } else {
                    view.reason = Some("inconsistent_data".to_owned());
                    "unavailable (inconsistent_data)".clone_into(&mut view.text);
                }
            }
            Reading::Unavailable(reason) => view.reason = Some(reason.as_str().to_owned()),
            Reading::Unrecognized(_) => view.reason = Some("unrecognized".to_owned()),
        }
        if view.value.is_some() {
            view.availability = "available";
        }
        view
    }
}

fn foreground_text(state: ForegroundState) -> &'static str {
    match state {
        ForegroundState::Foreground => "foreground",
        ForegroundState::Background => "background",
        ForegroundState::Unknown => "unknown",
    }
}

/// The application or job of a process, for the text form.
fn association_text(association: &ProcessAssociation) -> String {
    match association.verified_membership() {
        Some(VerifiedMembership::Application {
            bundle_identifier, ..
        }) => escape(bundle_identifier),
        Some(VerifiedMembership::ManagedJob { label, .. }) => format!("job {}", escape(label)),
        None => "-".to_owned(),
    }
}

/// One entry of `processes top`.
#[derive(Debug, Clone, Serialize)]
struct TopEntry {
    position: usize,
    /// The identity to give to `processes show --target`.
    target_id: ProcessGenerationId,
    pid: Pid,
    /// The last component of the executable path. Presentation data only.
    label: Option<String>,
    association: ProcessAssociation,
    foreground: &'static str,
    rank_value: RankValueView,
    footprint: Observation<Bytes>,
    resident: Observation<Bytes>,
}

/// The processes that the collection found and did not record.
#[derive(Debug, Clone, Serialize)]
struct OmissionsView {
    other_user: usize,
    permission_denied: usize,
    exited: usize,
    identity_changed: usize,
    failed: usize,
}

impl OmissionsView {
    fn new(omissions: Omissions, coverage: &mut ScopeCoverage) -> Self {
        // A process whose identity query failed can be a process of the
        // current user. A process of a different user is out of scope, and a
        // process that exited is not a part of the inventory.
        if omissions.failed > 0 {
            coverage.missing("process inventory (identity query failed)");
        }
        Self {
            other_user: omissions.other_user,
            permission_denied: omissions.permission_denied,
            exited: omissions.exited,
            identity_changed: omissions.identity_changed,
            failed: omissions.failed,
        }
    }

    fn text_line(&self) -> String {
        format!(
            "Not recorded: {} of another user, {} denied, {} exited, {} replaced, {} failed.\n",
            self.other_user,
            self.permission_denied,
            self.exited,
            self.identity_changed,
            self.failed
        )
    }
}

/// The result of `processes top`.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct TopView {
    sort: &'static str,
    limit: usize,
    captured_at: WallTime,
    /// The time between the two snapshots of a derived metric.
    derived_interval_ns: Option<Nanoseconds>,
    target_id_note: &'static str,
    entries: Vec<TopEntry>,
    /// Processes with a value that the limit removed.
    omitted_available: usize,
    /// Processes with no value that the limit removed.
    omitted_unavailable: usize,
    recorded_processes: usize,
    omissions: OmissionsView,
    /// The reason no process has an application attribution.
    launch_services_unavailable: Option<String>,
    /// The reason some processes have no `responsible_process` attribution.
    responsible_process_unavailable: Option<String>,
    coverage: ScopeCoverage,
}

const fn rank_metric(sort: ProcessSort) -> (RankMetric, &'static str) {
    match sort {
        ProcessSort::Footprint => (RankMetric::Footprint, "footprint"),
        ProcessSort::Rss => (RankMetric::Resident, "rss"),
        ProcessSort::Growth => (RankMetric::FootprintGrowth, "growth"),
        ProcessSort::Cpu => (RankMetric::Cpu, "cpu"),
    }
}

impl TopView {
    pub(crate) fn new(
        snapshot: &ProcessSnapshot,
        derived: Option<&DerivedMetrics>,
        derived_interval: Option<Nanoseconds>,
        sort: ProcessSort,
        limit: usize,
    ) -> Self {
        let (metric, sort_name): (RankMetric, &'static str) = rank_metric(sort);
        let ranking: Ranking<'_> = rank_processes(&snapshot.records, metric, derived, Some(limit));
        let mut coverage = ScopeCoverage::new();
        let omissions = OmissionsView::new(snapshot.omissions, &mut coverage);
        Self {
            sort: sort_name,
            limit,
            captured_at: snapshot.captured_at,
            derived_interval_ns: derived_interval,
            target_id_note: TARGET_NOTE,
            entries: ranking
                .entries
                .iter()
                .map(|entry| TopEntry {
                    position: entry.position,
                    target_id: entry.record.identity.generation_id.clone(),
                    pid: entry.record.identity.pid,
                    label: entry.record.display_label(),
                    association: entry.record.identity.association.clone(),
                    foreground: foreground_text(entry.record.foreground),
                    rank_value: RankValueView::new(metric, &entry.value),
                    footprint: entry.record.metrics.footprint.clone(),
                    resident: entry.record.metrics.resident.clone(),
                })
                .collect(),
            omitted_available: ranking.omitted_available,
            omitted_unavailable: ranking.omitted_unavailable,
            recorded_processes: snapshot.records.len(),
            omissions,
            launch_services_unavailable: snapshot
                .launch_services_unavailable
                .as_ref()
                .map(|reason| reason.as_str().to_owned()),
            responsible_process_unavailable: snapshot
                .responsible_process_unavailable
                .as_ref()
                .map(|reason| reason.as_str().to_owned()),
            coverage,
        }
    }

    pub(crate) fn render(&self) -> String {
        let mut out = String::new();
        put_line!(
            out,
            "Processes of the current user by {}, at {} ({} recorded)",
            self.sort,
            self.captured_at,
            self.recorded_processes
        );
        if let Some(interval) = self.derived_interval_ns {
            put_line!(
                out,
                "The value is the change between two snapshots, {} apart.",
                human_duration(interval)
            );
        }
        out.push('\n');
        let rows: Vec<Vec<String>> = self
            .entries
            .iter()
            .map(|entry| {
                vec![
                    entry.position.to_string(),
                    entry.rank_value.text.clone(),
                    observed_bytes(&entry.footprint),
                    observed_bytes(&entry.resident),
                    entry.pid.get().to_string(),
                    entry
                        .label
                        .as_deref()
                        .map_or_else(|| "-".to_owned(), escape),
                    association_text(&entry.association),
                    entry.target_id.as_str().to_owned(),
                ]
            })
            .collect();
        out.push_str(&table(
            &[
                "#",
                "VALUE",
                "FOOTPRINT",
                "RSS",
                "PID",
                "NAME",
                "APPLICATION",
                "TARGET ID",
            ],
            &[true, true, true, true, true, false, false, false],
            &rows,
        ));
        out.push('\n');
        put_line!(
            out,
            "Not shown because of the limit of {}: {} with a value, {} with no value.",
            self.limit,
            self.omitted_available,
            self.omitted_unavailable
        );
        out.push_str(&self.omissions.text_line());
        if let Some(reason) = &self.launch_services_unavailable {
            put_line!(
                out,
                "Application attribution is unavailable ({}).",
                escape(reason)
            );
        }
        if let Some(reason) = &self.responsible_process_unavailable {
            put_line!(
                out,
                "The responsible-process attribution is unavailable for some processes ({}).",
                escape(reason)
            );
        }
        put_line!(out, "{TARGET_NOTE}");
        out.push_str(&self.coverage.text_line());
        out
    }
}

/// The measurements of one process.
#[derive(Debug, Clone, Serialize)]
struct MetricsView {
    footprint: Observation<Bytes>,
    resident: Observation<Bytes>,
    peak_footprint: Observation<Bytes>,
    cpu_time: Observation<CounterValue>,
    disk_read: Observation<CounterValue>,
    disk_written: Observation<CounterValue>,
}

/// The application instance of a process and the sum of its members.
#[derive(Debug, Clone, Serialize)]
struct ApplicationView {
    instance_id: ApplicationInstanceId,
    /// The processes with a verified membership in the instance.
    member_count: usize,
    /// The checked sum of the member footprints that have a value. `null`
    /// when the sum overflows.
    measured_footprint_bytes: Option<Bytes>,
    /// The members whose footprint has no value. The sum does not include
    /// them, so it is a lower bound when this number is not zero.
    members_without_footprint: usize,
}

impl ApplicationView {
    fn new(snapshot: &ProcessSnapshot, instance_id: &ApplicationInstanceId) -> Self {
        let members: Vec<&ProcessRecord> = snapshot.members_of(instance_id);
        let mut sum: Option<Bytes> = Some(Bytes::ZERO);
        let mut without: usize = 0;
        for member in &members {
            match member.metrics.footprint.value() {
                Some(bytes) => sum = sum.and_then(|total| total.checked_add(*bytes)),
                None => without += 1,
            }
        }
        Self {
            instance_id: instance_id.clone(),
            member_count: members.len(),
            measured_footprint_bytes: sum,
            members_without_footprint: without,
        }
    }
}

/// The policy eligibility of a target. This build does not evaluate it.
#[derive(Debug, Clone, Serialize)]
struct EligibilityView {
    evaluated: bool,
    note: &'static str,
}

/// The result of `processes show`.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct ShowView {
    target_id: ProcessGenerationId,
    target_id_note: &'static str,
    captured_at: WallTime,
    identity: ProcessIdentity,
    real_uid: Uid,
    parent_pid: Option<Pid>,
    /// The reason there is no executable path.
    executable_unavailable: Option<String>,
    foreground: &'static str,
    metrics: MetricsView,
    application: Option<ApplicationView>,
    policy_eligibility: EligibilityView,
}

impl ShowView {
    pub(crate) fn new(snapshot: &ProcessSnapshot, record: &ProcessRecord) -> Self {
        let application: Option<ApplicationView> =
            match record.identity.association.verified_membership() {
                Some(
                    VerifiedMembership::Application { instance_id, .. }
                    | VerifiedMembership::ManagedJob { instance_id, .. },
                ) => Some(ApplicationView::new(snapshot, instance_id)),
                None => None,
            };
        Self {
            target_id: record.identity.generation_id.clone(),
            target_id_note: TARGET_NOTE,
            captured_at: snapshot.captured_at,
            identity: record.identity.clone(),
            real_uid: record.real_uid,
            parent_pid: record.parent_pid,
            executable_unavailable: record
                .executable_unavailable
                .as_ref()
                .map(|reason| reason.as_str().to_owned()),
            foreground: foreground_text(record.foreground),
            metrics: MetricsView {
                footprint: record.metrics.footprint.clone(),
                resident: record.metrics.resident.clone(),
                peak_footprint: record.metrics.peak_footprint.clone(),
                cpu_time: record.metrics.cpu_time.clone(),
                disk_read: record.metrics.disk_read.clone(),
                disk_written: record.metrics.disk_written.clone(),
            },
            application,
            policy_eligibility: EligibilityView {
                evaluated: false,
                note: ELIGIBILITY_NOTE,
            },
        }
    }

    pub(crate) fn render(&self) -> String {
        let mut out = String::new();
        put_line!(out, "Target {}, at {}", self.target_id, self.captured_at);
        self.render_identity(&mut out);
        self.render_measurements(&mut out);
        if let Some(application) = &self.application {
            out.push_str("Application instance\n");
            field(&mut out, "Instance", 14, application.instance_id.as_str());
            field(
                &mut out,
                "Members",
                14,
                &application.member_count.to_string(),
            );
            let sum: String = application.measured_footprint_bytes.map_or_else(
                || "unavailable (overflow)".to_owned(),
                |bytes| human_bytes(bytes.get()),
            );
            let qualifier: String = if application.members_without_footprint == 0 {
                String::new()
            } else {
                format!(
                    " (a lower bound: {} members have no value)",
                    application.members_without_footprint
                )
            };
            field(&mut out, "Footprint sum", 14, &format!("{sum}{qualifier}"));
        }
        put_line!(out, "Policy eligibility: not evaluated. {ELIGIBILITY_NOTE}");
        put_line!(out, "{TARGET_NOTE}");
        out
    }

    fn render_identity(&self, out: &mut String) {
        let identity: &ProcessIdentity = &self.identity;
        out.push_str("Identity\n");
        field(out, "PID", 14, &identity.pid.get().to_string());
        field(
            out,
            "Start time",
            14,
            &format!(
                "{} (microseconds since the Unix epoch)",
                identity.start_time
            ),
        );
        field(
            out,
            "User",
            14,
            &format!(
                "effective {}, real {}",
                identity.uid.get(),
                self.real_uid.get()
            ),
        );
        field(
            out,
            "Parent PID",
            14,
            &self
                .parent_pid
                .map_or_else(|| "unknown".to_owned(), |pid| pid.get().to_string()),
        );
        let executable: String = match (&identity.executable, &self.executable_unavailable) {
            (Some(executable), _) => executable.path.display_label(),
            (None, Some(reason)) => format!("unavailable ({})", escape(reason)),
            (None, None) => "unavailable".to_owned(),
        };
        field(out, "Executable", 14, &executable);
        field(
            out,
            "Application",
            14,
            &association_text(&identity.association),
        );
        field(out, "Foreground", 14, self.foreground);
    }

    fn render_measurements(&self, out: &mut String) {
        out.push_str("Measurements\n");
        let metrics: &MetricsView = &self.metrics;
        field(out, "Footprint", 14, &observed_bytes(&metrics.footprint));
        field(out, "Resident", 14, &observed_bytes(&metrics.resident));
        field(
            out,
            "Peak footprint",
            14,
            &observed_bytes(&metrics.peak_footprint),
        );
        field(
            out,
            "CPU time",
            14,
            &observed(&metrics.cpu_time, |time| {
                human_duration(Nanoseconds::new(time.get()))
            }),
        );
        field(
            out,
            "Disk read",
            14,
            &observed(&metrics.disk_read, |bytes| human_bytes(bytes.get())),
        );
        field(
            out,
            "Disk written",
            14,
            &observed(&metrics.disk_written, |bytes| human_bytes(bytes.get())),
        );
        out.push_str(
            "  Footprint and resident size are different quantities. A large footprint alone is not a reason to stop a process.\n",
        );
    }
}

/// Parses the `--target` value.
pub(crate) fn parse_target(text: &str) -> Result<ProcessGenerationId, ErrorBody> {
    let invalid = || ErrorBody {
        code: "invalid_target".into(),
        family: ErrorFamily::Request,
        stage: ErrorStage::Arguments,
        message: "the target ID is not valid; use a `TARGET ID` value of `svalnir processes top`"
            .to_owned(),
        fields: &["target"],
        operation_id: None,
        plan_id: None,
        next_action: NextAction::CorrectRequest,
    };
    let id: ProcessGenerationId = ProcessGenerationId::new(text).map_err(|_| invalid())?;
    // The shape is `pg-<pid>-<start time>`, both decimal.
    let is_shaped: bool = id.as_str().strip_prefix("pg-").is_some_and(|rest| {
        rest.split_once('-').is_some_and(|(pid, start)| {
            [pid, start]
                .iter()
                .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
        })
    });
    if !is_shaped {
        return Err(invalid());
    }
    Ok(id)
}

/// Finds the target in a snapshot.
pub(crate) fn find_target<'a>(
    snapshot: &'a ProcessSnapshot,
    target: &str,
) -> Result<&'a ProcessRecord, ErrorBody> {
    let id: ProcessGenerationId = parse_target(target)?;
    snapshot.find_generation(&id).ok_or_else(|| ErrorBody {
        code: "target_not_found".into(),
        family: ErrorFamily::Evidence,
        stage: ErrorStage::Collection,
        message: "the target is not in the snapshot of this invocation: the process exited, is of another user, or the ID is of another boot; the command made no change".to_owned(),
        fields: &["target"],
        operation_id: None,
        plan_id: None,
        next_action: NextAction::RefreshObservation,
    })
}

/// Reads the process inventory. With `derived`, reads it two times and
/// derives the growth and the CPU use between the two snapshots.
#[cfg(target_os = "macos")]
fn collect(
    derived: bool,
) -> Result<(ProcessSnapshot, Option<DerivedMetrics>, Option<Nanoseconds>), ErrorBody> {
    use svalnir_agent::platform::process::derive_between;

    use crate::host::{Host, collector_unavailable};

    let host: Host = Host::open()?;
    let collector = host.process_collector()?;
    let read = || {
        collector
            .collect()
            .map_err(|error| collector_unavailable(&error.to_string()))
    };
    let first: ProcessSnapshot = read()?;
    if !derived {
        return Ok((first, None, None));
    }
    std::thread::sleep(DERIVED_INTERVAL);
    let later: ProcessSnapshot = read()?;
    let metrics: DerivedMetrics = derive_between(&first, &later);
    let interval: Option<Nanoseconds> = later
        .started_monotonic_ns
        .checked_duration_since(first.started_monotonic_ns);
    Ok((later, Some(metrics), interval))
}

#[cfg(not(target_os = "macos"))]
fn collect(
    _derived: bool,
) -> Result<(ProcessSnapshot, Option<DerivedMetrics>, Option<Nanoseconds>), ErrorBody> {
    Err(crate::host::unsupported_platform("processes"))
}

/// Reads the process inventory one time, for a stop request.
pub(crate) fn collect_snapshot() -> Result<ProcessSnapshot, ErrorBody> {
    collect(false).map(|(snapshot, _, _)| snapshot)
}

pub(crate) fn top(
    arguments: &ProcessesTopArgs,
    invocation: &mut Invocation<'_>,
) -> Result<ExitStatus, CommandFailure> {
    let derived: bool = matches!(arguments.sort, ProcessSort::Growth | ProcessSort::Cpu);
    let (snapshot, metrics, interval) = collect(derived)?;
    let limit: usize = arguments.limit.map_or(DEFAULT_TOP_LIMIT, |limit| {
        usize::try_from(limit).unwrap_or(usize::MAX)
    });
    let view = TopView::new(&snapshot, metrics.as_ref(), interval, arguments.sort, limit);
    invocation.emit(Kind::Snapshot, &view, TopView::render)?;
    Ok(super::resources::snapshot_status(&view.coverage))
}

pub(crate) fn show(
    arguments: &TargetRef,
    invocation: &mut Invocation<'_>,
) -> Result<ExitStatus, CommandFailure> {
    // The target text is checked before the inventory is read.
    parse_target(&arguments.target)?;
    let (snapshot, _, _) = collect(false)?;
    let record: &ProcessRecord = find_target(&snapshot, &arguments.target)?;
    let view = ShowView::new(&snapshot, record);
    invocation.emit(Kind::Snapshot, &view, ShowView::render)?;
    Ok(ExitStatus::Success)
}

#[cfg(test)]
mod target_shape_tests {
    use super::parse_target;

    #[test]
    fn a_target_has_the_shape_pg_digits_digits() {
        assert!(parse_target("pg-123-456789").is_ok());
        for text in [
            "pg-",
            "pg-abc.def",
            "pg-1",
            "pg-1-",
            "pg--2",
            "pg-1-2-3",
            "pg-a-b",
            "xx-1-2",
        ] {
            let error = parse_target(text).unwrap_err();
            assert_eq!(&*error.code, "invalid_target", "{text}");
        }
    }
}

#[cfg(test)]
mod tests {
    use svalnir_core::observation::{Reading, UnavailableReason};

    use super::{ShowView, TopView, find_target};
    use crate::cli::ProcessSort;
    use crate::output::{ErrorFamily, ExitStatus};
    use crate::test_support::process_snapshot;

    #[test]
    fn top_orders_by_footprint_and_keeps_an_unavailable_value_last() {
        let snapshot = process_snapshot();
        let view = TopView::new(&snapshot, None, None, ProcessSort::Footprint, 10);
        let text = view.render();
        let rows: Vec<&str> = text.lines().filter(|line| line.contains("pg-")).collect();
        assert_eq!(rows.len(), 3, "{text}");
        assert!(
            rows[0].contains("editor") && rows[0].contains("3.0 GiB"),
            "{text}"
        );
        assert!(rows[0].contains("com.example.editor"), "{text}");
        assert!(
            rows[1].contains("helper") && rows[1].contains("1.0 GiB"),
            "{text}"
        );
        assert!(
            rows[2].contains("unavailable (permission_denied)"),
            "{text}"
        );
        assert!(!rows[2].contains(" 0 B"), "{text}");
        assert!(text.contains("is not permission to act"), "{text}");
        assert!(text.contains(
            "Not recorded: 40 of another user, 2 denied, 1 exited, 0 replaced, 0 failed."
        ));
        assert_eq!(view.coverage.required_scope, "complete");
    }

    #[test]
    fn top_json_has_target_ids_and_canonical_observations() {
        let snapshot = process_snapshot();
        let view = TopView::new(&snapshot, None, None, ProcessSort::Rss, 2);
        let json = serde_json::to_value(&view).unwrap();
        assert_eq!(json["sort"], "rss");
        assert_eq!(json["entries"].as_array().unwrap().len(), 2);
        assert_eq!(json["entries"][0]["target_id"], "pg-200-1700000000000000");
        assert_eq!(json["entries"][0]["pid"], 200);
        assert_eq!(
            json["entries"][0]["rank_value"]["quantity"],
            "process.resident_bytes"
        );
        assert_eq!(json["entries"][0]["rank_value"]["value"], "2147483648");
        assert_eq!(
            json["entries"][0]["footprint"]["metric_id"],
            "process.footprint_bytes"
        );
        assert_eq!(json["entries"][0]["association"]["kind"], "application");
        assert_eq!(json["omitted_available"], 0);
        assert_eq!(json["omitted_unavailable"], 1);
        assert_eq!(json["omissions"]["other_user"], 40);
        // No arguments and no environment are in the output.
        let text = json.to_string();
        assert!(!text.contains("argv") && !text.contains("environment"));
    }

    #[test]
    fn a_derived_sort_without_two_samples_says_not_initialized() {
        let snapshot = process_snapshot();
        let view = TopView::new(&snapshot, None, None, ProcessSort::Cpu, 10);
        let json = serde_json::to_value(&view).unwrap();
        assert_eq!(
            json["entries"][0]["rank_value"]["availability"],
            "unavailable"
        );
        assert_eq!(
            json["entries"][0]["rank_value"]["reason"],
            "not_initialized"
        );
        assert_eq!(
            json["entries"][0]["rank_value"]["value"],
            serde_json::Value::Null
        );
    }

    #[test]
    fn a_failed_identity_query_makes_the_inventory_partial() {
        let mut snapshot = process_snapshot();
        snapshot.omissions.failed = 1;
        let view = TopView::new(&snapshot, None, None, ProcessSort::Footprint, 10);
        assert!(view.coverage.is_partial());
        assert_eq!(
            crate::commands::resources::snapshot_status(&view.coverage),
            ExitStatus::Partial
        );
    }

    #[test]
    fn a_control_character_in_a_name_is_escaped() {
        let mut snapshot = process_snapshot();
        let executable = snapshot.records[0].identity.executable.as_mut().unwrap();
        executable.path =
            svalnir_core::file::LosslessPath::from_bytes(b"/Apps/ed\x1b[2Jitor".to_vec()).unwrap();
        let view = TopView::new(&snapshot, None, None, ProcessSort::Footprint, 10);
        let text = view.render();
        assert!(!text.contains('\x1b'), "{text:?}");
        assert!(text.contains("ed\\u{1b}[2Jitor"), "{text}");
    }

    #[test]
    fn show_explains_the_target_and_does_not_evaluate_eligibility() {
        let snapshot = process_snapshot();
        let record = find_target(&snapshot, "pg-200-1700000000000000").unwrap();
        let view = ShowView::new(&snapshot, record);
        let text = view.render();
        assert!(
            text.starts_with("Target pg-200-1700000000000000, at "),
            "{text}"
        );
        assert!(
            text.contains("Executable      /Applications/Editor.app/Contents/MacOS/editor"),
            "{text}"
        );
        assert!(text.contains("Footprint       3.0 GiB"), "{text}");
        assert!(text.contains("Members         2"), "{text}");
        assert!(text.contains("Footprint sum   4.0 GiB"), "{text}");
        assert!(
            text.contains("Policy eligibility: not evaluated."),
            "{text}"
        );
        let json = serde_json::to_value(&view).unwrap();
        assert_eq!(json["identity"]["start_time"], "1700000000000000");
        assert_eq!(json["policy_eligibility"]["evaluated"], false);
        assert_eq!(
            json["application"]["measured_footprint_bytes"],
            "4294967296"
        );
        assert_eq!(json["metrics"]["cpu_time"]["unit"], "nanosecond");
    }

    #[test]
    fn show_of_a_process_with_no_footprint_says_unavailable() {
        let mut snapshot = process_snapshot();
        snapshot.records[0].metrics.footprint.reading =
            Reading::Unavailable(UnavailableReason::ResourceGone);
        let record = find_target(&snapshot, "pg-200-1700000000000000").unwrap();
        let text = ShowView::new(&snapshot, record).render();
        assert!(
            text.contains("Footprint       unavailable (resource_gone)"),
            "{text}"
        );
        assert!(
            text.contains("a lower bound: 1 members have no value"),
            "{text}"
        );
    }

    #[test]
    fn an_unknown_or_malformed_target_is_an_error() {
        let snapshot = process_snapshot();
        let gone = find_target(&snapshot, "pg-999-1").unwrap_err();
        assert_eq!(&*gone.code, "target_not_found");
        assert_eq!(gone.family, ErrorFamily::Evidence);
        assert_eq!(gone.exit_status(), ExitStatus::Conflict);
        for text in ["200", "editor", "pg 200", "app-200-1700000000000000", ""] {
            let invalid = find_target(&snapshot, text).unwrap_err();
            assert_eq!(&*invalid.code, "invalid_target", "{text}");
            assert_eq!(invalid.exit_status(), ExitStatus::Usage);
        }
    }
}
