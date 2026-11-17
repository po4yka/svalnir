//! `scan PATH [--save]` and `report --scan ID`.
//!
//! A scan reads metadata below one root and changes nothing below it.
//! `--save` writes the result to the catalog store in the state directory;
//! that is the only write of these commands, and it does not authorize a
//! cleanup. `report` reads a saved result.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use svalnir_agent::platform::memory::CollectionContext;
use svalnir_agent::platform::volume;
use svalnir_agent::scan::{
    CancellationToken, NoObserver, ScanClock, ScanCompletion, ScanError, ScanLimits,
    ScanObservations, ScanRequest, ScanResult, ScanTimestamp, WallScanClock, run_scan,
};
use svalnir_agent::store::{RetentionPolicy, ScanRecord, Store, StoreError, StoreOptions};
use svalnir_core::config;
use svalnir_core::file::LosslessPath;
use svalnir_core::id::{AdapterId, SampleId, ScanId};
use svalnir_core::observation::{Coverage, Observation, Sample, Source};
use svalnir_core::quantity::{Bytes, EntryCount};
use svalnir_core::time::WallTime;

use super::{CommandFailure, Invocation};
use crate::cli::{ReportArgs, ScanArgs};
use crate::environment::Environment;
use crate::host::Host;
use crate::interrupt::Interrupt;
use crate::output::{ErrorBody, ErrorFamily, ErrorStage, ExitStatus, Kind, NextAction};
use crate::text::{escape, field, human_bytes, human_duration, put_line, table};

/// The number of entries of each list in the text form. The JSON form has
/// each recorded entry.
const TEXT_LIST_LIMIT: usize = 10;

/// The time between two checks of the interrupt flag during a scan.
const INTERRUPT_POLL: Duration = Duration::from_millis(50);

/// The statement of each scan result about authority.
const AUTHORITY_NOTE: &str = "A scan and a saved scan record do not authorize a cleanup. The allocated size is not exclusive size and not reclaimable size.";

/// The totals of a scan as observations of the `scan` scope.
#[derive(Debug, Clone, Serialize)]
struct ObservationsView {
    logical_bytes: Observation<Bytes>,
    allocated_bytes: Observation<Bytes>,
    exclusive_bytes: Observation<Bytes>,
    entries: Observation<EntryCount>,
}

impl From<ScanObservations> for ObservationsView {
    fn from(observations: ScanObservations) -> Self {
        Self {
            logical_bytes: observations.logical_bytes,
            allocated_bytes: observations.allocated_bytes,
            exclusive_bytes: observations.exclusive_bytes,
            entries: observations.entries,
        }
    }
}

/// Whether the result is in the catalog store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SaveState {
    /// `--save` was not given.
    NotRequested,
    /// The result is in the catalog store.
    Saved,
    /// The user interrupted the scan, so the result was not saved.
    NotSavedInterrupted,
    /// The result was saved, and the size limit of the catalog store then
    /// removed it. A report cannot read it.
    RemovedByRetention,
}

/// The result of `scan`.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct ScanView {
    scan: ScanResult,
    /// The totals as observations. `null` when the host gave no collection
    /// context or no monotonic time.
    observations: Option<ObservationsView>,
    save: SaveState,
    /// The error of the retention pass after the save, when it failed. The
    /// record stays saved.
    retention_error: Option<String>,
    note: &'static str,
}

/// The result of `report`.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct ReportView {
    scan: ScanResult,
    /// The wall-clock times of the record in the catalog store.
    recorded_started_at: WallTime,
    recorded_finished_at: WallTime,
    note: &'static str,
}

/// The serialized name of a plain enumeration value.
fn wire_name<T: Serialize>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(name)) => name,
        _ => "unknown".to_owned(),
    }
}

/// The identity, the totals, and the coverage of a scan.
fn render_summary(result: &ScanResult, out: &mut String) {
    put_line!(
        out,
        "Scan {} of {}",
        result.scan_id,
        result.root.display_label()
    );
    field(out, "Completion", 14, &wire_name(&result.completion));
    field(out, "Coverage", 14, &escape(result.coverage.as_str()));
    if let Some(finished) = result.finished.wall {
        field(out, "Finished", 14, &finished.to_string());
    }
    if let Some(elapsed) = result.elapsed {
        field(out, "Elapsed", 14, &human_duration(elapsed));
    }
    let totals = &result.totals;
    field(
        out,
        "Entries",
        14,
        &format!(
            "{} measured ({} files, {} directories, {} symbolic links, {} other); {} names examined",
            totals.entries,
            totals.files,
            totals.directories,
            totals.symlinks,
            totals.other_entries,
            result.entries_examined
        ),
    );
    field(
        out,
        "Logical size",
        14,
        &human_bytes(totals.logical_bytes.get()),
    );
    field(
        out,
        "Allocated size",
        14,
        &human_bytes(totals.allocated_bytes.get()),
    );
    field(out, "Exclusive size", 14, "unavailable (unsupported)");
    let shared = &result.shared_storage;
    field(
        out,
        "Shared storage",
        14,
        &format!(
            "{} hard-linked objects, {} compressed files, {} files allocated below their logical size",
            shared.hard_linked_objects,
            shared.compressed_files,
            shared.files_allocated_below_logical
        ),
    );
    if result.coverage != Coverage::Complete {
        out.push_str("  The totals are a sum of the measured part only.\n");
    }
}

/// The largest directories and files.
fn render_largest(result: &ScanResult, out: &mut String) {
    if !result.largest_directories.is_empty() {
        out.push_str("\nLargest directories by allocated size\n");
        let rows: Vec<Vec<String>> = result
            .largest_directories
            .iter()
            .take(TEXT_LIST_LIMIT)
            .map(|directory| {
                vec![
                    human_bytes(directory.allocated_bytes.get()),
                    human_bytes(directory.logical_bytes.get()),
                    directory.entries.to_string(),
                    escape(directory.coverage.as_str()),
                    directory.path.display_label(),
                ]
            })
            .collect();
        out.push_str(&table(
            &["ALLOCATED", "LOGICAL", "ENTRIES", "COVERAGE", "PATH"],
            &[true, true, true, false, false],
            &rows,
        ));
    }
    if !result.largest_files.is_empty() {
        out.push_str("\nLargest files by allocated size\n");
        let rows: Vec<Vec<String>> = result
            .largest_files
            .iter()
            .take(TEXT_LIST_LIMIT)
            .map(|file| {
                vec![
                    human_bytes(file.allocated_bytes.get()),
                    human_bytes(file.logical_bytes.get()),
                    file.link_count.to_string(),
                    file.path.display_label(),
                ]
            })
            .collect();
        out.push_str(&table(
            &["ALLOCATED", "LOGICAL", "LINKS", "PATH"],
            &[true, true, true, false],
            &rows,
        ));
    }
}

/// The mount boundaries and the regions that the totals do not cover.
fn render_gaps(result: &ScanResult, out: &mut String) {
    if !result.boundaries.is_empty() || result.boundaries_omitted != EntryCount::ZERO {
        put_line!(
            out,
            "\nMount boundaries that the scan did not cross: {} listed, {} more not listed",
            result.boundaries.len(),
            result.boundaries_omitted
        );
        for boundary in result.boundaries.iter().take(TEXT_LIST_LIMIT) {
            put_line!(out, "  {}", boundary.path.display_label());
        }
    }
    if !result.regions.is_empty() || result.regions_omitted != EntryCount::ZERO {
        put_line!(
            out,
            "\nRegions that the totals do not fully cover: {} listed, {} more not listed",
            result.regions.len(),
            result.regions_omitted
        );
        let rows: Vec<Vec<String>> = result
            .regions
            .iter()
            .take(TEXT_LIST_LIMIT)
            .map(|region| {
                vec![
                    wire_name(&region.kind()),
                    wire_name(&region.cause),
                    region.path.display_label(),
                ]
            })
            .collect();
        out.push_str(&table(
            &["KIND", "CAUSE", "PATH"],
            &[false, false, false],
            &rows,
        ));
        if result.regions.len() > TEXT_LIST_LIMIT {
            out.push_str("  The JSON form has each listed region.\n");
        }
    }
}

/// Renders a scan result as text.
pub(crate) fn render_result(result: &ScanResult) -> String {
    let mut out = String::new();
    render_summary(result, &mut out);
    render_largest(result, &mut out);
    render_gaps(result, &mut out);
    out
}

impl ScanView {
    pub(crate) fn render(&self) -> String {
        let mut out: String = render_result(&self.scan);
        out.push('\n');
        match self.save {
            SaveState::NotRequested => {
                out.push_str(
                    "The result is not saved. Use `--save` to keep it for `svalnir report`.\n",
                );
            }
            SaveState::Saved => {
                put_line!(
                    out,
                    "Saved. Read it again with `svalnir report --scan {}`.",
                    self.scan.scan_id
                );
            }
            SaveState::NotSavedInterrupted => {
                out.push_str("The scan was interrupted, so the result is not saved.\n");
            }
            SaveState::RemovedByRetention => {
                out.push_str(
                    "The size limit of the catalog store removed the result after the save. `svalnir report` cannot read it.\n",
                );
            }
        }
        if let Some(error) = &self.retention_error {
            put_line!(
                out,
                "The retention of the catalog store failed: {}",
                escape(error)
            );
        }
        put_line!(out, "{AUTHORITY_NOTE}");
        out
    }

    /// The exit status: 130 for an interrupted scan, 4 for partial coverage.
    pub(crate) fn status(&self) -> ExitStatus {
        if self.scan.completion == ScanCompletion::Cancelled {
            ExitStatus::Interrupted
        } else if self.scan.coverage == Coverage::Complete {
            ExitStatus::Success
        } else {
            ExitStatus::Partial
        }
    }
}

impl ReportView {
    pub(crate) fn render(&self) -> String {
        let mut out: String = render_result(&self.scan);
        put_line!(
            out,
            "\nThis is a saved record from {}. The files can be different now.",
            self.recorded_finished_at
        );
        put_line!(out, "{AUTHORITY_NOTE}");
        out
    }
}

/// A scan clock that reads the clock of the collection context, so the
/// monotonic times of a scan are on the timeline of the other observations.
struct HostScanClock<'a>(&'a CollectionContext);

impl ScanClock for HostScanClock<'_> {
    fn now(&self) -> ScanTimestamp {
        let clock = self.0.clock();
        ScanTimestamp {
            wall: clock.wall_now().ok(),
            monotonic_ns: clock.monotonic_now().ok(),
        }
    }
}

/// Makes the identity of a new scan from the wall clock and the process ID.
fn generate_scan_id() -> Result<ScanId, ErrorBody> {
    let nanoseconds: u128 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    ScanId::new(format!("scan_{nanoseconds:x}_{:x}", std::process::id())).map_err(|_| ErrorBody {
        code: "scan_identity_unavailable",
        family: ErrorFamily::Native,
        stage: ErrorStage::Collection,
        message: "the scan identity cannot be made".to_owned(),
        fields: Vec::new(),
        operation_id: None,
        plan_id: None,
        next_action: NextAction::None,
    })
}

fn scan_error(error: &ScanError) -> ErrorBody {
    let (code, family, next_action): (&'static str, ErrorFamily, NextAction) = match error {
        ScanError::RootPath(_) | ScanError::RootNotDirectory | ScanError::LimitTooLarge { .. } => (
            "invalid_scan_root",
            ErrorFamily::Request,
            NextAction::CorrectRequest,
        ),
        ScanError::RootUnavailable(source) if source.kind() == std::io::ErrorKind::NotFound => (
            "scan_root_not_found",
            ErrorFamily::Request,
            NextAction::CorrectRequest,
        ),
        ScanError::RootUnavailable(_)
        | ScanError::RootNotHydrated
        | ScanError::RootDeviceUnsupported
        | ScanError::VolumeMismatch
        | ScanError::Unsupported => (
            "scan_root_unavailable",
            ErrorFamily::Native,
            NextAction::None,
        ),
    };
    let detail: String = match error {
        ScanError::RootUnavailable(source) => format!("{error}: {}", source.kind()),
        other => other.to_string(),
    };
    ErrorBody {
        code,
        family,
        stage: if family == ErrorFamily::Request {
            ErrorStage::Arguments
        } else {
            ErrorStage::Collection
        },
        message: format!("the scan did not start: {detail}; the command made no change"),
        fields: vec!["path"],
        operation_id: None,
        plan_id: None,
        next_action,
    }
}

fn store_error(error: &StoreError) -> ErrorBody {
    ErrorBody {
        code: "state_store_unavailable",
        family: ErrorFamily::Recording,
        stage: ErrorStage::Storage,
        message: format!("the catalog store gave an error: {error}"),
        fields: Vec::new(),
        operation_id: None,
        plan_id: None,
        next_action: NextAction::None,
    }
}

/// The store options and the retention of the catalog store: the `[history]`
/// values of the configuration template. This build has no effective
/// configuration revision, so a proposal file does not change them.
fn catalog_limits() -> (StoreOptions, Option<RetentionPolicy>) {
    let template = config::parse_and_validate("schema_version = 1\n");
    match template.config() {
        Some(config) => {
            let history = config.history();
            (
                StoreOptions {
                    max_database_size: Some(history.max_database_size),
                    ..StoreOptions::default()
                },
                Some(RetentionPolicy::for_history(
                    history.retention,
                    history.max_database_size,
                )),
            )
        }
        None => (StoreOptions::default(), None),
    }
}

/// Opens the catalog store for a write. Creates the state directory.
fn open_catalog_for_write(environment: &Environment) -> Result<Store, ErrorBody> {
    environment.create_state_directory()?;
    let (options, _) = catalog_limits();
    Store::open(&environment.catalog_path()?, &options).map_err(|error| store_error(&error))
}

/// Stops the watcher when the scan ends, also when the scan panics.
/// The scope joins the watcher before it passes a panic on, so a flag
/// that only a normal return sets would leave the process waiting.
struct Finish<'a>(&'a AtomicBool);
impl Drop for Finish<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// Runs the scan and stops it when the user interrupts.
fn run_with_interrupt(
    request: &ScanRequest,
    clock: &dyn ScanClock,
    interrupt: &Interrupt,
) -> Result<ScanResult, ScanError> {
    interrupt.arm();
    let cancel = CancellationToken::new();
    let finished = AtomicBool::new(false);
    std::thread::scope(|scope| {
        scope.spawn(|| {
            while !finished.load(Ordering::SeqCst) {
                if interrupt.is_requested() {
                    cancel.cancel();
                    return;
                }
                std::thread::sleep(INTERRUPT_POLL);
            }
        });
        let _finish = Finish(&finished);
        run_scan(request, &cancel, clock, &mut NoObserver)
    })
}

/// The totals of the scan as observations, when the host gives the context.
fn observations(result: &ScanResult, host: Option<&Host>) -> Option<ObservationsView> {
    let identity = host?.context().identity();
    let started = result.started.monotonic_ns?;
    let finished = result.finished.monotonic_ns?;
    if finished < started {
        return None;
    }
    let sample = Sample {
        sample_id: SampleId::new(format!("sample_{}", result.scan_id)).ok()?,
        clock_domain: identity.clock_domain.clone(),
        boot_id: identity.boot_id.clone(),
        collector_epoch: identity.collector_epoch.clone(),
        started_monotonic_ns: started,
        finished_monotonic_ns: finished,
        captured_at: result.finished.wall?,
    };
    let source = Source {
        adapter_id: AdapterId::new("svalnir.scan").ok()?,
        adapter_revision: "1".to_owned(),
        native_api: "fstatat".to_owned(),
        native_field: "st_size, st_blocks".to_owned(),
        worker_id: identity.worker_id.clone(),
    };
    result
        .observations(&source, &sample)
        .ok()
        .map(ObservationsView::from)
}

/// Scans `root` and, with `save`, records the result.
pub(crate) fn scan_root(
    root: &Path,
    save: bool,
    environment: &Environment,
) -> Result<ScanView, ErrorBody> {
    let lossless: LosslessPath =
        LosslessPath::from_path(root).map_err(|error| scan_error(&ScanError::RootPath(error)))?;
    let scan_id: ScanId = generate_scan_id()?;
    // The store is opened before the scan, so that a store that is not
    // writable fails before the work and not after it.
    // A root that is not a directory cannot be scanned, so nothing is created
    // for it.
    let mut store: Option<Store> = if save && root.is_dir() {
        Some(open_catalog_for_write(environment)?)
    } else {
        None
    };
    // The scanner is portable. The collection context is not, so its absence
    // removes only the monotonic times and the observation envelope.
    let host: Option<Host> = Host::open().ok();
    let host_clock: Option<HostScanClock<'_>> =
        host.as_ref().map(|host| HostScanClock(host.context()));
    let clock: &dyn ScanClock = match &host_clock {
        Some(clock) => clock,
        None => &WallScanClock,
    };
    let mut request = ScanRequest {
        scan_id,
        root: lossless.clone(),
        limits: ScanLimits::default(),
        volume: volume::volume_at(root).ok().map(|mounted| mounted.identity),
    };
    let result: ScanResult = match run_with_interrupt(&request, clock, &environment.interrupt) {
        // The identity is evidence, not a requirement: scan without it.
        Err(ScanError::VolumeMismatch) => {
            request.volume = None;
            run_with_interrupt(&request, clock, &environment.interrupt)
        }
        other => other,
    }
    .map_err(|error| scan_error(&error))?;

    let mut save_state: SaveState = SaveState::NotRequested;
    let mut retention_error: Option<String> = None;
    if let Some(store) = &mut store {
        if result.completion == ScanCompletion::Cancelled {
            save_state = SaveState::NotSavedInterrupted;
        } else {
            let now: WallTime =
                WallTime::try_from(SystemTime::now()).unwrap_or(WallTime::UNIX_EPOCH);
            let finished_at: WallTime = result.finished.wall.unwrap_or(now);
            let record = ScanRecord {
                scan_id: result.scan_id.clone(),
                root: lossless,
                started_at: result.started.wall.unwrap_or(finished_at),
                finished_at,
                result_json: serde_json::to_string(&result).map_err(|_| ErrorBody {
                    code: "scan_record_not_encoded",
                    family: ErrorFamily::Recording,
                    stage: ErrorStage::Storage,
                    message: "the scan result cannot be encoded; it is not saved".to_owned(),
                    fields: Vec::new(),
                    operation_id: None,
                    plan_id: None,
                    next_action: NextAction::None,
                })?,
            };
            store
                .insert_scan(&record)
                .map_err(|error| store_error(&error))?;
            // The record is committed. A retention failure does not undo it,
            // and the size rule of the retention can remove the new record.
            if let (_, Some(retention)) = catalog_limits()
                && let Err(error) = store.apply_retention(now, &retention)
            {
                retention_error = Some(error.to_string());
            }
            save_state = match store.scan(&record.scan_id) {
                Ok(Some(_)) => SaveState::Saved,
                Ok(None) => SaveState::RemovedByRetention,
                Err(error) => return Err(store_error(&error)),
            };
        }
    }
    Ok(ScanView {
        observations: observations(&result, host.as_ref()),
        scan: result,
        save: save_state,
        retention_error,
        note: AUTHORITY_NOTE,
    })
}

/// Reads a saved scan.
pub(crate) fn load_report(scan: &str, environment: &Environment) -> Result<ReportView, ErrorBody> {
    let scan_id: ScanId = ScanId::new(scan).map_err(|_| ErrorBody {
        code: "invalid_scan_id",
        family: ErrorFamily::Request,
        stage: ErrorStage::Arguments,
        message: "the scan ID is not valid; use the ID that `svalnir scan --save` printed"
            .to_owned(),
        fields: vec!["scan"],
        operation_id: None,
        plan_id: None,
        next_action: NextAction::CorrectRequest,
    })?;
    let not_found = || {
        ErrorBody {
        code: "scan_not_found",
        family: ErrorFamily::Evidence,
        stage: ErrorStage::Storage,
        message: "no saved scan has this ID: the scan was not saved, or the retention removed it; the command made no change".to_owned(),
        fields: vec!["scan"],
        operation_id: None,
        plan_id: None,
        next_action: NextAction::RefreshObservation,
    }
    };
    let path: PathBuf = environment.catalog_path()?;
    // A report does not create the store.
    if !path.is_file() {
        return Err(not_found());
    }
    let (options, _) = catalog_limits();
    let store: Store = Store::open(&path, &options).map_err(|error| store_error(&error))?;
    let record: ScanRecord = store
        .scan(&scan_id)
        .map_err(|error| store_error(&error))?
        .ok_or_else(not_found)?;
    let result: ScanResult = serde_json::from_str(&record.result_json).map_err(|_| ErrorBody {
        code: "scan_record_unreadable",
        family: ErrorFamily::Recording,
        stage: ErrorStage::Storage,
        message: "the saved scan record is not readable by this build".to_owned(),
        fields: vec!["scan"],
        operation_id: None,
        plan_id: None,
        next_action: NextAction::RefreshObservation,
    })?;
    Ok(ReportView {
        scan: result,
        recorded_started_at: record.started_at,
        recorded_finished_at: record.finished_at,
        note: AUTHORITY_NOTE,
    })
}

pub(crate) fn scan(
    arguments: &ScanArgs,
    invocation: &mut Invocation<'_>,
) -> Result<ExitStatus, CommandFailure> {
    let root: PathBuf = invocation.environment.resolve(&arguments.path, "path")?;
    let view: ScanView = scan_root(&root, arguments.save, invocation.environment)?;
    invocation.emit(Kind::Snapshot, &view, ScanView::render)?;
    Ok(view.status())
}

pub(crate) fn report(
    arguments: &ReportArgs,
    invocation: &mut Invocation<'_>,
) -> Result<ExitStatus, CommandFailure> {
    let view: ReportView = load_report(&arguments.scan, invocation.environment)?;
    invocation.emit(Kind::Report, &view, ReportView::render)?;
    // The query succeeded. The coverage of the saved scan is in the result.
    Ok(ExitStatus::Success)
}

#[cfg(test)]
mod tests {
    use super::{ReportView, SaveState, ScanView, render_result};
    use crate::output::ExitStatus;
    use crate::test_support::scan_result;

    #[test]
    fn the_text_of_a_complete_scan_has_the_totals_and_the_lists() {
        let result = scan_result(false);
        let text = render_result(&result);
        assert!(
            text.starts_with("Scan scan_test of /data/project\n"),
            "{text}"
        );
        assert!(text.contains("Completion      finished"), "{text}");
        assert!(text.contains("Coverage        complete"), "{text}");
        assert!(text.contains("Logical size    3.0 MiB"), "{text}");
        assert!(text.contains("Allocated size  4.0 MiB"), "{text}");
        assert!(
            text.contains("Exclusive size  unavailable (unsupported)"),
            "{text}"
        );
        assert!(text.contains("/data/project/big.bin"), "{text}");
        assert!(!text.contains("Regions that the totals"), "{text}");
        let view = ScanView {
            scan: result,
            observations: None,
            save: SaveState::NotRequested,
            retention_error: None,
            note: super::AUTHORITY_NOTE,
        };
        assert_eq!(view.status(), ExitStatus::Success);
        assert!(view.render().contains("The result is not saved."));
        assert!(view.render().contains("do not authorize a cleanup"));
    }

    #[test]
    fn a_partial_scan_names_its_regions_and_has_status_4() {
        let result = scan_result(true);
        let view = ScanView {
            scan: result,
            observations: None,
            save: SaveState::Saved,
            retention_error: None,
            note: super::AUTHORITY_NOTE,
        };
        let text = view.render();
        assert!(text.contains("Coverage        partial"), "{text}");
        assert!(
            text.contains("The totals are a sum of the measured part only."),
            "{text}"
        );
        assert!(
            text.contains("inaccessible  permission_denied  /data/project/secret"),
            "{text}"
        );
        // A control character in a file name does not reach the terminal.
        assert!(text.contains("/data/project/a\\u{1b}[31mb"), "{text}");
        assert!(!text.contains('\x1b'));
        assert!(text.contains("svalnir report --scan scan_test"), "{text}");
        assert_eq!(view.status(), ExitStatus::Partial);
        let json = serde_json::to_value(&view).unwrap();
        assert_eq!(json["scan"]["coverage"], "partial");
        assert_eq!(json["scan"]["totals"]["allocated_bytes"], "4194304");
        assert_eq!(json["scan"]["regions"][0]["cause"], "permission_denied");
        assert_eq!(json["scan"]["root"]["encoding"], "utf8");
        assert_eq!(json["save"], "saved");
        assert_eq!(json["observations"], serde_json::Value::Null);
    }

    #[test]
    fn a_report_says_that_the_record_is_from_the_past() {
        let result = scan_result(false);
        let finished = result.finished.wall.unwrap();
        let view = ReportView {
            scan: result,
            recorded_started_at: finished,
            recorded_finished_at: finished,
            note: super::AUTHORITY_NOTE,
        };
        let text = view.render();
        assert!(
            text.contains("This is a saved record from 2026-01-02T03:04:05Z."),
            "{text}"
        );
        let json = serde_json::to_value(&view).unwrap();
        assert_eq!(json["recorded_finished_at"], "2026-01-02T03:04:05Z");
    }
}
