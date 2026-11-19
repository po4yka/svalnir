//! The live source: the shared read layer of the agent library, in process.

use super::{
    DataSource,
    model::{
        AgentSnapshot, AgentState, ChildSize, GapRow, GuardRow, HostSnapshot, Measured,
        OperationPhase, OperationRow, PressureLevel, ScanEnd, ScanProgress, ScanSummary,
        ServiceSnapshot,
    },
};
use super::{
    live_records,
    records::{
        AutomationSnapshot, DiagnosticsSnapshot, HistorySnapshot, MemorySnapshot, ProcessesSnapshot,
    },
};
use std::{
    collections::{HashMap, HashSet},
    ffi::{OsStr, OsString},
    path::{Path, PathBuf},
    sync::{Mutex, PoisonError},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use svalnir_agent::{
    journal::AgentRecord,
    observe::{self, DiskReading, Host},
    platform::volume,
    runtime::{AgentStatus, journal_path},
    scan::{
        CancellationToken, DirectoryRecord, EntryKind, EntryRecord, RegionCause, ScanCompletion,
        ScanError, ScanLimits, ScanObserver, ScanRequest, ScanResult, WallScanClock, run_scan,
    },
};
use svalnir_core::{
    file::LosslessPath, grant::AuthorityState, id::ScanId, observation::Coverage, time::WallTime,
};
use svalnir_core::{observation::Observation, quantity::Bytes, state::PressureState};

/// The state directory override variable; the same as the CLI reads.
const STATE_DIRECTORY_VARIABLE: &str = "SVALNIR_STATE_DIR";
/// The default state directory under `$HOME`; the same as the CLI uses.
const DEFAULT_STATE_DIRECTORY: &str = "Library/Application Support/Svalnir";

/// Reads the host in this process. It never creates the state directory or
/// the journal.
#[derive(Debug)]
pub struct LiveSource {
    host: Mutex<Option<Host>>,
    state_directory: Option<PathBuf>,
}

impl LiveSource {
    /// Creates the source for `state_directory`. `None` means that the
    /// directory is not known, so the agent state is `NoJournal`.
    #[must_use]
    pub fn new(state_directory: Option<PathBuf>) -> Self {
        Self {
            host: Mutex::new(None),
            state_directory,
        }
    }

    /// Runs `read` with the host of this source, which it opens one time.
    fn with_host<T>(&self, read: impl FnOnce(&Host) -> Result<T, String>) -> Result<T, String> {
        let mut guard = self.host.lock().unwrap_or_else(PoisonError::into_inner);
        if guard.is_none() {
            *guard = Some(Host::open().map_err(|error| error.to_string())?);
        }
        match guard.as_ref() {
            Some(host) => read(host),
            None => Err("the host is not open".to_owned()),
        }
    }

    /// Creates the source for the state directory of the environment.
    #[must_use]
    pub fn from_environment() -> Self {
        Self::new(default_state_directory())
    }
}

/// The state directory by the rule of the CLI: an absolute override, else
/// `$HOME` plus the default path.
fn default_state_directory() -> Option<PathBuf> {
    if let Some(text) = std::env::var_os(STATE_DIRECTORY_VARIABLE) {
        let path: PathBuf = PathBuf::from(text);
        return path.is_absolute().then_some(path);
    }
    let home: PathBuf = PathBuf::from(std::env::var_os("HOME")?);
    home.is_absolute()
        .then(|| home.join(DEFAULT_STATE_DIRECTORY))
}

fn bytes(observation: &Observation<Bytes>) -> Measured<u64> {
    match observation.value() {
        Some(value) => Measured::Value(value.get()),
        None => Measured::Unavailable(
            observation
                .reason()
                .map_or_else(|| "unrecognized".to_owned(), ToString::to_string),
        ),
    }
}

fn pressure(observation: &Observation<PressureState>) -> Measured<PressureLevel> {
    match observation.value() {
        Some(PressureState::Normal) => Measured::Value(PressureLevel::Normal),
        Some(PressureState::Warning) => Measured::Value(PressureLevel::Warning),
        Some(PressureState::Critical) => Measured::Value(PressureLevel::Critical),
        Some(PressureState::Unrecognized(text)) => {
            Measured::Unavailable(format!("unrecognized pressure state `{}`", text.as_str()))
        }
        None => Measured::Unavailable(
            observation
                .reason()
                .map_or_else(|| "unrecognized".to_owned(), ToString::to_string),
        ),
    }
}

impl DataSource for LiveSource {
    fn host(&self) -> Result<HostSnapshot, String> {
        let mut guard = self.host.lock().unwrap_or_else(PoisonError::into_inner);
        if guard.is_none() {
            *guard = Some(Host::open().map_err(|error| error.to_string())?);
        }
        let Some(host) = guard.as_ref() else {
            return Err("the host is not open".to_owned());
        };
        let reading = observe::collect(host).map_err(|error| error.to_string())?;
        let unavailable =
            |reason: &str| -> Measured<u64> { Measured::Unavailable(reason.to_owned()) };
        let (volume_name, disk_total, disk_available, disk_free) = match &reading.disk {
            DiskReading::Measured {
                identity, capacity, ..
            } => (
                Some(identity.mount_point.display_label()),
                bytes(&capacity.total),
                bytes(&capacity.available),
                bytes(&capacity.free),
            ),
            DiskReading::CapacityUnavailable { identity, reason } => (
                Some(identity.mount_point.display_label()),
                unavailable(reason),
                unavailable(reason),
                unavailable(reason),
            ),
            DiskReading::Unresolved(reason) => (
                None,
                unavailable(reason),
                unavailable(reason),
                unavailable(reason),
            ),
        };
        let captured_at: SystemTime = SystemTime::now();
        Ok(HostSnapshot {
            captured_at,
            utc_offset: crate::platform::utc_offset_seconds(captured_at),
            volume_name,
            disk_total,
            disk_available,
            disk_free,
            pressure: pressure(&reading.memory.pressure),
            memory_total: bytes(&reading.memory.physical),
            swap_used: bytes(&reading.memory.swap.used),
            swap_total: bytes(&reading.memory.swap.allocated),
            source: "in-process collection",
        })
    }

    fn agent(&self) -> AgentSnapshot {
        let state: AgentState = match &self.state_directory {
            None => AgentState::NoJournal,
            Some(directory) => agent_state(&journal_path(directory)),
        };
        AgentSnapshot {
            state,
            captured_at: SystemTime::now(),
        }
    }

    fn service(&self) -> ServiceSnapshot {
        let captured_at: SystemTime = SystemTime::now();
        let mut snapshot = ServiceSnapshot {
            journal_present: false,
            active_revision: None,
            guards: Vec::new(),
            latest_operation: None,
            problems: Vec::new(),
            captured_at,
        };
        let uid = observe::current_uid();
        let Ok(now) = WallTime::try_from(captured_at) else {
            snapshot.problems.push(
                "The system clock has no usable value, so the guards are not shown.".to_owned(),
            );
            return snapshot;
        };
        let opened = match &self.state_directory {
            None => Ok(None),
            Some(directory) => observe::open_existing_journal_read_only(&journal_path(directory)),
        };
        let journal = match opened {
            Ok(Some(journal)) => journal,
            Ok(None) => {
                snapshot.guards = guard_rows(&AuthorityState::new(uid), now);
                return snapshot;
            }
            Err(error) => {
                snapshot.journal_present = true;
                snapshot
                    .problems
                    .push(format!("The journal cannot be read: {error}."));
                return snapshot;
            }
        };
        snapshot.journal_present = true;
        match observe::read_authority(&journal, uid) {
            Ok(stored) => {
                snapshot.active_revision = stored
                    .state
                    .active
                    .as_ref()
                    .map(|active| active.revision.revision_id.to_string());
                snapshot.guards = guard_rows(&stored.state, now);
            }
            Err(error) => snapshot
                .problems
                .push(format!("The authority record cannot be read: {error}.")),
        }
        match journal.recent_operations(1) {
            Ok(operations) => {
                snapshot.latest_operation = operations.first().map(|operation| {
                    let (state, state_text) = OperationPhase::of(operation.state());
                    OperationRow {
                        operation_id: operation.operation_id().to_string(),
                        state,
                        state_text,
                        admitted_at: system_time(operation.admitted_at()),
                        trigger: operation.trigger_class().as_str().to_owned(),
                    }
                });
            }
            Err(error) => snapshot
                .problems
                .push(format!("The latest operation cannot be read: {error}.")),
        }
        snapshot
    }

    fn memory(&self) -> Result<MemorySnapshot, String> {
        self.with_host(live_records::memory)
    }

    fn processes(&self) -> Result<ProcessesSnapshot, String> {
        self.with_host(live_records::processes)
    }

    fn automation(&self) -> AutomationSnapshot {
        live_records::automation(self.state_directory.as_deref())
    }

    fn history(&self) -> HistorySnapshot {
        live_records::history(self.state_directory.as_deref())
    }

    fn diagnostics(&self) -> DiagnosticsSnapshot {
        live_records::diagnostics(self.state_directory.as_deref())
    }

    fn scan(
        &self,
        root: &Path,
        cancel: &CancellationToken,
        progress: &dyn Fn(ScanProgress),
    ) -> Result<ScanSummary, String> {
        let lossless: LosslessPath = LosslessPath::from_path(root)
            .map_err(|error| format!("the root is not valid: {error}"))?;
        let nanoseconds: u128 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos());
        let scan_id: ScanId = ScanId::new(format!("scan_{nanoseconds:x}_{:x}", std::process::id()))
            .map_err(|_| "the scan identity cannot be made".to_owned())?;
        let mut request = ScanRequest {
            scan_id,
            root: lossless,
            limits: ScanLimits::default(),
            volume: volume::volume_at(root).ok().map(|mounted| mounted.identity),
        };
        let mut observer = ChildObserver::new(root, progress);
        let result: ScanResult = match run_scan(&request, cancel, &WallScanClock, &mut observer) {
            // The identity is evidence, not a requirement: scan without it.
            Err(ScanError::VolumeMismatch) => {
                request.volume = None;
                observer = ChildObserver::new(root, progress);
                run_scan(&request, cancel, &WallScanClock, &mut observer)
            }
            other => other,
        }
        .map_err(|error| format!("the scan did not run: {error}"))?;
        let (children, unsized_children) = observer.into_children();
        Ok(summarize(root, &result, children, unsized_children))
    }

    fn default_scan_root(&self) -> Option<PathBuf> {
        let home: PathBuf = PathBuf::from(std::env::var_os("HOME")?);
        (home.is_absolute() && home.is_dir()).then_some(home)
    }

    fn label(&self) -> &'static str {
        "in-process collection"
    }
}

/// The shortest interval between two progress calls.
const PROGRESS_INTERVAL: Duration = Duration::from_millis(100);
/// The most children that one progress value carries.
const PROGRESS_CHILDREN: usize = 32;

/// Sums the sizes of the direct children of the root and reports progress.
struct ChildObserver<'a> {
    root: PathBuf,
    children: HashMap<OsString, ChildSize>,
    /// The names of `children` in the order of their first insertion.
    order: Vec<OsString>,
    entries: u64,
    logical: u64,
    allocated: u64,
    /// Direct children with neither a logical nor an allocated size.
    unsized_children: u64,
    current: Option<PathBuf>,
    last_report: Option<Instant>,
    progress: &'a dyn Fn(ScanProgress),
}

impl<'a> ChildObserver<'a> {
    fn new(root: &Path, progress: &'a dyn Fn(ScanProgress)) -> Self {
        Self {
            root: root.to_path_buf(),
            children: HashMap::new(),
            order: Vec::new(),
            entries: 0,
            logical: 0,
            allocated: 0,
            unsized_children: 0,
            current: None,
            last_report: None,
            progress,
        }
    }

    /// The sized children and the number of direct children with no size.
    fn into_children(self) -> (Vec<ChildSize>, u64) {
        (self.children.into_values().collect(), self.unsized_children)
    }

    /// The direct child that `path` names, keyed by its exact name.
    fn child_key(&self, path: &Path) -> Option<OsString> {
        (path.parent() == Some(self.root.as_path()))
            .then(|| path.file_name().map(OsStr::to_os_string))
            .flatten()
    }

    /// Records `child`; a name seen first joins the end of the order.
    fn record(&mut self, key: OsString, child: ChildSize) {
        if self.children.insert(key.clone(), child).is_none() {
            self.order.push(key);
        }
    }

    /// The at most 32 largest children by allocated size, in first-seen order.
    fn snapshot_children(&self) -> Vec<ChildSize> {
        let mut largest: Vec<(&OsString, u64)> = self
            .children
            .iter()
            .map(|(key, child)| (key, child.allocated))
            .collect();
        largest.sort_by_key(|entry| std::cmp::Reverse(entry.1));
        largest.truncate(PROGRESS_CHILDREN);
        let keep: HashSet<&OsString> = largest.into_iter().map(|entry| entry.0).collect();
        self.order
            .iter()
            .filter(|key| keep.contains(key))
            .filter_map(|key| self.children.get(key).cloned())
            .collect()
    }

    fn report(&mut self) {
        let due: bool = self
            .last_report
            .is_none_or(|last| last.elapsed() >= PROGRESS_INTERVAL);
        if due {
            self.last_report = Some(Instant::now());
            (self.progress)(ScanProgress {
                entries: self.entries,
                current_path: self.current.clone(),
                logical: self.logical,
                allocated: self.allocated,
                children: self.snapshot_children(),
            });
        }
    }
}

impl ScanObserver for ChildObserver<'_> {
    fn directory_opened(&mut self, path: &Path) {
        self.current = Some(path.to_path_buf());
        self.report();
    }

    fn entry_listed(&mut self, _path: &Path) {
        self.entries = self.entries.saturating_add(1);
        self.report();
    }

    fn entry_measured(&mut self, entry: &EntryRecord<'_>) {
        if !entry.counted_in_totals {
            return;
        }
        let logical: u64 = entry.logical_bytes.map_or(0, Bytes::get);
        let allocated: u64 = entry.allocated_bytes.map_or(0, Bytes::get);
        self.logical = self.logical.saturating_add(logical);
        self.allocated = self.allocated.saturating_add(allocated);
        if entry.kind != EntryKind::Directory
            && let Some(key) = self.child_key(entry.path)
        {
            // A child with no size (a socket, a FIFO) is not a zero-byte
            // child: it is counted as a gap.
            if entry.logical_bytes.is_none() && entry.allocated_bytes.is_none() {
                self.unsized_children = self.unsized_children.saturating_add(1);
                self.report();
                return;
            }
            let child = ChildSize {
                name: key.to_string_lossy().into_owned(),
                path: entry.path.to_path_buf(),
                is_directory: false,
                logical,
                allocated,
            };
            self.record(key, child);
        }
        self.report();
    }

    fn directory_finished(&mut self, directory: &DirectoryRecord<'_>) {
        if let Some(key) = self.child_key(directory.path) {
            let child = ChildSize {
                name: key.to_string_lossy().into_owned(),
                path: directory.path.to_path_buf(),
                is_directory: true,
                logical: directory.logical_bytes.get(),
                allocated: directory.allocated_bytes.get(),
            };
            self.record(key, child);
        }
    }
}

const fn cause_text(cause: RegionCause) -> &'static str {
    match cause {
        RegionCause::PermissionDenied => "permission denied",
        RegionCause::ReadFailed => "read failed",
        RegionCause::ResourceLimit => "resource limit",
        RegionCause::NotHydrated => "not downloaded",
        RegionCause::Disappeared => "disappeared",
        RegionCause::IdentityChanged => "replaced during the scan",
        RegionCause::InconsistentMetadata => "inconsistent metadata",
        RegionCause::DepthLimit => "below the depth limit",
        RegionCause::EntryLimit => "entry limit reached",
        RegionCause::Cancelled => "cancelled",
        RegionCause::HardLinkLimit => "hard-link limit",
        RegionCause::Overflow => "total too large",
    }
}

fn summarize(
    root: &Path,
    result: &ScanResult,
    children: Vec<ChildSize>,
    unsized_children: u64,
) -> ScanSummary {
    let mut counts: Vec<(RegionCause, usize)> = Vec::new();
    for region in &result.regions {
        match counts.iter_mut().find(|(cause, _)| *cause == region.cause) {
            Some((_, count)) => *count += 1,
            None => counts.push((region.cause, 1)),
        }
    }
    let mut gaps: Vec<GapRow> = counts
        .into_iter()
        .map(|(cause, count)| GapRow {
            cause_text: cause_text(cause).to_owned(),
            count,
        })
        .collect();
    let omitted: u64 = result.regions_omitted.get();
    if omitted > 0 {
        gaps.push(GapRow {
            cause_text: "other regions not listed".to_owned(),
            count: usize::try_from(omitted).unwrap_or(usize::MAX),
        });
    }
    if unsized_children > 0 {
        gaps.push(GapRow {
            cause_text: "size not known".to_owned(),
            count: usize::try_from(unsized_children).unwrap_or(usize::MAX),
        });
    }
    let ended: ScanEnd = match result.completion {
        ScanCompletion::Finished => ScanEnd::Finished,
        ScanCompletion::Cancelled => ScanEnd::Cancelled,
        ScanCompletion::EntryLimitReached => ScanEnd::LimitReached,
    };
    ScanSummary {
        root: root.to_path_buf(),
        children,
        total_logical: result.totals.logical_bytes.get(),
        total_allocated: result.totals.allocated_bytes.get(),
        entries_examined: result.entries_examined.get(),
        complete: result.coverage == Coverage::Complete && ended == ScanEnd::Finished,
        ended,
        gaps,
        elapsed: result.elapsed.map(Duration::from),
        finished_at: SystemTime::now(),
    }
}

/// Three status intervals of the agent (the agent rewrites its status
/// record at least every 30 s: `status_interval` in `svalnir-agent`
/// `main.rs`).
const STATUS_FRESH: Duration = Duration::from_secs(90);

/// Reads the status record of the agent through the read-only journal. The
/// coordinator lock is not read: a lock probe can make a starting agent exit.
fn agent_state(journal_file: &Path) -> AgentState {
    let journal = match observe::open_existing_journal_read_only(journal_file) {
        Ok(Some(journal)) => journal,
        Ok(None) => return AgentState::NoJournal,
        Err(error) => return AgentState::Unknown(format!("the journal cannot be read: {error}")),
    };
    match journal.agent_record::<AgentStatus>(AgentRecord::Status) {
        Ok(None) => AgentState::NoRecord,
        Ok(Some(stored)) => {
            agent_state_from_status(system_time(stored.record.written_at), SystemTime::now())
        }
        Err(error) => AgentState::Unknown(format!("the status record cannot be read: {error}")),
    }
}

/// Classifies the age of the status record. A record dated ahead of `now`
/// by at most `STATUS_FRESH` is clock skew and counts as fresh; a record
/// dated further ahead is not trusted.
fn agent_state_from_status(written: SystemTime, now: SystemTime) -> AgentState {
    match now.duration_since(written) {
        Ok(age) if age < STATUS_FRESH => AgentState::Reporting { since: written },
        Ok(_) => AgentState::Silent { last: written },
        Err(ahead) if ahead.duration() <= STATUS_FRESH => AgentState::Reporting { since: written },
        Err(_) => {
            AgentState::Unknown("the status record of the agent is dated in the future".to_owned())
        }
    }
}

fn guard_rows(state: &AuthorityState, now: WallTime) -> Vec<GuardRow> {
    observe::guard_standings(state, now)
        .into_iter()
        .map(|(policy, standing)| GuardRow::new(policy.as_str(), standing))
        .collect()
}

fn system_time(time: WallTime) -> SystemTime {
    let seconds: i64 = time.unix_seconds();
    let nanos: Duration = Duration::from_nanos(u64::from(time.subsecond_nanoseconds()));
    if seconds >= 0 {
        UNIX_EPOCH + Duration::from_secs(seconds.unsigned_abs()) + nanos
    } else {
        UNIX_EPOCH - Duration::from_secs(seconds.unsigned_abs()) + nanos
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use svalnir_core::file::{DeviceNumber, FileObjectEvidence, InodeNumber};

    #[test]
    fn status_age_classification() {
        let now: SystemTime = UNIX_EPOCH + Duration::from_secs(10_000_000);
        let at = |back: u64| now - Duration::from_secs(back);
        assert!(matches!(
            agent_state_from_status(at(10), now),
            AgentState::Reporting { .. }
        ));
        assert!(matches!(
            agent_state_from_status(at(120), now),
            AgentState::Silent { .. }
        ));
        assert!(matches!(
            agent_state_from_status(now + Duration::from_secs(30), now),
            AgentState::Reporting { .. }
        ));
        assert!(matches!(
            agent_state_from_status(now + Duration::from_hours(24), now),
            AgentState::Unknown(_)
        ));
    }

    fn record(
        path: &Path,
        kind: EntryKind,
        logical: Option<u64>,
        allocated: Option<u64>,
    ) -> EntryRecord<'_> {
        EntryRecord {
            path,
            kind,
            depth: 1,
            logical_bytes: logical.map(Bytes::new),
            allocated_bytes: allocated.map(Bytes::new),
            link_count: 1,
            object: FileObjectEvidence {
                device: DeviceNumber::new(1),
                inode: InodeNumber::new(1),
            },
            counted_in_totals: true,
            owner: svalnir_core::process::Uid::new(0),
            modified: None,
            changed: None,
        }
    }

    #[test]
    fn a_child_with_no_size_is_a_gap_and_not_a_zero_byte_child() {
        let progress = |_: ScanProgress| {};
        let root = Path::new("/r");
        let mut observer = ChildObserver::new(root, &progress);
        let socket = PathBuf::from("/r/socket");
        let file = PathBuf::from("/r/file");
        observer.entry_measured(&record(&socket, EntryKind::Other, None, None));
        observer.entry_measured(&record(&file, EntryKind::File, Some(10), Some(4096)));
        let (children, unsized_children) = observer.into_children();
        assert_eq!(unsized_children, 1);
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].name, "file");
    }
}
