//! The application model: the latest snapshots and the poll loop.

use super::{
    DataSource,
    model::{
        AgentSnapshot, HostSnapshot, Loadable, Measured, PressureLevel, ScanEnd, ScanProgress,
        ScanState, ScanSummary, ServiceSnapshot,
    },
};
use gpui_kit::{AppContext as _, AsyncApp, Context, Task};
use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant, SystemTime},
};
use svalnir_agent::scan::CancellationToken;

/// How often the model copies the scan progress.
const PROGRESS_TICK: Duration = Duration::from_millis(100);
/// The reason that a scan does not start under memory pressure.
const PRESSURE_REFUSAL: &str = "A scan does not start while memory pressure is not normal.";

/// The refusal while the pressure reading is stale.
const STALE_REFUSAL: &str = "The memory pressure reading is stale. Refresh, then scan again.";

/// The decision of the scan gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanGate {
    /// The scan may start now.
    Start,
    /// The first host reading is not here; the request waits for it.
    Wait,
    /// The scan is refused; the text is the sentence for the user.
    Refuse(&'static str),
}

/// Whether a scan may start. A scan does not start while the memory
/// pressure is Warning or Critical, or while the reading is `Stale`. While
/// the host is `Loading` the request waits. An `Unavailable` host and an
/// unavailable pressure value do not block: a failed query is not a refusal.
#[must_use]
pub fn scan_allowed(host: &Loadable<HostSnapshot>) -> ScanGate {
    match host {
        Loadable::Loading => ScanGate::Wait,
        Loadable::Unavailable(_) => ScanGate::Start,
        Loadable::Stale(_) => ScanGate::Refuse(STALE_REFUSAL),
        Loadable::Ready(snapshot) => match &snapshot.pressure {
            Measured::Value(PressureLevel::Warning | PressureLevel::Critical) => {
                ScanGate::Refuse(PRESSURE_REFUSAL)
            }
            _ => ScanGate::Start,
        },
    }
}

/// The poll interval while the window is active.
pub const ACTIVE_INTERVAL: Duration = Duration::from_secs(2);
/// The poll interval while the window is not active.
pub const INACTIVE_INTERVAL: Duration = Duration::from_secs(30);
/// A value is stale when it is older than this many intervals.
pub const STALE_INTERVALS: u32 = 3;

/// The poll interval for the activity of the window.
#[must_use]
pub const fn next_interval(active: bool) -> Duration {
    if active {
        ACTIVE_INTERVAL
    } else {
        INACTIVE_INTERVAL
    }
}

/// Whether a value captured at `captured_at` is older than three intervals
/// at `now`. A capture time in the future is not stale.
#[must_use]
pub fn is_stale(captured_at: SystemTime, now: SystemTime, interval: Duration) -> bool {
    now.duration_since(captured_at)
        .is_ok_and(|age| age > interval * STALE_INTERVALS)
}

/// The reads that run now, one flag for each kind.
#[derive(Debug, Default, Clone, Copy)]
struct InFlight {
    host: bool,
    agent: bool,
    service: bool,
}

/// The most scan roots that keep an earlier result.
pub const SCAN_ROOTS_MAX: usize = 8;

/// The latest finished scan of one root and the one before it.
#[derive(Debug, Clone)]
struct ScanRecord {
    latest: Arc<ScanSummary>,
    earlier: Option<Arc<ScanSummary>>,
}

/// Records the finished scan `summary` in `records`: the earlier latest scan
/// of the same root becomes the earlier result. A cancelled scan changes
/// nothing. At most [`SCAN_ROOTS_MAX`] roots stay; the oldest goes first.
fn record_scan(records: &mut Vec<ScanRecord>, summary: &Arc<ScanSummary>) {
    if summary.ended == ScanEnd::Cancelled {
        return;
    }
    let earlier: Option<Arc<ScanSummary>> = records
        .iter()
        .position(|r| r.latest.root == summary.root)
        .map(|index| records.remove(index).latest);
    records.push(ScanRecord {
        latest: Arc::clone(summary),
        earlier,
    });
    while records.len() > SCAN_ROOTS_MAX {
        records.remove(0);
    }
}

/// The latest host and agent snapshots of one source.
#[derive(Debug)]
pub struct AppModel {
    source: Arc<dyn DataSource>,
    /// The host reading.
    pub host: Loadable<HostSnapshot>,
    /// The recent host readings, oldest first, at most `HISTORY_MAX`.
    pub history: std::collections::VecDeque<crate::data::model::HostSample>,
    /// The agent state.
    pub agent: Loadable<AgentSnapshot>,
    /// The guards and the latest operation.
    pub service: Loadable<ServiceSnapshot>,
    /// The state of the scan of the Storage screen.
    pub scan: ScanState,
    /// A refusal that does not replace a finished result.
    pub scan_notice: Option<String>,
    /// The root that the Storage screen offers first. A background probe
    /// fills it once, so that `render` never touches the file system.
    default_root: Option<PathBuf>,
    pending_scan: Option<PathBuf>,
    scan_records: Vec<ScanRecord>,
    rescan_once: bool,
    scan_cancel: Option<CancellationToken>,
    scan_task: Option<Task<()>>,
    scan_ticker: Option<Task<()>>,
    source_label: &'static str,
    fixture_name: Option<&'static str>,
    last_refresh: Option<SystemTime>,
    active: bool,
    in_flight: InFlight,
    _poll: Task<()>,
}

impl AppModel {
    /// Creates the model, starts the first load, and starts the poll loop.
    pub fn new(source: Arc<dyn DataSource>, cx: &mut Context<Self>) -> Self {
        Self::new_seeded(source, 0, cx)
    }

    /// Like [`Self::new`], but takes `readings` host readings at once, through
    /// the same path as a refresh, so the history has that many samples
    /// before the first paint. With 0 it is the same as `new`.
    pub fn new_seeded(
        source: Arc<dyn DataSource>,
        readings: usize,
        cx: &mut Context<Self>,
    ) -> Self {
        let poll: Task<()> = cx.spawn(async move |this, cx: &mut AsyncApp| {
            loop {
                let interval: Option<Duration> =
                    this.update(cx, |model, _| next_interval(model.active)).ok();
                let Some(interval) = interval else { break };
                cx.background_executor().timer(interval).await;
                let alive: bool = this
                    .update(cx, |model, cx| {
                        model.mark_stale();
                        model.refresh(cx);
                        cx.notify();
                    })
                    .is_ok();
                if !alive {
                    break;
                }
            }
        });
        let mut model = Self {
            source_label: source.label(),
            fixture_name: source.fixture_name(),
            source,
            host: Loadable::Loading,
            history: std::collections::VecDeque::new(),
            agent: Loadable::Loading,
            service: Loadable::Loading,
            scan: ScanState::Idle,
            scan_notice: None,
            default_root: None,
            pending_scan: None,
            scan_records: Vec::new(),
            rescan_once: false,
            scan_cancel: None,
            scan_task: None,
            scan_ticker: None,
            last_refresh: None,
            active: true,
            in_flight: InFlight::default(),
            _poll: poll,
        };
        if readings == 0 {
            model.refresh(cx);
        } else {
            for _ in 0..readings {
                let result: Result<HostSnapshot, String> = model.source.host();
                model.apply_host(result);
            }
            model.mark_stale();
            model.refresh_kinds(false, cx);
        }
        let probe: Arc<dyn DataSource> = Arc::clone(&model.source);
        cx.spawn(async move |this, cx: &mut AsyncApp| {
            let root: Option<PathBuf> = cx
                .background_executor()
                .spawn(async move { probe.default_scan_root() })
                .await;
            // The model can be gone before the probe ends; nothing to do then.
            let _alive: bool = this
                .update(cx, |model, cx| {
                    model.default_root = root;
                    cx.notify();
                })
                .is_ok();
        })
        .detach();
        model
    }

    /// The root that the Storage screen offers first.
    #[must_use]
    pub fn default_scan_root(&self) -> Option<PathBuf> {
        self.default_root.clone()
    }

    /// The result that `summary` is compared with: the scan of the same root
    /// before it. `None` when `summary` is not the latest finished scan of
    /// its root (a cancelled scan) or when there is no earlier scan.
    #[must_use]
    pub fn earlier_scan(&self, summary: &Arc<ScanSummary>) -> Option<Arc<ScanSummary>> {
        self.scan_records
            .iter()
            .find(|r| Arc::ptr_eq(&r.latest, summary))
            .and_then(|r| r.earlier.clone())
    }

    /// Asks for one more scan of the same root when the next scan ends with
    /// a result. The launch option `--rescan` sets it.
    pub fn set_rescan_once(&mut self, on: bool) {
        self.rescan_once = on;
    }

    /// Starts a scan of `root`. A request while a scan runs is ignored. A
    /// scan under memory pressure is refused.
    pub fn start_scan(&mut self, root: &Path, cx: &mut Context<Self>) {
        if matches!(self.scan, ScanState::Running { .. }) {
            return;
        }
        match scan_allowed(&self.host) {
            ScanGate::Start => {}
            ScanGate::Wait => {
                self.pending_scan = Some(root.to_path_buf());
                return;
            }
            ScanGate::Refuse(reason) => {
                if matches!(self.scan, ScanState::Done(_)) {
                    self.scan_notice = Some(reason.to_owned());
                } else {
                    self.scan = ScanState::Failed {
                        root: root.to_path_buf(),
                        reason: reason.to_owned(),
                    };
                }
                cx.notify();
                return;
            }
        }
        self.pending_scan = None;
        self.scan_notice = None;
        let cancel: CancellationToken = CancellationToken::new();
        self.scan_cancel = Some(cancel.clone());
        self.scan = ScanState::Running {
            root: root.to_path_buf(),
            progress: ScanProgress::default(),
            started: Instant::now(),
        };
        let slot: Arc<Mutex<Option<ScanProgress>>> = Arc::new(Mutex::new(None));
        let source: Arc<dyn DataSource> = Arc::clone(&self.source);
        let scan_root: PathBuf = root.to_path_buf();
        let worker_slot: Arc<Mutex<Option<ScanProgress>>> = Arc::clone(&slot);
        let job = cx.background_spawn(async move {
            let publish = |progress: ScanProgress| {
                *worker_slot.lock().unwrap_or_else(PoisonError::into_inner) = Some(progress);
            };
            source.scan(&scan_root, &cancel, &publish)
        });
        let failed_root: PathBuf = root.to_path_buf();
        self.scan_task = Some(cx.spawn(async move |this, cx: &mut AsyncApp| {
            let result = job.await;
            if this
                .update(cx, |model, cx| {
                    model.scan_cancel = None;
                    model.scan_ticker = None;
                    model.scan = match result {
                        Ok(summary) => {
                            let summary: Arc<ScanSummary> = Arc::new(summary);
                            record_scan(&mut model.scan_records, &summary);
                            ScanState::Done(summary)
                        }
                        Err(reason) => ScanState::Failed {
                            root: failed_root.clone(),
                            reason,
                        },
                    };
                    // The model observes its own scan state: a requested
                    // second scan starts when the first one has a result.
                    // A scan that the user cancelled does not start it.
                    let finished: bool = matches!(
                        &model.scan,
                        ScanState::Done(summary) if summary.ended != ScanEnd::Cancelled
                    );
                    if model.rescan_once && finished {
                        model.rescan_once = false;
                        model.start_scan(&failed_root, cx);
                    }
                    cx.notify();
                })
                .is_err()
            {
                tracing::debug!("the model closed before the scan finished");
            }
        }));
        // The latest value wins: the ticker copies the slot into the model.
        self.scan_ticker = Some(cx.spawn(async move |this, cx: &mut AsyncApp| {
            loop {
                cx.background_executor().timer(PROGRESS_TICK).await;
                let latest: Option<ScanProgress> =
                    slot.lock().unwrap_or_else(PoisonError::into_inner).take();
                let alive: bool = this
                    .update(cx, |model, cx| {
                        if let ScanState::Running { progress, .. } = &mut model.scan {
                            if let Some(latest) = latest {
                                *progress = latest;
                            }
                            // The elapsed time changes at every tick.
                            cx.notify();
                        }
                        matches!(model.scan, ScanState::Running { .. })
                    })
                    .unwrap_or(false);
                if !alive {
                    break;
                }
            }
        }));
        cx.notify();
    }

    /// Asks the running scan to stop. The scan returns the part that it read.
    pub fn cancel_scan(&mut self) {
        if let Some(cancel) = &self.scan_cancel {
            cancel.cancel();
        }
    }

    /// The label of the source.
    #[must_use]
    pub fn source_label(&self) -> &'static str {
        self.source_label
    }

    /// The fixture scenario name, when the source is a fixture.
    #[must_use]
    pub fn fixture_name(&self) -> Option<&'static str> {
        self.fixture_name
    }

    /// When the last refresh finished.
    #[must_use]
    pub fn last_refresh(&self) -> Option<SystemTime> {
        self.last_refresh
    }

    /// Whether the window is active.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Sets the activity of the window; it selects the poll interval.
    pub fn set_active(&mut self, active: bool, cx: &mut Context<Self>) {
        if self.active != active {
            self.active = active;
            if active {
                self.refresh(cx);
            }
        }
    }

    /// Starts one background read of each kind. A request for a kind that is
    /// in flight is dropped.
    pub fn refresh(&mut self, cx: &mut Context<Self>) {
        self.refresh_kinds(true, cx);
    }

    /// Stores one host reading: the latest value and the history sample.
    fn apply_host(&mut self, result: Result<HostSnapshot, String>) {
        self.host = match result {
            Ok(snapshot) => {
                crate::data::model::push_bounded(
                    &mut self.history,
                    crate::data::model::HostSample::of(&snapshot),
                    crate::data::model::HISTORY_MAX,
                );
                Loadable::Ready(Arc::new(snapshot))
            }
            Err(reason) => Loadable::Unavailable(reason),
        };
        self.last_refresh = Some(SystemTime::now());
    }

    /// Starts the reads; the host read only when `host` is true.
    fn refresh_kinds(&mut self, host: bool, cx: &mut Context<Self>) {
        if host && !self.in_flight.host {
            self.in_flight.host = true;
            let source: Arc<dyn DataSource> = Arc::clone(&self.source);
            cx.spawn(async move |this, cx: &mut AsyncApp| {
                let result = cx.background_spawn(async move { source.host() }).await;
                if this
                    .update(cx, |model, cx| {
                        model.in_flight.host = false;
                        model.apply_host(result);
                        model.mark_stale();
                        if let Some(root) = model.pending_scan.take() {
                            model.start_scan(&root, cx);
                        }
                        cx.notify();
                    })
                    .is_err()
                {
                    tracing::debug!("the model closed before the read finished");
                }
            })
            .detach();
        }
        if !self.in_flight.agent {
            self.in_flight.agent = true;
            let source: Arc<dyn DataSource> = Arc::clone(&self.source);
            cx.spawn(async move |this, cx: &mut AsyncApp| {
                let snapshot = cx.background_spawn(async move { source.agent() }).await;
                if this
                    .update(cx, |model, cx| {
                        model.in_flight.agent = false;
                        model.agent = Loadable::Ready(Arc::new(snapshot));
                        cx.notify();
                    })
                    .is_err()
                {
                    tracing::debug!("the model closed before the read finished");
                }
            })
            .detach();
        }
        if !self.in_flight.service {
            self.in_flight.service = true;
            let source: Arc<dyn DataSource> = Arc::clone(&self.source);
            cx.spawn(async move |this, cx: &mut AsyncApp| {
                let snapshot = cx.background_spawn(async move { source.service() }).await;
                if this
                    .update(cx, |model, cx| {
                        model.in_flight.service = false;
                        model.service = Loadable::Ready(Arc::new(snapshot));
                        cx.notify();
                    })
                    .is_err()
                {
                    tracing::debug!("the model closed before the read finished");
                }
            })
            .detach();
        }
    }

    /// Turns a `Ready` value that is stale into `Stale`.
    fn mark_stale(&mut self) {
        let now: SystemTime = SystemTime::now();
        let interval: Duration = next_interval(self.active);
        if let Loadable::Ready(snapshot) = &self.host
            && is_stale(snapshot.captured_at, now, interval)
        {
            self.host = Loadable::Stale(Arc::clone(snapshot));
        }
        if let Loadable::Ready(snapshot) = &self.agent
            && is_stale(snapshot.captured_at, now, interval)
        {
            self.agent = Loadable::Stale(Arc::clone(snapshot));
        }
        if let Loadable::Ready(snapshot) = &self.service
            && is_stale(snapshot.captured_at, now, interval)
        {
            self.service = Loadable::Stale(Arc::clone(snapshot));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summary(root: &str, ended: ScanEnd) -> Arc<ScanSummary> {
        Arc::new(ScanSummary {
            root: PathBuf::from(root),
            children: Vec::new(),
            total_logical: 0,
            total_allocated: 0,
            entries_examined: 0,
            complete: true,
            ended,
            gaps: Vec::new(),
            elapsed: None,
            finished_at: SystemTime::UNIX_EPOCH,
        })
    }

    #[test]
    fn a_scan_keeps_one_earlier_result_for_each_root() {
        let mut records: Vec<ScanRecord> = Vec::new();
        let first = summary("/a", ScanEnd::Finished);
        record_scan(&mut records, &first);
        assert!(records[0].earlier.is_none());
        let second = summary("/a", ScanEnd::Finished);
        record_scan(&mut records, &second);
        assert_eq!(records.len(), 1);
        assert!(
            records[0]
                .earlier
                .as_ref()
                .is_some_and(|e| Arc::ptr_eq(e, &first))
        );
        // A cancelled scan replaces nothing.
        record_scan(&mut records, &summary("/a", ScanEnd::Cancelled));
        assert!(Arc::ptr_eq(&records[0].latest, &second));
    }

    #[test]
    fn at_most_eight_roots_stay() {
        let mut records: Vec<ScanRecord> = Vec::new();
        for index in 0..12 {
            record_scan(
                &mut records,
                &summary(&format!("/r{index}"), ScanEnd::Finished),
            );
        }
        assert_eq!(records.len(), SCAN_ROOTS_MAX);
        assert_eq!(records[0].latest.root, PathBuf::from("/r4"));
    }

    #[test]
    fn scan_allowed_by_pressure() {
        let snapshot = |pressure: Measured<PressureLevel>| -> Loadable<HostSnapshot> {
            Loadable::Ready(Arc::new(HostSnapshot {
                captured_at: SystemTime::UNIX_EPOCH,
                utc_offset: None,
                volume_name: None,
                disk_total: Measured::Unavailable(String::new()),
                disk_available: Measured::Unavailable(String::new()),
                disk_free: Measured::Unavailable(String::new()),
                pressure,
                memory_total: Measured::Unavailable(String::new()),
                swap_used: Measured::Unavailable(String::new()),
                swap_total: Measured::Unavailable(String::new()),
                source: "test",
            }))
        };
        let start = |host: &Loadable<HostSnapshot>| scan_allowed(host) == ScanGate::Start;
        let refused =
            |host: &Loadable<HostSnapshot>| matches!(scan_allowed(host), ScanGate::Refuse(_));
        assert!(start(&snapshot(Measured::Value(PressureLevel::Normal))));
        assert!(start(&snapshot(Measured::Unavailable("x".into()))));
        assert!(refused(&snapshot(Measured::Value(PressureLevel::Warning))));
        assert!(refused(&snapshot(Measured::Value(PressureLevel::Critical))));
        assert_eq!(scan_allowed(&Loadable::Loading), ScanGate::Wait);
        assert!(start(&Loadable::Unavailable("x".into())));
        let Loadable::Ready(stale) = snapshot(Measured::Value(PressureLevel::Normal)) else {
            return;
        };
        assert_eq!(
            scan_allowed(&Loadable::Stale(stale)),
            ScanGate::Refuse(STALE_REFUSAL)
        );
    }

    #[test]
    fn interval_follows_activity() {
        assert_eq!(next_interval(true), Duration::from_secs(2));
        assert_eq!(next_interval(false), Duration::from_secs(30));
    }

    #[test]
    fn stale_after_three_intervals() {
        let now: SystemTime = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
        let interval: Duration = Duration::from_secs(2);
        assert!(!is_stale(now - Duration::from_secs(6), now, interval));
        assert!(is_stale(now - Duration::from_secs(7), now, interval));
        assert!(!is_stale(now + Duration::from_secs(60), now, interval));
    }
}
