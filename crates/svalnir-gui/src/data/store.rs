//! The application model: the latest snapshots and the poll loop.

use super::{
    DataSource,
    model::{
        AgentSnapshot, HostSnapshot, Loadable, Measured, PressureLevel, ScanProgress, ScanState,
        ServiceSnapshot,
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

/// The latest host and agent snapshots of one source.
#[derive(Debug)]
pub struct AppModel {
    source: Arc<dyn DataSource>,
    /// The host reading.
    pub host: Loadable<HostSnapshot>,
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
            agent: Loadable::Loading,
            service: Loadable::Loading,
            scan: ScanState::Idle,
            scan_notice: None,
            default_root: None,
            pending_scan: None,
            scan_cancel: None,
            scan_task: None,
            scan_ticker: None,
            last_refresh: None,
            active: true,
            in_flight: InFlight::default(),
            _poll: poll,
        };
        model.refresh(cx);
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
                        Ok(summary) => ScanState::Done(Arc::new(summary)),
                        Err(reason) => ScanState::Failed {
                            root: failed_root,
                            reason,
                        },
                    };
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
        if !self.in_flight.host {
            self.in_flight.host = true;
            let source: Arc<dyn DataSource> = Arc::clone(&self.source);
            cx.spawn(async move |this, cx: &mut AsyncApp| {
                let result = cx.background_spawn(async move { source.host() }).await;
                if this
                    .update(cx, |model, cx| {
                        model.in_flight.host = false;
                        model.host = match result {
                            Ok(snapshot) => Loadable::Ready(Arc::new(snapshot)),
                            Err(reason) => Loadable::Unavailable(reason),
                        };
                        model.last_refresh = Some(SystemTime::now());
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

    #[test]
    fn scan_allowed_by_pressure() {
        let snapshot = |pressure: Measured<PressureLevel>| -> Loadable<HostSnapshot> {
            Loadable::Ready(Arc::new(HostSnapshot {
                captured_at: SystemTime::UNIX_EPOCH,
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
