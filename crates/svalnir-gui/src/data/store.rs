//! The application model: the latest snapshots and the poll loop.

use super::{
    DataSource,
    model::{AgentSnapshot, HostSnapshot, Loadable, ServiceSnapshot},
};
use gpui_kit::{AppContext as _, AsyncApp, Context, Task};
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

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
            last_refresh: None,
            active: true,
            in_flight: InFlight::default(),
            _poll: poll,
        };
        model.refresh(cx);
        model
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
