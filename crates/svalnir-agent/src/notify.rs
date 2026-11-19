//! The system notifications of the agent (owner decision 7 of 2026-11-19:
//! the agent posts them, and the GPUI client does not).
//!
//! The agent posts a notification at a meaningful change of state, also
//! when no window is open:
//!
//! | Kind | When |
//! | --- | --- |
//! | [`NoticeKind::MemoryPressureCritical`] | The memory pressure state of the host changes to critical. Not for the first value that the agent reads. |
//! | [`NoticeKind::GuardActing`] | A guard starts an automatic operation (its phase changes to `Acting`). |
//! | [`NoticeKind::IncidentBudgetExhausted`] | A ceiling of an incident admits no further automatic work. |
//! | [`NoticeKind::AutomaticOperationNotCompleted`] | An automatic operation settles in a state that is not `Completed` or `NoAction`. |
//! | [`NoticeKind::StopSettled`] | A stop of an application that a person requested has its final record. |
//! | [`NoticeKind::ManualOperationNotCompleted`] | A different operation that a person requested settles in a state that is not `Completed` or `NoAction`. |
//!
//! The two client conditions "the agent stopped reporting" and "the agent
//! did not answer a request" are not here: the agent cannot see its own
//! absence.
//!
//! A notice has identities, guard names, and state names. It has no path,
//! no process argument, no process name, and no secret.
//!
//! # Delivery
//!
//! [`NotificationService`] is the only path from the agent to a
//! [`NotificationCenter`]. A notice goes through three bounds before a post:
//!
//! 1. [`NoticeGate`]: the same tag posts at most one time in
//!    [`TAG_INTERVAL`], and all tags together at most [`RATE_LIMIT`] times
//!    in [`RATE_WINDOW`]. An incident thus cannot post a flood.
//! 2. The queue: at most [`QUEUE_CAPACITY`] notices wait. A new notice
//!    replaces a waiting notice with the same tag; when the queue is full,
//!    the oldest waiting notice is dropped. An offer never waits for the
//!    center.
//! 3. One worker thread takes the notices and calls the center. A slow or
//!    blocked center stalls only that thread, never the controller or the
//!    coordinator.
//!
//! An authorization that is denied or not available is a reported
//! capability ([`NotificationStatus`] in the status record of the agent and
//! a row of `svalnir doctor`), not an error. Nothing in this module asks
//! the user for a permission.
//!
//! # The center of this build
//!
//! This build has no native center: [`UnavailableCenter`] reports the
//! capability as `unsupported` and posts nothing. Apple Developer Technical
//! Support states that the User Notifications framework does not deliver
//! for a launchd agent that runs from an executable inside the application
//! bundle (Apple Developer Forums thread 804854); the agent of `Svalnir.app`
//! is such an agent.
// TODO(npochaev): add a native center when the bundle has a component that
// the User Notifications framework accepts (for example a nested
// `LSUIElement` application that Launch Services starts in the login
// session), and decide when the agent asks for the authorization.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};

use serde::{Deserialize, Serialize};
use svalnir_core::action::OperationState;
use svalnir_core::quantity::Nanoseconds;
use svalnir_core::state::{CapabilityState, PressureState};
use svalnir_core::time::MonotonicNanos;

use crate::controller::{BlockedReason, Guard, GuardPhase, Notification};
use crate::coordinator::SettledOperation;
use crate::runtime::Notifier;

/// The largest number of notices that wait for the center.
pub const QUEUE_CAPACITY: usize = 8;

/// The shortest time between two posts with the same tag: 15 minutes.
pub const TAG_INTERVAL: Nanoseconds = Nanoseconds::new(15 * 60 * 1_000_000_000);

/// The window of [`RATE_LIMIT`]: 10 minutes.
pub const RATE_WINDOW: Nanoseconds = Nanoseconds::new(10 * 60 * 1_000_000_000);

/// The largest number of notices that the gate admits in [`RATE_WINDOW`].
pub const RATE_LIMIT: usize = 6;

/// The largest number of tags that the gate remembers. A tag that it
/// forgets can post again before [`TAG_INTERVAL`]; [`RATE_LIMIT`] still
/// applies.
pub const MAX_GATE_TAGS: usize = 64;

/// The kind of a notice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoticeKind {
    /// The memory pressure state changed to critical.
    MemoryPressureCritical,
    /// A guard started an automatic operation.
    GuardActing,
    /// A ceiling of an incident admits no further automatic work.
    IncidentBudgetExhausted,
    /// An automatic operation did not complete.
    AutomaticOperationNotCompleted,
    /// A requested application stop has its final record.
    StopSettled,
    /// A different requested operation did not complete.
    ManualOperationNotCompleted,
}

/// One notification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {
    /// The kind.
    pub kind: NoticeKind,
    /// The tag of the condition. A notice with the same tag replaces the
    /// earlier one in the queue and in the notification center.
    pub tag: String,
    /// The headline.
    pub title: String,
    /// One or two sentences.
    pub body: String,
}

const fn guard_name(guard: Guard) -> &'static str {
    match guard {
        Guard::Disk => "disk",
        Guard::Memory => "memory",
    }
}

/// True for a settled state that a person must know: the operation did not
/// do all that its plan asked.
fn not_completed(state: &OperationState) -> bool {
    !matches!(state, OperationState::Completed | OperationState::NoAction)
}

fn exhausted(guard: Guard) -> Notice {
    let name: &str = guard_name(guard);
    Notice {
        kind: NoticeKind::IncidentBudgetExhausted,
        tag: format!("svalnir-guard-{name}-exhausted"),
        title: format!("The {name} guard reached its incident budget"),
        body: "A ceiling of the incident admits no further automatic work until the incident ends or a person rearms it. See Automation.".to_owned(),
    }
}

/// The notice of a notification of the controller, when it has one.
#[must_use]
pub fn controller_notice(notification: &Notification) -> Option<Notice> {
    match notification {
        Notification::Phase {
            guard,
            phase: GuardPhase::Acting,
        } => {
            let name: &str = guard_name(*guard);
            Some(Notice {
                kind: NoticeKind::GuardActing,
                tag: format!("svalnir-guard-{name}-acting"),
                title: format!("The {name} guard acts"),
                body: format!(
                    "The {name} guard started an automatic operation under its standing policy. See Automation."
                ),
            })
        }
        Notification::Phase {
            guard,
            phase: GuardPhase::Exhausted,
        }
        | Notification::Blocked {
            guard,
            reason: BlockedReason::Exhausted,
        } => Some(exhausted(*guard)),
        Notification::Finished {
            guard,
            plan_id,
            state,
            ..
        } => {
            let settled: OperationState = OperationState::from_wire(state);
            if !not_completed(&settled) {
                return None;
            }
            let name: &str = guard_name(*guard);
            Some(Notice {
                kind: NoticeKind::AutomaticOperationNotCompleted,
                tag: format!("svalnir-plan-{plan_id}"),
                title: format!("An automatic operation of the {name} guard did not complete"),
                body: outcome_sentence(&settled),
            })
        }
        Notification::Phase { .. } | Notification::Blocked { .. } => None,
    }
}

fn outcome_sentence(state: &OperationState) -> String {
    if *state == OperationState::UnknownOutcome {
        "Its effect is not known. Its leases stay until a reconciliation or `svalnir operations acknowledge`. See History.".to_owned()
    } else {
        format!(
            "It ended in the state {}. See History for each target.",
            state.as_str()
        )
    }
}

/// The notice of an operation that the coordinator settled, when it has
/// one. An automatic operation has its notice from the controller
/// ([`controller_notice`]), so this function gives none for it.
#[must_use]
pub fn settled_notice(operation: &SettledOperation) -> Option<Notice> {
    if operation.automatic {
        return None;
    }
    let id = &operation.operation_id;
    if operation.stops_application {
        let title: String = if operation.state == OperationState::Completed {
            "Stop: completed".to_owned()
        } else {
            format!("Stop: {}", operation.state.as_str())
        };
        let body: String = if operation.state == OperationState::Completed {
            "The requested stop has its final record: each process of the target exited. See History.".to_owned()
        } else {
            outcome_sentence(&operation.state)
        };
        return Some(Notice {
            kind: NoticeKind::StopSettled,
            tag: format!("svalnir-stop-{id}"),
            title,
            body,
        });
    }
    not_completed(&operation.state).then(|| Notice {
        kind: NoticeKind::ManualOperationNotCompleted,
        tag: format!("svalnir-operation-{id}"),
        title: "A requested operation did not complete".to_owned(),
        body: outcome_sentence(&operation.state),
    })
}

/// The notice of a pressure reading: at a change from a different reading
/// to critical. `None` is a reading that is not a value; it changes
/// nothing.
#[derive(Debug, Default)]
pub struct PressureWatch {
    last: Option<PressureState>,
}

impl PressureWatch {
    /// The notice of `reading`, when it is a change to critical.
    pub fn observe(&mut self, reading: Option<&PressureState>) -> Option<Notice> {
        let reading: &PressureState = reading?;
        let before: Option<PressureState> = self.last.replace(reading.clone());
        (*reading == PressureState::Critical
            && before.is_some_and(|before| before != PressureState::Critical))
        .then(|| Notice {
            kind: NoticeKind::MemoryPressureCritical,
            tag: "svalnir-memory-pressure".to_owned(),
            title: "Memory pressure is critical".to_owned(),
            body: "The system memory pressure state changed to critical. See Memory for the footprint of each application.".to_owned(),
        })
    }
}

/// The decision of the gate on one notice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// The notice goes to the queue.
    Admitted,
    /// The same tag posted less than [`TAG_INTERVAL`] ago.
    Coalesced,
    /// [`RATE_LIMIT`] notices were admitted in the last [`RATE_WINDOW`].
    RateLimited,
}

/// The rate bound of the notices, on the monotonic clock of the agent.
#[derive(Debug, Default)]
pub struct NoticeGate {
    /// The time of the latest admission of each tag.
    last: BTreeMap<String, MonotonicNanos>,
    /// The times of the admissions in the window, oldest first.
    admitted: VecDeque<MonotonicNanos>,
}

/// True when `at` is less than `interval` before `now`. A time after
/// `now`, of a different timeline, is not recent.
fn within(at: MonotonicNanos, now: MonotonicNanos, interval: Nanoseconds) -> bool {
    now.checked_duration_since(at)
        .is_some_and(|age| age < interval)
}

impl NoticeGate {
    /// Decides one notice with the tag `tag` at `now`.
    pub fn admit(&mut self, tag: &str, now: MonotonicNanos) -> Admission {
        if self
            .last
            .get(tag)
            .is_some_and(|at| within(*at, now, TAG_INTERVAL))
        {
            return Admission::Coalesced;
        }
        while self
            .admitted
            .front()
            .is_some_and(|at| !within(*at, now, RATE_WINDOW))
        {
            self.admitted.pop_front();
        }
        if self.admitted.len() >= RATE_LIMIT {
            return Admission::RateLimited;
        }
        self.admitted.push_back(now);
        self.last.insert(tag.to_owned(), now);
        if self.last.len() > MAX_GATE_TAGS {
            // The tag with the oldest admission goes first.
            if let Some(oldest) = self
                .last
                .iter()
                .min_by_key(|(_, at)| at.get())
                .map(|(tag, _)| tag.clone())
            {
                self.last.remove(&oldest);
            }
        }
        Admission::Admitted
    }
}

/// The authorization of the notifications of this process, as the center
/// reports it. Reading it never asks the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CenterAuthorization {
    /// The center did not report yet.
    NotRead,
    /// The user permits the notifications.
    Authorized,
    /// The center delivers quietly to the notification history.
    Provisional,
    /// The user turned the notifications off.
    Denied,
    /// The user did not decide, and the agent did not ask.
    NotDetermined,
    /// This process cannot post notifications.
    Unavailable,
}

impl CenterAuthorization {
    /// The capability state of the authorization.
    #[must_use]
    pub fn capability(self) -> CapabilityState {
        match self {
            Self::Authorized | Self::Provisional => CapabilityState::Available,
            Self::Denied => CapabilityState::Denied,
            Self::Unavailable => CapabilityState::Unsupported,
            Self::NotRead | Self::NotDetermined => CapabilityState::Unknown,
        }
    }

    const fn permits_posts(self) -> bool {
        matches!(self, Self::Authorized | Self::Provisional)
    }
}

/// The reason a post failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PostError {
    /// The center refused the post because of the authorization.
    NotAuthorized,
    /// The center did not take the post. The text has no path.
    Failed(String),
}

/// A system notification center. A test uses a fake; this build has
/// [`UnavailableCenter`] only.
///
/// The worker thread of [`NotificationService`] calls it; a call can block
/// that thread.
pub trait NotificationCenter: Send {
    /// The authorization, with the reason as one sentence. This call never
    /// asks the user.
    fn authorization(&mut self) -> (CenterAuthorization, String);

    /// Posts one notice.
    ///
    /// # Errors
    ///
    /// Returns a [`PostError`] when the center did not take the notice.
    fn post(&mut self, notice: &Notice) -> Result<(), PostError>;
}

/// The center of a build with no native adapter: it posts nothing.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnavailableCenter;

/// The reason of [`UnavailableCenter`].
pub const UNAVAILABLE_REASON: &str = "This build has no notification adapter for the agent: the User Notifications framework does not deliver notifications for a launchd agent that runs from an executable inside the application bundle.";

impl NotificationCenter for UnavailableCenter {
    fn authorization(&mut self) -> (CenterAuthorization, String) {
        (
            CenterAuthorization::Unavailable,
            UNAVAILABLE_REASON.to_owned(),
        )
    }

    fn post(&mut self, _notice: &Notice) -> Result<(), PostError> {
        Err(PostError::NotAuthorized)
    }
}

/// What happened to the notices of this agent lifetime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct NotificationCounts {
    /// Notices that the center took.
    pub posted: u64,
    /// Notices that the gate or the queue joined with a notice of the same
    /// tag.
    pub coalesced: u64,
    /// Notices that the rate limit refused.
    pub rate_limited: u64,
    /// Notices that a full or closed queue dropped.
    pub dropped: u64,
    /// Notices that the authorization did not permit.
    pub not_authorized: u64,
    /// Notices that the center did not take for a different reason.
    pub failed: u64,
}

/// The notification capability of the agent, for its status record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationStatus {
    /// The capability state of the authorization.
    pub state: CapabilityState,
    /// The authorization that the center reported last.
    pub authorization: CenterAuthorization,
    /// One sentence about the state, from the center. It has no path.
    pub detail: String,
    /// What happened to the notices of this lifetime.
    pub counts: NotificationCounts,
}

#[derive(Debug)]
struct QueueState {
    pending: VecDeque<Notice>,
    closed: bool,
    authorization: CenterAuthorization,
    detail: String,
    counts: NotificationCounts,
}

#[derive(Debug)]
struct Shared {
    state: Mutex<QueueState>,
    ready: Condvar,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, QueueState> {
        // The state has counters and a queue only; a panic of the worker
        // leaves it usable.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The bounded delivery of the notices to one center.
#[derive(Debug)]
pub struct NotificationService {
    shared: Arc<Shared>,
    gate: NoticeGate,
    pressure: PressureWatch,
}

impl NotificationService {
    /// Starts the worker thread of `center`. When the thread does not
    /// start, the service drops each notice and reports the capability as
    /// unavailable.
    #[must_use]
    pub fn start(center: Box<dyn NotificationCenter>) -> Self {
        let shared: Arc<Shared> = Arc::new(Shared {
            state: Mutex::new(QueueState {
                pending: VecDeque::with_capacity(QUEUE_CAPACITY),
                closed: false,
                authorization: CenterAuthorization::NotRead,
                detail: "The notification center did not report yet.".to_owned(),
                counts: NotificationCounts::default(),
            }),
            ready: Condvar::new(),
        });
        let worker: Arc<Shared> = Arc::clone(&shared);
        let started = std::thread::Builder::new()
            .name("svalnir-notify".to_owned())
            .spawn(move || deliver(&worker, center));
        if started.is_err() {
            let mut state = shared.lock();
            state.closed = true;
            state.authorization = CenterAuthorization::Unavailable;
            "The notification thread did not start.".clone_into(&mut state.detail);
        }
        // The thread is not joined: a center that blocks must not stall
        // the stop of the agent. It ends at its next notice after
        // `close`, or with the process.
        Self {
            shared,
            gate: NoticeGate::default(),
            pressure: PressureWatch::default(),
        }
    }

    /// Offers `notice` at `now`. The call never waits for the center.
    pub fn offer(&mut self, notice: Notice, now: MonotonicNanos) {
        let admission: Admission = self.gate.admit(&notice.tag, now);
        let mut state = self.shared.lock();
        match admission {
            Admission::Coalesced => {
                state.counts.coalesced = state.counts.coalesced.saturating_add(1);
                return;
            }
            Admission::RateLimited => {
                state.counts.rate_limited = state.counts.rate_limited.saturating_add(1);
                return;
            }
            Admission::Admitted => {}
        }
        if state.closed {
            state.counts.dropped = state.counts.dropped.saturating_add(1);
            return;
        }
        if let Some(waiting) = state
            .pending
            .iter_mut()
            .find(|waiting| waiting.tag == notice.tag)
        {
            *waiting = notice;
            state.counts.coalesced = state.counts.coalesced.saturating_add(1);
            return;
        }
        if state.pending.len() >= QUEUE_CAPACITY {
            state.pending.pop_front();
            state.counts.dropped = state.counts.dropped.saturating_add(1);
        }
        state.pending.push_back(notice);
        drop(state);
        self.shared.ready.notify_one();
    }

    /// Offers the notice of a pressure reading, when it has one.
    pub fn observe_pressure(&mut self, reading: Option<&PressureState>, now: MonotonicNanos) {
        if let Some(notice) = self.pressure.observe(reading) {
            self.offer(notice, now);
        }
    }

    /// The capability and the counts now.
    #[must_use]
    pub fn status(&self) -> NotificationStatus {
        let state = self.shared.lock();
        NotificationStatus {
            state: state.authorization.capability(),
            authorization: state.authorization,
            detail: state.detail.clone(),
            counts: state.counts,
        }
    }

    /// The number of notices that wait for the center.
    #[must_use]
    pub fn waiting(&self) -> usize {
        self.shared.lock().pending.len()
    }

    /// Ends the delivery: the waiting notices are dropped, and the worker
    /// ends after the call to the center that runs now, if one runs.
    pub fn close(&self) {
        let mut state = self.shared.lock();
        state.closed = true;
        let dropped: u64 = u64::try_from(state.pending.len()).unwrap_or(u64::MAX);
        state.pending.clear();
        state.counts.dropped = state.counts.dropped.saturating_add(dropped);
        drop(state);
        self.shared.ready.notify_all();
    }
}

impl Drop for NotificationService {
    fn drop(&mut self) {
        self.close();
    }
}

/// The loop of the worker thread.
fn deliver(shared: &Shared, mut center: Box<dyn NotificationCenter>) {
    // The first reading, so that the status has the capability before the
    // first notice.
    let (authorization, detail) = center.authorization();
    {
        let mut state = shared.lock();
        state.authorization = authorization;
        state.detail = detail;
    }
    loop {
        let notice: Notice = {
            let mut state = shared.lock();
            loop {
                if state.closed {
                    return;
                }
                if let Some(notice) = state.pending.pop_front() {
                    break notice;
                }
                state = shared
                    .ready
                    .wait(state)
                    .unwrap_or_else(PoisonError::into_inner);
            }
        };
        // The center is called with no lock held: an offer does not wait
        // for it.
        let (authorization, detail) = center.authorization();
        let result: Result<(), PostError> = if authorization.permits_posts() {
            center.post(&notice)
        } else {
            Err(PostError::NotAuthorized)
        };
        let mut state = shared.lock();
        state.authorization = authorization;
        state.detail = detail;
        let counter: &mut u64 = match result {
            Ok(()) => &mut state.counts.posted,
            Err(PostError::NotAuthorized) => &mut state.counts.not_authorized,
            Err(PostError::Failed(_)) => &mut state.counts.failed,
        };
        *counter = counter.saturating_add(1);
    }
}

/// The notifier of the agent: it writes each notification of the
/// controller to the structured log, as the agent did before it posted
/// notifications, and offers the notice of each meaningful change to a
/// [`NotificationService`].
#[derive(Debug)]
pub struct AgentNotifier {
    service: NotificationService,
}

impl AgentNotifier {
    /// The notifier of `center`. It starts the worker thread.
    #[must_use]
    pub fn new(center: Box<dyn NotificationCenter>) -> Self {
        Self {
            service: NotificationService::start(center),
        }
    }
}

impl Notifier for AgentNotifier {
    fn notify(&mut self, notification: &Notification, at: MonotonicNanos) {
        // A notification has identities and reason names; it has no path
        // and no process argument.
        if let Ok(event) = serde_json::to_string(notification) {
            tracing::info!(%event, "controller notification");
        } else {
            tracing::warn!("a controller notification was not encoded");
        }
        if let Some(notice) = controller_notice(notification) {
            self.service.offer(notice, at);
        }
    }

    fn settled(&mut self, operation: &SettledOperation, at: MonotonicNanos) {
        if let Some(notice) = settled_notice(operation) {
            self.service.offer(notice, at);
        }
    }

    fn pressure(&mut self, reading: Option<&PressureState>, at: MonotonicNanos) {
        self.service.observe_pressure(reading, at);
    }

    fn status(&self) -> Option<NotificationStatus> {
        Some(self.service.status())
    }
}

/// A center for tests: it records the notices, and a test sets its
/// authorization, its failure, and a gate that holds each post. It never
/// posts a real notification and never asks for a permission.
#[cfg(any(test, feature = "test-support"))]
pub mod fake {
    use std::sync::{Arc, Condvar, Mutex, PoisonError};

    use super::{CenterAuthorization, Notice, NotificationCenter, PostError};

    /// The shared state of a [`FakeCenter`].
    #[derive(Debug)]
    pub struct FakeState {
        /// The authorization that the center reports.
        pub authorization: CenterAuthorization,
        /// The posts that the center took.
        pub posted: Vec<Notice>,
        /// When true, each post fails.
        pub fail: bool,
        /// When true, each post waits until a test sets it to false.
        pub hold: bool,
        /// The number of posts that wait now.
        pub held: usize,
    }

    /// A center that records its posts.
    #[derive(Debug, Clone)]
    pub struct FakeCenter {
        /// The state, which the test reads and changes.
        pub state: Arc<(Mutex<FakeState>, Condvar)>,
    }

    impl FakeCenter {
        /// A center with `authorization`.
        #[must_use]
        pub fn new(authorization: CenterAuthorization) -> Self {
            Self {
                state: Arc::new((
                    Mutex::new(FakeState {
                        authorization,
                        posted: Vec::new(),
                        fail: false,
                        hold: false,
                        held: 0,
                    }),
                    Condvar::new(),
                )),
            }
        }

        /// Changes the state and wakes a held post.
        pub fn with<T>(&self, change: impl FnOnce(&mut FakeState) -> T) -> T {
            let (lock, wake) = &*self.state;
            let mut state = lock.lock().unwrap_or_else(PoisonError::into_inner);
            let value: T = change(&mut state);
            wake.notify_all();
            value
        }
    }

    impl NotificationCenter for FakeCenter {
        fn authorization(&mut self) -> (CenterAuthorization, String) {
            let authorization = self.with(|state| state.authorization);
            (authorization, format!("fake: {authorization:?}"))
        }

        fn post(&mut self, notice: &Notice) -> Result<(), PostError> {
            let (lock, wake) = &*self.state;
            let mut state = lock.lock().unwrap_or_else(PoisonError::into_inner);
            state.held += 1;
            while state.hold {
                state = wake.wait(state).unwrap_or_else(PoisonError::into_inner);
            }
            state.held -= 1;
            if state.fail {
                return Err(PostError::Failed("fake failure".to_owned()));
            }
            state.posted.push(notice.clone());
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests;
