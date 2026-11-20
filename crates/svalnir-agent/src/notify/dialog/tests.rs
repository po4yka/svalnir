//! Tests of the dialog center. Each test uses a fake display: no test
//! shows a real dialog.

use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use svalnir_core::state::CapabilityState;
use svalnir_core::time::MonotonicNanos;

use super::{DIALOG_DETAIL, DialogCenter, DialogDisplay, DialogText, DisplayError, dialog_text};
use crate::notify::{
    CenterAuthorization, Notice, NoticeKind, NotificationService, NotificationStatus,
    QUEUE_CAPACITY, RATE_LIMIT, RATE_WINDOW, fixture_notice,
};

const SECOND: u64 = 1_000_000_000;

fn at(seconds: u64) -> MonotonicNanos {
    MonotonicNanos::new(seconds * SECOND)
}

#[derive(Debug, Default)]
struct DisplayState {
    shown: Vec<DialogText>,
    calls: usize,
    fail: Option<DisplayError>,
    hold: bool,
    held: usize,
}

/// A display that records each dialog and never shows one.
#[derive(Debug, Clone, Default)]
struct FakeDisplay(Arc<(Mutex<DisplayState>, Condvar)>);

impl FakeDisplay {
    fn with<T>(&self, change: impl FnOnce(&mut DisplayState) -> T) -> T {
        let (lock, wake) = &*self.0;
        let mut state = lock.lock().unwrap_or_else(PoisonError::into_inner);
        let value: T = change(&mut state);
        wake.notify_all();
        value
    }
}

impl DialogDisplay for FakeDisplay {
    fn show(&mut self, text: &DialogText) -> Result<(), DisplayError> {
        let (lock, wake) = &*self.0;
        let mut state = lock.lock().unwrap_or_else(PoisonError::into_inner);
        state.calls += 1;
        state.held += 1;
        while state.hold {
            state = wake.wait(state).unwrap_or_else(PoisonError::into_inner);
        }
        state.held -= 1;
        if let Some(code) = state.fail {
            return Err(code);
        }
        state.shown.push(text.clone());
        Ok(())
    }
}

fn service(display: &FakeDisplay) -> NotificationService {
    NotificationService::start(Box::new(DialogCenter::new(display.clone())))
}

fn eventually(service: &NotificationService, done: impl Fn(&NotificationStatus) -> bool) {
    let start: Instant = Instant::now();
    loop {
        let status: NotificationStatus = service.status();
        if done(&status) {
            return;
        }
        assert!(start.elapsed() < Duration::from_secs(5), "{status:?}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn wait_held(display: &FakeDisplay) {
    let start: Instant = Instant::now();
    while display.with(|state| state.held) == 0 {
        assert!(start.elapsed() < Duration::from_secs(5));
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn of_kind(kind: NoticeKind, tag: &str) -> Notice {
    Notice {
        kind,
        tag: tag.to_owned(),
        title: format!("title {tag}"),
        body: "body".to_owned(),
    }
}

#[test]
fn only_the_three_urgent_kinds_reach_the_dialog() {
    let display = FakeDisplay::default();
    let mut service = service(&display);
    for (index, kind) in NoticeKind::ALL.into_iter().enumerate() {
        service.offer(of_kind(kind, &format!("k{index}")), at(0));
    }
    eventually(&service, |status| status.counts.posted == 3);
    let status = service.status();
    assert_eq!(status.counts.not_presented, 3, "{status:?}");
    assert_eq!(status.counts.rate_limited, 0, "{status:?}");
    assert_eq!(status.counts.failed, 0, "{status:?}");
    let headers: Vec<String> =
        display.with(|state| state.shown.iter().map(|text| text.header.clone()).collect());
    // `ALL` order: the kinds 0, 2, and 3 are urgent.
    assert_eq!(
        headers,
        [
            "Svalnir: title k0",
            "Svalnir: title k2",
            "Svalnir: title k3"
        ],
    );
    assert_eq!(display.with(|state| state.calls), 3);
}

#[test]
fn the_status_reports_a_dialog_and_no_banner() {
    let display = FakeDisplay::default();
    let service = service(&display);
    eventually(&service, |status| {
        status.authorization == CenterAuthorization::Authorized
    });
    let status = service.status();
    assert_eq!(status.state, CapabilityState::Available);
    assert_eq!(status.detail, DIALOG_DETAIL);
    assert!(
        status
            .detail
            .starts_with("Dialog for urgent notices, no banner")
    );
    assert_eq!(display.with(|state| state.calls), 0);
}

/// A flood of notices that are not urgent takes no place of the gate: the
/// urgent notices after it are admitted up to the rate limit, and no
/// further.
#[test]
fn the_other_kinds_take_no_place_of_the_gate_and_the_gate_bounds_the_dialogs() {
    let display = FakeDisplay::default();
    let mut service = service(&display);
    for index in 0..20 {
        service.offer(
            of_kind(NoticeKind::StopSettled, &format!("s{index}")),
            at(0),
        );
    }
    for index in 0..RATE_LIMIT + 2 {
        service.offer(
            of_kind(NoticeKind::MemoryPressureCritical, &format!("u{index}")),
            at(0),
        );
    }
    // The same tag again in the interval is coalesced.
    service.offer(of_kind(NoticeKind::MemoryPressureCritical, "u0"), at(1));
    let limit: u64 = u64::try_from(RATE_LIMIT).unwrap();
    eventually(&service, |status| status.counts.posted == limit);
    let status = service.status();
    assert_eq!(status.counts.not_presented, 20, "{status:?}");
    assert_eq!(status.counts.rate_limited, 2, "{status:?}");
    assert_eq!(status.counts.coalesced, 1, "{status:?}");
    assert_eq!(display.with(|state| state.calls), RATE_LIMIT);
}

#[test]
fn a_held_dialog_never_blocks_an_offer_and_the_queue_stays_bounded() {
    let display = FakeDisplay::default();
    display.with(|state| state.hold = true);
    let mut service = service(&display);
    service.offer(of_kind(NoticeKind::IncidentBudgetExhausted, "held"), at(0));
    wait_held(&display);
    let window: u64 = RATE_WINDOW.get() / SECOND;
    let offers: Instant = Instant::now();
    for index in 0..=QUEUE_CAPACITY {
        let time: u64 = (u64::try_from(index).unwrap() + 1) * window;
        service.offer(
            of_kind(
                NoticeKind::AutomaticOperationNotCompleted,
                &format!("n{index}"),
            ),
            at(time),
        );
    }
    assert!(offers.elapsed() < Duration::from_secs(1));
    assert_eq!(service.waiting(), QUEUE_CAPACITY);
    assert_eq!(service.status().counts.dropped, 1);
    display.with(|state| state.hold = false);
    eventually(&service, |status| {
        status.counts.posted == u64::try_from(QUEUE_CAPACITY + 1).unwrap()
    });
}

/// A native call that fails is a counted outcome. The worker does not
/// call again for the same notice, and the next notice is shown.
#[test]
fn a_failed_native_call_is_reported_once_and_not_retried() {
    let display = FakeDisplay::default();
    display.with(|state| state.fail = Some(DisplayError::Code(-1)));
    let mut service = service(&display);
    service.offer(of_kind(NoticeKind::MemoryPressureCritical, "a"), at(0));
    eventually(&service, |status| status.counts.failed == 1);
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(display.with(|state| state.calls), 1);
    assert_eq!(service.status().counts.failed, 1);
    // A string that did not become a native string is also one failure.
    display.with(|state| state.fail = Some(DisplayError::NotAString));
    service.offer(of_kind(NoticeKind::MemoryPressureCritical, "b"), at(1));
    eventually(&service, |status| status.counts.failed == 2);
    display.with(|state| state.fail = None);
    service.offer(of_kind(NoticeKind::MemoryPressureCritical, "c"), at(2));
    eventually(&service, |status| status.counts.posted == 1);
    assert_eq!(display.with(|state| state.calls), 3);
    let status = service.status();
    assert_eq!(status.state, CapabilityState::Available, "{status:?}");
}

#[test]
fn the_center_refuses_a_kind_that_is_not_urgent_also_when_called_directly() {
    use crate::notify::{NotificationCenter as _, PostError};
    let display = FakeDisplay::default();
    let mut center = DialogCenter::new(display.clone());
    for kind in NoticeKind::ALL {
        assert_eq!(center.presents(kind), kind.is_urgent(), "{kind:?}");
        let result = center.post(&of_kind(kind, "x"));
        if kind.is_urgent() {
            assert_eq!(result, Ok(()), "{kind:?}");
        } else {
            assert!(matches!(result, Err(PostError::Failed(_))), "{kind:?}");
        }
    }
    assert_eq!(display.with(|state| state.calls), 3);
}

/// The text of each urgent dialog: the product name, a short title, and
/// one sentence, with no path, no code span, and no process argument.
#[test]
fn a_dialog_has_the_product_name_a_short_title_and_one_sentence() {
    for kind in NoticeKind::ALL {
        let Some(notice) = fixture_notice(kind) else {
            assert!(!kind.is_urgent(), "{kind:?}");
            assert!(dialog_text(&of_kind(kind, "x")).is_none(), "{kind:?}");
            continue;
        };
        assert_eq!(notice.kind, kind);
        let text: DialogText = dialog_text(&notice).unwrap();
        assert!(text.header.starts_with("Svalnir: "), "{text:?}");
        assert!(text.header.len() <= 80, "{text:?}");
        assert!(!text.header.ends_with('.'), "{text:?}");
        assert_eq!(text.message.matches(". ").count(), 0, "{text:?}");
        assert!(text.message.ends_with('.'), "{text:?}");
        for part in [&text.header, &text.message] {
            assert!(!part.contains('/'), "{text:?}");
            assert!(!part.contains('`'), "{text:?}");
            assert!(!part.contains('='), "{text:?}");
        }
    }
}
