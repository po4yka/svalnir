//! Tests of the notifications of the agent. Each test uses the fake
//! center: no test posts a real notification or asks for a permission.

use std::time::{Duration, Instant};

use svalnir_core::action::OperationState;
use svalnir_core::id::{OperationId, PlanId};
use svalnir_core::state::{CapabilityState, PressureState};
use svalnir_core::time::MonotonicNanos;

use super::fake::FakeCenter;
use super::{
    Admission, CenterAuthorization, MAX_GATE_TAGS, Notice, NoticeGate, NoticeKind,
    NotificationService, NotificationStatus, QUEUE_CAPACITY, RATE_LIMIT, RATE_WINDOW, TAG_INTERVAL,
    UnavailableCenter, controller_notice, settled_notice,
};
use crate::controller::{BlockedReason, Guard, GuardPhase, Notification};
use crate::coordinator::SettledOperation;

const SECOND: u64 = 1_000_000_000;

fn at(seconds: u64) -> MonotonicNanos {
    MonotonicNanos::new(seconds * SECOND)
}

fn notice(tag: &str) -> Notice {
    Notice {
        kind: NoticeKind::GuardActing,
        tag: tag.to_owned(),
        title: "title".to_owned(),
        body: "body".to_owned(),
    }
}

/// Waits until `done` holds, at most 5 s. The worker is a real thread.
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

#[test]
fn an_authorized_center_gets_each_admitted_notice() {
    let center = FakeCenter::new(CenterAuthorization::Authorized);
    let mut service = NotificationService::start(Box::new(center.clone()));
    service.offer(notice("a"), at(0));
    service.offer(notice("b"), at(1));
    eventually(&service, |status| status.counts.posted == 2);
    let status = service.status();
    assert_eq!(status.state, CapabilityState::Available);
    assert_eq!(status.authorization, CenterAuthorization::Authorized);
    let tags: Vec<String> = center.with(|state| {
        state
            .posted
            .iter()
            .map(|notice| notice.tag.clone())
            .collect()
    });
    assert_eq!(tags, ["a", "b"]);
}

#[test]
fn a_denied_center_is_a_reported_capability_and_gets_no_post() {
    let center = FakeCenter::new(CenterAuthorization::Denied);
    let mut service = NotificationService::start(Box::new(center.clone()));
    // The capability is known before the first notice.
    eventually(&service, |status| {
        status.authorization == CenterAuthorization::Denied
    });
    assert_eq!(service.status().state, CapabilityState::Denied);
    service.offer(notice("a"), at(0));
    eventually(&service, |status| status.counts.not_authorized == 1);
    assert!(center.with(|state| state.posted.is_empty()));
    // The user permits the notifications later: the next notice posts.
    center.with(|state| state.authorization = CenterAuthorization::Authorized);
    service.offer(notice("b"), at(1));
    eventually(&service, |status| status.counts.posted == 1);
    assert_eq!(service.status().state, CapabilityState::Available);
}

#[test]
fn a_center_that_is_not_determined_gets_no_post_and_no_request() {
    let center = FakeCenter::new(CenterAuthorization::NotDetermined);
    let mut service = NotificationService::start(Box::new(center.clone()));
    service.offer(notice("a"), at(0));
    eventually(&service, |status| status.counts.not_authorized == 1);
    assert_eq!(service.status().state, CapabilityState::Unknown);
    assert!(center.with(|state| state.posted.is_empty()));
}

#[test]
fn a_failed_post_is_counted_and_not_retried() {
    let center = FakeCenter::new(CenterAuthorization::Authorized);
    center.with(|state| state.fail = true);
    let mut service = NotificationService::start(Box::new(center.clone()));
    service.offer(notice("a"), at(0));
    eventually(&service, |status| status.counts.failed == 1);
    center.with(|state| state.fail = false);
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(service.status().counts.posted, 0);
}

#[test]
fn the_center_of_this_build_is_unsupported_and_posts_nothing() {
    let mut service = NotificationService::start(Box::new(UnavailableCenter));
    eventually(&service, |status| {
        status.authorization == CenterAuthorization::Unavailable
    });
    let status = service.status();
    assert_eq!(status.state, CapabilityState::Unsupported);
    assert!(status.detail.contains("no notification adapter"));
    service.offer(notice("a"), at(0));
    eventually(&service, |status| status.counts.not_authorized == 1);
}

/// A center that blocks does not block the caller: each offer returns at
/// once, and the rate gate bounds the notices that wait. The drop of a
/// full queue is in `a_full_queue_drops_its_oldest_notice`.
#[test]
fn a_slow_center_never_blocks_an_offer_and_the_gate_bounds_the_waiting_notices() {
    let center = FakeCenter::new(CenterAuthorization::Authorized);
    center.with(|state| state.hold = true);
    let mut service = NotificationService::start(Box::new(center.clone()));
    service.offer(notice("first"), at(0));
    // The worker holds the first notice in the center.
    let start: Instant = Instant::now();
    while center.with(|state| state.held) == 0 {
        assert!(start.elapsed() < Duration::from_secs(5));
        std::thread::sleep(Duration::from_millis(5));
    }
    let offers: Instant = Instant::now();
    let extra: usize = 3;
    for index in 0..QUEUE_CAPACITY + extra {
        // Different times and tags, inside the rate limit of the gate.
        service.offer(notice(&format!("n{index}")), at(0));
    }
    assert!(offers.elapsed() < Duration::from_secs(1));
    // The gate admitted at most its rate limit; each admitted notice
    // waits in a queue of at most its capacity.
    let status = service.status();
    let admitted: usize = RATE_LIMIT - 1;
    assert_eq!(
        status.counts.rate_limited,
        u64::try_from(QUEUE_CAPACITY + extra - admitted).unwrap()
    );
    assert_eq!(service.waiting(), admitted.min(QUEUE_CAPACITY));
    center.with(|state| state.hold = false);
    eventually(&service, |status| {
        status.counts.posted == u64::try_from(admitted + 1).unwrap()
    });
}

#[test]
fn a_full_queue_drops_its_oldest_notice() {
    let center = FakeCenter::new(CenterAuthorization::Authorized);
    center.with(|state| state.hold = true);
    let mut service = NotificationService::start(Box::new(center.clone()));
    service.offer(notice("held"), at(0));
    let start: Instant = Instant::now();
    while center.with(|state| state.held) == 0 {
        assert!(start.elapsed() < Duration::from_secs(5));
        std::thread::sleep(Duration::from_millis(5));
    }
    // Each offer is in a new rate window, so the gate admits each one.
    let window: u64 = RATE_WINDOW.get() / SECOND;
    for index in 0..=QUEUE_CAPACITY {
        let time: u64 = (u64::try_from(index).unwrap() + 1) * window;
        service.offer(notice(&format!("n{index}")), at(time));
    }
    assert_eq!(service.waiting(), QUEUE_CAPACITY);
    assert_eq!(service.status().counts.dropped, 1);
    center.with(|state| state.hold = false);
    eventually(&service, |status| {
        status.counts.posted == u64::try_from(QUEUE_CAPACITY + 1).unwrap()
    });
    let tags: Vec<String> = center.with(|state| {
        state
            .posted
            .iter()
            .map(|notice| notice.tag.clone())
            .collect()
    });
    // `n0` was the oldest waiting notice.
    assert!(!tags.contains(&"n0".to_owned()), "{tags:?}");
    assert!(tags.contains(&format!("n{QUEUE_CAPACITY}")), "{tags:?}");
}

#[test]
fn a_waiting_notice_with_the_same_tag_is_replaced() {
    let center = FakeCenter::new(CenterAuthorization::Authorized);
    center.with(|state| state.hold = true);
    let mut service = NotificationService::start(Box::new(center.clone()));
    service.offer(notice("held"), at(0));
    let start: Instant = Instant::now();
    while center.with(|state| state.held) == 0 {
        assert!(start.elapsed() < Duration::from_secs(5));
        std::thread::sleep(Duration::from_millis(5));
    }
    let interval: u64 = TAG_INTERVAL.get() / SECOND;
    let mut first: Notice = notice("same");
    first.body = "first".to_owned();
    let mut second: Notice = notice("same");
    second.body = "second".to_owned();
    service.offer(first, at(interval));
    service.offer(second, at(2 * interval + 1));
    assert_eq!(service.waiting(), 1);
    assert_eq!(service.status().counts.coalesced, 1);
    center.with(|state| state.hold = false);
    eventually(&service, |status| status.counts.posted == 2);
    let bodies: Vec<String> = center.with(|state| {
        state
            .posted
            .iter()
            .map(|notice| notice.body.clone())
            .collect()
    });
    assert_eq!(bodies, ["body", "second"]);
}

#[test]
fn a_closed_service_drops_its_notices() {
    let center = FakeCenter::new(CenterAuthorization::Authorized);
    let mut service = NotificationService::start(Box::new(center.clone()));
    service.close();
    service.offer(notice("a"), at(0));
    assert_eq!(service.status().counts.dropped, 1);
    // The dropped notice took no place of the gate.
    assert_eq!(service.gate.admit("a", at(1)), Admission::Admitted);
    std::thread::sleep(Duration::from_millis(20));
    assert!(center.with(|state| state.posted.is_empty()));
}

#[test]
fn the_gate_coalesces_a_tag_and_bounds_a_flood() {
    let mut gate = NoticeGate::default();
    assert_eq!(gate.admit("a", at(0)), Admission::Admitted);
    // The same tag inside its interval.
    let interval: u64 = TAG_INTERVAL.get() / SECOND;
    assert_eq!(gate.admit("a", at(interval - 1)), Admission::Coalesced);
    assert_eq!(gate.admit("a", at(interval)), Admission::Admitted);

    // A flood of different tags: at most the rate limit in each window.
    let mut gate = NoticeGate::default();
    let admitted: usize = (0..1_000)
        .filter(|index| gate.admit(&format!("t{index}"), at(0)) == Admission::Admitted)
        .count();
    assert_eq!(admitted, RATE_LIMIT);
    let window: u64 = RATE_WINDOW.get() / SECOND;
    assert_eq!(gate.admit("late", at(window - 1)), Admission::RateLimited);
    assert_eq!(gate.admit("late", at(window)), Admission::Admitted);
    // The gate remembers a bounded number of tags.
    assert!(gate.last.len() <= MAX_GATE_TAGS);
}

#[test]
fn the_gate_bounds_the_tags_that_it_remembers() {
    let mut gate = NoticeGate::default();
    let window: u64 = RATE_WINDOW.get() / SECOND;
    for index in 0..u64::try_from(MAX_GATE_TAGS * 2).unwrap() {
        assert_eq!(
            gate.admit(&format!("t{index}"), at(index * window)),
            Admission::Admitted
        );
    }
    assert_eq!(gate.last.len(), MAX_GATE_TAGS);
    assert!(gate.admitted.len() <= RATE_LIMIT);
}

/// An incident that changes between two phases many times posts the
/// notice of its phase once in the tag interval.
#[test]
fn an_incident_that_flaps_posts_once() {
    let center = FakeCenter::new(CenterAuthorization::Authorized);
    let mut service = NotificationService::start(Box::new(center.clone()));
    let acting = Notification::Phase {
        guard: Guard::Disk,
        phase: GuardPhase::Acting,
    };
    for second in 0..200 {
        if let Some(notice) = controller_notice(&acting) {
            service.offer(notice, at(second));
        }
    }
    eventually(&service, |status| status.counts.posted == 1);
    assert_eq!(service.status().counts.coalesced, 199);
}

#[test]
fn the_controller_notices_are_the_meaningful_changes() {
    let phase = |phase: GuardPhase| {
        controller_notice(&Notification::Phase {
            guard: Guard::Memory,
            phase,
        })
        .map(|notice| notice.kind)
    };
    assert_eq!(phase(GuardPhase::Acting), Some(NoticeKind::GuardActing));
    assert_eq!(
        phase(GuardPhase::Exhausted),
        Some(NoticeKind::IncidentBudgetExhausted)
    );
    for quiet in [
        GuardPhase::Normal,
        GuardPhase::Warning,
        GuardPhase::Qualifying,
        GuardPhase::Recovering,
        GuardPhase::Cooldown,
    ] {
        assert_eq!(phase(quiet), None);
    }
    let blocked = controller_notice(&Notification::Blocked {
        guard: Guard::Disk,
        reason: BlockedReason::Exhausted,
    })
    .unwrap();
    assert_eq!(blocked.kind, NoticeKind::IncidentBudgetExhausted);
    // The phase and the reason of one exhaustion have one tag.
    assert_eq!(
        blocked.tag,
        controller_notice(&Notification::Phase {
            guard: Guard::Disk,
            phase: GuardPhase::Exhausted,
        })
        .unwrap()
        .tag
    );
    assert_eq!(
        controller_notice(&Notification::Blocked {
            guard: Guard::Disk,
            reason: BlockedReason::Paused,
        }),
        None
    );

    let finished = |state: &str| {
        controller_notice(&Notification::Finished {
            guard: Guard::Disk,
            plan_id: PlanId::new("plan_1").unwrap(),
            state: state.to_owned(),
            low_benefit: false,
        })
    };
    assert_eq!(finished("Completed"), None);
    assert_eq!(finished("NoAction"), None);
    for state in ["Failed", "Partial", "Incomplete"] {
        let notice = finished(state).unwrap();
        assert_eq!(notice.kind, NoticeKind::AutomaticOperationNotCompleted);
        assert!(notice.body.contains(state), "{}", notice.body);
    }
    let unknown = finished("UnknownOutcome").unwrap();
    assert!(unknown.body.contains("not known"), "{}", unknown.body);
    // A state that this build does not recognize is not a completion.
    assert!(finished("Unexpected").is_some());
    // An operation that is not settled, for example one whose record the
    // journal refused, has no notice of a final state.
    assert_eq!(finished("Admitted"), None);
}

#[test]
fn a_settled_stop_has_a_notice_and_an_automatic_operation_has_none_twice() {
    let settled = |automatic: bool, stops_application: bool, state: OperationState| {
        settled_notice(&SettledOperation {
            operation_id: OperationId::new("operation_1").unwrap(),
            automatic,
            stops_application,
            state,
        })
    };
    let stop = settled(false, true, OperationState::Completed).unwrap();
    assert_eq!(stop.kind, NoticeKind::StopSettled);
    assert_eq!(stop.tag, "svalnir-stop-operation_1");
    assert_eq!(stop.title, "Stop: completed");
    let failed = settled(false, true, OperationState::Failed).unwrap();
    assert_eq!(failed.title, "Stop: Failed");
    // The controller has the notice of an automatic operation.
    assert_eq!(settled(true, true, OperationState::Failed), None);
    // A cleanup that a person requested has a notice only when it did not
    // complete.
    assert_eq!(settled(false, false, OperationState::Completed), None);
    assert_eq!(
        settled(false, false, OperationState::UnknownOutcome).map(|notice| notice.kind),
        Some(NoticeKind::ManualOperationNotCompleted)
    );
}

#[test]
fn critical_pressure_posts_at_a_change_and_not_for_the_first_reading() {
    let center = FakeCenter::new(CenterAuthorization::Authorized);
    let mut service = NotificationService::start(Box::new(center.clone()));
    let interval: u64 = TAG_INTERVAL.get() / SECOND;
    // The first reading is critical: no notice.
    service.observe_pressure(Some(&PressureState::Critical), at(0));
    // A reading that is not a value changes nothing.
    service.observe_pressure(None, at(1));
    service.observe_pressure(Some(&PressureState::Critical), at(2));
    service.observe_pressure(Some(&PressureState::Warning), at(3));
    service.observe_pressure(Some(&PressureState::Critical), at(4));
    service.observe_pressure(Some(&PressureState::Normal), at(5));
    // Inside the tag interval: coalesced.
    service.observe_pressure(Some(&PressureState::Critical), at(6));
    // The first notice is posted, so the next one does not join it in
    // the queue.
    eventually(&service, |status| status.counts.posted == 1);
    service.observe_pressure(Some(&PressureState::Normal), at(interval + 4));
    service.observe_pressure(Some(&PressureState::Critical), at(interval + 5));
    eventually(&service, |status| status.counts.posted == 2);
    assert_eq!(service.status().counts.coalesced, 1);
    let kinds: Vec<NoticeKind> =
        center.with(|state| state.posted.iter().map(|notice| notice.kind).collect());
    assert_eq!(kinds, [NoticeKind::MemoryPressureCritical; 2]);
}

/// A notice has no path and no process argument: its text comes from
/// identities and state names only.
#[test]
fn a_notice_has_no_path() {
    let notices: Vec<Notice> = [
        controller_notice(&Notification::Finished {
            guard: Guard::Disk,
            plan_id: PlanId::new("plan_1").unwrap(),
            state: "Failed".to_owned(),
            low_benefit: true,
        }),
        settled_notice(&SettledOperation {
            operation_id: OperationId::new("operation_1").unwrap(),
            automatic: false,
            stops_application: true,
            state: OperationState::Partial,
        }),
    ]
    .into_iter()
    .flatten()
    .collect();
    assert_eq!(notices.len(), 2);
    for notice in notices {
        for text in [&notice.title, &notice.body, &notice.tag] {
            assert!(!text.contains('/'), "{text}");
        }
    }
}
