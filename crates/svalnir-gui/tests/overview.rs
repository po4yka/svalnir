//! UI tests of the Overview screen: values, captions, pills, and unavailable data.
#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test code fails by panicking"
)]

use gpui_kit::{
    AnyWindowHandle, AppContext as _, Bounds, Pixels, Point, TestAppContext, px, size,
    test::TestWindowExt as _,
};
use std::sync::Arc;
use svalnir_gui::{
    app::{open_main_window, open_main_window_seeded},
    data::fixture::{FixtureScenario, FixtureSource},
    shell::nav,
    viz::hover::{FocusTarget, request_launch_focus},
};

fn open(scenario: FixtureScenario, cx: &mut TestAppContext) -> AnyWindowHandle {
    cx.update(gpui_kit::init);
    cx.update(nav::bind_keys);
    let (handle, _view) = cx.update(|cx| {
        open_main_window(
            Bounds::new(Point::default(), size(px(1120.0), px(720.0))),
            Arc::new(FixtureSource::new(scenario)),
            None,
            cx,
        )
        .expect("open test window")
    });
    cx.run_until_parked();
    handle
}

fn label(handle: AnyWindowHandle, id: &'static str, cx: &mut TestAppContext) -> Option<String> {
    let mut found: Option<String> = None;
    cx.update_window(handle, |_, window, cx| {
        window.render_frame(cx);
        found = window
            .try_find(id)
            .and_then(|node| node.label().map(str::to_owned));
    })
    .unwrap();
    found
}

#[gpui_kit::test]
fn healthy_shows_value_scale_and_pill(cx: &mut TestAppContext) {
    let handle = open(FixtureScenario::Healthy, cx);
    let disk = label(handle, "disk-grid-scale", cx).expect("scale caption");
    assert!(disk.starts_with("1 cell = "), "{disk}");
    let pill = label(handle, "pressure-pill", cx).expect("pressure pill");
    assert_eq!(pill, "Normal");
    let chart = label(handle, "disk-grid", cx).expect("grid label");
    assert!(chart.starts_with("Disk: "), "{chart}");
}

#[gpui_kit::test]
fn pressure_shows_warning_pill(cx: &mut TestAppContext) {
    let handle = open(FixtureScenario::Pressure, cx);
    assert_eq!(
        label(handle, "pressure-pill", cx).as_deref(),
        Some("Warning")
    );
}

#[gpui_kit::test]
fn unavailable_disk_is_a_dash_with_reason(cx: &mut TestAppContext) {
    let handle = open(FixtureScenario::Unavailable, cx);
    let reason = label(handle, "disk-value-reason", cx).expect("reason");
    assert!(reason.contains("disk available"), "{reason}");
    let chart = label(handle, "disk-grid", cx).expect("grid label");
    assert!(chart.contains('\u{2014}'), "{chart}");
    assert_eq!(
        label(handle, "pressure-pill", cx).as_deref(),
        Some("Unavailable")
    );
}

#[gpui_kit::test]
fn absent_agent_is_not_running(cx: &mut TestAppContext) {
    let handle = open(FixtureScenario::AgentAbsent, cx);
    assert_eq!(
        label(handle, "agent-pill", cx).as_deref(),
        Some("Not running")
    );
}

#[gpui_kit::test]
fn healthy_shows_guard_and_completed_operation(cx: &mut TestAppContext) {
    let handle = open(FixtureScenario::Healthy, cx);
    assert_eq!(
        label(handle, "guard-disk-guard", cx).as_deref(),
        Some("Active")
    );
    assert_eq!(
        label(handle, "operation-pill", cx).as_deref(),
        Some("Completed")
    );
}

#[gpui_kit::test]
fn pressure_shows_running_operation(cx: &mut TestAppContext) {
    let handle = open(FixtureScenario::Pressure, cx);
    assert_eq!(
        label(handle, "operation-pill", cx).as_deref(),
        Some("Running")
    );
}

#[gpui_kit::test]
fn absent_journal_says_so_and_no_guard_can_act(cx: &mut TestAppContext) {
    let handle = open(FixtureScenario::AgentAbsent, cx);
    assert_eq!(
        label(handle, "intervention-empty", cx).as_deref(),
        Some("No journal exists in the state directory.")
    );
    let caption = label(handle, "policies-no-guard", cx).expect("no-guard caption");
    assert!(caption.starts_with("No guard can act."), "{caption}");
}

#[gpui_kit::test]
fn unavailable_service_shows_a_problem_line(cx: &mut TestAppContext) {
    let handle = open(FixtureScenario::Unavailable, cx);
    let problem = label(handle, "policies-problem", cx).expect("problem line");
    assert!(problem.contains("cannot be read"), "{problem}");
}

#[gpui_kit::test]
fn hero_chart_label_has_the_used_percentage(cx: &mut TestAppContext) {
    let handle = open(FixtureScenario::Healthy, cx);
    let chart = label(handle, "disk-grid", cx).expect("hero chart");
    assert!(
        chart.ends_with('%') && chart.contains(" used of "),
        "{chart}"
    );
}

#[gpui_kit::test]
fn unavailable_hero_has_a_dash_and_the_track_counts_no_normal_sample(cx: &mut TestAppContext) {
    let handle = open(FixtureScenario::Unavailable, cx);
    let chart = label(handle, "disk-grid", cx).expect("hero chart");
    assert!(chart.contains('\u{2014}'), "{chart}");
    let track = label(handle, "pressure-track", cx).expect("tick track");
    assert!(track.contains(" 0 normal"), "{track}");
}

#[gpui_kit::test]
fn two_refreshes_give_two_warning_samples(cx: &mut TestAppContext) {
    // The first refresh is the load when the window opens; cmd-r is the second.
    let handle = open(FixtureScenario::Pressure, cx);
    cx.update_window(handle, |_, window, cx| window.press("cmd-r", cx))
        .unwrap();
    cx.run_until_parked();
    let track = label(handle, "pressure-track", cx).expect("tick track");
    assert!(track.contains("2 warning"), "{track}");
}

#[gpui_kit::test]
fn the_tick_track_counts_a_sample_per_refresh(cx: &mut TestAppContext) {
    let handle = open(FixtureScenario::Pressure, cx);
    let first = label(handle, "pressure-track", cx).expect("tick track");
    assert!(first.contains("1 warning"), "{first}");
}

#[gpui_kit::test]
fn the_dial_states_the_three_values_in_words(cx: &mut TestAppContext) {
    let handle = open(FixtureScenario::Healthy, cx);
    let dial = label(handle, "headroom-dial", cx).expect("dial label");
    assert!(dial.contains("Disk: "), "{dial}");
    assert!(dial.contains("Swap: "), "{dial}");
    assert!(dial.contains("Memory pressure: Normal"), "{dial}");
    assert!(label(handle, "dial-row-disk", cx).is_some());
    assert!(label(handle, "dial-row-swap", cx).is_some());
    assert!(label(handle, "dial-row-pressure", cx).is_some());
}

#[gpui_kit::test]
fn the_dial_follows_the_pressure_state(cx: &mut TestAppContext) {
    let handle = open(FixtureScenario::Pressure, cx);
    let dial = label(handle, "headroom-dial", cx).expect("dial label");
    assert!(dial.contains("Memory pressure: Warning"), "{dial}");
    assert_eq!(
        label(handle, "dial-center-value", cx).as_deref(),
        Some("Warning"),
        "the pressure ring is picked"
    );
}

#[gpui_kit::test]
fn an_unavailable_dial_has_dashes_and_no_zero(cx: &mut TestAppContext) {
    let handle = open(FixtureScenario::Unavailable, cx);
    let dial = label(handle, "headroom-dial", cx).expect("dial label");
    assert!(dial.contains('\u{2014}'), "{dial}");
    assert!(!dial.contains("0 B"), "{dial}");
    let row = label(handle, "dial-row-disk", cx).expect("disk row");
    assert!(row.contains('\u{2014}') && !row.contains("0 B"), "{row}");
}

#[gpui_kit::test]
fn the_session_chart_counts_one_reading_then_two(cx: &mut TestAppContext) {
    let handle = open(FixtureScenario::Healthy, cx);
    let first = label(handle, "session-chart", cx).expect("session chart");
    assert!(first.contains("1 reading,"), "{first}");
    assert_eq!(
        label(handle, "session-scale", cx).as_deref(),
        Some("1 column = 1 reading")
    );
    cx.update_window(handle, |_, window, cx| window.press("cmd-r", cx))
        .unwrap();
    cx.run_until_parked();
    let second = label(handle, "session-chart", cx).expect("session chart");
    assert!(second.contains("2 readings"), "{second}");
    assert!(second.contains("2 normal"), "{second}");
}

#[gpui_kit::test]
fn an_unavailable_session_has_no_range_and_no_zero(cx: &mut TestAppContext) {
    let handle = open(FixtureScenario::Unavailable, cx);
    let chart = label(handle, "session-chart", cx).expect("session chart");
    assert!(chart.contains('\u{2014}'), "{chart}");
    assert!(!chart.contains("0 B"), "{chart}");
}

fn open_drift(readings: usize, cx: &mut TestAppContext) -> AnyWindowHandle {
    cx.update(gpui_kit::init);
    cx.update(nav::bind_keys);
    let (handle, _view) = cx.update(|cx| {
        open_main_window_seeded(
            Bounds::new(Point::default(), size(px(1120.0), px(720.0))),
            Arc::new(FixtureSource::new(FixtureScenario::Drift).with_seeded_readings(readings)),
            None,
            readings,
            cx,
        )
        .expect("open test window")
    });
    cx.run_until_parked();
    handle
}

#[gpui_kit::test]
fn drift_readings_fill_the_session_chart_before_the_first_paint(cx: &mut TestAppContext) {
    let handle = open_drift(100, cx);
    let chart = label(handle, "session-chart", cx).expect("session chart");
    assert!(chart.contains("100 readings"), "{chart}");
    // 3 of the 100 readings are unavailable: they are not a pressure state.
    assert!(chart.contains("77 normal"), "{chart}");
    assert!(chart.contains("15 warning"), "{chart}");
    assert!(chart.contains("5 critical"), "{chart}");
    // Three pressure changes and one operation.
    assert!(chart.contains("4 events"), "{chart}");
}

#[gpui_kit::test]
fn an_unavailable_reading_is_not_counted_as_a_value(cx: &mut TestAppContext) {
    // Steps 0 to 20 hold 20 values; step 20 is the first unavailable one.
    let handle = open_drift(21, cx);
    let chart = label(handle, "session-chart", cx).expect("session chart");
    assert!(chart.contains("21 readings"), "{chart}");
    assert!(chart.contains("20 normal"), "{chart}");
    assert!(
        chart.contains("0 warning") && chart.contains("0 critical"),
        "{chart}"
    );
}

#[gpui_kit::test]
fn keyboard_focus_on_a_legend_row_picks_the_ring_and_blur_clears_it(cx: &mut TestAppContext) {
    let handle = open(FixtureScenario::Healthy, cx);
    assert_eq!(
        label(handle, "dial-center-caption", cx).as_deref(),
        Some("Disk used")
    );
    let mut seen_swap: bool = false;
    for _ in 0..16 {
        cx.update_window(handle, |_, window, cx| window.press("tab", cx))
            .unwrap();
        cx.run_until_parked();
        if label(handle, "dial-center-caption", cx).as_deref() == Some("Swap used") {
            seen_swap = true;
            break;
        }
    }
    assert!(seen_swap, "tab never focused the swap row");
    // Leave the legend: the pick clears.
    let mut cleared: bool = false;
    for _ in 0..16 {
        cx.update_window(handle, |_, window, cx| window.press("tab", cx))
            .unwrap();
        cx.run_until_parked();
        if label(handle, "dial-center-caption", cx).as_deref() == Some("Disk used") {
            cleared = true;
            break;
        }
    }
    assert!(cleared, "blur did not clear the pick");
}

#[gpui_kit::test]
fn the_header_aside_shows_pressure_or_the_disk_share(cx: &mut TestAppContext) {
    let healthy = open(FixtureScenario::Healthy, cx);
    let text = label(healthy, "headroom-aside", cx).expect("aside");
    assert!(text.ends_with("% disk used"), "{text}");
    let pressure = open(FixtureScenario::Pressure, cx);
    assert_eq!(
        label(pressure, "headroom-aside", cx).as_deref(),
        Some("Warning")
    );
}

#[gpui_kit::test]
fn the_detail_panel_has_rows_and_dashes_for_unknown_values(cx: &mut TestAppContext) {
    let handle = open(FixtureScenario::Healthy, cx);
    let detail = label(handle, "dial-detail", cx).expect("detail");
    for row in ["Used ", "Available ", "Free ", "Reclaimable ", "Total "] {
        assert!(detail.contains(row), "{detail}");
    }
    assert!(detail.contains("in use"), "{detail}");
    let none = open(FixtureScenario::Unavailable, cx);
    let detail = label(none, "dial-detail", cx).expect("detail");
    assert!(detail.contains('\u{2014}'), "{detail}");
    assert!(!detail.contains("0 B"), "{detail}");
    assert!(label(none, "dial-key", cx).is_some());
}

#[gpui_kit::test]
fn the_detail_panel_follows_the_focused_legend_row(cx: &mut TestAppContext) {
    let handle = open(FixtureScenario::Healthy, cx);
    assert!(
        label(handle, "dial-detail", cx)
            .expect("detail")
            .starts_with("Disk")
    );
    let mut seen: bool = false;
    for _ in 0..16 {
        cx.update_window(handle, |_, window, cx| window.press("tab", cx))
            .unwrap();
        cx.run_until_parked();
        if label(handle, "dial-center-caption", cx).as_deref() == Some("Swap used") {
            let detail = label(handle, "dial-detail", cx).expect("detail");
            assert!(detail.starts_with("Swap. "), "{detail}");
            assert!(
                detail.contains("swap space that the system uses"),
                "{detail}"
            );
            seen = true;
            break;
        }
    }
    assert!(seen, "tab never focused the swap row");
}

#[gpui_kit::test]
fn the_headroom_stat_row_shows_three_values(cx: &mut TestAppContext) {
    let handle = open(FixtureScenario::Healthy, cx);
    let disk = label(handle, "headroom-stat-disk", cx).expect("disk stat");
    assert!(disk.starts_with("Disk available "), "{disk}");
    assert!(
        label(handle, "headroom-stat-swap", cx)
            .expect("swap")
            .contains(" of ")
    );
    assert_eq!(
        label(handle, "headroom-stat-pressure", cx).as_deref(),
        Some("Pressure Normal")
    );
    let none = open(FixtureScenario::Unavailable, cx);
    assert_eq!(
        label(none, "headroom-stat-pressure", cx).as_deref(),
        Some("Pressure \u{2014}")
    );
    assert!(
        label(none, "headroom-stat-disk", cx)
            .expect("disk stat")
            .ends_with('\u{2014}')
    );
}

#[gpui_kit::test]
fn the_session_tags_state_readings_events_and_state(cx: &mut TestAppContext) {
    let handle = open_drift(100, cx);
    assert_eq!(
        label(handle, "session-tag-readings", cx).as_deref(),
        Some("readings 100")
    );
    assert_eq!(
        label(handle, "session-tag-events", cx).as_deref(),
        Some("events 4")
    );
    let state = label(handle, "session-tag-state", cx).expect("state tag");
    assert!(state.starts_with("now "), "{state}");
    let range = label(handle, "session-tag-range", cx).expect("range tag");
    assert!(range.starts_with("range "), "{range}");
    assert!(label(handle, "session-rows", cx).is_none());
    assert!(label(handle, "session-key", cx).is_some());
}

#[gpui_kit::test]
fn the_chip_names_the_newest_event_with_its_fact(cx: &mut TestAppContext) {
    let handle = open_drift(100, cx);
    let chip = label(handle, "session-chip", cx).expect("chip");
    assert!(chip.contains(" UTC"), "{chip}");
    assert!(
        chip.contains("after ") && chip.contains(" readings") || chip.ends_with("Completed"),
        "{chip}"
    );
    let chart = label(handle, "session-chart", cx).expect("chart");
    assert!(chart.contains(", min "), "{chart}");
}

#[gpui_kit::test]
fn a_falling_session_shows_a_labeled_runway(cx: &mut TestAppContext) {
    let handle = open_drift(100, cx);
    let tag = label(handle, "session-tag-runway", cx).expect("runway tag");
    assert!(tag.starts_with("runway \u{2248} "), "{tag}");
    assert!(
        [" min", " h", " d"].iter().any(|unit| tag.ends_with(unit)),
        "{tag}"
    );
    let chart = label(handle, "session-chart", cx).expect("session chart");
    assert!(chart.contains("runway \u{2248} "), "{chart}");
    assert!(chart.contains("an estimate"), "{chart}");
    let detail = label(handle, "dial-detail", cx).expect("detail panel");
    assert!(detail.contains("Runway \u{2248} "), "{detail}");
    assert!(detail.contains("Runway: estimate from "), "{detail}");
    for text in [&tag, &chart, &detail] {
        assert!(
            !text.contains("freed") && !text.contains("reclaimed"),
            "{text}"
        );
    }
}

#[gpui_kit::test]
fn a_healthy_session_without_a_trend_shows_no_runway(cx: &mut TestAppContext) {
    let handle = open(FixtureScenario::Healthy, cx);
    assert!(label(handle, "session-tag-runway", cx).is_none());
    let chart = label(handle, "session-chart", cx);
    assert!(chart.is_none_or(|c| !c.contains("runway")));
    let detail = label(handle, "dial-detail", cx).unwrap_or_default();
    assert!(!detail.contains("Runway"), "{detail}");
}

/// Asks the chart of `target` to take focus at launch, as `--focus` does.
fn launch_focus(target: FocusTarget, cx: &mut TestAppContext) {
    cx.update(|cx| request_launch_focus(target, cx));
}

fn press(handle: AnyWindowHandle, key: &'static str, cx: &mut TestAppContext) {
    cx.update_window(handle, |_, window, cx| window.press(key, cx))
        .unwrap();
    cx.run_until_parked();
}

/// The window bounds of an element, after a fresh frame.
fn bounds_of(
    handle: AnyWindowHandle,
    id: &'static str,
    cx: &mut TestAppContext,
) -> Option<Bounds<Pixels>> {
    let mut found: Option<Bounds<Pixels>> = None;
    cx.update_window(handle, |_, window, cx| {
        window.render_frame(cx);
        found = window.try_find(id).map(|node| node.bounds());
    })
    .unwrap();
    found
}

fn reading_number(card: &str) -> usize {
    let tail: &str = card.rsplit("Reading ").next().expect("reading note");
    tail.split(' ')
        .next()
        .and_then(|n| n.parse().ok())
        .expect("reading number")
}

#[gpui_kit::test]
fn the_launch_focus_shows_the_newest_reading_and_keys_move_it(cx: &mut TestAppContext) {
    launch_focus(FocusTarget::Session, cx);
    let handle = open_drift(100, cx);
    let card = label(handle, "session-tip", cx).expect("card of the newest reading");
    assert!(card.contains("Available: "), "{card}");
    assert!(card.contains("Disk used: "), "{card}");
    assert!(card.contains("Swap used: "), "{card}");
    assert!(card.contains("Pressure: "), "{card}");
    assert!(card.contains("Changes: "), "{card}");
    assert!(card.ends_with("Reading 100 of 100"), "{card}");
    press(handle, "left", cx);
    let card = label(handle, "session-tip", cx).expect("card after Left");
    assert_eq!(reading_number(&card), 99, "{card}");
    press(handle, "home", cx);
    let card = label(handle, "session-tip", cx).expect("card after Home");
    assert_eq!(reading_number(&card), 1, "{card}");
    press(handle, "escape", cx);
    assert!(label(handle, "session-tip", cx).is_none());
}

#[gpui_kit::test]
fn an_unavailable_reading_card_has_dashes_and_no_zero(cx: &mut TestAppContext) {
    launch_focus(FocusTarget::Session, cx);
    // Step 20 of the Drift fixture is unavailable; 21 readings end there.
    let handle = open_drift(21, cx);
    let card = label(handle, "session-tip", cx).expect("card");
    assert!(card.contains("Available: —"), "{card}");
    assert!(!card.contains("0 B") && !card.contains("0%"), "{card}");
}

#[gpui_kit::test]
fn the_dial_card_follows_the_arrow_keys_and_the_detail_panel(cx: &mut TestAppContext) {
    launch_focus(FocusTarget::Dial, cx);
    let handle = open(FixtureScenario::Healthy, cx);
    let card = label(handle, "headroom-dial-tip", cx).expect("dial card");
    assert!(
        card.contains("Used: ") && card.contains("Total: "),
        "{card}"
    );
    assert!(card.contains('%'), "{card}");
    let detail = label(handle, "dial-detail", cx);
    press(handle, "down", cx);
    let next = label(handle, "headroom-dial-tip", cx).expect("card after Down");
    assert_ne!(next, card);
    assert_ne!(label(handle, "dial-detail", cx), detail);
    press(handle, "escape", cx);
    assert!(label(handle, "headroom-dial-tip", cx).is_none());
}

#[gpui_kit::test]
fn the_unavailable_dial_card_has_a_dash_and_the_reason(cx: &mut TestAppContext) {
    launch_focus(FocusTarget::Dial, cx);
    let handle = open(FixtureScenario::Unavailable, cx);
    let card = label(handle, "headroom-dial-tip", cx).expect("dial card");
    assert!(card.contains("Used: —"), "{card}");
    assert!(!card.contains("0 B") && !card.contains("0%"), "{card}");
}

#[gpui_kit::test]
fn the_cards_sit_in_the_window_near_their_marks(cx: &mut TestAppContext) {
    let window = Bounds::new(Point::default(), size(px(1120.0), px(720.0)));
    launch_focus(FocusTarget::Session, cx);
    let handle = open_drift(100, cx);
    let card = bounds_of(handle, "session-tip", cx).expect("session card bounds");
    let chart = bounds_of(handle, "session-chart", cx).expect("session chart bounds");
    assert!(card.origin.x >= window.origin.x && card.origin.y >= window.origin.y);
    assert!(card.right() <= window.right() && card.bottom() <= window.bottom());
    // The card is next to the chart in window space, not at the window corner.
    assert!(
        card.origin.x >= chart.origin.x - px(16.0),
        "{card:?} {chart:?}"
    );
    assert!(
        card.origin.y >= chart.origin.y - px(300.0),
        "{card:?} {chart:?}"
    );
}
