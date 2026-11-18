//! UI tests of the Overview screen: values, captions, pills, and unavailable data.
#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test code fails by panicking"
)]

use gpui_kit::{
    AnyWindowHandle, AppContext as _, Bounds, Point, TestAppContext, px, size,
    test::TestWindowExt as _,
};
use std::sync::Arc;
use svalnir_gui::{
    app::{open_main_window, open_main_window_seeded},
    data::fixture::{FixtureScenario, FixtureSource},
    shell::nav,
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
    assert!(chart.ends_with("4 events"), "{chart}");
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
