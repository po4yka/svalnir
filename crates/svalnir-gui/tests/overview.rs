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
    app::open_main_window,
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
