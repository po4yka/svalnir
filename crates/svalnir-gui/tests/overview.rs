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
    assert_eq!(disk, "1 cell = 5%");
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
