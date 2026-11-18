//! UI tests of the data layer: model loading, status line, and banners.
#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test code fails by panicking"
)]

use gpui_kit::{
    AnyWindowHandle, AppContext as _, Bounds, Entity, Point, TestAppContext, px, size,
    test::TestWindowExt as _,
};
use std::sync::Arc;
use svalnir_gui::{
    app::open_main_window,
    data::{
        DataSource,
        fixture::{FixtureScenario, FixtureSource},
        live::LiveSource,
        model::{AgentState, Loadable, Measured},
        store::AppModel,
    },
    shell::{nav, window::MainWindow},
};

fn open(
    scenario: FixtureScenario,
    cx: &mut TestAppContext,
) -> (AnyWindowHandle, Entity<MainWindow>) {
    cx.update(gpui_kit::init);
    cx.update(nav::bind_keys);
    let opened = cx.update(|cx| {
        open_main_window(
            Bounds::new(Point::default(), size(px(1120.0), px(720.0))),
            Arc::new(FixtureSource::new(scenario)),
            None,
            cx,
        )
        .expect("open test window")
    });
    cx.run_until_parked();
    opened
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
fn fixture_shows_status_and_banner(cx: &mut TestAppContext) {
    let (handle, _view) = open(FixtureScenario::Healthy, cx);
    let status = label(handle, "status-line", cx).expect("status line");
    assert!(status.contains("fixture"), "{status}");
    assert!(status.contains("agent running"), "{status}");
    let banner = label(handle, "data-banner", cx).expect("fixture banner");
    assert!(banner.contains("Fixture data: healthy"), "{banner}");
}

#[gpui_kit::test]
fn absent_agent_is_reported(cx: &mut TestAppContext) {
    let (handle, _view) = open(FixtureScenario::AgentAbsent, cx);
    let status = label(handle, "status-line", cx).expect("status line");
    assert!(status.contains("agent no journal"), "{status}");
    assert!(label(handle, "data-banner", cx).is_some());
}

#[gpui_kit::test]
fn unavailable_fields_are_not_zero(cx: &mut TestAppContext) {
    cx.update(gpui_kit::init);
    let model = cx.update(|cx| {
        cx.new(|cx| {
            AppModel::new(
                Arc::new(FixtureSource::new(FixtureScenario::Unavailable)),
                cx,
            )
        })
    });
    cx.run_until_parked();
    cx.update(|cx| {
        let Loadable::Ready(host) = &model.read(cx).host else {
            panic!("host must be Ready");
        };
        assert!(matches!(host.disk_total, Measured::Unavailable(_)));
        assert!(matches!(host.pressure, Measured::Unavailable(_)));
        assert!(matches!(host.swap_used, Measured::Unavailable(_)));
    });
}

#[test]
fn live_agent_without_journal_is_no_journal() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let source = LiveSource::new(Some(directory.path().to_path_buf()));
    assert_eq!(source.agent().state, AgentState::NoJournal);
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
}
