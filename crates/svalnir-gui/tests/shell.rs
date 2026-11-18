//! UI tests of the window frame and navigation.
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
    data::fixture::{FixtureScenario, FixtureSource},
    shell::{
        nav::{self, Screen},
        window::MainWindow,
    },
};

fn open(cx: &mut TestAppContext) -> (AnyWindowHandle, Entity<MainWindow>) {
    cx.update(gpui_kit::init);
    cx.update(nav::bind_keys);
    cx.update(|cx| {
        open_main_window(
            Bounds::new(Point::default(), size(px(1120.0), px(720.0))),
            Arc::new(FixtureSource::new(FixtureScenario::Healthy)),
            None,
            cx,
        )
        .expect("open test window")
    })
}

fn title_label(handle: AnyWindowHandle, cx: &mut TestAppContext) -> Option<String> {
    let mut label: Option<String> = None;
    cx.update_window(handle, |_, window, cx| {
        window.render_frame(cx);
        label = window
            .try_find("screen-title")
            .and_then(|node| node.label().map(str::to_owned));
    })
    .unwrap();
    label
}

#[gpui_kit::test]
fn window_opens_on_overview(cx: &mut TestAppContext) {
    let (handle, view) = open(cx);
    assert_eq!(title_label(handle, cx).as_deref(), Some("Overview"));
    cx.update(|cx| assert_eq!(view.read(cx).active(), Screen::Overview));
}

#[gpui_kit::test]
fn command_number_selects_each_screen(cx: &mut TestAppContext) {
    let (handle, view) = open(cx);
    for screen in Screen::ALL {
        let key = format!("cmd-{}", screen.index() + 1);
        cx.update_window(handle, |_, window, cx| window.press(&key, cx))
            .unwrap();
        cx.update(|cx| assert_eq!(view.read(cx).active(), screen, "key {key}"));
        assert_eq!(title_label(handle, cx).as_deref(), Some(screen.title()));
    }
}

#[gpui_kit::test]
fn screen_entities_survive_navigation(cx: &mut TestAppContext) {
    let (handle, view) = open(cx);
    let before = cx.update(|cx| view.read(cx).screen_entity_id(Screen::Storage));
    assert!(before.is_some());
    for key in ["cmd-2", "cmd-5", "cmd-2"] {
        cx.update_window(handle, |_, window, cx| window.press(key, cx))
            .unwrap();
    }
    let after = cx.update(|cx| view.read(cx).screen_entity_id(Screen::Storage));
    assert_eq!(before, after);
    cx.update(|cx| assert_eq!(view.read(cx).active(), Screen::Storage));
}

#[gpui_kit::test]
fn refresh_keeps_the_screen(cx: &mut TestAppContext) {
    let (handle, view) = open(cx);
    cx.update_window(handle, |_, window, cx| window.press("cmd-r", cx))
        .unwrap();
    cx.update(|cx| assert_eq!(view.read(cx).active(), Screen::Overview));
}
