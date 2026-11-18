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
        nav::{self, NavGroup, Screen},
        window::MainWindow,
    },
};

fn open(cx: &mut TestAppContext) -> (AnyWindowHandle, Entity<MainWindow>) {
    open_with(cx, 1120.0, FixtureScenario::Healthy)
}

fn open_with(
    cx: &mut TestAppContext,
    width: f32,
    scenario: FixtureScenario,
) -> (AnyWindowHandle, Entity<MainWindow>) {
    open_sized(cx, width, 720.0, scenario)
}

fn open_sized(
    cx: &mut TestAppContext,
    width: f32,
    height: f32,
    scenario: FixtureScenario,
) -> (AnyWindowHandle, Entity<MainWindow>) {
    cx.update(gpui_kit::init);
    cx.update(nav::bind_keys);
    let opened = cx.update(|cx| {
        open_main_window(
            Bounds::new(Point::default(), size(px(width), px(height))),
            Arc::new(FixtureSource::new(scenario)),
            None,
            cx,
        )
        .expect("open test window")
    });
    cx.run_until_parked();
    opened
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

fn press(handle: AnyWindowHandle, key: &str, cx: &mut TestAppContext) {
    cx.update_window(handle, |_, window, cx| window.press(key, cx))
        .unwrap();
}

fn narrow(handle: AnyWindowHandle, view: &Entity<MainWindow>, cx: &mut TestAppContext) -> bool {
    let mut result: bool = false;
    cx.update_window(handle, |_, window, cx| {
        window.render_frame(cx);
        result = view.read(cx).sidebar_narrow(window);
    })
    .unwrap();
    result
}

fn label_of(handle: AnyWindowHandle, id: &str, cx: &mut TestAppContext) -> Option<String> {
    let mut label: Option<String> = None;
    cx.update_window(handle, |_, window, cx| {
        window.render_frame(cx);
        label = window
            .try_find(id.to_owned())
            .and_then(|node| node.label().map(str::to_owned));
    })
    .unwrap();
    label
}

#[gpui_kit::test]
fn the_wide_sidebar_has_screen_items_and_nested_items(cx: &mut TestAppContext) {
    let (handle, view) = open(cx);
    assert!(!narrow(handle, &view, cx));
    // The component names the rows "{group}-{menu}-{item}[-{nested}]". It
    // gives the row text no test id, so the test checks that each row exists.
    let mut found: Vec<String> = Vec::new();
    let mut missing: Vec<String> = Vec::new();
    cx.update_window(handle, |_, window, cx| {
        window.render_frame(cx);
        for (group_ix, group) in NavGroup::ALL.iter().enumerate() {
            for (item_ix, screen) in group.screens().iter().enumerate() {
                let id: String = format!("{group_ix}-0-{item_ix}");
                assert!(window.try_find(id.clone()).is_some(), "row {id}");
                found.push(id);
                for nested in 0..screen.sections().len() {
                    let id: String = format!("{group_ix}-0-{item_ix}-{nested}");
                    if window.try_find(id.clone()).is_some() {
                        found.push(id);
                    } else {
                        missing.push(id);
                    }
                }
            }
        }
    })
    .unwrap();
    // Seven screens, six nested items of Overview; the two of Storage are closed.
    assert_eq!(found.len(), 7 + 6, "{found:?}");
    assert_eq!(missing, ["0-0-1-0", "0-0-1-1"]);
}

#[gpui_kit::test]
fn a_nested_item_click_selects_its_screen(cx: &mut TestAppContext) {
    let (handle, view) = open(cx);
    // The Storage item opens by its caret; a click on the name opens it too.
    cx.update_window(handle, |_, window, cx| {
        window.render_frame(cx);
        window.click("0-0-1", cx);
        window.render_frame(cx);
    })
    .unwrap();
    cx.update(|cx| assert_eq!(view.read(cx).active(), Screen::Storage));
    cx.update_window(handle, |_, window, cx| {
        window.render_frame(cx);
        window.click("0-0-0-3", cx);
        window.render_frame(cx);
    })
    .unwrap();
    cx.update(|cx| assert_eq!(view.read(cx).active(), Screen::Overview));
}

#[gpui_kit::test]
fn the_toggle_key_changes_the_width(cx: &mut TestAppContext) {
    let (handle, view) = open(cx);
    assert!(!narrow(handle, &view, cx));
    press(handle, "ctrl-cmd-s", cx);
    assert!(narrow(handle, &view, cx));
    press(handle, "ctrl-cmd-s", cx);
    assert!(!narrow(handle, &view, cx));
}

#[gpui_kit::test]
fn a_narrow_window_starts_narrow_and_the_toggle_makes_it_wide(cx: &mut TestAppContext) {
    let (handle, view) = open_with(cx, 800.0, FixtureScenario::Healthy);
    assert!(narrow(handle, &view, cx));
    cx.update_window(handle, |_, window, cx| {
        window.render_frame(cx);
        window.click("collapse", cx);
    })
    .unwrap();
    assert!(!narrow(handle, &view, cx));
}

#[gpui_kit::test]
fn next_and_previous_stop_at_the_ends(cx: &mut TestAppContext) {
    let (handle, view) = open(cx);
    press(handle, "cmd-[", cx);
    cx.update(|cx| assert_eq!(view.read(cx).active(), Screen::Overview));
    for screen in &Screen::ALL[1..] {
        press(handle, "cmd-]", cx);
        cx.update(|cx| assert_eq!(view.read(cx).active(), *screen));
    }
    press(handle, "cmd-]", cx);
    cx.update(|cx| assert_eq!(view.read(cx).active(), Screen::Diagnostics));
    press(handle, "cmd-[", cx);
    cx.update(|cx| assert_eq!(view.read(cx).active(), Screen::History));
}

#[gpui_kit::test]
fn the_agent_footer_shows_the_state(cx: &mut TestAppContext) {
    let (handle, _view) = open(cx);
    assert_eq!(
        label_of(handle, "nav-agent", cx).as_deref(),
        Some("Agent reporting")
    );
    let (handle, _view) = open_with(cx, 1120.0, FixtureScenario::AgentAbsent);
    assert_eq!(
        label_of(handle, "nav-agent", cx).as_deref(),
        Some("Agent no journal")
    );
}

#[gpui_kit::test]
fn the_memory_mark_follows_the_pressure(cx: &mut TestAppContext) {
    let (handle, _view) = open(cx);
    assert_eq!(label_of(handle, "nav-mark-memory", cx), None);
    let (handle, _view) = open_with(cx, 1120.0, FixtureScenario::Pressure);
    let text: Option<String> = label_of(handle, "nav-mark-memory", cx);
    assert!(text.is_some_and(|text| text.starts_with("Memory pressure: ")));
}

fn frames(handle: AnyWindowHandle, count: usize, cx: &mut TestAppContext) {
    for _ in 0..count {
        cx.update_window(handle, |_, window, cx| window.render_frame(cx))
            .unwrap();
        cx.run_until_parked();
    }
}

fn offset(view: &Entity<MainWindow>, cx: &mut TestAppContext) -> f32 {
    cx.update(|cx| view.read(cx).scroll_offset_y())
}

#[gpui_kit::test]
fn a_section_of_another_screen_shows_the_screen_and_scrolls(cx: &mut TestAppContext) {
    let (handle, view) = open_sized(cx, 1120.0, 560.0, FixtureScenario::Healthy);
    frames(handle, 2, cx);
    // Open the caret of Storage, then click "Folder sizes".
    cx.update_window(handle, |_, window, cx| {
        window.within("0-0-1").click("caret", cx);
    })
    .unwrap();
    frames(handle, 2, cx);
    cx.update_window(handle, |_, window, _| {
        assert!(window.try_find("0-0-1-1").is_some(), "caret opens Storage");
    })
    .unwrap();
    cx.update_window(handle, |_, window, cx| window.click("0-0-1-1", cx))
        .unwrap();
    frames(handle, 6, cx);
    cx.update(|cx| assert_eq!(view.read(cx).active(), Screen::Storage));
    assert!(offset(&view, cx) < 0.0, "offset {}", offset(&view, cx));
    cx.update_window(handle, |_, window, _| {
        assert!(window.try_find("nav-storage-folder-sizes").is_some());
    })
    .unwrap();
    // From Storage to a section of Overview below the fold.
    cx.update_window(handle, |_, window, cx| window.click("0-0-0-5", cx))
        .unwrap();
    frames(handle, 6, cx);
    cx.update(|cx| assert_eq!(view.read(cx).active(), Screen::Overview));
    assert!(offset(&view, cx) < 0.0, "offset {}", offset(&view, cx));
}

#[gpui_kit::test]
fn each_screen_keeps_its_scroll_offset(cx: &mut TestAppContext) {
    let (handle, view) = open_sized(cx, 1120.0, 480.0, FixtureScenario::Healthy);
    frames(handle, 2, cx);
    cx.update_window(handle, |_, window, cx| window.click("0-0-0-4", cx))
        .unwrap();
    frames(handle, 6, cx);
    let overview: f32 = offset(&view, cx);
    assert!(overview < 0.0, "offset {overview}");
    press(handle, "cmd-2", cx);
    frames(handle, 3, cx);
    assert!(offset(&view, cx).abs() < 0.5, "Storage starts at the top");
    press(handle, "cmd-1", cx);
    frames(handle, 3, cx);
    assert!((offset(&view, cx) - overview).abs() < 0.5);
}

#[gpui_kit::test]
fn marks_follow_stale_and_unavailable_readings(cx: &mut TestAppContext) {
    for scenario in [FixtureScenario::Stale, FixtureScenario::Unavailable] {
        let (handle, _view) = open_with(cx, 1120.0, scenario);
        assert_eq!(label_of(handle, "nav-mark-memory", cx), None);
    }
    // The Critical case is covered by the unit test of `pressure_mark_name`:
    // no fixture holds a Critical pressure.
}
