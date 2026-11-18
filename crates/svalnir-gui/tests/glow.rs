//! The glow of the LED marks follows the display settings and the pressure.
#![expect(clippy::expect_used, reason = "test code fails by panicking")]

use gpui_kit::{Bounds, Entity, Point, TestAppContext, px, size};
use std::sync::Arc;
use svalnir_gui::{
    app::open_main_window,
    data::fixture::{FixtureScenario, FixtureSource},
    platform::DisplayAccessibility,
    shell::{nav, window::MainWindow},
    theme::glow,
};

fn open(scenario: FixtureScenario, cx: &mut TestAppContext) -> Entity<MainWindow> {
    cx.update(gpui_kit::init);
    cx.update(nav::bind_keys);
    let (_, view) = cx.update(|cx| {
        open_main_window(
            Bounds::new(Point::default(), size(px(1120.0), px(720.0))),
            Arc::new(FixtureSource::new(scenario)),
            None,
            cx,
        )
        .expect("open test window")
    });
    cx.run_until_parked();
    view
}

fn glow_with(
    view: &Entity<MainWindow>,
    display: DisplayAccessibility,
    cx: &mut TestAppContext,
) -> bool {
    cx.update(|cx| view.update(cx, |view, cx| view.set_display(display, cx)));
    cx.run_until_parked();
    cx.update(|cx| glow::enabled(cx))
}

#[gpui_kit::test]
fn the_glow_is_on_with_default_settings_and_normal_pressure(cx: &mut TestAppContext) {
    let view = open(FixtureScenario::Healthy, cx);
    assert!(glow_with(&view, DisplayAccessibility::default(), cx));
}

#[gpui_kit::test]
fn reduce_transparency_and_increase_contrast_turn_the_glow_off(cx: &mut TestAppContext) {
    let view = open(FixtureScenario::Healthy, cx);
    let reduce = DisplayAccessibility {
        reduce_transparency: true,
        increase_contrast: false,
    };
    let contrast = DisplayAccessibility {
        reduce_transparency: false,
        increase_contrast: true,
    };
    assert!(!glow_with(&view, reduce, cx));
    assert!(!glow_with(&view, contrast, cx));
    assert!(glow_with(&view, DisplayAccessibility::default(), cx));
}

#[gpui_kit::test]
fn memory_pressure_turns_the_glow_off(cx: &mut TestAppContext) {
    let view = open(FixtureScenario::Pressure, cx);
    assert!(!glow_with(&view, DisplayAccessibility::default(), cx));
}

#[gpui_kit::test]
fn an_unavailable_pressure_reading_keeps_the_glow(cx: &mut TestAppContext) {
    let view = open(FixtureScenario::Unavailable, cx);
    assert!(glow_with(&view, DisplayAccessibility::default(), cx));
}
