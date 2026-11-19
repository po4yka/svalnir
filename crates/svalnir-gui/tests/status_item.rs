//! Tests of the view of the menu bar item. The `AppKit` surface needs a real
//! menu bar, so these tests check the view that the surface draws.

use gpui_kit::{AppContext as _, Bounds, Entity, Point, TestAppContext, px, size};
use std::{sync::Arc, time::SystemTime};
use svalnir_gui::{
    actions::fixture::ActionScript,
    app::{after_last_window_closed, open_main_window_with_model},
    data::{
        fixture::{FixtureScenario, FixtureSource},
        model::Loadable,
        store::{AppModel, INACTIVE_INTERVAL, Topic},
    },
    status_item::{MenuCommand, MenuRow, StatusView, pause_action, status_view},
};

fn model(
    scenario: FixtureScenario,
    actions: ActionScript,
    standing: bool,
    cx: &mut TestAppContext,
) -> Entity<AppModel> {
    cx.update(gpui_kit::init);
    let model: Entity<AppModel> = cx.update(|cx| {
        cx.new(|cx| {
            AppModel::new(
                Arc::new(FixtureSource::new(scenario).with_actions(actions)),
                cx,
            )
        })
    });
    if standing {
        cx.update(|cx| {
            model.update(cx, |model, cx| {
                model.set_standing_topics(&[Topic::Automation], cx);
            });
        });
    }
    cx.run_until_parked();
    model
}

fn view(model: &Entity<AppModel>, cx: &mut TestAppContext) -> StatusView {
    cx.update(|cx| status_view(model.read(cx), SystemTime::now()))
}

fn commands(view: &StatusView) -> Vec<(MenuCommand, bool)> {
    view.rows
        .iter()
        .filter_map(|row| match row {
            MenuRow::Command {
                command, enabled, ..
            } => Some((*command, *enabled)),
            _ => None,
        })
        .collect()
}

fn infos(view: &StatusView) -> Vec<String> {
    view.rows
        .iter()
        .filter_map(|row| match row {
            MenuRow::Info { title, .. } => Some(title.clone()),
            _ => None,
        })
        .collect()
}

#[gpui_kit::test]
fn a_healthy_host_shows_the_grid_the_pressure_and_the_pause_control(cx: &mut TestAppContext) {
    let model = model(FixtureScenario::Healthy, ActionScript::Accept, true, cx);
    let view = view(&model, cx);
    let cells = view.cells.expect("the capacity is known");
    assert!(cells.iter().any(|cell| *cell), "some space is used");
    assert!(!cells.iter().all(|cell| *cell), "some space is free");
    assert_eq!(view.title, "Normal");
    assert!(view.label.contains("Disk:"), "{}", view.label);
    assert!(
        view.label.contains("Memory pressure: Normal"),
        "{}",
        view.label
    );
    assert!(
        view.label.contains("Automation: Not paused"),
        "{}",
        view.label
    );
    assert_eq!(
        commands(&view),
        vec![
            (MenuCommand::PauseHour, true),
            (MenuCommand::PauseOpen, true),
            (MenuCommand::OpenWindow, true),
            (MenuCommand::Quit, true),
        ]
    );
}

#[gpui_kit::test]
fn a_recorded_pause_offers_a_resume(cx: &mut TestAppContext) {
    let model = model(FixtureScenario::Pressure, ActionScript::Accept, true, cx);
    let view = view(&model, cx);
    assert_eq!(view.title, "Warning");
    assert!(
        infos(&view).contains(&"Automation: Paused".to_owned()),
        "{:?}",
        view.rows
    );
    assert_eq!(
        commands(&view),
        vec![
            (MenuCommand::Resume, true),
            (MenuCommand::OpenWindow, true),
            (MenuCommand::Quit, true),
        ]
    );
}

#[gpui_kit::test]
fn an_unavailable_reading_draws_no_grid_and_no_value(cx: &mut TestAppContext) {
    let model = model(FixtureScenario::Unavailable, ActionScript::Accept, true, cx);
    let view = view(&model, cx);
    assert_eq!(view.cells, None, "a failed read is not an empty grid");
    assert_eq!(view.title, "\u{2014}");
    assert!(
        view.label.contains("Memory pressure: \u{2014}"),
        "{}",
        view.label
    );
}

#[gpui_kit::test]
fn without_the_standing_topic_the_pause_is_not_known(cx: &mut TestAppContext) {
    let model = model(FixtureScenario::Healthy, ActionScript::Accept, false, cx);
    cx.update(|cx| {
        assert!(matches!(model.read(cx).automation, Loadable::Loading));
    });
    let view = view(&model, cx);
    assert!(
        infos(&view).contains(&"Automation: Unknown".to_owned()),
        "{:?}",
        view.rows
    );
    // With no authority record read, the control is absent.
    assert_eq!(
        commands(&view),
        vec![(MenuCommand::OpenWindow, true), (MenuCommand::Quit, true)]
    );
}

#[gpui_kit::test]
fn a_pause_command_goes_through_the_model_action(cx: &mut TestAppContext) {
    let model = model(
        FixtureScenario::Healthy,
        ActionScript::Unavailable,
        true,
        cx,
    );
    let action = pause_action(MenuCommand::PauseHour).expect("a pause command");
    cx.update(|cx| model.update(cx, |model, cx| model.run_action(action, cx)));
    cx.run_until_parked();
    let view = view(&model, cx);
    assert!(
        infos(&view).contains(&"Pause request: Unavailable".to_owned()),
        "{:?}",
        view.rows
    );
}

#[gpui_kit::test]
fn the_model_keeps_reading_after_its_window_closes(cx: &mut TestAppContext) {
    let model = model(FixtureScenario::Healthy, ActionScript::Accept, true, cx);
    let (handle, _view) = cx.update(|cx| {
        open_main_window_with_model(
            Bounds::new(Point::default(), size(px(1120.0), px(720.0))),
            model.clone(),
            None,
            cx,
        )
        .expect("open test window")
    });
    cx.run_until_parked();
    cx.update_window(handle, |_, window, _| window.remove_window())
        .unwrap();
    cx.run_until_parked();
    cx.update(|cx| {
        assert_eq!(cx.windows().len(), 0);
        after_last_window_closed(true, &model, cx);
    });
    cx.run_until_parked();
    cx.update(|cx| {
        let model: &AppModel = model.read(cx);
        assert!(!model.is_active(), "no window is active");
        assert!(model.topics().is_empty(), "no screen is in front");
        assert_eq!(model.standing_topics(), &[Topic::Automation]);
        assert!(model.actions.stop.is_none(), "no stop dialog is open");
    });
    // The poll of the model runs on its own at the inactive interval.
    cx.executor().advance_clock(INACTIVE_INTERVAL * 2);
    cx.run_until_parked();
    let view = view(&model, cx);
    assert!(view.cells.is_some(), "the item still has the readings");
    assert_eq!(view.title, "Normal");
}

#[gpui_kit::test]
fn a_stale_pause_state_is_marked(cx: &mut TestAppContext) {
    let model = model(FixtureScenario::Stale, ActionScript::Accept, true, cx);
    let stale: bool = cx.update(|cx| matches!(model.read(cx).automation, Loadable::Stale(_)));
    assert!(stale, "the stale fixture gives a stale authority record");
    let view = view(&model, cx);
    let automation: Vec<String> = infos(&view)
        .into_iter()
        .filter(|title| title.starts_with("Automation:"))
        .collect();
    assert_eq!(automation.len(), 1, "{:?}", view.rows);
    assert!(automation[0].ends_with("(stale)"), "{automation:?}");
    assert!(view.label.contains("(stale)"), "{}", view.label);
}
