//! Tests of the view of the menu bar item. The `AppKit` surface needs a real
//! menu bar, so these tests check the view that the surface draws.

use gpui_kit::{App, AppContext as _, Bounds, Entity, Point, TestAppContext, px, size};
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
    sync::Arc,
    time::{Duration, SystemTime},
};
use svalnir_gui::{
    actions::fixture::ActionScript,
    app::{after_last_window_closed, open_main_window_with_model},
    data::{
        fixture::{FixtureScenario, FixtureSource},
        model::Loadable,
        store::{ACTIVE_INTERVAL, AppModel, INACTIVE_INTERVAL, Topic},
    },
    status_item::{
        CellPaint, ItemTone, MenuCommand, MenuRow, StatusView, Surface, install_surface,
        is_installed, menu_closed, pause_action, remove, run_command, status_view, update_item,
    },
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
    let grid = view.grid.expect("the capacity is known");
    assert!(
        grid.contains(&CellPaint::Filled(ItemTone::Brand)),
        "some space is used: {grid:?}"
    );
    // The fixture disk guard warns below 40 GiB free of 512 GB (cells 18
    // and 19) and has its emergency below 10 GiB free, 2% of the volume:
    // less than half a cell, so the zone keeps the last cell, and the
    // warning zone stays before it.
    assert_eq!(grid[17], CellPaint::Empty, "{grid:?}");
    assert_eq!(grid[18], CellPaint::Tint(ItemTone::Warning), "{grid:?}");
    assert_eq!(grid[19], CellPaint::Tint(ItemTone::Negative), "{grid:?}");
    assert_eq!(view.pressure, Some(ItemTone::Positive));
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
    assert_eq!(view.pressure, Some(ItemTone::Warning), "tone and text");
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
    assert_eq!(view.grid, None, "a failed read is not an empty grid");
    assert_eq!(view.pressure, None, "a failed read has no tone");
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
    // With no agent, the pause is written to the authority record
    // directly, as the window and the CLI do, and the menu says so.
    assert!(
        view.rows.iter().any(|row| matches!(
            row,
            MenuRow::Info { title, detail: Some(detail) }
                if title == "Pause request: Accepted" && detail.contains("Path: no agent runs")
        )),
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
    let before: Option<SystemTime> = cx.update(|cx| model.read(cx).last_refresh());
    // The poll of the model runs on its own at the inactive interval.
    cx.executor().advance_clock(INACTIVE_INTERVAL * 2);
    cx.run_until_parked();
    let after: Option<SystemTime> = cx.update(|cx| model.read(cx).last_refresh());
    assert!(
        after.is_some() && after != before,
        "a poll ran after the window closed: {before:?} then {after:?}"
    );
    let view = view(&model, cx);
    assert!(view.grid.is_some(), "the item still has the readings");
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

#[gpui_kit::test]
fn an_absent_agent_is_not_shown_as_a_normal_state(cx: &mut TestAppContext) {
    let model = model(FixtureScenario::AgentAbsent, ActionScript::Accept, true, cx);
    let view = view(&model, cx);
    assert!(
        infos(&view).contains(&"Agent: no journal".to_owned()),
        "{:?}",
        view.rows
    );
    assert!(
        view.label
            .contains("No automatic protection is known to be active."),
        "{}",
        view.label
    );
}

#[gpui_kit::test]
fn fixture_values_are_marked_as_not_measured(cx: &mut TestAppContext) {
    let model = model(FixtureScenario::Healthy, ActionScript::Accept, true, cx);
    let view = view(&model, cx);
    let first: Option<&MenuRow> = view.rows.first();
    assert!(
        matches!(first, Some(MenuRow::Info { title, .. }) if title.starts_with("Fixture data: healthy.")),
        "{:?}",
        view.rows
    );
    assert!(
        view.label.contains("Values are not measurements."),
        "{}",
        view.label
    );
}

/// A surface that records each view, with a menu that a test opens.
#[derive(Default)]
struct Recorder {
    views: RefCell<Vec<StatusView>>,
    menu_open: Cell<bool>,
}

struct RecordingSurface(Rc<Recorder>);

impl Surface for RecordingSurface {
    fn apply(&self, view: &StatusView) -> bool {
        self.0.views.borrow_mut().push(view.clone());
        !self.0.menu_open.get()
    }
}

fn installed(
    cx: &mut TestAppContext,
    actions: ActionScript,
) -> (Entity<AppModel>, Rc<Recorder>, Rc<Cell<usize>>) {
    let model = model(FixtureScenario::Healthy, actions, false, cx);
    let recorder: Rc<Recorder> = Rc::new(Recorder::default());
    let shown: Rc<Cell<usize>> = Rc::new(Cell::new(0));
    let counter: Rc<Cell<usize>> = Rc::clone(&shown);
    let show: Rc<dyn Fn(&mut App)> = Rc::new(move |_: &mut App| counter.set(counter.get() + 1));
    let surface = RecordingSurface(Rc::clone(&recorder));
    cx.update(|cx| install_surface(model.clone(), show, Box::new(surface), cx));
    cx.run_until_parked();
    (model, recorder, shown)
}

#[gpui_kit::test]
fn the_item_draws_a_view_only_when_it_changes(cx: &mut TestAppContext) {
    let (model, recorder, _) = installed(cx, ActionScript::Accept);
    cx.update(|cx| {
        assert!(is_installed(cx));
        assert_eq!(model.read(cx).standing_topics(), &[Topic::Automation]);
    });
    let drawn: usize = recorder.views.borrow().len();
    assert!(drawn >= 1, "the install draws the first view");
    cx.update(update_item);
    cx.update(update_item);
    assert_eq!(
        recorder.views.borrow().len(),
        drawn,
        "an equal view is not drawn again"
    );
}

#[gpui_kit::test]
fn a_view_that_waits_for_the_menu_is_drawn_when_the_menu_closes(cx: &mut TestAppContext) {
    let (model, recorder, _) = installed(cx, ActionScript::Unavailable);
    recorder.menu_open.set(true);
    // A pause request changes the view while the menu is open.
    let action = pause_action(MenuCommand::PauseHour).expect("a pause command");
    cx.update(|cx| model.update(cx, |model, cx| model.run_action(action, cx)));
    cx.run_until_parked();
    let while_open: usize = recorder.views.borrow().len();
    cx.update(update_item);
    cx.update(update_item);
    assert_eq!(
        recorder.views.borrow().len(),
        while_open,
        "the same waiting view is not drawn at each poll"
    );
    recorder.menu_open.set(false);
    cx.update(menu_closed);
    let views = recorder.views.borrow();
    assert_eq!(
        views.len(),
        while_open + 1,
        "the close draws the waiting view"
    );
    let last: &StatusView = views.last().expect("a view");
    assert!(
        infos(last).contains(&"Pause request: Accepted".to_owned()),
        "{:?}",
        last.rows
    );
}

#[gpui_kit::test]
fn the_menu_commands_reach_the_window_and_the_model(cx: &mut TestAppContext) {
    let (model, _recorder, shown) = installed(cx, ActionScript::Refuse);
    cx.update(|cx| run_command(MenuCommand::OpenWindow, cx));
    assert_eq!(shown.get(), 1, "Open Svalnir opens or focuses the window");
    cx.update(|cx| run_command(MenuCommand::PauseOpen, cx));
    cx.run_until_parked();
    let view = view(&model, cx);
    assert!(
        infos(&view)
            .iter()
            .any(|title| title.starts_with("Pause request: ")),
        "the refusal of the pause shows in the menu: {:?}",
        view.rows
    );
}

#[gpui_kit::test]
fn a_removed_item_runs_no_command(cx: &mut TestAppContext) {
    let (_model, _recorder, shown) = installed(cx, ActionScript::Accept);
    cx.update(|cx| {
        assert!(remove(cx));
        assert!(!is_installed(cx));
        run_command(MenuCommand::OpenWindow, cx);
        update_item(cx);
        menu_closed(cx);
        assert!(!remove(cx));
    });
    assert_eq!(shown.get(), 0);
}

/// Regression for D-13 of host run 4: after a resume from the menu, the
/// menu said "Pause request: Accepted". The line is named after the last
/// command.
#[gpui_kit::test]
fn the_request_line_names_the_last_command(cx: &mut TestAppContext) {
    let (model, _recorder, _shown) = installed(cx, ActionScript::Unavailable);
    cx.update(|cx| run_command(MenuCommand::PauseHour, cx));
    cx.run_until_parked();
    let paused = view(&model, cx);
    assert!(
        infos(&paused).contains(&"Pause request: Accepted".to_owned()),
        "{:?}",
        paused.rows
    );
    cx.update(|cx| run_command(MenuCommand::Resume, cx));
    cx.run_until_parked();
    let resumed = view(&model, cx);
    let titles = infos(&resumed);
    assert!(
        titles.contains(&"Resume request: Accepted".to_owned()),
        "{titles:?}"
    );
    assert!(
        !titles
            .iter()
            .any(|title| title.starts_with("Pause request: ")),
        "{titles:?}"
    );
}

/// A window that becomes active again reads at the active interval at once.
/// The poll loop does not finish the long sleep of the inactive interval
/// first, so the readings do not stop for up to 30 s.
#[gpui_kit::test]
fn the_poll_follows_a_window_that_becomes_active(cx: &mut TestAppContext) {
    let model = model(FixtureScenario::Healthy, ActionScript::Accept, false, cx);
    cx.run_until_parked();
    cx.update(|cx| model.update(cx, |model, cx| model.set_active(false, cx)));
    // The loop starts its next pass and sleeps the inactive interval.
    cx.executor().advance_clock(ACTIVE_INTERVAL);
    cx.run_until_parked();
    cx.update(|cx| model.update(cx, |model, cx| model.set_active(true, cx)));
    cx.run_until_parked();
    let before: usize = cx.update(|cx| model.read(cx).history.len());
    cx.executor()
        .advance_clock(ACTIVE_INTERVAL + Duration::from_millis(100));
    cx.run_until_parked();
    let after: usize = cx.update(|cx| model.read(cx).history.len());
    assert!(
        after > before,
        "no host reading in one active interval: {before} then {after}"
    );
}
