//! UI tests of the state-changing actions with fixture sources: each action
//! state (accepted, refused, unavailable, pending, waiting for exit, and
//! exited), the confirmations, and their cancel. A fixture action path
//! writes nothing.
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
    actions::{ActionState, Slot, fixture::ActionScript},
    app::open_main_window,
    data::{
        fixture::{FixtureScenario, FixtureSource},
        model::Loadable,
        records::Protection,
    },
    shell::{
        nav::{self, Screen},
        window::MainWindow,
    },
};

/// Opens the window with `source` and shows `screen`.
fn open(
    source: FixtureSource,
    screen: Screen,
    cx: &mut TestAppContext,
) -> (AnyWindowHandle, Entity<MainWindow>) {
    cx.update(gpui_kit::init);
    cx.update(nav::bind_keys);
    let (handle, view) = cx.update(|cx| {
        open_main_window(
            Bounds::new(Point::default(), size(px(1280.0), px(900.0))),
            Arc::new(source),
            None,
            cx,
        )
        .expect("open test window")
    });
    cx.run_until_parked();
    let key: String = format!("cmd-{}", screen.index() + 1);
    cx.update_window(handle, |_, window, cx| window.press(&key, cx))
        .unwrap();
    cx.run_until_parked();
    (handle, view)
}

fn label(handle: AnyWindowHandle, id: &str, cx: &mut TestAppContext) -> Option<String> {
    let mut found: Option<String> = None;
    cx.update_window(handle, |_, window, cx| {
        window.render_frame(cx);
        found = window
            .try_find(id.to_owned())
            .and_then(|node| node.label().map(str::to_owned));
    })
    .unwrap();
    found
}

fn click(handle: AnyWindowHandle, id: &str, cx: &mut TestAppContext) {
    cx.update_window(handle, |_, window, cx| {
        window.render_frame(cx);
        window.click(id.to_owned(), cx);
    })
    .unwrap();
    cx.run_until_parked();
}

fn state_of(
    view: &Entity<MainWindow>,
    slot: &Slot,
    cx: &mut TestAppContext,
) -> Option<ActionState> {
    cx.update(|cx| view.read(cx).model().read(cx).actions.state(slot).cloned())
}

#[gpui_kit::test]
fn a_pause_with_an_agent_is_accepted(cx: &mut TestAppContext) {
    let (handle, view) = open(
        FixtureSource::new(FixtureScenario::Healthy),
        Screen::Automation,
        cx,
    );
    assert_eq!(label(handle, "automation-pause-state", cx), None);
    click(handle, "automation-pause-hour", cx);
    let text = label(handle, "automation-pause-state", cx).expect("state line");
    assert!(text.starts_with("Accepted: Pause is accepted."), "{text}");
    assert!(
        text.contains("Path: the agent holds the coordinator lock"),
        "{text}"
    );
    assert!(text.ends_with("(Fixture: nothing was written.)"), "{text}");
    assert!(matches!(
        state_of(&view, &Slot::Pause, cx),
        Some(ActionState::Accepted { .. })
    ));
}

#[gpui_kit::test]
fn with_no_agent_a_pause_is_written_directly_and_names_the_path(cx: &mut TestAppContext) {
    let (handle, view) = open(
        FixtureSource::new(FixtureScenario::AgentAbsent),
        Screen::Automation,
        cx,
    );
    click(handle, "automation-pause-open", cx);
    let text = label(handle, "automation-pause-state", cx).expect("state line");
    assert!(text.starts_with("Accepted: Pause is accepted."), "{text}");
    assert!(
        text.contains("Path: no agent runs, so the window wrote the record directly"),
        "{text}"
    );
    assert!(matches!(
        state_of(&view, &Slot::Pause, cx),
        Some(ActionState::Accepted { .. })
    ));
}

#[gpui_kit::test]
fn with_no_agent_a_queue_request_is_unavailable_and_names_the_cause(cx: &mut TestAppContext) {
    let (handle, view) = open(
        FixtureSource::new(FixtureScenario::Pressure).with_actions(ActionScript::Unavailable),
        Screen::History,
        cx,
    );
    click(handle, "history-cancel-op_fixture_0002", cx);
    let text = label(handle, "history-action-op_fixture_0002", cx).expect("state line");
    assert!(
        text.starts_with("Unavailable: No agent holds the coordinator lock"),
        "{text}"
    );
    assert!(
        text.contains("does not act in place of the agent"),
        "{text}"
    );
    assert!(matches!(
        state_of(&view, &Slot::Operation("op_fixture_0002".to_owned()), cx),
        Some(ActionState::Unavailable(_))
    ));
}

#[gpui_kit::test]
fn a_refusal_shows_the_typed_reason(cx: &mut TestAppContext) {
    let (handle, _view) = open(
        FixtureSource::new(FixtureScenario::Drift),
        Screen::Automation,
        cx,
    );
    click(handle, "automation-disable-disk-guard", cx);
    let text = label(handle, "automation-guard-state-disk-guard", cx).expect("state line");
    assert!(text.starts_with("Refused: "), "{text}");
    assert!(
        text.ends_with("(policy_revision_changed). Nothing changed."),
        "{text}"
    );
}

#[gpui_kit::test]
fn a_pending_request_takes_no_second_request(cx: &mut TestAppContext) {
    let (handle, view) = open(
        FixtureSource::new(FixtureScenario::Healthy).with_actions(ActionScript::Pending),
        Screen::Automation,
        cx,
    );
    click(handle, "automation-pause-hour", cx);
    let text = label(handle, "automation-pause-state", cx).expect("state line");
    assert_eq!(
        text,
        "Sent: The request is sent. The agent did not answer yet."
    );
    // The button shows its loading state and takes no click.
    click(handle, "automation-pause-open", cx);
    assert_eq!(
        state_of(&view, &Slot::Pause, cx),
        Some(ActionState::Pending)
    );
}

#[gpui_kit::test]
fn an_enable_needs_the_confirmation_that_shows_the_revision_and_the_classes(
    cx: &mut TestAppContext,
) {
    let (handle, view) = open(
        FixtureSource::new(FixtureScenario::Healthy),
        Screen::Automation,
        cx,
    );
    let slot = Slot::Guard(svalnir_core::policy::PolicyId::MemoryGuard);
    click(handle, "automation-enable-memory-guard", cx);
    // The click opens the confirmation; it sends nothing.
    assert_eq!(state_of(&view, &slot, cx), None);
    let object = label(handle, "confirm-object", cx).expect("object");
    assert!(
        object.starts_with("Revision rev-fixture-1 is in effect"),
        "{object}"
    );
    assert!(label(handle, "confirm-class-ForceApplicationExit", cx).is_some());
    let consequence = label(handle, "confirm-consequence", cx).expect("consequence");
    assert!(
        consequence.contains("force an application to quit"),
        "{consequence}"
    );
    // Cancel closes it and sends nothing.
    click(handle, "confirm-cancel", cx);
    assert_eq!(label(handle, "confirm-object", cx), None);
    assert_eq!(state_of(&view, &slot, cx), None);
    // A confirmation sends the request.
    click(handle, "automation-enable-memory-guard", cx);
    click(handle, "confirm-ok", cx);
    assert!(matches!(
        state_of(&view, &slot, cx),
        Some(ActionState::Accepted { .. })
    ));
}

#[gpui_kit::test]
fn a_rearm_names_the_incident_and_the_generation(cx: &mut TestAppContext) {
    let (handle, view) = open(
        FixtureSource::new(FixtureScenario::Pressure),
        Screen::Automation,
        cx,
    );
    assert_eq!(
        label(handle, "automation-incident-inc-fixture-memory-1", cx).as_deref(),
        Some("Open incident: inc-fixture-memory-1 · generation 2")
    );
    click(handle, "automation-rearm-inc-fixture-memory-1", cx);
    let object = label(handle, "confirm-object", cx).expect("object");
    assert!(object.contains("budget generation 2 ends"), "{object}");
    click(handle, "confirm-ok", cx);
    assert!(matches!(
        state_of(
            &view,
            &Slot::Incident("inc-fixture-memory-1".to_owned()),
            cx
        ),
        Some(ActionState::Accepted { .. })
    ));
}

#[gpui_kit::test]
fn an_unknown_outcome_has_an_acknowledgment_and_an_admitted_operation_a_cancel(
    cx: &mut TestAppContext,
) {
    let (handle, view) = open(
        FixtureSource::new(FixtureScenario::Pressure),
        Screen::History,
        cx,
    );
    // A completed operation has no control.
    assert_eq!(label(handle, "history-cancel-op_fixture_0001", cx), None);
    assert_eq!(
        label(handle, "history-acknowledge-op_fixture_0001", cx),
        None
    );
    assert!(label(handle, "history-acknowledge-op_fixture_00zz", cx).is_some());
    assert_eq!(label(handle, "history-cancel-op_fixture_00zz", cx), None);
    click(handle, "history-cancel-op_fixture_0002", cx);
    let text = label(handle, "history-action-op_fixture_0002", cx).expect("state line");
    assert!(text.starts_with("Accepted: Cancel is accepted."), "{text}");
    click(handle, "history-acknowledge-op_fixture_00zz", cx);
    assert!(matches!(
        state_of(&view, &Slot::Operation("op_fixture_00zz".to_owned()), cx),
        Some(ActionState::Accepted { .. })
    ));
}

/// The first group that the catalog does not protect: its instance and
/// name.
fn stoppable_group(view: &Entity<MainWindow>, cx: &mut TestAppContext) -> (String, String) {
    cx.update(|cx| {
        let model = view.read(cx).model().read(cx);
        let processes = match &model.processes {
            Loadable::Ready(processes) => Some(processes),
            _ => None,
        }
        .expect("the processes are read");
        let group = processes
            .applications
            .iter()
            .find(|row| row.protection == Protection::NotProtected)
            .expect("a group that is not protected");
        (group.instance.clone(), group.name.clone())
    })
}

#[gpui_kit::test]
fn a_stop_shows_the_bound_processes_and_is_done_only_after_the_exit(cx: &mut TestAppContext) {
    let (handle, view) = open(
        FixtureSource::new(FixtureScenario::Healthy),
        Screen::Applications,
        cx,
    );
    let (instance, name) = stoppable_group(&view, cx);
    let slot = Slot::Stop(instance.clone());
    click(handle, &format!("applications-stop-{instance}"), cx);
    let object = label(handle, "confirm-object", cx).expect("object");
    assert!(object.starts_with("The plans bind "), "{object}");
    assert!(object.contains(&name), "{object}");
    let consequence = label(handle, "confirm-consequence", cx).expect("consequence");
    assert!(consequence.contains("Unsaved data"), "{consequence}");
    assert!(label(handle, "confirm-expiry", cx).is_some());
    // The confirmation sends nothing.
    assert_eq!(state_of(&view, &slot, cx), None);
    click(handle, "confirm-force", cx);
    assert_eq!(label(handle, "confirm-object", cx), None);
    let text = label(handle, &format!("applications-stop-state-{instance}"), cx).expect("state");
    assert!(
        text.starts_with("Waiting for exit: The agent admitted operation op-fixture-stop."),
        "{text}"
    );
    // A refresh reads the record of the operation, as the poll does.
    cx.update_window(handle, |_, window, cx| window.press("cmd-r", cx))
        .unwrap();
    cx.run_until_parked();
    let text = label(handle, &format!("applications-stop-state-{instance}"), cx).expect("state");
    assert_eq!(
        text,
        "Exited: Operation op-fixture-stop completed: the agent confirmed the exit."
    );
}

#[gpui_kit::test]
fn escape_cancels_the_stop_confirmation(cx: &mut TestAppContext) {
    let (handle, view) = open(
        FixtureSource::new(FixtureScenario::Healthy),
        Screen::Applications,
        cx,
    );
    let (instance, _name) = stoppable_group(&view, cx);
    click(handle, &format!("applications-stop-{instance}"), cx);
    assert!(label(handle, "confirm-object", cx).is_some());
    cx.update_window(handle, |_, window, cx| window.press("escape", cx))
        .unwrap();
    cx.run_until_parked();
    assert_eq!(label(handle, "confirm-object", cx), None);
    assert!(cx.update(|cx| view.read(cx).model().read(cx).actions.stop.is_none()));
    assert_eq!(state_of(&view, &Slot::Stop(instance), cx), None);
}

#[gpui_kit::test]
fn with_no_agent_no_stop_plan_is_made(cx: &mut TestAppContext) {
    let (handle, view) = open(
        FixtureSource::new(FixtureScenario::Healthy).with_actions(ActionScript::Unavailable),
        Screen::Applications,
        cx,
    );
    let (instance, _name) = stoppable_group(&view, cx);
    click(handle, &format!("applications-stop-{instance}"), cx);
    let text = label(handle, "confirm-failed", cx).expect("failed state");
    assert!(
        text.starts_with("Unavailable: No agent holds the coordinator lock"),
        "{text}"
    );
    assert_eq!(label(handle, "confirm-force", cx), None);
}

#[gpui_kit::test]
fn a_protected_group_has_no_stop(cx: &mut TestAppContext) {
    let (handle, view) = open(
        FixtureSource::new(FixtureScenario::Healthy),
        Screen::Applications,
        cx,
    );
    let protected: Option<String> = cx.update(|cx| {
        let model = view.read(cx).model().read(cx);
        let Loadable::Ready(processes) = &model.processes else {
            return None;
        };
        processes
            .applications
            .iter()
            .find(|row| row.protection != Protection::NotProtected)
            .map(|row| row.instance.clone())
    });
    let instance = protected.expect("the fixture has a protected group");
    assert_eq!(
        label(handle, &format!("applications-stop-{instance}"), cx),
        None
    );
    assert_eq!(
        label(handle, &format!("applications-stop-none-{instance}"), cx).as_deref(),
        Some("No stop")
    );
}

/// Opens Applications, stops the first group that is not protected with a
/// force quit, and reads the final record of its operation.
fn stop_until_settled(cx: &mut TestAppContext) {
    let (handle, view) = open(
        FixtureSource::new(FixtureScenario::Healthy),
        Screen::Applications,
        cx,
    );
    let (instance, _name) = stoppable_group(&view, cx);
    click(handle, &format!("applications-stop-{instance}"), cx);
    click(handle, "confirm-force", cx);
    for _ in 0..2 {
        cx.update_window(handle, |_, window, cx| window.press("cmd-r", cx))
            .unwrap();
        cx.run_until_parked();
    }
}

#[gpui_kit::test]
fn a_settled_stop_posts_one_notification(cx: &mut TestAppContext) {
    cx.update(|cx| cx.set_app_identity("dev.svalnir.test", "Svalnir"));
    stop_until_settled(cx);
    let shown = cx.shown_system_notifications();
    let stops: Vec<_> = shown
        .iter()
        .filter(|note| note.tag.as_ref() == "svalnir-stop-op-fixture-stop")
        .collect();
    assert_eq!(stops.len(), 1, "{shown:?}");
    assert_eq!(
        stops.first().map(|note| note.title.as_ref()),
        Some("Stop: Exited")
    );
}

#[gpui_kit::test]
fn the_off_switch_posts_no_notification(cx: &mut TestAppContext) {
    cx.update(|cx| {
        cx.set_app_identity("dev.svalnir.test", "Svalnir");
        cx.set_global(svalnir_gui::notify::NotificationsOff);
    });
    stop_until_settled(cx);
    assert_eq!(cx.shown_system_notifications(), Vec::new());
}
