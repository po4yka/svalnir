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
    AnyWindowHandle, AppContext as _, Bounds, Context, Entity, IntoElement, ParentElement as _,
    Pixels, Point, Render, Styled as _, TestAppContext, Window, WindowOptions, div, px, size,
    test::TestWindowExt as _,
};
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};
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
    theme::tokens::Tokens,
    ui::action_status::action_status_short,
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

fn bounds_of(handle: AnyWindowHandle, id: &str, cx: &mut TestAppContext) -> Option<Bounds<Pixels>> {
    let mut found: Option<Bounds<Pixels>> = None;
    cx.update_window(handle, |_, window, cx| {
        window.render_frame(cx);
        found = window.try_find(id.to_owned()).map(|node| node.bounds());
    })
    .unwrap();
    found
}

/// Moves the pointer over `id` and waits longer than the show delay of a
/// tooltip. Gives the accessible label of the tooltip of `id`, or `None`
/// when no tooltip shows.
fn tooltip_of(handle: AnyWindowHandle, id: &str, cx: &mut TestAppContext) -> Option<String> {
    cx.update_window(handle, |_, window, cx| window.hover(id.to_owned(), cx))
        .unwrap();
    cx.executor().advance_clock(Duration::from_secs(1));
    cx.run_until_parked();
    label(handle, &format!("{id}-tooltip"), cx)
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
    // The acknowledgment first: the state line of the cancel wraps in its
    // cell and moves the later rows down.
    click(handle, "history-acknowledge-op_fixture_00zz", cx);
    assert!(matches!(
        state_of(&view, &Slot::Operation("op_fixture_00zz".to_owned()), cx),
        Some(ActionState::Accepted { .. })
    ));
    click(handle, "history-cancel-op_fixture_0002", cx);
    let text = label(handle, "history-action-op_fixture_0002", cx).expect("state line");
    assert!(
        text.starts_with("Accepted: The stop fence is recorded."),
        "{text}"
    );
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

#[gpui_kit::test]
fn a_stale_controller_reading_turns_the_rearm_off_with_the_reason(cx: &mut TestAppContext) {
    let (handle, view) = open(
        FixtureSource::new(FixtureScenario::Stale),
        Screen::Automation,
        cx,
    );
    // The stale status record names the incident; the control is off.
    assert_eq!(
        label(handle, "automation-incident-inc-fixture-memory-1", cx).as_deref(),
        Some("Open incident: inc-fixture-memory-1 · generation 2")
    );
    let reason = label(handle, "automation-rearm-off-memory-guard", cx).expect("reason");
    assert!(
        reason.starts_with("Rearm is off: ") && reason.contains("12 min"),
        "{reason}"
    );
    click(handle, "automation-rearm-inc-fixture-memory-1", cx);
    assert_eq!(label(handle, "confirm-object", cx), None, "no dialog opens");
    assert_eq!(
        state_of(
            &view,
            &Slot::Incident("inc-fixture-memory-1".to_owned()),
            cx
        ),
        None
    );
}

#[gpui_kit::test]
fn the_rearm_offers_an_incident_that_only_the_controller_reading_has(cx: &mut TestAppContext) {
    let (handle, _view) = open(
        FixtureSource::new(FixtureScenario::Drift).with_actions(ActionScript::Accept),
        Screen::Automation,
        cx,
    );
    assert_eq!(
        label(handle, "automation-incident-inc-fixture-disk-1", cx).as_deref(),
        Some("Open incident: inc-fixture-disk-1 · generation 1")
    );
    assert_eq!(label(handle, "automation-rearm-off-disk-guard", cx), None);
    click(handle, "automation-rearm-inc-fixture-disk-1", cx);
    let object = label(handle, "confirm-object", cx).expect("object");
    assert!(object.contains("inc-fixture-disk-1"), "{object}");
}

#[gpui_kit::test]
fn with_no_journal_the_rearm_is_off(cx: &mut TestAppContext) {
    let (handle, _view) = open(
        FixtureSource::new(FixtureScenario::AgentAbsent),
        Screen::Automation,
        cx,
    );
    let reasons: Vec<String> = ["memory-guard", "disk-guard"]
        .into_iter()
        .filter_map(|name| label(handle, &format!("automation-rearm-off-{name}"), cx))
        .collect();
    assert!(!reasons.is_empty(), "no guard says that the rearm is off");
    for reason in reasons {
        assert!(reason.starts_with("Rearm is off: "), "{reason}");
    }
}

#[gpui_kit::test]
fn the_stop_confirmation_lists_each_bound_target_with_its_evidence(cx: &mut TestAppContext) {
    let (handle, view) = open(
        FixtureSource::new(FixtureScenario::Healthy),
        Screen::Applications,
        cx,
    );
    let (instance, _name) = stoppable_group(&view, cx);
    click(handle, &format!("applications-stop-{instance}"), cx);
    let targets = cx.update(|cx| {
        view.read(cx)
            .model()
            .read(cx)
            .actions
            .stop
            .as_ref()
            .and_then(|(_, proposal)| match proposal {
                svalnir_gui::actions::Proposal::Ready(ready) => Some(ready.targets.clone()),
                _ => None,
            })
            .expect("ready plans")
    });
    assert!(targets.len() > 12, "the fixture plan binds more than 12");
    let list = label(handle, "confirm-targets", cx).expect("list");
    assert!(
        list.starts_with(&format!("{} bound processes.", targets.len())),
        "{list}"
    );
    assert!(list.contains("arrow keys"), "{list}");
    // Each target of the plan has a row, also past the twelfth; there is no
    // count of the others.
    for target in &targets {
        let row = label(handle, &format!("confirm-target-{}", target.pid), cx)
            .unwrap_or_else(|| panic!("no row for PID {}", target.pid));
        assert!(row.contains(&target.evidence()), "{row}");
        assert!(row.contains("start "), "{row}");
    }
    assert_eq!(label(handle, "confirm-more", cx), None);
}

/// Regression for D-9: the button row of the stop confirmation was wider
/// than the dialog, so a button with a long application name was outside
/// the left edge of the dialog.
#[gpui_kit::test]
fn the_stop_buttons_stay_inside_the_dialog_with_a_long_name(cx: &mut TestAppContext) {
    let (handle, _view) = open(
        FixtureSource::new(FixtureScenario::Healthy),
        Screen::Applications,
        cx,
    );
    let name = "com.example.sync.agent.background-transfer-service";
    click(handle, &format!("applications-stop-fixture-{name}"), cx);
    let object = bounds_of(handle, "confirm-object", cx).expect("object");
    let footer = bounds_of(handle, "confirm-footer", cx).expect("footer");
    assert!(
        footer.left() >= object.left() - px(1.0) && footer.right() <= object.right() + px(1.0),
        "footer {footer:?}, body {object:?}"
    );
    for id in ["confirm-cancel", "confirm-ok", "confirm-force"] {
        let button = bounds_of(handle, id, cx).expect(id);
        assert!(
            button.left() >= footer.left() && button.right() <= footer.right(),
            "{id} {button:?}, footer {footer:?}"
        );
    }
    // The accessible label keeps the full name.
    let force = label(handle, "confirm-force", cx).expect("force");
    assert_eq!(force, format!("Force quit {name}"));
}

/// Regression for D-10: the state line of a cancel overflowed the State
/// column and covered the "Observed change" column. A line that wraps in
/// full made the row about ten lines tall, so the row shows at most two
/// lines of the sentence. The text is not cut with no path to it: the
/// accessible label of the row line and the line in the detail view, which
/// the Details button of the row opens, have the full text.
#[gpui_kit::test]
fn the_state_line_of_a_cancel_stays_in_the_state_column(cx: &mut TestAppContext) {
    let (handle, view) = open(
        FixtureSource::new(FixtureScenario::Pressure),
        Screen::History,
        cx,
    );
    click(handle, "history-cancel-op_fixture_0002", cx);
    let line = bounds_of(handle, "history-action-op_fixture_0002", cx).expect("state line");
    let state = bounds_of(handle, "history-state-op_fixture_0002", cx).expect("pill");
    let observed = bounds_of(handle, "history-observed-op_fixture_0002", cx).expect("observed");
    assert!(line.left() >= state.left() - px(1.0), "{line:?} {state:?}");
    assert!(
        line.right() <= observed.left(),
        "state line {line:?}, observed change {observed:?}"
    );
    // Two lines of 12 px text: the line height of the theme is less than
    // 21 px. The full sentence of the fixture needs more than six lines in
    // the State column.
    let sentence =
        bounds_of(handle, "history-action-op_fixture_0002-sentence", cx).expect("sentence");
    assert!(
        sentence.size.height <= px(42.0),
        "the sentence of the row is not short: {sentence:?}"
    );
    let Some(ActionState::Accepted { detail }) =
        state_of(&view, &Slot::Operation("op_fixture_0002".to_owned()), cx)
    else {
        panic!("the cancel is accepted");
    };
    let full: String = format!("Accepted: {detail}");
    assert_eq!(
        label(handle, "history-action-op_fixture_0002", cx).as_deref(),
        Some(full.as_str())
    );
    // The pointer path: the sentence is cut, so the line has a tooltip with
    // the full text.
    assert_eq!(
        tooltip_of(handle, "history-action-op_fixture_0002", cx).as_deref(),
        Some(full.as_str())
    );
    // The keyboard path to the full text: the Details button of the row.
    assert_eq!(
        label(handle, "history-detail-action-op_fixture_0002", cx),
        None
    );
    click(handle, "history-details-op_fixture_0002", cx);
    assert_eq!(
        label(handle, "history-detail-action-op_fixture_0002", cx).as_deref(),
        Some(full.as_str())
    );
}

/// Two short state lines in cells of the same width: one sentence fits in
/// two lines, the other does not.
struct ShortLines;

/// The width of a cell of [`ShortLines`].
const CELL_WIDTH: f32 = 240.0;

/// A sentence that fits in two lines of [`CELL_WIDTH`].
const FITS: &str = "Done.";

/// A sentence that needs more than two lines of [`CELL_WIDTH`].
const CUT: &str = "The stop fence is recorded. The agent stops the operation at the next safe point and records the result in the journal.";

impl Render for ShortLines {
    fn render(&mut self, _: &mut Window, _: &mut Context<Self>) -> impl IntoElement {
        let tokens: Tokens = *Tokens::for_dark(false);
        let now: SystemTime = SystemTime::UNIX_EPOCH;
        let line = |id: &'static str, detail: &str| {
            div().w(px(CELL_WIDTH)).child(action_status_short(
                id,
                &ActionState::Accepted {
                    detail: detail.to_owned(),
                },
                now,
                &tokens,
            ))
        };
        div()
            .size_full()
            .flex()
            .flex_col()
            .gap(px(40.0))
            .child(line("fits", FITS))
            .child(line("cut", CUT))
    }
}

/// The tooltip of a short state line shows only when the line cuts the
/// sentence. The accessible label has the full text in each case.
#[gpui_kit::test]
fn a_short_line_has_a_tooltip_only_when_its_sentence_is_cut(cx: &mut TestAppContext) {
    cx.update(gpui_kit::init);
    let window = cx.update(|cx| {
        cx.open_window(WindowOptions::default(), |_, cx| cx.new(|_| ShortLines))
            .expect("open test window")
    });
    let handle: AnyWindowHandle = window.into();
    cx.run_until_parked();
    let fits: String = format!("Accepted: {FITS}");
    let cut: String = format!("Accepted: {CUT}");
    assert_eq!(label(handle, "fits", cx).as_deref(), Some(fits.as_str()));
    assert_eq!(label(handle, "cut", cx).as_deref(), Some(cut.as_str()));
    let cut_sentence = bounds_of(handle, "cut-sentence", cx).expect("sentence");
    assert!(
        cut_sentence.size.height <= px(42.0),
        "the sentence is not cut: {cut_sentence:?}"
    );
    assert_eq!(tooltip_of(handle, "fits", cx), None);
    assert_eq!(tooltip_of(handle, "cut", cx).as_deref(), Some(cut.as_str()));
}

/// Opens the window with `source` at `width` and shows `screen`.
fn open_at(
    source: FixtureSource,
    screen: Screen,
    width: f32,
    cx: &mut TestAppContext,
) -> (AnyWindowHandle, Entity<MainWindow>) {
    cx.update(gpui_kit::init);
    cx.update(nav::bind_keys);
    let (handle, view) = cx.update(|cx| {
        open_main_window(
            Bounds::new(Point::default(), size(px(width), px(900.0))),
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

/// Regression for D-14 of host run 4: the pill "Waiting for admission" and
/// its sentence were wider than the Stop column and were cut at the right
/// edge of the table. The short state line is now in a row below the row
/// of the group and spans the table, with the full line as its label, its
/// tooltip, and in the dialog of the Details button.
#[gpui_kit::test]
fn the_state_of_a_stop_stays_inside_its_row(cx: &mut TestAppContext) {
    for width in [1120.0, 720.0] {
        let (handle, view) = open_at(
            FixtureSource::new(FixtureScenario::Healthy).with_actions(ActionScript::Pending),
            Screen::Applications,
            width,
            cx,
        );
        let (instance, _name) = stoppable_group(&view, cx);
        click(handle, &format!("applications-stop-{instance}"), cx);
        click(handle, "confirm-ok", cx);
        let id: String = format!("applications-stop-state-{instance}");
        let Some(state @ ActionState::AwaitingAdmission { .. }) =
            state_of(&view, &Slot::Stop(instance.clone()), cx)
        else {
            panic!("the stop waits for admission");
        };
        let row = bounds_of(handle, &format!("applications-row-{instance}"), cx).expect("row");
        let line = bounds_of(handle, &id, cx).expect("state line");
        let pill = bounds_of(handle, &format!("{id}-pill"), cx).expect("pill");
        let window_right: Pixels = px(width);
        for (what, bounds) in [("line", line), ("pill", pill)] {
            assert!(
                bounds.right() <= row.right() + px(1.0) && bounds.right() <= window_right,
                "{width}: {what} {bounds:?}, row {row:?}"
            );
        }
        let sentence = bounds_of(handle, &format!("{id}-sentence"), cx).expect("sentence");
        assert!(
            sentence.size.height <= px(42.0),
            "{width}: the sentence of the cell is not short: {sentence:?}"
        );
        let full: String = label(handle, &id, cx).expect("label");
        assert!(
            full.starts_with("Waiting for admission: The plan is recorded"),
            "{full}"
        );
        assert!(full.contains("30 s after the plan expires."), "{full}");
        assert!(matches!(state, ActionState::AwaitingAdmission { .. }));
        // The keyboard path to the full line: the Details button opens a
        // dialog with the full line.
        assert_eq!(label(handle, "state-detail-line", cx), None);
        click(handle, &format!("applications-stop-details-{instance}"), cx);
        let detail = label(handle, "state-detail-line", cx).expect("detail line");
        assert!(detail.starts_with("Waiting for admission: "), "{detail}");
        assert!(detail.contains("30 s after the plan expires."), "{detail}");
        click(handle, "state-detail-close", cx);
        cx.executor().advance_clock(Duration::from_secs(1));
        cx.run_until_parked();
        assert_eq!(label(handle, "state-detail-line", cx), None);
    }
}

/// Regression for D-15 of host run 4: "Stop…" stayed active while its
/// confirmation was open, and a second press opened a second confirmation
/// of the same group above the first. The window has at most one stop
/// confirmation, and each stop control is off while it is open, with the
/// reason at the control of its group.
#[gpui_kit::test]
fn a_second_press_opens_no_second_stop_confirmation(cx: &mut TestAppContext) {
    let (handle, view) = open(
        FixtureSource::new(FixtureScenario::Healthy),
        Screen::Applications,
        cx,
    );
    let (instance, name) = stoppable_group(&view, cx);
    let model = cx.update(|cx| view.read(cx).model().clone());
    click(handle, &format!("applications-stop-{instance}"), cx);
    assert!(label(handle, "confirm-object", cx).is_some());
    assert_eq!(
        label(handle, &format!("applications-stop-open-{instance}"), cx).as_deref(),
        Some(svalnir_gui::screens::applications::STOP_OPEN)
    );
    // A second press, by the pointer or by the keyboard, comes to the same
    // function as the first. It must open no second dialog. With a second
    // dialog, the next lookup of "confirm-cancel" is ambiguous and fails.
    cx.update_window(handle, |_, window, cx| {
        svalnir_gui::screens::controls::open_stop(&model, &instance, &name, window, cx);
    })
    .unwrap();
    cx.run_until_parked();
    click(handle, "confirm-cancel", cx);
    cx.executor().advance_clock(Duration::from_secs(1));
    cx.run_until_parked();
    let open: bool = cx
        .update_window(handle, |_, window, cx| {
            use gpui_kit::component::WindowExt as _;
            window.has_active_dialog(cx)
        })
        .unwrap();
    assert!(!open, "one close leaves no stop confirmation open");
    assert!(cx.update(|cx| view.read(cx).model().read(cx).actions.stop.is_none()));
    assert_eq!(
        label(handle, &format!("applications-stop-open-{instance}"), cx),
        None
    );
    // After the close, the control opens the confirmation again.
    click(handle, &format!("applications-stop-{instance}"), cx);
    assert!(label(handle, "confirm-object", cx).is_some());
}

/// Regression for D-17 of host run 4: the tooltip of a cut state line was
/// one line and was cut at the right edge of the window. The tooltip has a
/// maximum width, and its text wraps.
#[gpui_kit::test]
fn the_tooltip_of_a_cut_line_wraps_in_its_maximum_width(cx: &mut TestAppContext) {
    cx.update(gpui_kit::init);
    let window = cx.update(|cx| {
        cx.open_window(WindowOptions::default(), |_, cx| cx.new(|_| ShortLines))
            .expect("open test window")
    });
    let handle: AnyWindowHandle = window.into();
    cx.run_until_parked();
    let cut: String = format!("Accepted: {CUT}");
    assert_eq!(tooltip_of(handle, "cut", cx).as_deref(), Some(cut.as_str()));
    let tooltip = bounds_of(handle, "cut-tooltip", cx).expect("tooltip");
    assert!(
        tooltip.size.width <= px(svalnir_gui::ui::action_status::TOOLTIP_MAX_WIDTH),
        "the tooltip is wider than its maximum: {tooltip:?}"
    );
    assert!(
        tooltip.size.height > px(24.0),
        "the text of the tooltip does not wrap: {tooltip:?}"
    );
}

/// Review finding on the correction of D-15: Quit in the stop confirmation
/// of a group whose last stop still waits sent no request and closed the
/// dialog, but the model kept the dialog as open, so each stop control
/// stayed off.
#[gpui_kit::test]
fn a_confirmation_that_sends_nothing_still_closes_the_stop(cx: &mut TestAppContext) {
    let (handle, view) = open(
        FixtureSource::new(FixtureScenario::Healthy).with_actions(ActionScript::Pending),
        Screen::Applications,
        cx,
    );
    let (instance, name) = stoppable_group(&view, cx);
    let model = cx.update(|cx| view.read(cx).model().clone());
    click(handle, &format!("applications-stop-{instance}"), cx);
    click(handle, "confirm-ok", cx);
    let slot = Slot::Stop(instance.clone());
    assert!(cx.update(|cx| view.read(cx).model().read(cx).actions.is_busy(&slot)));
    // The control is off while the stop waits; a launch option can still
    // open the confirmation of the same group.
    cx.update_window(handle, |_, window, cx| {
        svalnir_gui::screens::controls::open_stop(&model, &instance, &name, window, cx);
    })
    .unwrap();
    cx.run_until_parked();
    click(handle, "confirm-ok", cx);
    assert!(cx.update(|cx| view.read(cx).model().read(cx).actions.stop.is_none()));
    assert_eq!(
        label(handle, &format!("applications-stop-open-{instance}"), cx),
        None
    );
}

/// The groups of the open window that have a protection reason: the
/// instance and the full reason.
fn reasoned_groups(view: &Entity<MainWindow>, cx: &mut TestAppContext) -> Vec<(String, String)> {
    cx.update(|cx| {
        let model = view.read(cx).model().read(cx);
        let processes = match &model.processes {
            Loadable::Ready(processes) => Some(processes),
            _ => None,
        }
        .expect("the processes are read");
        processes
            .applications
            .iter()
            .filter_map(|row| {
                svalnir_gui::screens::applications::protection_reason(row.protection)
                    .map(|reason| (row.instance.clone(), reason.to_owned()))
            })
            .collect()
    })
}

/// Regression for the cut stop control of host run 4: in its loading state
/// the stop control adds a spinner, so it was wider than the Stop column,
/// and the table cut its label to "Stop..". The control stays inside the
/// row of its group in each state.
#[gpui_kit::test]
fn the_stop_control_stays_inside_its_row_while_it_loads(cx: &mut TestAppContext) {
    for width in [1280.0, 1120.0, 720.0] {
        let (handle, view) = open_at(
            FixtureSource::new(FixtureScenario::Healthy).with_actions(ActionScript::Pending),
            Screen::Applications,
            width,
            cx,
        );
        let (instance, _name) = stoppable_group(&view, cx);
        let id: String = format!("applications-stop-{instance}");
        let row_id: String = format!("applications-row-{instance}");
        let idle = bounds_of(handle, &id, cx).expect("stop control");
        let row = bounds_of(handle, &row_id, cx).expect("row");
        assert!(
            idle.right() <= row.right() + px(1.0),
            "{width}: idle control {idle:?}, row {row:?}"
        );
        click(handle, &id, cx);
        click(handle, "confirm-ok", cx);
        assert!(cx.update(|cx| {
            view.read(cx)
                .model()
                .read(cx)
                .actions
                .is_busy(&Slot::Stop(instance.clone()))
        }));
        let loading = bounds_of(handle, &id, cx).expect("stop control");
        let row = bounds_of(handle, &row_id, cx).expect("row");
        assert!(
            loading.right() <= row.right() + px(1.0) && loading.right() <= px(width),
            "{width}: loading control {loading:?}, row {row:?}"
        );
        assert_eq!(label(handle, &id, cx).as_deref(), Some("Stop…"));
    }
}

/// Regression for the cut protection reason of host run 4: the reason of a
/// hard protection was wider than its column and was cut at the next
/// column. It is a short caption: it stays inside its column, shows at most
/// two lines, has the full reason as its label, and has a tooltip with the
/// full reason only when it is cut. A reason that wraps onto two lines and
/// is not cut has no tooltip.
#[gpui_kit::test]
fn the_protection_reason_stays_inside_its_column(cx: &mut TestAppContext) {
    let (mut cut_seen, mut wrapped_whole_seen): (bool, bool) = (false, false);
    for width in [1800.0, 1280.0, 720.0] {
        let (handle, view) = open_at(
            FixtureSource::new(FixtureScenario::Healthy),
            Screen::Applications,
            width,
            cx,
        );
        let groups = reasoned_groups(&view, cx);
        assert!(!groups.is_empty(), "the fixture has a protected group");
        for (instance, reason) in groups {
            let id: String = format!("applications-protection-reason-{instance}");
            let caption = bounds_of(handle, &id, cx).expect("reason");
            let next = bounds_of(handle, &format!("applications-stop-none-{instance}"), cx)
                .expect("stop cell");
            assert!(
                caption.right() <= next.left(),
                "{width}: reason {caption:?}, next cell {next:?}"
            );
            assert!(
                caption.size.height <= px(42.0),
                "{width}: the reason is not short: {caption:?}"
            );
            assert_eq!(label(handle, &id, cx).as_deref(), Some(reason.as_str()));
            match tooltip_of(handle, &id, cx) {
                Some(tooltip) => {
                    assert!(width < 1800.0, "{width}: {reason} is cut");
                    assert_eq!(tooltip, reason, "{width}");
                    cut_seen = true;
                }
                None => wrapped_whole_seen |= caption.size.height > px(24.0),
            }
        }
    }
    assert!(cut_seen, "no width cuts a reason");
    assert!(
        wrapped_whole_seen,
        "no width wraps a reason that is not cut"
    );
}
