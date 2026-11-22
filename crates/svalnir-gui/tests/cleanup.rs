//! UI tests of the Cleanup section of the Storage screen with fixture
//! sources: the inspection of each rule, the plan confirmation, the consent
//! to a `clear` command, the refusal of a `proposed` rule, and the refusal
//! with no agent. A fixture action path reads nothing and writes nothing.
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
    data::fixture::{FixtureScenario, FixtureSource},
    shell::{
        nav::{self, Screen},
        window::MainWindow,
    },
};

const PROJECT: &str = "project.dependency-directory";
const GO: &str = "go.build-cache";
const HOMEBREW: &str = "homebrew.cleanup";

/// Opens a tall window with `source` on the Storage screen, so that the
/// Cleanup card is inside the window.
fn open(source: FixtureSource, cx: &mut TestAppContext) -> (AnyWindowHandle, Entity<MainWindow>) {
    cx.update(gpui_kit::init);
    cx.update(nav::bind_keys);
    let (handle, view) = cx.update(|cx| {
        open_main_window(
            Bounds::new(Point::default(), size(px(1280.0), px(3200.0))),
            Arc::new(source),
            None,
            cx,
        )
        .expect("open test window")
    });
    cx.run_until_parked();
    let key: String = format!("cmd-{}", Screen::Storage.index() + 1);
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

fn state_of(view: &Entity<MainWindow>, rule: &str, cx: &mut TestAppContext) -> Option<ActionState> {
    cx.update(|cx| {
        view.read(cx)
            .model()
            .read(cx)
            .actions
            .state(&Slot::Cleanup(rule.to_owned()))
            .cloned()
    })
}

#[gpui_kit::test]
fn the_rules_show_their_units_sizes_lifecycle_and_reasons(cx: &mut TestAppContext) {
    let (handle, _view) = open(FixtureSource::new(FixtureScenario::Healthy), cx);
    let rule = label(handle, &format!("cleanup-rule-{PROJECT}"), cx).expect("rule");
    assert!(
        rule.contains("lifecycle state manual_action_validated (fixture"),
        "{rule}"
    );
    let proposed = label(handle, &format!("cleanup-rule-{HOMEBREW}"), cx).expect("rule");
    assert!(proposed.ends_with("lifecycle state proposed"), "{proposed}");
    let unit = label(handle, &format!("cleanup-unit-{PROJECT}-0"), cx).expect("unit");
    assert!(unit.contains("private allocated"), "{unit}");
    let active = label(handle, &format!("cleanup-unit-{PROJECT}-3"), cx).expect("unit");
    assert!(
        active.ends_with("Not eligible now: project_active"),
        "{active}"
    );
    let whole = label(handle, &format!("cleanup-unit-{HOMEBREW}-0"), cx).expect("unit");
    assert!(
        whole.contains("whole cache, not a reclaim figure"),
        "{whole}"
    );
    let command = label(handle, &format!("cleanup-command-{GO}"), cx).expect("command");
    assert!(command.contains("go clean -cache"), "{command}");
    // A rule with the inspection mode only has no plan control.
    assert_eq!(label(handle, "cleanup-plan-pnpm.content-store", cx), None);
    assert!(label(handle, "cleanup-gate-pnpm.content-store", cx).is_some());
}

#[gpui_kit::test]
fn a_plan_is_sent_only_after_its_confirmation(cx: &mut TestAppContext) {
    let (handle, view) = open(FixtureSource::new(FixtureScenario::Healthy), cx);
    click(handle, &format!("cleanup-plan-{PROJECT}"), cx);
    let object = label(handle, "confirm-object", cx).expect("object");
    assert!(
        object.starts_with(&format!("The plan of {PROJECT} binds 3 entries")),
        "{object}"
    );
    let consequence = label(handle, "confirm-consequence", cx).expect("consequence");
    assert!(
        consequence.starts_with("Permanent deletion."),
        "{consequence}"
    );
    assert!(
        label(handle, "confirm-warning-0", cx).is_some_and(|w| w.contains("nested_repository"))
    );
    let estimate = label(handle, "confirm-estimate", cx).expect("estimate");
    assert!(estimate.starts_with("Estimated: about "), "{estimate}");
    assert!(label(handle, "confirm-expiry", cx).is_some());
    // The confirmation alone sends nothing.
    assert_eq!(state_of(&view, PROJECT, cx), None);
    click(handle, "confirm-ok", cx);
    assert_eq!(label(handle, "confirm-object", cx), None);
    let text = label(handle, &format!("cleanup-state-{PROJECT}"), cx).expect("state");
    assert!(
        text.starts_with("Running: The agent admitted operation op-fixture-clean"),
        "{text}"
    );
    // A refresh reads the record of the operation, as the poll does.
    cx.update_window(handle, |_, window, cx| window.press("cmd-r", cx))
        .unwrap();
    cx.run_until_parked();
    let text = label(handle, &format!("cleanup-state-{PROJECT}"), cx).expect("state");
    assert!(
        text.starts_with("Completed: Operation op-fixture-clean completed."),
        "{text}"
    );
}

#[gpui_kit::test]
fn escape_cancels_the_plan_and_sends_nothing(cx: &mut TestAppContext) {
    let (handle, view) = open(FixtureSource::new(FixtureScenario::Healthy), cx);
    click(handle, &format!("cleanup-plan-{PROJECT}"), cx);
    assert!(label(handle, "confirm-object", cx).is_some());
    cx.update_window(handle, |_, window, cx| window.press("escape", cx))
        .unwrap();
    cx.run_until_parked();
    assert_eq!(label(handle, "confirm-object", cx), None);
    assert!(cx.update(|cx| view.read(cx).model().read(cx).cleanup_book.dialog.is_none()));
    assert_eq!(state_of(&view, PROJECT, cx), None);
}

#[gpui_kit::test]
fn with_no_agent_no_plan_is_made_and_nothing_is_written(cx: &mut TestAppContext) {
    let (handle, view) = open(
        FixtureSource::new(FixtureScenario::Healthy).with_actions(ActionScript::Unavailable),
        cx,
    );
    click(handle, &format!("cleanup-plan-{PROJECT}"), cx);
    let text = label(handle, "confirm-failed", cx).expect("failed state");
    assert!(
        text.starts_with("Unavailable: No agent holds the coordinator lock"),
        "{text}"
    );
    assert!(text.contains("(agent_not_running)"), "{text}");
    assert_eq!(label(handle, "confirm-ok", cx), None);
    assert_eq!(state_of(&view, PROJECT, cx), None);
}

#[gpui_kit::test]
fn a_proposed_rule_is_refused_with_its_code(cx: &mut TestAppContext) {
    let (handle, view) = open(FixtureSource::new(FixtureScenario::Healthy), cx);
    click(handle, &format!("cleanup-plan-{HOMEBREW}"), cx);
    let text = label(handle, "confirm-failed", cx).expect("refusal");
    assert!(
        text.starts_with("Refused: This rule is in the lifecycle state proposed."),
        "{text}"
    );
    assert!(
        text.ends_with("(rule_mode_not_validated). Nothing changed."),
        "{text}"
    );
    assert_eq!(label(handle, "confirm-ok", cx), None);
    assert_eq!(state_of(&view, HOMEBREW, cx), None);
}

#[gpui_kit::test]
fn the_clear_consent_gates_the_plan_of_a_clear_command(cx: &mut TestAppContext) {
    let (handle, view) = open(FixtureSource::new(FixtureScenario::Healthy), cx);
    let gate = label(handle, &format!("cleanup-gate-{GO}"), cx).expect("gate");
    assert!(
        gate.starts_with("Plan is off:") && gate.contains("consent"),
        "{gate}"
    );
    // The control is off: a press opens no dialog.
    click(handle, &format!("cleanup-plan-{GO}"), cx);
    assert_eq!(label(handle, "confirm-object", cx), None);
    assert!(cx.update(|cx| view.read(cx).model().read(cx).cleanup_book.dialog.is_none()));
    let consent = label(handle, &format!("cleanup-clear-{GO}"), cx).expect("consent");
    assert!(consent.ends_with("(not checked)"), "{consent}");
    click(handle, &format!("cleanup-clear-{GO}"), cx);
    let consent = label(handle, &format!("cleanup-clear-{GO}"), cx).expect("consent");
    assert!(consent.ends_with("(checked)"), "{consent}");
    assert_eq!(label(handle, &format!("cleanup-gate-{GO}"), cx), None);
    click(handle, &format!("cleanup-plan-{GO}"), cx);
    let command = label(handle, "confirm-command", cx).expect("command");
    assert!(
        command.contains("/opt/homebrew/bin/go clean -cache"),
        "{command}"
    );
    let effect = label(handle, "confirm-effect", cx).expect("effect");
    assert!(effect.starts_with("Effect: go removes"), "{effect}");
    assert!(
        label(handle, "confirm-consequence", cx)
            .is_some_and(|text| text.starts_with("Permanent deletion."))
    );
    assert_eq!(state_of(&view, GO, cx), None);
}

#[gpui_kit::test]
fn a_second_plan_dialog_is_not_opened(cx: &mut TestAppContext) {
    let (handle, view) = open(FixtureSource::new(FixtureScenario::Healthy), cx);
    click(handle, &format!("cleanup-plan-{PROJECT}"), cx);
    let opened = cx.update(|cx| {
        let model = view.read(cx).model().clone();
        model.update(cx, |model, cx| {
            model.prepare_cleanup(HOMEBREW, svalnir_gui::actions::cleanup::PlanKind::Owner, cx)
        })
    });
    assert!(!opened);
    assert_eq!(
        cx.update(|cx| view
            .read(cx)
            .model()
            .read(cx)
            .cleanup_book
            .open_rule()
            .map(str::to_owned)),
        Some(PROJECT.to_owned())
    );
}

#[gpui_kit::test]
fn the_storage_screen_has_a_cleanup_section(cx: &mut TestAppContext) {
    let (handle, _view) = open(FixtureSource::new(FixtureScenario::Healthy), cx);
    let mut found: bool = false;
    cx.update_window(handle, |_, window, cx| {
        window.render_frame(cx);
        found = window.try_find("nav-storage-cleanup".to_owned()).is_some();
    })
    .unwrap();
    assert!(found, "the card of the Cleanup section");
    assert!(
        label(handle, "cleanup-intro", cx).is_some_and(|text| text.contains("changes nothing"))
    );
}
