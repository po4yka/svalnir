//! UI tests of the Memory, Applications, Automation, History, and
//! Diagnostics screens: values, states, and the data states of each fixture.
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
        fixture::{FixtureScenario, FixtureSource},
        model::Loadable,
        store::Topic,
    },
    shell::{
        nav::{self, Screen},
        window::{MainWindow, topics_of},
    },
};

/// Opens the window with `scenario` and shows `screen`.
fn open(
    scenario: FixtureScenario,
    screen: Screen,
    cx: &mut TestAppContext,
) -> (AnyWindowHandle, Entity<MainWindow>) {
    cx.update(gpui_kit::init);
    cx.update(nav::bind_keys);
    let (handle, view) = cx.update(|cx| {
        open_main_window(
            Bounds::new(Point::default(), size(px(1280.0), px(900.0))),
            Arc::new(FixtureSource::new(scenario)),
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

#[gpui_kit::test]
fn a_topic_is_read_only_when_its_screen_is_in_front(cx: &mut TestAppContext) {
    let (handle, view) = open(FixtureScenario::Healthy, Screen::Overview, cx);
    cx.update(|cx| {
        let model = view.read(cx).model().read(cx);
        assert_eq!(model.topics(), []);
        assert!(matches!(model.processes, Loadable::Loading));
        assert!(matches!(model.diagnostics, Loadable::Loading));
    });
    cx.update_window(handle, |_, window, cx| window.press("cmd-3", cx))
        .unwrap();
    cx.run_until_parked();
    cx.update(|cx| {
        let model = view.read(cx).model().read(cx);
        assert_eq!(model.topics(), [Topic::Memory, Topic::Processes]);
        assert!(matches!(model.processes, Loadable::Ready(_)));
        assert!(matches!(model.memory, Loadable::Ready(_)));
        // No screen asked for the probes.
        assert!(matches!(model.diagnostics, Loadable::Loading));
    });
}

#[test]
fn only_diagnostics_asks_for_the_probes() {
    for screen in Screen::ALL {
        assert_eq!(
            topics_of(screen).contains(&Topic::Diagnostics),
            screen == Screen::Diagnostics
        );
    }
}

#[gpui_kit::test]
fn memory_shows_the_quantities_and_the_processes(cx: &mut TestAppContext) {
    let (handle, _view) = open(FixtureScenario::Healthy, Screen::Memory, cx);
    assert_eq!(
        label(handle, "memory-pressure-pill", cx).as_deref(),
        Some("Normal")
    );
    assert_eq!(
        label(handle, "memory-wired", cx).as_deref(),
        Some("Wired: 4.2 GB")
    );
    let track = label(handle, "memory-pressure-track", cx).expect("track");
    assert!(track.contains("readings of this window"), "{track}");
    let first = label(handle, "memory-process-name-412", cx).expect("row");
    assert_eq!(first, "Xcode, process 412, footprint 3.8 GB");
    // A process with no footprint value is a row with a reason, not zero.
    let exited = label(handle, "memory-process-name-743", cx).expect("row");
    assert!(exited.contains("footprint not available"), "{exited}");
    let summary = label(handle, "memory-processes-summary", cx).expect("summary");
    assert!(summary.starts_with("12 of 12 processes"), "{summary}");
}

#[gpui_kit::test]
fn memory_unavailable_is_a_dash_with_the_reason(cx: &mut TestAppContext) {
    let (handle, _view) = open(FixtureScenario::Unavailable, Screen::Memory, cx);
    let reason = label(handle, "memory-processes-value-reason", cx).expect("reason");
    assert!(reason.contains("the process list"), "{reason}");
    let reason = label(handle, "memory-detail-value-reason", cx).expect("reason");
    assert!(reason.contains("the memory reading"), "{reason}");
    assert_eq!(
        label(handle, "memory-pressure-pill", cx).as_deref(),
        Some("Unavailable")
    );
    assert_eq!(
        label(handle, "memory-physical", cx).as_deref(),
        Some("Physical memory: \u{2014}")
    );
    assert_eq!(label(handle, "memory-process-name-412", cx), None);
}

#[gpui_kit::test]
fn a_stale_reading_keeps_its_value_and_shows_its_age(cx: &mut TestAppContext) {
    let (handle, _view) = open(FixtureScenario::Stale, Screen::Memory, cx);
    assert_eq!(
        label(handle, "memory-processes-stale", cx).as_deref(),
        Some("Stale: read 12 min ago")
    );
    assert!(label(handle, "memory-process-name-412", cx).is_some());
    let (handle, _view) = open(FixtureScenario::Stale, Screen::Automation, cx);
    assert_eq!(
        label(handle, "automation-stale", cx).as_deref(),
        Some("Stale: read 12 min ago")
    );
    let (handle, _view) = open(FixtureScenario::Stale, Screen::History, cx);
    assert_eq!(
        label(handle, "history-stale", cx).as_deref(),
        Some("Stale: read 12 min ago")
    );
    let (handle, _view) = open(FixtureScenario::Healthy, Screen::History, cx);
    assert_eq!(label(handle, "history-stale", cx), None);
}

#[gpui_kit::test]
fn applications_show_groups_protection_and_a_partial_sum(cx: &mut TestAppContext) {
    let (handle, _view) = open(FixtureScenario::Healthy, Screen::Applications, cx);
    assert_eq!(
        label(
            handle,
            "applications-protection-fixture-com.apple.finder",
            cx
        )
        .as_deref(),
        Some("Protected")
    );
    assert_eq!(
        label(
            handle,
            "applications-protection-fixture-com.apple.Terminal",
            cx
        )
        .as_deref(),
        Some("Unknown")
    );
    assert_eq!(
        label(handle, "applications-partial-fixture-com.apple.Safari", cx).as_deref(),
        Some("partial")
    );
    assert_eq!(
        label(
            handle,
            "applications-partial-fixture-com.apple.dt.Xcode",
            cx
        ),
        None
    );
    assert_eq!(
        label(handle, "attribution-unattributed", cx).as_deref(),
        Some("With no verified group: 3")
    );
    let note = label(handle, "applications-stop-note", cx).expect("note");
    assert!(note.starts_with("Stop makes a quit plan"), "{note}");
}

#[gpui_kit::test]
fn applications_unavailable_is_not_an_empty_list(cx: &mut TestAppContext) {
    let (handle, _view) = open(FixtureScenario::Unavailable, Screen::Applications, cx);
    assert!(label(handle, "applications-value-reason", cx).is_some());
    assert_eq!(label(handle, "applications-empty", cx), None);
}

#[gpui_kit::test]
fn automation_shows_guards_grants_and_the_pause(cx: &mut TestAppContext) {
    let (handle, _view) = open(FixtureScenario::Healthy, Screen::Automation, cx);
    assert_eq!(
        label(handle, "automation-guard-disk-guard", cx).as_deref(),
        Some("Active")
    );
    assert_eq!(
        label(handle, "automation-guard-memory-guard", cx).as_deref(),
        Some("Inactive")
    );
    assert_eq!(
        label(handle, "automation-grant-disk-guard", cx).as_deref(),
        Some("In effect")
    );
    assert_eq!(
        label(
            handle,
            "automation-class-disk-guard-EvictRegenerableData",
            cx
        )
        .as_deref(),
        Some("EvictRegenerableData")
    );
    assert!(label(handle, "automation-no-grant-memory-guard", cx).is_some());
    assert_eq!(
        label(handle, "automation-pause-pill", cx).as_deref(),
        Some("Not paused")
    );
    assert_eq!(
        label(handle, "automation-revision", cx).as_deref(),
        Some("Revision in effect: rev-fixture-1")
    );
    let (handle, _view) = open(FixtureScenario::Pressure, Screen::Automation, cx);
    assert_eq!(
        label(handle, "automation-pause-pill", cx).as_deref(),
        Some("Paused")
    );
}

#[gpui_kit::test]
fn automation_with_a_failed_read_does_not_say_not_paused(cx: &mut TestAppContext) {
    let (handle, _view) = open(FixtureScenario::Unavailable, Screen::Automation, cx);
    assert_eq!(
        label(handle, "automation-pause-pill", cx).as_deref(),
        Some("Unknown")
    );
    let problem = label(handle, "automation-problem-0", cx).expect("problem");
    assert!(problem.contains("cannot be read"), "{problem}");
    assert_eq!(label(handle, "automation-guard-disk-guard", cx), None);
    let (handle, _view) = open(FixtureScenario::AgentAbsent, Screen::Automation, cx);
    let text = label(handle, "automation-no-revision", cx).expect("no revision");
    assert!(text.starts_with("No journal exists"), "{text}");
    assert_eq!(
        label(handle, "automation-guard-disk-guard", cx).as_deref(),
        Some("Inactive")
    );
}

#[gpui_kit::test]
fn history_shows_each_outcome_with_its_own_state(cx: &mut TestAppContext) {
    let (handle, _view) = open(FixtureScenario::Healthy, Screen::History, cx);
    let state =
        |id: &str, cx: &mut TestAppContext| label(handle, &format!("history-state-{id}"), cx);
    assert_eq!(state("op_fixture_0001", cx).as_deref(), Some("Completed"));
    assert_eq!(state("op_fixture_0000", cx).as_deref(), Some("Partial"));
    assert_eq!(
        state("op_fixture_00zz", cx).as_deref(),
        Some("Unknown outcome")
    );
    assert_eq!(state("op_fixture_00yy", cx).as_deref(), Some("Failed"));
    assert_eq!(state("op_fixture_00xx", cx).as_deref(), Some("No action"));
    assert_eq!(
        label(handle, "history-observed-op_fixture_0001", cx).as_deref(),
        Some("Available capacity 22.0 GB before, 31.4 GB after, change +9.4 GB")
    );
    // A move to the Trash has no capacity observation, which is not a zero.
    assert_eq!(
        label(handle, "history-observed-op_fixture_0000", cx).as_deref(),
        Some("No measurement in the journal")
    );
    assert_eq!(
        label(handle, "history-steps-op_fixture_0000", cx).as_deref(),
        Some("4 steps: 2 Completed, 1 Failed, 1 NoAction")
    );
    let (handle, _view) = open(FixtureScenario::Pressure, Screen::History, cx);
    assert_eq!(
        label(handle, "history-state-op_fixture_0002", cx).as_deref(),
        Some("Running")
    );
}

#[gpui_kit::test]
fn history_separates_no_journal_no_operation_and_a_failed_read(cx: &mut TestAppContext) {
    let (handle, _view) = open(FixtureScenario::AgentAbsent, Screen::History, cx);
    assert_eq!(
        label(handle, "history-empty", cx).as_deref(),
        Some("No journal exists in the state directory.")
    );
    let (handle, _view) = open(FixtureScenario::Unavailable, Screen::History, cx);
    assert_eq!(label(handle, "history-empty", cx), None);
    assert!(label(handle, "history-operations-reason", cx).is_some());
    let problem = label(handle, "history-problem-0", cx).expect("problem");
    assert!(problem.starts_with("Problem: "), "{problem}");
}

#[gpui_kit::test]
fn diagnostics_shows_each_capability_with_its_state_and_fix(cx: &mut TestAppContext) {
    let (handle, _view) = open(FixtureScenario::Healthy, Screen::Diagnostics, cx);
    assert_eq!(
        label(handle, "diagnostics-verdict", cx).as_deref(),
        Some("Ready")
    );
    assert_eq!(
        label(handle, "diagnostics-level-privacy.full_disk_access", cx).as_deref(),
        Some("Denied")
    );
    let fix = label(handle, "diagnostics-fix-privacy.full_disk_access", cx).expect("fix");
    assert!(fix.starts_with("Fix: Open System Settings"), "{fix}");
    assert_eq!(
        label(handle, "diagnostics-agent-state", cx).as_deref(),
        Some("Run state in the record: running")
    );
    assert_eq!(label(handle, "diagnostics-start-failure-pill", cx), None);
}

#[gpui_kit::test]
fn diagnostics_shows_a_probe_with_no_result_and_a_start_failure(cx: &mut TestAppContext) {
    let (handle, _view) = open(FixtureScenario::Unavailable, Screen::Diagnostics, cx);
    assert_eq!(
        label(handle, "diagnostics-verdict", cx).as_deref(),
        Some("Not verified")
    );
    assert_eq!(
        label(handle, "diagnostics-level-metrics.memory", cx).as_deref(),
        Some("Unknown")
    );
    assert!(label(handle, "diagnostics-agent-none", cx).is_some());
    assert!(label(handle, "diagnostics-problem-0", cx).is_some());
    let (handle, _view) = open(FixtureScenario::AgentAbsent, Screen::Diagnostics, cx);
    assert_eq!(
        label(handle, "diagnostics-start-failure-pill", cx).as_deref(),
        Some("Start failed")
    );
    assert_eq!(
        label(handle, "diagnostics-agent-none", cx).as_deref(),
        Some("No journal exists in the state directory.")
    );
    assert_eq!(
        label(handle, "diagnostics-journal-present", cx).as_deref(),
        Some("Exists: No")
    );
}
