//! UI and model tests of the Storage screen.
#![expect(clippy::expect_used, reason = "test code fails by panicking")]

use gpui_kit::{
    AnyWindowHandle, AppContext as _, Bounds, Point, TestAppContext, px, size,
    test::TestWindowExt as _,
};
use std::{path::Path, sync::Arc};
use svalnir_agent::scan::CancellationToken;
use svalnir_gui::{
    app::open_main_window,
    data::{
        DataSource,
        fixture::{FixtureScenario, FixtureSource},
        live::LiveSource,
        model::{ScanProgress, ScanState, ScanSummary},
        store::AppModel,
    },
    shell::nav,
};

fn model_for(source: Arc<dyn DataSource>, cx: &mut TestAppContext) -> gpui_kit::Entity<AppModel> {
    let model = cx.new(|cx| AppModel::new(source, cx));
    cx.run_until_parked();
    model
}

fn open(scenario: FixtureScenario, cx: &mut TestAppContext) -> AnyWindowHandle {
    cx.update(gpui_kit::init);
    cx.update(nav::bind_keys);
    let (handle, _view) = cx.update(|cx| {
        open_main_window(
            Bounds::new(Point::default(), size(px(1120.0), px(720.0))),
            Arc::new(FixtureSource::new(scenario)),
            None,
            cx,
        )
        .expect("open test window")
    });
    cx.run_until_parked();
    handle
}

#[gpui_kit::test]
fn fixture_scan_reaches_done_with_the_total(cx: &mut TestAppContext) {
    cx.update(gpui_kit::init);
    let model = model_for(Arc::new(FixtureSource::new(FixtureScenario::Healthy)), cx);
    let root = cx
        .read(|cx| model.read(cx).default_scan_root())
        .expect("root");
    assert!(matches!(
        cx.read(|cx| model.read(cx).scan.clone()),
        ScanState::Idle
    ));
    model.update(cx, |model, cx| model.start_scan(&root, cx));
    cx.run_until_parked();
    let state = cx.read(|cx| model.read(cx).scan.clone());
    let ScanState::Done(summary) = state else {
        panic!("expected Done, got {state:?}")
    };
    assert!(
        summary
            .children
            .iter()
            .any(|child| child.name == "Pictures")
    );
    assert!(!summary.complete);
    assert_eq!(summary.gaps[0].count, 3);
}

#[gpui_kit::test]
fn pressure_refuses_the_scan(cx: &mut TestAppContext) {
    cx.update(gpui_kit::init);
    let model = model_for(Arc::new(FixtureSource::new(FixtureScenario::Pressure)), cx);
    model.update(cx, |model, cx| {
        model.start_scan(Path::new("/Users/fixture"), cx);
    });
    cx.run_until_parked();
    match cx.read(|cx| model.read(cx).scan.clone()) {
        ScanState::Failed { reason, .. } => {
            assert_eq!(
                reason,
                "A scan does not start while memory pressure is not normal."
            );
        }
        other => panic!("expected Failed, got {other:?}"),
    }
}

#[gpui_kit::test]
fn unavailable_shows_the_failure_reason(cx: &mut TestAppContext) {
    cx.update(gpui_kit::init);
    let model = model_for(
        Arc::new(FixtureSource::new(FixtureScenario::Unavailable)),
        cx,
    );
    model.update(cx, |model, cx| {
        model.start_scan(Path::new("/Users/fixture"), cx);
    });
    cx.run_until_parked();
    match cx.read(|cx| model.read(cx).scan.clone()) {
        ScanState::Failed { reason, .. } => {
            assert_eq!(reason, "the scan root is not readable in this fixture");
        }
        other => panic!("expected Failed, got {other:?}"),
    }
}

#[gpui_kit::test]
fn storage_screen_idle_shows_the_scan_button(cx: &mut TestAppContext) {
    let handle = open(FixtureScenario::Healthy, cx);
    cx.update_window(handle, |_, window, cx| {
        window.render_frame(cx);
    })
    .unwrap();
}

#[test]
fn live_scan_measures_a_temporary_directory() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("a.bin"), vec![1_u8; 3000]).unwrap();
    std::fs::write(dir.path().join("b.bin"), vec![1_u8; 1000]).unwrap();
    std::fs::create_dir(dir.path().join("sub")).unwrap();
    std::fs::write(dir.path().join("sub").join("c.bin"), vec![1_u8; 500]).unwrap();
    let source = LiveSource::new(None);
    let summary: ScanSummary = source
        .scan(dir.path(), &CancellationToken::new(), &|_: ScanProgress| {})
        .expect("scan");
    assert!(summary.complete);
    let size_of = |name: &str| {
        summary
            .children
            .iter()
            .find(|c| c.name == name)
            .map(|c| c.logical)
    };
    assert_eq!(size_of("a.bin"), Some(3000));
    assert_eq!(size_of("b.bin"), Some(1000));
    assert_eq!(size_of("sub"), Some(500));
    assert_eq!(summary.children.len(), 3);
}

/// A source whose scan waits for the token.
#[derive(Debug)]
struct WaitingSource;

impl DataSource for WaitingSource {
    fn host(&self) -> Result<svalnir_gui::data::model::HostSnapshot, String> {
        Err("none".to_owned())
    }
    fn agent(&self) -> svalnir_gui::data::model::AgentSnapshot {
        FixtureSource::new(FixtureScenario::Healthy).agent()
    }
    fn service(&self) -> svalnir_gui::data::model::ServiceSnapshot {
        FixtureSource::new(FixtureScenario::Healthy).service()
    }
    fn label(&self) -> &'static str {
        "waiting"
    }
    fn scan(
        &self,
        root: &Path,
        cancel: &CancellationToken,
        _progress: &dyn Fn(ScanProgress),
    ) -> Result<ScanSummary, String> {
        while !cancel.is_cancelled() {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let mut summary = FixtureSource::new(FixtureScenario::Healthy)
            .scan(root, cancel, &|_| {})
            .expect("fixture");
        summary.ended = svalnir_gui::data::model::ScanEnd::Cancelled;
        summary.complete = false;
        Ok(summary)
    }
    fn default_scan_root(&self) -> Option<std::path::PathBuf> {
        None
    }
}

#[gpui_kit::test]
fn cancel_ends_the_scan_as_cancelled(cx: &mut TestAppContext) {
    cx.update(gpui_kit::init);
    let model = model_for(Arc::new(WaitingSource), cx);
    model.update(cx, |model, cx| model.start_scan(Path::new("/x"), cx));
    assert!(matches!(
        cx.read(|cx| model.read(cx).scan.clone()),
        ScanState::Running { .. }
    ));
    model.update(cx, |model, _| model.cancel_scan());
    cx.executor().allow_parking();
    for _ in 0..200 {
        cx.run_until_parked();
        if matches!(
            cx.read(|cx| model.read(cx).scan.clone()),
            ScanState::Done(_)
        ) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    match cx.read(|cx| model.read(cx).scan.clone()) {
        ScanState::Done(summary) => {
            assert_eq!(summary.ended, svalnir_gui::data::model::ScanEnd::Cancelled);
        }
        other => panic!("expected Done, got {other:?}"),
    }
}
