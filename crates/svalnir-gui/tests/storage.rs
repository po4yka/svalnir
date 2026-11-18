//! UI and model tests of the Storage screen.
#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test code fails by panicking"
)]

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
    screens::storage::StorageScreen,
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
    assert_eq!(summary.children.len(), 19);
    assert_eq!(
        summary.total_allocated,
        summary.children.iter().map(|c| c.allocated).sum::<u64>()
    );
    assert_eq!(
        summary.total_logical,
        summary.children.iter().map(|c| c.logical).sum::<u64>()
    );
    assert_eq!(summary.entries_examined, 120_000);
    assert!(summary.total_allocated > summary.total_logical);
    assert!(
        summary
            .children
            .iter()
            .all(|c| c.path == summary.root.join(&c.name))
    );
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
fn a_scan_requested_while_loading_ends_in_the_pressure_refusal(cx: &mut TestAppContext) {
    cx.update(gpui_kit::init);
    let source = Arc::new(FixtureSource::new(FixtureScenario::Pressure));
    let model = cx.new(|cx| AppModel::new(source, cx));
    model.update(cx, |model, cx| {
        model.start_scan(Path::new("/Users/fixture"), cx);
    });
    assert!(matches!(
        cx.read(|cx| model.read(cx).scan.clone()),
        ScanState::Idle
    ));
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

fn label_of(handle: AnyWindowHandle, id: &'static str, cx: &mut TestAppContext) -> Option<String> {
    let mut label: Option<String> = None;
    cx.update_window(handle, |_, window, cx| {
        window.render_frame(cx);
        label = window
            .try_find(id)
            .map(|node| node.label().unwrap_or_default().to_owned());
    })
    .unwrap();
    label
}

#[gpui_kit::test]
fn storage_screen_scan_button_runs_the_scan(cx: &mut TestAppContext) {
    let handle = open(FixtureScenario::Healthy, cx);
    cx.update_window(handle, |_, window, cx| window.press("cmd-2", cx))
        .unwrap();
    cx.run_until_parked();
    assert_eq!(
        label_of(handle, "screen-title", cx).as_deref(),
        Some("Storage")
    );
    assert!(label_of(handle, "scan-start", cx).is_some(), "scan button");
    cx.update_window(handle, |_, window, cx| window.click("scan-start", cx))
        .unwrap();
    cx.run_until_parked();
    let total = label_of(handle, "scan-total", cx).expect("total text");
    assert_eq!(total, "266.1");
    let row = label_of(handle, "storage-legend-row-0", cx).expect("first legend row");
    assert!(row.starts_with("Pictures: "), "row {row}");
    let allocated = label_of(handle, "scan-metric", cx).expect("caption");
    cx.update_window(handle, |_, window, cx| window.click("metric-logical", cx))
        .unwrap();
    cx.run_until_parked();
    let logical = label_of(handle, "scan-metric", cx).expect("caption");
    assert_ne!(allocated, logical);
    assert_eq!(logical, "Logical size");
}

/// A source whose scan fails below the root.
#[derive(Debug)]
struct SubfolderFails;

impl DataSource for SubfolderFails {
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
        "subfolder-fails"
    }
    fn scan(
        &self,
        root: &Path,
        cancel: &CancellationToken,
        progress: &dyn Fn(ScanProgress),
    ) -> Result<ScanSummary, String> {
        if root == Path::new("/root") {
            FixtureSource::new(FixtureScenario::Healthy).scan(root, cancel, progress)
        } else {
            Err("the folder is not readable".to_owned())
        }
    }
    fn default_scan_root(&self) -> Option<std::path::PathBuf> {
        Some(std::path::PathBuf::from("/root"))
    }
}

#[gpui_kit::test]
fn a_failed_scan_in_a_subfolder_has_a_way_back(cx: &mut TestAppContext) {
    cx.update(gpui_kit::init);
    let model = model_for(Arc::new(SubfolderFails), cx);
    let screen = cx.new(|cx| StorageScreen::new(model.clone(), cx));
    screen.update(cx, |screen, cx| screen.pop_to(0, cx));
    cx.run_until_parked();
    assert!(matches!(
        cx.read(|cx| model.read(cx).scan.clone()),
        ScanState::Done(_)
    ));
    screen.update(cx, |screen, cx| screen.push("/root/sub".into(), cx));
    cx.run_until_parked();
    assert!(matches!(
        cx.read(|cx| model.read(cx).scan.clone()),
        ScanState::Failed { .. }
    ));
    // The breadcrumb action for the root level.
    screen.update(cx, |screen, cx| screen.pop_to(0, cx));
    cx.run_until_parked();
    assert!(matches!(
        cx.read(|cx| model.read(cx).scan.clone()),
        ScanState::Done(_)
    ));
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

#[test]
fn live_scan_counts_a_nested_directory_once_in_its_top_level_ancestor() {
    let dir = tempfile::tempdir().expect("tempdir");
    let deep = dir.path().join("top").join("mid");
    std::fs::create_dir_all(&deep).unwrap();
    std::fs::write(dir.path().join("top").join("t.bin"), vec![1_u8; 100]).unwrap();
    std::fs::write(deep.join("d.bin"), vec![1_u8; 700]).unwrap();
    let summary: ScanSummary = LiveSource::new(None)
        .scan(dir.path(), &CancellationToken::new(), &|_: ScanProgress| {})
        .expect("scan");
    assert_eq!(summary.children.len(), 1);
    assert_eq!(summary.children[0].name, "top");
    assert_eq!(summary.children[0].logical, 800);
    assert_eq!(summary.total_logical, 800);
}

#[cfg(unix)]
#[test]
fn live_scan_through_a_symlinked_root_has_children() {
    let dir = tempfile::tempdir().expect("tempdir");
    let real = dir.path().join("real");
    std::fs::create_dir(&real).unwrap();
    std::fs::write(real.join("a.bin"), vec![1_u8; 300]).unwrap();
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let summary: ScanSummary = LiveSource::new(None)
        .scan(&link, &CancellationToken::new(), &|_: ScanProgress| {})
        .expect("scan");
    assert_eq!(summary.children.len(), 1);
    assert_eq!(summary.children[0].logical, 300);
    assert_eq!(summary.children[0].path, link.join("a.bin"));
}

#[cfg(unix)]
#[test]
fn live_scan_keeps_two_names_that_are_not_utf8_apart() {
    use std::{ffi::OsStr, os::unix::ffi::OsStrExt as _};
    let dir = tempfile::tempdir().expect("tempdir");
    let first = dir.path().join(OsStr::from_bytes(b"a\xFF"));
    let second = dir.path().join(OsStr::from_bytes(b"a\xFE"));
    for path in [&first, &second] {
        if let Err(error) = std::fs::create_dir(path) {
            eprintln!("skipped: the file system refuses the name: {error}");
            return;
        }
    }
    std::fs::write(first.join("x"), vec![1_u8; 100]).unwrap();
    std::fs::write(second.join("y"), vec![1_u8; 250]).unwrap();
    let summary: ScanSummary = LiveSource::new(None)
        .scan(dir.path(), &CancellationToken::new(), &|_: ScanProgress| {})
        .expect("scan");
    assert_eq!(summary.children.len(), 2);
    let find = |path: &Path| summary.children.iter().find(|c| c.path == path);
    assert_eq!(find(&first).map(|c| c.logical), Some(100));
    assert_eq!(find(&second).map(|c| c.logical), Some(250));
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

#[test]
fn the_fixture_scan_publishes_growing_children_before_done() {
    use std::cell::RefCell;
    let seen: RefCell<Vec<ScanProgress>> = RefCell::new(Vec::new());
    let source = FixtureSource::new(FixtureScenario::Healthy);
    let summary = source
        .scan(Path::new("/root"), &CancellationToken::new(), &|p| {
            seen.borrow_mut().push(p);
        })
        .expect("scan");
    let seen = seen.into_inner();
    assert_eq!(seen.len(), 12);
    assert!(seen.iter().all(|p| !p.children.is_empty()));
    assert!(seen.windows(2).all(|w| {
        w[0].allocated <= w[1].allocated
            && w[1].children.len() >= w[0].children.len()
            && w[1]
                .children
                .iter()
                .zip(&w[0].children)
                .all(|(a, b)| a.name == b.name)
    }));
    assert!(seen.iter().all(|p| p.children.len() <= 32));
    assert!(seen[11].allocated <= summary.total_allocated);
}

fn done_screen(
    reduce: bool,
    cx: &mut TestAppContext,
) -> (
    gpui_kit::Entity<StorageScreen>,
    std::rc::Rc<std::cell::Cell<std::time::Duration>>,
    gpui_kit::VisualTestContext,
) {
    cx.update(gpui_kit::init);
    cx.update(|cx| cx.set_reduce_motion(reduce));
    let model = model_for(Arc::new(FixtureSource::new(FixtureScenario::Healthy)), cx);
    let (screen, vcx) = cx.add_window_view(|_, cx| StorageScreen::new(model.clone(), cx));
    let mut vcx = vcx.clone();
    let base = std::time::Instant::now();
    let offset = std::rc::Rc::new(std::cell::Cell::new(std::time::Duration::ZERO));
    let read = std::rc::Rc::clone(&offset);
    screen.update(&mut vcx, |screen, _| {
        screen.set_clock(svalnir_gui::screens::storage::Clock::new(move || {
            base + read.get()
        }));
    });
    screen.update(&mut vcx, |screen, cx| screen.pop_to(0, cx));
    vcx.run_until_parked();
    (screen, offset, vcx)
}

#[gpui_kit::test]
fn reduce_motion_fills_the_chart_at_once(cx: &mut TestAppContext) {
    let (screen, _offset, vcx) = done_screen(true, cx);
    assert!((screen.read_with(&vcx, |s, _| s.chart_fill()) - 1.0).abs() < f32::EPSILON);
    vcx.run_until_parked();
}

#[gpui_kit::test]
fn the_chart_fills_in_over_time_and_ends_at_one(cx: &mut TestAppContext) {
    let (screen, offset, mut vcx) = done_screen(false, cx);
    assert!(screen.read_with(&vcx, |s, _| s.chart_fill()) < 1.0);
    offset.set(std::time::Duration::from_secs(2));
    screen.update(&mut vcx, |_, cx| cx.notify());
    vcx.run_until_parked();
    assert!((screen.read_with(&vcx, |s, _| s.chart_fill()) - 1.0).abs() < f32::EPSILON);
}
