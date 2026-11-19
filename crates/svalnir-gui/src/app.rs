//! Application bootstrap: gpui-kit, fonts, theme, key bindings, main window.

use crate::{
    actions::fixture::ActionScript,
    data::{
        DataSource,
        fixture::{FixtureScenario, FixtureSource},
        live::LiveSource,
        store::AppModel,
    },
    shell::{
        nav::{self, Screen},
        window::MainWindow,
    },
    theme::{apply, fonts},
    viz::{
        hover::{FocusTarget, request_launch_focus},
        storage_layouts::StorageLayout,
    },
};
use gpui_kit::{
    AnyWindowHandle, App, AppContext as _, Bounds, Entity, Pixels, WindowAppearance, WindowBounds,
    WindowOptions,
    base::{ReduceMotionPreference, set_reduce_motion_preference},
    component::TitleBar,
    px, size,
};
use std::{path::PathBuf, process::ExitCode, rc::Rc, sync::Arc};

/// The usage text of `--help`.
pub const USAGE: &str = "Usage: svalnir-gui [OPTIONS]

Options:
  --fixture NAME       Show fixed data instead of measurements
                       (healthy, pressure, unavailable, stale, agent-absent, drift)
  --appearance MODE    Force the theme: light or dark
  --reduce-motion      Force Reduce Motion on
  --screen NAME        Open on a screen (overview, storage, memory,
                       applications, automation, history, diagnostics)
  --sidebar WIDTH      Set the choice for the sidebar width: narrow or wide.
                       Without it, the sidebar is narrow below 900 points
  --size WxH           Set the window size in points, for example 1120x720
  --layout NAME        Open the folder chart of Storage in a layout
                       (tiles, band, columns, ring)
  --scan PATH          Start a size scan of the directory PATH at launch.
                       The scan reads sizes only
  --rescan             With --scan only: when the first scan ends, scan the
                       same directory once more
  --readings N         With --fixture only: take N readings (1 to 180) at
                       launch, so the session chart has N readings
  --focus CHART        Give a chart keyboard focus at launch and pick its
                       first mark, so its card shows without a pointer
                       (dial, session, volume, folders)
  --actions NAME       With --fixture only: the answer of each action
                       (accept, refuse, unavailable, pending). The fixture
                       writes nothing
  --detail OPERATION   With --fixture only: open the detail of the
                       operation OPERATION on History
  --open-stop          With --fixture only: open the stop confirmation of
                       the first group that the catalog does not protect
  --no-status-item     Add no item to the menu bar. The client then quits
                       when its last window closes
  --help               Print this text
";

/// A theme mode that the launch arguments force.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForcedAppearance {
    /// The light theme.
    Light,
    /// The dark theme.
    Dark,
}

impl ForcedAppearance {
    /// The window appearance of the mode.
    #[must_use]
    pub const fn window_appearance(self) -> WindowAppearance {
        match self {
            Self::Light => WindowAppearance::Light,
            Self::Dark => WindowAppearance::Dark,
        }
    }
}

/// The options of one launch.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "one independent flag for each launch option"
)]
pub struct LaunchOptions {
    /// The fixture scenario; `None` selects the live source.
    pub fixture: Option<FixtureScenario>,
    /// The forced theme; `None` follows the system.
    pub appearance: Option<ForcedAppearance>,
    /// Whether Reduce Motion is forced on.
    pub reduce_motion: bool,
    /// The screen that the window opens on; `None` is the Overview.
    pub screen: Option<Screen>,
    /// The directory of a scan that starts at launch.
    pub scan: Option<PathBuf>,
    /// Whether a second scan of the same directory starts when the first ends.
    pub rescan: bool,
    /// The layout of the folder chart; `None` is the default layout.
    pub layout: Option<StorageLayout>,
    /// The window size in points; `None` is the default size.
    pub size: Option<(u16, u16)>,
    /// The number of readings that a fixture takes at launch, 1 to 180.
    pub readings: Option<usize>,
    /// The choice for the sidebar width: `Some(true)` is narrow.
    pub sidebar_narrow: Option<bool>,
    /// The chart that has keyboard focus at launch.
    pub focus: Option<FocusTarget>,
    /// The answer of each action of a fixture; `None` is the answer of
    /// the scenario.
    pub actions: Option<ActionScript>,
    /// The operation whose History detail opens at launch.
    pub detail: Option<String>,
    /// Whether the stop confirmation of the first group that the catalog
    /// does not protect opens at launch.
    pub open_stop: bool,
    /// Whether the menu bar item is off.
    pub no_status_item: bool,
    /// Whether `--help` was given.
    pub help: bool,
}

/// Parses the launch arguments, without the program name.
///
/// # Errors
///
/// Returns a message for an unknown option, a missing or invalid value.
#[expect(clippy::too_many_lines, reason = "one match arm for each option")]
pub fn parse_args(mut args: impl Iterator<Item = String>) -> Result<LaunchOptions, String> {
    let mut options = LaunchOptions::default();
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--fixture" => {
                let name: String = args
                    .next()
                    .ok_or_else(|| "`--fixture` needs a name".to_owned())?;
                options.fixture = Some(FixtureScenario::from_name(&name).ok_or_else(|| {
                    let names: Vec<&str> = FixtureScenario::ALL.iter().map(|s| s.name()).collect();
                    format!(
                        "unknown fixture `{name}`; valid names: {}",
                        names.join(", ")
                    )
                })?);
            }
            "--appearance" => {
                let mode: String = args
                    .next()
                    .ok_or_else(|| "`--appearance` needs `light` or `dark`".to_owned())?;
                options.appearance = Some(match mode.as_str() {
                    "light" => ForcedAppearance::Light,
                    "dark" => ForcedAppearance::Dark,
                    other => {
                        return Err(format!(
                            "unknown appearance `{other}`; use `light` or `dark`"
                        ));
                    }
                });
            }
            "--reduce-motion" => options.reduce_motion = true,
            "--screen" => {
                let name: String = args
                    .next()
                    .ok_or_else(|| "`--screen` needs a name".to_owned())?;
                options.screen = Some(
                    Screen::ALL
                        .into_iter()
                        .find(|screen| screen.title().eq_ignore_ascii_case(&name))
                        .ok_or_else(|| format!("unknown screen `{name}`"))?,
                );
            }
            "--sidebar" => {
                let mode: String = args
                    .next()
                    .ok_or_else(|| "`--sidebar` needs `narrow` or `wide`".to_owned())?;
                options.sidebar_narrow = Some(match mode.as_str() {
                    "narrow" => true,
                    "wide" => false,
                    other => {
                        return Err(format!("unknown sidebar `{other}`; use `narrow` or `wide`"));
                    }
                });
            }
            "--size" => {
                let text: String = args
                    .next()
                    .ok_or_else(|| "`--size` needs a value such as 1120x720".to_owned())?;
                let parsed: Option<(u16, u16)> = text
                    .split_once('x')
                    .and_then(|(w, h)| Some((w.parse::<u16>().ok()?, h.parse::<u16>().ok()?)));
                options.size = Some(
                    parsed
                        .filter(|(w, h)| f32::from(*w) >= MIN_SIZE.0 && f32::from(*h) >= MIN_SIZE.1)
                        .ok_or_else(|| {
                            format!("`--size` needs WxH of 720x480 or more, not `{text}`")
                        })?,
                );
            }
            "--layout" => {
                let name: String = args
                    .next()
                    .ok_or_else(|| "`--layout` needs a name".to_owned())?;
                options.layout = Some(
                    StorageLayout::ALL
                        .into_iter()
                        .find(|layout| layout.name().eq_ignore_ascii_case(&name))
                        .ok_or_else(|| format!("unknown layout `{name}`"))?,
                );
            }
            "--scan" => {
                let path: PathBuf = args
                    .next()
                    .map(PathBuf::from)
                    .ok_or_else(|| "`--scan` needs a directory".to_owned())?;
                if !path.is_absolute() {
                    return Err("`--scan` needs an absolute path".to_owned());
                }
                options.scan = Some(path);
            }
            "--rescan" => options.rescan = true,
            "--readings" => {
                let text: String = args
                    .next()
                    .ok_or_else(|| "`--readings` needs a number from 1 to 180".to_owned())?;
                options.readings = Some(
                    text.parse::<usize>()
                        .ok()
                        .filter(|count| (1..=MAX_READINGS).contains(count))
                        .ok_or_else(|| {
                            format!("`--readings` needs a number from 1 to 180, not `{text}`")
                        })?,
                );
            }
            "--focus" => {
                let name: String = args
                    .next()
                    .ok_or_else(|| "`--focus` needs a chart name".to_owned())?;
                options.focus = Some(FocusTarget::from_name(&name).ok_or_else(|| {
                    format!("unknown chart `{name}`; use dial, session, volume, or folders")
                })?);
            }
            "--actions" => {
                let name: String = args
                    .next()
                    .ok_or_else(|| "`--actions` needs a name".to_owned())?;
                options.actions = Some(ActionScript::from_name(&name).ok_or_else(|| {
                    format!("unknown actions `{name}`; use accept, refuse, unavailable, or pending")
                })?);
            }
            "--detail" => {
                options.detail = Some(
                    args.next()
                        .ok_or_else(|| "`--detail` needs an operation".to_owned())?,
                );
            }
            "--open-stop" => options.open_stop = true,
            "--no-status-item" => options.no_status_item = true,
            "--help" | "-h" => options.help = true,
            other => return Err(format!("unknown argument `{other}`")),
        }
    }
    if options.readings.is_some() && options.fixture.is_none() {
        return Err("`--readings` is valid only with `--fixture`".to_owned());
    }
    if options.rescan && options.scan.is_none() {
        return Err("`--rescan` is valid only with `--scan`".to_owned());
    }
    if options.actions.is_some() && options.fixture.is_none() {
        return Err("`--actions` is valid only with `--fixture`".to_owned());
    }
    if options.detail.is_some() && options.fixture.is_none() {
        return Err("`--detail` is valid only with `--fixture`".to_owned());
    }
    if options.open_stop && options.fixture.is_none() {
        return Err("`--open-stop` is valid only with `--fixture`".to_owned());
    }
    Ok(options)
}

/// Opens the stop confirmation of the first group of the fixture
/// `scenario` that the catalog does not protect, for a screenshot of the
/// dialog. The fixture path records nothing.
fn open_fixture_stop(
    handle: AnyWindowHandle,
    view: &Entity<MainWindow>,
    scenario: FixtureScenario,
    cx: &mut App,
) {
    let group = FixtureSource::new(scenario)
        .processes()
        .ok()
        .and_then(|processes| {
            processes
                .applications
                .into_iter()
                .find(|row| row.protection == crate::data::records::Protection::NotProtected)
        });
    let Some(group) = group else {
        tracing::error!("the fixture has no group that the catalog does not protect");
        return;
    };
    let model: Entity<AppModel> = view.read(cx).model().clone();
    let opened = handle.update(cx, |_, window, cx| {
        crate::screens::controls::open_stop(&model, &group.instance, &group.name, window, cx);
    });
    if let Err(error) = opened {
        tracing::error!(%error, "cannot open the stop confirmation");
    }
}

/// The most readings that `--readings` takes.
pub const MAX_READINGS: usize = 180;

/// Default window size.
const DEFAULT_SIZE: (f32, f32) = (1120.0, 720.0);
/// Minimum window size.
const MIN_SIZE: (f32, f32) = (720.0, 480.0);

/// Opens the main window with `bounds`, reading `source`. `appearance`
/// forces the theme and stops the system-appearance observer.
///
/// # Errors
///
/// Returns the platform error when the window cannot open.
pub fn open_main_window(
    bounds: Bounds<Pixels>,
    source: Arc<dyn DataSource>,
    appearance: Option<ForcedAppearance>,
    cx: &mut App,
) -> gpui_kit::Result<(AnyWindowHandle, Entity<MainWindow>)> {
    open_main_window_seeded(bounds, source, appearance, 0, cx)
}

/// Like [`open_main_window`], and the model takes `readings` host readings
/// before the first paint (0 takes none at once).
///
/// # Errors
///
/// Returns the platform error when the window cannot open.
pub fn open_main_window_seeded(
    bounds: Bounds<Pixels>,
    source: Arc<dyn DataSource>,
    appearance: Option<ForcedAppearance>,
    readings: usize,
    cx: &mut App,
) -> gpui_kit::Result<(AnyWindowHandle, Entity<MainWindow>)> {
    let model: Entity<AppModel> = cx.new(|cx| AppModel::new_seeded(source, readings, cx));
    open_main_window_with_model(bounds, model, appearance, cx)
}

/// Opens the main window with `bounds` on a model that already exists, so
/// that a window that opens again shows the same readings and actions.
///
/// # Errors
///
/// Returns the platform error when the window cannot open.
pub fn open_main_window_with_model(
    bounds: Bounds<Pixels>,
    model: Entity<AppModel>,
    appearance: Option<ForcedAppearance>,
    cx: &mut App,
) -> gpui_kit::Result<(AnyWindowHandle, Entity<MainWindow>)> {
    let options = WindowOptions {
        window_bounds: Some(WindowBounds::Windowed(bounds)),
        window_min_size: Some(size(px(MIN_SIZE.0), px(MIN_SIZE.1))),
        ..TitleBar::window_options()
    };
    gpui_kit::open_window(options, cx, |window, cx| {
        match appearance {
            Some(forced) => apply::install_fixed(forced.window_appearance(), cx),
            None => apply::install(window, cx),
        }
        cx.new(|cx| MainWindow::new(model, window, cx))
    })
}

/// What the client does when its last window closed. With no menu bar item
/// (`item` is false), it quits. With the item, it keeps running: no screen is
/// in front, so the model reads only the host, the agent, and the standing
/// topics of the item, at the inactive interval, and a stop dialog that was
/// open closes with no record, as when the user closes it.
pub fn after_last_window_closed(item: bool, model: &Entity<AppModel>, cx: &mut App) {
    if !item {
        cx.quit();
        return;
    }
    model.update(cx, |model, cx| {
        model.set_active(false, cx);
        model.set_topics(&[], cx);
        model.close_stop(cx);
    });
}

/// Brings the main window to the front, or opens it again on `model` when
/// no window is open.
fn show_main_window(
    model: &Entity<AppModel>,
    appearance: Option<ForcedAppearance>,
    window_size: (f32, f32),
    cx: &mut App,
) {
    if let Some(handle) = cx.windows().first().copied() {
        if handle
            .update(cx, |_, window, _| window.activate_window())
            .is_err()
        {
            tracing::debug!("the window closed before it came to the front");
        }
    } else {
        let bounds = Bounds::centered(None, size(px(window_size.0), px(window_size.1)), cx);
        if let Err(error) = open_main_window_with_model(bounds, model.clone(), appearance, cx) {
            tracing::error!(%error, "cannot open the main window");
            return;
        }
    }
    cx.activate(true);
}

/// Runs the client until the last window closes, or with the menu bar
/// item, until Quit Svalnir. A bad argument prints the
/// reason and exits with code 2.
pub fn run() -> ExitCode {
    let options: LaunchOptions = match parse_args(std::env::args().skip(1)) {
        Ok(options) => options,
        Err(message) => {
            eprintln!("svalnir-gui: {message}");
            return ExitCode::from(2);
        }
    };
    if options.help {
        print!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let source: Arc<dyn DataSource> = match options.fixture {
        Some(scenario) => Arc::new(
            FixtureSource::new(scenario)
                .with_pacing(std::time::Duration::from_millis(120))
                .with_seeded_readings(options.readings.unwrap_or(0))
                .with_local_time()
                .with_actions(
                    options
                        .actions
                        .unwrap_or_else(|| ActionScript::of(scenario)),
                ),
        ),
        None => Arc::new(LiveSource::from_environment()),
    };
    let application = gpui_kit::application().with_assets(gpui_kit::assets::Assets);
    // A launch of the application while it runs with no window open, for
    // example from the Dock, opens the window that the menu bar item opens.
    application.on_reopen(crate::status_item::show_window);
    application.run(move |cx: &mut App| {
        gpui_kit::init(cx);
        if options.reduce_motion {
            set_reduce_motion_preference(ReduceMotionPreference::Reduce, cx);
        }
        fonts::register(cx);
        nav::bind_keys(cx);

        let (width, height): (f32, f32) = options
            .size
            .map_or(DEFAULT_SIZE, |(w, h)| (f32::from(w), f32::from(h)));
        // The model belongs to the application, not to the window: the
        // menu bar item reads it while no window is open.
        let readings: usize = options.readings.unwrap_or(0);
        let model: Entity<AppModel> = cx.new(|cx| AppModel::new_seeded(source, readings, cx));

        let appearance: Option<ForcedAppearance> = options.appearance;
        let item: bool = !options.no_status_item && {
            let shown: Entity<AppModel> = model.clone();
            let show: Rc<dyn Fn(&mut App)> = Rc::new(move |cx: &mut App| {
                show_main_window(&shown, appearance, (width, height), cx);
            });
            crate::status_item::install(model.clone(), show, cx)
        };
        let closed: Entity<AppModel> = model.clone();
        cx.on_window_closed(move |cx, _window_id| {
            if cx.windows().is_empty() {
                after_last_window_closed(item, &closed, cx);
            }
        })
        .detach();
        let bounds = Bounds::centered(None, size(px(width), px(height)), cx);
        let (handle, view) = match open_main_window_with_model(bounds, model, appearance, cx) {
            Ok((handle, view)) => (handle, view),
            Err(error) => {
                tracing::error!(%error, "cannot open the main window");
                cx.quit();
                return;
            }
        };
        if let Some(screen) = options.screen {
            view.update(cx, |view, cx| view.select(screen, cx));
        }
        if options.sidebar_narrow.is_some() {
            view.update(cx, |view, cx| {
                view.set_sidebar_choice(options.sidebar_narrow, cx);
            });
        }
        if let Some(layout) = options.layout {
            view.update(cx, |view, cx| view.set_storage_layout(layout, cx));
        }
        if let Some(target) = options.focus {
            request_launch_focus(target, cx);
        }
        if let Some(operation) = &options.detail {
            view.update(cx, |view, cx| view.show_history_detail(operation, cx));
        }
        if let (true, Some(scenario)) = (options.open_stop, options.fixture) {
            open_fixture_stop(handle, &view, scenario, cx);
        }
        if let Some(root) = &options.scan {
            let model: Entity<AppModel> = view.read(cx).model().clone();
            let rescan: bool = options.rescan;
            model.update(cx, |model, cx| {
                model.set_rescan_once(rescan);
                model.start_scan(root, cx);
            });
        }
        // A window that is not in front gets no frame, so its values stay
        // at the first paint.
        cx.activate(true);
    });
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<LaunchOptions, String> {
        parse_args(args.iter().map(|a| (*a).to_owned()))
    }

    #[test]
    fn the_launch_dialogs_need_a_fixture() {
        assert!(parse(&["--detail", "op-1"]).is_err());
        assert!(parse(&["--open-stop"]).is_err());
        assert!(parse(&["--fixture", "healthy", "--detail"]).is_err());
        assert_eq!(
            parse(&["--fixture", "healthy", "--open-stop"]).map(|o| o.open_stop),
            Ok(true)
        );
    }

    #[test]
    fn defaults_are_live() {
        assert_eq!(parse(&[]), Ok(LaunchOptions::default()));
    }

    #[test]
    fn every_option_parses() {
        let options = parse(&[
            "--fixture",
            "pressure",
            "--readings",
            "40",
            "--appearance",
            "light",
            "--reduce-motion",
            "--screen",
            "storage",
            "--scan",
            "/tmp/a",
            "--sidebar",
            "narrow",
            "--rescan",
            "--size",
            "1200x900",
            "--layout",
            "ring",
            "--focus",
            "dial",
            "--actions",
            "refuse",
            "--detail",
            "op-1",
            "--open-stop",
            "--no-status-item",
            "--help",
        ]);
        assert_eq!(
            options,
            Ok(LaunchOptions {
                fixture: Some(FixtureScenario::Pressure),
                appearance: Some(ForcedAppearance::Light),
                reduce_motion: true,
                screen: Some(Screen::Storage),
                scan: Some(PathBuf::from("/tmp/a")),
                rescan: true,
                size: Some((1200, 900)),
                layout: Some(StorageLayout::Ring),
                readings: Some(40),
                sidebar_narrow: Some(true),
                focus: Some(FocusTarget::Dial),
                actions: Some(ActionScript::Refuse),
                detail: Some("op-1".to_owned()),
                open_stop: true,
                no_status_item: true,
                help: true,
            })
        );
    }

    #[test]
    fn bad_input_is_an_error() {
        let unknown = parse(&["--fixture", "nope"]);
        assert!(unknown.is_err_and(|m| m.contains("agent-absent")));
        assert!(parse(&["--fixture"]).is_err());
        assert!(parse(&["--appearance", "blue"]).is_err());
        assert!(parse(&["--appearance"]).is_err());
        assert!(parse(&["--bogus"]).is_err());
        assert!(parse(&["--screen", "nowhere"]).is_err());
        assert!(parse(&["--scan", "relative/path"]).is_err());
        assert!(parse(&["--scan"]).is_err());
        assert!(parse(&["--sidebar", "tiny"]).is_err());
        assert!(parse(&["--sidebar"]).is_err());
        assert_eq!(
            parse(&["--sidebar", "wide"]).map(|o| o.sidebar_narrow),
            Ok(Some(false))
        );
        assert!(parse(&["--rescan"]).is_err(), "needs a scan");
        assert!(parse(&["--actions", "accept"]).is_err(), "needs a fixture");
        assert!(parse(&["--fixture", "healthy", "--actions", "maybe"]).is_err());
        assert!(parse(&["--rescan", "--scan", "/tmp/a"]).is_ok());
        assert!(parse(&["--size", "100x100"]).is_err());
        assert!(parse(&["--size", "wide"]).is_err());
        assert!(parse(&["--layout", "spiral"]).is_err());
        assert!(parse(&["--focus", "tree"]).is_err());
        assert!(parse(&["--focus"]).is_err());
        assert_eq!(
            parse(&["--focus", "folders"]).map(|o| o.focus),
            Ok(Some(FocusTarget::Folders))
        );
        assert!(parse(&["--fixture", "drift", "--readings", "0"]).is_err());
        assert!(parse(&["--fixture", "drift", "--readings", "181"]).is_err());
        assert!(parse(&["--fixture", "drift", "--readings", "x"]).is_err());
        assert!(parse(&["--fixture", "drift", "--readings"]).is_err());
        assert!(parse(&["--readings", "10"]).is_err(), "needs a fixture");
        assert!(parse(&["--readings", "10", "--fixture", "drift"]).is_ok());
        assert!(parse(&["--fixture", "drift", "--readings", "180"]).is_ok());
    }
}
