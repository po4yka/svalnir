//! Application bootstrap: gpui-kit, fonts, theme, key bindings, main window.

use crate::{
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
use std::{path::PathBuf, process::ExitCode, sync::Arc};

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
    Ok(options)
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
        let model: Entity<AppModel> = cx.new(|cx| AppModel::new_seeded(source, readings, cx));
        cx.new(|cx| MainWindow::new(model, window, cx))
    })
}

/// Runs the client until the last window closes. A bad argument prints the
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
                .with_local_time(),
        ),
        None => Arc::new(LiveSource::from_environment()),
    };
    gpui_kit::application()
        .with_assets(gpui_kit::assets::Assets)
        .run(move |cx: &mut App| {
            gpui_kit::init(cx);
            if options.reduce_motion {
                set_reduce_motion_preference(ReduceMotionPreference::Reduce, cx);
            }
            fonts::register(cx);
            nav::bind_keys(cx);

            cx.on_window_closed(|cx, _window_id| {
                if cx.windows().is_empty() {
                    cx.quit();
                }
            })
            .detach();

            let (width, height): (f32, f32) = options
                .size
                .map_or(DEFAULT_SIZE, |(w, h)| (f32::from(w), f32::from(h)));
            let bounds = Bounds::centered(None, size(px(width), px(height)), cx);
            let view = match open_main_window_seeded(
                bounds,
                source,
                options.appearance,
                options.readings.unwrap_or(0),
                cx,
            ) {
                Ok((_, view)) => view,
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
