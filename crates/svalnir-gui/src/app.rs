//! Application bootstrap: gpui-kit, fonts, theme, key bindings, main window.

use crate::{
    data::{
        DataSource,
        fixture::{FixtureScenario, FixtureSource},
        live::LiveSource,
        store::AppModel,
    },
    shell::{nav, window::MainWindow},
    theme::{apply, fonts},
};
use gpui_kit::{
    AnyWindowHandle, App, AppContext as _, Bounds, Entity, Pixels, WindowAppearance, WindowBounds,
    WindowOptions,
    base::{ReduceMotionPreference, set_reduce_motion_preference},
    component::TitleBar,
    px, size,
};
use std::{process::ExitCode, sync::Arc};

/// The usage text of `--help`.
pub const USAGE: &str = "Usage: svalnir-gui [OPTIONS]

Options:
  --fixture NAME       Show fixed data instead of measurements
                       (healthy, pressure, unavailable, stale, agent-absent)
  --appearance MODE    Force the theme: light or dark
  --reduce-motion      Force Reduce Motion on
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
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LaunchOptions {
    /// The fixture scenario; `None` selects the live source.
    pub fixture: Option<FixtureScenario>,
    /// The forced theme; `None` follows the system.
    pub appearance: Option<ForcedAppearance>,
    /// Whether Reduce Motion is forced on.
    pub reduce_motion: bool,
    /// Whether `--help` was given.
    pub help: bool,
}

/// Parses the launch arguments, without the program name.
///
/// # Errors
///
/// Returns a message for an unknown option, a missing or invalid value.
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
            "--help" | "-h" => options.help = true,
            other => return Err(format!("unknown argument `{other}`")),
        }
    }
    Ok(options)
}

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
        let model = cx.new(|cx| AppModel::new(source, cx));
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
        Some(scenario) => Arc::new(FixtureSource::new(scenario)),
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

            let bounds = Bounds::centered(None, size(px(DEFAULT_SIZE.0), px(DEFAULT_SIZE.1)), cx);
            if let Err(error) = open_main_window(bounds, source, options.appearance, cx) {
                tracing::error!(%error, "cannot open the main window");
                cx.quit();
                return;
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
            "--appearance",
            "light",
            "--reduce-motion",
            "--help",
        ]);
        assert_eq!(
            options,
            Ok(LaunchOptions {
                fixture: Some(FixtureScenario::Pressure),
                appearance: Some(ForcedAppearance::Light),
                reduce_motion: true,
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
    }
}
