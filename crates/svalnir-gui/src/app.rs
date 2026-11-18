//! Application bootstrap: gpui-kit, fonts, theme, key bindings, main window.

use crate::{
    shell::{nav, window::MainWindow},
    theme::{apply, fonts},
};
use gpui_kit::{
    AnyWindowHandle, App, AppContext as _, Bounds, Entity, Pixels, WindowBounds, WindowOptions,
    component::TitleBar, px, size,
};

/// Default window size.
const DEFAULT_SIZE: (f32, f32) = (1120.0, 720.0);
/// Minimum window size.
const MIN_SIZE: (f32, f32) = (720.0, 480.0);

/// Opens the main window with `bounds`.
///
/// # Errors
///
/// Returns the platform error when the window cannot open.
pub fn open_main_window(
    bounds: Bounds<Pixels>,
    cx: &mut App,
) -> gpui_kit::Result<(AnyWindowHandle, Entity<MainWindow>)> {
    let options = WindowOptions {
        window_bounds: Some(WindowBounds::Windowed(bounds)),
        window_min_size: Some(size(px(MIN_SIZE.0), px(MIN_SIZE.1))),
        ..TitleBar::window_options()
    };
    gpui_kit::open_window(options, cx, |window, cx| {
        apply::install(window, cx);
        cx.new(|cx| MainWindow::new(window, cx))
    })
}

/// Runs the client until the last window closes.
pub fn run() {
    gpui_kit::application()
        .with_assets(gpui_kit::assets::Assets)
        .run(|cx: &mut App| {
            gpui_kit::init(cx);
            fonts::register(cx);
            nav::bind_keys(cx);

            cx.on_window_closed(|cx, _window_id| {
                if cx.windows().is_empty() {
                    cx.quit();
                }
            })
            .detach();

            let bounds = Bounds::centered(None, size(px(DEFAULT_SIZE.0), px(DEFAULT_SIZE.1)), cx);
            if let Err(error) = open_main_window(bounds, cx) {
                tracing::error!(%error, "cannot open the main window");
                cx.quit();
            }
        });
}
