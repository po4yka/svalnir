//! Svalnir GPUI interface.
//!
//! Renders views and sends requests to the agent. It does not enforce policy
//! or run blocking native work on the UI thread.

use gpui_kit::{
    App, Bounds, Context, IntoElement, Render, Window, WindowBounds, WindowOptions, div,
    prelude::*, px, size,
};

#[derive(Debug)]
struct MainView;

impl Render for MainView {
    fn render(&mut self, _window: &mut Window, _cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .flex()
            .size_full()
            .justify_center()
            .items_center()
            .child("Svalnir")
    }
}

fn main() {
    gpui_kit::application()
        .with_assets(gpui_kit::assets::Assets)
        .run(|cx: &mut App| {
            // Initialize gpui-kit before a window opens.
            gpui_kit::init(cx);

            let bounds = Bounds::centered(None, size(px(640.0), px(400.0)), cx);
            let options = WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                ..Default::default()
            };
            // `gpui_kit::open_window` mounts the root view that dialogs,
            // notifications, tooltips, and menus need.
            if let Err(error) = gpui_kit::open_window(options, cx, |_, cx| cx.new(|_| MainView)) {
                tracing::error!(%error, "cannot open the main window");
                cx.quit();
            }
        });
}
