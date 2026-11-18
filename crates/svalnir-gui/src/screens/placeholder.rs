//! Titled empty state used by every screen until it is built.

use crate::{
    shell::nav::Screen,
    theme::tokens::{self, Tokens, to_hsla},
    ui::surface::{Panel, Shell, ShellHeader},
};
use gpui_kit::{
    Context, FontWeight, IntoElement, ParentElement, Render, Role, Styled, TestSupportExt as _,
    Window, component::ActiveTheme as _, div, prelude::*, px,
};

/// A screen that shows its title and that it is not built yet.
#[derive(Debug)]
pub struct Placeholder {
    screen: Screen,
}

impl Placeholder {
    /// Creates the placeholder of `screen`.
    pub fn new(screen: Screen) -> Self {
        Self { screen }
    }
}

impl Render for Placeholder {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tokens: &Tokens = Tokens::for_dark(cx.theme().is_dark());
        let title: &'static str = self.screen.title();
        div()
            .flex()
            .flex_col()
            .gap(tokens::GRID_GAP)
            .child(
                div()
                    .id("screen-title")
                    .role(Role::Heading)
                    .test_support()
                    .aria_label(title)
                    .text_size(px(24.0))
                    .font_weight(FontWeight::SEMIBOLD)
                    .child(title),
            )
            .child(
                Shell::new()
                    .child(ShellHeader::new(self.screen.icon(), title).subtitle("Placeholder"))
                    .child(
                        Panel::new().child(
                            div()
                                .text_size(px(14.0))
                                .text_color(to_hsla(tokens.muted_foreground))
                                .child("This screen is not built yet."),
                        ),
                    ),
            )
    }
}
