//! The three surface layers of `DESIGN.md` section 3. No border, no shadow.

use crate::theme::tokens::{self, Tokens, to_hsla};
use gpui_kit::{
    AnyElement, App, FontWeight, IntoElement, ParentElement, RenderOnce, SharedString, Styled,
    Window,
    component::{ActiveTheme as _, Icon, IconName},
    div, px,
};
use std::fmt;

fn tokens_of(cx: &App) -> &'static Tokens {
    Tokens::for_dark(cx.theme().is_dark())
}

macro_rules! container {
    ($(#[$doc:meta])* $name:ident, $fill:ident, $radius:expr, $pad_x:expr, $pad_y:expr) => {
        $(#[$doc])*
        #[derive(IntoElement)]
        pub struct $name {
            children: Vec<AnyElement>,
            grow: bool,
        }

        impl $name {
            /// Creates an empty container.
            pub fn new() -> Self {
                Self { children: Vec::new(), grow: false }
            }

            /// Grows to the free height of the parent.
            #[must_use]
            pub const fn grow(mut self) -> Self {
                self.grow = true;
                self
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($name))
                    .field("children", &self.children.len())
                    .finish()
            }
        }

        impl ParentElement for $name {
            fn extend(&mut self, elements: impl IntoIterator<Item = AnyElement>) {
                self.children.extend(elements);
            }
        }

        impl RenderOnce for $name {
            fn render(self, _window: &mut Window, cx: &mut App) -> impl IntoElement {
                let fill = to_hsla(tokens_of(cx).$fill);
                let mut base = div().flex().flex_col();
                if self.grow {
                    base = base.flex_grow(1.0);
                }
                base
                    .bg(fill)
                    .rounded($radius)
                    .px($pad_x)
                    .py($pad_y)
                    .children(self.children)
            }
        }
    };
}

container!(
    /// Shell: `surface` fill, 22 px radius, 6 px padding.
    Shell,
    surface,
    tokens::SHELL_RADIUS,
    tokens::SHELL_PADDING,
    tokens::SHELL_PADDING
);
container!(
    /// Panel: `surface-inset` fill, 16 px radius, 16 px padding.
    Panel,
    surface_inset,
    tokens::PANEL_RADIUS,
    tokens::PANEL_PADDING,
    tokens::PANEL_PADDING
);
container!(
    /// Inset: `inset-tint` fill, 12 px radius, 12 by 14 px padding.
    Inset,
    inset_tint,
    tokens::INSET_RADIUS,
    tokens::INSET_PADDING_X,
    tokens::INSET_PADDING_Y
);

/// Shell header: icon tile, title with optional subtitle, and one aside.
#[derive(IntoElement)]
pub struct ShellHeader {
    icon: IconName,
    title: SharedString,
    subtitle: Option<SharedString>,
    aside: Option<AnyElement>,
}

impl fmt::Debug for ShellHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShellHeader")
            .field("title", &self.title)
            .field("subtitle", &self.subtitle)
            .finish_non_exhaustive()
    }
}

impl ShellHeader {
    /// Creates a header with an icon and a title.
    pub fn new(icon: IconName, title: impl Into<SharedString>) -> Self {
        Self {
            icon,
            title: title.into(),
            subtitle: None,
            aside: None,
        }
    }

    #[must_use]
    /// Sets the caption below the title.
    pub fn subtitle(mut self, subtitle: impl Into<SharedString>) -> Self {
        self.subtitle = Some(subtitle.into());
        self
    }

    #[must_use]
    /// Sets the single aside element: a pill, a value, or a small action.
    pub fn aside(mut self, aside: impl IntoElement) -> Self {
        self.aside = Some(aside.into_any_element());
        self
    }
}

impl RenderOnce for ShellHeader {
    fn render(self, _window: &mut Window, cx: &mut App) -> impl IntoElement {
        let tokens: &Tokens = tokens_of(cx);
        let muted = to_hsla(tokens.muted_foreground);
        div()
            .flex()
            .items_center()
            .gap(tokens::SPACE_3)
            // The inner padding of a control, not a layout gap.
            .px(px(10.0))
            .py(tokens::SPACE_2)
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_center()
                    .flex_shrink_0()
                    .size(tokens::ICON_TILE_SIZE)
                    .rounded(tokens::ICON_TILE_RADIUS)
                    .bg(to_hsla(tokens.inset_tint))
                    .child(Icon::new(self.icon).size(tokens::ICON_TILE_GLYPH)),
            )
            .child(
                div()
                    .flex()
                    .flex_col()
                    .flex_1()
                    .min_w_0()
                    .child(
                        div()
                            .text_size(px(15.0))
                            .font_weight(FontWeight::MEDIUM)
                            .child(self.title),
                    )
                    .children(self.subtitle.map(|subtitle| {
                        div().text_size(px(12.0)).text_color(muted).child(subtitle)
                    })),
            )
            .children(self.aside)
    }
}
