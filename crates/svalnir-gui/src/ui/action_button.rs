//! The action button of `DESIGN.md` section 4: a full pill with a silver
//! or a dark gradient, or no fill.

use crate::theme::tokens::{self, Tokens, hex_alpha, to_hsla};
use gpui_kit::{
    App, BoxShadow, ClickEvent, ElementId, FocusHandle, FontWeight, Hsla, InteractiveElement as _,
    IntoElement, ParentElement as _, RenderOnce, Role, SharedString,
    StatefulInteractiveElement as _, Styled as _, TestSupportExt as _, Window,
    component::{ActiveTheme as _, Icon, IconName, h_flex},
    div, linear_color_stop, linear_gradient, point, px,
};
use std::rc::Rc;

/// The look of a button.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ButtonVariant {
    /// The silver gradient.
    Primary,
    /// The dark or light gradient with `foreground` text.
    Secondary,
    /// No fill; a 6% fill on hover.
    Quiet,
}

/// The height of a button.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ButtonSize {
    /// 32 px.
    Sm,
    /// 36 px.
    Md,
}

impl ButtonSize {
    /// The height in pixels.
    #[must_use]
    pub const fn height(self) -> f32 {
        match self {
            Self::Sm => 32.0,
            Self::Md => 36.0,
        }
    }
}

type ClickHandler = Rc<dyn Fn(&ClickEvent, &mut Window, &mut App)>;

/// A button with a variant, a size, and an optional leading icon.
#[derive(IntoElement)]
pub struct ActionButton {
    id: SharedString,
    label: SharedString,
    variant: ButtonVariant,
    size: ButtonSize,
    icon: Option<IconName>,
    disabled: bool,
    on_click: Option<ClickHandler>,
}

impl std::fmt::Debug for ActionButton {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActionButton")
            .field("id", &self.id)
            .field("variant", &self.variant)
            .finish_non_exhaustive()
    }
}

impl ActionButton {
    /// Creates a button.
    pub fn new(id: impl Into<SharedString>, label: impl Into<SharedString>) -> Self {
        Self {
            id: id.into(),
            label: label.into(),
            variant: ButtonVariant::Secondary,
            size: ButtonSize::Sm,
            icon: None,
            disabled: false,
            on_click: None,
        }
    }

    /// Sets the variant.
    #[must_use]
    pub const fn variant(mut self, variant: ButtonVariant) -> Self {
        self.variant = variant;
        self
    }

    /// Sets the size.
    #[must_use]
    pub const fn size(mut self, size: ButtonSize) -> Self {
        self.size = size;
        self
    }

    /// Adds a leading icon.
    #[must_use]
    pub const fn icon(mut self, icon: IconName) -> Self {
        self.icon = Some(icon);
        self
    }

    /// Disables the button.
    #[must_use]
    pub const fn disabled(mut self, disabled: bool) -> Self {
        self.disabled = disabled;
        self
    }

    /// Sets the click handler.
    #[must_use]
    pub fn on_click(mut self, f: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static) -> Self {
        self.on_click = Some(Rc::new(f));
        self
    }
}

/// The color mixed `amount` toward black.
fn darken(color: Hsla, amount: f32) -> Hsla {
    Hsla {
        l: color.l * (1.0 - amount),
        ..color
    }
}

impl RenderOnce for ActionButton {
    fn render(self, window: &mut Window, cx: &mut App) -> impl IntoElement {
        let dark: bool = cx.theme().is_dark();
        let tokens: &Tokens = Tokens::for_dark(dark);
        let focus: FocusHandle = window
            .use_keyed_state(
                ElementId::from(SharedString::from(format!("{}-focus", self.id))),
                cx,
                |_, cx| cx.focus_handle().tab_stop(true),
            )
            .read(cx)
            .clone();
        let (top, bottom): (Hsla, Hsla) = match self.variant {
            ButtonVariant::Primary => (to_hsla(tokens.primary_bottom), to_hsla(tokens.primary_top)),
            _ => (
                to_hsla(tokens.secondary_bottom),
                to_hsla(tokens.secondary_top),
            ),
        };
        let text: Hsla = match self.variant {
            ButtonVariant::Primary => to_hsla(tokens.primary_text),
            _ => to_hsla(tokens.foreground),
        };
        let edge: Hsla = match self.variant {
            ButtonVariant::Primary if dark => to_hsla(hex_alpha(0xff_ffff, 0.5)),
            ButtonVariant::Primary => to_hsla(hex_alpha(0x00_0000, 0.1)),
            _ => Hsla::transparent_black(),
        };
        let gradient = |from: Hsla, to: Hsla| {
            linear_gradient(
                0.0,
                linear_color_stop(from, 0.0),
                linear_color_stop(to, 1.0),
            )
        };
        let ring: Vec<BoxShadow> = vec![
            BoxShadow {
                color: to_hsla(tokens.surface),
                offset: point(px(0.0), px(0.0)),
                blur_radius: px(0.0),
                spread_radius: px(2.0),
                inset: false,
            },
            BoxShadow {
                color: to_hsla(tokens.brand),
                offset: point(px(0.0), px(0.0)),
                blur_radius: px(0.0),
                spread_radius: px(4.0),
                inset: false,
            },
        ];
        let handler: Option<ClickHandler> = self.on_click;
        let disabled: bool = self.disabled;
        let mut base = h_flex()
            .id(ElementId::from(self.id))
            .role(Role::Button)
            .test_support()
            .aria_label(self.label.clone())
            .track_focus(&focus)
            .h(px(self.size.height()))
            // The inner padding of a control, not a layout gap.
            .px(px(14.0))
            .gap(tokens::SPACE_2)
            .items_center()
            .justify_center()
            .flex_shrink_0()
            .rounded_full()
            .border_1()
            .border_color(edge)
            .text_color(text)
            .text_size(px(13.0))
            .font_weight(FontWeight::MEDIUM)
            .focus_visible(move |s| s.shadow(ring));
        base = match self.variant {
            ButtonVariant::Quiet => base
                .hover(|s| s.bg(to_hsla(tokens.foreground).opacity(0.06)))
                .active(|s| s.bg(to_hsla(tokens.foreground).opacity(0.1))),
            _ => base
                .bg(gradient(bottom, top))
                .active(move |s| s.bg(gradient(darken(bottom, 0.06), darken(top, 0.06)))),
        };
        if disabled {
            base = base.opacity(0.5);
        } else {
            base = base.cursor_pointer();
            if let Some(handler) = handler {
                let key_handler: ClickHandler = Rc::clone(&handler);
                base = base
                    .on_key_down(move |event, window, cx| {
                        if matches!(event.keystroke.key.as_str(), "enter" | "space") {
                            key_handler(&ClickEvent::default(), window, cx);
                            cx.stop_propagation();
                        }
                    })
                    .on_click(move |event, window, cx| handler(event, window, cx));
            }
        }
        base.children(self.icon.map(|icon| Icon::new(icon).size_4()))
            .child(div().child(self.label))
    }
}
