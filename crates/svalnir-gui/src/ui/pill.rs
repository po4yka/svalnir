//! The status pill: a tone, an optional icon, and always a text.

use crate::theme::tokens::{self, Tokens, to_hsla};
use gpui_kit::{
    App, FontWeight, InteractiveElement as _, IntoElement, ParentElement as _, RenderOnce, Role,
    SharedString, Styled as _, TestSupportExt as _, Window,
    component::{ActiveTheme as _, Icon, IconName, h_flex},
    div,
    prelude::*,
    px,
};

/// The tone of a pill.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    /// No state: `muted-foreground`.
    Neutral,
    /// Activity: `brand`.
    Brand,
    /// Good: `positive`.
    Positive,
    /// Failure: `negative`.
    Negative,
    /// Near a threshold: `warning`.
    Warning,
}

/// A 24 px high pill with the tone at 15% alpha as fill.
#[derive(IntoElement)]
pub struct StatusPill {
    text: SharedString,
    tone: Tone,
    icon: Option<IconName>,
    id: SharedString,
}

impl std::fmt::Debug for StatusPill {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StatusPill")
            .field("text", &self.text)
            .field("tone", &self.tone)
            .finish_non_exhaustive()
    }
}

impl StatusPill {
    /// Creates a pill with a text.
    pub fn new(text: impl Into<SharedString>, tone: Tone) -> Self {
        Self {
            text: text.into(),
            tone,
            icon: None,
            id: SharedString::from("status-pill"),
        }
    }

    /// Adds an icon before the text.
    #[must_use]
    pub fn icon(mut self, icon: IconName) -> Self {
        self.icon = Some(icon);
        self
    }

    /// Sets the element id.
    #[must_use]
    pub fn id(mut self, id: impl Into<SharedString>) -> Self {
        self.id = id.into();
        self
    }
}

impl RenderOnce for StatusPill {
    fn render(self, _window: &mut Window, cx: &mut App) -> impl IntoElement {
        let tokens: &Tokens = Tokens::for_dark(cx.theme().is_dark());
        let color = to_hsla(match self.tone {
            Tone::Neutral => tokens.muted_foreground,
            Tone::Brand => tokens.brand,
            Tone::Positive => tokens.positive,
            Tone::Negative => tokens.negative,
            Tone::Warning => tokens.warning,
        });
        h_flex()
            .id(self.id)
            .role(Role::Status)
            .test_support()
            .aria_label(self.text.clone())
            .h(px(24.0))
            // The inner padding of a control, not a layout gap.
            .px(px(10.0))
            .gap(tokens::SPACE_1)
            .items_center()
            .flex_shrink_0()
            // A pill keeps its own width in a column that stretches its children.
            .self_start()
            .rounded_full()
            .bg(color.opacity(0.15))
            .text_color(color)
            .text_size(px(12.0))
            .font_weight(FontWeight::MEDIUM)
            .children(self.icon.map(|icon| Icon::new(icon).size_3()))
            .child(div().child(self.text))
    }
}

/// A small tag with a mono text: `surface-raised` fill, 6 px radius, 11 px
/// text (`DESIGN.md` section 4).
#[derive(IntoElement)]
pub struct MonoTag {
    text: SharedString,
    id: SharedString,
}

impl std::fmt::Debug for MonoTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MonoTag")
            .field("text", &self.text)
            .finish_non_exhaustive()
    }
}

impl MonoTag {
    /// Creates a tag with a text and an element id.
    pub fn new(id: impl Into<SharedString>, text: impl Into<SharedString>) -> Self {
        Self {
            text: text.into(),
            id: id.into(),
        }
    }
}

impl RenderOnce for MonoTag {
    fn render(self, _window: &mut Window, cx: &mut App) -> impl IntoElement {
        let tokens: &Tokens = Tokens::for_dark(cx.theme().is_dark());
        div()
            .id(self.id)
            .test_support()
            .aria_label(self.text.clone())
            .px(tokens::SPACE_2)
            .py(tokens::SPACE_1)
            .rounded(px(6.0))
            .bg(to_hsla(tokens.surface_raised))
            .font_family(cx.theme().mono_font_family.clone())
            .text_size(px(11.0))
            .text_color(to_hsla(tokens.muted_foreground))
            .whitespace_nowrap()
            .child(self.text)
    }
}
