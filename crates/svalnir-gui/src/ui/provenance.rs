//! The provenance line of a card: source, age, and scope.

use crate::{
    theme::tokens::{Tokens, to_hsla},
    ui::data_state::format_age,
};
use gpui_kit::{
    App, FontWeight, InteractiveElement as _, IntoElement, ParentElement as _, RenderOnce,
    SharedString, Styled as _, Window, component::ActiveTheme as _, div, px,
};
use std::time::SystemTime;

/// The text of a provenance line, in upper case.
#[must_use]
pub fn provenance_text(source: &str, captured_at: SystemTime, scope: &str) -> String {
    let age: String = format_age(
        SystemTime::now()
            .duration_since(captured_at)
            .unwrap_or_default(),
    );
    format!("{source} \u{b7} {age} \u{b7} {scope}").to_uppercase()
}

/// One line in the Overline style.
#[derive(Debug, IntoElement)]
pub struct ProvenanceLine {
    text: String,
    id: SharedString,
}

impl ProvenanceLine {
    /// Creates a line for a reading of `source` taken at `captured_at`.
    pub fn new(source: &str, captured_at: SystemTime, scope: &str) -> Self {
        Self {
            text: provenance_text(source, captured_at, scope),
            id: SharedString::from("provenance"),
        }
    }

    /// Sets the element id.
    #[must_use]
    pub fn id(mut self, id: impl Into<SharedString>) -> Self {
        self.id = id.into();
        self
    }
}

impl RenderOnce for ProvenanceLine {
    fn render(self, _window: &mut Window, cx: &mut App) -> impl IntoElement {
        let tokens: &Tokens = Tokens::for_dark(cx.theme().is_dark());
        div()
            .id(self.id)
            .font_family(cx.theme().mono_font_family.clone())
            .text_size(px(11.0))
            .font_weight(FontWeight::MEDIUM)
            .text_color(to_hsla(tokens.muted_foreground))
            .child(self.text)
    }
}
