//! The large value of a card with its unit and context.

use crate::{
    theme::tokens::{self, Tokens, to_hsla},
    ui::{data_state::UNAVAILABLE_TEXT, rolling::RollingNumber},
};
use gpui_kit::{
    App, Entity, FontWeight, InteractiveElement as _, IntoElement, ParentElement as _, RenderOnce,
    SharedString, Styled as _, TestSupportExt as _, Window,
    component::{ActiveTheme as _, h_flex, v_flex},
    div,
    prelude::*,
    px,
};

/// The text size of the value.
const VALUE_SIZE: f32 = 30.0;
/// The line height of the value. The rolling number uses the same height:
/// 1.25 of the size, rounded.
const VALUE_LINE: f32 = 38.0;
/// The text size of the unit and the context.
const UNIT_SIZE: f32 = 12.0;
/// The line height of the unit and the context.
const UNIT_LINE: f32 = 16.0;

/// The distance from the baseline of a text line to the bottom of its box,
/// for the UI font at `weight` and `size` in a line of `line` px.
fn below_baseline(window: &Window, weight: FontWeight, size: f32, line: f32) -> f32 {
    let mut font = window.text_style().font();
    font.weight = weight;
    let system = window.text_system();
    let id = system.resolve_font(&font);
    let ascent: f32 = f32::from(system.ascent(id, px(size))).abs();
    let descent: f32 = f32::from(system.descent(id, px(size))).abs();
    (line - (ascent + descent)) / 2.0 + descent
}

/// A value at 30 px with a muted unit and context, baseline-aligned.
#[derive(IntoElement)]
pub struct DisplayValue {
    value: SharedString,
    unit: SharedString,
    context: Option<SharedString>,
    muted: bool,
    reason: Option<SharedString>,
    id: SharedString,
    rolling: Option<Entity<RollingNumber>>,
}

impl std::fmt::Debug for DisplayValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DisplayValue")
            .field("value", &self.value)
            .finish_non_exhaustive()
    }
}

impl DisplayValue {
    /// Creates a value with a unit.
    pub fn new(value: impl Into<SharedString>, unit: impl Into<SharedString>) -> Self {
        Self {
            value: value.into(),
            unit: unit.into(),
            context: None,
            muted: false,
            reason: None,
            id: SharedString::from("display-value"),
            rolling: None,
        }
    }

    /// Creates the unavailable form: a dash with the reason as the caption.
    pub fn unavailable(reason: impl Into<SharedString>) -> Self {
        let mut value: Self = Self::new(UNAVAILABLE_TEXT, "");
        value.reason = Some(reason.into());
        value
    }

    /// Adds context after the unit, such as "of 512 GB".
    #[must_use]
    pub fn context(mut self, context: impl Into<SharedString>) -> Self {
        self.context = Some(context.into());
        self
    }

    /// Draws the value in the muted color, for stale data.
    #[must_use]
    pub fn muted(mut self, muted: bool) -> Self {
        self.muted = muted;
        self
    }

    /// Draws the value through `rolling`, whose digits roll on a change.
    #[must_use]
    pub fn rolling(mut self, rolling: Entity<RollingNumber>) -> Self {
        self.rolling = Some(rolling);
        self
    }

    /// Sets the element id of the value; the reason uses `{id}-reason`.
    #[must_use]
    pub fn id(mut self, id: impl Into<SharedString>) -> Self {
        self.id = id.into();
        self
    }
}

impl RenderOnce for DisplayValue {
    fn render(self, window: &mut Window, cx: &mut App) -> impl IntoElement {
        let tokens: &Tokens = Tokens::for_dark(cx.theme().is_dark());
        // The row puts the bottoms of the two text boxes on one line, so the
        // unit gets a bottom padding that puts its baseline on the baseline
        // of the number.
        let lift: f32 = (below_baseline(window, FontWeight::MEDIUM, VALUE_SIZE, VALUE_LINE)
            - below_baseline(window, FontWeight::NORMAL, UNIT_SIZE, UNIT_LINE))
        .max(0.0);
        let muted = to_hsla(tokens.muted_foreground);
        let value_color = if self.muted || self.reason.is_some() {
            muted
        } else {
            to_hsla(tokens.foreground)
        };
        let suffix: String = match &self.context {
            Some(context) if self.unit.is_empty() => context.to_string(),
            Some(context) => format!("{} {context}", self.unit),
            None => self.unit.to_string(),
        };
        let shown: gpui_kit::AnyElement = match (&self.rolling, self.reason.is_none()) {
            (Some(rolling), true) => {
                let text: SharedString = self.value.clone();
                rolling.update(cx, |number, cx| {
                    number.set_style(VALUE_SIZE, FontWeight::MEDIUM, value_color);
                    number.set_text(text, cx);
                });
                rolling.clone().into_any_element()
            }
            _ => self.value.clone().into_any_element(),
        };
        v_flex()
            .gap(tokens::SPACE_1)
            .child(
                h_flex()
                    .items_end()
                    .gap(tokens::SPACE_1)
                    .child(
                        div()
                            .id(self.id.clone())
                            .test_support()
                            .aria_label(self.value.clone())
                            .text_size(px(VALUE_SIZE))
                            .line_height(px(VALUE_LINE))
                            .font_weight(FontWeight::MEDIUM)
                            .text_color(value_color)
                            .child(shown),
                    )
                    .child(
                        div()
                            // Not a layout step: the offset of two baselines.
                            .pb(px(lift))
                            .text_size(px(UNIT_SIZE))
                            .line_height(px(UNIT_LINE))
                            .text_color(muted)
                            .child(suffix),
                    ),
            )
            .children(self.reason.map(|reason| {
                div()
                    .id(SharedString::from(format!("{}-reason", self.id)))
                    .test_support()
                    .aria_label(reason.clone())
                    .text_size(px(12.0))
                    .text_color(muted)
                    .child(reason)
            }))
    }
}
