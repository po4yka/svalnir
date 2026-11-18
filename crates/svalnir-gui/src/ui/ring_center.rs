//! The text in the middle of a ring chart: a number with a small unit, or a
//! state word, and a caption below (`DESIGN.md` section 5).

use crate::theme::tokens::{self, Tokens, to_hsla};
use crate::ui::data_state::UNAVAILABLE_TEXT;
use gpui_kit::{
    App, FontWeight, Hsla, InteractiveElement as _, IntoElement, ParentElement as _, RenderOnce,
    SharedString, Styled as _, TestSupportExt as _, Window,
    component::{ActiveTheme as _, h_flex, v_flex},
    div,
    prelude::*,
    px, relative,
};

/// The size of the number.
const NUMBER_SIZE: f32 = 28.0;
/// The size of the number when it does not fit the inner ring.
const NUMBER_SIZE_SMALL: f32 = 22.0;
/// The size of a state word.
const STATE_SIZE: f32 = 22.0;
/// The size of the unit.
const UNIT_SIZE: f32 = 13.0;
/// The size of the caption.
const CAPTION_SIZE: f32 = 12.0;
/// The free space between the text and the inner ring on both sides.
const INNER_MARGIN: f32 = 16.0;

/// The center of a ring chart.
#[derive(IntoElement, Debug)]
pub struct RingCenter {
    id: SharedString,
    caption_id: Option<SharedString>,
    text: SharedString,
    caption: SharedString,
    state_tone: Option<Hsla>,
    muted: bool,
    inner_diameter: f32,
}

impl RingCenter {
    /// Creates a center. `text` is a number with its unit ("326.5 GB"), a
    /// state word, or the em dash; `inner_diameter` is the free diameter of
    /// the inner ring in pixels.
    #[must_use]
    pub fn new(
        id: impl Into<SharedString>,
        text: impl Into<SharedString>,
        caption: impl Into<SharedString>,
        inner_diameter: f32,
    ) -> Self {
        Self {
            id: id.into(),
            caption_id: None,
            text: text.into(),
            caption: caption.into(),
            state_tone: None,
            muted: false,
            inner_diameter,
        }
    }

    /// Sets the element id of the caption.
    #[must_use]
    pub fn caption_id(mut self, id: impl Into<SharedString>) -> Self {
        self.caption_id = Some(id.into());
        self
    }

    /// Draws `text` as a state word in `tone`, with no unit.
    #[must_use]
    pub const fn state(mut self, tone: Hsla) -> Self {
        self.state_tone = Some(tone);
        self
    }

    /// Draws the number in the muted color, for stale data.
    #[must_use]
    pub const fn muted(mut self, muted: bool) -> Self {
        self.muted = muted;
        self
    }
}

/// Splits "326.5 GB" into the number and the unit. A text with no space has no unit.
fn split_unit(text: &str) -> (&str, &str) {
    text.rsplit_once(' ').unwrap_or((text, ""))
}

/// A rough width of the number row at `size`, in pixels. The sans glyphs of
/// a digit are about 0.58 em wide.
#[expect(
    clippy::cast_precision_loss,
    reason = "a text length is far below 2^24"
)]
fn estimated_width(number: &str, unit: &str, size: f32) -> f32 {
    let unit_width: f32 = if unit.is_empty() {
        0.0
    } else {
        f32::from(tokens::SPACE_1) + unit.chars().count() as f32 * UNIT_SIZE * 0.62
    };
    number.chars().count() as f32 * size * 0.58 + unit_width
}

impl RenderOnce for RingCenter {
    fn render(self, _window: &mut Window, cx: &mut App) -> impl IntoElement {
        let tokens: &Tokens = Tokens::for_dark(cx.theme().is_dark());
        let sans: SharedString = cx.theme().font_family.clone();
        let muted: Hsla = to_hsla(tokens.muted_foreground);
        let unavailable: bool = self.text.as_ref() == UNAVAILABLE_TEXT;
        let (number, unit): (&str, &str) = if self.state_tone.is_some() || unavailable {
            (self.text.as_ref(), "")
        } else {
            split_unit(self.text.as_ref())
        };
        let (size, weight, color): (f32, FontWeight, Hsla) = if let Some(tone) = self.state_tone {
            (STATE_SIZE, FontWeight::SEMIBOLD, tone)
        } else {
            let ink: Hsla = if self.muted || unavailable {
                muted
            } else {
                to_hsla(tokens.foreground)
            };
            let fits: bool =
                estimated_width(number, unit, NUMBER_SIZE) <= self.inner_diameter - INNER_MARGIN;
            let size: f32 = if fits { NUMBER_SIZE } else { NUMBER_SIZE_SMALL };
            (size, FontWeight::SEMIBOLD, ink)
        };
        let unit_text: SharedString = SharedString::from(unit.to_owned());
        let number_text: SharedString = SharedString::from(number.to_owned());
        let caption_id: SharedString = self
            .caption_id
            .clone()
            .unwrap_or_else(|| SharedString::from(format!("{}-caption", self.id)));
        let caption = div()
            .id(caption_id)
            .test_support()
            .aria_label(self.caption.clone())
            .max_w(px(self.inner_diameter - INNER_MARGIN))
            .overflow_hidden()
            .text_size(px(CAPTION_SIZE))
            .text_color(muted)
            .whitespace_nowrap()
            .text_ellipsis();
        v_flex()
            .absolute()
            .top_0()
            .left_0()
            .size_full()
            .items_center()
            .justify_center()
            .gap(tokens::SPACE_1)
            .child(
                h_flex()
                    .id(self.id)
                    .test_support()
                    .aria_label(self.text.clone())
                    .items_baseline()
                    .justify_center()
                    .gap(tokens::SPACE_1)
                    .whitespace_nowrap()
                    .font_family(sans)
                    .child(
                        div()
                            .font_weight(weight)
                            .text_size(px(size))
                            .line_height(relative(1.0))
                            .text_color(color)
                            .child(number_text),
                    )
                    .children((!unit.is_empty()).then(|| {
                        div()
                            .font_weight(FontWeight::MEDIUM)
                            .text_size(px(UNIT_SIZE))
                            .text_color(muted)
                            .child(unit_text)
                    })),
            )
            .child(caption.child(self.caption))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_unit_is_the_last_word() {
        assert_eq!(split_unit("326.5 GB"), ("326.5", "GB"));
        assert_eq!(split_unit("Normal"), ("Normal", ""));
    }

    #[test]
    fn a_long_number_gets_the_small_size() {
        assert!(estimated_width("1234.5", "GB", NUMBER_SIZE) > 96.0 - INNER_MARGIN);
        assert!(estimated_width("85.5", "GB", NUMBER_SIZE) < 96.0 - INNER_MARGIN + 20.0);
    }
}
