//! The state line of a control after its last action (`DESIGN.md` §7): a
//! status pill with the tone and the icon of the state, and one sentence.

use crate::{
    actions::ActionState,
    theme::tokens::{self, Tokens, to_hsla},
    ui::pill::StatusPill,
};
use gpui_kit::{
    AnyElement, InteractiveElement as _, IntoElement, ParentElement as _, SharedString,
    StatefulInteractiveElement as _, Styled as _, TestSupportExt as _,
    component::{h_flex, tooltip::Tooltip, v_flex},
    div, px,
};
use std::time::SystemTime;

/// The largest number of lines of the sentence in a short state line.
pub const SHORT_LINES: usize = 2;

/// How much of the sentence a state line shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fit {
    /// The full sentence, wrapped in the width of the line.
    Full,
    /// At most [`SHORT_LINES`] lines. A longer sentence ends with an
    /// ellipsis.
    Short,
}

/// The state line of `state` at `now`. The row has the label
/// "{pill}: {sentence}", so that a screen reader and a test read the same
/// text.
pub fn action_status(
    id: impl Into<SharedString>,
    state: &ActionState,
    now: SystemTime,
    tokens: &Tokens,
) -> AnyElement {
    state_line(&id.into(), state, now, Fit::Full, tokens)
}

/// The state line of `state` at `now` for a dense row: the sentence shows
/// at most [`SHORT_LINES`] lines, and a longer sentence ends with an
/// ellipsis. The full text is the accessible label and the tooltip of the
/// line. The screen that uses this line must also show the full line
/// ([`action_status`]) in a place that the keyboard reaches.
pub fn action_status_short(
    id: impl Into<SharedString>,
    state: &ActionState,
    now: SystemTime,
    tokens: &Tokens,
) -> AnyElement {
    state_line(&id.into(), state, now, Fit::Short, tokens)
}

fn state_line(
    id: &SharedString,
    state: &ActionState,
    now: SystemTime,
    fit: Fit,
    tokens: &Tokens,
) -> AnyElement {
    let (text, tone, icon) = state.pill();
    let sentence: String = state.sentence(now);
    let label: SharedString = SharedString::from(format!("{text}: {sentence}"));
    let mut sentence_line = div()
        .id(SharedString::from(format!("{id}-sentence")))
        .test_support()
        .text_size(px(12.0))
        .text_color(to_hsla(tokens.muted_foreground));
    if fit == Fit::Short {
        sentence_line = sentence_line.line_clamp(SHORT_LINES).text_ellipsis();
    }
    let line = v_flex()
        .id(id.clone())
        .test_support()
        .aria_label(label.clone())
        .min_w_0()
        .max_w_full()
        .gap(tokens::SPACE_1)
        .child(
            h_flex().child(
                StatusPill::new(text, tone)
                    .icon(icon)
                    .id(SharedString::from(format!("{id}-pill"))),
            ),
        )
        .child(sentence_line.child(sentence));
    match fit {
        Fit::Full => line.into_any_element(),
        Fit::Short => line
            .tooltip(move |window, cx| Tooltip::new(label.clone()).build(window, cx))
            .into_any_element(),
    }
}
