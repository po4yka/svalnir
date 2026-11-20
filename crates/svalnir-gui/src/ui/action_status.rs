//! The state line of a control after its last action (`DESIGN.md` §7): a
//! status pill with the tone and the icon of the state, and one sentence.

use crate::{
    actions::ActionState,
    theme::tokens::{self, Tokens, to_hsla},
    ui::pill::StatusPill,
};
use gpui_kit::{
    AnyElement, AnyView, App, AppContext as _, Empty, InteractiveElement as _, IntoElement,
    ParentElement as _, SharedString, StatefulInteractiveElement as _, Styled as _, StyledText,
    TestSupportExt as _, TextLayout, Window,
    component::{h_flex, tooltip::Tooltip, v_flex},
    div, px,
};
use std::{cell::Cell, rc::Rc, time::SystemTime};

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
/// ellipsis. The full text is the accessible label of the line in each
/// case, and the tooltip of the line only when the sentence is cut. The
/// screen that uses this line must also show the full line
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
    let sentence: SharedString = SharedString::from(state.sentence(now));
    let label: SharedString = SharedString::from(format!("{text}: {sentence}"));
    let sentence_text = StyledText::new(sentence.clone());
    // The text element cuts the sentence when it lays it out, and adds the
    // ellipsis. That cut also decides the tooltip, so the two cannot
    // disagree: after the text of a frame is prepainted, the listener
    // compares its laid-out text with the sentence.
    let cut: Rc<Cell<bool>> = Rc::new(Cell::new(false));
    let mut sentence_line = div();
    if fit == Fit::Short {
        let layout: TextLayout = sentence_text.layout().clone();
        let cut = Rc::clone(&cut);
        let full = sentence.clone();
        sentence_line = sentence_line
            .on_children_prepainted(move |_, _, _| cut.set(layout.text() != full.as_ref()))
            .line_clamp(SHORT_LINES)
            .text_ellipsis();
    }
    let sentence_line = sentence_line
        .id(SharedString::from(format!("{id}-sentence")))
        .test_support()
        .text_size(px(12.0))
        .text_color(to_hsla(tokens.muted_foreground))
        .child(sentence_text);
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
        .child(sentence_line);
    match fit {
        Fit::Full => line.into_any_element(),
        Fit::Short => {
            let tooltip_id = SharedString::from(format!("{id}-tooltip"));
            line.tooltip(move |window, cx| cut_tooltip(cut.get(), &tooltip_id, &label, window, cx))
                .into_any_element()
        }
    }
}

/// The tooltip of a short line. A sentence that the line shows in full has
/// no tooltip: the pinned GPUI shows a tooltip view for each hover of an
/// element with a tooltip builder, so the builder gives an empty view, which
/// paints nothing.
fn cut_tooltip(
    cut: bool,
    id: &SharedString,
    label: &SharedString,
    window: &mut Window,
    cx: &mut App,
) -> AnyView {
    if !cut {
        return cx.new(|_| Empty).into();
    }
    let id = id.clone();
    let label = label.clone();
    Tooltip::element(move |_, _| {
        div()
            .id(id.clone())
            .test_support()
            .aria_label(label.clone())
            .child(label.clone())
    })
    .build(window, cx)
}
