//! The state line of a control after its last action (`DESIGN.md` §7): a
//! status pill with the tone and the icon of the state, and one sentence.
//! Also the short caption of a dense table cell ([`short_caption`]), which
//! cuts its text in the same way as the short state line.

use crate::{
    actions::ActionState,
    theme::tokens::{self, Tokens, to_hsla},
    ui::pill::StatusPill,
};
use gpui_kit::{
    AnyElement, AnyView, App, AppContext as _, Div, Empty, InteractiveElement as _, IntoElement,
    ParentElement as _, SharedString, StatefulInteractiveElement as _, Styled as _, StyledText,
    TestSupportExt as _, TextLayout, Window,
    component::{h_flex, tooltip::Tooltip, v_flex},
    div, px,
};
use std::{cell::Cell, rc::Rc, time::Instant};

/// The largest number of lines of the sentence in a short state line.
pub const SHORT_LINES: usize = 2;

/// The largest width of the tooltip of a cut line, in pixels. A longer
/// text wraps onto more lines, so that the tooltip stays inside a window of
/// the minimum width and its end can be read.
pub const TOOLTIP_MAX_WIDTH: f32 = 320.0;

/// How much of the sentence a state line shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fit {
    /// The full sentence, wrapped in the width of the line.
    Full,
    /// At most [`SHORT_LINES`] lines. A longer sentence ends with an
    /// ellipsis.
    Short,
}

/// The state line of `state` now. The row has the label
/// "{pill}: {sentence}", so that a screen reader and a test read the same
/// text.
pub fn action_status(
    id: impl Into<SharedString>,
    state: &ActionState,
    tokens: &Tokens,
) -> AnyElement {
    state_line(&id.into(), state, Fit::Full, tokens)
}

/// The state line of `state` now for a dense row: the sentence shows
/// at most [`SHORT_LINES`] lines, and a longer sentence ends with an
/// ellipsis. The full text is the accessible label of the line in each
/// case, and the tooltip of the line only when the sentence is cut. The
/// screen that uses this line must also show the full line
/// ([`action_status`]) in a place that the keyboard reaches.
pub fn action_status_short(
    id: impl Into<SharedString>,
    state: &ActionState,
    tokens: &Tokens,
) -> AnyElement {
    state_line(&id.into(), state, Fit::Short, tokens)
}

fn state_line(id: &SharedString, state: &ActionState, fit: Fit, tokens: &Tokens) -> AnyElement {
    let (text, tone, icon) = state.pill();
    let sentence: SharedString = SharedString::from(state.sentence(Instant::now()));
    let label: SharedString = SharedString::from(format!("{text}: {sentence}"));
    let (sentence_line, cut) = muted_text(&sentence, fit, tokens);
    let sentence_line = sentence_line
        .id(SharedString::from(format!("{id}-sentence")))
        .test_support();
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

/// A caption of a dense table cell, such as the protection reason of
/// Applications: at most [`SHORT_LINES`] lines, and a longer text ends with
/// an ellipsis. The full text is the accessible label of the caption in
/// each case, and its tooltip (id `{id}-tooltip`) only when the text is
/// cut. The cell must let the caption shrink (`min_w_0`), so that the text
/// wraps and is cut inside the cell.
pub fn short_caption(
    id: impl Into<SharedString>,
    text: impl Into<SharedString>,
    tokens: &Tokens,
) -> AnyElement {
    let id: SharedString = id.into();
    let text: SharedString = text.into();
    let (caption, cut) = muted_text(&text, Fit::Short, tokens);
    let tooltip_id = SharedString::from(format!("{id}-tooltip"));
    caption
        .id(id)
        .test_support()
        .aria_label(text.clone())
        .min_w_0()
        .max_w_full()
        .tooltip(move |window, cx| cut_tooltip(cut.get(), &tooltip_id, &text, window, cx))
        .into_any_element()
}

/// The muted 12 px text of `text`, and the flag that tells, after the text
/// of a frame is prepainted, whether the text element cut it. With
/// [`Fit::Full`] the flag stays `false`.
fn muted_text(text: &SharedString, fit: Fit, tokens: &Tokens) -> (Div, Rc<Cell<bool>>) {
    let styled = StyledText::new(text.clone());
    // The text element cuts the text when it lays it out, and adds the
    // ellipsis. That cut also decides the tooltip, so the two cannot
    // disagree: after the text of a frame is prepainted, the listener
    // compares its laid-out text with the full text.
    let cut: Rc<Cell<bool>> = Rc::new(Cell::new(false));
    let mut element = div();
    if fit == Fit::Short {
        let layout: TextLayout = styled.layout().clone();
        let flag = Rc::clone(&cut);
        let full = text.clone();
        element = element
            .on_children_prepainted(move |_, _, _| flag.set(layout.text() != full.as_ref()))
            .line_clamp(SHORT_LINES)
            .text_ellipsis();
    }
    let element = element
        .text_size(px(12.0))
        .text_color(to_hsla(tokens.muted_foreground))
        .child(styled);
    (element, cut)
}

/// The tooltip of a short line or of a short caption. A sentence that the line shows in full has
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
            .max_w(px(TOOLTIP_MAX_WIDTH))
            .whitespace_normal()
            .child(label.clone())
    })
    .build(window, cx)
}
