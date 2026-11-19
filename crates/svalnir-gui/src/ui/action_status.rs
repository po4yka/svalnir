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
    component::{h_flex, v_flex},
    div, px,
};
use std::time::SystemTime;

/// The state line of `state` at `now`. The row has the label
/// "{pill}: {sentence}", so that a screen reader and a test read the same
/// text.
pub fn action_status(
    id: impl Into<SharedString>,
    state: &ActionState,
    now: SystemTime,
    tokens: &Tokens,
) -> AnyElement {
    let id: SharedString = id.into();
    let (text, tone, icon) = state.pill();
    let sentence: String = state.sentence(now);
    let label: SharedString = SharedString::from(format!("{text}: {sentence}"));
    v_flex()
        .id(id.clone())
        .test_support()
        .aria_label(label)
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
        .child(
            div()
                .text_size(px(12.0))
                .text_color(to_hsla(tokens.muted_foreground))
                .child(sentence),
        )
        .into_any_element()
}
