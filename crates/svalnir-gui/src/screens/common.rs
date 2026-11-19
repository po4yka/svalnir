//! Parts that the read-only record screens share: the screen frame, a card,
//! the data states of `DESIGN.md` section 8, and a fact list.

use crate::{
    data::model::{Loadable, Measured},
    theme::tokens::{self, Tokens, to_hsla},
    ui::{
        data_state::{UNAVAILABLE_TEXT, format_age, format_bytes},
        entry::card_entry,
        surface::{Panel, Shell, ShellHeader},
        value::DisplayValue,
    },
};
use gpui_kit::{
    AnyElement, FontWeight, IntoElement, ParentElement, Role, SharedString, Styled,
    TestSupportExt as _,
    component::{
        skeleton::Skeleton,
        table::{TableCell, TableHead},
        v_flex,
    },
    div,
    prelude::*,
    px,
};
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

/// The least width of a card (`DESIGN.md` section 9).
pub const MIN_CARD_WIDTH: f32 = 320.0;

/// The least width of a table column. The component gives a column 100 px
/// for each unit of its span, which is wider than a card of 320 px; the span
/// stays the relative width.
const CELL_MIN_WIDTH: gpui_kit::Pixels = px(48.0);

/// How a card reads a loadable value.
#[derive(Debug, Clone)]
pub enum Shown<T> {
    /// The first load is not done: a skeleton.
    Loading,
    /// The load failed: an em dash and the reason.
    Failed(String),
    /// A value. `stale_age` is the age text of a stale value, which the
    /// card shows in a caption with the value in the muted color.
    Data {
        /// The value.
        value: Arc<T>,
        /// The age text of a stale value.
        stale_age: Option<String>,
    },
}

/// The presentation state of `loadable` at `now`. `captured_at` gives the
/// time of the reading for the age of a stale value.
pub fn shown<T>(
    loadable: &Loadable<T>,
    now: SystemTime,
    captured_at: impl Fn(&T) -> SystemTime,
) -> Shown<T> {
    match loadable {
        Loadable::Loading => Shown::Loading,
        Loadable::Unavailable(reason) => Shown::Failed(reason.clone()),
        Loadable::Ready(value) => Shown::Data {
            value: Arc::clone(value),
            stale_age: None,
        },
        Loadable::Stale(value) => Shown::Data {
            value: Arc::clone(value),
            stale_age: Some(format_age(
                now.duration_since(captured_at(value)).unwrap_or_default(),
            )),
        },
    }
}

/// "185.5 GB" for a value and an em dash for an unavailable value.
#[must_use]
pub fn bytes_text(measured: &Measured<u64>) -> String {
    match measured {
        Measured::Value(bytes) => {
            let (value, unit) = format_bytes(*bytes);
            format!("{value} {unit}")
        }
        Measured::Unavailable(_) => UNAVAILABLE_TEXT.to_owned(),
    }
}

/// The age of `time` at `now`, with hours and days for an old time: "just
/// now", "12 s ago", "5 min ago", "3 h ago", "2 d ago". A time after `now`
/// is "just now".
#[must_use]
pub fn ago(time: SystemTime, now: SystemTime) -> String {
    let age: Duration = now.duration_since(time).unwrap_or_default();
    let seconds: u64 = age.as_secs();
    if seconds < 3_600 {
        format_age(age)
    } else if seconds < 86_400 {
        format!("{} h ago", seconds / 3_600)
    } else {
        format!("{} d ago", seconds / 86_400)
    }
}

/// The time from `now` to `time`: "in 20 min", "in 3 h", "in 2 d". `None`
/// when `time` is not after `now`.
#[must_use]
pub fn until(time: SystemTime, now: SystemTime) -> Option<String> {
    let seconds: u64 = time.duration_since(now).ok()?.as_secs();
    if seconds == 0 {
        return None;
    }
    Some(if seconds < 60 {
        format!("in {seconds} s")
    } else if seconds < 3_600 {
        format!("in {} min", seconds / 60)
    } else if seconds < 86_400 {
        format!("in {} h", seconds / 3_600)
    } else {
        format!("in {} d", seconds / 86_400)
    })
}

/// The screen title: one heading for each screen.
pub fn screen_title(title: &'static str) -> AnyElement {
    div()
        .id("screen-title")
        .role(Role::Heading)
        .test_support()
        .aria_label(title)
        .text_size(px(24.0))
        .font_weight(FontWeight::SEMIBOLD)
        .child(title)
        .into_any_element()
}

/// The frame of a screen: the title and the cards in a wrapping row. Each
/// card enters with the motion of `ui::entry`.
pub fn screen(
    title: &'static str,
    cards: Vec<(CardWidth, AnyElement)>,
    activation: u64,
    reduce_motion: bool,
) -> AnyElement {
    let cards = cards.into_iter().enumerate().map(|(index, (width, card))| {
        let card: AnyElement = card_entry(card, index, activation, reduce_motion);
        let slot = div().flex().flex_col().min_w(px(MIN_CARD_WIDTH));
        match width {
            CardWidth::Full => slot.w_full(),
            CardWidth::Share => slot.flex_1(),
        }
        .child(card)
    });
    div()
        .flex()
        .flex_col()
        .gap(tokens::GRID_GAP)
        .child(screen_title(title))
        .child(
            div()
                .flex()
                .flex_wrap()
                .gap(tokens::GRID_GAP)
                .children(cards),
        )
        .into_any_element()
}

/// The width of a card in the row of a screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CardWidth {
    /// The card has the width of the content.
    Full,
    /// The card shares a row with its neighbours and does not go below
    /// [`MIN_CARD_WIDTH`].
    Share,
}

/// A card: a shell with a header and one panel.
pub fn card(header: ShellHeader, body: impl IntoElement) -> AnyElement {
    Shell::new()
        .grow()
        .child(header)
        .child(
            Panel::new()
                .grow()
                .child(v_flex().flex_1().gap(tokens::SPACE_3).child(body)),
        )
        .into_any_element()
}

/// A caption line with an element id and the same text as its label.
pub fn caption(
    id: impl Into<SharedString>,
    text: impl Into<SharedString>,
    tokens: &Tokens,
) -> AnyElement {
    let text: SharedString = text.into();
    div()
        .id(id.into())
        .test_support()
        .aria_label(text.clone())
        .text_size(px(12.0))
        .text_color(to_hsla(tokens.muted_foreground))
        .child(text)
        .into_any_element()
}

/// A line of body text with an element id and the same text as its label.
pub fn body_line(
    id: impl Into<SharedString>,
    text: impl Into<SharedString>,
    muted: bool,
    tokens: &Tokens,
) -> AnyElement {
    let text: SharedString = text.into();
    div()
        .id(id.into())
        .test_support()
        .aria_label(text.clone())
        .text_size(px(14.0))
        .text_color(to_hsla(if muted {
            tokens.muted_foreground
        } else {
            tokens.foreground
        }))
        .child(text)
        .into_any_element()
}

/// The skeleton of a card that loads for the first time: rows in the shape
/// of a list.
pub fn skeleton_rows(rows: usize) -> AnyElement {
    v_flex()
        .id("card-skeleton")
        .test_support()
        .aria_label("Loading")
        .gap(tokens::SPACE_2)
        .children((0..rows).map(|_| Skeleton::new().w_full().h(px(20.0))))
        .into_any_element()
}

/// The body of a card whose read failed: an em dash, the reason, and the
/// statement that nothing is a zero.
pub fn failed_body(id: &'static str, reason: &str, tokens: &Tokens) -> AnyElement {
    v_flex()
        .gap(tokens::SPACE_2)
        .child(DisplayValue::unavailable(reason.to_owned()).id(id))
        .child(caption(
            format!("{id}-note"),
            "Nothing is shown as zero.",
            tokens,
        ))
        .into_any_element()
}

/// The age caption of a stale value: "Stale: read 12 min ago".
pub fn stale_line(id: &'static str, age: &str, tokens: &Tokens) -> AnyElement {
    caption(id, format!("Stale: read {age}"), tokens)
}

/// A compact inset block.
pub fn inset(content: impl IntoElement, tokens: &Tokens) -> AnyElement {
    div()
        .rounded(tokens::INSET_RADIUS)
        .bg(to_hsla(tokens.inset_tint))
        .px(tokens::INSET_PADDING_X)
        .py(tokens::INSET_PADDING_Y)
        .child(content)
        .into_any_element()
}

/// One fact: a muted label at the left and a mono value at the right. The
/// row has the label "{label}: {value}".
pub fn fact(
    id: impl Into<SharedString>,
    label: &str,
    value: impl Into<SharedString>,
    mono: &SharedString,
    muted_value: bool,
    tokens: &Tokens,
) -> AnyElement {
    let value: SharedString = value.into();
    div()
        .id(id.into())
        .test_support()
        .aria_label(format!("{label}: {value}"))
        .flex()
        .items_start()
        .justify_between()
        .gap(tokens::SPACE_4)
        .text_size(px(13.0))
        .child(
            div()
                .flex_shrink_0()
                .text_color(to_hsla(tokens.muted_foreground))
                .child(label.to_owned()),
        )
        .child(
            div()
                .min_w_0()
                .font_family(mono.clone())
                .text_color(to_hsla(if muted_value {
                    tokens.muted_foreground
                } else {
                    tokens.foreground
                }))
                .child(value),
        )
        .into_any_element()
}

/// The problem lines of a snapshot, in the `warning` tone with the word
/// "Problem" so that the tone is not the only signal.
pub fn problem_lines(
    prefix: &'static str,
    problems: &[String],
    tokens: &Tokens,
) -> Vec<AnyElement> {
    problems
        .iter()
        .enumerate()
        .map(|(index, problem)| {
            let text: String = format!("Problem: {problem}");
            div()
                .id(SharedString::from(format!("{prefix}-problem-{index}")))
                .test_support()
                .aria_label(text.clone())
                .text_size(px(12.0))
                .text_color(to_hsla(tokens.warning))
                .child(text)
                .into_any_element()
        })
        .collect()
}

/// A header cell of a table. `span` is the relative width of the column.
pub fn head(text: &'static str, span: usize, right: bool, tokens: &Tokens) -> TableHead {
    let cell: TableHead = TableHead::new()
        .col_span(span)
        .min_w(CELL_MIN_WIDTH)
        .text_color(to_hsla(tokens.muted_foreground))
        .child(text);
    if right { cell.text_right() } else { cell }
}

/// A data cell of a table. `span` is the relative width of the column.
pub fn cell(content: impl IntoElement, span: usize, right: bool) -> TableCell {
    let cell: TableCell = TableCell::new()
        .col_span(span)
        .min_w(CELL_MIN_WIDTH)
        .child(content);
    if right { cell.text_right() } else { cell }
}

/// A mono text for a data cell, in the muted color when `muted` is true.
pub fn mono_text(
    text: impl Into<SharedString>,
    mono: &SharedString,
    muted: bool,
    tokens: &Tokens,
) -> AnyElement {
    div()
        .min_w_0()
        .font_family(mono.clone())
        .text_size(px(12.0))
        .text_color(to_hsla(if muted {
            tokens.muted_foreground
        } else {
            tokens.foreground
        }))
        .child(text.into())
        .into_any_element()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_loadable_state_has_its_presentation() {
        let now: SystemTime = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
        let at = |_: &u8| now - Duration::from_mins(12);
        assert!(matches!(shown(&Loadable::Loading, now, at), Shown::Loading));
        assert!(matches!(
            shown(&Loadable::<u8>::Unavailable("denied".into()), now, at),
            Shown::Failed(reason) if reason == "denied"
        ));
        assert!(matches!(
            shown(&Loadable::Ready(Arc::new(7_u8)), now, at),
            Shown::Data {
                stale_age: None,
                ..
            }
        ));
        assert!(matches!(
            shown(&Loadable::Stale(Arc::new(7_u8)), now, at),
            Shown::Data { stale_age: Some(age), .. } if age == "12 min ago"
        ));
    }

    #[test]
    fn an_unavailable_size_is_a_dash_and_a_zero_is_a_zero() {
        assert_eq!(bytes_text(&Measured::Unavailable("x".into())), "\u{2014}");
        assert_eq!(bytes_text(&Measured::Value(0)), "0 B");
        assert_eq!(bytes_text(&Measured::Value(1_500_000_000)), "1.5 GB");
    }

    #[test]
    fn an_old_time_has_hours_and_days() {
        let now: SystemTime = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let back = |seconds: u64| now - Duration::from_secs(seconds);
        assert_eq!(ago(back(1), now), "just now");
        assert_eq!(ago(back(300), now), "5 min ago");
        assert_eq!(ago(back(7_500), now), "2 h ago");
        assert_eq!(ago(back(180_000), now), "2 d ago");
        assert_eq!(ago(now + Duration::from_secs(60), now), "just now");
    }

    #[test]
    fn a_future_time_has_a_remaining_text_and_a_past_time_has_none() {
        let now: SystemTime = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        assert_eq!(
            until(now + Duration::from_mins(20), now).as_deref(),
            Some("in 20 min")
        );
        assert_eq!(
            until(now + Duration::from_secs(30), now).as_deref(),
            Some("in 30 s")
        );
        assert_eq!(
            until(now + Duration::from_hours(5), now).as_deref(),
            Some("in 5 h")
        );
        assert_eq!(until(now, now), None);
        assert_eq!(until(now - Duration::from_secs(5), now), None);
    }
}
