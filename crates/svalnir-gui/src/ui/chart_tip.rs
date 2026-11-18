//! The detail card of a chart mark (`DESIGN.md` section 4, "Detail card").
//!
//! The card states the measured values of the mark under the pointer or under
//! the keyboard focus. It has no control and takes no pointer event. It is
//! painted above the other content of the window, next to the mark.

use crate::theme::{
    motion::{self, FAST},
    tokens::{self, Tokens, to_hsla},
};
use gpui_kit::{
    AnchoredPositionMode, Animation, AnimationExt as _, App, Bounds, FontWeight, Hsla,
    InteractiveElement as _, IntoElement, ParentElement as _, Pixels, Point, RenderOnce, Role,
    SharedString, Size, StatefulInteractiveElement as _, Styled as _, TestSupportExt as _, Window,
    anchored, component::ActiveTheme as _, deferred, div, point, px, size,
};

/// The distance between the mark and the card, in pixels.
pub const TIP_GAP: f32 = 8.0;
/// The distance that the card moves while it appears, in pixels.
pub const TIP_MOVE: f32 = 4.0;
/// The smallest width of the card, in pixels.
pub const TIP_MIN_WIDTH: f32 = 148.0;
/// The largest width of the card, in pixels.
pub const TIP_MAX_WIDTH: f32 = 260.0;
/// The most rows that a card shows.
pub const TIP_MAX_ROWS: usize = 6;
/// The height of one line of text, in pixels.
const LINE: f32 = 16.0;
/// The estimated width of one character, in pixels.
const CHAR_WIDTH: f32 = 6.6;
/// The corner radius of the card.
const TIP_RADIUS: f32 = 10.0;

/// One row of a card: a label and a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TipRow {
    /// The label, at the left.
    pub label: String,
    /// The value, at the right.
    pub value: String,
}

impl TipRow {
    /// Creates a row.
    pub fn new(label: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            value: value.into(),
        }
    }
}

/// The text of one card.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TipContent {
    /// The title.
    pub title: String,
    /// The text at the right of the title.
    pub aside: Option<String>,
    /// The rows; a card shows at most `TIP_MAX_ROWS`.
    pub rows: Vec<TipRow>,
    /// The one-line note under the rows.
    pub note: Option<String>,
}

impl TipContent {
    /// Creates a card with a title only.
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            ..Self::default()
        }
    }

    /// Sets the text at the right of the title.
    #[must_use]
    pub fn aside(mut self, aside: impl Into<String>) -> Self {
        self.aside = Some(aside.into());
        self
    }

    /// Adds a row.
    #[must_use]
    pub fn row(mut self, label: impl Into<String>, value: impl Into<String>) -> Self {
        self.rows.push(TipRow::new(label, value));
        self
    }

    /// Sets the note.
    #[must_use]
    pub fn note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }

    /// The rows that the card shows.
    #[must_use]
    pub fn shown_rows(&self) -> &[TipRow] {
        &self.rows[..self.rows.len().min(TIP_MAX_ROWS)]
    }

    /// The text of the card as one string, for the accessible label: the
    /// title, then each row, then the note.
    #[must_use]
    pub fn spoken(&self) -> String {
        let mut text: String = self.title.clone();
        if let Some(aside) = &self.aside {
            text.push_str(", ");
            text.push_str(aside);
        }
        for row in self.shown_rows() {
            text.push_str(". ");
            text.push_str(&row.label);
            text.push_str(": ");
            text.push_str(&row.value);
        }
        if let Some(note) = &self.note {
            text.push_str(". ");
            text.push_str(note);
        }
        text
    }

    /// The estimated size of the card in pixels. The width follows the longest
    /// line, between `TIP_MIN_WIDTH` and `TIP_MAX_WIDTH`.
    #[must_use]
    pub fn estimated_size(&self) -> (f32, f32) {
        let chars = |text: &str| -> f32 {
            f32::from(u8::try_from(text.chars().count().min(200)).unwrap_or(200))
        };
        let head: f32 = chars(&self.title) + self.aside.as_deref().map_or(0.0, |a| chars(a) + 2.0);
        let mut longest: f32 = head;
        for row in self.shown_rows() {
            longest = longest.max(chars(&row.label) + chars(&row.value) + 3.0);
        }
        if let Some(note) = &self.note {
            longest = longest.max(chars(note));
        }
        let pad: f32 = f32::from(u8::try_from(2 * 12).unwrap_or(24));
        let width: f32 = (longest * CHAR_WIDTH + pad).clamp(TIP_MIN_WIDTH, TIP_MAX_WIDTH);
        let lines: f32 = 1.0
            + f32::from(u8::try_from(self.shown_rows().len()).unwrap_or(6))
            + f32::from(u8::from(self.note.is_some()));
        (width, lines * LINE + 2.0 * 8.0)
    }
}

/// The side of the mark where the card sits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TipSide {
    /// At the right of the mark.
    Right,
    /// At the left of the mark.
    Left,
    /// Under the mark.
    Below,
    /// Above the mark.
    Above,
}

/// The place of a card of `card` size next to `mark`, in a window of `window`
/// size. The card keeps `TIP_GAP` from the mark. It sits at the right when it
/// fits there, else at the left, else under or above the mark. It never leaves
/// the window.
#[must_use]
pub fn place_tip(
    mark: Bounds<Pixels>,
    card: Size<Pixels>,
    window: Size<Pixels>,
) -> (Point<Pixels>, TipSide) {
    let gap: Pixels = px(TIP_GAP);
    let max_x: Pixels = (window.width - card.width).max(px(0.0));
    let max_y: Pixels = (window.height - card.height).max(px(0.0));
    let centered_y: Pixels = (mark.center().y - card.height / 2.0)
        .max(px(0.0))
        .min(max_y);
    let centered_x: Pixels = (mark.center().x - card.width / 2.0).max(px(0.0)).min(max_x);
    let right_x: Pixels = mark.right() + gap;
    if right_x + card.width <= window.width {
        return (point(right_x, centered_y), TipSide::Right);
    }
    let left_x: Pixels = mark.left() - gap - card.width;
    if left_x >= px(0.0) {
        return (point(left_x, centered_y), TipSide::Left);
    }
    let below_y: Pixels = mark.bottom() + gap;
    if below_y + card.height <= window.height {
        return (point(centered_x, below_y), TipSide::Below);
    }
    let above_y: Pixels = mark.top() - gap - card.height;
    if above_y >= px(0.0) {
        return (point(centered_x, above_y), TipSide::Above);
    }
    // No side has room: keep the card inside the window at the right.
    (
        point(right_x.max(px(0.0)).min(max_x), centered_y),
        TipSide::Right,
    )
}

/// The place of a card next to a mark that is given in chart coordinates, as an
/// offset from the top-left corner of the chart. `origin` is the position of
/// the chart in the window; the side of the card is chosen in window space, so
/// a mark near the window edge flips as it should. The result is chart
/// coordinates again: add the real origin of the chart to get the window
/// position.
#[must_use]
pub fn place_tip_local(
    mark: Bounds<Pixels>,
    origin: Point<Pixels>,
    card: Size<Pixels>,
    window: Size<Pixels>,
) -> (Point<Pixels>, TipSide) {
    let in_window: Bounds<Pixels> = Bounds::new(mark.origin + origin, mark.size);
    let (at, side) = place_tip(in_window, card, window);
    (at - origin, side)
}

/// The card as an element. Put it in the tree of the chart: it paints above
/// the other content of the window.
#[derive(IntoElement)]
pub struct ChartTip {
    id: SharedString,
    content: TipContent,
    mark: Bounds<Pixels>,
    origin: Point<Pixels>,
    animate: bool,
}

impl std::fmt::Debug for ChartTip {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChartTip")
            .field("title", &self.content.title)
            .finish_non_exhaustive()
    }
}

impl ChartTip {
    /// Creates the card of `content` for the `mark`, a rectangle in chart
    /// coordinates. The element that holds the card is the chart: the card is
    /// positioned from its top-left corner, so the position is right on the
    /// first frame. `origin` is the last known position of the chart in the
    /// window; it only decides the side of the card, and the window edge
    /// clamp uses the real bounds. A zero origin means that the chart has not
    /// painted yet: the card shows nothing and asks for one more frame. With `animate` false (Reduce Motion) the
    /// card appears at once.
    pub fn new(
        id: impl Into<SharedString>,
        content: TipContent,
        mark: Bounds<Pixels>,
        origin: Point<Pixels>,
        animate: bool,
    ) -> Self {
        Self {
            id: id.into(),
            content,
            mark,
            origin,
            animate,
        }
    }
}

impl RenderOnce for ChartTip {
    #[expect(clippy::too_many_lines, reason = "one build of the card")]
    fn render(self, window: &mut Window, cx: &mut App) -> impl IntoElement {
        // The chart sets its origin when it paints. A zero origin means that
        // the chart has not painted yet, for example at a launch focus, so the
        // side of the card would be chosen as if the chart were at the corner
        // of the window. Show the card from the next frame.
        if self.origin == Point::default() {
            window.request_animation_frame();
            return div().into_any_element();
        }
        let tokens: &Tokens = Tokens::for_dark(cx.theme().is_dark());
        let mono: SharedString = cx.theme().mono_font_family.clone();
        let foreground: Hsla = to_hsla(tokens.foreground);
        let muted: Hsla = to_hsla(tokens.muted_foreground);
        let (width, height): (f32, f32) = self.content.estimated_size();
        let (origin, side): (Point<Pixels>, TipSide) = place_tip_local(
            self.mark,
            self.origin,
            size(px(width), px(height)),
            window.viewport_size(),
        );
        let mut body = div()
            .flex()
            .flex_col()
            .w(px(width))
            .px(tokens::SPACE_3)
            .py(tokens::SPACE_2)
            .rounded(px(TIP_RADIUS))
            .bg(to_hsla(tokens.surface_raised))
            .child(
                div()
                    .flex()
                    .justify_between()
                    .gap(tokens::SPACE_2)
                    .h(px(LINE))
                    .child(
                        div()
                            .text_size(px(12.0))
                            .font_weight(FontWeight::MEDIUM)
                            .text_color(foreground)
                            .whitespace_nowrap()
                            .overflow_hidden()
                            .text_ellipsis()
                            .child(self.content.title.clone()),
                    )
                    .children(self.content.aside.clone().map(|aside| {
                        div()
                            .font_family(mono.clone())
                            .text_size(px(11.0))
                            .text_color(muted)
                            .whitespace_nowrap()
                            .child(aside)
                    })),
            );
        for row in self.content.shown_rows() {
            body = body.child(
                div()
                    .flex()
                    .justify_between()
                    .gap(tokens::SPACE_2)
                    .h(px(LINE))
                    .child(
                        div()
                            .text_size(px(11.0))
                            .text_color(muted)
                            .whitespace_nowrap()
                            .child(row.label.clone()),
                    )
                    .child(
                        div()
                            .font_family(mono.clone())
                            .text_size(px(11.0))
                            .text_color(foreground)
                            .whitespace_nowrap()
                            .child(row.value.clone()),
                    ),
            );
        }
        if let Some(note) = self.content.note.clone() {
            body = body.child(
                div()
                    .h(px(LINE))
                    .text_size(px(11.0))
                    .text_color(muted)
                    .whitespace_nowrap()
                    .overflow_hidden()
                    .text_ellipsis()
                    .child(note),
            );
        }
        let card = div()
            .id(self.id.clone())
            .role(Role::Group)
            .test_support()
            .aria_label(self.content.spoken())
            .relative()
            .child(body);
        // The card starts `TIP_MOVE` toward the mark and moves to its place.
        let (dx, dy): (f32, f32) = match side {
            TipSide::Right => (-TIP_MOVE, 0.0),
            TipSide::Left => (TIP_MOVE, 0.0),
            TipSide::Below => (0.0, -TIP_MOVE),
            TipSide::Above => (0.0, TIP_MOVE),
        };
        let shown = if self.animate {
            card.with_animation(
                SharedString::from(format!("{}-appear", self.id)),
                Animation::new(FAST),
                move |element, t| {
                    let eased: f32 = motion::ease_ui_out(t);
                    element
                        .opacity(eased)
                        .left(px(dx * (1.0 - eased)))
                        .top(px(dy * (1.0 - eased)))
                },
            )
            .into_any_element()
        } else {
            card.into_any_element()
        };
        deferred(
            anchored()
                .position_mode(AnchoredPositionMode::Local)
                .position(origin)
                .snap_to_window()
                .child(shown),
        )
        .with_priority(1)
        .into_any_element()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mark(x: f32, y: f32, w: f32, h: f32) -> Bounds<Pixels> {
        Bounds::new(point(px(x), px(y)), size(px(w), px(h)))
    }

    const CARD: (f32, f32) = (150.0, 60.0);

    fn place(m: Bounds<Pixels>) -> (Point<Pixels>, TipSide) {
        place_tip(m, size(px(CARD.0), px(CARD.1)), size(px(800.0), px(600.0)))
    }

    #[test]
    fn the_card_sits_at_the_right_with_a_gap_when_there_is_room() {
        let (at, side) = place(mark(100.0, 200.0, 50.0, 40.0));
        assert_eq!(side, TipSide::Right);
        assert_eq!(at.x, px(158.0));
        // It is centered on the mark.
        assert_eq!(at.y, px(220.0 - 30.0));
    }

    #[test]
    fn the_card_flips_to_the_left_without_room_at_the_right() {
        let (at, side) = place(mark(700.0, 200.0, 50.0, 40.0));
        assert_eq!(side, TipSide::Left);
        assert_eq!(at.x, px(700.0 - 8.0 - CARD.0));
    }

    #[test]
    fn the_card_stays_inside_at_the_top_and_the_bottom() {
        let (top, _) = place(mark(100.0, 0.0, 20.0, 10.0));
        assert_eq!(top.y, px(0.0));
        let (bottom, _) = place(mark(100.0, 590.0, 20.0, 10.0));
        assert_eq!(bottom.y, px(600.0 - CARD.1));
    }

    #[test]
    fn a_mark_as_wide_as_the_window_puts_the_card_under_or_above_it() {
        let (under, side) = place(mark(0.0, 100.0, 800.0, 20.0));
        assert_eq!(side, TipSide::Below);
        assert_eq!(under.y, px(128.0));
        let (over, side) = place(mark(0.0, 560.0, 800.0, 30.0));
        assert_eq!(side, TipSide::Above);
        assert_eq!(over.y, px(560.0 - 8.0 - CARD.1));
    }

    #[test]
    fn a_chart_mark_is_placed_in_window_space() {
        let window = size(px(1200.0), px(1080.0));
        let card = size(px(CARD.0), px(CARD.1));
        // A tile at the chart origin (250, 520) with the local rect 0..228.
        let origin = point(px(250.0), px(520.0));
        let (at, side) = place_tip_local(mark(0.0, 0.0, 228.0, 294.0), origin, card, window);
        assert_eq!(side, TipSide::Right);
        // Local: 8 px right of the tile; in the window: 250 + 228 + 8.
        assert_eq!(at.x, px(236.0));
        assert_eq!((at + origin).x, px(486.0));
        assert_eq!((at + origin).y, px(520.0 + 147.0 - 30.0));
        // The side follows the window edge, not the chart edge.
        let far = point(px(1000.0), px(0.0));
        let (_, side) = place_tip_local(mark(100.0, 10.0, 4.0, 4.0), far, card, window);
        assert_eq!(side, TipSide::Left);
    }

    #[test]
    fn the_text_has_the_title_each_row_and_the_note() {
        let content = TipContent::new("Pictures")
            .aside("27%")
            .row("Allocated", "12.3 GB")
            .row("Items", "4,200")
            .note("The scan did not read this part");
        assert_eq!(
            content.spoken(),
            "Pictures, 27%. Allocated: 12.3 GB. Items: 4,200. The scan did not read this part"
        );
    }

    #[test]
    fn a_card_shows_six_rows_at_most_and_keeps_its_width_between_the_limits() {
        let mut content = TipContent::new("A");
        for n in 0..9 {
            content = content.row(format!("Row {n}"), "1");
        }
        assert_eq!(content.shown_rows().len(), TIP_MAX_ROWS);
        let (width, height) = content.estimated_size();
        assert!((TIP_MIN_WIDTH..=TIP_MAX_WIDTH).contains(&width));
        assert!((height - (7.0 * 16.0 + 16.0)).abs() < f32::EPSILON);
        let long = TipContent::new("x".repeat(100));
        assert!((long.estimated_size().0 - TIP_MAX_WIDTH).abs() < f32::EPSILON);
    }
}
