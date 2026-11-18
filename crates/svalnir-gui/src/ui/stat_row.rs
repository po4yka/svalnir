//! The stat row: up to four values in the footer of a card or below a chart
//! (`DESIGN.md` section 5, "Stat row").

use crate::{
    theme::tokens::{self, Tokens, to_hsla},
    ui::data_state::UNAVAILABLE_TEXT,
};
use gpui_kit::{
    AnyElement, App, FontWeight, Hsla, InteractiveElement as _, IntoElement, ParentElement as _,
    RenderOnce, SharedString, StatefulInteractiveElement as _, Styled as _, TestSupportExt as _,
    Window,
    component::{ActiveTheme as _, h_flex, v_flex},
    div, px,
};

/// The most items of one row.
pub const MAX_ITEMS: usize = 4;

/// One value of a stat row.
#[derive(Debug, Clone)]
pub struct StatItem {
    key: SharedString,
    label: SharedString,
    value: Option<SharedString>,
    suffix: Option<SharedString>,
    color: Hsla,
}

impl StatItem {
    /// Creates an item. `key` ends the element id. A `value` of `None` is
    /// unavailable and shows an em dash, with no suffix.
    pub fn new(
        key: impl Into<SharedString>,
        label: impl Into<SharedString>,
        value: Option<impl Into<SharedString>>,
        color: Hsla,
    ) -> Self {
        Self {
            key: key.into(),
            label: label.into(),
            value: value.map(Into::into),
            suffix: None,
            color,
        }
    }

    /// Sets the muted suffix after the number.
    #[must_use]
    pub fn suffix(mut self, suffix: impl Into<SharedString>) -> Self {
        self.suffix = Some(suffix.into());
        self
    }

    /// The accessible label: the label, the value, and the suffix.
    #[must_use]
    pub fn text(&self) -> String {
        match (&self.value, &self.suffix) {
            (Some(value), Some(suffix)) => format!("{} {value} {suffix}", self.label),
            (Some(value), None) => format!("{} {value}", self.label),
            (None, _) => format!("{} {UNAVAILABLE_TEXT}", self.label),
        }
    }
}

/// A row of at most `MAX_ITEMS` values.
#[derive(IntoElement, Debug)]
pub struct StatRow {
    prefix: SharedString,
    items: Vec<StatItem>,
}

impl StatRow {
    /// Creates a row. The id of an item is `prefix` and its key.
    pub fn new(prefix: impl Into<SharedString>) -> Self {
        Self {
            prefix: prefix.into(),
            items: Vec::new(),
        }
    }

    /// Adds an item; items after the fourth are dropped.
    #[must_use]
    pub fn item(mut self, item: StatItem) -> Self {
        if self.items.len() < MAX_ITEMS {
            self.items.push(item);
        }
        self
    }
}

impl RenderOnce for StatRow {
    fn render(self, _window: &mut Window, cx: &mut App) -> impl IntoElement {
        let tokens: &Tokens = Tokens::for_dark(cx.theme().is_dark());
        let muted: Hsla = to_hsla(tokens.muted_foreground);
        let mut row = h_flex()
            .flex_wrap()
            .gap_x(tokens::SPACE_6)
            .gap_y(tokens::SPACE_2);
        for item in self.items {
            let text: SharedString = item.text().into();
            let id: SharedString = format!("{}{}", self.prefix, item.key).into();
            let number: AnyElement = match &item.value {
                Some(value) => div()
                    .text_size(px(16.0))
                    .font_weight(FontWeight::MEDIUM)
                    .child(value.clone())
                    .into_any_element(),
                None => div()
                    .text_size(px(16.0))
                    .text_color(muted)
                    .child(UNAVAILABLE_TEXT)
                    .into_any_element(),
            };
            let suffix: Option<AnyElement> =
                item.value.as_ref().and(item.suffix.clone()).map(|s| {
                    div()
                        .text_size(px(12.0))
                        .text_color(muted)
                        .child(s)
                        .into_any_element()
                });
            row = row.child(
                v_flex()
                    .id(id)
                    .test_support()
                    .aria_label(text)
                    .gap(tokens::SPACE_1)
                    .child(
                        div()
                            .text_size(px(12.0))
                            .text_color(muted)
                            .child(item.label.clone()),
                    )
                    .child(
                        h_flex()
                            .items_center()
                            .gap(tokens::SPACE_1)
                            // The dash of the series color: 2 px by 8 px.
                            .child(div().w(px(2.0)).h(px(8.0)).flex_shrink_0().bg(item.color))
                            .child(number)
                            .children(suffix),
                    ),
            );
        }
        row
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gpui_kit::hsla;

    #[test]
    fn the_text_has_label_value_and_suffix() {
        let color: Hsla = hsla(0.0, 0.0, 0.5, 1.0);
        let item = StatItem::new("swap", "Swap used", Some("1.0"), color).suffix("of 4.0 GB");
        assert_eq!(item.text(), "Swap used 1.0 of 4.0 GB");
    }

    #[test]
    fn an_unavailable_value_is_an_em_dash_and_never_zero() {
        let color: Hsla = hsla(0.0, 0.0, 0.5, 1.0);
        let item = StatItem::new("disk", "Disk available", None::<&str>, color).suffix("GB");
        assert_eq!(item.text(), "Disk available \u{2014}");
    }

    #[test]
    fn a_row_keeps_at_most_four_items() {
        let color: Hsla = hsla(0.0, 0.0, 0.5, 1.0);
        let mut row = StatRow::new("t-");
        for key in ["a", "b", "c", "d", "e"] {
            row = row.item(StatItem::new(key, key, Some("1"), color));
        }
        assert_eq!(row.items.len(), MAX_ITEMS);
    }
}
