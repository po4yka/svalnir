//! The legend of a segmented chart: one button row for each segment.

use crate::theme::tokens::{self, Tokens, to_hsla};
use gpui_kit::{
    App, Hsla, IntoElement, ParentElement as _, RenderOnce, SharedString, Styled as _,
    TestSupportExt as _, Window,
    component::{
        ActiveTheme as _, Disableable as _, Icon, IconName,
        button::{Button, ButtonVariants as _},
        h_flex, v_flex,
    },
    div,
    prelude::*,
    px,
};
use std::rc::Rc;

/// Width from which the legend has two columns.
pub const TWO_COLUMN_WIDTH: f32 = 520.0;

/// One legend row.
#[derive(Debug, Clone)]
pub struct LegendRow {
    /// The name.
    pub name: SharedString,
    /// The size text.
    pub size: SharedString,
    /// The color of the square.
    pub color: Hsla,
    /// Whether the row can be activated (a directory).
    pub activatable: bool,
}

/// The number of columns for a width.
#[must_use]
pub fn columns_for(width: f32) -> usize {
    if width >= TWO_COLUMN_WIDTH { 2 } else { 1 }
}

type Select = Rc<dyn Fn(usize, &mut Window, &mut App)>;
type Hover = Rc<dyn Fn(Option<usize>, &mut Window, &mut App)>;

/// The legend.
#[derive(IntoElement)]
pub struct Legend {
    rows: Vec<LegendRow>,
    width: f32,
    id: SharedString,
    on_select: Option<Select>,
    on_hover: Option<Hover>,
}

impl std::fmt::Debug for Legend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Legend")
            .field("rows", &self.rows.len())
            .finish_non_exhaustive()
    }
}

impl Legend {
    /// Creates the legend for a container of `width` pixels.
    pub fn new(rows: Vec<LegendRow>, width: f32, id: impl Into<SharedString>) -> Self {
        Self {
            rows,
            width,
            id: id.into(),
            on_select: None,
            on_hover: None,
        }
    }

    /// Sets the handler for the activation of a directory row.
    #[must_use]
    pub fn on_select(mut self, f: impl Fn(usize, &mut Window, &mut App) + 'static) -> Self {
        self.on_select = Some(Rc::new(f));
        self
    }

    /// Sets the handler for the hover of a row.
    #[must_use]
    pub fn on_hover(mut self, f: impl Fn(Option<usize>, &mut Window, &mut App) + 'static) -> Self {
        self.on_hover = Some(Rc::new(f));
        self
    }
}

impl RenderOnce for Legend {
    fn render(self, _window: &mut Window, cx: &mut App) -> impl IntoElement {
        let tokens: &Tokens = Tokens::for_dark(cx.theme().is_dark());
        let mono: SharedString = cx.theme().mono_font_family.clone();
        let muted: Hsla = to_hsla(tokens.muted_foreground);
        let columns: usize = columns_for(self.width);
        let items: Vec<_> = self
            .rows
            .iter()
            .enumerate()
            .map(|(index, row)| {
                let row_id: SharedString = format!("{}-row-{index}", self.id).into();
                let on_select = self.on_select.clone();
                let on_hover = self.on_hover.clone();
                let name_button = Button::new(SharedString::from(format!("{row_id}-button")))
                    .ghost()
                    .label(row.name.clone())
                    .disabled(!row.activatable)
                    .on_click(move |_, window, cx| {
                        if let Some(select) = &on_select {
                            select(index, window, cx);
                        }
                    });
                let label: String = format!("{}: {}", row.name, row.size);
                h_flex()
                    .id(row_id)
                    .test_support()
                    .aria_label(label)
                    .gap(tokens::SPACE_2)
                    .items_center()
                    .min_w(px(0.0))
                    .w(gpui_kit::relative(if columns == 2 { 0.5 } else { 1.0 }))
                    // Each column gives half of the SPACE_4 gutter: equal widths,
                    // and the right column ends at the content edge.
                    .pr(if columns == 2 && index % 2 == 0 {
                        tokens::SPACE_4 * 0.5
                    } else {
                        px(0.0)
                    })
                    .pl(if columns == 2 && index % 2 == 1 {
                        tokens::SPACE_4 * 0.5
                    } else {
                        px(0.0)
                    })
                    .on_hover(move |hovered, window, cx| {
                        if let Some(hover) = &on_hover {
                            hover(hovered.then_some(index), window, cx);
                        }
                    })
                    .child(
                        div()
                            .size(px(10.0))
                            .flex_shrink_0()
                            .rounded(px(2.0))
                            .bg(row.color),
                    )
                    .child(
                        h_flex()
                            .flex_1()
                            .min_w(px(0.0))
                            .justify_start()
                            .overflow_hidden()
                            .child(name_button),
                    )
                    .children(
                        row.activatable
                            .then(|| Icon::new(IconName::ChevronRight).size_3().text_color(muted)),
                    )
                    .child(
                        div()
                            .font_family(mono.clone())
                            .text_size(px(12.0))
                            .text_color(muted)
                            .child(row.size.clone()),
                    )
            })
            .collect();
        v_flex()
            .id(self.id.clone())
            .child(h_flex().flex_wrap().gap_y(tokens::SPACE_1).children(items))
    }
}
