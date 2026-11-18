//! One element that paints all cells or ticks of a chart.

use crate::theme::tokens::{self, Tokens, to_hsla};
use crate::viz::alloc::{CellState, count_f32};
use gpui_kit::{
    App, Bounds, Hsla, IntoElement, Pixels, Point, RenderOnce, Rgba, Role, SharedString, Styled,
    TestSupportExt as _, Window, canvas, component::ActiveTheme as _, div, fill, point, prelude::*,
    px, size,
};

/// One cell: its state and its base color.
#[derive(Debug, Clone, Copy)]
pub struct Cell {
    /// The state.
    pub state: CellState,
    /// The base color; an empty cell uses the `border` token instead.
    pub color: Hsla,
}

/// The layout of a strip.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CellLayout {
    /// Square cells in rows of `columns`.
    Grid {
        /// Cells per row.
        columns: usize,
        /// Side of a cell.
        cell: Pixels,
        /// Gap between cells.
        gap: Pixels,
    },
    /// Thin tall ticks in one row.
    Ticks {
        /// Width of a tick.
        width: Pixels,
        /// Height of a tick.
        height: Pixels,
        /// Gap between ticks.
        gap: Pixels,
    },
}

impl CellLayout {
    /// The default grid: 14 px cells, 4 px gap, 20 columns.
    #[must_use]
    pub const fn grid() -> Self {
        Self::Grid {
            columns: 20,
            cell: tokens::CELL_SIZE,
            gap: tokens::CELL_GAP,
        }
    }

    /// The inline grid: one row of 8 px cells with a 3 px gap.
    #[must_use]
    pub const fn inline(columns: usize) -> Self {
        Self::Grid {
            columns,
            cell: px(8.0),
            gap: px(3.0),
        }
    }

    /// The size of `count` cells.
    #[must_use]
    pub fn size_for(self, count: usize) -> (Pixels, Pixels) {
        let (columns, cell_w, cell_h, gap): (usize, Pixels, Pixels, Pixels) = match self {
            Self::Grid { columns, cell, gap } => (columns.max(1), cell, cell, gap),
            Self::Ticks { width, height, gap } => (count.max(1), width, height, gap),
        };
        let used_columns: usize = count.min(columns).max(1);
        let rows: usize = count.div_ceil(columns).max(1);
        (
            cell_w * count_f32(used_columns) + gap * count_f32(used_columns.saturating_sub(1)),
            cell_h * count_f32(rows) + gap * count_f32(rows.saturating_sub(1)),
        )
    }
}

/// The paint color of a cell.
#[must_use]
pub fn cell_color(cell: Cell, empty: Hsla) -> Hsla {
    match cell.state {
        CellState::Empty => empty,
        CellState::Filled => cell.color,
        CellState::Head => {
            let base: Rgba = Rgba::from(cell.color);
            Hsla::from(Rgba {
                r: f32::midpoint(base.r, 1.0),
                g: f32::midpoint(base.g, 1.0),
                b: f32::midpoint(base.b, 1.0),
                a: base.a,
            })
        }
        CellState::Dimmed => cell.color.opacity(0.25),
    }
}

/// All cells of a chart, painted by one canvas.
#[derive(IntoElement)]
pub struct CellStrip {
    cells: Vec<Cell>,
    layout: CellLayout,
    radius: Pixels,
    label: SharedString,
    id: SharedString,
}

impl std::fmt::Debug for CellStrip {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CellStrip")
            .field("cells", &self.cells.len())
            .field("label", &self.label)
            .finish_non_exhaustive()
    }
}

impl CellStrip {
    /// Creates a strip with the default 3 px radius.
    pub fn new(
        cells: Vec<Cell>,
        layout: CellLayout,
        id: impl Into<SharedString>,
        label: impl Into<SharedString>,
    ) -> Self {
        Self {
            cells,
            layout,
            radius: tokens::CELL_RADIUS,
            label: label.into(),
            id: id.into(),
        }
    }

    /// Sets the corner radius.
    #[must_use]
    pub fn radius(mut self, radius: Pixels) -> Self {
        self.radius = radius;
        self
    }
}

impl RenderOnce for CellStrip {
    fn render(self, _window: &mut Window, cx: &mut App) -> impl IntoElement {
        let tokens: &Tokens = Tokens::for_dark(cx.theme().is_dark());
        let empty: Hsla = to_hsla(tokens.border);
        let (width, height): (Pixels, Pixels) = self.layout.size_for(self.cells.len());
        let cells: Vec<Cell> = self.cells;
        let layout: CellLayout = self.layout;
        let radius: Pixels = self.radius;
        div()
            .id(self.id)
            .role(Role::Image)
            .test_support()
            .aria_label(self.label)
            .w(width)
            .h(height)
            .flex_shrink_0()
            .child(
                canvas(
                    |_, _, _| (),
                    move |bounds: Bounds<Pixels>, (), window: &mut Window, _cx: &mut App| {
                        let (columns, cell_w, cell_h, gap): (usize, Pixels, Pixels, Pixels) =
                            match layout {
                                CellLayout::Grid { columns, cell, gap } => {
                                    (columns.max(1), cell, cell, gap)
                                }
                                CellLayout::Ticks { width, height, gap } => {
                                    (cells.len().max(1), width, height, gap)
                                }
                            };
                        for (index, cell) in cells.iter().enumerate() {
                            let column: usize = index % columns;
                            let row: usize = index / columns;
                            let origin: Point<Pixels> = point(
                                bounds.origin.x + (cell_w + gap) * count_f32(column),
                                bounds.origin.y + (cell_h + gap) * count_f32(row),
                            );
                            let cell_bounds: Bounds<Pixels> =
                                Bounds::new(origin, size(cell_w, cell_h));
                            window.paint_quad(
                                fill(cell_bounds, cell_color(*cell, empty)).corner_radii(radius),
                            );
                        }
                    },
                )
                .size_full(),
            )
    }
}
