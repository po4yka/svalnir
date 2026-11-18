//! One band of cells that splits the scanned bytes among segments.

use crate::{
    theme::{
        palette,
        tokens::{Tokens, to_hsla},
    },
    ui::data_state::format_bytes,
    viz::{
        alloc::{CellState, allocate_cells},
        breakdown::Segment,
        cells::{Cell, CellLayout, CellStrip},
    },
};
use gpui_kit::{
    App, Hsla, IntoElement, ParentElement as _, RenderOnce, SharedString, Styled as _,
    TestSupportExt as _, Window,
    component::{ActiveTheme as _, v_flex},
    div,
    prelude::*,
    px,
};

/// Columns of the band.
pub const BAND_COLUMNS: usize = 60;
/// Rows of the band.
pub const BAND_ROWS: usize = 4;
/// Cells of the band.
pub const BAND_CELLS: usize = BAND_COLUMNS * BAND_ROWS;

/// The caption of the scale. The size of one cell is rounded to the nearest
/// byte; below one byte it reads "1 cell < 1 B". A total of 0 reads
/// "Nothing was measured."
#[must_use]
pub fn scale_caption(total: u64) -> String {
    if total == 0 {
        return "Nothing was measured.".to_owned();
    }
    let cells: u128 = u128::try_from(BAND_CELLS).unwrap_or(1);
    let per_cell: u128 = (u128::from(total) + cells / 2) / cells;
    if per_cell == 0 {
        return "1 cell < 1 B".to_owned();
    }
    let (text, unit) = format_bytes(u64::try_from(per_cell).unwrap_or(u64::MAX));
    format!("1 cell = {text} {unit}")
}

/// The accessible label of the band.
#[must_use]
pub fn band_label(root: &str, segments: &[Segment]) -> String {
    let parts: Vec<String> = segments
        .iter()
        .map(|segment| {
            let (text, unit) = format_bytes(segment.bytes);
            format!("{}: {text} {unit}", segment.label)
        })
        .collect();
    format!("Breakdown of {root}: {}", parts.join(", "))
}

/// The band. It shows only the scanned bytes; `free` adds empty cells.
#[derive(IntoElement, Debug)]
pub struct CellBand {
    segments: Vec<Segment>,
    root: SharedString,
    id: SharedString,
    dimmed_except: Option<usize>,
    free: Option<u64>,
}

impl CellBand {
    /// Creates the band.
    pub fn new(
        segments: Vec<Segment>,
        root: impl Into<SharedString>,
        id: impl Into<SharedString>,
    ) -> Self {
        Self {
            segments,
            root: root.into(),
            id: id.into(),
            dimmed_except: None,
            free: None,
        }
    }

    /// Dims each segment except the one at `index`.
    #[must_use]
    pub fn dimmed_except(mut self, index: Option<usize>) -> Self {
        self.dimmed_except = index;
        self
    }

    /// Appends empty cells for `bytes` of free space, with a label.
    #[must_use]
    pub fn free(mut self, bytes: u64) -> Self {
        self.free = Some(bytes);
        self
    }
}

impl RenderOnce for CellBand {
    fn render(self, _window: &mut Window, cx: &mut App) -> impl IntoElement {
        let dark: bool = cx.theme().is_dark();
        let tokens: &Tokens = Tokens::for_dark(dark);
        let used: u64 = self
            .segments
            .iter()
            .map(|s| s.bytes)
            .fold(0, u64::saturating_add);
        let total: u64 = used.saturating_add(self.free.unwrap_or(0));
        if total == 0 {
            let note: String = scale_caption(0);
            return div()
                .id(SharedString::from(format!("{}-scale", self.id)))
                .test_support()
                .aria_label(note.clone())
                .text_size(px(12.0))
                .text_color(to_hsla(tokens.muted_foreground))
                .child(note)
                .into_any_element();
        }
        let parts: Vec<u64> = self.segments.iter().map(|s| s.bytes).collect();
        let counts: Vec<usize> = allocate_cells(&parts, total, BAND_CELLS);
        let mut cells: Vec<Cell> = Vec::with_capacity(BAND_CELLS);
        let mut color_index: usize = 0;
        for (index, (segment, count)) in self.segments.iter().zip(&counts).enumerate() {
            let color: Hsla = if segment.is_other {
                Hsla::from(palette::neutral_color(dark))
            } else {
                let color = Hsla::from(palette::category_color(color_index, dark));
                color_index += 1;
                color
            };
            let state: CellState = match self.dimmed_except {
                Some(focus) if focus != index => CellState::Dimmed,
                _ => CellState::Filled,
            };
            cells.extend((0..*count).map(|_| Cell { state, color }));
        }
        let empty: Hsla = to_hsla(tokens.border);
        while cells.len() < BAND_CELLS {
            cells.push(Cell {
                state: CellState::Empty,
                color: empty,
            });
        }
        let layout: CellLayout = CellLayout::Grid {
            columns: BAND_COLUMNS,
            cell: px(8.0),
            gap: px(3.0),
        };
        let label: String = band_label(&self.root, &self.segments);
        let scale: String = scale_caption(total);
        let muted: Hsla = to_hsla(tokens.muted_foreground);
        let band = v_flex()
            .gap(px(8.0))
            .child(CellStrip::new(cells, layout, self.id.clone(), label))
            .children(
                self.free
                    .map(|_| div().text_size(px(12.0)).text_color(muted).child("Free")),
            )
            .child(
                div()
                    .id(SharedString::from(format!("{}-scale", self.id)))
                    .test_support()
                    .aria_label(scale.clone())
                    .text_size(px(12.0))
                    .text_color(muted)
                    .child(scale),
            );
        band.into_any_element()
    }
}

#[cfg(test)]
mod scale_tests {
    use super::*;

    #[test]
    fn scale_caption_rounds_and_never_says_zero_bytes() {
        assert_eq!(scale_caption(0), "Nothing was measured.");
        assert_eq!(scale_caption(100), "1 cell < 1 B");
        assert_eq!(scale_caption(120), "1 cell = 1 B");
        assert_eq!(scale_caption(239), "1 cell = 1 B");
        assert_eq!(scale_caption(360), "1 cell = 2 B");
    }
}
