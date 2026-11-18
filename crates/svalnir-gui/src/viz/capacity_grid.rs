//! The capacity grid: used space of a volume as cells.

use crate::{
    data::model::Measured,
    theme::tokens::{Tokens, to_hsla},
    ui::data_state::{UNAVAILABLE_TEXT, format_bytes},
    viz::{
        alloc::{CellState, used_cells, zone_start},
        cells::{Cell, CellLayout, CellStrip},
    },
};
use gpui_kit::{
    App, Hsla, InteractiveElement as _, IntoElement, ParentElement as _, RenderOnce, SharedString,
    Styled as _, TestSupportExt as _, Window,
    component::{ActiveTheme as _, v_flex},
    div,
    prelude::*,
    px,
};

/// The cell count of the full grid.
pub const FULL_CELLS: usize = 100;
/// The cell count of the inline variant.
pub const INLINE_CELLS: usize = 20;

/// The scale caption: "1 cell = 1%" or "1 cell = 5%".
#[must_use]
pub const fn scale_caption(inline: bool) -> &'static str {
    if inline { "1 cell = 5%" } else { "1 cell = 1%" }
}

/// The text label of a capacity chart.
#[must_use]
pub fn capacity_label(used: &Measured<u64>, total: &Measured<u64>) -> String {
    match (used, total) {
        (Measured::Value(used), Measured::Value(total)) if *total > 0 => {
            let (used_value, used_unit) = format_bytes(*used);
            let (total_value, total_unit) = format_bytes(*total);
            let percent: usize = used_cells(*used, *total, 100);
            format!("Disk: {used_value} {used_unit} used of {total_value} {total_unit}, {percent}%")
        }
        _ => format!("Disk: used space is {UNAVAILABLE_TEXT}"),
    }
}

/// Used space of a volume as a grid of cells.
#[derive(IntoElement)]
pub struct CapacityGrid {
    used: Measured<u64>,
    total: Measured<u64>,
    inline: bool,
    warning_at: Option<f32>,
    critical_at: Option<f32>,
    id: SharedString,
}

impl std::fmt::Debug for CapacityGrid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CapacityGrid")
            .field("inline", &self.inline)
            .finish_non_exhaustive()
    }
}

impl CapacityGrid {
    /// Creates a grid for `used` of `total` bytes.
    pub fn new(used: Measured<u64>, total: Measured<u64>) -> Self {
        Self {
            used,
            total,
            inline: false,
            warning_at: None,
            critical_at: None,
            id: SharedString::from("capacity-grid"),
        }
    }

    /// Chooses the inline variant: 20 cells in one row.
    #[must_use]
    pub fn inline(mut self, inline: bool) -> Self {
        self.inline = inline;
        self
    }

    /// Tints the cells from this used fraction as a warning zone.
    #[must_use]
    pub fn warning_at(mut self, fraction: f32) -> Self {
        self.warning_at = Some(fraction);
        self
    }

    /// Tints the cells from this used fraction as a critical zone.
    #[must_use]
    pub fn critical_at(mut self, fraction: f32) -> Self {
        self.critical_at = Some(fraction);
        self
    }

    /// Sets the element id of the grid; the caption uses `{id}-scale`.
    #[must_use]
    pub fn id(mut self, id: impl Into<SharedString>) -> Self {
        self.id = id.into();
        self
    }
}

impl RenderOnce for CapacityGrid {
    fn render(self, _window: &mut Window, cx: &mut App) -> impl IntoElement {
        let tokens: &Tokens = Tokens::for_dark(cx.theme().is_dark());
        let count: usize = if self.inline {
            INLINE_CELLS
        } else {
            FULL_CELLS
        };
        let layout: CellLayout = if self.inline {
            CellLayout::inline(INLINE_CELLS)
        } else {
            CellLayout::grid()
        };
        let known: Option<(u64, u64)> = match (&self.used, &self.total) {
            (Measured::Value(used), Measured::Value(total)) => Some((*used, *total)),
            _ => None,
        };
        let filled: usize = known.map_or(0, |(used, total)| used_cells(used, total, count));
        let warning: Hsla = to_hsla(tokens.warning);
        let negative: Hsla = to_hsla(tokens.negative);
        let brand: Hsla = to_hsla(tokens.brand);
        let warn_start: Option<usize> = known
            .and(self.warning_at)
            .map(|fraction| zone_start(fraction, count));
        let crit_start: Option<usize> = known
            .and(self.critical_at)
            .map(|fraction| zone_start(fraction, count));
        let cells: Vec<Cell> = (0..count)
            .map(|index| {
                let in_critical: bool = crit_start.is_some_and(|start| index >= start);
                let in_warning: bool = warn_start.is_some_and(|start| index >= start);
                let zone: Option<Hsla> = if in_critical {
                    Some(negative)
                } else if in_warning {
                    Some(warning)
                } else {
                    None
                };
                if index < filled {
                    let color: Hsla = zone.unwrap_or(brand);
                    // A capacity is a level, not work in progress: no head cell.
                    Cell {
                        state: CellState::Filled,
                        color,
                    }
                } else if let Some(color) = zone {
                    // An empty cell in a zone is a tint, not an empty cell.
                    Cell {
                        state: CellState::Dimmed,
                        color,
                    }
                } else {
                    Cell {
                        state: CellState::Empty,
                        color: brand,
                    }
                }
            })
            .collect();
        let label: String = capacity_label(&self.used, &self.total);
        v_flex()
            .gap(px(8.0))
            .child(CellStrip::new(cells, layout, self.id.clone(), label))
            .child(
                div()
                    .id(SharedString::from(format!("{}-scale", self.id)))
                    .test_support()
                    .aria_label(scale_caption(self.inline))
                    .text_size(px(12.0))
                    .text_color(to_hsla(tokens.muted_foreground))
                    .child(scale_caption(self.inline)),
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captions_state_the_scale() {
        assert_eq!(scale_caption(true), "1 cell = 5%");
        assert_eq!(scale_caption(false), "1 cell = 1%");
    }

    #[test]
    fn label_states_the_percent() {
        let label: String = capacity_label(
            &Measured::Value(326_500_000_000),
            &Measured::Value(512_000_000_000),
        );
        assert_eq!(label, "Disk: 326.5 GB used of 512.0 GB, 64%");
        assert!(
            capacity_label(&Measured::Unavailable("x".into()), &Measured::Value(1))
                .contains('\u{2014}')
        );
    }
}
