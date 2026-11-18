//! The layouts of the Storage chart over the same segments.

use crate::{
    ui::data_state::format_bytes,
    viz::{
        alloc::allocate_cells,
        led::{
            FillAxis, LABEL_MIN_COLUMNS, LABEL_MIN_ROWS, LabelPlace, LedField, LedSegment,
            MAX_CELLS, TileLabel, label_block,
        },
        treemap::{CellRect, squarify},
    },
};
use gpui_kit::Hsla;

/// The rows of the band layout.
pub const BAND_ROWS: u16 = 14;
/// The rows of the strip on the volume card.
pub const STRIP_ROWS: u16 = 10;
/// The rows of the tiles and the columns for a chart of 300 px.
pub const CHART_ROWS: u16 = 50;
/// The width of a column of the columns layout, in cells.
const COLUMN_WIDTH: u16 = 6;
/// The gap between two columns, in cells.
const COLUMN_GAP: u16 = 3;
/// The smallest free region that is drawn, in cells.
const MIN_FREE_COLUMNS: u16 = 6;

/// The layout of the chart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StorageLayout {
    /// A treemap of blocks.
    #[default]
    Tiles,
    /// One strip.
    Band,
    /// One column for each segment.
    Columns,
    /// Four rings of dots. `CellRing` paints it; `layout_field` treats it
    /// like the band.
    Ring,
}

impl StorageLayout {
    /// Each layout, in the order of the control.
    pub const ALL: [Self; 4] = [Self::Tiles, Self::Band, Self::Columns, Self::Ring];

    /// The name for labels.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Tiles => "Tiles",
            Self::Band => "Band",
            Self::Columns => "Columns",
            Self::Ring => "Ring",
        }
    }
}

/// One item of the chart: a segment of the breakdown, or "Not scanned".
#[derive(Debug, Clone, PartialEq)]
pub struct ChartItem {
    /// The name.
    pub label: String,
    /// The size in bytes.
    pub bytes: u64,
    /// The color, as in the legend.
    pub color: Hsla,
    /// Whether a click opens the folder.
    pub activatable: bool,
    /// Whether the item is always de-emphasized (not scanned).
    pub inert: bool,
}

fn seed_of(index: usize) -> u32 {
    u32::try_from(index)
        .unwrap_or(u32::MAX)
        .wrapping_add(1)
        .wrapping_mul(0x9e37_79b9)
}

fn size_text(bytes: u64) -> String {
    let (text, unit) = format_bytes(bytes);
    format!("{text} {unit}")
}

fn to_u16(value: u32) -> u16 {
    u16::try_from(value).unwrap_or(u16::MAX)
}

/// Clamps the lattice so that it has at most `MAX_CELLS` cells.
#[must_use]
pub fn clamp_lattice(columns: u16, rows: u16) -> (u16, u16) {
    let rows: u16 = rows.max(1);
    let limit: u16 = to_u16(u32::try_from(MAX_CELLS).unwrap_or(0) / u32::from(rows));
    (columns.clamp(1, limit.max(1)), rows)
}

/// Lays `items` out as a field, with the labels of the tiles.
///
/// `total_bytes` is the sum of the items; with `free_bytes` the free region
/// takes a share of the width in proportion to `free / (free + total)`. The
/// segments of the field have the order of `items`; an item of zero bytes has
/// an empty rectangle.
#[must_use]
pub fn layout_field(
    items: &[ChartItem],
    total_bytes: u64,
    free_bytes: Option<u64>,
    layout: StorageLayout,
    columns: u16,
    rows: u16,
) -> (LedField, Vec<TileLabel>) {
    let (columns, rows): (u16, u16) = clamp_lattice(columns, rows);
    let weights: Vec<u64> = items.iter().map(|i| i.bytes).collect();
    let free: Option<u64> = free_bytes.filter(|&f| f > 0);
    let mut free_rect: Option<CellRect> = None;
    let rects: Vec<CellRect> = match layout {
        StorageLayout::Tiles => {
            let reserved: u16 = free.map_or(0, |f| share(columns, f, total_bytes));
            let start: u16 =
                if reserved >= MIN_FREE_COLUMNS && columns - reserved >= MIN_FREE_COLUMNS {
                    free_rect = Some(CellRect::new(0, 0, reserved - 1, rows));
                    reserved
                } else {
                    0
                };
            let area: CellRect = CellRect::new(start, 0, columns - start, rows);
            squarify(&weights, area)
                .into_iter()
                .map(CellRect::gapped)
                .collect()
        }
        StorageLayout::Band | StorageLayout::Ring => {
            let mut parts: Vec<u64> = weights.clone();
            parts.push(free.unwrap_or(0));
            let all: u64 = total_bytes.saturating_add(free.unwrap_or(0));
            let widths: Vec<usize> = allocate_cells(&parts, all, usize::from(columns));
            let mut x: u16 = 0;
            let mut out: Vec<CellRect> = Vec::with_capacity(items.len());
            for (index, width) in widths.iter().enumerate() {
                let w: u16 = u16::try_from(*width).unwrap_or(columns);
                let drawn: u16 = if w > 1 { w - 1 } else { w };
                if index < items.len() {
                    out.push(CellRect::new(x, 0, drawn, rows));
                } else if w >= MIN_FREE_COLUMNS {
                    free_rect = Some(CellRect::new(x, 0, drawn, rows));
                }
                x = x.saturating_add(w);
            }
            out
        }
        StorageLayout::Columns => columns_rects(&weights, columns, rows),
    };
    let mut segments: Vec<LedSegment> = Vec::with_capacity(items.len());
    let mut labels: Vec<TileLabel> = Vec::new();
    for (index, (item, rect)) in items.iter().zip(&rects).enumerate() {
        let mut segment: LedSegment = LedSegment::new(*rect, item.color, seed_of(index));
        segment.dimmed = item.inert;
        if layout == StorageLayout::Columns {
            segment.axis = FillAxis::Vertical;
        }
        let big: bool = rect.w >= LABEL_MIN_COLUMNS && rect.h >= LABEL_MIN_ROWS;
        if layout == StorageLayout::Tiles && big {
            segment.label_rect = Some(label_block(*rect, &item.label, &size_text(item.bytes), 6.0));
        }
        segments.push(segment);
        if rect.is_empty() {
            continue;
        }
        let (show_text, place): (bool, LabelPlace) = match layout {
            StorageLayout::Tiles => (big, LabelPlace::Inside),
            StorageLayout::Band | StorageLayout::Ring => (false, LabelPlace::Inside),
            StorageLayout::Columns => (true, LabelPlace::Below),
        };
        labels.push(TileLabel {
            index: Some(index),
            rect: *rect,
            name: item.label.clone(),
            size: size_text(item.bytes),
            show_text,
            place,
            activatable: item.activatable,
        });
    }
    if let (Some(rect), Some(bytes)) = (free_rect, free) {
        labels.push(TileLabel {
            index: None,
            rect,
            name: "Free".to_owned(),
            size: size_text(bytes),
            show_text: layout != StorageLayout::Columns && rect.w >= 12 && rect.h >= 8,
            place: LabelPlace::Inside,
            activatable: false,
        });
    }
    let field: LedField = LedField {
        columns,
        rows,
        segments,
        free: free_rect,
        head: None,
        phase: None,
    };
    (field, labels)
}

/// The columns of `part / (part + rest)` of `columns`, rounded.
fn share(columns: u16, part: u64, rest: u64) -> u16 {
    let whole: u128 = u128::from(part) + u128::from(rest);
    if whole == 0 {
        return 0;
    }
    let value: u128 = (u128::from(columns) * u128::from(part) * 2 + whole) / (whole * 2);
    u16::try_from(value).unwrap_or(columns)
}

fn columns_rects(weights: &[u64], columns: u16, rows: u16) -> Vec<CellRect> {
    let count: u16 = to_u16(u32::try_from(weights.len()).unwrap_or(u32::MAX)).max(1);
    let fits: bool = u32::from(count) * u32::from(COLUMN_WIDTH + COLUMN_GAP)
        - u32::from(COLUMN_GAP)
        <= u32::from(columns);
    let width: u16 = if fits {
        COLUMN_WIDTH
    } else {
        ((columns + COLUMN_GAP) / count)
            .saturating_sub(COLUMN_GAP)
            .max(1)
    };
    let max: u64 = weights.iter().copied().max().unwrap_or(0);
    weights
        .iter()
        .enumerate()
        .map(|(index, &bytes)| {
            let x: u16 = u16::try_from(index)
                .unwrap_or(u16::MAX)
                .saturating_mul(width + COLUMN_GAP);
            if bytes == 0 || max == 0 {
                return CellRect::new(x, rows, 0, 0);
            }
            let h: u16 = share(rows, bytes, max - bytes).clamp(1, rows);
            CellRect::new(x, rows - h, width, h)
        })
        .collect()
}

/// Marks each segment but the one at `focus` as de-emphasized.
pub fn apply_focus(field: &mut LedField, focus: Option<usize>) {
    if let Some(focus) = focus {
        for (index, segment) in field.segments.iter_mut().enumerate() {
            if index != focus {
                segment.dimmed = true;
            }
        }
    }
}

/// The bytes that one lattice cell stands for: the largest item over its area.
#[must_use]
pub fn bytes_per_cell(items: &[ChartItem], field: &LedField) -> u64 {
    items
        .iter()
        .zip(&field.segments)
        .filter(|(_, s)| !s.rect.is_empty())
        .max_by_key(|(item, _)| item.bytes)
        .map_or(0, |(item, s)| item.bytes / u64::from(s.rect.area().max(1)))
}

/// The caption of the scale. A cell below one byte reads "1 cell < 1 B"; a
/// `total` of 0 reads "Nothing was measured."
#[must_use]
pub fn scale_caption(per_cell: u64, total: u64) -> String {
    if total == 0 {
        return "Nothing was measured.".to_owned();
    }
    if per_cell == 0 {
        return "1 cell < 1 B".to_owned();
    }
    format!("1 cell = {}", size_text(per_cell))
}

/// The accessible label of the chart.
#[must_use]
pub fn chart_label(layout: StorageLayout, root: &str, items: &[ChartItem]) -> String {
    let parts: Vec<String> = items
        .iter()
        .map(|i| format!("{}: {}", i.label, size_text(i.bytes)))
        .collect();
    format!(
        "{} layout, breakdown of {root}: {}",
        layout.name(),
        parts.join(", ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use gpui_kit::hsla;

    fn items(sizes: &[u64]) -> Vec<ChartItem> {
        sizes
            .iter()
            .enumerate()
            .map(|(i, &bytes)| ChartItem {
                label: format!("item{i}"),
                bytes,
                color: hsla(0.5, 0.5, 0.5, 1.0),
                activatable: i % 2 == 0,
                inert: false,
            })
            .collect()
    }

    fn total(items: &[ChartItem]) -> u64 {
        items.iter().map(|i| i.bytes).sum()
    }

    #[test]
    fn tiles_with_free_keep_the_free_share_left_of_the_tiles() {
        let items = items(&[600, 300, 100]);
        let (field, labels) = layout_field(
            &items,
            total(&items),
            Some(1000),
            StorageLayout::Tiles,
            100,
            50,
        );
        let free = field.free.expect("free region");
        assert_eq!(free.x, 0);
        assert!((48..=50).contains(&free.w), "{free:?}");
        assert!(field.segments.iter().all(|s| s.rect.x >= 50));
        assert!(labels.iter().any(|l| l.index.is_none() && l.show_text));
    }

    #[test]
    fn tiles_without_free_use_the_whole_field() {
        let items = items(&[600, 300, 100]);
        let (field, _) = layout_field(&items, 1000, None, StorageLayout::Tiles, 100, 50);
        assert!(field.free.is_none());
        let right: u16 = field
            .segments
            .iter()
            .map(|s| s.rect.x + s.rect.w)
            .max()
            .unwrap_or(0);
        assert!(right >= 98, "{right}");
    }

    #[test]
    fn only_large_tiles_carry_a_label() {
        let items = items(&[900_000, 90_000, 10]);
        let (field, labels) =
            layout_field(&items, total(&items), None, StorageLayout::Tiles, 100, 50);
        assert!(field.segments[0].label_rect.is_some());
        assert!(labels[0].show_text);
        let tiny = labels
            .iter()
            .find(|l| l.index == Some(2))
            .map(|l| l.show_text);
        assert_ne!(tiny, Some(true));
    }

    #[test]
    fn band_is_one_strip_with_free_at_the_right() {
        let items = items(&[500, 300, 200]);
        let (field, _) = layout_field(
            &items,
            1000,
            Some(1000),
            StorageLayout::Band,
            120,
            BAND_ROWS,
        );
        assert_eq!(field.rows, BAND_ROWS);
        let free = field.free.expect("free");
        assert!(field.segments.iter().all(|s| s.rect.x + s.rect.w <= free.x));
        assert!(field.segments.iter().all(|s| s.rect.h == BAND_ROWS));
    }

    #[test]
    fn columns_are_bottom_aligned_and_the_largest_is_full_height() {
        let items = items(&[800, 400, 100]);
        let (field, labels) = layout_field(&items, 1300, None, StorageLayout::Columns, 100, 50);
        assert_eq!(field.segments[0].rect.h, 50);
        assert_eq!(field.segments[1].rect.h, 25);
        assert!(field.segments.iter().all(|s| s.rect.y + s.rect.h == 50));
        assert_eq!(field.segments[0].rect.w, 6);
        assert_eq!(field.segments[1].rect.x, 9);
        assert!(
            labels
                .iter()
                .all(|l| l.place == LabelPlace::Below && l.show_text)
        );
    }

    #[test]
    fn the_lattice_is_clamped() {
        let (columns, rows) = clamp_lattice(u16::MAX, 100);
        assert!(usize::from(columns) * usize::from(rows) <= MAX_CELLS);
    }

    #[test]
    fn focus_dims_the_other_segments() {
        let items = items(&[3, 2, 1]);
        let (mut field, _) = layout_field(&items, 6, None, StorageLayout::Band, 60, BAND_ROWS);
        apply_focus(&mut field, Some(1));
        let dimmed: Vec<bool> = field.segments.iter().map(|s| s.dimmed).collect();
        assert_eq!(dimmed, [true, false, true]);
    }

    #[test]
    fn scale_caption_rounds_and_never_says_zero_bytes() {
        assert_eq!(scale_caption(0, 0), "Nothing was measured.");
        assert_eq!(scale_caption(0, 100), "1 cell < 1 B");
        assert_eq!(scale_caption(1, 100), "1 cell = 1 B");
    }
}
