//! The LED matrix: one fine lattice of cells, with segments painted into it.
//!
//! The layout is pure data (`LedField`). `paint_led_field` paints a whole
//! chart from one canvas; no element exists per cell.

use crate::{
    theme::tokens::{Tokens, to_hsla},
    viz::treemap::CellRect,
};
use gpui_kit::{
    App, BorderStyle, Bounds, BoxShadow, Corners, Edges, FontWeight, Hsla, InteractiveElement as _,
    IntoElement, MouseButton, ParentElement as _, Pixels, Point, RenderOnce, Role, SharedString,
    StatefulInteractiveElement as _, Styled as _, TestSupportExt as _, Window, canvas,
    component::ActiveTheme as _, div, fill, hsla, point, px, quad, size,
};
use std::rc::Rc;

/// The most cells that one chart may have.
pub const MAX_CELLS: usize = 8_000;
/// The smallest tile that carries a label, in cells.
pub const LABEL_MIN_COLUMNS: u16 = 16;
/// The smallest tile height that carries a label, in cells.
pub const LABEL_MIN_ROWS: u16 = 9;
/// The rows that a tile label covers.
pub const LABEL_ROWS: u16 = 8;

/// The tone of one cell inside a segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CellTone {
    /// Bright: the color mixed toward white.
    Lit,
    /// Faint: the color at low alpha.
    Dim,
}

/// A 32-bit integer mix (the finalizer of `MurmurHash3`).
const fn mix(mut h: u32) -> u32 {
    h ^= h >> 16;
    h = h.wrapping_mul(0x85eb_ca6b);
    h ^= h >> 13;
    h = h.wrapping_mul(0xc2b2_ae35);
    h ^ (h >> 16)
}

/// Hashes a lattice position and a seed.
#[must_use]
pub const fn cell_hash(x: u32, y: u32, seed: u32) -> u32 {
    mix(x.wrapping_mul(0x9e37_79b1) ^ mix(y.wrapping_mul(0x85eb_ca77) ^ mix(seed)))
}

/// The tone of the cell `(x, y)` of a segment with `seed`.
///
/// A hash of the 2 by 2 block (weight 3) joins a hash of the cell (weight 1),
/// so that neighbours tend to agree. About 45% of the cells are lit. The
/// result depends on nothing else: it is the same in each frame and each run.
#[must_use]
pub const fn cell_tone(x: u16, y: u16, seed: u32) -> CellTone {
    cell_tone_at(x, y, seed, DEFAULT_THRESHOLD)
}

/// The default threshold of [`cell_tone`]: about 45% of the cells are lit.
const DEFAULT_THRESHOLD: u32 = 472;

/// The lit share of a segment for a density `0.0..=1.0`: 20% plus 70% of the
/// density. `None` (and a value that is not a number) gives the default 45%.
#[must_use]
pub fn lit_share(density: Option<f32>) -> f32 {
    match density {
        Some(d) if d.is_finite() => 0.20 + 0.70 * d.clamp(0.0, 1.0),
        _ => 0.45,
    }
}

/// How many of the 65 536 pairs `(block, own)` have `block * 3 + own <= t`.
fn pairs_up_to(t: u32) -> u32 {
    (0..256_u32)
        .filter(|b| t >= b * 3)
        .map(|b| (t - b * 3 + 1).min(256))
        .sum()
}

/// The threshold of the tone sum for a lit `share`: the smallest value whose
/// part of all sums reaches the share. It grows with the share, so a larger
/// share adds lit cells and moves none.
#[must_use]
pub fn lit_threshold(share: Option<f32>) -> u32 {
    let Some(share) = share.filter(|s| s.is_finite()) else {
        return DEFAULT_THRESHOLD;
    };
    let share: f64 = f64::from(share.clamp(0.0, 1.0));
    let target: f64 = share * 65_536.0;
    let (mut low, mut high): (u32, u32) = (0, 1_021);
    while low < high {
        let mid: u32 = u32::midpoint(low, high);
        if f64::from(pairs_up_to(mid)) >= target {
            high = mid;
        } else {
            low = mid + 1;
        }
    }
    // The tone is lit when the sum is below the threshold.
    low + 1
}

/// The tone of a cell for a threshold from [`lit_threshold`].
#[must_use]
pub const fn cell_tone_at(x: u16, y: u16, seed: u32, threshold: u32) -> CellTone {
    let block: u32 = cell_hash((x / 2) as u32, (y / 2) as u32, seed) >> 24;
    let own: u32 = cell_hash(x as u32, y as u32, seed ^ 0x5bd1_e995) >> 24;
    if block * 3 + own < threshold {
        CellTone::Lit
    } else {
        CellTone::Dim
    }
}

/// Whether the free region draws a bright point at `(x, y)`: 1 cell in 60.
#[must_use]
pub const fn free_point(x: u16, y: u16) -> bool {
    cell_hash(x as u32, y as u32, 0xf4ee).is_multiple_of(60)
}

/// The axis along which a segment fills up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FillAxis {
    /// From the left edge.
    Horizontal,
    /// From the bottom edge.
    Vertical,
}

/// The end of a segment, where the scan ghost marks a change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndEdge {
    /// The right edge; the last cells are the rightmost columns.
    Right,
    /// The top edge; the last cells are the top rows.
    Top,
}

/// Whether the cell `(x, y)` is among the last `count` cells of `rect` in the
/// order of `edge`.
#[must_use]
pub fn in_last_cells(rect: CellRect, edge: EndEdge, count: u32, x: u16, y: u16) -> bool {
    if count == 0 || !rect.contains(x, y) {
        return false;
    }
    let (w, h): (u32, u32) = (u32::from(rect.w), u32::from(rect.h));
    let index: u32 = match edge {
        EndEdge::Right => u32::from(x - rect.x) * h + u32::from(y - rect.y),
        EndEdge::Top => u32::from(rect.y + rect.h - 1 - y) * w + u32::from(x - rect.x),
    };
    index + count >= w * h
}

/// One segment of a field.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LedSegment {
    /// The cells of the segment.
    pub rect: CellRect,
    /// The color.
    pub color: Hsla,
    /// The seed of the tone pattern.
    pub seed: u32,
    /// The part of the rectangle that is filled along `axis`, `0.0..=1.0`.
    /// Cells beyond it show the empty lattice.
    pub fill: f32,
    /// The direction of the fill.
    pub axis: FillAxis,
    /// The cells under the label text block, forced dim.
    pub label_rect: Option<CellRect>,
    /// Whether the segment is de-emphasized: dim cells, half outline, no glow.
    pub dimmed: bool,
    /// The density `0.0..=1.0` that sets the lit share; `None` is 45%.
    pub density: Option<f32>,
    /// The cells at the end of the segment that the scan ghost hatches.
    pub growth_cells: u32,
    /// Whether the scan ghost draws the dashed line of a smaller item.
    pub shrunk: bool,
    /// The end of the segment for the ghost.
    pub end_edge: EndEdge,
}

impl LedSegment {
    /// A full segment without a label band.
    #[must_use]
    pub const fn new(rect: CellRect, color: Hsla, seed: u32) -> Self {
        Self {
            rect,
            color,
            seed,
            fill: 1.0,
            axis: FillAxis::Horizontal,
            label_rect: None,
            dimmed: false,
            density: None,
            growth_cells: 0,
            shrunk: false,
            end_edge: EndEdge::Right,
        }
    }
}

/// A bright block of cells, for the front of a fill.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LedHead {
    /// The cells of the head. The rightmost column is the front.
    pub rect: CellRect,
    /// The color under the white: the color of the last block.
    pub color: Hsla,
}

/// The white weight of column `index` of a head of `width` columns: 1.0 at
/// the front (the last column), then 0.6, then 0.3, and 0.15 beyond.
#[must_use]
pub fn head_white(index: u16, width: u16) -> f32 {
    match width.saturating_sub(1).saturating_sub(index) {
        0 => 1.0,
        1 => 0.6,
        2 => 0.3,
        _ => 0.15,
    }
}

/// The brightness `0.0..=1.0` of the free point at `(x, y)` at `phase`
/// seconds. Each point has its own period (2.5 s to 5 s) and offset from its
/// hash; about a third of the points are visible at a time.
#[must_use]
pub fn twinkle(x: u16, y: u16, phase: f32) -> f32 {
    let h: u32 = cell_hash(u32::from(x), u32::from(y), 0x7717);
    let period: f32 = 2.5 + f32::from(u8::try_from(h & 0xff).unwrap_or(0)) / 255.0 * 2.5;
    let offset: f32 = f32::from(u16::try_from((h >> 8) & 0xffff).unwrap_or(0)) / 65_535.0 * period;
    let turn: f32 = ((phase + offset) / period).rem_euclid(1.0);
    let pulse: f32 = (turn * std::f32::consts::PI).sin().powi(2);
    ((pulse - 0.75) / 0.25).clamp(0.0, 1.0)
}

/// The data of one chart.
#[derive(Debug, Clone, PartialEq)]
pub struct LedField {
    /// Columns of the lattice.
    pub columns: u16,
    /// Rows of the lattice.
    pub rows: u16,
    /// The segments, in paint order.
    pub segments: Vec<LedSegment>,
    /// The free region: a dashed outline, the lattice, and a few points.
    pub free: Option<CellRect>,
    /// The bright head.
    pub head: Option<LedHead>,
    /// The time in seconds that drives the twinkle of the free points;
    /// `None` leaves the points static.
    pub phase: Option<f32>,
}

/// Pixel measures and colors of a chart, from the tokens of one theme.
#[derive(Debug, Clone, Copy)]
pub struct LedStyle {
    /// Distance from cell to cell.
    pub pitch: f32,
    /// Side of one cell.
    pub cell: f32,
    /// Corner radius of a cell.
    pub cell_radius: f32,
    /// Width of a segment outline.
    pub outline: f32,
    /// Corner radius of an outline.
    pub outline_radius: f32,
    /// The color of an empty cell.
    pub lattice: Hsla,
    /// The alpha of the glow. Zero turns off the glow of the segments and
    /// of the head.
    pub glow_alpha: f32,
    /// The alpha of a dim cell.
    pub dim_alpha: f32,
    /// The color of the free points.
    pub point: Hsla,
    /// The color of the free outline.
    pub free_outline: Hsla,
    /// The color of the marks of the scan ghost: the lit cells of a hatched
    /// part and the dashed line of a smaller item. It is the text color, so
    /// the marks differ from the density texture in each theme.
    pub ghost_line: Hsla,
}

impl LedStyle {
    /// The style of the dark or the light theme.
    #[must_use]
    pub fn for_dark(dark: bool) -> Self {
        let tokens: &Tokens = Tokens::for_dark(dark);
        let lattice: Hsla = to_hsla(tokens.border);
        Self {
            pitch: 6.0,
            cell: 4.5,
            cell_radius: 1.0,
            outline: 1.5,
            outline_radius: 6.0,
            lattice: lattice.opacity(0.5),
            glow_alpha: if dark { 0.45 } else { 0.22 },
            dim_alpha: if dark { 0.28 } else { 0.22 },
            point: to_hsla(tokens.foreground).opacity(0.8),
            free_outline: to_hsla(tokens.muted_foreground).opacity(0.35),
            ghost_line: to_hsla(tokens.foreground).opacity(0.85),
        }
    }

    /// The pixel width of `columns` cells, without the trailing gap.
    #[must_use]
    pub fn span(&self, cells: u16) -> f32 {
        if cells == 0 {
            0.0
        } else {
            f32::from(cells) * self.pitch - (self.pitch - self.cell)
        }
    }
}

/// The color mixed 15% toward white.
#[must_use]
pub fn lit_color(color: Hsla) -> Hsla {
    let white: Hsla = hsla(0.0, 0.0, 1.0, color.a);
    let mixed = color.to_rgb();
    let target = white.to_rgb();
    let blend = |a: f32, b: f32| a + (b - a) * 0.15;
    Hsla::from(gpui_kit::Rgba {
        r: blend(mixed.r, target.r),
        g: blend(mixed.g, target.g),
        b: blend(mixed.b, target.b),
        a: color.a,
    })
}

/// Converts a rounded, non-negative float to cells, saturating.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "the value is rounded and clamped to the cell range first"
)]
fn to_cells(value: f32) -> u16 {
    value.clamp(0.0, f32::from(u16::MAX)) as u16
}

/// How many cells of `len` the fill `fraction` lights.
fn filled_cells(len: u16, fraction: f32) -> u16 {
    let wanted: f32 = (f32::from(len) * fraction.clamp(0.0, 1.0)).ceil();
    to_cells(wanted).min(len)
}

/// Paints a whole field from `bounds`: shadows, lattice, cells, outlines.
#[expect(clippy::too_many_lines, reason = "one pass in paint order")]
pub fn paint_led_field(
    field: &LedField,
    bounds: Bounds<Pixels>,
    style: &LedStyle,
    window: &mut Window,
) {
    let columns: usize = usize::from(field.columns);
    let rows: usize = usize::from(field.rows);
    if columns == 0 || rows == 0 || columns * rows > MAX_CELLS {
        return;
    }
    let pitch: f32 = style.pitch;
    let cell_bounds = |x: u16, y: u16| -> Bounds<Pixels> {
        Bounds::new(
            point(
                bounds.origin.x + px(f32::from(x) * pitch),
                bounds.origin.y + px(f32::from(y) * pitch),
            ),
            size(px(style.cell), px(style.cell)),
        )
    };
    let rect_bounds = |rect: CellRect| -> Bounds<Pixels> {
        Bounds::new(
            point(
                bounds.origin.x + px(f32::from(rect.x) * pitch),
                bounds.origin.y + px(f32::from(rect.y) * pitch),
            ),
            size(px(style.span(rect.w)), px(style.span(rect.h))),
        )
    };
    let outline_bounds = |rect: CellRect| -> Bounds<Pixels> {
        let b: Bounds<Pixels> = rect_bounds(rect);
        Bounds::new(
            point(b.origin.x - px(1.0), b.origin.y - px(1.0)),
            size(b.size.width + px(2.0), b.size.height + px(2.0)),
        )
    };
    let radii: Corners<Pixels> = Corners::all(px(style.outline_radius));
    // Glow first: the cells and the outlines cover it.
    let glow_on: bool = style.glow_alpha > 0.0;
    for segment in field
        .segments
        .iter()
        .filter(|s| glow_on && !s.dimmed && !s.rect.is_empty())
    {
        let shadow: BoxShadow = BoxShadow {
            color: segment.color.opacity(style.glow_alpha),
            offset: Point::default(),
            blur_radius: px(14.0),
            spread_radius: px(0.0),
            inset: false,
        };
        window.paint_drop_shadows(outline_bounds(segment.rect), radii, &[shadow]);
    }
    // The lattice: each cell that no segment paints.
    let mut owned: Vec<bool> = vec![false; columns * rows];
    for segment in &field.segments {
        let r: CellRect = segment.rect;
        for y in r.y..r.y.saturating_add(r.h).min(field.rows) {
            for x in r.x..r.x.saturating_add(r.w).min(field.columns) {
                let filled: bool = match segment.axis {
                    FillAxis::Horizontal => x - r.x < filled_cells(r.w, segment.fill),
                    FillAxis::Vertical => r.y + r.h - 1 - y < filled_cells(r.h, segment.fill),
                };
                if filled {
                    owned[usize::from(y) * columns + usize::from(x)] = true;
                }
            }
        }
    }
    let cell_radii: Corners<Pixels> = Corners::all(px(style.cell_radius));
    for y in 0..field.rows {
        for x in 0..field.columns {
            if owned[usize::from(y) * columns + usize::from(x)] {
                continue;
            }
            window.paint_quad(fill(cell_bounds(x, y), style.lattice).corner_radii(cell_radii));
            let brightness: f32 = field.phase.map_or(1.0, |phase| twinkle(x, y, phase));
            if field.free.is_some_and(|r| r.contains(x, y)) && free_point(x, y) && brightness > 0.0
            {
                let c: Bounds<Pixels> = cell_bounds(x, y);
                let inset: Pixels = px((style.cell - 3.0) / 2.0);
                let dot: Bounds<Pixels> = Bounds::new(
                    point(c.origin.x + inset, c.origin.y + inset),
                    size(px(3.0), px(3.0)),
                );
                window.paint_quad(
                    fill(dot, style.point.opacity(style.point.a * brightness))
                        .corner_radii(Corners::all(px(1.5))),
                );
            }
        }
    }
    // A faint inner tint under the cells: the block reads as lit glass.
    for segment in field
        .segments
        .iter()
        .filter(|s| !s.dimmed && !s.rect.is_empty())
    {
        window.paint_quad(
            fill(rect_bounds(segment.rect), segment.color.opacity(0.08)).corner_radii(radii),
        );
    }
    // The cells of each segment.
    for segment in &field.segments {
        let r: CellRect = segment.rect;
        let lit: Hsla = lit_color(segment.color);
        let dim: Hsla = segment.color.opacity(style.dim_alpha);
        let threshold: u32 = lit_threshold(segment.density.map(|d| lit_share(Some(d))));
        for y in r.y..r.y.saturating_add(r.h).min(field.rows) {
            for x in r.x..r.x.saturating_add(r.w).min(field.columns) {
                if !owned[usize::from(y) * columns + usize::from(x)] {
                    continue;
                }
                let in_label: bool = segment.label_rect.is_some_and(|b| b.contains(x, y));
                let hatched: bool = in_last_cells(r, segment.end_edge, segment.growth_cells, x, y);
                if hatched && (x + y) % 2 == 1 {
                    // A checkerboard: the odd cells of the growth are empty.
                    window.paint_quad(
                        fill(cell_bounds(x, y), style.lattice).corner_radii(cell_radii),
                    );
                    continue;
                }
                let tone: CellTone = if segment.dimmed || in_label {
                    CellTone::Dim
                } else if hatched {
                    CellTone::Lit
                } else {
                    cell_tone_at(x, y, segment.seed, threshold)
                };
                let color: Hsla = match tone {
                    // A hatched cell is not a cell of the density texture.
                    CellTone::Lit if hatched && !segment.dimmed && !in_label => style.ghost_line,
                    CellTone::Lit => lit,
                    CellTone::Dim => dim,
                };
                window.paint_quad(fill(cell_bounds(x, y), color).corner_radii(cell_radii));
            }
        }
    }
    if let Some(head) = field.head.filter(|h| !h.rect.is_empty()) {
        let r: CellRect = head.rect;
        let glow: BoxShadow = BoxShadow {
            color: hsla(0.0, 0.0, 1.0, 0.5),
            offset: Point::default(),
            blur_radius: px(16.0),
            spread_radius: px(0.0),
            inset: false,
        };
        if glow_on {
            window.paint_drop_shadows(rect_bounds(r), Corners::all(px(2.0)), &[glow]);
        }
        let base: Hsla = lit_color(head.color);
        for y in r.y..r.y.saturating_add(r.h).min(field.rows) {
            for x in r.x..r.x.saturating_add(r.w).min(field.columns) {
                window.paint_quad(fill(cell_bounds(x, y), base).corner_radii(cell_radii));
                let white: Hsla = hsla(0.0, 0.0, 1.0, head_white(x - r.x, r.w));
                window.paint_quad(fill(cell_bounds(x, y), white).corner_radii(cell_radii));
            }
        }
    }
    // Outlines last, on top of the cells.
    for segment in field.segments.iter().filter(|s| !s.rect.is_empty()) {
        let alpha: f32 = if segment.dimmed { 0.35 } else { 1.0 };
        window.paint_quad(quad(
            outline_bounds(segment.rect),
            radii,
            hsla(0.0, 0.0, 0.0, 0.0),
            Edges::all(px(style.outline)),
            segment.color.opacity(alpha),
            BorderStyle::Solid,
        ));
    }
    // A smaller item: a dashed 1.5 px line along the end edge, in the middle
    // of the last column or row of cells.
    for segment in field
        .segments
        .iter()
        .filter(|s| s.shrunk && !s.rect.is_empty())
    {
        let b: Bounds<Pixels> = rect_bounds(segment.rect);
        let horizontal: bool = segment.end_edge == EndEdge::Top;
        let length: f32 = if horizontal {
            f32::from(b.size.width)
        } else {
            f32::from(b.size.height)
        };
        let mut at: f32 = 0.0;
        while at < length {
            let dash: f32 = 4.0_f32.min(length - at);
            let (origin, extent) = if horizontal {
                (
                    point(
                        b.origin.x + px(at),
                        b.origin.y + px(style.cell / 2.0 - 0.75),
                    ),
                    size(px(dash), px(1.5)),
                )
            } else {
                (
                    point(
                        b.origin.x + b.size.width - px(style.cell / 2.0 + 0.75),
                        b.origin.y + px(at),
                    ),
                    size(px(1.5), px(dash)),
                )
            };
            window.paint_quad(fill(Bounds::new(origin, extent), style.ghost_line));
            at += 7.0;
        }
    }
    if let Some(free) = field.free.filter(|r| !r.is_empty()) {
        window.paint_quad(quad(
            outline_bounds(free),
            radii,
            hsla(0.0, 0.0, 0.0, 0.0),
            Edges::all(px(1.0)),
            style.free_outline,
            BorderStyle::Dashed,
        ));
    }
}

/// A swatch of `columns` by `rows` cells with the lit `share`, painted with
/// the cell rule of a segment in `color`. The key of the density texture uses
/// it.
pub fn density_swatch(
    share: f32,
    columns: u16,
    rows: u16,
    color: Hsla,
    dark: bool,
) -> impl IntoElement {
    let style: LedStyle = LedStyle::for_dark(dark);
    let threshold: u32 = lit_threshold(Some(share));
    let width: f32 = style.span(columns);
    let height: f32 = style.span(rows);
    div().w(px(width)).h(px(height)).flex_shrink_0().child(
        canvas(
            |_, _, _| (),
            move |bounds: Bounds<Pixels>, (), window: &mut Window, _: &mut App| {
                let radii: Corners<Pixels> = Corners::all(px(style.cell_radius));
                for y in 0..rows {
                    for x in 0..columns {
                        let tone: CellTone = cell_tone_at(x, y, 0x51ab, threshold);
                        let paint: Hsla = match tone {
                            CellTone::Lit => lit_color(color),
                            CellTone::Dim => color.opacity(style.dim_alpha),
                        };
                        let cell = Bounds::new(
                            point(
                                bounds.origin.x + px(f32::from(x) * style.pitch),
                                bounds.origin.y + px(f32::from(y) * style.pitch),
                            ),
                            size(px(style.cell), px(style.cell)),
                        );
                        window.paint_quad(fill(cell, paint).corner_radii(radii));
                    }
                }
            },
        )
        .size_full(),
    )
}

/// Pixel offset of the label text from the left of its tile.
const LABEL_LEFT_PX: f32 = 10.0;
/// Pixel offset of the label text from the top of its tile.
const LABEL_TOP_PX: f32 = 8.0;
/// Estimated height of the two text lines.
const LABEL_HEIGHT_PX: f32 = 36.0;
/// Estimated width of one label character.
const LABEL_CHAR_PX: f32 = 7.5;
/// The horizontal padding of the plate of a label inside a tile. The plate
/// is a part of the chart, so its padding is chart geometry.
const LABEL_PLATE_X: f32 = 6.0;
/// The vertical padding of the plate of a label inside a tile.
const LABEL_PLATE_Y: f32 = 4.0;

/// The cells under a label text block of two lines at the top left of `rect`,
/// with one cell of padding, clipped to `rect`. Cell coordinates are absolute.
#[must_use]
pub fn label_block(rect: CellRect, name: &str, size: &str, pitch: f32) -> CellRect {
    #[expect(
        clippy::cast_precision_loss,
        reason = "a label is far shorter than 2^24"
    )]
    let chars: f32 = name.chars().count().max(size.chars().count()) as f32;
    let max_w: f32 = (f32::from(rect.w) * pitch - 20.0).max(0.0);
    let text_w: f32 = (chars * LABEL_CHAR_PX).min(max_w);
    let cells = |px: f32| -> u16 { to_cells((px / pitch).ceil()) };
    let x0: u16 = to_cells((LABEL_LEFT_PX / pitch).floor()).saturating_sub(1);
    let y0: u16 = to_cells((LABEL_TOP_PX / pitch).floor()).saturating_sub(1);
    let x1: u16 = (cells(LABEL_LEFT_PX + text_w) + 1).min(rect.w);
    let y1: u16 = (cells(LABEL_TOP_PX + LABEL_HEIGHT_PX) + 1).min(rect.h);
    CellRect::new(
        rect.x + x0,
        rect.y + y0,
        x1.saturating_sub(x0),
        y1.saturating_sub(y0),
    )
}

/// Where a label sits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabelPlace {
    /// Inside the top-left corner of the rectangle.
    Inside,
    /// Under the rectangle, outside the canvas.
    Below,
}

/// A label, and the hit area, of one segment or of the free region.
#[derive(Debug, Clone, PartialEq)]
pub struct TileLabel {
    /// The index of the segment in the input items; `None` for the free region.
    pub index: Option<usize>,
    /// The cells of the segment.
    pub rect: CellRect,
    /// The name.
    pub name: String,
    /// The size text.
    pub size: String,
    /// Whether the text is shown; the legend names the tiles without text.
    pub show_text: bool,
    /// Where the text sits.
    pub place: LabelPlace,
    /// Whether a click opens the segment.
    pub activatable: bool,
}

type SelectHandler = Rc<dyn Fn(usize, &mut Window, &mut App)>;

/// A chart: the canvas of a field and the labels over it.
#[derive(IntoElement)]
pub struct LedChart {
    field: LedField,
    labels: Vec<TileLabel>,
    id: SharedString,
    label: SharedString,
    on_select: Option<SelectHandler>,
}

impl std::fmt::Debug for LedChart {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LedChart")
            .field("label", &self.label)
            .field("segments", &self.field.segments.len())
            .finish_non_exhaustive()
    }
}

impl LedChart {
    /// Creates a chart with an element id and an accessible label.
    pub fn new(
        field: LedField,
        labels: Vec<TileLabel>,
        id: impl Into<SharedString>,
        label: impl Into<SharedString>,
    ) -> Self {
        Self {
            field,
            labels,
            id: id.into(),
            label: label.into(),
            on_select: None,
        }
    }

    /// Sets the handler of a click on an activatable tile; it gets the index.
    #[must_use]
    pub fn on_select(mut self, f: impl Fn(usize, &mut Window, &mut App) + 'static) -> Self {
        self.on_select = Some(Rc::new(f));
        self
    }
}

impl RenderOnce for LedChart {
    #[expect(
        clippy::too_many_lines,
        reason = "one build of the chart and its labels"
    )]
    fn render(self, _window: &mut Window, cx: &mut App) -> impl IntoElement {
        let dark: bool = cx.theme().is_dark();
        let tokens: &Tokens = Tokens::for_dark(dark);
        let mut style: LedStyle = LedStyle::for_dark(dark);
        if !crate::theme::glow::enabled(cx) {
            style.glow_alpha = 0.0;
        }
        let mono: SharedString = cx.theme().mono_font_family.clone();
        let plate: Hsla = to_hsla(tokens.surface_inset).opacity(0.86);
        let width: f32 = style.span(self.field.columns);
        let height: f32 = style.span(self.field.rows);
        let has_below: bool = self.labels.iter().any(|l| l.place == LabelPlace::Below);
        let field: LedField = self.field;
        let mut root = div()
            .id(self.id.clone())
            .role(Role::Image)
            .test_support()
            .aria_label(self.label)
            .relative()
            .w(px(width))
            .h(px(height + if has_below { 48.0 } else { 0.0 }))
            .flex_shrink_0()
            .child(
                div()
                    .absolute()
                    .top_0()
                    .left_0()
                    .w(px(width))
                    .h(px(height))
                    .child(
                        canvas(
                            |_, _, _| (),
                            move |bounds: Bounds<Pixels>, (), window: &mut Window, _: &mut App| {
                                paint_led_field(&field, bounds, &style, window);
                            },
                        )
                        .size_full(),
                    ),
            );
        let foreground: Hsla = to_hsla(tokens.foreground);
        let muted: Hsla = to_hsla(tokens.muted_foreground);
        for (n, label) in self.labels.into_iter().enumerate() {
            let left: f32 = f32::from(label.rect.x) * style.pitch;
            let top: f32 = f32::from(label.rect.y) * style.pitch;
            let w: f32 = style.span(label.rect.w);
            let h: f32 = style.span(label.rect.h);
            let free: bool = label.index.is_none();
            if label.activatable
                && let (Some(index), Some(handler)) = (label.index, self.on_select.clone())
            {
                {
                    root = root.child(
                        div()
                            .id(SharedString::from(format!("{}-tile-{index}", self.id)))
                            .absolute()
                            .left(px(left))
                            .top(px(top))
                            .w(px(w))
                            .h(px(h))
                            .cursor_pointer()
                            .on_mouse_down(MouseButton::Left, |_, window, _| {
                                window.prevent_default();
                            })
                            .on_click(move |_, window, app| handler(index, window, app)),
                    );
                }
            }
            if !label.show_text {
                continue;
            }
            let (name_color, size_color): (Hsla, Hsla) = if free {
                (muted, muted)
            } else {
                (foreground, foreground.opacity(0.8))
            };
            // A label inside a tile sits on a plate in the color of the
            // panel, so the text does not sit on the cell pattern.
            let inside: bool = label.place == LabelPlace::Inside && !free;
            let text = div()
                .id(SharedString::from(format!("{}-label-{n}", self.id)))
                .absolute()
                .overflow_hidden()
                .max_w(px(match label.place {
                    LabelPlace::Inside => (w - 20.0).max(0.0),
                    LabelPlace::Below => f32::from(label.rect.w + 3) * style.pitch,
                }))
                .child(
                    div()
                        .text_size(px(13.0))
                        .font_weight(FontWeight::MEDIUM)
                        .text_color(name_color)
                        .whitespace_nowrap()
                        .text_ellipsis()
                        .child(label.name),
                )
                .child(
                    div()
                        .font_family(mono.clone())
                        .text_size(px(12.0))
                        .text_color(size_color)
                        .whitespace_nowrap()
                        .child(label.size),
                );
            let text = if inside {
                text.bg(plate)
                    .rounded(px(6.0))
                    .px(px(LABEL_PLATE_X))
                    .py(px(LABEL_PLATE_Y))
            } else {
                text
            };
            let (pad_x, pad_y): (f32, f32) = if inside {
                (LABEL_PLATE_X, LABEL_PLATE_Y)
            } else {
                (0.0, 0.0)
            };
            root = root.child(match label.place {
                LabelPlace::Inside => text
                    .left(px(left + 10.0 - pad_x))
                    .top(px(top + 8.0 - pad_y)),
                LabelPlace::Below => text.left(px(left)).top(px(height + 6.0)),
            });
        }
        root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_lit_share_follows_the_density() {
        assert!((lit_share(None) - 0.45).abs() < 1e-6);
        assert!((lit_share(Some(0.0)) - 0.20).abs() < 1e-6);
        assert!((lit_share(Some(1.0)) - 0.90).abs() < 1e-6);
        assert!((lit_share(Some(7.0)) - 0.90).abs() < 1e-6, "clamped");
        assert!((lit_share(Some(f32::NAN)) - 0.45).abs() < 1e-6);
    }

    #[test]
    fn a_larger_share_only_adds_lit_cells() {
        let count = |share: f32| -> (usize, Vec<bool>) {
            let t = lit_threshold(Some(share));
            let lit: Vec<bool> = (0..60_u16)
                .flat_map(|y| (0..60_u16).map(move |x| (x, y)))
                .map(|(x, y)| cell_tone_at(x, y, 7, t) == CellTone::Lit)
                .collect();
            (lit.iter().filter(|l| **l).count(), lit)
        };
        let (low, a) = count(0.2);
        let (mid, b) = count(0.5);
        let (high, c) = count(0.9);
        assert!(low < mid && mid < high);
        assert!(a.iter().zip(&b).all(|(x, y)| !*x || *y));
        assert!(b.iter().zip(&c).all(|(x, y)| !*x || *y));
        // The share is near the asked value.
        let total = 3_600.0_f32;
        for (n, want) in [(low, 0.2_f32), (mid, 0.5), (high, 0.9)] {
            let got = f32::from(u16::try_from(n).unwrap_or(0)) / total;
            assert!((got - want).abs() < 0.08, "{got} vs {want}");
        }
        assert_eq!(lit_threshold(None), 472);
    }

    #[test]
    fn the_last_cells_follow_the_end_edge() {
        let r = CellRect::new(2, 3, 4, 3);
        let n = |edge| {
            (0..12_u16)
                .flat_map(|y| (0..12_u16).map(move |x| (x, y)))
                .filter(|(x, y)| in_last_cells(r, edge, 5, *x, *y))
                .count()
        };
        assert_eq!(n(EndEdge::Right), 5);
        assert_eq!(n(EndEdge::Top), 5);
        assert!(in_last_cells(r, EndEdge::Right, 3, 5, 5), "bottom right");
        assert!(!in_last_cells(r, EndEdge::Right, 3, 2, 3), "first cell");
        assert!(in_last_cells(r, EndEdge::Top, 4, 2, 3), "top left");
        assert!(!in_last_cells(r, EndEdge::Top, 0, 2, 3));
    }

    #[test]
    fn the_label_block_covers_the_text_and_one_cell_of_padding_only() {
        let tile = CellRect::new(10, 4, 40, 20);
        let block = label_block(tile, "Pictures", "12.3 GB", 6.0);
        // 8 characters at 7.5 px, plus the 10 px offset: 70 px, 12 cells, +1.
        assert_eq!((block.x, block.y), (10, 4));
        assert_eq!(block.w, 13);
        assert_eq!(block.h, 9);
        assert!(block.w < tile.w && block.h < tile.h);
        // A narrow tile clips the block to the tile.
        let narrow = label_block(
            CellRect::new(0, 0, 16, 9),
            "A very long folder name",
            "1 GB",
            6.0,
        );
        assert!(narrow.w <= 16 && narrow.h <= 9);
    }

    #[test]
    fn the_tone_is_stable() {
        for (x, y, seed) in [(0_u16, 0_u16, 1_u32), (7, 3, 99), (200, 50, 12345)] {
            assert_eq!(cell_tone(x, y, seed), cell_tone(x, y, seed));
        }
    }

    #[test]
    fn about_half_of_a_block_is_lit() {
        for seed in [1_u32, 2, 77, 0xdead_beef] {
            let lit: usize = (0..40_u16)
                .flat_map(|y| (0..40_u16).map(move |x| (x, y)))
                .filter(|&(x, y)| cell_tone(x, y, seed) == CellTone::Lit)
                .count();
            let share: f64 = f64::from(u32::try_from(lit).unwrap_or(0)) / 1600.0;
            assert!((0.35..=0.55).contains(&share), "seed {seed}: {share}");
        }
    }

    #[test]
    fn neighbours_agree_more_than_chance() {
        let mut same: usize = 0;
        let mut total: usize = 0;
        for y in 0..40_u16 {
            for x in (0..40_u16).step_by(2) {
                total += 1;
                if cell_tone(x, y, 5) == cell_tone(x + 1, y, 5) {
                    same += 1;
                }
            }
        }
        // Independent cells at 45% agree in 50.5% of the pairs.
        assert!(same * 100 > total * 65, "{same} of {total}");
    }

    #[test]
    fn free_points_are_about_one_in_sixty() {
        let n: usize = (0..100_u16)
            .flat_map(|y| (0..100_u16).map(move |x| (x, y)))
            .filter(|&(x, y)| free_point(x, y))
            .count();
        assert!((100..=240).contains(&n), "{n}");
    }

    #[test]
    fn the_fill_rounds_up_inside_the_length() {
        assert_eq!(filled_cells(10, 1.0), 10);
        assert_eq!(filled_cells(10, 0.0), 0);
        assert_eq!(filled_cells(10, 0.31), 4);
        assert_eq!(filled_cells(10, 7.0), 10);
    }
}

#[cfg(test)]
mod motion_tests {
    use super::*;

    #[test]
    fn twinkle_stays_in_bounds_and_about_a_third_shows() {
        let mut visible: u32 = 0;
        let mut total: u32 = 0;
        for x in 0..40_u16 {
            for y in 0..10_u16 {
                for step in 0..50_u16 {
                    let b: f32 = twinkle(x, y, f32::from(step) * 0.2);
                    assert!((0.0..=1.0).contains(&b));
                    total += 1;
                    visible += u32::from(b > 0.0);
                }
            }
        }
        let percent: u32 = visible * 100 / total;
        assert!((20..45).contains(&percent), "percent {percent}");
    }

    #[test]
    fn head_columns_fade_from_the_front() {
        assert!((head_white(2, 3) - 1.0).abs() < f32::EPSILON);
        assert!((head_white(1, 3) - 0.6).abs() < f32::EPSILON);
        assert!((head_white(0, 3) - 0.3).abs() < f32::EPSILON);
    }
}
