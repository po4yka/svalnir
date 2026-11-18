//! The cell ring: the ring layout of a storage chart. Four concentric rings
//! of round dots; a segment covers the steps of its share on all four rings
//! (`DESIGN.md` section 5, "Cell ring").

use crate::{
    ui::ring_center::RingCenter,
    viz::{
        alloc::allocate_cells,
        dial::{DIAL_SIZE, dot_center, ring_progress},
        ghost::{Change, growth_cells},
        led::{CellTone, LedStyle, cell_tone_at, lit_color, lit_share, lit_threshold},
        storage_layouts::ChartItem,
    },
};
use gpui_kit::{
    App, Bounds, Corners, Hsla, InteractiveElement as _, IntoElement, MouseButton,
    ParentElement as _, Pixels, Point, RenderOnce, Role, SharedString,
    StatefulInteractiveElement as _, Styled as _, TestSupportExt as _, Window, canvas,
    component::ActiveTheme as _, div, fill, point, px, size,
};
use std::{cell::Cell, rc::Rc};

/// The number of rings.
pub const RINGS: usize = 4;
/// The angular steps of a ring.
pub const STEPS: usize = 120;
/// The radius of each ring, from the inside.
pub const RADII: [f32; RINGS] = [66.0, 72.0, 78.0, 84.0];
/// The diameter of one dot, in pixels. The inner ring has 3.45 px between two
/// steps, so a dot of 4 px would touch its neighbours.
const DOT: f32 = 3.0;

/// The steps of one segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    /// The first step.
    pub start: usize,
    /// The number of steps; 0 for an item of no bytes.
    pub len: usize,
}

/// The steps of the items and of the free space.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RingSpans {
    /// One span for each item, in the order of the items.
    pub items: Vec<Span>,
    /// The span of the free space.
    pub free: Option<Span>,
}

/// Divides the steps among the items and the free space by their bytes.
///
/// Every two neighbour segments (the last and the first too) keep a gap of
/// one step. A segment of more than one step gives its last step as the gap.
/// A segment of one step keeps its lit step; the gap after it comes from the
/// larger of its two neighbours, or from the largest segment when both
/// neighbours have one step. The steps of the segments and the gaps add up to
/// the steps that the allocation gives. A part of no steps has an empty span.
/// A segment of one step that finds no segment to give a step gets no step
/// and is not drawn. The Storage screen groups the small items into "Other",
/// so its charts have few segments and do not reach this case.
#[must_use]
pub fn ring_spans(weights: &[u64], free: Option<u64>) -> RingSpans {
    let free: u64 = free.unwrap_or(0);
    let mut parts: Vec<u64> = weights.to_vec();
    parts.push(free);
    let all: u64 = parts
        .iter()
        .fold(0_u64, |sum, part| sum.saturating_add(*part));
    let widths: Vec<usize> = allocate_cells(&parts, all, STEPS);
    let present: Vec<usize> = (0..widths.len()).filter(|i| widths[*i] > 0).collect();
    let mut lens: Vec<usize> = present
        .iter()
        .map(|i| if widths[*i] > 1 { widths[*i] - 1 } else { 1 })
        .collect();
    let count: usize = present.len();
    for pos in 0..count {
        if widths[present[pos]] != 1 || count < 2 {
            continue;
        }
        let before: usize = (pos + count - 1) % count;
        let after: usize = (pos + 1) % count;
        let (first, second): (usize, usize) = if lens[before] > lens[after] {
            (before, after)
        } else {
            (after, before)
        };
        let largest: usize = (0..count)
            .max_by_key(|i| (lens[*i], count - *i))
            .unwrap_or(0);
        if let Some(donor) = [first, second, largest]
            .into_iter()
            .find(|d| *d != pos && lens[*d] > 1)
        {
            lens[donor] -= 1;
        } else {
            // No segment can give a step: this one gives up its own.
            lens[pos] = 0;
        }
    }
    let mut spans: Vec<Span> = vec![Span { start: 0, len: 0 }; widths.len()];
    let mut start: usize = 0;
    for (pos, index) in present.iter().enumerate() {
        spans[*index] = Span {
            start,
            len: lens[pos],
        };
        start += lens[pos] + 1;
    }
    let free_span: Option<Span> = spans.pop().filter(|span| free > 0 && span.len > 0);
    RingSpans {
        items: spans,
        free: free_span,
    }
}

/// The index of the item at the pointer position `(x, y)` in a chart of
/// `DIAL_SIZE` pixels, from its top-left corner. The pointer must be between
/// the inner and the outer ring, each plus 3 px. The angle gives the step and
/// the step gives the item. A gap step, the free space, and the outside give
/// `None`.
#[must_use]
pub fn segment_at(x: f32, y: f32, spans: &RingSpans) -> Option<usize> {
    let dx: f32 = x - DIAL_SIZE / 2.0;
    let dy: f32 = y - DIAL_SIZE / 2.0;
    let radius: f32 = dx.hypot(dy);
    if radius < RADII[0] - 3.0 || radius > RADII[RINGS - 1] + 3.0 {
        return None;
    }
    // The first step is at the top and the ring runs clockwise.
    let turn: f32 = dx.atan2(-dy).rem_euclid(std::f32::consts::TAU) / std::f32::consts::TAU;
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss,
        reason = "the value is between 0 and 120 and rounded first"
    )]
    let step: usize = ((turn * STEPS as f32).round() as usize) % STEPS;
    spans
        .items
        .iter()
        .position(|span| span.len > 0 && step >= span.start && step < span.start + span.len)
}

/// The step in the middle of a span.
#[must_use]
pub const fn mid_step(span: Span) -> usize {
    span.start + span.len / 2
}

fn dot_box(origin: Point<Pixels>, center: (f32, f32)) -> Bounds<Pixels> {
    Bounds::new(
        point(
            origin.x + px(DIAL_SIZE / 2.0 + center.0 - DOT / 2.0),
            origin.y + px(DIAL_SIZE / 2.0 + center.1 - DOT / 2.0),
        ),
        size(px(DOT), px(DOT)),
    )
}

/// Everything one paint needs.
#[derive(Debug, Clone)]
struct RingPaint {
    spans: RingSpans,
    colors: Vec<Hsla>,
    dimmed: Vec<bool>,
    /// The lit threshold of each item, from its density.
    thresholds: Vec<u32>,
    /// The last steps of each span that the scan ghost hatches.
    growth: Vec<usize>,
    dim_alpha: f32,
    /// The color of a hatched dot of the scan ghost.
    ghost: Hsla,
    empty: Hsla,
    sweep: Option<f32>,
}

fn paint_ring(paint: &RingPaint, bounds: Bounds<Pixels>, window: &mut Window) {
    let corners: Corners<Pixels> = Corners::all(px(DOT / 2.0));
    for (ring, radius) in RADII.into_iter().enumerate() {
        // A ring shows the steps before its sweep front.
        let reach: usize = paint.sweep.map_or(STEPS, |overall| {
            let progress: f32 = ring_progress(overall, ring, RINGS);
            #[expect(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                clippy::cast_precision_loss,
                reason = "the product is at most 120 and rounded up first"
            )]
            let steps: usize = (STEPS as f32 * progress).ceil() as usize;
            steps
        });
        for (index, span) in paint.spans.items.iter().enumerate() {
            let color: Hsla = paint.colors[index];
            let seed: u32 = u32::try_from(index)
                .unwrap_or(0)
                .wrapping_add(1)
                .wrapping_mul(0x9e37_79b9);
            for step in span.start..span.start + span.len {
                if step >= reach {
                    break;
                }
                // The hatched steps keep every second dot empty.
                let hatched: bool = step + paint.growth[index] >= span.start + span.len;
                if hatched && (step + ring) % 2 == 1 {
                    continue;
                }
                let tone: CellTone = if paint.dimmed[index] {
                    CellTone::Dim
                } else if hatched {
                    CellTone::Lit
                } else {
                    cell_tone_at(
                        u16::try_from(step).unwrap_or(0),
                        u16::try_from(ring).unwrap_or(0),
                        seed,
                        paint.thresholds[index],
                    )
                };
                let fill_color: Hsla = match tone {
                    // A hatched dot is not a dot of the density texture.
                    CellTone::Lit if hatched && !paint.dimmed[index] => paint.ghost,
                    CellTone::Lit => lit_color(color),
                    CellTone::Dim => color.opacity(paint.dim_alpha),
                };
                window.paint_quad(
                    fill(
                        dot_box(bounds.origin, dot_center(step, STEPS, radius)),
                        fill_color,
                    )
                    .corner_radii(corners),
                );
            }
        }
        if let Some(free) = paint.spans.free {
            for step in (free.start..free.start + free.len).step_by(2) {
                if step < reach {
                    window.paint_quad(
                        fill(
                            dot_box(bounds.origin, dot_center(step, STEPS, radius)),
                            paint.empty,
                        )
                        .corner_radii(corners),
                    );
                }
            }
        }
    }
}

type SelectHandler = Rc<dyn Fn(usize, &mut Window, &mut App)>;
type HoverHandler = Rc<dyn Fn(Option<usize>, &mut Window, &mut App)>;

/// The ring chart as an element.
#[derive(IntoElement)]
pub struct CellRing {
    items: Vec<ChartItem>,
    free_bytes: Option<u64>,
    focus: Option<usize>,
    sweep: Option<f32>,
    id: SharedString,
    label: SharedString,
    center: (SharedString, SharedString),
    on_select: Option<SelectHandler>,
    on_hover: Option<HoverHandler>,
}

impl std::fmt::Debug for CellRing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CellRing")
            .field("label", &self.label)
            .finish_non_exhaustive()
    }
}

impl CellRing {
    /// Creates a ring of `items`; `center` is the used value and its caption.
    pub fn new(
        items: Vec<ChartItem>,
        free_bytes: Option<u64>,
        id: impl Into<SharedString>,
        label: impl Into<SharedString>,
        center: (impl Into<SharedString>, impl Into<SharedString>),
    ) -> Self {
        Self {
            items,
            free_bytes,
            focus: None,
            sweep: None,
            id: id.into(),
            label: label.into(),
            center: (center.0.into(), center.1.into()),
            on_select: None,
            on_hover: None,
        }
    }

    /// Dims each segment but the one at `focus`.
    #[must_use]
    pub const fn focus(mut self, focus: Option<usize>) -> Self {
        self.focus = focus;
        self
    }

    /// The progress `0.0..=1.0` of the entry sweep; `None` is the final state.
    #[must_use]
    pub const fn sweep(mut self, sweep: Option<f32>) -> Self {
        self.sweep = sweep;
        self
    }

    /// Sets the handler of the pointer over a segment: the index of the item,
    /// and `None` when the pointer is on no segment.
    #[must_use]
    pub fn on_hover(mut self, f: impl Fn(Option<usize>, &mut Window, &mut App) + 'static) -> Self {
        self.on_hover = Some(Rc::new(f));
        self
    }

    /// Sets the handler of a click on an activatable segment.
    #[must_use]
    pub fn on_select(mut self, f: impl Fn(usize, &mut Window, &mut App) + 'static) -> Self {
        self.on_select = Some(Rc::new(f));
        self
    }
}

impl RenderOnce for CellRing {
    #[expect(
        clippy::too_many_lines,
        reason = "one build of the ring and its hit area"
    )]
    fn render(self, _window: &mut Window, cx: &mut App) -> impl IntoElement {
        let dark: bool = cx.theme().is_dark();
        let style: LedStyle = LedStyle::for_dark(dark);
        let weights: Vec<u64> = self.items.iter().map(|i| i.bytes).collect();
        let spans: RingSpans = ring_spans(&weights, self.free_bytes);
        let paint: RingPaint = RingPaint {
            spans: spans.clone(),
            colors: self.items.iter().map(|i| i.color).collect(),
            dimmed: self
                .items
                .iter()
                .enumerate()
                .map(|(index, item)| item.inert || self.focus.is_some_and(|f| f != index))
                .collect(),
            thresholds: self
                .items
                .iter()
                .map(|i| lit_threshold(i.density.map(|d| lit_share(Some(d)))))
                .collect(),
            growth: self
                .items
                .iter()
                .zip(&spans.items)
                .map(|(item, span)| match item.change {
                    Some(Change::Larger(diff)) => {
                        let all: u64 = weights
                            .iter()
                            .fold(self.free_bytes.unwrap_or(0), |a, w| a.saturating_add(*w));
                        let per_step: u64 = all.div_ceil(u64::try_from(STEPS).unwrap_or(1)).max(1);
                        usize::try_from(growth_cells(
                            diff,
                            per_step,
                            u32::try_from(span.len).unwrap_or(u32::MAX),
                        ))
                        .unwrap_or(0)
                    }
                    _ => 0,
                })
                .collect(),
            dim_alpha: style.dim_alpha,
            ghost: style.ghost_line,
            empty: style.lattice,
            sweep: self.sweep,
        };
        let origin: Rc<Cell<Point<Pixels>>> = Rc::new(Cell::new(Point::default()));
        let origin_paint: Rc<Cell<Point<Pixels>>> = Rc::clone(&origin);
        let mut root = div()
            .id(self.id.clone())
            .role(Role::Image)
            .test_support()
            .aria_label(self.label)
            .relative()
            .w(px(DIAL_SIZE))
            .h(px(DIAL_SIZE))
            .flex_shrink_0()
            .child(
                div().absolute().top_0().left_0().size_full().child(
                    canvas(
                        move |bounds: Bounds<Pixels>, _, _| origin_paint.set(bounds.origin),
                        move |bounds: Bounds<Pixels>, (), window: &mut Window, _: &mut App| {
                            paint_ring(&paint, bounds, window);
                        },
                    )
                    .size_full(),
                ),
            );
        // One hit test of the whole arc of a segment, from the pointer.
        if self.on_select.is_some() || self.on_hover.is_some() {
            let items_active: Vec<bool> = self.items.iter().map(|i| i.activatable).collect();
            let hit_spans: RingSpans = spans.clone();
            let hover: Option<HoverHandler> = self.on_hover.clone();
            let select: Option<SelectHandler> = self.on_select.clone();
            let hover_origin: Rc<Cell<Point<Pixels>>> = Rc::clone(&origin);
            let hover_spans: RingSpans = spans.clone();
            let mut overlay = div()
                .id(SharedString::from(format!("{}-hit", self.id)))
                .absolute()
                .top_0()
                .left_0()
                .size_full()
                .on_mouse_down(MouseButton::Left, |_, window, _| window.prevent_default())
                .on_mouse_move(move |event, window, app| {
                    if let Some(handler) = &hover {
                        let at: Point<Pixels> = event.position - hover_origin.get();
                        handler(
                            segment_at(at.x.into(), at.y.into(), &hover_spans),
                            window,
                            app,
                        );
                    }
                })
                .on_hover({
                    let leave: Option<HoverHandler> = self.on_hover.clone();
                    move |hovered, window, app| {
                        if !*hovered && let Some(handler) = &leave {
                            handler(None, window, app);
                        }
                    }
                });
            if let Some(handler) = select {
                overlay = overlay.on_click(move |event, window, app| {
                    let at: Point<Pixels> = event.position() - origin.get();
                    if let Some(index) = segment_at(at.x.into(), at.y.into(), &hit_spans)
                        && items_active.get(index).copied().unwrap_or(false)
                    {
                        handler(index, window, app);
                    }
                });
            }
            root = root.child(overlay);
        }
        root.child(
            RingCenter::new(
                SharedString::from(format!("{}-center", self.id)),
                self.center.0,
                self.center.1,
                // The inner ring: its diameter without the dot.
                2.0 * RADII[0] - DOT,
            )
            .caption_id(SharedString::from(format!("{}-center-caption", self.id))),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_gaps(spans: &RingSpans) {
        let mut taken: Vec<bool> = vec![false; STEPS];
        let all: Vec<Span> = spans.items.iter().copied().chain(spans.free).collect();
        for span in all.iter().filter(|s| s.len > 0) {
            for slot in &mut taken[span.start..span.start + span.len] {
                assert!(!*slot, "a step is used twice");
                *slot = true;
            }
        }
        // No two segments touch: the step after a segment is a gap, also
        // from the last step to the first.
        for span in all.iter().filter(|s| s.len > 0) {
            assert!(!taken[(span.start + span.len) % STEPS], "{span:?} touches");
        }
    }

    #[test]
    fn a_one_step_segment_keeps_its_step_and_the_larger_neighbour_gives_the_gap() {
        // 1 step, 60 steps, 1 step, 58 steps and free space of one step.
        let spans = ring_spans(&[1, 60, 1, 58], Some(1));
        assert_eq!(spans.items[0].len, 1);
        assert_eq!(spans.items[2].len, 1);
        assert!(spans.free.is_some_and(|f| f.len == 1));
        assert_gaps(&spans);
        let total: usize = spans
            .items
            .iter()
            .chain(spans.free.iter())
            .filter(|s| s.len > 0)
            .map(|s| s.len + 1)
            .sum();
        assert_eq!(total, STEPS, "steps and gaps add up to 120");
    }

    #[test]
    fn several_shapes_never_touch() {
        for (weights, free) in [
            (vec![600_u64, 300], Some(100_u64)),
            (vec![1, 1, 1, 1000], None),
            (vec![50, 50], Some(1)),
            (vec![1, 1], Some(1)),
            (vec![1000], None),
        ] {
            let spans = ring_spans(&weights, free);
            assert_gaps(&spans);
        }
    }

    fn point_at(step: f32, radius: f32) -> (f32, f32) {
        let turn: f32 = step / 120.0 * std::f32::consts::TAU;
        (
            DIAL_SIZE / 2.0 + radius * turn.sin(),
            DIAL_SIZE / 2.0 - radius * turn.cos(),
        )
    }

    #[test]
    fn the_whole_arc_selects_a_segment() {
        // Item 0: steps 0..59, gap 59, item 1: 60..89, gap 89, free 90..119.
        let spans = RingSpans {
            items: vec![Span { start: 0, len: 59 }, Span { start: 60, len: 29 }],
            free: Some(Span { start: 90, len: 29 }),
        };
        let mid: f32 = DIAL_SIZE / 2.0;
        assert_eq!(segment_at(mid, mid, &spans), None, "center");
        assert_eq!(segment_at(0.0, 0.0, &spans), None, "outside");
        assert_eq!(
            segment_at(mid, mid - 100.0, &spans),
            None,
            "beyond the ring"
        );
        // Each quadrant: the right (step 30), the bottom (step 60 is item 1).
        let (x, y) = point_at(30.0, 75.0);
        assert_eq!(segment_at(x, y, &spans), Some(0), "right side");
        let (x, y) = point_at(45.0, 69.0);
        assert_eq!(segment_at(x, y, &spans), Some(0), "lower right, inner edge");
        let (x, y) = point_at(75.0, 81.0);
        assert_eq!(segment_at(x, y, &spans), Some(1), "lower left");
        let (x, y) = point_at(10.0, 84.0 + 3.0);
        assert_eq!(segment_at(x, y, &spans), Some(0), "outer edge plus 3 px");
        let (x, y) = point_at(10.0, 84.0 + 4.0);
        assert_eq!(segment_at(x, y, &spans), None, "outside the outer edge");
        let (x, y) = point_at(59.0, 75.0);
        assert_eq!(segment_at(x, y, &spans), None, "the gap step");
        let (x, y) = point_at(100.0, 75.0);
        assert_eq!(segment_at(x, y, &spans), None, "the free region");
        let (x, y) = point_at(105.0, 75.0);
        assert_eq!(segment_at(x, y, &spans), None, "upper left is free space");
    }

    #[test]
    fn spans_follow_the_shares_and_leave_a_gap() {
        let spans = ring_spans(&[600, 300], Some(100));
        assert_eq!(spans.items.len(), 2);
        assert_eq!(spans.items[0], Span { start: 0, len: 71 });
        assert_eq!(spans.items[1].start, 72);
        assert!(spans.free.is_some());
        let end = spans.free.map_or(0, |f| f.start + f.len);
        assert!(end <= STEPS);
    }

    #[test]
    fn an_item_of_no_bytes_has_no_steps_and_no_free_space_has_no_span() {
        let spans = ring_spans(&[100, 0], None);
        assert_eq!(spans.items[1].len, 0);
        assert!(spans.free.is_none());
    }

    #[test]
    fn nothing_to_divide_gives_empty_spans() {
        let spans = ring_spans(&[], None);
        assert!(spans.items.is_empty() && spans.free.is_none());
    }
}
