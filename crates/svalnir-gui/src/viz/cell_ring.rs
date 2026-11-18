//! The cell ring: the ring layout of a storage chart. Four concentric rings
//! of round dots; a segment covers the steps of its share on all four rings
//! (`DESIGN.md` section 5, "Cell ring").

use crate::{
    ui::{
        chart_tip::{ChartTip, TipContent},
        ring_center::RingCenter,
    },
    viz::{
        alloc::allocate_cells,
        dial::{DIAL_SIZE, dot_center, ring_progress},
        ghost::{Change, growth_cells},
        hover::{FocusTarget, Mark, Tween, take_launch_focus},
        led::{CellTone, LedStyle, cell_tone_at, lit_color, lit_share, lit_threshold, mix_color},
        storage_layouts::ChartItem,
    },
};
use gpui_kit::{
    App, Bounds, Corners, Entity, FocusHandle, Hsla, InteractiveElement as _, IntoElement,
    MouseButton, ParentElement as _, Pixels, Point, RenderOnce, Role, SharedString,
    StatefulInteractiveElement as _, Styled as _, TestSupportExt as _, Window, canvas,
    component::ActiveTheme as _, div, fill, point, px, size,
};
use std::{cell::Cell, rc::Rc, time::Instant};

/// The number of rings.
pub const RINGS: usize = 4;
/// The angular steps of a ring.
pub const STEPS: usize = 120;
/// The radius of each ring, from the inside.
pub const RADII: [f32; RINGS] = [66.0, 72.0, 78.0, 84.0];
/// The diameter of one dot, in pixels. The inner ring has 3.45 px between two
/// steps, so a dot of 4 px would touch its neighbours.
const DOT: f32 = 3.0;
/// The diameter of a dot of the hovered segment, in pixels.
const DOT_HOT: f32 = 4.0;

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
    ring_mark_at(x, y, spans).and_then(Mark::segment)
}

/// The mark under the point `(x, y)` in pixels from the top-left corner of the
/// ring: a segment, or the free space. A gap step and the outside give `None`.
#[must_use]
pub fn ring_mark_at(x: f32, y: f32, spans: &RingSpans) -> Option<Mark> {
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
    let inside = |span: &Span| span.len > 0 && step >= span.start && step < span.start + span.len;
    if let Some(index) = spans.items.iter().position(inside) {
        return Some(Mark::Segment(index));
    }
    spans.free.filter(inside).map(|_| Mark::Free)
}

/// The marks of a ring in keyboard order: the segments that have steps, then
/// the free space.
#[must_use]
pub fn ring_marks(spans: &RingSpans) -> Vec<Mark> {
    let mut out: Vec<Mark> = spans
        .items
        .iter()
        .enumerate()
        .filter(|(_, span)| span.len > 0)
        .map(|(index, _)| Mark::Segment(index))
        .collect();
    if spans.free.is_some_and(|span| span.len > 0) {
        out.push(Mark::Free);
    }
    out
}

/// The mark after `current` when the keyboard moves by `delta` places. With no
/// mark, a move forward picks the first and a move back picks the last. The
/// move stops at both ends.
#[must_use]
pub fn step_ring_mark(spans: &RingSpans, current: Option<Mark>, delta: i32) -> Option<Mark> {
    let order: Vec<Mark> = ring_marks(spans);
    let last: usize = order.len().checked_sub(1)?;
    let next: usize = match current.and_then(|c| order.iter().position(|m| *m == c)) {
        Some(at) => {
            let moved: i64 = i64::try_from(at).unwrap_or(0) + i64::from(delta);
            usize::try_from(moved.max(0)).unwrap_or(0).min(last)
        }
        None if delta >= 0 => 0,
        None => last,
    };
    order.get(next).copied()
}

/// The center of the outer ring at the middle of a mark, in pixels from the
/// top-left corner of the ring.
#[must_use]
pub fn ring_mark_point(spans: &RingSpans, mark: Mark) -> Option<(f32, f32)> {
    let span: Span = match mark {
        Mark::Segment(index) => *spans.items.get(index)?,
        Mark::Free => spans.free?,
    };
    let (x, y) = dot_center(mid_step(span), STEPS, RADII[RINGS - 1]);
    Some((DIAL_SIZE / 2.0 + x, DIAL_SIZE / 2.0 + y))
}

/// The step in the middle of a span.
#[must_use]
pub const fn mid_step(span: Span) -> usize {
    span.start + span.len / 2
}

fn dot_box(origin: Point<Pixels>, center: (f32, f32), side: f32) -> Bounds<Pixels> {
    Bounds::new(
        point(
            origin.x + px(DIAL_SIZE / 2.0 + center.0 - side / 2.0),
            origin.y + px(DIAL_SIZE / 2.0 + center.1 - side / 2.0),
        ),
        size(px(side), px(side)),
    )
}

/// Everything one paint needs.
#[derive(Debug, Clone)]
struct RingPaint {
    spans: RingSpans,
    colors: Vec<Hsla>,
    /// The dim amount `0.0..=1.0` of each segment.
    dim: Vec<f32>,
    /// The growth amount `0.0..=1.0` of the dots of each segment.
    grow: Vec<f32>,
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
                let tone: CellTone = if hatched {
                    CellTone::Lit
                } else {
                    cell_tone_at(
                        u16::try_from(step).unwrap_or(0),
                        u16::try_from(ring).unwrap_or(0),
                        seed,
                        paint.thresholds[index],
                    )
                };
                let normal: Hsla = match tone {
                    // A hatched dot is not a dot of the density texture.
                    CellTone::Lit if hatched => paint.ghost,
                    CellTone::Lit => lit_color(color),
                    CellTone::Dim => color.opacity(paint.dim_alpha),
                };
                let dim: f32 = paint.dim[index];
                let fill_color: Hsla = if dim > 0.0 {
                    mix_color(normal, color.opacity(paint.dim_alpha), dim)
                } else {
                    normal
                };
                let side: f32 = DOT + (DOT_HOT - DOT) * paint.grow[index];
                window.paint_quad(
                    fill(
                        dot_box(bounds.origin, dot_center(step, STEPS, radius), side),
                        fill_color,
                    )
                    .corner_radii(Corners::all(px(side / 2.0))),
                );
            }
        }
        if let Some(free) = paint.spans.free {
            for step in (free.start..free.start + free.len).step_by(2) {
                if step < reach {
                    window.paint_quad(
                        fill(
                            dot_box(bounds.origin, dot_center(step, STEPS, radius), DOT),
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
    tips: Vec<TipContent>,
    free_tip: Option<TipContent>,
    reduce_motion: bool,
    launch: Option<FocusTarget>,
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
            tips: Vec::new(),
            free_tip: None,
            reduce_motion: false,
            launch: None,
        }
    }

    /// Sets the cards of the segments, in the order of the items.
    #[must_use]
    pub fn tips(mut self, tips: Vec<TipContent>) -> Self {
        self.tips = tips;
        self
    }

    /// Sets the card of the free space.
    #[must_use]
    pub fn free_tip(mut self, tip: Option<TipContent>) -> Self {
        self.free_tip = tip;
        self
    }

    /// With `reduce` true, hover changes apply in one step.
    #[must_use]
    pub const fn reduce_motion(mut self, reduce: bool) -> Self {
        self.reduce_motion = reduce;
        self
    }

    /// Lets a launch request for `target` focus this ring and pick its first
    /// mark.
    #[must_use]
    pub const fn launch_focus(mut self, target: FocusTarget) -> Self {
        self.launch = Some(target);
        self
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

/// The hover state that one ring keeps between frames.
struct RingHover {
    /// The mark under the pointer or under the keyboard.
    mark: Option<Mark>,
    /// Whether the keyboard set the mark.
    keyboard: bool,
    /// The dim and growth amounts of the segments.
    tween: Option<Tween>,
    /// The focus of the ring, for Tab and the arrow keys.
    handle: FocusHandle,
    /// The position of the ring in the window, set at each paint.
    origin: Rc<Cell<Point<Pixels>>>,
}

/// Sets the mark of the ring. It redraws the ring and calls `hover` only when
/// the mark changes.
fn set_ring_mark(
    state: &Entity<RingHover>,
    mark: Option<Mark>,
    keyboard: bool,
    hover: Option<&HoverHandler>,
    window: &mut Window,
    app: &mut App,
) {
    let changed: bool = state.update(app, |s, cx| {
        if s.mark == mark {
            return false;
        }
        s.mark = mark;
        s.keyboard = keyboard && mark.is_some();
        cx.notify();
        true
    });
    if changed && let Some(handler) = hover {
        handler(mark.and_then(Mark::segment), window, app);
    }
}

impl RenderOnce for CellRing {
    #[expect(
        clippy::too_many_lines,
        reason = "one build of the ring and its hit area"
    )]
    fn render(self, window: &mut Window, cx: &mut App) -> impl IntoElement {
        let dark: bool = cx.theme().is_dark();
        let style: LedStyle = LedStyle::for_dark(dark);
        let weights: Vec<u64> = self.items.iter().map(|i| i.bytes).collect();
        let spans: RingSpans = ring_spans(&weights, self.free_bytes);
        let animate: bool = !(self.reduce_motion || cx.reduce_motion());
        let state: Entity<RingHover> = window.use_keyed_state(
            SharedString::from(format!("{}-hover", self.id)),
            cx,
            |_, cx| RingHover {
                mark: None,
                keyboard: false,
                tween: None,
                handle: cx.focus_handle().tab_stop(true),
                origin: Rc::new(Cell::new(Point::default())),
            },
        );
        let handle: FocusHandle = state.read(cx).handle.clone();
        let mut focused: bool = handle.is_focused(window);
        // A launch request waits without cost until the ring has a mark.
        let first: Option<Mark> = ring_marks(&spans).first().copied();
        if first.is_some()
            && self
                .launch
                .is_some_and(|target| take_launch_focus(target, cx))
        {
            set_ring_mark(&state, first, true, self.on_hover.as_ref(), window, cx);
            let to_focus: FocusHandle = handle.clone();
            window.defer(cx, move |window, cx| window.focus(&to_focus, cx));
            // The focus follows after this frame; keep the mark meanwhile.
            focused = true;
        }
        let now: Instant = Instant::now();
        let count: usize = self.items.len();
        let focus: Option<usize> = self.focus;
        let inert: Vec<bool> = self.items.iter().map(|i| i.inert).collect();
        let (mark, values, running): (Option<Mark>, Vec<f32>, bool) = state.update(cx, |s, _| {
            if s.keyboard && !focused {
                s.mark = None;
                s.keyboard = false;
            }
            let highlight: Option<usize> = focus.or(s.mark.and_then(Mark::segment));
            let mut target: Vec<f32> = vec![0.0; 2 * count];
            for (index, is_inert) in inert.iter().enumerate() {
                target[index] =
                    f32::from(u8::from(*is_inert || highlight.is_some_and(|h| h != index)));
                target[count + index] = f32::from(u8::from(highlight == Some(index)));
            }
            let tween: &mut Tween = s
                .tween
                .get_or_insert_with(|| Tween::new(target.clone(), now));
            tween.retarget(target, now, animate);
            (s.mark, tween.value_at(now), tween.running(now))
        });
        if running {
            window.request_animation_frame();
        }
        let (dim, grow): (Vec<f32>, Vec<f32>) = if values.len() == 2 * count {
            (values[..count].to_vec(), values[count..].to_vec())
        } else {
            (vec![0.0; count], vec![0.0; count])
        };
        let paint: RingPaint = RingPaint {
            spans: spans.clone(),
            colors: self.items.iter().map(|i| i.color).collect(),
            dim,
            grow,
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
        let origin: Rc<Cell<Point<Pixels>>> = Rc::clone(&state.read(cx).origin);
        let tip: Option<ChartTip> = mark.and_then(|m| {
            let content: TipContent = match m {
                Mark::Segment(index) => self.tips.get(index).cloned()?,
                Mark::Free => self.free_tip.clone()?,
            };
            let (x, y) = ring_mark_point(&spans, m)?;
            Some(ChartTip::new(
                SharedString::from(format!("{}-tip", self.id)),
                content,
                Bounds::new(
                    point(px(x - DOT / 2.0), px(y - DOT / 2.0)),
                    size(px(DOT), px(DOT)),
                ),
                origin.get(),
                animate,
            ))
        });
        let origin_paint: Rc<Cell<Point<Pixels>>> = Rc::clone(&origin);
        let items_active: Vec<bool> = self.items.iter().map(|i| i.activatable).collect();
        let hit_spans: Rc<RingSpans> = Rc::new(spans);
        let move_spans: Rc<RingSpans> = Rc::clone(&hit_spans);
        let key_spans: Rc<RingSpans> = Rc::clone(&hit_spans);
        let move_origin: Rc<Cell<Point<Pixels>>> = Rc::clone(&origin);
        let move_state: Entity<RingHover> = state.clone();
        let move_hover: Option<HoverHandler> = self.on_hover.clone();
        let leave_state: Entity<RingHover> = state.clone();
        let leave_hover: Option<HoverHandler> = self.on_hover.clone();
        let key_state: Entity<RingHover> = state;
        let key_hover: Option<HoverHandler> = self.on_hover.clone();
        let select: Option<SelectHandler> = self.on_select.clone();
        let mut overlay = div()
            .id(SharedString::from(format!("{}-hit", self.id)))
            .absolute()
            .top_0()
            .left_0()
            .size_full()
            .on_mouse_down(MouseButton::Left, |_, window, _| window.prevent_default())
            .on_mouse_move(move |event, window, app| {
                let at: Point<Pixels> = event.position - move_origin.get();
                let mark: Option<Mark> = ring_mark_at(at.x.into(), at.y.into(), &move_spans);
                set_ring_mark(&move_state, mark, false, move_hover.as_ref(), window, app);
            })
            .on_hover(move |hovered, window, app| {
                let from_pointer: bool = !leave_state.read(app).keyboard;
                if !*hovered && from_pointer {
                    set_ring_mark(&leave_state, None, false, leave_hover.as_ref(), window, app);
                }
            });
        if let Some(handler) = select {
            let click_origin: Rc<Cell<Point<Pixels>>> = Rc::clone(&origin);
            let click_spans: Rc<RingSpans> = Rc::clone(&hit_spans);
            overlay = overlay.on_click(move |event, window, app| {
                let at: Point<Pixels> = event.position() - click_origin.get();
                if let Some(index) = segment_at(at.x.into(), at.y.into(), &click_spans)
                    && items_active.get(index).copied().unwrap_or(false)
                {
                    handler(index, window, app);
                }
            });
        }
        div()
            .id(self.id.clone())
            .role(Role::Image)
            .test_support()
            .aria_label(self.label)
            .track_focus(&handle)
            .relative()
            .w(px(DIAL_SIZE))
            .h(px(DIAL_SIZE))
            .flex_shrink_0()
            .on_key_down(move |event, window, app| {
                let current: Option<Mark> = key_state.read(app).mark;
                let next: Option<Option<Mark>> = match event.keystroke.key.as_str() {
                    "right" | "down" => Some(step_ring_mark(&key_spans, current, 1)),
                    "left" | "up" => Some(step_ring_mark(&key_spans, current, -1)),
                    "home" => Some(ring_marks(&key_spans).first().copied()),
                    "end" => Some(ring_marks(&key_spans).last().copied()),
                    "escape" => Some(None),
                    _ => None,
                };
                if let Some(mark) = next {
                    set_ring_mark(&key_state, mark, true, key_hover.as_ref(), window, app);
                    app.stop_propagation();
                }
            })
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
            )
            .child(overlay)
            .child(
                RingCenter::new(
                    SharedString::from(format!("{}-center", self.id)),
                    self.center.0,
                    self.center.1,
                    // The inner ring: its diameter without the dot.
                    2.0 * RADII[0] - DOT,
                )
                .caption_id(SharedString::from(format!("{}-center-caption", self.id))),
            )
            .children(tip)
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

    fn marks_spans() -> RingSpans {
        RingSpans {
            items: vec![Span { start: 0, len: 59 }, Span { start: 60, len: 29 }],
            free: Some(Span { start: 90, len: 29 }),
        }
    }

    #[test]
    fn the_free_space_is_a_mark_and_a_gap_is_not() {
        let spans = marks_spans();
        let (x, y) = point_at(100.0, 75.0);
        assert_eq!(ring_mark_at(x, y, &spans), Some(Mark::Free));
        let (x, y) = point_at(30.0, 75.0);
        assert_eq!(ring_mark_at(x, y, &spans), Some(Mark::Segment(0)));
        let (x, y) = point_at(59.0, 75.0);
        assert_eq!(ring_mark_at(x, y, &spans), None);
    }

    #[test]
    fn the_keyboard_walks_the_segments_then_the_free_space() {
        let spans = marks_spans();
        let seg = Mark::Segment;
        assert_eq!(step_ring_mark(&spans, None, 1), Some(seg(0)));
        assert_eq!(step_ring_mark(&spans, None, -1), Some(Mark::Free));
        assert_eq!(step_ring_mark(&spans, Some(seg(1)), 1), Some(Mark::Free));
        assert_eq!(
            step_ring_mark(&spans, Some(Mark::Free), 1),
            Some(Mark::Free)
        );
        assert_eq!(step_ring_mark(&spans, Some(seg(0)), -1), Some(seg(0)));
        assert_eq!(ring_marks(&spans).len(), 3);
    }

    #[test]
    fn the_card_anchor_is_on_the_outer_ring_in_the_middle_of_the_mark() {
        let spans = marks_spans();
        let (x, y) = ring_mark_point(&spans, Mark::Segment(0)).expect("a segment");
        let radius = (x - DIAL_SIZE / 2.0).hypot(y - DIAL_SIZE / 2.0);
        assert!((radius - RADII[RINGS - 1]).abs() < 0.01);
        // The middle of the first segment is on the right half of the ring.
        assert!(x > DIAL_SIZE / 2.0);
        assert!(ring_mark_point(&spans, Mark::Segment(9)).is_none());
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
