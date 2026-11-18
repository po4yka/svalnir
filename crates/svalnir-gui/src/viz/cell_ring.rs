//! The cell ring: the ring layout of a storage chart. Four concentric rings
//! of round dots; a segment covers the steps of its share on all four rings
//! (`DESIGN.md` section 5, "Cell ring").

use crate::{
    theme::tokens::{Tokens, to_hsla},
    viz::{
        alloc::allocate_cells,
        dial::{DIAL_SIZE, dot_center, ring_progress},
        led::{CellTone, LedStyle, cell_tone, lit_color},
        storage_layouts::ChartItem,
    },
};
use gpui_kit::{
    App, Bounds, Corners, FontWeight, Hsla, InteractiveElement as _, IntoElement, MouseButton,
    ParentElement as _, Pixels, Point, RenderOnce, Role, SharedString,
    StatefulInteractiveElement as _, Styled as _, TestSupportExt as _, Window, canvas,
    component::{ActiveTheme as _, v_flex},
    div, fill, point, px, size,
};
use std::rc::Rc;

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

/// Divides the steps among the items and the free space by their bytes. Each
/// span that has more than one step leaves its last step as a gap.
#[must_use]
pub fn ring_spans(weights: &[u64], free: Option<u64>) -> RingSpans {
    let free: u64 = free.unwrap_or(0);
    let mut parts: Vec<u64> = weights.to_vec();
    parts.push(free);
    let all: u64 = parts
        .iter()
        .fold(0_u64, |sum, part| sum.saturating_add(*part));
    let widths: Vec<usize> = allocate_cells(&parts, all, STEPS);
    let mut start: usize = 0;
    let mut items: Vec<Span> = Vec::with_capacity(weights.len());
    let mut free_span: Option<Span> = None;
    for (index, width) in widths.iter().enumerate() {
        let len: usize = if *width > 1 { width - 1 } else { *width };
        let span: Span = Span { start, len };
        if index < weights.len() {
            items.push(span);
        } else if free > 0 && len > 0 {
            free_span = Some(span);
        }
        start += width;
    }
    RingSpans {
        items,
        free: free_span,
    }
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
    dim_alpha: f32,
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
                let tone: CellTone = if paint.dimmed[index] {
                    CellTone::Dim
                } else {
                    cell_tone(
                        u16::try_from(step).unwrap_or(0),
                        u16::try_from(ring).unwrap_or(0),
                        seed,
                    )
                };
                let fill_color: Hsla = match tone {
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

    /// Sets the handler of a click on an activatable segment.
    #[must_use]
    pub fn on_select(mut self, f: impl Fn(usize, &mut Window, &mut App) + 'static) -> Self {
        self.on_select = Some(Rc::new(f));
        self
    }
}

impl RenderOnce for CellRing {
    fn render(self, _window: &mut Window, cx: &mut App) -> impl IntoElement {
        let dark: bool = cx.theme().is_dark();
        let tokens: &Tokens = Tokens::for_dark(dark);
        let style: LedStyle = LedStyle::for_dark(dark);
        let mono: SharedString = cx.theme().mono_font_family.clone();
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
            dim_alpha: style.dim_alpha,
            empty: style.lattice,
            sweep: self.sweep,
        };
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
                        |_, _, _| (),
                        move |bounds: Bounds<Pixels>, (), window: &mut Window, _: &mut App| {
                            paint_ring(&paint, bounds, window);
                        },
                    )
                    .size_full(),
                ),
            );
        // One hit area in the middle of each activatable segment.
        if let Some(handler) = &self.on_select {
            for (index, (item, span)) in self.items.iter().zip(&spans.items).enumerate() {
                if !item.activatable || span.len == 0 {
                    continue;
                }
                let (x, y): (f32, f32) = dot_center(mid_step(*span), STEPS, 75.0);
                let handler: SelectHandler = Rc::clone(handler);
                root = root.child(
                    div()
                        .id(SharedString::from(format!("{}-tile-{index}", self.id)))
                        .absolute()
                        .left(px(DIAL_SIZE / 2.0 + x - 12.0))
                        .top(px(DIAL_SIZE / 2.0 + y - 12.0))
                        .size(px(24.0))
                        .cursor_pointer()
                        .on_mouse_down(MouseButton::Left, |_, window, _| window.prevent_default())
                        .on_click(move |_, window, app| handler(index, window, app)),
                );
            }
        }
        root.child(
            v_flex()
                .absolute()
                .top_0()
                .left_0()
                .size_full()
                .items_center()
                .justify_center()
                .child(
                    div()
                        .id(SharedString::from(format!("{}-center", self.id)))
                        .test_support()
                        .aria_label(self.center.0.clone())
                        .font_family(mono)
                        .font_weight(FontWeight::MEDIUM)
                        .text_size(px(20.0))
                        .text_color(to_hsla(tokens.foreground))
                        .whitespace_nowrap()
                        .child(self.center.0),
                )
                .child(
                    div()
                        .max_w(px(100.0))
                        .overflow_hidden()
                        .text_size(px(11.0))
                        .text_color(to_hsla(tokens.muted_foreground))
                        .whitespace_nowrap()
                        .text_ellipsis()
                        .child(self.center.1),
                ),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
