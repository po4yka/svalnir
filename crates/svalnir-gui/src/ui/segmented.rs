//! The segmented control of `DESIGN.md` section 4: a pill track whose active
//! pill slides to the new option.

use crate::theme::{
    motion::{self, Gate},
    tokens::{Tokens, to_hsla},
};
use gpui_kit::{
    App, ElementId, FocusHandle, FontWeight, Hsla, InteractiveElement as _, IntoElement,
    ParentElement as _, RenderOnce, Role, SharedString, StatefulInteractiveElement as _,
    Styled as _, TestSupportExt as _, Window,
    component::{ActiveTheme as _, h_flex},
    div, px,
};
use std::{
    rc::Rc,
    time::{Duration, Instant},
};

/// Duration of the slide of the pill.
pub const SLIDE: Duration = Duration::from_millis(200);
/// Height of the track.
const TRACK_HEIGHT: f32 = 32.0;
/// Space between the track edge and the pill.
const TRACK_PAD: f32 = 2.0;
/// Horizontal padding of one option.
const OPTION_PAD: f32 = 12.0;
/// Estimated width of one label character at 13 px medium.
const CHAR_WIDTH: f32 = 7.2;

type ChangeHandler = Rc<dyn Fn(usize, &mut Window, &mut App)>;

/// The option index after a Left (`-1`) or Right (`1`) key; the ends do not wrap.
#[must_use]
pub fn step_index(active: usize, len: usize, delta: i32) -> usize {
    let last: usize = len.saturating_sub(1);
    if delta < 0 {
        active.saturating_sub(1)
    } else {
        active.saturating_add(1).min(last)
    }
}

/// The width of the option with `label`.
#[must_use]
pub fn option_width(label: &str) -> f32 {
    #[expect(
        clippy::cast_precision_loss,
        reason = "a label has far fewer than 2^24 characters"
    )]
    let chars: f32 = label.chars().count() as f32;
    chars * CHAR_WIDTH + 2.0 * OPTION_PAD
}

/// The left edge of the pill of option `index`, inside the track padding.
#[must_use]
pub fn pill_offset(widths: &[f32], index: usize) -> f32 {
    widths.iter().take(index).sum()
}

/// The left edge of the pill at `progress` of a slide from `from` to `to`.
#[must_use]
pub fn pill_position(widths: &[f32], from: usize, to: usize, progress: f32) -> f32 {
    let a: f32 = pill_offset(widths, from);
    let b: f32 = pill_offset(widths, to);
    a + (b - a) * motion::ease_ui_out(progress)
}

/// The state that outlives one render: focus and the slide.
struct SlideState {
    focus: FocusHandle,
    from: usize,
    to: usize,
    started: Option<Instant>,
}

/// A segmented control.
#[derive(IntoElement)]
pub struct SegmentedControl {
    id: SharedString,
    options: Vec<(SharedString, SharedString)>,
    active: usize,
    track: Option<Hsla>,
    on_change: Option<ChangeHandler>,
}

impl std::fmt::Debug for SegmentedControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SegmentedControl")
            .field("id", &self.id)
            .field("active", &self.active)
            .finish_non_exhaustive()
    }
}

impl SegmentedControl {
    /// Creates a control from `(id, label)` options and the active index.
    pub fn new(
        id: impl Into<SharedString>,
        options: Vec<(SharedString, SharedString)>,
        active: usize,
    ) -> Self {
        Self {
            id: id.into(),
            options,
            active,
            track: None,
            on_change: None,
        }
    }

    /// Sets the track color (`surface-inset` in a shell header).
    #[must_use]
    pub fn track(mut self, color: Hsla) -> Self {
        self.track = Some(color);
        self
    }

    /// Sets the handler of a change of the option.
    #[must_use]
    pub fn on_change(mut self, f: impl Fn(usize, &mut Window, &mut App) + 'static) -> Self {
        self.on_change = Some(Rc::new(f));
        self
    }
}

impl RenderOnce for SegmentedControl {
    #[expect(
        clippy::too_many_lines,
        reason = "one build of the track and its options"
    )]
    fn render(self, window: &mut Window, cx: &mut App) -> impl IntoElement {
        let tokens: &Tokens = Tokens::for_dark(cx.theme().is_dark());
        let len: usize = self.options.len();
        let active: usize = self.active.min(len.saturating_sub(1));
        let state = window.use_keyed_state(
            ElementId::from(SharedString::from(format!("{}-state", self.id))),
            cx,
            |_, cx| SlideState {
                focus: cx.focus_handle().tab_stop(true),
                from: active,
                to: active,
                started: None,
            },
        );
        // A change that no click made (the keyboard, the model) jumps.
        state.update(cx, |s, _| {
            if s.to != active {
                s.from = active;
                s.to = active;
                s.started = None;
            }
        });
        let (focus, from, to, started) = {
            let s = state.read(cx);
            (s.focus.clone(), s.from, s.to, s.started)
        };
        let widths: Vec<f32> = self.options.iter().map(|o| option_width(&o.1)).collect();
        let progress: f32 = started.map_or(1.0, |at| {
            motion::progress(at.elapsed(), Duration::ZERO, SLIDE)
        });
        if progress < 1.0 {
            window.request_animation_frame();
        }
        let left: f32 = pill_position(&widths, from, to, progress);
        let pill_width: f32 = widths.get(to).copied().unwrap_or(0.0);
        let focused: bool = focus.is_focused(window);
        let ring: Hsla = if focused {
            to_hsla(tokens.brand)
        } else {
            Hsla::transparent_black()
        };
        let track: Hsla = self.track.unwrap_or_else(|| to_hsla(tokens.surface));
        let on_change: Option<ChangeHandler> = self.on_change.clone();
        let key_change: Option<ChangeHandler> = self.on_change;
        let mut row = h_flex().relative().h(px(TRACK_HEIGHT)).p(px(TRACK_PAD));
        row = row.child(
            div()
                .absolute()
                .top(px(TRACK_PAD))
                .left(px(TRACK_PAD + left))
                .h(px(TRACK_HEIGHT - 2.0 * TRACK_PAD))
                .w(px(pill_width))
                .rounded_full()
                .bg(to_hsla(tokens.surface_raised)),
        );
        for (index, (option_id, label)) in self.options.iter().enumerate() {
            let is_active: bool = index == active;
            let state = state.clone();
            let focus = focus.clone();
            let handler: Option<ChangeHandler> = on_change.clone();
            row = row.child(
                div()
                    .id(ElementId::from(option_id.clone()))
                    .test_support()
                    .aria_label(label.clone())
                    .relative()
                    .h(px(TRACK_HEIGHT - 2.0 * TRACK_PAD))
                    .w(px(widths.get(index).copied().unwrap_or(0.0)))
                    .flex()
                    .items_center()
                    .justify_center()
                    .rounded_full()
                    .cursor_pointer()
                    .text_size(px(13.0))
                    .font_weight(FontWeight::MEDIUM)
                    .text_color(to_hsla(if is_active {
                        tokens.foreground
                    } else {
                        tokens.muted_foreground
                    }))
                    .on_click(move |_, window, cx| {
                        focus.focus(window, cx);
                        if index == active {
                            return;
                        }
                        let gate = Gate {
                            reduce_motion: cx.reduce_motion(),
                            window_active: true,
                            pressure_normal: true,
                            low_power: false,
                            incident_open: false,
                        };
                        state.update(cx, |s, _| {
                            s.from = s.to;
                            s.to = index;
                            s.started = gate.transitions().then(Instant::now);
                        });
                        if let Some(handler) = &handler {
                            handler(index, window, cx);
                        }
                    })
                    .child(label.clone()),
            );
        }
        let keys = move |event: &gpui_kit::KeyDownEvent, window: &mut Window, cx: &mut App| {
            let delta: i32 = match event.keystroke.key.as_str() {
                "left" => -1,
                "right" => 1,
                _ => return,
            };
            let next: usize = step_index(active, len, delta);
            if next != active
                && let Some(handler) = &key_change
            {
                handler(next, window, cx);
            }
        };
        div()
            .id(ElementId::from(self.id))
            .role(Role::RadioGroup)
            .track_focus(&focus)
            .on_key_down(keys)
            .flex_shrink_0()
            // The track padding of a control, not a layout gap.
            .p(px(2.0))
            .rounded_full()
            .border_2()
            .border_color(ring)
            .child(div().rounded_full().bg(track).child(row))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_step_and_clamp_at_the_ends() {
        assert_eq!(step_index(1, 3, 1), 2);
        assert_eq!(step_index(2, 3, 1), 2);
        assert_eq!(step_index(1, 3, -1), 0);
        assert_eq!(step_index(0, 3, -1), 0);
        assert_eq!(step_index(0, 0, 1), 0);
    }

    #[test]
    fn the_pill_slides_between_option_edges() {
        let widths: [f32; 3] = [50.0, 60.0, 70.0];
        assert!((pill_offset(&widths, 2) - 110.0).abs() < f32::EPSILON);
        assert!((pill_position(&widths, 0, 2, 0.0)).abs() < f32::EPSILON);
        assert!((pill_position(&widths, 0, 2, 1.0) - 110.0).abs() < 1e-3);
        let mid: f32 = pill_position(&widths, 0, 2, 0.5);
        assert!(mid > 0.0 && mid < 110.0);
    }
}
