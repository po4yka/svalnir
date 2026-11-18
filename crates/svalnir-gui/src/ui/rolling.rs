//! A number whose digits roll to a new digit when the value changes.

use crate::theme::motion::{self, DIGIT_STAGGER, ENTER};
use gpui_kit::{
    App, AppContext as _, Context, Entity, FontWeight, Hsla, InteractiveElement as _, IntoElement,
    ParentElement as _, Pixels, Render, SharedString, Styled as _, Window, div, px,
};
use std::time::{Duration, Instant};

/// What one character slot of the text does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slot {
    /// A separator, a unit, or a digit that did not change.
    Still(char),
    /// A digit that rolls from `from` to `to`, `delay` after the start.
    Roll {
        /// The old digit.
        from: char,
        /// The new digit.
        to: char,
        /// The wait before the roll.
        delay: Duration,
    },
    /// A digit in a slot that the old text did not have.
    FadeIn {
        /// The digit.
        digit: char,
        /// The wait before the fade.
        delay: Duration,
    },
}

/// The slots of `new`, compared with `old` from the right. The digit slots
/// are ranked from the right: the rightmost starts first, and each one to the
/// left starts `DIGIT_STAGGER` later.
#[must_use]
pub fn diff_slots(old: &str, new: &str) -> Vec<Slot> {
    let old: Vec<char> = old.chars().collect();
    let new: Vec<char> = new.chars().collect();
    let mut rank: u32 = 0;
    let mut slots: Vec<Slot> = Vec::with_capacity(new.len());
    for (index, &ch) in new.iter().enumerate().rev() {
        let from_right: usize = new.len() - 1 - index;
        let before: Option<char> = old.len().checked_sub(1 + from_right).map(|i| old[i]);
        if !ch.is_ascii_digit() {
            slots.push(Slot::Still(ch));
            continue;
        }
        let delay: Duration = DIGIT_STAGGER.saturating_mul(rank);
        rank += 1;
        slots.push(match before {
            Some(prev) if prev == ch => Slot::Still(ch),
            Some(prev) if prev.is_ascii_digit() => Slot::Roll {
                from: prev,
                to: ch,
                delay,
            },
            _ => Slot::FadeIn { digit: ch, delay },
        });
    }
    slots.reverse();
    slots
}

/// When the roll of `slots` ends, from its start.
#[must_use]
pub fn roll_total(slots: &[Slot]) -> Duration {
    slots
        .iter()
        .filter_map(|slot| match slot {
            Slot::Roll { delay, .. } | Slot::FadeIn { delay, .. } => Some(*delay),
            Slot::Still(_) => None,
        })
        .max()
        .map_or(Duration::ZERO, |delay| delay + ENTER)
}

/// The entity that remembers the old text and the start of the roll.
#[derive(Debug)]
pub struct RollingNumber {
    id: SharedString,
    text: SharedString,
    slots: Vec<Slot>,
    started: Instant,
    size: f32,
    weight: FontWeight,
    color: Hsla,
    digit_width: Option<(f32, f32)>,
}

impl RollingNumber {
    /// Creates the entity with an element id.
    pub fn new(id: impl Into<SharedString>, cx: &mut App) -> Entity<Self> {
        let id: SharedString = id.into();
        cx.new(|_| Self {
            id,
            text: SharedString::default(),
            slots: Vec::new(),
            started: Instant::now(),
            size: 30.0,
            weight: FontWeight::MEDIUM,
            color: Hsla::default(),
            digit_width: None,
        })
    }

    /// Sets the text. An equal text changes nothing. With Reduce Motion the
    /// text applies in one step.
    pub fn set_text(&mut self, text: SharedString, cx: &mut Context<Self>) {
        if self.text == text {
            return;
        }
        self.slots = if cx.reduce_motion() || self.text.is_empty() {
            diff_slots(&text, &text)
        } else {
            diff_slots(&self.text, &text)
        };
        self.text = text;
        self.started = Instant::now();
        cx.notify();
    }

    /// Sets the text size, weight, and color.
    pub fn set_style(&mut self, size: f32, weight: FontWeight, color: Hsla) {
        self.size = size;
        self.weight = weight;
        self.color = color;
    }
}

impl Render for RollingNumber {
    fn render(&mut self, window: &mut Window, _cx: &mut Context<Self>) -> impl IntoElement {
        let size: f32 = self.size;
        let line: f32 = (size * 1.25).round();
        let width: f32 = match self.digit_width {
            Some((for_size, w)) if (for_size - size).abs() < f32::EPSILON => w,
            _ => {
                let mut font = window.text_style().font();
                font.weight = self.weight;
                let id = window.text_system().resolve_font(&font);
                let measured: Pixels = window
                    .text_system()
                    .advance(id, px(size), '0')
                    .map_or(px(size * 0.6), |advance| advance.width);
                let w: f32 = f32::from(measured);
                self.digit_width = Some((size, w));
                w
            }
        };
        let elapsed: Duration = self.started.elapsed();
        if elapsed < roll_total(&self.slots) {
            window.request_animation_frame();
        }
        let color: Hsla = self.color;
        let mut row = div()
            .id(self.id.clone())
            .flex()
            .flex_row()
            .h(px(line))
            .text_size(px(size))
            .font_weight(self.weight)
            .text_color(color);
        for slot in &self.slots {
            let cell = |top: f32, ch: char, alpha: f32| {
                div()
                    .absolute()
                    .top(px(top))
                    .left_0()
                    .w(px(width))
                    .h(px(line))
                    .opacity(alpha)
                    .child(ch.to_string())
            };
            row = row.child(match *slot {
                Slot::Still(ch) if ch.is_ascii_digit() => div()
                    .relative()
                    .w(px(width))
                    .h(px(line))
                    .child(cell(0.0, ch, 1.0)),
                Slot::Still(ch) => div().h(px(line)).child(ch.to_string()),
                Slot::Roll { from, to, delay } => {
                    let t: f32 = motion::ease_ui_out(motion::progress(elapsed, delay, ENTER));
                    div()
                        .relative()
                        .overflow_hidden()
                        .w(px(width))
                        .h(px(line))
                        .child(cell(-t * line, from, 1.0))
                        .child(cell((1.0 - t) * line, to, 1.0))
                }
                Slot::FadeIn { digit, delay } => {
                    let t: f32 = motion::ease_ui_out(motion::progress(elapsed, delay, ENTER));
                    div()
                        .relative()
                        .w(px(width))
                        .h(px(line))
                        .child(cell(0.0, digit, t))
                }
            });
        }
        row
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_changed_digits_roll_and_the_right_one_starts_first() {
        let slots = diff_slots("266.1", "266.4");
        assert_eq!(slots[0], Slot::Still('2'));
        assert_eq!(slots[3], Slot::Still('.'));
        assert_eq!(
            slots[4],
            Slot::Roll {
                from: '1',
                to: '4',
                delay: Duration::ZERO
            }
        );
        let slots = diff_slots("266.1", "277.1");
        assert_eq!(
            slots[1],
            Slot::Roll {
                from: '6',
                to: '7',
                delay: DIGIT_STAGGER * 2
            }
        );
        assert_eq!(slots[0], Slot::Still('2'));
    }

    #[test]
    fn a_new_slot_fades_in() {
        let slots = diff_slots("99.9", "100.0");
        assert!(matches!(slots[0], Slot::FadeIn { digit: '1', .. }));
        assert!(matches!(
            slots[4],
            Slot::Roll {
                from: '9',
                to: '0',
                ..
            }
        ));
    }

    #[test]
    fn equal_text_has_no_motion() {
        assert_eq!(roll_total(&diff_slots("12.5", "12.5")), Duration::ZERO);
        assert_eq!(roll_total(&diff_slots("12.5", "12.6")), ENTER);
    }
}
