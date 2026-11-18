//! The pressure history of the Overview: one tick per host sample.

use crate::{
    data::model::{HostSample, Measured, PressureLevel},
    theme::tokens::{Tokens, to_hsla},
};
use gpui_kit::{
    App, BoxShadow, ElementId, Hsla, InteractiveElement as _, IntoElement, ParentElement as _,
    RenderOnce, Role, SharedString, Styled as _, TestSupportExt as _, Window,
    component::{ActiveTheme as _, h_flex},
    div, hsla, point,
    prelude::*,
    px,
};

/// The most ticks of the track.
pub const TRACK_TICKS: usize = 90;

/// What one slot of the track shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TickState {
    /// Normal pressure.
    Normal,
    /// Warning pressure.
    Warning,
    /// Critical pressure.
    Critical,
    /// An unavailable sample, or a slot without a sample.
    Empty,
}

/// The state of one pressure reading; unavailable is never Normal.
#[must_use]
pub const fn state_of(pressure: &Measured<PressureLevel>) -> TickState {
    match pressure {
        Measured::Value(PressureLevel::Normal) => TickState::Normal,
        Measured::Value(PressureLevel::Warning) => TickState::Warning,
        Measured::Value(PressureLevel::Critical) => TickState::Critical,
        Measured::Unavailable(_) => TickState::Empty,
    }
}

/// The `slots` states of the track: the newest sample at the right, empty
/// slots at the left.
#[must_use]
pub fn track_states<'a>(
    history: impl ExactSizeIterator<Item = &'a HostSample>,
    slots: usize,
) -> Vec<TickState> {
    let skip: usize = history.len().saturating_sub(slots);
    let mut states: Vec<TickState> = history.skip(skip).map(|s| state_of(&s.pressure)).collect();
    let mut out: Vec<TickState> = vec![TickState::Empty; slots.saturating_sub(states.len())];
    out.append(&mut states);
    out
}

/// The accessible label: the count of each level.
#[must_use]
pub fn track_label(states: &[TickState]) -> String {
    let count = |wanted: TickState| states.iter().filter(|s| **s == wanted).count();
    let samples: usize = states.iter().filter(|s| **s != TickState::Empty).count();
    format!(
        "Pressure history: {samples} measured samples, {} normal, {} warning, {} critical",
        count(TickState::Normal),
        count(TickState::Warning),
        count(TickState::Critical)
    )
}

/// The track as an element.
#[derive(IntoElement, Debug)]
pub struct TickTrack {
    id: SharedString,
    states: Vec<TickState>,
    sample_count: usize,
}

impl TickTrack {
    /// Creates a track from `states` (see [`track_states`]); `sample_count`
    /// is the number of samples that the caption names.
    pub fn new(id: impl Into<SharedString>, states: Vec<TickState>, sample_count: usize) -> Self {
        Self {
            id: id.into(),
            states,
            sample_count,
        }
    }
}

impl RenderOnce for TickTrack {
    fn render(self, _window: &mut Window, cx: &mut App) -> impl IntoElement {
        let tokens: &Tokens = Tokens::for_dark(cx.theme().is_dark());
        let mono: SharedString = cx.theme().mono_font_family.clone();
        let label: String = track_label(&self.states);
        let last: usize = self.states.len().saturating_sub(1);
        let mut row = h_flex().gap(px(2.0)).h(px(16.0));
        for (index, state) in self.states.iter().enumerate() {
            let color: Hsla = match state {
                TickState::Normal => to_hsla(tokens.positive),
                TickState::Warning => to_hsla(tokens.warning),
                TickState::Critical => to_hsla(tokens.negative),
                TickState::Empty => to_hsla(tokens.border),
            };
            let head: bool = index == last && *state != TickState::Empty;
            let mut tick = div().w(px(3.0)).h(px(16.0)).rounded(px(1.0));
            if head {
                let white: Hsla = hsla(0.0, 0.0, 1.0, 0.5);
                tick = tick.bg(color).shadow(vec![BoxShadow {
                    color: color.opacity(0.6),
                    offset: point(px(0.0), px(0.0)),
                    blur_radius: px(8.0),
                    spread_radius: px(0.0),
                    inset: false,
                }]);
                tick = tick.child(div().size_full().rounded(px(1.0)).bg(white));
            } else {
                tick = tick.bg(color);
            }
            row = row.child(tick);
        }
        div()
            .flex()
            .flex_col()
            .gap(px(6.0))
            .child(
                div()
                    .id(ElementId::from(self.id.clone()))
                    .role(Role::Image)
                    .test_support()
                    .aria_label(SharedString::from(label))
                    .child(row),
            )
            .child(
                div()
                    .font_family(mono)
                    .text_size(px(10.0))
                    .text_color(to_hsla(tokens.muted_foreground))
                    .child(format!(
                        "PRESSURE \u{b7} {} {} \u{b7} SINCE THIS WINDOW OPENED \u{b7} 1 TICK = 1 SAMPLE",
                        self.sample_count,
                        if self.sample_count == 1 {
                            "SAMPLE"
                        } else {
                            "SAMPLES"
                        }
                    )),
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    fn sample(pressure: Measured<PressureLevel>) -> HostSample {
        HostSample {
            at: SystemTime::UNIX_EPOCH,
            pressure,
            swap_used: Measured::Value(0),
            disk_available: Measured::Value(0),
        }
    }

    #[test]
    fn unavailable_is_empty_not_normal() {
        assert_eq!(
            state_of(&Measured::Unavailable("x".into())),
            TickState::Empty
        );
        assert_eq!(
            state_of(&Measured::Value(PressureLevel::Normal)),
            TickState::Normal
        );
    }

    #[test]
    fn the_newest_sample_is_at_the_right_and_slots_pad_left() {
        let history = [
            sample(Measured::Value(PressureLevel::Normal)),
            sample(Measured::Unavailable("x".into())),
            sample(Measured::Value(PressureLevel::Critical)),
        ];
        let states = track_states(history.iter(), 5);
        assert_eq!(
            states,
            vec![
                TickState::Empty,
                TickState::Empty,
                TickState::Normal,
                TickState::Empty,
                TickState::Critical
            ]
        );
        let label = track_label(&states);
        assert!(label.contains("2 measured samples"), "{label}");
        assert!(
            label.contains("1 normal") && label.contains("1 critical"),
            "{label}"
        );
    }

    #[test]
    fn the_track_keeps_only_the_newest_slots() {
        let history: Vec<HostSample> = (0..100)
            .map(|_| sample(Measured::Value(PressureLevel::Warning)))
            .collect();
        assert_eq!(track_states(history.iter(), TRACK_TICKS).len(), TRACK_TICKS);
    }
}
