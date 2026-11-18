//! A line of ticks with labeled thresholds.

use crate::{
    data::model::{Measured, PressureLevel},
    theme::tokens::{Tokens, to_hsla},
    viz::{
        alloc::{CellState, count_f32},
        cells::{Cell, CellLayout, CellStrip},
    },
};
use gpui_kit::{
    App, Hsla, IntoElement, ParentElement as _, Pixels, RenderOnce, SharedString, Styled as _,
    Window,
    component::{ActiveTheme as _, v_flex},
    div, px,
};

/// The tick count of the pressure gauge.
pub const PRESSURE_TICKS: usize = 40;
const TICK_WIDTH: f32 = 4.0;
const TICK_HEIGHT: f32 = 24.0;
const TICK_GAP: f32 = 3.0;

/// Which tone fills the ticks of a pressure level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PressureTone {
    /// The `positive` token.
    Positive,
    /// The `warning` token.
    Warning,
    /// The `negative` token.
    Negative,
}

/// The filled ticks and the tone of a pressure reading; `None` when unavailable.
#[must_use]
pub fn pressure_gauge(
    pressure: &Measured<PressureLevel>,
    ticks: usize,
) -> Option<(usize, PressureTone)> {
    match pressure {
        Measured::Value(PressureLevel::Normal) => Some((ticks / 3, PressureTone::Positive)),
        Measured::Value(PressureLevel::Warning) => Some((ticks * 2 / 3, PressureTone::Warning)),
        Measured::Value(PressureLevel::Critical) => Some((ticks, PressureTone::Negative)),
        Measured::Unavailable(_) => None,
    }
}

/// A line of ticks.
#[derive(IntoElement)]
pub struct TickGauge {
    level: Option<usize>,
    ticks: usize,
    thresholds: Vec<(usize, SharedString)>,
    tone: Option<Hsla>,
    label: SharedString,
    id: SharedString,
}

impl std::fmt::Debug for TickGauge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TickGauge")
            .field("level", &self.level)
            .field("ticks", &self.ticks)
            .finish_non_exhaustive()
    }
}

impl TickGauge {
    /// Creates a gauge with `level` filled ticks of `ticks`; `None` is unavailable.
    pub fn new(level: Option<usize>, ticks: usize) -> Self {
        Self {
            level,
            ticks,
            thresholds: Vec::new(),
            tone: None,
            label: SharedString::from("Gauge"),
            id: SharedString::from("tick-gauge"),
        }
    }

    /// Adds a threshold marker above tick `index`, with a text label.
    #[must_use]
    pub fn threshold(mut self, index: usize, label: impl Into<SharedString>) -> Self {
        self.thresholds.push((index, label.into()));
        self
    }

    /// Sets the color of the filled ticks.
    #[must_use]
    pub fn tone(mut self, tone: Hsla) -> Self {
        self.tone = Some(tone);
        self
    }

    /// Sets the accessible label.
    #[must_use]
    pub fn label(mut self, label: impl Into<SharedString>) -> Self {
        self.label = label.into();
        self
    }

    /// Sets the element id.
    #[must_use]
    pub fn id(mut self, id: impl Into<SharedString>) -> Self {
        self.id = id.into();
        self
    }
}

impl RenderOnce for TickGauge {
    fn render(self, _window: &mut Window, cx: &mut App) -> impl IntoElement {
        let tokens: &Tokens = Tokens::for_dark(cx.theme().is_dark());
        let muted: Hsla = to_hsla(tokens.muted_foreground);
        let layout: CellLayout = CellLayout::Ticks {
            width: px(TICK_WIDTH),
            height: px(TICK_HEIGHT),
            gap: px(TICK_GAP),
        };
        let color: Hsla = self.tone.unwrap_or(muted);
        let filled: usize = if self.tone.is_some() {
            self.level.unwrap_or(0)
        } else {
            0
        };
        let cells: Vec<Cell> = (0..self.ticks)
            .map(|index| Cell {
                state: if index < filled {
                    CellState::Filled
                } else {
                    CellState::Empty
                },
                color,
            })
            .collect();
        let pitch: Pixels = px(TICK_WIDTH + TICK_GAP);
        let (width, _): (Pixels, Pixels) = layout.size_for(self.ticks);
        let markers = self.thresholds.into_iter().map(|(index, text)| {
            div()
                .absolute()
                .left(pitch * count_f32(index))
                .top(px(0.0))
                .flex()
                .flex_col()
                .child(div().w(px(1.0)).h(px(8.0)).bg(muted))
                .child(div().text_size(px(11.0)).text_color(muted).child(text))
        });
        v_flex()
            .child(div().relative().w(width).h(px(28.0)).children(markers))
            .child(CellStrip::new(cells, layout, self.id, self.label).radius(px(1.0)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pressure_maps_to_thirds() {
        assert_eq!(
            pressure_gauge(&Measured::Value(PressureLevel::Normal), 40),
            Some((13, PressureTone::Positive))
        );
        assert_eq!(
            pressure_gauge(&Measured::Value(PressureLevel::Warning), 40),
            Some((26, PressureTone::Warning))
        );
        assert_eq!(
            pressure_gauge(&Measured::Value(PressureLevel::Critical), 40),
            Some((40, PressureTone::Negative))
        );
        assert_eq!(pressure_gauge(&Measured::Unavailable("x".into()), 40), None);
    }
}
