//! Motion constants of `DESIGN.md` section 6.

use std::time::Duration;

/// Control points of a CSS-style cubic Bezier easing curve.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CubicBezier {
    /// First control point, x.
    pub x1: f32,
    /// First control point, y.
    pub y1: f32,
    /// Second control point, x.
    pub x2: f32,
    /// Second control point, y.
    pub y2: f32,
}

/// Default for entry and for value changes.
pub const EASE_UI_OUT: CubicBezier = CubicBezier {
    x1: 0.23,
    y1: 1.0,
    x2: 0.32,
    y2: 1.0,
};
/// Sheets and large panels.
pub const EASE_DRAWER: CubicBezier = CubicBezier {
    x1: 0.32,
    y1: 0.72,
    x2: 0.0,
    y2: 1.0,
};
/// Color and opacity changes.
pub const EASE_STANDARD: CubicBezier = CubicBezier {
    x1: 0.4,
    y1: 0.0,
    x2: 0.2,
    y2: 1.0,
};

/// Hover, press, color.
pub const FAST: Duration = Duration::from_millis(150);
/// Segmented pill, tabs, tooltip, menu (the 225 ms middle of 200 to 250 ms).
pub const BASE: Duration = Duration::from_millis(225);
/// Card or row entry: fade and move up 6 px.
pub const ENTER: Duration = Duration::from_millis(320);
/// Bar fill, gauge sweep, chart redraw (the 600 ms middle of 500 to 700 ms).
pub const SLOW: Duration = Duration::from_millis(600);
/// Delay between adjacent digits, right to left.
pub const DIGIT_STAGGER: Duration = Duration::from_millis(24);
/// Delay between adjacent cells or ticks (the 10 ms middle of 8 to 12 ms).
pub const CELL_STAGGER: Duration = Duration::from_millis(10);
/// Distance of the entry move, in pixels.
pub const ENTER_DISTANCE_PX: f32 = 6.0;
/// Opacity-only change that replaces movement with Reduce Motion on.
pub const REDUCED_FADE: Duration = Duration::from_millis(150);
