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

impl CubicBezier {
    /// The eased value at progress `t`, `0.0..=1.0`: the y of the curve at
    /// the parameter whose x is `t`, found by bisection.
    #[must_use]
    pub fn ease(self, t: f32) -> f32 {
        let t: f32 = t.clamp(0.0, 1.0);
        if t <= 0.0 || t >= 1.0 {
            return t;
        }
        let axis = |a: f32, b: f32, u: f32| -> f32 {
            let v: f32 = 1.0 - u;
            3.0 * v * v * u * a + 3.0 * v * u * u * b + u * u * u
        };
        let (mut low, mut high): (f32, f32) = (0.0, 1.0);
        for _ in 0..24 {
            let mid: f32 = f32::midpoint(low, high);
            if axis(self.x1, self.x2, mid) < t {
                low = mid;
            } else {
                high = mid;
            }
        }
        axis(self.y1, self.y2, f32::midpoint(low, high)).clamp(0.0, 1.0)
    }
}

/// `ease-ui-out` at progress `t`: 0 at 0, 1 at 1, monotone between.
#[must_use]
pub fn ease_ui_out(t: f32) -> f32 {
    EASE_UI_OUT.ease(t)
}

/// What allows motion right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gate {
    /// The user set Reduce Motion.
    pub reduce_motion: bool,
    /// The window is the active window.
    pub window_active: bool,
    /// The memory pressure is Normal.
    pub pressure_normal: bool,
}

impl Gate {
    /// Whether a value or a fill may change over time. Only Reduce Motion
    /// forbids it: the value then applies in one step.
    #[must_use]
    pub const fn transitions(&self) -> bool {
        !self.reduce_motion
    }

    /// Whether an effect that never ends (the twinkle) may run. It needs
    /// motion, an active window, and Normal pressure.
    #[must_use]
    pub const fn continuous(&self) -> bool {
        self.transitions() && self.window_active && self.pressure_normal
    }
}

/// The progress `0.0..=1.0` of an animation that started `elapsed` ago, after
/// `delay`, over `duration`.
#[must_use]
pub fn progress(elapsed: Duration, delay: Duration, duration: Duration) -> f32 {
    let Some(running) = elapsed.checked_sub(delay) else {
        return 0.0;
    };
    if duration.is_zero() {
        return 1.0;
    }
    (running.as_secs_f32() / duration.as_secs_f32()).clamp(0.0, 1.0)
}

/// A fraction `0.0..=1.0` in thousandths.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "the value is clamped to 0..=1000 first"
)]
fn to_milli(fraction: f32) -> u32 {
    (fraction.clamp(0.0, 1.0) * 1000.0).round() as u32
}

/// The time at which the fill-in of `segments` segments ends.
#[must_use]
pub fn fill_in_total(segments: usize) -> Duration {
    FILL_STAGGER
        .saturating_mul(u32::try_from(segments.saturating_sub(1)).unwrap_or(u32::MAX))
        .saturating_add(SLOW)
}

/// The fill of segment `index` at `elapsed` into a fill-in: eased over
/// `SLOW`, started `FILL_STAGGER` after the segment before. It ends at 1.0.
#[must_use]
pub fn fill_in(elapsed: Duration, index: usize) -> f32 {
    let delay: Duration = FILL_STAGGER.saturating_mul(u32::try_from(index).unwrap_or(u32::MAX));
    ease_ui_out(progress(elapsed, delay, SLOW))
}

/// The shown front of a scan, easing toward the measured `target`. It starts
/// at `from`, takes `FRONT_EASE`, and never passes `target`.
#[must_use]
pub fn eased_front(from: u64, target: u64, elapsed: Duration) -> u64 {
    if target <= from {
        return target;
    }
    let t: f32 = progress(elapsed, Duration::ZERO, FRONT_EASE);
    if t >= 1.0 {
        return target;
    }
    let part: u128 = u128::from(target - from) * u128::from(to_milli(ease_ui_out(t))) / 1000;
    from.saturating_add(u64::try_from(part).unwrap_or(u64::MAX))
        .min(target)
}

/// Delay between two segments of a fill-in.
pub const FILL_STAGGER: Duration = Duration::from_millis(40);
/// How long the front of a scan takes to reach a new measured value.
pub const FRONT_EASE: Duration = Duration::from_millis(250);
/// The interval of the twinkle timer (about 12 Hz).
pub const TWINKLE_TICK: Duration = Duration::from_millis(83);
/// The interval of the timer of the live head (about 30 Hz).
pub const LIVE_TICK: Duration = Duration::from_millis(33);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_live_head_redraws_at_30_hz_at_most() {
        assert!(LIVE_TICK >= Duration::from_millis(33));
    }

    #[test]
    fn ease_ends_and_is_monotone() {
        assert!(ease_ui_out(0.0).abs() < f32::EPSILON);
        assert!((ease_ui_out(1.0) - 1.0).abs() < f32::EPSILON);
        let mut last: f32 = 0.0;
        for step in 1..=100_u16 {
            let value: f32 = ease_ui_out(f32::from(step) / 100.0);
            assert!(value >= last - 1e-6, "step {step}");
            assert!(value <= 1.0);
            last = value;
        }
        assert!(ease_ui_out(0.2) > 0.5, "ease-out is fast at the start");
    }

    #[test]
    fn gate_follows_reduce_motion_window_and_pressure() {
        for bits in 0..8_u8 {
            let gate = Gate {
                reduce_motion: bits & 1 != 0,
                window_active: bits & 2 != 0,
                pressure_normal: bits & 4 != 0,
            };
            assert_eq!(gate.transitions(), !gate.reduce_motion);
            assert_eq!(
                gate.continuous(),
                !gate.reduce_motion && gate.window_active && gate.pressure_normal
            );
        }
    }

    #[test]
    fn fill_in_per_segment() {
        assert!(fill_in(Duration::ZERO, 0).abs() < f32::EPSILON);
        assert!(fill_in(Duration::from_millis(300), 0) > 0.5);
        // Segment 3 starts 120 ms in.
        assert!(fill_in(Duration::from_millis(100), 3).abs() < f32::EPSILON);
        assert!(fill_in(Duration::from_millis(300), 3) > 0.0);
        let end: Duration = fill_in_total(5);
        for index in 0..5 {
            assert!((fill_in(end, index) - 1.0).abs() < f32::EPSILON, "{index}");
        }
        assert_eq!(end, Duration::from_millis(760));
    }

    #[test]
    fn front_never_passes_and_reaches_the_target() {
        for ms in 0..=300_u64 {
            let shown: u64 = eased_front(100, 1_000, Duration::from_millis(ms));
            assert!((100..=1_000).contains(&shown), "{ms}");
        }
        assert_eq!(eased_front(100, 1_000, FRONT_EASE), 1_000);
        assert_eq!(eased_front(500, 400, Duration::ZERO), 400);
        assert_eq!(eased_front(100, 1_000, Duration::ZERO), 100);
    }
}
