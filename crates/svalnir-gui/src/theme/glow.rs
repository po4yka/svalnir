//! Whether the client draws the glow of the LED marks (`DESIGN.md` §5).

use crate::platform::DisplayAccessibility;
use gpui_kit::{App, Global};

/// The state of the glow for all windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Glow {
    enabled: bool,
}

impl Global for Glow {}

/// Decides the glow: off with Reduce Transparency, with Increase Contrast,
/// and while the memory pressure state is not normal.
#[must_use]
pub const fn decide(display: DisplayAccessibility, pressure_normal: bool) -> bool {
    !display.reduce_transparency && !display.increase_contrast && pressure_normal
}

/// Whether a mark draws its glow now. With no decision yet, the glow is on.
#[must_use]
pub fn enabled(cx: &App) -> bool {
    cx.try_global::<Glow>().is_none_or(|glow| glow.enabled)
}

/// Records the decision. Each window draws again when the decision changes.
pub fn set(enabled: bool, cx: &mut App) {
    if cx.try_global::<Glow>().map(|glow| glow.enabled) != Some(enabled) {
        cx.set_global(Glow { enabled });
        cx.refresh_windows();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn display(reduce_transparency: bool, increase_contrast: bool) -> DisplayAccessibility {
        DisplayAccessibility {
            reduce_transparency,
            increase_contrast,
        }
    }

    #[test]
    fn the_glow_needs_each_condition() {
        assert!(decide(display(false, false), true));
        assert!(!decide(display(true, false), true));
        assert!(!decide(display(false, true), true));
        assert!(!decide(display(false, false), false));
    }
}
