//! The entry of a card when its screen becomes active.

use crate::theme::motion::{self, ENTER, ENTER_DISTANCE_PX, REDUCED_FADE};
use gpui_kit::{
    Animation, AnimationExt as _, AnyElement, InteractiveElement as _, IntoElement,
    ParentElement as _, Styled as _, div, px,
};
use std::time::Duration;

/// The delay between two cards.
pub const CARD_STAGGER: Duration = Duration::from_millis(40);

/// The opacity and the rise in pixels of card `index` at `progress` of the
/// whole entry (`0.0..=1.0` over `total`).
#[must_use]
pub fn entry_state(index: usize, total: Duration, progress: f32, reduce: bool) -> (f32, f32) {
    if reduce {
        return (progress.clamp(0.0, 1.0), 0.0);
    }
    let delay: Duration = CARD_STAGGER.saturating_mul(u32::try_from(index).unwrap_or(u32::MAX));
    let elapsed: Duration = total.mul_f32(progress.clamp(0.0, 1.0));
    let t: f32 = motion::ease_ui_out(motion::progress(elapsed, delay, ENTER));
    (t, ENTER_DISTANCE_PX * (1.0 - t))
}

/// Wraps `card` so that it fades in and rises on activation number
/// `activation`. A new activation number replays the entry. With Reduce
/// Motion only the opacity changes, over 150 ms.
pub fn card_entry(card: AnyElement, index: usize, activation: u64, reduce: bool) -> AnyElement {
    let total: Duration = if reduce {
        REDUCED_FADE
    } else {
        ENTER + CARD_STAGGER.saturating_mul(u32::try_from(index).unwrap_or(0))
    };
    div()
        .id(gpui_kit::SharedString::from(format!(
            "card-entry-{index}-{activation}"
        )))
        .relative()
        .child(card)
        .with_animation(
            gpui_kit::SharedString::from(format!("card-anim-{index}-{activation}")),
            Animation::new(total),
            move |element, progress| {
                let (opacity, rise): (f32, f32) = entry_state(index, total, progress, reduce);
                element.opacity(opacity).top(px(rise))
            },
        )
        .into_any_element()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_starts_hidden_low_and_ends_shown_in_place() {
        let total: Duration = ENTER + CARD_STAGGER * 2;
        let (opacity, rise) = entry_state(2, total, 0.0, false);
        assert!(opacity.abs() < f32::EPSILON && (rise - ENTER_DISTANCE_PX).abs() < f32::EPSILON);
        let (opacity, rise) = entry_state(2, total, 1.0, false);
        assert!((opacity - 1.0).abs() < f32::EPSILON && rise.abs() < f32::EPSILON);
        // A later card waits for its stagger.
        assert!(entry_state(2, total, 0.1, false).0 < entry_state(0, total, 0.1, false).0);
    }

    #[test]
    fn reduce_motion_changes_only_the_opacity() {
        let (opacity, rise) = entry_state(3, REDUCED_FADE, 0.5, true);
        assert!((opacity - 0.5).abs() < f32::EPSILON);
        assert!(rise.abs() < f32::EPSILON);
    }
}
