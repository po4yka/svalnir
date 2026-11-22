//! Maps the tokens onto the `gpui-kit` theme per `DESIGN.md` section 2.

use super::{
    fonts, motion,
    tokens::{Tokens, to_hsla},
};
use gpui_kit::{
    App, Hsla, Rgba, Window, WindowAppearance,
    base::Easing,
    component::{ActiveTheme as _, Theme},
};

fn mix(a: Rgba, b: Rgba) -> Rgba {
    Rgba {
        r: f32::midpoint(a.r, b.r),
        g: f32::midpoint(a.g, b.g),
        b: f32::midpoint(a.b, b.b),
        a: f32::midpoint(a.a, b.a),
    }
}

fn bezier(curve: motion::CubicBezier) -> Option<Easing> {
    Easing::cubic_bezier(curve.x1, curve.y1, curve.x2, curve.y2).ok()
}

/// Writes the tokens of `tokens` into `theme`.
///
/// `primary` is the silver button color, not the brand color. The button
/// gradient itself is a Svalnir style on the button; the theme holds the
/// middle of its two stops, with the lighter stop for hover.
pub fn apply_tokens(theme: &mut Theme, tokens: &Tokens, bundled_fonts: bool) {
    let c = |color: Rgba| -> Hsla { to_hsla(color) };
    let colors = &mut theme.colors;

    colors.background = c(tokens.background);
    colors.title_bar = c(tokens.background);
    colors.title_bar_border = c(tokens.border);

    for slot in [
        &mut colors.sidebar,
        &mut colors.group_box,
        &mut colors.secondary,
        &mut colors.tab_bar,
        &mut colors.status_bar,
    ] {
        *slot = c(tokens.surface);
    }
    colors.status_bar_border = c(tokens.border);

    for slot in [&mut colors.list, &mut colors.table] {
        *slot = c(tokens.surface_inset);
    }
    // `input` is the edge of a checkbox and of a text field in `gpui-kit`,
    // so it has the control edge and not the panel fill.
    colors.input = c(tokens.control_border);

    for slot in [
        &mut colors.popover,
        &mut colors.tab_active,
        &mut colors.list_active,
        &mut colors.sidebar_accent,
    ] {
        *slot = c(tokens.surface_raised);
    }

    colors.muted = c(tokens.inset_tint);

    for slot in [
        &mut colors.foreground,
        &mut colors.popover_foreground,
        &mut colors.sidebar_foreground,
        &mut colors.sidebar_accent_foreground,
    ] {
        *slot = c(tokens.foreground);
    }
    colors.muted_foreground = c(tokens.muted_foreground);

    for slot in [
        &mut colors.border,
        &mut colors.table_row_border,
        &mut colors.sidebar_border,
    ] {
        *slot = c(tokens.border);
    }

    for slot in [
        &mut colors.ring,
        &mut colors.selection,
        &mut colors.link,
        &mut colors.info,
        &mut colors.progress_bar,
    ] {
        *slot = c(tokens.brand);
    }

    colors.success = c(tokens.positive);
    colors.danger = c(tokens.negative);
    colors.warning = c(tokens.warning);

    let silver: Hsla = c(mix(tokens.primary_top, tokens.primary_bottom));
    let silver_hover: Hsla = c(tokens.primary_bottom);
    let silver_active: Hsla = c(tokens.primary_top);
    let on_silver: Hsla = c(tokens.primary_text);
    colors.primary = silver;
    colors.primary_hover = silver_hover;
    colors.primary_active = silver_active;
    colors.primary_foreground = on_silver;
    colors.button_primary = silver;
    colors.button_primary_hover = silver_hover;
    colors.button_primary_active = silver_active;
    colors.button_primary_foreground = on_silver;

    theme.shadow = false;
    theme.focus_ring = true;

    if bundled_fonts {
        theme.font_family = fonts::SANS_FAMILY.into();
        theme.mono_font_family = fonts::MONO_FAMILY.into();
    }

    theme.motion.duration_fast = motion::FAST;
    theme.motion.duration_normal = motion::BASE;
    theme.motion.duration_slow = motion::SLOW;
    if let Some(easing) = bezier(motion::EASE_UI_OUT) {
        theme.motion.easing_enter = easing;
    }
    if let Some(easing) = bezier(motion::EASE_STANDARD) {
        theme.motion.easing_move = easing;
    }
}

/// Maps the tokens of the current theme mode onto the global theme.
///
/// Call it after `Theme::change`, which reloads the registered theme and
/// overwrites earlier edits.
pub fn apply(cx: &mut App) {
    let tokens: Tokens = *Tokens::for_dark(cx.theme().is_dark());
    let geist: bool = fonts::is_registered(fonts::SANS_FAMILY, cx)
        && fonts::is_registered(fonts::MONO_FAMILY, cx);
    Theme::update(cx, |theme| apply_tokens(theme, &tokens, geist));
}

/// Switches the theme to `appearance`, then applies the tokens.
pub fn sync(appearance: WindowAppearance, cx: &mut App) {
    Theme::change(appearance, None, cx);
    apply(cx);
}

/// Applies the theme for `window` now and again when its appearance changes.
pub fn install(window: &mut Window, cx: &mut App) {
    sync(window.appearance(), cx);
    window
        .observe_window_appearance(|window, cx| sync(window.appearance(), cx))
        .detach();
}

/// Applies the theme of `appearance` for good: no observer follows the
/// system appearance afterwards.
pub fn install_fixed(appearance: WindowAppearance, cx: &mut App) {
    sync(appearance, cx);
}
