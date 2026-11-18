//! Tests of the theme mapping.

use gpui_kit::{
    TestAppContext, WindowAppearance,
    component::{ActiveTheme as _, Theme},
};
use svalnir_gui::theme::{
    apply,
    tokens::{Tokens, to_hsla},
};

#[gpui_kit::test]
fn dark_and_light_tokens_reach_the_theme(cx: &mut TestAppContext) {
    cx.update(gpui_kit::init);
    for (appearance, tokens) in [
        (WindowAppearance::Dark, Tokens::DARK),
        (WindowAppearance::Light, Tokens::LIGHT),
    ] {
        cx.update(|cx| apply::sync(appearance, cx));
        cx.update(|cx| {
            let theme: &Theme = cx.theme();
            assert_eq!(theme.is_dark(), appearance == WindowAppearance::Dark);
            assert_eq!(theme.background, to_hsla(tokens.background));
            assert_eq!(theme.sidebar, to_hsla(tokens.surface));
            assert_eq!(theme.ring, to_hsla(tokens.brand));
            assert_eq!(theme.danger, to_hsla(tokens.negative));
            assert_ne!(theme.primary, to_hsla(tokens.brand));
            assert!(!theme.shadow);
            assert!(theme.focus_ring);
            assert_eq!(theme.motion.duration_fast.as_millis(), 150);
            assert_eq!(theme.motion.duration_normal.as_millis(), 225);
            assert_eq!(theme.motion.duration_slow.as_millis(), 600);
        });
    }
}
