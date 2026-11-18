//! Bundled fonts: Geist and Geist Mono (SIL Open Font License 1.1).

use gpui_kit::App;
use std::borrow::Cow;

/// Family name of the bundled sans font.
pub const SANS_FAMILY: &str = "Geist";
/// Family name of the bundled mono font.
pub const MONO_FAMILY: &str = "Geist Mono";

/// The bundled font files: Geist v1.9.2 static instances.
const FONTS: &[&[u8]] = &[
    include_bytes!("../../assets/fonts/Geist-Regular.ttf"),
    include_bytes!("../../assets/fonts/Geist-Medium.ttf"),
    include_bytes!("../../assets/fonts/Geist-SemiBold.ttf"),
    include_bytes!("../../assets/fonts/GeistMono-Regular.ttf"),
    include_bytes!("../../assets/fonts/GeistMono-Medium.ttf"),
];

/// Registers the bundled fonts with the text system. When the registration
/// fails, the system fonts apply.
pub fn register(cx: &mut App) {
    let fonts: Vec<Cow<'static, [u8]>> = FONTS.iter().map(|bytes| Cow::Borrowed(*bytes)).collect();
    if let Err(error) = cx.text_system().add_fonts(fonts) {
        tracing::warn!(%error, "cannot register the bundled fonts; using system fonts");
    }
}

/// Returns true when `family` is known to the text system.
pub fn is_registered(family: &str, cx: &App) -> bool {
    cx.text_system()
        .all_font_names()
        .iter()
        .any(|name| name == family)
}
