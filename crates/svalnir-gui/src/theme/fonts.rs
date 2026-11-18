//! Bundled fonts: Geist and Geist Mono (SIL Open Font License 1.1).

use gpui_kit::App;
use std::borrow::Cow;

/// Family name of the bundled sans font.
pub const SANS_FAMILY: &str = "Geist";
/// Family name of the bundled mono font.
pub const MONO_FAMILY: &str = "Geist Mono";

// TODO(npochaev): add the Geist and Geist Mono font files (SIL OFL 1.1, with
// OFL.txt and a THIRD_PARTY_NOTICES.md entry) to `crates/svalnir-gui/assets/fonts/`
// and list them here with `include_bytes!`, for example
// `include_bytes!("../../assets/fonts/Geist-Regular.ttf")`. Until then the
// client uses the system fonts.
const FONTS: &[&[u8]] = &[];

/// Registers the bundled fonts with the text system. Does nothing while no
/// font file is bundled.
pub fn register(cx: &mut App) {
    if FONTS.is_empty() {
        return;
    }
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
