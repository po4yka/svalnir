//! Categorical palette of `DESIGN.md` section 2.

use super::tokens::hex;
use gpui_kit::Rgba;

/// Number of ordered categorical colors; the neutral color is separate.
pub const CATEGORY_COUNT: usize = 8;

const DARK: [u32; CATEGORY_COUNT] = [
    0x0a_84ff, 0x5e_5ce6, 0xbf_5af2, 0x40_c8e0, 0xff_375f, 0xff_d60a, 0x30_d158, 0xff_9f0a,
];
const LIGHT: [u32; CATEGORY_COUNT] = [
    0x00_71e3, 0x4b_49c8, 0x9a_3fc9, 0x0a_7ea4, 0xd8_1e5b, 0x8f_6a00, 0x24_8a3d, 0xc9_3400,
];
const NEUTRAL_DARK: u32 = 0x98_989d;
const NEUTRAL_LIGHT: u32 = 0x6e_6e73;

/// Returns the category color at `index` (0-based, wraps after eight).
pub fn category_color(index: usize, dark: bool) -> Rgba {
    let row: &[u32; CATEGORY_COUNT] = if dark { &DARK } else { &LIGHT };
    hex(row[index % CATEGORY_COUNT])
}

/// Returns the neutral color for system-managed and unclassified data.
pub fn neutral_color(dark: bool) -> Rgba {
    hex(if dark { NEUTRAL_DARK } else { NEUTRAL_LIGHT })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::theme::tokens::Tokens;

    #[test]
    fn colors_1_7_8_equal_brand_positive_warning() {
        for dark in [true, false] {
            let tokens = Tokens::for_dark(dark);
            assert_eq!(category_color(0, dark), tokens.brand);
            assert_eq!(category_color(6, dark), tokens.positive);
            assert_eq!(category_color(7, dark), tokens.warning);
        }
    }

    #[test]
    fn index_wraps() {
        assert_eq!(category_color(8, true), category_color(0, true));
    }
}
