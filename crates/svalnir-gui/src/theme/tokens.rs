//! Color and shape tokens of `DESIGN.md` section 2.

use gpui_kit::{Hsla, Pixels, Rgba, px};

/// Builds an opaque color from a `0xRRGGBB` value.
pub const fn hex(value: u32) -> Rgba {
    hex_alpha(value, 1.0)
}

/// Builds a color from a `0xRRGGBB` value and an alpha in `0.0..=1.0`.
pub const fn hex_alpha(value: u32, alpha: f32) -> Rgba {
    Rgba {
        r: ((value >> 16) & 0xff) as u8 as f32 / 255.0,
        g: ((value >> 8) & 0xff) as u8 as f32 / 255.0,
        b: (value & 0xff) as u8 as f32 / 255.0,
        a: alpha,
    }
}

/// Converts a token color to the `Hsla` that GPUI styles take.
pub fn to_hsla(color: Rgba) -> Hsla {
    Hsla::from(color)
}

/// One theme of the color table in `DESIGN.md` section 2.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Tokens {
    /// Window.
    pub background: Rgba,
    /// Shell.
    pub surface: Rgba,
    /// Panel.
    pub surface_inset: Rgba,
    /// Popover, menu, tooltip, active segment.
    pub surface_raised: Rgba,
    /// Inset block inside a panel: foreground at 4%.
    pub inset_tint: Rgba,
    /// Primary text and values.
    pub foreground: Rgba,
    /// Labels, units, secondary text.
    pub muted_foreground: Rgba,
    /// Dividers and empty cells only.
    pub border: Rgba,
    /// The edge of an unchecked checkbox, a radio, and a text field: 3:1 or
    /// more against `surface`, `surface-inset`, and `inset-tint`.
    pub control_border: Rgba,
    /// Activity in progress, selection, focus ring.
    pub brand: Rgba,
    /// Verified good outcome.
    pub positive: Rgba,
    /// Failure, destructive action.
    pub negative: Rgba,
    /// Threshold near, partial or unknown outcome.
    pub warning: Rgba,
    /// Top stop of the silver primary button gradient.
    pub primary_top: Rgba,
    /// Bottom stop of the silver primary button gradient.
    pub primary_bottom: Rgba,
    /// Text on the primary button.
    pub primary_text: Rgba,
    /// Top stop of the secondary button gradient.
    pub secondary_top: Rgba,
    /// Bottom stop of the secondary button gradient.
    pub secondary_bottom: Rgba,
}

impl Tokens {
    /// The dark theme, the reference theme.
    pub const DARK: Self = Self {
        background: hex(0x0c_0c0c),
        surface: hex(0x19_1919),
        surface_inset: hex(0x10_1010),
        surface_raised: hex(0x25_2525),
        inset_tint: hex_alpha(0xf5_f5f5, 0.04),
        foreground: hex(0xf5_f5f5),
        muted_foreground: hex(0x98_989b),
        border: hex_alpha(0xff_ffff, 0.06),
        control_border: hex(0x6e_6e72),
        brand: hex(0x0a_84ff),
        positive: hex(0x30_d158),
        negative: hex(0xff_453a),
        warning: hex(0xff_9f0a),
        primary_top: hex(0xab_abab),
        primary_bottom: hex(0xff_ffff),
        primary_text: hex(0x11_1111),
        secondary_top: hex(0x1d_1d1d),
        secondary_bottom: hex(0x26_2626),
    };

    /// The light theme.
    pub const LIGHT: Self = Self {
        background: hex(0xf7_f7f8),
        surface: hex(0xed_edef),
        surface_inset: hex(0xff_ffff),
        surface_raised: hex(0xe2_e2e4),
        inset_tint: hex_alpha(0x16_1618, 0.04),
        foreground: hex(0x16_1618),
        muted_foreground: hex(0x63_6368),
        border: hex_alpha(0x16_1618, 0.07),
        control_border: hex(0x8e_8e93),
        brand: hex(0x00_71e3),
        positive: hex(0x24_8a3d),
        negative: hex(0xd7_0015),
        warning: hex(0xc9_3400),
        primary_top: hex(0xe6_e6e6),
        primary_bottom: hex(0xff_ffff),
        primary_text: hex(0x11_1111),
        secondary_top: hex(0xe2_e2e2),
        secondary_bottom: hex(0xec_ecec),
    };

    /// Returns the tokens of the dark or the light theme.
    pub const fn for_dark(dark: bool) -> &'static Self {
        if dark { &Self::DARK } else { &Self::LIGHT }
    }
}

/// Shell radius.
pub const SHELL_RADIUS: Pixels = px(22.0);
/// Shell padding.
pub const SHELL_PADDING: Pixels = px(6.0);
/// Panel radius.
pub const PANEL_RADIUS: Pixels = px(16.0);
/// Panel padding.
pub const PANEL_PADDING: Pixels = px(16.0);
/// Panel padding in dense lists.
pub const PANEL_PADDING_DENSE: Pixels = px(12.0);
/// Inset radius.
pub const INSET_RADIUS: Pixels = px(12.0);
/// Inset vertical padding.
pub const INSET_PADDING_Y: Pixels = px(12.0);
/// Inset horizontal padding.
pub const INSET_PADDING_X: Pixels = px(14.0);
/// Icon tile radius.
pub const ICON_TILE_RADIUS: Pixels = px(10.0);
/// Icon tile size (square).
pub const ICON_TILE_SIZE: Pixels = px(36.0);
/// Icon size inside an icon tile.
pub const ICON_TILE_GLYPH: Pixels = px(18.0);
/// Gap between shells in a dashboard.
pub const GRID_GAP: Pixels = px(12.0);
/// Spacing step 1: a label and its own value or caption.
pub const SPACE_1: Pixels = px(4.0);
/// Spacing step 2: rows of one group.
pub const SPACE_2: Pixels = px(8.0);
/// Spacing step 3: blocks inside a panel. Same as `GRID_GAP`.
pub const SPACE_3: Pixels = px(12.0);
/// Spacing step 4: panel padding and the gap between two columns of one chart block.
pub const SPACE_4: Pixels = px(16.0);
/// Spacing step 6: a chart and its legend side by side, and the content padding of the window.
pub const SPACE_6: Pixels = px(24.0);
/// Cell radius.
pub const CELL_RADIUS: Pixels = px(3.0);
/// Default cell size in a grid.
pub const CELL_SIZE: Pixels = px(14.0);
/// Gap between cells in a grid.
pub const CELL_GAP: Pixels = px(4.0);
/// Padding of the content area.
pub const CONTENT_PADDING: Pixels = px(24.0);
/// Height of the status line.
pub const STATUS_LINE_HEIGHT: Pixels = px(28.0);
/// Window width below which the sidebar collapses to icons.
pub const SIDEBAR_COLLAPSE_WIDTH: Pixels = px(900.0);

#[cfg(test)]
mod tests {
    use super::*;

    fn close(a: f32, b: f32) -> bool {
        (a - b).abs() < 1e-6
    }

    #[test]
    fn hex_splits_channels() {
        let color: Rgba = hex(0x0c_80ff);
        assert!(close(color.r, 12.0 / 255.0));
        assert!(close(color.g, 128.0 / 255.0));
        assert!(close(color.b, 1.0));
        assert!(close(color.a, 1.0));
    }

    #[test]
    fn hex_alpha_keeps_alpha() {
        assert!(close(hex_alpha(0xff_ffff, 0.06).a, 0.06));
    }

    #[test]
    fn dark_tokens_match_the_design_table() {
        assert_eq!(Tokens::DARK.background, hex(0x0c_0c0c));
        assert_eq!(Tokens::DARK.surface, hex(0x19_1919));
        assert_eq!(Tokens::DARK.brand, hex(0x0a_84ff));
        assert_eq!(Tokens::DARK.primary_top, hex(0xab_abab));
        assert!(close(Tokens::DARK.border.a, 0.06));
    }

    #[test]
    fn light_tokens_match_the_design_table() {
        assert_eq!(Tokens::LIGHT.background, hex(0xf7_f7f8));
        assert_eq!(Tokens::LIGHT.surface_inset, hex(0xff_ffff));
        assert_eq!(Tokens::LIGHT.warning, hex(0xc9_3400));
        assert_eq!(Tokens::LIGHT.secondary_bottom, hex(0xec_ecec));
        assert!(close(Tokens::LIGHT.border.a, 0.07));
    }

    #[test]
    fn for_dark_selects_the_theme() {
        assert_eq!(Tokens::for_dark(true), &Tokens::DARK);
        assert_eq!(Tokens::for_dark(false), &Tokens::LIGHT);
    }
}
