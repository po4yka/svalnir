//! Display settings of macOS that GPUI does not report.
//!
//! This is the only module of the client that calls `AppKit` directly.

/// The accessibility display settings that change how the client draws.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DisplayAccessibility {
    /// The user set Reduce Transparency.
    pub reduce_transparency: bool,
    /// The user set Increase Contrast.
    pub increase_contrast: bool,
}

impl DisplayAccessibility {
    /// Reads the settings from the shared workspace. Call it on the main
    /// thread. On a host that is not macOS, each setting is off.
    #[must_use]
    pub fn read() -> Self {
        #[cfg(target_os = "macos")]
        {
            let workspace = objc2_app_kit::NSWorkspace::sharedWorkspace();
            Self {
                reduce_transparency: workspace.accessibilityDisplayShouldReduceTransparency(),
                increase_contrast: workspace.accessibilityDisplayShouldIncreaseContrast(),
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            Self::default()
        }
    }
}
