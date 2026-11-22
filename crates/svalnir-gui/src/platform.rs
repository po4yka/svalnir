//! Display settings of macOS that GPUI does not report.
//!
//! This is the only module of the client that calls `AppKit` or the C
//! library directly.

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

/// Whether the system reports Low Power Mode. On a host that is not macOS,
/// it is off.
#[must_use]
pub fn low_power_mode() -> bool {
    #[cfg(target_os = "macos")]
    {
        objc2_foundation::NSProcessInfo::processInfo().isLowPowerModeEnabled()
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

/// The offset of the local time zone from UTC at `time`, in seconds east.
/// `None` when the host cannot give it; the caller then shows UTC.
///
/// The first call can read the time zone file of the host, so a data source
/// calls this function on its background thread, not in a render.
#[must_use]
pub fn utc_offset_seconds(time: std::time::SystemTime) -> Option<i32> {
    #[cfg(unix)]
    {
        let seconds: u64 = time
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .ok()?
            .as_secs();
        let clock: libc::time_t = libc::time_t::try_from(seconds).ok()?;
        let mut parts = std::mem::MaybeUninit::<libc::tm>::zeroed();
        // SAFETY: `clock` and `parts` are valid for the call and are not
        // shared. `localtime_r` writes only into `parts` and keeps no
        // pointer to it. It returns null on failure, and then `parts` is
        // not read.
        let filled = unsafe { libc::localtime_r(&raw const clock, parts.as_mut_ptr()) };
        if filled.is_null() {
            return None;
        }
        // SAFETY: `localtime_r` returned a pointer that is not null, so it
        // wrote each field of `parts`.
        let parts: libc::tm = unsafe { parts.assume_init() };
        i32::try_from(parts.tm_gmtoff)
            .ok()
            // A real zone is within 18 hours of UTC.
            .filter(|offset| offset.abs() <= 18 * 3600)
    }
    #[cfg(not(unix))]
    {
        let _ = time;
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(unix)]
    fn the_local_offset_of_now_is_a_real_zone() {
        let offset = utc_offset_seconds(std::time::SystemTime::now());
        assert!(offset.is_some_and(|seconds| seconds.abs() <= 18 * 3600));
    }

    #[test]
    fn a_time_before_the_epoch_has_no_offset() {
        let before = std::time::SystemTime::UNIX_EPOCH - std::time::Duration::from_secs(1);
        assert_eq!(utc_offset_seconds(before), None);
    }
}
