//! The adapter for a host that is not macOS.
//!
//! Each query reports that the source does not support the metric. The
//! functions have the signatures of `native.rs`.

use svalnir_core::observation::UnavailableReason;

use super::raw::{RawSwapUsage, RawVmStatistics};

pub(super) fn physical_memory_bytes() -> Result<u64, UnavailableReason> {
    Err(UnavailableReason::Unsupported)
}

pub(super) fn pressure_level() -> Result<i32, UnavailableReason> {
    Err(UnavailableReason::Unsupported)
}

pub(super) fn swap_usage() -> Result<RawSwapUsage, UnavailableReason> {
    Err(UnavailableReason::Unsupported)
}

pub(super) fn boot_session_uuid() -> Result<String, UnavailableReason> {
    Err(UnavailableReason::Unsupported)
}

pub(super) fn vm_page_size() -> Result<u64, UnavailableReason> {
    Err(UnavailableReason::Unsupported)
}

pub(super) fn vm_statistics() -> Result<RawVmStatistics, UnavailableReason> {
    Err(UnavailableReason::Unsupported)
}

pub(super) fn monotonic_raw_nanoseconds() -> Option<u64> {
    None
}

/// No clock is read on this host.
pub(super) const CLOCK_DOMAIN: &str = "unsupported.clock";
