//! The clock of the helper.

use std::time::{SystemTime, UNIX_EPOCH};

use svalnir_core::id::{BootId, ClockDomainId};
use svalnir_core::time::{MonotonicNanos, WallTime};
use thiserror::Error;

use crate::native;
use crate::validation::HelperClock;

/// The clock domain of the monotonic time of the helper. The agent states
/// the same domain for the validity of a request: the two processes read
/// `clock_gettime(CLOCK_MONOTONIC_RAW)` on one host.
pub const CLOCK_DOMAIN: &str = "macos.clock_monotonic_raw";

/// The helper cannot read its clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("the clock of the helper is not available")]
pub struct ClockUnavailable;

/// The source of the time of one validation.
pub trait ClockSource: Send + Sync {
    /// Reads the clocks.
    ///
    /// # Errors
    ///
    /// Returns [`ClockUnavailable`] when a clock cannot be read. The
    /// service then refuses the request.
    fn now(&self) -> Result<HelperClock, ClockUnavailable>;
}

/// The clocks of the host.
///
/// The monotonic time is `clock_gettime(CLOCK_MONOTONIC_RAW)`, and the
/// boot is `kern.bootsessionuuid` with the prefix `boot_`, as the agent
/// states them. The helper compares the timeline of a request with these
/// values; it does not take the timeline from the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemClock {
    clock_domain: ClockDomainId,
    boot_id: BootId,
}

impl SystemClock {
    /// Reads the boot session of the host and makes the clock.
    ///
    /// # Errors
    ///
    /// Returns [`ClockUnavailable`] when the host gives no boot session.
    pub fn new() -> Result<Self, ClockUnavailable> {
        let boot: String = native::boot_session_uuid().ok_or(ClockUnavailable)?;
        Ok(Self {
            clock_domain: ClockDomainId::new(CLOCK_DOMAIN).map_err(|_| ClockUnavailable)?,
            boot_id: BootId::new(format!("boot_{boot}")).map_err(|_| ClockUnavailable)?,
        })
    }
}

impl ClockSource for SystemClock {
    fn now(&self) -> Result<HelperClock, ClockUnavailable> {
        let monotonic: u64 = native::monotonic_raw_nanoseconds().ok_or(ClockUnavailable)?;
        let since_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ClockUnavailable)?;
        let seconds: i64 = i64::try_from(since_epoch.as_secs()).map_err(|_| ClockUnavailable)?;
        let wall: WallTime = WallTime::from_unix(seconds, since_epoch.subsec_nanos())
            .map_err(|_| ClockUnavailable)?;
        Ok(HelperClock {
            wall,
            monotonic: MonotonicNanos::new(monotonic),
            clock_domain: self.clock_domain.clone(),
            boot_id: self.boot_id.clone(),
        })
    }
}
