//! Host memory adapters.
//!
//! The module reads the native memory-pressure state, the physical memory,
//! the VM statistics with the runtime page size, and the swap space, and
//! gives them as host-scoped observations. It changes nothing on the host.
//!
//! Owning specification: `docs/RESOURCE_MODEL.md` sections 5, 6, 9, 10, and
//! 12.
//!
//! | Item | Use |
//! | --- | --- |
//! | [`CollectionContext`] | Who collects, in which boot, on which clock |
//! | [`collect_memory_snapshot`] | Each host memory metric, one time |
//! | [`collect_pressure`] | `memory.pressure` from a synchronous query |
//! | [`collect_physical_memory`] | `memory.physical_bytes` |
//! | [`collect_vm_statistics`] | The `memory.vm.*`, `memory.compressor.*`, and swap counters |
//! | [`collect_swap_usage`] | The `memory.swap.*_bytes` gauges |
//! | [`swap_activity`] | Swap-in and swap-out rates from two VM samples |
//! | `PressureSubscription` | Native pressure events (macOS only) |
//!
//! A failed or denied native query is an unavailable reading with a reason.
//! It is not a zero. The builders ([`pressure_observation`],
//! [`physical_memory_observation`], [`vm_statistics`], [`swap_usage`]) take
//! raw samples, so policy code and tests can use recorded or synthetic
//! numbers.
//!
//! `native.rs` and `event.rs` are the only files of this module with
//! `unsafe` code.

pub mod context;
#[cfg(target_os = "macos")]
pub mod event;
pub mod host;
pub mod pressure;
pub mod rate;
pub mod raw;

#[cfg(target_os = "macos")]
mod native;
#[cfg(not(target_os = "macos"))]
#[path = "unsupported.rs"]
mod native;

use svalnir_core::observation::Observation;
use svalnir_core::quantity::Bytes;
use svalnir_core::state::PressureState;

pub use context::{
    Clock, ClockError, CollectError, CollectionContext, ContextError, ContextIdentity, SystemClock,
};
#[cfg(target_os = "macos")]
pub use event::{PressureEvent, PressureSubscription, ReceiveTime, SubscribeError};
pub use host::{
    SwapUsage, VmStatistics, collect_physical_memory, collect_swap_usage, collect_vm_statistics,
    physical_memory_observation, swap_usage, vm_statistics,
};
pub use pressure::{collect_pressure, pressure_observation, pressure_state_from_level};
pub use rate::{
    CounterRate, PageRate, RateLimits, RateUnavailable, SwapActivity, counter_rate, swap_activity,
};
pub use raw::{RawSwapUsage, RawVmStatistics, RawVmStatisticsRevision1};

/// Each host memory metric from one collection pass.
///
/// The four parts come from four native queries. Each part has its own
/// sample, so a consumer can check the skew between them. The parts are not
/// one simultaneous kernel observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemorySnapshot {
    /// `memory.pressure` from a synchronous query.
    pub pressure: Observation<PressureState>,
    /// `memory.physical_bytes`.
    pub physical: Observation<Bytes>,
    /// The VM gauges, the compressor metrics, and the paging and swap
    /// counters.
    pub vm: VmStatistics,
    /// The swap space gauges.
    pub swap: SwapUsage,
}

/// Reads each host memory metric one time.
///
/// # Errors
///
/// Returns a [`CollectError`] when the clock gives no acquisition window. A
/// failed native query is an unavailable reading in the snapshot, not an
/// error.
pub fn collect_memory_snapshot(
    context: &CollectionContext,
) -> Result<MemorySnapshot, CollectError> {
    Ok(MemorySnapshot {
        pressure: collect_pressure(context)?,
        physical: collect_physical_memory(context)?,
        vm: collect_vm_statistics(context)?,
        swap: collect_swap_usage(context)?,
    })
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use std::collections::HashSet;

    use super::{CollectionContext, RateLimits, collect_memory_snapshot, swap_activity};

    const LIMITS: RateLimits = RateLimits {
        max_interval: svalnir_core::quantity::Nanoseconds::new(60_000_000_000),
    };

    #[test]
    fn a_snapshot_of_the_host_has_each_part_with_its_own_sample() {
        let context = CollectionContext::for_current_process().unwrap();
        let snapshot = collect_memory_snapshot(&context).unwrap();
        let samples: HashSet<&str> = [
            snapshot.pressure.sample.sample_id.as_str(),
            snapshot.physical.sample.sample_id.as_str(),
            snapshot.vm.sample.sample_id.as_str(),
            snapshot.swap.used.sample.sample_id.as_str(),
        ]
        .into_iter()
        .collect();
        assert_eq!(samples.len(), 4);
        assert!(snapshot.physical.is_available());
        assert!(snapshot.vm.free.is_available());
        assert!(snapshot.swap.allocated.is_available());
        serde_json::to_string(&snapshot.physical).unwrap();
        serde_json::to_string(&snapshot.vm.swapouts).unwrap();
    }

    #[test]
    fn two_snapshots_of_the_host_give_a_finite_swap_rate() {
        let context = CollectionContext::for_current_process().unwrap();
        let earlier = collect_memory_snapshot(&context).unwrap().vm;
        assert!(swap_activity(None, &earlier, LIMITS).swapins.is_err());
        std::thread::sleep(std::time::Duration::from_millis(20));
        let later = collect_memory_snapshot(&context).unwrap().vm;
        let activity = swap_activity(Some(&earlier), &later, LIMITS);
        let swapins = activity.swapins.unwrap();
        let swapouts = activity.swapouts.unwrap();
        assert!(swapins.pages_per_second().is_finite());
        assert!(swapins.pages_per_second() >= 0.0);
        assert!(swapouts.page_equivalent_bytes_per_second().is_finite());
        assert!(swapouts.rate.interval.get() > 0);
    }
}
