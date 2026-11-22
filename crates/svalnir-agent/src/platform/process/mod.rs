//! Process inventory and identity adapters.
//!
//! The module gives the inventory of the processes of the current user, the
//! identity of each process generation (PID, start time, owner, boot, and
//! executable), the application association, and the process measures. It
//! reads data only: no function sends a signal or changes a process.
//!
//! Owning specification: `docs/RESOURCE_MODEL.md` sections 2, 6, 11, and 12.
//!
//! | Part | Content |
//! | --- | --- |
//! | [`ProcessSource`] | The safe boundary of the native queries |
//! | [`DarwinProcessSource`] | The macOS queries; the only `unsafe` code |
//! | [`ProcessCollector`] | Identity, metrics, and attribution of a snapshot |
//! | [`footprint_growth`], [`cpu_usage`], [`derive_between`] | Pure functions over injected samples |
//! | [`rank_processes`] | The order for `processes top` |
//! | [`application_candidates`], [`control_plane`] | The instances of a snapshot as candidates of a memory-guard evaluation, with their hard protection |
//! | [`collect_path_uses`] | The paths that the processes of the user use now (open files, mapped files, working directory, executable, arguments), in a scope; for the use check of a file rule |
//! | [`ProcessCollector::collect_context`] | The working directory and the listening TCP ports of one process generation, on request, for a person; not a policy input |
//!
//! # Identity
//!
//! A PID alone is not an identity. The collector reads the start time, the
//! owner, and the executable of each process, and reads the start time and
//! the owner again after the other queries. A process that exited or was
//! replaced during the collection is not in the snapshot.
//!
//! # Metrics
//!
//! | Metric | Native field of `proc_pid_rusage(RUSAGE_INFO_V4)` |
//! | --- | --- |
//! | `process.footprint_bytes` | `ri_phys_footprint` |
//! | `process.resident_bytes` | `ri_resident_size` |
//! | `process.peak_footprint_bytes` | `ri_lifetime_max_phys_footprint` |
//! | `process.cpu_time_ns` | `ri_user_time + ri_system_time`, converted with `mach_timebase_info` |
//! | [`DISK_READ_METRIC`] | `ri_diskio_bytesread` |
//! | [`DISK_WRITTEN_METRIC`] | `ri_diskio_byteswritten` |
//!
//! Physical footprint and resident size are different quantities. A query
//! that fails or is denied gives an unavailable observation with a reason.
//!
//! # Attribution
//!
//! A process is a member of an application only with positive evidence: it
//! is the registered process of a running application (`launch_services`),
//! or the system names that registered process as responsible for it
//! (`responsible_process`). A name, the basename of the executable, the
//! parent, or the signing team gives no membership. Read a membership
//! through `ProcessAssociation::verified_membership`.

mod candidates;
mod context;
mod derived;
mod inventory;
#[cfg(target_os = "macos")]
mod native;
mod rank;
mod source;
mod uses;

#[cfg(test)]
#[cfg(target_os = "macos")]
mod context_smoke_tests;
#[cfg(test)]
mod context_tests;
#[cfg(test)]
mod fake;
#[cfg(test)]
#[cfg(target_os = "macos")]
mod smoke_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod uses_tests;

pub use candidates::{
    MAX_CONTROL_PLANE_ANCESTORS, application_candidates, control_plane,
    control_plane_of_this_process, instance_count,
};
pub use context::{
    AddressFamily, ContextLimits, DEFAULT_MAX_DESCRIPTORS, DEFAULT_MAX_PORTS,
    LISTENING_TCP_PORTS_METRIC, ListeningPort, ListeningPorts, ProcessContext,
    WORKING_DIRECTORY_METRIC,
};
pub use derived::{
    CpuSample, CpuUsage, DerivedMetrics, DerivedUnavailable, FootprintGrowth, FootprintSample,
    GrowthWindow, cpu_usage, derive_between, footprint_growth,
};
pub use inventory::{
    ADAPTER_ID, ADAPTER_REVISION, CLOCK_DOMAIN, CollectError, CollectionContext, DISK_READ_METRIC,
    DISK_WRITTEN_METRIC, ForegroundState, Omissions, ProcessCollector, ProcessMetrics,
    ProcessRecord, ProcessSnapshot, generation_id,
};
#[cfg(target_os = "macos")]
pub use native::DarwinProcessSource;
pub use rank::{RankMetric, RankValue, RankedProcess, Ranking, rank_processes};
pub use source::{
    ProcessSource, QueryFailure, RawArguments, RawListeningSocket, RawListeningSockets, RawPaths,
    RawProcessInfo, RawUsage, RawVnode, RunningApplication, SocketFamily, Timebase, VnodeObject,
};
pub use uses::{
    InventoryGap, MAX_NAME_BYTES, MAX_UNKNOWN_PROCESSES, PathInventory, PathUseKind,
    ProcessPathUse, ProcessUses, UnknownProcess, UseLimits, collect_path_uses,
    refused_process_passes_platform_gate,
};

#[cfg(target_os = "macos")]
impl CollectionContext {
    /// The context of the calling process on this host.
    ///
    /// The boot identity comes from `kern.bootsessionuuid`. The worker and
    /// the collector epoch come from the ID of the calling process and the
    /// monotonic clock.
    ///
    /// # Errors
    ///
    /// Returns a [`CollectError`] when the host gives no boot session
    /// identity or no clock value.
    pub fn for_this_process() -> Result<Self, CollectError> {
        use svalnir_core::id::{BootId, CollectorEpochId, WorkerId};

        let boot: String = native::boot_session_uuid().map_err(CollectError::BootSession)?;
        let now = DarwinProcessSource::new()
            .monotonic_now()
            .map_err(CollectError::Clock)?;
        let process_id: u32 = std::process::id();
        Ok(Self {
            worker_id: WorkerId::new(format!("worker-{process_id}"))?,
            boot_id: BootId::new(format!("boot-{boot}"))?,
            collector_epoch: CollectorEpochId::new(format!("epoch-{process_id}-{}", now.get()))?,
        })
    }
}

#[cfg(target_os = "macos")]
impl ProcessCollector<DarwinProcessSource> {
    /// A collector for the processes of this host, with the context of the
    /// calling process.
    ///
    /// # Errors
    ///
    /// Returns a [`CollectError`] as [`CollectionContext::for_this_process`]
    /// and [`ProcessCollector::new`] do.
    pub fn for_this_host() -> Result<Self, CollectError> {
        Self::new(
            DarwinProcessSource::new(),
            CollectionContext::for_this_process()?,
        )
    }
}
