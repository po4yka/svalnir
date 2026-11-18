//! Read-only readings of the host for a client process.
//!
//! This build has no IPC. A client (the CLI or the GUI) links this library
//! and reads the host in its own process. This module has the composition
//! that the clients share: one collection context, the disk and memory
//! reading of the host, and the query of the coordinator lock. No function
//! here changes the host, and none registers a coordinator.
//!
//! A function here can block on a native call. A client with an event
//! thread calls it from a background thread.

use std::path::Path;

use serde::Serialize;
use svalnir_core::observation::UnavailableReason;
use svalnir_core::volume::VolumeIdentity;

use crate::journal::{CoordinatorLock, CoordinatorLockError, coordinator_lock_path};
use crate::platform::memory::{
    self, CollectError, CollectionContext, ContextError, MemorySnapshot,
};
use crate::platform::volume::{
    self, FoundationCapacity, MountedVolume, VolumeCapacity, VolumeQueryError,
};

/// The mount point of the data volume of the startup volume group on macOS.
const STARTUP_DATA_MOUNT_POINT: &str = "/System/Volumes/Data";

/// The collectors of one client process.
#[derive(Debug)]
pub struct Host {
    context: CollectionContext,
}

impl Host {
    /// Makes the collection context of this process.
    ///
    /// # Errors
    ///
    /// Returns a [`ContextError`] when the host gives no boot identity or no
    /// monotonic clock.
    pub fn open() -> Result<Self, ContextError> {
        CollectionContext::for_current_process().map(|context| Self { context })
    }

    /// The collection context.
    #[must_use]
    pub fn context(&self) -> &CollectionContext {
        &self.context
    }

    /// The volume that the `startup-data` selector names: the data volume of
    /// the startup volume group, or the root volume on a host that has no
    /// separate data volume.
    ///
    /// # Errors
    ///
    /// Returns a [`VolumeQueryError`] when the volume has no identity.
    pub fn startup_data_volume() -> Result<MountedVolume, VolumeQueryError> {
        let data: &Path = Path::new(STARTUP_DATA_MOUNT_POINT);
        if data.is_dir() {
            volume::volume_at(data)
        } else {
            volume::volume_at(Path::new("/"))
        }
    }
}

/// The disk part of a host reading, as the collectors gave it.
#[derive(Debug, Clone)]
#[expect(
    clippy::large_enum_variant,
    reason = "a snapshot has one disk reading, and a box adds an allocation to each one"
)]
pub enum DiskReading {
    /// The startup data volume and its capacity.
    Measured {
        /// The identity of the volume.
        identity: VolumeIdentity,
        /// The `statfs` capacity.
        capacity: VolumeCapacity,
        /// The Foundation planning values.
        foundation: FoundationCapacity,
    },
    /// The startup data volume has an identity, and the `statfs` capacity
    /// collection failed. The reading has no capacity.
    CapacityUnavailable {
        /// The identity of the volume.
        identity: VolumeIdentity,
        /// The text of the collection error.
        reason: String,
    },
    /// The startup data volume has no identity, so nothing was measured.
    Unresolved(String),
}

/// One reading of the host.
#[derive(Debug, Clone)]
pub struct HostReading {
    /// The disk capacity of the startup data volume.
    pub disk: DiskReading,
    /// The memory state of the host.
    pub memory: MemorySnapshot,
}

/// Reads the disk capacity of the startup data volume.
///
/// A failed collection is a value, not an error. The `statfs` capacity is
/// required: when it fails, the reading says so. The Foundation values are
/// optional planning values: when they fail, their observations are
/// unavailable.
#[must_use]
pub fn collect_disk(host: &Host) -> DiskReading {
    let mounted = match Host::startup_data_volume() {
        Ok(mounted) => mounted,
        Err(error) => return DiskReading::Unresolved(error.to_string()),
    };
    let capacity: VolumeCapacity = match volume::collect_capacity(host.context(), &mounted.identity)
    {
        Ok(capacity) => capacity,
        Err(error) => {
            return DiskReading::CapacityUnavailable {
                identity: mounted.identity,
                reason: error.to_string(),
            };
        }
    };
    let foundation: FoundationCapacity =
        match volume::collect_foundation_capacity(host.context(), &mounted.identity) {
            Ok(foundation) => foundation,
            Err(_) => volume::foundation_capacity_observations(
                host.context(),
                &mounted.identity,
                Err(UnavailableReason::TransientFailure),
                &capacity.total.sample,
            ),
        };
    DiskReading::Measured {
        identity: mounted.identity,
        capacity,
        foundation,
    }
}

/// Reads the disk capacity and the memory state of the host.
///
/// A disk collection failure keeps the memory reading.
///
/// # Errors
///
/// Returns a [`CollectError`] when the memory collection has no acquisition
/// window.
pub fn collect(host: &Host) -> Result<HostReading, CollectError> {
    let disk: DiskReading = collect_disk(host);
    let memory: MemorySnapshot = memory::collect_memory_snapshot(host.context())?;
    Ok(HostReading { disk, memory })
}

/// Whether a coordinator process holds the coordinator lock of the journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoordinatorPresence {
    /// A process holds the lock: an agent, or a client that executes a
    /// request.
    Running,
    /// No process holds the lock.
    NotRunning,
    /// The lock file cannot be used, so the answer is not known.
    Unknown,
}

/// Reads the coordinator lock of the journal at `journal_path`. The
/// function takes the lock for an instant and releases it; it registers no
/// coordinator. The journal file must exist.
#[must_use]
pub fn coordinator_presence(journal_path: &Path) -> CoordinatorPresence {
    // With no lock file, no coordinator ran on this journal. A query does
    // not make the file.
    let lock_path = coordinator_lock_path(journal_path);
    if matches!(
        std::fs::symlink_metadata(&lock_path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
    ) {
        return CoordinatorPresence::NotRunning;
    }
    match CoordinatorLock::try_acquire(journal_path) {
        Ok(lock) => {
            drop(lock);
            CoordinatorPresence::NotRunning
        }
        Err(CoordinatorLockError::Held) => CoordinatorPresence::Running,
        Err(CoordinatorLockError::Io(_)) => CoordinatorPresence::Unknown,
    }
}
