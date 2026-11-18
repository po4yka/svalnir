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
use svalnir_core::grant::{AuthorityState, GuardStanding, InstanceInhibition, guard_standing};
use svalnir_core::observation::UnavailableReason;
use svalnir_core::policy::PolicyId;
use svalnir_core::process::Uid;
use svalnir_core::time::WallTime;
use svalnir_core::volume::VolumeIdentity;

use crate::journal::{
    AgentRecord, CoordinatorLock, CoordinatorLockError, JournalOptions, OperationJournal,
    OperationJournalError, coordinator_lock_path,
};
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

/// The user of this process.
#[must_use]
pub fn current_uid() -> Uid {
    #[cfg(unix)]
    {
        // SAFETY: `geteuid` has no argument, changes nothing, and does not
        // fail.
        Uid::new(unsafe { libc::geteuid() })
    }
    #[cfg(not(unix))]
    {
        Uid::new(0)
    }
}

/// Why the journal file could not be opened for a read.
#[derive(Debug, thiserror::Error)]
pub enum ExistingJournalError {
    /// The path is not a regular file.
    #[error("the path of the operation journal is not a regular file")]
    NotAJournal,
    /// The path could not be inspected.
    #[error("the operation journal cannot be inspected")]
    Inspect,
    /// The journal file exists and could not be opened.
    #[error("the operation journal cannot be opened: {0}")]
    Open(OperationJournalError),
}

/// Opens the journal when its file exists. The function does not make the
/// state directory or the journal. `Ok(None)` means that the file is absent.
///
/// # Errors
///
/// Returns [`ExistingJournalError`] when the path is not a regular file,
/// cannot be inspected, or cannot be opened as a journal.
pub fn open_existing_journal(
    path: &Path,
    options: &JournalOptions,
) -> Result<Option<OperationJournal>, ExistingJournalError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => {}
        Ok(_) => return Err(ExistingJournalError::NotAJournal),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(ExistingJournalError::Inspect),
    }
    OperationJournal::open(path, options)
        .map(Some)
        .map_err(ExistingJournalError::Open)
}

/// The authority record of the journal with its record revision.
#[derive(Debug, Clone)]
pub struct StoredAuthority {
    /// The record. With no record, the state of a user with no activation.
    pub state: AuthorityState,
    /// The revision of the record, or 0 with no record.
    pub revision: u64,
}

/// Why the authority record could not be read.
#[derive(Debug, thiserror::Error)]
pub enum AuthorityReadError {
    /// The journal could not give the record.
    #[error("the authority record cannot be read: {0}")]
    Journal(OperationJournalError),
    /// The record belongs to a different user.
    #[error("the authority record of the journal is of a different user")]
    DifferentUser,
}

/// Reads the authority record of the journal for `uid`.
///
/// # Errors
///
/// Returns [`AuthorityReadError::DifferentUser`] for a record of a
/// different user, and [`AuthorityReadError::Journal`] for a record that
/// cannot be read.
pub fn read_authority(
    journal: &OperationJournal,
    uid: Uid,
) -> Result<StoredAuthority, AuthorityReadError> {
    match journal
        .agent_record::<AuthorityState>(AgentRecord::Authority)
        .map_err(AuthorityReadError::Journal)?
    {
        None => Ok(StoredAuthority {
            state: AuthorityState::new(uid),
            revision: 0,
        }),
        Some(stored) if stored.record.principal != uid => Err(AuthorityReadError::DifferentUser),
        Some(stored) => Ok(StoredAuthority {
            state: stored.record,
            revision: stored.revision,
        }),
    }
}

/// The standing of each guard at `now`, in the order of [`PolicyId::ALL`].
/// The reading has no instance inhibition: a client process is not the
/// running instance of the agent.
#[must_use]
pub fn guard_standings(state: &AuthorityState, now: WallTime) -> Vec<(PolicyId, GuardStanding)> {
    PolicyId::ALL
        .iter()
        .map(|policy| {
            (
                *policy,
                guard_standing(state, &InstanceInhibition::default(), *policy, now),
            )
        })
        .collect()
}
