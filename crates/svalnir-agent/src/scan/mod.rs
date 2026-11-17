//! Volume-aware filesystem scanner.
//!
//! A scan examines one root directory and returns a [`ScanResult`]: totals,
//! bounded lists of the largest files and directories, the mount boundaries
//! that it did not cross, and each region that it could not measure. The
//! scan is read-only. It reads metadata and no file content.
//!
//! Owning specification: `docs/RESOURCE_MODEL.md` section 8.
//! `docs/CLEANUP_RULES.md` owns rule scopes. This module has no cleanup
//! candidate, no cache classification, and no deletion.
//!
//! # Use
//!
//! Make a [`ScanRequest`] and call [`run_scan`] on a worker thread. Keep a
//! clone of the [`CancellationToken`] to stop the scan from another thread.
//! Give a [`ScanObserver`] to receive each measured entry; the scan itself
//! keeps aggregates only. [`ScanResult`] is the record to save and to
//! report. [`ScanResult::observations`] gives the totals as observations of
//! the `scan` scope.
//!
//! # Sizes
//!
//! - Logical size is `st_size` of a regular file or a symbolic link.
//! - Allocated size is `st_blocks * 512` of a regular file, a directory
//!   object, or a symbolic link.
//! - The totals count an object with several hard links one time, on its
//!   device and inode number. The entry counts count each name.
//! - Allocated size is not exclusive size and not reclaimable size. APFS
//!   clones, snapshots, sparse files, and compressed files share or save
//!   storage, and a metadata scan cannot measure that.
//!
//! # Traversal
//!
//! - The scan stays on the device of the root. An entry with another device
//!   number is recorded as a [`MountBoundary`] and is not counted.
//! - A symbolic link is counted as an entry and is not followed.
//! - Each directory below the root is opened relative to its open parent,
//!   with no-follow protection, and is then compared with the measured
//!   object.
//! - A directory that is a dataless cloud placeholder is not read, so the
//!   scan starts no download.
//! - A directory with several hard links (HFS+ only) is not deduplicated:
//!   the scan reads it through each name.
//! - The scan holds each open directory. A directory that another actor
//!   moves out of the root during the scan is still read to its end.
//! - A failure below the root leaves the measured part in place and is
//!   recorded as a [`ScanRegion`]. The coverage is then `partial`.

mod control;
mod model;
#[cfg(any(target_os = "macos", target_os = "linux"))]
mod native;
#[cfg(any(target_os = "macos", target_os = "linux"))]
mod top;
#[cfg(any(target_os = "macos", target_os = "linux"))]
mod walk;

#[cfg(test)]
#[cfg(any(target_os = "macos", target_os = "linux"))]
mod tests;

pub use control::{CancellationToken, NoObserver, ScanClock, ScanObserver, WallScanClock};
pub use model::{
    DirectoryRecord, EntryKind, EntryRecord, LargeDirectory, LargeFile, MAX_DEPTH_LIMIT,
    MAX_HARD_LINK_OBJECTS_LIMIT, MAX_LARGEST_ITEMS_LIMIT, MAX_RECORDED_REGIONS_LIMIT,
    METRIC_SCAN_ALLOCATED_BYTES, METRIC_SCAN_ENTRIES, METRIC_SCAN_EXCLUSIVE_BYTES,
    METRIC_SCAN_LOGICAL_BYTES, MountBoundary, RegionCause, RegionKind, SCAN_RESULT_SCHEMA_VERSION,
    ScanCompletion, ScanError, ScanLimits, ScanObservations, ScanRegion, ScanRequest, ScanResult,
    ScanTimestamp, ScanTotals, ScanVolumeEvidence, SharedStorageEvidence,
};
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub use walk::run_scan;

/// Scans one root directory. This build has no scanner for the host
/// operating system.
///
/// # Errors
///
/// Returns [`ScanError::Unsupported`].
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn run_scan(
    _request: &ScanRequest,
    _cancel: &CancellationToken,
    _clock: &dyn ScanClock,
    _observer: &mut dyn ScanObserver,
) -> Result<ScanResult, ScanError> {
    Err(ScanError::Unsupported)
}
