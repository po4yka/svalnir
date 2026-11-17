//! The control surface of a scan: cancellation, the clock, and the observer.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::SystemTime;

use svalnir_core::time::WallTime;

use super::model::{DirectoryRecord, EntryRecord, ScanTimestamp};

/// A flag that stops a scan.
///
/// Each clone refers to the same flag, so another thread can cancel a scan
/// that runs on a worker. The scan reads the flag before each name. A
/// cancelled scan returns its partial result.
#[derive(Debug, Clone, Default)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    /// Makes a token that is not cancelled.
    pub fn new() -> Self {
        Self::default()
    }

    /// Requests the scan to stop. A token stays cancelled.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    /// Whether [`CancellationToken::cancel`] was called.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

/// The source of the start and finish times of a scan.
///
/// The host monotonic timeline belongs to the clock adapter of the
/// platform. A scan does not define a second timeline: the caller gives a
/// clock that reads that adapter.
pub trait ScanClock {
    /// The time now. A value that the clock cannot give is `None`.
    fn now(&self) -> ScanTimestamp;
}

/// A clock that gives the wall-clock time of the system and no monotonic
/// time.
#[derive(Debug, Clone, Copy, Default)]
pub struct WallScanClock;

impl ScanClock for WallScanClock {
    fn now(&self) -> ScanTimestamp {
        ScanTimestamp {
            wall: WallTime::try_from(SystemTime::now()).ok(),
            monotonic_ns: None,
        }
    }
}

/// Receives each measured entry and each finished directory of a scan.
///
/// The scan does not keep each entry. A caller that saves a catalog writes
/// the records from this trait to its own bounded store. Each method runs
/// on the worker of the scan, between two native calls, so a slow method
/// makes the scan slow. Each method has an empty default.
pub trait ScanObserver {
    /// The scan opened a directory and will read its names.
    fn directory_opened(&mut self, path: &Path) {
        let _ = path;
    }

    /// The scan read a name from a directory and will measure it.
    fn entry_listed(&mut self, path: &Path) {
        let _ = path;
    }

    /// The scan measured an entry.
    fn entry_measured(&mut self, entry: &EntryRecord<'_>) {
        let _ = entry;
    }

    /// The scan left a directory. The record has the totals of the
    /// directory.
    fn directory_finished(&mut self, directory: &DirectoryRecord<'_>) {
        let _ = directory;
    }
}

/// An observer that does nothing.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoObserver;

impl ScanObserver for NoObserver {}
