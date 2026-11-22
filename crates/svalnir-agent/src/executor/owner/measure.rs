//! The measurement of the scope of an owner operation with the read-only
//! scanner.

use std::path::Path;

use svalnir_core::action::ScopeMeasurement;
use svalnir_core::file::LosslessPath;
use svalnir_core::id::ScanId;
use svalnir_core::observation::Coverage;
use svalnir_core::quantity::EntryCount;

use crate::scan::{
    CancellationToken, NoObserver, PrivateBytes, ScanClock, ScanCompletion, ScanLimits,
    ScanRequest, ScanResult, run_scan,
};

/// The scan identity of a measurement of a scope.
const SCOPE_SCAN_ID: &str = "owner-operation-scope";

/// The bounds of one measurement of a scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScopeLimits {
    /// The deepest directory level below the scope root.
    pub max_depth: u32,
    /// The largest number of entries. A scope with more entries has a
    /// measurement that is not complete.
    pub max_entries: EntryCount,
}

impl Default for ScopeLimits {
    fn default() -> Self {
        Self {
            max_depth: 256,
            max_entries: EntryCount::new(2_000_000),
        }
    }
}

/// Measures the scope at `root` with the read-only scanner.
///
/// The scan reads metadata only and stays on the device of the root. The
/// measurement is complete only when the scan examined each directory
/// that it could open, with no region that it could not measure. `None`
/// when the scan cannot start, for example because the root is not a
/// directory.
pub fn measure_scope(
    root: &Path,
    limits: ScopeLimits,
    cancel: &CancellationToken,
    clock: &dyn ScanClock,
) -> Option<ScopeMeasurement> {
    let request: ScanRequest = ScanRequest {
        scan_id: ScanId::new(SCOPE_SCAN_ID).ok()?,
        root: LosslessPath::from_path(root).ok()?,
        limits: ScanLimits {
            max_depth: limits.max_depth,
            max_entries: limits.max_entries,
            max_largest_files: 0,
            max_largest_directories: 0,
            max_recorded_regions: 64,
            max_recorded_boundaries: 16,
            max_hard_link_objects: 100_000,
        },
        volume: None,
    };
    let result: ScanResult = run_scan(&request, cancel, clock, &mut NoObserver).ok()?;
    let complete: bool = matches!(result.completion, ScanCompletion::Finished)
        && result.coverage == Coverage::Complete;
    let private_allocated_bytes = match result.private_allocation.bytes {
        PrivateBytes::Available { bytes } => Some(bytes),
        PrivateBytes::Unavailable { .. } => None,
    };
    Some(ScopeMeasurement {
        allocated_bytes: result.totals.allocated_bytes,
        private_allocated_bytes,
        entries: result.totals.entries,
        complete,
        measured_at: result.finished.wall,
    })
}
