//! The capacity of one volume that the saved scan does not explain.
//!
//! The report has four separate, labeled entries
//! (`docs/RESOURCE_MODEL.md` section 7): the allocated size that a saved
//! scan of the volume measured, the used capacity that the scan does not
//! explain, the local snapshots of the volume, and the difference between
//! the Foundation capacity for important usage and `disk.available_bytes`.
//! Each entry is an observation with its own reason when it has no value. A
//! consumer must not add an entry to the available capacity or to a reclaim
//! estimate. The report is read-only: it removes no snapshot and changes
//! nothing on the host.
//!
//! The local snapshots are always unavailable in this build. The one
//! interface that lists them, `fs_snapshot_list(2)`, needs superuser
//! privileges and an entitlement (its manual page in the macOS 27.2 SDK),
//! and the report calls no privileged tool.

use serde::Serialize;
use svalnir_core::id::ScanId;
use svalnir_core::observation::{
    Coverage, MetricId, MetricKind, Observation, Reading, Sample, Scope, UnavailableReason, Unit,
    metric,
};
use svalnir_core::quantity::{ByteDelta, Bytes, EntryCount};
use svalnir_core::time::WallTime;
use svalnir_core::volume::VolumeIdentity;

use crate::platform::memory::context::{CollectError, CollectionContext, MetricSpec, Provenance};
use crate::platform::volume::{FoundationCapacity, VolumeCapacity};
use crate::scan::ScanResult;

/// The detail of the snapshot entry: why this build has no snapshot count.
pub const SNAPSHOT_LIST_DETAIL: &str = "snapshot_list_needs_superuser_and_entitlement";
/// The detail of the scan entries when no saved scan of the volume exists.
pub const NO_SCAN_DETAIL: &str = "no_saved_scan_of_the_volume";
/// The detail of the scan entries when the saved scan has no volume
/// identity, so it cannot be bound to the volume.
pub const NO_SCAN_VOLUME_DETAIL: &str = "scan_has_no_volume_identity";
/// The detail of the scan entries when the scan is of another volume.
pub const OTHER_VOLUME_DETAIL: &str = "scan_of_another_volume";
/// The detail of the unexplained entry when the scan measured more than
/// the used capacity, for example because clones share blocks.
pub const SCAN_EXCEEDS_USED_DETAIL: &str = "scan_exceeds_used_capacity";

/// The statement of the report about its entries.
pub const REPORT_NOTE: &str = "Each entry is a separate reading. Do not add an entry to the available capacity or to a reclaim estimate. The report removes no snapshot and authorizes no action.";

const EXPLAINED_LABEL: &str =
    "Allocated size below the root of the saved scan, at the time of the scan";
const UNEXPLAINED_LABEL: &str = "Used capacity of the volume (total minus free) that the saved scan does not explain. It includes the other volumes of the container, local snapshots, and files outside the scan root. It is not reclaimable capacity";
const SNAPSHOTS_LABEL: &str = "Local snapshots of the volume";
const FOUNDATION_LABEL: &str = "Foundation capacity for important usage minus disk.available_bytes. Space that the system reports that it can make free, for example purgeable data. It is not available capacity";

/// One labeled entry of the report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CapacityEntry<T> {
    /// What the entry measures, for a person.
    pub label: &'static str,
    /// The reading.
    pub observation: Observation<T>,
    /// A stable code with more detail on the reading, or `None`.
    pub detail: Option<&'static str>,
}

/// The saved scan that the report compares with the volume.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScanReference {
    /// The scan.
    pub scan_id: ScanId,
    /// The display label of the scan root.
    pub root: String,
    /// When the scan finished, by the wall clock, when it is known.
    pub finished_at: Option<WallTime>,
    /// The coverage of the scan. A partial scan explains less.
    pub coverage: Coverage,
}

/// The capacity of one volume that the saved scan does not explain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CapacityReport {
    /// The volume.
    pub volume: VolumeIdentity,
    /// The saved scan, or `None` when there is none.
    pub scan: Option<ScanReference>,
    /// `disk.scan_explained_bytes`.
    pub explained_by_scan: CapacityEntry<Bytes>,
    /// `disk.scan_unexplained_bytes`.
    pub not_explained_by_scan: CapacityEntry<Bytes>,
    /// `disk.local_snapshot_count`.
    pub local_snapshots: CapacityEntry<EntryCount>,
    /// `disk.important_minus_available_bytes`.
    pub important_minus_available: CapacityEntry<ByteDelta>,
    /// [`REPORT_NOTE`].
    pub note: &'static str,
}

/// The reason of an observation with no value.
fn reason_of<T: svalnir_core::observation::ObservationValue>(
    observation: &Observation<T>,
) -> UnavailableReason {
    observation
        .reason()
        .cloned()
        .unwrap_or(UnavailableReason::InconsistentData)
}

/// The used capacity: `disk.total_bytes` minus `disk.free_bytes`.
fn used(capacity: &VolumeCapacity) -> Result<Bytes, UnavailableReason> {
    let total: Bytes = *capacity
        .total
        .value()
        .ok_or_else(|| reason_of(&capacity.total))?;
    let free: Bytes = *capacity
        .free
        .value()
        .ok_or_else(|| reason_of(&capacity.free))?;
    total
        .get()
        .checked_sub(free.get())
        .map(Bytes::new)
        .ok_or(UnavailableReason::InconsistentData)
}

/// The value of the explained entry and its detail.
fn explained(
    identity: &VolumeIdentity,
    scan: Option<&ScanResult>,
) -> (Result<Bytes, UnavailableReason>, Option<&'static str>) {
    let Some(scan) = scan else {
        return (Err(UnavailableReason::NotCollected), Some(NO_SCAN_DETAIL));
    };
    let Some(scanned) = scan.volume.identity.as_ref() else {
        return (
            Err(UnavailableReason::IdentityChanged),
            Some(NO_SCAN_VOLUME_DETAIL),
        );
    };
    if scanned.volume_id == identity.volume_id {
        (Ok(scan.totals.allocated_bytes), None)
    } else {
        (
            Err(UnavailableReason::IdentityChanged),
            Some(OTHER_VOLUME_DETAIL),
        )
    }
}

/// The value of the unexplained entry and its detail.
fn unexplained(
    capacity: &VolumeCapacity,
    explained: &Result<Bytes, UnavailableReason>,
    explained_detail: Option<&'static str>,
) -> (Result<Bytes, UnavailableReason>, Option<&'static str>) {
    let explained: Bytes = match explained {
        Ok(explained) => *explained,
        Err(reason) => return (Err(reason.clone()), explained_detail),
    };
    match used(capacity) {
        Err(reason) => (Err(reason), None),
        Ok(used) => match used.get().checked_sub(explained.get()) {
            Some(rest) => (Ok(Bytes::new(rest)), None),
            None => (
                Err(UnavailableReason::InconsistentData),
                Some(SCAN_EXCEEDS_USED_DETAIL),
            ),
        },
    }
}

/// `disk.important_available_bytes` minus `disk.available_bytes`.
fn important_minus_available(
    capacity: &VolumeCapacity,
    foundation: &FoundationCapacity,
) -> Result<ByteDelta, UnavailableReason> {
    let important: &Bytes = foundation
        .important
        .value()
        .ok_or_else(|| reason_of(&foundation.important))?;
    let available: &Bytes = capacity
        .available
        .value()
        .ok_or_else(|| reason_of(&capacity.available))?;
    Ok(important.delta_from(*available))
}

/// The snapshot entry. This build calls no snapshot interface, so the entry
/// is always unavailable and never a count of zero.
fn snapshot_entry(
    context: &CollectionContext,
    scope: &Scope,
    sample: &Sample,
) -> CapacityEntry<EntryCount> {
    CapacityEntry {
        label: SNAPSHOTS_LABEL,
        observation: context.observation(
            MetricSpec::new(
                metric::DISK_LOCAL_SNAPSHOT_COUNT,
                Unit::Entry,
                MetricKind::Gauge,
            ),
            scope.clone(),
            Reading::Unavailable(UnavailableReason::Unsupported),
            Provenance {
                adapter: &context.adapters.fs_snapshot,
                native_api: "fs_snapshot_list",
                native_field: "not called",
            },
            sample,
        ),
        detail: Some(SNAPSHOT_LIST_DETAIL),
    }
}

/// Makes the report from the current capacity readings of `identity` and a
/// saved scan.
///
/// The derived entries have one new acquisition of this call; their source
/// names the inputs. The scan entries have the coverage of the scan.
///
/// # Errors
///
/// Returns a [`CollectError`] when the clock gives no acquisition window.
pub fn capacity_report(
    context: &CollectionContext,
    identity: &VolumeIdentity,
    capacity: &VolumeCapacity,
    foundation: &FoundationCapacity,
    scan: Option<&ScanResult>,
) -> Result<CapacityReport, CollectError> {
    let acquisition = context.begin()?;
    let sample: Sample = context.finish(acquisition)?;
    let scope: Scope = Scope::volume(identity.volume_id.clone());
    let derived = |field: &'static str| Provenance {
        adapter: &context.adapters.capacity_report,
        native_api: "derived",
        native_field: field,
    };
    let scan_coverage: Coverage = scan.map_or(Coverage::Unknown, |scan| scan.coverage.clone());
    let with_coverage = |mut observation: Observation<Bytes>| {
        if observation.reading.is_available() {
            observation.coverage = scan_coverage.clone();
        }
        observation
    };

    let (explained_value, explained_detail) = explained(identity, scan);
    let (unexplained_value, unexplained_detail) =
        unexplained(capacity, &explained_value, explained_detail);
    let bytes = |id: MetricId, kind: MetricKind, value: Result<Bytes, UnavailableReason>, field| {
        context.observation(
            MetricSpec::new(id, Unit::Byte, kind),
            scope.clone(),
            reading(value),
            derived(field),
            &sample,
        )
    };
    let explained_by_scan = CapacityEntry {
        label: EXPLAINED_LABEL,
        observation: with_coverage(bytes(
            metric::DISK_SCAN_EXPLAINED_BYTES,
            MetricKind::Gauge,
            explained_value,
            "scan.allocated_bytes",
        )),
        detail: explained_detail,
    };
    let not_explained_by_scan = CapacityEntry {
        label: UNEXPLAINED_LABEL,
        observation: with_coverage(bytes(
            metric::DISK_SCAN_UNEXPLAINED_BYTES,
            MetricKind::Estimate,
            unexplained_value,
            "(disk.total_bytes - disk.free_bytes) - scan.allocated_bytes",
        )),
        detail: unexplained_detail,
    };

    let local_snapshots: CapacityEntry<EntryCount> = snapshot_entry(context, &scope, &sample);
    let important_minus_available = CapacityEntry {
        label: FOUNDATION_LABEL,
        observation: context.observation(
            MetricSpec::new(
                metric::DISK_IMPORTANT_MINUS_AVAILABLE_BYTES,
                Unit::Byte,
                MetricKind::Estimate,
            ),
            scope,
            reading(important_minus_available(capacity, foundation)),
            derived("disk.important_available_bytes - disk.available_bytes"),
            &sample,
        ),
        detail: None,
    };

    Ok(CapacityReport {
        volume: identity.clone(),
        scan: scan.map(|scan| ScanReference {
            scan_id: scan.scan_id.clone(),
            root: scan.root.display_label(),
            finished_at: scan.finished.wall,
            coverage: scan.coverage.clone(),
        }),
        explained_by_scan,
        not_explained_by_scan,
        local_snapshots,
        important_minus_available,
        note: REPORT_NOTE,
    })
}

fn reading<T>(value: Result<T, UnavailableReason>) -> Reading<T> {
    match value {
        Ok(value) => Reading::Available(value),
        Err(reason) => Reading::Unavailable(reason),
    }
}
