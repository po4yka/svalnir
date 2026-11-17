//! Capacity observations of one volume.
//!
//! `docs/RESOURCE_MODEL.md` section 7 owns the metrics. The `statfs` values
//! are the product of a block count and `f_bsize`, with checked arithmetic.
//! The Foundation values are separate metrics: they are planning values and
//! are never the physically free space of the volume.

use svalnir_core::observation::{
    MetricId, MetricKind, Observation, Sample, Scope, UnavailableReason, Unit, metric,
};
use svalnir_core::quantity::Bytes;
use svalnir_core::volume::VolumeIdentity;

use super::identity::mount_id;
use super::raw::{RawFoundationCapacity, RawMount};
use crate::platform::memory::context::{
    CollectError, CollectionContext, MetricSpec, Provenance, reading_from,
};

/// The native API of the `statfs` capacity metrics.
pub const STATFS_NATIVE_API: &str = "statfs";
/// The native API of the Foundation capacity metrics.
pub const FOUNDATION_NATIVE_API: &str = "NSURL.resourceValuesForKeys";

/// The `statfs` capacity of one volume from one query.
///
/// The three observations have the same sample and the scope of the volume.
/// The values of sibling volumes of one capacity domain describe shared
/// space: do not add them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeCapacity {
    /// `disk.total_bytes`: `f_blocks * f_bsize`.
    pub total: Observation<Bytes>,
    /// `disk.free_bytes`: `f_bfree * f_bsize`.
    pub free: Observation<Bytes>,
    /// `disk.available_bytes`: `f_bavail * f_bsize`. The baseline policy
    /// input.
    pub available: Observation<Bytes>,
}

/// Checks that a raw `statfs` result is the mount of `identity`.
///
/// A different mount point means that the volume is not mounted at its path:
/// the query reached the filesystem under it. A different `f_fsid` or type
/// at the same path is another mount generation.
fn same_mount(identity: &VolumeIdentity, raw: &RawMount) -> Result<(), UnavailableReason> {
    if raw.mount_point != identity.mount_point.as_bytes() {
        return Err(UnavailableReason::ResourceGone);
    }
    let same_generation: bool = mount_id(raw.fsid).is_ok_and(|id| id == identity.mount_id)
        && raw.fsid[0] == identity.device.get()
        && raw.filesystem_type == identity.filesystem_type.as_bytes();
    if same_generation {
        Ok(())
    } else {
        Err(UnavailableReason::IdentityChanged)
    }
}

/// The bytes of `blocks` filesystem blocks.
fn block_bytes(raw: &RawMount, blocks: u64) -> Result<Bytes, UnavailableReason> {
    if raw.block_size == 0 {
        // A block count with no block size has no byte meaning.
        return Err(UnavailableReason::InconsistentData);
    }
    if blocks > raw.blocks {
        // More free blocks than total blocks: a sentinel or a bad value.
        return Err(UnavailableReason::InconsistentData);
    }
    Bytes::new(u64::from(raw.block_size))
        .checked_mul(blocks)
        .ok_or(UnavailableReason::Overflow)
}

/// Makes the `statfs` capacity observations of `identity` from a raw
/// result.
///
/// Each reading is unavailable when the query failed, when the result is
/// not the mount of `identity`, when the block size is zero, when a block
/// count is larger than the total, or when a product overflows. A failed
/// query is never a capacity of zero.
pub fn capacity_observations(
    context: &CollectionContext,
    identity: &VolumeIdentity,
    raw: Result<RawMount, UnavailableReason>,
    sample: &Sample,
) -> VolumeCapacity {
    let raw: Result<RawMount, UnavailableReason> =
        raw.and_then(|raw| same_mount(identity, &raw).map(|()| raw));
    let gauge = |id: MetricId, field: &str, select: fn(&RawMount) -> u64| {
        let value: Result<Bytes, UnavailableReason> = raw
            .as_ref()
            .map_err(Clone::clone)
            .and_then(|raw| block_bytes(raw, select(raw)));
        context.observation(
            MetricSpec::new(id, Unit::Byte, MetricKind::Gauge),
            Scope::volume(identity.volume_id.clone()),
            reading_from(value),
            Provenance {
                adapter: &context.adapters.statfs,
                native_api: STATFS_NATIVE_API,
                native_field: field,
            },
            sample,
        )
    };
    VolumeCapacity {
        total: gauge(metric::DISK_TOTAL_BYTES, "f_blocks * f_bsize", |raw| {
            raw.blocks
        }),
        free: gauge(metric::DISK_FREE_BYTES, "f_bfree * f_bsize", |raw| {
            raw.blocks_free
        }),
        available: gauge(metric::DISK_AVAILABLE_BYTES, "f_bavail * f_bsize", |raw| {
            raw.blocks_available
        }),
    }
}

/// The Foundation capacity values of one volume.
///
/// The two values are planning inputs of the system for a kind of use. They
/// can include space that the system can make free, so they can be larger
/// than `disk.available_bytes`. Do not show them as free physical space and
/// do not add them to another capacity value.
///
/// Foundation gives a zero for a volume that it makes no plan for. On macOS
/// 27.2 this occurs for the system helper volumes and for read-only disk
/// images. The collector keeps the native value: it cannot tell that zero
/// from the zero of a full volume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundationCapacity {
    /// `disk.important_available_bytes`.
    pub important: Observation<Bytes>,
    /// `disk.opportunistic_available_bytes`.
    pub opportunistic: Observation<Bytes>,
}

/// Makes the Foundation capacity observations of `identity` from a raw
/// result. The observations have the kind `estimate`.
pub fn foundation_capacity_observations(
    context: &CollectionContext,
    identity: &VolumeIdentity,
    raw: Result<RawFoundationCapacity, UnavailableReason>,
    sample: &Sample,
) -> FoundationCapacity {
    let (important, opportunistic) = match raw {
        Ok(raw) => (raw.important, raw.opportunistic),
        Err(reason) => (Err(reason.clone()), Err(reason)),
    };
    let estimate = |id: MetricId, field: &str, value: Result<u64, UnavailableReason>| {
        context.observation(
            MetricSpec::new(id, Unit::Byte, MetricKind::Estimate),
            Scope::volume(identity.volume_id.clone()),
            reading_from(value.map(Bytes::new)),
            Provenance {
                adapter: &context.adapters.foundation_volume,
                native_api: FOUNDATION_NATIVE_API,
                native_field: field,
            },
            sample,
        )
    };
    FoundationCapacity {
        important: estimate(
            metric::DISK_IMPORTANT_AVAILABLE_BYTES,
            "NSURLVolumeAvailableCapacityForImportantUsageKey",
            important,
        ),
        opportunistic: estimate(
            metric::DISK_OPPORTUNISTIC_AVAILABLE_BYTES,
            "NSURLVolumeAvailableCapacityForOpportunisticUsageKey",
            opportunistic,
        ),
    }
}

/// Reads the `statfs` capacity of the volume `identity`.
///
/// The query is `statfs` of the mount point, so the values are current. The
/// call can wait for a network filesystem that does not answer.
///
/// # Errors
///
/// Returns a [`CollectError`] when the clock gives no acquisition window. A
/// failed query is an unavailable reading, not an error.
pub fn collect_capacity(
    context: &CollectionContext,
    identity: &VolumeIdentity,
) -> Result<VolumeCapacity, CollectError> {
    let acquisition = context.begin()?;
    let raw: Result<RawMount, UnavailableReason> =
        super::native::filesystem_at(identity.mount_point.as_bytes());
    let sample: Sample = context.finish(acquisition)?;
    Ok(capacity_observations(context, identity, raw, &sample))
}

/// Reads the Foundation capacity values of the volume `identity`.
///
/// # Errors
///
/// Returns a [`CollectError`] when the clock gives no acquisition window. A
/// failed query is an unavailable reading, not an error.
pub fn collect_foundation_capacity(
    context: &CollectionContext,
    identity: &VolumeIdentity,
) -> Result<FoundationCapacity, CollectError> {
    let acquisition = context.begin()?;
    let raw: Result<RawFoundationCapacity, UnavailableReason> =
        super::native::foundation_capacity(identity.mount_point.as_bytes());
    let sample: Sample = context.finish(acquisition)?;
    Ok(foundation_capacity_observations(
        context, identity, raw, &sample,
    ))
}

#[cfg(test)]
mod tests {
    use svalnir_core::observation::{
        Coverage, MetricKind, ScopeKind, UnavailableReason, Unit, metric,
    };
    use svalnir_core::quantity::Bytes;
    use svalnir_core::volume::VolumeIdentity;

    use super::super::identity::testing::apfs_mount;
    use super::super::identity::{ContainerLookup, mounted_volume};
    use super::super::raw::{RawFoundationCapacity, RawMount};
    use super::{capacity_observations, foundation_capacity_observations};
    use crate::platform::memory::context::testing;

    fn data_volume() -> (RawMount, VolumeIdentity) {
        let raw = apfs_mount("disk3s5", "/System/Volumes/Data", 16_777_234);
        let identity = mounted_volume(&raw, None, ContainerLookup::NotExamined)
            .unwrap()
            .identity;
        (raw, identity)
    }

    #[test]
    fn each_capacity_is_a_block_count_multiplied_by_the_block_size() {
        let (context, _clock) = testing::context();
        let sample = testing::sample_at(&context, 10);
        let (raw, identity) = data_volume();
        let capacity = capacity_observations(&context, &identity, Ok(raw), &sample);

        for (observation, id, field, bytes) in [
            (
                &capacity.total,
                metric::DISK_TOTAL_BYTES,
                "f_blocks * f_bsize",
                4_096_000_000_u64,
            ),
            (
                &capacity.free,
                metric::DISK_FREE_BYTES,
                "f_bfree * f_bsize",
                1_638_400_000,
            ),
            (
                &capacity.available,
                metric::DISK_AVAILABLE_BYTES,
                "f_bavail * f_bsize",
                1_228_800_000,
            ),
        ] {
            assert_eq!(observation.metric_id, id);
            assert_eq!(observation.unit, Unit::Byte);
            assert_eq!(observation.kind, MetricKind::Gauge);
            assert_eq!(observation.coverage, Coverage::Complete);
            assert_eq!(observation.scope.kind, ScopeKind::Volume);
            assert_eq!(
                observation.scope.identity_id.as_str(),
                identity.volume_id.as_str()
            );
            assert_eq!(observation.value(), Some(&Bytes::new(bytes)));
            assert_eq!(observation.source.adapter_id.as_str(), "macos.statfs");
            assert_eq!(observation.source.native_api, "statfs");
            assert_eq!(observation.source.native_field, field);
            assert_eq!(observation.sample, sample);
            serde_json::to_string(observation).unwrap();
        }
    }

    #[test]
    fn a_full_volume_is_a_measured_zero_and_a_failed_query_is_not() {
        let (context, _clock) = testing::context();
        let sample = testing::sample_at(&context, 10);
        let (mut raw, identity) = data_volume();
        raw.blocks_available = 0;
        let full = capacity_observations(&context, &identity, Ok(raw), &sample);
        assert_eq!(full.available.value(), Some(&Bytes::ZERO));

        let failed = capacity_observations(
            &context,
            &identity,
            Err(UnavailableReason::PermissionDenied),
            &sample,
        );
        for observation in [&failed.total, &failed.free, &failed.available] {
            assert_eq!(observation.value(), None);
            assert_eq!(
                observation.reason(),
                Some(&UnavailableReason::PermissionDenied)
            );
            assert_eq!(observation.coverage, Coverage::Unknown);
        }
    }

    #[test]
    fn a_product_that_overflows_is_unavailable() {
        let (context, _clock) = testing::context();
        let sample = testing::sample_at(&context, 10);
        let (mut raw, identity) = data_volume();
        raw.block_size = u32::MAX;
        raw.blocks = u64::MAX / 2;
        raw.blocks_free = 1_000;
        raw.blocks_available = u64::MAX / 4;
        let capacity = capacity_observations(&context, &identity, Ok(raw), &sample);
        assert_eq!(capacity.total.reason(), Some(&UnavailableReason::Overflow));
        assert_eq!(
            capacity.available.reason(),
            Some(&UnavailableReason::Overflow)
        );
        // A product that fits is still a measurement.
        assert_eq!(
            capacity.free.value(),
            Some(&Bytes::new(1_000 * u64::from(u32::MAX)))
        );
    }

    #[test]
    fn values_that_are_not_consistent_are_unavailable() {
        let (context, _clock) = testing::context();
        let sample = testing::sample_at(&context, 10);

        let (mut no_block_size, identity) = data_volume();
        no_block_size.block_size = 0;
        let capacity = capacity_observations(&context, &identity, Ok(no_block_size), &sample);
        for observation in [&capacity.total, &capacity.free, &capacity.available] {
            assert_eq!(
                observation.reason(),
                Some(&UnavailableReason::InconsistentData)
            );
        }

        // A sentinel count is not an enormous capacity.
        let (mut sentinel, identity) = data_volume();
        sentinel.blocks_available = u64::MAX;
        sentinel.blocks_free = sentinel.blocks + 1;
        let capacity = capacity_observations(&context, &identity, Ok(sentinel), &sample);
        assert!(capacity.total.is_available());
        assert_eq!(
            capacity.available.reason(),
            Some(&UnavailableReason::InconsistentData)
        );
        assert_eq!(
            capacity.free.reason(),
            Some(&UnavailableReason::InconsistentData)
        );
    }

    #[test]
    fn a_result_of_another_mount_is_not_the_capacity_of_the_volume() {
        let (context, _clock) = testing::context();
        let sample = testing::sample_at(&context, 10);
        let (raw, identity) = data_volume();

        // The volume is not mounted: `statfs` reached the root filesystem.
        let mut parent = raw.clone();
        parent.mount_point = b"/".to_vec();
        parent.fsid = [1, 26];
        let gone = capacity_observations(&context, &identity, Ok(parent), &sample);
        assert_eq!(
            gone.available.reason(),
            Some(&UnavailableReason::ResourceGone)
        );

        // Another filesystem is mounted at the same path.
        for change in [
            |raw: &mut RawMount| raw.fsid[0] += 1,
            |raw: &mut RawMount| raw.fsid[1] += 1,
            |raw: &mut RawMount| raw.filesystem_type = b"hfs".to_vec(),
        ] {
            let mut remounted = raw.clone();
            change(&mut remounted);
            let changed = capacity_observations(&context, &identity, Ok(remounted), &sample);
            for observation in [&changed.total, &changed.free, &changed.available] {
                assert_eq!(
                    observation.reason(),
                    Some(&UnavailableReason::IdentityChanged)
                );
            }
        }
    }

    #[test]
    fn the_foundation_values_are_separate_estimates() {
        let (context, _clock) = testing::context();
        let sample = testing::sample_at(&context, 10);
        let (raw, identity) = data_volume();
        let statfs = capacity_observations(&context, &identity, Ok(raw), &sample);
        let foundation = foundation_capacity_observations(
            &context,
            &identity,
            Ok(RawFoundationCapacity {
                important: Ok(9_000_000_000),
                opportunistic: Err(UnavailableReason::Unsupported),
            }),
            &sample,
        );

        assert_eq!(
            foundation.important.metric_id,
            metric::DISK_IMPORTANT_AVAILABLE_BYTES
        );
        assert_eq!(
            foundation.opportunistic.metric_id,
            metric::DISK_OPPORTUNISTIC_AVAILABLE_BYTES
        );
        assert_ne!(foundation.important.metric_id, statfs.available.metric_id);
        assert_eq!(foundation.important.kind, MetricKind::Estimate);
        assert_eq!(foundation.important.scope, statfs.available.scope);
        assert_eq!(
            foundation.important.source.adapter_id.as_str(),
            "macos.foundation_volume"
        );
        // The estimate can be larger than the physically available bytes.
        assert_eq!(
            foundation.important.value(),
            Some(&Bytes::new(9_000_000_000))
        );
        assert_eq!(
            foundation.opportunistic.reason(),
            Some(&UnavailableReason::Unsupported)
        );
        serde_json::to_string(&foundation.important).unwrap();

        let failed = foundation_capacity_observations(
            &context,
            &identity,
            Err(UnavailableReason::ResourceGone),
            &sample,
        );
        for observation in [&failed.important, &failed.opportunistic] {
            assert_eq!(observation.value(), None);
            assert_eq!(observation.reason(), Some(&UnavailableReason::ResourceGone));
        }
    }
}
