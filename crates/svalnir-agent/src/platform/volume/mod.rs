//! Volume capacity adapters.
//!
//! The module lists the mounted volumes, makes a
//! [`VolumeIdentity`](svalnir_core::volume::VolumeIdentity) for each from
//! `statfs` evidence, reads the capacity of one volume, and establishes
//! capacity-domain membership, so that the shared space of an APFS container
//! is not counted two times. It changes nothing on the host.
//!
//! Owning specification: `docs/RESOURCE_MODEL.md` sections 2 and 7.
//!
//! | Item | Use |
//! | --- | --- |
//! | [`enumerate_volumes`] | The identity and evidence of each mounted volume |
//! | [`volume_at`] | The volume that contains a path |
//! | [`collect_capacity`] | `disk.total_bytes`, `disk.free_bytes`, `disk.available_bytes` |
//! | [`collect_foundation_capacity`] | The two Foundation planning values |
//! | [`group_by_capacity_pool`] | Volumes grouped by shared free space |
//! | [`MountTable`] | Whether a path or a device is on a local filesystem |
//!
//! The collectors take the [`CollectionContext`] of the memory module:
//! `crate::platform::memory::CollectionContext`.
//!
//! `native.rs` is the only file of this module with `unsafe` code.

pub mod capacity;
pub mod identity;
pub mod locality;
pub mod pool;
pub mod raw;

#[cfg(target_os = "macos")]
mod native;
#[cfg(not(target_os = "macos"))]
#[path = "unsupported.rs"]
mod native;

use std::path::Path;

use svalnir_core::observation::UnavailableReason;
use thiserror::Error;

pub use capacity::{
    FoundationCapacity, VolumeCapacity, capacity_observations, collect_capacity,
    collect_foundation_capacity, foundation_capacity_observations,
};
pub use identity::{
    CapacityDomainEvidence, ContainerLookup, MountEvidence, MountedVolume, VolumeIdentityError,
    VolumeUuidLookup, apfs_device_name, mounted_volume, reject_ambiguous_containers,
    reject_duplicate_volume_uuids,
};
pub use locality::{Locality, MountTable, MountTableSource};
pub use pool::{CapacityGrouping, CapacityPool, CapacityPoolMembers, group_by_capacity_pool};
pub use raw::{RawApfsContainer, RawFoundationCapacity, RawMount};

pub use crate::platform::memory::context::{CollectError, CollectionContext};

/// The mounted volumes of the host at one time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeInventory {
    /// Each mounted volume with an identity, in the order of the mount
    /// table.
    pub volumes: Vec<MountedVolume>,
    /// The mounts that gave no identity. The inventory is not complete when
    /// this list is not empty.
    pub rejected: Vec<VolumeIdentityError>,
}

/// The reason a volume query gave no result.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum VolumeQueryError {
    /// The native query failed.
    #[error("the volume query is unavailable: {}", .0.as_str())]
    Unavailable(UnavailableReason),
    /// The mount gave no identity.
    #[error(transparent)]
    Identity(#[from] VolumeIdentityError),
}

/// The volume UUID and the container lookup of one raw mount.
///
/// The two probes are made only for a local filesystem, so that a network
/// filesystem that does not answer cannot stop the enumeration.
fn probe(raw: &RawMount) -> (VolumeUuidLookup, ContainerLookup) {
    if raw.flags & raw::MOUNT_FLAG_LOCAL == 0 {
        return (VolumeUuidLookup::NotExamined, ContainerLookup::NotExamined);
    }
    let container: ContainerLookup = match apfs_device_name(raw) {
        Some(device_name) => match native::apfs_container(device_name) {
            Ok(container) => ContainerLookup::Found(container),
            Err(reason) => ContainerLookup::Failed(reason),
        },
        None => ContainerLookup::NotExamined,
    };
    (
        native::volume_uuid(&raw.mount_point, raw.fsid).into(),
        container,
    )
}

/// Makes the inventory of a list of raw mounts with the probes of the host.
fn inventory_of(mounts: &[RawMount]) -> VolumeInventory {
    let (mut uuids, mut lookups): (Vec<VolumeUuidLookup>, Vec<ContainerLookup>) =
        mounts.iter().map(probe).unzip();
    reject_ambiguous_containers(&mut lookups);
    reject_duplicate_volume_uuids(mounts, &mut uuids);
    let mut inventory = VolumeInventory {
        volumes: Vec::with_capacity(mounts.len()),
        rejected: Vec::new(),
    };
    for ((raw, volume_uuid), container) in mounts.iter().zip(uuids).zip(lookups) {
        match mounted_volume(raw, volume_uuid, container) {
            Ok(volume) => inventory.volumes.push(volume),
            Err(error) => inventory.rejected.push(error),
        }
    }
    inventory
}

/// Lists the mounted volumes of the host with their identities.
///
/// The list comes from `getfsstat` with `MNT_NOWAIT`. It gives identity and
/// evidence only; use [`collect_capacity`] for a capacity measurement.
///
/// # Errors
///
/// Returns [`VolumeQueryError::Unavailable`] when the mount table cannot be
/// read.
pub fn enumerate_volumes() -> Result<VolumeInventory, VolumeQueryError> {
    let mounts: Vec<RawMount> =
        native::mounted_filesystems().map_err(VolumeQueryError::Unavailable)?;
    Ok(inventory_of(&mounts))
}

/// The mounted volume that contains `path`.
///
/// Use this to select the volume of a path that the user gave. It is the
/// volume of that path, not the volume of the executable. The identity is
/// the one that [`enumerate_volumes`] gives for the same mount.
///
/// # Errors
///
/// Returns a [`VolumeQueryError`] when `statfs` of the path fails, when the
/// mount is not in the mount table, or when the mount gives no identity.
#[cfg(unix)]
pub fn volume_at(path: &Path) -> Result<MountedVolume, VolumeQueryError> {
    use std::os::unix::ffi::OsStrExt as _;
    let selected: RawMount = native::filesystem_at(path.as_os_str().as_bytes())
        .map_err(VolumeQueryError::Unavailable)?;
    // The whole mount table is the input of the container check, so the
    // membership of the selected volume is the same as in the list.
    let mounts: Vec<RawMount> =
        native::mounted_filesystems().map_err(VolumeQueryError::Unavailable)?;
    let position: usize = mounts
        .iter()
        .position(|raw| raw.fsid == selected.fsid && raw.mount_point == selected.mount_point)
        .ok_or(VolumeQueryError::Unavailable(
            UnavailableReason::ResourceGone,
        ))?;
    let (mut uuids, mut lookups): (Vec<VolumeUuidLookup>, Vec<ContainerLookup>) =
        mounts.iter().map(probe).unzip();
    reject_ambiguous_containers(&mut lookups);
    reject_duplicate_volume_uuids(&mounts, &mut uuids);
    let volume_uuid: VolumeUuidLookup = uuids
        .into_iter()
        .nth(position)
        .unwrap_or(VolumeUuidLookup::NotExamined);
    let container: ContainerLookup = lookups
        .into_iter()
        .nth(position)
        .unwrap_or(ContainerLookup::NotExamined);
    Ok(mounted_volume(&selected, volume_uuid, container)?)
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use std::path::Path;

    use svalnir_core::observation::UnavailableReason;
    use svalnir_core::quantity::Bytes;
    use svalnir_core::volume::CapacityDomainMembership;

    use super::{
        CapacityDomainEvidence, CollectionContext, VolumeQueryError, VolumeUuidLookup,
        collect_capacity, collect_foundation_capacity, enumerate_volumes, group_by_capacity_pool,
        volume_at,
    };

    #[test]
    fn the_host_has_a_root_volume_with_consistent_evidence() {
        let inventory = enumerate_volumes().unwrap();
        assert_eq!(inventory.rejected, []);
        let root = inventory
            .volumes
            .iter()
            .find(|volume| volume.identity.mount_point.as_bytes() == b"/")
            .expect("the host has a root volume");
        assert_ne!(root.identity.filesystem_type, "");
        assert_eq!(root.evidence.fsid[0], root.identity.device.get());
        assert!(root.evidence.local);
        // The `fsid` of `getattrlist` agrees with the one of `getfsstat`.
        assert!(!matches!(
            root.evidence.volume_uuid,
            VolumeUuidLookup::Failed(_)
        ));

        // Each mount generation is in the list one time.
        let mut mount_ids: Vec<&str> = inventory
            .volumes
            .iter()
            .map(|volume| volume.identity.mount_id.as_str())
            .collect();
        mount_ids.sort_unstable();
        let count = mount_ids.len();
        mount_ids.dedup();
        assert_eq!(mount_ids.len(), count);

        // The selection by path gives the same identity as the list.
        let selected = volume_at(Path::new("/")).unwrap();
        assert_eq!(selected.identity, root.identity);
    }

    #[test]
    fn a_shared_membership_has_registry_evidence_and_only_for_apfs() {
        let inventory = enumerate_volumes().unwrap();
        for volume in &inventory.volumes {
            match (
                &volume.identity.capacity_domain,
                &volume.evidence.capacity_domain,
            ) {
                (
                    CapacityDomainMembership::Shared { domain_id, .. },
                    CapacityDomainEvidence::ApfsContainerRegistryEntry { container_uuid, .. },
                ) => {
                    assert_eq!(volume.identity.filesystem_type, "apfs");
                    assert_eq!(domain_id.as_str(), format!("apfs_{container_uuid}"));
                }
                (
                    CapacityDomainMembership::Unknown,
                    CapacityDomainEvidence::NotExamined | CapacityDomainEvidence::LookupFailed(_),
                ) => {}
                other => panic!("the membership does not agree with its evidence: {other:?}"),
            }
        }

        // The grouping has each volume one time: in a pool or unverified.
        let grouping = group_by_capacity_pool(inventory.volumes.iter().map(|v| &v.identity));
        let mut grouped: Vec<&str> = grouping
            .pools
            .iter()
            .flat_map(|pool| pool.members.iter())
            .chain(grouping.unverified.iter())
            .map(svalnir_core::id::VolumeId::as_str)
            .collect();
        grouped.sort_unstable();
        let mut expected: Vec<&str> = inventory
            .volumes
            .iter()
            .map(|volume| volume.identity.volume_id.as_str())
            .collect();
        expected.sort_unstable();
        expected.dedup();
        assert_eq!(grouped, expected);
    }

    #[test]
    fn the_system_and_data_volumes_of_one_container_share_a_domain() {
        let inventory = enumerate_volumes().unwrap();
        let find = |mount_point: &[u8]| {
            inventory
                .volumes
                .iter()
                .find(|volume| volume.identity.mount_point.as_bytes() == mount_point)
        };
        let (Some(root), Some(data)) = (find(b"/"), find(b"/System/Volumes/Data")) else {
            // The host does not have the two standard volumes.
            return;
        };
        if root.identity.capacity_key().is_none() || data.identity.capacity_key().is_none() {
            // The registry lookup is not available to this process.
            return;
        }
        assert!(root.identity.shares_capacity_with(&data.identity));
        let grouping = group_by_capacity_pool([&root.identity, &data.identity]);
        assert_eq!(grouping.pools.len(), 1);
    }

    #[test]
    fn the_capacity_of_each_local_volume_keeps_its_invariants() {
        let context = CollectionContext::for_current_process().unwrap();
        let inventory = enumerate_volumes().unwrap();
        let mut measured: usize = 0;
        for volume in inventory.volumes.iter().filter(|v| v.evidence.local) {
            let capacity = collect_capacity(&context, &volume.identity).unwrap();
            let (Some(total), Some(available)) =
                (capacity.total.value(), capacity.available.value())
            else {
                // A volume that went away or was denied has a reason.
                assert!(capacity.total.reason().is_some() || capacity.available.reason().is_some());
                continue;
            };
            assert!(available <= total);
            if let Some(free) = capacity.free.value() {
                assert!(free <= total);
            }
            assert_eq!(
                capacity.available.scope.identity_id.as_str(),
                volume.identity.volume_id.as_str()
            );
            measured += 1;
        }
        assert!(measured > 0);

        let root = volume_at(Path::new("/")).unwrap();
        let capacity = collect_capacity(&context, &root.identity).unwrap();
        assert!(*capacity.total.value().unwrap() > Bytes::ZERO);
    }

    #[test]
    fn the_foundation_values_of_the_root_volume_are_values_or_reasons() {
        let context = CollectionContext::for_current_process().unwrap();
        let root = volume_at(Path::new("/")).unwrap();
        let statfs = collect_capacity(&context, &root.identity).unwrap();
        let foundation = collect_foundation_capacity(&context, &root.identity).unwrap();
        let total: Bytes = *statfs.total.value().unwrap();
        for observation in [&foundation.important, &foundation.opportunistic] {
            match observation.value() {
                // A planning value is not larger than the volume.
                Some(bytes) => assert!(*bytes <= total),
                None => assert!(observation.reason().is_some()),
            }
            assert_ne!(observation.metric_id, statfs.available.metric_id);
        }
        assert_ne!(
            foundation.important.sample.sample_id,
            statfs.available.sample.sample_id
        );
    }

    #[test]
    fn a_path_that_does_not_exist_is_gone_and_not_an_empty_volume() {
        let missing = Path::new("/svalnir-test-path-that-does-not-exist/a");
        assert_eq!(
            volume_at(missing),
            Err(VolumeQueryError::Unavailable(
                UnavailableReason::ResourceGone
            ))
        );

        // A volume identity whose mount point is gone gives a reason.
        let context = CollectionContext::for_current_process().unwrap();
        let mut gone = volume_at(Path::new("/")).unwrap().identity;
        gone.mount_point = svalnir_core::file::LosslessPath::from_path(missing).unwrap();
        let capacity = collect_capacity(&context, &gone).unwrap();
        assert_eq!(
            capacity.available.reason(),
            Some(&UnavailableReason::ResourceGone)
        );
        let foundation = collect_foundation_capacity(&context, &gone).unwrap();
        assert_eq!(foundation.important.value(), None);

        // A path inside a volume is not the mount of that volume.
        let temporary = tempdir_inside_root();
        let mut inside = volume_at(Path::new("/")).unwrap().identity;
        inside.mount_point = svalnir_core::file::LosslessPath::from_path(&temporary).unwrap();
        let capacity = collect_capacity(&context, &inside).unwrap();
        assert!(!capacity.available.is_available());
    }

    /// The temporary directory of the test process. Nothing is written.
    fn tempdir_inside_root() -> std::path::PathBuf {
        std::env::temp_dir()
    }
}
