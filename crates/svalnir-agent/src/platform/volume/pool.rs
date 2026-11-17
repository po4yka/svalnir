//! Grouping of volumes by the pool of free space that they draw on.
//!
//! `docs/RESOURCE_MODEL.md` section 7 owns the rule. Sibling volumes of one
//! APFS container report the same shared free space. A consumer counts that
//! space one time, and it does not add the available values of the siblings.
//!
//! The grouping makes no capacity value for a pool: the specification needs
//! a verified domain-level source for that, and `statfs` of one member is
//! not one. A volume with unknown membership is in no pool, which blocks a
//! cross-volume sum that includes it.

use svalnir_core::id::{CapacityDomainId, VolumeId};
use svalnir_core::volume::{CapacityKey, VolumeIdentity};

/// A pool of free space.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CapacityPool {
    /// A verified shared-capacity domain, such as an APFS container.
    Domain(CapacityDomainId),
    /// One volume that is verified to share its free space with no other
    /// volume.
    Volume(VolumeId),
}

/// One pool and the volumes that draw on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapacityPoolMembers {
    /// The pool.
    pub pool: CapacityPool,
    /// The volumes of the pool, each one time, in input order.
    pub members: Vec<VolumeId>,
}

/// Volumes grouped by pool.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CapacityGrouping {
    /// Each pool one time, in the order of its first member.
    pub pools: Vec<CapacityPoolMembers>,
    /// The volumes with a membership that is not verified, each one time.
    /// Do not use them in a cross-volume sum.
    pub unverified: Vec<VolumeId>,
}

impl CapacityGrouping {
    /// Whether each input volume is in a verified pool, so that a
    /// cross-volume view can count each pool one time.
    pub fn is_fully_verified(&self) -> bool {
        self.unverified.is_empty()
    }
}

fn push_unique(list: &mut Vec<VolumeId>, id: &VolumeId) {
    if !list.contains(id) {
        list.push(id.clone());
    }
}

/// Groups volumes by the pool of free space that they draw on.
///
/// Two volumes of one capacity domain are in one pool. A volume that is
/// mounted two times is one member.
pub fn group_by_capacity_pool<'a>(
    volumes: impl IntoIterator<Item = &'a VolumeIdentity>,
) -> CapacityGrouping {
    let mut grouping = CapacityGrouping::default();
    for volume in volumes {
        let pool: CapacityPool = match volume.capacity_key() {
            Some(CapacityKey::Domain(domain_id)) => CapacityPool::Domain(domain_id.clone()),
            Some(CapacityKey::Volume(volume_id)) => CapacityPool::Volume(volume_id.clone()),
            None => {
                push_unique(&mut grouping.unverified, &volume.volume_id);
                continue;
            }
        };
        match grouping.pools.iter_mut().find(|entry| entry.pool == pool) {
            Some(entry) => push_unique(&mut entry.members, &volume.volume_id),
            None => grouping.pools.push(CapacityPoolMembers {
                pool,
                members: vec![volume.volume_id.clone()],
            }),
        }
    }
    grouping
}

#[cfg(test)]
mod tests {
    use svalnir_core::volume::{CapacityDomainMembership, VolumeIdentity};

    use super::super::identity::testing::{apfs_mount, found as found_entry};
    use super::super::identity::{ContainerLookup, mounted_volume};
    use super::{CapacityPool, group_by_capacity_pool};

    const CONTAINER_A: &str = "B700DD4E-AFB3-4299-B1D2-EE46695C99E5";
    const CONTAINER_B: &str = "194AC3EF-6AFE-432A-B74B-6F0325A52637";

    fn volume(
        device: &str,
        mount_point: &str,
        fsid: i32,
        lookup: ContainerLookup,
    ) -> VolumeIdentity {
        let mut uuid = [0_u8; 16];
        uuid[..4].copy_from_slice(&fsid.to_be_bytes());
        mounted_volume(&apfs_mount(device, mount_point, fsid), Some(uuid), lookup)
            .unwrap()
            .identity
    }

    /// A lookup of `container`. Each container UUID has one registry entry.
    fn found(container: &str) -> ContainerLookup {
        let entry_id: u64 = if container.eq_ignore_ascii_case(CONTAINER_A) {
            1
        } else {
            2
        };
        found_entry(container, entry_id)
    }

    #[test]
    fn the_volumes_of_one_container_are_one_pool() {
        let root = volume("disk3s1s1", "/", 1, found(CONTAINER_A));
        let data = volume("disk3s5", "/System/Volumes/Data", 2, found(CONTAINER_A));
        let preboot = volume("disk3s2", "/System/Volumes/Preboot", 3, found(CONTAINER_A));
        let hardware = volume("disk1s3", "/System/Volumes/Hardware", 4, found(CONTAINER_B));

        // The siblings have one domain identity and report shared space.
        assert!(root.shares_capacity_with(&data));
        assert!(data.shares_capacity_with(&preboot));
        assert!(!data.shares_capacity_with(&hardware));

        let grouping = group_by_capacity_pool([&root, &data, &preboot, &hardware]);
        assert!(grouping.is_fully_verified());
        assert_eq!(grouping.pools.len(), 2);
        assert_eq!(
            grouping.pools[0].members,
            vec![
                root.volume_id.clone(),
                data.volume_id.clone(),
                preboot.volume_id.clone()
            ]
        );
        assert_eq!(grouping.pools[1].members, vec![hardware.volume_id.clone()]);
        assert!(matches!(grouping.pools[0].pool, CapacityPool::Domain(_)));
        assert_ne!(grouping.pools[0].pool, grouping.pools[1].pool);
    }

    #[test]
    fn the_domain_identity_does_not_depend_on_the_case_of_the_registry_text() {
        let upper = volume("disk3s5", "/a", 1, found(CONTAINER_A));
        let lower = volume("disk3s2", "/b", 2, found(&CONTAINER_A.to_lowercase()));
        assert!(upper.shares_capacity_with(&lower));
        assert_eq!(group_by_capacity_pool([&upper, &lower]).pools.len(), 1);
    }

    #[test]
    fn an_unknown_membership_is_in_no_pool_and_blocks_the_sum() {
        let data = volume("disk3s5", "/System/Volumes/Data", 2, found(CONTAINER_A));
        // Two volumes that are possibly siblings: the lookup failed.
        let unknown_a = volume("disk5s1", "/Volumes/a", 5, ContainerLookup::NotExamined);
        let unknown_b = volume(
            "disk5s2",
            "/Volumes/b",
            6,
            ContainerLookup::Failed(svalnir_core::observation::UnavailableReason::ResourceGone),
        );
        assert!(!unknown_a.shares_capacity_with(&unknown_b));
        assert!(!unknown_a.shares_capacity_with(&unknown_a));

        let grouping = group_by_capacity_pool([&data, &unknown_a, &unknown_b]);
        assert!(!grouping.is_fully_verified());
        assert_eq!(grouping.pools.len(), 1);
        assert_eq!(
            grouping.unverified,
            vec![unknown_a.volume_id.clone(), unknown_b.volume_id.clone()]
        );
    }

    #[test]
    fn a_volume_that_is_mounted_two_times_is_one_member() {
        let first = volume("disk3s5", "/System/Volumes/Data", 2, found(CONTAINER_A));
        let mut second = first.clone();
        second.mount_point =
            svalnir_core::file::LosslessPath::from_bytes("/Volumes/Again").unwrap();
        let grouping = group_by_capacity_pool([&first, &second]);
        assert_eq!(grouping.pools.len(), 1);
        assert_eq!(grouping.pools[0].members, vec![first.volume_id.clone()]);

        let mut unknown = first.clone();
        unknown.capacity_domain = CapacityDomainMembership::Unknown;
        let grouping = group_by_capacity_pool([&unknown, &unknown]);
        assert_eq!(grouping.unverified, vec![unknown.volume_id.clone()]);
    }

    #[test]
    fn an_exclusive_volume_is_its_own_pool() {
        let mut alone = volume("disk8s1", "/Volumes/Alone", 8, ContainerLookup::NotExamined);
        alone.capacity_domain = CapacityDomainMembership::Exclusive;
        let mut other = volume("disk9s1", "/Volumes/Other", 9, ContainerLookup::NotExamined);
        other.capacity_domain = CapacityDomainMembership::Exclusive;
        let grouping = group_by_capacity_pool([&alone, &other]);
        assert!(grouping.is_fully_verified());
        assert_eq!(grouping.pools.len(), 2);
        assert_eq!(
            grouping.pools[0].pool,
            CapacityPool::Volume(alone.volume_id.clone())
        );
    }

    #[test]
    fn no_volume_gives_no_pool() {
        let grouping = group_by_capacity_pool(std::iter::empty());
        assert_eq!(grouping.pools, []);
        assert!(grouping.is_fully_verified());
    }
}
