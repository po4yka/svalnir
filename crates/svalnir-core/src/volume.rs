//! Volume identity and capacity-domain membership.
//!
//! `docs/RESOURCE_MODEL.md` sections 2 and 7 own the identity. APFS volumes
//! of one container share free space. The identity records that
//! relationship, so a consumer does not add the available capacity of
//! sibling volumes.

use serde::{Deserialize, Serialize};

use crate::encoding::wire_enum;
use crate::file::{DeviceNumber, LosslessPath};
use crate::id::{CapacityDomainId, MountId, VolumeId};

wire_enum! {
    /// The kind of a shared-capacity domain.
    CapacityDomainKind {
        /// An APFS container.
        ApfsContainer => "apfs_container",
    }
}

/// Whether a volume shares its free space with other volumes.
///
/// JSON encodes the value as an object with a `membership` field. A
/// `membership` that this build does not know decodes to `Unrecognized`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "membership", rename_all = "snake_case")]
pub enum CapacityDomainMembership {
    /// The volume is a verified member of a shared-capacity domain.
    Shared {
        /// The domain. Sibling volumes have the same identity.
        domain_id: CapacityDomainId,
        /// The kind of the domain.
        domain_kind: CapacityDomainKind,
    },
    /// The volume is verified to share its free space with no other volume.
    Exclusive,
    /// The relationship is not verified. Do not use the volume in a
    /// cross-volume sum or in shared-domain automation.
    Unknown,
    /// A membership value that this build does not recognize. Use it as
    /// `Unknown`.
    #[serde(other)]
    Unrecognized,
}

/// The pool of free space that a capacity measurement of a volume draws on.
///
/// Two volumes with equal keys report the same free space. Count that space
/// one time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CapacityKey<'a> {
    /// A shared-capacity domain.
    Domain(&'a CapacityDomainId),
    /// One volume with exclusive free space.
    Volume(&'a VolumeId),
}

/// The identity of one mounted volume.
///
/// A mount path, a volume UUID, or a device number alone is not a durable
/// identity. The record keeps each piece of evidence that the collector has.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VolumeIdentity {
    /// The opaque identity of the volume record.
    pub volume_id: VolumeId,
    /// The mount generation. A remount makes a new generation.
    pub mount_id: MountId,
    /// The path at which the volume is mounted.
    pub mount_point: LosslessPath,
    /// The device number of the mounted filesystem.
    pub device: DeviceNumber,
    /// The filesystem type name that `statfs` reports, for example `apfs`.
    pub filesystem_type: String,
    /// The volume UUID, when the collector can read it.
    pub volume_uuid: Option<String>,
    /// The shared-capacity relationship of the volume.
    pub capacity_domain: CapacityDomainMembership,
}

impl VolumeIdentity {
    /// The pool of free space that this volume draws on. Returns `None`
    /// when the relationship is not verified; the capacity of such a volume
    /// cannot be added to that of another volume.
    pub fn capacity_key(&self) -> Option<CapacityKey<'_>> {
        match &self.capacity_domain {
            CapacityDomainMembership::Shared { domain_id, .. } => {
                Some(CapacityKey::Domain(domain_id))
            }
            CapacityDomainMembership::Exclusive => Some(CapacityKey::Volume(&self.volume_id)),
            CapacityDomainMembership::Unknown | CapacityDomainMembership::Unrecognized => None,
        }
    }

    /// Whether the two volumes are verified to report the same free space.
    pub fn shares_capacity_with(&self, other: &Self) -> bool {
        match (self.capacity_key(), other.capacity_key()) {
            (Some(own), Some(theirs)) => own == theirs,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use serde_json::{Value, json};

    use super::{CapacityDomainKind, CapacityDomainMembership, CapacityKey, VolumeIdentity};
    use crate::file::{DeviceNumber, LosslessPath};
    use crate::id::{CapacityDomainId, MountId, VolumeId};

    fn volume(
        name: &str,
        mount_point: &str,
        membership: CapacityDomainMembership,
    ) -> VolumeIdentity {
        VolumeIdentity {
            volume_id: VolumeId::new(format!("vol_{name}")).unwrap(),
            mount_id: MountId::new(format!("mount_{name}")).unwrap(),
            mount_point: LosslessPath::from_bytes(mount_point).unwrap(),
            device: DeviceNumber::new(16_777_234),
            filesystem_type: "apfs".to_owned(),
            volume_uuid: None,
            capacity_domain: membership,
        }
    }

    fn container(name: &str) -> CapacityDomainMembership {
        CapacityDomainMembership::Shared {
            domain_id: CapacityDomainId::new(name).unwrap(),
            domain_kind: CapacityDomainKind::ApfsContainer,
        }
    }

    #[test]
    fn a_volume_identity_round_trips() {
        let mut identity: VolumeIdentity =
            volume("data", "/System/Volumes/Data", container("domain_disk3"));
        identity.volume_uuid = Some("6F1E7C1A-0000-4000-8000-000000000001".to_owned());
        let value: Value = serde_json::to_value(&identity).unwrap();
        assert_eq!(
            value,
            json!({
                "volume_id": "vol_data",
                "mount_id": "mount_data",
                "mount_point": { "encoding": "utf8", "value": "/System/Volumes/Data" },
                "device": 16_777_234,
                "filesystem_type": "apfs",
                "volume_uuid": "6F1E7C1A-0000-4000-8000-000000000001",
                "capacity_domain": {
                    "membership": "shared",
                    "domain_id": "domain_disk3",
                    "domain_kind": "apfs_container"
                }
            })
        );
        assert_eq!(
            serde_json::from_value::<VolumeIdentity>(value).unwrap(),
            identity
        );
    }

    #[test]
    fn sibling_volumes_of_one_container_count_one_time() {
        let volumes: Vec<VolumeIdentity> = vec![
            volume("system", "/", container("domain_disk3")),
            volume("data", "/System/Volumes/Data", container("domain_disk3")),
            volume("external", "/Volumes/External", container("domain_disk5")),
            volume("usb", "/Volumes/USB", CapacityDomainMembership::Exclusive),
            volume(
                "network",
                "/Volumes/Share",
                CapacityDomainMembership::Unknown,
            ),
        ];
        assert!(volumes[0].shares_capacity_with(&volumes[1]));
        assert!(!volumes[0].shares_capacity_with(&volumes[2]));
        assert!(!volumes[3].shares_capacity_with(&volumes[0]));
        // An unknown relationship is not a verified one, also with itself.
        assert!(!volumes[4].shares_capacity_with(&volumes[4]));

        let keys: HashSet<CapacityKey<'_>> = volumes
            .iter()
            .filter_map(VolumeIdentity::capacity_key)
            .collect();
        assert_eq!(keys.len(), 3);
        assert_eq!(volumes[4].capacity_key(), None);
    }

    #[test]
    fn an_unknown_membership_is_not_verified() {
        let membership: CapacityDomainMembership =
            serde_json::from_value(json!({ "membership": "volume_group", "group_id": "g1" }))
                .unwrap();
        assert_eq!(membership, CapacityDomainMembership::Unrecognized);
        assert_eq!(volume("x", "/x", membership).capacity_key(), None);

        let shared: CapacityDomainMembership = serde_json::from_value(json!({
            "membership": "shared",
            "domain_id": "domain_x",
            "domain_kind": "core_storage_group"
        }))
        .unwrap();
        let CapacityDomainMembership::Shared { domain_kind, .. } = shared else {
            panic!("the membership is not shared");
        };
        assert!(!domain_kind.is_recognized());
        assert_eq!(
            serde_json::to_value(CapacityDomainMembership::Exclusive).unwrap(),
            json!({ "membership": "exclusive" })
        );
    }
}
