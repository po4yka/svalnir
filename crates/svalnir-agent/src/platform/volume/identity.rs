//! Volume identity from `statfs` evidence.
//!
//! `docs/RESOURCE_MODEL.md` sections 2 and 7 own the identity. The builder
//! takes a raw mount, an optional volume UUID, and the result of a container
//! lookup, so a test can make identities from literals.
//!
//! Capacity-domain membership comes only from the I/O Registry: the device
//! of an APFS mount is found by its BSD name, and the `UUID` property of the
//! `AppleAPFSContainer` object above it names the domain. The collector does
//! not derive a container from the digits of a device name. When the lookup
//! is not made or fails, the membership is `Unknown`.

use std::collections::{HashMap, HashSet};

use svalnir_core::file::{DeviceNumber, LosslessPath, PathError};
use svalnir_core::id::{CapacityDomainId, IdError, MountId, VolumeId};
use svalnir_core::observation::UnavailableReason;
use svalnir_core::volume::{CapacityDomainKind, CapacityDomainMembership, VolumeIdentity};
use thiserror::Error;

use super::raw::{
    MOUNT_FLAG_DONT_BROWSE, MOUNT_FLAG_LOCAL, MOUNT_FLAG_READ_ONLY, RawApfsContainer, RawMount,
};

/// The filesystem type name of APFS.
const APFS_TYPE: &[u8] = b"apfs";
/// The directory of device nodes. An APFS mount source in it names a device.
const DEVICE_PREFIX: &[u8] = b"/dev/";
/// The length of the text form of a UUID.
const UUID_TEXT_LENGTH: usize = 36;

/// The result of the capacity-domain lookup of one mount.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContainerLookup {
    /// No lookup was made: the mount is not an APFS mount of a device.
    NotExamined,
    /// The I/O Registry gave the APFS container of the device.
    Found(RawApfsContainer),
    /// The lookup failed.
    Failed(UnavailableReason),
}

/// How the capacity-domain membership of a volume was established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapacityDomainEvidence {
    /// The I/O Registry has an `AppleAPFSContainer` object above the device
    /// of the mount, and its `UUID` property is the container UUID.
    ApfsContainerRegistryEntry {
        /// The UUID of the container.
        container_uuid: String,
        /// The registry entry ID of the container object, unique in one
        /// boot.
        registry_entry_id: u64,
    },
    /// The mount is not an APFS mount of a device. The collector has no
    /// verified source for its relationship, so the membership is unknown.
    NotExamined,
    /// The lookup failed or gave a value that is not a UUID. The membership
    /// is unknown.
    LookupFailed(UnavailableReason),
}

/// How the volume UUID of a mount was established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VolumeUuidLookup {
    /// No query was made, for example for a network filesystem.
    NotExamined,
    /// The query gave this UUID for the mount.
    Found([u8; 16]),
    /// The filesystem has no volume UUID. The identity is fsid-based.
    NotProvided,
    /// The query failed, so the identity is fsid-based because of this
    /// reason. It is not the same as a filesystem with no UUID.
    Failed(UnavailableReason),
    /// Mounts with different `f_fsid` have this UUID, for example two copies
    /// of one disk image. The UUID does not name one volume, so the identity
    /// is fsid-based.
    Duplicate([u8; 16]),
}

impl From<Option<[u8; 16]>> for VolumeUuidLookup {
    fn from(uuid: Option<[u8; 16]>) -> Self {
        uuid.map_or(Self::NotProvided, Self::Found)
    }
}

impl From<Result<Option<[u8; 16]>, UnavailableReason>> for VolumeUuidLookup {
    fn from(result: Result<Option<[u8; 16]>, UnavailableReason>) -> Self {
        match result {
            Ok(uuid) => uuid.into(),
            Err(reason) => Self::Failed(reason),
        }
    }
}

/// The `statfs` evidence of one mount, apart from the identity fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountEvidence {
    /// `f_mntfromname`: the mounted device or source. `None` when empty.
    pub mounted_from: Option<LosslessPath>,
    /// `f_fsid`: the two words of the filesystem identity.
    pub fsid: [i32; 2],
    /// `MNT_RDONLY`: the volume is mounted read-only. This is an action
    /// constraint; it does not make the available capacity zero.
    pub read_only: bool,
    /// `MNT_LOCAL`: the volume is stored locally.
    pub local: bool,
    /// The complement of `MNT_DONTBROWSE`: the volume is shown to the user.
    pub browsable: bool,
    /// How the capacity-domain membership was established.
    pub capacity_domain: CapacityDomainEvidence,
    /// How the volume UUID was established.
    pub volume_uuid: VolumeUuidLookup,
}

/// One mounted volume: its identity and the evidence of the identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountedVolume {
    /// The identity of the volume.
    pub identity: VolumeIdentity,
    /// The evidence of the mount.
    pub evidence: MountEvidence,
}

/// The reason a raw mount gives no volume identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum VolumeIdentityError {
    /// The mount point is empty or has a NUL byte.
    #[error("the mount point is not a path: {0}")]
    MountPoint(#[from] PathError),
    /// The filesystem type name is empty or is not UTF-8 text.
    #[error("the filesystem type name is empty or is not text")]
    FilesystemType,
    /// A derived identity is not valid.
    #[error("a derived identity is not valid: {0}")]
    Identity(#[from] IdError),
}

/// The BSD device name of an APFS mount, for example `disk3s5`.
///
/// Returns `None` when the filesystem is not APFS or the mount source is not
/// a node in `/dev`. The name is only the key of a registry lookup; no
/// container is derived from its text.
pub fn apfs_device_name(raw: &RawMount) -> Option<&[u8]> {
    if raw.filesystem_type != APFS_TYPE {
        return None;
    }
    raw.mounted_from
        .strip_prefix(DEVICE_PREFIX)
        .filter(|name| !name.is_empty() && !name.contains(&b'/'))
}

/// The text form of a UUID: uppercase hexadecimal digits in groups of 8, 4,
/// 4, 4, and 12.
pub fn uuid_text(uuid: [u8; 16]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let mut text = String::with_capacity(UUID_TEXT_LENGTH);
    for (index, byte) in uuid.iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            text.push('-');
        }
        text.push(char::from(DIGITS[usize::from(byte >> 4)]));
        text.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    text
}

/// Whether `text` has the form of a UUID.
fn is_uuid_text(text: &str) -> bool {
    text.len() == UUID_TEXT_LENGTH
        && text.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

/// The mount generation identity for the two words of `f_fsid`.
///
/// The identity is comparable in one boot. A remount that gets the same
/// `f_fsid` is not distinguished: `statfs` gives no mount time.
///
/// # Errors
///
/// Returns an [`IdError`] when the text is not an identity. The text has
/// only hexadecimal digits, so a test shows that this does not occur.
pub fn mount_id(fsid: [i32; 2]) -> Result<MountId, IdError> {
    MountId::new(format!("mount_{:08x}_{:08x}", fsid[0], fsid[1]))
}

fn volume_id(uuid: Option<&str>, fsid: [i32; 2]) -> Result<VolumeId, IdError> {
    match uuid {
        Some(uuid) => VolumeId::new(format!("vol_{uuid}")),
        // No UUID: the record is the mounted filesystem of this boot.
        None => VolumeId::new(format!("vol_fsid_{:08x}_{:08x}", fsid[0], fsid[1])),
    }
}

fn capacity_domain(
    lookup: ContainerLookup,
) -> Result<(CapacityDomainMembership, CapacityDomainEvidence), IdError> {
    match lookup {
        ContainerLookup::NotExamined => Ok((
            CapacityDomainMembership::Unknown,
            CapacityDomainEvidence::NotExamined,
        )),
        ContainerLookup::Failed(reason) => Ok((
            CapacityDomainMembership::Unknown,
            CapacityDomainEvidence::LookupFailed(reason),
        )),
        ContainerLookup::Found(container) => {
            let container_uuid: String = container.uuid;
            if !is_uuid_text(&container_uuid) {
                return Ok((
                    CapacityDomainMembership::Unknown,
                    CapacityDomainEvidence::LookupFailed(UnavailableReason::InconsistentData),
                ));
            }
            let container_uuid: String = container_uuid.to_ascii_uppercase();
            let domain_id = CapacityDomainId::new(format!("apfs_{container_uuid}"))?;
            Ok((
                CapacityDomainMembership::Shared {
                    domain_id,
                    domain_kind: CapacityDomainKind::ApfsContainer,
                },
                CapacityDomainEvidence::ApfsContainerRegistryEntry {
                    container_uuid,
                    registry_entry_id: container.registry_entry_id,
                },
            ))
        }
    }
}

/// Marks each volume UUID that mounts with different `f_fsid` words have.
///
/// Two attached copies of one disk image have the same volume UUID. The UUID
/// then does not name one volume, so each such lookup becomes
/// [`VolumeUuidLookup::Duplicate`], and the identity of each of those mounts
/// is derived from its `f_fsid`.
///
/// `mounts` and `lookups` have the same length and order.
pub fn reject_duplicate_volume_uuids(mounts: &[RawMount], lookups: &mut [VolumeUuidLookup]) {
    let mut first_fsid: HashMap<[u8; 16], [i32; 2]> = HashMap::new();
    let mut duplicated: HashSet<[u8; 16]> = HashSet::new();
    for (raw, lookup) in mounts.iter().zip(lookups.iter()) {
        if let VolumeUuidLookup::Found(uuid) = lookup {
            match first_fsid.get(uuid) {
                Some(fsid) if *fsid != raw.fsid => {
                    duplicated.insert(*uuid);
                }
                Some(_) => {}
                None => {
                    first_fsid.insert(*uuid, raw.fsid);
                }
            }
        }
    }
    for lookup in lookups.iter_mut() {
        if let VolumeUuidLookup::Found(uuid) = *lookup
            && duplicated.contains(&uuid)
        {
            *lookup = VolumeUuidLookup::Duplicate(uuid);
        }
    }
}

/// Rejects each container UUID that two different container objects have.
///
/// Two attached copies of one disk image have the same container UUID and
/// do not share free space. The UUID then does not name one pool, so each
/// lookup with that UUID becomes a failed lookup with the reason
/// `inconsistent_data`, and the membership of those volumes is unknown.
pub fn reject_ambiguous_containers(lookups: &mut [ContainerLookup]) {
    let mut first_entry: HashMap<String, u64> = HashMap::new();
    let mut ambiguous: HashSet<String> = HashSet::new();
    for lookup in lookups.iter() {
        if let ContainerLookup::Found(container) = lookup {
            let uuid: String = container.uuid.to_ascii_uppercase();
            match first_entry.get(&uuid) {
                Some(entry_id) if *entry_id != container.registry_entry_id => {
                    ambiguous.insert(uuid);
                }
                Some(_) => {}
                None => {
                    first_entry.insert(uuid, container.registry_entry_id);
                }
            }
        }
    }
    for lookup in lookups.iter_mut() {
        let is_ambiguous: bool = matches!(
            lookup,
            ContainerLookup::Found(container)
                if ambiguous.contains(&container.uuid.to_ascii_uppercase())
        );
        if is_ambiguous {
            *lookup = ContainerLookup::Failed(UnavailableReason::InconsistentData);
        }
    }
}

/// Makes the identity of one mounted volume from its evidence.
///
/// The volume identity has the volume UUID when there is one, and the
/// `f_fsid` words when there is none. The device number is the first word of
/// `f_fsid`.
///
/// # Errors
///
/// Returns a [`VolumeIdentityError`] when the mount point is not a path or
/// the filesystem type name is not text.
pub fn mounted_volume(
    raw: &RawMount,
    volume_uuid: impl Into<VolumeUuidLookup>,
    container: ContainerLookup,
) -> Result<MountedVolume, VolumeIdentityError> {
    let uuid_lookup: VolumeUuidLookup = volume_uuid.into();
    let mount_point: LosslessPath = LosslessPath::from_bytes(raw.mount_point.clone())?;
    let filesystem_type: String = String::from_utf8(raw.filesystem_type.clone())
        .ok()
        .filter(|name| !name.is_empty())
        .ok_or(VolumeIdentityError::FilesystemType)?;
    let volume_uuid: Option<String> = match uuid_lookup {
        VolumeUuidLookup::Found(uuid) => Some(uuid_text(uuid)),
        _ => None,
    };
    let (membership, evidence) = capacity_domain(container)?;
    Ok(MountedVolume {
        identity: VolumeIdentity {
            volume_id: volume_id(volume_uuid.as_deref(), raw.fsid)?,
            mount_id: mount_id(raw.fsid)?,
            mount_point,
            device: DeviceNumber::new(raw.fsid[0]),
            filesystem_type,
            volume_uuid,
            capacity_domain: membership,
        },
        evidence: MountEvidence {
            mounted_from: LosslessPath::from_bytes(raw.mounted_from.clone()).ok(),
            fsid: raw.fsid,
            read_only: raw.flags & MOUNT_FLAG_READ_ONLY != 0,
            local: raw.flags & MOUNT_FLAG_LOCAL != 0,
            browsable: raw.flags & MOUNT_FLAG_DONT_BROWSE == 0,
            capacity_domain: evidence,
            volume_uuid: uuid_lookup,
        },
    })
}

#[cfg(test)]
pub(crate) mod testing {
    use super::super::raw::{MOUNT_FLAG_LOCAL, RawApfsContainer, RawMount};
    use super::ContainerLookup;

    /// A successful lookup of the container `uuid` with the registry entry
    /// `registry_entry_id`.
    pub(crate) fn found(uuid: &str, registry_entry_id: u64) -> ContainerLookup {
        ContainerLookup::Found(RawApfsContainer {
            uuid: uuid.to_owned(),
            registry_entry_id,
        })
    }

    /// A raw APFS mount of `/dev/DEVICE` at `mount_point`.
    pub(crate) fn apfs_mount(device: &str, mount_point: &str, fsid: i32) -> RawMount {
        RawMount {
            mount_point: mount_point.as_bytes().to_vec(),
            mounted_from: format!("/dev/{device}").into_bytes(),
            filesystem_type: b"apfs".to_vec(),
            fsid: [fsid, 26],
            flags: MOUNT_FLAG_LOCAL,
            block_size: 4_096,
            blocks: 1_000_000,
            blocks_free: 400_000,
            blocks_available: 300_000,
        }
    }
}

#[cfg(test)]
mod tests {
    use svalnir_core::observation::UnavailableReason;
    use svalnir_core::volume::{CapacityDomainKind, CapacityDomainMembership};

    use super::super::raw::{
        MOUNT_FLAG_DONT_BROWSE, MOUNT_FLAG_LOCAL, MOUNT_FLAG_READ_ONLY, RawMount,
    };
    use super::testing::{apfs_mount, found};
    use super::{
        CapacityDomainEvidence, ContainerLookup, VolumeIdentityError, VolumeUuidLookup,
        apfs_device_name, mount_id, mounted_volume, reject_ambiguous_containers,
        reject_duplicate_volume_uuids, uuid_text,
    };

    const CONTAINER: &str = "B700DD4E-AFB3-4299-B1D2-EE46695C99E5";
    const VOLUME_UUID: [u8; 16] = [
        0x6f, 0x1e, 0x7c, 0x1a, 0x00, 0x00, 0x40, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01,
    ];

    #[test]
    fn a_uuid_has_its_canonical_text() {
        assert_eq!(
            uuid_text(VOLUME_UUID),
            "6F1E7C1A-0000-4000-8000-000000000001"
        );
    }

    #[test]
    fn the_identity_keeps_each_piece_of_statfs_evidence() {
        let mut raw = apfs_mount("disk3s5", "/System/Volumes/Data", 16_777_234);
        raw.flags = MOUNT_FLAG_LOCAL | MOUNT_FLAG_DONT_BROWSE;
        let volume =
            mounted_volume(&raw, Some(VOLUME_UUID), found(CONTAINER, 0x1_0000_0a36)).unwrap();

        let identity = &volume.identity;
        assert_eq!(
            identity.volume_id.as_str(),
            "vol_6F1E7C1A-0000-4000-8000-000000000001"
        );
        assert_eq!(identity.mount_id.as_str(), "mount_01000012_0000001a");
        assert_eq!(identity.mount_id, mount_id([16_777_234, 26]).unwrap());
        assert_eq!(identity.mount_point.as_utf8(), Some("/System/Volumes/Data"));
        assert_eq!(identity.device.get(), 16_777_234);
        assert_eq!(identity.filesystem_type, "apfs");
        assert_eq!(
            identity.volume_uuid.as_deref(),
            Some("6F1E7C1A-0000-4000-8000-000000000001")
        );
        match &identity.capacity_domain {
            CapacityDomainMembership::Shared {
                domain_id,
                domain_kind,
            } => {
                assert_eq!(
                    domain_id.as_str(),
                    "apfs_B700DD4E-AFB3-4299-B1D2-EE46695C99E5"
                );
                assert_eq!(*domain_kind, CapacityDomainKind::ApfsContainer);
            }
            other => panic!("the membership is {other:?}"),
        }

        let evidence = &volume.evidence;
        assert_eq!(
            evidence
                .mounted_from
                .as_ref()
                .and_then(|from| from.as_utf8()),
            Some("/dev/disk3s5")
        );
        assert_eq!(evidence.fsid, [16_777_234, 26]);
        assert!(evidence.local);
        assert!(!evidence.read_only);
        assert!(!evidence.browsable);
        assert_eq!(
            evidence.capacity_domain,
            CapacityDomainEvidence::ApfsContainerRegistryEntry {
                container_uuid: CONTAINER.to_owned(),
                registry_entry_id: 0x1_0000_0a36,
            }
        );
        // The identity encodes.
        serde_json::to_string(identity).unwrap();
    }

    #[test]
    fn a_volume_with_no_uuid_has_an_identity_from_its_fsid() {
        let raw = RawMount {
            mount_point: b"/dev".to_vec(),
            mounted_from: b"devfs".to_vec(),
            filesystem_type: b"devfs".to_vec(),
            fsid: [-1_694_498_816, 19],
            flags: MOUNT_FLAG_LOCAL | MOUNT_FLAG_DONT_BROWSE | MOUNT_FLAG_READ_ONLY,
            block_size: 512,
            blocks: 0,
            blocks_free: 0,
            blocks_available: 0,
        };
        let volume = mounted_volume(&raw, None, ContainerLookup::NotExamined).unwrap();
        assert_eq!(
            volume.identity.volume_id.as_str(),
            "vol_fsid_9b000000_00000013"
        );
        assert_eq!(volume.identity.volume_uuid, None);
        assert_eq!(volume.identity.device.get(), -1_694_498_816);
        assert_eq!(
            volume.identity.capacity_domain,
            CapacityDomainMembership::Unknown
        );
        assert_eq!(volume.identity.capacity_key(), None);
        assert!(volume.evidence.read_only);
        assert_eq!(
            volume.evidence.capacity_domain,
            CapacityDomainEvidence::NotExamined
        );
    }

    #[test]
    fn a_membership_that_is_not_verified_is_unknown() {
        let raw = apfs_mount("disk3s5", "/System/Volumes/Data", 7);
        for (lookup, evidence) in [
            (
                ContainerLookup::Failed(UnavailableReason::ResourceGone),
                CapacityDomainEvidence::LookupFailed(UnavailableReason::ResourceGone),
            ),
            (
                // The registry value is not a UUID.
                found("disk3", 1),
                CapacityDomainEvidence::LookupFailed(UnavailableReason::InconsistentData),
            ),
            (
                found("", 1),
                CapacityDomainEvidence::LookupFailed(UnavailableReason::InconsistentData),
            ),
            (
                ContainerLookup::NotExamined,
                CapacityDomainEvidence::NotExamined,
            ),
        ] {
            let volume = mounted_volume(&raw, Some(VOLUME_UUID), lookup).unwrap();
            assert_eq!(
                volume.identity.capacity_domain,
                CapacityDomainMembership::Unknown
            );
            assert_eq!(volume.identity.capacity_key(), None);
            assert_eq!(volume.evidence.capacity_domain, evidence);
        }
    }

    #[test]
    fn a_uuid_of_two_container_objects_names_no_pool() {
        const IMAGE: &str = "53829015-7AC8-4FB7-A06F-622A3F5BE8CC";
        let mut lookups = vec![
            found(CONTAINER, 10),
            found(IMAGE, 20),
            ContainerLookup::NotExamined,
            found(CONTAINER, 10),
            // The same image is attached a second time.
            found(&IMAGE.to_lowercase(), 21),
            ContainerLookup::Failed(UnavailableReason::ResourceGone),
        ];
        reject_ambiguous_containers(&mut lookups);
        assert_eq!(
            lookups,
            vec![
                found(CONTAINER, 10),
                ContainerLookup::Failed(UnavailableReason::InconsistentData),
                ContainerLookup::NotExamined,
                found(CONTAINER, 10),
                ContainerLookup::Failed(UnavailableReason::InconsistentData),
                ContainerLookup::Failed(UnavailableReason::ResourceGone),
            ]
        );

        let raw = apfs_mount("disk11s1", "/Volumes/Image", 11);
        let volume = mounted_volume(&raw, None, lookups[1].clone()).unwrap();
        assert_eq!(
            volume.identity.capacity_domain,
            CapacityDomainMembership::Unknown
        );
    }

    #[test]
    fn only_an_apfs_mount_of_a_device_node_gives_a_lookup_key() {
        let raw = apfs_mount("disk3s1s1", "/", 7);
        assert_eq!(apfs_device_name(&raw), Some(b"disk3s1s1".as_slice()));

        let mut other_type = raw.clone();
        other_type.filesystem_type = b"hfs".to_vec();
        assert_eq!(apfs_device_name(&other_type), None);

        for source in ["disk3s1", "/dev/", "/dev/a/b", "map auto_home", ""] {
            let mut other_source = raw.clone();
            other_source.mounted_from = source.as_bytes().to_vec();
            assert_eq!(apfs_device_name(&other_source), None, "{source}");
        }
    }

    #[test]
    fn a_mount_with_no_path_or_type_gives_no_identity() {
        let mut no_path = apfs_mount("disk3s5", "/", 7);
        no_path.mount_point.clear();
        assert!(matches!(
            mounted_volume(&no_path, None, ContainerLookup::NotExamined),
            Err(VolumeIdentityError::MountPoint(_))
        ));

        for filesystem_type in [b"".to_vec(), vec![0xff, 0xfe]] {
            let mut no_type = apfs_mount("disk3s5", "/", 7);
            no_type.filesystem_type = filesystem_type;
            assert_eq!(
                mounted_volume(&no_type, None, ContainerLookup::NotExamined),
                Err(VolumeIdentityError::FilesystemType)
            );
        }
    }

    #[test]
    fn a_mount_point_that_is_not_text_is_kept_exactly() {
        let mut raw = apfs_mount("disk9s1", "/Volumes/x", 9);
        raw.mount_point = b"/Volumes/\xff\xfe".to_vec();
        let volume = mounted_volume(&raw, None, ContainerLookup::NotExamined).unwrap();
        assert_eq!(volume.identity.mount_point.as_bytes(), b"/Volumes/\xff\xfe");
    }

    #[test]
    fn two_mounts_with_one_volume_uuid_get_identities_from_their_fsid() {
        let first = apfs_mount("disk4s1", "/Volumes/Image", 40);
        let second = apfs_mount("disk5s1", "/Volumes/Image 1", 50);
        let other = apfs_mount("disk6s1", "/Volumes/Other", 60);
        let mut same_fsid = first.clone();
        same_fsid.mount_point = b"/Volumes/Alias".to_vec();
        let mounts = [first, second, other, same_fsid];
        let mut lookups = vec![
            VolumeUuidLookup::Found(VOLUME_UUID),
            VolumeUuidLookup::Found(VOLUME_UUID),
            VolumeUuidLookup::Found([9; 16]),
            VolumeUuidLookup::Found(VOLUME_UUID),
        ];
        reject_duplicate_volume_uuids(&mounts, &mut lookups);
        assert_eq!(lookups[0], VolumeUuidLookup::Duplicate(VOLUME_UUID));
        assert_eq!(lookups[1], VolumeUuidLookup::Duplicate(VOLUME_UUID));
        assert_eq!(lookups[2], VolumeUuidLookup::Found([9; 16]));
        assert_eq!(lookups[3], VolumeUuidLookup::Duplicate(VOLUME_UUID));

        let ids: Vec<String> = mounts
            .iter()
            .zip(&lookups)
            .map(|(raw, lookup)| {
                let volume =
                    mounted_volume(raw, lookup.clone(), ContainerLookup::NotExamined).unwrap();
                assert_eq!(volume.evidence.volume_uuid, lookup.clone(),);
                volume.identity.volume_id.as_str().to_owned()
            })
            .collect();
        assert_eq!(ids[0], "vol_fsid_00000028_0000001a");
        assert_eq!(ids[1], "vol_fsid_00000032_0000001a");
        assert_ne!(ids[0], ids[1]);
        assert!(ids[2].starts_with("vol_09090909"));
    }

    #[test]
    fn a_failed_uuid_query_is_kept_apart_from_a_filesystem_with_no_uuid() {
        let raw = apfs_mount("disk3s5", "/", 7);
        let failed = mounted_volume(
            &raw,
            Err::<Option<[u8; 16]>, _>(UnavailableReason::IdentityChanged),
            ContainerLookup::NotExamined,
        )
        .unwrap();
        let none = mounted_volume(&raw, None, ContainerLookup::NotExamined).unwrap();
        assert_eq!(failed.identity.volume_id, none.identity.volume_id);
        assert_eq!(
            failed.evidence.volume_uuid,
            VolumeUuidLookup::Failed(UnavailableReason::IdentityChanged)
        );
        assert_eq!(none.evidence.volume_uuid, VolumeUuidLookup::NotProvided);
    }
}
