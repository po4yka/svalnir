//! Raw native samples of the volume queries.
//!
//! A raw sample has the native values of one call with no interpretation.
//! The native adapter makes it, and a test can make it from literals.

use svalnir_core::observation::UnavailableReason;

/// The fields of one `statfs` structure that the collector reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawMount {
    /// `f_mntonname`: the path at which the filesystem is mounted, as bytes.
    pub mount_point: Vec<u8>,
    /// `f_mntfromname`: the mounted device or source, as bytes.
    pub mounted_from: Vec<u8>,
    /// `f_fstypename`: the filesystem type name, as bytes.
    pub filesystem_type: Vec<u8>,
    /// `f_fsid`: the two words of the filesystem identity. The first word is
    /// the device number of the mounted filesystem.
    pub fsid: [i32; 2],
    /// `f_flags`: the mount flags.
    pub flags: u32,
    /// `f_bsize`: the filesystem block size, the unit of the block counts.
    pub block_size: u32,
    /// `f_blocks`: the total data blocks.
    pub blocks: u64,
    /// `f_bfree`: the free blocks.
    pub blocks_free: u64,
    /// `f_bavail`: the free blocks that a user without privilege can use.
    pub blocks_available: u64,
}

/// `MNT_RDONLY`: the filesystem is mounted read-only.
pub const MOUNT_FLAG_READ_ONLY: u32 = 0x0000_0001;
/// `MNT_LOCAL`: the filesystem is stored locally.
pub const MOUNT_FLAG_LOCAL: u32 = 0x0000_1000;
/// `MNT_DONTBROWSE`: the filesystem is not shown to the user.
pub const MOUNT_FLAG_DONT_BROWSE: u32 = 0x0010_0000;

/// The Foundation capacity values of one volume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawFoundationCapacity {
    /// `NSURLVolumeAvailableCapacityForImportantUsageKey`, in bytes.
    pub important: Result<u64, UnavailableReason>,
    /// `NSURLVolumeAvailableCapacityForOpportunisticUsageKey`, in bytes.
    pub opportunistic: Result<u64, UnavailableReason>,
}

/// The APFS container of one device, from the I/O Registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawApfsContainer {
    /// The `UUID` property of the `AppleAPFSContainer` object.
    pub uuid: String,
    /// The registry entry ID of the `AppleAPFSContainer` object. It is
    /// unique in one boot, so it tells two containers with one UUID apart.
    pub registry_entry_id: u64,
}
