//! Whether a path or a device is on a filesystem of this host, from the
//! mount table.
//!
//! A cleanup root, a discovery root, and the project path of a rule must be
//! on a filesystem that the mount flags report as local (`MNT_LOCAL`). A
//! local external disk is local. A network filesystem and an automounter
//! map (`autofs`) are not.
//!
//! The table comes from `getfsstat` with `MNT_NOWAIT`. That call does not
//! wait for a filesystem that does not answer. The two queries of
//! [`MountTable`] read the table only: [`MountTable::path_locality`]
//! compares the text of a path with the mount points, and
//! [`MountTable::device_locality`] compares a device number with the
//! filesystem identities. Neither query calls the filesystem of the path,
//! so neither can start an automount or wait on a remote filesystem. A
//! caller asks [`MountTable::path_locality`] before its first call that
//! uses the path, and [`MountTable::device_locality`] for the device of
//! each object that it measured.
//!
//! Owning specifications: `docs/CLEANUP_RULES.md` section 4 and
//! `docs/ACTION_CONTRACTS.md` section 7.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;

use svalnir_core::file::DeviceNumber;
use svalnir_core::observation::UnavailableReason;

use super::native;
use super::raw::{MOUNT_FLAG_LOCAL, RawMount};

/// The mount point of the data volume of macOS. A firmlink shows each
/// directory of that volume also at the same path below `/`, so a mount
/// point below it has a second path, and a mount point below a firmlink
/// of `/` has a second path below it.
const DATA_VOLUME: &[u8] = b"/System/Volumes/Data";

/// The filesystem type of the automounter. A lookup below one of its
/// mounts can start a mount of a remote filesystem.
const AUTOFS: &[u8] = b"autofs";

/// Whether a filesystem is stored on this host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Locality {
    /// Each mount that matches has the flag `MNT_LOCAL`, and none is an
    /// automounter map.
    Local,
    /// A mount that matches has no `MNT_LOCAL`, or is an automounter map.
    NotLocal,
    /// No mount of the table matches, or the table is not available.
    Unknown,
}

/// The mounted filesystems of the host at one time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountTable {
    mounts: Vec<RawMount>,
}

/// The function that gives the mount table. Production code uses
/// [`MountTable::read`]; a test gives a table with a filesystem that is not
/// local, so that no test mounts anything.
pub type MountTableSource = fn() -> Result<MountTable, UnavailableReason>;

/// Whether `raw` is a local filesystem that is not an automounter map.
fn is_local(raw: &RawMount) -> bool {
    raw.flags & MOUNT_FLAG_LOCAL != 0 && raw.filesystem_type != AUTOFS
}

impl MountTable {
    /// Reads the mount table of the host with `getfsstat` and `MNT_NOWAIT`.
    ///
    /// # Errors
    ///
    /// Returns the reason when the table cannot be read.
    pub fn read() -> Result<Self, UnavailableReason> {
        native::mounted_filesystems().map(Self::from_mounts)
    }

    /// A table of the given mounts, in the order of the mount table: a
    /// later mount at the same point is on top of an earlier one.
    pub fn from_mounts(mounts: Vec<RawMount>) -> Self {
        Self { mounts }
    }

    /// The mounts of the table.
    pub fn mounts(&self) -> &[RawMount] {
        &self.mounts
    }

    /// The locality of the filesystem whose identity has the first word
    /// `device`, the `st_dev` of an object on it.
    pub fn device_locality(&self, device: DeviceNumber) -> Locality {
        let mut found: Option<bool> = None;
        for raw in self.mounts.iter().filter(|raw| raw.fsid[0] == device.get()) {
            found = Some(found.unwrap_or(true) && is_local(raw));
        }
        match found {
            Some(true) => Locality::Local,
            Some(false) => Locality::NotLocal,
            None => Locality::Unknown,
        }
    }

    /// The locality of the mount whose mount point is the longest prefix of
    /// the text of `path`, by whole components. A mount point below the
    /// data volume is also compared at its firmlink path below `/`, and a
    /// mount point below `/` also at its path below the data volume. The
    /// query makes no call on the path.
    ///
    /// The text does not show a symbolic link in the path: the caller also
    /// compares the device of each object that it measures.
    pub fn path_locality(&self, path: &Path) -> Locality {
        if !path.is_absolute() {
            return Locality::Unknown;
        }
        // The number of components of the best mount point, and whether its
        // mount is local.
        let mut best: Option<(usize, bool)> = None;
        for raw in &self.mounts {
            let point: &[u8] = raw.mount_point.as_slice();
            // The firmlinks go in the two directions: a mount point below
            // the data volume has a second path below `/`, and a mount
            // point below `/` (for example `/Volumes/NAS`) has a second path
            // below the data volume.
            let below_data: Option<&[u8]> = point
                .strip_prefix(DATA_VOLUME)
                .filter(|rest| rest.starts_with(b"/"));
            let in_data: Option<Vec<u8>> = (below_data.is_none()
                && point.starts_with(b"/")
                && point != b"/"
                && point != DATA_VOLUME)
                .then(|| [DATA_VOLUME, point].concat());
            let alias: Option<&[u8]> = below_data.or(in_data.as_deref());
            for point in std::iter::once(point).chain(alias) {
                let point: &Path = Path::new(OsStr::from_bytes(point));
                if !point.is_absolute() || !path.starts_with(point) {
                    continue;
                }
                let length: usize = point.components().count();
                // A later mount at the same point is on top.
                if best.is_none_or(|(longest, _)| length >= longest) {
                    best = Some((length, is_local(raw)));
                }
            }
        }
        match best {
            Some((_, true)) => Locality::Local,
            Some((_, false)) => Locality::NotLocal,
            None => Locality::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::MetadataExt as _;
    use std::path::Path;

    use svalnir_core::file::DeviceNumber;

    use super::{Locality, MountTable};
    use crate::platform::volume::raw::{MOUNT_FLAG_LOCAL, RawMount};

    fn mount(point: &str, filesystem_type: &str, device: i32, flags: u32) -> RawMount {
        RawMount {
            mount_point: point.as_bytes().to_vec(),
            mounted_from: b"source".to_vec(),
            filesystem_type: filesystem_type.as_bytes().to_vec(),
            fsid: [device, 1],
            flags,
            block_size: 4_096,
            blocks: 1,
            blocks_free: 1,
            blocks_available: 1,
        }
    }

    fn table() -> MountTable {
        MountTable::from_mounts(vec![
            mount("/", "apfs", 1, MOUNT_FLAG_LOCAL),
            mount("/System/Volumes/Data", "apfs", 2, MOUNT_FLAG_LOCAL),
            mount("/System/Volumes/Data/home", "autofs", 3, 0),
            mount("/Volumes/External", "apfs", 4, MOUNT_FLAG_LOCAL),
            mount("/Volumes/Share", "smbfs", 5, 0),
            mount("/net", "autofs", 6, MOUNT_FLAG_LOCAL),
            // A network filesystem on top of a local directory.
            mount("/Volumes/External/Stack", "apfs", 7, MOUNT_FLAG_LOCAL),
            mount("/Volumes/External/Stack", "nfs", 8, 0),
        ])
    }

    #[test]
    fn the_longest_mount_point_of_the_path_text_gives_the_locality() {
        let table = table();
        let locality = |path: &str| table.path_locality(Path::new(path));
        assert_eq!(locality("/Users/me/App"), Locality::Local);
        // A local external disk stays usable.
        assert_eq!(locality("/Volumes/External/App"), Locality::Local);
        assert_eq!(locality("/Volumes/Share/App"), Locality::NotLocal);
        assert_eq!(locality("/Volumes/Share"), Locality::NotLocal);
        // A component prefix only: `/Volumes/SharePoint` is not below
        // `/Volumes/Share`.
        assert_eq!(locality("/Volumes/SharePoint/App"), Locality::Local);
        // An automounter map is not local, with each flag.
        assert_eq!(locality("/net/host/App"), Locality::NotLocal);
        assert_eq!(locality("/System/Volumes/Data/home/me"), Locality::NotLocal);
        // The firmlink path of a mount point below the data volume.
        assert_eq!(locality("/home/me/App"), Locality::NotLocal);
        // The data-volume path of a mount point below `/`.
        assert_eq!(
            locality("/System/Volumes/Data/Volumes/Share/App"),
            Locality::NotLocal
        );
        assert_eq!(
            locality("/System/Volumes/Data/net/host/App"),
            Locality::NotLocal
        );
        assert_eq!(
            locality("/System/Volumes/Data/Volumes/External/App"),
            Locality::Local
        );
        assert_eq!(locality("/System/Volumes/Data/Users/me"), Locality::Local);
        // The later mount at one point is on top.
        assert_eq!(locality("/Volumes/External/Stack/App"), Locality::NotLocal);
        assert_eq!(locality("relative/App"), Locality::Unknown);
        assert_eq!(
            MountTable::from_mounts(Vec::new()).path_locality(Path::new("/Users")),
            Locality::Unknown
        );
    }

    #[test]
    fn the_device_gives_the_locality_of_each_mount_with_its_identity() {
        let table = table();
        let locality = |device: i32| table.device_locality(DeviceNumber::new(device));
        assert_eq!(locality(2), Locality::Local);
        assert_eq!(locality(4), Locality::Local);
        assert_eq!(locality(5), Locality::NotLocal);
        assert_eq!(locality(6), Locality::NotLocal);
        assert_eq!(locality(99), Locality::Unknown);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_host_table_reports_the_temporary_directory_of_the_test_as_local() {
        let directory = tempfile::tempdir().unwrap();
        let path = fs::canonicalize(directory.path()).unwrap();
        let device: i32 = i32::try_from(fs::metadata(&path).unwrap().dev()).unwrap();
        let table = MountTable::read().unwrap();
        assert_eq!(table.path_locality(&path), Locality::Local);
        assert_eq!(
            table.device_locality(DeviceNumber::new(device)),
            Locality::Local
        );
    }
}
