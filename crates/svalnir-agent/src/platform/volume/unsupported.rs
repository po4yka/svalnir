//! The adapter for a host that is not macOS.
//!
//! Each query reports that the source does not support the metric. The
//! functions have the signatures of `native.rs`.

use svalnir_core::observation::UnavailableReason;

use super::raw::{RawApfsContainer, RawFoundationCapacity, RawMount};

pub(super) fn mounted_filesystems() -> Result<Vec<RawMount>, UnavailableReason> {
    Err(UnavailableReason::Unsupported)
}

pub(super) fn filesystem_at(_path: &[u8]) -> Result<RawMount, UnavailableReason> {
    Err(UnavailableReason::Unsupported)
}

pub(super) fn volume_uuid(_mount_point: &[u8]) -> Option<[u8; 16]> {
    None
}

pub(super) fn apfs_container(_bsd_name: &[u8]) -> Result<RawApfsContainer, UnavailableReason> {
    Err(UnavailableReason::Unsupported)
}

pub(super) fn foundation_capacity(
    _path: &[u8],
) -> Result<RawFoundationCapacity, UnavailableReason> {
    Err(UnavailableReason::Unsupported)
}
