//! The Trash backend.
//!
//! [`TrashBackend`] is the one operation that moves an entry to Trash. The
//! executor calls it only after the revalidation of the target, and it
//! never replaces a failed move with a permanent removal.
//!
//! [`SystemTrash`] is the supported system operation of macOS:
//! `-[NSFileManager trashItemAtURL:resultingItemURL:error:]`. That
//! operation takes a path, so the operating system resolves each component
//! of the path again. An actor that can write to a directory of the path
//! can replace a component between the revalidation and the call; the
//! system then moves the replacement to Trash. The executor cannot close
//! that interval, because the operation has no form that takes a
//! descriptor. It reduces the consequence: the move is to Trash and not a
//! removal, and after the call the executor compares the identity of the
//! moved item with the identity of the plan and reports a difference as an
//! outcome that is not established.
//!
//! A test must not use [`SystemTrash`]: the system selects the Trash
//! directory of the real user, and no parameter directs it elsewhere. The
//! tests of the executor use a backend that moves the entry to a directory
//! that the test made.

use std::fmt::Debug;

use svalnir_core::file::{FileObjectEvidence, LosslessPath};

/// One request to move an entry to Trash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrashRequest<'a> {
    /// The absolute path of the entry. The executor revalidated each
    /// component of it immediately before the request.
    pub path: &'a LosslessPath,
    /// Whether the entry is a directory.
    pub is_directory: bool,
}

/// Why a Trash backend did not move an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrashFailure {
    /// The entry was absent.
    NotFound,
    /// The backend had no permission.
    PermissionDenied,
    /// The volume is read-only.
    ReadOnlyVolume,
    /// The backend or the volume has no Trash for the entry.
    Unsupported,
    /// The backend returned this error number.
    Errno(i32),
    /// The backend failed and gave no reason that this build knows.
    Other,
}

/// The reply of a Trash backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrashReply {
    /// The backend reports that it moved the entry.
    Moved {
        /// The path of the item in Trash, when the backend gave one. The
        /// name can be different from the source name.
        item: Option<LosslessPath>,
        /// The device and the inode of the item in Trash, when the backend
        /// measured them.
        item_object: Option<FileObjectEvidence>,
    },
    /// The backend reports that it did not move the entry.
    Failed(TrashFailure),
    /// The backend gave no result. The entry was possibly moved.
    Unknown,
}

/// The operation that moves one entry to Trash.
///
/// An implementation moves exactly the entry of the request. It does not
/// remove the entry permanently, does not copy it to another location,
/// does not empty Trash, and does not move another entry.
pub trait TrashBackend: Debug + Send + Sync {
    /// Moves the entry of `request` to Trash.
    fn move_to_trash(&self, request: &TrashRequest<'_>) -> TrashReply;
}

/// The Trash of the operating system.
///
/// On macOS this is `NSFileManager`. Each other system has no supported
/// Trash operation in this build, and the reply is
/// [`TrashFailure::Unsupported`].
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemTrash;

#[cfg(target_os = "macos")]
mod system {
    use std::os::unix::fs::MetadataExt as _;
    use std::path::PathBuf;

    use objc2::rc::{Retained, autoreleasepool};
    use objc2_foundation::{
        NSError, NSFeatureUnsupportedError, NSFileManager, NSFileNoSuchFileError,
        NSFileReadNoPermissionError, NSFileReadNoSuchFileError, NSFileWriteNoPermissionError,
        NSFileWriteVolumeReadOnlyError, NSURL,
    };
    use svalnir_core::file::{DeviceNumber, FileObjectEvidence, LosslessPath};

    use super::{TrashFailure, TrashReply, TrashRequest};

    /// The value of `NSCocoaErrorDomain`. The text is compared, so this
    /// file reads no external static and has no `unsafe` block.
    const COCOA_ERROR_DOMAIN: &str = "NSCocoaErrorDomain";
    /// The value of `NSPOSIXErrorDomain`.
    const POSIX_ERROR_DOMAIN: &str = "NSPOSIXErrorDomain";

    fn failure_of(error: &NSError) -> TrashFailure {
        let domain: String = error.domain().to_string();
        let code: isize = error.code();
        if domain == COCOA_ERROR_DOMAIN {
            let absent: bool = code == NSFileNoSuchFileError || code == NSFileReadNoSuchFileError;
            let denied: bool =
                code == NSFileWriteNoPermissionError || code == NSFileReadNoPermissionError;
            return if absent {
                TrashFailure::NotFound
            } else if denied {
                TrashFailure::PermissionDenied
            } else if code == NSFileWriteVolumeReadOnlyError {
                TrashFailure::ReadOnlyVolume
            } else if code == NSFeatureUnsupportedError {
                TrashFailure::Unsupported
            } else {
                TrashFailure::Other
            };
        }
        if domain == POSIX_ERROR_DOMAIN {
            return i32::try_from(code).map_or(TrashFailure::Other, TrashFailure::Errno);
        }
        TrashFailure::Other
    }

    /// Measures the item in Trash without following a symbolic link.
    fn object_of(path: &PathBuf) -> Option<FileObjectEvidence> {
        let metadata = std::fs::symlink_metadata(path).ok()?;
        let device: i32 = i32::try_from(metadata.dev()).ok()?;
        Some(FileObjectEvidence {
            device: DeviceNumber::new(device),
            inode: metadata.ino().into(),
        })
    }

    pub(super) fn move_to_trash(request: &TrashRequest<'_>) -> TrashReply {
        autoreleasepool(|_| {
            // Foundation reads the path of a file URL as text. A name that
            // is not valid UTF-8 can then address another entry, so the
            // backend does not accept it.
            if request.path.as_utf8().is_none() {
                return TrashReply::Failed(TrashFailure::Unsupported);
            }
            let path: PathBuf = request.path.to_path_buf();
            // The URL has no trailing `/`, also for a directory: with a
            // trailing `/` the system follows a symbolic link in the last
            // component.
            let url: Option<Retained<NSURL>> = NSURL::from_file_path(&path);
            let Some(url) = url else {
                return TrashReply::Failed(TrashFailure::Unsupported);
            };
            let manager = NSFileManager::defaultManager();
            let mut resulting: Option<Retained<NSURL>> = None;
            match manager.trashItemAtURL_resultingItemURL_error(&url, Some(&mut resulting)) {
                Ok(()) => {
                    let item_path: Option<PathBuf> = resulting.and_then(|item| item.to_file_path());
                    let item_object: Option<FileObjectEvidence> =
                        item_path.as_ref().and_then(object_of);
                    let item: Option<LosslessPath> = item_path
                        .as_deref()
                        .and_then(|item| LosslessPath::from_path(item).ok());
                    TrashReply::Moved { item, item_object }
                }
                Err(error) => TrashReply::Failed(failure_of(&error)),
            }
        })
    }
}

impl TrashBackend for SystemTrash {
    #[cfg(target_os = "macos")]
    fn move_to_trash(&self, request: &TrashRequest<'_>) -> TrashReply {
        system::move_to_trash(request)
    }

    #[cfg(not(target_os = "macos"))]
    fn move_to_trash(&self, _request: &TrashRequest<'_>) -> TrashReply {
        TrashReply::Failed(TrashFailure::Unsupported)
    }
}
