//! The macOS adapter for the volume queries.
//!
//! This file is the only place in the volume module with `unsafe` code. Each
//! function makes one read-only native query and returns the raw values, or
//! the reason there are none.

use std::ffi::{CStr, CString, c_char, c_void};
use std::io;
use std::mem::{MaybeUninit, size_of};
use std::ptr::{self, NonNull};

use libc::{c_int, kern_return_t, mach_port_t};
use objc2::rc::{Retained, autoreleasepool};
use objc2::runtime::AnyObject;
use objc2_foundation::{
    NSArray, NSCocoaErrorDomain, NSError, NSNumber, NSString, NSURL, NSURLResourceKey,
    NSURLVolumeAvailableCapacityForImportantUsageKey,
    NSURLVolumeAvailableCapacityForOpportunisticUsageKey,
};
use svalnir_core::observation::UnavailableReason;

use super::raw::{RawApfsContainer, RawFoundationCapacity, RawMount};

/// The largest number of mounted filesystems that one enumeration reads.
const MAX_MOUNTS: usize = 4_096;
/// The spare entries of the enumeration buffer, for a mount that appears
/// between the count query and the read.
const MOUNT_HEADROOM: usize = 8;
/// The largest number of enumeration attempts when the mount table grows.
const MAX_ENUMERATION_ATTEMPTS: usize = 3;
/// The largest number of parent steps from a volume or snapshot entry to its
/// container in the I/O Registry. A snapshot is two steps from its container.
const MAX_REGISTRY_PARENT_STEPS: usize = 4;
/// The length of an `io_name_t`.
const IO_NAME_LENGTH: usize = 128;

/// `NSFileNoSuchFileError`.
const NS_FILE_NO_SUCH_FILE: isize = 4;
/// `NSFileReadNoPermissionError`.
const NS_FILE_READ_NO_PERMISSION: isize = 257;
/// `NSFileReadNoSuchFileError`.
const NS_FILE_READ_NO_SUCH_FILE: isize = 260;

// `fsid_t` is two 32-bit words (`sys/mount.h`).
const _: () = assert!(size_of::<libc::fsid_t>() == size_of::<[i32; 2]>());

/// An I/O Registry object handle (`io_object_t`).
type IoObject = mach_port_t;

#[link(name = "IOKit", kind = "framework")]
unsafe extern "C" {
    /// Makes a matching dictionary for the `IOMedia` object with a BSD name.
    /// Returns a dictionary that the caller owns, or null.
    fn IOBSDNameMatching(
        main_port: mach_port_t,
        options: u32,
        bsd_name: *const c_char,
    ) -> *mut c_void;

    /// Returns the first object that matches. Consumes one reference to
    /// `matching`. Returns zero when no object matches.
    fn IOServiceGetMatchingService(main_port: mach_port_t, matching: *mut c_void) -> IoObject;

    /// Writes the parent of `entry` in `plane` to `parent`.
    fn IORegistryEntryGetParentEntry(
        entry: IoObject,
        plane: *const c_char,
        parent: *mut IoObject,
    ) -> kern_return_t;

    /// Whether `object` is of the class `class_name` or of a subclass.
    fn IOObjectConformsTo(object: IoObject, class_name: *const c_char) -> libc::boolean_t;

    /// Returns a copy of one property that the caller owns, or null.
    fn IORegistryEntryCreateCFProperty(
        entry: IoObject,
        key: *const c_void,
        allocator: *const c_void,
        options: u32,
    ) -> *mut c_void;

    /// Writes the registry entry ID of `entry` to `entry_id`.
    fn IORegistryEntryGetRegistryEntryID(entry: IoObject, entry_id: *mut u64) -> kern_return_t;

    /// Releases one reference to an I/O Registry object handle.
    fn IOObjectRelease(object: IoObject) -> kern_return_t;
}

/// Maps the `errno` of a failed path query to a stable reason.
fn reason_from_errno(error: &io::Error) -> UnavailableReason {
    match error.raw_os_error() {
        Some(libc::EPERM | libc::EACCES) => UnavailableReason::PermissionDenied,
        Some(libc::ENOENT | libc::ENOTDIR) => UnavailableReason::ResourceGone,
        Some(libc::ENOTSUP | libc::EINVAL) => UnavailableReason::Unsupported,
        // The path is not valid for this query. Another attempt with the same
        // path fails in the same way, so the failure is not transient.
        Some(libc::ENAMETOOLONG | libc::ELOOP) => UnavailableReason::InconsistentData,
        _ => UnavailableReason::TransientFailure,
    }
}

/// The bytes of a fixed C character array before its terminator.
fn bytes_until_nul(characters: &[c_char]) -> Vec<u8> {
    characters
        .iter()
        .take_while(|character| **character != 0)
        .map(|character| character.to_ne_bytes()[0])
        .collect()
}

fn zeroed_statfs() -> libc::statfs {
    // SAFETY: the structure has only integers and integer arrays, and each
    // bit pattern, zero included, is a valid value of it.
    unsafe { MaybeUninit::<libc::statfs>::zeroed().assume_init() }
}

fn raw_mount(native: &libc::statfs) -> RawMount {
    // SAFETY: `fsid_t` is a `repr(C)` structure of one `[i32; 2]` field. A
    // constant assertion shows that the two types have the same size, and
    // each bit pattern is valid for the target type.
    let fsid: [i32; 2] = unsafe { std::mem::transmute::<libc::fsid_t, [i32; 2]>(native.f_fsid) };
    RawMount {
        mount_point: bytes_until_nul(&native.f_mntonname),
        mounted_from: bytes_until_nul(&native.f_mntfromname),
        filesystem_type: bytes_until_nul(&native.f_fstypename),
        fsid,
        flags: native.f_flags,
        block_size: native.f_bsize,
        blocks: native.f_blocks,
        blocks_free: native.f_bfree,
        blocks_available: native.f_bavail,
    }
}

/// `getfsstat` with `MNT_NOWAIT`: the mounted filesystems of the host.
///
/// The query does not wait for a filesystem that does not answer, so the
/// capacity fields can be a cached value. Use [`filesystem_at`] for a
/// capacity measurement.
pub(super) fn mounted_filesystems() -> Result<Vec<RawMount>, UnavailableReason> {
    for _ in 0..MAX_ENUMERATION_ATTEMPTS {
        // SAFETY: a null buffer with a size of zero asks only for the number
        // of mounted filesystems.
        let reported: c_int = unsafe { libc::getfsstat(ptr::null_mut(), 0, libc::MNT_NOWAIT) };
        if reported < 0 {
            return Err(reason_from_errno(&io::Error::last_os_error()));
        }
        let reported: usize = usize::try_from(reported).map_err(|_| UnavailableReason::Overflow)?;
        let capacity: usize = reported.saturating_add(MOUNT_HEADROOM).min(MAX_MOUNTS);
        let mut buffer: Vec<libc::statfs> = vec![zeroed_statfs(); capacity];
        let byte_size: c_int = capacity
            .checked_mul(size_of::<libc::statfs>())
            .and_then(|bytes| c_int::try_from(bytes).ok())
            .ok_or(UnavailableReason::Overflow)?;
        // SAFETY: `buffer` is writable for `byte_size` bytes, which is the
        // size of its `capacity` initialized entries. The kernel writes no
        // more than that and returns the number of entries that it wrote.
        let written: c_int =
            unsafe { libc::getfsstat(buffer.as_mut_ptr(), byte_size, libc::MNT_NOWAIT) };
        if written < 0 {
            return Err(reason_from_errno(&io::Error::last_os_error()));
        }
        let written: usize = usize::try_from(written).map_err(|_| UnavailableReason::Overflow)?;
        if written > capacity {
            return Err(UnavailableReason::InconsistentData);
        }
        if written == capacity && capacity < MAX_MOUNTS {
            // The buffer is full: the mount table can have more entries.
            continue;
        }
        if written == capacity {
            // More than `MAX_MOUNTS` filesystems: the list is not complete.
            return Err(UnavailableReason::Overflow);
        }
        return Ok(buffer.iter().take(written).map(raw_mount).collect());
    }
    Err(UnavailableReason::TransientFailure)
}

/// `statfs`: the filesystem that contains `path`, with current capacity.
pub(super) fn filesystem_at(path: &[u8]) -> Result<RawMount, UnavailableReason> {
    let path: CString = CString::new(path).map_err(|_| UnavailableReason::InconsistentData)?;
    let mut native: libc::statfs = zeroed_statfs();
    // SAFETY: `path` is a NUL-terminated string. `native` is writable for
    // one `statfs` structure.
    let status: c_int = unsafe { libc::statfs(path.as_ptr(), &raw mut native) };
    if status != 0 {
        return Err(reason_from_errno(&io::Error::last_os_error()));
    }
    Ok(raw_mount(&native))
}

/// The result buffer of `getattrlist` for `ATTR_CMN_FSID` and
/// `ATTR_VOL_UUID`. The kernel writes the length word first, then the common
/// attributes in bit order, then the volume attributes. The structure has no
/// padding: each field has an alignment of at most four bytes.
#[repr(C)]
struct VolumeUuidAttributes {
    length: u32,
    fsid: [i32; 2],
    uuid: [u8; 16],
}

const _: () = assert!(size_of::<VolumeUuidAttributes>() == 28);

/// `getattrlist` with `ATTR_CMN_FSID` and `ATTR_VOL_UUID`: the UUID of the
/// volume that is mounted at `mount_point`.
///
/// The query asks for the `fsid` of the object in the same call. A result
/// whose `fsid` is not `expected_fsid` is another mount that took the path
/// after the enumeration, and gives `IdentityChanged`, not a UUID.
///
/// Returns `Ok(None)` when the filesystem has no UUID (`ENOTSUP`, or a zero
/// UUID). A failed query is an error with its reason.
///
/// # Errors
///
/// Returns the reason of a failed query, of a result of an unexpected size,
/// or of an `fsid` that is not the expected one.
pub(super) fn volume_uuid(
    mount_point: &[u8],
    expected_fsid: [i32; 2],
) -> Result<Option<[u8; 16]>, UnavailableReason> {
    let path: CString =
        CString::new(mount_point).map_err(|_| UnavailableReason::InconsistentData)?;
    let mut request = libc::attrlist {
        bitmapcount: libc::ATTR_BIT_MAP_COUNT,
        reserved: 0,
        commonattr: libc::ATTR_CMN_FSID,
        volattr: libc::ATTR_VOL_INFO | libc::ATTR_VOL_UUID,
        dirattr: 0,
        fileattr: 0,
        forkattr: 0,
    };
    let mut attributes = VolumeUuidAttributes {
        length: 0,
        fsid: [0; 2],
        uuid: [0; 16],
    };
    // SAFETY: `path` is a NUL-terminated string. `request` is a valid
    // attribute list that asks for fixed-size attributes only. `attributes`
    // is writable for its size, and the kernel writes no more than that
    // size. `FSOPT_NOFOLLOW` keeps a symbolic link at the path from
    // redirecting the query.
    let status: c_int = unsafe {
        libc::getattrlist(
            path.as_ptr(),
            (&raw mut request).cast::<c_void>(),
            (&raw mut attributes).cast::<c_void>(),
            size_of::<VolumeUuidAttributes>(),
            libc::FSOPT_NOFOLLOW,
        )
    };
    if status != 0 {
        let error: io::Error = io::Error::last_os_error();
        return if error.raw_os_error() == Some(libc::ENOTSUP) {
            Ok(None)
        } else {
            Err(reason_from_errno(&error))
        };
    }
    let complete: bool = usize::try_from(attributes.length)
        .is_ok_and(|length| length == size_of::<VolumeUuidAttributes>());
    if !complete {
        return Err(UnavailableReason::InconsistentData);
    }
    if attributes.fsid != expected_fsid {
        return Err(UnavailableReason::IdentityChanged);
    }
    Ok((attributes.uuid != [0; 16]).then_some(attributes.uuid))
}

/// An I/O Registry object handle that is released on drop.
struct RegistryEntry(IoObject);

impl Drop for RegistryEntry {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a handle that this process owns with one
        // reference, and this is its only release.
        let status: kern_return_t = unsafe { IOObjectRelease(self.0) };
        // A failure leaves one handle reference. There is no recovery.
        let _: kern_return_t = status;
    }
}

/// A NUL-padded `io_name_t` with `name`. Returns `None` when the name does
/// not fit with its terminator.
fn io_name(name: &[u8]) -> Option<[c_char; IO_NAME_LENGTH]> {
    if name.len() >= IO_NAME_LENGTH || name.contains(&0) {
        return None;
    }
    let mut buffer: [c_char; IO_NAME_LENGTH] = [0; IO_NAME_LENGTH];
    for (target, byte) in buffer.iter_mut().zip(name) {
        *target = c_char::from_ne_bytes([*byte]);
    }
    Some(buffer)
}

impl RegistryEntry {
    /// The `IOMedia` object with the BSD name `bsd_name`, for example
    /// `disk3s5`.
    fn media_with_bsd_name(bsd_name: &CStr) -> Result<Self, UnavailableReason> {
        // SAFETY: a main port of zero is the default main port. `bsd_name`
        // is a NUL-terminated string that the call copies.
        let matching: *mut c_void = unsafe { IOBSDNameMatching(0, 0, bsd_name.as_ptr()) };
        if matching.is_null() {
            return Err(UnavailableReason::TransientFailure);
        }
        // SAFETY: `matching` is a dictionary that this function owns. The
        // call consumes that reference, so there is no later release.
        let entry: IoObject = unsafe { IOServiceGetMatchingService(0, matching) };
        if entry == 0 {
            return Err(UnavailableReason::ResourceGone);
        }
        Ok(Self(entry))
    }

    fn conforms_to(&self, class_name: &[c_char; IO_NAME_LENGTH]) -> bool {
        // SAFETY: `self.0` is a live handle. `class_name` is a NUL-padded
        // `io_name_t` that the call reads.
        let conforms: libc::boolean_t = unsafe { IOObjectConformsTo(self.0, class_name.as_ptr()) };
        conforms != 0
    }

    fn parent(&self, plane: &[c_char; IO_NAME_LENGTH]) -> Result<Self, UnavailableReason> {
        let mut parent: IoObject = 0;
        // SAFETY: `self.0` is a live handle. `plane` is a NUL-padded
        // `io_name_t`. `parent` is writable; on success it gets a handle
        // that this function owns.
        let status: kern_return_t =
            unsafe { IORegistryEntryGetParentEntry(self.0, plane.as_ptr(), &raw mut parent) };
        if status != libc::KERN_SUCCESS || parent == 0 {
            return Err(UnavailableReason::InconsistentData);
        }
        Ok(Self(parent))
    }

    /// The registry entry ID: a number that is unique in one boot.
    fn registry_entry_id(&self) -> Result<u64, UnavailableReason> {
        let mut entry_id: u64 = 0;
        // SAFETY: `self.0` is a live handle. `entry_id` is writable.
        let status: kern_return_t =
            unsafe { IORegistryEntryGetRegistryEntryID(self.0, &raw mut entry_id) };
        if status != libc::KERN_SUCCESS {
            return Err(UnavailableReason::InconsistentData);
        }
        Ok(entry_id)
    }

    /// The text of a string property. Returns `None` when the entry has no
    /// such property or the property is not a string.
    fn string_property(&self, key: &str) -> Option<String> {
        let key: Retained<NSString> = NSString::from_str(key);
        // SAFETY: `self.0` is a live handle. An `NSString` is toll-free
        // bridged to `CFString`, and `key` lives for the call. A null
        // allocator is the default allocator.
        let value: *mut c_void = unsafe {
            IORegistryEntryCreateCFProperty(
                self.0,
                Retained::as_ptr(&key).cast::<c_void>(),
                ptr::null(),
                0,
            )
        };
        // SAFETY: a non-null result is a Core Foundation object that the
        // caller owns with one reference. Each Core Foundation object is an
        // Objective-C object, and `Retained` takes over that one reference.
        let value: Retained<AnyObject> = unsafe { Retained::from_raw(value.cast::<AnyObject>()) }?;
        let text: Retained<NSString> = value.downcast::<NSString>().ok()?;
        Some(text.to_string())
    }
}

/// The APFS container of the device with the BSD name `bsd_name`, from the
/// I/O Registry.
///
/// The lookup finds the `IOMedia` object of the device, goes up the service
/// plane to the first `AppleAPFSContainer` object, and reads its `UUID`
/// property and its registry entry ID. The result is `unsupported` when the
/// device has no APFS container above it.
pub(super) fn apfs_container(bsd_name: &[u8]) -> Result<RawApfsContainer, UnavailableReason> {
    let bsd_name: CString =
        CString::new(bsd_name).map_err(|_| UnavailableReason::InconsistentData)?;
    let container_class: [c_char; IO_NAME_LENGTH] =
        io_name(b"AppleAPFSContainer").ok_or(UnavailableReason::InconsistentData)?;
    let service_plane: [c_char; IO_NAME_LENGTH] =
        io_name(b"IOService").ok_or(UnavailableReason::InconsistentData)?;

    autoreleasepool(|_| {
        let mut entry: RegistryEntry = RegistryEntry::media_with_bsd_name(&bsd_name)?;
        for step in 0..=MAX_REGISTRY_PARENT_STEPS {
            if entry.conforms_to(&container_class) {
                return Ok(RawApfsContainer {
                    uuid: entry
                        .string_property("UUID")
                        .ok_or(UnavailableReason::InconsistentData)?,
                    registry_entry_id: entry.registry_entry_id()?,
                });
            }
            if step == MAX_REGISTRY_PARENT_STEPS {
                // The last entry was checked. A parent call now would be
                // unused, and its failure would hide `Unsupported`.
                break;
            }
            entry = entry.parent(&service_plane)?;
        }
        Err(UnavailableReason::Unsupported)
    })
}

fn reason_from_foundation_error(error: &NSError) -> UnavailableReason {
    // SAFETY: Foundation initializes the constant before any code of this
    // process runs, and does not change it.
    let cocoa_domain: &NSString = unsafe { NSCocoaErrorDomain };
    if *error.domain() != *cocoa_domain {
        // The Cocoa codes do not apply to an error of another domain.
        return UnavailableReason::TransientFailure;
    }
    match error.code() {
        NS_FILE_READ_NO_PERMISSION => UnavailableReason::PermissionDenied,
        NS_FILE_NO_SUCH_FILE | NS_FILE_READ_NO_SUCH_FILE => UnavailableReason::ResourceGone,
        _ => UnavailableReason::TransientFailure,
    }
}

/// The Foundation capacity values of the volume that contains `path`.
///
/// # Errors
///
/// Returns a reason when the resource query itself fails. A value that the
/// volume does not give is a reason in the returned structure.
pub(super) fn foundation_capacity(path: &[u8]) -> Result<RawFoundationCapacity, UnavailableReason> {
    let path: CString = CString::new(path).map_err(|_| UnavailableReason::InconsistentData)?;
    let path_pointer: NonNull<c_char> =
        NonNull::new(path.as_ptr().cast_mut()).ok_or(UnavailableReason::InconsistentData)?;

    autoreleasepool(|_| {
        // SAFETY: `path_pointer` is a NUL-terminated file-system
        // representation that lives for the call. The method copies it and
        // does not write through the pointer.
        let url: Retained<NSURL> = unsafe {
            NSURL::fileURLWithFileSystemRepresentation_isDirectory_relativeToURL(
                path_pointer,
                true,
                None,
            )
        };
        // SAFETY: Foundation initializes the constant before any code of
        // this process runs, and does not change it.
        let important_key: &NSURLResourceKey =
            unsafe { NSURLVolumeAvailableCapacityForImportantUsageKey };
        // SAFETY: as for the important-usage key.
        let opportunistic_key: &NSURLResourceKey =
            unsafe { NSURLVolumeAvailableCapacityForOpportunisticUsageKey };
        let keys: Retained<NSArray<NSURLResourceKey>> =
            NSArray::from_slice(&[important_key, opportunistic_key]);
        let values = url
            .resourceValuesForKeys_error(&keys)
            .map_err(|error| reason_from_foundation_error(&error))?;
        let read = |key: &NSURLResourceKey| -> Result<u64, UnavailableReason> {
            // An absent key: the volume does not support the value.
            let value: Retained<AnyObject> = values
                .objectForKey(key)
                .ok_or(UnavailableReason::Unsupported)?;
            let number: Retained<NSNumber> = value
                .downcast::<NSNumber>()
                .map_err(|_| UnavailableReason::InconsistentData)?;
            // A negative capacity is not a measurement.
            u64::try_from(number.longLongValue()).map_err(|_| UnavailableReason::InconsistentData)
        };
        Ok(RawFoundationCapacity {
            important: read(important_key),
            opportunistic: read(opportunistic_key),
        })
    })
}
