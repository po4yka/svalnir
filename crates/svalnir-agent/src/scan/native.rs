//! The native calls of the scanner.
//!
//! Each `unsafe` block of the scanner is in this file. The scanner opens the
//! root one time by its path. It opens each other directory with `openat`
//! relative to the open parent directory, with `O_NOFOLLOW` and
//! `O_DIRECTORY`, and it measures each entry with `fstatat` and
//! `AT_SYMLINK_NOFOLLOW`. No call below the root resolves a path of more
//! than one component, so a replaced path component cannot redirect the
//! scan.

use std::ffi::CStr;
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd as _, BorrowedFd, FromRawFd as _, IntoRawFd as _, OwnedFd, RawFd};
use std::ptr::NonNull;

use svalnir_core::file::DeviceNumber;

use super::model::EntryKind;

/// Reads the soft limit of open descriptors of the process
/// (`RLIMIT_NOFILE`). Returns `None` when the call fails.
pub(super) fn soft_descriptor_limit() -> Option<u64> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a valid `rlimit` structure for a write, and the
    // call keeps no pointer after it returns.
    let status: libc::c_int = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut limit) };
    (status == 0).then_some(limit.rlim_cur)
}

/// The `stat` fields that the scanner uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct RawMetadata {
    /// The kind, from `st_mode`.
    pub(super) kind: EntryKind,
    /// `st_size`. The value can be negative; the caller validates it.
    pub(super) size: i64,
    /// `st_blocks`, in units of 512 bytes. The value can be negative; the
    /// caller validates it.
    pub(super) blocks: i64,
    /// `st_nlink`.
    pub(super) link_count: u64,
    /// `st_dev`. `None` when the number does not fit the device-number
    /// type.
    pub(super) device: Option<DeviceNumber>,
    /// `st_ino`.
    pub(super) inode: u64,
    /// Whether the object is a dataless placeholder (`SF_DATALESS`).
    pub(super) dataless: bool,
    /// Whether the file is compressed by the filesystem (`UF_COMPRESSED`).
    pub(super) compressed: bool,
    /// `st_uid`.
    pub(super) owner: u32,
    /// `st_mtime` and `st_mtime_nsec`. The caller validates the values.
    pub(super) modified: (i64, i64),
    /// `st_ctime` and `st_ctime_nsec`. The caller validates the values.
    pub(super) changed: (i64, i64),
}

/// `SF_DATALESS` of `<sys/stat.h>` in the macOS SDK. The `libc` crate does
/// not have this constant.
#[cfg(target_os = "macos")]
const SF_DATALESS: u32 = 0x4000_0000;

#[cfg(target_os = "macos")]
fn link_count(stat: &libc::stat) -> u64 {
    u64::from(stat.st_nlink)
}

#[cfg(not(target_os = "macos"))]
fn link_count(stat: &libc::stat) -> u64 {
    u64::try_from(stat.st_nlink).unwrap_or(u64::MAX)
}

#[cfg(target_os = "macos")]
fn file_flags(stat: &libc::stat) -> (bool, bool) {
    (
        stat.st_flags & SF_DATALESS != 0,
        stat.st_flags & libc::UF_COMPRESSED != 0,
    )
}

#[cfg(not(target_os = "macos"))]
fn file_flags(_stat: &libc::stat) -> (bool, bool) {
    (false, false)
}

fn metadata_from(stat: &libc::stat) -> RawMetadata {
    let kind: EntryKind = match stat.st_mode & libc::S_IFMT {
        libc::S_IFREG => EntryKind::File,
        libc::S_IFDIR => EntryKind::Directory,
        libc::S_IFLNK => EntryKind::Symlink,
        _ => EntryKind::Other,
    };
    let (dataless, compressed) = file_flags(stat);
    // `dev_t` is the 32-bit type of the device number on macOS.
    #[cfg(target_os = "macos")]
    let device: Option<DeviceNumber> = Some(DeviceNumber::new(stat.st_dev));
    #[cfg(not(target_os = "macos"))]
    let device: Option<DeviceNumber> = i32::try_from(stat.st_dev).ok().map(DeviceNumber::new);
    RawMetadata {
        kind,
        size: stat.st_size,
        blocks: stat.st_blocks,
        link_count: link_count(stat),
        device,
        inode: stat.st_ino,
        dataless,
        compressed,
        owner: stat.st_uid,
        modified: (stat.st_mtime, stat.st_mtime_nsec),
        changed: (stat.st_ctime, stat.st_ctime_nsec),
    }
}

const DIRECTORY_FLAGS: libc::c_int = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC;

fn owned_descriptor(descriptor: libc::c_int) -> io::Result<OwnedFd> {
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `descriptor` is not negative, so the `open` or `openat` call
    // that returned it succeeded. The descriptor is open and no other owner
    // has it.
    Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
}

/// Opens the root directory by its path. The operating system resolves the
/// path, which includes a symbolic link in it.
pub(super) fn open_root(path: &CStr) -> io::Result<OwnedFd> {
    // SAFETY: `path` is a NUL-terminated string that lives for the call.
    // The flags have no `O_CREAT`, so the call needs no mode argument.
    let descriptor: libc::c_int = unsafe { libc::open(path.as_ptr(), DIRECTORY_FLAGS) };
    owned_descriptor(descriptor)
}

/// Opens the directory `name` in the open directory `parent`. The call
/// fails when `name` is a symbolic link or is not a directory.
pub(super) fn open_child(parent: BorrowedFd<'_>, name: &CStr) -> io::Result<OwnedFd> {
    // SAFETY: `parent` is an open descriptor for the call, and `name` is a
    // NUL-terminated string that lives for the call. The flags have no
    // `O_CREAT`, so the call needs no mode argument.
    let descriptor: libc::c_int = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            DIRECTORY_FLAGS | libc::O_NOFOLLOW,
        )
    };
    owned_descriptor(descriptor)
}

fn metadata_after(status: libc::c_int, buffer: MaybeUninit<libc::stat>) -> io::Result<RawMetadata> {
    if status != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the buffer was made with `zeroed`, and each field of `stat`
    // is an integer, for which zero is a valid value. The successful call
    // then wrote the structure.
    let stat: libc::stat = unsafe { buffer.assume_init() };
    Ok(metadata_from(&stat))
}

/// Measures the open object `descriptor` with `fstat`.
pub(super) fn stat_descriptor(descriptor: BorrowedFd<'_>) -> io::Result<RawMetadata> {
    let mut buffer: MaybeUninit<libc::stat> = MaybeUninit::zeroed();
    // SAFETY: `descriptor` is open for the call, and `buffer` is valid for
    // a write of one `stat` structure.
    let status: libc::c_int = unsafe { libc::fstat(descriptor.as_raw_fd(), buffer.as_mut_ptr()) };
    metadata_after(status, buffer)
}

/// Measures the entry `name` of the open directory `parent`. The call does
/// not follow a symbolic link.
pub(super) fn stat_child(parent: BorrowedFd<'_>, name: &CStr) -> io::Result<RawMetadata> {
    let mut buffer: MaybeUninit<libc::stat> = MaybeUninit::zeroed();
    // SAFETY: `parent` is open for the call, `name` is a NUL-terminated
    // string that lives for the call, and `buffer` is valid for a write of
    // one `stat` structure.
    let status: libc::c_int = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            buffer.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    metadata_after(status, buffer)
}

/// The filesystem type name and the mount point of an open object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct FilesystemEvidence {
    /// `f_fstypename`.
    pub(super) type_name: Vec<u8>,
    /// `f_mntonname`.
    pub(super) mount_point: Vec<u8>,
}

#[cfg(target_os = "macos")]
fn text_field(field: &[libc::c_char]) -> Vec<u8> {
    field
        .iter()
        .take_while(|character| **character != 0)
        .map(|character| u8::from_ne_bytes(character.to_ne_bytes()))
        .collect()
}

/// Reads the filesystem evidence of the open object `descriptor` with
/// `fstatfs`.
#[cfg(target_os = "macos")]
pub(super) fn filesystem_evidence(descriptor: BorrowedFd<'_>) -> io::Result<FilesystemEvidence> {
    let mut buffer: MaybeUninit<libc::statfs> = MaybeUninit::zeroed();
    // SAFETY: `descriptor` is open for the call, and `buffer` is valid for
    // a write of one `statfs` structure.
    let status: libc::c_int = unsafe { libc::fstatfs(descriptor.as_raw_fd(), buffer.as_mut_ptr()) };
    if status != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the buffer was made with `zeroed`, and each field of `statfs`
    // is an integer or an array of integers, for which zero is a valid
    // value. The successful call then wrote the structure.
    let filled: libc::statfs = unsafe { buffer.assume_init() };
    Ok(FilesystemEvidence {
        type_name: text_field(&filled.f_fstypename),
        mount_point: text_field(&filled.f_mntonname),
    })
}

/// This system has no filesystem type name and mount point in `statfs`.
#[cfg(not(target_os = "macos"))]
pub(super) fn filesystem_evidence(_descriptor: BorrowedFd<'_>) -> io::Result<FilesystemEvidence> {
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

fn clear_errno() {
    // SAFETY: the call has no precondition. It returns the address of the
    // `errno` of the calling thread.
    #[cfg(target_os = "macos")]
    let location: *mut libc::c_int = unsafe { libc::__error() };
    // SAFETY: the call has no precondition. It returns the address of the
    // `errno` of the calling thread.
    #[cfg(not(target_os = "macos"))]
    let location: *mut libc::c_int = unsafe { libc::__errno_location() };
    // SAFETY: `location` is the address of the `errno` of this thread. It
    // is valid for a write while the thread runs, and no reference to it
    // exists.
    unsafe { *location = 0 };
}

/// An open directory stream. The stream owns its file descriptor.
#[derive(Debug)]
pub(super) struct DirStream {
    /// The stream from `fdopendir`. `closedir` in `Drop` releases it.
    stream: NonNull<libc::DIR>,
    /// The descriptor that `fdopendir` received. The stream owns it.
    descriptor: RawFd,
}

impl DirStream {
    /// Makes a stream from an open directory. The stream takes the
    /// descriptor.
    pub(super) fn from_descriptor(descriptor: OwnedFd) -> io::Result<Self> {
        let raw: RawFd = descriptor.into_raw_fd();
        // SAFETY: `raw` is an open descriptor that this function owns. On
        // success the stream owns it.
        let stream: *mut libc::DIR = unsafe { libc::fdopendir(raw) };
        if let Some(stream) = NonNull::new(stream) {
            return Ok(Self {
                stream,
                descriptor: raw,
            });
        }
        let error: io::Error = io::Error::last_os_error();
        // SAFETY: `fdopendir` failed, so it did not take `raw`. The
        // descriptor is open and this function is its only owner.
        drop(unsafe { OwnedFd::from_raw_fd(raw) });
        Err(error)
    }

    /// The descriptor of the directory, for `openat` and `fstatat`.
    pub(super) fn descriptor(&self) -> BorrowedFd<'_> {
        // SAFETY: the stream owns `descriptor` and closes it only in
        // `Drop`. The borrow cannot outlive `self`.
        unsafe { BorrowedFd::borrow_raw(self.descriptor) }
    }

    /// Reads the next name into `name`, with its NUL terminator. The names
    /// `.` and `..` are not given. Returns `false` at the end of the
    /// directory.
    pub(super) fn next_name(&mut self, name: &mut Vec<u8>) -> io::Result<bool> {
        loop {
            // `readdir` returns a null pointer at the end and on an error.
            // Only `errno` tells the two apart.
            clear_errno();
            // SAFETY: `stream` is an open stream that only `self` uses, and
            // `&mut self` excludes a second call at the same time.
            let entry: *mut libc::dirent = unsafe { libc::readdir(self.stream.as_ptr()) };
            let Some(entry) = NonNull::new(entry) else {
                let error: io::Error = io::Error::last_os_error();
                return match error.raw_os_error() {
                    None | Some(0) => Ok(false),
                    Some(_) => Err(error),
                };
            };
            // SAFETY: `entry` is a `dirent` record of the stream. The
            // expression takes the address of its name field and makes no
            // reference, because the record can be shorter than the
            // declared structure.
            let name_field: *const libc::c_char =
                unsafe { (&raw const (*entry.as_ptr()).d_name).cast() };
            // SAFETY: the operating system ends `d_name` with a NUL byte in
            // the record. The record is valid until the next `readdir` or
            // `closedir` on the stream, and neither occurs while `text` is
            // in use.
            let text: &CStr = unsafe { CStr::from_ptr(name_field) };
            let bytes: &[u8] = text.to_bytes();
            if bytes == b"." || bytes == b".." {
                continue;
            }
            name.clear();
            name.extend_from_slice(text.to_bytes_with_nul());
            return Ok(true);
        }
    }
}

impl Drop for DirStream {
    fn drop(&mut self) {
        // SAFETY: `stream` is an open stream from `fdopendir`, and this is
        // the only `closedir` call for it. The call also closes the
        // descriptor. A failure leaves nothing to release.
        let _status: libc::c_int = unsafe { libc::closedir(self.stream.as_ptr()) };
    }
}

/// `IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES` of `<sys/resource.h>`.
#[cfg(target_os = "macos")]
const IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES: libc::c_int = 3;
/// `IOPOL_SCOPE_THREAD` of `<sys/resource.h>`.
#[cfg(target_os = "macos")]
const IOPOL_SCOPE_THREAD: libc::c_int = 1;
/// `IOPOL_MATERIALIZE_DATALESS_FILES_OFF` of `<sys/resource.h>`.
#[cfg(target_os = "macos")]
const IOPOL_MATERIALIZE_DATALESS_FILES_OFF: libc::c_int = 1;

// The `libc` crate does not declare these two functions of
// `<sys/resource.h>` in the macOS SDK:
// `int getiopolicy_np(int iotype, int scope)` and
// `int setiopolicy_np(int iotype, int scope, int policy)`.
#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn getiopolicy_np(iotype: libc::c_int, scope: libc::c_int) -> libc::c_int;
    fn setiopolicy_np(iotype: libc::c_int, scope: libc::c_int, policy: libc::c_int) -> libc::c_int;
}

/// Sets the calling thread to not materialize dataless objects, and puts
/// the earlier policy back in `Drop`.
///
/// While the guard lives, a call of this thread that needs the content of a
/// cloud placeholder fails with `EDEADLK` and starts no download. The
/// scanner also examines `SF_DATALESS` before it opens a directory; the
/// guard closes the interval between that measurement and the open.
///
/// The guard is not `Send`: the policy belongs to the thread that made it.
#[derive(Debug)]
pub(super) struct MaterializationOff {
    /// The policy to put back. `None` when the policy was not changed.
    #[cfg(target_os = "macos")]
    earlier: Option<libc::c_int>,
    not_send: std::marker::PhantomData<*const ()>,
}

impl MaterializationOff {
    /// Changes the policy of the calling thread. When the system refuses
    /// the change, the guard does nothing and the scan continues with the
    /// `SF_DATALESS` examination only.
    #[cfg(target_os = "macos")]
    pub(super) fn for_this_thread() -> Self {
        // SAFETY: the call takes integers only and reads the policy of the
        // calling thread. It returns -1 on failure.
        let earlier: libc::c_int = unsafe {
            getiopolicy_np(
                IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES,
                IOPOL_SCOPE_THREAD,
            )
        };
        let changed: bool = earlier >= 0 && {
            // SAFETY: the call takes integers only and changes the policy
            // of the calling thread. It returns 0 on success.
            let status: libc::c_int = unsafe {
                setiopolicy_np(
                    IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES,
                    IOPOL_SCOPE_THREAD,
                    IOPOL_MATERIALIZE_DATALESS_FILES_OFF,
                )
            };
            status == 0
        };
        Self {
            earlier: changed.then_some(earlier),
            not_send: std::marker::PhantomData,
        }
    }

    /// This system has no such policy.
    #[cfg(not(target_os = "macos"))]
    pub(super) fn for_this_thread() -> Self {
        Self {
            not_send: std::marker::PhantomData,
        }
    }
}

impl Drop for MaterializationOff {
    fn drop(&mut self) {
        #[cfg(target_os = "macos")]
        if let Some(earlier) = self.earlier {
            // SAFETY: the call takes integers only and puts back the policy
            // that `getiopolicy_np` gave for this thread. The guard is not
            // `Send`, so this is the thread that made it. A failure leaves
            // the stricter policy, which loses no data.
            let _status: libc::c_int = unsafe {
                setiopolicy_np(
                    IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES,
                    IOPOL_SCOPE_THREAD,
                    earlier,
                )
            };
        }
    }
}

/// The dataless-materialization policy of the calling thread, for a test.
#[cfg(all(test, target_os = "macos"))]
pub(super) fn materialization_policy_of_this_thread() -> libc::c_int {
    // SAFETY: the call takes integers only and reads the policy of the
    // calling thread.
    unsafe {
        getiopolicy_np(
            IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES,
            IOPOL_SCOPE_THREAD,
        )
    }
}

/// The private-size attributes of one regular file, from `getattrlistat`.
///
/// Each field is `None` when the volume did not return the attribute.
/// `docs/RESOURCE_MODEL.md` section 8 defines how the scan uses them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) struct PrivateAttributes {
    /// `ATTR_CMN_FILEID`, which is `st_ino` on APFS.
    pub(super) file_id: Option<u64>,
    /// `ATTR_CMNEXT_PRIVATESIZE`: the bytes that only this file uses. The
    /// value can be negative; the caller validates it.
    pub(super) private_size: Option<i64>,
    /// `ATTR_CMNEXT_CLONEID`: the identity of the clone family.
    pub(super) clone_id: Option<u64>,
    /// `ATTR_CMNEXT_CLONE_REFCNT`: the number of files in the clone family.
    pub(super) clone_count: Option<u32>,
}

/// The layout of the attribute buffer and the request constants of
/// `<sys/attr.h>` in the macOS 27.2 SDK.
#[cfg(target_os = "macos")]
mod attributes {
    use std::mem::{offset_of, size_of};

    /// `ATTR_CMNEXT_CLONE_REFCNT`. The `libc` crate does not have this
    /// constant.
    pub(super) const ATTR_CMNEXT_CLONE_REFCNT: libc::attrgroup_t = 0x0000_1000;

    pub(super) const COMMON: libc::attrgroup_t =
        libc::ATTR_CMN_RETURNED_ATTRS | libc::ATTR_CMN_FILEID;
    pub(super) const FORK: libc::attrgroup_t =
        libc::ATTR_CMNEXT_PRIVATESIZE | libc::ATTR_CMNEXT_CLONEID | ATTR_CMNEXT_CLONE_REFCNT;
    /// `FSOPT_NOFOLLOW | FSOPT_PACK_INVAL_ATTRS | FSOPT_ATTR_CMN_EXTENDED`.
    /// With `FSOPT_PACK_INVAL_ATTRS`, each requested attribute has its
    /// place in the buffer, and the returned set tells which ones are valid.
    /// `FSOPT_ATTR_CMN_EXTENDED` makes the fork group carry the `CMNEXT`
    /// attributes.
    pub(super) const OPTIONS: libc::c_ulong =
        (libc::FSOPT_NOFOLLOW | libc::FSOPT_PACK_INVAL_ATTRS | libc::FSOPT_ATTR_CMN_EXTENDED)
            as libc::c_ulong;

    /// The buffer that the call writes: the length, the returned attribute
    /// set, then the values in the order of their bits, common group before
    /// fork group. The kernel aligns each value to 4 bytes, so a 64-bit
    /// value can be at an offset that is not a multiple of 8.
    #[repr(C, packed(4))]
    #[derive(Clone, Copy)]
    pub(super) struct Buffer {
        pub(super) length: u32,
        pub(super) returned: libc::attribute_set_t,
        pub(super) file_id: u64,
        pub(super) private_size: libc::off_t,
        pub(super) clone_id: u64,
        pub(super) clone_count: u32,
    }

    // The values of `<sys/attr.h>` and of `getattrlist(2)` in the SDK.
    const _: () = assert!(libc::ATTR_BIT_MAP_COUNT == 5);
    const _: () = assert!(libc::ATTR_CMN_RETURNED_ATTRS == 0x8000_0000);
    const _: () = assert!(libc::ATTR_CMN_FILEID == 0x0200_0000);
    const _: () = assert!(libc::ATTR_CMNEXT_PRIVATESIZE == 0x0000_0008);
    const _: () = assert!(libc::ATTR_CMNEXT_CLONEID == 0x0000_0100);
    const _: () = assert!(libc::FSOPT_NOFOLLOW == 0x0000_0001);
    const _: () = assert!(libc::FSOPT_PACK_INVAL_ATTRS == 0x0000_0008);
    const _: () = assert!(libc::FSOPT_ATTR_CMN_EXTENDED == 0x0000_0020);
    const _: () = assert!(size_of::<libc::attrlist>() == 24);
    const _: () = assert!(size_of::<libc::attribute_set_t>() == 20);
    const _: () = assert!(size_of::<libc::off_t>() == 8);
    const _: () = assert!(offset_of!(Buffer, returned) == 4);
    const _: () = assert!(offset_of!(Buffer, file_id) == 24);
    const _: () = assert!(offset_of!(Buffer, private_size) == 32);
    const _: () = assert!(offset_of!(Buffer, clone_id) == 40);
    const _: () = assert!(offset_of!(Buffer, clone_count) == 48);
    const _: () = assert!(size_of::<Buffer>() == 52);
}

/// Reads the private-size attributes of the regular file `name` of the
/// open directory `parent`. The call does not follow a symbolic link.
#[cfg(target_os = "macos")]
///
/// With `with_clone_count` false, the request has no
/// `ATTR_CMNEXT_CLONE_REFCNT`, which an older kernel can refuse with
/// `EINVAL`, and the result has no clone count.
pub(super) fn private_attributes(
    parent: BorrowedFd<'_>,
    name: &CStr,
    with_clone_count: bool,
) -> io::Result<PrivateAttributes> {
    let fork: libc::attrgroup_t = if with_clone_count {
        attributes::FORK
    } else {
        attributes::FORK & !attributes::ATTR_CMNEXT_CLONE_REFCNT
    };
    let mut request = libc::attrlist {
        bitmapcount: libc::ATTR_BIT_MAP_COUNT,
        reserved: 0,
        commonattr: attributes::COMMON,
        volattr: 0,
        dirattr: 0,
        fileattr: 0,
        forkattr: fork,
    };
    let mut buffer: MaybeUninit<attributes::Buffer> = MaybeUninit::zeroed();
    // SAFETY: `parent` is open for the call, `name` is a NUL-terminated
    // string that lives for the call, `request` is a valid `attrlist` for
    // the call, and `buffer` is valid for a write of its full size, which
    // is the size that the call gets. The call keeps no pointer after it
    // returns.
    let status: libc::c_int = unsafe {
        libc::getattrlistat(
            parent.as_raw_fd(),
            name.as_ptr(),
            (&raw mut request).cast(),
            buffer.as_mut_ptr().cast(),
            size_of::<attributes::Buffer>(),
            attributes::OPTIONS,
        )
    };
    if status != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the buffer was made with `zeroed`, and each field is an
    // integer, for which zero is a valid value. The call wrote at most the
    // size of the buffer.
    let buffer: attributes::Buffer = unsafe { buffer.assume_init() };
    let length: u32 = buffer.length;
    // Without the clone count, the layout ends before its field.
    let expected: usize = if with_clone_count {
        size_of::<attributes::Buffer>()
    } else {
        std::mem::offset_of!(attributes::Buffer, clone_count)
    };
    if usize::try_from(length).ok() != Some(expected) {
        // With `FSOPT_PACK_INVAL_ATTRS`, the length is the full layout.
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    let returned: libc::attribute_set_t = buffer.returned;
    let valid = |group: libc::attrgroup_t, bit: libc::attrgroup_t| group & bit == bit;
    Ok(PrivateAttributes {
        file_id: valid(returned.commonattr, libc::ATTR_CMN_FILEID).then_some(buffer.file_id),
        private_size: valid(returned.forkattr, libc::ATTR_CMNEXT_PRIVATESIZE)
            .then_some(buffer.private_size),
        clone_id: valid(returned.forkattr, libc::ATTR_CMNEXT_CLONEID).then_some(buffer.clone_id),
        clone_count: (with_clone_count
            && valid(returned.forkattr, attributes::ATTR_CMNEXT_CLONE_REFCNT))
        .then_some(buffer.clone_count),
    })
}

/// A system that is not macOS reports no private size.
#[cfg(not(target_os = "macos"))]
pub(super) fn private_attributes(
    _parent: BorrowedFd<'_>,
    _name: &CStr,
    _with_clone_count: bool,
) -> io::Result<PrivateAttributes> {
    Ok(PrivateAttributes::default())
}
