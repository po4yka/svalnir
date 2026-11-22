//! The native calls of the filesystem executor.
//!
//! Each `unsafe` block of the executor is in this file. Each call that takes
//! a name takes one path component relative to an open directory: `openat`
//! with `O_NOFOLLOW` and `O_DIRECTORY`, `fstatat` with
//! `AT_SYMLINK_NOFOLLOW`, and `unlinkat`. The only path that the operating
//! system resolves is `/`, which has one component. A replaced path
//! component thus cannot redirect a call to another directory.
//!
//! The read-only walk of `rules::nested_git` uses the calls that read
//! (`openat`, `fstatat`, `fstat`, and the directory stream); no other
//! module of the crate uses the call that removes.

use std::ffi::CStr;
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd as _, BorrowedFd, FromRawFd as _, IntoRawFd as _, OwnedFd, RawFd};
use std::ptr::NonNull;

use svalnir_core::file::DeviceNumber;

/// The kind of a file object, from `st_mode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    /// A regular file.
    File,
    /// A directory.
    Directory,
    /// A symbolic link.
    Symlink,
    /// Each other type: a socket, a FIFO, or a device.
    Other,
}

/// The `stat` fields that the executor uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Metadata {
    /// The kind, from `st_mode`.
    pub(crate) kind: Kind,
    /// `st_size`. The value can be negative; the caller validates it.
    pub(crate) size: i64,
    /// `st_blocks`, in units of 512 bytes. The value can be negative; the
    /// caller validates it.
    pub(crate) blocks: i64,
    /// `st_nlink`.
    pub(crate) link_count: u64,
    /// `st_dev`. `None` when the number does not fit the device-number
    /// type.
    pub(crate) device: Option<DeviceNumber>,
    /// `st_ino`.
    pub(crate) inode: u64,
    /// `st_uid`.
    pub(crate) owner: u32,
    /// Whether the object is a dataless placeholder (`SF_DATALESS`).
    pub(crate) dataless: bool,
    /// Whether a flag prevents the removal of the object or of the entries
    /// of a directory: `UF_IMMUTABLE`, `UF_APPEND`, `SF_IMMUTABLE`,
    /// `SF_APPEND`, or `SF_RESTRICTED`.
    pub(crate) locked: bool,
}

/// `SF_RESTRICTED` of `<sys/stat.h>` in the macOS SDK. The `libc` crate does
/// not have this constant.
#[cfg(target_os = "macos")]
const SF_RESTRICTED: u32 = 0x0008_0000;

/// The flags that make `unlinkat` or `rename` fail with `EPERM` for the
/// object, or for the entries of a directory.
#[cfg(target_os = "macos")]
const LOCKING_FLAGS: u32 =
    libc::UF_IMMUTABLE | libc::UF_APPEND | libc::SF_IMMUTABLE | libc::SF_APPEND | SF_RESTRICTED;

#[cfg(target_os = "macos")]
fn is_locked(stat: &libc::stat) -> bool {
    stat.st_flags & LOCKING_FLAGS != 0
}

#[cfg(not(target_os = "macos"))]
fn is_locked(_stat: &libc::stat) -> bool {
    false
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
fn is_dataless(stat: &libc::stat) -> bool {
    stat.st_flags & SF_DATALESS != 0
}

#[cfg(not(target_os = "macos"))]
fn is_dataless(_stat: &libc::stat) -> bool {
    false
}

fn metadata_from(stat: &libc::stat) -> Metadata {
    let kind: Kind = match stat.st_mode & libc::S_IFMT {
        libc::S_IFREG => Kind::File,
        libc::S_IFDIR => Kind::Directory,
        libc::S_IFLNK => Kind::Symlink,
        _ => Kind::Other,
    };
    // `dev_t` is the 32-bit type of the device number on macOS.
    #[cfg(target_os = "macos")]
    let device: Option<DeviceNumber> = Some(DeviceNumber::new(stat.st_dev));
    #[cfg(not(target_os = "macos"))]
    let device: Option<DeviceNumber> = i32::try_from(stat.st_dev).ok().map(DeviceNumber::new);
    Metadata {
        kind,
        size: stat.st_size,
        blocks: stat.st_blocks,
        link_count: link_count(stat),
        device,
        inode: stat.st_ino,
        owner: stat.st_uid,
        dataless: is_dataless(stat),
        locked: is_locked(stat),
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

/// Opens the directory `/`. The path has one component, so the operating
/// system resolves no symbolic link.
pub(crate) fn open_filesystem_root() -> io::Result<OwnedFd> {
    // SAFETY: the path is a NUL-terminated literal. The flags have no
    // `O_CREAT`, so the call needs no mode argument.
    let descriptor: libc::c_int = unsafe { libc::open(c"/".as_ptr(), DIRECTORY_FLAGS) };
    owned_descriptor(descriptor)
}

/// Opens the directory `name` in the open directory `parent`. The call
/// fails when `name` is a symbolic link or is not a directory. `name` is
/// one path component.
pub(crate) fn open_directory_at(parent: BorrowedFd<'_>, name: &CStr) -> io::Result<OwnedFd> {
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

fn metadata_after(status: libc::c_int, buffer: MaybeUninit<libc::stat>) -> io::Result<Metadata> {
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
pub(crate) fn stat_descriptor(descriptor: BorrowedFd<'_>) -> io::Result<Metadata> {
    let mut buffer: MaybeUninit<libc::stat> = MaybeUninit::zeroed();
    // SAFETY: `descriptor` is open for the call, and `buffer` is valid for
    // a write of one `stat` structure.
    let status: libc::c_int = unsafe { libc::fstat(descriptor.as_raw_fd(), buffer.as_mut_ptr()) };
    metadata_after(status, buffer)
}

/// Measures the entry `name` of the open directory `parent`. The call does
/// not follow a symbolic link. `name` is one path component.
pub(crate) fn stat_at(parent: BorrowedFd<'_>, name: &CStr) -> io::Result<Metadata> {
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

/// Removes the entry `name` of the open directory `parent` with `unlinkat`.
///
/// With `directory` set, the call has `AT_REMOVEDIR`: it removes an empty
/// directory and fails for each other object. Without it, the call removes
/// a name that is not a directory; a symbolic link is removed and is not
/// followed. `name` is one path component.
pub(super) fn unlink_at(parent: BorrowedFd<'_>, name: &CStr, directory: bool) -> io::Result<()> {
    let flags: libc::c_int = if directory { libc::AT_REMOVEDIR } else { 0 };
    // SAFETY: `parent` is open for the call, and `name` is a NUL-terminated
    // string that lives for the call.
    let status: libc::c_int = unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// The effective user of the process.
pub(super) fn effective_uid() -> u32 {
    // SAFETY: the call has no precondition and cannot fail.
    unsafe { libc::geteuid() }
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
pub(crate) struct DirStream {
    /// The stream from `fdopendir`. `closedir` in `Drop` releases it.
    stream: NonNull<libc::DIR>,
    /// The descriptor that `fdopendir` received. The stream owns it.
    descriptor: RawFd,
}

impl DirStream {
    /// Makes a stream from an open directory. The stream takes the
    /// descriptor.
    pub(crate) fn from_descriptor(descriptor: OwnedFd) -> io::Result<Self> {
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

    /// The descriptor of the directory, for `openat`, `fstatat`, and
    /// `unlinkat`.
    pub(crate) fn descriptor(&self) -> BorrowedFd<'_> {
        // SAFETY: the stream owns `descriptor` and closes it only in
        // `Drop`. The borrow cannot outlive `self`.
        unsafe { BorrowedFd::borrow_raw(self.descriptor) }
    }

    /// Reads the next name into `name`, with its NUL terminator. The names
    /// `.` and `..` are not given. Returns `false` at the end of the
    /// directory.
    pub(crate) fn next_name(&mut self, name: &mut Vec<u8>) -> io::Result<bool> {
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
