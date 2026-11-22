//! The native calls of the executor and of the clock.
//!
//! Each `unsafe` block of the helper that is not a call of XPC or of the
//! Security framework is in this file. Each filesystem call that takes a
//! name takes one path component relative to an open directory: `openat`
//! with `O_NOFOLLOW` and `O_DIRECTORY`, `fstatat` with
//! `AT_SYMLINK_NOFOLLOW`, and `unlinkat`. The only path that the operating
//! system resolves is `/`, which has one component. A replaced path
//! component thus cannot redirect a call to another directory.
//!
//! The helper does not link the agent, so this file has its own copy of
//! the calls that the filesystem executor of the agent also has.

use std::ffi::CStr;
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd};

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
    /// The permission bits of `st_mode`.
    pub(crate) permissions: u32,
    /// `st_blocks`, in units of 512 bytes. The value can be negative; the
    /// caller validates it.
    pub(crate) blocks: i64,
    /// `st_nlink`.
    pub(crate) link_count: u64,
    /// `st_dev`. `None` when the number does not fit 32 bits.
    pub(crate) device: Option<i32>,
    /// `st_ino`.
    pub(crate) inode: u64,
    /// `st_uid`.
    pub(crate) owner: u32,
    /// Whether the object is a dataless placeholder (`SF_DATALESS`).
    pub(crate) dataless: bool,
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
    let device: Option<i32> = Some(stat.st_dev);
    #[cfg(not(target_os = "macos"))]
    let device: Option<i32> = i32::try_from(stat.st_dev).ok();
    Metadata {
        kind,
        permissions: u32::from(stat.st_mode & 0o7777),
        blocks: stat.st_blocks,
        link_count: link_count(stat),
        device,
        inode: stat.st_ino,
        owner: stat.st_uid,
        dataless: is_dataless(stat),
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
pub(crate) fn unlink_at(parent: BorrowedFd<'_>, name: &CStr, directory: bool) -> io::Result<()> {
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

/// Whether the filesystem of the open object `descriptor` is local
/// (`MNT_LOCAL`). `None` means that the mount flags cannot be read.
#[cfg(target_os = "macos")]
pub(crate) fn is_on_local_filesystem(descriptor: BorrowedFd<'_>) -> Option<bool> {
    let mut buffer: MaybeUninit<libc::statfs> = MaybeUninit::zeroed();
    // SAFETY: `descriptor` is open for the call, and `buffer` is valid for
    // a write of one `statfs` structure.
    let status: libc::c_int = unsafe { libc::fstatfs(descriptor.as_raw_fd(), buffer.as_mut_ptr()) };
    if status != 0 {
        return None;
    }
    // SAFETY: the buffer was made with `zeroed`, and each field of `statfs`
    // is an integer or an array of integers, for which zero is a valid
    // value. The successful call then wrote the structure.
    let mount: libc::statfs = unsafe { buffer.assume_init() };
    let local: u32 = u32::try_from(libc::MNT_LOCAL).ok()?;
    Some(mount.f_flags & local != 0)
}

/// On a host other than macOS the mount flags are not read: the helper is
/// a macOS component, and this build is for the portable checks only.
#[cfg(not(target_os = "macos"))]
pub(crate) fn is_on_local_filesystem(_descriptor: BorrowedFd<'_>) -> Option<bool> {
    Some(true)
}

/// The largest buffer that [`home_directory_of`] gives `getpwuid_r`.
const MAX_ACCOUNT_RECORD_BYTES: usize = 64 * 1024;

/// The home directory of the account record of `uid`, from `getpwuid_r`.
/// `None` when the user has no record, when the record has no home
/// directory, or when the call fails.
pub(crate) fn home_directory_of(uid: u32) -> Option<Vec<u8>> {
    let mut size: usize = 4096;
    loop {
        let mut buffer: Vec<libc::c_char> = vec![0; size];
        let mut record = MaybeUninit::<libc::passwd>::uninit();
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: `record` is writable storage for one `passwd`, `buffer` is
        // a live, writable array of `size` bytes for the strings of the
        // record, and `result` is a live pointer that the call sets. The
        // strings that the call writes stay in `buffer`, which lives to the
        // end of this iteration.
        let status: libc::c_int = unsafe {
            libc::getpwuid_r(
                uid,
                record.as_mut_ptr(),
                buffer.as_mut_ptr(),
                size,
                &raw mut result,
            )
        };
        if status == libc::ERANGE && size < MAX_ACCOUNT_RECORD_BYTES {
            size = size.saturating_mul(2);
            continue;
        }
        if status != 0 || result.is_null() {
            return None;
        }
        // SAFETY: the call returned 0 and a non-null `result`, so it
        // initialized `record`.
        let record: libc::passwd = unsafe { record.assume_init() };
        if record.pw_dir.is_null() {
            return None;
        }
        // SAFETY: `pw_dir` is a NUL-terminated string in `buffer`, which is
        // still alive; the bytes are copied before `buffer` is dropped.
        let home: &CStr = unsafe { CStr::from_ptr(record.pw_dir) };
        return Some(home.to_bytes().to_vec());
    }
}

/// The effective user of the process.
pub(crate) fn effective_uid() -> u32 {
    // SAFETY: the call has no precondition and cannot fail.
    unsafe { libc::geteuid() }
}

/// The monotonic time in nanoseconds, from
/// `clock_gettime(CLOCK_MONOTONIC_RAW)`. The agent reads the same clock
/// for the validity of a request.
pub(crate) fn monotonic_raw_nanoseconds() -> Option<u64> {
    let mut time: libc::timespec = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `time` is a live, writable `timespec`. The kernel writes the
    // clock value into it.
    let status: libc::c_int =
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC_RAW, &raw mut time) };
    if status != 0 {
        return None;
    }
    let seconds: u64 = u64::try_from(time.tv_sec).ok()?;
    let nanoseconds: u64 = u64::try_from(time.tv_nsec).ok()?;
    seconds.checked_mul(1_000_000_000)?.checked_add(nanoseconds)
}

/// The identifier of the current boot session, from
/// `kern.bootsessionuuid`. `None` means that the kernel gives no value or
/// that the value is not text.
#[cfg(target_os = "macos")]
pub(crate) fn boot_session_uuid() -> Option<String> {
    const NAME: &CStr = c"kern.bootsessionuuid";
    let mut buffer: [u8; 64] = [0; 64];
    let mut length: libc::size_t = buffer.len();
    // SAFETY: `NAME` is a NUL-terminated string. `buffer` is a live,
    // writable array and `length` holds its size, so the kernel writes at
    // most that number of bytes. The call sets no new value.
    let status: libc::c_int = unsafe {
        libc::sysctlbyname(
            NAME.as_ptr(),
            buffer.as_mut_ptr().cast::<libc::c_void>(),
            &raw mut length,
            std::ptr::null_mut(),
            0,
        )
    };
    if status != 0 {
        return None;
    }
    let written: &[u8] = buffer.get(..length)?;
    let text: &str = CStr::from_bytes_until_nul(written).ok()?.to_str().ok()?;
    if text.is_empty() {
        return None;
    }
    Some(text.to_owned())
}

/// A host other than macOS has no boot session identifier that the agent
/// also reads, so the clock of the helper is not available there.
#[cfg(not(target_os = "macos"))]
pub(crate) fn boot_session_uuid() -> Option<String> {
    None
}
