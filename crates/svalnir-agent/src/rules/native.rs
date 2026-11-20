//! The native calls of the rules: a query for an advisory lock, and two
//! queries of a process (its working directory and its owner) for the
//! process evidence of `project.dependency-directory`.
//!
//! The process queries name a process by its identifier and do not check
//! it again between the queries of one inventory. A process that exits and
//! whose identifier another process takes between two queries gives the
//! facts of two processes. Two of the mixes are fail-safe for the
//! evidence: a working directory or an executable of the other process can
//! only add a process that blocks a unit, and a process that is not seen at
//! all is a process that exited, the same result as an inventory a moment
//! later. The third is a residual risk: when the identity query of a
//! process is denied, its owner comes from a second query, and a process of
//! a different user that took the identifier between the two queries makes
//! the inventory drop the first process. The window is the time between
//! two system calls.

use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;

/// The lock-type constant as the field type of `flock`. The two types
/// are different on some targets.
fn lock_type(constant: impl TryInto<libc::c_short>) -> io::Result<libc::c_short> {
    constant
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::Unsupported, "unsupported lock constant"))
}

/// Whether a lock that this query can see is on a part of `file`.
///
/// The query is `fcntl(F_GETLK)` for a write lock on the whole file. It
/// takes no lock and changes nothing. It sees a record lock of another
/// process. It does not see a record lock of this process, and it does
/// not see a writer that takes no lock. On macOS it also sees a `flock`
/// lock of another open file description, of each process.
///
/// # Errors
///
/// Returns the error of the operating system when the query fails. A
/// failed query does not show that the file has no lock.
pub(super) fn is_locked_by_another_process(file: &File) -> io::Result<bool> {
    let mut query: libc::flock = libc::flock {
        l_start: 0,
        // A length of zero is the range to the end of the file and each
        // byte after it.
        l_len: 0,
        l_pid: 0,
        l_type: lock_type(libc::F_WRLCK)?,
        l_whence: lock_type(libc::SEEK_SET)?,
    };
    // SAFETY: the descriptor is open for the full call, because `file` is
    // borrowed. `query` is an initialized `flock` that this function owns,
    // and the pointer is valid for a write for the full call. `F_GETLK`
    // reads the request from the structure and writes the result to it.
    let status: libc::c_int =
        unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETLK, &raw mut query) };
    if status == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(query.l_type != lock_type(libc::F_UNLCK)?)
}

/// The result of `proc_pidinfo` for `pid` and `flavor` into a value of
/// `T`, a plain C structure of integers and arrays of integers.
///
/// `errno` is set to zero before the call, so a failure reads the value of
/// this call and not a value that an earlier call left.
///
/// # Safety
///
/// `T` must be the structure that the kernel writes for `flavor`, and each
/// bit pattern must be a valid value of `T`.
#[cfg(target_os = "macos")]
unsafe fn pid_info<T>(
    pid: svalnir_core::process::Pid,
    flavor: libc::c_int,
) -> Result<T, crate::platform::process::QueryFailure> {
    use crate::platform::process::QueryFailure;

    let size: libc::c_int =
        libc::c_int::try_from(size_of::<T>()).map_err(|_| QueryFailure::Inconsistent)?;
    let mut info: std::mem::MaybeUninit<T> = std::mem::MaybeUninit::zeroed();
    // SAFETY: `__error` takes no argument and gives the address of the
    // `errno` of this thread.
    let errno: *mut libc::c_int = unsafe { libc::__error() };
    // SAFETY: the address is valid for a write for the life of the thread,
    // and only this thread uses it.
    unsafe { *errno = 0 };
    // SAFETY: the pointer is valid for a write of `size` bytes for the
    // full call, because `info` is a local value of that size that this
    // function owns. The call writes at most `size` bytes.
    let written: libc::c_int = unsafe {
        libc::proc_pidinfo(
            pid.get(),
            flavor,
            0,
            info.as_mut_ptr().cast::<libc::c_void>(),
            size,
        )
    };
    if written <= 0 {
        return Err(match io::Error::last_os_error().raw_os_error() {
            Some(libc::ESRCH) => QueryFailure::Gone,
            Some(libc::EPERM | libc::EACCES) => QueryFailure::PermissionDenied,
            _ => QueryFailure::Inconsistent,
        });
    }
    if written != size {
        return Err(QueryFailure::Inconsistent);
    }
    // SAFETY: the kernel wrote the full structure, and the caller
    // guarantees that each bit pattern is a valid value of `T`.
    Ok(unsafe { info.assume_init() })
}

/// The current working directory of the process `pid`.
///
/// The query is `proc_pidinfo(PROC_PIDVNODEPATHINFO)`. It reads the path
/// that the kernel keeps for the directory and changes nothing.
///
/// # Errors
///
/// Returns [`crate::platform::process::QueryFailure::Gone`] for a process
/// that exited, `PermissionDenied` when the system denies the query, and
/// `Inconsistent` for a result that is not consistent, for example a path
/// with no NUL byte at its end or a relative path.
#[cfg(target_os = "macos")]
pub(super) fn working_directory(
    pid: svalnir_core::process::Pid,
) -> Result<std::path::PathBuf, crate::platform::process::QueryFailure> {
    use crate::platform::process::QueryFailure;
    use std::os::unix::ffi::OsStrExt;

    // SAFETY: the kernel writes a `proc_vnodepathinfo` for this flavor. It
    // is a structure of integers and byte arrays, so each bit pattern is a
    // valid value.
    let info: libc::proc_vnodepathinfo = unsafe { pid_info(pid, libc::PROC_PIDVNODEPATHINFO)? };
    let raw: Vec<u8> = info
        .pvi_cdir
        .vip_path
        .iter()
        .flatten()
        .map(|byte| byte.to_ne_bytes()[0])
        .collect();
    // The path is a NUL-terminated byte string in a fixed array.
    let length: usize = raw
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(QueryFailure::Inconsistent)?;
    let bytes: &[u8] = &raw[..length];
    if bytes.first() != Some(&b'/') {
        return Err(QueryFailure::Inconsistent);
    }
    Ok(std::path::PathBuf::from(std::ffi::OsStr::from_bytes(bytes)))
}

/// The effective and the real user of the process `pid`.
///
/// The query is `proc_pidinfo(PROC_PIDT_SHORTBSDINFO)`, which the system
/// answers also for many processes whose `PROC_PIDTBSDINFO` query it
/// denies. It changes nothing.
///
/// # Errors
///
/// Returns the failure of the query, as [`working_directory`] does.
#[cfg(target_os = "macos")]
pub(super) fn process_owner(
    pid: svalnir_core::process::Pid,
) -> Result<
    (svalnir_core::process::Uid, svalnir_core::process::Uid),
    crate::platform::process::QueryFailure,
> {
    use crate::platform::process::QueryFailure;
    use svalnir_core::process::Uid;

    // SAFETY: the kernel writes a `proc_bsdshortinfo` for this flavor. It
    // is a structure of integers and byte arrays, so each bit pattern is a
    // valid value.
    let info: libc::proc_bsdshortinfo = unsafe { pid_info(pid, libc::PROC_PIDT_SHORTBSDINFO)? };
    if i32::try_from(info.pbsi_pid).ok() != Some(pid.get()) {
        return Err(QueryFailure::Inconsistent);
    }
    Ok((Uid::new(info.pbsi_uid), Uid::new(info.pbsi_ruid)))
}
