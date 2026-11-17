//! The one native call of the rules: a query for an advisory lock.

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
