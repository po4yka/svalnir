//! Read-only native queries of macOS for the capability probes.
//!
//! Each function makes one bounded query and does not keep a metric value.
//! The collectors in `crate::platform` own the measurement; these functions
//! show only that a source answers under the tested process.

use std::ffi::CStr;
use std::io;
use std::mem::{MaybeUninit, size_of};
use std::ptr;

use super::probe::SourceFinding;

/// The `sysctl` name of the memory-pressure level.
pub(super) const PRESSURE_LEVEL: &CStr = c"kern.memorystatus_vm_pressure_level";
/// The `sysctl` name of the swap usage.
pub(super) const SWAP_USAGE: &CStr = c"vm.swapusage";
/// The `sysctl` name of the product version of the operating system.
pub(super) const OS_PRODUCT_VERSION: &CStr = c"kern.osproductversion";
/// The `sysctl` name of the build of the operating system.
pub(super) const OS_BUILD: &CStr = c"kern.osversion";
/// The `sysctl` name that is 1 on Apple Silicon hardware.
pub(super) const HARDWARE_ARM64: &CStr = c"hw.optional.arm64";
/// The `sysctl` name that is 1 for a process under binary translation.
pub(super) const PROCESS_TRANSLATED: &CStr = c"sysctl.proc_translated";

/// Reads one `sysctl` value into `buffer` and returns the number of bytes
/// that the kernel wrote.
fn sysctl_read(name: &CStr, buffer: &mut [u8]) -> io::Result<usize> {
    let mut length: libc::size_t = buffer.len();
    // SAFETY: `name` is a NUL-terminated string. `buffer` is valid for
    // writes of `length` bytes, and the kernel writes no more than `length`
    // bytes. `length` is a live `size_t`. The new-value pointer is null with
    // length 0, so the call does not change a value.
    let status = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            buffer.as_mut_ptr().cast(),
            &raw mut length,
            ptr::null_mut(),
            0,
        )
    };
    if status == 0 {
        Ok(length.min(buffer.len()))
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Reads a `sysctl` value that is a 32-bit integer.
pub(super) fn sysctl_i32(name: &CStr) -> io::Result<i32> {
    let mut buffer = [0_u8; size_of::<i32>()];
    let length = sysctl_read(name, &mut buffer)?;
    if length == buffer.len() {
        Ok(i32::from_ne_bytes(buffer))
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("the value has {length} bytes, not 4"),
        ))
    }
}

/// Reads a `sysctl` value that is a short string.
pub(super) fn sysctl_string(name: &CStr) -> io::Result<String> {
    let mut buffer = [0_u8; 256];
    let length = sysctl_read(name, &mut buffer)?;
    let bytes = buffer.get(..length).unwrap_or(&buffer);
    let text = bytes.split(|byte| *byte == 0).next().unwrap_or(&[]);
    Ok(String::from_utf8_lossy(text).into_owned())
}

/// Turns the error of a native query into a finding.
fn error_finding(what: &str, error: &io::Error) -> SourceFinding {
    let detail = format!("{what}: {error}");
    match error.raw_os_error() {
        Some(libc::EPERM | libc::EACCES) => SourceFinding::Denied { detail },
        Some(libc::ENOENT | libc::ENOTSUP) => SourceFinding::Unsupported { detail },
        _ => SourceFinding::Failed { detail },
    }
}

/// Queries the memory-pressure level.
pub(super) fn memory_pressure() -> SourceFinding {
    match sysctl_i32(PRESSURE_LEVEL) {
        Ok(_) => SourceFinding::Responded {
            detail: "The query returned a level.".to_owned(),
        },
        Err(error) => error_finding("sysctlbyname", &error),
    }
}

/// Queries the swap usage.
pub(super) fn swap_usage() -> SourceFinding {
    let mut buffer = [0_u8; size_of::<libc::xsw_usage>()];
    match sysctl_read(SWAP_USAGE, &mut buffer) {
        Ok(length) if length == buffer.len() => SourceFinding::Responded {
            detail: format!("The query returned a record of {length} bytes."),
        },
        Ok(length) => SourceFinding::Failed {
            detail: format!(
                "The query returned {length} bytes, not the {} bytes of the record.",
                buffer.len()
            ),
        },
        Err(error) => error_finding("sysctlbyname", &error),
    }
}

/// Queries the virtual-memory statistics of the host.
pub(super) fn vm_statistics() -> SourceFinding {
    let mut statistics = MaybeUninit::<libc::vm_statistics64>::zeroed();
    let mut count: libc::mach_msg_type_number_t = libc::HOST_VM_INFO64_COUNT;
    // `libc` has no `mach_port_deallocate`, so one user reference to the
    // host port stays in this process for each call. The port name is the
    // same for each call and the reference count saturates, so a repeated
    // probe does not use more port names.
    #[expect(
        deprecated,
        reason = "libc directs to the mach2 crate, which is not a workspace dependency"
    )]
    // SAFETY: The function has no argument and returns a port name.
    let host = unsafe { libc::mach_host_self() };
    // SAFETY: `statistics` is valid for writes of `count` words of
    // `integer_t`, because `count` is `HOST_VM_INFO64_COUNT`, the size of
    // `vm_statistics64` in those words. `count` is a live value that the
    // kernel updates. The call reads host statistics and changes no state.
    let status = unsafe {
        libc::host_statistics64(
            host,
            libc::HOST_VM_INFO64,
            statistics.as_mut_ptr().cast(),
            &raw mut count,
        )
    };
    if status == libc::KERN_SUCCESS {
        SourceFinding::Responded {
            detail: format!("The query returned {count} words of statistics."),
        }
    } else {
        SourceFinding::Failed {
            detail: format!("host_statistics64 returned the Mach error {status}."),
        }
    }
}

/// Queries the capacity record of the volume that contains `path`.
pub(super) fn volume_capacity(path: &CStr) -> SourceFinding {
    let mut record = MaybeUninit::<libc::statfs>::zeroed();
    // SAFETY: `path` is a NUL-terminated string, and `record` is valid for
    // a write of one `statfs` record. The call reads volume metadata only.
    let status = unsafe { libc::statfs(path.as_ptr(), record.as_mut_ptr()) };
    if status == 0 {
        SourceFinding::Responded {
            detail: "The query returned the record of the root volume.".to_owned(),
        }
    } else {
        error_finding("statfs", &io::Error::last_os_error())
    }
}

/// Queries the BSD information of the own process.
pub(super) fn own_process() -> SourceFinding {
    let Ok(pid) = libc::c_int::try_from(std::process::id()) else {
        return SourceFinding::Failed {
            detail: "The process ID is not a valid native value.".to_owned(),
        };
    };
    let Ok(size) = libc::c_int::try_from(size_of::<libc::proc_bsdinfo>()) else {
        return SourceFinding::Failed {
            detail: "The record size is not a valid native value.".to_owned(),
        };
    };
    let mut record = MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    // SAFETY: `record` is valid for writes of `size` bytes, the size of one
    // `proc_bsdinfo`. The call reads the information of the own process.
    let written = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            record.as_mut_ptr().cast(),
            size,
        )
    };
    if written == size {
        SourceFinding::Responded {
            detail: "The query returned the record of the own process.".to_owned(),
        }
    } else if written <= 0 {
        error_finding("proc_pidinfo", &io::Error::last_os_error())
    } else {
        SourceFinding::Failed {
            detail: format!("The query returned {written} bytes, not {size}."),
        }
    }
}
