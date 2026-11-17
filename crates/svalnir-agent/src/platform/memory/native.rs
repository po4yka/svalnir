//! The macOS adapter for the host memory queries.
//!
//! This file and `event.rs` are the only places in the memory module with
//! `unsafe` code. Each function makes one native query and returns the raw
//! numbers, or the reason there are none. A failed query is never a zero.

use std::ffi::CStr;
use std::io;
use std::mem::{MaybeUninit, offset_of, size_of};
use std::ptr;

use libc::{c_int, kern_return_t, mach_port_t, vm_size_t};
use svalnir_core::observation::UnavailableReason;

use super::raw::{RawSwapUsage, RawVmStatistics, RawVmStatisticsRevision1};

/// The largest text length that [`boot_session_uuid`] accepts, with the
/// terminator. A UUID has 36 characters.
const BOOT_SESSION_UUID_CAPACITY: usize = 64;

/// The number of `integer_t` words of revision 0 of `vm_statistics64`: the
/// fields before `decompressions`.
const VM_INFO64_REVISION_0_WORDS: usize = offset_of!(libc::vm_statistics64, decompressions) / 4;

/// The number of `integer_t` words of revision 1 of `vm_statistics64`: the
/// fields before `swapped_count`. The adapter asks for this revision, so the
/// kernel writes no more than these words.
const VM_INFO64_REVISION_1_WORDS: usize = offset_of!(libc::vm_statistics64, swapped_count) / 4;

// `mach/vm_statistics.h` of the macOS 27.2 SDK gives these two layouts. A
// `libc` release that moves a field stops the build here.
const _: () = assert!(VM_INFO64_REVISION_0_WORDS == 24);
const _: () = assert!(VM_INFO64_REVISION_1_WORDS == 38);
const _: () = assert!(size_of::<libc::vm_statistics64>() >= VM_INFO64_REVISION_1_WORDS * 4);
// `sys/sysctl.h`: three 64-bit fields, the page size, and the encrypted flag.
const _: () = assert!(size_of::<libc::xsw_usage>() == 32);

unsafe extern "C" {
    /// The task port of this process. The Mach runtime sets it before `main`
    /// and does not change it.
    static mach_task_self_: mach_port_t;

    /// Returns a send right to the host port, or `MACH_PORT_NULL`.
    fn mach_host_self() -> mach_port_t;

    /// Releases one user reference to a port name of `task`.
    fn mach_port_deallocate(task: mach_port_t, name: mach_port_t) -> kern_return_t;

    /// Writes the page size of the host to `out_page_size`.
    fn host_page_size(host: mach_port_t, out_page_size: *mut vm_size_t) -> kern_return_t;
}

/// A value that `sysctlbyname` can write into directly.
///
/// # Safety
///
/// The type has no invalid bit pattern, no pointer, and no drop glue, so the
/// bytes that the kernel writes always make a valid value.
unsafe trait SysctlValue: Copy {}

// SAFETY: an integer accepts each bit pattern.
unsafe impl SysctlValue for u64 {}
// SAFETY: an integer accepts each bit pattern.
unsafe impl SysctlValue for c_int {}
// SAFETY: the structure has only integer fields and no padding (32 bytes).
unsafe impl SysctlValue for libc::xsw_usage {}

/// Maps the `errno` of a failed query to a stable reason.
fn reason_from_errno(error: &io::Error) -> UnavailableReason {
    match error.raw_os_error() {
        Some(libc::EPERM | libc::EACCES) => UnavailableReason::PermissionDenied,
        Some(libc::ENOENT | libc::ENOTSUP) => UnavailableReason::Unsupported,
        // The kernel value does not have the length of the typed buffer.
        Some(libc::ENOMEM | libc::EINVAL) => UnavailableReason::InconsistentData,
        _ => UnavailableReason::TransientFailure,
    }
}

/// Reads a fixed-size value with `sysctlbyname`.
///
/// The read fails when the kernel value does not have exactly the size of
/// `T`.
fn read_fixed<T: SysctlValue>(name: &CStr) -> Result<T, UnavailableReason> {
    let mut value: MaybeUninit<T> = MaybeUninit::zeroed();
    let mut length: libc::size_t = size_of::<T>();
    // SAFETY: `name` is a NUL-terminated string. `value` is writable for
    // `length` bytes, which is the size of `T`. The kernel writes no more
    // than `length` bytes and stores the written length. No new value is set.
    let status: c_int = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            value.as_mut_ptr().cast(),
            &raw mut length,
            ptr::null_mut(),
            0,
        )
    };
    if status != 0 {
        return Err(reason_from_errno(&io::Error::last_os_error()));
    }
    if length != size_of::<T>() {
        return Err(UnavailableReason::InconsistentData);
    }
    // SAFETY: the buffer was zeroed and the kernel then wrote all its bytes.
    // `T: SysctlValue` accepts each bit pattern.
    Ok(unsafe { value.assume_init() })
}

/// `hw.memsize`: the physical memory of the host, in bytes.
pub(super) fn physical_memory_bytes() -> Result<u64, UnavailableReason> {
    read_fixed::<u64>(c"hw.memsize")
}

/// `kern.memorystatus_vm_pressure_level`: the native memory-pressure level.
pub(super) fn pressure_level() -> Result<i32, UnavailableReason> {
    read_fixed::<c_int>(c"kern.memorystatus_vm_pressure_level")
}

/// `vm.swapusage`: the swap space of the host, in bytes.
pub(super) fn swap_usage() -> Result<RawSwapUsage, UnavailableReason> {
    let usage: libc::xsw_usage = read_fixed::<libc::xsw_usage>(c"vm.swapusage")?;
    Ok(RawSwapUsage {
        total: usage.xsu_total,
        available: usage.xsu_avail,
        used: usage.xsu_used,
    })
}

/// `kern.bootsessionuuid`: a UUID that the kernel makes at each boot.
pub(super) fn boot_session_uuid() -> Result<String, UnavailableReason> {
    let mut buffer = [0_u8; BOOT_SESSION_UUID_CAPACITY];
    let mut length: libc::size_t = buffer.len();
    // SAFETY: the name is a NUL-terminated string. `buffer` is writable for
    // `length` bytes. The kernel writes no more than `length` bytes and
    // stores the written length. No new value is set.
    let status: c_int = unsafe {
        libc::sysctlbyname(
            c"kern.bootsessionuuid".as_ptr(),
            buffer.as_mut_ptr().cast(),
            &raw mut length,
            ptr::null_mut(),
            0,
        )
    };
    if status != 0 {
        return Err(reason_from_errno(&io::Error::last_os_error()));
    }
    let written: &[u8] = buffer
        .get(..length)
        .ok_or(UnavailableReason::InconsistentData)?;
    let text: &CStr =
        CStr::from_bytes_until_nul(written).map_err(|_| UnavailableReason::InconsistentData)?;
    let text: &str = text
        .to_str()
        .map_err(|_| UnavailableReason::InconsistentData)?;
    if text.is_empty() {
        return Err(UnavailableReason::InconsistentData);
    }
    Ok(text.to_owned())
}

/// A send right to the host port. The drop releases the user reference that
/// `mach_host_self` added.
struct HostPort(mach_port_t);

impl HostPort {
    fn acquire() -> Result<Self, UnavailableReason> {
        // SAFETY: the call has no argument and no precondition.
        let port: mach_port_t = unsafe { mach_host_self() };
        if port == 0 {
            // `MACH_PORT_NULL`: the task has no host port.
            return Err(UnavailableReason::TransientFailure);
        }
        Ok(Self(port))
    }
}

impl Drop for HostPort {
    fn drop(&mut self) {
        // SAFETY: the Mach runtime set the static before `main`; the read
        // copies an integer.
        let task: mach_port_t = unsafe { mach_task_self_ };
        // SAFETY: `self.0` is a port name of this task with one user
        // reference from `mach_host_self`, and this is its only release.
        let status: kern_return_t = unsafe { mach_port_deallocate(task, self.0) };
        // A failure leaves one user reference to the host port. The port is
        // not usable through `self` after the drop, and there is no recovery.
        let _: kern_return_t = status;
    }
}

/// `host_page_size`: the page size, in bytes, that the host VM counters use.
pub(super) fn vm_page_size() -> Result<u64, UnavailableReason> {
    let host: HostPort = HostPort::acquire()?;
    let mut page_size: vm_size_t = 0;
    // SAFETY: `host.0` is a valid host port. `page_size` is writable.
    let status: kern_return_t = unsafe { host_page_size(host.0, &raw mut page_size) };
    if status != libc::KERN_SUCCESS {
        return Err(UnavailableReason::TransientFailure);
    }
    u64::try_from(page_size).map_err(|_| UnavailableReason::Overflow)
}

/// `host_statistics64` with `HOST_VM_INFO64`: the VM statistics of the host.
pub(super) fn vm_statistics() -> Result<RawVmStatistics, UnavailableReason> {
    let host: HostPort = HostPort::acquire()?;
    let mut statistics: MaybeUninit<libc::vm_statistics64> = MaybeUninit::zeroed();
    let requested: libc::mach_msg_type_number_t =
        libc::mach_msg_type_number_t::try_from(VM_INFO64_REVISION_1_WORDS)
            .map_err(|_| UnavailableReason::Overflow)?;
    let mut count: libc::mach_msg_type_number_t = requested;
    // SAFETY: `host.0` is a valid host port. `statistics` is writable for
    // `count` words: a constant assertion shows that the structure is not
    // smaller than revision 1. The kernel writes no more than `count` words
    // and stores the number of words that it wrote.
    let status: kern_return_t = unsafe {
        libc::host_statistics64(
            host.0,
            libc::HOST_VM_INFO64,
            statistics.as_mut_ptr().cast(),
            &raw mut count,
        )
    };
    if status != libc::KERN_SUCCESS {
        return Err(UnavailableReason::TransientFailure);
    }
    let written: usize = usize::try_from(count).map_err(|_| UnavailableReason::Overflow)?;
    if written < VM_INFO64_REVISION_0_WORDS || count > requested {
        return Err(UnavailableReason::InconsistentData);
    }
    // SAFETY: the structure was zeroed, each field is an integer, and each
    // bit pattern is a valid integer.
    let statistics: libc::vm_statistics64 = unsafe { statistics.assume_init() };
    let revision_1: Option<RawVmStatisticsRevision1> = (written >= VM_INFO64_REVISION_1_WORDS)
        .then_some(RawVmStatisticsRevision1 {
            decompressions: statistics.decompressions,
            compressions: statistics.compressions,
            swapins: statistics.swapins,
            swapouts: statistics.swapouts,
            compressor_page_count: statistics.compressor_page_count,
            external_page_count: statistics.external_page_count,
            internal_page_count: statistics.internal_page_count,
            total_uncompressed_pages_in_compressor: statistics
                .total_uncompressed_pages_in_compressor,
        });
    Ok(RawVmStatistics {
        free_count: statistics.free_count,
        active_count: statistics.active_count,
        inactive_count: statistics.inactive_count,
        wire_count: statistics.wire_count,
        speculative_count: statistics.speculative_count,
        pageins: statistics.pageins,
        pageouts: statistics.pageouts,
        revision_1,
    })
}

/// `clock_gettime(CLOCK_MONOTONIC_RAW)`: nanoseconds on the monotonic clock
/// of the host. The clock continues while the host sleeps.
pub(super) fn monotonic_raw_nanoseconds() -> Option<u64> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `time` is writable for the duration of the call.
    let status: c_int = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC_RAW, &raw mut time) };
    if status != 0 {
        return None;
    }
    let seconds: u64 = u64::try_from(time.tv_sec).ok()?;
    let nanoseconds: u64 = u64::try_from(time.tv_nsec).ok()?;
    seconds.checked_mul(1_000_000_000)?.checked_add(nanoseconds)
}

/// The name of the clock that [`monotonic_raw_nanoseconds`] reads.
pub(super) const CLOCK_DOMAIN: &str = "macos.clock_monotonic_raw";
