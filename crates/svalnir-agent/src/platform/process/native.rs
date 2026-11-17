//! The Darwin process queries. This file is the only place in the process
//! module that has `unsafe` code.
//!
//! Each function is safe to call. It passes a buffer that it owns to one
//! native call, checks the returned size or status, and converts the result
//! to a checked type. A failure is a [`QueryFailure`]; it is never a zero.
//!
//! | Query | Native API |
//! | --- | --- |
//! | Process list | `proc_listallpids` |
//! | Identity evidence | `proc_pidinfo(PROC_PIDTBSDINFO)` |
//! | Executable path | `proc_pidpath` |
//! | Resource use | `proc_pid_rusage(RUSAGE_INFO_V4)` |
//! | Responsible process | `responsibility_get_pid_responsible_for_pid` |
//! | Running applications | `NSWorkspace.runningApplications` |
//! | Application executable | `NSRunningApplication.executableURL` |
//! | CPU time ratio | `mach_timebase_info` |
//! | Monotonic clock | `clock_gettime(CLOCK_MONOTONIC_RAW)` |
//! | Boot session | `sysctlbyname("kern.bootsessionuuid")` |
//!
//! `responsibility_get_pid_responsible_for_pid` is not in the public SDK.
//! The adapter finds it with `dlsym` at run time. When the symbol is absent,
//! the query is [`QueryFailure::Unsupported`] and no process gets a
//! `responsible_process` attribution.

use std::ffi::{CStr, c_int, c_void};
use std::mem::MaybeUninit;
use std::os::unix::fs::MetadataExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::SystemTime;

/// Whether the next application list is the first one of the process.
static FIRST_APPLICATION_LIST: AtomicBool = AtomicBool::new(true);

use objc2::rc::autoreleasepool;
use objc2_app_kit::NSWorkspace;
use svalnir_core::file::{DeviceNumber, FileObjectEvidence, InodeNumber, LosslessPath};
use svalnir_core::observation::UnavailableReason;
use svalnir_core::process::{Pid, ProcessStartTime, Uid};
use svalnir_core::quantity::Nanoseconds;
use svalnir_core::time::{MonotonicNanos, WallTime};

use super::source::{
    ProcessSource, QueryFailure, RawProcessInfo, RawUsage, RunningApplication, Timebase,
};

/// The largest number of process IDs that one list can have. The value is
/// much more than the process limit of macOS; it bounds the buffer.
const MAX_LISTED_PIDS: usize = 1 << 18;

/// The number of times that the list query runs again with a larger buffer.
const LIST_ATTEMPTS: u32 = 4;

/// The process queries of the running macOS host.
#[derive(Debug, Clone, Copy, Default)]
pub struct DarwinProcessSource;

impl DarwinProcessSource {
    /// Makes the source. It holds no native resource.
    pub const fn new() -> Self {
        Self
    }
}

/// The failure that the current `errno` value gives.
fn last_failure() -> QueryFailure {
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::ESRCH) => QueryFailure::Gone,
        Some(libc::EPERM | libc::EACCES) => QueryFailure::PermissionDenied,
        Some(libc::ENOTSUP | libc::ENOSYS) => QueryFailure::Unsupported,
        Some(code) => QueryFailure::Failed(code),
        None => QueryFailure::Failed(0),
    }
}

fn list_pids() -> Result<Vec<Pid>, QueryFailure> {
    // SAFETY: a null buffer with a size of zero is the documented request
    // for the number of process IDs. The kernel writes nothing.
    let estimate: c_int = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
    if estimate <= 0 {
        return Err(last_failure());
    }
    let mut capacity: usize = usize::try_from(estimate)
        .map_err(|_| QueryFailure::Inconsistent)?
        .saturating_add(64)
        .min(MAX_LISTED_PIDS);

    for _ in 0..LIST_ATTEMPTS {
        let mut buffer: Vec<libc::pid_t> = vec![0; capacity];
        let byte_size: c_int = c_int::try_from(capacity.saturating_mul(size_of::<libc::pid_t>()))
            .map_err(|_| QueryFailure::Overflow)?;
        // SAFETY: `buffer` is a live allocation of `byte_size` bytes with
        // the alignment of `pid_t`. The kernel writes at most `byte_size`
        // bytes of `pid_t` values into it.
        let count: c_int =
            unsafe { libc::proc_listallpids(buffer.as_mut_ptr().cast::<c_void>(), byte_size) };
        if count <= 0 {
            return Err(last_failure());
        }
        let count: usize = usize::try_from(count).map_err(|_| QueryFailure::Inconsistent)?;
        if count > capacity {
            return Err(QueryFailure::Inconsistent);
        }
        if count == capacity && capacity < MAX_LISTED_PIDS {
            // The buffer was full, so the list can be incomplete.
            capacity = capacity.saturating_mul(2).min(MAX_LISTED_PIDS);
            continue;
        }
        buffer.truncate(count);
        // PID 0 is the kernel task. It is not a process that the inventory
        // can address.
        return Ok(buffer
            .into_iter()
            .filter_map(|pid| Pid::new(pid).ok())
            .collect());
    }
    Err(QueryFailure::Inconsistent)
}

fn process_info(pid: Pid) -> Result<RawProcessInfo, QueryFailure> {
    let mut info: MaybeUninit<libc::proc_bsdinfo> = MaybeUninit::zeroed();
    let size: c_int =
        c_int::try_from(size_of::<libc::proc_bsdinfo>()).map_err(|_| QueryFailure::Overflow)?;
    // SAFETY: `info` is a live, writable `proc_bsdinfo` of `size` bytes. The
    // kernel writes at most `size` bytes for `PROC_PIDTBSDINFO`.
    let written: c_int = unsafe {
        libc::proc_pidinfo(
            pid.get(),
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast::<c_void>(),
            size,
        )
    };
    if written <= 0 {
        return Err(last_failure());
    }
    if written != size {
        return Err(QueryFailure::Inconsistent);
    }
    // SAFETY: the kernel wrote the full structure. Each field is an integer
    // or an array of integers, so each bit pattern is a valid value.
    let info: libc::proc_bsdinfo = unsafe { info.assume_init() };

    let reported: Pid = i32::try_from(info.pbi_pid)
        .ok()
        .and_then(|value| Pid::new(value).ok())
        .ok_or(QueryFailure::Inconsistent)?;
    if reported != pid {
        return Err(QueryFailure::Inconsistent);
    }
    let microseconds: u32 =
        u32::try_from(info.pbi_start_tvusec).map_err(|_| QueryFailure::Inconsistent)?;
    let start_time: ProcessStartTime =
        ProcessStartTime::from_timeval(info.pbi_start_tvsec, microseconds)
            .ok_or(QueryFailure::Inconsistent)?;
    Ok(RawProcessInfo {
        pid: reported,
        parent_pid: i32::try_from(info.pbi_ppid)
            .ok()
            .and_then(|value| Pid::new(value).ok()),
        effective_uid: Uid::new(info.pbi_uid),
        real_uid: Uid::new(info.pbi_ruid),
        start_time,
        zombie: info.pbi_status == libc::SZOMB,
    })
}

fn executable_path(pid: Pid) -> Result<LosslessPath, QueryFailure> {
    const CAPACITY: usize = 4096;
    const _: () = assert!(CAPACITY == libc::PROC_PIDPATHINFO_MAXSIZE as usize);
    let mut buffer: [u8; CAPACITY] = [0; CAPACITY];
    let capacity: u32 = u32::try_from(CAPACITY).map_err(|_| QueryFailure::Overflow)?;
    // SAFETY: `buffer` is a live, writable array of `capacity` bytes. The
    // kernel writes at most `capacity` bytes into it.
    let length: c_int =
        unsafe { libc::proc_pidpath(pid.get(), buffer.as_mut_ptr().cast::<c_void>(), capacity) };
    if length <= 0 {
        return Err(last_failure());
    }
    let length: usize = usize::try_from(length).map_err(|_| QueryFailure::Inconsistent)?;
    let bytes: &[u8] = buffer.get(..length).ok_or(QueryFailure::Inconsistent)?;
    LosslessPath::from_bytes(bytes).map_err(|_| QueryFailure::Inconsistent)
}

fn file_evidence(path: &LosslessPath) -> Result<FileObjectEvidence, QueryFailure> {
    let metadata: std::fs::Metadata =
        std::fs::metadata(path.to_path_buf()).map_err(|error| match error.kind() {
            std::io::ErrorKind::NotFound => QueryFailure::Gone,
            std::io::ErrorKind::PermissionDenied => QueryFailure::PermissionDenied,
            _ => QueryFailure::Failed(error.raw_os_error().unwrap_or(0)),
        })?;
    // The standard library widens the signed 32-bit `dev_t` to `u64`. The
    // low 32 bits are the native value.
    let device_bits: u32 = u32::try_from(metadata.dev() & u64::from(u32::MAX))
        .map_err(|_| QueryFailure::Inconsistent)?;
    Ok(FileObjectEvidence {
        device: DeviceNumber::new(device_bits.cast_signed()),
        inode: InodeNumber::new(metadata.ino()),
    })
}

fn usage(pid: Pid) -> Result<RawUsage, QueryFailure> {
    let mut info: MaybeUninit<libc::rusage_info_v4> = MaybeUninit::zeroed();
    // SAFETY: `info` is a live, writable `rusage_info_v4`. For the flavor
    // `RUSAGE_INFO_V4` the kernel writes one structure of that type. The
    // pointer cast follows the C prototype, which declares the buffer as
    // `rusage_info_t *`.
    let status: c_int = unsafe {
        libc::proc_pid_rusage(
            pid.get(),
            libc::RUSAGE_INFO_V4,
            info.as_mut_ptr().cast::<libc::rusage_info_t>(),
        )
    };
    if status != 0 {
        return Err(last_failure());
    }
    // SAFETY: the call succeeded, so the kernel wrote the structure. Each
    // field is an integer or an array of integers, so each bit pattern is a
    // valid value.
    let info: libc::rusage_info_v4 = unsafe { info.assume_init() };
    Ok(RawUsage {
        physical_footprint: info.ri_phys_footprint,
        resident_size: info.ri_resident_size,
        lifetime_max_physical_footprint: info.ri_lifetime_max_phys_footprint,
        user_time_mach: info.ri_user_time,
        system_time_mach: info.ri_system_time,
        disk_bytes_read: info.ri_diskio_bytesread,
        disk_bytes_written: info.ri_diskio_byteswritten,
    })
}

/// The C signature of `responsibility_get_pid_responsible_for_pid`.
type ResponsiblePidFn = unsafe extern "C" fn(libc::pid_t) -> libc::pid_t;

fn responsible_pid(pid: Pid) -> Result<Pid, QueryFailure> {
    const SYMBOL: &CStr = c"responsibility_get_pid_responsible_for_pid";
    // SAFETY: `SYMBOL` is a NUL-terminated string that lives for the call.
    // `RTLD_DEFAULT` searches the images that the process loaded.
    let address: *mut c_void = unsafe { libc::dlsym(libc::RTLD_DEFAULT, SYMBOL.as_ptr()) };
    if address.is_null() {
        return Err(QueryFailure::Unsupported);
    }
    // SAFETY: the address is not null and is the address of the system
    // function with this name, which has the C signature
    // `pid_t (pid_t)`. A function pointer and a data pointer have the same
    // size on each Darwin target.
    let function: ResponsiblePidFn =
        unsafe { std::mem::transmute::<*mut c_void, ResponsiblePidFn>(address) };
    // The function has no documented `errno` contract. Clear the value, so
    // that a failure does not get the `errno` of an earlier call.
    // SAFETY: `__error` has no argument and returns the address of the
    // `errno` of this thread.
    let errno: *mut c_int = unsafe { libc::__error() };
    // SAFETY: the address is valid for a write for the life of this thread,
    // and no reference to the value exists.
    unsafe { *errno = 0 };
    // SAFETY: the function takes a PID by value and keeps no pointer.
    let responsible: libc::pid_t = unsafe { function(pid.get()) };
    if responsible < 0 {
        return Err(match last_failure() {
            QueryFailure::Failed(0) => QueryFailure::Inconsistent,
            failure => failure,
        });
    }
    Pid::new(responsible).map_err(|_| QueryFailure::Inconsistent)
}

fn running_applications() -> Vec<RunningApplication> {
    autoreleasepool(|_| {
        NSWorkspace::sharedWorkspace()
            .runningApplications()
            .iter()
            .filter_map(|application| {
                let pid: Pid = Pid::new(application.processIdentifier()).ok()?;
                Some(RunningApplication {
                    pid,
                    bundle_identifier: application
                        .bundleIdentifier()
                        .map(|identifier| identifier.to_string()),
                    executable_path: application
                        .executableURL()
                        .and_then(|url| url.path())
                        .and_then(|path| LosslessPath::from_bytes(path.to_string()).ok()),
                    active: application.isActive(),
                    terminated: application.isTerminated(),
                })
            })
            .collect()
    })
}

/// The C layout of `struct mach_timebase_info`.
#[repr(C)]
struct MachTimebaseInfo {
    numerator: u32,
    denominator: u32,
}

// `libc` marks its declaration of this function as deprecated and directs
// to the `mach2` crate, which is not a workspace dependency.
unsafe extern "C" {
    /// `kern_return_t mach_timebase_info(mach_timebase_info_t info)`.
    fn mach_timebase_info(info: *mut MachTimebaseInfo) -> c_int;
}

fn timebase() -> Result<Timebase, QueryFailure> {
    let mut info: MachTimebaseInfo = MachTimebaseInfo {
        numerator: 0,
        denominator: 0,
    };
    // SAFETY: `info` is a live, writable structure with the C layout of
    // `struct mach_timebase_info`. The kernel writes the two terms into it.
    let status: c_int = unsafe { mach_timebase_info(&raw mut info) };
    if status != 0 {
        return Err(QueryFailure::Failed(status));
    }
    Timebase::new(info.numerator, info.denominator).ok_or(QueryFailure::Inconsistent)
}

fn monotonic_now() -> Result<MonotonicNanos, QueryFailure> {
    let mut time: libc::timespec = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `time` is a live, writable `timespec`. The kernel writes the
    // clock value into it.
    let status: c_int = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC_RAW, &raw mut time) };
    if status != 0 {
        return Err(last_failure());
    }
    let seconds: u64 = u64::try_from(time.tv_sec).map_err(|_| QueryFailure::Inconsistent)?;
    let nanoseconds: u64 = u64::try_from(time.tv_nsec).map_err(|_| QueryFailure::Inconsistent)?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|whole| whole.checked_add(nanoseconds))
        .map(MonotonicNanos::new)
        .ok_or(QueryFailure::Overflow)
}

/// The identifier of the current boot session, from `kern.bootsessionuuid`.
///
/// # Errors
///
/// Returns a [`QueryFailure`] when the kernel gives no value or the value is
/// not text.
pub(super) fn boot_session_uuid() -> Result<String, QueryFailure> {
    const NAME: &CStr = c"kern.bootsessionuuid";
    let mut buffer: [u8; 64] = [0; 64];
    let mut length: libc::size_t = buffer.len();
    // SAFETY: `NAME` is a NUL-terminated string. `buffer` is a live,
    // writable array and `length` holds its size, so the kernel writes at
    // most that number of bytes. The call sets no new value.
    let status: c_int = unsafe {
        libc::sysctlbyname(
            NAME.as_ptr(),
            buffer.as_mut_ptr().cast::<c_void>(),
            &raw mut length,
            std::ptr::null_mut(),
            0,
        )
    };
    if status != 0 {
        return Err(last_failure());
    }
    let written: &[u8] = buffer.get(..length).ok_or(QueryFailure::Inconsistent)?;
    let text: &CStr =
        CStr::from_bytes_until_nul(written).map_err(|_| QueryFailure::Inconsistent)?;
    let text: &str = text.to_str().map_err(|_| QueryFailure::Inconsistent)?;
    if text.is_empty() {
        return Err(QueryFailure::Inconsistent);
    }
    Ok(text.to_owned())
}

impl ProcessSource for DarwinProcessSource {
    fn effective_uid(&self) -> Uid {
        // SAFETY: `geteuid` has no argument, cannot fail, and changes no
        // state.
        Uid::new(unsafe { libc::geteuid() })
    }

    fn list_pids(&self) -> Result<Vec<Pid>, QueryFailure> {
        list_pids()
    }

    fn process_info(&self, pid: Pid) -> Result<RawProcessInfo, QueryFailure> {
        process_info(pid)
    }

    fn executable_path(&self, pid: Pid) -> Result<LosslessPath, QueryFailure> {
        executable_path(pid)
    }

    fn file_evidence(&self, path: &LosslessPath) -> Result<FileObjectEvidence, QueryFailure> {
        file_evidence(path)
    }

    fn usage(&self, pid: Pid) -> Result<RawUsage, QueryFailure> {
        usage(pid)
    }

    fn responsible_pid(&self, pid: Pid) -> Result<Pid, QueryFailure> {
        responsible_pid(pid)
    }

    fn application_list_current(&self) -> bool {
        // The first call in the process reads a fresh list. After it, the
        // list is refreshed only when the main run loop runs, and this source
        // has no evidence of that, so a later list is not known to be
        // current.
        // TODO(npochaev): report a later list as current when the host process
        // runs the main run loop.
        FIRST_APPLICATION_LIST.swap(false, Ordering::Relaxed)
    }

    fn running_applications(&self) -> Result<Vec<RunningApplication>, QueryFailure> {
        Ok(running_applications())
    }

    fn timebase(&self) -> Result<Timebase, QueryFailure> {
        timebase()
    }

    fn monotonic_now(&self) -> Result<MonotonicNanos, QueryFailure> {
        monotonic_now()
    }

    fn sleep_time(&self) -> Result<Nanoseconds, UnavailableReason> {
        crate::platform::sleep::native_sleep_time()
    }

    fn wall_now(&self) -> Result<WallTime, QueryFailure> {
        WallTime::try_from(SystemTime::now()).map_err(|_| QueryFailure::Inconsistent)
    }
}
