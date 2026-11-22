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
//! | Working directory | `proc_pidinfo(PROC_PIDVNODEPATHINFO)`, field `pvi_cdir.vip_path` |
//! | File descriptors | `proc_pidinfo(PROC_PIDLISTFDS)` |
//! | Socket of a descriptor | `proc_pidfdinfo(PROC_PIDFDSOCKETINFO)` |
//! | File of a descriptor | `proc_pidfdinfo(PROC_PIDFDVNODEPATHINFO)` |
//! | Mapped files | `proc_pidinfo(PROC_PIDREGIONPATHINFO2)`, confirmed with `PROC_PIDREGIONPATHINFO`, one region per call |
//! | Arguments | `sysctl(CTL_KERN, KERN_PROCARGS2)`; the environment is not read |
//! | Apple platform code | `SecCodeCopyGuestWithAttributes(kSecGuestAttributePid)`, `SecCodeCheckValidity` with `anchor apple`, `kSecCodeInfoPlatformIdentifier` |
//! | Owner of a denied process | `proc_pidinfo(PROC_PIDT_SHORTBSDINFO)` |
//!
//! `responsibility_get_pid_responsible_for_pid` is not in the public SDK.
//! The adapter finds it with `dlsym` at run time. When the symbol is absent,
//! the query is [`QueryFailure::Unsupported`] and no process gets a
//! `responsible_process` attribution.

use std::ffi::{CStr, c_int, c_void};
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::MetadataExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::SystemTime;

/// Whether the next application list is the first one of the process.
static FIRST_APPLICATION_LIST: AtomicBool = AtomicBool::new(true);

use objc2::rc::autoreleasepool;
use objc2_core_foundation::{CFDictionary, CFNumber, CFRetained, CFString, CFType};

use crate::platform::run_loop;
use objc2_app_kit::NSWorkspace;
use svalnir_core::file::{DeviceNumber, FileObjectEvidence, InodeNumber, LosslessPath};
use svalnir_core::observation::UnavailableReason;
use svalnir_core::process::{Pid, ProcessStartTime, Uid};
use svalnir_core::quantity::Nanoseconds;
use svalnir_core::time::{MonotonicNanos, WallTime};

use super::source::{
    ProcessSource, QueryFailure, RawArguments, RawListeningSocket, RawListeningSockets, RawPaths,
    RawProcessInfo, RawUsage, RawVnode, RunningApplication, SocketFamily, Timebase, VnodeObject,
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
        Some(libc::EPERM) => QueryFailure::PermissionDenied,
        Some(libc::EACCES) => QueryFailure::AccessDenied,
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

/// The capacity of `vip_path`: `MAXPATHLEN` in `<sys/param.h>`.
const VNODE_PATH_CAPACITY: usize = 1024;

// `libc::proc_vnodepathinfo` must have the size and the field offset of
// `struct proc_vnodepathinfo` in `<sys/proc_info.h>` of the macOS SDK. The
// values were measured with `sizeof` and `offsetof` against that header.
const _: () = assert!(size_of::<libc::proc_vnodepathinfo>() == 2352);
const _: () = assert!(
    std::mem::offset_of!(libc::proc_vnodepathinfo, pvi_cdir)
        + std::mem::offset_of!(libc::vnode_info_path, vip_path)
        == 152
);
const _: () = assert!(size_of::<[[libc::c_char; 32]; 32]>() == VNODE_PATH_CAPACITY);

fn working_directory(pid: Pid) -> Result<LosslessPath, QueryFailure> {
    let mut info: MaybeUninit<libc::proc_vnodepathinfo> = MaybeUninit::zeroed();
    let size: c_int = c_int::try_from(size_of::<libc::proc_vnodepathinfo>())
        .map_err(|_| QueryFailure::Overflow)?;
    // SAFETY: `info` is a live, writable `proc_vnodepathinfo` of `size`
    // bytes. The kernel writes at most `size` bytes for
    // `PROC_PIDVNODEPATHINFO`.
    let written: c_int = unsafe {
        libc::proc_pidinfo(
            pid.get(),
            libc::PROC_PIDVNODEPATHINFO,
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
    // SAFETY: the kernel wrote the full structure, and the buffer was zeroed
    // before. Each field is an integer or an array of integers, so each bit
    // pattern is a valid value.
    let info: libc::proc_vnodepathinfo = unsafe { info.assume_init() };
    let bytes: Vec<u8> = info
        .pvi_cdir
        .vip_path
        .as_flattened()
        .iter()
        .map(|byte| byte.cast_unsigned())
        .collect();
    // The path ends at the first NUL. A path with no NUL in the buffer is
    // not complete.
    let end: usize = bytes
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(QueryFailure::Inconsistent)?;
    let path: &[u8] = bytes.get(..end).ok_or(QueryFailure::Inconsistent)?;
    if path.first() != Some(&b'/') {
        // An empty or relative path is not a working directory.
        return Err(QueryFailure::Inconsistent);
    }
    LosslessPath::from_bytes(path).map_err(|_| QueryFailure::Inconsistent)
}

/// The working directory of `pid` with the identity of its vnode.
fn working_directory_vnode(pid: Pid) -> Result<RawVnode, QueryFailure> {
    let path: LosslessPath = working_directory(pid)?;
    let mut info: MaybeUninit<libc::proc_vnodepathinfo> = MaybeUninit::zeroed();
    let size: c_int = c_int::try_from(size_of::<libc::proc_vnodepathinfo>())
        .map_err(|_| QueryFailure::Overflow)?;
    // SAFETY: as in `working_directory`.
    let written: c_int = unsafe {
        libc::proc_pidinfo(
            pid.get(),
            libc::PROC_PIDVNODEPATHINFO,
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
    // SAFETY: as in `working_directory`.
    let info: libc::proc_vnodepathinfo = unsafe { info.assume_init() };
    let stat: libc::vinfo_stat = info.pvi_cdir.vip_vi.vi_stat;
    let bytes: Vec<u8> = info
        .pvi_cdir
        .vip_path
        .as_flattened()
        .iter()
        .map(|byte| byte.cast_unsigned())
        .collect();
    // The two readings must name one path; a different path is a change
    // of the working directory between them.
    let end: usize = bytes
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(QueryFailure::Inconsistent)?;
    if bytes.get(..end) != Some(path.as_bytes()) {
        return Err(QueryFailure::Inconsistent);
    }
    Ok(RawVnode {
        path: Some(path),
        vnode: VnodeObject {
            object: FileObjectEvidence {
                device: DeviceNumber::new(stat.vst_dev.cast_signed()),
                inode: InodeNumber::new(stat.vst_ino),
            },
            links: stat.vst_nlink,
        },
    })
}

/// `PROC_PIDFDSOCKETINFO` in `<sys/proc_info.h>`.
const PROC_PIDFDSOCKETINFO: c_int = 3;

/// `sizeof(struct socket_fdinfo)` in `<sys/proc_info.h>` of the macOS SDK.
const SOCKET_FDINFO_SIZE: usize = 792;

/// The offsets in `struct socket_fdinfo` that the adapter reads. The values
/// were measured with `offsetof` against `<sys/proc_info.h>` of the macOS
/// SDK. The adapter reads no other field, so it reads no remote address.
mod socket_offsets {
    /// `psi.soi_family`, an `int`.
    pub(super) const FAMILY: usize = 184;
    /// `psi.soi_kind`, an `int`.
    pub(super) const KIND: usize = 256;
    /// `psi.soi_proto.pri_tcp.tcpsi_ini.insi_lport`, an `int` that holds the
    /// port in network byte order.
    pub(super) const LOCAL_PORT: usize = 268;
    /// `psi.soi_proto.pri_tcp.tcpsi_ini.insi_vflag`, a `uint8_t`.
    pub(super) const VERSION_FLAGS: usize = 288;
    /// `psi.soi_proto.pri_tcp.tcpsi_ini.insi_laddr`, 16 bytes. An IPv4
    /// address is the last 4 bytes (`struct in4in6_addr`).
    pub(super) const LOCAL_ADDRESS: usize = 312;
    /// `psi.soi_proto.pri_tcp.tcpsi_state`, an `int`.
    pub(super) const TCP_STATE: usize = 344;
}

/// `SOCKINFO_TCP` in `<sys/proc_info.h>`.
const SOCKINFO_TCP: i32 = 2;
/// `TSI_S_LISTEN` in `<sys/proc_info.h>`.
const TSI_S_LISTEN: i32 = 1;
/// `INI_IPV4` in `<sys/proc_info.h>`.
const INI_IPV4: u8 = 0x1;
/// `INI_IPV6` in `<sys/proc_info.h>`.
const INI_IPV6: u8 = 0x2;

/// A buffer with the size and the alignment of `struct socket_fdinfo`. The
/// kernel writes the structure as bytes, and [`parse_listening_socket`]
/// reads the fields at their offsets, so no field is read through a type.
#[repr(C, align(8))]
pub(super) struct SocketFdInfoBytes(pub(super) [u8; SOCKET_FDINFO_SIZE]);

fn read_i32(bytes: &[u8], offset: usize) -> Result<i32, QueryFailure> {
    let field: [u8; 4] = bytes
        .get(offset..offset.saturating_add(4))
        .and_then(|slice| slice.try_into().ok())
        .ok_or(QueryFailure::Inconsistent)?;
    Ok(i32::from_ne_bytes(field))
}

/// The listening TCP socket of one `struct socket_fdinfo`, or `None` for a
/// socket that is not a TCP socket of the Internet families in the
/// listening state.
pub(super) fn parse_listening_socket(
    info: &SocketFdInfoBytes,
) -> Result<Option<RawListeningSocket>, QueryFailure> {
    let bytes: &[u8] = &info.0;
    if read_i32(bytes, socket_offsets::KIND)? != SOCKINFO_TCP {
        return Ok(None);
    }
    let family: SocketFamily = match read_i32(bytes, socket_offsets::FAMILY)? {
        libc::AF_INET => SocketFamily::Ipv4,
        libc::AF_INET6 => SocketFamily::Ipv6,
        _ => return Ok(None),
    };
    if read_i32(bytes, socket_offsets::TCP_STATE)? != TSI_S_LISTEN {
        return Ok(None);
    }
    let raw_port: u16 = u16::try_from(read_i32(bytes, socket_offsets::LOCAL_PORT)?)
        .map_err(|_| QueryFailure::Inconsistent)?;
    let port: u16 = u16::from_be(raw_port);
    let flags: u8 = *bytes
        .get(socket_offsets::VERSION_FLAGS)
        .ok_or(QueryFailure::Inconsistent)?;
    let address: [u8; 16] = bytes
        .get(socket_offsets::LOCAL_ADDRESS..socket_offsets::LOCAL_ADDRESS + 16)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(QueryFailure::Inconsistent)?;
    let [.., a, b, c, d] = address;
    let ipv4: Ipv4Addr = Ipv4Addr::new(a, b, c, d);
    let address: IpAddr = match family {
        SocketFamily::Ipv4 => IpAddr::V4(ipv4),
        SocketFamily::Ipv6 if flags & INI_IPV6 != 0 => IpAddr::V6(Ipv6Addr::from(address)),
        // An IPv6 socket with an IPv4 address keeps its family: the address
        // is the IPv4-mapped IPv6 address.
        SocketFamily::Ipv6 if flags & INI_IPV4 != 0 => IpAddr::V6(ipv4.to_ipv6_mapped()),
        SocketFamily::Ipv6 => return Err(QueryFailure::Inconsistent),
    };
    Ok(Some(RawListeningSocket {
        family,
        address,
        port,
    }))
}

/// The socket of one descriptor, or `None` when the descriptor was closed
/// after the list was read.
fn socket_of_descriptor(
    pid: Pid,
    descriptor: i32,
) -> Result<Option<RawListeningSocket>, QueryFailure> {
    let mut info: SocketFdInfoBytes = SocketFdInfoBytes([0; SOCKET_FDINFO_SIZE]);
    let size: c_int = c_int::try_from(SOCKET_FDINFO_SIZE).map_err(|_| QueryFailure::Overflow)?;
    // SAFETY: `info` is a live, writable buffer of `size` bytes with the
    // alignment of `struct socket_fdinfo`. The kernel writes at most `size`
    // bytes for `PROC_PIDFDSOCKETINFO`.
    let written: c_int = unsafe {
        libc::proc_pidfdinfo(
            pid.get(),
            descriptor,
            PROC_PIDFDSOCKETINFO,
            info.0.as_mut_ptr().cast::<c_void>(),
            size,
        )
    };
    if written <= 0 {
        return match std::io::Error::last_os_error().raw_os_error() {
            // The descriptor was closed, or it is no longer a socket.
            Some(libc::EBADF | libc::ENOTSUP | libc::EINVAL) => Ok(None),
            _ => Err(last_failure()),
        };
    }
    if written != size {
        return Err(QueryFailure::Inconsistent);
    }
    parse_listening_socket(&info)
}

/// The open file descriptors of `pid`, at most `max_descriptors` of them,
/// and whether the process has more.
fn list_descriptors(
    pid: Pid,
    max_descriptors: usize,
) -> Result<(Vec<libc::proc_fdinfo>, bool), QueryFailure> {
    if max_descriptors == 0 {
        return Err(QueryFailure::Inconsistent);
    }
    // One more entry than the ceiling shows whether the ceiling was reached.
    let capacity: usize = max_descriptors.saturating_add(1);
    let entry: libc::proc_fdinfo = libc::proc_fdinfo {
        proc_fd: 0,
        proc_fdtype: 0,
    };
    let mut descriptors: Vec<libc::proc_fdinfo> = vec![entry; capacity];
    let byte_size: c_int = c_int::try_from(capacity.saturating_mul(size_of::<libc::proc_fdinfo>()))
        .map_err(|_| QueryFailure::Overflow)?;
    // `proc_pidinfo` gives 0 both for a failure and for a process with no
    // open descriptor. A zero `errno` before the call tells the two apart.
    // SAFETY: `__error` has no argument and gives the address of the
    // `errno` of the calling thread.
    let errno: *mut c_int = unsafe { libc::__error() };
    // SAFETY: the address is valid and aligned for the life of the calling
    // thread, and only this thread writes it.
    unsafe { errno.write(0) };
    // SAFETY: `descriptors` is a live allocation of `byte_size` bytes with
    // the alignment of `proc_fdinfo`. The kernel writes at most `byte_size`
    // bytes of `proc_fdinfo` records into it.
    let written: c_int = unsafe {
        libc::proc_pidinfo(
            pid.get(),
            libc::PROC_PIDLISTFDS,
            0,
            descriptors.as_mut_ptr().cast::<c_void>(),
            byte_size,
        )
    };
    if written == 0
        && matches!(
            std::io::Error::last_os_error().raw_os_error(),
            None | Some(0)
        )
    {
        return Ok((Vec::new(), false));
    }
    if written <= 0 {
        return Err(last_failure());
    }
    let written: usize = usize::try_from(written).map_err(|_| QueryFailure::Inconsistent)?;
    if !written.is_multiple_of(size_of::<libc::proc_fdinfo>()) {
        return Err(QueryFailure::Inconsistent);
    }
    let count: usize = written / size_of::<libc::proc_fdinfo>();
    if count > capacity {
        return Err(QueryFailure::Inconsistent);
    }
    descriptors.truncate(count.min(max_descriptors));
    Ok((descriptors, count > max_descriptors))
}

fn listening_tcp_sockets(
    pid: Pid,
    max_descriptors: usize,
) -> Result<RawListeningSockets, QueryFailure> {
    let (descriptors, descriptors_truncated) = list_descriptors(pid, max_descriptors)?;
    let mut sockets: Vec<RawListeningSocket> = Vec::new();
    for descriptor in &descriptors {
        if descriptor.proc_fdtype != libc::PROX_FDTYPE_SOCKET.cast_unsigned() {
            continue;
        }
        if let Some(socket) = socket_of_descriptor(pid, descriptor.proc_fd)? {
            sockets.push(socket);
        }
    }
    Ok(RawListeningSockets {
        sockets,
        descriptors_truncated,
    })
}

/// `PROC_PIDFDVNODEPATHINFO` in `<sys/proc_info.h>`.
const PROC_PIDFDVNODEPATHINFO: c_int = 2;
/// `PROC_PIDREGIONPATHINFO` in `<sys/proc_info.h>`.
const PROC_PIDREGIONPATHINFO: c_int = 8;
/// `PROC_PIDREGIONPATHINFO2` of the kernel source (`bsd/sys/proc_info.h`
/// of XNU): the next region that maps a vnode. The public SDK header does
/// not declare it. Its result has the layout of `PROC_PIDREGIONPATHINFO`.
const PROC_PIDREGIONPATHINFO2: c_int = 22;
/// `sizeof(struct vnode_fdinfowithpath)` in `<sys/proc_info.h>`.
const VNODE_FDINFOWITHPATH_SIZE: usize = 1200;
/// `offsetof(struct vnode_fdinfowithpath, pvip.vip_path)`.
const VNODE_FDINFOWITHPATH_PATH: usize = 176;
/// `offsetof(struct vnode_fdinfowithpath, pvip.vip_vi.vi_stat)`.
const VNODE_FDINFOWITHPATH_INFO: usize = 24;
/// `sizeof(struct proc_regionwithpathinfo)` in `<sys/proc_info.h>`.
const REGIONWITHPATHINFO_SIZE: usize = 1272;
/// `offsetof(struct proc_regionwithpathinfo, prp_prinfo.pri_address)`, a
/// `uint64_t`.
const REGION_ADDRESS: usize = 80;
/// `offsetof(struct proc_regionwithpathinfo, prp_prinfo.pri_size)`, a
/// `uint64_t`.
const REGION_SIZE: usize = 88;
/// `offsetof(struct proc_regionwithpathinfo, prp_vip.vip_path)`.
const REGIONWITHPATHINFO_PATH: usize = 248;
/// `offsetof(struct proc_regionwithpathinfo, prp_vip.vip_vi.vi_stat)`.
const REGIONWITHPATHINFO_INFO: usize = 96;

// The sizes and offsets above were measured with `sizeof` and `offsetof`
// against `<sys/proc_info.h>` of the macOS SDK. Each path field is a
// `vip_path` of `MAXPATHLEN` bytes, and each one ends inside its structure.
const _: () = assert!(VNODE_FDINFOWITHPATH_PATH + VNODE_PATH_CAPACITY <= VNODE_FDINFOWITHPATH_SIZE);
const _: () = assert!(REGIONWITHPATHINFO_PATH + VNODE_PATH_CAPACITY <= REGIONWITHPATHINFO_SIZE);
const _: () = assert!(REGION_SIZE + 8 <= REGIONWITHPATHINFO_INFO);
const _: () = assert!(REGIONWITHPATHINFO_INFO + VST_INO + 8 <= REGIONWITHPATHINFO_PATH);
const _: () = assert!(VNODE_FDINFOWITHPATH_INFO + VST_INO + 8 <= VNODE_FDINFOWITHPATH_PATH);
// `libc::vinfo_stat` has the field offsets that the byte reads use.
const _: () = assert!(std::mem::offset_of!(libc::vinfo_stat, vst_dev) == VST_DEV);
const _: () = assert!(std::mem::offset_of!(libc::vinfo_stat, vst_nlink) == VST_NLINK);
const _: () = assert!(std::mem::offset_of!(libc::vinfo_stat, vst_ino) == VST_INO);
const _: () = assert!(libc::PROX_FDTYPE_VNODE == 1);
const _: () = assert!(libc::KERN_PROCARGS2 == 49);
const _: () = assert!(libc::MAXPATHLEN as usize == VNODE_PATH_CAPACITY);

/// A buffer with the size and the alignment of `struct
/// vnode_fdinfowithpath`. The fields are read at their offsets.
#[repr(C, align(8))]
struct FdVnodeBytes([u8; VNODE_FDINFOWITHPATH_SIZE]);

/// A buffer with the size and the alignment of `struct
/// proc_regionwithpathinfo`. The fields are read at their offsets.
#[repr(C, align(8))]
struct RegionBytes([u8; REGIONWITHPATHINFO_SIZE]);

/// The NUL-terminated absolute path of the `vip_path` field at `offset` of
/// `bytes`. An empty path is `None`: the kernel gave no path for the vnode.
pub(super) fn vnode_path_at(
    bytes: &[u8],
    offset: usize,
) -> Result<Option<LosslessPath>, QueryFailure> {
    let field: &[u8] = bytes
        .get(offset..offset.saturating_add(VNODE_PATH_CAPACITY))
        .ok_or(QueryFailure::Inconsistent)?;
    let end: usize = field
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(QueryFailure::Inconsistent)?;
    let path: &[u8] = field.get(..end).ok_or(QueryFailure::Inconsistent)?;
    if path.is_empty() {
        return Ok(None);
    }
    if path.first() != Some(&b'/') {
        return Err(QueryFailure::Inconsistent);
    }
    LosslessPath::from_bytes(path)
        .map(Some)
        .map_err(|_| QueryFailure::Inconsistent)
}

/// The offsets of `vst_dev` (`uint32_t`), `vst_nlink` (`uint16_t`), and
/// `vst_ino` (`uint64_t`) of `vip_vi.vi_stat`, relative to the start of the
/// `struct vnode_info_path`, measured against `<sys/proc_info.h>`.
const VST_DEV: usize = 0;
const VST_NLINK: usize = 6;
const VST_INO: usize = 8;

/// The vnode identity of the `struct vnode_info_path` at `info` of `bytes`,
/// with the path at `path`. `None` for an identity of zeros, which the
/// kernel gives for a region that maps no vnode.
pub(super) fn vnode_at(
    bytes: &[u8],
    info: usize,
    path: usize,
) -> Result<Option<RawVnode>, QueryFailure> {
    let device: u32 = read_u32(bytes, info + VST_DEV)?;
    let links: [u8; 2] = bytes
        .get(info + VST_NLINK..info + VST_NLINK + 2)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(QueryFailure::Inconsistent)?;
    let inode: u64 = read_u64(bytes, info + VST_INO)?;
    let path: Option<LosslessPath> = vnode_path_at(bytes, path)?;
    if device == 0 && inode == 0 && path.is_none() {
        return Ok(None);
    }
    Ok(Some(RawVnode {
        path,
        vnode: VnodeObject {
            object: FileObjectEvidence {
                device: DeviceNumber::new(device.cast_signed()),
                inode: InodeNumber::new(inode),
            },
            links: u16::from_ne_bytes(links),
        },
    }))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, QueryFailure> {
    let field: [u8; 4] = bytes
        .get(offset..offset.saturating_add(4))
        .and_then(|slice| slice.try_into().ok())
        .ok_or(QueryFailure::Inconsistent)?;
    Ok(u32::from_ne_bytes(field))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, QueryFailure> {
    let field: [u8; 8] = bytes
        .get(offset..offset.saturating_add(8))
        .and_then(|slice| slice.try_into().ok())
        .ok_or(QueryFailure::Inconsistent)?;
    Ok(u64::from_ne_bytes(field))
}

/// Adds `vnode` to `vnodes` when it is not there.
fn push_unique(vnodes: &mut Vec<RawVnode>, vnode: RawVnode) {
    if !vnodes.contains(&vnode) {
        vnodes.push(vnode);
    }
}

/// The vnode of one descriptor, or `None` when the descriptor closed after
/// the list was read.
fn vnode_of_descriptor(pid: Pid, descriptor: i32) -> Result<Option<RawVnode>, QueryFailure> {
    let mut info: FdVnodeBytes = FdVnodeBytes([0; VNODE_FDINFOWITHPATH_SIZE]);
    let size: c_int =
        c_int::try_from(VNODE_FDINFOWITHPATH_SIZE).map_err(|_| QueryFailure::Overflow)?;
    // SAFETY: `info` is a live, writable buffer of `size` bytes with the
    // alignment of `struct vnode_fdinfowithpath`. The kernel writes at most
    // `size` bytes for `PROC_PIDFDVNODEPATHINFO`.
    let written: c_int = unsafe {
        libc::proc_pidfdinfo(
            pid.get(),
            descriptor,
            PROC_PIDFDVNODEPATHINFO,
            info.0.as_mut_ptr().cast::<c_void>(),
            size,
        )
    };
    if written <= 0 {
        return match std::io::Error::last_os_error().raw_os_error() {
            // The descriptor closed, or it is no longer a vnode.
            Some(libc::EBADF | libc::ENOTSUP | libc::EINVAL | libc::ENOENT) => Ok(None),
            _ => Err(last_failure()),
        };
    }
    if written != size {
        return Err(QueryFailure::Inconsistent);
    }
    vnode_at(
        &info.0,
        VNODE_FDINFOWITHPATH_INFO,
        VNODE_FDINFOWITHPATH_PATH,
    )
}

fn open_file_paths(pid: Pid, max_descriptors: usize) -> Result<RawPaths, QueryFailure> {
    let (descriptors, truncated) = list_descriptors(pid, max_descriptors)?;
    let mut paths: Vec<RawVnode> = Vec::new();
    for descriptor in &descriptors {
        if descriptor.proc_fdtype != libc::PROX_FDTYPE_VNODE.cast_unsigned() {
            continue;
        }
        if let Some(vnode) = vnode_of_descriptor(pid, descriptor.proc_fd)? {
            push_unique(&mut paths, vnode);
        }
    }
    Ok(RawPaths { paths, truncated })
}

fn mapped_file_paths_flavor(
    pid: Pid,
    max_regions: usize,
    flavor: c_int,
) -> Result<RawPaths, QueryFailure> {
    let size: c_int =
        c_int::try_from(REGIONWITHPATHINFO_SIZE).map_err(|_| QueryFailure::Overflow)?;
    let mut paths: Vec<RawVnode> = Vec::new();
    let mut address: u64 = 0;
    for _ in 0..max_regions {
        let mut info: RegionBytes = RegionBytes([0; REGIONWITHPATHINFO_SIZE]);
        // SAFETY: `info` is a live, writable buffer of `size` bytes with the
        // alignment of `struct proc_regionwithpathinfo`. The kernel writes at
        // most `size` bytes for `PROC_PIDREGIONPATHINFO`. The argument is the
        // address from which the kernel looks for the next region.
        let written: c_int = unsafe {
            libc::proc_pidinfo(
                pid.get(),
                flavor,
                address,
                info.0.as_mut_ptr().cast::<c_void>(),
                size,
            )
        };
        if written <= 0 {
            return match std::io::Error::last_os_error().raw_os_error() {
                // No region is at or after the address: the list is at its
                // end.
                Some(libc::EINVAL) => Ok(RawPaths {
                    paths,
                    truncated: false,
                }),
                _ => Err(last_failure()),
            };
        }
        if written != size {
            return Err(QueryFailure::Inconsistent);
        }
        if let Some(vnode) = vnode_at(&info.0, REGIONWITHPATHINFO_INFO, REGIONWITHPATHINFO_PATH)? {
            push_unique(&mut paths, vnode);
        }
        let start: u64 = read_u64(&info.0, REGION_ADDRESS)?;
        let length: u64 = read_u64(&info.0, REGION_SIZE)?;
        let Some(next) = start.checked_add(length) else {
            // The region ends at the top of the address space.
            return Ok(RawPaths {
                paths,
                truncated: false,
            });
        };
        if next <= address {
            return Err(QueryFailure::Inconsistent);
        }
        address = next;
    }
    Ok(RawPaths {
        paths,
        truncated: true,
    })
}

/// The arguments in a `KERN_PROCARGS2` buffer: an `int` count, the
/// executable path, NUL padding, and the count of NUL-terminated arguments.
/// The environment after the arguments is not read. `complete` is false
/// when the buffer has fewer arguments than the count.
pub(super) fn parse_procargs(buffer: &[u8], complete: bool) -> Result<RawArguments, QueryFailure> {
    let count: [u8; 4] = buffer
        .get(..4)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(QueryFailure::Inconsistent)?;
    let count: usize =
        usize::try_from(i32::from_ne_bytes(count)).map_err(|_| QueryFailure::Inconsistent)?;
    let rest: &[u8] = buffer.get(4..).unwrap_or_default();
    // The executable path, then the padding.
    let after_path: usize = rest
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(rest.len());
    let mut position: usize = after_path;
    while rest.get(position) == Some(&0) {
        position += 1;
    }
    let mut values: Vec<Vec<u8>> = Vec::with_capacity(count.min(4096));
    while values.len() < count {
        let Some(tail) = rest.get(position..).filter(|tail| !tail.is_empty()) else {
            break;
        };
        let Some(end) = tail.iter().position(|byte| *byte == 0) else {
            break;
        };
        values.push(tail.get(..end).unwrap_or_default().to_vec());
        position += end + 1;
    }
    let truncated: bool = values.len() < count;
    if truncated && complete {
        return Err(QueryFailure::Inconsistent);
    }
    Ok(RawArguments { values, truncated })
}

/// The mapped files of `pid`. The query is first the flavor
/// [`PROC_PIDREGIONPATHINFO2`], which gives only the regions that map a
/// vnode; on the hosts that were measured it gave the same paths as the
/// public flavor in about one thirtieth of the time. A result with no path
/// can also come from a kernel that does not know the flavor, so it is
/// confirmed with the public flavor [`PROC_PIDREGIONPATHINFO`].
fn mapped_file_paths(pid: Pid, max_regions: usize) -> Result<RawPaths, QueryFailure> {
    // SAFETY: of the result, not of memory (owner decision of 2026-11-22).
    // The private flavor is kept because the public flavor walks each
    // region, also each region with no file, and made the inventory of one
    // host take 9 s instead of 0.3 s; both flavors gave the same paths for
    // each of its 1079 processes. A kernel that does not know the private
    // flavor fails the call or gives no region. For each failure other
    // than an exit, and for a result with no path, the public flavor reads
    // the regions again, so the private flavor can only add speed and
    // never removes a path from the result. The buffer and its layout are
    // the same for the two flavors.
    match mapped_file_paths_flavor(pid, max_regions, PROC_PIDREGIONPATHINFO2) {
        Ok(found) if !found.paths.is_empty() || found.truncated => Ok(found),
        Err(QueryFailure::Gone) => Err(QueryFailure::Gone),
        Ok(_) | Err(_) => mapped_file_paths_flavor(pid, max_regions, PROC_PIDREGIONPATHINFO),
    }
}

fn arguments(pid: Pid, max_bytes: usize) -> Result<RawArguments, QueryFailure> {
    let mut name: [c_int; 3] = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid.get()];
    let mut buffer: Vec<u8> = vec![0; max_bytes.max(8)];
    let mut length: libc::size_t = buffer.len();
    // SAFETY: `name` is a live array of 3 integers. `buffer` is a live,
    // writable allocation and `length` holds its size, so the kernel writes
    // at most that number of bytes. The call sets no new value.
    let status: c_int = unsafe {
        libc::sysctl(
            name.as_mut_ptr(),
            3,
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
    // A full buffer can be the start of a longer argument area.
    parse_procargs(written, length < buffer.len())
}

fn process_owner(pid: Pid) -> Result<(Uid, Uid), QueryFailure> {
    let mut info: MaybeUninit<libc::proc_bsdshortinfo> = MaybeUninit::zeroed();
    let size: c_int = c_int::try_from(size_of::<libc::proc_bsdshortinfo>())
        .map_err(|_| QueryFailure::Overflow)?;
    // SAFETY: `info` is a live, writable `proc_bsdshortinfo` of `size`
    // bytes. The kernel writes at most `size` bytes for
    // `PROC_PIDT_SHORTBSDINFO`.
    let written: c_int = unsafe {
        libc::proc_pidinfo(
            pid.get(),
            libc::PROC_PIDT_SHORTBSDINFO,
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
    let info: libc::proc_bsdshortinfo = unsafe { info.assume_init() };
    if i32::try_from(info.pbsi_pid).ok() != Some(pid.get()) {
        return Err(QueryFailure::Inconsistent);
    }
    Ok((Uid::new(info.pbsi_uid), Uid::new(info.pbsi_ruid)))
}

// The Security framework calls of the platform-code check. Each code,
// requirement, and dictionary reference is a Core Foundation object.
#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    /// `const CFStringRef kSecGuestAttributePid` in `<Security/SecCode.h>`.
    static kSecGuestAttributePid: Option<&'static CFString>;
    /// `const CFStringRef kSecCodeInfoPlatformIdentifier` in
    /// `<Security/SecCode.h>`: present when the code was signed as part of
    /// an operating system release.
    static kSecCodeInfoPlatformIdentifier: Option<&'static CFString>;
    /// `OSStatus SecCodeCopyGuestWithAttributes(SecCodeRef host,
    /// CFDictionaryRef attributes, SecCSFlags flags, SecCodeRef *guest)`.
    fn SecCodeCopyGuestWithAttributes(
        host: *const CFType,
        attributes: *const CFDictionary,
        flags: u32,
        guest: *mut *mut CFType,
    ) -> i32;
    /// `OSStatus SecRequirementCreateWithString(CFStringRef text,
    /// SecCSFlags flags, SecRequirementRef *requirement)`.
    fn SecRequirementCreateWithString(
        text: *const CFString,
        flags: u32,
        requirement: *mut *mut CFType,
    ) -> i32;
    /// `OSStatus SecCodeCheckValidity(SecCodeRef code, SecCSFlags flags,
    /// SecRequirementRef requirement)`.
    fn SecCodeCheckValidity(code: *const CFType, flags: u32, requirement: *const CFType) -> i32;
    /// `OSStatus SecCodeCopySigningInformation(SecStaticCodeRef code,
    /// SecCSFlags flags, CFDictionaryRef *information)`. A `SecCodeRef` is
    /// accepted for the static code.
    fn SecCodeCopySigningInformation(
        code: *const CFType,
        flags: u32,
        information: *mut *mut CFDictionary,
    ) -> i32;
}

/// `kSecCSDefaultFlags` in `<Security/CSCommon.h>`.
const SEC_CS_DEFAULT_FLAGS: u32 = 0;
/// `errSecCSReqFailed` in `<Security/CSCommon.h>`: the code is valid and
/// does not satisfy the requirement.
const ERR_SEC_CS_REQ_FAILED: i32 = -67050;

/// Takes ownership of a reference that a `Copy` or `Create` call returned.
///
/// # Safety
///
/// `pointer` must be null or a Core Foundation object of type `T` with a
/// +1 retain count that the caller owns.
unsafe fn owned<T: objc2_core_foundation::Type>(pointer: *mut T) -> Option<CFRetained<T>> {
    // SAFETY: the caller guarantees the type and the ownership.
    std::ptr::NonNull::new(pointer).map(|pointer| unsafe { CFRetained::from_raw(pointer) })
}

/// Whether the process `pid` runs Apple platform code: the dynamic code
/// signature is valid for `anchor apple`, and the signing information has a
/// platform identifier.
///
/// The guest is found by its PID, which the documentation of
/// `kSecGuestAttributePid` names as less precise than an audit token: a
/// process that exits and whose PID a new process takes between this check
/// and the use queries is examined as the new process. The caller applies
/// the result only to a process of the user whose executable is on the
/// sealed system volume, so the new process must also be such a process.
fn apple_platform_code(pid: Pid) -> Result<bool, QueryFailure> {
    // SAFETY: the statics are constant strings of the framework. A null
    // value is `None`.
    let (Some(pid_key), Some(platform_key)) = (unsafe { kSecGuestAttributePid }, unsafe {
        kSecCodeInfoPlatformIdentifier
    }) else {
        return Err(QueryFailure::Unsupported);
    };
    let value: CFRetained<CFNumber> = CFNumber::new_i32(pid.get());
    let attributes: CFRetained<CFDictionary<CFString, CFNumber>> =
        CFDictionary::from_slices(&[pid_key], &[&*value]);
    let mut guest: *mut CFType = std::ptr::null_mut();
    // SAFETY: a null host is the documented request for the system root
    // host. The dictionary lives for the call. The call writes one owned
    // reference into `guest` on success.
    let status: i32 = unsafe {
        SecCodeCopyGuestWithAttributes(
            std::ptr::null(),
            CFRetained::as_ptr(&attributes)
                .as_ptr()
                .cast::<CFDictionary>(),
            SEC_CS_DEFAULT_FLAGS,
            &raw mut guest,
        )
    };
    // SAFETY: on success `guest` is an owned `SecCodeRef`; it is null
    // otherwise.
    let guest: Option<CFRetained<CFType>> = unsafe { owned(guest) };
    let Some(guest) = guest.filter(|_| status == 0) else {
        return Err(QueryFailure::Failed(status));
    };
    let text: CFRetained<CFString> = CFString::from_static_str("anchor apple");
    let mut requirement: *mut CFType = std::ptr::null_mut();
    // SAFETY: `text` lives for the call. The call writes one owned
    // `SecRequirementRef` into `requirement` on success.
    let status: i32 = unsafe {
        SecRequirementCreateWithString(
            CFRetained::as_ptr(&text).as_ptr(),
            SEC_CS_DEFAULT_FLAGS,
            &raw mut requirement,
        )
    };
    // SAFETY: as for `guest`.
    let requirement: Option<CFRetained<CFType>> = unsafe { owned(requirement) };
    let Some(requirement) = requirement.filter(|_| status == 0) else {
        return Err(QueryFailure::Failed(status));
    };
    // SAFETY: both references are live owned objects of the expected types
    // for the call.
    let validity: i32 = unsafe {
        SecCodeCheckValidity(
            CFRetained::as_ptr(&guest).as_ptr(),
            SEC_CS_DEFAULT_FLAGS,
            CFRetained::as_ptr(&requirement).as_ptr(),
        )
    };
    match validity {
        0 => {}
        ERR_SEC_CS_REQ_FAILED => return Ok(false),
        other => return Err(QueryFailure::Failed(other)),
    }
    let mut information: *mut CFDictionary = std::ptr::null_mut();
    // SAFETY: `guest` is a live code object. The call writes one owned
    // dictionary into `information` on success.
    let status: i32 = unsafe {
        SecCodeCopySigningInformation(
            CFRetained::as_ptr(&guest).as_ptr(),
            SEC_CS_DEFAULT_FLAGS,
            &raw mut information,
        )
    };
    // SAFETY: as for `guest`; the dictionary has string keys.
    let information: Option<CFRetained<CFDictionary>> = unsafe { owned(information) };
    let Some(information) = information.filter(|_| status == 0) else {
        return Err(QueryFailure::Failed(status));
    };
    // SAFETY: the keys of the signing information are strings.
    let information: &CFDictionary<CFString, CFType> = unsafe { information.cast_unchecked() };
    Ok(information.get(platform_key).is_some())
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
        // list is refreshed only when the main run loop runs, so a later
        // list is current only when the run loop ran for this call.
        FIRST_APPLICATION_LIST.swap(false, Ordering::Relaxed) || run_loop::turn_main_run_loop()
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

    fn working_directory(&self, pid: Pid) -> Result<LosslessPath, QueryFailure> {
        working_directory(pid)
    }

    fn listening_tcp_sockets(
        &self,
        pid: Pid,
        max_descriptors: usize,
    ) -> Result<RawListeningSockets, QueryFailure> {
        listening_tcp_sockets(pid, max_descriptors)
    }

    fn process_owner(&self, pid: Pid) -> Result<(Uid, Uid), QueryFailure> {
        process_owner(pid)
    }

    fn working_directory_vnode(&self, pid: Pid) -> Result<RawVnode, QueryFailure> {
        working_directory_vnode(pid)
    }

    fn open_file_paths(&self, pid: Pid, max_descriptors: usize) -> Result<RawPaths, QueryFailure> {
        open_file_paths(pid, max_descriptors)
    }

    fn mapped_file_paths(&self, pid: Pid, max_regions: usize) -> Result<RawPaths, QueryFailure> {
        mapped_file_paths(pid, max_regions)
    }

    fn arguments(&self, pid: Pid, max_bytes: usize) -> Result<RawArguments, QueryFailure> {
        arguments(pid, max_bytes)
    }

    fn apple_platform_code(&self, pid: Pid) -> Result<bool, QueryFailure> {
        apple_platform_code(pid)
    }
}
