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

use crate::platform::run_loop;
use objc2_app_kit::NSWorkspace;
use svalnir_core::file::{DeviceNumber, FileObjectEvidence, InodeNumber, LosslessPath};
use svalnir_core::observation::UnavailableReason;
use svalnir_core::process::{Pid, ProcessStartTime, Uid};
use svalnir_core::quantity::Nanoseconds;
use svalnir_core::time::{MonotonicNanos, WallTime};

use super::source::{
    ProcessSource, QueryFailure, RawListeningSocket, RawListeningSockets, RawProcessInfo, RawUsage,
    RunningApplication, SocketFamily, Timebase,
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

fn listening_tcp_sockets(
    pid: Pid,
    max_descriptors: usize,
) -> Result<RawListeningSockets, QueryFailure> {
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
        return Ok(RawListeningSockets {
            sockets: Vec::new(),
            descriptors_truncated: false,
        });
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
    let descriptors_truncated: bool = count > max_descriptors;
    let examined: usize = count.min(max_descriptors);
    let mut sockets: Vec<RawListeningSocket> = Vec::new();
    for descriptor in descriptors.get(..examined).unwrap_or_default() {
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
}
