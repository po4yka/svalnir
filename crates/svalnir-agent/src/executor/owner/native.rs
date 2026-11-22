//! The native calls of the owner executor: the responsibility functions of
//! the system, the suspended start, the vnode of the main text, and the
//! process table.
//!
//! Owner decision D1 of 2026-11-22: each command starts with the
//! responsibility disclaim, so it is its own responsible process and gets
//! no privacy (TCC) permission of Svalnir. The two functions are private
//! functions of `libquarantine`, a part of `libSystem`, and the executor
//! resolves them with `dlsym`. A function that is absent refuses the
//! command: no command starts without the disclaim.

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::ptr;

use svalnir_core::file::FileObjectEvidence;
use svalnir_core::process::ProcessStartTime;

/// The names of the responsibility functions and of their image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponsibilitySymbols {
    /// The path of the image that has the two functions.
    pub image: &'static CStr,
    /// The function that sets the disclaim in the start attributes.
    pub disclaim: &'static CStr,
    /// The function that gives the responsible process of a process.
    pub responsible: &'static CStr,
}

impl Default for ResponsibilitySymbols {
    fn default() -> Self {
        Self {
            image: c"/usr/lib/system/libquarantine.dylib",
            disclaim: c"responsibility_spawnattrs_setdisclaim",
            responsible: c"responsibility_get_pid_responsible_for_pid",
        }
    }
}

type DisclaimFn = unsafe extern "C" fn(*mut libc::posix_spawnattr_t, c_int) -> c_int;
type ResponsibleFn = unsafe extern "C" fn(libc::pid_t) -> libc::pid_t;

/// The two resolved responsibility functions.
#[derive(Debug, Clone, Copy)]
pub(super) struct Responsibility {
    disclaim: DisclaimFn,
    responsible: ResponsibleFn,
}

/// The address of the symbol `name` of `handle`. `None` when it is absent.
fn symbol(handle: *mut c_void, name: &CStr) -> Option<*mut c_void> {
    // SAFETY: `handle` is a handle of `dlopen`, and `name` is a valid C
    // string that lives for the call.
    let address: *mut c_void = unsafe { libc::dlsym(handle, name.as_ptr()) };
    (!address.is_null()).then_some(address)
}

impl Responsibility {
    /// Resolves the functions of `symbols`. `None` when the image or a
    /// function is absent.
    pub(super) fn resolve(symbols: &ResponsibilitySymbols) -> Option<Self> {
        // SAFETY: `image` is a valid C string. The image is a part of
        // `libSystem`, which each process has loaded, so `RTLD_NOLOAD` gives
        // its handle and loads no code. The handle is not closed: the image
        // stays loaded for the life of the process.
        let mut handle: *mut c_void =
            unsafe { libc::dlopen(symbols.image.as_ptr(), libc::RTLD_LAZY | libc::RTLD_NOLOAD) };
        if handle.is_null() {
            // SAFETY: as above; the image is a system library of the
            // shared cache.
            handle = unsafe { libc::dlopen(symbols.image.as_ptr(), libc::RTLD_LAZY) };
        }
        if handle.is_null() {
            return None;
        }
        let disclaim: *mut c_void = symbol(handle, symbols.disclaim)?;
        let responsible: *mut c_void = symbol(handle, symbols.responsible)?;
        // SAFETY: the symbol is the function of the system `int
        // responsibility_spawnattrs_setdisclaim(posix_spawnattr_t *, int)`.
        // A function pointer has the size and the representation of a data
        // pointer on the platforms of this crate.
        let disclaim: DisclaimFn =
            unsafe { std::mem::transmute::<*mut c_void, DisclaimFn>(disclaim) };
        // SAFETY: the symbol is the function of the system `pid_t
        // responsibility_get_pid_responsible_for_pid(pid_t)`, as above.
        let responsible: ResponsibleFn =
            unsafe { std::mem::transmute::<*mut c_void, ResponsibleFn>(responsible) };
        Some(Self {
            disclaim,
            responsible,
        })
    }

    /// The responsible process of `pid`. `None` when the call fails.
    pub(super) fn responsible_for(self, pid: libc::pid_t) -> Option<libc::pid_t> {
        // SAFETY: the function takes a process ID and no pointer.
        let responsible: libc::pid_t = unsafe { (self.responsible)(pid) };
        (responsible > 0).then_some(responsible)
    }
}

/// A process that the executor started suspended, with the read ends of
/// its standard output and standard error.
#[derive(Debug)]
pub(super) struct Started {
    pub(super) pid: libc::pid_t,
    pub(super) stdout: OwnedFd,
    pub(super) stderr: OwnedFd,
}

/// The reason a start failed.
#[derive(Debug)]
pub(super) enum StartFailure {
    /// The disclaim could not be set in the start attributes.
    Disclaim,
    /// The system refused the start, or a preparation failed.
    Spawn,
}

/// A pipe with the close-on-exec flag on each end.
fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut ends: [c_int; 2] = [0; 2];
    // SAFETY: `ends` has room for the two descriptors that `pipe` writes.
    if unsafe { libc::pipe(ends.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `pipe` returned a new descriptor that nothing else owns.
    let read: OwnedFd = unsafe { OwnedFd::from_raw_fd(ends[0]) };
    // SAFETY: as above, for the second descriptor.
    let write: OwnedFd = unsafe { OwnedFd::from_raw_fd(ends[1]) };
    for end in [ends[0], ends[1]] {
        // SAFETY: `end` is an open descriptor of this function.
        if unsafe { libc::fcntl(end, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok((read, write))
}

fn check(result: c_int) -> io::Result<()> {
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(result))
    }
}

/// The start attributes of one start. Drop destroys them.
struct Attributes(libc::posix_spawnattr_t);

impl Attributes {
    fn new() -> io::Result<Self> {
        let mut raw = MaybeUninit::<libc::posix_spawnattr_t>::uninit();
        // SAFETY: `raw` has room for one object, which the call initializes.
        check(unsafe { libc::posix_spawnattr_init(raw.as_mut_ptr()) })?;
        // SAFETY: the call above initialized the object.
        Ok(Self(unsafe { raw.assume_init() }))
    }
}

impl Drop for Attributes {
    fn drop(&mut self) {
        // SAFETY: the object was initialized by `new` and is destroyed one
        // time here.
        unsafe { libc::posix_spawnattr_destroy(&raw mut self.0) };
    }
}

/// The file actions of one start. Drop destroys them.
struct Actions(libc::posix_spawn_file_actions_t);

impl Actions {
    fn new() -> io::Result<Self> {
        let mut raw = MaybeUninit::<libc::posix_spawn_file_actions_t>::uninit();
        // SAFETY: `raw` has room for one object, which the call initializes.
        check(unsafe { libc::posix_spawn_file_actions_init(raw.as_mut_ptr()) })?;
        // SAFETY: the call above initialized the object.
        Ok(Self(unsafe { raw.assume_init() }))
    }
}

impl Drop for Actions {
    fn drop(&mut self) {
        // SAFETY: the object was initialized by `new` and is destroyed one
        // time here.
        unsafe { libc::posix_spawn_file_actions_destroy(&raw mut self.0) };
    }
}

/// A full signal set and an empty signal set.
fn signal_sets() -> (libc::sigset_t, libc::sigset_t) {
    let mut all = MaybeUninit::<libc::sigset_t>::uninit();
    let mut none = MaybeUninit::<libc::sigset_t>::uninit();
    // SAFETY: `all` has room for one set, which the call fills.
    unsafe { libc::sigfillset(all.as_mut_ptr()) };
    // SAFETY: `none` has room for one set, which the call empties.
    unsafe { libc::sigemptyset(none.as_mut_ptr()) };
    // SAFETY: the two calls above initialized the two sets.
    let all: libc::sigset_t = unsafe { all.assume_init() };
    // SAFETY: as above.
    let none: libc::sigset_t = unsafe { none.assume_init() };
    (all, none)
}

/// The start attributes of a command: the flags, its own process group,
/// the default action of each signal, no blocked signal, and the
/// responsibility disclaim.
fn attributes(responsibility: Responsibility) -> Result<Attributes, StartFailure> {
    let mut attributes: Attributes = Attributes::new().map_err(|_| StartFailure::Spawn)?;
    let flags: c_int = libc::POSIX_SPAWN_SETPGROUP
        | libc::POSIX_SPAWN_SETSIGDEF
        | libc::POSIX_SPAWN_SETSIGMASK
        | libc::POSIX_SPAWN_START_SUSPENDED
        | libc::POSIX_SPAWN_CLOEXEC_DEFAULT;
    let flags: libc::c_short = libc::c_short::try_from(flags).map_err(|_| StartFailure::Spawn)?;
    let (all, none) = signal_sets();
    let raw: *mut libc::posix_spawnattr_t = &raw mut attributes.0;
    // SAFETY: `raw` is an initialized attribute object of this function.
    check(unsafe { libc::posix_spawnattr_setflags(raw, flags) })
        .map_err(|_| StartFailure::Spawn)?;
    // SAFETY: as above.
    check(unsafe { libc::posix_spawnattr_setpgroup(raw, 0) }).map_err(|_| StartFailure::Spawn)?;
    // SAFETY: as above; `all` lives for the call.
    check(unsafe { libc::posix_spawnattr_setsigdefault(raw, &raw const all) })
        .map_err(|_| StartFailure::Spawn)?;
    // SAFETY: as above; `none` lives for the call.
    check(unsafe { libc::posix_spawnattr_setsigmask(raw, &raw const none) })
        .map_err(|_| StartFailure::Spawn)?;
    // SAFETY: the function of the system takes an initialized attribute
    // object and an integer.
    if unsafe { (responsibility.disclaim)(raw, 1) } != 0 {
        return Err(StartFailure::Disclaim);
    }
    Ok(attributes)
}

/// The file actions of a command: `/dev/null` as its standard input, the
/// two pipes as its standard output and standard error, and its working
/// directory.
fn actions(stdout: &OwnedFd, stderr: &OwnedFd, directory: &CStr) -> io::Result<Actions> {
    let mut actions: Actions = Actions::new()?;
    let raw: *mut libc::posix_spawn_file_actions_t = &raw mut actions.0;
    // SAFETY: `raw` is an initialized object of this function, and the path
    // is a valid C string.
    check(unsafe {
        libc::posix_spawn_file_actions_addopen(raw, 0, c"/dev/null".as_ptr(), libc::O_RDONLY, 0)
    })?;
    // SAFETY: as above; the descriptor is open for the call.
    check(unsafe { libc::posix_spawn_file_actions_adddup2(raw, stdout.as_raw_fd(), 1) })?;
    // SAFETY: as above.
    check(unsafe { libc::posix_spawn_file_actions_adddup2(raw, stderr.as_raw_fd(), 2) })?;
    // SAFETY: as above; `directory` is a valid C string.
    check(unsafe { libc::posix_spawn_file_actions_addchdir_np(raw, directory.as_ptr()) })?;
    Ok(actions)
}

/// Starts `path` suspended, with `arguments` as its argument vector (the
/// first one is its name), only `environment`, the working directory
/// `directory`, `/dev/null` as its standard input, two pipes as its standard
/// output and standard error, no other inherited descriptor, the default
/// action of each signal, no blocked signal, a process group of its own,
/// and the responsibility disclaim.
pub(super) fn spawn_suspended(
    responsibility: Responsibility,
    path: &CStr,
    arguments: &[CString],
    environment: &[CString],
    directory: &CStr,
) -> Result<Started, StartFailure> {
    let (stdout_read, stdout_write) = pipe().map_err(|_| StartFailure::Spawn)?;
    let (stderr_read, stderr_write) = pipe().map_err(|_| StartFailure::Spawn)?;
    let attributes: Attributes = attributes(responsibility)?;
    let actions: Actions =
        actions(&stdout_write, &stderr_write, directory).map_err(|_| StartFailure::Spawn)?;
    let mut argv: Vec<*mut c_char> = arguments
        .iter()
        .map(|argument| argument.as_ptr().cast_mut())
        .collect();
    argv.push(ptr::null_mut());
    let mut envp: Vec<*mut c_char> = environment
        .iter()
        .map(|entry| entry.as_ptr().cast_mut())
        .collect();
    envp.push(ptr::null_mut());
    let mut pid: libc::pid_t = 0;
    // SAFETY: `path`, each argument, and each entry are valid C strings
    // that live for the call, the two vectors end with a null pointer, and
    // the attributes and the actions are initialized.
    let result: c_int = unsafe {
        libc::posix_spawn(
            &raw mut pid,
            path.as_ptr(),
            &raw const actions.0,
            &raw const attributes.0,
            argv.as_ptr(),
            envp.as_ptr(),
        )
    };
    drop(attributes);
    drop(actions);
    drop(stdout_write);
    drop(stderr_write);
    check(result).map_err(|_| StartFailure::Spawn)?;
    Ok(Started {
        pid,
        stdout: stdout_read,
        stderr: stderr_read,
    })
}

/// `struct proc_regioninfo` of `<sys/proc_info.h>`.
#[repr(C)]
#[derive(Clone, Copy)]
struct RegionInfo {
    protection: u32,
    max_protection: u32,
    inheritance: u32,
    flags: u32,
    offset: u64,
    behavior: u32,
    user_wired_count: u32,
    user_tag: u32,
    pages_resident: u32,
    pages_shared_now_private: u32,
    pages_swapped_out: u32,
    pages_dirtied: u32,
    ref_count: u32,
    shadow_depth: u32,
    share_mode: u32,
    private_pages_resident: u32,
    shared_pages_resident: u32,
    obj_id: u32,
    depth: u32,
    address: u64,
    size: u64,
}

/// `struct proc_regionwithpathinfo` of `<sys/proc_info.h>`.
#[repr(C)]
struct RegionWithPath {
    region: RegionInfo,
    vnode: libc::vnode_info_path,
}

/// `PROC_PIDREGIONPATHINFO` of `<sys/proc_info.h>`.
const PROC_PIDREGIONPATHINFO: c_int = 8;

/// The execute bit of a region protection (`VM_PROT_EXECUTE`).
const VM_PROT_EXECUTE: u32 = 4;

/// The largest number of regions that the reading examines. A suspended
/// process has few: its main executable, `dyld`, and its stacks and heaps.
const MAX_REGIONS: usize = 4096;

/// The dynamic loader, which the kernel maps in each new process.
const DYLD_PATH: &str = "/usr/lib/dyld";

/// The device and the inode of each file-backed executable region of the
/// process `pid`, in address sequence. `None` when the reading fails.
pub(super) fn executable_regions(pid: libc::pid_t) -> Option<Vec<(u32, u64)>> {
    let mut address: u64 = 0;
    let size: c_int = c_int::try_from(size_of::<RegionWithPath>()).ok()?;
    let mut regions: Vec<(u32, u64)> = Vec::new();
    for _ in 0..MAX_REGIONS {
        let mut info = MaybeUninit::<RegionWithPath>::zeroed();
        // SAFETY: `info` has room for one `proc_regionwithpathinfo`, whose
        // size the call gets.
        let written: c_int = unsafe {
            libc::proc_pidinfo(
                pid,
                PROC_PIDREGIONPATHINFO,
                address,
                info.as_mut_ptr().cast(),
                size,
            )
        };
        if written <= 0 {
            // No region at or above the address: the end of the map. A
            // process that is gone has no region, which no check accepts.
            return Some(regions);
        }
        if written != size {
            return None;
        }
        // SAFETY: the call wrote the whole value, and each field is plain
        // data.
        let info: RegionWithPath = unsafe { info.assume_init() };
        let has_path: bool = info.vnode.vip_path[0][0] != 0;
        if has_path && info.region.protection & VM_PROT_EXECUTE != 0 {
            let stat = &info.vnode.vip_vi.vi_stat;
            regions.push((stat.vst_dev, stat.vst_ino));
        }
        address = info.region.address.checked_add(info.region.size)?;
    }
    None
}

/// The device and the inode of a file object, as a region reports them.
fn region_identity(object: &FileObjectEvidence) -> (u32, u64) {
    (
        u32::from_ne_bytes(object.device.get().to_ne_bytes()),
        object.inode.get(),
    )
}

/// Whether the executable regions of the suspended process `pid` are the
/// bound file `object` and the dynamic loader only: the first file-backed
/// executable region is `object`, and each other one is `/usr/lib/dyld`.
pub(super) fn main_text_agrees(pid: libc::pid_t, object: &FileObjectEvidence) -> bool {
    let Ok(loader) = std::fs::symlink_metadata(DYLD_PATH) else {
        return false;
    };
    let Some(loader) = super::verify::object_of(&loader).map(|object| region_identity(&object))
    else {
        return false;
    };
    match executable_regions(pid).as_deref() {
        Some([first, rest @ ..]) => {
            *first == region_identity(object) && rest.iter().all(|region| *region == loader)
        }
        _ => false,
    }
}

/// The BSD information of the process `pid`. `None` when it has none.
fn bsd_info(pid: libc::pid_t) -> Option<libc::proc_bsdinfo> {
    let size: c_int = c_int::try_from(size_of::<libc::proc_bsdinfo>()).ok()?;
    let mut info = MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    // SAFETY: `info` has room for one `proc_bsdinfo`, whose size the call
    // gets.
    let written: c_int = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            size,
        )
    };
    // SAFETY: the call wrote the whole value, and each field is plain data.
    (written == size).then(|| unsafe { info.assume_init() })
}

/// The real user of the process `pid`. `None` when it has none.
pub(super) fn owner_of(pid: libc::pid_t) -> Option<u32> {
    bsd_info(pid).map(|info| info.pbi_uid)
}

/// Whether the process `pid` is stopped (`SSTOP`), as a process that
/// `POSIX_SPAWN_START_SUSPENDED` started and that did not resume.
pub(super) fn is_stopped(pid: libc::pid_t) -> bool {
    /// `SSTOP` of `<sys/proc.h>`.
    const SSTOP: u32 = 4;
    bsd_info(pid).is_some_and(|info| info.pbi_status == SSTOP)
}

/// The members of the process group `group`.
pub(super) fn group_members(group: libc::pid_t) -> Vec<libc::pid_t> {
    list(4096, |buffer, bytes| {
        // SAFETY: `buffer` has room for `bytes` bytes.
        unsafe { libc::proc_listpgrppids(group, buffer, bytes) }
    })
}

/// The start time of the process `pid`. `None` when it has none.
pub(super) fn start_time(pid: libc::pid_t) -> Option<ProcessStartTime> {
    let info: libc::proc_bsdinfo = bsd_info(pid)?;
    ProcessStartTime::from_timeval(
        info.pbi_start_tvsec,
        u32::try_from(info.pbi_start_tvusec).ok()?,
    )
}

/// The process IDs of a list call with a buffer for `capacity` IDs.
fn list(capacity: usize, call: impl Fn(*mut c_void, c_int) -> c_int) -> Vec<libc::pid_t> {
    let mut buffer: Vec<libc::pid_t> = vec![0; capacity];
    let Ok(bytes) = c_int::try_from(capacity * size_of::<libc::pid_t>()) else {
        return Vec::new();
    };
    let count: c_int = call(buffer.as_mut_ptr().cast(), bytes);
    let count: usize = usize::try_from(count).unwrap_or(0).min(capacity);
    buffer.truncate(count);
    buffer.retain(|pid| *pid > 0);
    buffer
}

/// The largest number of processes that one reading of the table gives.
const MAX_PROCESSES: usize = 16_384;

/// The children of the process `pid`.
pub(super) fn children(pid: libc::pid_t) -> Vec<libc::pid_t> {
    list(1024, |buffer, bytes| {
        // SAFETY: `buffer` has room for `bytes` bytes.
        unsafe { libc::proc_listchildpids(pid, buffer, bytes) }
    })
}

/// Each process of the host.
pub(super) fn all_processes() -> Vec<libc::pid_t> {
    list(MAX_PROCESSES, |buffer, bytes| {
        // SAFETY: `buffer` has room for `bytes` bytes.
        unsafe { libc::proc_listallpids(buffer, bytes) }
    })
}

/// Sends `signal` to the process or the group `target` (a negative value
/// names a group). Returns false when no such process exists (`ESRCH`).
pub(super) fn signal(target: libc::pid_t, signal: c_int) -> bool {
    // SAFETY: `kill` takes no pointer. A caller names only the command, its
    // process group, or a process that it found with the start time of its
    // record, so a signal does not reach an unrelated process.
    let result: c_int = unsafe { libc::kill(target, signal) };
    result == 0 || io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}

/// Whether the process `pid` with the start time `started` lives.
pub(super) fn lives(pid: libc::pid_t, started: ProcessStartTime) -> bool {
    start_time(pid) == Some(started)
}

/// The result of `waitpid` with `WNOHANG` for the child `pid`.
pub(super) enum Wait {
    /// The child runs.
    Running,
    /// The child ended with this status word.
    Ended(c_int),
    /// The call failed.
    Failed,
}

/// Reads the state of the child `pid` with no wait.
pub(super) fn try_wait(pid: libc::pid_t) -> Wait {
    let mut status: c_int = 0;
    // SAFETY: `status` is a valid pointer for the call.
    match unsafe { libc::waitpid(pid, &raw mut status, libc::WNOHANG) } {
        0 => Wait::Running,
        found if found == pid => Wait::Ended(status),
        _ => Wait::Failed,
    }
}
