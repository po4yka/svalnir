//! The probes of the real host.
//!
//! Each probe is read-only and bounded. No probe shows a consent dialog,
//! registers a service, creates a file or a directory, or uses elevated
//! rights. The protected-location probe tries only locations of the Full
//! Disk Access class, which the system refuses with no dialog; it does not
//! try a location such as Desktop or Documents, for which the system can
//! show a dialog.

use std::ffi::CString;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use svalnir_core::file::LosslessPath;
use svalnir_core::process::{Pid, Uid};
use svalnir_core::time::WallTime;

use super::probe::{
    CapabilityProbes, DirectoryFinding, MetricSource, PlatformFinding, Probed, ProtectedAttempt,
    ProtectedLocationsFinding, ProtectedReadOutcome, ServiceFinding, ServiceKind, ServiceLocation,
    ServiceLocationOutcome, SipFinding, SourceFinding, UserDirectory,
};
use super::report::{ProbeSubject, WorkerRole};
#[cfg(target_os = "macos")]
use super::{native, sip};

/// The prefix of each Svalnir service name. It is the bundle identifier
/// that `scripts/package.sh` gives to the application.
pub const SERVICE_IDENTIFIER_PREFIX: &str = "dev.po4yka.svalnir";

/// The state directory, relative to the home directory.
pub const STATE_DIRECTORY: &str = "Library/Application Support/Svalnir";

/// The log directory, relative to the home directory.
pub const LOG_DIRECTORY: &str = "Library/Logs/Svalnir";

/// Locations of the Full Disk Access class, relative to the home directory.
/// Apple documents that Full Disk Access covers the data of Mail, Messages,
/// and Safari.
const PROTECTED_LOCATIONS: [&str; 3] = ["Library/Safari", "Library/Mail", "Library/Messages"];

/// The largest number of directory entries that the service probe reads in
/// one directory.
const MAX_SERVICE_ENTRIES: usize = 4096;

/// The largest number of entry names that the service probe keeps for one
/// directory.
const MAX_SERVICE_NAMES: usize = 8;

/// The probes of the real host, under the identity of this process.
#[derive(Debug, Clone)]
pub struct HostProbes {
    home: Option<PathBuf>,
    root: PathBuf,
}

impl HostProbes {
    /// Makes the probes for the home directory of the user and the root
    /// directory of the host.
    pub fn new() -> Self {
        Self {
            home: std::env::home_dir().filter(|home| !home.as_os_str().is_empty()),
            root: PathBuf::from("/"),
        }
    }

    /// Makes the probes for a different home directory and root directory.
    ///
    /// The directory, protected-location, and service probes look below
    /// these directories. A test uses this with a temporary directory.
    pub fn with_roots(home: Option<PathBuf>, root: PathBuf) -> Self {
        Self { home, root }
    }

    fn directory_path(&self, directory: UserDirectory) -> Option<PathBuf> {
        let home = self.home.as_ref()?;
        Some(match directory {
            UserDirectory::Home => home.clone(),
            UserDirectory::State => home.join(STATE_DIRECTORY),
            UserDirectory::Logs => home.join(LOG_DIRECTORY),
        })
    }
}

impl Default for HostProbes {
    fn default() -> Self {
        Self::new()
    }
}

impl ProbeSubject {
    /// The identity of this process, with the role that the caller states.
    pub fn current(role: WorkerRole) -> Self {
        let (real_uid, effective_uid) = current_uids();
        Self {
            role,
            executable: std::env::current_exe()
                .ok()
                .and_then(|path| LosslessPath::from_path(&path).ok()),
            pid: i32::try_from(std::process::id())
                .ok()
                .and_then(|pid| Pid::new(pid).ok()),
            real_uid,
            effective_uid,
        }
    }
}

/// The real and the effective user ID of this process.
fn current_uids() -> (Uid, Uid) {
    // SAFETY: `getuid` has no argument, no failure mode, and no effect.
    let real_uid = unsafe { libc::getuid() };
    // SAFETY: `geteuid` has no argument, no failure mode, and no effect.
    let effective_uid = unsafe { libc::geteuid() };
    (Uid::new(real_uid), Uid::new(effective_uid))
}

/// The current wall-clock time, when the clock gives a valid time.
pub(super) fn now() -> Option<WallTime> {
    WallTime::try_from(SystemTime::now()).ok()
}

impl CapabilityProbes for HostProbes {
    fn platform(&self) -> Probed<PlatformFinding> {
        Probed::new(
            "The target of this executable, and the `kern.osproductversion`, \
             `kern.osversion`, `hw.optional.arm64`, and `sysctl.proc_translated` values of \
             `sysctlbyname`.",
            platform_finding(),
        )
    }

    fn user_directory(&self, directory: UserDirectory) -> Probed<DirectoryFinding> {
        let finding = match self.directory_path(directory) {
            Some(path) => inspect_directory(&path),
            None => DirectoryFinding::Failed {
                path: None,
                error: "The home directory of the user is not known.".to_owned(),
            },
        };
        Probed::new(
            "File metadata (`stat`) and an access check (`faccessat`) for the effective user ID. The \
             probe does not open, create, or change the directory.",
            finding,
        )
    }

    fn protected_locations(&self) -> Probed<ProtectedLocationsFinding> {
        let attempts = self.home.as_ref().map_or_else(Vec::new, |home| {
            PROTECTED_LOCATIONS
                .iter()
                .map(|relative| {
                    let path = home.join(relative);
                    let outcome = list_protected(&path);
                    ProtectedAttempt { path, outcome }
                })
                .collect()
        });
        Probed::new(
            "A read-only attempt to open each directory and read one entry. The directories \
             hold data of Safari, Mail, and Messages, which Full Disk Access covers. `EPERM` \
             is the refusal of the privacy control. The probe keeps no entry name, reads no \
             file content, and does not read a TCC database.",
            ProtectedLocationsFinding { attempts },
        )
    }

    fn metric_source(&self, source: MetricSource) -> Probed<SourceFinding> {
        let method = match source {
            MetricSource::MemoryPressure => {
                "`sysctlbyname` for `kern.memorystatus_vm_pressure_level`."
            }
            MetricSource::VmStatistics => "`host_statistics64` with `HOST_VM_INFO64`.",
            MetricSource::SwapUsage => "`sysctlbyname` for `vm.swapusage`.",
            MetricSource::VolumeCapacity => "`statfs` on the root directory.",
            MetricSource::ProcessInspection => {
                "`proc_pidinfo` with `PROC_PIDTBSDINFO` on the own process. The result does \
                 not show that a process of a different user can be inspected."
            }
        };
        Probed::new(method, metric_source_finding(source))
    }

    fn service(&self, service: ServiceKind) -> Probed<ServiceFinding> {
        let mut directories: Vec<PathBuf> = Vec::new();
        match service {
            ServiceKind::BackgroundAgent => {
                if let Some(home) = &self.home {
                    directories.push(home.join("Library/LaunchAgents"));
                }
                directories.push(self.root.join("Library/LaunchAgents"));
            }
            ServiceKind::PrivilegedHelper => {
                directories.push(self.root.join("Library/LaunchDaemons"));
                directories.push(self.root.join("Library/PrivilegedHelperTools"));
            }
        }
        let locations = directories
            .into_iter()
            .map(|directory| {
                let outcome = search_service_directory(&directory);
                ServiceLocation { directory, outcome }
            })
            .collect();
        Probed::new(
            format!(
                "A listing of the conventional registration directories for names that start \
                 with `{SERVICE_IDENTIFIER_PREFIX}`. The probe does not ask launchd or the \
                 Service Management framework, so it does not see a registration through the \
                 application bundle, a loaded state, or a service that the user disabled."
            ),
            ServiceFinding { locations },
        )
    }

    fn system_integrity_protection(&self) -> Probed<SipFinding> {
        Probed::new(
            "The output of `/usr/bin/csrutil status`, which reads the status only.",
            sip_finding(),
        )
    }
}

/// Reads a `sysctl` flag. A name that does not exist is `false`: the
/// kernel has `hw.optional.arm64` on Apple Silicon only, and
/// `sysctl.proc_translated` only where binary translation exists.
#[cfg(target_os = "macos")]
fn sysctl_flag(name: &std::ffi::CStr) -> Option<bool> {
    match native::sysctl_i32(name) {
        Ok(value) => Some(value != 0),
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Some(false),
        Err(_) => None,
    }
}

#[cfg(target_os = "macos")]
fn platform_finding() -> PlatformFinding {
    PlatformFinding {
        os: std::env::consts::OS.to_owned(),
        os_version: native::sysctl_string(native::OS_PRODUCT_VERSION).ok(),
        os_build: native::sysctl_string(native::OS_BUILD).ok(),
        process_architecture: std::env::consts::ARCH.to_owned(),
        apple_silicon_hardware: sysctl_flag(native::HARDWARE_ARM64),
        translated: sysctl_flag(native::PROCESS_TRANSLATED),
    }
}

#[cfg(not(target_os = "macos"))]
fn platform_finding() -> PlatformFinding {
    PlatformFinding {
        os: std::env::consts::OS.to_owned(),
        os_version: None,
        os_build: None,
        process_architecture: std::env::consts::ARCH.to_owned(),
        apple_silicon_hardware: Some(false),
        translated: None,
    }
}

#[cfg(target_os = "macos")]
fn metric_source_finding(source: MetricSource) -> SourceFinding {
    match source {
        MetricSource::MemoryPressure => native::memory_pressure(),
        MetricSource::VmStatistics => native::vm_statistics(),
        MetricSource::SwapUsage => native::swap_usage(),
        MetricSource::VolumeCapacity => native::volume_capacity(c"/"),
        MetricSource::ProcessInspection => native::own_process(),
    }
}

#[cfg(not(target_os = "macos"))]
fn metric_source_finding(_source: MetricSource) -> SourceFinding {
    SourceFinding::Unsupported {
        detail: "The source is a macOS interface.".to_owned(),
    }
}

/// Whether the effective user ID of this process has the access `mode` to
/// `path`. Only a refusal of the system is `Ok(false)`; a different error
/// does not establish a result.
fn has_access(path: &Path, mode: libc::c_int) -> io::Result<bool> {
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    // SAFETY: `path` is a NUL-terminated string that lives for the call.
    // `faccessat` reads permissions only.
    let status = unsafe { libc::faccessat(libc::AT_FDCWD, path.as_ptr(), mode, libc::AT_EACCESS) };
    if status == 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::EACCES | libc::EPERM | libc::EROFS) => Ok(false),
        _ => Err(error),
    }
}

fn inspect_directory(path: &Path) -> DirectoryFinding {
    let failed = |error: &io::Error| DirectoryFinding::Failed {
        path: Some(path.to_path_buf()),
        error: error.to_string(),
    };
    match fs::metadata(path) {
        Ok(metadata) => {
            // A directory also needs search permission for a listing and
            // for a new entry.
            let search = if metadata.is_dir() { libc::X_OK } else { 0 };
            let readable = has_access(path, libc::R_OK | search);
            let writable = has_access(path, libc::W_OK | search);
            match (readable, writable) {
                (Ok(readable), Ok(writable)) => DirectoryFinding::Present {
                    path: path.to_path_buf(),
                    is_directory: metadata.is_dir(),
                    readable,
                    writable,
                },
                (Err(error), _) | (_, Err(error)) => failed(&error),
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let ancestor = path
                .ancestors()
                .skip(1)
                .find_map(|ancestor| fs::metadata(ancestor).ok().map(|data| (ancestor, data)));
            let Some((ancestor, metadata)) = ancestor else {
                return DirectoryFinding::Failed {
                    path: Some(path.to_path_buf()),
                    error: "No ancestor of the path exists.".to_owned(),
                };
            };
            let ancestor_writable = if metadata.is_dir() {
                has_access(ancestor, libc::W_OK | libc::X_OK)
            } else {
                Ok(false)
            };
            match ancestor_writable {
                Ok(ancestor_writable) => DirectoryFinding::Absent {
                    path: path.to_path_buf(),
                    nearest_ancestor: ancestor.to_path_buf(),
                    ancestor_writable,
                },
                Err(error) => failed(&error),
            }
        }
        Err(error) => failed(&error),
    }
}

fn protected_outcome(error: &io::Error) -> ProtectedReadOutcome {
    match error.raw_os_error() {
        Some(libc::EPERM) => ProtectedReadOutcome::NotPermitted,
        Some(libc::EACCES) => ProtectedReadOutcome::PermissionDenied,
        Some(libc::ENOENT) => ProtectedReadOutcome::Absent,
        _ => ProtectedReadOutcome::Failed(error.to_string()),
    }
}

/// Opens the directory and reads one entry. The entry is dropped.
fn list_protected(path: &Path) -> ProtectedReadOutcome {
    match fs::read_dir(path) {
        Ok(mut entries) => match entries.next() {
            None | Some(Ok(_)) => ProtectedReadOutcome::Listed,
            Some(Err(error)) => protected_outcome(&error),
        },
        Err(error) => protected_outcome(&error),
    }
}

fn search_service_directory(directory: &Path) -> ServiceLocationOutcome {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return ServiceLocationOutcome::Absent;
        }
        Err(error) => return ServiceLocationOutcome::Unreadable(error.to_string()),
    };
    let mut names: Vec<String> = Vec::new();
    for (index, entry) in entries.enumerate() {
        if index >= MAX_SERVICE_ENTRIES {
            return ServiceLocationOutcome::Unreadable(format!(
                "The directory has more than {MAX_SERVICE_ENTRIES} entries; the probe stopped."
            ));
        }
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => return ServiceLocationOutcome::Unreadable(error.to_string()),
        };
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(SERVICE_IDENTIFIER_PREFIX) && names.len() < MAX_SERVICE_NAMES {
            names.push(name.into_owned());
        }
    }
    if names.is_empty() {
        ServiceLocationOutcome::NotFound
    } else {
        names.sort();
        ServiceLocationOutcome::Found(names)
    }
}

#[cfg(target_os = "macos")]
fn sip_finding() -> SipFinding {
    sip::status()
}

#[cfg(not(target_os = "macos"))]
fn sip_finding() -> SipFinding {
    SipFinding::Unsupported
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    /// A temporary directory that the test removes at its end.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            static NEXT: AtomicU32 = AtomicU32::new(0);
            let path = std::env::temp_dir().join(format!(
                "svalnir-capability-{label}-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path.canonicalize().unwrap())
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            drop(fs::remove_dir_all(&self.0));
        }
    }

    /// Whether the test runs as root. File permissions do not limit root, so
    /// a test of a refusal has no meaning then.
    fn is_root() -> bool {
        current_uids().1 == Uid::new(0)
    }

    fn probes_in(temp: &TempDir) -> HostProbes {
        HostProbes::with_roots(Some(temp.0.join("home")), temp.0.join("root"))
    }

    #[test]
    fn an_absent_directory_is_reported_and_not_created() {
        let temp = TempDir::new("absent");
        fs::create_dir_all(temp.0.join("home")).unwrap();
        let probes = probes_in(&temp);

        let finding = probes.user_directory(UserDirectory::State).finding;
        assert_eq!(
            finding,
            DirectoryFinding::Absent {
                path: temp.0.join("home").join(STATE_DIRECTORY),
                nearest_ancestor: temp.0.join("home"),
                ancestor_writable: true,
            }
        );
        assert!(!temp.0.join("home/Library").exists());

        let home = probes.user_directory(UserDirectory::Home).finding;
        assert_eq!(
            home,
            DirectoryFinding::Present {
                path: temp.0.join("home"),
                is_directory: true,
                readable: true,
                writable: true,
            }
        );
    }

    #[test]
    fn a_present_directory_reports_its_access_mode() {
        if is_root() {
            return;
        }
        let temp = TempDir::new("present");
        let logs = temp.0.join("home").join(LOG_DIRECTORY);
        fs::create_dir_all(&logs).unwrap();
        fs::set_permissions(&logs, fs::Permissions::from_mode(0o500)).unwrap();
        let probes = probes_in(&temp);

        let finding = probes.user_directory(UserDirectory::Logs).finding;
        fs::set_permissions(&logs, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            finding,
            DirectoryFinding::Present {
                path: logs,
                is_directory: true,
                readable: true,
                writable: false,
            }
        );
    }

    #[test]
    fn a_directory_without_search_permission_is_not_usable() {
        if is_root() {
            return;
        }
        let temp = TempDir::new("search");
        let state = temp.0.join("home").join(STATE_DIRECTORY);
        fs::create_dir_all(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o600)).unwrap();
        let probes = probes_in(&temp);

        let finding = probes.user_directory(UserDirectory::State).finding;
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            finding,
            DirectoryFinding::Present {
                path: state,
                is_directory: true,
                readable: false,
                writable: false,
            }
        );
    }

    #[test]
    fn a_read_only_ancestor_is_not_writable() {
        if is_root() {
            return;
        }
        let temp = TempDir::new("ancestor");
        let library = temp.0.join("home/Library");
        fs::create_dir_all(&library).unwrap();
        fs::set_permissions(&library, fs::Permissions::from_mode(0o500)).unwrap();
        let probes = probes_in(&temp);

        let finding = probes.user_directory(UserDirectory::Logs).finding;
        fs::set_permissions(&library, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            finding,
            DirectoryFinding::Absent {
                path: temp.0.join("home").join(LOG_DIRECTORY),
                nearest_ancestor: library,
                ancestor_writable: false,
            }
        );
    }

    #[test]
    fn an_unknown_home_is_a_failed_finding() {
        let probes = HostProbes::with_roots(None, PathBuf::from("/"));
        for directory in [
            UserDirectory::Home,
            UserDirectory::State,
            UserDirectory::Logs,
        ] {
            assert!(matches!(
                probes.user_directory(directory).finding,
                DirectoryFinding::Failed { path: None, .. }
            ));
        }
        assert_eq!(probes.protected_locations().finding.attempts, []);
    }

    #[test]
    fn protected_locations_distinguish_listed_absent_and_file_permissions() {
        if is_root() {
            return;
        }
        let temp = TempDir::new("protected");
        let home = temp.0.join("home");
        fs::create_dir_all(home.join("Library/Safari")).unwrap();
        let mail = home.join("Library/Mail");
        fs::create_dir_all(&mail).unwrap();
        fs::set_permissions(&mail, fs::Permissions::from_mode(0o000)).unwrap();
        let probes = probes_in(&temp);

        let attempts = probes.protected_locations().finding.attempts;
        fs::set_permissions(&mail, fs::Permissions::from_mode(0o700)).unwrap();
        let outcomes: Vec<ProtectedReadOutcome> = attempts
            .into_iter()
            .map(|attempt| attempt.outcome)
            .collect();
        assert_eq!(
            outcomes,
            [
                ProtectedReadOutcome::Listed,
                // File permissions give `EACCES`, which is not the refusal
                // of the privacy control.
                ProtectedReadOutcome::PermissionDenied,
                ProtectedReadOutcome::Absent,
            ]
        );
    }

    #[test]
    fn the_refusal_of_the_privacy_control_is_eperm() {
        assert_eq!(
            protected_outcome(&io::Error::from_raw_os_error(libc::EPERM)),
            ProtectedReadOutcome::NotPermitted
        );
        assert!(matches!(
            protected_outcome(&io::Error::from_raw_os_error(libc::EIO)),
            ProtectedReadOutcome::Failed(_)
        ));
    }

    #[test]
    fn the_service_probe_finds_only_names_with_the_prefix() {
        let temp = TempDir::new("service");
        let user_agents = temp.0.join("home/Library/LaunchAgents");
        fs::create_dir_all(&user_agents).unwrap();
        fs::write(user_agents.join("com.example.other.plist"), b"").unwrap();
        let probes = probes_in(&temp);

        let finding = probes.service(ServiceKind::BackgroundAgent).finding;
        assert_eq!(
            finding.locations,
            [
                ServiceLocation {
                    directory: user_agents.clone(),
                    outcome: ServiceLocationOutcome::NotFound,
                },
                ServiceLocation {
                    directory: temp.0.join("root/Library/LaunchAgents"),
                    outcome: ServiceLocationOutcome::Absent,
                },
            ]
        );

        let name = format!("{SERVICE_IDENTIFIER_PREFIX}.agent.plist");
        fs::write(user_agents.join(&name), b"").unwrap();
        let finding = probes.service(ServiceKind::BackgroundAgent).finding;
        assert_eq!(
            finding.locations.first().map(|location| &location.outcome),
            Some(&ServiceLocationOutcome::Found(vec![name]))
        );

        let helper = probes.service(ServiceKind::PrivilegedHelper).finding;
        let directories: Vec<PathBuf> = helper
            .locations
            .into_iter()
            .map(|location| location.directory)
            .collect();
        assert_eq!(
            directories,
            [
                temp.0.join("root/Library/LaunchDaemons"),
                temp.0.join("root/Library/PrivilegedHelperTools"),
            ]
        );
    }

    #[test]
    fn the_subject_is_this_process() {
        let subject = ProbeSubject::current(WorkerRole::Cli);
        assert_eq!(subject.role, WorkerRole::Cli);
        assert_eq!(
            subject.pid.map(Pid::get),
            i32::try_from(std::process::id()).ok()
        );
        let executable = subject.executable.expect("a test has an executable path");
        assert_eq!(executable.to_path_buf(), std::env::current_exe().unwrap());
    }

    /// Smoke test of the probes on the real host. It checks only that each
    /// probe returns a defined finding; the result depends on the host.
    #[test]
    fn each_real_probe_returns_a_finding() {
        let probes = HostProbes::new();

        let platform = probes.platform();
        assert_ne!(platform.method, "");
        assert_eq!(platform.finding.os, std::env::consts::OS);

        for directory in [
            UserDirectory::Home,
            UserDirectory::State,
            UserDirectory::Logs,
        ] {
            assert_ne!(probes.user_directory(directory).method, "");
        }
        assert!(probes.protected_locations().finding.attempts.len() <= PROTECTED_LOCATIONS.len());
        for source in MetricSource::ALL {
            assert_ne!(probes.metric_source(source).method, "");
        }
        for service in [ServiceKind::BackgroundAgent, ServiceKind::PrivilegedHelper] {
            assert_eq!(probes.service(service).finding.locations.len(), 2);
        }
        assert_ne!(probes.system_integrity_protection().method, "");
    }

    /// On macOS each native metric source answers for an ordinary user.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_native_metric_sources_answer_on_macos() {
        let probes = HostProbes::new();
        for source in MetricSource::ALL {
            let finding = probes.metric_source(source).finding;
            assert!(
                matches!(finding, SourceFinding::Responded { .. }),
                "{source:?}: {finding:?}"
            );
        }
        let platform = probes.platform().finding;
        assert!(platform.os_version.is_some());
        assert!(platform.os_build.is_some());
    }
}
