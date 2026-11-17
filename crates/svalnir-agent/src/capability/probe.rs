//! The probe interface and the findings that a probe returns.
//!
//! A probe looks at the host and returns a finding: what the probe saw, with
//! no capability state. `super::report` turns a finding into a capability
//! state. Thus a test can inject each finding and check the classification
//! with no access to the host.
//!
//! Each probe is read-only. A probe does not show a consent dialog, does not
//! register a service, does not write a file, and does not use elevated
//! rights.

use std::path::PathBuf;

/// A finding together with the method that produced it.
///
/// The method goes into the evidence of the report, so that a reader knows
/// what the state is based on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probed<T> {
    /// A short description of what the probe did.
    pub method: String,
    /// What the probe saw.
    pub finding: T,
}

impl<T> Probed<T> {
    /// Makes a probed finding.
    pub fn new(method: impl Into<String>, finding: T) -> Self {
        Self {
            method: method.into(),
            finding,
        }
    }
}

/// The read-only probes behind the capability report.
///
/// [`super::host::HostProbes`] is the implementation for the real host.
pub trait CapabilityProbes {
    /// The operating system, its version, and the hardware architecture.
    fn platform(&self) -> Probed<PlatformFinding>;

    /// The existence and the access mode of one user directory. The probe
    /// does not create the directory.
    fn user_directory(&self, directory: UserDirectory) -> Probed<DirectoryFinding>;

    /// Read-only attempts on locations that need Full Disk Access.
    fn protected_locations(&self) -> Probed<ProtectedLocationsFinding>;

    /// One native metric source that a collector needs.
    fn metric_source(&self, source: MetricSource) -> Probed<SourceFinding>;

    /// The registration files of one background service.
    fn service(&self, service: ServiceKind) -> Probed<ServiceFinding>;

    /// The status of System Integrity Protection.
    fn system_integrity_protection(&self) -> Probed<SipFinding>;
}

/// What the platform probe saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformFinding {
    /// The operating system family of this executable, as
    /// `std::env::consts::OS` spells it (`macos` on a Mac).
    pub os: String,
    /// The product version of the operating system, when the query succeeded.
    pub os_version: Option<String>,
    /// The build of the operating system, when the query succeeded.
    pub os_build: Option<String>,
    /// The architecture of this executable, as `std::env::consts::ARCH`
    /// spells it (`aarch64` on Apple Silicon).
    pub process_architecture: String,
    /// Whether the hardware is Apple Silicon. `None` when the query failed.
    pub apple_silicon_hardware: Option<bool>,
    /// Whether this process runs under binary translation. `None` when the
    /// query failed.
    pub translated: Option<bool>,
}

/// A user directory that Svalnir uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UserDirectory {
    /// The home directory of the user.
    Home,
    /// `~/Library/Application Support/Svalnir/`.
    State,
    /// `~/Library/Logs/Svalnir/`.
    Logs,
}

/// What the directory probe saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectoryFinding {
    /// An object is at the path.
    Present {
        /// The path that the probe examined.
        path: PathBuf,
        /// Whether the object is a directory.
        is_directory: bool,
        /// Whether the process can read the object.
        readable: bool,
        /// Whether the process can write to the object.
        writable: bool,
    },
    /// Nothing is at the path.
    Absent {
        /// The path that the probe examined.
        path: PathBuf,
        /// The nearest ancestor that exists.
        nearest_ancestor: PathBuf,
        /// Whether the process can make an entry in that ancestor.
        ancestor_writable: bool,
    },
    /// The probe could not examine the path.
    Failed {
        /// The path, when the probe could resolve it.
        path: Option<PathBuf>,
        /// The error text.
        error: String,
    },
}

/// What the protected-location probe saw.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProtectedLocationsFinding {
    /// One attempt for each candidate location. Empty when the probe could
    /// not resolve a candidate.
    pub attempts: Vec<ProtectedAttempt>,
}

/// One read-only attempt on a protected location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedAttempt {
    /// The location.
    pub path: PathBuf,
    /// The result of the attempt.
    pub outcome: ProtectedReadOutcome,
}

/// The result of a read-only attempt on a protected location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtectedReadOutcome {
    /// The process opened the directory and read from it.
    Listed,
    /// The system refused with `EPERM`. This is the error of the privacy
    /// control.
    NotPermitted,
    /// The system refused with `EACCES`. This is the error of the file
    /// permissions, which does not show the state of the privacy control.
    PermissionDenied,
    /// The location does not exist.
    Absent,
    /// A different error.
    Failed(String),
}

/// A native metric source that a Milestone 1 collector needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MetricSource {
    /// The memory-pressure level query.
    MemoryPressure,
    /// The virtual-memory statistics of the host.
    VmStatistics,
    /// The swap usage query.
    SwapUsage,
    /// The capacity query for a mounted volume (`statfs`).
    VolumeCapacity,
    /// The inspection of a process, tested on the own process.
    ProcessInspection,
}

impl MetricSource {
    /// Each source, in report order.
    pub const ALL: [Self; 5] = [
        Self::MemoryPressure,
        Self::VmStatistics,
        Self::SwapUsage,
        Self::VolumeCapacity,
        Self::ProcessInspection,
    ];
}

/// What a metric-source probe saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceFinding {
    /// The source answered the query.
    Responded {
        /// What the source returned, without a metric value.
        detail: String,
    },
    /// The system refused the query.
    Denied {
        /// The error text.
        detail: String,
    },
    /// The host does not have the source.
    Unsupported {
        /// Why the source is absent.
        detail: String,
    },
    /// The query failed for a different reason.
    Failed {
        /// The error text.
        detail: String,
    },
}

/// A background service of Svalnir.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ServiceKind {
    /// The user-session agent.
    BackgroundAgent,
    /// The privileged helper.
    PrivilegedHelper,
}

/// What the service probe saw.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ServiceFinding {
    /// One result for each conventional registration directory.
    pub locations: Vec<ServiceLocation>,
}

/// The result of the search in one registration directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceLocation {
    /// The directory.
    pub directory: PathBuf,
    /// The result of the search.
    pub outcome: ServiceLocationOutcome,
}

/// The result of the search for Svalnir entries in one directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceLocationOutcome {
    /// The directory has entries with the Svalnir identifier prefix. The
    /// list of names is bounded.
    Found(Vec<String>),
    /// The directory has no such entry.
    NotFound,
    /// The directory does not exist.
    Absent,
    /// The probe could not read the directory.
    Unreadable(String),
}

/// What the System Integrity Protection probe saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SipFinding {
    /// The system reports that the protection is on.
    Enabled,
    /// The system reports that the protection is off.
    Disabled,
    /// The system reports a different status, for example a custom
    /// configuration. The text is bounded.
    Other(String),
    /// The host has no System Integrity Protection.
    Unsupported,
    /// The probe could not read the status.
    NotDetermined(String),
}
