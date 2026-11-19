//! The capability report and the logic that builds it from probe findings.
//!
//! [`build_report`] has no access to the host. It reads the findings of a
//! [`CapabilityProbes`] implementation and gives each capability a
//! [`CapabilityState`]. A finding that does not establish a result becomes
//! `unknown`; it does not become `denied`.

use std::fmt;
use std::path::Path;

use serde::{Deserialize, Serialize};
use svalnir_core::file::LosslessPath;
use svalnir_core::process::{Pid, Uid};
use svalnir_core::state::CapabilityState;
use svalnir_core::time::WallTime;

use super::probe::{
    CapabilityProbes, DirectoryFinding, MetricSource, PlatformFinding, Probed, ProtectedAttempt,
    ProtectedLocationsFinding, ProtectedReadOutcome, ServiceFinding, ServiceKind,
    ServiceLocationOutcome, SipFinding, SourceFinding, UserDirectory,
};

/// The stable identifier of a capability.
///
/// The JSON spelling is the text of [`CapabilityId::as_str`]. An identifier
/// does not change after its first release; a retired identifier stays
/// reserved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CapabilityId {
    /// The operating system and the hardware architecture.
    #[serde(rename = "host.platform")]
    HostPlatform,
    /// Read access to the home directory of the user.
    #[serde(rename = "user.home_directory")]
    UserHomeDirectory,
    /// The state directory `~/Library/Application Support/Svalnir/`.
    #[serde(rename = "user.state_directory")]
    UserStateDirectory,
    /// The log directory `~/Library/Logs/Svalnir/`.
    #[serde(rename = "user.log_directory")]
    UserLogDirectory,
    /// Full Disk Access of the tested process.
    #[serde(rename = "privacy.full_disk_access")]
    FullDiskAccess,
    /// The memory-pressure level query.
    #[serde(rename = "metrics.memory_pressure")]
    MetricsMemoryPressure,
    /// The virtual-memory statistics of the host.
    #[serde(rename = "metrics.vm_statistics")]
    MetricsVmStatistics,
    /// The swap usage query.
    #[serde(rename = "metrics.swap_usage")]
    MetricsSwapUsage,
    /// The capacity query for a mounted volume.
    #[serde(rename = "metrics.volume_capacity")]
    MetricsVolumeCapacity,
    /// The inspection of a process.
    #[serde(rename = "metrics.process_inspection")]
    MetricsProcessInspection,
    /// The registration of the background agent.
    #[serde(rename = "service.background_agent")]
    ServiceBackgroundAgent,
    /// The registration of the privileged helper.
    #[serde(rename = "service.privileged_helper")]
    ServicePrivilegedHelper,
    /// The status of System Integrity Protection.
    #[serde(rename = "system.integrity_protection")]
    SystemIntegrityProtection,
}

impl CapabilityId {
    /// Each identifier, in report order.
    pub const ALL: [Self; 13] = [
        Self::HostPlatform,
        Self::UserHomeDirectory,
        Self::UserStateDirectory,
        Self::UserLogDirectory,
        Self::FullDiskAccess,
        Self::MetricsMemoryPressure,
        Self::MetricsVmStatistics,
        Self::MetricsSwapUsage,
        Self::MetricsVolumeCapacity,
        Self::MetricsProcessInspection,
        Self::ServiceBackgroundAgent,
        Self::ServicePrivilegedHelper,
        Self::SystemIntegrityProtection,
    ];

    /// The stable text of the identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HostPlatform => "host.platform",
            Self::UserHomeDirectory => "user.home_directory",
            Self::UserStateDirectory => "user.state_directory",
            Self::UserLogDirectory => "user.log_directory",
            Self::FullDiskAccess => "privacy.full_disk_access",
            Self::MetricsMemoryPressure => "metrics.memory_pressure",
            Self::MetricsVmStatistics => "metrics.vm_statistics",
            Self::MetricsSwapUsage => "metrics.swap_usage",
            Self::MetricsVolumeCapacity => "metrics.volume_capacity",
            Self::MetricsProcessInspection => "metrics.process_inspection",
            Self::ServiceBackgroundAgent => "service.background_agent",
            Self::ServicePrivilegedHelper => "service.privileged_helper",
            Self::SystemIntegrityProtection => "system.integrity_protection",
        }
    }

    /// A short name for a table.
    pub const fn title(self) -> &'static str {
        match self {
            Self::HostPlatform => "Supported platform",
            Self::UserHomeDirectory => "Home directory",
            Self::UserStateDirectory => "State directory",
            Self::UserLogDirectory => "Log directory",
            Self::FullDiskAccess => "Full Disk Access",
            Self::MetricsMemoryPressure => "Memory-pressure query",
            Self::MetricsVmStatistics => "VM statistics",
            Self::MetricsSwapUsage => "Swap usage query",
            Self::MetricsVolumeCapacity => "Volume capacity query",
            Self::MetricsProcessInspection => "Process inspection",
            Self::ServiceBackgroundAgent => "Background agent",
            Self::ServicePrivilegedHelper => "Privileged helper",
            Self::SystemIntegrityProtection => "System Integrity Protection",
        }
    }

    /// What the capability enables.
    pub const fn enables(self) -> &'static str {
        match self {
            Self::HostPlatform => "Operation on a host that Svalnir is validated for.",
            Self::UserHomeDirectory => {
                "Scans of the files of the user and access to the user configuration."
            }
            Self::UserStateDirectory => {
                "Storage of the configuration, the scan index, and the metric history."
            }
            Self::UserLogDirectory => "Storage of the log files.",
            Self::FullDiskAccess => {
                "Scans of privacy-protected locations. It does not authorize deletion."
            }
            Self::MetricsMemoryPressure => "The memory-pressure state in the status commands.",
            Self::MetricsVmStatistics => "The memory page counts in the status commands.",
            Self::MetricsSwapUsage => "The swap usage in the status commands.",
            Self::MetricsVolumeCapacity => "The capacity of each mounted volume.",
            Self::MetricsProcessInspection => "The process inventory and the memory of a process.",
            Self::ServiceBackgroundAgent => {
                "Monitoring that continues when no Svalnir window or command is open."
            }
            Self::ServicePrivilegedHelper => {
                "Supported operations on data of other owners or of the system."
            }
            Self::SystemIntegrityProtection => {
                "Nothing. This entry is information only. Svalnir does not need a change to it."
            }
        }
    }

    /// The class of the capability for the read-only Milestone 1 commands.
    pub const fn requirement(self) -> Requirement {
        match self {
            Self::HostPlatform
            | Self::UserHomeDirectory
            | Self::MetricsMemoryPressure
            | Self::MetricsVmStatistics
            | Self::MetricsSwapUsage
            | Self::MetricsVolumeCapacity
            | Self::MetricsProcessInspection => Requirement::Required,
            Self::UserStateDirectory
            | Self::UserLogDirectory
            | Self::FullDiskAccess
            | Self::ServiceBackgroundAgent
            | Self::ServicePrivilegedHelper => Requirement::Optional,
            Self::SystemIntegrityProtection => Requirement::Informational,
        }
    }
}

impl fmt::Display for CapabilityId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.pad(self.as_str())
    }
}

/// The class of a capability for the read-only Milestone 1 commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Requirement {
    /// A read-only Milestone 1 command needs the capability.
    Required,
    /// The capability increases coverage or enables a later feature.
    Optional,
    /// The entry is information only. It has no effect on the verdict.
    Informational,
}

impl Requirement {
    /// The stable text of the class.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::Optional => "optional",
            Self::Informational => "informational",
        }
    }
}

/// The component that ran the probes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerRole {
    /// The command-line client.
    Cli,
    /// The graphical client: a window process of `Svalnir.app`. It runs the
    /// same probes as the command-line client and has the same
    /// requirements, because its screens show the same readings.
    Window,
    /// The user-session agent.
    Agent,
    /// The privileged helper.
    Helper,
}

impl WorkerRole {
    /// The stable text of the role.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cli => "cli",
            Self::Window => "window",
            Self::Agent => "agent",
            Self::Helper => "helper",
        }
    }
}

/// The process identity that the probes ran under.
///
/// A capability state applies to this process only. Access that the user
/// gave to a terminal application does not show that a separately started
/// service has the same access.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeSubject {
    /// The component that ran the probes.
    pub role: WorkerRole,
    /// The path of the executable, when the system gave it.
    pub executable: Option<LosslessPath>,
    /// The process ID, when it is a valid value.
    pub pid: Option<Pid>,
    /// The real user ID.
    pub real_uid: Uid,
    /// The effective user ID.
    pub effective_uid: Uid,
}

/// The registration state of a background service, from read-only
/// inspection of the conventional registration directories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    /// No registration file is in a conventional directory.
    NotInstalled,
    /// A registration file is present. The inspection does not show
    /// whether the service is loaded, running, or disabled by the user.
    RegistrationFilePresent,
    /// The inspection could not establish a result.
    Unknown,
}

impl RegistrationState {
    /// The stable text of the state.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotInstalled => "not_installed",
            Self::RegistrationFilePresent => "registration_file_present",
            Self::Unknown => "unknown",
        }
    }
}

/// One named observation in the evidence of a capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceFact {
    /// The name of the observation.
    pub name: String,
    /// The value, as text.
    pub value: String,
}

/// What a capability state is based on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    /// What the probe did.
    pub method: String,
    /// What the probe saw.
    pub facts: Vec<EvidenceFact>,
}

/// One capability in the report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityEntry {
    /// The stable identifier.
    pub id: CapabilityId,
    /// A short name for a table.
    pub title: String,
    /// The class for the read-only Milestone 1 commands.
    pub requirement: Requirement,
    /// The state under the tested process identity.
    pub state: CapabilityState,
    /// One line that summarizes the result.
    pub detail: String,
    /// What the state is based on.
    pub evidence: Evidence,
    /// Why the capability is not `available`. `None` when it is available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// What the capability enables.
    pub enables: String,
    /// A safe action for the user, when one applies. A hint does not ask
    /// the user to remove a system protection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    /// The registration state. Present for a service entry only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration: Option<RegistrationState>,
}

/// The number of capabilities in each state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct StateCounts {
    /// Capabilities that are `available`.
    pub available: u32,
    /// Capabilities that are `denied`.
    pub denied: u32,
    /// Capabilities that are `unsupported`.
    pub unsupported: u32,
    /// Capabilities that are `unknown`.
    pub unknown: u32,
    /// Capabilities with a state that this build does not recognize.
    pub unrecognized: u32,
}

impl StateCounts {
    fn record(&mut self, state: &CapabilityState) {
        let counter = match state {
            CapabilityState::Available => &mut self.available,
            CapabilityState::Denied => &mut self.denied,
            CapabilityState::Unsupported => &mut self.unsupported,
            CapabilityState::Unknown => &mut self.unknown,
            CapabilityState::Unrecognized(_) => &mut self.unrecognized,
        };
        *counter = counter.saturating_add(1);
    }
}

/// The result for the read-only Milestone 1 commands.
///
/// Only the required capabilities set the verdict. An optional capability
/// that is denied, unsupported, or unknown does not change it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Each required capability is available.
    Ready,
    /// No required capability is denied or unsupported, but one or more
    /// have no established result.
    Unverified,
    /// One or more required capabilities are denied or unsupported.
    Blocked,
}

impl Verdict {
    /// The stable text of the verdict.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Unverified => "unverified",
            Self::Blocked => "blocked",
        }
    }
}

/// The summary of a report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Summary {
    /// The result for the read-only Milestone 1 commands.
    pub verdict: Verdict,
    /// The states of the required capabilities.
    pub required: StateCounts,
    /// The states of the optional capabilities.
    pub optional: StateCounts,
    /// The states of the entries that are information only.
    pub informational: StateCounts,
    /// The required capabilities that are not available, in report order.
    pub required_not_available: Vec<CapabilityId>,
    /// The optional capabilities that are not available, in report order.
    pub optional_not_available: Vec<CapabilityId>,
}

impl Summary {
    /// Makes the summary of the entries.
    pub fn of(entries: &[CapabilityEntry]) -> Self {
        let mut summary = Self {
            verdict: Verdict::Ready,
            required: StateCounts::default(),
            optional: StateCounts::default(),
            informational: StateCounts::default(),
            required_not_available: Vec::new(),
            optional_not_available: Vec::new(),
        };
        for entry in entries {
            let available = entry.state == CapabilityState::Available;
            match entry.requirement {
                Requirement::Required => {
                    summary.required.record(&entry.state);
                    if !available {
                        summary.required_not_available.push(entry.id);
                    }
                }
                Requirement::Optional => {
                    summary.optional.record(&entry.state);
                    if !available {
                        summary.optional_not_available.push(entry.id);
                    }
                }
                Requirement::Informational => summary.informational.record(&entry.state),
            }
        }
        summary.verdict = if summary.required.denied > 0 || summary.required.unsupported > 0 {
            Verdict::Blocked
        } else if summary.required.unknown > 0 || summary.required.unrecognized > 0 {
            Verdict::Unverified
        } else {
            Verdict::Ready
        };
        summary
    }
}

/// The capability report behind `svalnir doctor`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityReport {
    /// The process identity that the probes ran under.
    pub subject: ProbeSubject,
    /// What the results apply to, as a sentence for the user.
    pub scope_note: String,
    /// The time of the probes, when the clock gave a valid time.
    pub probed_at: Option<WallTime>,
    /// The summary of the capabilities.
    pub summary: Summary,
    /// One entry for each capability, in the order of
    /// [`CapabilityId::ALL`].
    pub capabilities: Vec<CapabilityEntry>,
}

impl CapabilityReport {
    /// The entry of one capability.
    pub fn entry(&self, id: CapabilityId) -> Option<&CapabilityEntry> {
        self.capabilities.iter().find(|entry| entry.id == id)
    }

    /// Whether each capability that the read-only Milestone 1 commands
    /// need is available.
    pub fn required_satisfied(&self) -> bool {
        self.summary.verdict == Verdict::Ready
    }
}

/// Builds the report from the findings of the probes.
///
/// The function calls each probe one time. It does not touch the host
/// itself.
pub fn build_report(
    subject: ProbeSubject,
    probed_at: Option<WallTime>,
    probes: &impl CapabilityProbes,
) -> CapabilityReport {
    let capabilities: Vec<CapabilityEntry> = CapabilityId::ALL
        .iter()
        .map(|id| probe_entry(*id, subject.role, probes))
        .collect();
    CapabilityReport {
        scope_note: scope_note(subject.role).to_owned(),
        subject,
        probed_at,
        summary: Summary::of(&capabilities),
        capabilities,
    }
}

fn scope_note(role: WorkerRole) -> &'static str {
    match role {
        WorkerRole::Cli => {
            "The results apply to this command-line process and to the application that \
             started it, for example a terminal. They do not show the access of the \
             background agent or of the privileged helper."
        }
        WorkerRole::Window => {
            "The results apply to this window process of the graphical client. They do not \
             show the access of the background agent, of a terminal, or of the privileged \
             helper."
        }
        WorkerRole::Agent => {
            "The results apply to the background agent process. They do not show the access \
             of a terminal, of the graphical client, or of the privileged helper."
        }
        WorkerRole::Helper => {
            "The results apply to the privileged helper process. They do not show the access \
             of the background agent or of a client."
        }
    }
}

fn probe_entry(
    id: CapabilityId,
    role: WorkerRole,
    probes: &impl CapabilityProbes,
) -> CapabilityEntry {
    match id {
        CapabilityId::HostPlatform => platform_entry(probes.platform()),
        CapabilityId::UserHomeDirectory => home_entry(probes.user_directory(UserDirectory::Home)),
        CapabilityId::UserStateDirectory => {
            writable_directory_entry(id, probes.user_directory(UserDirectory::State))
        }
        CapabilityId::UserLogDirectory => {
            writable_directory_entry(id, probes.user_directory(UserDirectory::Logs))
        }
        CapabilityId::FullDiskAccess => full_disk_access_entry(role, probes.protected_locations()),
        CapabilityId::MetricsMemoryPressure => {
            source_entry(id, probes.metric_source(MetricSource::MemoryPressure))
        }
        CapabilityId::MetricsVmStatistics => {
            source_entry(id, probes.metric_source(MetricSource::VmStatistics))
        }
        CapabilityId::MetricsSwapUsage => {
            source_entry(id, probes.metric_source(MetricSource::SwapUsage))
        }
        CapabilityId::MetricsVolumeCapacity => {
            source_entry(id, probes.metric_source(MetricSource::VolumeCapacity))
        }
        CapabilityId::MetricsProcessInspection => {
            source_entry(id, probes.metric_source(MetricSource::ProcessInspection))
        }
        CapabilityId::ServiceBackgroundAgent => {
            service_entry(id, probes.service(ServiceKind::BackgroundAgent))
        }
        CapabilityId::ServicePrivilegedHelper => {
            service_entry(id, probes.service(ServiceKind::PrivilegedHelper))
        }
        CapabilityId::SystemIntegrityProtection => sip_entry(probes.system_integrity_protection()),
    }
}

/// The parts of an entry that the classification of one finding sets.
struct Classified {
    state: CapabilityState,
    detail: String,
    facts: Vec<EvidenceFact>,
    reason: Option<String>,
    remediation: Option<String>,
    registration: Option<RegistrationState>,
}

impl Classified {
    fn new(state: CapabilityState, detail: impl Into<String>) -> Self {
        Self {
            state,
            detail: detail.into(),
            facts: Vec::new(),
            reason: None,
            remediation: None,
            registration: None,
        }
    }

    fn available(detail: impl Into<String>) -> Self {
        Self::new(CapabilityState::Available, detail)
    }

    /// A state that is not `available`. The detail is also the reason.
    fn not_available(state: CapabilityState, reason: impl Into<String>) -> Self {
        let reason: String = reason.into();
        let mut classified = Self::new(state, reason.clone());
        classified.reason = Some(reason);
        classified
    }

    fn fact(mut self, name: &str, value: impl Into<String>) -> Self {
        self.facts.push(EvidenceFact {
            name: name.to_owned(),
            value: value.into(),
        });
        self
    }

    fn remediation(mut self, hint: &str) -> Self {
        self.remediation = Some(hint.to_owned());
        self
    }

    fn into_entry(self, id: CapabilityId, method: String) -> CapabilityEntry {
        CapabilityEntry {
            id,
            title: id.title().to_owned(),
            requirement: id.requirement(),
            state: self.state,
            detail: self.detail,
            evidence: Evidence {
                method,
                facts: self.facts,
            },
            reason: self.reason,
            enables: id.enables().to_owned(),
            remediation: self.remediation,
            registration: self.registration,
        }
    }
}

/// Text of a path for a report. It is for display only.
fn path_label(path: &Path) -> String {
    LosslessPath::from_path(path).map_or_else(
        |_| path.to_string_lossy().into_owned(),
        |lossless| lossless.display_label(),
    )
}

fn optional_text(value: Option<&str>) -> String {
    value.map_or_else(|| "unavailable".to_owned(), str::to_owned)
}

fn optional_flag(value: Option<bool>) -> String {
    match value {
        Some(true) => "true".to_owned(),
        Some(false) => "false".to_owned(),
        None => "unavailable".to_owned(),
    }
}

fn platform_entry(probed: Probed<PlatformFinding>) -> CapabilityEntry {
    let finding = probed.finding;
    let version = optional_text(finding.os_version.as_deref());
    let classified = if finding.os != "macos" {
        Classified::not_available(
            CapabilityState::Unsupported,
            format!(
                "The operating system is `{}`. Svalnir operates on macOS only.",
                finding.os
            ),
        )
    } else if finding.translated == Some(true) {
        Classified::not_available(
            CapabilityState::Unknown,
            "This process runs under binary translation. That configuration is not validated.",
        )
        .remediation("Use a build of Svalnir for Apple Silicon (`aarch64-apple-darwin`).")
    } else {
        let apple_silicon = finding
            .apple_silicon_hardware
            .unwrap_or(finding.process_architecture == "aarch64");
        if apple_silicon {
            Classified::available(format!("macOS {version} on Apple Silicon."))
        } else if finding.apple_silicon_hardware.is_none() {
            Classified::not_available(
                CapabilityState::Unknown,
                "The probe could not read the hardware architecture.",
            )
        } else {
            Classified::not_available(
                CapabilityState::Unknown,
                format!(
                    "macOS {version} on hardware that is not Apple Silicon. Apple Silicon is \
                     the first validation target; this hardware is not validated."
                ),
            )
        }
    };
    classified
        .fact("os", finding.os)
        .fact("os_version", version)
        .fact("os_build", optional_text(finding.os_build.as_deref()))
        .fact("process_architecture", finding.process_architecture)
        .fact(
            "apple_silicon_hardware",
            optional_flag(finding.apple_silicon_hardware),
        )
        .fact("translated", optional_flag(finding.translated))
        .into_entry(CapabilityId::HostPlatform, probed.method)
}

fn directory_facts(classified: Classified, finding: &DirectoryFinding) -> Classified {
    match finding {
        DirectoryFinding::Present {
            path,
            is_directory,
            readable,
            writable,
        } => classified
            .fact("path", path_label(path))
            .fact("exists", "true")
            .fact("is_directory", optional_flag(Some(*is_directory)))
            .fact("readable", optional_flag(Some(*readable)))
            .fact("writable", optional_flag(Some(*writable))),
        DirectoryFinding::Absent {
            path,
            nearest_ancestor,
            ancestor_writable,
        } => classified
            .fact("path", path_label(path))
            .fact("exists", "false")
            .fact("nearest_ancestor", path_label(nearest_ancestor))
            .fact("ancestor_writable", optional_flag(Some(*ancestor_writable))),
        DirectoryFinding::Failed { path, error } => classified
            .fact(
                "path",
                path.as_deref()
                    .map_or_else(|| "unavailable".to_owned(), path_label),
            )
            .fact("error", error.clone()),
    }
}

fn home_entry(probed: Probed<DirectoryFinding>) -> CapabilityEntry {
    let classified = match &probed.finding {
        DirectoryFinding::Present {
            is_directory: true,
            readable: true,
            ..
        } => Classified::available("The home directory is readable."),
        DirectoryFinding::Present {
            is_directory: false,
            ..
        } => Classified::not_available(
            CapabilityState::Unknown,
            "The home path is not a directory.",
        ),
        DirectoryFinding::Present { .. } => Classified::not_available(
            CapabilityState::Denied,
            "This process cannot read the home directory.",
        )
        .remediation("Make sure that the user owns the home directory and can read it."),
        DirectoryFinding::Absent { .. } => Classified::not_available(
            CapabilityState::Unknown,
            "The home directory does not exist.",
        ),
        DirectoryFinding::Failed { error, .. } => Classified::not_available(
            CapabilityState::Unknown,
            format!("The probe could not examine the home directory: {error}"),
        ),
    };
    directory_facts(classified, &probed.finding)
        .into_entry(CapabilityId::UserHomeDirectory, probed.method)
}

fn writable_directory_entry(id: CapabilityId, probed: Probed<DirectoryFinding>) -> CapabilityEntry {
    const OWNERSHIP_HINT: &str =
        "Make sure that the user owns the directory and its parent and can write to them.";
    let classified = match &probed.finding {
        DirectoryFinding::Present {
            is_directory: true,
            readable: true,
            writable: true,
            ..
        } => Classified::available("The directory exists and is writable."),
        DirectoryFinding::Present {
            is_directory: false,
            ..
        } => Classified::not_available(
            CapabilityState::Unknown,
            "An object that is not a directory is at the path.",
        )
        .remediation("Examine the object at the path. Svalnir does not replace it."),
        DirectoryFinding::Present { .. } => Classified::not_available(
            CapabilityState::Denied,
            "The directory exists, but this process cannot read and write it.",
        )
        .remediation(OWNERSHIP_HINT),
        DirectoryFinding::Absent {
            ancestor_writable: true,
            ..
        } => Classified::available(
            "The directory does not exist yet. Its nearest ancestor is writable, so Svalnir \
             can create it at first use. The probe did not create it.",
        ),
        DirectoryFinding::Absent { .. } => Classified::not_available(
            CapabilityState::Denied,
            "The directory does not exist, and this process cannot write to its nearest \
             ancestor.",
        )
        .remediation(OWNERSHIP_HINT),
        DirectoryFinding::Failed { error, .. } => Classified::not_available(
            CapabilityState::Unknown,
            format!("The probe could not examine the directory: {error}"),
        ),
    };
    directory_facts(classified, &probed.finding).into_entry(id, probed.method)
}

fn protected_outcome_text(outcome: &ProtectedReadOutcome) -> String {
    match outcome {
        ProtectedReadOutcome::Listed => "listed".to_owned(),
        ProtectedReadOutcome::NotPermitted => "operation_not_permitted".to_owned(),
        ProtectedReadOutcome::PermissionDenied => "permission_denied".to_owned(),
        ProtectedReadOutcome::Absent => "absent".to_owned(),
        ProtectedReadOutcome::Failed(error) => format!("failed: {error}"),
    }
}

fn full_disk_access_entry(
    role: WorkerRole,
    probed: Probed<ProtectedLocationsFinding>,
) -> CapabilityEntry {
    let attempts: &[ProtectedAttempt] = &probed.finding.attempts;
    let refused = attempts
        .iter()
        .any(|attempt| attempt.outcome == ProtectedReadOutcome::NotPermitted);
    let listed = attempts
        .iter()
        .any(|attempt| attempt.outcome == ProtectedReadOutcome::Listed);
    let mut classified = if refused {
        Classified::not_available(
            CapabilityState::Denied,
            "The system refused a read of a privacy-protected location. This process does \
             not have Full Disk Access.",
        )
        .remediation(match role {
            WorkerRole::Cli => {
                "Optional. To scan privacy-protected locations from this command, open System \
                 Settings > Privacy & Security > Full Disk Access and add the application that \
                 starts the command, for example your terminal. Then start that application \
                 again. This does not give the access to the background agent."
            }
            WorkerRole::Window => {
                "Optional. To scan privacy-protected locations from this window, open System \
                 Settings > Privacy & Security > Full Disk Access and add Svalnir. Then open \
                 Svalnir again. This does not give the access to the background agent."
            }
            WorkerRole::Agent | WorkerRole::Helper => {
                "Optional. To scan privacy-protected locations, open System Settings > Privacy \
                 & Security > Full Disk Access and add Svalnir."
            }
        })
    } else if listed {
        Classified::available(
            "This process read one or more privacy-protected locations, and the system \
             refused none. This does not show access to every protected location.",
        )
    } else if attempts.is_empty() {
        Classified::not_available(
            CapabilityState::Unknown,
            "The probe could not resolve a privacy-protected location to try. The home \
             directory of the account database is not known.",
        )
    } else {
        Classified::not_available(
            CapabilityState::Unknown,
            "No attempt gave a result that shows the state of the privacy control. Each \
             candidate location is absent or failed for a different reason.",
        )
    };
    for attempt in attempts {
        classified = classified.fact(
            &path_label(&attempt.path),
            protected_outcome_text(&attempt.outcome),
        );
    }
    if let Some(error) = &probed.finding.account_home_error {
        classified = classified.fact("account_home_error", error.clone());
    }
    if let Some(home) = &probed.finding.home_variable_differs {
        classified = classified.fact("home_variable_differs", path_label(home));
        if let Some(account) = &probed.finding.account_home {
            classified = classified.fact("account_home", path_label(account));
        }
    }
    classified.into_entry(CapabilityId::FullDiskAccess, probed.method)
}

fn source_entry(id: CapabilityId, probed: Probed<SourceFinding>) -> CapabilityEntry {
    let classified = match probed.finding {
        SourceFinding::Responded { detail } => {
            Classified::available("The source answered the query.").fact("result", detail)
        }
        SourceFinding::Denied { detail } => Classified::not_available(
            CapabilityState::Denied,
            format!("The system refused the query: {detail}"),
        ),
        SourceFinding::Unsupported { detail } => Classified::not_available(
            CapabilityState::Unsupported,
            format!("The host does not have this source: {detail}"),
        ),
        SourceFinding::Failed { detail } => Classified::not_available(
            CapabilityState::Unknown,
            format!("The query failed: {detail}"),
        ),
    };
    classified.into_entry(id, probed.method)
}

fn service_entry(id: CapabilityId, probed: Probed<ServiceFinding>) -> CapabilityEntry {
    let locations = &probed.finding.locations;
    let found = locations
        .iter()
        .any(|location| matches!(location.outcome, ServiceLocationOutcome::Found(_)));
    let unreadable = locations
        .iter()
        .any(|location| matches!(location.outcome, ServiceLocationOutcome::Unreadable(_)));
    let (registration, reason) = if found {
        (
            RegistrationState::RegistrationFilePresent,
            "A registration file is present. A client cannot show that the service is loaded \
             or that it passed its own access probes; the service must report them.",
        )
    } else if unreadable || locations.is_empty() {
        (
            RegistrationState::Unknown,
            "The probe could not read each conventional registration directory, so the \
             registration state is not established.",
        )
    } else {
        (
            RegistrationState::NotInstalled,
            "No registration file is in a conventional directory, so the service is not \
             installed there. A registration through the application bundle is not visible \
             to this check. With no service process, no probe ran under its identity.",
        )
    };
    let mut classified = Classified::not_available(CapabilityState::Unknown, reason)
        .fact("registration", registration.as_str());
    classified.registration = Some(registration);
    for location in locations {
        let value = match &location.outcome {
            ServiceLocationOutcome::Found(names) => format!("found: {}", names.join(", ")),
            ServiceLocationOutcome::NotFound => "no Svalnir entry".to_owned(),
            ServiceLocationOutcome::Absent => "absent".to_owned(),
            ServiceLocationOutcome::Unreadable(error) => format!("unreadable: {error}"),
        };
        classified = classified.fact(&path_label(&location.directory), value);
    }
    classified.into_entry(id, probed.method)
}

fn sip_entry(probed: Probed<SipFinding>) -> CapabilityEntry {
    let classified = match probed.finding {
        SipFinding::Enabled => Classified::available("System Integrity Protection is enabled.")
            .fact("status", "enabled"),
        SipFinding::Disabled => Classified::available(
            "System Integrity Protection is disabled. Svalnir does not need this; Apple \
             recommends that the protection stays enabled.",
        )
        .fact("status", "disabled"),
        SipFinding::Other(status) => Classified::available(
            "The system reports a status of System Integrity Protection that is not plain \
             `enabled` or `disabled`.",
        )
        .fact("status", status),
        SipFinding::Unsupported => Classified::not_available(
            CapabilityState::Unsupported,
            "The host has no System Integrity Protection.",
        ),
        SipFinding::NotDetermined(error) => Classified::not_available(
            CapabilityState::Unknown,
            format!("The probe could not read the status: {error}"),
        ),
    };
    classified.into_entry(CapabilityId::SystemIntegrityProtection, probed.method)
}
