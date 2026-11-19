//! The catalog of hard protections of application and job instances.
//!
//! Owning specification: `docs/ACTION_CONTRACTS.md` section 8. A hard
//! protection is a product protection: no profile, policy, or grant removes
//! it. The catalog is pure. The caller gives the processes of one instance
//! and the facts of the control plane, and gets a [`ProtectionFact`].
//!
//! Each rule can only add a protection. A name, a path, or a bundle
//! identifier never makes a process a target; it can make a process
//! protected. An instance with a member that the catalog cannot classify is
//! [`ProtectionFact::Unknown`], which each evaluation skips.

use serde::Serialize;

use super::control::ProtectionFact;
use crate::process::{Pid, ProcessAssociation, ProcessIdentity, ProcessStartTime, Uid};

/// The directories of the operating system. An executable below one of them
/// is an essential system process. The comparison ignores ASCII case.
pub const SYSTEM_DIRECTORIES: [&str; 5] =
    ["/System/", "/usr/", "/bin/", "/sbin/", "/Library/Apple/"];

/// The directory below `/usr/` that the operating system does not own.
pub const LOCAL_DIRECTORY: &str = "/usr/local/";

/// The bundle identifiers of the applications of the login session. The
/// comparison ignores ASCII case.
pub const SESSION_BUNDLE_IDENTIFIERS: [&str; 10] = [
    "com.apple.finder",
    "com.apple.dock",
    "com.apple.loginwindow",
    "com.apple.systemuiserver",
    "com.apple.controlcenter",
    "com.apple.notificationcenterui",
    "com.apple.WindowManager",
    "com.apple.Spotlight",
    "com.apple.SecurityAgent",
    "com.apple.coreservices.uiagent",
];

/// The bundle identifier of Svalnir, and the prefix of the bundle
/// identifiers of its components.
pub const CONTROL_PLANE_BUNDLE_IDENTIFIER: &str = "dev.po4yka.svalnir";

/// The file names of the Svalnir executables. The comparison ignores ASCII
/// case.
pub const CONTROL_PLANE_EXECUTABLES: [&str; 4] = [
    "svalnir",
    "svalnir-agent",
    "svalnir-privileged",
    "svalnir-gui",
];

/// The process ID of `launchd`.
const LAUNCHD_PID: i32 = 1;

/// The user ID of root.
const ROOT_UID: u32 = 0;

/// One process of the control plane: the process that evaluates, or one of
/// its ancestors.
///
/// The start time is part of the identity, so a new process that got the PID
/// of an ancestor that exited has no protection from this record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ControlPlaneProcess {
    /// The process ID.
    pub pid: Pid,
    /// The start time that the kernel reports.
    pub start_time: ProcessStartTime,
}

/// The facts that the catalog needs about the evaluating process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtectionContext<'a> {
    /// The user that the evaluation acts for.
    pub principal: Uid,
    /// The evaluating process and its ancestors. `None` when the caller
    /// could not establish them: then no instance is known to be outside the
    /// control plane.
    pub control_plane: Option<&'a [ControlPlaneProcess]>,
}

/// The entry that the executable path matches. The outer `None` means that
/// the path is not one that the catalog can classify; `Some(None)` means
/// that the path matches no entry.
///
/// The comparison ignores ASCII case, because the default volume format of
/// macOS does. A rule can only add a protection, so a match that a
/// case-sensitive volume would not make is the safe direction.
fn path_entry(path: &[u8]) -> Option<Option<HardProtectionEntry>> {
    // The path must be absolute, with no empty, `.`, or `..` component: such
    // a component can make the text name a file outside its prefix.
    let mut components = path.split(|byte| *byte == b'/');
    if components.next() != Some(b"".as_slice()) {
        return None;
    }
    let mut file_name: Option<&[u8]> = None;
    for component in components {
        if component.is_empty() || component == b"." || component == b".." {
            return None;
        }
        file_name = Some(component);
    }
    let file_name: &[u8] = file_name?;
    let has_prefix = |prefix: &str| {
        path.get(..prefix.len())
            .is_some_and(|start| start.eq_ignore_ascii_case(prefix.as_bytes()))
    };
    let in_system_directory: bool = SYSTEM_DIRECTORIES
        .iter()
        .any(|directory| has_prefix(directory))
        && !has_prefix(LOCAL_DIRECTORY);
    let is_control_plane: bool = CONTROL_PLANE_EXECUTABLES
        .iter()
        .any(|name| file_name.eq_ignore_ascii_case(name.as_bytes()));
    Some(if in_system_directory {
        Some(HardProtectionEntry::SystemLocation)
    } else if is_control_plane {
        Some(HardProtectionEntry::ControlPlaneExecutable)
    } else {
        None
    })
}

/// The entry of the catalog that protects one process.
///
/// The catalog examines the entries in the sequence of this list, and the
/// first entry that matches is the reason. A process can match more than
/// one entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HardProtectionEntry {
    /// The owner of the process is not the principal.
    DifferentOwner,
    /// The owner of the process is root.
    RootOwner,
    /// The process is `launchd`.
    Launchd,
    /// The bundle identifier is in [`SESSION_BUNDLE_IDENTIFIERS`]: an
    /// application of the login session.
    SessionApplication,
    /// The bundle identifier is the identifier of Svalnir or of one of its
    /// components.
    ControlPlaneBundle,
    /// The process is the evaluating process or one of its ancestors.
    ControlPlaneProcess,
    /// The executable is below one of the [`SYSTEM_DIRECTORIES`] and not
    /// below [`LOCAL_DIRECTORY`].
    SystemLocation,
    /// The executable has the file name of a Svalnir executable.
    ControlPlaneExecutable,
}

impl HardProtectionEntry {
    /// The stable text of the entry.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DifferentOwner => "different_owner",
            Self::RootOwner => "root_owner",
            Self::Launchd => "launchd",
            Self::SessionApplication => "session_application",
            Self::ControlPlaneBundle => "control_plane_bundle",
            Self::ControlPlaneProcess => "control_plane_process",
            Self::SystemLocation => "system_location",
            Self::ControlPlaneExecutable => "control_plane_executable",
        }
    }
}

/// The reason the catalog cannot classify one process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionUnknownCause {
    /// The instance has no member.
    NoMember,
    /// The process has no executable evidence.
    NoExecutableEvidence,
    /// The executable path is not one that the catalog can classify: a
    /// relative path, or a path with an empty, `.`, or `..` component.
    PathNotClassified,
    /// The caller could not establish the processes of the control plane.
    ControlPlaneNotKnown,
}

impl ProtectionUnknownCause {
    /// The stable text of the cause.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoMember => "no_member",
            Self::NoExecutableEvidence => "no_executable_evidence",
            Self::PathNotClassified => "path_not_classified",
            Self::ControlPlaneNotKnown => "control_plane_not_known",
        }
    }
}

/// One member of an instance: the process ID with the start time, so that a
/// new process with the same PID is not the same member.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProtectionMember {
    /// The process ID.
    pub pid: Pid,
    /// The start time that the kernel reports.
    pub start_time: ProcessStartTime,
}

/// The hard protection of one instance, with the member and the catalog
/// entry that decided it. [`HardProtectionExplanation::fact`] is the value
/// of [`hard_protection`] for the same inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HardProtectionExplanation {
    /// Each member is classified, and none is protected.
    NotProtected,
    /// A member is protected. The value names the first protected member in
    /// the sequence of the input and the first entry that it matches. A
    /// different member can match a different entry.
    Protected {
        /// The member.
        member: ProtectionMember,
        /// The entry of the catalog.
        entry: HardProtectionEntry,
    },
    /// No member is protected, and the catalog cannot classify the
    /// instance. The value names the first member with no classification.
    Unknown {
        /// The member. `None` when the instance has no member.
        member: Option<ProtectionMember>,
        /// The cause.
        cause: ProtectionUnknownCause,
    },
}

impl HardProtectionExplanation {
    /// The protection fact.
    pub const fn fact(&self) -> ProtectionFact {
        match self {
            Self::NotProtected => ProtectionFact::NotProtected,
            Self::Protected { .. } => ProtectionFact::Protected,
            Self::Unknown { .. } => ProtectionFact::Unknown,
        }
    }
}

/// The classification of one process.
enum ProcessProtection {
    NotProtected,
    Protected(HardProtectionEntry),
    Unknown(ProtectionUnknownCause),
}

fn bundle_entry(association: &ProcessAssociation) -> Option<HardProtectionEntry> {
    // The association is read without the membership check: a claim that
    // has no verified method still protects.
    let ProcessAssociation::Application {
        bundle_identifier, ..
    } = association
    else {
        return None;
    };
    if SESSION_BUNDLE_IDENTIFIERS
        .iter()
        .any(|protected| bundle_identifier.eq_ignore_ascii_case(protected))
    {
        return Some(HardProtectionEntry::SessionApplication);
    }
    let component_prefix: String = format!("{CONTROL_PLANE_BUNDLE_IDENTIFIER}.");
    let is_control_plane: bool = bundle_identifier
        .eq_ignore_ascii_case(CONTROL_PLANE_BUNDLE_IDENTIFIER)
        || bundle_identifier
            .get(..component_prefix.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(&component_prefix));
    is_control_plane.then_some(HardProtectionEntry::ControlPlaneBundle)
}

/// The entry that the owner, the process ID, or the bundle identifier of a
/// process matches.
fn identity_entry(
    process: &ProcessIdentity,
    context: &ProtectionContext<'_>,
) -> Option<HardProtectionEntry> {
    if process.uid != context.principal {
        Some(HardProtectionEntry::DifferentOwner)
    } else if process.uid.get() == ROOT_UID {
        Some(HardProtectionEntry::RootOwner)
    } else if process.pid.get() == LAUNCHD_PID {
        Some(HardProtectionEntry::Launchd)
    } else {
        bundle_entry(&process.association)
    }
}

fn process_protection(
    process: &ProcessIdentity,
    context: &ProtectionContext<'_>,
) -> ProcessProtection {
    if let Some(entry) = identity_entry(process, context) {
        return ProcessProtection::Protected(entry);
    }
    let in_control_plane: Option<bool> = context.control_plane.map(|control_plane| {
        control_plane
            .iter()
            .any(|member| member.pid == process.pid && member.start_time == process.start_time)
    });
    if in_control_plane == Some(true) {
        return ProcessProtection::Protected(HardProtectionEntry::ControlPlaneProcess);
    }
    let Some(executable) = process.executable.as_ref() else {
        return ProcessProtection::Unknown(ProtectionUnknownCause::NoExecutableEvidence);
    };
    match (path_entry(executable.path.as_bytes()), in_control_plane) {
        (Some(Some(entry)), _) => ProcessProtection::Protected(entry),
        (Some(None), Some(false)) => ProcessProtection::NotProtected,
        (None, _) => ProcessProtection::Unknown(ProtectionUnknownCause::PathNotClassified),
        // `Some(true)` returned before this point.
        (Some(None), _) => ProcessProtection::Unknown(ProtectionUnknownCause::ControlPlaneNotKnown),
    }
}

/// The hard protection of one application or job instance, with its reason.
///
/// The decision is the decision of [`hard_protection`]: that function
/// returns [`HardProtectionExplanation::fact`] of this value. The value adds
/// the member and the entry of the catalog that decided it, so that a view
/// can tell the user why an instance is protected.
///
/// The catalog has no entry for a configured protection. The bundle
/// identifiers and the executable paths of `[protections]` and of
/// `[memory_guard]` are not hard protections: the evaluation of the memory
/// guard applies them and gives its own reasons.
pub fn explain_hard_protection(
    processes: &[ProcessIdentity],
    context: &ProtectionContext<'_>,
) -> HardProtectionExplanation {
    let mut unknown: Option<HardProtectionExplanation> = None;
    for process in processes {
        let member: ProtectionMember = ProtectionMember {
            pid: process.pid,
            start_time: process.start_time,
        };
        match process_protection(process, context) {
            ProcessProtection::Protected(entry) => {
                return HardProtectionExplanation::Protected { member, entry };
            }
            ProcessProtection::Unknown(cause) => {
                unknown.get_or_insert(HardProtectionExplanation::Unknown {
                    member: Some(member),
                    cause,
                });
            }
            ProcessProtection::NotProtected => {}
        }
    }
    if processes.is_empty() {
        return HardProtectionExplanation::Unknown {
            member: None,
            cause: ProtectionUnknownCause::NoMember,
        };
    }
    unknown.unwrap_or(HardProtectionExplanation::NotProtected)
}

/// The hard protection of one application or job instance.
///
/// `processes` are the members of the instance. The instance is protected
/// when one member is protected:
///
/// - The owner is not the principal, or is root.
/// - The process is `launchd`.
/// - The process is the evaluating process or one of its ancestors.
/// - The bundle identifier is in [`SESSION_BUNDLE_IDENTIFIERS`], or is the
///   identifier of Svalnir or of one of its components.
/// - The executable is below one of the [`SYSTEM_DIRECTORIES`] and not below
///   [`LOCAL_DIRECTORY`], or has the file name of a Svalnir executable.
///
/// With no protected member, the instance is [`ProtectionFact::Unknown`]
/// when it has no member, a member has no executable evidence or a path that
/// the catalog cannot classify (a relative path, or a path with an empty,
/// `.`, or `..` component), or the control plane is not known. In each
/// other case it is [`ProtectionFact::NotProtected`].
pub fn hard_protection(
    processes: &[ProcessIdentity],
    context: &ProtectionContext<'_>,
) -> ProtectionFact {
    explain_hard_protection(processes, context).fact()
}
