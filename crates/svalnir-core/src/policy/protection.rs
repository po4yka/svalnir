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

use super::control::ProtectionFact;
use crate::process::{Pid, ProcessAssociation, ProcessIdentity, ProcessStartTime, Uid};

/// The directories of the operating system. An executable below one of them
/// is an essential system process.
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
pub const CONTROL_PLANE_BUNDLE_IDENTIFIER: &str = "dev.svalnir";

/// The file names of the Svalnir executables.
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

fn has_protected_bundle(association: &ProcessAssociation) -> bool {
    // The association is read without the membership check: a claim that
    // has no verified method still protects.
    let ProcessAssociation::Application {
        bundle_identifier, ..
    } = association
    else {
        return false;
    };
    let component_prefix: String = format!("{CONTROL_PLANE_BUNDLE_IDENTIFIER}.");
    SESSION_BUNDLE_IDENTIFIERS
        .iter()
        .any(|protected| bundle_identifier.eq_ignore_ascii_case(protected))
        || bundle_identifier.eq_ignore_ascii_case(CONTROL_PLANE_BUNDLE_IDENTIFIER)
        || bundle_identifier
            .get(..component_prefix.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(&component_prefix))
}

/// The protection that the executable path gives. `None` when the path is
/// not one that the catalog can classify.
fn path_protection(path: &[u8]) -> Option<bool> {
    // A path with a parent component can leave the directory of its prefix.
    let has_parent_component: bool = path.split(|byte| *byte == b'/').any(|part| part == b"..");
    if has_parent_component || !path.starts_with(b"/") {
        return None;
    }
    let in_system_directory: bool = SYSTEM_DIRECTORIES
        .iter()
        .any(|directory| path.starts_with(directory.as_bytes()))
        && !path.starts_with(LOCAL_DIRECTORY.as_bytes());
    let file_name: &[u8] = path.rsplit(|byte| *byte == b'/').next().unwrap_or(path);
    let is_control_plane: bool = CONTROL_PLANE_EXECUTABLES
        .iter()
        .any(|name| file_name == name.as_bytes());
    Some(in_system_directory || is_control_plane)
}

fn process_protection(
    process: &ProcessIdentity,
    context: &ProtectionContext<'_>,
) -> ProtectionFact {
    if process.uid != context.principal
        || process.uid.get() == ROOT_UID
        || process.pid.get() == LAUNCHD_PID
        || has_protected_bundle(&process.association)
    {
        return ProtectionFact::Protected;
    }
    let in_control_plane: Option<bool> = context.control_plane.map(|control_plane| {
        control_plane
            .iter()
            .any(|member| member.pid == process.pid && member.start_time == process.start_time)
    });
    if in_control_plane == Some(true) {
        return ProtectionFact::Protected;
    }
    let by_path: Option<bool> = process
        .executable
        .as_ref()
        .and_then(|executable| path_protection(executable.path.as_bytes()));
    match (by_path, in_control_plane) {
        (Some(true), _) => ProtectionFact::Protected,
        (Some(false), Some(false)) => ProtectionFact::NotProtected,
        // No executable evidence, a path that cannot be classified, or an
        // unknown control plane.
        _ => ProtectionFact::Unknown,
    }
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
/// the catalog cannot classify, or the control plane is not known. In each
/// other case it is [`ProtectionFact::NotProtected`].
pub fn hard_protection(
    processes: &[ProcessIdentity],
    context: &ProtectionContext<'_>,
) -> ProtectionFact {
    let mut result: ProtectionFact = if processes.is_empty() {
        ProtectionFact::Unknown
    } else {
        ProtectionFact::NotProtected
    };
    for process in processes {
        match process_protection(process, context) {
            ProtectionFact::Protected => return ProtectionFact::Protected,
            ProtectionFact::Unknown => result = ProtectionFact::Unknown,
            ProtectionFact::NotProtected => {}
        }
    }
    result
}
