//! Diagnostic capability probes: the data behind `svalnir doctor`.
//!
//! [`diagnose`] runs bounded, read-only probes under the identity of the
//! calling process and returns a [`CapabilityReport`]. Each capability has
//! an `available`, `denied`, `unsupported`, or `unknown` state, the evidence
//! for it, what it enables, and a safe hint for the user.
//!
//! The report applies to the process that ran the probes. Access that the
//! user gave to a terminal does not show that a separately started service
//! has the same access, so the report names the tested process and its role.
//! A read probe does not authorize deletion or signaling, and a capability
//! can go away after a successful probe.
//!
//! No probe shows a consent dialog, registers or removes a service, writes a
//! file, or uses elevated rights. Where no reliable read-only check exists,
//! the state is `unknown` with the reason; it is not `denied`.
//!
//! A diagnostic query succeeds when it reports a denied capability. The
//! [`Summary`] separates the capabilities that the read-only Milestone 1
//! commands need from the optional ones; only the required ones set the
//! [`Verdict`].
//!
//! | Module | Content |
//! | --- | --- |
//! | [`report`] | The report types and the classification of findings |
//! | [`probe`] | The probe interface and the finding types |
//! | [`host`] | The probes of the real host |
//!
//! Owning specification: `docs/RESOURCE_MODEL.md` section 13.

pub mod host;
#[cfg(target_os = "macos")]
mod native;
pub mod probe;
pub mod report;
#[cfg(target_os = "macos")]
mod sip;

pub use host::HostProbes;
pub use probe::CapabilityProbes;
pub use report::{
    CapabilityEntry, CapabilityId, CapabilityReport, Evidence, EvidenceFact, ProbeSubject,
    RegistrationState, Requirement, StateCounts, Summary, Verdict, WorkerRole, build_report,
};

/// Runs each probe on the real host under the identity of this process.
///
/// `role` states which component the calling process is. The function
/// cannot establish the role itself; the CLI passes [`WorkerRole::Cli`], and a
/// window of the graphical client passes [`WorkerRole::Window`].
pub fn diagnose(role: WorkerRole) -> CapabilityReport {
    build_report(ProbeSubject::current(role), host::now(), &HostProbes::new())
}

/// Runs each probe as [`diagnose`] does, for a process that uses
/// `state_directory`.
///
/// The state-directory entry describes `state_directory`, which can be a
/// directory other than the default one below the home directory.
pub fn diagnose_in(role: WorkerRole, state_directory: &std::path::Path) -> CapabilityReport {
    build_report(
        ProbeSubject::current(role),
        host::now(),
        &HostProbes::new().with_state_directory(state_directory.to_path_buf()),
    )
}

#[cfg(test)]
mod tests;
