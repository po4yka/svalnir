//! The safe boundary between the native process queries and the inventory
//! logic.
//!
//! [`ProcessSource`] has one method for each native query. The Darwin
//! implementation is in `native.rs`. A test gives a synthetic implementation,
//! so the identity and attribution logic runs with no live process.

use svalnir_core::file::{FileObjectEvidence, LosslessPath};
use svalnir_core::observation::UnavailableReason;
use svalnir_core::process::{Pid, ProcessStartTime, Uid};
use svalnir_core::quantity::Nanoseconds;
use svalnir_core::time::{MonotonicNanos, WallTime};
use thiserror::Error;

/// The reason a native query gave no result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum QueryFailure {
    /// The process does not exist, or it is a zombie that has no data.
    #[error("the process does not exist")]
    Gone,
    /// The worker has no permission for the query.
    #[error("the worker has no permission for the query")]
    PermissionDenied,
    /// The host does not supply the query.
    #[error("the host does not supply the query")]
    Unsupported,
    /// The source returned data that is not consistent, for example a
    /// structure of an incorrect size.
    #[error("the source returned data that is not consistent")]
    Inconsistent,
    /// A checked conversion of the native value overflowed.
    #[error("a checked conversion overflowed")]
    Overflow,
    /// The query failed with this `errno` value and can succeed later.
    #[error("the query failed with errno {0}")]
    Failed(i32),
}

impl QueryFailure {
    /// The stable reason for an unavailable reading.
    pub fn reason(self) -> UnavailableReason {
        match self {
            Self::Gone => UnavailableReason::ResourceGone,
            Self::PermissionDenied => UnavailableReason::PermissionDenied,
            Self::Unsupported => UnavailableReason::Unsupported,
            Self::Inconsistent => UnavailableReason::InconsistentData,
            Self::Overflow => UnavailableReason::Overflow,
            Self::Failed(_) => UnavailableReason::TransientFailure,
        }
    }
}

/// The identity evidence of one process as the kernel reports it at one
/// time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawProcessInfo {
    /// The process ID that the kernel wrote into the record.
    pub pid: Pid,
    /// The parent process ID. `None` when the kernel reports no parent.
    pub parent_pid: Option<Pid>,
    /// The effective user ID.
    pub effective_uid: Uid,
    /// The real user ID.
    pub real_uid: Uid,
    /// The start time.
    pub start_time: ProcessStartTime,
    /// The process is a zombie: it exited and its parent has not collected
    /// its status.
    pub zombie: bool,
}

/// The resource use of one process as `proc_pid_rusage` reports it.
///
/// The CPU fields are in Mach absolute-time units. They are not nanoseconds
/// until [`Timebase::to_nanoseconds`] converts them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawUsage {
    /// `ri_phys_footprint`, in bytes.
    pub physical_footprint: u64,
    /// `ri_resident_size`, in bytes.
    pub resident_size: u64,
    /// `ri_lifetime_max_phys_footprint`, in bytes.
    pub lifetime_max_physical_footprint: u64,
    /// `ri_user_time`, in Mach absolute-time units.
    pub user_time_mach: u64,
    /// `ri_system_time`, in Mach absolute-time units.
    pub system_time_mach: u64,
    /// `ri_diskio_bytesread`, in bytes.
    pub disk_bytes_read: u64,
    /// `ri_diskio_byteswritten`, in bytes.
    pub disk_bytes_written: u64,
}

/// The ratio that converts Mach absolute-time units to nanoseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timebase {
    numerator: u32,
    denominator: u32,
}

impl Timebase {
    /// Makes the ratio. Returns `None` when a term is zero.
    pub const fn new(numerator: u32, denominator: u32) -> Option<Self> {
        if numerator == 0 || denominator == 0 {
            return None;
        }
        Some(Self {
            numerator,
            denominator,
        })
    }

    /// Converts Mach absolute-time units to nanoseconds. Returns `None` on
    /// overflow.
    pub fn to_nanoseconds(self, mach_units: u64) -> Option<u64> {
        let scaled: u128 = u128::from(mach_units).checked_mul(u128::from(self.numerator))?;
        u64::try_from(scaled / u128::from(self.denominator)).ok()
    }
}

/// One running application as Launch Services registers it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunningApplication {
    /// The process ID of the registered process of the application.
    pub pid: Pid,
    /// The bundle identifier. `None` when the application has no bundle
    /// identifier.
    pub bundle_identifier: Option<String>,
    /// The path of the executable of the application, when Launch Services
    /// gives one.
    pub executable_path: Option<LosslessPath>,
    /// The application is the active (frontmost) application.
    pub active: bool,
    /// The application has terminated.
    pub terminated: bool,
}

/// The native queries that the inventory uses.
///
/// Each method addresses a process by its PID, because the native API does.
/// A PID is not an identity. The inventory reads the start time before and
/// after the other queries and drops a process whose evidence changed.
pub trait ProcessSource {
    /// The effective user ID of the collecting process.
    fn effective_uid(&self) -> Uid;

    /// The process IDs that exist now.
    ///
    /// # Errors
    ///
    /// Returns a [`QueryFailure`] when the kernel gives no list.
    fn list_pids(&self) -> Result<Vec<Pid>, QueryFailure>;

    /// The identity evidence of the process that has this PID now.
    ///
    /// # Errors
    ///
    /// Returns a [`QueryFailure`] when the process does not exist or the
    /// query is denied.
    fn process_info(&self, pid: Pid) -> Result<RawProcessInfo, QueryFailure>;

    /// The path of the executable of the process that has this PID now.
    ///
    /// # Errors
    ///
    /// Returns a [`QueryFailure`] when the kernel gives no path.
    fn executable_path(&self, pid: Pid) -> Result<LosslessPath, QueryFailure>;

    /// The file object at `path` now.
    ///
    /// # Errors
    ///
    /// Returns a [`QueryFailure`] when the collector cannot read the file
    /// attributes.
    fn file_evidence(&self, path: &LosslessPath) -> Result<FileObjectEvidence, QueryFailure>;

    /// The resource use of the process that has this PID now.
    ///
    /// # Errors
    ///
    /// Returns a [`QueryFailure`] when the process does not exist or the
    /// query is denied.
    fn usage(&self, pid: Pid) -> Result<RawUsage, QueryFailure>;

    /// The process that the system names as responsible for the process that
    /// has this PID now.
    ///
    /// # Errors
    ///
    /// Returns a [`QueryFailure`] when the host does not supply the
    /// relationship or the query fails.
    fn responsible_pid(&self, pid: Pid) -> Result<Pid, QueryFailure>;

    /// Whether the list of [`running_applications`](Self::running_applications)
    /// is known to be current.
    ///
    /// The collector calls this once for each collection, before it reads the
    /// list. The first collection in a process is current. A later one is
    /// current only with evidence that the list was refreshed.
    fn application_list_current(&self) -> bool;

    /// The applications that Launch Services registers as running.
    ///
    /// The list can be older than the call: `NSWorkspace` refreshes it only
    /// when the main run loop runs. Thus an entry is bound to a process
    /// generation by its executable path, not by its PID alone.
    ///
    /// # Errors
    ///
    /// Returns a [`QueryFailure`] when the host gives no list.
    fn running_applications(&self) -> Result<Vec<RunningApplication>, QueryFailure>;

    /// The ratio that converts the CPU fields of [`RawUsage`].
    ///
    /// # Errors
    ///
    /// Returns a [`QueryFailure`] when the kernel gives no valid ratio.
    fn timebase(&self) -> Result<Timebase, QueryFailure>;

    /// The time on the monotonic clock of [`CLOCK_DOMAIN`](super::CLOCK_DOMAIN).
    ///
    /// # Errors
    ///
    /// Returns a [`QueryFailure`] when the clock gives no value.
    fn monotonic_now(&self) -> Result<MonotonicNanos, QueryFailure>;

    /// The cumulative time that the host slept in the current boot.
    ///
    /// # Errors
    ///
    /// Returns the reason the host gives no sleep time.
    fn sleep_time(&self) -> Result<Nanoseconds, UnavailableReason>;

    /// The wall-clock time.
    ///
    /// # Errors
    ///
    /// Returns a [`QueryFailure`] when the clock gives no valid value.
    fn wall_now(&self) -> Result<WallTime, QueryFailure>;
}

#[cfg(test)]
mod tests {
    use svalnir_core::observation::UnavailableReason;

    use super::{QueryFailure, Timebase};

    #[test]
    fn a_timebase_converts_with_the_ratio() {
        // The ratio of Apple silicon: one unit is 125/3 nanoseconds.
        let timebase: Timebase = Timebase::new(125, 3).unwrap();
        assert_eq!(timebase.to_nanoseconds(24), Some(1_000));
        assert_eq!(timebase.to_nanoseconds(0), Some(0));
        let identity: Timebase = Timebase::new(1, 1).unwrap();
        assert_eq!(identity.to_nanoseconds(u64::MAX), Some(u64::MAX));
    }

    #[test]
    fn a_timebase_reports_overflow_and_rejects_zero_terms() {
        let timebase: Timebase = Timebase::new(125, 3).unwrap();
        assert_eq!(timebase.to_nanoseconds(u64::MAX), None);
        assert_eq!(Timebase::new(0, 1), None);
        assert_eq!(Timebase::new(1, 0), None);
    }

    #[test]
    fn each_failure_has_a_stable_reason() {
        assert_eq!(QueryFailure::Gone.reason(), UnavailableReason::ResourceGone);
        assert_eq!(
            QueryFailure::PermissionDenied.reason(),
            UnavailableReason::PermissionDenied
        );
        assert_eq!(
            QueryFailure::Unsupported.reason(),
            UnavailableReason::Unsupported
        );
        assert_eq!(
            QueryFailure::Inconsistent.reason(),
            UnavailableReason::InconsistentData
        );
        assert_eq!(QueryFailure::Overflow.reason(), UnavailableReason::Overflow);
        assert_eq!(
            QueryFailure::Failed(5).reason(),
            UnavailableReason::TransientFailure
        );
    }
}
