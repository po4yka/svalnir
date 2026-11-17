//! Process observation identity.
//!
//! `docs/RESOURCE_MODEL.md` sections 2 and 11 own the identity. A process
//! generation binds the PID to its start evidence, owner, boot, and
//! executable. A PID, a name, or a bundle identifier alone is not identity:
//! a restarted application is a different generation.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::encoding::unsigned_quantity;
use crate::file::{FileObjectEvidence, LosslessPath};
use crate::id::{ApplicationInstanceId, BootId, ProcessGenerationId};

/// The process ID is zero or negative.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("the process ID is not a positive integer")]
pub struct PidError;

/// A process ID (`pid_t`). The value is positive.
///
/// JSON encodes it as an integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "i32", into = "i32")]
pub struct Pid(i32);

impl Pid {
    /// Makes a process ID.
    ///
    /// # Errors
    ///
    /// Returns [`PidError`] when the value is zero or negative. Those values
    /// address the kernel or a process group, not one process.
    pub const fn new(value: i32) -> Result<Self, PidError> {
        if value <= 0 {
            return Err(PidError);
        }
        Ok(Self(value))
    }

    /// The native value.
    pub const fn get(self) -> i32 {
        self.0
    }
}

impl TryFrom<i32> for Pid {
    type Error = PidError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<Pid> for i32 {
    fn from(pid: Pid) -> Self {
        pid.0
    }
}

/// A user ID (`uid_t`). JSON encodes it as an integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Uid(u32);

impl Uid {
    /// Makes the value from the native number.
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// The native value.
    pub const fn get(self) -> u32 {
        self.0
    }
}

unsigned_quantity! {
    /// The start time of a process as the kernel reports it, in microseconds
    /// since the Unix epoch.
    ///
    /// The value is identity evidence. It is not a wall-clock time for
    /// display and not a monotonic timestamp.
    ProcessStartTime
}

impl ProcessStartTime {
    /// Makes the value from the seconds and microseconds of a native
    /// `timeval`. Returns `None` when the microseconds are one second or
    /// more, or on overflow.
    #[must_use]
    pub const fn from_timeval(seconds: u64, microseconds: u32) -> Option<Self> {
        if microseconds >= 1_000_000 {
            return None;
        }
        let Some(whole) = seconds.checked_mul(1_000_000) else {
            return None;
        };
        match whole.checked_add(microseconds as u64) {
            Some(value) => Some(Self::new(value)),
            None => None,
        }
    }
}

/// Evidence of the executable that a process runs.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ExecutableIdentity {
    /// The path of the executable as the kernel reports it.
    pub path: LosslessPath,
    /// The file object at that path, when the collector can read it.
    pub file: Option<FileObjectEvidence>,
}

/// The application or managed job that a process belongs to.
///
/// Membership needs positive application or job evidence. Parentage, a
/// display name, or the basename of the executable does not make a process a
/// member.
///
/// JSON encodes the association as an object with a `kind` field. A `kind`
/// that this build does not know decodes to `Unrecognized`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProcessAssociation {
    /// The process belongs to a running application.
    Application {
        /// The running application instance.
        instance_id: ApplicationInstanceId,
        /// The bundle identifier of the application.
        bundle_identifier: String,
    },
    /// The process belongs to a managed job, for example a launchd job.
    ManagedJob {
        /// The running job instance.
        instance_id: ApplicationInstanceId,
        /// The label of the job.
        label: String,
    },
    /// No application or job evidence was found.
    Unattributed,
    /// An association kind that this build does not recognize. It is not
    /// `Unattributed`.
    #[serde(other)]
    Unrecognized,
}

/// The identity of one observed process generation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcessIdentity {
    /// The opaque identity of this generation.
    pub generation_id: ProcessGenerationId,
    /// The process ID.
    pub pid: Pid,
    /// The start time that the kernel reports.
    pub start_time: ProcessStartTime,
    /// The user that owns the process.
    pub uid: Uid,
    /// The boot in which the process runs.
    pub boot_id: BootId,
    /// The executable, when the collector can read it. `None` limits the
    /// operations that this record can support.
    pub executable: Option<ExecutableIdentity>,
    /// The application or job association.
    pub association: ProcessAssociation,
}

impl ProcessIdentity {
    /// Whether `other` has the same native evidence: PID, start time, owner,
    /// boot, and executable.
    ///
    /// The opaque identity and the association are not compared. A `false`
    /// result means that the process was replaced, changed its owner, or
    /// changed its executable. A `true` result does not make a later signal
    /// atomic with this check.
    pub fn has_same_evidence(&self, other: &Self) -> bool {
        self.pid == other.pid
            && self.start_time == other.start_time
            && self.uid == other.uid
            && self.boot_id == other.boot_id
            && self.executable == other.executable
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::{
        ExecutableIdentity, Pid, PidError, ProcessAssociation, ProcessIdentity, ProcessStartTime,
        Uid,
    };
    use crate::file::{DeviceNumber, FileObjectEvidence, InodeNumber, LosslessPath};
    use crate::id::{ApplicationInstanceId, BootId, ProcessGenerationId};

    fn example() -> ProcessIdentity {
        ProcessIdentity {
            generation_id: ProcessGenerationId::new("proc_example").unwrap(),
            pid: Pid::new(4242).unwrap(),
            start_time: ProcessStartTime::from_timeval(1_794_830_400, 250_000).unwrap(),
            uid: Uid::new(501),
            boot_id: BootId::new("boot_example").unwrap(),
            executable: Some(ExecutableIdentity {
                path: LosslessPath::from_bytes("/Applications/Example.app/Contents/MacOS/Example")
                    .unwrap(),
                file: Some(FileObjectEvidence {
                    device: DeviceNumber::new(16_777_234),
                    inode: InodeNumber::new(991),
                }),
            }),
            association: ProcessAssociation::Application {
                instance_id: ApplicationInstanceId::new("app_example").unwrap(),
                bundle_identifier: "com.example.Example".to_owned(),
            },
        }
    }

    #[test]
    fn a_process_identity_round_trips() {
        let identity: ProcessIdentity = example();
        let value: Value = serde_json::to_value(&identity).unwrap();
        assert_eq!(
            value,
            json!({
                "generation_id": "proc_example",
                "pid": 4242,
                "start_time": "1794830400250000",
                "uid": 501,
                "boot_id": "boot_example",
                "executable": {
                    "path": {
                        "encoding": "utf8",
                        "value": "/Applications/Example.app/Contents/MacOS/Example"
                    },
                    "file": { "device": 16_777_234, "inode": "991" }
                },
                "association": {
                    "kind": "application",
                    "instance_id": "app_example",
                    "bundle_identifier": "com.example.Example"
                }
            })
        );
        assert_eq!(
            serde_json::from_value::<ProcessIdentity>(value).unwrap(),
            identity
        );
    }

    #[test]
    fn a_reused_pid_is_a_different_process() {
        let first: ProcessIdentity = example();
        let mut restarted: ProcessIdentity = example();
        restarted.start_time = ProcessStartTime::from_timeval(1_794_830_460, 0).unwrap();
        assert!(!first.has_same_evidence(&restarted));

        let mut other_owner: ProcessIdentity = example();
        other_owner.uid = Uid::new(0);
        assert!(!first.has_same_evidence(&other_owner));

        let mut other_boot: ProcessIdentity = example();
        other_boot.boot_id = BootId::new("boot_later").unwrap();
        assert!(!first.has_same_evidence(&other_boot));

        let mut relabeled: ProcessIdentity = example();
        relabeled.generation_id = ProcessGenerationId::new("proc_other").unwrap();
        relabeled.association = ProcessAssociation::Unattributed;
        assert!(first.has_same_evidence(&relabeled));
    }

    #[test]
    fn a_pid_is_positive() {
        assert_eq!(Pid::new(0), Err(PidError));
        assert_eq!(Pid::new(-1), Err(PidError));
        assert!(serde_json::from_str::<Pid>("0").is_err());
        assert!(serde_json::from_str::<Pid>("-7").is_err());
        assert!(serde_json::from_str::<Pid>("\"7\"").is_err());
        assert_eq!(serde_json::from_str::<Pid>("7").unwrap().get(), 7);
    }

    #[test]
    fn a_start_time_is_checked() {
        assert_eq!(ProcessStartTime::from_timeval(1, 1_000_000), None);
        assert_eq!(ProcessStartTime::from_timeval(u64::MAX, 0), None);
        assert_eq!(
            ProcessStartTime::from_timeval(2, 5),
            Some(ProcessStartTime::new(2_000_005))
        );
    }

    #[test]
    fn each_association_round_trips() {
        let job = ProcessAssociation::ManagedJob {
            instance_id: ApplicationInstanceId::new("job_example").unwrap(),
            label: "com.example.agent".to_owned(),
        };
        let value: Value = serde_json::to_value(&job).unwrap();
        assert_eq!(
            value,
            json!({ "kind": "managed_job", "instance_id": "job_example", "label": "com.example.agent" })
        );
        assert_eq!(
            serde_json::from_value::<ProcessAssociation>(value).unwrap(),
            job
        );
        assert_eq!(
            serde_json::to_value(ProcessAssociation::Unattributed).unwrap(),
            json!({ "kind": "unattributed" })
        );
    }

    #[test]
    fn an_unknown_association_kind_is_not_unattributed() {
        let association: ProcessAssociation =
            serde_json::from_value(json!({ "kind": "extension_host", "owner": "app_example" }))
                .unwrap();
        assert_eq!(association, ProcessAssociation::Unrecognized);
        assert_ne!(association, ProcessAssociation::Unattributed);
    }
}
