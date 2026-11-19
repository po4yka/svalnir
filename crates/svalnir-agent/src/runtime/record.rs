//! The status and lifecycle records of the agent, and the restart backoff.
//!
//! The two records are agent records of the journal
//! ([`AgentRecord::Status`](crate::journal::AgentRecord) and
//! [`AgentRecord::Lifecycle`](crate::journal::AgentRecord)). A client reads
//! the status record through its own journal connection. The records have
//! no path of user data, no process argument, and no secret.

use serde::{Deserialize, Serialize};
use svalnir_core::id::{ExecutorEpochId, PolicyRevisionId};
use svalnir_core::quantity::Nanoseconds;
use svalnir_core::time::WallTime;

use crate::capability::{CapabilityEntry, CapabilityId, CapabilityReport, Requirement};
use crate::controller::ControllerStatus;
use crate::notify::NotificationStatus;
use svalnir_core::state::CapabilityState;

/// The version of the [`AgentStatus`] record.
pub const AGENT_STATUS_VERSION: u32 = 2;

/// The version of the [`LifecycleRecord`].
pub const LIFECYCLE_VERSION: u32 = 1;

/// The restart backoff after the first stop that was not clean. Each
/// further such stop doubles it. It is also the `ThrottleInterval` of the
/// `LaunchAgent` definition.
pub const RESTART_BACKOFF_BASE: Nanoseconds = Nanoseconds::new(10_000_000_000);

/// The largest restart backoff.
pub const RESTART_BACKOFF_MAX: Nanoseconds = Nanoseconds::new(600_000_000_000);

/// The largest number of degraded reasons that a status keeps.
pub const MAX_DEGRADED_REASONS: usize = 16;

/// Where the agent is in its lifetime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunState {
    /// The agent reconciles and takes its first sample.
    Starting,
    /// The agent observes and controls.
    Running,
    /// The agent stops: no new dispatch starts.
    Stopping,
    /// The agent stopped. `clean` in the lifecycle record says how.
    Stopped,
}

/// The policy that the agent evaluates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicySource {
    /// The policy revision in effect. `None`: the agent evaluates its
    /// configuration proposal and only observes.
    pub revision: Option<PolicyRevisionId>,
    /// The reason the authority record of the journal is not usable. With
    /// a reason the agent only observes.
    pub problem: Option<String>,
}

/// The result of the capability check at the start.
///
/// The agent runs the probes one time, at its start, under its own process
/// identity. Access that the user gives later, for example Full Disk Access,
/// applies to the agent only after a restart, so the start is the time of
/// the probes. A client shows [`CapabilitySummary::probed_at`] with the
/// lines.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilitySummary {
    /// `ready`, `unverified`, or `blocked`.
    pub verdict: String,
    /// The required capabilities that are not available.
    pub required_not_available: Vec<String>,
    /// The time of the probes, when the clock gave a valid time.
    pub probed_at: Option<WallTime>,
    /// One line for each capability, in report order. At most
    /// [`CapabilityId::ALL`] lines.
    pub lines: Vec<CapabilityLine>,
    /// The notification capability of the agent and the counts of its
    /// notices, at the time of the status record. Unlike the lines, the
    /// agent reads it again at each status write. `None` when the agent
    /// has no notification service. A status record with no capability
    /// summary has no notification capability either.
    pub notifications: Option<NotificationStatus>,
}

/// One capability of the agent process, as the status record keeps it.
///
/// A line has no evidence facts: the facts name paths of the home
/// directory, and the status record has no path of user data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityLine {
    /// The stable identifier.
    pub id: CapabilityId,
    /// A short name for a table.
    pub title: String,
    /// The class of the capability.
    pub requirement: Requirement,
    /// The state under the identity of the agent process.
    pub state: CapabilityState,
    /// One line that summarizes the result.
    pub detail: String,
    /// A safe action for the user, when one applies.
    pub remediation: Option<String>,
}

impl CapabilityLine {
    fn of(entry: &CapabilityEntry) -> Self {
        Self {
            id: entry.id,
            title: entry.title.clone(),
            requirement: entry.requirement,
            state: entry.state.clone(),
            detail: entry.detail.clone(),
            remediation: entry.remediation.clone(),
        }
    }
}

impl CapabilitySummary {
    /// The summary of a capability report of the agent process.
    #[must_use]
    pub fn of(report: &CapabilityReport) -> Self {
        Self {
            verdict: report.summary.verdict.as_str().to_owned(),
            required_not_available: report
                .summary
                .required_not_available
                .iter()
                .map(|capability| capability.as_str().to_owned())
                .collect(),
            probed_at: report.probed_at,
            lines: report
                .capabilities
                .iter()
                .take(CapabilityId::ALL.len())
                .map(CapabilityLine::of)
                .collect(),
            notifications: None,
        }
    }
}

/// The self-limits of the agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelfLimits {
    /// The physical footprint of the agent process, in bytes. `None` when
    /// the measurement is not available.
    pub footprint_bytes: Option<u64>,
    /// The budget of the footprint, in bytes.
    pub budget_bytes: u64,
    /// True when the footprint is larger than the budget.
    pub over_budget: bool,
    /// True when the agent reduced its optional work.
    pub optional_work_reduced: bool,
}

/// The compact status of the agent. A client reads it from the journal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentStatus {
    /// [`AGENT_STATUS_VERSION`].
    pub schema_version: u32,
    /// The executor lifetime of the agent that wrote the record. The
    /// coordinator registration of the journal has the same value while
    /// the agent runs.
    pub executor_epoch: ExecutorEpochId,
    /// The process identity of the agent.
    pub process_id: u32,
    /// The wall-clock time of the start.
    pub started_at: WallTime,
    /// The wall-clock time of this record. A record that is old is not
    /// evidence that the agent runs; the coordinator lock is.
    pub written_at: WallTime,
    /// Where the agent is in its lifetime.
    pub state: RunState,
    /// The status of the controller. `None` before the first step.
    pub controller: Option<ControllerStatus>,
    /// The policy that the agent evaluates.
    pub policy: PolicySource,
    /// The capability check of the start.
    pub capabilities: Option<CapabilitySummary>,
    /// The self-limits.
    pub limits: SelfLimits,
    /// The conditions of the runtime that reduce its function, as short
    /// names.
    pub degraded: Vec<String>,
    /// The number of stops in sequence that were not clean, before this
    /// start.
    pub unclean_stops: u32,
    /// True while the restart backoff inhibits automatic work.
    pub restart_backoff: bool,
}

/// The lifecycle record of the agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleRecord {
    /// [`LIFECYCLE_VERSION`].
    pub schema_version: u32,
    /// The wall-clock time of the latest start.
    pub last_start: Option<WallTime>,
    /// The wall-clock time of the latest clean stop.
    pub last_stop: Option<WallTime>,
    /// True when the latest lifetime wrote a clean stop. The start of a
    /// lifetime sets it to `false`.
    pub stopped_cleanly: bool,
    /// The number of stops in sequence that were not clean.
    pub unclean_stops: u32,
    /// A compact reason for the latest degraded stop.
    pub degraded_reason: Option<String>,
}

impl Default for LifecycleRecord {
    fn default() -> Self {
        Self {
            schema_version: LIFECYCLE_VERSION,
            last_start: None,
            last_stop: None,
            // A journal with no record has no earlier lifetime.
            stopped_cleanly: true,
            unclean_stops: 0,
            degraded_reason: None,
        }
    }
}

impl LifecycleRecord {
    /// The record that stands for a stored record that this build cannot
    /// read: a decode error, a storage error, or a different schema
    /// version. The number of stops that were not clean is not known, so
    /// it is the smallest number that gives the longest restart backoff.
    /// A record that is not readable never makes the backoff shorter.
    #[must_use]
    pub fn unreadable() -> Self {
        let mut unclean_stops: u32 = 0;
        while restart_backoff(unclean_stops.saturating_add(1)) < RESTART_BACKOFF_MAX
            && unclean_stops < 64
        {
            unclean_stops = unclean_stops.saturating_add(1);
        }
        Self {
            stopped_cleanly: false,
            unclean_stops,
            ..Self::default()
        }
    }

    /// The record at the start of a new lifetime. A lifetime before this
    /// one that did not write a clean stop adds one to the count.
    #[must_use]
    pub fn started(&self, now: WallTime) -> Self {
        let unclean_stops: u32 = if self.stopped_cleanly {
            0
        } else {
            self.unclean_stops.saturating_add(1)
        };
        Self {
            schema_version: LIFECYCLE_VERSION,
            last_start: Some(now),
            last_stop: self.last_stop,
            stopped_cleanly: false,
            unclean_stops,
            degraded_reason: if self.stopped_cleanly {
                None
            } else {
                Some("the lifetime before this one did not stop cleanly".to_owned())
            },
        }
    }

    /// The record of a clean stop.
    #[must_use]
    pub fn stopped(&self, now: WallTime) -> Self {
        Self {
            schema_version: LIFECYCLE_VERSION,
            last_start: self.last_start,
            last_stop: Some(now),
            stopped_cleanly: true,
            unclean_stops: 0,
            degraded_reason: None,
        }
    }
}

/// The time for which automatic work waits after `unclean_stops` stops in
/// sequence that were not clean: nothing for zero, the base for one, and
/// two times the wait before for each further one, to the maximum.
#[must_use]
pub fn restart_backoff(unclean_stops: u32) -> Nanoseconds {
    if unclean_stops == 0 {
        return Nanoseconds::ZERO;
    }
    let doublings: u32 = unclean_stops.saturating_sub(1).min(32);
    let factor: u64 = 1_u64.checked_shl(doublings).unwrap_or(u64::MAX);
    Nanoseconds::new(
        RESTART_BACKOFF_BASE
            .get()
            .saturating_mul(factor)
            .min(RESTART_BACKOFF_MAX.get()),
    )
}

#[cfg(test)]
mod tests {
    use svalnir_core::quantity::Nanoseconds;
    use svalnir_core::time::WallTime;

    use super::{LifecycleRecord, RESTART_BACKOFF_BASE, RESTART_BACKOFF_MAX, restart_backoff};

    fn wall(seconds: i64) -> WallTime {
        WallTime::from_unix(seconds, 0).unwrap()
    }

    #[test]
    fn the_backoff_doubles_to_its_maximum() {
        assert_eq!(restart_backoff(0), Nanoseconds::ZERO);
        assert_eq!(restart_backoff(1), RESTART_BACKOFF_BASE);
        assert_eq!(
            restart_backoff(3),
            Nanoseconds::new(RESTART_BACKOFF_BASE.get() * 4)
        );
        assert_eq!(restart_backoff(20), RESTART_BACKOFF_MAX);
        assert_eq!(restart_backoff(u32::MAX), RESTART_BACKOFF_MAX);
    }

    #[test]
    fn a_stop_that_is_not_clean_is_counted_and_a_clean_stop_resets_the_count() {
        let first: LifecycleRecord = LifecycleRecord::default().started(wall(10));
        assert_eq!(first.unclean_stops, 0);
        assert!(!first.stopped_cleanly);
        // The lifetime ended with no record of a stop.
        let second: LifecycleRecord = first.started(wall(20));
        assert_eq!(second.unclean_stops, 1);
        assert!(second.degraded_reason.is_some());
        let third: LifecycleRecord = second.started(wall(30));
        assert_eq!(third.unclean_stops, 2);
        let stopped: LifecycleRecord = third.stopped(wall(40));
        assert!(stopped.stopped_cleanly);
        let fourth: LifecycleRecord = stopped.started(wall(50));
        assert_eq!(fourth.unclean_stops, 0);
        assert_eq!(fourth.last_stop, Some(wall(40)));
    }

    #[test]
    fn a_record_that_is_not_readable_gives_the_longest_backoff() {
        let started: LifecycleRecord = LifecycleRecord::unreadable().started(wall(10));
        assert!(!started.stopped_cleanly);
        assert_eq!(restart_backoff(started.unclean_stops), RESTART_BACKOFF_MAX);
        // The count is the smallest one with that backoff, so the status
        // shows a number of the same size as a real count.
        assert!(restart_backoff(started.unclean_stops - 1) < RESTART_BACKOFF_MAX);
        // A clean stop still resets it.
        assert_eq!(started.stopped(wall(20)).started(wall(30)).unclean_stops, 0);
    }
}
