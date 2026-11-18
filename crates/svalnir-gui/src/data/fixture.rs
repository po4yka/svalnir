//! Fixed data for screenshots and tests. Values are not measurements.

use super::{
    DataSource,
    model::{
        AgentSnapshot, AgentState, ChildSize, GapRow, GuardRow, HostSnapshot, Measured,
        OperationPhase, OperationRow, PressureLevel, ScanEnd, ScanProgress, ScanSummary,
        ServiceSnapshot,
    },
};
use std::{
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};
use svalnir_agent::scan::CancellationToken;
use svalnir_core::{grant::GuardStanding, policy::PolicyId};

const GB: u64 = 1_000_000_000;

/// A named fixture scenario.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixtureScenario {
    /// Normal pressure, free space, agent running.
    Healthy,
    /// Warning pressure and high swap use.
    Pressure,
    /// Every measured value is unavailable.
    Unavailable,
    /// A snapshot that is 12 minutes old.
    Stale,
    /// The agent has no journal.
    AgentAbsent,
}

impl FixtureScenario {
    /// Every scenario.
    pub const ALL: [Self; 5] = [
        Self::Healthy,
        Self::Pressure,
        Self::Unavailable,
        Self::Stale,
        Self::AgentAbsent,
    ];

    /// The name on the command line.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Pressure => "pressure",
            Self::Unavailable => "unavailable",
            Self::Stale => "stale",
            Self::AgentAbsent => "agent-absent",
        }
    }

    /// The scenario with `name`.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|scenario| scenario.name() == name)
    }
}

/// A [`DataSource`] with fixed values.
#[derive(Debug, Clone, Copy)]
pub struct FixtureSource {
    scenario: FixtureScenario,
    pacing: Duration,
}

impl FixtureSource {
    /// Creates the source of `scenario`.
    #[must_use]
    pub const fn new(scenario: FixtureScenario) -> Self {
        Self {
            scenario,
            pacing: Duration::ZERO,
        }
    }

    /// Sleeps `pacing` between the progress steps of a scan. The default is
    /// zero, so that a test does not wait.
    #[must_use]
    pub const fn with_pacing(mut self, pacing: Duration) -> Self {
        self.pacing = pacing;
        self
    }
}

impl DataSource for FixtureSource {
    fn host(&self) -> Result<HostSnapshot, String> {
        let now: SystemTime = SystemTime::now();
        let mut snapshot = HostSnapshot {
            captured_at: now,
            volume_name: Some("/System/Volumes/Data".to_owned()),
            disk_total: Measured::Value(512 * GB),
            disk_available: Measured::Value(185 * GB + GB / 2),
            disk_free: Measured::Value(170 * GB),
            pressure: Measured::Value(PressureLevel::Normal),
            memory_total: Measured::Value(32 * GB),
            swap_used: Measured::Value(GB / 2),
            swap_total: Measured::Value(2 * GB),
            source: "fixture",
        };
        match self.scenario {
            FixtureScenario::Healthy | FixtureScenario::AgentAbsent => {}
            FixtureScenario::Pressure => {
                snapshot.pressure = Measured::Value(PressureLevel::Warning);
                snapshot.swap_used = Measured::Value(9 * GB);
                snapshot.swap_total = Measured::Value(10 * GB);
                snapshot.disk_available = Measured::Value(24 * GB);
                snapshot.disk_free = Measured::Value(20 * GB);
            }
            FixtureScenario::Unavailable => {
                let no =
                    |what: &str| -> String { format!("{what} is not available in this fixture") };
                snapshot.volume_name = None;
                snapshot.disk_total = Measured::Unavailable(no("disk total"));
                snapshot.disk_available = Measured::Unavailable(no("disk available"));
                snapshot.disk_free = Measured::Unavailable(no("disk free"));
                snapshot.pressure = Measured::Unavailable(no("pressure"));
                snapshot.memory_total = Measured::Unavailable(no("physical memory"));
                snapshot.swap_used = Measured::Unavailable(no("swap used"));
                snapshot.swap_total = Measured::Unavailable(no("swap total"));
            }
            FixtureScenario::Stale => {
                snapshot.captured_at = now.checked_sub(Duration::from_mins(12)).unwrap_or(now);
            }
        }
        Ok(snapshot)
    }

    fn agent(&self) -> AgentSnapshot {
        let state: AgentState = match self.scenario {
            FixtureScenario::AgentAbsent => AgentState::NoJournal,
            _ => AgentState::Reporting {
                since: SystemTime::now(),
            },
        };
        AgentSnapshot {
            state,
            captured_at: SystemTime::now(),
        }
    }

    fn service(&self) -> ServiceSnapshot {
        let now: SystemTime = SystemTime::now();
        let present: bool = self.scenario != FixtureScenario::AgentAbsent;
        let standing = |policy: PolicyId| -> GuardStanding {
            let active: bool = match self.scenario {
                FixtureScenario::Healthy | FixtureScenario::Stale => policy == PolicyId::DiskGuard,
                FixtureScenario::Pressure => true,
                FixtureScenario::Unavailable | FixtureScenario::AgentAbsent => false,
            };
            if active {
                GuardStanding::Active
            } else if present {
                GuardStanding::Disabled
            } else {
                GuardStanding::NoActiveRevision
            }
        };
        let mut snapshot = ServiceSnapshot {
            journal_present: present,
            active_revision: present.then(|| "rev-fixture-1".to_owned()),
            guards: PolicyId::ALL
                .iter()
                .map(|policy| GuardRow::new(policy.as_str(), standing(*policy)))
                .collect(),
            latest_operation: None,
            problems: Vec::new(),
            captured_at: now,
        };
        match self.scenario {
            FixtureScenario::Healthy | FixtureScenario::Stale => {
                snapshot.latest_operation = Some(OperationRow {
                    operation_id: "op_fixture_0001".to_owned(),
                    state: OperationPhase::Completed,
                    state_text: "Completed".to_owned(),
                    admitted_at: now.checked_sub(Duration::from_mins(5)).unwrap_or(now),
                    trigger: "automatic".to_owned(),
                });
            }
            FixtureScenario::Pressure => {
                snapshot.latest_operation = Some(OperationRow {
                    operation_id: "op_fixture_0002".to_owned(),
                    state: OperationPhase::Running,
                    state_text: "Running".to_owned(),
                    admitted_at: now.checked_sub(Duration::from_secs(40)).unwrap_or(now),
                    trigger: "automatic".to_owned(),
                });
            }
            FixtureScenario::Unavailable => {
                snapshot.active_revision = None;
                snapshot.guards.clear();
                snapshot
                    .problems
                    .push("The authority record cannot be read in this fixture.".to_owned());
                snapshot
                    .problems
                    .push("The latest operation cannot be read in this fixture.".to_owned());
            }
            FixtureScenario::AgentAbsent => {}
        }
        snapshot
    }

    fn scan(
        &self,
        root: &Path,
        _cancel: &CancellationToken,
        progress: &dyn Fn(ScanProgress),
    ) -> Result<ScanSummary, String> {
        if self.scenario == FixtureScenario::Unavailable {
            return Err("the scan root is not readable in this fixture".to_owned());
        }
        let big: [(&str, bool, u64); 7] = [
            ("Library", true, 614),
            ("Developer", true, 482),
            ("Pictures", true, 729),
            ("Documents", true, 273),
            ("Movies", true, 316),
            ("Music", true, 98),
            (".Trash", true, 141),
        ];
        let mut children: Vec<ChildSize> = big
            .iter()
            .map(|(name, is_directory, tenth_gb)| ChildSize {
                name: (*name).to_owned(),
                path: root.join(name),
                is_directory: *is_directory,
                logical: tenth_gb * GB / 10,
                allocated: tenth_gb * GB / 10 + GB / 100,
            })
            .collect();
        for index in 0..12_u64 {
            children.push(ChildSize {
                name: format!("item-{index:02}"),
                path: root.join(format!("item-{index:02}")),
                is_directory: index % 2 == 0,
                logical: 50_000_000 + index * 1_000_000,
                allocated: 52_000_000 + index * 1_000_000,
            });
        }
        let steps: u64 = 12;
        for step in 1..=steps {
            let shown: usize = usize::try_from(step)
                .unwrap_or(1)
                .saturating_mul(children.len())
                .div_ceil(usize::try_from(steps).unwrap_or(1))
                .max(1);
            let grown: Vec<ChildSize> = children
                .iter()
                .take(shown)
                .map(|child| ChildSize {
                    logical: child.logical / steps * step,
                    allocated: child.allocated / steps * step,
                    ..child.clone()
                })
                .collect();
            progress(ScanProgress {
                entries: step * 40_000,
                current_path: grown.last().map(|child| child.path.clone()),
                logical: grown.iter().map(|child| child.logical).sum(),
                allocated: grown.iter().map(|child| child.allocated).sum(),
                children: grown,
            });
            if !self.pacing.is_zero() {
                std::thread::sleep(self.pacing);
            }
        }
        let total_logical: u64 = children.iter().map(|child| child.logical).sum();
        let total_allocated: u64 = children.iter().map(|child| child.allocated).sum();
        Ok(ScanSummary {
            root: root.to_path_buf(),
            children,
            total_logical,
            total_allocated,
            entries_examined: 120_000,
            complete: false,
            ended: ScanEnd::Finished,
            gaps: vec![GapRow {
                cause_text: "permission denied".to_owned(),
                count: 3,
            }],
            elapsed: Some(Duration::from_secs(41)),
            finished_at: SystemTime::now(),
        })
    }

    fn default_scan_root(&self) -> Option<PathBuf> {
        Some(PathBuf::from("/Users/fixture"))
    }

    fn label(&self) -> &'static str {
        "fixture"
    }

    fn fixture_name(&self) -> Option<&'static str> {
        Some(self.scenario.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip() {
        for scenario in FixtureScenario::ALL {
            assert_eq!(FixtureScenario::from_name(scenario.name()), Some(scenario));
        }
        assert_eq!(FixtureScenario::from_name("nope"), None);
        assert_eq!(FixtureScenario::from_name("Healthy"), None);
    }

    #[test]
    fn unavailable_has_no_value() {
        let snapshot = FixtureSource::new(FixtureScenario::Unavailable)
            .host()
            .map_err(|error| error.len());
        let Ok(snapshot) = snapshot else {
            panic!("the unavailable scenario must read");
        };
        assert!(snapshot.disk_total.value().is_none());
        assert!(snapshot.pressure.value().is_none());
        assert!(snapshot.swap_used.value().is_none());
    }

    #[test]
    fn stale_is_twelve_minutes_old() {
        let Ok(snapshot) = FixtureSource::new(FixtureScenario::Stale).host() else {
            panic!("the stale scenario must read");
        };
        let age = SystemTime::now()
            .duration_since(snapshot.captured_at)
            .unwrap_or_default();
        assert!(age >= Duration::from_mins(12));
    }

    #[test]
    fn agent_absent_has_no_journal() {
        let source = FixtureSource::new(FixtureScenario::AgentAbsent);
        assert_eq!(source.agent().state, AgentState::NoJournal);
    }
}
