//! Fixed data for screenshots and tests. Values are not measurements.

use super::{
    DataSource,
    model::{AgentSnapshot, AgentState, HostSnapshot, Measured, PressureLevel},
};
use std::time::{Duration, SystemTime};

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
}

impl FixtureSource {
    /// Creates the source of `scenario`.
    #[must_use]
    pub const fn new(scenario: FixtureScenario) -> Self {
        Self { scenario }
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
            _ => AgentState::Running,
        };
        AgentSnapshot {
            state,
            captured_at: SystemTime::now(),
        }
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
