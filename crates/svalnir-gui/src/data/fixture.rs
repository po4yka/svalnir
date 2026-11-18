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
    sync::{
        Arc, OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime},
};
use svalnir_agent::scan::CancellationToken;
use svalnir_core::{grant::GuardStanding, policy::PolicyId};

const GB: u64 = 1_000_000_000;

/// The folders of the scan fixture: the name, the size in tenths of a GB, and
/// the density (allocated over logical) in percent.
const FOLDERS: [(&str, u64, u64); 7] = [
    ("Library", 614, 80),
    ("Developer", 482, 55),
    ("Pictures", 729, 100),
    ("Documents", 273, 95),
    ("Movies", 316, 100),
    ("Music", 98, 100),
    (".Trash", 141, 70),
];

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
    /// A fixed sequence: each host reading is the next step. Available space
    /// falls with small steps up and down, swap rises in steps, and the
    /// pressure runs Normal, Warning, Critical, Normal, with three readings
    /// unavailable. See [`drift_step`].
    Drift,
}

impl FixtureScenario {
    /// Every scenario.
    pub const ALL: [Self; 6] = [
        Self::Healthy,
        Self::Pressure,
        Self::Unavailable,
        Self::Stale,
        Self::AgentAbsent,
        Self::Drift,
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
            Self::Drift => "drift",
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
#[derive(Debug, Clone)]
pub struct FixtureSource {
    scenario: FixtureScenario,
    pacing: Duration,
    /// Whether a reading has the offset of the local time zone.
    local_time: bool,
    /// The readings that the origin of the `drift` times lies in the past.
    lead: u32,
    /// The number of host readings taken, for the `drift` sequence.
    step: Arc<AtomicUsize>,
    /// The time of the first call, the origin of the `drift` times.
    base: Arc<OnceLock<SystemTime>>,
    /// The number of scans that started, for the changed sizes of a later scan.
    scans: Arc<AtomicUsize>,
}

/// The time between two readings of the `drift` sequence.
pub const DRIFT_SPACING: Duration = Duration::from_secs(10);
/// The number of steps after which the `drift` sequence repeats.
pub const DRIFT_PERIOD: usize = 360;

/// The step of the `drift` sequence at which its operation is admitted.
pub const DRIFT_OPERATION_STEP: u32 = 50;

/// What a step of the `drift` sequence reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriftReading {
    /// No value can be read.
    Unavailable,
    /// The values: available bytes, used swap bytes, and the pressure.
    Values {
        /// The available space of the volume.
        available: u64,
        /// The used swap.
        swap_used: u64,
        /// The memory pressure.
        pressure: PressureLevel,
    },
}

/// The reading at `step` of the `drift` sequence. It has no randomness and
/// no clock. Pressure is Normal for steps 0 to 39, Warning for 40 to 54,
/// Critical for 55 to 59, and Normal again. Steps 20, 21, and 70 are
/// unavailable. The sequence repeats after [`DRIFT_PERIOD`] steps. Available space falls by 0.4 GB a step with a wobble of up to
/// 0.5 GB, so single steps go up too. Swap rises by 0.25 GB every 12 steps.
#[must_use]
pub fn drift_step(step: usize) -> DriftReading {
    // The sequence repeats, so a window that stays open keeps valid values:
    // the swap stays below its total and the available space above zero.
    let step: usize = step % DRIFT_PERIOD;
    if matches!(step, 20 | 21 | 70) {
        return DriftReading::Unavailable;
    }
    let wobble: [i64; 5] = [0, 5, -2, 4, -3];
    let fall: i64 = i64::try_from(step).unwrap_or(0) * 4;
    let tenths: i64 = 3000 - fall + wobble[step % 5];
    let available: u64 = u64::try_from(tenths).unwrap_or(0) * GB / 10;
    let swap_used: u64 = u64::try_from(step / 12).unwrap_or(0) * GB / 4;
    let pressure: PressureLevel = match step {
        40..=54 => PressureLevel::Warning,
        55..=59 => PressureLevel::Critical,
        _ => PressureLevel::Normal,
    };
    DriftReading::Values {
        available,
        swap_used,
        pressure,
    }
}

impl FixtureSource {
    /// Creates the source of `scenario`.
    #[must_use]
    pub fn new(scenario: FixtureScenario) -> Self {
        Self {
            scenario,
            pacing: Duration::ZERO,
            local_time: false,
            lead: 0,
            step: Arc::new(AtomicUsize::new(0)),
            base: Arc::new(OnceLock::new()),
            scans: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// The origin of the `drift` times: the span of the seeded readings
    /// before the first call.
    fn origin(&self) -> SystemTime {
        *self.base.get_or_init(|| {
            let now: SystemTime = SystemTime::now();
            now.checked_sub(DRIFT_SPACING * self.lead).unwrap_or(now)
        })
    }

    /// Puts the origin of the `drift` times `readings` readings in the past,
    /// so that the last of the readings taken at launch has the time of the
    /// launch and none has a time in the future.
    #[must_use]
    pub fn with_seeded_readings(mut self, readings: usize) -> Self {
        self.lead = u32::try_from(readings.saturating_sub(1)).unwrap_or(u32::MAX);
        self
    }

    /// Gives each reading the offset of the local time zone, so that the
    /// times on screen are local. Without it the times are UTC, which keeps
    /// a test independent of the zone of the host.
    #[must_use]
    pub const fn with_local_time(mut self) -> Self {
        self.local_time = true;
        self
    }

    /// Sleeps `pacing` between the progress steps of a scan. The default is
    /// zero, so that a test does not wait.
    #[must_use]
    pub fn with_pacing(mut self, pacing: Duration) -> Self {
        self.pacing = pacing;
        self
    }
}

impl DataSource for FixtureSource {
    fn host(&self) -> Result<HostSnapshot, String> {
        let mut now: SystemTime = SystemTime::now();
        let drift: Option<DriftReading> = (self.scenario == FixtureScenario::Drift).then(|| {
            let step: usize = self.step.fetch_add(1, Ordering::Relaxed);
            let spacing: u32 = u32::try_from(step).unwrap_or(u32::MAX);
            // A reading never has a time in the future.
            now = now.min(self.origin() + DRIFT_SPACING * spacing);
            drift_step(step)
        });
        let mut snapshot = HostSnapshot {
            captured_at: now,
            // A test has no local zone; the launch asks for it.
            utc_offset: self
                .local_time
                .then(|| crate::platform::utc_offset_seconds(now))
                .flatten(),
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
            FixtureScenario::Drift => {
                if let Some(DriftReading::Values {
                    available,
                    swap_used,
                    pressure,
                }) = drift
                {
                    snapshot.disk_available = Measured::Value(available);
                    snapshot.disk_free = Measured::Value(available.saturating_sub(3 * GB));
                    snapshot.swap_used = Measured::Value(swap_used);
                    snapshot.swap_total = Measured::Value(8 * GB);
                    snapshot.pressure = Measured::Value(pressure);
                } else {
                    let no = |what: &str| -> String {
                        format!("{what} is not available in this reading")
                    };
                    snapshot.disk_total = Measured::Unavailable(no("disk total"));
                    snapshot.disk_available = Measured::Unavailable(no("disk available"));
                    snapshot.disk_free = Measured::Unavailable(no("disk free"));
                    snapshot.pressure = Measured::Unavailable(no("pressure"));
                    snapshot.memory_total = Measured::Unavailable(no("physical memory"));
                    snapshot.swap_used = Measured::Unavailable(no("swap used"));
                    snapshot.swap_total = Measured::Unavailable(no("swap total"));
                }
            }
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
                FixtureScenario::Healthy | FixtureScenario::Stale | FixtureScenario::Drift => {
                    policy == PolicyId::DiskGuard
                }
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
            FixtureScenario::Drift => {
                // Admitted inside the span of the readings, relative to the
                // first call.
                snapshot.latest_operation = Some(OperationRow {
                    operation_id: "op_fixture_0003".to_owned(),
                    state: OperationPhase::Completed,
                    state_text: "Completed".to_owned(),
                    admitted_at: SystemTime::now().min(
                        self.origin() + DRIFT_SPACING * DRIFT_OPERATION_STEP + DRIFT_SPACING / 2,
                    ),
                    trigger: "automatic".to_owned(),
                });
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
        // The first scan, and then each later scan with changed sizes: a
        // larger folder, a smaller one, a new one, and one that is gone.
        let later: bool = self.scans.fetch_add(1, Ordering::Relaxed) > 0;
        let mut big: Vec<(&str, u64, u64)> = FOLDERS
            .iter()
            .map(|(name, tenth_gb, percent)| (*name, *tenth_gb, *percent))
            .collect();
        if later {
            big.retain(|(name, _, _)| *name != ".Trash");
            for (name, tenth_gb, _) in &mut big {
                match *name {
                    "Developer" => *tenth_gb += 21,
                    "Movies" => *tenth_gb -= 8,
                    _ => {}
                }
            }
            big.push(("Downloads", 12, 100));
        }
        let mut children: Vec<ChildSize> = big
            .iter()
            .map(|(name, tenth_gb, percent)| {
                let allocated: u64 = tenth_gb * GB / 10 + GB / 100;
                ChildSize {
                    name: (*name).to_owned(),
                    path: root.join(name),
                    is_directory: true,
                    // The density of the folder is allocated over logical.
                    logical: allocated * 100 / percent,
                    allocated,
                }
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

    fn scan_of(source: &FixtureSource) -> ScanSummary {
        let cancel = CancellationToken::new();
        let Ok(summary) = source.scan(Path::new("/r"), &cancel, &|_| {}) else {
            panic!("the fixture scan must end");
        };
        summary
    }

    #[test]
    fn folders_differ_in_density_and_later_scans_change() {
        let source = FixtureSource::new(FixtureScenario::Healthy);
        let first = scan_of(&source);
        let named = |s: &ScanSummary, n: &str| s.children.iter().find(|c| c.name == n).cloned();
        let library = named(&first, "Library").expect("library");
        assert!(library.logical > library.allocated, "density below 1");
        let pictures = named(&first, "Pictures").expect("pictures");
        assert!(pictures.logical <= pictures.allocated);
        assert!(named(&first, ".Trash").is_some());
        let second = scan_of(&source);
        assert!(named(&second, ".Trash").is_none());
        assert!(named(&second, "Downloads").is_some());
        let before = named(&first, "Developer").expect("developer").allocated;
        let after = named(&second, "Developer").expect("developer").allocated;
        assert_eq!(after - before, 21 * GB / 10);
        let movies_before = named(&first, "Movies").expect("movies").allocated;
        let movies_after = named(&second, "Movies").expect("movies").allocated;
        assert_eq!(movies_before - movies_after, 8 * GB / 10);
        assert_eq!(scan_of(&source).children, second.children, "stable later");
    }

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

#[cfg(test)]
mod drift_tests {
    use super::*;

    #[test]
    fn the_drift_sequence_is_fixed() {
        let pressure = |step: usize| match drift_step(step) {
            DriftReading::Values { pressure, .. } => Some(pressure),
            DriftReading::Unavailable => None,
        };
        assert_eq!(pressure(0), Some(PressureLevel::Normal));
        assert_eq!(pressure(39), Some(PressureLevel::Normal));
        assert_eq!(pressure(40), Some(PressureLevel::Warning));
        assert_eq!(pressure(54), Some(PressureLevel::Warning));
        assert_eq!(pressure(55), Some(PressureLevel::Critical));
        assert_eq!(pressure(59), Some(PressureLevel::Critical));
        assert_eq!(pressure(60), Some(PressureLevel::Normal));
        let unavailable: Vec<usize> = (0..180)
            .filter(|s| drift_step(*s) == DriftReading::Unavailable)
            .collect();
        assert_eq!(unavailable, [20, 21, 70]);
        assert_eq!(drift_step(33), drift_step(33), "no randomness");
        assert_eq!(drift_step(DRIFT_PERIOD + 33), drift_step(33), "it repeats");
        assert_eq!(
            drift_step(usize::MAX),
            drift_step(usize::MAX % DRIFT_PERIOD)
        );
        for step in 0..DRIFT_PERIOD {
            if let DriftReading::Values {
                available,
                swap_used,
                ..
            } = drift_step(step)
            {
                assert!(available > 0 && swap_used < 8 * GB, "step {step}");
            }
        }
    }

    #[test]
    fn available_space_falls_with_small_steps_up_and_down() {
        let available = |step: usize| match drift_step(step) {
            DriftReading::Values { available, .. } => available,
            DriftReading::Unavailable => 0,
        };
        assert!(available(0) > available(19));
        assert!(available(60) > available(100));
        let ups: usize = (1..19)
            .filter(|s| available(*s) > available(*s - 1))
            .count();
        let downs: usize = (1..19)
            .filter(|s| available(*s) < available(*s - 1))
            .count();
        assert!(ups > 0 && downs > 0, "{ups} {downs}");
    }

    #[test]
    fn each_call_is_the_next_step_with_spaced_times() {
        // Seeded readings are spaced in the past, and none is in the future.
        let source = FixtureSource::new(FixtureScenario::Drift).with_seeded_readings(100);
        let first = source.host().map(|h| h.captured_at);
        let second = source.host().map(|h| h.captured_at);
        let (Ok(first), Ok(second)) = (first, second) else {
            panic!("the fixture always reads")
        };
        assert_eq!(second.duration_since(first).ok(), Some(DRIFT_SPACING));
        assert!(second <= SystemTime::now());
        let operation = source.service().latest_operation;
        assert!(
            operation
                .is_some_and(|op| op.admitted_at > first && op.admitted_at <= SystemTime::now())
        );
        // With no seed, a reading has the time of its call.
        let live = FixtureSource::new(FixtureScenario::Drift);
        assert!(live.host().is_ok());
        let later = live.host().map(|h| h.captured_at);
        assert!(later.is_ok_and(|at| at <= SystemTime::now()));
    }
}
