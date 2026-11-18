//! The live source: the shared read layer of the agent library, in process.

use super::{
    DataSource,
    model::{
        AgentSnapshot, AgentState, GuardRow, HostSnapshot, Measured, OperationPhase, OperationRow,
        PressureLevel, ServiceSnapshot,
    },
};
use std::{
    path::{Path, PathBuf},
    sync::{Mutex, PoisonError},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use svalnir_agent::{
    journal::JournalOptions,
    observe::{self, CoordinatorPresence, DiskReading, Host},
    runtime::journal_path,
};
use svalnir_core::{grant::AuthorityState, time::WallTime};
use svalnir_core::{observation::Observation, quantity::Bytes, state::PressureState};

/// The state directory override variable; the same as the CLI reads.
const STATE_DIRECTORY_VARIABLE: &str = "SVALNIR_STATE_DIR";
/// The default state directory under `$HOME`; the same as the CLI uses.
const DEFAULT_STATE_DIRECTORY: &str = "Library/Application Support/Svalnir";

/// Reads the host in this process. It never creates the state directory or
/// the journal.
#[derive(Debug)]
pub struct LiveSource {
    host: Mutex<Option<Host>>,
    state_directory: Option<PathBuf>,
}

impl LiveSource {
    /// Creates the source for `state_directory`. `None` means that the
    /// directory is not known, so the agent state is `NoJournal`.
    #[must_use]
    pub fn new(state_directory: Option<PathBuf>) -> Self {
        Self {
            host: Mutex::new(None),
            state_directory,
        }
    }

    /// Creates the source for the state directory of the environment.
    #[must_use]
    pub fn from_environment() -> Self {
        Self::new(default_state_directory())
    }
}

/// The state directory by the rule of the CLI: an absolute override, else
/// `$HOME` plus the default path.
fn default_state_directory() -> Option<PathBuf> {
    if let Some(text) = std::env::var_os(STATE_DIRECTORY_VARIABLE) {
        let path: PathBuf = PathBuf::from(text);
        return path.is_absolute().then_some(path);
    }
    let home: PathBuf = PathBuf::from(std::env::var_os("HOME")?);
    home.is_absolute()
        .then(|| home.join(DEFAULT_STATE_DIRECTORY))
}

fn bytes(observation: &Observation<Bytes>) -> Measured<u64> {
    match observation.value() {
        Some(value) => Measured::Value(value.get()),
        None => Measured::Unavailable(
            observation
                .reason()
                .map_or_else(|| "unrecognized".to_owned(), ToString::to_string),
        ),
    }
}

fn pressure(observation: &Observation<PressureState>) -> Measured<PressureLevel> {
    match observation.value() {
        Some(PressureState::Normal) => Measured::Value(PressureLevel::Normal),
        Some(PressureState::Warning) => Measured::Value(PressureLevel::Warning),
        Some(PressureState::Critical) => Measured::Value(PressureLevel::Critical),
        Some(PressureState::Unrecognized(text)) => {
            Measured::Unavailable(format!("unrecognized pressure state `{}`", text.as_str()))
        }
        None => Measured::Unavailable(
            observation
                .reason()
                .map_or_else(|| "unrecognized".to_owned(), ToString::to_string),
        ),
    }
}

impl DataSource for LiveSource {
    fn host(&self) -> Result<HostSnapshot, String> {
        let mut guard = self.host.lock().unwrap_or_else(PoisonError::into_inner);
        if guard.is_none() {
            *guard = Some(Host::open().map_err(|error| error.to_string())?);
        }
        let Some(host) = guard.as_ref() else {
            return Err("the host is not open".to_owned());
        };
        let reading = observe::collect(host).map_err(|error| error.to_string())?;
        let unavailable =
            |reason: &str| -> Measured<u64> { Measured::Unavailable(reason.to_owned()) };
        let (volume_name, disk_total, disk_available, disk_free) = match &reading.disk {
            DiskReading::Measured {
                identity, capacity, ..
            } => (
                Some(identity.mount_point.display_label()),
                bytes(&capacity.total),
                bytes(&capacity.available),
                bytes(&capacity.free),
            ),
            DiskReading::CapacityUnavailable { identity, reason } => (
                Some(identity.mount_point.display_label()),
                unavailable(reason),
                unavailable(reason),
                unavailable(reason),
            ),
            DiskReading::Unresolved(reason) => (
                None,
                unavailable(reason),
                unavailable(reason),
                unavailable(reason),
            ),
        };
        Ok(HostSnapshot {
            captured_at: SystemTime::now(),
            volume_name,
            disk_total,
            disk_available,
            disk_free,
            pressure: pressure(&reading.memory.pressure),
            memory_total: bytes(&reading.memory.physical),
            swap_used: bytes(&reading.memory.swap.used),
            swap_total: bytes(&reading.memory.swap.allocated),
            source: "in-process collection",
        })
    }

    fn agent(&self) -> AgentSnapshot {
        let state: AgentState = match &self.state_directory {
            None => AgentState::NoJournal,
            Some(directory) => agent_state(&journal_path(directory)),
        };
        AgentSnapshot {
            state,
            captured_at: SystemTime::now(),
        }
    }

    fn service(&self) -> ServiceSnapshot {
        let captured_at: SystemTime = SystemTime::now();
        let mut snapshot = ServiceSnapshot {
            journal_present: false,
            active_revision: None,
            guards: Vec::new(),
            latest_operation: None,
            problems: Vec::new(),
            captured_at,
        };
        let uid = observe::current_uid();
        let Ok(now) = WallTime::try_from(captured_at) else {
            snapshot.problems.push(
                "The system clock has no usable value, so the guards are not shown.".to_owned(),
            );
            return snapshot;
        };
        let opened = match &self.state_directory {
            None => Ok(None),
            Some(directory) => {
                observe::open_existing_journal(&journal_path(directory), &JournalOptions::default())
            }
        };
        let journal = match opened {
            Ok(Some(journal)) => journal,
            Ok(None) => {
                snapshot.guards = guard_rows(&AuthorityState::new(uid), now);
                return snapshot;
            }
            Err(error) => {
                snapshot.journal_present = true;
                snapshot
                    .problems
                    .push(format!("The journal cannot be read: {error}."));
                return snapshot;
            }
        };
        snapshot.journal_present = true;
        match observe::read_authority(&journal, uid) {
            Ok(stored) => {
                snapshot.active_revision = stored
                    .state
                    .active
                    .as_ref()
                    .map(|active| active.revision.revision_id.to_string());
                snapshot.guards = guard_rows(&stored.state, now);
            }
            Err(error) => snapshot
                .problems
                .push(format!("The authority record cannot be read: {error}.")),
        }
        match journal.recent_operations(1) {
            Ok(operations) => {
                snapshot.latest_operation = operations.first().map(|operation| {
                    let (state, state_text) = OperationPhase::of(operation.state());
                    OperationRow {
                        operation_id: operation.operation_id().to_string(),
                        state,
                        state_text,
                        admitted_at: system_time(operation.admitted_at()),
                        trigger: operation.trigger_class().as_str().to_owned(),
                    }
                });
            }
            Err(error) => snapshot
                .problems
                .push(format!("The latest operation cannot be read: {error}.")),
        }
        snapshot
    }

    fn label(&self) -> &'static str {
        "in-process collection"
    }
}

fn agent_state(journal: &Path) -> AgentState {
    if !journal.exists() {
        return AgentState::NoJournal;
    }
    match observe::coordinator_presence(journal) {
        CoordinatorPresence::Running => AgentState::Running,
        CoordinatorPresence::NotRunning => AgentState::NotRunning,
        CoordinatorPresence::Unknown => AgentState::Unknown,
    }
}

fn guard_rows(state: &AuthorityState, now: WallTime) -> Vec<GuardRow> {
    observe::guard_standings(state, now)
        .into_iter()
        .map(|(policy, standing)| GuardRow::new(policy.as_str(), standing))
        .collect()
}

fn system_time(time: WallTime) -> SystemTime {
    let seconds: i64 = time.unix_seconds();
    let nanos: Duration = Duration::from_nanos(u64::from(time.subsecond_nanoseconds()));
    if seconds >= 0 {
        UNIX_EPOCH + Duration::from_secs(seconds.unsigned_abs()) + nanos
    } else {
        UNIX_EPOCH - Duration::from_secs(seconds.unsigned_abs()) + nanos
    }
}
