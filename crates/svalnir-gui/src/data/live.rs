//! The live source: the shared read layer of the agent library, in process.

use super::{
    DataSource,
    model::{AgentSnapshot, AgentState, HostSnapshot, Measured, PressureLevel},
};
use std::{
    path::{Path, PathBuf},
    sync::{Mutex, PoisonError},
    time::SystemTime,
};
use svalnir_agent::{
    observe::{self, CoordinatorPresence, DiskReading, Host},
    runtime::journal_path,
};
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
