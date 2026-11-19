//! The data layer: snapshot types, the sources, and the model that polls them.

pub mod fixture;
mod fixture_records;
pub mod live;
pub(crate) mod live_records;
pub mod model;
pub mod records;
pub mod store;

use crate::actions::{
    ActionPort,
    fixture::{ActionScript, FixturePort},
};
use model::{AgentSnapshot, HostSnapshot, ScanProgress, ScanSummary, ServiceSnapshot};
use records::{
    AutomationSnapshot, DiagnosticsSnapshot, HistorySnapshot, MemorySnapshot, ProcessesSnapshot,
};
use std::{
    fmt::Debug,
    path::{Path, PathBuf},
    sync::Arc,
};
use svalnir_agent::scan::CancellationToken;

/// A source of snapshots. The methods can block; the model calls them only
/// from a background thread.
pub trait DataSource: Send + Sync + Debug {
    /// Reads the host.
    ///
    /// # Errors
    ///
    /// Returns the reason when no reading is possible at all.
    fn host(&self) -> Result<HostSnapshot, String>;

    /// Reads the agent state.
    fn agent(&self) -> AgentSnapshot;

    /// Reads the guards and the latest operation from the journal.
    fn service(&self) -> ServiceSnapshot;

    /// Reads the memory quantities of the host.
    ///
    /// # Errors
    ///
    /// Returns the reason when no reading is possible at all.
    fn memory(&self) -> Result<MemorySnapshot, String>;

    /// Reads the processes of the current user and their application
    /// groups. The read examines each process of the host one time.
    ///
    /// # Errors
    ///
    /// Returns the reason when no reading is possible at all.
    fn processes(&self) -> Result<ProcessesSnapshot, String>;

    /// Reads the authority record of the journal: the revision, the guards
    /// with their grants, and the pause.
    fn automation(&self) -> AutomationSnapshot;

    /// Reads the latest operations of the journal.
    fn history(&self) -> HistorySnapshot;

    /// Runs the capability probes of this process and reads the records of
    /// the service. The live source starts `csrutil status`, so the model
    /// calls this only when the Diagnostics screen asks for it.
    fn diagnostics(&self) -> DiagnosticsSnapshot;

    /// Scans the direct children of `root` and reads sizes only. `progress`
    /// is called while the scan runs.
    ///
    /// # Errors
    ///
    /// Returns the reason when the scan cannot run.
    fn scan(
        &self,
        root: &Path,
        cancel: &CancellationToken,
        progress: &dyn Fn(ScanProgress),
    ) -> Result<ScanSummary, String>;

    /// The root that the Storage screen offers first.
    fn default_scan_root(&self) -> Option<PathBuf>;

    /// The label of the source for the status line.
    fn label(&self) -> &'static str;

    /// The name of the fixture scenario, when the source is a fixture.
    fn fixture_name(&self) -> Option<&'static str> {
        None
    }

    /// The path of the state-changing actions for this source. The default
    /// path changes nothing and gives "no agent" for each action.
    fn actions(&self) -> Arc<dyn ActionPort> {
        Arc::new(FixturePort::new(
            fixture::FixtureScenario::Healthy,
            ActionScript::Unavailable,
        ))
    }
}
