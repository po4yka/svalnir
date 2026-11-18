//! The data layer: snapshot types, the sources, and the model that polls them.

pub mod fixture;
pub mod live;
pub mod model;
pub mod store;

use model::{AgentSnapshot, HostSnapshot, ServiceSnapshot};
use std::fmt::Debug;

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

    /// The label of the source for the status line.
    fn label(&self) -> &'static str;

    /// The name of the fixture scenario, when the source is a fixture.
    fn fixture_name(&self) -> Option<&'static str> {
        None
    }
}
