//! Access to the collectors of the agent library, in this process.
//!
//! This build has no IPC. A read-only command makes
//! one [`Host`], which holds one collection context, and reads the host
//! through the adapters of `svalnir_agent`. No function here changes the
//! host.

use std::path::Path;

use serde::Serialize;
use svalnir_agent::platform::memory::{CollectError, CollectionContext};
use svalnir_agent::platform::volume::{self, MountedVolume, VolumeQueryError};
use svalnir_core::observation::{Observation, ObservationValue, Reading};

use crate::output::{ErrorBody, ErrorFamily, ErrorStage, NextAction};

/// The mount point of the data volume of the startup volume group on macOS.
const STARTUP_DATA_MOUNT_POINT: &str = "/System/Volumes/Data";

/// The collectors of this process.
#[derive(Debug)]
pub(crate) struct Host {
    context: CollectionContext,
}

impl Host {
    /// Makes the collection context of this process.
    ///
    /// # Errors
    ///
    /// Returns `collector_unavailable` when the host gives no boot identity
    /// or no monotonic clock.
    pub(crate) fn open() -> Result<Self, ErrorBody> {
        CollectionContext::for_current_process()
            .map(|context| Self { context })
            .map_err(|error| collector_unavailable(&error.to_string()))
    }

    /// The collection context.
    pub(crate) fn context(&self) -> &CollectionContext {
        &self.context
    }

    /// The volume that the `startup-data` selector names: the data volume of
    /// the startup volume group, or the root volume on a host that has no
    /// separate data volume.
    pub(crate) fn startup_data_volume() -> Result<MountedVolume, VolumeQueryError> {
        let data: &Path = Path::new(STARTUP_DATA_MOUNT_POINT);
        if data.is_dir() {
            volume::volume_at(data)
        } else {
            volume::volume_at(Path::new("/"))
        }
    }

    /// A collector for the processes of the current user, with the boot,
    /// worker, and epoch identities of this context.
    #[cfg(target_os = "macos")]
    pub(crate) fn process_collector(
        &self,
    ) -> Result<
        svalnir_agent::platform::process::ProcessCollector<
            svalnir_agent::platform::process::DarwinProcessSource,
        >,
        ErrorBody,
    > {
        use svalnir_agent::platform::process::{
            CollectionContext as ProcessContext, DarwinProcessSource, ProcessCollector,
        };
        let identity = self.context.identity();
        ProcessCollector::new(
            DarwinProcessSource::new(),
            ProcessContext {
                worker_id: identity.worker_id.clone(),
                boot_id: identity.boot_id.clone(),
                collector_epoch: identity.collector_epoch.clone(),
            },
        )
        .map_err(|error| collector_unavailable(&error.to_string()))
    }
}

/// The error for a collector that gave no observation envelope.
pub(crate) fn collector_unavailable(detail: &str) -> ErrorBody {
    ErrorBody {
        code: "collector_unavailable".into(),
        family: ErrorFamily::Native,
        stage: ErrorStage::Collection,
        message: format!("a collector of this host is not available: {detail}"),
        fields: &[],
        operation_id: None,
        plan_id: None,
        next_action: NextAction::RefreshObservation,
    }
}

impl From<CollectError> for ErrorBody {
    fn from(error: CollectError) -> Self {
        collector_unavailable(&error.to_string())
    }
}

/// The error for a command whose collector exists only on macOS.
#[cfg(not(target_os = "macos"))]
pub(crate) fn unsupported_platform(command: &str) -> ErrorBody {
    ErrorBody {
        code: "unsupported_platform".into(),
        family: ErrorFamily::Native,
        stage: ErrorStage::Collection,
        message: format!("`svalnir {command}` has a collector for macOS only"),
        fields: &[],
        operation_id: None,
        plan_id: None,
        next_action: NextAction::None,
    }
}

/// A value that is not an observation, with the reason when there is none.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ReadingView<T> {
    pub(crate) value: Option<T>,
    pub(crate) availability: &'static str,
    pub(crate) reason: Option<String>,
}

impl<T: Clone> ReadingView<T> {
    pub(crate) fn of(reading: &Reading<T>) -> Self {
        match reading {
            Reading::Available(value) => Self {
                value: Some(value.clone()),
                availability: "available",
                reason: None,
            },
            Reading::Unavailable(reason) => Self {
                value: None,
                availability: "unavailable",
                reason: Some(reason.as_str().to_owned()),
            },
            Reading::Unrecognized(_) => Self {
                value: None,
                availability: "unavailable",
                reason: Some("unrecognized".to_owned()),
            },
        }
    }
}

/// Whether the required read scope of a command is complete.
///
/// A required observation that has no value makes the scope partial, and the
/// command then ends with exit status 4. An optional observation that has no
/// value does not (`docs/INTERFACES.md` section 8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ScopeCoverage {
    /// `complete` or `partial`.
    pub(crate) required_scope: &'static str,
    /// The required items that have no value.
    pub(crate) missing_required: Vec<String>,
}

impl ScopeCoverage {
    pub(crate) fn new() -> Self {
        Self {
            required_scope: "complete",
            missing_required: Vec::new(),
        }
    }

    /// Records a required observation.
    pub(crate) fn require<T: ObservationValue>(&mut self, observation: &Observation<T>) {
        if !observation.is_available() {
            self.missing(observation.metric_id.as_str());
        }
    }

    /// Records a required item that has no value.
    pub(crate) fn missing(&mut self, item: &str) {
        self.required_scope = "partial";
        self.missing_required.push(item.to_owned());
    }

    pub(crate) fn is_partial(&self) -> bool {
        !self.missing_required.is_empty()
    }

    /// One line for the text output.
    pub(crate) fn text_line(&self) -> String {
        if self.is_partial() {
            format!(
                "Required scope: partial (no value for {})\n",
                self.missing_required.join(", ")
            )
        } else {
            "Required scope: complete\n".to_owned()
        }
    }
}
