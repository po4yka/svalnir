//! Read-only capacity readings for a client: the capacity of a volume that
//! the saved scan does not explain, the history of `disk.available_bytes`,
//! and an estimate of the time to a threshold.
//!
//! Owning specification: `docs/RESOURCE_MODEL.md` section 7. Each reading
//! changes nothing on the host and authorizes no action. The policy
//! evaluation in `svalnir-core` does not depend on this library, so no guard
//! can read the estimate as a trigger.
//!
//! | Item | Use |
//! | --- | --- |
//! | [`capacity_report`] | The four labeled entries of one volume |
//! | [`capacity_history`] | A bounded query of the stored samples |
//! | [`series_points`] | The samples of a history with their sleep evidence |
//! | [`forecast`] | The estimate of the time to a threshold, with its label |

pub mod estimate;
pub mod history;
pub mod report;

#[cfg(test)]
mod tests;

pub use estimate::{
    ESTIMATE_MODEL, ESTIMATE_NOTE, EstimateLimits, NoEstimateReason, SeriesPoint,
    ThresholdEstimate, ThresholdForecast, TimeToThreshold, estimate_time_to_threshold, forecast,
};
pub use history::{CapacityHistory, DEFAULT_HISTORY_LIMIT, capacity_history, series_points};
pub use report::{CapacityEntry, CapacityReport, REPORT_NOTE, ScanReference, capacity_report};
