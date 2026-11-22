//! `disk`: the free and available space of the volume of the home
//! directory.
//!
//! The command reads the volume one time in this process, with the
//! collectors that `status` uses. With `--warn-below SIZE` it is a check
//! for a hook: it prints a warning only when the available capacity is
//! below SIZE, each error goes to stderr, and the exit status is 0
//! (`docs/INTERFACES.md` section 4).

use std::path::Path;

use serde::Serialize;
use svalnir_agent::observe;
use svalnir_core::byte_size::parse_byte_size;
use svalnir_core::quantity::Bytes;

use super::resources::{DiskReading, DiskView, snapshot_status};
use super::{CommandFailure, Invocation};
use crate::cli::{DiskArgs, Format};
use crate::host::{Host, ScopeCoverage};
use crate::output::{ErrorBody, ErrorFamily, ErrorStage, ExitStatus, Kind, NextAction};
use crate::text::{escape, human_bytes, put_line};

/// The advice of a warning.
const WARNING_ADVICE: &str = "Run `svalnir disk` for the reading, and `svalnir clean inspect --rule RULE_ID` to find regenerable data.";

/// The result of `disk`.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct DiskReport {
    /// The home directory whose volume was read.
    home: String,
    disk: DiskView,
    /// The value of `--warn-below`, when it is given.
    threshold: Option<Bytes>,
    /// Whether the available capacity is below the threshold. `null` with
    /// no threshold.
    below_threshold: Option<bool>,
    /// The warning text, when the available capacity is below the
    /// threshold.
    warning: Option<String>,
    coverage: ScopeCoverage,
}

impl DiskReport {
    /// Makes the report of `reading`. With a threshold, an available
    /// capacity that has no value is an error: the check cannot be made.
    pub(crate) fn new(
        home: &Path,
        reading: &DiskReading,
        threshold: Option<Bytes>,
    ) -> Result<Self, ErrorBody> {
        let mut coverage: ScopeCoverage = ScopeCoverage::new();
        let disk: DiskView = DiskView::of_home(reading, &mut coverage);
        let (below_threshold, warning): (Option<bool>, Option<String>) = match threshold {
            None => (None, None),
            Some(threshold) => {
                let available: Bytes = disk
                    .available()
                    .and_then(|observation| observation.value().copied())
                    .ok_or_else(available_unknown)?;
                if available < threshold {
                    (
                        Some(true),
                        Some(format!(
                            "Warning: only {} is available on the volume of the home directory, below {}. {WARNING_ADVICE}",
                            human_bytes(available.get()),
                            human_bytes(threshold.get()),
                        )),
                    )
                } else {
                    (Some(false), None)
                }
            }
        };
        Ok(Self {
            home: home.to_string_lossy().into_owned(),
            disk,
            threshold,
            below_threshold,
            warning,
            coverage,
        })
    }

    pub(crate) fn render(&self) -> String {
        let mut out: String = String::new();
        self.disk.render(&mut out);
        put_line!(out, "  Home directory: {}", escape(&self.home));
        out.push_str(&self.coverage.text_line());
        out
    }

    /// The text of the warning mode: the warning, or nothing.
    fn render_warning(&self) -> String {
        self.warning
            .as_ref()
            .map_or_else(String::new, |warning| format!("{}\n", escape(warning)))
    }
}

fn available_unknown() -> ErrorBody {
    ErrorBody::new(
        "collector_unavailable",
        ErrorFamily::Native,
        ErrorStage::Collection,
        "the available capacity of the volume of the home directory is not known",
    )
}

fn home_not_set() -> ErrorBody {
    ErrorBody::new(
        "home_not_set",
        ErrorFamily::Native,
        ErrorStage::Dispatch,
        "`HOME` is not set to an absolute path, so the volume of the home directory is not known",
    )
    .with_next_action(NextAction::None)
}

fn invalid_size(text: &str, reason: &str) -> ErrorBody {
    ErrorBody::new(
        "invalid_arguments",
        ErrorFamily::Request,
        ErrorStage::Arguments,
        format!(
            "the value `{}` of `--warn-below` is not a size: {reason}",
            escape(text)
        ),
    )
    .with_fields(&["warn_below"])
}

/// Reads the volume of the home directory and makes the report.
fn collect(invocation: &Invocation<'_>, threshold: Option<Bytes>) -> Result<DiskReport, ErrorBody> {
    let home: &Path = invocation
        .environment
        .home
        .as_deref()
        .filter(|home| home.is_absolute())
        .ok_or_else(home_not_set)?;
    let host: Host = Host::open()?;
    let reading: DiskReading = observe::collect_disk_at(host.observed(), home);
    DiskReport::new(home, &reading, threshold)
}

pub(crate) fn run(
    arguments: &DiskArgs,
    invocation: &mut Invocation<'_>,
) -> Result<ExitStatus, CommandFailure> {
    let Some(text) = arguments.warn_below.as_deref() else {
        let report: DiskReport = collect(invocation, None)?;
        invocation.emit(Kind::Snapshot, &report, DiskReport::render)?;
        return Ok(snapshot_status(&report.coverage));
    };
    // The warning mode never fails: a hook that runs it must not stop the
    // session of the user. An error goes to stderr only.
    let checked: Result<DiskReport, ErrorBody> = parse_byte_size(text)
        .map_err(|error| invalid_size(text, &error.to_string()))
        .and_then(|threshold| collect(invocation, Some(threshold)));
    let report: DiskReport = match checked {
        Ok(report) => report,
        Err(error) => {
            for warning in std::mem::take(&mut invocation.warnings) {
                writeln!(invocation.stderr, "warning: {}", warning.message)?;
            }
            writeln!(invocation.stderr, "error: {}", error.message)?;
            return Ok(ExitStatus::Success);
        }
    };
    // The text form has the warning or nothing. A machine format always
    // has the report, with `below_threshold`.
    if invocation.format == Format::Text && report.warning.is_none() {
        for warning in std::mem::take(&mut invocation.warnings) {
            writeln!(invocation.stderr, "warning: {}", warning.message)?;
        }
        return Ok(ExitStatus::Success);
    }
    invocation.emit(Kind::Snapshot, &report, DiskReport::render_warning)?;
    Ok(ExitStatus::Success)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use svalnir_core::quantity::Bytes;

    use super::{DiskReading, DiskReport};
    use crate::test_support::volume_capacity;

    fn measured() -> DiskReading {
        let (identity, capacity, foundation) = volume_capacity();
        DiskReading::Measured {
            identity,
            capacity,
            foundation,
        }
    }

    const GIB: u64 = 1024 * 1024 * 1024;

    #[test]
    fn the_report_has_the_capacity_of_the_volume_of_the_home_directory() {
        let report = DiskReport::new(Path::new("/Users/test"), &measured(), None).unwrap();
        let text = report.render();
        assert!(
            text.contains("Disk (volume of the home directory, /System/Volumes/Data)"),
            "{text}"
        );
        assert!(text.contains("Available      100.0 GiB"), "{text}");
        assert!(text.contains("Home directory: /Users/test"), "{text}");
        assert!(report.warning.is_none());
        assert!(report.below_threshold.is_none());
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["disk"]["selector"], "home");
        assert!(json["threshold"].is_null());
    }

    #[test]
    fn a_threshold_above_the_available_capacity_gives_a_warning() {
        let below = DiskReport::new(
            Path::new("/Users/test"),
            &measured(),
            Some(Bytes::new(200 * GIB)),
        )
        .unwrap();
        assert_eq!(below.below_threshold, Some(true));
        let warning = below.render_warning();
        assert!(
            warning.starts_with("Warning: only 100.0 GiB is available on the volume of the home directory, below 200.0 GiB."),
            "{warning}"
        );
        let above = DiskReport::new(
            Path::new("/Users/test"),
            &measured(),
            Some(Bytes::new(20 * GIB)),
        )
        .unwrap();
        assert_eq!(above.below_threshold, Some(false));
        assert_eq!(above.render_warning(), "");
    }

    #[test]
    fn a_threshold_with_no_available_capacity_is_an_error() {
        let reading = DiskReading::Unresolved("no volume".to_owned());
        let error =
            DiskReport::new(Path::new("/Users/test"), &reading, Some(Bytes::new(GIB))).unwrap_err();
        assert_eq!(&*error.code, "collector_unavailable");
        // With no threshold, the report has a partial scope.
        let report = DiskReport::new(Path::new("/Users/test"), &reading, None).unwrap();
        assert!(report.coverage.is_partial());
    }
}
