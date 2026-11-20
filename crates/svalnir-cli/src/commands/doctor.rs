//! `doctor`: the capability report of this process, the notification
//! capability and the catalog invalidation capability of the agent from
//! its status record, and the latest permanent start error of the agent.
//!
//! A denied or unknown capability is a successful diagnostic, so the exit
//! status is 0 for each verdict (`docs/INTERFACES.md` section 8).

use serde::Serialize;
use svalnir_agent::capability::{self, CapabilityReport, WorkerRole};
use svalnir_agent::notify::NotificationStatus;
use svalnir_agent::observe::{self, AgentCapabilityReading, Freshness};
use svalnir_agent::runtime::invalidation::CatalogWatchStatus;
use svalnir_core::time::WallTime;

use super::start_failure::StartFailureView;
use super::{CommandFailure, Invocation};
use crate::output::{ExitStatus, Kind};
use crate::text::{escape, put_line, table};

/// Renders the report as text.
pub(crate) fn render(report: &CapabilityReport) -> String {
    let mut out = String::new();
    put_line!(
        out,
        "Capability report: {}",
        report.summary.verdict.as_str()
    );
    put_line!(out, "{}", escape(&report.scope_note));
    if let Some(executable) = &report.subject.executable {
        put_line!(out, "Executable: {}", executable.display_label());
    }
    out.push('\n');
    let rows: Vec<Vec<String>> = report
        .capabilities
        .iter()
        .map(|entry| {
            vec![
                entry.id.as_str().to_owned(),
                entry.requirement.as_str().to_owned(),
                escape(entry.state.as_str()),
                escape(&entry.detail),
            ]
        })
        .collect();
    out.push_str(&table(
        &["CAPABILITY", "CLASS", "STATE", "DETAIL"],
        &[false, false, false, false],
        &rows,
    ));
    let hints: Vec<String> = report
        .capabilities
        .iter()
        .filter_map(|entry| {
            entry
                .remediation
                .as_ref()
                .map(|hint| format!("  {}: {}", entry.id.as_str(), escape(hint)))
        })
        .collect();
    if !hints.is_empty() {
        out.push_str("\nNext steps\n");
        for hint in hints {
            put_line!(out, "{hint}");
        }
    }
    // The table has no path. A directory row shows which directory the
    // probe examined: the state directory can be other than the default.
    let directories: Vec<String> = report
        .capabilities
        .iter()
        .filter(|entry| {
            matches!(
                entry.id,
                capability::CapabilityId::UserStateDirectory
                    | capability::CapabilityId::UserLogDirectory
            )
        })
        .filter_map(|entry| {
            entry
                .evidence
                .facts
                .iter()
                .find(|fact| fact.name == "path")
                .map(|fact| format!("  {}: {}", entry.id.as_str(), escape(&fact.value)))
        })
        .collect();
    if !directories.is_empty() {
        out.push_str("\nExamined directories\n");
        for directory in directories {
            put_line!(out, "{directory}");
        }
    }
    let not_available = |ids: &[capability::CapabilityId]| -> String {
        ids.iter()
            .map(|id| id.as_str())
            .collect::<Vec<&str>>()
            .join(", ")
    };
    if !report.summary.required_not_available.is_empty() {
        put_line!(
            out,
            "\nRequired and not available: {}",
            not_available(&report.summary.required_not_available)
        );
    }
    if !report.summary.optional_not_available.is_empty() {
        put_line!(
            out,
            "\nOptional and not available: {}",
            not_available(&report.summary.optional_not_available)
        );
    }
    out
}

/// The notification capability of the agent, as its status record has
/// it. A client process does not post notifications, so this capability
/// is of the agent process only.
#[derive(Debug, Serialize)]
#[serde(tag = "reading", rename_all = "snake_case")]
enum AgentNotificationsView {
    /// The state directory has no journal, or no status record.
    NoStatus,
    /// The journal or the status record cannot be read.
    Unreadable { reason: String },
    /// The status record has no notification capability.
    NotRecorded { freshness: Freshness },
    /// The capability.
    Recorded {
        freshness: Freshness,
        #[serde(flatten)]
        notifications: NotificationStatus,
    },
}

/// The capability summary of the agent from its status record. The read
/// makes no state directory and no journal.
fn read_agent_capabilities(invocation: &Invocation<'_>) -> AgentCapabilityReading {
    let journal = match super::session::open_existing_journal(invocation.environment) {
        Ok(Some(journal)) => journal,
        Ok(None) => return AgentCapabilityReading::NoStatus,
        Err(error) => {
            return AgentCapabilityReading::Unreadable {
                reason: error.message,
            };
        }
    };
    let now: WallTime =
        WallTime::try_from(std::time::SystemTime::now()).unwrap_or(WallTime::UNIX_EPOCH);
    observe::agent_capabilities(&observe::read_status(&journal, now))
}

impl AgentNotificationsView {
    fn of(reading: &AgentCapabilityReading) -> Self {
        match reading {
            AgentCapabilityReading::NoStatus => Self::NoStatus,
            AgentCapabilityReading::Unreadable { reason } => Self::Unreadable {
                reason: reason.clone(),
            },
            AgentCapabilityReading::NotRecorded { freshness } => Self::NotRecorded {
                freshness: *freshness,
            },
            AgentCapabilityReading::Recorded { summary, freshness } => {
                match &summary.notifications {
                    Some(notifications) => Self::Recorded {
                        freshness: *freshness,
                        notifications: notifications.clone(),
                    },
                    None => Self::NotRecorded {
                        freshness: *freshness,
                    },
                }
            }
        }
    }

    fn render(&self, out: &mut String) {
        out.push_str(
            "Agent notifications (agent.notifications, from the status record of the agent)\n",
        );
        match self {
            Self::NoStatus => out.push_str(
                "  No status record of the agent: no agent ran on this state directory.\n",
            ),
            Self::Unreadable { reason } => {
                put_line!(
                    out,
                    "  The status record cannot be read: {}",
                    escape(reason)
                );
            }
            Self::NotRecorded { .. } => {
                out.push_str("  The status record has no notification capability of the agent.\n");
            }
            Self::Recorded {
                freshness,
                notifications,
            } => {
                put_line!(
                    out,
                    "  State: {} ({})",
                    escape(notifications.state.as_str()),
                    freshness_text(freshness)
                );
                put_line!(out, "  {}", escape(&notifications.detail));
                let counts = &notifications.counts;
                put_line!(
                    out,
                    "  Notices of this agent lifetime: {} posted, {} not authorized, {} failed, {} dropped, {} rate limited, {} coalesced, {} not shown (a kind that the center does not show)",
                    counts.posted,
                    counts.not_authorized,
                    counts.failed,
                    counts.dropped,
                    counts.rate_limited,
                    counts.coalesced,
                    counts.not_presented
                );
            }
        }
    }
}

/// The `FSEvents` invalidation of the candidate catalog of the agent, as its
/// status record has it. Only the agent has a candidate source.
#[derive(Debug, Serialize)]
#[serde(tag = "reading", rename_all = "snake_case")]
enum AgentCatalogWatchView {
    /// The state directory has no journal, or no status record.
    NoStatus,
    /// The journal or the status record cannot be read.
    Unreadable { reason: String },
    /// The status record has no catalog invalidation capability.
    NotRecorded { freshness: Freshness },
    /// The capability.
    Recorded {
        freshness: Freshness,
        #[serde(flatten)]
        watch: CatalogWatchStatus,
    },
}

impl AgentCatalogWatchView {
    fn of(reading: &AgentCapabilityReading) -> Self {
        match reading {
            AgentCapabilityReading::NoStatus => Self::NoStatus,
            AgentCapabilityReading::Unreadable { reason } => Self::Unreadable {
                reason: reason.clone(),
            },
            AgentCapabilityReading::NotRecorded { freshness } => Self::NotRecorded {
                freshness: *freshness,
            },
            AgentCapabilityReading::Recorded { summary, freshness } => {
                match &summary.catalog_watch {
                    Some(watch) => Self::Recorded {
                        freshness: *freshness,
                        watch: watch.clone(),
                    },
                    None => Self::NotRecorded {
                        freshness: *freshness,
                    },
                }
            }
        }
    }

    fn render(&self, out: &mut String) {
        out.push_str(
            "Agent catalog invalidation (agent.catalog_watch, from the status record of the agent)\n",
        );
        match self {
            Self::NoStatus => out.push_str(
                "  No status record of the agent: no agent ran on this state directory.\n",
            ),
            Self::Unreadable { reason } => {
                put_line!(
                    out,
                    "  The status record cannot be read: {}",
                    escape(reason)
                );
            }
            Self::NotRecorded { .. } => {
                out.push_str(
                    "  The status record has no catalog invalidation capability of the agent.\n",
                );
            }
            Self::Recorded { freshness, watch } => {
                put_line!(
                    out,
                    "  State: {} ({})",
                    escape(watch.state.as_str()),
                    freshness_text(freshness)
                );
                put_line!(out, "  {}", escape(&watch.detail));
                let counts = &watch.counts;
                put_line!(
                    out,
                    "  Stream of {} approved roots: {} events, {} dirty regions, {} full reconciliations{}, {} invalidations",
                    watch.roots,
                    counts.events,
                    counts.regions,
                    counts.reconciliations,
                    counts
                        .last_reconcile_reason
                        .map_or_else(String::new, |reason| format!(
                            " (latest: {})",
                            reason.as_str()
                        )),
                    counts.invalidations
                );
            }
        }
    }
}

fn freshness_text(freshness: &Freshness) -> &'static str {
    match freshness {
        Freshness::Current { .. } => "current status record",
        Freshness::Stale { .. } => "stale status record: the agent does not write now",
        Freshness::Stopped => "the agent stopped",
        Freshness::Unknown => "the age of the status record is not known",
    }
}

/// The result of `doctor`: the capability report of this process, the
/// notification capability and the catalog invalidation capability of the
/// agent, and the latest permanent start error of the agent.
#[derive(Debug, Serialize)]
struct DoctorView {
    #[serde(flatten)]
    report: CapabilityReport,
    agent_notifications: AgentNotificationsView,
    agent_catalog_watch: AgentCatalogWatchView,
    agent_start_failure: StartFailureView,
}

fn render_view(view: &DoctorView) -> String {
    let mut out: String = render(&view.report);
    out.push('\n');
    view.agent_notifications.render(&mut out);
    out.push('\n');
    view.agent_catalog_watch.render(&mut out);
    out.push('\n');
    view.agent_start_failure.render(&mut out);
    out
}

pub(crate) fn run(invocation: &mut Invocation<'_>) -> Result<ExitStatus, CommandFailure> {
    // The state-directory entry is for the directory that this invocation
    // uses. With no usable state directory, the entry is for the default
    // directory, and a warning says why: each other command refuses then.
    let report: CapabilityReport = match invocation.environment.state_directory() {
        Ok(state_directory) => capability::diagnose_in(WorkerRole::Cli, &state_directory),
        Err(error) => {
            invocation.warnings.push(crate::output::Warning {
                code: error.code.clone(),
                message: format!(
                    "{}; the row `user.state_directory` is for the default directory, which the other commands do not use",
                    error.message
                ),
            });
            capability::diagnose(WorkerRole::Cli)
        }
    };
    let agent: AgentCapabilityReading = read_agent_capabilities(invocation);
    let view = DoctorView {
        report,
        agent_notifications: AgentNotificationsView::of(&agent),
        agent_catalog_watch: AgentCatalogWatchView::of(&agent),
        agent_start_failure: StartFailureView::read(invocation.environment),
    };
    invocation.emit(Kind::Report, &view, render_view)?;
    Ok(ExitStatus::Success)
}

#[cfg(test)]
mod tests {
    use super::render;
    use crate::test_support::capability_report;

    #[test]
    fn the_text_has_one_row_for_each_capability_and_the_hints() {
        let report = capability_report(true);
        let text = render(&report);
        assert!(text.starts_with("Capability report: blocked\n"), "{text}");
        assert!(text.contains("metrics.memory_pressure"), "{text}");
        assert!(text.contains("denied"), "{text}");
        assert!(text.contains("Required and not available: "), "{text}");
        assert_eq!(
            text.lines()
                .filter(|line| line.contains("required"))
                .count(),
            7,
            "{text}"
        );
    }

    #[test]
    fn the_json_is_the_report_of_the_library() {
        let report = capability_report(false);
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["summary"]["verdict"], "ready");
        assert_eq!(json["subject"]["role"], "cli");
        assert_eq!(json["capabilities"].as_array().unwrap().len(), 13);
        assert!(render(&report).starts_with("Capability report: ready\n"));
    }
}
