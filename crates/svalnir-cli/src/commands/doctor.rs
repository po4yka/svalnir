//! `doctor`: the capability report of this process.
//!
//! A denied or unknown capability is a successful diagnostic, so the exit
//! status is 0 for each verdict (`docs/INTERFACES.md` section 8).

use svalnir_agent::capability::{self, CapabilityReport, WorkerRole};

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

pub(crate) fn run(invocation: &mut Invocation<'_>) -> Result<ExitStatus, CommandFailure> {
    let report: CapabilityReport = capability::diagnose(WorkerRole::Cli);
    invocation.emit(Kind::Report, &report, render)?;
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
