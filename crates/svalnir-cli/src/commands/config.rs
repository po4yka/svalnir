//! `config validate` and `config show`.
//!
//! A configuration file is a proposal. These commands read it and never make
//! it active (`docs/INTERFACES.md` section 13). The checks that need the
//! agent are named in each result as `requires_agent`.

use std::io::Read as _;
use std::path::{Path, PathBuf};

use serde::Serialize;
use svalnir_core::config::{
    self, CheckId, CheckReport, Finding, MAX_DOCUMENT_BYTES, ValidatedConfig, Validation,
};
use svalnir_core::file::LosslessPath;
use svalnir_core::policy::{self, PolicyDescription, PolicyId};
use svalnir_core::quantity::{Bytes, Nanoseconds};

use super::{CommandFailure, Invocation};
use crate::cli::{ConfigShowArgs, ProposalOption};
use crate::environment::Environment;
use crate::output::{ErrorBody, ErrorFamily, ErrorStage, ExitStatus, Kind, NextAction};
use crate::text::{escape, json_tree, put_line, table};

/// The text of the configuration template: a document with no key other than
/// the schema version, so that each value comes from the template.
const TEMPLATE_DOCUMENT: &str = "schema_version = 1\n";

/// The statement of each result about activation.
const PROPOSAL_NOTE: &str = "This is a proposal. It is not active, and this command did not change the active behavior. A check with the status `requires_agent` did not run: the rule registry, the volume selectors, the application identities, the worker capabilities, and the action grants need the background agent.";

/// The statement of `config show --effective`.
const EFFECTIVE_NOTE: &str = "These are the values of the revision in effect, from the operation journal. A value that the revision does not give comes from the built-in template. An activation makes no grant: `svalnir agent status` shows the standing of each guard.";

/// Where a proposal comes from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct SourceView {
    /// `file`, `built_in_template`, or `active_revision`.
    pub(crate) kind: &'static str,
    /// The file, or the default path that has no file.
    pub(crate) path: Option<LosslessPath>,
    /// `option` for `--config`, `default` for the configuration path of the
    /// user.
    pub(crate) selected_by: &'static str,
}

impl SourceView {
    pub(crate) fn text(&self) -> String {
        let path: String = self
            .path
            .as_ref()
            .map_or_else(|| "unknown path".to_owned(), LosslessPath::display_label);
        match self.kind {
            "active_revision" => "the revision in effect, from the operation journal".to_owned(),
            "file" => format!("{path} (file, selected by {})", self.selected_by),
            _ => format!("built-in template (no file at {path})"),
        }
    }

    /// A label for a simulation report.
    pub(crate) fn revision_label(&self) -> &'static str {
        match (self.kind, self.selected_by) {
            ("file", "option") => "proposal file of --config",
            ("file", _) => "proposal file at the default path",
            _ => "built-in template",
        }
    }
}

/// A configuration text and its source.
#[derive(Debug, Clone)]
pub(crate) struct Proposal {
    pub(crate) source: SourceView,
    pub(crate) text: String,
}

fn input_error(code: &'static str, family: ErrorFamily, message: String) -> ErrorBody {
    let next_action: NextAction = if family == ErrorFamily::Request {
        NextAction::CorrectRequest
    } else {
        NextAction::None
    };
    ErrorBody {
        code: code.into(),
        family,
        stage: ErrorStage::Input,
        message,
        fields: &["config"],
        operation_id: None,
        plan_id: None,
        next_action,
    }
}

/// Reads a configuration file. The read stops one byte after the largest
/// accepted document, so a large file cannot use much memory; the validation
/// then reports `document_too_large`.
///
/// The file is opened with `O_NONBLOCK`, so opening a FIFO or a terminal
/// cannot wait. Anything that is not a regular file is an invalid argument.
fn read_document(path: &Path) -> Result<String, ErrorBody> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(|error| match error.kind() {
        std::io::ErrorKind::NotFound => input_error(
            "config_not_found",
            ErrorFamily::Request,
            "the configuration file does not exist".to_owned(),
        ),
        kind => input_error(
            "config_unreadable",
            ErrorFamily::Native,
            format!("the configuration file cannot be read: {kind}"),
        ),
    })?;
    let is_regular: bool = file.metadata().is_ok_and(|metadata| metadata.is_file());
    if !is_regular {
        return Err(input_error(
            "invalid_configuration",
            ErrorFamily::Request,
            "the configuration path is not a regular file".to_owned(),
        ));
    }
    let limit: u64 = u64::try_from(MAX_DOCUMENT_BYTES)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut bytes: Vec<u8> = Vec::new();
    file.take(limit).read_to_end(&mut bytes).map_err(|error| {
        input_error(
            "config_unreadable",
            ErrorFamily::Native,
            format!("the configuration file cannot be read: {}", error.kind()),
        )
    })?;
    if bytes.len() > MAX_DOCUMENT_BYTES {
        // The cut can fall inside a character. The text is too large in any
        // case, and the validation reports that. A replacement character
        // is never shorter than the bytes it replaces.
        return Ok(String::from_utf8_lossy(&bytes).into_owned());
    }
    String::from_utf8(bytes).map_err(|_| {
        input_error(
            "invalid_configuration",
            ErrorFamily::Request,
            "the configuration file is not UTF-8 text".to_owned(),
        )
    })
}

/// Loads the proposal that a command reads.
///
/// `--config` selects a file, relative to the invocation directory. Without
/// it, the proposal is the configuration file of the user. When that file
/// does not exist and `allow_template` is true, the proposal is the built-in
/// template.
pub(crate) fn load(
    environment: &Environment,
    option: &ProposalOption,
    allow_template: bool,
) -> Result<Proposal, ErrorBody> {
    if let Some(path) = &option.config {
        let path: PathBuf = environment.resolve(path, &["config"])?;
        return Ok(Proposal {
            text: read_document(&path)?,
            source: SourceView {
                kind: "file",
                path: LosslessPath::from_path(&path).ok(),
                selected_by: "option",
            },
        });
    }
    let path: PathBuf = environment.config_path()?;
    let lossless: Option<LosslessPath> = LosslessPath::from_path(&path).ok();
    match read_document(&path) {
        Ok(text) => Ok(Proposal {
            text,
            source: SourceView {
                kind: "file",
                path: lossless,
                selected_by: "default",
            },
        }),
        Err(error) if &*error.code == "config_not_found" && allow_template => Ok(Proposal {
            text: TEMPLATE_DOCUMENT.to_owned(),
            source: SourceView {
                kind: "built_in_template",
                path: lossless,
                selected_by: "default",
            },
        }),
        Err(mut error) => {
            if &*error.code == "config_not_found" {
                "no configuration file is at the default path; give `--config PATH`"
                    .clone_into(&mut error.message);
            }
            Err(error)
        }
    }
}

/// The validated configuration of a proposal, for a command that needs one.
pub(crate) fn validated(proposal: &Proposal) -> Result<ValidatedConfig, ErrorBody> {
    let validation: Validation = config::parse_and_validate(&proposal.text);
    match validation.result {
        Ok(config) => Ok(config),
        Err(findings) => Err(input_error(
            "invalid_configuration",
            ErrorFamily::Request,
            format!(
                "the configuration proposal has {} findings; `svalnir config validate` lists them",
                findings.len()
            ),
        )),
    }
}

/// The result of `config validate`.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct ValidateView {
    source: SourceView,
    valid: bool,
    /// The acknowledgement of `docs/INTERFACES.md` section 13.
    acknowledgement: &'static str,
    active_configuration_changed: bool,
    /// Each check with its status.
    checks: CheckReport,
    /// The checks that only the agent can do.
    requires_agent: Vec<CheckId>,
    findings: Vec<Finding>,
    note: &'static str,
}

impl ValidateView {
    pub(crate) fn new(proposal: &Proposal) -> Self {
        let validation: Validation = config::parse_and_validate(&proposal.text);
        Self {
            source: proposal.source.clone(),
            valid: validation.config().is_some(),
            acknowledgement: "validated_proposal",
            active_configuration_changed: false,
            requires_agent: validation.checks.requires_agent().collect(),
            findings: validation.findings().to_vec(),
            checks: validation.checks,
            note: PROPOSAL_NOTE,
        }
    }

    pub(crate) fn render(&self) -> String {
        let mut out = String::new();
        put_line!(out, "Configuration proposal: {}", self.source.text());
        if self.valid {
            out.push_str("Result: valid for the checks that ran\n");
        } else {
            put_line!(out, "Result: not valid ({} findings)", self.findings.len());
        }
        out.push_str("\nChecks\n");
        let rows: Vec<Vec<String>> = self
            .checks
            .outcomes()
            .iter()
            .map(|outcome| {
                vec![
                    format!("  {}", outcome.check.as_str()),
                    outcome.status.as_str().to_owned(),
                ]
            })
            .collect();
        out.push_str(&table(&["  CHECK", "STATUS"], &[false, false], &rows));
        if !self.findings.is_empty() {
            out.push_str("\nFindings\n");
            for finding in &self.findings {
                let position: String = finding.location.map_or_else(String::new, |location| {
                    format!(" (line {}, column {})", location.line, location.column)
                });
                let path: &str = if finding.path.is_empty() {
                    "document"
                } else {
                    &finding.path
                };
                put_line!(
                    out,
                    "  {}{position}: {} [{}]",
                    escape(path),
                    escape(&finding.message),
                    finding.code.as_str()
                );
            }
        }
        put_line!(out, "\n{PROPOSAL_NOTE}");
        out
    }

    /// Exit status 2 for a document that is not valid.
    pub(crate) fn status(&self) -> ExitStatus {
        if self.valid {
            ExitStatus::Success
        } else {
            ExitStatus::Usage
        }
    }
}

/// The `[history]` table.
#[derive(Debug, Clone, Serialize)]
struct HistoryView {
    retention: Nanoseconds,
    max_database_size: Bytes,
    redact_exported_paths: bool,
}

/// The `[cleanup.projects]` table.
#[derive(Debug, Clone, Serialize)]
struct ProjectCleanupView {
    quiet_period: Nanoseconds,
    paseo_agents: bool,
}

/// The `[cleanup]` table.
#[derive(Debug, Clone, Serialize)]
struct CleanupView {
    projects: ProjectCleanupView,
}

/// The `[privacy]` table.
#[derive(Debug, Clone, Serialize)]
struct PrivacyView {
    telemetry: bool,
    include_command_arguments: bool,
}

/// The result of `config show`.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct ShowView {
    source: SourceView,
    /// True for the revision in effect (`--effective`). False for a
    /// proposal.
    active: bool,
    /// The revision in effect, for `--effective`.
    revision: Option<svalnir_core::authority::PolicyRevision>,
    schema_version: u32,
    template_revision: u32,
    profile: &'static str,
    /// The guard tables, the `[agent]` timing, and the `[protections]`
    /// table, as `policy show` gives them.
    policies: Vec<PolicyDescription>,
    cleanup: CleanupView,
    history: HistoryView,
    privacy: PrivacyView,
    /// The keys that the document gives. Each other value comes from the
    /// template.
    explicit_keys: Vec<String>,
    note: &'static str,
}

impl ShowView {
    pub(crate) fn new(source: SourceView, config: &ValidatedConfig) -> Self {
        let history = config.history();
        let privacy = config.privacy();
        let projects = &config.cleanup().projects;
        Self {
            source,
            active: false,
            revision: None,
            schema_version: config.schema_version(),
            template_revision: config.template_revision(),
            profile: config.agent().profile.as_str(),
            policies: PolicyId::ALL
                .iter()
                .map(|id| policy::show_policy(config, *id))
                .collect(),
            cleanup: CleanupView {
                projects: ProjectCleanupView {
                    // The validation bounds the period to 90 days, so it
                    // fits.
                    quiet_period: Nanoseconds::try_from(projects.quiet_period)
                        .unwrap_or(Nanoseconds::MAX),
                    paseo_agents: projects.paseo_agents,
                },
            },
            history: HistoryView {
                // A validated duration fits; a value that does not fit shows
                // as the largest value.
                retention: Nanoseconds::try_from(history.retention).unwrap_or(Nanoseconds::MAX),
                max_database_size: history.max_database_size,
                redact_exported_paths: history.redact_exported_paths,
            },
            privacy: PrivacyView {
                telemetry: privacy.telemetry,
                include_command_arguments: privacy.include_command_arguments,
            },
            explicit_keys: config.explicit_keys().map(str::to_owned).collect(),
            note: PROPOSAL_NOTE,
        }
    }

    /// The view of the revision in effect.
    pub(crate) fn effective(active: &super::session::ActiveConfig) -> Self {
        let mut view = Self::new(
            SourceView {
                kind: "active_revision",
                path: None,
                selected_by: "journal",
            },
            &active.config,
        );
        view.active = true;
        view.revision = Some(active.active.revision.clone());
        view.note = EFFECTIVE_NOTE;
        view
    }

    pub(crate) fn render(&self) -> String {
        let heading: &str = if self.active {
            "Effective configuration (the revision in effect)"
        } else {
            "Configuration proposal (not active)"
        };
        proposal_text(heading, &self.source, self)
    }
}

/// The text of a report about a proposal: a heading, the source, and each
/// field of the report with its machine name.
pub(crate) fn proposal_text<T: Serialize>(heading: &str, source: &SourceView, view: &T) -> String {
    let mut out = String::new();
    put_line!(out, "{heading}");
    put_line!(out, "Source: {}", source.text());
    out.push('\n');
    match serde_json::to_value(view) {
        Ok(serde_json::Value::Object(mut fields)) => {
            // The heading and the source line have these two values.
            fields.remove("source");
            let note: Option<serde_json::Value> = fields.remove("note");
            out.push_str(&json_tree(&serde_json::Value::Object(fields)));
            if let Some(serde_json::Value::String(note)) = note {
                put_line!(out, "\n{}", escape(&note));
            }
        }
        Ok(other) => out.push_str(&json_tree(&other)),
        Err(_) => out.push_str("The report cannot be shown as text; use `--format json`.\n"),
    }
    out
}

/// One warning for each personal folder of the default `[protections]`
/// table that the `excluded_paths` list of the document does not protect
/// (`docs/POLICY_SPEC.md` section 12). The home directory of the client
/// resolves a path that starts from `/`.
pub(crate) fn personal_folder_warnings(
    config: &ValidatedConfig,
    environment: &Environment,
) -> Vec<crate::output::Warning> {
    config
        .unprotected_personal_folders(environment.home.as_deref())
        .into_iter()
        .map(|folder| crate::output::Warning {
            code: "personal_folder_not_protected".into(),
            message: format!(
                "the `[protections].excluded_paths` list of the document replaces the default list and does not protect `{folder}`: a manual or automatic action can include entries there"
            ),
        })
        .collect()
}

pub(crate) fn validate(
    arguments: &ProposalOption,
    invocation: &mut Invocation<'_>,
) -> Result<ExitStatus, CommandFailure> {
    let proposal: Proposal = load(invocation.environment, arguments, false)?;
    if let Some(config) = config::parse_and_validate(&proposal.text).config() {
        let warnings = personal_folder_warnings(config, invocation.environment);
        invocation.warnings.extend(warnings);
    }
    let view = ValidateView::new(&proposal);
    invocation.emit(Kind::Report, &view, ValidateView::render)?;
    Ok(view.status())
}

pub(crate) fn show(
    arguments: &ConfigShowArgs,
    invocation: &mut Invocation<'_>,
) -> Result<ExitStatus, CommandFailure> {
    if arguments.effective {
        let journal = super::session::open_existing_journal(invocation.environment)?
            .ok_or_else(super::session::no_active_revision)?;
        let authority = super::session::read_authority(&journal)?;
        let active = super::session::active_config(&journal, &authority.state)?;
        let warnings = personal_folder_warnings(&active.config, invocation.environment);
        invocation.warnings.extend(warnings);
        let view = ShowView::effective(&active);
        invocation.emit(Kind::Report, &view, ShowView::render)?;
        return Ok(ExitStatus::Success);
    }
    let proposal: Proposal = load(
        invocation.environment,
        &ProposalOption { config: None },
        true,
    )?;
    let config: ValidatedConfig = validated(&proposal)?;
    let warnings = personal_folder_warnings(&config, invocation.environment);
    invocation.warnings.extend(warnings);
    let view = ShowView::new(proposal.source, &config);
    invocation.emit(Kind::Report, &view, ShowView::render)?;
    Ok(ExitStatus::Success)
}

#[cfg(test)]
mod tests {
    use super::{Proposal, ShowView, SourceView, ValidateView, read_document, validated};
    use crate::output::{ErrorFamily, ExitStatus};
    use crate::test_support::TempDirectory;
    use svalnir_core::config::MAX_DOCUMENT_BYTES;
    use svalnir_core::file::LosslessPath;

    #[test]
    fn a_directory_is_an_invalid_argument() {
        let directory = TempDirectory::new();
        let error = read_document(directory.path()).unwrap_err();
        assert_eq!(error.family, ErrorFamily::Request);
        assert_eq!(error.exit_status(), ExitStatus::Usage);
    }

    #[cfg(unix)]
    #[test]
    fn a_fifo_is_rejected_and_does_not_block() {
        use std::os::unix::ffi::OsStrExt as _;
        let directory = TempDirectory::new();
        let path = directory.path().join("fifo");
        let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: `name` is a valid NUL-terminated path that lives through the call.
        let made: libc::c_int = unsafe { libc::mkfifo(name.as_ptr(), 0o600) };
        assert_eq!(made, 0);
        let error = read_document(&path).unwrap_err();
        assert_eq!(error.family, ErrorFamily::Request);
    }

    #[test]
    fn an_oversized_file_cut_inside_a_character_is_too_large_not_invalid_utf8() {
        let directory = TempDirectory::new();
        let path = directory.path().join("big.toml");
        // Each character has 2 bytes, so the cut at MAX + 1 splits one
        // when MAX is even.
        let text: String = "\u{e9}".repeat(MAX_DOCUMENT_BYTES);
        std::fs::write(&path, text).unwrap();
        let read: String = read_document(&path).unwrap();
        assert!(read.len() > MAX_DOCUMENT_BYTES);
    }

    fn proposal(text: &str) -> Proposal {
        Proposal {
            source: SourceView {
                kind: "file",
                path: Some(LosslessPath::from_bytes(b"/tmp/config.toml".to_vec()).unwrap()),
                selected_by: "option",
            },
            text: text.to_owned(),
        }
    }

    #[test]
    fn a_valid_proposal_lists_the_checks_that_ran_and_those_that_need_the_agent() {
        let view = ValidateView::new(&proposal("schema_version = 1\n"));
        assert_eq!(view.status(), ExitStatus::Success);
        let text = view.render();
        assert!(
            text.contains("Configuration proposal: /tmp/config.toml (file, selected by option)")
        );
        assert!(
            text.contains("Result: valid for the checks that ran"),
            "{text}"
        );
        assert!(text.contains("  syntax                  passed"), "{text}");
        assert!(
            text.contains("  rule_registry           requires_agent"),
            "{text}"
        );
        assert!(
            text.contains("did not change the active behavior"),
            "{text}"
        );
        let json = serde_json::to_value(&view).unwrap();
        assert_eq!(json["valid"], true);
        assert_eq!(json["acknowledgement"], "validated_proposal");
        assert_eq!(json["active_configuration_changed"], false);
        assert_eq!(json["checks"][0]["check"], "syntax");
        assert_eq!(json["checks"][0]["status"], "passed");
        assert_eq!(
            json["requires_agent"],
            serde_json::json!([
                "rule_registry",
                "volume_selectors",
                "application_identities",
                "worker_capabilities",
                "action_grants"
            ])
        );
        assert_eq!(json["findings"], serde_json::json!([]));
    }

    #[test]
    fn an_invalid_proposal_has_each_finding_and_status_2() {
        let view = ValidateView::new(&proposal(
            "schema_version = 1\n[disk_guard]\nwarn_below = \"10GiB\"\nreclaim_below = \"20GiB\"\nunknown = 1\n",
        ));
        assert_eq!(view.status(), ExitStatus::Usage);
        let text = view.render();
        assert!(text.contains("Result: not valid ("), "{text}");
        assert!(text.contains("disk_guard.unknown"), "{text}");
        assert!(text.contains("[unknown_key]"), "{text}");
        assert!(text.contains("[threshold_order]"), "{text}");
        let json = serde_json::to_value(&view).unwrap();
        assert_eq!(json["valid"], false);
        assert!(json["findings"].as_array().unwrap().len() >= 2);
    }

    #[test]
    fn a_syntax_finding_has_a_position() {
        let view = ValidateView::new(&proposal("schema_version = \n"));
        let text = view.render();
        assert!(text.contains("document (line 1, column "), "{text}");
        assert!(text.contains("  schema                  not_run"), "{text}");
    }

    #[test]
    fn show_labels_the_proposal_as_not_active() {
        let proposal = proposal("schema_version = 1\n[disk_guard]\nenabled = true\n");
        let config = validated(&proposal).unwrap();
        let view = ShowView::new(proposal.source, &config);
        let text = view.render();
        assert!(
            text.starts_with("Configuration proposal (not active)\n"),
            "{text}"
        );
        assert!(text.contains("active: false"), "{text}");
        assert!(text.contains("- disk_guard.enabled"), "{text}");
        assert!(text.contains("profile: observe"), "{text}");
        let json = serde_json::to_value(&view).unwrap();
        assert_eq!(json["active"], false);
        assert_eq!(json["policies"][0]["policy"], "disk-guard");
        assert_eq!(json["source"]["kind"], "file");
        assert_eq!(
            json["explicit_keys"],
            serde_json::json!(["disk_guard", "disk_guard.enabled", "schema_version"])
        );
    }

    #[test]
    fn an_invalid_proposal_is_an_error_for_a_command_that_needs_values() {
        let error = validated(&proposal("schema_version = 2\n")).unwrap_err();
        assert_eq!(&*error.code, "invalid_configuration");
        assert_eq!(error.exit_status(), ExitStatus::Usage);
    }
}
