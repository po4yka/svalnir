//! The checks of configuration validation and their status.
//!
//! `docs/INTERFACES.md` section 13 requires that `config validate` reports
//! which checks ran and which checks need the agent. This module does the
//! portable checks only. It reports each live check as
//! [`CheckStatus::RequiresAgent`]; it does not report a live check as passed.

use serde::Serialize;

use super::finding::{Finding, FindingCode};

/// A check of a proposed configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CheckId {
    /// The text is a TOML document of an accepted size. Portable.
    Syntax,
    /// Keys, value types, scalar grammars, enumerations, identifiers, and
    /// paths agree with the schema. Portable.
    Schema,
    /// The required relationships between values are true. Portable.
    Relationships,
    /// Each approved rule is in the compiled reviewed registry and can be an
    /// automatic rule. Live.
    RuleRegistry,
    /// Each volume selector resolves to a current volume identity. Live.
    VolumeSelectors,
    /// Each application selector resolves to a verified application or job
    /// identity. Live.
    ApplicationIdentities,
    /// The workers and adapters support the configured strategies. Live.
    WorkerCapabilities,
    /// The action grants and privilege grants admit the configuration. Live.
    ActionGrants,
}

impl CheckId {
    /// Each check, in the sequence of the report.
    pub const ALL: [Self; 8] = [
        Self::Syntax,
        Self::Schema,
        Self::Relationships,
        Self::RuleRegistry,
        Self::VolumeSelectors,
        Self::ApplicationIdentities,
        Self::WorkerCapabilities,
        Self::ActionGrants,
    ];

    /// The stable text of the check.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Syntax => "syntax",
            Self::Schema => "schema",
            Self::Relationships => "relationships",
            Self::RuleRegistry => "rule_registry",
            Self::VolumeSelectors => "volume_selectors",
            Self::ApplicationIdentities => "application_identities",
            Self::WorkerCapabilities => "worker_capabilities",
            Self::ActionGrants => "action_grants",
        }
    }

    /// True when the check needs the agent or the supported platform.
    pub const fn is_live(self) -> bool {
        !matches!(self, Self::Syntax | Self::Schema | Self::Relationships)
    }
}

/// The status of one check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CheckStatus {
    /// The check ran on the full document and found no problem.
    Passed,
    /// The check ran and has one or more findings.
    Failed,
    /// The check has no finding in the result, but its cover is not
    /// complete: it ran only on the values that passed an earlier check, or
    /// the list of findings was cut. A problem can be hidden.
    Partial,
    /// The check did not run because an earlier check failed.
    NotRun,
    /// The check did not run because it needs the agent or the supported
    /// platform. This module cannot do it.
    RequiresAgent,
}

impl CheckStatus {
    /// The stable text of the status.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::Partial => "partial",
            Self::NotRun => "not_run",
            Self::RequiresAgent => "requires_agent",
        }
    }
}

/// The status of one check in a report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CheckOutcome {
    /// The check.
    pub check: CheckId,
    /// Its status.
    pub status: CheckStatus,
}

/// The status of each check, in the sequence of [`CheckId::ALL`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct CheckReport {
    outcomes: Vec<CheckOutcome>,
}

impl CheckReport {
    /// Makes the report from the findings of the portable checks.
    ///
    /// `document_parsed` is false when the syntax check stopped the
    /// validation. `schema_complete` is false when the schema check stopped
    /// before it read each table.
    pub(super) fn from_findings(
        findings: &[Finding],
        document_parsed: bool,
        schema_complete: bool,
    ) -> Self {
        let failed = |check: CheckId| {
            findings
                .iter()
                .any(|finding| finding.code.check() == Some(check))
        };
        // A cut list can hide a finding of the schema or relationship check.
        let cut: bool = findings
            .iter()
            .any(|finding| finding.code == FindingCode::TooManyFindings);
        let outcomes: Vec<CheckOutcome> = CheckId::ALL
            .into_iter()
            .map(|check| {
                let status: CheckStatus = if check.is_live() {
                    CheckStatus::RequiresAgent
                } else if failed(check) {
                    CheckStatus::Failed
                } else if check == CheckId::Syntax {
                    CheckStatus::Passed
                } else if !document_parsed || (check == CheckId::Relationships && !schema_complete)
                {
                    CheckStatus::NotRun
                } else if cut || (check == CheckId::Relationships && failed(CheckId::Schema)) {
                    CheckStatus::Partial
                } else {
                    CheckStatus::Passed
                };
                CheckOutcome { check, status }
            })
            .collect();
        Self { outcomes }
    }

    /// Each check and its status.
    pub fn outcomes(&self) -> &[CheckOutcome] {
        &self.outcomes
    }

    /// The status of one check.
    pub fn status(&self, check: CheckId) -> CheckStatus {
        self.outcomes
            .iter()
            .find(|outcome| outcome.check == check)
            .map_or(CheckStatus::NotRun, |outcome| outcome.status)
    }

    /// The checks that need the agent or the supported platform.
    pub fn requires_agent(&self) -> impl Iterator<Item = CheckId> + '_ {
        self.outcomes
            .iter()
            .filter(|outcome| outcome.status == CheckStatus::RequiresAgent)
            .map(|outcome| outcome.check)
    }
}
