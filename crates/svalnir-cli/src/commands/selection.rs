//! The entry selection of `clean plan` (`docs/INTERFACES.md` section 4).
//!
//! The user names each entry of a plan in the `trash` or the `permanent`
//! mode with `--entry PATH`. A named entry must be an entry of the saved
//! scan record: the comparison is exact, with no glob and no prefix. With
//! no entry, the command lists the candidates of the scan, makes no plan,
//! and changes nothing. A named entry that a protection covers is refused,
//! and nothing is planned.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::Serialize;
use svalnir_core::action::FileObjectType;
use svalnir_core::file::LosslessPath;
use svalnir_core::id::ScanId;
use svalnir_core::plan::{CleanupEntry, OmissionReason, PlanOutcome};
use svalnir_core::policy::ProtectionFact;
use svalnir_core::quantity::Bytes;

use super::clean::StaleEntry;
use crate::environment::Environment;
use crate::output::{ErrorBody, ErrorFamily, ErrorStage, ExitStatus, NextAction};
use crate::text::{escape, put_line};

/// The exit status of `clean plan` with no entry: the request has no
/// selection, so it is not a plan. The result is a report.
pub(crate) const NO_ENTRY_STATUS: ExitStatus = ExitStatus::Usage;

const CANDIDATES_NOTE: &str = "This command made no plan and changed nothing. Name each entry to clean with `--entry PATH`, as the path of the candidate. The plan builder then applies the protections and the `[protections]` table to each named entry.";

/// The location of `path`: its directory with each symbolic link resolved,
/// and its name. The hard protection and the `[protections]` list compare
/// this form as well as the path text, so the selection does also. `None` for a path with no name or whose directory does not
/// resolve.
fn location(path: &Path) -> Option<PathBuf> {
    let name = path.file_name()?;
    let directory: &Path = path.parent()?;
    std::fs::canonicalize(directory)
        .ok()
        .map(|directory| directory.join(name))
}

/// The recorded entries of the scan that the arguments name, as the paths
/// of the scan record.
///
/// # Errors
///
/// Returns `entry_not_in_scan` when an argument is not the path of an
/// entry of the scan record, and the error of a relative argument when the
/// invocation directory is not known.
pub(crate) fn named_entries(
    recorded: &[&LosslessPath],
    named: &[PathBuf],
    environment: &Environment,
) -> Result<BTreeSet<LosslessPath>, ErrorBody> {
    let mut selected: BTreeSet<LosslessPath> = BTreeSet::new();
    for argument in named {
        let path: PathBuf = environment.resolve(argument, &["entry"])?;
        let text: Option<LosslessPath> = LosslessPath::from_path(&path).ok();
        let wanted: Option<PathBuf> = location(&path);
        let found: Option<&LosslessPath> = recorded.iter().copied().find(|entry| {
            text.as_ref() == Some(*entry)
                || wanted
                    .as_ref()
                    .is_some_and(|wanted| location(&entry.to_path_buf()).as_ref() == Some(wanted))
        });
        match found {
            Some(entry) => {
                selected.insert(entry.clone());
            }
            None => {
                return Err(ErrorBody::new(
                    "entry_not_in_scan",
                    ErrorFamily::Request,
                    ErrorStage::Arguments,
                    "a path of `--entry` is not an entry of the saved scan record; give the exact path of a candidate that `svalnir clean plan --scan SCAN_ID` lists; the command made no plan",
                )
                .with_fields(&["entry"]));
            }
        }
    }
    Ok(selected)
}

/// The error of `--entry` in the `evict` mode, whose candidates come from
/// the reviewed rule.
pub(crate) fn entry_not_accepted() -> ErrorBody {
    ErrorBody::new(
        "entry_not_accepted",
        ErrorFamily::Request,
        ErrorStage::Arguments,
        "the `evict` mode takes its candidates from the reviewed rule and accepts no `--entry`; the command made no plan",
    )
    .with_fields(&["entry", "mode"])
}

/// Refuses a plan in which a protection covers a named entry. Nothing is
/// recorded before this check.
///
/// # Errors
///
/// Returns `target_protected` when a hard protection or a path of
/// `[protections].excluded_paths` covers a named entry, and
/// `target_protection_unknown` when the protection of a named entry is not
/// known.
pub(crate) fn refuse_protected(outcome: &PlanOutcome) -> Result<(), ErrorBody> {
    let reasons = || {
        outcome
            .preview
            .omitted
            .iter()
            .flat_map(|omission| omission.reasons.iter())
    };
    if reasons().any(|reason| *reason == OmissionReason::HardProtected) {
        return Err(ErrorBody::new(
            "target_protected",
            ErrorFamily::Eligibility,
            ErrorStage::Admission,
            "a hard protection covers a named entry: storage of the operating system, swap storage, the state directory of Svalnir, or the home directory or a directory that contains it; no configuration changes it; the command made no plan",
        )
        .with_fields(&["entry"]));
    }
    if reasons().any(|reason| *reason == OmissionReason::ExcludedPath) {
        return Err(ErrorBody::new(
            "target_protected",
            ErrorFamily::Eligibility,
            ErrorStage::Admission,
            "a path of `[protections].excluded_paths` is a named entry, contains it, or is inside it; by default the list has the personal folders of the home directory; to permit a manual cleanup there, give `excluded_paths` without that folder in the configuration and activate it with `svalnir config apply`; the command made no plan",
        )
        .with_fields(&["entry"]));
    }
    let unknown = |reason: &OmissionReason| {
        matches!(
            reason,
            OmissionReason::ProtectionUnknown | OmissionReason::HomeDirectoryUnknown
        )
    };
    if reasons().any(unknown) {
        return Err(ErrorBody::new(
            "target_protection_unknown",
            ErrorFamily::Evidence,
            ErrorStage::Admission,
            "the protection of a named entry is not known: the entry or its directory does not resolve, or the home directory is not usable; the command made no plan",
        )
        .with_fields(&["entry"])
        .with_next_action(NextAction::RefreshObservation));
    }
    Ok(())
}

/// One candidate of the scan record.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct CandidateView {
    pub(crate) path: LosslessPath,
    pub(crate) object_type: FileObjectType,
    pub(crate) logical_bytes: Option<Bytes>,
    pub(crate) allocated_bytes: Option<Bytes>,
    /// `protected`, `not_protected`, or `unknown`: the hard protection
    /// only. The `[protections]` table applies when the entry is named.
    pub(crate) hard_protection: &'static str,
}

impl CandidateView {
    pub(crate) fn of(entry: &CleanupEntry) -> Self {
        Self {
            path: entry.path.clone(),
            object_type: entry.object_type.clone(),
            logical_bytes: entry.estimate.logical_bytes,
            allocated_bytes: entry.estimate.allocated_bytes,
            hard_protection: match entry.hard_protection {
                ProtectionFact::Protected => "protected",
                ProtectionFact::NotProtected => "not_protected",
                ProtectionFact::Unknown => "unknown",
            },
        }
    }
}

/// The result of `clean plan` in the `trash` or the `permanent` mode with
/// no entry: the candidates for review, and no plan.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct CandidatesView {
    pub(crate) scan_id: ScanId,
    /// `trash` or `permanent`.
    pub(crate) mode: &'static str,
    /// `entries_required`: the plan needs `--entry`.
    pub(crate) selection: &'static str,
    pub(crate) candidates: Vec<CandidateView>,
    /// The entries of the scan record that are not candidates now.
    pub(crate) stale_entries: Vec<StaleEntry>,
    pub(crate) note: &'static str,
}

impl CandidatesView {
    pub(crate) fn new(
        scan_id: ScanId,
        mode: &'static str,
        candidates: &[CleanupEntry],
        stale_entries: Vec<StaleEntry>,
    ) -> Self {
        Self {
            scan_id,
            mode,
            selection: "entries_required",
            candidates: candidates.iter().map(CandidateView::of).collect(),
            stale_entries,
            note: CANDIDATES_NOTE,
        }
    }

    pub(crate) fn render(&self) -> String {
        let mut out = String::new();
        put_line!(
            out,
            "Candidates of scan {} ({} entries); no plan was made:",
            self.scan_id,
            self.candidates.len()
        );
        for candidate in &self.candidates {
            let size: String = candidate
                .allocated_bytes
                .map_or_else(|| "unknown".to_owned(), |bytes| bytes.get().to_string());
            put_line!(
                out,
                "  {}  {} bytes allocated  {}  hard protection: {}",
                candidate.object_type.as_str(),
                size,
                candidate.path.display_label(),
                candidate.hard_protection
            );
        }
        for entry in &self.stale_entries {
            put_line!(
                out,
                "  not a candidate now: {}  {}",
                entry.reason,
                entry.path.display_label()
            );
        }
        put_line!(out, "\n{}", escape(self.note));
        out
    }
}
