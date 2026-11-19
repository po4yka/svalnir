//! `clean plan`, `clean show`, and `clean apply`.
//!
//! `clean plan` and `clean show` change no file of the user: they read a
//! saved scan, the current identity of each recorded entry, and the
//! journal, and they write only the sealed plan and the plan document of
//! this client. `clean apply` hands the plan to the coordinator
//! ([`super::apply`]).
//!
//! The candidates of a plan in the `trash` or the `permanent` mode are the
//! entries that the saved scan record names: its largest files and its
//! largest directories below the scan root. The user names each entry of
//! the plan ([`super::selection`]); with no entry, the command lists the
//! candidates and makes no plan. The plan builder leaves out an
//! overlapping entry and states the reason, and the command refuses a
//! named entry that a protection covers.

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use serde::Serialize;
use svalnir_agent::journal::OperationJournal;
use svalnir_agent::platform::volume;
use svalnir_agent::protection::ProtectedLocations;
use svalnir_agent::rules::root_id_of;
use svalnir_agent::scan::ScanResult;
use svalnir_core::action::{FileObjectType, Plan, TargetBinding, WorkCharge};
use svalnir_core::authority::AuthorityBinding;
use svalnir_core::file::{DeviceNumber, FileObjectEvidence, InodeNumber, LosslessPath};
use svalnir_core::id::{OperationId, PlanId, RootId, ScanId, StepId, TargetId};
use svalnir_core::plan::{
    CleanupEntry, CleanupLimits, CleanupRequest, ModeSelection, PlanBuildError, PlanContext,
    PlanExplanation, PlanMode, PlanOutcome, PlanPreview, SelectionPreset, SizeEstimate,
    TargetPreview, build_cleanup_plan, explain, manual_plan_lifetime, mode_of,
};
use svalnir_core::policy::ProtectionFact;
use svalnir_core::process::Uid;
use svalnir_core::quantity::{Bytes, EntryCount, Nanoseconds};
use svalnir_core::volume::VolumeIdentity;

use super::apply::{self, ApplyFlow};
use super::plan_store::{self, PlanDocument, RootRecord};
use super::session::{self, ActiveConfig, Now, journal_error};
use super::{CommandFailure, Invocation};
use super::{plan_view, selection};
use crate::cli::{CleanApplyArgs, CleanMode, CleanPlanArgs, PlanRef};
use crate::environment::Environment;
use crate::host::Host;
use crate::output::{ErrorBody, ErrorFamily, ErrorStage, ExitStatus, Kind, NextAction};
use crate::text::{escape, put_line};

/// The work ceiling of one manual cleanup plan. A manual plan is bounded
/// by its selection; these values only keep the arithmetic in range.
const PLAN_WORK_BYTES: u64 = 1 << 50;
const PLAN_WORK_ITEMS: u64 = 4_000_000;

/// The work ceiling of one batch of a manual cleanup plan.
const BATCH_WORK_ITEMS: u64 = 100_000;

/// The time that the execution of a manual cleanup plan can use.
pub(crate) const EXECUTION_DEADLINE: Nanoseconds = Nanoseconds::new(30 * 60 * 1_000_000_000);

/// The time in which the executor verifies the effect of one step.
pub(crate) const VERIFICATION_WINDOW: Nanoseconds = Nanoseconds::new(5 * 1_000_000_000);

pub(crate) const PLAN_NOTE: &str = "This command changed no file. The plan gives no authority: apply it with `svalnir clean apply --plan PLAN_ID`, which asks for the approval of this plan and checks each target again.";

pub(crate) const EMPTY_PLAN_NOTE: &str =
    "No entry is in the plan, so there is no plan to apply. This command changed no file.";

/// An entry of the scan record that is not a candidate now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct StaleEntry {
    pub(crate) path: LosslessPath,
    /// `absent`, `changed_since_scan`, `outside_scan_root`,
    /// `type_not_supported`, or `not_readable`.
    pub(crate) reason: &'static str,
}

/// The result of `clean plan` and `clean show`.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct PlanView {
    /// The scan that supplied the candidates.
    pub(crate) scan_id: Option<ScanId>,
    /// The plan, its consequence, its targets, and the entries that were
    /// left out.
    pub(crate) explanation: PlanExplanation,
    /// The entries of the scan record that are not candidates now.
    pub(crate) stale_entries: Vec<StaleEntry>,
    /// The operation of the plan, when it was applied.
    pub(crate) operation_id: Option<OperationId>,
    /// The cleanup roots of the plan, from the root path that the sealed
    /// plan binds for each file target: the executor changes no entry that
    /// is not below one of them. Empty when the plan has no file target.
    pub(crate) cleanup_roots: Vec<LosslessPath>,
    /// False when this client has no usable plan document: the estimates
    /// and the entries that were left out are then not known. The paths
    /// are those of the sealed plan.
    pub(crate) has_plan_document: bool,
    /// `used`, `absent`, `not_readable`, or `disagrees_with_plan`.
    pub(crate) plan_document: &'static str,
    /// The rule discovery behind the plan, for a plan of the `evict` mode
    /// that this invocation made. A plan of a scan has none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) discovery: Option<super::evict::DiscoveryView>,
    pub(crate) note: &'static str,
}

impl PlanView {
    pub(crate) fn render(&self) -> String {
        let mut out = String::new();
        plan_view::render(&self.explanation, &self.cleanup_roots, &mut out);
        if !self.stale_entries.is_empty() {
            put_line!(
                out,
                "\nNot candidates now ({} entries of the scan record):",
                self.stale_entries.len()
            );
            for entry in self.stale_entries.iter().take(plan_view::TEXT_LIST_LIMIT) {
                put_line!(out, "  {}  {}", entry.reason, entry.path.display_label());
            }
            if self.stale_entries.len() > plan_view::TEXT_LIST_LIMIT {
                out.push_str("  ...\n");
            }
        }
        if let Some(discovery) = &self.discovery {
            discovery.render(&mut out);
        }
        if let Some(operation_id) = &self.operation_id {
            put_line!(out, "\nApplied: operation {operation_id}");
        }
        if !self.has_plan_document {
            out.push_str(match self.plan_document {
                "not_readable" => {
                    "\nThe plan document of this client cannot be read, so the estimates are not known.\n"
                }
                "disagrees_with_plan" => {
                    "\nThe plan document of this client does not agree with the stored plan and is not used, so the estimates are not known.\n"
                }
                _ => {
                    "\nThis client has no plan document for the plan, so the estimates are not known.\n"
                }
            });
        }
        put_line!(out, "\n{}", escape(self.note));
        out
    }
}

pub(crate) fn plan_error(error: &PlanBuildError) -> ErrorBody {
    let code: &'static str = match error {
        PlanBuildError::TooManyEntries { .. } => "selection_too_large",
        PlanBuildError::Rule(_) => "rule_mode_not_validated",
        PlanBuildError::UnsupportedExecutor => "helper_not_available",
        PlanBuildError::Authority | PlanBuildError::Principal => "plan_authority_not_usable",
        PlanBuildError::Lifetime | PlanBuildError::Limits => "plan_limits_not_usable",
        _ => "plan_not_buildable",
    };
    ErrorBody::new(
        code,
        error.family(),
        ErrorStage::Admission,
        format!("the plan cannot be built: {error}; the command made no change"),
    )
}

/// The device and inode of a file, when the device number fits.
fn object_of(metadata: &std::fs::Metadata) -> Option<FileObjectEvidence> {
    Some(FileObjectEvidence {
        device: DeviceNumber::new(i32::try_from(metadata.dev()).ok()?),
        inode: InodeNumber::new(metadata.ino()),
    })
}

fn scan_stale(detail: &str) -> ErrorBody {
    ErrorBody::new(
        "scan_stale",
        ErrorFamily::Evidence,
        ErrorStage::Collection,
        format!("the saved scan does not describe the current state: {detail}; scan again; the command made no change"),
    )
    .with_fields(&["scan"])
    .with_next_action(NextAction::RefreshObservation)
}

/// Refuses the root path `/`. A root path with no component is not an
/// approved root of the plan rule and of the executor, so a plan under it
/// could not be applied.
fn refuse_root_without_component(path: &Path) -> Result<(), ErrorBody> {
    if path
        .components()
        .all(|part| matches!(part, std::path::Component::RootDir))
    {
        return Err(ErrorBody::new(
            "plan_not_buildable",
            ErrorFamily::Request,
            ErrorStage::Admission,
            "the path `/` cannot be a cleanup root; scan a directory below it and clean that scan; the command made no change",
        )
        .with_fields(&["scan"]));
    }
    Ok(())
}

/// The cleanup root of a scan: the scan root, with its current identity
/// and its volume. The root must be the directory that the scan read.
fn root_record(scan: &ScanResult) -> Result<RootRecord, ErrorBody> {
    let path: PathBuf = scan.root.to_path_buf();
    refuse_root_without_component(&path)?;
    let metadata = std::fs::symlink_metadata(&path)
        .map_err(|_| scan_stale("the scan root is not readable"))?;
    let object: FileObjectEvidence = object_of(&metadata)
        .filter(|_| metadata.is_dir())
        .ok_or_else(|| scan_stale("the scan root is not a directory"))?;
    if object != scan.volume.root_object {
        return Err(scan_stale(
            "the scan root is a different directory than at the scan",
        ));
    }
    // The volume identity is read again, so a volume that was mounted
    // again has its current mount generation.
    let volume: VolumeIdentity = volume::volume_at(&path)
        .map(|mounted| mounted.identity)
        .map_err(|_| {
            ErrorBody::new(
                "volume_identity_unavailable",
                ErrorFamily::Evidence,
                ErrorStage::Collection,
                "the volume of the scan root has no identity that a plan can bind; the command made no change",
            )
        })?;
    Ok(RootRecord {
        root_id: root_id_of(&scan.root, object, &volume).ok_or_else(session::identity_error)?,
        path: scan.root.clone(),
        object,
        volume,
    })
}

/// Whether a plan document agrees with the sealed plan of the journal:
/// the same digest, the same plan, and cleanup roots that are exactly
/// those that the file targets of the plan bind, each with the path and
/// the object that the sealed plan binds for it and with the identity
/// that its values give.
///
/// A root that no target binds is refused. The document gives the
/// executor no root: the coordinator takes the approved roots from the
/// sealed plan. The check keeps a changed document out of the view and out
/// of the volumes of the capacity observations.
fn document_agrees(document: &PlanDocument, plan: &Plan) -> bool {
    let bindings = || {
        plan.targets
            .iter()
            .filter_map(|target| match &target.binding {
                TargetBinding::File(binding) => Some(binding),
                TargetBinding::Application(_) | TargetBinding::Process(_) => None,
            })
    };
    let bound: BTreeSet<&RootId> = bindings().map(|binding| &binding.root_id).collect();
    let named: BTreeSet<&RootId> = document.roots.iter().map(|root| &root.root_id).collect();
    let bound_roots: Vec<(&RootId, &LosslessPath, &FileObjectEvidence)> = bindings()
        .map(|binding| (&binding.root_id, &binding.root_path, &binding.root_object))
        .collect();
    named == bound
        && roots_agree(&document.roots, &bound_roots)
        && named.len() == document.roots.len()
        && document.roots.iter().all(|root| {
            root_id_of(&root.path, root.object, &root.volume).as_ref() == Some(&root.root_id)
        })
        && &document.digest == plan.digest()
        && document.outcome.plan.as_ref() == Some(plan)
}

/// Whether each root that a sealed plan binds has, in `roots`, a record with
/// the same identity, the same path, and the same object. The sealed plan
/// binds the path and the object of the root of each target, so the root of
/// a document must be that root.
fn roots_agree(
    roots: &[RootRecord],
    bound: &[(&RootId, &LosslessPath, &FileObjectEvidence)],
) -> bool {
    bound.iter().all(|(root_id, path, object)| {
        roots
            .iter()
            .any(|root| &root.root_id == *root_id && &root.path == *path && &root.object == *object)
    })
}

/// The display path of each file target of a stored plan: the path of its
/// cleanup root and its relative entry, which the sealed plan binds. No
/// plan document is necessary, and the path text of a document is not
/// used.
pub(crate) fn bound_paths(plan: &Plan) -> BTreeMap<TargetId, LosslessPath> {
    plan.targets
        .iter()
        .filter_map(|target| match &target.binding {
            TargetBinding::File(binding) => Some((target.target_id.clone(), bound_path(binding)?)),
            TargetBinding::Application(_) | TargetBinding::Process(_) => None,
        })
        .collect()
}

/// The path of a file target: the path of its cleanup root and its
/// relative entry, which the sealed plan binds.
fn bound_path(binding: &svalnir_core::action::FileBinding) -> Option<LosslessPath> {
    let mut bytes: Vec<u8> = binding.root_path.as_bytes().to_vec();
    if bytes.last() != Some(&b'/') {
        bytes.push(b'/');
    }
    bytes.extend_from_slice(binding.relative_entry.as_bytes());
    LosslessPath::from_bytes(bytes).ok()
}

/// The hard protection of a file entry, from the catalog of protected
/// file locations: storage of the operating system, swap storage, the
/// state directory of Svalnir, and the home directory with each directory
/// that contains it ([`ProtectedLocations`]). The coordinator applies the
/// same catalog again at admission, the filesystem executor refuses the
/// home directory and its ancestors, and the plan builder applies the
/// `[protections]` table.
///
/// `home` and `state_directory` have no symbolic link, as `canonicalize`
/// gives them. The catalog compares path text.
#[cfg(test)]
fn file_protection(
    path: &Path,
    home: Option<&Path>,
    state_directory: Option<&Path>,
) -> ProtectionFact {
    locations_of(home, state_directory).of_text(path)
}

fn locations_of(home: Option<&Path>, state_directory: Option<&Path>) -> ProtectedLocations {
    ProtectedLocations::from_resolved(
        home.map(Path::to_path_buf),
        state_directory.map(Path::to_path_buf),
    )
}

/// The hard protection of the entry at `path`, for its own location and
/// for its resolved form ([`ProtectedLocations::of_entry`]).
fn entry_protection(
    path: &Path,
    home: Option<&Path>,
    state_directory: Option<&Path>,
) -> ProtectionFact {
    locations_of(home, state_directory).of_entry(path)
}

/// The type of a file object that a plan can bind.
fn object_type_of(metadata: &std::fs::Metadata) -> Option<FileObjectType> {
    let file_type = metadata.file_type();
    if file_type.is_dir() {
        Some(FileObjectType::Directory)
    } else if file_type.is_file() {
        Some(FileObjectType::RegularFile)
    } else if file_type.is_symlink() {
        Some(FileObjectType::SymbolicLink)
    } else {
        None
    }
}

/// The entry relative to the scan root, whose path with a last `/` is
/// `prefix`. `None` for a path that is not below the root.
fn relative_entry(path: &LosslessPath, prefix: &[u8]) -> Option<LosslessPath> {
    path.as_bytes()
        .strip_prefix(prefix)
        .filter(|relative| !relative.is_empty())
        .and_then(|relative| LosslessPath::from_bytes(relative.to_vec()).ok())
}

/// One recorded entry of a scan.
struct Recorded<'a> {
    path: &'a LosslessPath,
    object: FileObjectEvidence,
    logical: Bytes,
    allocated: Bytes,
    /// The number of entries below a directory.
    entries: Option<EntryCount>,
}

struct Selection {
    entries: Vec<CleanupEntry>,
    stale: Vec<StaleEntry>,
}

/// The paths of the entries that the scan record names, in the sequence
/// of [`select`].
fn recorded_paths(scan: &ScanResult) -> impl Iterator<Item = &LosslessPath> {
    scan.largest_directories
        .iter()
        .map(|directory| &directory.path)
        .chain(scan.largest_files.iter().map(|file| &file.path))
}

/// Makes the candidates of a plan from the entries that the scan record
/// names, or only from those of `named`. Each entry is measured again with
/// `lstat`; an entry that is absent or is a different object than at the
/// scan is not a candidate.
fn select(
    scan: &ScanResult,
    root: &RootRecord,
    mode: CleanMode,
    plan_text: &str,
    environment: &Environment,
    named: Option<&BTreeSet<LosslessPath>>,
) -> Result<Selection, ErrorBody> {
    let home: Option<PathBuf> = environment
        .home
        .as_ref()
        .and_then(|home| std::fs::canonicalize(home).ok());
    // A state directory that does not resolve gives no state directory, so
    // an entry that no other rule protects has an unknown protection.
    let state_directory: Option<PathBuf> =
        std::fs::canonicalize(environment.state_directory()?).ok();
    let mut prefix: Vec<u8> = scan.root.as_bytes().to_vec();
    if prefix.last() != Some(&b'/') {
        prefix.push(b'/');
    }
    let recorded = scan
        .largest_directories
        .iter()
        .map(|directory| Recorded {
            path: &directory.path,
            object: directory.object,
            logical: directory.logical_bytes,
            allocated: directory.allocated_bytes,
            entries: Some(directory.entries),
        })
        .chain(scan.largest_files.iter().map(|file| Recorded {
            path: &file.path,
            object: file.object,
            logical: file.logical_bytes,
            allocated: file.allocated_bytes,
            entries: None,
        }));
    let mut selection = Selection {
        entries: Vec::new(),
        stale: Vec::new(),
    };
    for (index, entry) in recorded.enumerate() {
        if named.is_some_and(|named| !named.contains(entry.path)) {
            continue;
        }
        let mut stale = |reason: &'static str| {
            selection.stale.push(StaleEntry {
                path: entry.path.clone(),
                reason,
            });
        };
        // The scan root itself is the cleanup root; it is never a target.
        if entry.path == &scan.root {
            continue;
        }
        let Some(relative) = relative_entry(entry.path, &prefix) else {
            stale("outside_scan_root");
            continue;
        };
        let path: PathBuf = entry.path.to_path_buf();
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                stale("absent");
                continue;
            }
            Err(_) => {
                stale("not_readable");
                continue;
            }
        };
        if object_of(&metadata) != Some(entry.object) {
            stale("changed_since_scan");
            continue;
        }
        let Some(object_type) = object_type_of(&metadata) else {
            stale("type_not_supported");
            continue;
        };
        let work_bytes: Bytes = entry.logical.max(entry.allocated);
        let below: Option<u64> = entry.entries.map(EntryCount::get);
        let items: EntryCount = EntryCount::new(below.map_or(1, |count| count.saturating_add(1)));
        let identity = |kind: char| format!("{plan_text}-{kind}{index:04}");
        selection.entries.push(CleanupEntry {
            target_id: TargetId::new(identity('t')).map_err(|_| session::identity_error())?,
            step_id: StepId::new(identity('s')).map_err(|_| session::identity_error())?,
            path: entry.path.clone(),
            root_id: root.root_id.clone(),
            root_path: root.path.clone(),
            root_object: root.object,
            relative_entry: relative,
            volume_id: root.volume.volume_id.clone(),
            mount_id: root.volume.mount_id.clone(),
            object_type,
            owner: Some(Uid::new(metadata.uid())),
            object: Some(entry.object),
            // The entry was measured again above, so this is the number
            // of names of the object that the plan binds.
            link_count: Some(EntryCount::new(metadata.nlink())),
            charge: Some(WorkCharge::new(work_bytes, items)),
            estimate: SizeEstimate {
                logical_bytes: Some(entry.logical),
                allocated_bytes: Some(entry.allocated),
                // A move to Trash reclaims nothing. For a permanent
                // removal the allocated size is the estimate; shared
                // storage can make the reclaimed size smaller.
                estimated_reclaimable_bytes: (mode != CleanMode::Trash).then_some(entry.allocated),
            },
            hard_protection: entry_protection(&path, home.as_deref(), state_directory.as_deref()),
            resolved_paths: svalnir_agent::protection::resolved_forms(&path),
            rule: None,
        });
    }
    Ok(selection)
}

fn plan_not_found(plan_id: &str) -> ErrorBody {
    ErrorBody::new(
        "plan_not_found",
        ErrorFamily::Evidence,
        ErrorStage::Storage,
        "the journal has no plan with this ID; the command made no change",
    )
    .with_fields(&["plan"])
    .with_plan(plan_id)
    .with_next_action(NextAction::PrepareNewPlan)
}

fn parse_plan_id(text: &str) -> Result<PlanId, ErrorBody> {
    PlanId::new(text)
        .map_err(|_| session::invalid_identifier("invalid_plan_id", "plan ID", &["plan"]))
}

/// The selection of one plan of a scan.
struct ScanSelection<'a> {
    plan_id: &'a PlanId,
    policy_revision: &'a svalnir_core::id::PolicyRevisionId,
    mode: CleanMode,
    entries: &'a [CleanupEntry],
    preset: Option<&'a SelectionPreset>,
}

/// Builds the plan of a selection with the plan builder.
fn build(
    environment: &Environment,
    now: &Now,
    config: &svalnir_core::config::ValidatedConfig,
    selection: &ScanSelection<'_>,
) -> Result<PlanOutcome, ErrorBody> {
    let ScanSelection {
        plan_id,
        policy_revision,
        mode,
        entries,
        preset,
    } = *selection;
    let home: Option<LosslessPath> = environment
        .home
        .as_ref()
        .and_then(|home| std::fs::canonicalize(home).ok())
        .and_then(|home| LosslessPath::from_path(&home).ok());
    let lifetime: Nanoseconds =
        manual_plan_lifetime(config).ok_or_else(|| plan_error(&PlanBuildError::Lifetime))?;
    let context = PlanContext {
        plan_id: plan_id.clone(),
        principal: session::principal(),
        authority: AuthorityBinding {
            policy_revision: policy_revision.clone(),
            action_grants: Vec::new(),
            privilege_grant: None,
        },
        clock: &now.clock,
        created_wall: now.wall,
        lifetime,
        protections: config.protections(),
        home_directory: home.as_ref(),
    };
    let request = CleanupRequest {
        mode: match mode {
            CleanMode::Permanent => ModeSelection::Permanent,
            CleanMode::Trash | CleanMode::Evict => ModeSelection::Trash,
        },
        entries,
        preset,
        limits: CleanupLimits {
            plan: WorkCharge::new(
                Bytes::new(PLAN_WORK_BYTES),
                EntryCount::new(PLAN_WORK_ITEMS),
            ),
            batch: WorkCharge::new(
                Bytes::new(PLAN_WORK_BYTES),
                EntryCount::new(BATCH_WORK_ITEMS),
            ),
            execution_deadline: EXECUTION_DEADLINE,
            verification_window: VERIFICATION_WINDOW,
        },
    };
    build_cleanup_plan(&context, &request).map_err(|error| plan_error(&error))
}

/// The candidates of a scan for review, with no selection: no plan, no
/// plan document, and no journal change.
fn list_candidates(
    scan: &ScanResult,
    mode: CleanMode,
    invocation: &mut Invocation<'_>,
) -> Result<ExitStatus, CommandFailure> {
    let root: RootRecord = root_record(scan)?;
    let listed: Selection = select(scan, &root, mode, "candidate", invocation.environment, None)?;
    let view = selection::CandidatesView::new(
        scan.scan_id.clone(),
        if mode == CleanMode::Permanent {
            "permanent"
        } else {
            "trash"
        },
        &listed.entries,
        listed.stale,
    );
    invocation.emit(Kind::Report, &view, selection::CandidatesView::render)?;
    Ok(selection::NO_ENTRY_STATUS)
}

pub(crate) fn plan(
    arguments: &CleanPlanArgs,
    invocation: &mut Invocation<'_>,
) -> Result<ExitStatus, CommandFailure> {
    if arguments.mode == CleanMode::Evict {
        if !arguments.entries.is_empty() {
            return Err(selection::entry_not_accepted().into());
        }
        return super::evict::plan(arguments, invocation);
    }
    // A preset only filters: the plan builder leaves out each entry that
    // the preset does not include. An entry of a scan has no rule, so the
    // preset of this build includes none of them.
    let preset: Option<SelectionPreset> = arguments
        .profile
        .as_deref()
        .map(super::evict::preset)
        .transpose()?;
    let Some(scan_text) = arguments.scan.as_deref() else {
        return Err(ErrorBody::new(
            "scan_required",
            ErrorFamily::Request,
            ErrorStage::Arguments,
            "the `trash` and `permanent` modes need `--scan SCAN_ID`: their candidates are the entries of a saved scan; the command made no change",
        )
        .with_fields(&["scan"])
        .into());
    };
    let environment: &Environment = invocation.environment;
    let scan: ScanResult = super::scan::load_scan(scan_text, environment)?;
    if arguments.entries.is_empty() {
        return list_candidates(&scan, arguments.mode, invocation);
    }
    let named: BTreeSet<LosslessPath> = selection::named_entries(
        // The scan root is the cleanup root and never a target.
        &recorded_paths(&scan)
            .filter(|path| *path != &scan.root)
            .collect::<Vec<&LosslessPath>>(),
        &arguments.entries,
        environment,
    )?;
    let host: Host = Host::open()?;
    let now: Now = Now::read(&host)?;
    let mut journal: OperationJournal = session::open_journal(environment)?;
    let authority = session::read_authority(&journal)?;
    let ActiveConfig { active, config } = session::active_config(&journal, &authority.state)?;

    let plan_text: String = session::new_id("plan");
    let plan_id: PlanId = PlanId::new(plan_text.clone()).map_err(|_| session::identity_error())?;
    let root: RootRecord = root_record(&scan)?;
    let chosen: Selection = select(
        &scan,
        &root,
        arguments.mode,
        &plan_text,
        environment,
        Some(&named),
    )?;
    let outcome: PlanOutcome = build(
        environment,
        &now,
        &config,
        &ScanSelection {
            plan_id: &plan_id,
            policy_revision: &active.revision.revision_id,
            mode: arguments.mode,
            entries: &chosen.entries,
            preset: preset.as_ref(),
        },
    )?;
    selection::refuse_protected(&outcome)?;
    let has_plan: bool = outcome.plan.is_some();
    if let Some(plan) = &outcome.plan {
        // The journal has the sealed plan before the document names it.
        journal
            .try_record_plan(plan)
            .map_err(|error| journal_error(&error))?;
        let mut document =
            PlanDocument::new(plan_id.clone(), plan.digest().clone(), outcome.clone());
        document.roots = vec![root.clone()];
        document.scan_id = Some(scan.scan_id.clone());
        plan_store::save_plan(environment, &document)?;
        plan_store::prune(environment);
    }
    let view = PlanView {
        scan_id: Some(scan.scan_id),
        explanation: explain(&outcome, &now.clock),
        stale_entries: chosen.stale,
        operation_id: None,
        cleanup_roots: if has_plan {
            vec![root.path]
        } else {
            Vec::new()
        },
        has_plan_document: has_plan,
        plan_document: if has_plan { "used" } else { "absent" },
        discovery: None,
        note: if has_plan { PLAN_NOTE } else { EMPTY_PLAN_NOTE },
    };
    invocation.emit(Kind::Report, &view, PlanView::render)?;
    Ok(ExitStatus::Success)
}

/// What this client has as the plan document of a stored plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DocumentState {
    /// The document agrees with the stored plan and is used.
    Used,
    /// There is no document.
    Absent,
    /// The document cannot be read or decoded.
    NotReadable,
    /// The document does not agree with the stored plan.
    Disagrees,
}

impl DocumentState {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Used => "used",
            Self::Absent => "absent",
            Self::NotReadable => "not_readable",
            Self::Disagrees => "disagrees_with_plan",
        }
    }
}

/// The stored plan and the plan document of this client. A document that
/// does not agree with the stored plan is not used.
pub(crate) struct StoredPlan {
    pub(crate) plan: Plan,
    pub(crate) document: Option<PlanDocument>,
    pub(crate) document_state: DocumentState,
}

impl StoredPlan {
    /// The cleanup roots of the plan: the root path that the sealed plan
    /// binds for each file target, one time for each root identity. The
    /// digest that the user approves covers these values, so the list
    /// needs no plan document.
    pub(crate) fn cleanup_roots(&self) -> Vec<LosslessPath> {
        let roots: BTreeMap<&RootId, &LosslessPath> = self
            .plan
            .targets
            .iter()
            .filter_map(|target| match &target.binding {
                TargetBinding::File(binding) => Some((&binding.root_id, &binding.root_path)),
                TargetBinding::Application(_) | TargetBinding::Process(_) => None,
            })
            .collect();
        roots.into_values().cloned().collect()
    }
}

/// Reads the stored plan and the plan document of this client.
///
/// A document that cannot be read is not an error of this function: the
/// journal has the plan and its operation, and a result that needs no
/// document is not lost. [`StoredPlan::document_state`] has the reason.
pub(crate) fn load_plan(
    journal: Option<&OperationJournal>,
    environment: &Environment,
    plan_id: &PlanId,
) -> Result<StoredPlan, ErrorBody> {
    let plan: Plan = journal
        .ok_or_else(|| plan_not_found(plan_id.as_str()))?
        .try_plan(plan_id)
        .map_err(|error| journal_error(&error))?
        .ok_or_else(|| plan_not_found(plan_id.as_str()))?;
    let (document, document_state): (Option<PlanDocument>, DocumentState) =
        match plan_store::load_plan(environment, plan_id) {
            Ok(Some(document)) if document_agrees(&document, &plan) => {
                (Some(document), DocumentState::Used)
            }
            Ok(Some(_)) => (None, DocumentState::Disagrees),
            Ok(None) => (None, DocumentState::Absent),
            // A document of a different version is refused, as a stored
            // plan of a different version is: there is no migration.
            Err(error) if &*error.code == plan_store::PLAN_VERSION_NOT_SUPPORTED => {
                return Err(error.with_plan(plan_id.as_str()));
            }
            Err(_) => (None, DocumentState::NotReadable),
        };
    Ok(StoredPlan {
        plan,
        document,
        document_state,
    })
}

/// The stored plan of an operation for a report, when the journal has it.
/// A plan or a document that cannot be read gives a report with no
/// display path and no measurement.
pub(crate) fn load_for_report(
    journal: &OperationJournal,
    environment: &Environment,
    plan_id: &PlanId,
) -> Option<StoredPlan> {
    load_plan(Some(journal), environment, plan_id).ok()
}

/// The builder result of a stored plan: that of the plan document, or a
/// result with the plan and no display data.
pub(crate) fn outcome_of(stored: &StoredPlan) -> Result<PlanOutcome, ErrorBody> {
    if let Some(document) = &stored.document {
        // The display path of a file target comes from the values that
        // the sealed plan binds, not from the text of the document.
        let mut outcome: PlanOutcome = document.outcome.clone();
        for preview in &mut outcome.preview.targets {
            if let Some(TargetBinding::File(binding)) = stored
                .plan
                .target(&preview.target_id)
                .map(|target| &target.binding)
            {
                preview.path = bound_path(binding);
            }
        }
        return Ok(outcome);
    }
    let mode: PlanMode = mode_of(&stored.plan).ok_or_else(|| {
        ErrorBody::new(
            "plan_not_executable",
            ErrorFamily::Request,
            ErrorStage::Storage,
            "the stored plan has a mode that this build does not recognize",
        )
    })?;
    Ok(PlanOutcome {
        mode,
        preview: PlanPreview {
            targets: stored
                .plan
                .targets
                .iter()
                .map(|target| TargetPreview {
                    target_id: target.target_id.clone(),
                    // The path of a file target is in the sealed plan.
                    path: match &target.binding {
                        TargetBinding::File(binding) => bound_path(binding),
                        TargetBinding::Application(_) | TargetBinding::Process(_) => None,
                    },
                    estimate: SizeEstimate::default(),
                })
                .collect(),
            batches: Vec::new(),
            omitted: Vec::new(),
            preset: None,
        },
        plan: Some(stored.plan.clone()),
    })
}

pub(crate) fn show(
    arguments: &PlanRef,
    invocation: &mut Invocation<'_>,
) -> Result<ExitStatus, CommandFailure> {
    let plan_id: PlanId = parse_plan_id(&arguments.plan)?;
    let environment: &Environment = invocation.environment;
    let journal: Option<OperationJournal> = session::open_existing_journal(environment)?;
    let stored: StoredPlan = load_plan(journal.as_ref(), environment, &plan_id)?;
    let host: Host = Host::open()?;
    let now: Now = Now::read(&host)?;
    let operation_id: Option<OperationId> = match &journal {
        Some(journal) => apply::existing_operation(journal, &plan_id)?
            .map(|operation| operation.operation_id().clone()),
        None => None,
    };
    let view = PlanView {
        scan_id: stored
            .document
            .as_ref()
            .and_then(|document| document.scan_id.clone()),
        explanation: explain(&outcome_of(&stored)?, &now.clock),
        stale_entries: Vec::new(),
        operation_id,
        cleanup_roots: stored.cleanup_roots(),
        has_plan_document: stored.document.is_some(),
        plan_document: stored.document_state.as_str(),
        discovery: None,
        note: "This command changed nothing.",
    };
    invocation.emit(Kind::Report, &view, PlanView::render)?;
    Ok(ExitStatus::Success)
}

pub(crate) fn apply(
    arguments: &CleanApplyArgs,
    invocation: &mut Invocation<'_>,
) -> Result<ExitStatus, CommandFailure> {
    let plan_id: PlanId = parse_plan_id(&arguments.plan.plan)?;
    let environment: &Environment = invocation.environment;
    let journal: Option<OperationJournal> = session::open_existing_journal(environment)?;
    let stored: StoredPlan = load_plan(journal.as_ref(), environment, &plan_id)?;
    let is_cleanup: bool = matches!(mode_of(&stored.plan), Some(PlanMode::Cleanup(_)));
    if !is_cleanup {
        return Err(ErrorBody::new(
            "not_a_cleanup_plan",
            ErrorFamily::Request,
            ErrorStage::Arguments,
            "the plan is not a cleanup plan; a stop plan is applied by `svalnir processes stop`; the command made no change",
        )
        .with_fields(&["plan"])
        .with_plan(plan_id.as_str())
        .into());
    }
    let authority = match &journal {
        Some(journal) => session::read_authority(journal)?.state,
        None => return Err(plan_not_found(plan_id.as_str()).into()),
    };
    // The sealed plan binds the cleanup root of each file target, so a
    // client with no plan document can apply the plan: the question then
    // has each path and no estimate. A document that is present and that
    // cannot be read, or that does not agree with the stored plan, is a
    // sign of a changed state directory: the plan is not applied. A plan
    // that was applied before is reported in each case.
    let applied_before: bool = match &journal {
        Some(journal) => apply::existing_operation(journal, &plan_id)?.is_some(),
        None => false,
    };
    let unusable: Option<&'static str> = match stored.document_state {
        DocumentState::NotReadable => Some(
            "the plan document of this client cannot be read; prepare a new plan; the command made no change",
        ),
        DocumentState::Disagrees => Some(
            "the plan document of this client does not agree with the stored plan; prepare a new plan; the command made no change",
        ),
        DocumentState::Absent | DocumentState::Used => None,
    };
    if let Some(message) = unusable
        && !applied_before
    {
        return Err(ErrorBody::new(
            "plan_document_not_usable",
            ErrorFamily::Evidence,
            ErrorStage::Storage,
            message,
        )
        .with_plan(plan_id.as_str())
        .with_next_action(NextAction::PrepareNewPlan)
        .into());
    }
    drop(journal);
    // The question has each target and the cleanup roots. A clock that
    // cannot be read gives no question with a part of the scope.
    let now: Now = Now::read(&Host::open()?)?;
    let mut summary: String = String::new();
    plan_view::render_question(
        &explain(&outcome_of(&stored)?, &now.clock),
        &stored.cleanup_roots(),
        &mut summary,
    );
    apply::run(
        ApplyFlow {
            plan: &stored.plan,
            document: stored.document.clone(),
            authority,
            control_plane: None,
            no_wait: arguments.apply.no_wait,
            yes: arguments.apply.yes,
            summary,
            what: "the apply of the plan",
        },
        invocation,
    )
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use svalnir_core::policy::ProtectionFact;

    use svalnir_core::file::{DeviceNumber, FileObjectEvidence, InodeNumber, LosslessPath};
    use svalnir_core::id::RootId;

    use super::{
        entry_protection, file_protection, refuse_root_without_component, root_id_of, roots_agree,
    };
    use crate::commands::plan_store::RootRecord;
    use crate::test_support::{TempDirectory, volume_capacity};

    #[test]
    fn a_document_root_must_have_the_path_and_the_object_that_the_plan_binds() {
        let path = |text: &str| LosslessPath::from_bytes(text).unwrap();
        let object = |inode: u64| FileObjectEvidence {
            device: DeviceNumber::new(16_777_233),
            inode: InodeNumber::new(inode),
        };
        let (volume, _capacity, _foundation) = volume_capacity();
        let (a, b) = (path("/work/a"), path("/work/b"));
        let root_id: RootId = root_id_of(&a, object(2), &volume).unwrap();
        let roots = [RootRecord {
            root_id: root_id.clone(),
            path: a.clone(),
            object: object(2),
            volume,
        }];
        let (same, other) = (object(2), object(3));
        assert!(roots_agree(&roots, &[(&root_id, &a, &same)]));
        // The identity is the one of the root in both cases, so only the
        // comparison of the path and of the object refuses them.
        assert!(!roots_agree(&roots, &[(&root_id, &b, &same)]));
        assert!(!roots_agree(&roots, &[(&root_id, &a, &other)]));
    }

    #[test]
    fn a_link_entry_has_the_protection_of_its_own_location_and_of_its_target() {
        let directory = TempDirectory::new();
        let base = std::fs::canonicalize(directory.path()).unwrap();
        let (state, outside, work, home) = (
            base.join("state"),
            base.join("outside"),
            base.join("work"),
            base.join("home"),
        );
        for path in [&state, &outside, &work, &home] {
            std::fs::create_dir(path).unwrap();
        }
        std::fs::write(outside.join("file"), b"x").unwrap();
        std::fs::write(state.join("file"), b"x").unwrap();
        std::os::unix::fs::symlink(outside.join("file"), state.join("link")).unwrap();
        std::os::unix::fs::symlink(state.join("file"), work.join("link")).unwrap();
        std::os::unix::fs::symlink(outside.join("file"), work.join("out")).unwrap();
        std::os::unix::fs::symlink(base.join("absent"), work.join("dangling")).unwrap();
        // The configured path of the state directory is a link to it.
        std::os::unix::fs::symlink(&state, base.join("state-link")).unwrap();
        let protection =
            |path: &Path| entry_protection(path, Some(home.as_path()), Some(state.as_path()));
        // A link in the state directory is protected, also when it points out.
        assert_eq!(protection(&state.join("link")), ProtectionFact::Protected);
        // A link whose target is in the state directory, and a link at the
        // configured path of the state directory, are protected: the
        // removal of the second one disconnects the journal.
        assert_eq!(protection(&work.join("link")), ProtectionFact::Protected);
        assert_eq!(
            protection(&base.join("state-link")),
            ProtectionFact::Protected
        );
        // A link to the home directory is protected in the same way.
        std::os::unix::fs::symlink(&home, base.join("home-link")).unwrap();
        assert_eq!(
            protection(&base.join("home-link")),
            ProtectionFact::Protected
        );
        // A link with no protected form is not protected, and a link with
        // no target has an unknown protection.
        assert_eq!(protection(&work.join("out")), ProtectionFact::NotProtected);
        assert_eq!(protection(&work.join("dangling")), ProtectionFact::Unknown);
        assert_eq!(
            protection(&outside.join("file")),
            ProtectionFact::NotProtected
        );
    }

    #[test]
    fn an_entry_with_no_resolved_state_directory_has_an_unknown_protection() {
        let directory = TempDirectory::new();
        let base = std::fs::canonicalize(directory.path()).unwrap();
        let home = base.join("home");
        std::fs::create_dir(&home).unwrap();
        std::fs::write(base.join("file"), b"x").unwrap();
        assert_eq!(
            entry_protection(&base.join("file"), Some(home.as_path()), None),
            ProtectionFact::Unknown
        );
        // An entry whose directory does not resolve is unknown too.
        assert_eq!(
            entry_protection(&base.join("absent/file"), Some(home.as_path()), Some(&home)),
            ProtectionFact::Unknown
        );
    }

    #[test]
    fn the_path_of_the_file_system_root_is_refused_as_a_cleanup_root() {
        let refused = refuse_root_without_component(Path::new("/")).unwrap_err();
        assert_eq!(&*refused.code, "plan_not_buildable");
        assert!(refused.message.contains("scan a directory below it"));
        refuse_root_without_component(Path::new("/private/tmp")).unwrap();
    }

    #[test]
    fn the_home_directory_its_ancestors_and_the_state_directory_are_protected() {
        let home = Path::new("/Users/test");
        let state = Path::new("/Users/test/Library/Application Support/Svalnir");
        let protection = |path: &str| file_protection(Path::new(path), Some(home), Some(state));
        assert_eq!(protection("/Users/test"), ProtectionFact::Protected);
        assert_eq!(protection("/Users"), ProtectionFact::Protected);
        assert_eq!(
            protection("/Users/test/Library/Application Support/Svalnir/plans"),
            ProtectionFact::Protected
        );
        assert_eq!(protection("/Users/test/Library"), ProtectionFact::Protected);
        assert_eq!(
            protection("/Users/test/project/build"),
            ProtectionFact::NotProtected
        );
        assert_eq!(
            file_protection(Path::new("/tmp/x"), None, Some(state)),
            ProtectionFact::Unknown
        );
        // The catalog of the core crate also has the storage of the
        // operating system and the swap storage.
        assert_eq!(protection("/System/Library"), ProtectionFact::Protected);
        assert_eq!(
            protection("/private/var/vm/swapfile0"),
            ProtectionFact::Protected
        );
        assert_eq!(protection("/private"), ProtectionFact::Protected);
    }
}
