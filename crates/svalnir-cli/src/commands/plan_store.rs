//! The plan documents of this client, in `plans/` of the state directory.
//!
//! The operation journal stores the sealed plan, which is the only record
//! that an approval binds. The plan does not have the display paths, the
//! size estimates, the entries that were left out, or the path of a cleanup
//! root. A plan document keeps those values for `clean show`, for the
//! approved roots of the executor, and for the measurements that only the
//! executing process has. A document gives no authority: the executor
//! compares each root and each entry with the identity evidence of the
//! sealed plan before it acts.

use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use svalnir_core::digest::ContentDigest;
use svalnir_core::file::{FileObjectEvidence, LosslessPath};
use svalnir_core::id::{OperationId, PlanId, ProcessGenerationId, RootId, ScanId};
use svalnir_core::plan::{PlanOutcome, StopKind};
use svalnir_core::quantity::Nanoseconds;
use svalnir_core::volume::VolumeIdentity;

use super::operation_view::Measurements;
use crate::environment::Environment;
use crate::output::{ErrorBody, ErrorFamily, ErrorStage};

/// The version of the document format.
const DOCUMENT_VERSION: u32 = 1;

/// The largest document that this client reads.
const MAX_DOCUMENT_BYTES: u64 = 32 * 1024 * 1024;

/// The age after which a document is removed.
const RETENTION: Duration = Duration::from_hours(7 * 24);

/// The largest number of directory entries that one removal pass reads.
const MAX_PRUNE_ENTRIES: usize = 4096;

/// A cleanup root of a plan, with the identity evidence of the plan time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RootRecord {
    pub(crate) root_id: RootId,
    pub(crate) path: LosslessPath,
    pub(crate) object: FileObjectEvidence,
    pub(crate) volume: VolumeIdentity,
}

/// What this client keeps for one plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PlanDocument {
    pub(crate) schema_version: u32,
    pub(crate) plan_id: PlanId,
    /// The digest of the sealed plan. A document whose digest is not that
    /// of the plan in the journal is not used.
    pub(crate) digest: ContentDigest,
    /// The result of the plan builder: the plan, the display data, and the
    /// entries that were left out.
    pub(crate) outcome: PlanOutcome,
    /// The cleanup roots of a filesystem plan.
    pub(crate) roots: Vec<RootRecord>,
    /// The scan of a cleanup plan.
    pub(crate) scan_id: Option<ScanId>,
    /// The process of a stop plan.
    pub(crate) stop_target: Option<ProcessGenerationId>,
    /// The operation of the plan, after its admission.
    pub(crate) operation_id: Option<OperationId>,
    /// The measurements of the operation, when this client executed it.
    pub(crate) measurements: Option<Measurements>,
}

impl PlanDocument {
    pub(crate) fn new(plan_id: PlanId, digest: ContentDigest, outcome: PlanOutcome) -> Self {
        Self {
            schema_version: DOCUMENT_VERSION,
            plan_id,
            digest,
            outcome,
            roots: Vec::new(),
            scan_id: None,
            stop_target: None,
            operation_id: None,
            measurements: None,
        }
    }
}

/// The record that binds a stop request to its plan, so that a repeated
/// `processes stop` of the same process generation makes no second plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct StopRecord {
    pub(crate) schema_version: u32,
    pub(crate) target: ProcessGenerationId,
    pub(crate) plan_id: PlanId,
    pub(crate) kind: StopKind,
    pub(crate) grace: Option<Nanoseconds>,
    /// The time in which the exit is observed after a request.
    pub(crate) verification_window: Nanoseconds,
}

impl StopRecord {
    pub(crate) fn new(
        target: ProcessGenerationId,
        plan_id: PlanId,
        kind: StopKind,
        grace: Option<Nanoseconds>,
        verification_window: Nanoseconds,
    ) -> Self {
        Self {
            schema_version: DOCUMENT_VERSION,
            target,
            plan_id,
            kind,
            grace,
            verification_window,
        }
    }
}

fn store_error(detail: &str) -> ErrorBody {
    ErrorBody::new(
        "plan_document_unavailable",
        ErrorFamily::Recording,
        ErrorStage::Storage,
        format!("the plan document of this client {detail}"),
    )
}

fn plan_path(environment: &Environment, plan_id: &PlanId) -> Result<PathBuf, ErrorBody> {
    Ok(environment
        .plan_directory()?
        .join(format!("plan-{plan_id}.json")))
}

fn stop_path(
    environment: &Environment,
    target: &ProcessGenerationId,
) -> Result<PathBuf, ErrorBody> {
    Ok(environment
        .plan_directory()?
        .join(format!("stop-{target}.json")))
}

/// Writes a document beside its final name and renames it, so a reader
/// never sees a part of it. The file is readable only by its owner.
fn write_document<T: Serialize>(
    environment: &Environment,
    path: &Path,
    document: &T,
) -> Result<(), ErrorBody> {
    environment.create_state_directory()?;
    plan_directory(environment)?;
    write_file(path, document)
}

/// Makes the directory of the documents when it does not exist.
fn plan_directory(environment: &Environment) -> Result<PathBuf, ErrorBody> {
    let directory: PathBuf = environment.plan_directory()?;
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder
        .create(&directory)
        .map_err(|error| store_error(&format!("cannot be written: {}", error.kind())))?;
    // The directory of the documents is a directory of the state
    // directory, not a link to a different place.
    if !std::fs::symlink_metadata(&directory).is_ok_and(|metadata| metadata.is_dir()) {
        return Err(store_error("has a directory that is not a directory"));
    }
    Ok(directory)
}

fn write_file<T: Serialize>(path: &Path, document: &T) -> Result<(), ErrorBody> {
    let bytes: Vec<u8> =
        serde_json::to_vec(document).map_err(|_| store_error("cannot be encoded"))?;
    let mut temporary: std::ffi::OsString = path.as_os_str().to_owned();
    temporary.push(format!(".{}.new", std::process::id()));
    let temporary: PathBuf = PathBuf::from(temporary);
    let mut options = std::fs::OpenOptions::new();
    // A file that has the temporary name is of an earlier failure.
    drop(std::fs::remove_file(&temporary));
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let written: std::io::Result<()> = options.open(&temporary).and_then(|mut file| {
        file.write_all(&bytes)?;
        file.sync_all()
    });
    let renamed: std::io::Result<()> = written.and_then(|()| std::fs::rename(&temporary, path));
    renamed.map_err(|error| {
        drop(std::fs::remove_file(&temporary));
        store_error(&format!("cannot be written: {}", error.kind()))
    })
}

/// Reads a document. `Ok(None)` when the file does not exist.
fn read_document<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<Option<T>, ErrorBody> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(store_error(&format!("cannot be read: {}", error.kind())));
        }
    };
    if !file.metadata().is_ok_and(|metadata| metadata.is_file()) {
        return Err(store_error("is not a regular file"));
    }
    let mut bytes: Vec<u8> = Vec::new();
    file.take(MAX_DOCUMENT_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| store_error(&format!("cannot be read: {}", error.kind())))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_DOCUMENT_BYTES {
        return Err(store_error("is too large"));
    }
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| store_error("is not readable by this build"))
}

/// Writes the document of a plan.
pub(crate) fn save_plan(
    environment: &Environment,
    document: &PlanDocument,
) -> Result<(), ErrorBody> {
    write_document(
        environment,
        &plan_path(environment, &document.plan_id)?,
        document,
    )
}

/// Reads the document of a plan. A document of a different plan identity
/// or of a format that this build does not know is not used.
pub(crate) fn load_plan(
    environment: &Environment,
    plan_id: &PlanId,
) -> Result<Option<PlanDocument>, ErrorBody> {
    let document: Option<PlanDocument> = read_document(&plan_path(environment, plan_id)?)?;
    Ok(document.filter(|document| {
        document.schema_version == DOCUMENT_VERSION && &document.plan_id == plan_id
    }))
}

/// Writes the stop record of a process generation.
pub(crate) fn save_stop(environment: &Environment, record: &StopRecord) -> Result<(), ErrorBody> {
    write_document(
        environment,
        &stop_path(environment, &record.target)?,
        record,
    )
}

/// Reads the stop record of a process generation.
pub(crate) fn load_stop(
    environment: &Environment,
    target: &ProcessGenerationId,
) -> Result<Option<StopRecord>, ErrorBody> {
    let record: Option<StopRecord> = read_document(&stop_path(environment, target)?)?;
    match record {
        // A record that this build cannot interpret is not "no record":
        // an earlier request possibly sent a signal, so it permits no
        // new plan.
        Some(record) if record.schema_version != DOCUMENT_VERSION || &record.target != target => {
            Err(store_error(
                "of an earlier stop request is of a different format; this build makes no second plan for the process",
            ))
        }
        other => Ok(other),
    }
}

/// An exclusive lock for the stop requests of one process generation. It
/// is released when the value is dropped, and when the process ends.
#[derive(Debug)]
pub(crate) struct StopLock {
    _file: std::fs::File,
}

/// Takes the lock of the stop requests of `target`, and waits for a
/// different client that holds it. Two requests for one process
/// generation then make one plan.
pub(crate) fn lock_stop(
    environment: &Environment,
    target: &ProcessGenerationId,
) -> Result<StopLock, ErrorBody> {
    environment.create_state_directory()?;
    let directory: PathBuf = plan_directory(environment)?;
    let path: PathBuf = directory.join(format!("stop-{target}.lock"));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(&path).map_err(|error| {
        store_error(&format!("has a lock that cannot be used: {}", error.kind()))
    })?;
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd as _;
        // SAFETY: the descriptor is that of `file`, which is open for the
        // whole call. `flock` reads no memory of this process.
        let locked: libc::c_int = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if locked != 0 {
            return Err(store_error("has a lock that cannot be taken"));
        }
    }
    Ok(StopLock { _file: file })
}

/// Removes the documents that are older than the retention. The pass reads
/// a bounded number of entries and ignores each failure: a document that
/// stays is removed by a later pass.
pub(crate) fn prune(environment: &Environment) {
    let Ok(directory) = environment.plan_directory() else {
        return;
    };
    let Ok(entries) = std::fs::read_dir(&directory) else {
        return;
    };
    let now: SystemTime = SystemTime::now();
    for entry in entries.take(MAX_PRUNE_ENTRIES).flatten() {
        let path: PathBuf = entry.path();
        let is_document: bool = path.extension().is_some_and(|extension| {
            extension == "json" || extension == "new" || extension == "lock"
        }) && path
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .is_some_and(|name| name.starts_with("plan-") || name.starts_with("stop-"));
        let is_old: bool = entry
            .metadata()
            .ok()
            .filter(std::fs::Metadata::is_file)
            .and_then(|metadata| metadata.modified().ok())
            .and_then(|modified| now.duration_since(modified).ok())
            .is_some_and(|age| age > RETENTION);
        if is_document && is_old {
            drop(std::fs::remove_file(path));
        }
    }
}
