//! The fresh reading of a planned process generation.
//!
//! [`revalidate`] is the full check before a call: PID, start time, owner,
//! and executable evidence. [`observe`] is the check after a call: it reads
//! only whether the planned generation exists.

use svalnir_core::file::{FileObjectEvidence, LosslessPath};
use svalnir_core::process::{ExecutableIdentity, ProcessIdentity};

use crate::platform::process::{ProcessSource, QueryFailure, RawProcessInfo};

/// What a fresh reading shows about a planned process generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenerationState {
    /// The planned generation exists and is not a zombie.
    Running,
    /// No process has the PID, or the planned generation is a zombie: it
    /// exited and its parent has not collected its status.
    Exited,
    /// The PID belongs to a process with a different start time. The
    /// planned generation does not exist.
    Replaced,
    /// The query failed, so the reading shows nothing.
    Unknown(QueryFailure),
}

/// The result of the full check before a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Revalidation {
    /// Each item of the planned evidence agrees with the fresh reading.
    Same,
    /// The planned generation exited.
    Exited,
    /// The PID belongs to a different generation.
    Replaced,
    /// The effective or the real user of the process is not the planned
    /// owner.
    OwnerChanged,
    /// The executable path or its file object is not the planned one.
    ExecutableChanged,
    /// The plan has no executable evidence, the fresh reading gives no
    /// executable evidence, or one of the two has an item that the other
    /// does not have.
    EvidenceMissing,
    /// A query failed for a reason other than an absent process.
    Unknown(QueryFailure),
}

/// Reads whether the planned generation exists now.
pub(super) fn observe<S: ProcessSource>(source: &S, planned: &ProcessIdentity) -> GenerationState {
    classify(source.process_info(planned.pid), planned)
}

fn classify(
    info: Result<RawProcessInfo, QueryFailure>,
    planned: &ProcessIdentity,
) -> GenerationState {
    match info {
        Err(QueryFailure::Gone) => GenerationState::Exited,
        Err(failure) => GenerationState::Unknown(failure),
        Ok(info) if info.pid != planned.pid => GenerationState::Unknown(QueryFailure::Inconsistent),
        Ok(info) if info.start_time != planned.start_time => GenerationState::Replaced,
        Ok(info) if info.zombie => GenerationState::Exited,
        Ok(_) => GenerationState::Running,
    }
}

/// Compares the planned executable evidence with the fresh one.
fn compare_executable(
    planned: Option<&ExecutableIdentity>,
    path: Result<LosslessPath, QueryFailure>,
    file: Option<Result<FileObjectEvidence, QueryFailure>>,
) -> Revalidation {
    let Some(planned) = planned else {
        return Revalidation::EvidenceMissing;
    };
    // The executor cannot read a code signature again. A plan that has one
    // has evidence that the fresh reading does not have.
    if planned.code_signature.is_some() {
        return Revalidation::EvidenceMissing;
    }
    let Ok(path) = path else {
        return Revalidation::EvidenceMissing;
    };
    if path != planned.path {
        return Revalidation::ExecutableChanged;
    }
    match (planned.file, file.and_then(Result::ok)) {
        (Some(before), Some(now)) if before == now => Revalidation::Same,
        (Some(_), Some(_)) => Revalidation::ExecutableChanged,
        (None, None) => Revalidation::Same,
        _ => Revalidation::EvidenceMissing,
    }
}

/// Reads the process again and compares each item of the planned evidence.
///
/// The identity query runs before and after the executable queries. A
/// process that replaces its program image with `exec` keeps its PID and
/// its start time, so the executable evidence is read between two identity
/// readings. The second identity query is the last query: the time between
/// this check and the call that follows it has no other query in it.
pub(super) fn revalidate<S: ProcessSource>(source: &S, planned: &ProcessIdentity) -> Revalidation {
    let first: Result<RawProcessInfo, QueryFailure> = source.process_info(planned.pid);
    match classify(first, planned) {
        GenerationState::Exited => return Revalidation::Exited,
        GenerationState::Replaced => return Revalidation::Replaced,
        GenerationState::Unknown(failure) => return Revalidation::Unknown(failure),
        GenerationState::Running => {}
    }
    let path: Result<LosslessPath, QueryFailure> = source.executable_path(planned.pid);
    let file: Option<Result<FileObjectEvidence, QueryFailure>> =
        path.as_ref().ok().map(|path| source.file_evidence(path));
    let executable: Revalidation = compare_executable(planned.executable.as_ref(), path, file);
    let last: Result<RawProcessInfo, QueryFailure> = source.process_info(planned.pid);
    match classify(last, planned) {
        GenerationState::Exited => return Revalidation::Exited,
        GenerationState::Replaced => return Revalidation::Replaced,
        GenerationState::Unknown(failure) => return Revalidation::Unknown(failure),
        GenerationState::Running => {}
    }
    let owner_agrees = |info: Result<RawProcessInfo, QueryFailure>| {
        info.is_ok_and(|info| info.effective_uid == planned.uid && info.real_uid == planned.uid)
    };
    if !owner_agrees(first) || !owner_agrees(last) {
        return Revalidation::OwnerChanged;
    }
    executable
}
