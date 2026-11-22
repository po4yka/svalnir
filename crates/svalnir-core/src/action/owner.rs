//! The target of an owner operation: one fixed command of a producer on
//! one measured scope.
//!
//! `docs/ACTION_CONTRACTS.md` sections 3 and 7 own the binding and its
//! execution, and `docs/CLEANUP_RULES.md` section 9 owns the declaration
//! that the binding comes from ([`crate::rule::owner`]). The binding has
//! each value that the executor uses: the executable with its identity
//! and its digest, the argument vector, the environment, the working
//! directory, and the deadline. No value comes from user input or from
//! configuration text, and the plan digest covers each one.

use serde::{Deserialize, Serialize};

use super::budget::WorkCharge;
use super::plan::{ExecutorRole, PlanError};
use crate::digest::ContentDigest;
use crate::file::{FileObjectEvidence, LosslessPath};
use crate::id::{MountId, RootId, TargetId, VolumeId};
use crate::process::Uid;
use crate::quantity::{ByteDelta, Bytes, EntryCount, Nanoseconds};
use crate::rule::RuleRef;
use crate::time::WallTime;

/// The largest number of arguments of one command, the name of the
/// executable not included.
pub const MAX_OWNER_ARGUMENTS: usize = 32;

/// The largest number of entries of the environment of one command.
pub const MAX_OWNER_ENVIRONMENT: usize = 16;

/// The largest length, in bytes, of one argument, of one environment
/// name, of one environment value, and of the expected effect statement.
pub const MAX_OWNER_TEXT_BYTES: usize = 1024;

/// The longest deadline of one command: one hour.
pub const MAX_OWNER_DEADLINE: Nanoseconds = Nanoseconds::new(3_600_000_000_000);

/// The mode bits that permit a write by the group or by others.
pub const GROUP_OR_OTHER_WRITE: u32 = 0o022;

/// The user ID of root.
const ROOT_UID: u32 = 0;

/// The kind of an owner operation.
///
/// The kind is a closed value: a plan with a kind that this build does not
/// know is not decoded, so it is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerOperationKind {
    /// The producer removes the data that it does not use.
    Prune,
    /// The producer removes its cache data, also data that a project can
    /// use now. Only a manual plan with the flag `clear_opt_in` has it.
    Clear,
}

impl OwnerOperationKind {
    /// The spelling of the kind.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prune => "prune",
            Self::Clear => "clear",
        }
    }
}

/// What the declaration states about the data that the command can
/// change.
///
/// The bound is a closed value, as [`OwnerOperationKind`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerOperationBound {
    /// The command changes only data below the scope root, and the
    /// executor measures the scope again after the command. Only this
    /// bound permits an automatic plan.
    WithinScope,
    /// The declaration states no bound. The operation is manual only.
    Unbounded,
}

/// The executable of an owner operation, as the plan builder examined it.
///
/// The executor compares each value again immediately before it starts the
/// command, and starts nothing when one value is different.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutableBinding {
    /// The absolute path of the executable, with no symbolic link.
    pub path: LosslessPath,
    /// The device and the inode of the file.
    pub object: FileObjectEvidence,
    /// The owner of the file: root or the principal.
    pub owner: Uid,
    /// The mode bits of the file (`st_mode & 0o7777`).
    pub mode: u32,
    /// The size of the file.
    pub size: Bytes,
    /// The change time of the file (`st_ctimespec`).
    pub changed_at: FileTimestamp,
    /// The modification time of the file (`st_mtimespec`).
    pub modified_at: FileTimestamp,
    /// The SHA-256 digest of the content of the file.
    pub digest: ContentDigest,
    /// The code-signing identity of the file, when the builder read one.
    /// This build reads none, so the value is `None`.
    pub signature: Option<String>,
}

/// A time of a file as the filesystem reports it: seconds and nanoseconds
/// since the Unix epoch. It is compared for equality only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileTimestamp {
    /// The seconds.
    pub seconds: i64,
    /// The nanoseconds, below one second.
    pub nanoseconds: u32,
}

/// The interpreter of a script executable (owner decision D2 of
/// 2026-11-22): the executor starts this Mach-O file with `arguments` and
/// the path of the script, so no `#!` line is read by the kernel and no
/// `env` searches `PATH`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InterpreterBinding {
    /// The interpreter, a canonical interpreter location of the
    /// declaration.
    pub executable: ExecutableBinding,
    /// The interpreter argument of the `#!` line: none or one.
    pub arguments: Vec<String>,
}

/// The environment names that a binding and a declaration never have:
/// each one changes the code that a process loads.
pub const DENIED_ENVIRONMENT_NAMES: [&str; 5] =
    ["NODE_OPTIONS", "BASH_ENV", "ENV", "RUBYOPT", "PERL5OPT"];

/// The prefixes of the environment names that a binding and a declaration
/// never have.
pub const DENIED_ENVIRONMENT_PREFIXES: [&str; 3] = ["DYLD_", "LD_", "PYTHON"];

/// Whether `name` is an environment name that changes the code that a
/// process loads.
pub fn is_denied_environment(name: &str) -> bool {
    DENIED_ENVIRONMENT_NAMES.contains(&name)
        || DENIED_ENVIRONMENT_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(prefix))
}

/// One entry of the environment of a command.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentEntry {
    /// The name: an upper-case ASCII letter or `_`, then upper-case ASCII
    /// letters, digits, and `_`.
    pub name: String,
    /// The value.
    pub value: String,
}

/// One measurement of the scope of an owner operation with the read-only
/// scanner.
///
/// The measurement is not reclaimable bytes and not available capacity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeMeasurement {
    /// The allocated bytes of the scope, each object counted one time.
    pub allocated_bytes: Bytes,
    /// The private allocated bytes of the scope, when the scanner gives
    /// them. `None` is not zero.
    pub private_allocated_bytes: Option<Bytes>,
    /// The entries below the scope root. The root is not one of them.
    pub entries: EntryCount,
    /// Whether the scan measured the whole scope.
    pub complete: bool,
    /// The wall-clock time of the measurement, for history only.
    pub measured_at: Option<WallTime>,
}

impl ScopeMeasurement {
    /// The admission charge of the measured scope: its allocated bytes, and
    /// its entries with the root as one more item. `None` when the item
    /// count does not fit.
    pub fn charge(&self) -> Option<WorkCharge> {
        let items: u64 = self.entries.get().checked_add(1)?;
        Some(WorkCharge::new(
            self.allocated_bytes,
            EntryCount::new(items),
        ))
    }

    /// Whether the scope fits in `charge`: no more allocated bytes and no
    /// more items than the charge.
    pub fn fits_in(&self, charge: &WorkCharge) -> bool {
        self.charge().is_some_and(|own| own.fits_in(charge))
    }
}

/// The binding of an owner-operation target.
///
/// The scope is the approved root of the rule: its lease is the cleanup
/// root lease, so the operation conflicts with each file operation on the
/// same root.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerOperationBinding {
    /// The approved root of the scope.
    pub root_id: RootId,
    /// The absolute path of the scope root.
    pub root_path: LosslessPath,
    /// The native identifiers of the scope root.
    pub root_object: FileObjectEvidence,
    /// The volume of the scope root.
    pub volume_id: VolumeId,
    /// The mount generation of the volume.
    pub mount_id: MountId,
    /// The owner of the scope root.
    pub owner: Uid,
    /// The rule revision of the operation.
    pub rule: RuleRef,
    /// The layout that the rule found for the scope.
    pub layout: String,
    /// The kind.
    pub operation: OwnerOperationKind,
    /// The explicit consent to a `clear` operation. It is true exactly
    /// for the kind `clear`, and only a manual plan has it.
    pub clear_opt_in: bool,
    /// The bound of the declaration.
    pub bound: OwnerOperationBound,
    /// The executable.
    pub executable: ExecutableBinding,
    /// The interpreter of a script executable. `None` for a Mach-O
    /// executable.
    pub interpreter: Option<InterpreterBinding>,
    /// The arguments after the name of the executable.
    pub arguments: Vec<String>,
    /// The only entries of the environment of the command.
    pub environment: Vec<EnvironmentEntry>,
    /// The working directory of the command: the home directory.
    pub working_directory: LosslessPath,
    /// The deadline of the command, from its start.
    pub command_deadline: Nanoseconds,
    /// The measurement of the scope by the plan builder.
    pub measured: ScopeMeasurement,
    /// The admission charge of the measured scope.
    pub charge: WorkCharge,
    /// The expected effect statement of the declaration, for the review
    /// before an approval.
    pub expected_effect: String,
}

/// The change of the scope of an owner operation: the measurement before
/// the command and the measurement after it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ScopeAllocationWire")]
pub struct ScopeAllocationEffect {
    target_id: TargetId,
    before: ScopeMeasurement,
    after: Option<ScopeMeasurement>,
    delta: Option<ByteDelta>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScopeAllocationWire {
    target_id: TargetId,
    before: ScopeMeasurement,
    after: Option<ScopeMeasurement>,
    delta: Option<ByteDelta>,
}

/// The reason a scope allocation effect was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the change of the scope is not the difference of the two measurements")]
pub struct ScopeAllocationError;

impl TryFrom<ScopeAllocationWire> for ScopeAllocationEffect {
    type Error = ScopeAllocationError;

    fn try_from(wire: ScopeAllocationWire) -> Result<Self, Self::Error> {
        let effect = Self::new(wire.target_id, wire.before, wire.after);
        if effect.delta == wire.delta {
            Ok(effect)
        } else {
            Err(ScopeAllocationError)
        }
    }
}

impl ScopeAllocationEffect {
    /// Makes the effect from the two measurements.
    ///
    /// The change of the private allocated bytes has a value only when the
    /// two measurements are complete and have private allocated bytes.
    pub fn new(
        target_id: TargetId,
        before: ScopeMeasurement,
        after: Option<ScopeMeasurement>,
    ) -> Self {
        let delta: Option<ByteDelta> = after.and_then(|after| {
            if !before.complete || !after.complete {
                return None;
            }
            let earlier: Bytes = before.private_allocated_bytes?;
            let later: Bytes = after.private_allocated_bytes?;
            Some(later.delta_from(earlier))
        });
        Self {
            target_id,
            before,
            after,
            delta,
        }
    }

    /// The target of the operation.
    pub fn target_id(&self) -> &TargetId {
        &self.target_id
    }

    /// The measurement before the command.
    pub fn before(&self) -> &ScopeMeasurement {
        &self.before
    }

    /// The measurement after the command. `None` when no measurement was
    /// made.
    pub fn after(&self) -> Option<&ScopeMeasurement> {
        self.after.as_ref()
    }

    /// The change of the private allocated bytes: negative for a
    /// decrease. `None` when the change is not known.
    pub fn delta(&self) -> Option<ByteDelta> {
        self.delta
    }
}

/// Whether `text` is a text of a binding: not longer than the limit and
/// with no NUL byte.
fn is_bounded_text(text: &str) -> bool {
    text.len() <= MAX_OWNER_TEXT_BYTES && !text.contains('\0')
}

/// Whether `name` is an environment name: an upper-case ASCII letter or
/// `_`, then upper-case ASCII letters, digits, and `_`.
pub fn is_environment_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    let first_agrees: bool = bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_uppercase() || byte == b'_');
    first_agrees
        && name.len() <= MAX_OWNER_TEXT_BYTES
        && bytes.all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

/// Whether `path` is absolute with at least one component and no empty,
/// `.`, or `..` component.
pub(super) fn is_absolute_path(path: &LosslessPath) -> bool {
    let Some(relative) = path.as_bytes().strip_prefix(b"/") else {
        return false;
    };
    !relative.is_empty()
        && relative
            .split(|byte| *byte == b'/')
            .all(|component| !component.is_empty() && component != b"." && component != b"..")
}

/// Whether the file of `executable` has an owner and a mode that a
/// process of a different user cannot change: root or `principal` as the
/// owner, and no write bit for the group or for others.
pub fn executable_is_trusted(executable: &ExecutableBinding, principal: Uid) -> bool {
    let owner_agrees: bool = executable.owner.get() == ROOT_UID || executable.owner == principal;
    owner_agrees && executable.mode & GROUP_OR_OTHER_WRITE == 0
}

/// Checks the binding of an owner-operation target, for a plan of
/// `principal` with the executor `executor`.
///
/// `automatic` is true for a plan with an automatic trigger, and
/// `execution_deadline` is the execution deadline of the plan.
///
/// # Errors
///
/// Returns [`PlanError::Trigger`] when an automatic plan has a kind,
/// a bound, or a flag that only a manual plan can have, and
/// [`PlanError::Binding`] for each other rule of
/// `docs/ACTION_CONTRACTS.md` section 3.
pub(super) fn check_owner_binding(
    binding: &OwnerOperationBinding,
    principal: Uid,
    executor: &ExecutorRole,
    automatic: bool,
    execution_deadline: Nanoseconds,
) -> Result<(), PlanError> {
    if !executor.is_recognized() {
        return Err(PlanError::Unrecognized);
    }
    // A `clear` operation is manual only, and its plan has the explicit
    // flag. An automatic plan also needs a bound that the executor
    // verifies.
    let is_clear: bool = matches!(binding.operation, OwnerOperationKind::Clear);
    if binding.clear_opt_in != is_clear {
        return Err(PlanError::Binding);
    }
    if automatic && (is_clear || !matches!(binding.bound, OwnerOperationBound::WithinScope)) {
        return Err(PlanError::Trigger);
    }
    let paths_agree: bool = is_absolute_path(&binding.root_path)
        && is_absolute_path(&binding.working_directory)
        && is_absolute_path(&binding.executable.path);
    // The owner executor of this build is the executor of the user, and
    // it changes only a scope of that user.
    let executor_agrees: bool =
        matches!(executor, ExecutorRole::User) && binding.owner == principal;
    let mut names: Vec<&str> = binding
        .environment
        .iter()
        .map(|entry| entry.name.as_str())
        .collect();
    names.sort_unstable();
    names.dedup();
    let texts_agree: bool = binding.arguments.len() <= MAX_OWNER_ARGUMENTS
        && binding
            .arguments
            .iter()
            .all(|argument| is_bounded_text(argument))
        && binding.environment.len() <= MAX_OWNER_ENVIRONMENT
        && names.len() == binding.environment.len()
        && binding.environment.iter().all(|entry| {
            is_environment_name(&entry.name)
                && !is_denied_environment(&entry.name)
                && is_bounded_text(&entry.value)
        })
        && !binding.layout.is_empty()
        && is_bounded_text(&binding.layout)
        && !binding.expected_effect.is_empty()
        && is_bounded_text(&binding.expected_effect)
        && binding
            .executable
            .signature
            .as_ref()
            .is_none_or(|signature| is_bounded_text(signature));
    let deadline_agrees: bool = binding.command_deadline > Nanoseconds::ZERO
        && binding.command_deadline <= MAX_OWNER_DEADLINE
        && binding.command_deadline <= execution_deadline;
    // The charge covers the measurement, and an entry is a minimum of one
    // item.
    let charge_agrees: bool =
        binding.charge.items != EntryCount::ZERO && binding.measured.fits_in(&binding.charge);
    if paths_agree
        && executor_agrees
        && texts_agree
        && deadline_agrees
        && charge_agrees
        && executable_is_trusted(&binding.executable, principal)
        && binding.interpreter.as_ref().is_none_or(|interpreter| {
            is_absolute_path(&interpreter.executable.path)
                && executable_is_trusted(&interpreter.executable, principal)
                && interpreter.executable.signature.is_none()
                && interpreter.arguments.len() <= 1
                && interpreter
                    .arguments
                    .iter()
                    .all(|argument| is_bounded_text(argument))
        })
    {
        Ok(())
    } else {
        Err(PlanError::Binding)
    }
}
