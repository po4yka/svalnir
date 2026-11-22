//! The plan binding of an owner operation (`docs/CLEANUP_RULES.md`
//! section 9).
//!
//! [`bind_owner_operation`] makes the [`OwnerOperationBinding`] of one
//! reviewed declaration for one approved root: it binds the first
//! executable of the declaration that passes the checks of the owner
//! executor, resolves the typed parameters of the command, and measures
//! the scope. No value comes from user input or from configuration text.
//! The binding goes into a sealed plan of the class `RunOwnerOperation`;
//! this build has no command that makes such a plan, and only the fixture
//! tests call this function.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use svalnir_core::action::{
    ExecutableBinding, InterpreterBinding, OwnerOperationBinding, OwnerOperationKind,
    ScopeMeasurement,
};
use svalnir_core::file::LosslessPath;
use svalnir_core::process::Uid;
use svalnir_core::quantity::Nanoseconds;
use svalnir_core::rule::owner::{
    ExecutableBase, ExecutableLocation, InterpreterLocation, OwnerCommand, OwnerOperation,
    ParameterValues,
};
use thiserror::Error;

use crate::executor::fs::ApprovedRoot;
use crate::executor::owner::{
    ExecutableKind, ExecutableProblem, ScopeLimits, examine_program, executable_kind, measure_scope,
};
use crate::scan::{CancellationToken, ScanClock};

/// The reason no binding is made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum OwnerBindError {
    /// The declaration has no command of the kind.
    #[error("the declaration has no command of the kind")]
    NoCommand,
    /// A `clear` operation needs the explicit consent of the user.
    #[error("a clear operation needs the explicit consent of the user")]
    ClearNotConfirmed,
    /// No path of the declaration has an executable.
    #[error("no path of the declaration has an executable")]
    ExecutableNotFound,
    /// The `#!` line of a script names an interpreter that is not an
    /// interpreter location of the declaration.
    #[error("the interpreter of the script is not a location of the declaration")]
    InterpreterNotDeclared,
    /// An executable exists, and it or a directory above it does not pass
    /// the owner and mode checks.
    #[error("the executable does not pass the owner and mode checks")]
    ExecutableNotTrusted,
    /// The scope root or the home directory is not a UTF-8 path, so a
    /// typed parameter has no text.
    #[error("a path of a typed parameter is not UTF-8")]
    PathNotUtf8,
    /// The scope root is not a directory of the principal with the object
    /// of its root record.
    #[error("the scope root is not the approved root")]
    ScopeRootChanged,
    /// The measurement of the scope is not complete.
    #[error("the measurement of the scope is not complete")]
    ScopeNotMeasured,
}

/// One request for a binding.
#[derive(Debug, Clone, Copy)]
pub struct OwnerBindRequest<'a> {
    /// The reviewed declaration of the rule.
    pub declaration: &'a OwnerOperation,
    /// The kind of the operation.
    pub kind: OwnerOperationKind,
    /// The explicit consent of the user to a `clear` operation. A
    /// `prune` operation has none.
    pub clear_opt_in: bool,
    /// The approved root of the scope, bound to its object, its volume,
    /// and its mount generation.
    pub scope: &'a ApprovedRoot,
    /// The layout that the rule found for the scope.
    pub layout: &'a str,
    /// The home directory of the account record of the principal.
    pub home_directory: &'a Path,
    /// The principal of the plan.
    pub principal: Uid,
    /// The largest executable that the builder reads for its digest.
    pub max_executable_bytes: u64,
    /// The bounds of the measurement of the scope.
    pub scope_limits: ScopeLimits,
}

/// The absolute path of one executable location of a declaration, with
/// its symbolic links resolved. `None` when nothing is at the path.
fn resolve_location(base: ExecutableBase, path: &LosslessPath, home: &Path) -> Option<PathBuf> {
    let path: PathBuf = match base {
        ExecutableBase::Absolute => path.to_path_buf(),
        ExecutableBase::UserHome => home.join(path.to_path_buf()),
    };
    fs::canonicalize(path).ok()
}

/// The canonical paths of `locations` below `home`, in their sequence.
/// A location with nothing at its path has none.
pub fn canonical_locations(locations: &[ExecutableLocation], home: &Path) -> Vec<PathBuf> {
    locations
        .iter()
        .filter_map(|location| resolve_location(location.base, &location.path, home))
        .collect()
}

/// The canonical paths of the interpreters of a declaration below `home`,
/// each with its permitted interpreter arguments.
pub fn canonical_interpreters(
    interpreters: &[InterpreterLocation],
    home: &Path,
) -> Vec<(PathBuf, Vec<String>)> {
    interpreters
        .iter()
        .filter_map(|interpreter| {
            resolve_location(interpreter.location.base, &interpreter.location.path, home)
                .map(|path| (path, interpreter.arguments()))
        })
        .collect()
}

/// The executable of the declaration, with the interpreter of a script:
/// the first path that passes the checks of the owner executor.
fn bind_executable(
    request: &OwnerBindRequest<'_>,
) -> Result<(ExecutableBinding, Option<InterpreterBinding>), OwnerBindError> {
    let interpreters: Vec<(PathBuf, Vec<String>)> =
        canonical_interpreters(&request.declaration.interpreters, request.home_directory);
    let mut problem: OwnerBindError = OwnerBindError::ExecutableNotFound;
    for path in canonical_locations(&request.declaration.executables, request.home_directory) {
        match examine_program(
            &path,
            &interpreters,
            request.principal,
            request.max_executable_bytes,
        ) {
            Ok(program) => return Ok(program),
            Err(ExecutableProblem::NotFound) => {}
            Err(ExecutableProblem::InterpreterNotDeclared) => {
                problem = OwnerBindError::InterpreterNotDeclared;
            }
            Err(_) => problem = OwnerBindError::ExecutableNotTrusted,
        }
    }
    Err(problem)
}

/// Whether the paths of the executable and of the interpreter of `binding`
/// are canonical locations of `declaration` below `home`: the check of the
/// coordinator at admission, with the command check of
/// [`OwnerOperationDeclaration::agrees_with`](svalnir_core::rule::owner::OwnerOperationDeclaration::agrees_with).
pub fn binding_agrees(
    binding: &OwnerOperationBinding,
    declaration: &OwnerOperation,
    home: &Path,
) -> bool {
    let Some(home_text) = home.to_str() else {
        return false;
    };
    let located = |path: &LosslessPath, locations: &[ExecutableLocation]| {
        canonical_locations(locations, home).contains(&path.to_path_buf())
    };
    // The interpreter and its arguments are one declared pair, and a
    // binding has an interpreter exactly when its executable is a script.
    let interpreter_agrees: bool = match &binding.interpreter {
        Some(interpreter) => canonical_interpreters(&declaration.interpreters, home).contains(&(
            interpreter.executable.path.to_path_buf(),
            interpreter.arguments.clone(),
        )),
        None => true,
    };
    let is_script: Option<bool> = executable_kind(&binding.executable.path.to_path_buf())
        .ok()
        .map(|kind| matches!(kind, ExecutableKind::Script { .. }));
    declaration.agrees_with(binding, home_text)
        && located(&binding.executable.path, &declaration.executables)
        && interpreter_agrees
        && is_script == Some(binding.interpreter.is_some())
}

/// Makes the binding of `request`.
///
/// The scope root must be a directory of the principal with the object of
/// its root record, and its measurement must be complete. The charge of
/// the binding is the measured scope.
///
/// # Errors
///
/// Returns the [`OwnerBindError`] of the first check that fails.
pub fn bind_owner_operation(
    request: &OwnerBindRequest<'_>,
    cancel: &CancellationToken,
    clock: &dyn ScanClock,
) -> Result<OwnerOperationBinding, OwnerBindError> {
    let declaration = request.declaration;
    let command: &OwnerCommand = declaration
        .command(request.kind)
        .ok_or(OwnerBindError::NoCommand)?;
    let is_clear: bool = matches!(request.kind, OwnerOperationKind::Clear);
    if is_clear && !request.clear_opt_in {
        return Err(OwnerBindError::ClearNotConfirmed);
    }
    let root: PathBuf = request.scope.path.to_path_buf();
    let root_agrees: bool = fs::symlink_metadata(&root).is_ok_and(|metadata| {
        metadata.file_type().is_dir()
            && metadata.uid() == request.principal.get()
            && u64::from_ne_bytes(i64::from(request.scope.object.device.get()).to_ne_bytes())
                == metadata.dev()
            && request.scope.object.inode.get() == metadata.ino()
    });
    if !root_agrees {
        return Err(OwnerBindError::ScopeRootChanged);
    }
    let (executable, interpreter) = bind_executable(request)?;
    let values = ParameterValues {
        scope_root: request
            .scope
            .path
            .as_utf8()
            .ok_or(OwnerBindError::PathNotUtf8)?,
        home_directory: request
            .home_directory
            .to_str()
            .ok_or(OwnerBindError::PathNotUtf8)?,
    };
    let measured: ScopeMeasurement = measure_scope(&root, request.scope_limits, cancel, clock)
        .filter(|measurement| measurement.complete)
        .ok_or(OwnerBindError::ScopeNotMeasured)?;
    let deadline: Nanoseconds = declaration.command_deadline;
    Ok(OwnerOperationBinding {
        root_id: request.scope.root_id.clone(),
        root_path: request.scope.path.clone(),
        root_object: request.scope.object,
        volume_id: request.scope.volume_id.clone(),
        mount_id: request.scope.mount_id.clone(),
        owner: request.principal,
        rule: declaration.rule.clone(),
        layout: request.layout.to_owned(),
        operation: request.kind,
        clear_opt_in: is_clear,
        bound: command.bound,
        executable,
        interpreter,
        arguments: command.resolved_arguments(&values),
        environment: declaration.resolved_environment(&values),
        working_directory: LosslessPath::from_path(request.home_directory)
            .map_err(|_| OwnerBindError::PathNotUtf8)?,
        command_deadline: deadline,
        charge: measured.charge().ok_or(OwnerBindError::ScopeNotMeasured)?,
        measured,
        expected_effect: command.expected_effect.clone(),
    })
}
