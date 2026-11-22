//! The owner-operation declaration of a rule: the fixed command of a
//! producer that removes the data of the rule.
//!
//! `docs/CLEANUP_RULES.md` section 9 owns the contract. The declaration is
//! a reviewed constant of the build, beside the rule declaration of a rule
//! with the deletion method `producer_operation`. User configuration
//! supplies no part of it: the executable is a fixed list of paths, and
//! each argument and each environment value is literal text or a typed
//! parameter of this module. The plan builder resolves the parameters and
//! seals the result in an [`OwnerOperationBinding`].

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::RuleRef;
use crate::action::Checked;
use crate::action::{
    Check, EnvironmentEntry, MAX_OWNER_ARGUMENTS, MAX_OWNER_DEADLINE, MAX_OWNER_ENVIRONMENT,
    MAX_OWNER_TEXT_BYTES, OwnerOperationBinding, OwnerOperationBound, OwnerOperationKind,
    is_denied_environment, is_environment_name,
};
use crate::file::LosslessPath;
use crate::quantity::Nanoseconds;

/// The largest number of executable paths of one declaration.
pub const MAX_OWNER_EXECUTABLES: usize = 8;

/// What the path of an executable is relative to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutableBase {
    /// The path is absolute, for example below `/opt/homebrew`.
    Absolute,
    /// The path is relative to the home directory of the account record
    /// of the user, with no shell expansion.
    UserHome,
}

/// One path that the plan builder examines for the executable.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutableLocation {
    /// The base of the path.
    pub base: ExecutableBase,
    /// The path: absolute for [`ExecutableBase::Absolute`], relative for
    /// [`ExecutableBase::UserHome`]. No component is empty, `.`, or `..`.
    pub path: LosslessPath,
}

/// One interpreter of a declaration: its path and the interpreter
/// argument that the `#!` line of the script must have. An interpreter
/// argument of a plan that is not this value is refused, so a plan cannot
/// give the interpreter an option such as `--eval`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InterpreterLocation {
    /// The path of the interpreter.
    pub location: ExecutableLocation,
    /// The interpreter argument of the `#!` line, or `None` for a line
    /// with no argument. A `#!/usr/bin/env NAME` line passes no argument,
    /// so its interpreter has `None`.
    pub argument: Option<String>,
}

impl InterpreterLocation {
    /// The interpreter arguments of a binding of this interpreter.
    pub fn arguments(&self) -> Vec<String> {
        self.argument.iter().cloned().collect()
    }
}

/// One part of an argument or of an environment value.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "part", content = "text", rename_all = "snake_case")]
pub enum ParameterPart {
    /// The literal text.
    Literal(String),
    /// The absolute path of the scope root of the operation.
    ScopeRoot,
    /// The absolute path of the home directory of the user.
    HomeDirectory,
}

/// One command of a declaration.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerCommand {
    /// The kind of the command.
    pub kind: OwnerOperationKind,
    /// The arguments after the name of the executable.
    pub arguments: Vec<ParameterPart>,
    /// The bound that the review of the command established.
    pub bound: OwnerOperationBound,
    /// The expected effect statement, which the review before an approval
    /// shows.
    pub expected_effect: String,
}

/// One entry of the environment of a command.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentDeclaration {
    /// The name of the variable.
    pub name: String,
    /// The value.
    pub value: ParameterPart,
}

/// The owner-operation declaration of one rule revision.
/// [`OwnerOperation`] is the checked form.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerOperationDeclaration {
    /// The rule revision of the operation. The rule has the deletion
    /// method `producer_operation`.
    pub rule: RuleRef,
    /// The paths of the executable, in the sequence in which the plan
    /// builder examines them.
    pub executables: Vec<ExecutableLocation>,
    /// The interpreters that a script executable can name in its `#!`
    /// line, each with its one permitted interpreter argument (owner
    /// decision D2 of 2026-11-22). Empty for a producer whose executable is
    /// a Mach-O file.
    pub interpreters: Vec<InterpreterLocation>,
    /// One command for each supported kind.
    pub commands: Vec<OwnerCommand>,
    /// The only entries of the environment of a command.
    pub environment: Vec<EnvironmentDeclaration>,
    /// The deadline of a command, from its start.
    pub command_deadline: Nanoseconds,
}

/// A complete owner-operation declaration.
pub type OwnerOperation = Checked<OwnerOperationDeclaration>;

/// The reason an owner-operation declaration is incomplete.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum OwnerDeclarationError {
    /// The declaration has no executable, more than the limit, or a path
    /// that does not agree with its base.
    #[error("the executable paths of the declaration are not valid")]
    Executable,
    /// The declaration has no command, two commands of one kind, or more
    /// arguments than the limit.
    #[error("the commands of the declaration are not valid")]
    Command,
    /// A literal text is too long or has a NUL byte, or an expected effect
    /// statement is empty.
    #[error("a text of the declaration is not valid")]
    Text,
    /// The environment has more entries than the limit, a name that is not
    /// an environment name, a name that changes the code that a process
    /// loads, or one name two times.
    #[error("the environment of the declaration is not valid")]
    Environment,
    /// The deadline is zero or longer than one hour.
    #[error("the deadline of the declaration is not valid")]
    Deadline,
}

/// Whether `path` has components and no empty, `.`, or `..` component,
/// after one leading `/` when `absolute`.
fn is_confined_path(path: &LosslessPath, absolute: bool) -> bool {
    let bytes: &[u8] = path.as_bytes();
    let relative: &[u8] = match (absolute, bytes.strip_prefix(b"/")) {
        (true, Some(relative)) => relative,
        (false, None) => bytes,
        _ => return false,
    };
    !relative.is_empty()
        && relative
            .split(|byte| *byte == b'/')
            .all(|component| !matches!(component, b"" | b"." | b".."))
}

fn is_valid_part(part: &ParameterPart) -> bool {
    match part {
        ParameterPart::Literal(text) => text.len() <= MAX_OWNER_TEXT_BYTES && !text.contains('\0'),
        ParameterPart::ScopeRoot | ParameterPart::HomeDirectory => true,
    }
}

impl Check for OwnerOperationDeclaration {
    type Error = OwnerDeclarationError;

    fn check(&self) -> Result<(), OwnerDeclarationError> {
        let confined = |location: &ExecutableLocation| {
            is_confined_path(
                &location.path,
                matches!(location.base, ExecutableBase::Absolute),
            )
        };
        let executables_agree: bool = !self.executables.is_empty()
            && self.executables.len() <= MAX_OWNER_EXECUTABLES
            && self.interpreters.len() <= MAX_OWNER_EXECUTABLES
            && self.executables.iter().all(confined)
            && self.interpreters.iter().all(|interpreter| {
                confined(&interpreter.location)
                    && interpreter.argument.as_ref().is_none_or(|argument| {
                        !argument.is_empty()
                            && argument.len() <= MAX_OWNER_TEXT_BYTES
                            && !argument.contains(['\0', ' ', '\t', '\n'])
                    })
            });
        if !executables_agree {
            return Err(OwnerDeclarationError::Executable);
        }
        let mut kinds: Vec<OwnerOperationKind> =
            self.commands.iter().map(|command| command.kind).collect();
        kinds.sort_unstable();
        kinds.dedup();
        let commands_agree: bool = !self.commands.is_empty()
            && kinds.len() == self.commands.len()
            && self
                .commands
                .iter()
                .all(|command| command.arguments.len() <= MAX_OWNER_ARGUMENTS);
        if !commands_agree {
            return Err(OwnerDeclarationError::Command);
        }
        let texts_agree: bool = self.commands.iter().all(|command| {
            command.arguments.iter().all(is_valid_part)
                && !command.expected_effect.is_empty()
                && command.expected_effect.len() <= MAX_OWNER_TEXT_BYTES
                && !command.expected_effect.chars().any(char::is_control)
        }) && self
            .environment
            .iter()
            .all(|entry| is_valid_part(&entry.value));
        if !texts_agree {
            return Err(OwnerDeclarationError::Text);
        }
        let mut names: Vec<&str> = self
            .environment
            .iter()
            .map(|entry| entry.name.as_str())
            .collect();
        names.sort_unstable();
        names.dedup();
        let environment_agrees: bool = self.environment.len() <= MAX_OWNER_ENVIRONMENT
            && names.len() == self.environment.len()
            && self.environment.iter().all(|entry| {
                is_environment_name(&entry.name) && !is_denied_environment(&entry.name)
            });
        if !environment_agrees {
            return Err(OwnerDeclarationError::Environment);
        }
        if self.command_deadline == Nanoseconds::ZERO || self.command_deadline > MAX_OWNER_DEADLINE
        {
            return Err(OwnerDeclarationError::Deadline);
        }
        Ok(())
    }
}

/// The values of the typed parameters of one operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParameterValues<'a> {
    /// The absolute path of the scope root.
    pub scope_root: &'a str,
    /// The absolute path of the home directory.
    pub home_directory: &'a str,
}

impl ParameterPart {
    /// The text of the part with `values`.
    pub fn resolve(&self, values: &ParameterValues<'_>) -> String {
        match self {
            Self::Literal(text) => text.clone(),
            Self::ScopeRoot => values.scope_root.to_owned(),
            Self::HomeDirectory => values.home_directory.to_owned(),
        }
    }
}

impl OwnerOperationDeclaration {
    /// The command of `kind`, when the declaration has one.
    pub fn command(&self, kind: OwnerOperationKind) -> Option<&OwnerCommand> {
        self.commands.iter().find(|command| command.kind == kind)
    }

    /// Whether `binding` is the command that this declaration gives for its
    /// scope root and the home directory `home_directory`: the same rule
    /// revision, a command of its kind, the same arguments, environment,
    /// bound, expected effect statement, and deadline, and the home
    /// directory as its working directory. The paths of the executable
    /// and of the interpreter need the filesystem, so the caller compares
    /// them with the canonical locations of the declaration.
    pub fn agrees_with(&self, binding: &OwnerOperationBinding, home_directory: &str) -> bool {
        let Some(command) = self.command(binding.operation) else {
            return false;
        };
        let Some(scope_root) = binding.root_path.as_utf8() else {
            return false;
        };
        let values = ParameterValues {
            scope_root,
            home_directory,
        };
        // An interpreter argument of the plan is the argument of a declared
        // interpreter; the caller compares the path of that interpreter.
        let interpreter_agrees: bool = binding.interpreter.as_ref().is_none_or(|interpreter| {
            self.interpreters
                .iter()
                .any(|declared| declared.arguments() == interpreter.arguments)
        });
        binding.rule == self.rule
            && interpreter_agrees
            && binding.arguments == command.resolved_arguments(&values)
            && binding.environment == self.resolved_environment(&values)
            && binding.bound == command.bound
            && binding.expected_effect == command.expected_effect
            && binding.command_deadline == self.command_deadline
            && binding.working_directory.as_bytes() == home_directory.as_bytes()
    }

    /// The environment with `values`, sorted by name.
    pub fn resolved_environment(&self, values: &ParameterValues<'_>) -> Vec<EnvironmentEntry> {
        let mut entries: Vec<EnvironmentEntry> = self
            .environment
            .iter()
            .map(|entry| EnvironmentEntry {
                name: entry.name.clone(),
                value: entry.value.resolve(values),
            })
            .collect();
        entries.sort();
        entries
    }
}

impl OwnerCommand {
    /// The arguments with `values`.
    pub fn resolved_arguments(&self, values: &ParameterValues<'_>) -> Vec<String> {
        self.arguments
            .iter()
            .map(|part| part.resolve(values))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        EnvironmentDeclaration, ExecutableBase, ExecutableLocation, OwnerCommand,
        OwnerDeclarationError, OwnerOperationDeclaration, ParameterPart, ParameterValues,
    };
    use crate::action::{Check, OwnerOperationBound, OwnerOperationKind};
    use crate::file::LosslessPath;
    use crate::id::{RuleId, RuleRevisionId};
    use crate::quantity::Nanoseconds;
    use crate::rule::RuleRef;

    fn declaration() -> OwnerOperationDeclaration {
        OwnerOperationDeclaration {
            rule: RuleRef {
                id: RuleId::new("fixture.owner-operation").unwrap(),
                revision: RuleRevisionId::new("1").unwrap(),
            },
            executables: vec![ExecutableLocation {
                base: ExecutableBase::UserHome,
                path: LosslessPath::from_bytes(b".local/bin/tool".to_vec()).unwrap(),
            }],
            commands: vec![OwnerCommand {
                kind: OwnerOperationKind::Prune,
                arguments: vec![
                    ParameterPart::Literal("cache".to_owned()),
                    ParameterPart::Literal("prune".to_owned()),
                    ParameterPart::ScopeRoot,
                ],
                bound: OwnerOperationBound::WithinScope,
                expected_effect: "The tool removes the entries that no project uses.".to_owned(),
            }],
            environment: vec![EnvironmentDeclaration {
                name: "HOME".to_owned(),
                value: ParameterPart::HomeDirectory,
            }],
            command_deadline: Nanoseconds::new(60_000_000_000),
            interpreters: Vec::new(),
        }
    }

    #[test]
    fn the_denied_environment_names_are_refused_in_each_declaration() {
        for name in [
            "DYLD_LIBRARY_PATH",
            "LD_PRELOAD",
            "NODE_OPTIONS",
            "BASH_ENV",
            "ENV",
            "PYTHONSTARTUP",
            "RUBYOPT",
            "PERL5OPT",
        ] {
            assert!(crate::action::is_denied_environment(name), "{name}");
        }
        assert!(!crate::action::is_denied_environment("HOME"));
        assert!(!crate::action::is_denied_environment("PATH"));
    }

    #[test]
    fn a_complete_declaration_resolves_its_parameters() {
        let declaration = declaration();
        assert_eq!(declaration.check(), Ok(()));
        let values = ParameterValues {
            scope_root: "/Users/user/Library/Caches/tool",
            home_directory: "/Users/user",
        };
        let command = declaration.command(OwnerOperationKind::Prune).unwrap();
        assert_eq!(
            command.resolved_arguments(&values),
            ["cache", "prune", "/Users/user/Library/Caches/tool"]
        );
        let environment = declaration.resolved_environment(&values);
        assert_eq!(environment[0].name, "HOME");
        assert_eq!(environment[0].value, "/Users/user");
        assert!(declaration.command(OwnerOperationKind::Clear).is_none());
    }

    type Change = Box<dyn Fn(&mut OwnerOperationDeclaration)>;

    #[test]
    #[expect(clippy::too_many_lines, reason = "the test is one table of cases")]
    fn an_incomplete_declaration_is_refused() {
        let cases: Vec<(Change, OwnerDeclarationError)> = vec![
            (
                Box::new(|d| d.executables.clear()),
                OwnerDeclarationError::Executable,
            ),
            (
                Box::new(|d| {
                    d.executables[0].path =
                        LosslessPath::from_bytes(b"/bin/tool".to_vec()).unwrap();
                }),
                OwnerDeclarationError::Executable,
            ),
            (
                Box::new(|d| {
                    d.executables[0] = ExecutableLocation {
                        base: ExecutableBase::Absolute,
                        path: LosslessPath::from_bytes(b"/opt/../bin/tool".to_vec()).unwrap(),
                    };
                }),
                OwnerDeclarationError::Executable,
            ),
            (
                Box::new(|d| d.commands.clear()),
                OwnerDeclarationError::Command,
            ),
            (
                Box::new(|d| {
                    let again = d.commands[0].clone();
                    d.commands.push(again);
                }),
                OwnerDeclarationError::Command,
            ),
            (
                Box::new(|d| {
                    d.commands[0].arguments = vec![ParameterPart::ScopeRoot; 33];
                }),
                OwnerDeclarationError::Command,
            ),
            (
                Box::new(|d| {
                    d.commands[0].arguments = vec![ParameterPart::Literal("a\0b".to_owned())];
                }),
                OwnerDeclarationError::Text,
            ),
            (
                Box::new(|d| d.commands[0].expected_effect.clear()),
                OwnerDeclarationError::Text,
            ),
            (
                Box::new(|d| d.environment[0].name = "home".to_owned()),
                OwnerDeclarationError::Environment,
            ),
            (
                Box::new(|d| {
                    let again = d.environment[0].clone();
                    d.environment.push(again);
                }),
                OwnerDeclarationError::Environment,
            ),
            (
                Box::new(|d| d.environment[0].name = "DYLD_INSERT_LIBRARIES".to_owned()),
                OwnerDeclarationError::Environment,
            ),
            (
                Box::new(|d| d.environment[0].name = "PYTHONPATH".to_owned()),
                OwnerDeclarationError::Environment,
            ),
            (
                Box::new(|d| {
                    d.interpreters = vec![super::InterpreterLocation {
                        location: ExecutableLocation {
                            base: ExecutableBase::Absolute,
                            path: LosslessPath::from_bytes(b"bin/sh".to_vec()).unwrap(),
                        },
                        argument: None,
                    }];
                }),
                OwnerDeclarationError::Executable,
            ),
            (
                Box::new(|d| {
                    d.interpreters = vec![super::InterpreterLocation {
                        location: ExecutableLocation {
                            base: ExecutableBase::Absolute,
                            path: LosslessPath::from_bytes(b"/bin/sh".to_vec()).unwrap(),
                        },
                        argument: Some("-e -x".to_owned()),
                    }];
                }),
                OwnerDeclarationError::Executable,
            ),
            (
                Box::new(|d| d.command_deadline = Nanoseconds::ZERO),
                OwnerDeclarationError::Deadline,
            ),
            (
                Box::new(|d| d.command_deadline = Nanoseconds::new(3_600_000_000_001)),
                OwnerDeclarationError::Deadline,
            ),
        ];
        for (change, expected) in cases {
            let mut declaration = declaration();
            change(&mut declaration);
            assert_eq!(declaration.check(), Err(expected));
        }
    }
}
