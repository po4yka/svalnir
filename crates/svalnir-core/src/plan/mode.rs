//! The mode of a manual plan.

use serde::{Deserialize, Serialize};

use crate::action::{ActionClass, Escalation, OwnerOperationKind, PlanContent, TargetBinding};
use crate::rule::RuleMode;

/// A manual cleanup mode of the CLI (`docs/INTERFACES.md` section 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupMode {
    /// `trash`: move the selected entries to Trash (`MoveToTrash`).
    Trash,
    /// `permanent`: remove the selected entries permanently
    /// (`DeleteSelectedFiles`).
    Permanent,
    /// `evict`: remove the candidates of one exact rule revision
    /// permanently (`EvictRegenerableData`).
    Evict,
}

impl CleanupMode {
    /// Each mode, in the sequence of the specification.
    pub const ALL: [Self; 3] = [Self::Trash, Self::Permanent, Self::Evict];

    /// The spelling of the mode in a command.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Trash => "trash",
            Self::Permanent => "permanent",
            Self::Evict => "evict",
        }
    }

    /// Finds the mode for its spelling.
    pub fn from_text(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|mode| mode.as_str() == text)
    }

    /// The action class of each step of a plan of this mode.
    pub const fn action_class(self) -> ActionClass {
        match self {
            Self::Trash => ActionClass::MoveToTrash,
            Self::Permanent => ActionClass::DeleteSelectedFiles,
            Self::Evict => ActionClass::EvictRegenerableData,
        }
    }

    /// The rule mode that a rule revision must be validated for. Only the
    /// `evict` mode needs a rule.
    pub const fn rule_mode(self) -> Option<RuleMode> {
        match self {
            Self::Trash | Self::Permanent => None,
            Self::Evict => Some(RuleMode::ManualEviction),
        }
    }
}

impl std::fmt::Display for CleanupMode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The force strategy of a manual application stop, without its durations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopKind {
    /// A graceful request only.
    Graceful,
    /// A graceful request, and a force step after the grace period if the
    /// target is running.
    ForceAfterGrace,
    /// An immediate force step with no graceful step.
    ImmediateForce,
}

impl StopKind {
    /// The force strategy of the plan limits.
    pub const fn escalation(self) -> Escalation {
        match self {
            Self::Graceful => Escalation::None,
            Self::ForceAfterGrace => Escalation::ForceAfterGrace,
            Self::ImmediateForce => Escalation::ImmediateForce,
        }
    }
}

/// The mode of a manual plan: what an approval of the plan consents to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "mode", rename_all = "snake_case")]
pub enum PlanMode {
    /// A cleanup plan.
    Cleanup(CleanupMode),
    /// An application stop plan.
    Stop(StopKind),
    /// A plan of owner operations of one kind (`RunOwnerOperation`).
    Owner(OwnerOperationKind),
}

/// The mode of a plan content.
///
/// The result is `None` when the content has no step, has a value that this
/// build does not recognize, mixes action classes, or has steps that do
/// not agree with its force strategy. A sealed plan always
/// has a mode, because the check of the plan rejects each of these cases.
pub fn mode_of(plan: &PlanContent) -> Option<PlanMode> {
    let first: &ActionClass = &plan.steps.first()?.action_class;
    if first.is_filesystem() {
        if plan.steps.iter().any(|step| &step.action_class != first) {
            return None;
        }
        let mode: CleanupMode = match first {
            ActionClass::MoveToTrash => CleanupMode::Trash,
            ActionClass::DeleteSelectedFiles => CleanupMode::Permanent,
            ActionClass::EvictRegenerableData => CleanupMode::Evict,
            ActionClass::RunOwnerOperation => return owner_mode(plan),
            _ => return None,
        };
        return Some(PlanMode::Cleanup(mode));
    }
    if !plan
        .steps
        .iter()
        .all(|step| step.action_class.is_application_intervention())
    {
        return None;
    }
    let kind: StopKind = match plan.limits.escalation {
        Escalation::None => StopKind::Graceful,
        Escalation::ForceAfterGrace => StopKind::ForceAfterGrace,
        Escalation::ImmediateForce => StopKind::ImmediateForce,
        Escalation::Unrecognized(_) => return None,
    };
    // The steps agree with the force strategy: a force step exists exactly
    // when the strategy has one, and a graceful step exactly when the
    // strategy has one.
    let has = |class: &ActionClass| plan.steps.iter().any(|step| &step.action_class == class);
    let has_graceful: bool = has(&ActionClass::RequestApplicationExit);
    let has_force: bool = has(&ActionClass::ForceApplicationExit);
    let steps_agree: bool = match kind {
        StopKind::Graceful => has_graceful && !has_force,
        StopKind::ForceAfterGrace => has_graceful && has_force,
        StopKind::ImmediateForce => !has_graceful && has_force,
    };
    steps_agree.then_some(PlanMode::Stop(kind))
}

/// The mode of a plan of owner operations: the one kind of its targets.
/// `None` when a target is not an owner operation or when two targets
/// have different kinds.
fn owner_mode(plan: &PlanContent) -> Option<PlanMode> {
    let mut kind: Option<OwnerOperationKind> = None;
    for target in &plan.targets {
        let TargetBinding::OwnerOperation(owner) = &target.binding else {
            return None;
        };
        if kind.is_some_and(|first| first != owner.operation) {
            return None;
        }
        kind = Some(owner.operation);
    }
    kind.map(PlanMode::Owner)
}
