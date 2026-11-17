//! The reasons that leave an entry out of a manual plan.

use serde::{Deserialize, Serialize};

use super::context::SizeEstimate;
use crate::action::{ErrorFamily, WorkCharge};
use crate::file::LosslessPath;
use crate::id::TargetId;
use crate::rule::EligibilityPredicate;

/// One stable reason that an entry is not in a plan
/// (`docs/CLEANUP_RULES.md` section 13).
///
/// JSON encodes the reason as an object with a `reason` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
#[non_exhaustive]
pub enum OmissionReason {
    /// The target has a hard protection. No mode, preset, grant, or force
    /// strategy removes it.
    HardProtected,
    /// A path of `[protections].excluded_paths` is the entry, contains the
    /// entry, or is inside the entry.
    ExcludedPath,
    /// A process claims a bundle identifier of
    /// `[protections].protected_bundle_ids`.
    ProtectedBundleId,
    /// An executable is at or below a path of
    /// `[protections].protected_executable_paths`.
    ProtectedExecutablePath,
    /// The owner is a different user than the principal of the plan.
    OtherUser,
    /// The type of the object is one that this build does not recognize, or
    /// one that the rule does not remove.
    ObjectTypeNotSupported,
    /// The selection preset does not include the entry. A preset only
    /// filters.
    NotInPreset,
    /// The entry has no evidence of the exact rule revision of the plan.
    RuleNotSelected,
    /// The rule revision does not support the layout of the entry.
    LayoutNotSupported,
    /// The rule revision is not validated for manual eviction of the
    /// layout.
    ModeNotValidated,
    /// A protected descendant of the rule is the entry, contains the entry,
    /// or is inside the entry.
    RuleExclusion,
    /// The evidence shows that an eligibility predicate of the rule does
    /// not hold.
    EligibilityNotSatisfied {
        /// The predicate.
        predicate: EligibilityPredicate,
    },
    /// The processes are not the verified members of one instance.
    MembershipNotVerified,
    /// The entry has no item.
    NoItems,
    /// The entry is the same path as a different selected entry, or is
    /// inside it. A parent and a descendant are not two removals.
    OverlapsSelectedEntry,
    /// A path of the configuration starts from the home directory, and no
    /// usable home directory was given.
    HomeDirectoryUnknown,
    /// A path is not absolute and canonical, or the path and the relative
    /// entry of the binding do not agree.
    PathNotCanonical,
    /// The hard protection of the target is not known.
    ProtectionUnknown,
    /// The owner of the entry is not known.
    OwnerUnknown,
    /// The configuration protects executable paths, and a process has no
    /// executable evidence.
    ExecutableUnknown,
    /// The evidence does not establish an eligibility predicate of the
    /// rule.
    EligibilityUnknown {
        /// The predicate.
        predicate: EligibilityPredicate,
    },
    /// The work charge of the entry is not known. An unknown charge is not
    /// zero.
    WorkChargeUnknown,
    /// The charge is larger than the candidate ceiling of the rule.
    ExceedsCandidateCeiling,
    /// The charge is larger than the ceiling of one batch. An entry is
    /// indivisible.
    ExceedsBatchLimit,
    /// The charge does not fit in what remains of the plan ceiling.
    ExceedsPlanLimit,
}

impl OmissionReason {
    /// The error family of the reason (`docs/ACTION_CONTRACTS.md`
    /// section 10): `eligibility` for a protection, an exclusion, or a
    /// target that the mode does not support, `evidence` for a fact that is
    /// not known, and `limits` for a ceiling.
    pub const fn family(&self) -> ErrorFamily {
        match self {
            Self::HardProtected
            | Self::ExcludedPath
            | Self::ProtectedBundleId
            | Self::ProtectedExecutablePath
            | Self::OtherUser
            | Self::ObjectTypeNotSupported
            | Self::NotInPreset
            | Self::RuleNotSelected
            | Self::LayoutNotSupported
            | Self::ModeNotValidated
            | Self::RuleExclusion
            | Self::EligibilityNotSatisfied { .. }
            | Self::NoItems
            | Self::OverlapsSelectedEntry => ErrorFamily::Eligibility,
            Self::MembershipNotVerified
            | Self::HomeDirectoryUnknown
            | Self::PathNotCanonical
            | Self::ProtectionUnknown
            | Self::OwnerUnknown
            | Self::ExecutableUnknown
            | Self::EligibilityUnknown { .. }
            | Self::WorkChargeUnknown => ErrorFamily::Evidence,
            Self::ExceedsCandidateCeiling | Self::ExceedsBatchLimit | Self::ExceedsPlanLimit => {
                ErrorFamily::Limits
            }
        }
    }
}

/// Adds a reason to the list when the list does not have it.
pub(super) fn push_reason(reasons: &mut Vec<OmissionReason>, reason: OmissionReason) {
    if !reasons.contains(&reason) {
        reasons.push(reason);
    }
}

/// One entry that a plan does not have, with each reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Omission {
    /// The identity of the target.
    pub target_id: TargetId,
    /// The path of a file entry, for display. An application has none.
    pub path: Option<LosslessPath>,
    /// Each reason, in the sequence of the checks. The list is not empty.
    pub reasons: Vec<OmissionReason>,
    /// The admission charge of a file entry, when it is known.
    pub charge: Option<WorkCharge>,
    /// The size estimates of a file entry.
    pub estimate: SizeEstimate,
}
