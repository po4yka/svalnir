//! The rules of the data that only its owner tool can remove
//! (`docs/CLEANUP_RULES.md` sections 9 and 12): `simulator.devices`,
//! `container.build-cache`, and `homebrew.cleanup`.
//!
//! Each rule has the inspection mode only, and each of its layouts is
//! `proposed`. The removal of this data is a producer-supported operation
//! whose effect Svalnir cannot bound (`xcrun simctl delete`, `docker
//! builder prune`, `brew cleanup`), so it stays a manual owner workflow:
//! the inspection attributes the data from the documented on-disk layout
//! and gives the exact command that a person can run. This build runs no
//! producer tool, also no read-only query: `simctl list` starts the
//! simulator service, and the `docker` and `brew` executables are in
//! directories that the user can change.
//!
//! A rule of this module finds no candidate, has no discovery for an
//! eviction, and removes nothing. Simulator contents, persistent container
//! volumes, images in use, the disk image of a container engine, and the
//! installed kegs of the Cellar and the Caskroom are never a unit.

mod bplist;
mod container;
mod homebrew;
mod simulator;

#[cfg(test)]
mod tests;

use std::path::PathBuf;

use svalnir_core::action::{Checked, ExecutorRole, FileObjectType, WorkCharge};
use svalnir_core::file::LosslessPath;
use svalnir_core::id::{RuleId, RuleRevisionId};
use svalnir_core::policy::RebuildCost;
use svalnir_core::process::Uid;
use svalnir_core::quantity::{Bytes, EntryCount, Nanoseconds};
use svalnir_core::rule::{
    ActivityCheck, ActivityProtocol, AgeBasis, ApprovedRoot, DeletionMethod, LayoutSupport,
    LifecycleState, OwnerAttribution, Retention, RootBase, Rule, RuleBudget, RuleDeclaration,
    RuleExclusions, RuleMode, RuleOwner, RuleRef,
};

pub use container::{
    CONTAINER_ENGINES, ContainerDisk, ContainerEngine, ContainerInspection, DiskOutcome,
};
pub use homebrew::{
    HOMEBREW_PREFIXES, HomebrewInspection, HomebrewKeg, HomebrewPrefixReport, KegOutcome,
    PrefixOutcome,
};
pub use simulator::{
    DeviceOutcome, DeviceState, RuntimeLocation, SimulatorDevice, SimulatorInspection,
    SimulatorLocations, SimulatorRuntime,
};

use super::projects::ProcessEvidence;
use super::registry::RegistryError;
use crate::protection::ProtectedLocations;

/// The revision of each rule of this module.
pub const OWNER_TOOL_RULE_REVISION: &str = "r1";

/// The identity of the rule for simulator devices and runtimes.
pub const SIMULATOR_RULE_ID: &str = "simulator.devices";
/// The identity of the rule for the build cache of a container engine.
pub const CONTAINER_RULE_ID: &str = "container.build-cache";
/// The identity of the rule for the old versions of Homebrew.
pub const HOMEBREW_CLEANUP_RULE_ID: &str = "homebrew.cleanup";

/// The host facts of an inspection of this module.
#[derive(Clone, Copy)]
#[expect(
    missing_debug_implementations,
    reason = "the process evidence is a trait object with no `Debug` bound"
)]
pub struct OwnerToolHost<'a> {
    /// The user. Each directory that the inspection reads must have this
    /// owner, except a system location of the producer.
    pub principal: Uid,
    /// The home directory and the state directory, resolved.
    pub locations: &'a ProtectedLocations,
    /// The paths of `[protections]` and of the disk guard exclusions.
    pub user_exclusions: &'a [PathBuf],
    /// The process evidence.
    pub processes: &'a dyn ProcessEvidence,
}

/// The reviewed facts of one rule of this module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OwnerToolSpec {
    id: &'static str,
    producer: &'static str,
    layouts: &'static [&'static str],
    roots: &'static [(RootBase, &'static str)],
    rebuild_cost: RebuildCost,
}

const SPECS: [OwnerToolSpec; 3] = [
    OwnerToolSpec {
        id: SIMULATOR_RULE_ID,
        producer: "coresimulator",
        layouts: &["coresimulator-device", "coresimulator-runtime"],
        roots: &[
            (
                RootBase::UserHome,
                "Library/Developer/CoreSimulator/Devices",
            ),
            (
                RootBase::ProducerInstallation,
                "Library/Developer/CoreSimulator/Profiles/Runtimes",
            ),
        ],
        rebuild_cost: RebuildCost::High,
    },
    OwnerToolSpec {
        id: CONTAINER_RULE_ID,
        producer: "container-engine",
        layouts: &["docker-desktop-disk", "colima-disk"],
        roots: &[
            (
                RootBase::UserHome,
                "Library/Containers/com.docker.docker/Data",
            ),
            (RootBase::UserHome, ".colima"),
        ],
        rebuild_cost: RebuildCost::Medium,
    },
    OwnerToolSpec {
        id: HOMEBREW_CLEANUP_RULE_ID,
        producer: "homebrew",
        layouts: &["homebrew-cellar-keg"],
        roots: &[(RootBase::ProducerInstallation, "Cellar")],
        rebuild_cost: RebuildCost::Low,
    },
];

const MINUTE: u64 = 60_000_000_000;
const DAY: u64 = 86_400_000_000_000;
const GIBIBYTE: u64 = 1 << 30;

/// The declaration of the rule of `spec`. Each layout is `proposed`, the
/// implementation has the inspection mode only, and the deletion method
/// is the operation of the producer, which this build does not run.
///
/// The retention, the activity windows, and the budget are values of a
/// proposed rule. No promotion record confirms them (section 3).
fn declaration(spec: &OwnerToolSpec) -> Result<RuleDeclaration, RegistryError> {
    let path = |text: &str| {
        LosslessPath::from_bytes(text).map_err(|_| RegistryError::Declaration("a path"))
    };
    Ok(RuleDeclaration {
        reference: RuleRef {
            id: RuleId::new(spec.id)
                .map_err(|_| RegistryError::Declaration("the rule identity"))?,
            revision: RuleRevisionId::new(OWNER_TOOL_RULE_REVISION)
                .map_err(|_| RegistryError::Declaration("the rule revision"))?,
        },
        owner: RuleOwner {
            producer: spec.producer.to_owned(),
            attribution: OwnerAttribution::ProducerLayout,
        },
        layouts: spec
            .layouts
            .iter()
            .map(|layout| LayoutSupport {
                layout: (*layout).to_owned(),
                lifecycle: LifecycleState::Proposed,
            })
            .collect(),
        roots: spec
            .roots
            .iter()
            .map(|(base, relative)| {
                Ok(ApprovedRoot {
                    base: base.clone(),
                    relative: path(relative)?,
                })
            })
            .collect::<Result<Vec<ApprovedRoot>, RegistryError>>()?,
        retention: Retention {
            age_basis: AgeBasis::FilesystemMetadata,
            minimum_age: Nanoseconds::new(7 * DAY),
        },
        activity: ActivityProtocol {
            checks: vec![ActivityCheck::ProducerProcessAbsent],
            quiescence: Nanoseconds::new(10 * MINUTE),
            evidence_expiry: Nanoseconds::new(30_000_000_000),
        },
        exclusions: RuleExclusions {
            descendants: Vec::new(),
            supported_object_types: vec![FileObjectType::Directory],
            skip_hard_linked: true,
        },
        modes: vec![RuleMode::Inspection],
        deletion_method: DeletionMethod::ProducerOperation,
        executor: ExecutorRole::User,
        rebuild_cost: spec.rebuild_cost,
        budget: RuleBudget {
            per_candidate: WorkCharge::new(Bytes::new(50 * GIBIBYTE), EntryCount::new(2_000_000)),
            per_pass: WorkCharge::new(Bytes::new(100 * GIBIBYTE), EntryCount::new(4_000_000)),
            measurement_expiry: Nanoseconds::new(10 * MINUTE),
        },
    })
}

/// The checked declarations of the rules of this module.
#[derive(Debug, Clone)]
pub struct OwnerToolRules {
    simulator: Rule,
    container: Rule,
    homebrew: Rule,
}

impl OwnerToolRules {
    /// Makes the rules with the declarations of this build.
    ///
    /// # Errors
    ///
    /// Returns a [`RegistryError`] when a declaration is not complete.
    pub(super) fn new() -> Result<Self, RegistryError> {
        let [simulator, container, homebrew] = SPECS;
        let check = |spec: &OwnerToolSpec| -> Result<Rule, RegistryError> {
            Checked::new(declaration(spec)?).map_err(RegistryError::Incomplete)
        };
        Ok(Self {
            simulator: check(&simulator)?,
            container: check(&container)?,
            homebrew: check(&homebrew)?,
        })
    }

    /// The declaration of `simulator.devices`.
    pub fn simulator(&self) -> &Rule {
        &self.simulator
    }

    /// The declaration of `container.build-cache`.
    pub fn container(&self) -> &Rule {
        &self.container
    }

    /// The declaration of `homebrew.cleanup`.
    pub fn homebrew(&self) -> &Rule {
        &self.homebrew
    }

    /// The three declarations, in the sequence of the specification.
    pub fn rules(&self) -> [&Rule; 3] {
        [&self.simulator, &self.container, &self.homebrew]
    }
}
