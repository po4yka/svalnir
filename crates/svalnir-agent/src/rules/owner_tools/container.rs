//! The inspection of `container.build-cache`: the disk image of each known
//! container engine of the user.
//!
//! On macOS a container engine runs its images, containers, volumes, and
//! build cache in a virtual machine, and keeps them in one disk image. The
//! build cache is thus not a set of files that the inspection can see or
//! measure: only the engine can report it (`docker buildx du`) and remove
//! it (`docker builder prune`). The inspection reports where the disk image
//! is and how much storage it has, and it gives the owner workflow. The
//! disk image is never a unit: it holds persistent volumes and the images
//! in use (`docs/CLEANUP_RULES.md` section 5).
//!
//! The inspection reads the metadata of the disk image only. It runs no
//! `docker` command: the executable and its plug-ins are in directories
//! that the user can change, and the command talks to the engine.

use std::path::PathBuf;

use serde::Serialize;
use svalnir_core::policy::ProtectionFact;
use svalnir_core::quantity::Bytes;
use svalnir_core::rule::{LayoutSupport, RuleRef};

use super::{OwnerToolHost, OwnerToolRules};
use crate::platform::volume::{MountTable, MountTableSource};
use crate::rules::unit::{ObjectKind, WalkStop, walk_local};

/// One known container engine and the documented path of its disk image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ContainerEngine {
    /// The name of the engine.
    pub name: &'static str,
    /// The layout name of the declaration.
    pub layout: &'static str,
    /// The path of the disk image, relative to the home directory.
    pub disk: &'static str,
    /// The owner workflow, as a text for the user. Svalnir does not run it.
    pub owner_workflow: &'static str,
}

/// The engines of this revision. The paths are the documented defaults of
/// each engine; a disk image at another location is not seen.
pub const CONTAINER_ENGINES: [ContainerEngine; 2] = [
    ContainerEngine {
        name: "Docker Desktop",
        layout: "docker-desktop-disk",
        disk: "Library/Containers/com.docker.docker/Data/vms/0/data/Docker.raw",
        owner_workflow: "Run `docker buildx du` to see the build cache, then `docker builder prune` to remove the build cache that no build uses now. It keeps images, containers, and volumes. Do not use `docker system prune --volumes` for this: it removes volumes. Svalnir does not run them. The disk image does not become smaller until Docker Desktop reclaims the space.",
    },
    ContainerEngine {
        name: "Colima",
        layout: "colima-disk",
        disk: ".colima/_lima/colima/diffdisk",
        owner_workflow: "Run `docker buildx du` with the Colima context to see the build cache, then `docker builder prune`. It keeps images, containers, and volumes. Svalnir does not run them. The disk image does not become smaller until the virtual machine trims the free blocks.",
    },
];

/// The result of one disk image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DiskOutcome {
    /// The disk image exists. It is not a unit.
    Present {
        /// `st_size`: the size that the virtual machine sees. A sparse
        /// image is much larger than its storage.
        logical_bytes: Bytes,
        /// `st_blocks * 512`: the storage of the image. The build cache is
        /// an unknown part of it.
        allocated_bytes: Option<Bytes>,
    },
    /// No file is at the path.
    Absent,
    /// The path failed a check. The reason is a stable name.
    Refused {
        /// The reason.
        reason: &'static str,
    },
}

/// One disk image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ContainerDisk {
    /// The name of the engine.
    pub engine: &'static str,
    /// The layout.
    pub layout: &'static str,
    /// The path of the disk image, when the home directory is known.
    pub path: Option<PathBuf>,
    /// The result.
    pub outcome: DiskOutcome,
    /// The owner workflow.
    pub owner_workflow: &'static str,
}

/// The inspection of `container.build-cache`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ContainerInspection {
    /// The exact rule revision.
    pub rule: RuleRef,
    /// Each layout of the declaration with its lifecycle state.
    pub layouts: Vec<LayoutSupport>,
    /// The disk image of each engine, in the sequence of
    /// [`CONTAINER_ENGINES`].
    pub disks: Vec<ContainerDisk>,
}

impl OwnerToolRules {
    /// Inspects the disk image of each known container engine.
    pub fn inspect_container(&self, host: OwnerToolHost<'_>) -> ContainerInspection {
        self.inspect_container_with_mounts(host, MountTable::read)
    }

    /// [`OwnerToolRules::inspect_container`] with another source of the
    /// mount table.
    pub(crate) fn inspect_container_with_mounts(
        &self,
        host: OwnerToolHost<'_>,
        mounts: MountTableSource,
    ) -> ContainerInspection {
        let rule = self.container();
        let table: Option<MountTable> = mounts().ok();
        let disks: Vec<ContainerDisk> = CONTAINER_ENGINES
            .iter()
            .map(|engine| {
                let path: Option<PathBuf> = host
                    .locations
                    .home_directory()
                    .map(|home| home.join(engine.disk));
                let outcome: DiskOutcome = match (&path, &table) {
                    (None, _) => DiskOutcome::Refused {
                        reason: "home_unknown",
                    },
                    (Some(_), None) => DiskOutcome::Refused {
                        reason: "root_locality_unknown",
                    },
                    (Some(path), Some(table)) => disk(host, path, table),
                };
                ContainerDisk {
                    engine: engine.name,
                    layout: engine.layout,
                    path,
                    outcome,
                    owner_workflow: engine.owner_workflow,
                }
            })
            .collect();
        ContainerInspection {
            rule: rule.reference.clone(),
            layouts: rule.layouts.clone(),
            disks,
        }
    }
}

/// The metadata of the disk image at `path`.
fn disk(host: OwnerToolHost<'_>, path: &std::path::Path, mounts: &MountTable) -> DiskOutcome {
    let refused = |reason: &'static str| DiskOutcome::Refused { reason };
    if host.locations.of_text(path) != ProtectionFact::NotProtected {
        return refused("path_protected");
    }
    match walk_local(path, mounts) {
        Ok(snapshot) if snapshot.kind == ObjectKind::RegularFile => {
            if snapshot.owner != host.principal {
                return refused("disk_owner");
            }
            DiskOutcome::Present {
                logical_bytes: Bytes::new(snapshot.size),
                allocated_bytes: snapshot.allocated.map(Bytes::new),
            }
        }
        Ok(snapshot) if snapshot.kind == ObjectKind::SymbolicLink => refused("disk_symbolic_link"),
        Ok(_) => refused("disk_not_regular_file"),
        Err(WalkStop::Absent) => DiskOutcome::Absent,
        Err(WalkStop::LinkInAncestor) => refused("path_not_plain"),
        Err(WalkStop::NotLocal) => refused("disk_not_local"),
        Err(WalkStop::LocalityUnknown) => refused("disk_locality_unknown"),
        Err(WalkStop::Failed(_)) => refused("disk_not_readable"),
    }
}
