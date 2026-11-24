//! The catalog of protected file locations, applied to the entries of the
//! host.
//!
//! Owning specification: `docs/CLEANUP_RULES.md` section 5. The catalog of
//! `svalnir-core` ([`file_hard_protection`]) compares the text of paths.
//! This module gives it the paths of the host: the home directory and the
//! state directory with their symbolic links resolved, and the forms of the
//! path of one entry.
//!
//! Three callers use one implementation, so that a plan gets the same
//! answer at each of them: the client that builds a manual plan, the
//! discovery of a rule, and the coordinator at admission.
//!
//! A function of this module reads the names of the filesystem
//! (`realpath`). It changes nothing.

use std::path::{Path, PathBuf};

use svalnir_core::action::FileBinding;
use svalnir_core::file::LosslessPath;
use svalnir_core::policy::{FileProtectionContext, ProtectionFact, file_hard_protection};

use crate::platform::volume::{Locality, MountTable};

/// The locations of the user and of the control plane that the catalog
/// protects, each with its symbolic links resolved.
///
/// A location that did not resolve is `None`. The catalog then gives
/// [`ProtectionFact::Unknown`] for an entry that no other rule protects,
/// and each plan leaves such an entry out.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProtectedLocations {
    home_directory: Option<PathBuf>,
    state_directory: Option<PathBuf>,
}

impl ProtectedLocations {
    /// Resolves the home directory of the user and the state directory of
    /// Svalnir. A path that is absent or that does not resolve gives no
    /// location.
    #[must_use]
    pub fn resolve(home_directory: Option<&Path>, state_directory: Option<&Path>) -> Self {
        let resolved = |path: Option<&Path>| path.and_then(|path| std::fs::canonicalize(path).ok());
        Self {
            home_directory: resolved(home_directory),
            state_directory: resolved(state_directory),
        }
    }

    /// The locations from paths that the caller resolved before. A path
    /// with a symbolic link gives a comparison with a text that is not the
    /// location, so only a caller with resolved paths uses this function.
    #[must_use]
    pub const fn from_resolved(
        home_directory: Option<PathBuf>,
        state_directory: Option<PathBuf>,
    ) -> Self {
        Self {
            home_directory,
            state_directory,
        }
    }

    /// The home directory, with its symbolic links resolved.
    #[must_use]
    pub fn home_directory(&self) -> Option<&Path> {
        self.home_directory.as_deref()
    }

    /// The state directory, with its symbolic links resolved.
    #[must_use]
    pub fn state_directory(&self) -> Option<&Path> {
        self.state_directory.as_deref()
    }

    /// The fact of the catalog for the text of `path`. The caller resolved
    /// the symbolic links of the path; this function makes no call on the
    /// filesystem.
    #[must_use]
    pub fn of_text(&self, path: &Path) -> ProtectionFact {
        let lossless = |path: &Path| LosslessPath::from_path(path).ok();
        let Some(path) = lossless(path) else {
            return ProtectionFact::Unknown;
        };
        let home: Option<LosslessPath> = self.home_directory.as_deref().and_then(lossless);
        let state: Option<LosslessPath> = self.state_directory.as_deref().and_then(lossless);
        file_hard_protection(
            &path,
            &FileProtectionContext {
                home_directory: home.as_ref(),
                state_directory: state.as_ref(),
            },
        )
    }

    /// The hard protection of the entry at `path`, for two forms of its
    /// path:
    ///
    /// - Its own location: the directory of the entry with its symbolic
    ///   links resolved, and the name of the entry. A link in a protected
    ///   location is thus protected, also when it points out of it.
    /// - Its resolved form, with the entry itself resolved. A link whose
    ///   target is a protected location is thus protected also.
    ///
    /// The entry is protected when one form is protected. It is not
    /// protected only when the two forms are not protected. An entry whose
    /// directory does not resolve, or that does not resolve itself (a link
    /// with no target, or an entry that is absent), has an unknown
    /// protection.
    #[must_use]
    pub fn of_entry(&self, path: &Path) -> ProtectionFact {
        let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
            return ProtectionFact::Unknown;
        };
        let fact_of = |resolved: std::io::Result<PathBuf>| {
            resolved.map_or(ProtectionFact::Unknown, |form| self.of_text(&form))
        };
        let own_location: ProtectionFact =
            fact_of(std::fs::canonicalize(parent).map(|directory| directory.join(name)));
        let resolved: ProtectionFact = fact_of(std::fs::canonicalize(path));
        strictest(own_location, resolved)
    }

    /// The hard protection of the file target `file` of a plan, for the
    /// coordinator at admission.
    ///
    /// The entry is the root path of the binding and then its relative
    /// entry. The text of that path is examined in each case. When
    /// `mounts` reports the root path on a local filesystem, the two forms
    /// of [`ProtectedLocations::of_entry`] are examined also. For a root
    /// on a filesystem that is not local, or whose locality is not known,
    /// the function makes no call on the path: the filesystem executor
    /// refuses such a root before its first call
    /// (`docs/ACTION_CONTRACTS.md` section 7).
    ///
    /// A form that does not exist gives no fact, and the other forms
    /// decide: an entry that is absent at admission is not removed, and
    /// the executor compares the object of each entry with the plan before
    /// its call. A form that fails for a different cause, for example a
    /// directory that cannot be searched, gives an unknown protection.
    #[must_use]
    pub fn of_binding(&self, file: &FileBinding, mounts: Option<&MountTable>) -> ProtectionFact {
        let root: PathBuf = file.root_path.to_path_buf();
        let relative: PathBuf = file.relative_entry.to_path_buf();
        let is_plain: bool = relative
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
            && relative.components().next().is_some();
        if !root.is_absolute() || !is_plain {
            return ProtectionFact::Unknown;
        }
        let path: PathBuf = root.join(&relative);
        let text: ProtectionFact = self.of_text(&path);
        let is_local: bool =
            mounts.is_some_and(|mounts| mounts.path_locality(&root) == Locality::Local);
        if text == ProtectionFact::Protected || !is_local {
            return text;
        }
        let fact_of = |resolved: std::io::Result<PathBuf>| match resolved {
            Ok(form) => self.of_text(&form),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                ProtectionFact::NotProtected
            }
            Err(_) => ProtectionFact::Unknown,
        };
        let own_location: ProtectionFact = match (path.parent(), path.file_name()) {
            (Some(parent), Some(name)) => {
                fact_of(std::fs::canonicalize(parent).map(|directory| directory.join(name)))
            }
            _ => ProtectionFact::Unknown,
        };
        let resolved: ProtectionFact = fact_of(std::fs::canonicalize(&path));
        strictest(text, strictest(own_location, resolved))
    }

    /// The hard protection of the scope root `root` of an owner operation,
    /// for the coordinator at admission (`docs/ACTION_CONTRACTS.md`
    /// section 4). The rules of [`ProtectedLocations::of_binding`] apply,
    /// with the scope root as the entry.
    #[must_use]
    pub fn of_scope_root(&self, root: &Path, mounts: Option<&MountTable>) -> ProtectionFact {
        if !root.is_absolute() {
            return ProtectionFact::Unknown;
        }
        let text: ProtectionFact = self.of_text(root);
        let is_local: bool =
            mounts.is_some_and(|mounts| mounts.path_locality(root) == Locality::Local);
        if text == ProtectionFact::Protected || !is_local {
            return text;
        }
        strictest(text, self.of_entry(root))
    }
}

/// The stricter of two facts: protected, then unknown, then not protected.
fn strictest(first: ProtectionFact, second: ProtectionFact) -> ProtectionFact {
    match (first, second) {
        (ProtectionFact::Protected, _) | (_, ProtectionFact::Protected) => {
            ProtectionFact::Protected
        }
        (ProtectionFact::NotProtected, ProtectionFact::NotProtected) => {
            ProtectionFact::NotProtected
        }
        _ => ProtectionFact::Unknown,
    }
}

/// The two forms of [`ProtectedLocations::of_entry`] that resolve: the own
/// location and the resolved form. The plan builder applies the
/// `[protections]` list to them as well as to the path of the entry.
#[must_use]
pub fn resolved_forms(path: &Path) -> Vec<LosslessPath> {
    let own_location: Option<PathBuf> = match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) => std::fs::canonicalize(parent)
            .ok()
            .map(|directory| directory.join(name)),
        _ => None,
    };
    let mut forms: Vec<LosslessPath> = Vec::new();
    for form in [own_location, std::fs::canonicalize(path).ok()]
        .into_iter()
        .flatten()
    {
        if let Ok(form) = LosslessPath::from_path(&form)
            && !forms.contains(&form)
        {
            forms.push(form);
        }
    }
    forms
}

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::{Path, PathBuf};

    use svalnir_core::action::{FileBinding, FileObjectType, WorkCharge};
    use svalnir_core::file::{DeviceNumber, FileObjectEvidence, InodeNumber, LosslessPath};
    use svalnir_core::id::{MountId, RootId, VolumeId};
    use svalnir_core::policy::ProtectionFact;
    use svalnir_core::process::Uid;

    use super::ProtectedLocations;
    use crate::platform::volume::MountTable;

    /// A temporary directory with a home directory, a state directory in
    /// it, and a cache root. Each path has its symbolic links resolved.
    struct Tree {
        _directory: tempfile::TempDir,
        home: PathBuf,
        state: PathBuf,
        root: PathBuf,
    }

    fn tree() -> Tree {
        let directory = tempfile::tempdir().unwrap();
        let base: PathBuf = fs::canonicalize(directory.path()).unwrap();
        let home: PathBuf = base.join("home");
        let state: PathBuf = home.join("state");
        let root: PathBuf = home.join("cache");
        for path in [&home, &state, &root] {
            fs::create_dir(path).unwrap();
        }
        Tree {
            _directory: directory,
            home,
            state,
            root,
        }
    }

    fn locations(tree: &Tree) -> ProtectedLocations {
        ProtectedLocations::resolve(Some(&tree.home), Some(&tree.state))
    }

    fn binding(root: &Path, relative: &str) -> FileBinding {
        FileBinding {
            root_id: RootId::new("root-1").unwrap(),
            root_path: LosslessPath::from_path(root).unwrap(),
            root_object: FileObjectEvidence {
                device: DeviceNumber::new(1),
                inode: InodeNumber::new(2),
            },
            relative_entry: LosslessPath::from_bytes(relative).unwrap(),
            volume_id: VolumeId::new("volume-1").unwrap(),
            mount_id: MountId::new("mount-1").unwrap(),
            object_type: FileObjectType::Directory,
            owner: Uid::new(501),
            object: None,
            rule: None,
            layout: None,
            charge: WorkCharge::ZERO,
            repositories: Vec::new(),
        }
    }

    #[test]
    fn an_entry_below_the_home_directory_is_not_protected() {
        let tree = tree();
        fs::write(tree.root.join("unit"), b"x").unwrap();
        let mounts = MountTable::read().unwrap();
        assert_eq!(
            locations(&tree).of_binding(&binding(&tree.root, "unit"), Some(&mounts)),
            ProtectionFact::NotProtected
        );
    }

    #[test]
    fn the_state_directory_and_the_home_directory_are_protected() {
        let tree = tree();
        let mounts = MountTable::read().unwrap();
        let locations = locations(&tree);
        fs::write(tree.state.join("operations.sqlite"), b"x").unwrap();
        // An entry of the state directory.
        assert_eq!(
            locations.of_binding(&binding(&tree.state, "operations.sqlite"), Some(&mounts)),
            ProtectionFact::Protected
        );
        // The state directory as an entry of the home directory.
        assert_eq!(
            locations.of_binding(&binding(&tree.home, "state"), Some(&mounts)),
            ProtectionFact::Protected
        );
        // The home directory as an entry of the directory above it.
        let above: &Path = tree.home.parent().unwrap();
        assert_eq!(
            locations.of_binding(&binding(above, "home"), Some(&mounts)),
            ProtectionFact::Protected
        );
    }

    #[test]
    fn a_link_to_a_protected_location_is_protected() {
        let tree = tree();
        symlink(&tree.state, tree.root.join("link")).unwrap();
        let mounts = MountTable::read().unwrap();
        assert_eq!(
            locations(&tree).of_binding(&binding(&tree.root, "link"), Some(&mounts)),
            ProtectionFact::Protected
        );
    }

    #[test]
    fn an_absent_entry_has_the_fact_of_the_forms_that_exist() {
        let tree = tree();
        let mounts = MountTable::read().unwrap();
        let locations = locations(&tree);
        // The text and the directory of the entry decide.
        assert_eq!(
            locations.of_binding(&binding(&tree.root, "absent"), Some(&mounts)),
            ProtectionFact::NotProtected
        );
        assert_eq!(
            locations.of_binding(&binding(&tree.state, "absent"), Some(&mounts)),
            ProtectionFact::Protected
        );
        // A client that builds a plan needs each form.
        assert_eq!(
            locations.of_entry(&tree.root.join("absent")),
            ProtectionFact::Unknown
        );
    }

    #[test]
    fn a_directory_that_cannot_be_searched_gives_an_unknown_protection() {
        use std::os::unix::fs::PermissionsExt as _;

        let tree = tree();
        let closed = tree.root.join("closed");
        fs::create_dir(&closed).unwrap();
        fs::write(closed.join("unit"), b"x").unwrap();
        fs::set_permissions(&closed, fs::Permissions::from_mode(0o000)).unwrap();
        let mounts = MountTable::read().unwrap();
        let fact = locations(&tree).of_binding(&binding(&tree.root, "closed/unit"), Some(&mounts));
        fs::set_permissions(&closed, fs::Permissions::from_mode(0o700)).unwrap();
        // The superuser can search each directory.
        // SAFETY: `geteuid` has no argument, changes nothing, and does not
        // fail.
        if unsafe { libc::geteuid() } != 0 {
            assert_eq!(fact, ProtectionFact::Unknown);
        }
    }

    #[test]
    fn a_location_that_is_not_known_gives_an_unknown_protection() {
        let tree = tree();
        fs::write(tree.root.join("unit"), b"x").unwrap();
        let mounts = MountTable::read().unwrap();
        let no_state = ProtectedLocations::resolve(Some(&tree.home), None);
        assert_eq!(
            no_state.of_binding(&binding(&tree.root, "unit"), Some(&mounts)),
            ProtectionFact::Unknown
        );
        let no_home = ProtectedLocations::resolve(None, Some(&tree.state));
        assert_eq!(
            no_home.of_binding(&binding(&tree.root, "unit"), Some(&mounts)),
            ProtectionFact::Unknown
        );
    }

    #[test]
    fn a_relative_entry_that_is_not_plain_has_an_unknown_protection() {
        let tree = tree();
        let mounts = MountTable::read().unwrap();
        let mut file = binding(&tree.root, "unit");
        file.relative_entry = LosslessPath::from_bytes("../state").unwrap();
        assert_eq!(
            locations(&tree).of_binding(&file, Some(&mounts)),
            ProtectionFact::Unknown
        );
    }

    #[test]
    fn with_no_mount_table_only_the_text_is_examined() {
        let tree = tree();
        // The link resolves to the state directory. With no mount table,
        // the function makes no call, so only the text is the evidence.
        symlink(&tree.state, tree.root.join("link")).unwrap();
        assert_eq!(
            locations(&tree).of_binding(&binding(&tree.root, "link"), None),
            ProtectionFact::NotProtected
        );
        assert_eq!(
            locations(&tree).of_binding(&binding(&tree.home, "state"), None),
            ProtectionFact::Protected
        );
    }
}
