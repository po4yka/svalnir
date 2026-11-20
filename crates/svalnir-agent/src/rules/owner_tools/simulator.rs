//! The inspection of `simulator.devices`: the simulator devices of the
//! user and the installed simulator runtimes, from the on-disk layout of
//! `CoreSimulator`.
//!
//! The inspection reads the `device.plist` of each device directory (an
//! XML property list, or the binary form) and
//! the names of the runtime bundles. It runs no `simctl` command: `simctl
//! list` starts the simulator service of the user, which is not a read of
//! the disk. The removal is `xcrun simctl delete` or `xcrun simctl runtime
//! delete`, which a person runs.

use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;
use svalnir_core::policy::ProtectionFact;
use svalnir_core::rule::{LayoutSupport, RuleRef};

use super::bplist::{Scalar, parse_dictionary};
use super::{OwnerToolHost, OwnerToolRules};
use crate::platform::volume::{MountTable, MountTableSource};
use crate::rules::caches::{CacheMeasurement, InspectionLimits, ReclaimBasis, measure_unit};
use crate::rules::plist::parse_scalar_dictionary;
use crate::rules::unit::{ObjectKind, RecordRead, lstat, read_record, walk_local};
use crate::scan::{CancellationToken, ScanClock};

/// The largest `device.plist`, in bytes.
const MAX_DEVICE_PLIST_BYTES: u64 = 64 * 1024;

/// The largest number of devices and of runtimes in a report.
const MAX_ENTRIES: usize = 512;

/// The suffix of a runtime bundle.
const RUNTIME_SUFFIX: &str = ".simruntime";

/// The path of the runtime bundles in a runtime volume.
const VOLUME_RUNTIMES: &str = "Library/Developer/CoreSimulator/Profiles/Runtimes";

/// Where a runtime bundle is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeLocation {
    /// A bundle in `/Library/Developer/CoreSimulator/Profiles/Runtimes`.
    Profile,
    /// A bundle in a mounted runtime volume below
    /// `/Library/Developer/CoreSimulator/Volumes`.
    Volume,
}

/// The locations that the inspection reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimulatorLocations {
    /// The directory of the devices of the user.
    pub devices: PathBuf,
    /// The directory of the runtime bundles.
    pub profiles: PathBuf,
    /// The directory of the mounted runtime volumes.
    pub volumes: PathBuf,
}

impl SimulatorLocations {
    /// The documented locations of `CoreSimulator` for the home directory
    /// `home`.
    #[must_use]
    pub fn of_host(home: &Path) -> Self {
        Self {
            devices: home.join("Library/Developer/CoreSimulator/Devices"),
            profiles: PathBuf::from("/Library/Developer/CoreSimulator/Profiles/Runtimes"),
            volumes: PathBuf::from("/Library/Developer/CoreSimulator/Volumes"),
        }
    }
}

/// The state of a device, from the value `state` of its `device.plist`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum DeviceState {
    /// The value 1.
    Shutdown,
    /// The value 3. The owner tool shuts a device down before it deletes
    /// it.
    Booted,
    /// Another value, for example a device that boots or shuts down.
    Other(i64),
    /// The file has no integer value `state`.
    Unknown,
}

/// The result of one device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DeviceOutcome {
    /// The device was measured. The figure is information only: a device
    /// that `simctl clone` made shares blocks with its source through APFS
    /// clones, so the inspection gives no reclaim figure.
    Measured(CacheMeasurement),
    /// The directory has no `device.plist` in the accepted form.
    UnsupportedLayout,
    /// The device failed a check. The reason is a stable name.
    Refused {
        /// The reason.
        reason: &'static str,
    },
}

/// One simulator device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SimulatorDevice {
    /// The identity of the device: the name of its directory.
    pub udid: String,
    /// The directory of the device.
    pub path: PathBuf,
    /// The value `name`.
    pub name: Option<String>,
    /// The value `runtime`, for example
    /// `com.apple.CoreSimulator.SimRuntime.iOS-17-0`.
    pub runtime: Option<String>,
    /// The value `deviceType`.
    pub device_type: Option<String>,
    /// The state.
    pub state: DeviceState,
    /// The result.
    pub outcome: DeviceOutcome,
    /// The owner workflow, as a text for the user. Svalnir does not run
    /// it.
    pub owner_workflow: String,
}

/// One runtime bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SimulatorRuntime {
    /// The name of the bundle with no suffix, for example `iOS 17.0`.
    pub name: String,
    /// The path of the bundle.
    pub path: PathBuf,
    /// Where the bundle is.
    pub location: RuntimeLocation,
}

/// The inspection of `simulator.devices`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SimulatorInspection {
    /// The exact rule revision.
    pub rule: RuleRef,
    /// Each layout of the declaration with its lifecycle state.
    pub layouts: Vec<LayoutSupport>,
    /// The result of the device directory: `None` when it was read, or a
    /// stable reason.
    pub devices_refused: Option<&'static str>,
    /// The devices, in the sequence of their names.
    pub devices: Vec<SimulatorDevice>,
    /// The runtime bundles.
    pub runtimes: Vec<SimulatorRuntime>,
    /// The owner workflow for the runtimes. Svalnir does not run it.
    pub runtime_workflow: &'static str,
}

/// Whether `name` has the form of a device identity: 36 characters of
/// upper-case hexadecimal digits and hyphens.
fn is_udid(name: &str) -> bool {
    name.len() == 36
        && name.char_indices().all(|(index, character)| {
            if [8, 13, 18, 23].contains(&index) {
                character == '-'
            } else {
                character.is_ascii_digit() || ('A'..='F').contains(&character)
            }
        })
}

/// The names of the entries of the directory `path`, sorted, at most
/// [`MAX_ENTRIES`]. `None` when the directory cannot be read.
fn entries(path: &Path) -> Option<Vec<String>> {
    let mut names: Vec<String> = fs::read_dir(path)
        .ok()?
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect();
    names.sort();
    names.truncate(MAX_ENTRIES);
    Some(names)
}

impl OwnerToolRules {
    /// Inspects the simulator devices and runtimes at `locations`.
    pub fn inspect_simulator(
        &self,
        host: OwnerToolHost<'_>,
        locations: &SimulatorLocations,
        limits: InspectionLimits,
        cancel: &CancellationToken,
        clock: &dyn ScanClock,
    ) -> SimulatorInspection {
        self.inspect_simulator_with_mounts(host, locations, limits, cancel, clock, MountTable::read)
    }

    /// [`OwnerToolRules::inspect_simulator`] with another source of the
    /// mount table.
    pub(crate) fn inspect_simulator_with_mounts(
        &self,
        host: OwnerToolHost<'_>,
        locations: &SimulatorLocations,
        limits: InspectionLimits,
        cancel: &CancellationToken,
        clock: &dyn ScanClock,
        mounts: MountTableSource,
    ) -> SimulatorInspection {
        let rule = self.simulator();
        let mut inspection: SimulatorInspection = SimulatorInspection {
            rule: rule.reference.clone(),
            layouts: rule.layouts.clone(),
            devices_refused: None,
            devices: Vec::new(),
            runtimes: Vec::new(),
            runtime_workflow: "Run `xcrun simctl runtime list` to see the runtimes and the devices that use them, then `xcrun simctl runtime delete IDENTIFIER`, or remove a platform in the Components settings of Xcode. Svalnir does not run them. A runtime that a device uses makes the device unavailable.",
        };
        let Ok(table) = mounts() else {
            inspection.devices_refused = Some("root_locality_unknown");
            return inspection;
        };
        match devices(host, &locations.devices, &table, limits, cancel, clock) {
            Ok(found) => inspection.devices = found,
            Err(reason) => inspection.devices_refused = Some(reason),
        }
        inspection.runtimes = runtimes(locations, &table);
        inspection
    }
}

/// The devices in `directory`.
fn devices(
    host: OwnerToolHost<'_>,
    directory: &Path,
    mounts: &MountTable,
    limits: InspectionLimits,
    cancel: &CancellationToken,
    clock: &dyn ScanClock,
) -> Result<Vec<SimulatorDevice>, &'static str> {
    match host.locations.of_text(directory) {
        ProtectionFact::NotProtected => {}
        ProtectionFact::Protected => return Err("root_protected"),
        ProtectionFact::Unknown => return Err("root_protection_unknown"),
    }
    let root = match walk_local(directory, mounts) {
        Ok(root) => root,
        Err(crate::rules::unit::WalkStop::Absent) => return Ok(Vec::new()),
        Err(_) => return Err("root_not_local_or_not_readable"),
    };
    if root.kind != ObjectKind::Directory || root.owner != host.principal {
        return Err("root_not_directory_of_user");
    }
    let names: Vec<String> = entries(directory).ok_or("root_not_readable")?;
    let mut found: Vec<SimulatorDevice> = Vec::new();
    for udid in names.into_iter().filter(|name| is_udid(name)) {
        let path: PathBuf = directory.join(&udid);
        let mut device: SimulatorDevice = SimulatorDevice {
            owner_workflow: format!(
                "Run `xcrun simctl delete {udid}` to delete the device, or `xcrun simctl erase {udid}` to keep it and remove its contents and settings; `xcrun simctl delete unavailable` deletes each device whose runtime is not installed. Shut a booted device down first (`xcrun simctl shutdown {udid}`). Svalnir does not run them."
            ),
            udid,
            path: path.clone(),
            name: None,
            runtime: None,
            device_type: None,
            state: DeviceState::Unknown,
            outcome: DeviceOutcome::UnsupportedLayout,
        };
        let refused = |reason: &'static str| DeviceOutcome::Refused { reason };
        device.outcome = match lstat(&path) {
            Ok(snapshot)
                if snapshot.kind == ObjectKind::Directory
                    && snapshot.owner == host.principal
                    && snapshot.object.device == root.object.device =>
            {
                if host
                    .user_exclusions
                    .iter()
                    .any(|excluded| path.starts_with(excluded) || excluded.starts_with(&path))
                {
                    refused("unit_excluded")
                } else {
                    describe(&mut device, &path, host, limits, cancel, clock)
                }
            }
            Ok(snapshot) if snapshot.kind == ObjectKind::SymbolicLink => {
                refused("unit_symbolic_link")
            }
            Ok(_) => refused("unit_not_directory_of_user"),
            Err(_) => refused("unit_not_readable"),
        };
        found.push(device);
    }
    Ok(found)
}

/// Reads the `device.plist` of the device at `path` and measures it.
fn describe(
    device: &mut SimulatorDevice,
    path: &Path,
    host: OwnerToolHost<'_>,
    limits: InspectionLimits,
    cancel: &CancellationToken,
    clock: &dyn ScanClock,
) -> DeviceOutcome {
    let RecordRead::Read { bytes, .. } = read_record(
        &path.join("device.plist"),
        MAX_DEVICE_PLIST_BYTES,
        host.principal,
    ) else {
        return DeviceOutcome::UnsupportedLayout;
    };
    // CoreSimulator writes the file as XML; the binary form is also
    // accepted.
    let values: Option<Vec<(String, Scalar)>> = parse_scalar_dictionary(&bytes)
        .map(|entries| {
            entries
                .into_iter()
                .map(|(key, kind, content)| {
                    let value: Scalar = match kind {
                        "string" => Scalar::Text(content),
                        "integer" => content
                            .trim()
                            .parse()
                            .map_or(Scalar::Other, Scalar::Integer),
                        _ => Scalar::Other,
                    };
                    (key, value)
                })
                .collect()
        })
        .or_else(|| parse_dictionary(&bytes));
    let Some(values) = values else {
        return DeviceOutcome::UnsupportedLayout;
    };
    let text = |key: &str| {
        values.iter().find_map(|(name, value)| match value {
            Scalar::Text(text) if name == key => Some(text.clone()),
            _ => None,
        })
    };
    // The file names the device that its directory names.
    if text("UDID").as_deref() != Some(device.udid.as_str()) {
        return DeviceOutcome::UnsupportedLayout;
    }
    device.name = text("name");
    device.runtime = text("runtime");
    device.device_type = text("deviceType");
    device.state = values
        .iter()
        .find_map(|(name, value)| match value {
            Scalar::Integer(1) if name == "state" => Some(DeviceState::Shutdown),
            Scalar::Integer(3) if name == "state" => Some(DeviceState::Booted),
            Scalar::Integer(other) if name == "state" => Some(DeviceState::Other(*other)),
            _ => None,
        })
        .unwrap_or(DeviceState::Unknown);
    match measure_unit(path, limits, cancel, clock, ReclaimBasis::ClonedStorage) {
        Some(measurement) => DeviceOutcome::Measured(measurement),
        None => DeviceOutcome::Refused {
            reason: "unit_not_readable",
        },
    }
}

/// The runtime bundles of `locations`. A location that is not on a local
/// filesystem or cannot be read gives no bundle.
fn runtimes(locations: &SimulatorLocations, mounts: &MountTable) -> Vec<SimulatorRuntime> {
    let mut found: Vec<SimulatorRuntime> = Vec::new();
    let mut bundles = |directory: &Path, location: RuntimeLocation| {
        if walk_local(directory, mounts).is_err() {
            return;
        }
        for name in entries(directory).unwrap_or_default() {
            let Some(runtime) = name.strip_suffix(RUNTIME_SUFFIX) else {
                continue;
            };
            let path: PathBuf = directory.join(&name);
            if lstat(&path).is_ok_and(|bundle| bundle.kind == ObjectKind::Directory)
                && found.len() < MAX_ENTRIES
            {
                found.push(SimulatorRuntime {
                    name: runtime.to_owned(),
                    path,
                    location,
                });
            }
        }
    };
    bundles(&locations.profiles, RuntimeLocation::Profile);
    if walk_local(&locations.volumes, mounts).is_ok() {
        for volume in entries(&locations.volumes).unwrap_or_default() {
            let path: PathBuf = locations.volumes.join(volume);
            if lstat(&path).is_ok_and(|entry| entry.kind == ObjectKind::Directory) {
                bundles(&path.join(VOLUME_RUNTIMES), RuntimeLocation::Volume);
            }
        }
    }
    found
}
