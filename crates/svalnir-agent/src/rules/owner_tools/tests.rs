//! Fixture tests of the rules of the owner tools. Each test makes its
//! directories in a temporary directory; no test reads or changes a
//! simulator, a container engine, or a Homebrew installation of the host,
//! and no test runs `simctl`, `docker`, or `brew`.

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;

use svalnir_core::action::FileObjectType;
use svalnir_core::process::Uid;
use svalnir_core::rule::{DeletionMethod, LifecycleState, RuleMode, RuleRefusal, RuleRegistry};
use svalnir_core::time::MonotonicNanos;
use tempfile::TempDir;

use super::bplist::{Scalar, parse_dictionary};
use super::{
    DeviceOutcome, DeviceState, DiskOutcome, KegOutcome, OwnerToolHost, PrefixOutcome,
    RuntimeLocation, RuntimeLocationOutcome, SimulatorInspection, SimulatorLocations,
};
use crate::protection::ProtectedLocations;
use crate::rules::ReviewedRules;
use crate::rules::caches::{InspectionLimits, ReclaimFigure};
use crate::rules::fixture::{automatic_eviction_validated, manual_action_validated};
use crate::rules::projects::{BuildProcesses, ProcessEvidence, ProjectProcess};
use crate::scan::{CancellationToken, WallScanClock};

struct Fixed(BuildProcesses);

impl ProcessEvidence for Fixed {
    fn build_processes(&self, _principal: Uid) -> BuildProcesses {
        self.0.clone()
    }

    fn monotonic_now(&self) -> Option<MonotonicNanos> {
        self.0.observed_at
    }
}

fn processes(executables: &[PathBuf]) -> Fixed {
    let mut list: Vec<ProjectProcess> = vec![ProjectProcess {
        executable: PathBuf::from("/usr/bin/login"),
        working_directory: None,
    }];
    list.extend(executables.iter().map(|executable| ProjectProcess {
        executable: executable.clone(),
        working_directory: None,
    }));
    Fixed(BuildProcesses {
        processes: list,
        incomplete: None,
        observed_at: Some(MonotonicNanos::new(1)),
    })
}

struct Home {
    _directory: TempDir,
    path: PathBuf,
    locations: ProtectedLocations,
    principal: Uid,
}

impl Home {
    fn new() -> Self {
        let directory: TempDir = TempDir::new().unwrap();
        let path: PathBuf = fs::canonicalize(directory.path()).unwrap();
        let state: PathBuf = path.join("Library/Application Support/Svalnir");
        fs::create_dir_all(&state).unwrap();
        let principal: Uid = Uid::new(fs::metadata(&path).unwrap().uid());
        Self {
            locations: ProtectedLocations::from_resolved(Some(path.clone()), Some(state)),
            _directory: directory,
            path,
            principal,
        }
    }

    fn write(&self, relative: &str, content: &[u8]) -> PathBuf {
        let path: PathBuf = self.path.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, content).unwrap();
        path
    }

    fn host<'a>(&'a self, evidence: &'a Fixed) -> OwnerToolHost<'a> {
        OwnerToolHost {
            principal: self.principal,
            locations: &self.locations,
            user_exclusions: &[],
            processes: evidence,
        }
    }
}

const UDID: &str = "0A1B2C3D-4E5F-6A7B-8C9D-0E1F2A3B4C5D";
const OTHER_UDID: &str = "11111111-2222-3333-4444-555555555555";

/// The XML `device.plist` of a device.
fn device_plist(udid: &str, state: i64) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n\t<key>UDID</key>\n\t<string>{udid}</string>\n\t<key>deviceType</key>\n\t<string>com.apple.CoreSimulator.SimDeviceType.iPhone-15</string>\n\t<key>isDeleted</key>\n\t<false/>\n\t<key>name</key>\n\t<string>iPhone &amp; Test</string>\n\t<key>runtime</key>\n\t<string>com.apple.CoreSimulator.SimRuntime.iOS-17-0</string>\n\t<key>state</key>\n\t<integer>{state}</integer>\n</dict>\n</plist>\n"
    )
}

// ---------------------------------------------------------------------
// The registry.
// ---------------------------------------------------------------------

#[test]
fn each_owner_tool_rule_is_proposed_with_the_inspection_mode_only() {
    let registry: ReviewedRules = ReviewedRules::new().unwrap();
    let ids: Vec<&str> = registry
        .owner_tools()
        .rules()
        .iter()
        .map(|rule| rule.reference.id.as_str())
        .collect();
    assert_eq!(
        ids,
        [
            "simulator.devices",
            "container.build-cache",
            "homebrew.cleanup"
        ]
    );
    for rule in registry.owner_tools().rules() {
        assert_eq!(rule.modes, [RuleMode::Inspection]);
        assert_eq!(rule.deletion_method, DeletionMethod::ProducerOperation);
        for layout in &rule.layouts {
            assert_eq!(layout.lifecycle, LifecycleState::Proposed);
            for mode in RuleMode::ALL {
                assert_eq!(
                    registry
                        .resolve(&rule.reference, &layout.layout, &mode)
                        .err(),
                    Some(RuleRefusal::ModeNotValidated)
                );
            }
        }
    }
    for state in [manual_action_validated(), automatic_eviction_validated()] {
        let registry: ReviewedRules = ReviewedRules::with_fixture_lifecycle(&state).unwrap();
        for rule in registry.owner_tools().rules() {
            for layout in &rule.layouts {
                assert_eq!(layout.lifecycle, LifecycleState::Proposed);
            }
        }
    }
}

// ---------------------------------------------------------------------
// The binary property list.
// ---------------------------------------------------------------------

/// The binary form of the XML property list `xml`, from `plutil` on a
/// temporary copy.
fn binary_plist(xml: &str) -> Vec<u8> {
    let directory: TempDir = TempDir::new().unwrap();
    let path: PathBuf = directory.path().join("device.plist");
    fs::write(&path, xml).unwrap();
    let status = Command::new("/usr/bin/plutil")
        .args(["-convert", "binary1"])
        .arg(&path)
        .status()
        .unwrap();
    assert!(status.success());
    fs::read(&path).unwrap()
}

#[test]
fn the_binary_reader_decodes_the_scalars_of_the_top_dictionary() {
    let bytes: Vec<u8> = binary_plist(&device_plist(UDID, 3));
    let entries = parse_dictionary(&bytes).unwrap();
    let value = |key: &str| {
        entries
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.clone())
    };
    assert_eq!(value("UDID"), Some(Scalar::Text(UDID.to_owned())));
    assert_eq!(
        value("name"),
        Some(Scalar::Text("iPhone & Test".to_owned()))
    );
    assert_eq!(value("state"), Some(Scalar::Integer(3)));
    assert_eq!(value("isDeleted"), Some(Scalar::Boolean(false)));
    // Another form, a cut file, and a changed trailer are refused.
    assert_eq!(parse_dictionary(device_plist(UDID, 3).as_bytes()), None);
    assert_eq!(parse_dictionary(&bytes[..bytes.len() - 1]), None);
    let mut changed: Vec<u8> = bytes.clone();
    let objects: usize = changed.len() - 32 + 15;
    changed[objects] = 0xff;
    assert_eq!(parse_dictionary(&changed), None);
    assert_eq!(parse_dictionary(b"bplist00"), None);
}

// ---------------------------------------------------------------------
// Simulator devices and runtimes.
// ---------------------------------------------------------------------

fn simulator_locations(home: &Home) -> SimulatorLocations {
    SimulatorLocations {
        devices: home.path.join("Library/Developer/CoreSimulator/Devices"),
        profiles: home.path.join("system/Profiles/Runtimes"),
        volumes: home.path.join("system/Volumes"),
    }
}

#[test]
fn a_device_is_attributed_from_its_device_plist_with_no_reclaim_figure() {
    let home = Home::new();
    let devices: &str = "Library/Developer/CoreSimulator/Devices";
    home.write(
        &format!("{devices}/{UDID}/device.plist"),
        device_plist(UDID, 3).as_bytes(),
    );
    home.write(&format!("{devices}/{UDID}/data/Library/a.db"), b"data");
    // The binary form.
    home.write(
        &format!("{devices}/{OTHER_UDID}/device.plist"),
        &binary_plist(&device_plist(OTHER_UDID, 1)),
    );
    // A directory whose file names another device, a directory with no
    // file, a symbolic link, and a name that is not a device identity.
    let wrong: &str = "22222222-2222-3333-4444-555555555555";
    home.write(
        &format!("{devices}/{wrong}/device.plist"),
        device_plist(UDID, 1).as_bytes(),
    );
    let empty: &str = "33333333-2222-3333-4444-555555555555";
    fs::create_dir_all(home.path.join(devices).join(empty)).unwrap();
    let linked: &str = "44444444-2222-3333-4444-555555555555";
    symlink(
        home.path.join(devices).join(UDID),
        home.path.join(devices).join(linked),
    )
    .unwrap();
    home.write(&format!("{devices}/device_set.plist"), b"<plist/>");
    home.write(
        "system/Profiles/Runtimes/iOS 17.0.simruntime/Contents/Info.plist",
        b"",
    );
    home.write(
        "system/Volumes/iOS_21A328/Library/Developer/CoreSimulator/Profiles/Runtimes/iOS 17.2.simruntime/Contents/Info.plist",
        b"",
    );
    home.write("system/Profiles/Runtimes/README", b"");

    let registry: ReviewedRules = ReviewedRules::new().unwrap();
    let evidence = processes(&[]);
    let inspection = registry.owner_tools().inspect_simulator(
        home.host(&evidence),
        &simulator_locations(&home),
        InspectionLimits::default(),
        &CancellationToken::new(),
        &WallScanClock,
    );
    assert_eq!(inspection.devices_refused, None);
    let device = |udid: &str| {
        inspection
            .devices
            .iter()
            .find(|device| device.udid == udid)
            .unwrap()
    };
    let booted = device(UDID);
    assert_eq!(booted.name.as_deref(), Some("iPhone & Test"));
    assert_eq!(
        booted.runtime.as_deref(),
        Some("com.apple.CoreSimulator.SimRuntime.iOS-17-0")
    );
    assert_eq!(booted.state, DeviceState::Booted);
    let DeviceOutcome::Measured(measurement) = &booted.outcome else {
        panic!("not measured: {:?}", booted.outcome);
    };
    assert_eq!(measurement.reclaim, ReclaimFigure::NotKnownClonedStorage);
    assert!(
        booted
            .owner_workflow
            .contains(&format!("xcrun simctl delete {UDID}"))
    );
    assert_eq!(device(OTHER_UDID).state, DeviceState::Shutdown);
    assert_eq!(device(wrong).outcome, DeviceOutcome::UnsupportedLayout);
    assert_eq!(device(empty).outcome, DeviceOutcome::UnsupportedLayout);
    assert_eq!(
        device(linked).outcome,
        DeviceOutcome::Refused {
            reason: "unit_symbolic_link"
        }
    );
    assert_eq!(inspection.devices.len(), 5);
    let runtimes: Vec<(&str, RuntimeLocation)> = inspection
        .runtimes
        .iter()
        .map(|runtime| (runtime.name.as_str(), runtime.location))
        .collect();
    assert_eq!(
        runtimes,
        [
            ("iOS 17.0", RuntimeLocation::Profile),
            ("iOS 17.2", RuntimeLocation::Volume)
        ]
    );
    // The inspection changed nothing.
    assert!(
        home.path
            .join(devices)
            .join(UDID)
            .join("data/Library/a.db")
            .exists()
    );
}

#[test]
fn with_no_simulator_the_inspection_reports_nothing() {
    let home = Home::new();
    let registry: ReviewedRules = ReviewedRules::new().unwrap();
    let evidence = processes(&[]);
    let inspection = registry.owner_tools().inspect_simulator(
        home.host(&evidence),
        &simulator_locations(&home),
        InspectionLimits::default(),
        &CancellationToken::new(),
        &WallScanClock,
    );
    assert_eq!(inspection.devices_refused, None);
    assert_eq!(inspection.devices, []);
    assert_eq!(inspection.runtimes, []);
}

// ---------------------------------------------------------------------
// Container build cache.
// ---------------------------------------------------------------------

#[test]
fn the_disk_image_of_an_engine_is_reported_and_is_not_a_unit() {
    let home = Home::new();
    let image: PathBuf = home.write(
        "Library/Containers/com.docker.docker/Data/vms/0/data/Docker.raw",
        b"",
    );
    // A sparse image: the size that the virtual machine sees is much
    // larger than its storage.
    fs::File::options()
        .write(true)
        .open(&image)
        .unwrap()
        .set_len(1 << 30)
        .unwrap();
    // A disk image of Colima that is a symbolic link.
    fs::create_dir_all(home.path.join(".colima/_lima/colima")).unwrap();
    symlink(&image, home.path.join(".colima/_lima/colima/diffdisk")).unwrap();
    let registry: ReviewedRules = ReviewedRules::new().unwrap();
    let evidence = processes(&[]);
    let inspection = registry
        .owner_tools()
        .inspect_container(home.host(&evidence));
    let docker = &inspection.disks[0];
    assert_eq!(docker.engine, "Docker Desktop");
    let DiskOutcome::Present {
        logical_bytes,
        allocated_bytes,
    } = docker.outcome
    else {
        panic!("not present: {:?}", docker.outcome);
    };
    assert_eq!(logical_bytes.get(), 1 << 30);
    assert!(allocated_bytes.unwrap().get() < 1 << 30);
    assert!(docker.owner_workflow.contains("docker builder prune"));
    assert!(docker.owner_workflow.contains("removes volumes"));
    assert_eq!(
        inspection.disks[1].outcome,
        DiskOutcome::Refused {
            reason: "disk_symbolic_link"
        }
    );
    let empty = Home::new();
    let inspection = registry
        .owner_tools()
        .inspect_container(empty.host(&evidence));
    assert!(
        inspection
            .disks
            .iter()
            .all(|disk| disk.outcome == DiskOutcome::Absent)
    );
}

// ---------------------------------------------------------------------
// Homebrew cleanup.
// ---------------------------------------------------------------------

/// A prefix with the kegs `versions` of `formula`, and `opt` linked to
/// `current`.
fn formula(prefix: &Path, formula: &str, versions: &[&str], current: Option<&str>) {
    for version in versions {
        let bin: PathBuf = prefix
            .join("Cellar")
            .join(formula)
            .join(version)
            .join("bin");
        fs::create_dir_all(&bin).unwrap();
        fs::write(bin.join(formula), b"#!/bin/sh\n").unwrap();
    }
    if let Some(current) = current {
        fs::create_dir_all(prefix.join("opt")).unwrap();
        symlink(
            format!("../Cellar/{formula}/{current}"),
            prefix.join("opt").join(formula),
        )
        .unwrap();
    }
}

#[test]
fn the_old_kegs_of_a_formula_are_attributed_and_the_current_keg_is_not() {
    let home = Home::new();
    let prefix: PathBuf = home.path.join("homebrew");
    formula(&prefix, "wget", &["1.21", "1.24"], Some("1.24"));
    formula(&prefix, "node", &["20.1", "22.0"], Some("22.0"));
    fs::create_dir_all(prefix.join("var/homebrew/pinned")).unwrap();
    symlink("../../../opt/node", prefix.join("var/homebrew/pinned/node")).unwrap();
    formula(&prefix, "jq", &["1.6", "1.7"], None);
    formula(&prefix, "git", &["2.40", "2.50"], Some("2.50"));
    formula(&prefix, "curl", &["8.0"], Some("8.0"));
    // A process of the user runs the old keg of git.
    let evidence = processes(&[prefix.join("Cellar/git/2.40/bin/git")]);
    let registry: ReviewedRules = ReviewedRules::new().unwrap();
    let inspection = registry.owner_tools().inspect_homebrew(
        home.host(&evidence),
        &[prefix.clone(), home.path.join("absent")],
        InspectionLimits::default(),
        &CancellationToken::new(),
        &WallScanClock,
    );
    let report = &inspection.prefixes[0];
    assert_eq!(report.outcome, PrefixOutcome::Examined(false));
    let outcome = |name: &str, version: &str| {
        &report
            .kegs
            .iter()
            .find(|keg| keg.formula == name && keg.version == version)
            .unwrap()
            .outcome
    };
    let KegOutcome::OldVersion(measurement) = outcome("wget", "1.21") else {
        panic!("not an old version: {:?}", outcome("wget", "1.21"));
    };
    assert!(matches!(
        measurement.reclaim,
        ReclaimFigure::AllocatedUpperBound { .. }
    ));
    assert_eq!(*outcome("wget", "1.24"), KegOutcome::Current);
    // Each keg of a pinned formula is pinned, the current one too.
    assert_eq!(*outcome("node", "20.1"), KegOutcome::Pinned);
    assert_eq!(*outcome("node", "22.0"), KegOutcome::Pinned);
    assert_eq!(*outcome("jq", "1.6"), KegOutcome::CurrentVersionUnknown);
    assert_eq!(*outcome("jq", "1.7"), KegOutcome::CurrentVersionUnknown);
    assert_eq!(
        *outcome("git", "2.40"),
        KegOutcome::InUse {
            executable: prefix.join("Cellar/git/2.40/bin/git")
        }
    );
    // A formula with one keg has nothing to clean.
    assert!(report.kegs.iter().all(|keg| keg.formula != "curl"));
    assert_eq!(inspection.prefixes[1].outcome, PrefixOutcome::Absent);
    assert!(inspection.owner_workflow.contains("brew cleanup --dry-run"));
    // The inspection changed nothing.
    assert!(prefix.join("Cellar/wget/1.21/bin/wget").exists());
}

#[test]
fn an_incomplete_inventory_makes_the_activity_of_an_old_keg_unknown() {
    let home = Home::new();
    let prefix: PathBuf = home.path.join("homebrew");
    formula(&prefix, "wget", &["1.21", "1.24"], Some("1.24"));
    let evidence = Fixed(BuildProcesses {
        processes: Vec::new(),
        incomplete: Some("process_list_unavailable"),
        observed_at: None,
    });
    let registry: ReviewedRules = ReviewedRules::new().unwrap();
    let inspection = registry.owner_tools().inspect_homebrew(
        home.host(&evidence),
        &[prefix],
        InspectionLimits::default(),
        &CancellationToken::new(),
        &WallScanClock,
    );
    assert_eq!(
        inspection.prefixes[0].kegs[0].outcome,
        KegOutcome::ActivityUnknown {
            reason: "process_list_unavailable"
        }
    );
}

#[test]
fn a_cellar_that_is_a_symbolic_link_is_not_followed() {
    let home = Home::new();
    let real: PathBuf = home.path.join("real");
    formula(&real, "wget", &["1.21", "1.24"], Some("1.24"));
    let prefix: PathBuf = home.path.join("homebrew");
    fs::create_dir_all(&prefix).unwrap();
    symlink(real.join("Cellar"), prefix.join("Cellar")).unwrap();
    let evidence = processes(&[]);
    let registry: ReviewedRules = ReviewedRules::new().unwrap();
    let inspection = registry.owner_tools().inspect_homebrew(
        home.host(&evidence),
        &[prefix],
        InspectionLimits::default(),
        &CancellationToken::new(),
        &WallScanClock,
    );
    assert_eq!(
        inspection.prefixes[0].outcome,
        PrefixOutcome::Refused("root_not_directory")
    );
    assert_eq!(inspection.prefixes[0].kegs, []);
}

#[test]
fn the_declarations_name_each_root_and_the_object_type_of_a_unit() {
    let registry: ReviewedRules = ReviewedRules::new().unwrap();
    let rules = registry.owner_tools();
    assert_eq!(rules.simulator().roots.len(), 3);
    assert_eq!(
        rules.container().exclusions.supported_object_types,
        [FileObjectType::RegularFile]
    );
    assert_eq!(
        rules.homebrew().exclusions.supported_object_types,
        [FileObjectType::Directory]
    );
}

fn inspect_simulator(home: &Home) -> SimulatorInspection {
    let registry: ReviewedRules = ReviewedRules::new().unwrap();
    let evidence = processes(&[]);
    registry.owner_tools().inspect_simulator(
        home.host(&evidence),
        &simulator_locations(home),
        InspectionLimits::default(),
        &CancellationToken::new(),
        &WallScanClock,
    )
}

/// Makes the directory at `path` not readable for the test, and readable
/// again when the guard is dropped.
struct Locked(PathBuf);

impl Locked {
    fn new(path: PathBuf) -> Self {
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
        Self(path)
    }
}

impl Drop for Locked {
    fn drop(&mut self) {
        drop(fs::set_permissions(
            &self.0,
            fs::Permissions::from_mode(0o755),
        ));
    }
}

#[test]
fn a_runtime_location_that_is_a_link_or_not_readable_has_its_reason() {
    let home = Home::new();
    home.write("real/Runtimes/iOS 17.0.simruntime/Contents/Info.plist", b"");
    fs::create_dir_all(home.path.join("system/Profiles")).unwrap();
    symlink(
        home.path.join("real/Runtimes"),
        home.path.join("system/Profiles/Runtimes"),
    )
    .unwrap();
    let inspection = inspect_simulator(&home);
    assert_eq!(inspection.runtimes, []);
    assert_eq!(
        inspection.runtime_locations[0].outcome,
        RuntimeLocationOutcome::Refused("location_not_directory")
    );
    assert_eq!(
        inspection.runtime_locations[1].outcome,
        RuntimeLocationOutcome::Absent
    );
    fs::create_dir_all(home.path.join("system/Volumes")).unwrap();
    let _locked = Locked::new(home.path.join("system/Volumes"));
    let inspection = inspect_simulator(&home);
    assert_eq!(
        inspection.runtime_locations[1].outcome,
        RuntimeLocationOutcome::Refused("location_not_readable")
    );
}

#[test]
fn other_names_do_not_push_a_device_out_and_a_cut_list_is_marked() {
    let home = Home::new();
    let devices: &str = "Library/Developer/CoreSimulator/Devices";
    for index in 0..600 {
        home.write(&format!("{devices}/0-other-{index:04}"), b"");
    }
    home.write(
        &format!("{devices}/FFFFFFFF-2222-3333-4444-555555555555/device.plist"),
        device_plist("FFFFFFFF-2222-3333-4444-555555555555", 1).as_bytes(),
    );
    let inspection = inspect_simulator(&home);
    assert_eq!(inspection.devices.len(), 1);
    assert!(!inspection.devices_truncated);
    for index in 0..512 {
        fs::create_dir_all(
            home.path
                .join(devices)
                .join(format!("{index:08X}-2222-3333-4444-555555555555")),
        )
        .unwrap();
    }
    let inspection = inspect_simulator(&home);
    assert_eq!(inspection.devices.len(), 512);
    assert!(inspection.devices_truncated);
}

#[test]
fn a_device_plist_that_cannot_be_read_is_refused_and_not_a_layout() {
    let home = Home::new();
    let path: PathBuf = home.write(
        &format!("Library/Developer/CoreSimulator/Devices/{UDID}/device.plist"),
        device_plist(UDID, 1).as_bytes(),
    );
    fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
    let inspection = inspect_simulator(&home);
    assert_eq!(
        inspection.devices[0].outcome,
        DeviceOutcome::Refused {
            reason: "device_plist_denied"
        }
    );
}

#[test]
fn an_unknown_pin_state_and_a_cut_keg_list_are_reported() {
    let home = Home::new();
    let prefix: PathBuf = home.path.join("homebrew");
    formula(&prefix, "wget", &["1.21", "1.24"], Some("1.24"));
    let versions: Vec<String> = (0..70).map(|index| format!("1.{index}")).collect();
    let versions: Vec<&str> = versions.iter().map(String::as_str).collect();
    formula(&prefix, "many", &versions, Some("1.0"));
    fs::create_dir_all(prefix.join("var/homebrew/pinned")).unwrap();
    let locked = Locked::new(prefix.join("var/homebrew/pinned"));
    let evidence = processes(&[]);
    let registry: ReviewedRules = ReviewedRules::new().unwrap();
    let inspection = registry.owner_tools().inspect_homebrew(
        home.host(&evidence),
        std::slice::from_ref(&prefix),
        InspectionLimits::default(),
        &CancellationToken::new(),
        &WallScanClock,
    );
    drop(locked);
    let report = &inspection.prefixes[0];
    assert_eq!(report.truncated_formulae, ["many"]);
    let wget = report
        .kegs
        .iter()
        .find(|keg| keg.formula == "wget" && keg.version == "1.21")
        .unwrap();
    assert_eq!(
        wget.outcome,
        KegOutcome::Refused {
            reason: "pin_state_unknown"
        }
    );
}
