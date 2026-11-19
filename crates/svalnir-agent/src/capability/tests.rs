//! Tests of the report logic with injected probe findings.

use std::cell::Cell;
use std::path::PathBuf;

use svalnir_core::file::LosslessPath;
use svalnir_core::process::{Pid, Uid};
use svalnir_core::state::CapabilityState;
use svalnir_core::time::WallTime;

use super::diagnose;
use super::probe::{
    CapabilityProbes, DirectoryFinding, MetricSource, PlatformFinding, Probed, ProtectedAttempt,
    ProtectedLocationsFinding, ProtectedReadOutcome, ServiceFinding, ServiceKind, ServiceLocation,
    ServiceLocationOutcome, SipFinding, SourceFinding, UserDirectory,
};
use super::report::{
    CapabilityEntry, CapabilityId, CapabilityReport, ProbeSubject, RegistrationState, Requirement,
    Summary, Verdict, WorkerRole, build_report,
};

/// Probes that return the findings that a test sets.
struct InjectedProbes {
    platform: PlatformFinding,
    home: DirectoryFinding,
    state: DirectoryFinding,
    logs: DirectoryFinding,
    protected: Vec<ProtectedReadOutcome>,
    protected_home_differs: Option<PathBuf>,
    protected_lookup_error: Option<String>,
    failing_source: Option<(MetricSource, SourceFinding)>,
    agent: Vec<ServiceLocationOutcome>,
    helper: Vec<ServiceLocationOutcome>,
    sip: SipFinding,
    calls: Cell<u32>,
}

impl InjectedProbes {
    /// A healthy Apple Silicon Mac with no Svalnir service and no Full
    /// Disk Access.
    fn healthy() -> Self {
        Self {
            platform: PlatformFinding {
                os: "macos".to_owned(),
                os_version: Some("15.1".to_owned()),
                os_build: Some("24B83".to_owned()),
                process_architecture: "aarch64".to_owned(),
                apple_silicon_hardware: Some(true),
                translated: Some(false),
            },
            home: DirectoryFinding::Present {
                path: PathBuf::from("/Users/test"),
                is_directory: true,
                readable: true,
                writable: true,
            },
            state: absent("/Users/test/Library/Application Support/Svalnir", true),
            logs: absent("/Users/test/Library/Logs/Svalnir", true),
            protected: vec![ProtectedReadOutcome::NotPermitted],
            protected_home_differs: None,
            protected_lookup_error: None,
            failing_source: None,
            agent: vec![
                ServiceLocationOutcome::NotFound,
                ServiceLocationOutcome::NotFound,
            ],
            helper: vec![
                ServiceLocationOutcome::NotFound,
                ServiceLocationOutcome::Absent,
            ],
            sip: SipFinding::Enabled,
            calls: Cell::new(0),
        }
    }

    fn count(&self) {
        self.calls.set(self.calls.get() + 1);
    }
}

fn absent(path: &str, ancestor_writable: bool) -> DirectoryFinding {
    DirectoryFinding::Absent {
        path: PathBuf::from(path),
        nearest_ancestor: PathBuf::from("/Users/test/Library"),
        ancestor_writable,
    }
}

fn present(is_directory: bool, readable: bool, writable: bool) -> DirectoryFinding {
    DirectoryFinding::Present {
        path: PathBuf::from("/Users/test/dir"),
        is_directory,
        readable,
        writable,
    }
}

fn failed() -> DirectoryFinding {
    DirectoryFinding::Failed {
        path: None,
        error: "injected".to_owned(),
    }
}

impl CapabilityProbes for InjectedProbes {
    fn platform(&self) -> Probed<PlatformFinding> {
        self.count();
        Probed::new("injected platform", self.platform.clone())
    }

    fn user_directory(&self, directory: UserDirectory) -> Probed<DirectoryFinding> {
        self.count();
        let finding = match directory {
            UserDirectory::Home => &self.home,
            UserDirectory::State => &self.state,
            UserDirectory::Logs => &self.logs,
        };
        Probed::new("injected directory", finding.clone())
    }

    fn protected_locations(&self) -> Probed<ProtectedLocationsFinding> {
        self.count();
        let attempts = self
            .protected
            .iter()
            .enumerate()
            .map(|(index, outcome)| ProtectedAttempt {
                path: PathBuf::from(format!("/Users/test/Library/Protected{index}")),
                outcome: outcome.clone(),
            })
            .collect();
        Probed::new(
            "injected protected read",
            ProtectedLocationsFinding {
                attempts,
                account_home: self
                    .protected_lookup_error
                    .is_none()
                    .then(|| PathBuf::from("/Users/test")),
                account_home_error: self.protected_lookup_error.clone(),
                home_variable_differs: self.protected_home_differs.clone(),
            },
        )
    }

    fn metric_source(&self, source: MetricSource) -> Probed<SourceFinding> {
        self.count();
        let finding = match &self.failing_source {
            Some((failing, finding)) if *failing == source => finding.clone(),
            _ => SourceFinding::Responded {
                detail: "injected answer".to_owned(),
            },
        };
        Probed::new("injected source", finding)
    }

    fn service(&self, service: ServiceKind) -> Probed<ServiceFinding> {
        self.count();
        let outcomes = match service {
            ServiceKind::BackgroundAgent => &self.agent,
            ServiceKind::PrivilegedHelper => &self.helper,
        };
        let locations = outcomes
            .iter()
            .enumerate()
            .map(|(index, outcome)| ServiceLocation {
                directory: PathBuf::from(format!("/Library/Services{index}")),
                outcome: outcome.clone(),
            })
            .collect();
        Probed::new("injected service", ServiceFinding { locations })
    }

    fn system_integrity_protection(&self) -> Probed<SipFinding> {
        self.count();
        Probed::new("injected sip", self.sip.clone())
    }
}

fn subject(role: WorkerRole) -> ProbeSubject {
    ProbeSubject {
        role,
        executable: Some(LosslessPath::from_bytes("/usr/local/bin/svalnir").unwrap()),
        pid: Some(Pid::new(4242).unwrap()),
        real_uid: Uid::new(501),
        effective_uid: Uid::new(501),
    }
}

fn report_of(probes: &InjectedProbes) -> CapabilityReport {
    build_report(subject(WorkerRole::Cli), Some(WallTime::UNIX_EPOCH), probes)
}

fn entry(probes: &InjectedProbes, id: CapabilityId) -> CapabilityEntry {
    report_of(probes).entry(id).unwrap().clone()
}

/// Checks the invariants that hold for each entry.
fn assert_well_formed(report: &CapabilityReport) {
    let ids: Vec<CapabilityId> = report.capabilities.iter().map(|entry| entry.id).collect();
    assert_eq!(ids, CapabilityId::ALL);
    for entry in &report.capabilities {
        assert_eq!(entry.requirement, entry.id.requirement(), "{}", entry.id);
        assert_eq!(entry.title, entry.id.title());
        assert_eq!(entry.enables, entry.id.enables());
        assert!(!entry.detail.is_empty(), "{}", entry.id);
        assert!(!entry.evidence.method.is_empty(), "{}", entry.id);
        // An entry has a reason exactly when it is not available.
        assert_eq!(
            entry.reason.is_none(),
            entry.state == CapabilityState::Available,
            "{}",
            entry.id
        );
        let is_service = matches!(
            entry.id,
            CapabilityId::ServiceBackgroundAgent | CapabilityId::ServicePrivilegedHelper
        );
        assert_eq!(entry.registration.is_some(), is_service, "{}", entry.id);
    }
    assert_eq!(report.summary, Summary::of(&report.capabilities));
}

#[test]
fn a_healthy_host_is_ready_with_optional_capabilities_missing() {
    let probes = InjectedProbes::healthy();
    let report = report_of(&probes);
    assert_well_formed(&report);

    // Each probe runs one time: platform, three directories, the protected
    // locations, five sources, two services, and the status of the
    // protection.
    assert_eq!(probes.calls.get(), 13);

    assert_eq!(report.summary.verdict, Verdict::Ready);
    assert!(report.required_satisfied());
    assert_eq!(report.summary.required.available, 7);
    assert_eq!(report.summary.required_not_available, []);
    // Denied Full Disk Access and the two absent services are optional.
    assert_eq!(
        report.summary.optional_not_available,
        [
            CapabilityId::FullDiskAccess,
            CapabilityId::ServiceBackgroundAgent,
            CapabilityId::ServicePrivilegedHelper,
        ]
    );
    assert_eq!(report.summary.optional.available, 2);
    assert_eq!(report.summary.optional.denied, 1);
    assert_eq!(report.summary.optional.unknown, 2);
    assert_eq!(report.summary.informational.available, 1);
}

#[test]
fn the_identifiers_are_stable_and_distinct() {
    let texts: Vec<&str> = CapabilityId::ALL.iter().map(|id| id.as_str()).collect();
    assert_eq!(
        texts,
        [
            "host.platform",
            "user.home_directory",
            "user.state_directory",
            "user.log_directory",
            "privacy.full_disk_access",
            "metrics.memory_pressure",
            "metrics.vm_statistics",
            "metrics.swap_usage",
            "metrics.volume_capacity",
            "metrics.process_inspection",
            "service.background_agent",
            "service.privileged_helper",
            "system.integrity_protection",
        ]
    );
    for id in CapabilityId::ALL {
        // The JSON spelling is the text of `as_str`.
        assert_eq!(
            serde_json::to_string(&id).unwrap(),
            format!("\"{}\"", id.as_str())
        );
        assert_eq!(id.to_string(), id.as_str());
    }
}

#[test]
fn the_classes_separate_required_optional_and_informational() {
    let class = |requirement: Requirement| -> Vec<CapabilityId> {
        CapabilityId::ALL
            .into_iter()
            .filter(|id| id.requirement() == requirement)
            .collect()
    };
    assert_eq!(
        class(Requirement::Required),
        [
            CapabilityId::HostPlatform,
            CapabilityId::UserHomeDirectory,
            CapabilityId::MetricsMemoryPressure,
            CapabilityId::MetricsVmStatistics,
            CapabilityId::MetricsSwapUsage,
            CapabilityId::MetricsVolumeCapacity,
            CapabilityId::MetricsProcessInspection,
        ]
    );
    assert_eq!(
        class(Requirement::Optional),
        [
            CapabilityId::UserStateDirectory,
            CapabilityId::UserLogDirectory,
            CapabilityId::FullDiskAccess,
            CapabilityId::ServiceBackgroundAgent,
            CapabilityId::ServicePrivilegedHelper,
        ]
    );
    assert_eq!(
        class(Requirement::Informational),
        [CapabilityId::SystemIntegrityProtection]
    );
}

#[test]
fn the_platform_state_follows_the_host() {
    let state_of = |change: fn(&mut PlatformFinding)| {
        let mut probes = InjectedProbes::healthy();
        change(&mut probes.platform);
        entry(&probes, CapabilityId::HostPlatform).state
    };
    assert_eq!(state_of(|_| {}), CapabilityState::Available);
    assert_eq!(
        state_of(|platform| platform.os = "linux".to_owned()),
        CapabilityState::Unsupported
    );
    // Intel hardware is not validated; that is not a denial.
    assert_eq!(
        state_of(|platform| {
            platform.apple_silicon_hardware = Some(false);
            platform.process_architecture = "x86_64".to_owned();
        }),
        CapabilityState::Unknown
    );
    // A translated process on Apple Silicon is not validated.
    assert_eq!(
        state_of(|platform| {
            platform.translated = Some(true);
            platform.process_architecture = "x86_64".to_owned();
        }),
        CapabilityState::Unknown
    );
    // A native arm64 process shows Apple Silicon when the query failed.
    assert_eq!(
        state_of(|platform| platform.apple_silicon_hardware = None),
        CapabilityState::Available
    );
    assert_eq!(
        state_of(|platform| {
            platform.apple_silicon_hardware = None;
            platform.process_architecture = "x86_64".to_owned();
        }),
        CapabilityState::Unknown
    );
    // A failed version query does not change the state.
    assert_eq!(
        state_of(|platform| {
            platform.os_version = None;
            platform.os_build = None;
        }),
        CapabilityState::Available
    );
}

#[test]
fn the_home_directory_needs_read_access() {
    let state_of = |home: DirectoryFinding| {
        let mut probes = InjectedProbes::healthy();
        probes.home = home;
        entry(&probes, CapabilityId::UserHomeDirectory).state
    };
    assert_eq!(
        state_of(present(true, true, false)),
        CapabilityState::Available
    );
    assert_eq!(
        state_of(present(true, false, false)),
        CapabilityState::Denied
    );
    assert_eq!(
        state_of(present(false, true, true)),
        CapabilityState::Unknown
    );
    assert_eq!(
        state_of(absent("/Users/test", true)),
        CapabilityState::Unknown
    );
    assert_eq!(state_of(failed()), CapabilityState::Unknown);
}

#[test]
fn a_state_or_log_directory_needs_write_access_or_a_writable_ancestor() {
    for id in [
        CapabilityId::UserStateDirectory,
        CapabilityId::UserLogDirectory,
    ] {
        let state_of = |finding: DirectoryFinding| {
            let mut probes = InjectedProbes::healthy();
            probes.state = finding.clone();
            probes.logs = finding;
            entry(&probes, id).state
        };
        assert_eq!(
            state_of(present(true, true, true)),
            CapabilityState::Available
        );
        assert_eq!(
            state_of(present(true, true, false)),
            CapabilityState::Denied
        );
        assert_eq!(
            state_of(present(true, false, true)),
            CapabilityState::Denied
        );
        assert_eq!(
            state_of(present(false, true, true)),
            CapabilityState::Unknown
        );
        assert_eq!(state_of(absent("/x", true)), CapabilityState::Available);
        assert_eq!(state_of(absent("/x", false)), CapabilityState::Denied);
        assert_eq!(state_of(failed()), CapabilityState::Unknown);
    }
}

#[test]
fn an_absent_directory_is_reported_as_absent() {
    let probes = InjectedProbes::healthy();
    let entry = entry(&probes, CapabilityId::UserStateDirectory);
    let fact = |name: &str| {
        entry
            .evidence
            .facts
            .iter()
            .find(|fact| fact.name == name)
            .map(|fact| fact.value.as_str())
    };
    assert_eq!(fact("exists"), Some("false"));
    assert_eq!(fact("ancestor_writable"), Some("true"));
    assert_eq!(
        fact("path"),
        Some("/Users/test/Library/Application Support/Svalnir")
    );
    assert!(entry.detail.contains("did not create"));
}

#[test]
fn full_disk_access_is_denied_only_on_the_refusal_of_the_privacy_control() {
    use ProtectedReadOutcome::{Absent, Failed, Listed, NotPermitted, PermissionDenied};
    let state_of = |outcomes: Vec<ProtectedReadOutcome>| {
        let mut probes = InjectedProbes::healthy();
        probes.protected = outcomes;
        entry(&probes, CapabilityId::FullDiskAccess).state
    };
    assert_eq!(state_of(vec![Listed, Absent]), CapabilityState::Available);
    assert_eq!(
        state_of(vec![NotPermitted, Absent]),
        CapabilityState::Denied
    );
    // One refusal is an actual-resource failure, also when a different
    // location is readable.
    assert_eq!(
        state_of(vec![Listed, NotPermitted]),
        CapabilityState::Denied
    );
    // A result that the probe cannot establish is unknown, not denied.
    assert_eq!(state_of(vec![]), CapabilityState::Unknown);
    assert_eq!(state_of(vec![Absent, Absent]), CapabilityState::Unknown);
    assert_eq!(state_of(vec![PermissionDenied]), CapabilityState::Unknown);
    assert_eq!(
        state_of(vec![Failed("injected".to_owned()), Absent]),
        CapabilityState::Unknown
    );
}

#[test]
fn full_disk_access_records_a_different_home_and_a_failed_lookup() {
    let fact = |entry: &CapabilityEntry, name: &str| {
        entry
            .evidence
            .facts
            .iter()
            .find(|fact| fact.name == name)
            .map(|fact| fact.value.clone())
    };

    let mut differs = InjectedProbes::healthy();
    differs.protected = vec![ProtectedReadOutcome::Listed];
    differs.protected_home_differs = Some(PathBuf::from("/tmp/h"));
    let entry_differs = entry(&differs, CapabilityId::FullDiskAccess);
    assert_eq!(
        fact(&entry_differs, "home_variable_differs").as_deref(),
        Some("/tmp/h")
    );
    assert_eq!(
        fact(&entry_differs, "account_home").as_deref(),
        Some("/Users/test")
    );

    let mut failed_lookup = InjectedProbes::healthy();
    failed_lookup.protected = vec![];
    failed_lookup.protected_lookup_error = Some("getpwuid_r: injected".to_owned());
    let entry_failed = entry(&failed_lookup, CapabilityId::FullDiskAccess);
    assert_eq!(entry_failed.state, CapabilityState::Unknown);
    assert_eq!(
        fact(&entry_failed, "account_home_error").as_deref(),
        Some("getpwuid_r: injected")
    );
}

#[test]
fn the_full_disk_access_hint_names_the_tested_process() {
    let probes = InjectedProbes::healthy();
    let hint_for = |role: WorkerRole| {
        build_report(subject(role), None, &probes)
            .entry(CapabilityId::FullDiskAccess)
            .unwrap()
            .remediation
            .clone()
            .unwrap()
    };
    assert!(hint_for(WorkerRole::Cli).contains("terminal"));
    assert!(hint_for(WorkerRole::Cli).contains("does not give the access to the background agent"));
    assert!(!hint_for(WorkerRole::Agent).contains("terminal"));
    let window: String = hint_for(WorkerRole::Window);
    assert!(!window.contains("terminal"), "{window}");
    assert!(window.contains("add Svalnir"), "{window}");
    assert!(window.contains("does not give the access to the background agent"));

    let mut available = InjectedProbes::healthy();
    available.protected = vec![ProtectedReadOutcome::Listed];
    let entry = entry(&available, CapabilityId::FullDiskAccess);
    assert_eq!(entry.remediation, None);
    assert!(
        entry
            .detail
            .contains("does not show access to every protected location")
    );
}

#[test]
fn a_metric_source_maps_each_finding_to_one_state() {
    let ids = [
        (
            MetricSource::MemoryPressure,
            CapabilityId::MetricsMemoryPressure,
        ),
        (
            MetricSource::VmStatistics,
            CapabilityId::MetricsVmStatistics,
        ),
        (MetricSource::SwapUsage, CapabilityId::MetricsSwapUsage),
        (
            MetricSource::VolumeCapacity,
            CapabilityId::MetricsVolumeCapacity,
        ),
        (
            MetricSource::ProcessInspection,
            CapabilityId::MetricsProcessInspection,
        ),
    ];
    let detail = || "injected".to_owned();
    for (source, id) in ids {
        let cases = [
            (
                SourceFinding::Denied { detail: detail() },
                CapabilityState::Denied,
                Verdict::Blocked,
            ),
            (
                SourceFinding::Unsupported { detail: detail() },
                CapabilityState::Unsupported,
                Verdict::Blocked,
            ),
            (
                SourceFinding::Failed { detail: detail() },
                CapabilityState::Unknown,
                Verdict::Unverified,
            ),
        ];
        for (finding, state, verdict) in cases {
            let mut probes = InjectedProbes::healthy();
            probes.failing_source = Some((source, finding));
            let report = report_of(&probes);
            assert_well_formed(&report);
            assert_eq!(report.entry(id).unwrap().state, state);
            // A missing required source does not change a different entry.
            assert_eq!(report.summary.required_not_available, [id]);
            assert_eq!(report.summary.verdict, verdict);
            assert!(!report.required_satisfied());
        }
    }
}

#[test]
fn a_service_has_a_registration_state_and_an_unknown_capability() {
    use ServiceLocationOutcome::{Absent, Found, NotFound, Unreadable};
    let registration_of = |outcomes: Vec<ServiceLocationOutcome>| {
        let mut probes = InjectedProbes::healthy();
        probes.agent = outcomes.clone();
        probes.helper = outcomes;
        let report = report_of(&probes);
        assert_well_formed(&report);
        let agent = report.entry(CapabilityId::ServiceBackgroundAgent).unwrap();
        let helper = report.entry(CapabilityId::ServicePrivilegedHelper).unwrap();
        // A client cannot show what a service process can do.
        assert_eq!(agent.state, CapabilityState::Unknown);
        assert_eq!(helper.state, CapabilityState::Unknown);
        assert_eq!(agent.registration, helper.registration);
        agent.registration.unwrap()
    };
    assert_eq!(
        registration_of(vec![NotFound, Absent]),
        RegistrationState::NotInstalled
    );
    assert_eq!(
        registration_of(vec![
            NotFound,
            Found(vec!["dev.po4yka.svalnir.agent.plist".to_owned()])
        ]),
        RegistrationState::RegistrationFilePresent
    );
    // A directory that the probe cannot read leaves the result open.
    assert_eq!(
        registration_of(vec![NotFound, Unreadable("injected".to_owned())]),
        RegistrationState::Unknown
    );
    assert_eq!(registration_of(vec![]), RegistrationState::Unknown);
    // A found file is a positive result also with an unreadable directory.
    assert_eq!(
        registration_of(vec![
            Unreadable("injected".to_owned()),
            Found(vec!["dev.po4yka.svalnir.agent.plist".to_owned()])
        ]),
        RegistrationState::RegistrationFilePresent
    );
}

#[test]
fn system_integrity_protection_is_information_only() {
    let cases = [
        (SipFinding::Enabled, CapabilityState::Available),
        (SipFinding::Disabled, CapabilityState::Available),
        (
            SipFinding::Other("unknown (Custom Configuration)".to_owned()),
            CapabilityState::Available,
        ),
        (SipFinding::Unsupported, CapabilityState::Unsupported),
        (
            SipFinding::NotDetermined("injected".to_owned()),
            CapabilityState::Unknown,
        ),
    ];
    for (finding, state) in cases {
        let mut probes = InjectedProbes::healthy();
        probes.sip = finding;
        let report = report_of(&probes);
        assert_well_formed(&report);
        let entry = report
            .entry(CapabilityId::SystemIntegrityProtection)
            .unwrap();
        assert_eq!(entry.state, state);
        // No hint asks the user to change the protection.
        assert_eq!(entry.remediation, None);
        // The entry has no effect on the verdict.
        assert_eq!(report.summary.verdict, Verdict::Ready);
    }
}

#[test]
fn only_required_capabilities_set_the_verdict() {
    // Each optional capability is denied or unknown; the host is ready.
    let mut probes = InjectedProbes::healthy();
    probes.state = present(true, true, false);
    probes.logs = failed();
    let report = report_of(&probes);
    assert_eq!(report.summary.verdict, Verdict::Ready);
    assert_eq!(report.summary.optional.available, 0);
    assert_eq!(report.summary.optional_not_available.len(), 5);

    // A denied required capability blocks, also with an unknown one.
    let mut probes = InjectedProbes::healthy();
    probes.home = present(true, false, false);
    probes.platform.apple_silicon_hardware = Some(false);
    let report = report_of(&probes);
    assert_eq!(report.summary.verdict, Verdict::Blocked);
    assert_eq!(
        report.summary.required_not_available,
        [CapabilityId::HostPlatform, CapabilityId::UserHomeDirectory]
    );
    assert_eq!(report.summary.required.denied, 1);
    assert_eq!(report.summary.required.unknown, 1);
    assert_eq!(report.summary.required.available, 5);
}

#[test]
fn a_state_that_this_build_does_not_recognize_is_not_available() {
    let mut entries = report_of(&InjectedProbes::healthy()).capabilities;
    let home = entries
        .iter_mut()
        .find(|entry| entry.id == CapabilityId::UserHomeDirectory)
        .unwrap();
    home.state = CapabilityState::from_wire("restricted");
    let summary = Summary::of(&entries);
    assert_eq!(summary.required.unrecognized, 1);
    assert_eq!(summary.verdict, Verdict::Unverified);
    assert_eq!(
        summary.required_not_available,
        [CapabilityId::UserHomeDirectory]
    );
}

#[test]
fn a_window_has_the_requirements_and_the_verdict_of_a_command() {
    // The window shows the readings of the commands, so the same
    // capabilities are required, and a denied one blocks it the same way.
    let mut probes = InjectedProbes::healthy();
    let window = build_report(subject(WorkerRole::Window), None, &probes);
    let cli = build_report(subject(WorkerRole::Cli), None, &probes);
    assert_eq!(window.summary, cli.summary);
    assert_eq!(serde_json::to_value(window.subject.role).unwrap(), "window");
    probes.protected = vec![ProtectedReadOutcome::NotPermitted];
    let denied = build_report(subject(WorkerRole::Window), None, &probes);
    assert_eq!(
        denied.entry(CapabilityId::FullDiskAccess).unwrap().state,
        CapabilityState::Denied
    );
    assert_eq!(denied.summary.verdict, cli.summary.verdict);
}

#[test]
fn the_report_names_the_tested_process() {
    let probes = InjectedProbes::healthy();
    for (role, text) in [
        (WorkerRole::Cli, "command-line process"),
        (WorkerRole::Window, "window process of the graphical client"),
        (WorkerRole::Agent, "background agent process"),
        (WorkerRole::Helper, "privileged helper process"),
    ] {
        let report = build_report(subject(role), None, &probes);
        assert_eq!(report.subject, subject(role));
        assert!(report.scope_note.contains(text), "{}", report.scope_note);
        assert_eq!(report.probed_at, None);
    }
}

#[test]
fn the_report_serializes_with_stable_names() {
    let report = report_of(&InjectedProbes::healthy());
    let json = serde_json::to_value(&report).unwrap();

    assert_eq!(json["subject"]["role"], "cli");
    assert_eq!(json["subject"]["real_uid"], 501);
    assert_eq!(json["subject"]["effective_uid"], 501);
    assert_eq!(json["subject"]["pid"], 4242);
    assert!(!json["subject"]["executable"].is_null());
    assert_eq!(json["summary"]["verdict"], "ready");
    assert_eq!(json["summary"]["required"]["available"], 7);
    assert_eq!(
        json["summary"]["optional_not_available"][0],
        "privacy.full_disk_access"
    );

    let capabilities = json["capabilities"].as_array().unwrap();
    assert_eq!(capabilities.len(), CapabilityId::ALL.len());
    let full_disk_access = &capabilities[4];
    assert_eq!(full_disk_access["id"], "privacy.full_disk_access");
    assert_eq!(full_disk_access["title"], "Full Disk Access");
    assert_eq!(full_disk_access["requirement"], "optional");
    assert_eq!(full_disk_access["state"], "denied");
    assert_eq!(
        full_disk_access["evidence"]["method"],
        "injected protected read"
    );
    assert_eq!(
        full_disk_access["evidence"]["facts"][0]["value"],
        "operation_not_permitted"
    );
    assert!(full_disk_access["reason"].is_string());
    assert!(full_disk_access["remediation"].is_string());
    assert!(full_disk_access["enables"].is_string());
    // An absent optional field is not in the JSON.
    assert!(full_disk_access.get("registration").is_none());
    let platform = &capabilities[0];
    assert_eq!(platform["state"], "available");
    assert!(platform.get("reason").is_none());
    assert!(platform.get("remediation").is_none());
    let agent = &capabilities[10];
    assert_eq!(agent["registration"], "not_installed");
    assert_eq!(agent["state"], "unknown");

    let text = serde_json::to_string(&report).unwrap();
    let decoded: CapabilityReport = serde_json::from_str(&text).unwrap();
    assert_eq!(decoded, report);
}

#[test]
fn the_enumerations_have_the_text_of_their_json_spelling() {
    for requirement in [
        Requirement::Required,
        Requirement::Optional,
        Requirement::Informational,
    ] {
        assert_eq!(
            serde_json::to_value(requirement).unwrap(),
            requirement.as_str()
        );
    }
    for role in [
        WorkerRole::Cli,
        WorkerRole::Window,
        WorkerRole::Agent,
        WorkerRole::Helper,
    ] {
        assert_eq!(serde_json::to_value(role).unwrap(), role.as_str());
    }
    for verdict in [Verdict::Ready, Verdict::Unverified, Verdict::Blocked] {
        assert_eq!(serde_json::to_value(verdict).unwrap(), verdict.as_str());
    }
    for registration in [
        RegistrationState::NotInstalled,
        RegistrationState::RegistrationFilePresent,
        RegistrationState::Unknown,
    ] {
        assert_eq!(
            serde_json::to_value(registration).unwrap(),
            registration.as_str()
        );
    }
}

/// Smoke test of the real probes through the public entry point. It checks
/// only that each capability has a defined state; the states depend on the
/// host.
#[test]
fn the_real_diagnosis_gives_each_capability_a_defined_state() {
    let report = diagnose(WorkerRole::Cli);
    assert_well_formed(&report);
    assert_eq!(report.subject.role, WorkerRole::Cli);
    for entry in &report.capabilities {
        assert!(entry.state.is_recognized(), "{}", entry.id);
    }
    assert!(serde_json::to_string(&report).is_ok());
    // Shown with `cargo test -- --nocapture` for a manual check of the host.
    for entry in &report.capabilities {
        println!(
            "{:<28} {:<13} {:<11} {}",
            entry.id,
            entry.requirement.as_str(),
            entry.state.as_str(),
            entry.detail
        );
    }
}
