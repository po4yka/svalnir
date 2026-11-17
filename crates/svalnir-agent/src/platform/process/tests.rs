//! Tests of the identity, attribution, growth, and ranking logic with
//! synthetic data. No test reads a live process.

use svalnir_core::file::LosslessPath;
use svalnir_core::id::{ClockDomainId, ProcessGenerationId, SampleId};
use svalnir_core::observation::{Reading, UnavailableReason, Unit, metric};
use svalnir_core::process::{
    AttributionMethod, ProcessAssociation, ProcessStartTime, Uid, VerifiedMembership,
};
use svalnir_core::quantity::{ByteDelta, Bytes, CounterValue, Nanoseconds};
use svalnir_core::time::MonotonicNanos;

use super::fake::{FakeSource, USER, application, info, pid, usage};
use super::{
    CLOCK_DOMAIN, CpuSample, CpuUsage, DISK_READ_METRIC, DerivedMetrics, DerivedUnavailable,
    FootprintSample, ForegroundState, GrowthWindow, ProcessRecord, ProcessSnapshot, QueryFailure,
    RankMetric, RankValue, Ranking, cpu_usage, derive_between, footprint_growth, generation_id,
    rank_processes,
};

const MIB: u64 = 1 << 20;

fn snapshot(source: FakeSource) -> ProcessSnapshot {
    source.collector().collect().unwrap()
}

fn record(snapshot: &ProcessSnapshot, process: i32) -> &ProcessRecord {
    snapshot.find_pid(pid(process)).unwrap()
}

// Identity.

#[test]
fn a_record_has_the_full_identity_evidence() {
    let snapshot: ProcessSnapshot =
        snapshot(FakeSource::new().with_process(info(100, 50), "/bin/tool", usage(MIB, 2 * MIB)));

    assert_eq!(snapshot.records.len(), 1);
    let record: &ProcessRecord = record(&snapshot, 100);
    assert_eq!(record.identity.pid, pid(100));
    assert_eq!(
        record.identity.start_time,
        ProcessStartTime::from_timeval(50, 0).unwrap()
    );
    assert_eq!(record.identity.uid, Uid::new(USER));
    assert_eq!(record.real_uid, Uid::new(USER));
    assert_eq!(record.identity.boot_id.as_str(), "boot-test");
    let executable = record.identity.executable.as_ref().unwrap();
    assert_eq!(executable.path.as_utf8(), Some("/bin/tool"));
    assert_eq!(executable.file.unwrap().inode.get(), 100);
    assert_eq!(record.executable_unavailable, None);
    assert_eq!(record.display_label().as_deref(), Some("tool"));
    assert_eq!(record.parent_pid, Some(pid(1)));
    assert_eq!(
        record.identity.association,
        ProcessAssociation::Unattributed
    );
}

#[test]
fn a_restarted_process_is_a_different_generation() {
    let first: ProcessGenerationId =
        generation_id(pid(100), ProcessStartTime::from_timeval(50, 0).unwrap()).unwrap();
    let second: ProcessGenerationId =
        generation_id(pid(100), ProcessStartTime::from_timeval(50, 1).unwrap()).unwrap();
    assert_ne!(first, second);

    let before: ProcessSnapshot =
        snapshot(FakeSource::new().with_process(info(100, 50), "/bin/tool", usage(MIB, MIB)));
    let after: ProcessSnapshot =
        snapshot(FakeSource::new().with_process(info(100, 90), "/bin/tool", usage(MIB, MIB)));
    let old: &ProcessRecord = record(&before, 100);
    let new: &ProcessRecord = record(&after, 100);
    assert_ne!(old.identity.generation_id, new.identity.generation_id);
    assert!(!old.identity.has_same_evidence(&new.identity));
    assert!(after.find_generation(&old.identity.generation_id).is_none());
}

#[test]
fn a_process_replaced_during_collection_is_dropped() {
    // PID 100 is one process at the first identity reading and a different
    // process, with a different executable, at the last reading.
    let source: FakeSource = FakeSource::new()
        .with_process(info(100, 50), "/bin/old", usage(MIB, MIB))
        .with_info_sequence(pid(100), vec![Ok(info(100, 50)), Ok(info(100, 77))])
        .with_process(info(200, 60), "/bin/stable", usage(2 * MIB, MIB));
    let snapshot: ProcessSnapshot = snapshot(source);

    assert!(snapshot.find_pid(pid(100)).is_none());
    assert_eq!(snapshot.omissions.identity_changed, 1);
    assert_eq!(snapshot.records.len(), 1);
    let stable: &ProcessRecord = record(&snapshot, 200);
    assert_eq!(
        stable.identity.executable.as_ref().unwrap().path.as_utf8(),
        Some("/bin/stable")
    );
}

#[test]
fn a_process_that_exits_during_collection_is_dropped() {
    let source: FakeSource = FakeSource::new()
        .with_process(info(100, 50), "/bin/tool", usage(MIB, MIB))
        .with_info_sequence(pid(100), vec![Ok(info(100, 50)), Err(QueryFailure::Gone)])
        .with_info_sequence(pid(101), vec![Err(QueryFailure::Gone)]);
    let snapshot: ProcessSnapshot = snapshot(source);

    assert_eq!(snapshot.records.len(), 0);
    assert_eq!(snapshot.omissions.exited, 2);
}

#[test]
fn a_process_that_becomes_a_zombie_is_dropped_as_exited() {
    let mut zombie = info(100, 50);
    zombie.zombie = true;
    let mut zombie_at_first_reading = info(101, 10);
    zombie_at_first_reading.zombie = true;
    let source: FakeSource = FakeSource::new()
        .with_process(info(100, 50), "/bin/tool", usage(MIB, MIB))
        .with_info_sequence(pid(100), vec![Ok(info(100, 50)), Ok(zombie)])
        .with_info_sequence(pid(101), vec![Ok(zombie_at_first_reading)]);
    let snapshot: ProcessSnapshot = snapshot(source);

    assert_eq!(snapshot.records.len(), 0);
    assert_eq!(snapshot.omissions.exited, 2);
    assert_eq!(snapshot.omissions.identity_changed, 0);
}

#[test]
fn a_change_of_owner_during_collection_drops_the_process() {
    let mut elevated = info(100, 50);
    elevated.real_uid = Uid::new(0);
    let source: FakeSource = FakeSource::new()
        .with_process(info(100, 50), "/bin/tool", usage(MIB, MIB))
        .with_info_sequence(pid(100), vec![Ok(info(100, 50)), Ok(elevated)]);
    let snapshot: ProcessSnapshot = snapshot(source);

    assert_eq!(snapshot.records.len(), 0);
    assert_eq!(snapshot.omissions.identity_changed, 1);
}

#[test]
fn a_process_that_changes_its_executable_during_collection_is_dropped() {
    // An `exec` keeps the PID and the start time. The record must not have
    // the path of the old image and the measurements of the new image.
    let mut source: FakeSource =
        FakeSource::new().with_process(info(100, 50), "/usr/libexec/launcher", usage(MIB, MIB));
    source.paths_after_exec.insert(
        pid(100),
        LosslessPath::from_bytes("/usr/libexec/service").unwrap(),
    );
    let snapshot: ProcessSnapshot = snapshot(source);

    assert_eq!(snapshot.records.len(), 0);
    assert_eq!(snapshot.omissions.identity_changed, 1);
}

#[test]
fn processes_that_the_user_cannot_inspect_are_counted_and_not_recorded() {
    let mut root = info(300, 5);
    root.effective_uid = Uid::new(0);
    let source: FakeSource = FakeSource::new()
        .with_process(info(100, 50), "/bin/tool", usage(MIB, MIB))
        .with_process(root, "/sbin/daemon", usage(MIB, MIB))
        .with_info_sequence(pid(400), vec![Err(QueryFailure::PermissionDenied)])
        .with_info_sequence(pid(500), vec![Err(QueryFailure::Failed(5))]);
    let snapshot: ProcessSnapshot = snapshot(source);

    assert_eq!(snapshot.records.len(), 1);
    assert_eq!(snapshot.omissions.other_user, 1);
    assert_eq!(snapshot.omissions.permission_denied, 1);
    assert_eq!(snapshot.omissions.failed, 1);
}

#[test]
fn a_missing_executable_is_recorded_with_its_reason() {
    let mut source: FakeSource =
        FakeSource::new().with_process(info(100, 50), "/bin/tool", usage(MIB, MIB));
    source
        .paths
        .insert(pid(100), Err(QueryFailure::PermissionDenied));
    // The path of PID 101 is readable and the file object is not.
    source = source.with_process(info(101, 51), "/bin/unlinked", usage(MIB, MIB));
    source.files.remove(b"/bin/unlinked".as_slice());
    let snapshot: ProcessSnapshot = snapshot(source);

    let no_path: &ProcessRecord = record(&snapshot, 100);
    assert_eq!(no_path.identity.executable, None);
    assert_eq!(
        no_path.executable_unavailable,
        Some(UnavailableReason::PermissionDenied)
    );
    assert_eq!(no_path.display_label(), None);
    // The metrics do not depend on the executable evidence.
    assert!(no_path.metrics.footprint.is_available());

    let no_file: &ProcessRecord = record(&snapshot, 101);
    let executable = no_file.identity.executable.as_ref().unwrap();
    assert_eq!(executable.path.as_utf8(), Some("/bin/unlinked"));
    assert_eq!(executable.file, None);
}

#[test]
fn a_process_list_failure_fails_the_collection() {
    let mut source: FakeSource = FakeSource::new();
    source.list = Err(QueryFailure::PermissionDenied);
    assert!(source.collector().collect().is_err());
}

// Metrics.

#[test]
fn footprint_and_resident_size_are_separate_observations() {
    let snapshot: ProcessSnapshot = snapshot(FakeSource::new().with_process(
        info(100, 50),
        "/bin/tool",
        usage(3 * MIB, 7 * MIB),
    ));
    let metrics = &record(&snapshot, 100).metrics;

    assert_eq!(metrics.footprint.metric_id, metric::PROCESS_FOOTPRINT_BYTES);
    assert_eq!(metrics.footprint.value(), Some(&Bytes::new(3 * MIB)));
    assert_eq!(metrics.footprint.source.native_field, "ri_phys_footprint");
    assert_eq!(metrics.resident.metric_id, metric::PROCESS_RESIDENT_BYTES);
    assert_eq!(metrics.resident.value(), Some(&Bytes::new(7 * MIB)));
    assert_eq!(metrics.resident.source.native_field, "ri_resident_size");
    assert_eq!(
        metrics.peak_footprint.value(),
        Some(&Bytes::new(3 * MIB + 1))
    );

    // 48 Mach units with the ratio 125/3 are 2000 nanoseconds.
    assert_eq!(metrics.cpu_time.metric_id, metric::PROCESS_CPU_TIME_NS);
    assert_eq!(metrics.cpu_time.unit, Unit::Nanosecond);
    assert_eq!(metrics.cpu_time.value(), Some(&CounterValue::new(2_000)));
    assert_eq!(metrics.disk_read.metric_id.as_str(), DISK_READ_METRIC);
    assert_eq!(metrics.disk_read.value(), Some(&CounterValue::new(10)));
    assert_eq!(metrics.disk_written.value(), Some(&CounterValue::new(20)));

    let sample = metrics.sample();
    assert_eq!(sample.clock_domain.as_str(), CLOCK_DOMAIN);
    assert!(sample.acquisition_duration().is_some());
    assert_eq!(
        metrics.footprint.scope.identity_id.as_str(),
        record(&snapshot, 100).identity.generation_id.as_str()
    );
}

#[test]
fn a_denied_usage_query_is_unavailable_and_not_zero() {
    let mut source: FakeSource =
        FakeSource::new().with_process(info(100, 50), "/bin/tool", usage(MIB, MIB));
    source
        .usage
        .insert(pid(100), Err(QueryFailure::PermissionDenied));
    let snapshot: ProcessSnapshot = snapshot(source);
    let metrics = &record(&snapshot, 100).metrics;

    for observation in [
        &metrics.footprint,
        &metrics.resident,
        &metrics.peak_footprint,
    ] {
        assert_eq!(observation.value(), None);
        assert_eq!(
            observation.reason(),
            Some(&UnavailableReason::PermissionDenied)
        );
    }
    for observation in [&metrics.cpu_time, &metrics.disk_read, &metrics.disk_written] {
        assert_eq!(observation.value(), None);
        assert_eq!(
            observation.reason(),
            Some(&UnavailableReason::PermissionDenied)
        );
    }
}

#[test]
fn a_cpu_time_that_cannot_be_converted_is_unavailable() {
    let mut overflow = usage(MIB, MIB);
    overflow.user_time_mach = u64::MAX;
    let source: FakeSource = FakeSource::new().with_process(info(100, 50), "/bin/tool", overflow);
    let snapshot_overflow: ProcessSnapshot = snapshot(source);
    let metrics = &record(&snapshot_overflow, 100).metrics;
    assert_eq!(
        metrics.cpu_time.reason(),
        Some(&UnavailableReason::Overflow)
    );
    assert!(metrics.footprint.is_available());

    let mut source: FakeSource =
        FakeSource::new().with_process(info(100, 50), "/bin/tool", usage(MIB, MIB));
    source.timebase = Err(QueryFailure::Inconsistent);
    let snapshot_no_ratio: ProcessSnapshot = snapshot(source);
    let metrics = &record(&snapshot_no_ratio, 100).metrics;
    assert_eq!(
        metrics.cpu_time.reason(),
        Some(&UnavailableReason::InconsistentData)
    );
    assert!(metrics.disk_read.is_available());
}

// Attribution.

fn application_fixture() -> FakeSource {
    FakeSource::new()
        .with_process(
            info(200, 20),
            "/Applications/Editor.app/Contents/MacOS/Editor",
            usage(8 * MIB, 9 * MIB),
        )
        .with_process(
            info(201, 21),
            "/Applications/Editor.app/Contents/Helpers/Editor Helper",
            usage(4 * MIB, 5 * MIB),
        )
        .with_application(application(200, "com.example.Editor", true))
}

#[test]
fn the_registered_process_is_attributed_by_launch_services() {
    let snapshot: ProcessSnapshot = snapshot(application_fixture());
    let main: &ProcessRecord = record(&snapshot, 200);

    let ProcessAssociation::Application {
        instance_id,
        bundle_identifier,
        attribution,
    } = &main.identity.association
    else {
        panic!("the registered process has no application association");
    };
    assert_eq!(bundle_identifier, "com.example.Editor");
    assert_eq!(*attribution, AttributionMethod::LaunchServices);
    assert_eq!(main.foreground, ForegroundState::Foreground);
    assert_eq!(snapshot.members_of(instance_id).len(), 1);
    assert_eq!(snapshot.launch_services_unavailable, None);
}

#[test]
fn a_helper_with_a_responsible_application_is_a_member() {
    let snapshot: ProcessSnapshot = snapshot(application_fixture().with_responsible(201, 200));
    let main: &ProcessRecord = record(&snapshot, 200);
    let helper: &ProcessRecord = record(&snapshot, 201);

    let Some(VerifiedMembership::Application {
        instance_id,
        bundle_identifier,
    }) = helper.identity.association.verified_membership()
    else {
        panic!("the helper has no verified membership");
    };
    assert_eq!(bundle_identifier, "com.example.Editor");
    assert!(matches!(
        &helper.identity.association,
        ProcessAssociation::Application {
            attribution: AttributionMethod::ResponsibleProcess,
            ..
        }
    ));
    assert_eq!(helper.foreground, ForegroundState::Foreground);
    let members: Vec<&ProcessRecord> = snapshot.members_of(instance_id);
    assert_eq!(members, vec![main, helper]);
}

#[test]
fn a_name_a_path_or_a_parent_does_not_make_a_member() {
    // PID 201 has the bundle path of the application. PID 202 has the same
    // executable name and the application process as its parent. Neither
    // has a responsible-process relationship with the application.
    let mut child = info(202, 22);
    child.parent_pid = Some(pid(200));
    let source: FakeSource =
        application_fixture().with_process(child, "/usr/local/bin/Editor", usage(MIB, MIB));
    let snapshot: ProcessSnapshot = snapshot(source);

    for process in [201, 202] {
        let record: &ProcessRecord = record(&snapshot, process);
        assert_eq!(
            record.identity.association,
            ProcessAssociation::Unattributed
        );
        assert_eq!(record.identity.association.verified_membership(), None);
        assert_eq!(record.foreground, ForegroundState::Unknown);
    }
}

#[test]
fn a_responsible_process_that_is_not_an_application_gives_no_membership() {
    // PID 201 names PID 150, a shell, as responsible.
    let source: FakeSource = application_fixture()
        .with_process(info(150, 15), "/bin/zsh", usage(MIB, MIB))
        .with_responsible(201, 150);
    let snapshot: ProcessSnapshot = snapshot(source);

    assert_eq!(
        record(&snapshot, 201).identity.association,
        ProcessAssociation::Unattributed
    );
    assert_eq!(
        record(&snapshot, 150).identity.association,
        ProcessAssociation::Unattributed
    );
}

#[test]
fn a_background_application_is_not_foreground() {
    let source: FakeSource = FakeSource::new()
        .with_process(
            info(200, 20),
            "/Applications/A.app/Contents/MacOS/A",
            usage(MIB, MIB),
        )
        .with_process(
            info(201, 21),
            "/Applications/A.app/Contents/MacOS/H",
            usage(MIB, MIB),
        )
        .with_application(application(200, "com.example.A", false))
        .with_responsible(201, 200);
    let snapshot: ProcessSnapshot = snapshot(source);

    assert_eq!(
        record(&snapshot, 200).foreground,
        ForegroundState::Background
    );
    assert_eq!(
        record(&snapshot, 201).foreground,
        ForegroundState::Background
    );
}

#[test]
fn an_application_that_was_replaced_gives_no_membership() {
    // The application process exits during the collection and a different
    // process gets PID 200. The helper must not join the new process.
    let source: FakeSource = application_fixture()
        .with_responsible(201, 200)
        .with_info_sequence(pid(200), vec![Ok(info(200, 20)), Ok(info(200, 99))]);
    let snapshot: ProcessSnapshot = snapshot(source);

    assert!(snapshot.find_pid(pid(200)).is_none());
    assert_eq!(
        record(&snapshot, 201).identity.association,
        ProcessAssociation::Unattributed
    );
    assert_eq!(record(&snapshot, 201).foreground, ForegroundState::Unknown);
}

#[test]
fn a_stale_application_entry_does_not_attribute_a_new_process() {
    // The application list is older than the collection. The application
    // quit, and PID 200 is now a different program of the same user.
    let mut stale = application(200, "com.example.Editor", true);
    stale.executable_path =
        Some(LosslessPath::from_bytes("/Applications/Editor.app/Contents/MacOS/Editor").unwrap());
    let mut source: FakeSource = FakeSource::new()
        .with_process(info(200, 70), "/usr/bin/other", usage(MIB, MIB))
        .with_process(info(201, 21), "/usr/bin/helper", usage(MIB, MIB))
        .with_responsible(201, 200);
    source.applications = Ok(vec![stale]);
    let snapshot_stale: ProcessSnapshot = snapshot(source);
    for process in [200, 201] {
        assert_eq!(
            record(&snapshot_stale, process).identity.association,
            ProcessAssociation::Unattributed
        );
    }

    // An entry with no executable path is not evidence for a generation.
    let mut source: FakeSource = application_fixture();
    source.applications = Ok(vec![application(200, "com.example.Editor", true)]);
    let snapshot_no_path: ProcessSnapshot = snapshot(source);
    assert_eq!(
        record(&snapshot_no_path, 200).identity.association,
        ProcessAssociation::Unattributed
    );
}

#[test]
fn a_responsible_application_that_started_later_gives_no_membership() {
    // The kernel keeps the responsible process as a PID. The first owner of
    // PID 300 quit, and an application that started after the helper got
    // that PID. The helper is not a member of the new application.
    let source: FakeSource = FakeSource::new()
        .with_process(info(250, 40), "/usr/bin/server", usage(MIB, MIB))
        .with_process(
            info(300, 90),
            "/Applications/B.app/Contents/MacOS/B",
            usage(MIB, MIB),
        )
        .with_application(application(300, "com.example.B", true))
        .with_responsible(250, 300);
    let snapshot: ProcessSnapshot = snapshot(source);

    assert!(
        record(&snapshot, 300)
            .identity
            .association
            .verified_membership()
            .is_some()
    );
    assert_eq!(
        record(&snapshot, 250).identity.association,
        ProcessAssociation::Unattributed
    );
    assert_eq!(record(&snapshot, 250).foreground, ForegroundState::Unknown);
}

#[test]
fn a_terminated_or_unidentified_application_gives_no_membership() {
    let mut terminated = application(200, "com.example.Editor", true);
    terminated.terminated = true;
    let mut source: FakeSource = application_fixture().with_responsible(201, 200);
    source.applications = Ok(vec![terminated]);
    let snapshot_terminated: ProcessSnapshot = snapshot(source);
    for process in [200, 201] {
        assert_eq!(
            record(&snapshot_terminated, process).identity.association,
            ProcessAssociation::Unattributed
        );
    }

    let mut unidentified = application(200, "", true);
    unidentified.bundle_identifier = None;
    let mut source: FakeSource = application_fixture().with_responsible(201, 200);
    source.applications = Ok(vec![unidentified]);
    let snapshot_unidentified: ProcessSnapshot = snapshot(source);
    for process in [200, 201] {
        assert_eq!(
            record(&snapshot_unidentified, process).identity.association,
            ProcessAssociation::Unattributed
        );
    }
}

#[test]
fn an_unavailable_application_list_leaves_each_process_unattributed() {
    let mut source: FakeSource = application_fixture().with_responsible(201, 200);
    source.applications = Err(QueryFailure::Unsupported);
    source
        .responsible
        .insert(pid(201), Err(QueryFailure::Unsupported));
    let snapshot: ProcessSnapshot = snapshot(source);

    assert_eq!(snapshot.records.len(), 2);
    for record in &snapshot.records {
        assert_eq!(
            record.identity.association,
            ProcessAssociation::Unattributed
        );
        assert_eq!(record.foreground, ForegroundState::Unknown);
    }
    assert_eq!(
        snapshot.launch_services_unavailable,
        Some(UnavailableReason::Unsupported)
    );
    assert_eq!(
        snapshot.responsible_process_unavailable,
        Some(UnavailableReason::Unsupported)
    );
}

// Footprint growth.

fn clock() -> ClockDomainId {
    ClockDomainId::new(CLOCK_DOMAIN).unwrap()
}

fn generation(process: i32, start_seconds: u64) -> ProcessGenerationId {
    generation_id(
        pid(process),
        ProcessStartTime::from_timeval(start_seconds, 0).unwrap(),
    )
    .unwrap()
}

fn footprint_at(generation_id: &ProcessGenerationId, at: u64, bytes: u64) -> FootprintSample {
    FootprintSample {
        generation_id: generation_id.clone(),
        sample_id: SampleId::new(format!("s-{at}")).unwrap(),
        clock_domain: clock(),
        at: MonotonicNanos::new(at),
        footprint: Reading::Available(Bytes::new(bytes)),
    }
}

fn window(end: u64, length: u64) -> GrowthWindow {
    GrowthWindow {
        end: MonotonicNanos::new(end),
        length: Nanoseconds::new(length),
    }
}

#[test]
fn growth_is_the_signed_difference_over_the_window() {
    let process: ProcessGenerationId = generation(100, 50);
    // The samples are not in time order.
    let samples: Vec<FootprintSample> = vec![
        footprint_at(&process, 300, 30 * MIB),
        footprint_at(&process, 100, 10 * MIB),
        footprint_at(&process, 200, 25 * MIB),
    ];
    let growth = footprint_growth(&samples, &process, &clock(), window(300, 200)).unwrap();
    assert_eq!(growth.delta, ByteDelta::new(i128::from(20 * MIB)).unwrap());
    assert_eq!(growth.elapsed, Nanoseconds::new(200));
    assert_eq!(growth.first_sample_id.as_str(), "s-100");
    assert_eq!(growth.last_sample_id.as_str(), "s-300");
    assert_eq!(growth.available_samples, 3);
    assert_eq!(growth.gaps, 0);

    // A shorter window does not use the first sample.
    let growth = footprint_growth(&samples, &process, &clock(), window(300, 150)).unwrap();
    assert_eq!(growth.delta, ByteDelta::new(i128::from(5 * MIB)).unwrap());
    assert_eq!(growth.first_at, MonotonicNanos::new(200));

    // A footprint that decreases gives a negative value.
    let shrink: Vec<FootprintSample> = vec![
        footprint_at(&process, 100, 10 * MIB),
        footprint_at(&process, 200, 4 * MIB),
    ];
    let growth = footprint_growth(&shrink, &process, &clock(), window(200, 200)).unwrap();
    assert_eq!(growth.delta, ByteDelta::new(-i128::from(6 * MIB)).unwrap());
}

#[test]
fn a_restarted_process_does_not_continue_the_old_series() {
    // PID 100 restarts: the same PID, a new start time.
    let old: ProcessGenerationId = generation(100, 50);
    let new: ProcessGenerationId = generation(100, 80);
    let samples: Vec<FootprintSample> = vec![
        footprint_at(&old, 100, 900 * MIB),
        footprint_at(&old, 200, 950 * MIB),
        footprint_at(&new, 300, 10 * MIB),
    ];

    // The new generation has one sample, so it has no growth. It does not
    // get the difference from the 950 MiB of its predecessor.
    assert_eq!(
        footprint_growth(&samples, &new, &clock(), window(300, 300)),
        Err(DerivedUnavailable::InsufficientSamples)
    );
    let growth = footprint_growth(&samples, &old, &clock(), window(300, 300)).unwrap();
    assert_eq!(growth.delta, ByteDelta::new(i128::from(50 * MIB)).unwrap());
    assert_eq!(growth.last_at, MonotonicNanos::new(200));
}

#[test]
fn growth_reports_gaps_and_missing_data() {
    let process: ProcessGenerationId = generation(100, 50);
    let mut gap: FootprintSample = footprint_at(&process, 200, 0);
    gap.footprint = Reading::Unavailable(UnavailableReason::PermissionDenied);
    let samples: Vec<FootprintSample> = vec![
        footprint_at(&process, 100, 10 * MIB),
        gap.clone(),
        footprint_at(&process, 300, 12 * MIB),
    ];
    let growth = footprint_growth(&samples, &process, &clock(), window(300, 300)).unwrap();
    assert_eq!(growth.delta, ByteDelta::new(i128::from(2 * MIB)).unwrap());
    assert_eq!(growth.available_samples, 2);
    assert_eq!(growth.gaps, 1);

    // An unavailable sample is not a footprint of zero.
    let only_gap: Vec<FootprintSample> = vec![footprint_at(&process, 100, 10 * MIB), gap];
    assert_eq!(
        footprint_growth(&only_gap, &process, &clock(), window(300, 300)),
        Err(DerivedUnavailable::InsufficientSamples)
    );
    assert_eq!(
        footprint_growth(&samples, &generation(7, 7), &clock(), window(300, 300)),
        Err(DerivedUnavailable::NoSamples)
    );
    assert_eq!(
        footprint_growth(&samples, &process, &clock(), window(50, 10)),
        Err(DerivedUnavailable::NoSamples)
    );
}

#[test]
fn growth_rejects_a_different_clock_domain_and_equal_times() {
    let process: ProcessGenerationId = generation(100, 50);
    let mut other_clock: FootprintSample = footprint_at(&process, 200, 20 * MIB);
    other_clock.clock_domain = ClockDomainId::new("other").unwrap();
    let samples: Vec<FootprintSample> = vec![footprint_at(&process, 100, 10 * MIB), other_clock];
    assert_eq!(
        footprint_growth(&samples, &process, &clock(), window(300, 300)),
        Err(DerivedUnavailable::ClockDomainMismatch)
    );

    // Two samples at one time with different values are inconsistent.
    let same_time: Vec<FootprintSample> = vec![
        footprint_at(&process, 100, 10 * MIB),
        footprint_at(&process, 100, 20 * MIB),
    ];
    assert_eq!(
        footprint_growth(&same_time, &process, &clock(), window(300, 300)),
        Err(DerivedUnavailable::NotOrdered)
    );
    // Equal samples at one time are one point in time.
    let same_value: Vec<FootprintSample> = vec![
        footprint_at(&process, 100, 10 * MIB),
        footprint_at(&process, 100, 10 * MIB),
    ];
    assert_eq!(
        footprint_growth(&same_value, &process, &clock(), window(300, 300)),
        Err(DerivedUnavailable::InsufficientSamples)
    );
}

// CPU use.

fn cpu_at(generation_id: &ProcessGenerationId, at: u64, cpu_ns: u64) -> CpuSample {
    CpuSample {
        generation_id: generation_id.clone(),
        sample_id: SampleId::new(format!("s-{at}")).unwrap(),
        clock_domain: clock(),
        at: MonotonicNanos::new(at),
        cpu_time: Reading::Available(CounterValue::new(cpu_ns)),
        sleep_time: Reading::Available(Nanoseconds::ZERO),
    }
}

#[test]
fn cpu_use_rejects_an_interval_with_a_sleep() {
    let process: ProcessGenerationId = generation(7, 7);
    let earlier: CpuSample = cpu_at(&process, 1_000, 100);
    let mut later: CpuSample = cpu_at(&process, 2_000, 400);

    // The host slept for one second between the samples.
    later.sleep_time = Reading::Available(Nanoseconds::new(1_000_000_000));
    let slept: DerivedUnavailable = cpu_usage(&earlier, &later).unwrap_err();
    assert_eq!(slept, DerivedUnavailable::SleepInInterval);
    assert_eq!(slept.reason(), UnavailableReason::ClockDiscontinuity);

    // A sleep time that decreased is not consistent.
    assert_eq!(
        cpu_usage(&later, &cpu_at(&process, 3_000, 500)),
        Err(DerivedUnavailable::SleepTimeDecreased)
    );

    // A sleep time with no value is not evidence of an interval with no
    // sleep.
    later.sleep_time = Reading::Unavailable(UnavailableReason::Unsupported);
    assert_eq!(
        cpu_usage(&earlier, &later),
        Err(DerivedUnavailable::SampleUnavailable(
            UnavailableReason::Unsupported
        ))
    );
}

#[test]
fn a_sleep_between_snapshots_gives_no_cpu_use_and_keeps_the_growth() {
    let mut busy = usage(30 * MIB, MIB);
    busy.user_time_mach = 24_000;
    let before: FakeSource =
        FakeSource::new().with_process(info(100, 50), "/bin/a", usage(10 * MIB, MIB));
    let mut after: FakeSource = FakeSource::new().with_process(info(100, 50), "/bin/a", busy);
    after.clock.set(9_000_000);
    after.slept = Ok(Nanoseconds::new(5_000_000_000));
    let before: ProcessSnapshot = snapshot(before);
    let after: ProcessSnapshot = snapshot(after);
    assert_eq!(
        after.sleep_time,
        Reading::Available(Nanoseconds::new(5_000_000_000))
    );

    let derived: DerivedMetrics = derive_between(&before, &after);
    let id: &ProcessGenerationId = &record(&after, 100).identity.generation_id;
    assert_eq!(
        derived.cpu.get(id),
        Some(&Err(DerivedUnavailable::SleepInInterval))
    );
    // The footprint growth is a gauge difference.
    let growth = derived.growth.get(id).unwrap().as_ref().unwrap();
    assert_eq!(growth.delta, ByteDelta::new(i128::from(20 * MIB)).unwrap());
}

#[test]
fn cpu_use_is_the_counter_increase_over_the_interval() {
    let process: ProcessGenerationId = generation(100, 50);
    let use_ = cpu_usage(
        &cpu_at(&process, 1_000, 500),
        &cpu_at(&process, 3_000, 3_500),
    )
    .unwrap();
    assert_eq!(use_.cpu_delta, Nanoseconds::new(3_000));
    assert_eq!(use_.elapsed, Nanoseconds::new(2_000));
    assert_eq!(use_.earlier_sample_id.as_str(), "s-1000");
    assert_eq!(use_.later_sample_id.as_str(), "s-3000");
    // More than one core gives more than 100 percent.
    assert!((use_.core_equivalent_percent() - 150.0).abs() < 1e-9);
}

#[test]
fn cpu_use_rejects_samples_that_are_not_comparable() {
    let process: ProcessGenerationId = generation(100, 50);
    let restarted: ProcessGenerationId = generation(100, 80);
    let earlier: CpuSample = cpu_at(&process, 1_000, 500);

    assert_eq!(
        cpu_usage(&earlier, &cpu_at(&restarted, 2_000, 10)),
        Err(DerivedUnavailable::GenerationMismatch)
    );
    assert_eq!(
        cpu_usage(&earlier, &cpu_at(&process, 2_000, 400)),
        Err(DerivedUnavailable::CounterReset)
    );
    assert_eq!(
        cpu_usage(&earlier, &cpu_at(&process, 1_000, 900)),
        Err(DerivedUnavailable::NotOrdered)
    );
    let mut denied: CpuSample = cpu_at(&process, 2_000, 0);
    denied.cpu_time = Reading::Unavailable(UnavailableReason::PermissionDenied);
    let unavailable = cpu_usage(&earlier, &denied).unwrap_err();
    assert_eq!(unavailable.reason(), UnavailableReason::PermissionDenied);
    let mut other_clock: CpuSample = cpu_at(&process, 2_000, 900);
    other_clock.clock_domain = ClockDomainId::new("other").unwrap();
    assert_eq!(
        cpu_usage(&earlier, &other_clock),
        Err(DerivedUnavailable::ClockDomainMismatch)
    );
}

#[test]
fn a_sleep_during_a_collection_gives_no_sleep_time_and_no_cpu_use() {
    let before: ProcessSnapshot =
        snapshot(FakeSource::new().with_process(info(100, 50), "/bin/a", usage(MIB, MIB)));
    // The host sleeps after the first sleep-time read of the later
    // collection, so the read at the start agrees with the earlier snapshot.
    let mut later: FakeSource =
        FakeSource::new().with_process(info(100, 50), "/bin/a", usage(MIB, MIB));
    later.clock.set(9_000_000);
    later.slept_later = Some(Nanoseconds::new(5_000_000_000));
    let after: ProcessSnapshot = snapshot(later);
    assert_eq!(
        after.sleep_time,
        Reading::Unavailable(UnavailableReason::ClockDiscontinuity)
    );

    let derived: DerivedMetrics = derive_between(&before, &after);
    let id: &ProcessGenerationId = &record(&after, 100).identity.generation_id;
    assert_eq!(
        derived.cpu.get(id),
        Some(&Err(DerivedUnavailable::SampleUnavailable(
            UnavailableReason::ClockDiscontinuity
        )))
    );
}

#[test]
fn derived_values_join_snapshots_by_generation() {
    let mut busy = usage(30 * MIB, MIB);
    busy.user_time_mach = 24_000;
    let before: FakeSource = FakeSource::new()
        .with_process(info(100, 50), "/bin/a", usage(10 * MIB, MIB))
        .with_process(info(101, 51), "/bin/b", usage(500 * MIB, MIB));
    let after: FakeSource = FakeSource::new()
        .with_process(info(100, 50), "/bin/a", busy)
        // PID 101 restarted between the snapshots.
        .with_process(info(101, 99), "/bin/b", usage(5 * MIB, MIB));
    after.clock.set(9_000_000);
    let before: ProcessSnapshot = snapshot(before);
    let after: ProcessSnapshot = snapshot(after);

    let derived: DerivedMetrics = derive_between(&before, &after);
    let stable: &ProcessGenerationId = &record(&after, 100).identity.generation_id;
    let growth = derived.growth.get(stable).unwrap().as_ref().unwrap();
    assert_eq!(growth.delta, ByteDelta::new(i128::from(20 * MIB)).unwrap());
    let cpu: &CpuUsage = derived.cpu.get(stable).unwrap().as_ref().unwrap();
    // 24_000 more Mach units with the ratio 125/3 are 999_000 nanoseconds.
    assert_eq!(cpu.cpu_delta, Nanoseconds::new(999_000));

    let restarted: &ProcessGenerationId = &record(&after, 101).identity.generation_id;
    assert!(!derived.growth.contains_key(restarted));
    assert!(!derived.cpu.contains_key(restarted));
}

#[test]
fn snapshots_of_different_boots_give_no_derived_values() {
    let source = || FakeSource::new().with_process(info(100, 50), "/bin/a", usage(MIB, MIB));
    let before: ProcessSnapshot = snapshot(source());
    let mut after: ProcessSnapshot = snapshot(source());
    after.boot_id = svalnir_core::id::BootId::new("boot-other").unwrap();

    let derived: DerivedMetrics = derive_between(&before, &after);
    let id: &ProcessGenerationId = &record(&after, 100).identity.generation_id;
    assert_eq!(
        derived.growth.get(id),
        Some(&Err(DerivedUnavailable::GenerationMismatch))
    );
    assert_eq!(
        derived.cpu.get(id),
        Some(&Err(DerivedUnavailable::GenerationMismatch))
    );
}

#[test]
fn samples_at_the_same_time_with_different_values_are_inconsistent() {
    let process: ProcessGenerationId = generation(100, 50);
    let mut samples: Vec<FootprintSample> = vec![
        footprint_at(&process, 100, 10 * MIB),
        footprint_at(&process, 200, 20 * MIB),
        footprint_at(&process, 200, 30 * MIB),
    ];
    let expected = Err(DerivedUnavailable::NotOrdered);
    assert_eq!(
        footprint_growth(&samples, &process, &clock(), window(200, 200)),
        expected
    );
    // The input order has no effect.
    samples.reverse();
    assert_eq!(
        footprint_growth(&samples, &process, &clock(), window(200, 200)),
        expected
    );
    // The same value twice is not a conflict.
    let same: Vec<FootprintSample> = vec![
        footprint_at(&process, 100, 10 * MIB),
        footprint_at(&process, 200, 20 * MIB),
        footprint_at(&process, 200, 20 * MIB),
    ];
    assert!(footprint_growth(&same, &process, &clock(), window(200, 200)).is_ok());
}

#[test]
fn a_series_that_ends_unavailable_counts_the_trailing_gaps() {
    let process: ProcessGenerationId = generation(100, 50);
    let unavailable = |at: u64| {
        let mut gap: FootprintSample = footprint_at(&process, at, 0);
        gap.footprint = Reading::Unavailable(UnavailableReason::PermissionDenied);
        gap
    };
    let samples: Vec<FootprintSample> = vec![
        unavailable(50),
        footprint_at(&process, 100, 10 * MIB),
        footprint_at(&process, 200, 12 * MIB),
        unavailable(300),
        unavailable(400),
    ];
    let growth = footprint_growth(&samples, &process, &clock(), window(400, 400)).unwrap();
    assert_eq!(growth.available_samples, 2);
    assert_eq!(growth.gaps, 3);
}

// Ranking.

fn ranking_fixture() -> ProcessSnapshot {
    let mut source: FakeSource = FakeSource::new()
        .with_process(info(100, 50), "/bin/small", usage(MIB, 90 * MIB))
        .with_process(info(101, 51), "/bin/large", usage(50 * MIB, 2 * MIB))
        .with_process(info(102, 52), "/bin/denied", usage(MIB, MIB))
        .with_process(info(103, 53), "/bin/medium", usage(20 * MIB, 20 * MIB))
        .with_process(info(104, 54), "/bin/gone", usage(MIB, MIB));
    source
        .usage
        .insert(pid(102), Err(QueryFailure::PermissionDenied));
    source.usage.insert(pid(104), Err(QueryFailure::Gone));
    snapshot(source)
}

fn pids(ranking: &Ranking<'_>) -> Vec<i32> {
    ranking
        .entries
        .iter()
        .map(|entry| entry.record.identity.pid.get())
        .collect()
}

#[test]
fn ranking_by_footprint_puts_unavailable_values_last() {
    let snapshot: ProcessSnapshot = ranking_fixture();
    let ranking: Ranking<'_> = rank_processes(&snapshot.records, RankMetric::Footprint, None, None);

    assert_eq!(pids(&ranking), vec![101, 103, 100, 102, 104]);
    assert_eq!(
        ranking.entries[0].value,
        Reading::Available(RankValue::Bytes(Bytes::new(50 * MIB)))
    );
    assert_eq!(ranking.entries[0].position, 1);
    // The unavailable processes are present with their reasons. They are
    // not ranked as zero, which would be equal to no footprint.
    assert_eq!(
        ranking.entries[3].value,
        Reading::Unavailable(UnavailableReason::PermissionDenied)
    );
    assert_eq!(
        ranking.entries[4].value,
        Reading::Unavailable(UnavailableReason::ResourceGone)
    );
    assert_eq!(ranking.omitted_available, 0);
    assert_eq!(ranking.omitted_unavailable, 0);
}

#[test]
fn ranking_by_resident_size_uses_the_resident_metric() {
    let snapshot: ProcessSnapshot = ranking_fixture();
    let ranking: Ranking<'_> = rank_processes(&snapshot.records, RankMetric::Resident, None, None);
    assert_eq!(pids(&ranking), vec![100, 103, 101, 102, 104]);
}

#[test]
fn a_limit_counts_the_processes_that_it_removes() {
    let snapshot: ProcessSnapshot = ranking_fixture();
    let ranking: Ranking<'_> =
        rank_processes(&snapshot.records, RankMetric::Footprint, None, Some(2));
    assert_eq!(pids(&ranking), vec![101, 103]);
    assert_eq!(ranking.omitted_available, 1);
    assert_eq!(ranking.omitted_unavailable, 2);

    let ranking: Ranking<'_> =
        rank_processes(&snapshot.records, RankMetric::Footprint, None, Some(4));
    assert_eq!(pids(&ranking), vec![101, 103, 100, 102]);
    assert_eq!(ranking.omitted_available, 0);
    assert_eq!(ranking.omitted_unavailable, 1);
}

#[test]
fn ranking_by_growth_and_cpu_needs_derived_values() {
    let snapshot: ProcessSnapshot = ranking_fixture();

    // With no derived values, each process is present and unavailable.
    let ranking: Ranking<'_> =
        rank_processes(&snapshot.records, RankMetric::FootprintGrowth, None, None);
    assert_eq!(pids(&ranking), vec![100, 101, 102, 103, 104]);
    assert!(
        ranking
            .entries
            .iter()
            .all(|entry| entry.value == Reading::Unavailable(UnavailableReason::NotInitialized))
    );

    let id = |process: i32| record(&snapshot, process).identity.generation_id.clone();
    let growth = |bytes: i128| super::FootprintGrowth {
        delta: ByteDelta::new(bytes).unwrap(),
        elapsed: Nanoseconds::new(1_000),
        first_at: MonotonicNanos::new(0),
        last_at: MonotonicNanos::new(1_000),
        first_sample_id: SampleId::new("s-0").unwrap(),
        last_sample_id: SampleId::new("s-1000").unwrap(),
        available_samples: 2,
        gaps: 0,
    };
    let cpu = |delta: u64, elapsed: u64| CpuUsage {
        cpu_delta: Nanoseconds::new(delta),
        elapsed: Nanoseconds::new(elapsed),
        earlier_sample_id: SampleId::new("s-0").unwrap(),
        later_sample_id: SampleId::new("s-1").unwrap(),
    };
    let mut derived: DerivedMetrics = DerivedMetrics::default();
    derived.growth.insert(id(100), Ok(growth(-5)));
    derived.growth.insert(id(101), Ok(growth(7)));
    derived.growth.insert(id(103), Ok(growth(0)));
    derived
        .growth
        .insert(id(104), Err(DerivedUnavailable::InsufficientSamples));
    // 50 percent, 200 percent, and 50 percent of one core.
    derived.cpu.insert(id(100), Ok(cpu(500, 1_000)));
    derived.cpu.insert(id(101), Ok(cpu(4_000, 2_000)));
    derived.cpu.insert(id(103), Ok(cpu(1_500, 3_000)));
    derived
        .cpu
        .insert(id(102), Err(DerivedUnavailable::CounterReset));

    let ranking: Ranking<'_> = rank_processes(
        &snapshot.records,
        RankMetric::FootprintGrowth,
        Some(&derived),
        None,
    );
    // A decrease is a value: it ranks after no change and before a process
    // with no value.
    assert_eq!(pids(&ranking), vec![101, 103, 100, 102, 104]);
    assert_eq!(
        ranking.entries[2].value,
        Reading::Available(RankValue::Growth(ByteDelta::new(-5).unwrap()))
    );

    let ranking: Ranking<'_> =
        rank_processes(&snapshot.records, RankMetric::Cpu, Some(&derived), None);
    // The two equal ratios are in PID order.
    assert_eq!(pids(&ranking), vec![101, 100, 103, 102, 104]);
    assert_eq!(
        ranking.entries[3].value,
        Reading::Unavailable(UnavailableReason::InconsistentData)
    );
}

#[test]
fn a_responsible_owner_after_pid_reuse_is_not_inherited_by_a_grandchild() {
    // Application A (PID 500) started helper D (PID 260), then quit. PID 500
    // went to application B. D started C (PID 270). C inherited the
    // responsible PID 500, and B started before C, but C descends from D,
    // which is not a member of B.
    let mut d = info(260, 30);
    d.parent_pid = Some(pid(250));
    let mut c = info(270, 95);
    c.parent_pid = Some(pid(260));
    let source: FakeSource = FakeSource::new()
        .with_process(info(250, 10), "/usr/bin/supervisor", usage(MIB, MIB))
        .with_process(d, "/usr/bin/d", usage(MIB, MIB))
        .with_process(c, "/usr/bin/c", usage(MIB, MIB))
        .with_process(
            info(500, 90),
            "/Applications/B.app/Contents/MacOS/B",
            usage(MIB, MIB),
        )
        .with_application(application(500, "com.example.B", true))
        .with_responsible(260, 500)
        .with_responsible(270, 500);
    let snapshot: ProcessSnapshot = snapshot(source);

    for process in [260, 270] {
        assert_eq!(
            record(&snapshot, process).identity.association,
            ProcessAssociation::Unattributed,
            "PID {process}"
        );
    }
}

#[test]
fn a_chain_of_helpers_of_the_owner_is_attributed() {
    // PID 201 is a child of the application. PID 202 is a child of 201. The
    // smaller PID 199 is a child of 201 as well: the order of PIDs does not
    // matter.
    let mut h1 = info(201, 21);
    h1.parent_pid = Some(pid(200));
    let mut h2 = info(202, 22);
    h2.parent_pid = Some(pid(201));
    let mut h0 = info(199, 23);
    h0.parent_pid = Some(pid(201));
    let source: FakeSource = FakeSource::new()
        .with_process(
            info(200, 20),
            "/Applications/Editor.app/Contents/MacOS/Editor",
            usage(MIB, MIB),
        )
        .with_process(h1, "/bin/h1", usage(MIB, MIB))
        .with_process(h2, "/bin/h2", usage(MIB, MIB))
        .with_process(h0, "/bin/h0", usage(MIB, MIB))
        .with_application(application(200, "com.example.Editor", true))
        .with_responsible(201, 200)
        .with_responsible(202, 200)
        .with_responsible(199, 200);
    let snapshot: ProcessSnapshot = snapshot(source);

    for process in [201, 202, 199] {
        assert!(
            record(&snapshot, process)
                .identity
                .association
                .verified_membership()
                .is_some(),
            "PID {process}"
        );
    }
}

#[test]
fn a_list_that_is_not_known_to_be_current_gives_an_unknown_foreground() {
    let mut source: FakeSource = application_fixture().with_responsible(201, 200);
    source.list_current = false;
    let snapshot: ProcessSnapshot = snapshot(source);

    assert!(snapshot.application_list_may_be_stale);
    for process in [200, 201] {
        assert_eq!(
            record(&snapshot, process).foreground,
            ForegroundState::Unknown
        );
    }
    // The membership evidence is unchanged.
    assert!(
        record(&snapshot, 200)
            .identity
            .association
            .verified_membership()
            .is_some()
    );

    let current: ProcessSnapshot = self::snapshot(application_fixture());
    assert!(!current.application_list_may_be_stale);
    assert_eq!(
        record(&current, 200).foreground,
        ForegroundState::Foreground
    );
}

#[test]
fn a_failed_file_evidence_query_keeps_its_reason() {
    let mut source: FakeSource = FakeSource::new()
        .with_process(info(100, 50), "/bin/denied", usage(MIB, MIB))
        .with_process(info(101, 51), "/bin/ok", usage(MIB, MIB));
    source
        .file_failures
        .insert(b"/bin/denied".to_vec(), QueryFailure::PermissionDenied);
    let snapshot: ProcessSnapshot = snapshot(source);

    let denied: &ProcessRecord = record(&snapshot, 100);
    assert_eq!(denied.identity.executable.as_ref().unwrap().file, None);
    assert_eq!(
        denied.executable_file_unavailable,
        Some(UnavailableReason::PermissionDenied)
    );
    let ok: &ProcessRecord = record(&snapshot, 101);
    assert!(ok.identity.executable.as_ref().unwrap().file.is_some());
    assert_eq!(ok.executable_file_unavailable, None);
}
