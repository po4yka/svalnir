//! Smoke tests of the Darwin queries on the host that runs the tests.
//!
//! The assertions inspect only the test process and a child process that
//! the test starts and reaps. No test sends a signal to a different process
//! or depends on a running application.

use std::os::unix::fs::MetadataExt;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use svalnir_core::observation::Reading;
use svalnir_core::process::{Pid, ProcessAssociation};
use svalnir_core::quantity::{Bytes, CounterValue};

use super::{
    CollectionContext, DarwinProcessSource, DerivedMetrics, ProcessCollector, ProcessRecord,
    ProcessSnapshot, ProcessSource, QueryFailure, RankMetric, derive_between, rank_processes,
};

fn own_pid() -> Pid {
    Pid::new(i32::try_from(std::process::id()).unwrap()).unwrap()
}

fn collect() -> ProcessSnapshot {
    ProcessCollector::for_this_host()
        .unwrap()
        .collect()
        .unwrap()
}

/// A child process that does nothing and that the guard kills and reaps.
struct DisposableChild(Child);

impl DisposableChild {
    fn spawn() -> Self {
        Self(
            Command::new("/bin/sleep")
                .arg("60")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        )
    }

    fn pid(&self) -> Pid {
        Pid::new(i32::try_from(self.0.id()).unwrap()).unwrap()
    }

    fn kill_and_reap(&mut self) {
        // The child is a process that this test started. An error means
        // that it exited already.
        let killed = self.0.kill();
        let reaped = self.0.wait();
        drop((killed, reaped));
    }
}

impl Drop for DisposableChild {
    fn drop(&mut self) {
        self.kill_and_reap();
    }
}

#[test]
fn the_context_of_this_process_has_a_boot_identity() {
    let context: CollectionContext = CollectionContext::for_this_process().unwrap();
    assert!(context.boot_id.as_str().starts_with("boot-"));
    assert!(context.boot_id.as_str().len() > "boot-".len());
    let again: CollectionContext = CollectionContext::for_this_process().unwrap();
    assert_eq!(context.boot_id, again.boot_id);
    assert_ne!(context.collector_epoch, again.collector_epoch);
}

#[test]
fn the_test_process_is_in_the_snapshot_with_its_identity() {
    let source: DarwinProcessSource = DarwinProcessSource::new();
    let snapshot: ProcessSnapshot = collect();
    let own: &ProcessRecord = snapshot.find_pid(own_pid()).unwrap();

    assert_eq!(own.identity.uid, source.effective_uid());
    assert!(own.identity.start_time.get() > 0);
    assert_eq!(own.identity.boot_id, snapshot.boot_id);
    assert_eq!(
        snapshot.find_generation(&own.identity.generation_id),
        Some(own)
    );

    // The executable evidence is the file of the test binary.
    let expected = std::fs::metadata(std::env::current_exe().unwrap()).unwrap();
    let executable = own.identity.executable.as_ref().unwrap();
    assert_eq!(executable.file.unwrap().inode.get(), expected.ino());
    assert!(own.display_label().is_some());

    // The inventory has no process of a different effective user.
    assert!(
        snapshot
            .records
            .iter()
            .all(|record| record.identity.uid == source.effective_uid())
    );
    // The records are in PID order with no PID two times.
    assert!(
        snapshot
            .records
            .windows(2)
            .all(|pair| pair[0].identity.pid < pair[1].identity.pid)
    );

    // An association is unattributed or has positive evidence.
    match &own.identity.association {
        ProcessAssociation::Unattributed => {}
        other => assert!(other.verified_membership().is_some()),
    }
}

#[test]
fn the_test_process_has_separate_footprint_and_resident_metrics() {
    let snapshot: ProcessSnapshot = collect();
    let metrics = &snapshot.find_pid(own_pid()).unwrap().metrics;

    let footprint: Bytes = *metrics.footprint.value().unwrap();
    let resident: Bytes = *metrics.resident.value().unwrap();
    let peak: Bytes = *metrics.peak_footprint.value().unwrap();
    // A running test binary has more than 64 KiB of each and less than
    // 64 GiB. A value outside this range shows an incorrect field or unit.
    for value in [footprint, resident, peak] {
        assert!(value.get() > 64 << 10, "{value:?}");
        assert!(value.get() < 64 << 30, "{value:?}");
    }
    // The kernel does not read the peak and the current footprint at one
    // instant, and other test threads allocate memory. Thus the test does
    // not compare the two values.
    assert_eq!(metrics.footprint.source.native_field, "ri_phys_footprint");
    assert_eq!(metrics.resident.source.native_field, "ri_resident_size");
    assert!(metrics.cpu_time.is_available());
    assert!(metrics.disk_read.is_available());
    assert!(metrics.disk_written.is_available());
}

#[test]
fn the_cpu_time_is_in_nanoseconds() {
    let collector = ProcessCollector::for_this_host().unwrap();
    let cpu_time = |snapshot: &ProcessSnapshot| -> CounterValue {
        *snapshot
            .find_pid(own_pid())
            .unwrap()
            .metrics
            .cpu_time
            .value()
            .unwrap()
    };
    let before: ProcessSnapshot = collector.collect().unwrap();

    // Use one core for 500 ms of wall-clock time.
    let started: Instant = Instant::now();
    let mut sink: u64 = 0;
    while started.elapsed() < Duration::from_millis(500) {
        sink = std::hint::black_box(sink.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1));
    }
    let after: ProcessSnapshot = collector.collect().unwrap();

    // The loop used approximately 500 ms of CPU time, or less on a host
    // with a high load. Other test threads can add time. A value in Mach
    // units that was not converted is 41 times smaller on Apple silicon
    // (12 ms at most), and the inverse error is 41 times larger.
    let increase: u64 = cpu_time(&after).increase_since(cpu_time(&before)).unwrap();
    assert!(increase > 50_000_000, "{increase}");
    assert!(increase < 10_000_000_000, "{increase}");

    let derived: DerivedMetrics = derive_between(&before, &after);
    let own = &after.find_pid(own_pid()).unwrap().identity.generation_id;
    let usage = derived.cpu.get(own).unwrap().as_ref().unwrap();
    assert!(usage.core_equivalent_percent() > 5.0);
    assert!(derived.growth.get(own).unwrap().is_ok());

    let ranking = rank_processes(&after.records, RankMetric::Cpu, Some(&derived), None);
    assert_eq!(ranking.entries.len(), after.records.len());
    assert!(
        ranking
            .entries
            .iter()
            .any(|entry| entry.record.identity.pid == own_pid() && entry.value.is_available())
    );
}

#[test]
fn a_child_process_is_recorded_and_is_gone_after_it_exits() {
    let source: DarwinProcessSource = DarwinProcessSource::new();
    let mut child: DisposableChild = DisposableChild::spawn();
    let child_pid: Pid = child.pid();

    let snapshot: ProcessSnapshot = collect();
    let record: ProcessRecord = snapshot.find_pid(child_pid).unwrap().clone();
    assert_eq!(record.parent_pid, Some(own_pid()));
    assert_eq!(record.identity.uid, source.effective_uid());
    assert_eq!(record.display_label().as_deref(), Some("sleep"));
    assert!(record.metrics.footprint.is_available());
    assert_ne!(
        record.identity.generation_id,
        snapshot.find_pid(own_pid()).unwrap().identity.generation_id
    );
    // Two readings of one generation give the same identity.
    let again: ProcessSnapshot = collect();
    let same: &ProcessRecord = again
        .find_generation(&record.identity.generation_id)
        .unwrap();
    assert!(same.identity.has_same_evidence(&record.identity));

    child.kill_and_reap();

    // The reaped process has no data. A failed query is not a zero.
    assert_eq!(source.process_info(child_pid), Err(QueryFailure::Gone));
    assert_eq!(source.usage(child_pid), Err(QueryFailure::Gone));
    let after: ProcessSnapshot = collect();
    assert!(
        after
            .find_generation(&record.identity.generation_id)
            .is_none()
    );

    // A second child is a different generation. The tests with synthetic
    // data cover a new process that gets the PID of an old process.
    let second: DisposableChild = DisposableChild::spawn();
    let snapshot: ProcessSnapshot = collect();
    let second_record: &ProcessRecord = snapshot.find_pid(second.pid()).unwrap();
    assert_ne!(
        second_record.identity.generation_id,
        record.identity.generation_id
    );
    assert!(!second_record.identity.has_same_evidence(&record.identity));
}

#[test]
fn the_responsible_process_query_gives_a_process_or_a_reason() {
    let source: DarwinProcessSource = DarwinProcessSource::new();
    match source.responsible_pid(own_pid()) {
        // The responsible process is a live process: this process or an
        // ancestor application.
        Ok(responsible) => assert!(source.process_info(responsible).is_ok()),
        Err(failure) => assert_eq!(failure, QueryFailure::Unsupported),
    }
}

#[test]
fn a_ranking_of_the_host_keeps_each_record() {
    let snapshot: ProcessSnapshot = collect();
    let ranking = rank_processes(&snapshot.records, RankMetric::Footprint, None, None);
    assert_eq!(ranking.entries.len(), snapshot.records.len());
    // Each available value is before each unavailable value.
    let first_unavailable: usize = ranking
        .entries
        .iter()
        .position(|entry| !entry.value.is_available())
        .unwrap_or(ranking.entries.len());
    assert!(
        ranking
            .entries
            .iter()
            .skip(first_unavailable)
            .all(|entry| !matches!(entry.value, Reading::Available(_)))
    );
}
