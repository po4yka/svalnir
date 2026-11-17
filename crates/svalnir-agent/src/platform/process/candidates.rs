//! The application and job instances of a process snapshot as candidates of
//! a memory-guard evaluation.
//!
//! Each function is pure: it reads a snapshot and no live process. A
//! candidate is one membership snapshot: the verified members of one
//! instance, their attributed footprint, the foreground status, and the hard
//! protection from the catalog of `svalnir_core::policy`.

use std::collections::{BTreeMap, BTreeSet};

use svalnir_core::id::{ApplicationInstanceId, MembershipSnapshotId, SampleId};
use svalnir_core::observation::{
    Coverage, MetricKind, Observation, Reading, Sample, Scope, Source, UnavailableReason, Unit,
    metric,
};
use svalnir_core::policy::{
    ApplicationCandidate, ControlPlaneProcess, ForegroundStatus, ProtectionContext, hard_protection,
};
use svalnir_core::process::{Pid, ProcessIdentity, VerifiedMembership};
use svalnir_core::quantity::Bytes;
use svalnir_core::time::{MonotonicNanos, WallTime};

use super::inventory::{ForegroundState, ProcessRecord, ProcessSnapshot};

/// The largest number of ancestors that [`control_plane`] follows.
pub const MAX_CONTROL_PLANE_ANCESTORS: usize = 64;

/// The process with `own_pid` and its ancestors in `snapshot`, as the
/// control plane of a protection lookup.
///
/// The function follows the parent PID of each record. It stops at
/// `launchd`, at a parent that is not in the snapshot, and after
/// [`MAX_CONTROL_PLANE_ANCESTORS`] ancestors. A snapshot has only the
/// processes of one user, so an ancestor of a different user is not in the
/// result; the catalog protects such a process by its owner.
///
/// Returns `None` when the snapshot has no record of `own_pid`: then the
/// ancestors are not known.
pub fn control_plane(snapshot: &ProcessSnapshot, own_pid: Pid) -> Option<Vec<ControlPlaneProcess>> {
    let mut chain: Vec<ControlPlaneProcess> = Vec::new();
    let mut current: &ProcessRecord = snapshot.find_pid(own_pid)?;
    loop {
        chain.push(ControlPlaneProcess {
            pid: current.identity.pid,
            start_time: current.identity.start_time,
        });
        if chain.len() > MAX_CONTROL_PLANE_ANCESTORS {
            break;
        }
        let Some(parent) = current.parent_pid.and_then(|pid| snapshot.find_pid(pid)) else {
            break;
        };
        // A parent that is already in the chain is a PID that was reused.
        if chain.iter().any(|member| member.pid == parent.identity.pid) {
            break;
        }
        current = parent;
    }
    Some(chain)
}

/// The control plane of the calling process in `snapshot`.
///
/// Returns `None` when the snapshot has no record of the calling process.
pub fn control_plane_of_this_process(
    snapshot: &ProcessSnapshot,
) -> Option<Vec<ControlPlaneProcess>> {
    let own_pid: Pid = i32::try_from(std::process::id())
        .ok()
        .and_then(|pid| Pid::new(pid).ok())?;
    control_plane(snapshot, own_pid)
}

/// The verified members of each application and job instance.
fn instances(snapshot: &ProcessSnapshot) -> BTreeMap<&ApplicationInstanceId, Vec<&ProcessRecord>> {
    let mut instances: BTreeMap<&ApplicationInstanceId, Vec<&ProcessRecord>> = BTreeMap::new();
    for record in &snapshot.records {
        if let Some(
            VerifiedMembership::Application { instance_id, .. }
            | VerifiedMembership::ManagedJob { instance_id, .. },
        ) = record.identity.association.verified_membership()
        {
            instances.entry(instance_id).or_default().push(record);
        }
    }
    instances
}

/// A 64-bit FNV-1a hash of the member identities, for the identity of a
/// membership snapshot. A different member set gives a different identity.
fn membership_fingerprint(members: &[&ProcessRecord]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for member in members {
        for byte in member
            .identity
            .generation_id
            .as_str()
            .bytes()
            .chain(std::iter::once(0))
        {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    hash
}

/// The sum of the member footprints as one observation of the membership
/// snapshot. The observation has no value when a member has none: a sum
/// with a missing member is not the footprint of the application.
fn attributed_footprint(
    members: &[&ProcessRecord],
    membership: &MembershipSnapshotId,
    captured_at: WallTime,
) -> Option<Observation<Bytes>> {
    let first: &ProcessRecord = members.first()?;
    let first_sample: &Sample = first.metrics.sample();
    let mut reading: Reading<Bytes> = Reading::Available(Bytes::ZERO);
    let mut started: MonotonicNanos = first_sample.started_monotonic_ns;
    let mut finished: MonotonicNanos = first_sample.finished_monotonic_ns;
    for member in members {
        let footprint: &Observation<Bytes> = &member.metrics.footprint;
        started = started.min(footprint.sample.started_monotonic_ns);
        finished = finished.max(footprint.sample.finished_monotonic_ns);
        reading = match (reading, footprint.value(), &footprint.reading) {
            (Reading::Available(total), Some(bytes), _) => total.checked_add(*bytes).map_or(
                Reading::Unavailable(UnavailableReason::Overflow),
                Reading::Available,
            ),
            (Reading::Available(_), None, Reading::Unavailable(reason)) => {
                Reading::Unavailable(reason.clone())
            }
            (Reading::Available(_), None, _) => {
                Reading::Unavailable(UnavailableReason::InconsistentData)
            }
            (unavailable, _, _) => unavailable,
        };
    }
    let coverage: Coverage = if reading.is_available() {
        Coverage::Complete
    } else {
        Coverage::Partial
    };
    Some(Observation {
        metric_id: metric::APPLICATION_ATTRIBUTED_FOOTPRINT_BYTES,
        scope: Scope::application(membership.clone()),
        reading,
        unit: Unit::Byte,
        kind: MetricKind::Gauge,
        coverage,
        source: Source {
            native_field: "sum(ri_phys_footprint) of the membership snapshot".to_owned(),
            ..first.metrics.footprint.source.clone()
        },
        sample: Sample {
            sample_id: SampleId::new(format!("as-{}-{}", started.get(), first.identity.pid.get()))
                .ok()?,
            started_monotonic_ns: started,
            finished_monotonic_ns: finished,
            captured_at,
            ..first_sample.clone()
        },
    })
}

/// The foreground status of an instance from the states of its members.
fn foreground_status(members: &[&ProcessRecord]) -> ForegroundStatus {
    if members
        .iter()
        .any(|member| member.foreground == ForegroundState::Foreground)
    {
        ForegroundStatus::Foreground
    } else if members
        .iter()
        .all(|member| member.foreground == ForegroundState::Background)
    {
        ForegroundStatus::Background
    } else {
        ForegroundStatus::Unknown
    }
}

/// The application and job instances of a process snapshot as candidates of
/// a memory-guard evaluation.
///
/// Only a verified membership makes a process a member. A process with no
/// verified membership is in no candidate. The hard protection of each
/// candidate comes from [`hard_protection`] with `protection`. An instance
/// for which no membership identity or footprint observation can be made has
/// no candidate; [`instance_count`] counts it.
pub fn application_candidates(
    snapshot: &ProcessSnapshot,
    protection: &ProtectionContext<'_>,
) -> Vec<ApplicationCandidate> {
    instances(snapshot)
        .into_iter()
        .filter_map(|(instance_id, members)| {
            // The identity has the instance, the member count, and a hash of
            // the members, so a membership change makes a new identity.
            let instance: &str = instance_id.as_str();
            let instance: &str = instance.get(..80).unwrap_or(instance);
            let membership = MembershipSnapshotId::new(format!(
                "ms-{instance}-{}-{:016x}",
                members.len(),
                membership_fingerprint(&members)
            ))
            .ok()?;
            let processes: Vec<ProcessIdentity> = members
                .iter()
                .map(|member| member.identity.clone())
                .collect();
            Some(ApplicationCandidate {
                footprint: attributed_footprint(&members, &membership, snapshot.captured_at)?,
                hard_protection: hard_protection(&processes, protection),
                processes,
                membership_snapshot: membership,
                foreground: foreground_status(&members),
            })
        })
        .collect()
}

/// The number of application and job instances with a verified member.
pub fn instance_count(snapshot: &ProcessSnapshot) -> usize {
    snapshot
        .records
        .iter()
        .filter_map(
            |record| match record.identity.association.verified_membership() {
                Some(
                    VerifiedMembership::Application { instance_id, .. }
                    | VerifiedMembership::ManagedJob { instance_id, .. },
                ) => Some(instance_id),
                None => None,
            },
        )
        .collect::<BTreeSet<&ApplicationInstanceId>>()
        .len()
}

#[cfg(test)]
mod tests {
    use svalnir_core::observation::{Coverage, Reading, UnavailableReason};
    use svalnir_core::policy::{
        ControlPlaneProcess, ForegroundStatus, ProtectionContext, ProtectionFact,
    };
    use svalnir_core::process::Uid;
    use svalnir_core::quantity::Bytes;

    use super::super::fake::{FakeSource, USER, application, info, pid, usage};
    use super::super::inventory::ProcessSnapshot;
    use super::{
        MAX_CONTROL_PLANE_ANCESTORS, application_candidates, control_plane, instance_count,
    };

    const MIB: u64 = 1 << 20;
    const EDITOR: &str = "/Applications/Editor.app/Contents/MacOS/editor";
    const HELPER: &str = "/Applications/Editor.app/Contents/Helpers/helper";

    /// An editor (PID 200) with a helper (PID 201), a shell (PID 300) that is
    /// the parent of this tool (PID 301), and a process with no membership
    /// (PID 400).
    fn snapshot() -> ProcessSnapshot {
        let mut tool = info(301, 61);
        tool.parent_pid = Some(pid(300));
        FakeSource::new()
            .with_process(info(200, 50), EDITOR, usage(3_072 * MIB, MIB))
            .with_process(info(201, 51), HELPER, usage(1_024 * MIB, MIB))
            .with_process(
                info(300, 60),
                "/Applications/Term.app/Contents/MacOS/term",
                usage(MIB, MIB),
            )
            .with_process(tool, "/Users/me/bin/tool", usage(MIB, MIB))
            .with_process(info(400, 70), "/Users/me/bin/other", usage(MIB, MIB))
            .with_application(application(200, "com.example.editor", true))
            .with_application(application(300, "com.example.term", false))
            .with_responsible(201, 200)
            .collector()
            .collect()
            .unwrap()
    }

    fn context(control_plane: Option<&[ControlPlaneProcess]>) -> ProtectionContext<'_> {
        ProtectionContext {
            principal: Uid::new(USER),
            control_plane,
        }
    }

    #[test]
    fn candidates_have_only_verified_members() {
        let snapshot = snapshot();
        let candidates = application_candidates(&snapshot, &context(Some(&[])));
        // The editor and its helper are one instance, and the terminal is
        // one. The other two processes have no verified membership.
        assert_eq!(candidates.len(), 2);
        assert_eq!(instance_count(&snapshot), 2);
        let editor = candidates
            .iter()
            .find(|candidate| candidate.processes.len() == 2)
            .unwrap();
        assert_eq!(editor.foreground, ForegroundStatus::Foreground);
        assert_eq!(editor.footprint.value(), Some(&Bytes::new(4_096 * MIB)));
        assert_eq!(editor.footprint.coverage, Coverage::Complete);
        assert_eq!(
            editor.footprint.metric_id.as_str(),
            "application.attributed_footprint_bytes"
        );
        assert!(editor.membership_snapshot.as_str().starts_with("ms-"));
        assert_eq!(editor.hard_protection, ProtectionFact::NotProtected);

        // A different member set has a different identity.
        let mut smaller = snapshot.clone();
        smaller
            .records
            .retain(|record| record.identity.pid != pid(201));
        let other = application_candidates(&smaller, &context(Some(&[])));
        let other_editor = other
            .iter()
            .find(|candidate| candidate.processes[0].pid == pid(200))
            .unwrap();
        assert_ne!(other_editor.membership_snapshot, editor.membership_snapshot);
    }

    #[test]
    fn a_member_with_no_footprint_makes_the_sum_unavailable() {
        let mut snapshot = snapshot();
        let helper = snapshot
            .records
            .iter_mut()
            .find(|record| record.identity.pid == pid(201))
            .unwrap();
        helper.metrics.footprint.reading =
            Reading::Unavailable(UnavailableReason::PermissionDenied);
        let candidates = application_candidates(&snapshot, &context(Some(&[])));
        let editor = candidates
            .iter()
            .find(|candidate| candidate.processes.len() == 2)
            .unwrap();
        assert_eq!(editor.footprint.value(), None);
        assert_eq!(
            editor.footprint.reason(),
            Some(&UnavailableReason::PermissionDenied)
        );
        assert_eq!(editor.footprint.coverage, Coverage::Partial);
    }

    #[test]
    fn the_control_plane_is_this_process_and_its_ancestors_in_the_snapshot() {
        let snapshot = snapshot();
        let chain = control_plane(&snapshot, pid(301)).unwrap();
        // The tool and the shell. The parent of the shell is `launchd`,
        // which is not a process of the user.
        let pids: Vec<i32> = chain.iter().map(|member| member.pid.get()).collect();
        assert_eq!(pids, vec![301, 300]);
        assert_eq!(
            chain[1].start_time,
            snapshot.find_pid(pid(300)).unwrap().identity.start_time
        );

        // The terminal is an ancestor, so its instance is protected. The
        // editor is not.
        let candidates = application_candidates(&snapshot, &context(Some(&chain)));
        let protection = |process: i32| {
            candidates
                .iter()
                .find(|candidate| candidate.processes[0].pid == pid(process))
                .unwrap()
                .hard_protection
        };
        assert_eq!(protection(300), ProtectionFact::Protected);
        assert_eq!(protection(200), ProtectionFact::NotProtected);
    }

    #[test]
    fn a_snapshot_with_no_record_of_this_process_gives_no_control_plane() {
        let snapshot = snapshot();
        assert_eq!(control_plane(&snapshot, pid(999)), None);
        // With no control plane, no instance is known to be outside it.
        let candidates = application_candidates(&snapshot, &context(None));
        assert!(
            candidates
                .iter()
                .all(|candidate| candidate.hard_protection == ProtectionFact::Unknown)
        );
    }

    #[test]
    fn a_parent_cycle_ends_the_control_plane() {
        let mut first = info(500, 80);
        first.parent_pid = Some(pid(501));
        let mut second = info(501, 81);
        second.parent_pid = Some(pid(500));
        let snapshot: ProcessSnapshot = FakeSource::new()
            .with_process(first, "/Users/me/bin/a", usage(MIB, MIB))
            .with_process(second, "/Users/me/bin/b", usage(MIB, MIB))
            .collector()
            .collect()
            .unwrap();
        let chain = control_plane(&snapshot, pid(500)).unwrap();
        assert_eq!(chain.len(), 2);
        assert!(chain.len() <= MAX_CONTROL_PLANE_ANCESTORS + 1);
    }
}
