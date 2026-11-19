//! Test support: a child process that the test owns and a real stop plan
//! for it. A test never signals the child; the drop ends it, as the owner of
//! the child.

use crate::data::live_records::collect_processes;
use std::{
    path::Path,
    time::{Duration, SystemTime},
};
use svalnir_agent::{
    client::{self, StopMode},
    observe::{self, Host},
    platform::process::{ProcessSnapshot, control_plane_of_this_process},
};
use svalnir_core::{
    action::{ClientRole, Plan},
    authority::AuthorityBinding,
    id::{PlanId, PolicyRevisionId, StepId, TargetId},
    plan::{PlanContext, StopRequest, StopStepIds, build_stop_plan},
    policy::{ApplicationCandidate, EvaluationClock, ProtectionContext, ProtectionFact},
    quantity::Nanoseconds,
    time::WallTime,
};

/// A child process of the test.
pub(crate) struct Child(pub(crate) std::process::Child);

impl Child {
    /// Starts a copy of `/bin/sleep` in `directory` for 30 s. The copy is
    /// outside the system locations, which the catalog protects.
    pub(crate) fn sleeper(directory: &Path) -> Self {
        let sleeper = directory.join("sleeper");
        std::fs::copy("/bin/sleep", &sleeper).unwrap_or_else(|error| panic!("{error}"));
        Self(
            std::process::Command::new(&sleeper)
                .arg("30")
                .spawn()
                .unwrap_or_else(|error| panic!("{error}")),
        )
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        let _killed = self.0.kill();
        let _waited = self.0.wait();
    }
}

/// A real stop plan with the identity `plan_id` for the child, made with a
/// clock `age` in the past and a lifetime of one minute: with an age of
/// more than one minute it is expired now.
pub(crate) fn stop_plan(child: &mut Child, plan_id: &str, age: Duration) -> Plan {
    let pid: u32 = child.0.id();
    let host: Host = Host::open().unwrap_or_else(|error| panic!("{error}"));
    let (clock, _wall) =
        client::control_time(host.context()).unwrap_or_else(|error| panic!("{error}"));
    let wall =
        WallTime::try_from(SystemTime::now() - age).unwrap_or_else(|error| panic!("{error}"));
    let pid = svalnir_core::process::Pid::new(
        i32::try_from(pid).unwrap_or_else(|error| panic!("{error}")),
    )
    .unwrap_or_else(|error| panic!("{error:?}"));
    // The inventory can read a new child only after its start; the test
    // reads the processes again for at most 20 s. The bound is for a host
    // under load (several suites at the same time): the loop ends at the
    // first reading that has the child.
    let mut last: Option<String> = None;
    let snapshot: ProcessSnapshot = (0..200)
        .find_map(|_| {
            let snapshot = collect_processes(&host).unwrap_or_else(|error| panic!("{error}"));
            if snapshot.find_pid(pid).is_some() {
                return Some(snapshot);
            }
            last = Some(format!(
                "{:?}; child status: {:?}",
                snapshot.omissions,
                child.0.try_wait()
            ));
            std::thread::sleep(Duration::from_millis(100));
            None
        })
        .unwrap_or_else(|| panic!("the child is not in the reading; omissions: {last:?}"));
    let record = snapshot
        .find_pid(pid)
        .unwrap_or_else(|| panic!("the child is not in the reading"));
    let candidate = ApplicationCandidate {
        processes: vec![record.identity.clone()],
        membership_snapshot: svalnir_core::id::MembershipSnapshotId::new("ms-test-1")
            .unwrap_or_else(|error| panic!("{error}")),
        foreground: svalnir_core::policy::ForegroundStatus::Background,
        footprint: record.metrics.footprint.clone(),
        hard_protection: ProtectionFact::NotProtected,
    };
    let control_plane = control_plane_of_this_process(&snapshot);
    let protection = ProtectionContext {
        principal: observe::current_uid(),
        control_plane: control_plane.as_deref(),
    };
    let age_nanoseconds: u64 = u64::try_from(age.as_nanos()).unwrap_or(u64::MAX);
    let past = EvaluationClock {
        now: svalnir_core::time::MonotonicNanos::new(
            clock.now.get().saturating_sub(age_nanoseconds),
        ),
        ..clock
    };
    let config = svalnir_core::config::parse_and_validate("schema_version = 1\n")
        .config()
        .cloned()
        .unwrap_or_else(|| panic!("the minimal configuration is not valid"));
    let context = PlanContext {
        plan_id: PlanId::new(plan_id).unwrap_or_else(|error| panic!("{error}")),
        principal: client::principal(ClientRole::Gui),
        authority: AuthorityBinding {
            policy_revision: PolicyRevisionId::new("rev-test")
                .unwrap_or_else(|error| panic!("{error}")),
            action_grants: Vec::new(),
            privilege_grant: None,
        },
        clock: &past,
        created_wall: wall,
        lifetime: Nanoseconds::new(60_000_000_000),
        protections: config.protections(),
        home_directory: None,
    };
    let (strategy, limits) =
        client::manual_stop(StopMode::Graceful, Nanoseconds::new(10_000_000_000));
    let request = StopRequest {
        target_id: TargetId::new("target-test").unwrap_or_else(|error| panic!("{error}")),
        candidate: &candidate,
        protection: &protection,
        strategy,
        steps: StopStepIds {
            graceful: StepId::new("step-graceful").unwrap_or_else(|error| panic!("{error}")),
            force: StepId::new("step-force").unwrap_or_else(|error| panic!("{error}")),
        },
        limits,
    };
    let outcome = build_stop_plan(&context, &request).unwrap_or_else(|error| panic!("{error}"));
    let omitted = format!("{:?}", outcome.preview.omitted);
    outcome
        .plan
        .unwrap_or_else(|| panic!("the plan builder made no plan: {omitted}"))
}
