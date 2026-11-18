//! A rearm request of the queue goes to the controller of the agent; a
//! coordinator of a client rejects it.

use svalnir_core::authority::Generation;
use svalnir_core::id::{IncidentId, RequestId};
use svalnir_core::policy::PolicyId;

use super::super::{Start, code, rearm_rejection};
use super::support::{Bench, open_journal, queued};
use crate::journal::{CoordinatorRole, RequestBody, RequestCompletion, RequestStatus};

fn rearm_body() -> RequestBody {
    RequestBody::Rearm {
        policy: PolicyId::DiskGuard,
        incident_id: IncidentId::new("incident_disk_1").unwrap(),
        generation: Generation::new(1),
    }
}

fn status(bench: &Bench, id: &str) -> Option<RequestStatus> {
    open_journal(&bench.tree.database)
        .request_status(&RequestId::new(id).unwrap())
        .unwrap()
}

#[test]
fn a_coordinator_of_a_client_rejects_a_rearm_request() {
    let mut bench = Bench::new();
    let mut coordinator = bench.start();
    open_journal(&bench.tree.database)
        .enqueue_request(&queued("request_1", rearm_body(), bench.clock.now()))
        .unwrap();
    coordinator.step();
    assert_eq!(coordinator.take_rearm(), None);
    match status(&bench, "request_1") {
        Some(RequestStatus::Completed {
            completion: RequestCompletion::Rejected { error },
        }) => {
            assert_eq!(error.code.as_str(), code::AGENT_NOT_RUNNING);
            assert_eq!(error.plan_id, None);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_coordinator_of_the_agent_gives_a_rearm_request_to_its_caller() {
    let mut bench = Bench::new();
    let Start::Coordinating(mut coordinator) =
        bench.start_with(|_, config| config.role = CoordinatorRole::Agent)
    else {
        panic!("a different coordinator holds the lock");
    };
    {
        let mut journal = open_journal(&bench.tree.database);
        journal
            .enqueue_request(&queued("request_1", rearm_body(), bench.clock.now()))
            .unwrap();
        journal
            .enqueue_request(&queued("request_2", rearm_body(), bench.clock.now()))
            .unwrap();
    }
    coordinator.step();
    // The coordinator claimed the first request and keeps it. It claims
    // no further request while the first one waits.
    assert!(matches!(
        status(&bench, "request_1"),
        Some(RequestStatus::Claimed { .. })
    ));
    coordinator.step();
    assert_eq!(status(&bench, "request_2"), Some(RequestStatus::Queued));

    let pending = coordinator.take_rearm().unwrap();
    assert_eq!(pending.request_id.as_str(), "request_1");
    assert_eq!(pending.request.policy, PolicyId::DiskGuard);
    assert_eq!(pending.request.generation, Generation::new(1));
    assert_eq!(pending.request.principal, super::support::principal().uid);
    assert_eq!(coordinator.take_rearm(), None);
    let completion = RequestCompletion::Rearmed {
        incident_id: pending.request.incident_id.clone(),
        previous_generation: Generation::new(1),
        new_generation: Generation::new(2),
    };
    coordinator.complete_rearm(pending.request_id, completion.clone());
    assert_eq!(
        status(&bench, "request_1"),
        Some(RequestStatus::Completed { completion })
    );

    // The next step claims the second request.
    coordinator.step();
    let second = coordinator.take_rearm().unwrap();
    assert_eq!(second.request_id.as_str(), "request_2");
    let rejected = RequestCompletion::Rejected {
        error: rearm_rejection(
            "generation_conflict",
            svalnir_core::action::ErrorFamily::Evidence,
        ),
    };
    coordinator.complete_rearm(second.request_id, rejected.clone());
    assert_eq!(
        status(&bench, "request_2"),
        Some(RequestStatus::Completed {
            completion: rejected
        })
    );
}
