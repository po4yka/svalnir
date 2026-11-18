//! The rearm request of the queue (`policy rearm`).

use svalnir_core::authority::Generation;
use svalnir_core::id::{IncidentId, RequestId};
use svalnir_core::policy::PolicyId;

use super::super::{
    CoordinatorLock, CoordinatorRole, Enqueued, QueuedRequest, RequestBody, RequestCompletion,
    RequestStatus,
};
use super::{Fixture, epoch, principal, wall};

fn rearm_request() -> QueuedRequest {
    QueuedRequest {
        request_id: RequestId::new("request_rearm").unwrap(),
        principal: principal(),
        body: RequestBody::Rearm {
            policy: PolicyId::MemoryGuard,
            incident_id: IncidentId::new("incident_memory_1").unwrap(),
            generation: Generation::new(1),
        },
        enqueued_at: wall(0),
    }
}

#[test]
fn a_rearm_request_is_queued_claimed_and_completed_with_its_generations() {
    let fixture = Fixture::new();
    let mut journal = fixture.open();
    let lock = CoordinatorLock::try_acquire(&fixture.path(), CoordinatorRole::Agent).unwrap();
    journal
        .begin_coordination(&lock, &epoch("epoch_1"), wall(0))
        .unwrap();
    let request = rearm_request();
    assert_eq!(journal.enqueue_request(&request).unwrap(), Enqueued::New);
    // The same request again makes no second request.
    assert_eq!(
        journal.enqueue_request(&request).unwrap(),
        Enqueued::Existing(RequestStatus::Queued)
    );

    // The row has the kind and the values of the request.
    let claimed = journal
        .claim_next_request(&epoch("epoch_1"))
        .unwrap()
        .unwrap();
    assert_eq!(claimed.request, request);
    assert!(!claimed.redelivered);

    let completion = RequestCompletion::Rearmed {
        incident_id: IncidentId::new("incident_memory_1").unwrap(),
        previous_generation: Generation::new(1),
        new_generation: Generation::new(2),
    };
    journal
        .complete_request(&request.request_id, &epoch("epoch_1"), &completion)
        .unwrap();
    // A client on a new handle reads the completion.
    drop(journal);
    let client = fixture.open();
    assert_eq!(
        client.request_status(&request.request_id).unwrap(),
        Some(RequestStatus::Completed { completion })
    );
}

#[test]
fn the_rearm_request_has_a_stable_encoding() {
    let request = rearm_request();
    let body = serde_json::to_value(&request.body).unwrap();
    assert_eq!(
        body,
        serde_json::json!({
            "kind": "rearm",
            "policy": "memory-guard",
            "incident_id": "incident_memory_1",
            "generation": "1",
        })
    );
    assert_eq!(
        serde_json::from_value::<RequestBody>(body).unwrap(),
        request.body
    );
    // A guard that this build does not know is not decoded.
    let unknown = serde_json::json!({
        "kind": "rearm",
        "policy": "network-guard",
        "incident_id": "incident_memory_1",
        "generation": "1",
    });
    assert!(serde_json::from_value::<RequestBody>(unknown).is_err());
    let completion = RequestCompletion::Rearmed {
        incident_id: IncidentId::new("incident_memory_1").unwrap(),
        previous_generation: Generation::new(1),
        new_generation: Generation::new(2),
    };
    assert_eq!(
        serde_json::to_value(&completion).unwrap(),
        serde_json::json!({
            "result": "rearmed",
            "incident_id": "incident_memory_1",
            "previous_generation": "1",
            "new_generation": "2",
        })
    );
}
