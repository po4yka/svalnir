//! The rearm requests of the journal queue (`policy rearm`).
//!
//! The budget generation of an incident is state of the controller of the
//! agent, not of the coordinator. The coordinator of an agent claims a
//! rearm request and keeps it; the runtime takes it, decides it against
//! the authority record and the controller state, and gives the
//! completion back. A coordinator of a client rejects a rearm request with
//! [`code::AGENT_NOT_RUNNING`](super::code::AGENT_NOT_RUNNING).

use svalnir_core::grant::RearmRequest;
use svalnir_core::id::RequestId;

use super::core::Coordinator;
use super::ports::CoordinatorJournal;
use crate::journal::{RequestBody, RequestCompletion};

/// A rearm request that the coordinator of the agent claimed and that
/// waits for the controller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingRearm {
    /// The identity of the queued request.
    pub request_id: RequestId,
    /// The request, with the user of the queued request as its principal.
    pub request: RearmRequest,
}

impl<J: CoordinatorJournal> Coordinator<J> {
    /// Takes the rearm request that this coordinator claimed, when it has
    /// one. The caller decides it and gives the result to
    /// [`Coordinator::complete_rearm`]. Until then the claim stays in the
    /// journal: when this lifetime ends first, the next coordinator gets
    /// the request again, and the generation check of the rearm refuses a
    /// request that an earlier lifetime applied.
    pub fn take_rearm(&mut self) -> Option<PendingRearm> {
        let claimed = self.pending_rearm.take()?;
        let RequestBody::Rearm {
            policy,
            incident_id,
            generation,
        } = claimed.request.body
        else {
            return None;
        };
        Some(PendingRearm {
            request_id: claimed.request.request_id,
            request: RearmRequest {
                principal: claimed.request.principal.uid,
                policy,
                incident_id,
                generation,
            },
        })
    }

    /// Records the completion of a rearm request that
    /// [`Coordinator::take_rearm`] gave: [`RequestCompletion::Rearmed`], or
    /// [`RequestCompletion::Rejected`] with the code of the refusal. A
    /// completion that a storage failure stopped is written again before
    /// the next claim.
    pub fn complete_rearm(&mut self, request_id: RequestId, completion: RequestCompletion) {
        self.record_completion(request_id, completion);
    }
}
