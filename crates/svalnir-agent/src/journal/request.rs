//! The request queue between a client and the coordinator.
//!
//! Milestone 2 has no socket. A client writes a request to this queue, and
//! the coordinator that holds the coordinator lock claims it, executes it,
//! and writes its completion. The client reads the status of its request.
//!
//! A request has no authority of its own. An apply request names a plan
//! and the digest that the client reviewed; the coordinator does each
//! admission check, and the plan is consumed one time whatever the number
//! of requests that name it. A request that an earlier executor lifetime
//! claimed and did not complete goes back to the queue when a new
//! coordinator registers. The coordinator executes it through the calls of
//! the journal, which return the result of the earlier apply and submit no
//! second call.

use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use svalnir_core::action::{
    ActionError, ActionStage, DispatchState, ErrorCode, ErrorFamily, PlanApproval, Principal,
    StopFence,
};
use svalnir_core::authority::Generation;
use svalnir_core::digest::ContentDigest;
use svalnir_core::id::{ExecutorEpochId, IncidentId, OperationId, RequestId};
use svalnir_core::policy::PolicyId;
use svalnir_core::time::WallTime;

use super::error::{OperationJournalError, SequenceViolation};
use super::{OperationJournal, check_admission_capacity, commit, coordination, decode, encode};

/// The largest number of requests that are not completed. A new request
/// above it is refused with [`OperationJournalError::QueueFull`].
pub const MAX_OPEN_REQUESTS: u32 = 256;

/// What a client requests.
///
/// JSON encodes the value as an object with a `kind` field. An unknown
/// `kind` is rejected.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RequestBody {
    /// Apply a stored plan.
    Apply {
        /// The plan and the digest that the client reviewed.
        approval: PlanApproval,
    },
    /// Inhibit the future dispatch of an operation.
    Cancel {
        /// The operation.
        operation_id: OperationId,
    },
    /// Acknowledge an `UnknownOutcome` operation and release its leases.
    Acknowledge {
        /// The operation.
        operation_id: OperationId,
    },
    /// Rearm an incident of a guard: record a new budget generation
    /// (`policy rearm`). Only the controller of an agent serves it.
    Rearm {
        /// The guard.
        policy: PolicyId,
        /// The incident.
        incident_id: IncidentId,
        /// The budget generation that the user saw.
        generation: Generation,
    },
}

/// One request of a client.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueuedRequest {
    /// The identity of the request. The same identity with different
    /// content is an invalid request.
    pub request_id: RequestId,
    /// The user and client that made the request. The process that writes
    /// the request gives this value; the queue is same-user state and is
    /// not an authentication boundary.
    pub principal: Principal,
    /// What the client requests.
    pub body: RequestBody,
    /// The wall-clock time of the request, for history and retention.
    pub enqueued_at: WallTime,
}

/// The result of a request.
///
/// JSON encodes the value as an object with a `result` field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum RequestCompletion {
    /// The plan has this operation: this request admitted it, or an
    /// earlier apply did. The operation record has its state.
    Operation {
        /// The operation.
        operation_id: OperationId,
    },
    /// The request was rejected. No operation was made for it.
    Rejected {
        /// The rejection.
        error: ActionError,
    },
    /// The stop request was recorded.
    Stopped {
        /// How the stop was recorded.
        fence: StopFence,
    },
    /// The journal has the acknowledgment of the operation, and its
    /// leases are released.
    Acknowledged {
        /// The time of the acknowledgment.
        acknowledged_at: WallTime,
        /// True when an earlier request recorded the acknowledgment.
        repeated: bool,
    },
    /// The controller of the agent recorded a new budget generation of the
    /// incident.
    Rearmed {
        /// The incident.
        incident_id: IncidentId,
        /// The generation that the rearm ended.
        previous_generation: Generation,
        /// The generation that the rearm authorized.
        new_generation: Generation,
    },
}

/// The state of a request in the queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestStatus {
    /// No coordinator claimed the request.
    Queued,
    /// A coordinator claimed the request and did not complete it. The
    /// claim is not evidence that the coordinator runs.
    Claimed {
        /// The executor lifetime of the claim.
        executor_epoch: ExecutorEpochId,
    },
    /// The request is complete.
    Completed {
        /// The result.
        completion: RequestCompletion,
    },
}

/// The result of an enqueue call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Enqueued {
    /// The request is new, and it is in the queue.
    New,
    /// The queue has the same request already, with this status. No second
    /// request was made.
    Existing(RequestStatus),
}

/// A request that a coordinator claimed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimedRequest {
    /// The request.
    pub request: QueuedRequest,
    /// Whether an earlier executor lifetime claimed the request and did
    /// not complete it. The effect of that claim is not known from the
    /// queue: the journal calls return the result of an earlier apply.
    pub redelivered: bool,
}

/// The code of the rejection of a request row that this build cannot
/// decode.
pub const REQUEST_NOT_DECODABLE: &str = "request_not_decodable";

/// The completion of a request row that this build cannot decode: a
/// rejection of the family `request`, with no call and no operation.
fn not_decodable() -> Option<RequestCompletion> {
    Some(RequestCompletion::Rejected {
        error: ActionError {
            code: ErrorCode::new(REQUEST_NOT_DECODABLE).ok()?,
            family: ErrorFamily::Request,
            stage: ActionStage::Admission,
            dispatch: DispatchState::NotSubmitted,
            plan_id: None,
            operation_id: None,
            step_id: None,
        },
    })
}

/// One `request` row.
struct RequestRow {
    digest: String,
    state: String,
    claim_epoch: Option<String>,
    completion: Option<String>,
}

fn find_request(
    connection: &Connection,
    request_id: &RequestId,
) -> Result<Option<RequestRow>, OperationJournalError> {
    Ok(connection
        .query_row(
            "SELECT digest, state, claim_epoch, completion FROM request WHERE request_id = ?1",
            [request_id.as_str()],
            |row| {
                Ok(RequestRow {
                    digest: row.get(0)?,
                    state: row.get(1)?,
                    claim_epoch: row.get(2)?,
                    completion: row.get(3)?,
                })
            },
        )
        .optional()?)
}

impl RequestRow {
    fn status(&self) -> Result<RequestStatus, OperationJournalError> {
        let invalid = || OperationJournalError::row("request", "state");
        match (self.state.as_str(), &self.claim_epoch, &self.completion) {
            ("queued", None, None) => Ok(RequestStatus::Queued),
            ("claimed", Some(epoch), None) => Ok(RequestStatus::Claimed {
                executor_epoch: ExecutorEpochId::new(epoch.as_str()).map_err(|_| invalid())?,
            }),
            ("completed", _, Some(completion)) => Ok(RequestStatus::Completed {
                completion: decode("request", completion)?,
            }),
            _ => Err(invalid()),
        }
    }
}

impl OperationJournal {
    /// Puts a request in the queue. The same request again makes no
    /// second request and returns the status of the first one.
    ///
    /// # Errors
    ///
    /// Returns [`OperationJournalError::Conflict`] when the identity
    /// exists with different content,
    /// [`OperationJournalError::QueueFull`] when the queue has
    /// [`MAX_OPEN_REQUESTS`] open requests,
    /// [`OperationJournalError::AdmissionStopped`] when the journal cannot
    /// keep its size limits, or a storage error. On an error the request
    /// is not in the queue.
    pub fn enqueue_request(
        &mut self,
        request: &QueuedRequest,
    ) -> Result<Enqueued, OperationJournalError> {
        let payload: String = encode(request)?;
        let digest: ContentDigest =
            ContentDigest::of_json(request).map_err(OperationJournalError::Encode)?;
        let Self {
            connection,
            path,
            limits,
            commit_fault,
            ..
        } = self;
        let transaction = Self::write_transaction(connection)?;
        if let Some(existing) = find_request(&transaction, &request.request_id)? {
            return if existing.digest == digest.as_str() {
                Ok(Enqueued::Existing(existing.status()?))
            } else {
                Err(OperationJournalError::Conflict)
            };
        }
        let open: i64 = transaction.query_row(
            "SELECT count(*) FROM request WHERE state <> 'completed'",
            [],
            |row| row.get(0),
        )?;
        if open >= i64::from(MAX_OPEN_REQUESTS) {
            return Err(OperationJournalError::QueueFull {
                limit: MAX_OPEN_REQUESTS,
            });
        }
        check_admission_capacity(&transaction, path, limits)?;
        transaction.execute(
            "INSERT INTO request (request_id, digest, payload, enqueued_unix_s, state) \
             VALUES (?1, ?2, ?3, ?4, 'queued')",
            params![
                request.request_id.as_str(),
                digest.as_str(),
                payload,
                request.enqueued_at.unix_seconds(),
            ],
        )?;
        commit(transaction, commit_fault)?;
        Ok(Enqueued::New)
    }

    /// Claims the oldest request that no coordinator claimed, for the
    /// registered coordinator of the lifetime `epoch`. Each request is
    /// claimed by one call only.
    ///
    /// A request row that this build cannot decode (a row of a newer
    /// client, or a damaged row) is completed as rejected with the code
    /// [`REQUEST_NOT_DECODABLE`], and the call continues with the next
    /// row.
    ///
    /// # Errors
    ///
    /// Returns [`OperationJournalError::Sequence`] when `epoch` is not the
    /// registered lifetime, or a storage error. On an error no request was
    /// claimed.
    pub fn claim_next_request(
        &mut self,
        epoch: &ExecutorEpochId,
    ) -> Result<Option<ClaimedRequest>, OperationJournalError> {
        let Self {
            connection,
            commit_fault,
            ..
        } = self;
        let transaction = Self::write_transaction(connection)?;
        coordination::check_registered(&transaction, epoch)?;
        // Each turn of the loop completes one row that cannot be decoded,
        // so the loop ends: the queue has at most `MAX_OPEN_REQUESTS` open
        // rows and this transaction is the only writer.
        let mut rejected: bool = false;
        let claimed: Option<ClaimedRequest> = loop {
            let next: Option<(i64, String, bool)> = transaction
                .query_row(
                    "SELECT seq, payload, redelivered FROM request \
                     WHERE state = 'queued' ORDER BY seq LIMIT 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?;
            let Some((seq, payload, redelivered)) = next else {
                break None;
            };
            match decode::<QueuedRequest>("request", &payload) {
                Ok(request) => {
                    transaction.execute(
                        "UPDATE request SET state = 'claimed', claim_epoch = ?1 WHERE seq = ?2",
                        params![epoch.as_str(), seq],
                    )?;
                    break Some(ClaimedRequest {
                        request,
                        redelivered,
                    });
                }
                Err(error) => {
                    // A row that this build cannot decode is rejected, so
                    // that it does not stop each request after it.
                    let Some(completion) = not_decodable() else {
                        return Err(error);
                    };
                    transaction.execute(
                        "UPDATE request SET state = 'completed', claim_epoch = ?1, \
                         completion = ?2 WHERE seq = ?3",
                        params![epoch.as_str(), encode(&completion)?, seq],
                    )?;
                    rejected = true;
                }
            }
        };
        if claimed.is_some() || rejected {
            commit(transaction, commit_fault)?;
        }
        Ok(claimed)
    }

    /// Records the result of a request that the lifetime `epoch` claimed.
    /// The same result again is not an error.
    ///
    /// # Errors
    ///
    /// Returns [`OperationJournalError::NotFound`] when the queue has no
    /// request with the identity, [`OperationJournalError::Sequence`] when
    /// the request is not claimed by `epoch`,
    /// [`OperationJournalError::Conflict`] when the request has a
    /// different result, or a storage error.
    pub fn complete_request(
        &mut self,
        request_id: &RequestId,
        epoch: &ExecutorEpochId,
        completion: &RequestCompletion,
    ) -> Result<(), OperationJournalError> {
        let Self {
            connection,
            commit_fault,
            ..
        } = self;
        let transaction = Self::write_transaction(connection)?;
        let existing: RequestRow =
            find_request(&transaction, request_id)?.ok_or(OperationJournalError::NotFound)?;
        match existing.status()? {
            RequestStatus::Completed {
                completion: recorded,
            } => {
                return if &recorded == completion {
                    Ok(())
                } else {
                    Err(OperationJournalError::Conflict)
                };
            }
            RequestStatus::Claimed { executor_epoch } if &executor_epoch == epoch => {}
            RequestStatus::Claimed { .. } | RequestStatus::Queued => {
                return Err(SequenceViolation::Claim.into());
            }
        }
        transaction.execute(
            "UPDATE request SET state = 'completed', completion = ?1 WHERE request_id = ?2",
            params![encode(completion)?, request_id.as_str()],
        )?;
        commit(transaction, commit_fault)
    }

    /// Reads the status of a request.
    ///
    /// # Errors
    ///
    /// Returns a storage error. A request that does not exist is
    /// `Ok(None)`.
    pub fn request_status(
        &self,
        request_id: &RequestId,
    ) -> Result<Option<RequestStatus>, OperationJournalError> {
        find_request(&self.connection, request_id)?
            .map(|row| row.status())
            .transpose()
    }
}
