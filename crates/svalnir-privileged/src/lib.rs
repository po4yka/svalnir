//! Svalnir privileged helper library.
//!
//! The helper exposes only typed, independently validated administrative
//! operations. It is never an arbitrary shell or an unrestricted delete
//! service, and a denied user-level operation is not retried here as
//! root.
//!
//! This crate has the helper side of the signed local protocol: the
//! request and response messages, the transport interface with its macOS
//! XPC adapter, the decision logic, the executor, and the service that
//! connects them. The crate installs nothing and registers no service. A
//! build with no signing identity verifies no peer, so its helper refuses
//! each request.
//!
//! | Module | Responsibility |
//! | --- | --- |
//! | [`request`] | The request envelope, the closed set of operations, the identity of the caller, and the decoder of the encoded form |
//! | [`response`] | The response envelope, the entry results, the conditions with their error families and codes, and the decoder for a client |
//! | [`transport`] | The transport interface, the facts of the peer that the platform reports, the peer policy, and the macOS XPC adapter |
//! | [`validation`] | The state of the helper, the decision on one request, the bounded record of consumed requests, and the refusal reasons |
//! | [`executor`] | The executor interface and the filesystem executor of an accepted eviction |
//! | [`service`] | The service: one message of a transport in, one response out; the record store interface and the clock |
//!
//! # The path of one request
//!
//! 1. A [`transport::Transport`] receives a message and makes the
//!    [`transport::PeerFacts`] of its peer from the platform.
//! 2. [`service::HelperService`] refuses a peer that is not verified, then
//!    decodes the request with [`request::decode_request`].
//! 3. The service makes the [`request::CallerIdentity`] from the facts and
//!    reads the clock into a [`validation::HelperClock`].
//! 4. [`validation::HelperState::admit`] decides and consumes the step. The
//!    service makes the record durable through its
//!    [`service::RecordStore`]. Only then does the
//!    [`executor::EvictionExecutor`] get the [`validation::Dispatch`].
//! 5. The service records the state of the step with
//!    [`validation::HelperState::record_progress`] and replies with a
//!    [`response::HelperResponse`].
//!
//! # Threats and controls
//!
//! The threat identities are those of `docs/THREAT_MODEL.md` section 5.
//! The tests are in `validation::tests`, `service::tests`, `executor::tests`, and `transport::tests`. A threat that is not in the table
//! (`T-05`, `T-06`, `T-12`) has no control in this crate.
//!
//! | Threat | Control in this crate | Function | Tests |
//! | --- | --- | --- | --- |
//! | `T-01` Confused deputy through local IPC | The identity of the caller comes only from the transport, which reads the code identity, the user, and the login session of the live peer from the platform. A peer that the platform did not verify is refused before its message is decoded. The code-signing identity must be that of the agent, and the role must be the agent, for each operation. The operations are a closed set with no shell text, executable, or free path. | [`transport::PeerFacts`], [`service::HelperService`], [`request::CallerIdentity`], [`validation::validate`] (`check_caller`), [`request::HelperOperation`] | `a_peer_that_is_not_verified_is_refused_before_its_message_is_decoded`, `a_real_peer_of_an_unsigned_build_is_refused`, `refuses_a_caller_that_is_not_the_agent`, `refuses_each_role_other_than_the_agent_for_each_operation`, `a_forged_identity_field_in_the_body_is_rejected`, `an_unknown_operation_is_rejected` |
//! | `T-02` Configuration becomes administrative authority | The helper decides with its own grant record. The request names a grant, a root, and a rule by identity; the path of the root, the ceilings, and the rules come from the record. A statement of the caller can only make the operation smaller. | [`validation::validate`] (`check_grant`, `check_entries`), [`validation::HelperGrant::new`] | `the_audited_user_and_not_the_request_selects_the_grant`, `refuses_a_root_that_the_grant_does_not_have`, `refuses_a_rule_revision_that_the_root_does_not_have`, `evidence_of_the_caller_cannot_raise_a_limit`, `a_grant_record_that_does_not_agree_is_refused` |
//! | `T-03` Replay and stale authority | A step is consumed one time for its user, operation, and step. A repeated step gets its recorded state. A different content under a recorded step is refused. A request has an expiry and a longest validity on the clock of the helper. A grant reference of a different generation, a revoked grant, and an expired grant are refused. | [`validation::HelperState::admit`], [`validation::validate`] (`check_validity`, `check_grant`), [`validation::ConsumedRequests`] | `a_consumed_request_is_never_accepted_again`, `a_duplicate_in_flight_returns_the_known_state_and_consumes_nothing`, `a_new_transport_identity_does_not_make_the_step_executable_again`, `a_recorded_step_with_a_different_content_is_refused`, `refuses_an_expired_request`, `an_expired_request_that_the_helper_never_recorded_is_not_fresh`, `a_removed_record_does_not_make_its_request_fresh`, `refuses_a_grant_of_an_older_generation`, `refuses_an_expired_grant` |
//! | `T-04` Filesystem replacement and traversal races | A target is a list of names below a root of the grant: no absolute path, no empty name, no `.`, no `..`. The executor opens each name relative to a directory handle and follows no symbolic link. It checks the type, the native identifiers, the owner, the link count, and the filesystem of the object again immediately before its one call, and it requires directories that only the helper user and user 0 can write to. A removal has the attribution `possible`. | [`validation::EntryPath::parse`], [`validation::RootPath::parse`], [`executor::FsEvictor`] | `a_replaced_object_is_not_removed`, `an_object_that_is_replaced_during_the_step_is_not_removed`, `a_symbolic_link_in_the_path_is_not_followed`, `a_directory_that_another_user_can_write_to_is_refused`, `a_hard_linked_file_is_not_removed`, `refuses_each_entry_that_leaves_its_root`, `the_entry_check_agrees_with_an_independent_rule_for_each_short_path`, `a_root_is_an_absolute_path_of_names_below_the_filesystem_root` |
//! | `T-07` Incorrect pressure, accounting, or time | The request has no field for a measurement. A request of a different clock domain or boot is refused. Sums are checked and never saturate. | [`request::decode_request`], [`validation::validate`] (`check_validity`, `check_entries`) | `evidence_of_the_caller_cannot_raise_a_limit`, `refuses_times_that_cannot_be_compared_with_the_clock`, `a_sum_that_does_not_fit_is_refused_and_not_saturated`, `a_rate_sum_that_does_not_fit_is_refused_and_not_saturated` |
//! | `T-08` Pressure amplification and intervention loops | Ceilings of the grant for one operation (bytes, items, targets) and for a window (requests, work). The record of consumed requests has a fixed capacity; when it is full, the helper refuses. | [`validation::validate`] (`check_operation_ceiling`, `check_rate`), [`validation::ConsumedRequests::insert`] | `the_bytes_ceiling_is_inclusive`, `the_items_ceiling_is_inclusive`, `the_target_ceiling_is_inclusive`, `the_rate_ceiling_counts_accepted_requests_in_the_window`, `the_rate_ceiling_counts_accepted_work_in_the_window`, `a_full_record_refuses_each_new_request_and_removes_nothing` |
//! | `T-09` Malformed input and native boundary compromise | The decoder has a size limit and a nesting limit, rejects an unknown operation, an unknown field, a repeated field, and a value that is not in its canonical encoding. After repeated messages of one user that are not requests, a transport handles no message of that user for a time. The `unsafe` code is in two modules of native calls, `native` and `transport::xpc::sys`. | [`request::decode_request`], [`service::HelperService`] | `changed_bytes_of_a_request_never_decode_to_a_different_request`, `a_message_that_is_not_a_request_is_rejected_and_penalized`, `repeated_penalized_messages_of_a_user_stop_the_handling_of_its_messages`, `an_unknown_operation_is_rejected`, `an_unknown_field_is_rejected_at_each_level`, `an_unknown_authority_bearing_value_is_rejected`, `an_absent_field_and_a_repeated_field_are_rejected`, `an_encoded_form_over_a_limit_or_that_is_not_json_is_rejected` |
//! | `T-10` Journal failure and uncertain outcomes | The consumption is recorded in the call that accepts the step, and the service makes it durable before the executor gets the step. A failed write gives `NoAction` with no call. A result that is not durable is reported as such. Admission fails before an effect when the record has no room. A step that is not settled is never removed, and a restart of the host does not remove a settled step before its retention is complete. | [`validation::HelperState::admit`], [`validation::ConsumedRequests::remove_expired`], [`service::RecordStore`] | `a_step_whose_record_is_not_durable_submits_no_call`, `a_result_that_is_not_durable_is_reported`, `a_full_record_refuses_each_new_request_and_removes_nothing`, `a_record_is_removed_only_when_no_replay_is_possible`, `a_restart_of_the_host_does_not_free_a_record_or_a_rate_window`, `the_record_permits_only_the_transitions_of_a_consumed_step` |
//! | `T-11` State-file substitution and recovery poisoning | Decision part only. A state that does not agree with itself is refused, a restored record is not cut to fit, a restored step with a state before consumption is refused, and a restored step that was in work has an outcome that is not known. The crate reads no file of the user. | [`validation::HelperState::restore`], [`validation::ConsumedRequests::restore`] | `a_state_that_does_not_agree_is_refused`, `the_record_has_a_bounded_capacity`, `a_restored_record_with_a_state_before_consumption_is_refused`, `a_restored_step_that_was_in_work_has_an_outcome_that_is_not_known` |
//! | `T-13` Cross-user actions and shared-capacity conflicts | The deduplication identity and the grant lookup use the audited user. One user cannot read, repeat, or hide the step of another user, cannot use the grant of another user, and cannot fill the record: each user has a record quota. | [`validation::StepKey`], [`validation::validate`] (`check_grant`) | `the_step_of_one_user_is_not_the_step_of_another_user`, `the_audited_user_and_not_the_request_selects_the_grant`, `one_user_cannot_fill_the_record_of_the_helper` |
//! | `T-14` Revocation, pause, and lifecycle races | Each new step reads the current grant record: revocation and a new generation stop it. A step that was consumed before keeps its recorded state. | [`validation::validate`] (`check_grant`) | `refuses_a_revoked_grant`, `refuses_a_grant_of_an_older_generation`, `a_repeated_step_gets_its_state_also_after_its_grant_was_revoked` |
//! | `T-15` Compromised release or unsafe service installation | The protocol version is checked before each other part of a request. A grant record with an action class that this build cannot do is refused. | [`request::SupportedProtocols::check`], [`validation::HelperGrant::new`] | `refuses_a_different_protocol_major_version`, `the_decoder_reports_a_protocol_mismatch_before_an_unknown_field`, `a_grant_record_that_does_not_agree_is_refused` |
//!
//! Owning specifications: `docs/INTERFACES.md` sections 9, 10, and 12,
//! `docs/ARCHITECTURE.md` sections 10 and 11, `docs/ACTION_CONTRACTS.md`
//! sections 3, 4, and 11, and `docs/THREAT_MODEL.md`.

// The native calls are in two modules, each with its own expectation of
// this lint. Each other module has no `unsafe` code.
#![deny(unsafe_code)]

pub mod executor;
#[expect(
    unsafe_code,
    reason = "the libc calls of the executor and of the clock; each block has its safety argument"
)]
mod native;
pub mod request;
pub mod response;
pub mod service;
#[cfg(test)]
mod testing;
pub mod transport;
pub mod validation;
