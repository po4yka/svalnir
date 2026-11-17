//! Domain types, accounting, policy decisions, plans, and action/journal
//! contracts shared by every Svalnir component.
//!
//! This crate has no rendering, launchd, deletion, or signaling side effects.
//!
//! | Module | Contents | Owning specification |
//! | --- | --- | --- |
//! | [`quantity`] | Checked byte, page, entry, counter, and duration quantities | `docs/RESOURCE_MODEL.md` section 3 |
//! | [`time`] | Monotonic and wall-clock timestamps | `docs/RESOURCE_MODEL.md` section 5 |
//! | [`id`] | Opaque identities | `docs/RESOURCE_MODEL.md` section 2 |
//! | [`observation`] | The `Observation<T>` envelope and the metric names | `docs/RESOURCE_MODEL.md` section 4 |
//! | [`state`] | Pressure and capability states | `docs/RESOURCE_MODEL.md` sections 10 and 13 |
//! | [`mod@file`] | Lossless paths and file-object evidence | `docs/INTERFACES.md` section 3 |
//! | [`process`] | Process observation identity | `docs/RESOURCE_MODEL.md` section 11 |
//! | [`volume`] | Volume identity and capacity-domain membership | `docs/RESOURCE_MODEL.md` section 7 |
//! | [`encoding`] | Shared rules of the JSON encoding | `docs/INTERFACES.md` section 3 |
//! | [`byte_size`], [`duration`] | Text grammars of configuration values | `docs/POLICY_SPEC.md` section 3 |
//! | [`config`] | Configuration schema, parsing, and validation with structured findings | `docs/POLICY_SPEC.md` sections 3 and 4, `docs/INTERFACES.md` section 13 |
//! | [`policy`] | Deterministic policy evaluation, simulation, and policy descriptions | `docs/POLICY_SPEC.md` |
//! | [`action`] | Action classes, plans, operations, outcomes, errors, budgets, leases, and the journal interface | `docs/ACTION_CONTRACTS.md` |
//! | [`rule`] | Cleanup rule declarations, the registry interface, and candidate eligibility | `docs/CLEANUP_RULES.md` sections 2 to 9 |
//! | [`authority`] | The policy revision, action grant, and privilege grant records | `docs/ARCHITECTURE.md` section 11 |
//! | [`digest`] | Content digests | `docs/INTERFACES.md` section 5 |
//! | [`plan`] | The plan builder for a cleanup and for an application stop, the apply checks, and the plan explanation | `docs/ACTION_CONTRACTS.md` sections 2 and 3 |
//! | [`grant`] | Activation and grant logic: activation, enablement, disable and revoke, pause and resume, rearm, and the authorization question | `docs/ARCHITECTURE.md` section 11 |

#![forbid(unsafe_code)]

pub mod action;
pub mod authority;
pub mod byte_size;
pub mod config;
pub mod digest;
pub mod duration;
pub mod encoding;
pub mod file;
pub mod grant;
pub mod id;
pub mod observation;
pub mod plan;
pub mod policy;
pub mod process;
pub mod quantity;
pub mod rule;
pub mod state;
pub mod time;
pub mod volume;
