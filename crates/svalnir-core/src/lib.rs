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
//! | [`config`] | Configuration schema and validation (planned) | `docs/POLICY_SPEC.md` |
//! | [`policy`] | Deterministic policy evaluation (planned) | `docs/POLICY_SPEC.md` |

#![forbid(unsafe_code)]

// Only the tests use `serde_json` at this time, and the `config` module will
// use `toml`.
// TODO(npochaev): remove a line when a module uses the crate.
#[cfg(not(test))]
use serde_json as _;
use toml as _;

pub mod byte_size;
pub mod config;
pub mod duration;
pub mod encoding;
pub mod file;
pub mod id;
pub mod observation;
pub mod policy;
pub mod process;
pub mod quantity;
pub mod state;
pub mod time;
pub mod volume;
