//! Svalnir user agent library.
//!
//! Owns collection, lifecycle, the action coordinator, application adapters,
//! and the local client API. It has no rendering dependencies. The domain
//! types come from `svalnir_core`; a module here does not define a second
//! byte, timestamp, identity, or observation type.
//!
//! In Milestone 1 the CLI links this library and runs read-only commands in
//! its own process. The `svalnir-agent` binary is a skeleton: no background
//! agent, no coordinator, and no client API exist yet. No module deletes a
//! file or signals a process.
//!
//! | Module | Contents |
//! | --- | --- |
//! | [`platform::memory`] | Memory pressure, physical memory, VM statistics, swap usage, counter rates, pressure events, and the collection context |
//! | [`platform::volume`] | Volume identities, capacity, Foundation planning values, and capacity pools |
//! | [`platform::process`] | Process inventory, generation identity, footprint and resident size, application attribution, derived growth and CPU use, and ranking |
//! | [`platform::sleep`] | The sleep time of the host and the sleep-boundary check of a rate interval |
//! | [`scan`] | Bounded, volume-aware, read-only filesystem scanner with partial results |
//! | [`store`] | Local `SQLite` state for metric samples and scan records, with migrations and retention |
//! | [`capability`] | Diagnostic capability probes and the capability report |

pub mod capability;
pub mod platform;
pub mod scan;
pub mod store;
