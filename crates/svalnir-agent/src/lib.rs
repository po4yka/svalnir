//! Svalnir user agent library.
//!
//! Owns collection, lifecycle, the action coordinator, application adapters,
//! and the local client API. It has no rendering dependencies. The domain
//! types come from `svalnir_core`; a module here does not define a second
//! byte, timestamp, identity, or observation type.
//!
//! The CLI links this library and runs read-only commands in its own
//! process. The `svalnir-agent` binary is a skeleton that runs the main run
//! loop until a stop signal: no background agent, no coordinator, and no
//! client API exist yet. No module deletes a file or signals a process.
//!
//! The modules of Milestone 2 are declared and empty. Each one has only a
//! comment that states its planned responsibility.
//!
//! | Module | Contents |
//! | --- | --- |
//! | [`platform::memory`] | Memory pressure, physical memory, VM statistics, swap usage, counter rates, pressure events, and the collection context |
//! | [`platform::volume`] | Volume identities, capacity, Foundation planning values, and capacity pools |
//! | [`platform::process`] | Process inventory, generation identity, footprint and resident size, application attribution, derived growth and CPU use, and ranking |
//! | [`platform::run_loop`] | The main run loop of the process: the evidence that it ran, and the run until a stop signal |
//! | [`platform::sleep`] | The sleep time of the host and the sleep-boundary check of a rate interval |
//! | [`scan`] | Bounded, volume-aware, read-only filesystem scanner with partial results |
//! | [`store`] | Local `SQLite` state for metric samples and scan records, with migrations and retention |
//! | [`capability`] | Diagnostic capability probes and the capability report |
//! | [`journal`] | Declared, empty: the operation journal in `operations.sqlite` |
//! | [`executor::fs`] | Declared, empty: Trash move and permanent removal |
//! | [`executor::process`] | Declared, empty: graceful termination and force escalation |
//! | [`rules`] | Declared, empty: the rule registry and the reviewed rules |
//! | [`coordinator`] | Declared, empty: admission, serialization, and reconciliation |
//! | [`controller`] | Declared, empty: background disk protection and application budgets |
//! | [`runtime`] | Declared, empty: the agent process lifecycle |

pub mod capability;
pub mod controller;
pub mod coordinator;
pub mod executor;
pub mod journal;
pub mod platform;
pub mod rules;
pub mod runtime;
pub mod scan;
pub mod store;
