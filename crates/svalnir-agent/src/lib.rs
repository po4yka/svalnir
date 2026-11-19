//! Svalnir user agent library.
//!
//! Owns collection, lifecycle, the action coordinator, application adapters,
//! and the local client API. It has no rendering dependencies. The domain
//! types come from `svalnir_core`; a module here does not define a second
//! byte, timestamp, identity, or observation type.
//!
//! The CLI links this library. It runs the read-only commands in its own
//! process, and it applies a manual plan through the coordinator of this
//! library: as a transient coordinator when no agent holds the coordinator
//! lock, and through the request queue of the journal when one does. The
//! `svalnir-agent` binary runs the agent in the foreground. No socket and
//! no XPC service exist: a client and the agent share the journal.
//!
//! An executor acts only for a step that the coordinator admitted. Each
//! reviewed rule is in the `proposed` lifecycle state, so no rule permits
//! an eviction.
//!
//! | Module | Contents |
//! | --- | --- |
//! | [`platform::memory`] | Memory pressure, physical memory, VM statistics, swap usage, counter rates, pressure events, and the collection context |
//! | [`platform::volume`] | Volume identities, capacity, Foundation planning values, and capacity pools |
//! | [`platform::process`] | Process inventory, generation identity, footprint and resident size, application attribution, derived growth and CPU use, and ranking |
//! | [`platform::run_loop`] | The main run loop of the process: the evidence that it ran, and the run until a stop signal or a stop request of this process |
//! | [`platform::sleep`] | The sleep time of the host and the sleep-boundary check of a rate interval |
//! | [`scan`] | Bounded, volume-aware, read-only filesystem scanner with partial results |
//! | [`observe`] | The readings that a client process makes in its own process: the collection context, the disk and memory reading of the host, the query of the coordinator lock, and the read-only reads of the operation journal: the existing journal, the authority record, and the standing of each guard |
//! | [`client`] | The client side of the request queue and of the authority record, which the CLI and the GPUI client share: the holder of the coordinator lock, the principal and the identities of a request, the wait for a completion, and the compare-and-set write of the authority record |
//! | [`store`] | Local `SQLite` state for metric samples and scan records, with migrations and retention |
//! | [`capability`] | Diagnostic capability probes and the capability report |
//! | [`journal`] | The operation journal in `operations.sqlite`: plans, operations, the resource observations of an operation, revisions and grants, the request queue, the coordinator lock with the role of its holder and a reading that takes no lock, recovery reads, and the named agent records |
//! | [`executor::fs`] | The filesystem executor: the Trash move and the descriptor-relative permanent removal of one admitted step, with a stop between the entries of a directory target |
//! | [`executor::process`] | The process executor: the graceful request, the force signal, and the exit observation of one admitted step |
//! | [`rules`] | The rule registry, the two reviewed rules, each in the `proposed` lifecycle state, and the discovery for an eviction: the roots of a rule declaration, the process evidence, the overlap resolution, and the facts of admission |
//! | [`protection`] | The catalog of protected file locations for the paths of the host, for a client, a discovery, and the coordinator at admission |
//! | [`coordinator`] | The operation coordinator: admission, serialization, dispatch records, the approved roots of a manual operation from its sealed plan, cancellation, the queue service, the stop of new claims at a shutdown, and reconciliation |
//! | [`controller`] | The guard controller: the decisions of the disk guard and the memory guard from the authority record, and the open incidents that bound the retention of the journal |
//! | [`runtime`] | The agent process: the driver loop, the agent clock with the sleep continuity of the host, the status and lifecycle records, and the renderer of the `LaunchAgent` definition |

pub mod capability;
pub mod client;
pub mod controller;
pub mod coordinator;
pub mod executor;
pub mod journal;
pub mod observe;
pub mod platform;
pub mod protection;
pub mod rules;
pub mod runtime;
pub mod scan;
pub mod store;
