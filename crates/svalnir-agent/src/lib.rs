//! Svalnir user agent library.
//!
//! Owns collection, lifecycle, the action coordinator, application adapters,
//! and the local client API. It has no rendering dependencies. The domain
//! types come from `svalnir_core`; a module here does not define a second
//! byte, timestamp, identity, or observation type.
//!
//! In Milestone 1 the CLI links this library and runs read-only commands in
//! its own process. No module deletes a file or signals a process.
//!
//! | Module | Planned responsibility |
//! | --- | --- |
//! | [`platform`] | Native macOS adapters for memory, volumes, and processes |
//! | [`scan`] | Volume-aware filesystem scanner |
//! | [`store`] | Local `SQLite` state |
//! | [`capability`] | Diagnostic capability probes |

// The manifest has each dependency of the Milestone 1 modules, so that a
// module can use one with no manifest change. These imports mark the
// dependencies that no module uses yet.
// TODO(npochaev): remove a line when a module uses the crate.
#[cfg(target_os = "macos")]
use objc2_app_kit as _;
use rusqlite as _;
use svalnir_core as _;
use sysinfo as _;

pub mod capability;
pub mod platform;
pub mod scan;
pub mod store;
