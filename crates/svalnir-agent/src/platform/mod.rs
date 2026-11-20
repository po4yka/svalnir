//! Native macOS adapters.
//!
//! Each adapter keeps its FFI small and returns `svalnir_core` observations
//! with their source and sample. A failed native query is an unavailable
//! observation; it is not a zero.
//!
//! Owning specification: `docs/RESOURCE_MODEL.md`. `docs/ARCHITECTURE.md`
//! owns the component boundary.

pub mod account;
pub mod fsevents;
pub mod memory;
pub mod process;
pub mod run_loop;
pub mod sleep;
pub mod volume;
