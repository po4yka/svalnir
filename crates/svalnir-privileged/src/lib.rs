//! Svalnir privileged helper library.
//!
//! The helper exposes only typed, independently validated administrative
//! operations. It is never an arbitrary shell or an unrestricted delete
//! service, and a denied user-level operation is not retried here as
//! root.
//!
//! In Milestone 2 this crate has request types and validation logic with
//! tests only. Nothing is installed, no service is registered, and no
//! operation runs as root. Signed XPC belongs to Milestone 3.
//!
//! The modules are declared and empty. Each one has only a comment that
//! states its planned responsibility.
//!
//! | Module | Planned responsibility |
//! | --- | --- |
//! | [`request`] | The typed delegated operations and their replies |
//! | [`validation`] | Independent validation of a request against the privilege grant |
//!
//! Owning specifications: `docs/INTERFACES.md` section 10,
//! `docs/ARCHITECTURE.md` section 11, and `docs/THREAT_MODEL.md`.

#![forbid(unsafe_code)]

// The declared modules have no code yet.
// TODO(npochaev): remove each line when a module uses the crate.
use libc as _;
use serde as _;
use serde_json as _;
use svalnir_core as _;
use thiserror as _;

pub mod request;
pub mod validation;
