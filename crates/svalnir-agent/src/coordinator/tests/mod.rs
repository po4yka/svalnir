//! Tests of the operation coordinator.
//!
//! Each test uses a journal database and a file tree in a temporary
//! directory that it made, a controlled clock, and synthetic measurements.
//! A test removes or moves files only below that directory. The process
//! tests use a synthetic process host, and the tests of `children` signal
//! only a child process that the test started.

mod acknowledge;
mod admission;
mod application;
mod budget;
mod children;
mod cleanup;
mod crash;
mod protection;
mod queue;
mod rearm;
mod recording;
mod review;
mod stop;
mod support;
mod volatile;
