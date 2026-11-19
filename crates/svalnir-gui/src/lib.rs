//! Svalnir GPUI client library: theme, window frame, navigation, and screens.
//!
//! `main.rs` holds only the bootstrap so that tests can reach the views.

pub mod actions;
pub mod app;
pub mod data;
pub mod notify;
pub mod platform;
pub mod screens;
pub mod shell;
#[cfg(test)]
mod test_support;
pub mod theme;
pub mod ui;
pub mod viz;
