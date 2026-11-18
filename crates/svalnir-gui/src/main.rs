//! Svalnir GPUI interface.
//!
//! Renders views and sends requests to the agent. It does not enforce policy
//! or run blocking native work on the UI thread.

fn main() -> std::process::ExitCode {
    svalnir_gui::app::run()
}
