//! Svalnir command-line client.
//!
//! Parses arguments, renders output, and sends requests to the shared
//! application services. It has no independent destructive execution path.

use clap::Parser;

/// Local macOS resource manager.
#[derive(Debug, Parser)]
#[command(name = "svalnir", version, about)]
struct Cli {}

fn main() {
    let _cli: Cli = Cli::parse();
}

#[cfg(test)]
mod tests {
    use super::Cli;
    use clap::CommandFactory;

    #[test]
    fn command_definition_is_valid() {
        Cli::command().debug_assert();
    }
}
