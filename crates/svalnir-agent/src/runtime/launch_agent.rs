//! The definition of a conventional per-user `LaunchAgent`, as data.
//!
//! [`render`] makes the text of the property list. Nothing in this module
//! writes a file, calls `launchctl`, or uses `SMAppService`: the
//! installation is an explicit action of the user through the CLI.

use std::path::{Path, PathBuf};

use thiserror::Error;

use super::record::RESTART_BACKOFF_BASE;

/// The label of the agent job.
pub const LAUNCH_AGENT_LABEL: &str = "dev.po4yka.svalnir.agent";

/// The file name of the definition in a `LaunchAgents` directory.
pub const LAUNCH_AGENT_FILE_NAME: &str = "dev.po4yka.svalnir.agent.plist";

/// The file name of the log of the agent in [`agent_log_directory`].
pub const AGENT_LOG_FILE_NAME: &str = "agent.log";

/// The log directory of the agent: `~/Library/Logs/Svalnir/` below
/// `home`. It is the one log location of the agent.
///
/// `home` must be the home directory that a caller checked against the
/// account record of the effective user: a `HOME` value that a different
/// process set can name a directory of a different user.
#[must_use]
pub fn agent_log_directory(home: &Path) -> PathBuf {
    home.join(crate::capability::host::LOG_DIRECTORY)
}

/// The log file of the agent in [`agent_log_directory`].
#[must_use]
pub fn agent_log_path(home: &Path) -> PathBuf {
    agent_log_directory(home).join(AGENT_LOG_FILE_NAME)
}

/// The inputs of the definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchAgentDefinition {
    /// The absolute path of the `svalnir-agent` executable.
    pub program: PathBuf,
    /// The absolute path of the state directory.
    pub state_directory: PathBuf,
    /// The absolute path of the configuration file, when the agent reads
    /// one.
    pub config: Option<PathBuf>,
    /// The absolute path of the file that gets the standard error stream:
    /// the structured log of the agent, [`agent_log_path`] of the checked
    /// home directory. The service manager does not make its directory.
    pub log: PathBuf,
}

/// The reason a definition was not rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum LaunchAgentError {
    /// A path is not absolute.
    #[error("a path of the definition is not absolute")]
    RelativePath,
    /// A path is not UTF-8 text, or has a control character. A property
    /// list in the XML form cannot have it.
    #[error("a path of the definition is not text that a property list can have")]
    PathText,
}

/// The text of a path, with the characters of XML escaped.
fn xml_text(path: &Path) -> Result<String, LaunchAgentError> {
    if !path.is_absolute() {
        return Err(LaunchAgentError::RelativePath);
    }
    let text: &str = path.to_str().ok_or(LaunchAgentError::PathText)?;
    let mut escaped: String = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            control if control.is_control() => return Err(LaunchAgentError::PathText),
            // The two noncharacters that XML 1.0 does not permit.
            '\u{FFFE}' | '\u{FFFF}' => return Err(LaunchAgentError::PathText),
            other => escaped.push(other),
        }
    }
    Ok(escaped)
}

/// The `ThrottleInterval` of the definition, in seconds: the base of the
/// restart backoff of the agent.
#[must_use]
pub const fn throttle_interval_seconds() -> u64 {
    RESTART_BACKOFF_BASE.get() / 1_000_000_000
}

/// Renders the property list of the agent job.
///
/// The job starts the agent in the foreground at the load of the job
/// (`RunAtLoad`). `KeepAlive` has `SuccessfulExit` false: `launchd` starts
/// the agent again only after an exit that was not a success, so a stop
/// that the user requested stays a stop, and so does a permanent start
/// error, which exits with
/// [`PERMANENT_START_ERROR_STATUS`](super::start_failure::PERMANENT_START_ERROR_STATUS).
/// `ThrottleInterval` is the base of
/// the restart backoff, so `launchd` does not start the agent more often
/// than the agent permits automatic work again. `ProcessType` is
/// `Background`. The definition has no key that keeps the host awake.
///
/// # Errors
///
/// Returns a [`LaunchAgentError`] when a path is not absolute or is not
/// text that a property list can have.
pub fn render(definition: &LaunchAgentDefinition) -> Result<String, LaunchAgentError> {
    let mut arguments: Vec<String> = vec![
        xml_text(&definition.program)?,
        "--foreground".to_owned(),
        "--state-dir".to_owned(),
        xml_text(&definition.state_directory)?,
    ];
    if let Some(config) = &definition.config {
        arguments.push("--config".to_owned());
        arguments.push(xml_text(config)?);
    }
    let log: String = xml_text(&definition.log)?;
    let mut text: String = String::new();
    let mut line = |parts: &[&str]| {
        for part in parts {
            text.push_str(part);
        }
        text.push('\n');
    };
    line(&["<?xml version=\"1.0\" encoding=\"UTF-8\"?>"]);
    line(&[
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" ",
        "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">",
    ]);
    line(&["<plist version=\"1.0\">"]);
    line(&["<dict>"]);
    line(&["\t<key>Label</key>"]);
    line(&["\t<string>", LAUNCH_AGENT_LABEL, "</string>"]);
    line(&["\t<key>ProgramArguments</key>"]);
    line(&["\t<array>"]);
    for argument in &arguments {
        line(&["\t\t<string>", argument, "</string>"]);
    }
    line(&["\t</array>"]);
    line(&["\t<key>RunAtLoad</key>"]);
    line(&["\t<true/>"]);
    line(&["\t<key>KeepAlive</key>"]);
    line(&["\t<dict>"]);
    line(&["\t\t<key>SuccessfulExit</key>"]);
    line(&["\t\t<false/>"]);
    line(&["\t</dict>"]);
    line(&["\t<key>ThrottleInterval</key>"]);
    line(&[
        "\t<integer>",
        &throttle_interval_seconds().to_string(),
        "</integer>",
    ]);
    line(&["\t<key>ProcessType</key>"]);
    line(&["\t<string>Background</string>"]);
    line(&["\t<key>StandardErrorPath</key>"]);
    line(&["\t<string>", &log, "</string>"]);
    line(&["</dict>"]);
    line(&["</plist>"]);
    Ok(text)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{
        LAUNCH_AGENT_LABEL, LaunchAgentDefinition, LaunchAgentError, agent_log_path, render,
        throttle_interval_seconds,
    };

    #[test]
    fn the_log_is_in_the_log_directory_of_the_home_directory() {
        assert_eq!(
            agent_log_path(std::path::Path::new("/Users/example")),
            PathBuf::from("/Users/example/Library/Logs/Svalnir/agent.log")
        );
    }

    fn definition() -> LaunchAgentDefinition {
        LaunchAgentDefinition {
            program: PathBuf::from("/opt/svalnir/bin/svalnir-agent"),
            state_directory: PathBuf::from("/Users/example/Library/Application Support/Svalnir"),
            config: Some(PathBuf::from("/Users/example/.config/svalnir/config.toml")),
            log: agent_log_path(std::path::Path::new("/Users/example")),
        }
    }

    #[test]
    fn the_definition_has_the_label_the_arguments_and_the_restart_settings() {
        let text: String = render(&definition()).unwrap();
        let expected: &str = concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
            "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" ",
            "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n",
            "<plist version=\"1.0\">\n",
            "<dict>\n",
            "\t<key>Label</key>\n",
            "\t<string>dev.po4yka.svalnir.agent</string>\n",
            "\t<key>ProgramArguments</key>\n",
            "\t<array>\n",
            "\t\t<string>/opt/svalnir/bin/svalnir-agent</string>\n",
            "\t\t<string>--foreground</string>\n",
            "\t\t<string>--state-dir</string>\n",
            "\t\t<string>/Users/example/Library/Application Support/Svalnir</string>\n",
            "\t\t<string>--config</string>\n",
            "\t\t<string>/Users/example/.config/svalnir/config.toml</string>\n",
            "\t</array>\n",
            "\t<key>RunAtLoad</key>\n",
            "\t<true/>\n",
            "\t<key>KeepAlive</key>\n",
            "\t<dict>\n",
            "\t\t<key>SuccessfulExit</key>\n",
            "\t\t<false/>\n",
            "\t</dict>\n",
            "\t<key>ThrottleInterval</key>\n",
            "\t<integer>10</integer>\n",
            "\t<key>ProcessType</key>\n",
            "\t<string>Background</string>\n",
            "\t<key>StandardErrorPath</key>\n",
            "\t<string>/Users/example/Library/Logs/Svalnir/agent.log</string>\n",
            "</dict>\n",
            "</plist>\n",
        );
        assert_eq!(text, expected);
        assert_eq!(LAUNCH_AGENT_LABEL, "dev.po4yka.svalnir.agent");
        assert_eq!(throttle_interval_seconds(), 10);
    }

    #[test]
    fn the_definition_keeps_the_host_asleep_and_registers_nothing_else() {
        let text: String = render(&definition()).unwrap();
        for key in [
            "StartInterval",
            "StartCalendarInterval",
            "WatchPaths",
            "Sockets",
            "MachServices",
            "UserName",
            "EnvironmentVariables",
            "StandardOutPath",
        ] {
            assert!(!text.contains(key), "{key}");
        }
    }

    /// `launchd.plist(5)`: with `SuccessfulExit` false, the job is started
    /// again only after an exit status that is not zero. The agent ends a
    /// permanent start error with status zero, so the job stays stopped. A
    /// `KeepAlive` of `true` or a `Crashed` key would change that.
    #[test]
    fn the_definition_does_not_restart_the_status_of_a_permanent_start_error() {
        let text: String = render(&definition()).unwrap();
        assert_eq!(
            crate::runtime::start_failure::PERMANENT_START_ERROR_STATUS,
            0
        );
        assert!(text.contains(concat!(
            "\t<key>KeepAlive</key>\n",
            "\t<dict>\n",
            "\t\t<key>SuccessfulExit</key>\n",
            "\t\t<false/>\n",
            "\t</dict>\n",
        )));
        assert_eq!(text.matches("<key>KeepAlive</key>").count(), 1);
        for key in ["Crashed", "OnDemand", "PathState", "AfterInitialDemand"] {
            assert!(!text.contains(key), "{key}");
        }
    }

    #[test]
    fn the_configuration_argument_is_optional() {
        let mut definition: LaunchAgentDefinition = definition();
        definition.config = None;
        let text: String = render(&definition).unwrap();
        assert!(!text.contains("--config"));
        assert!(text.contains("--state-dir"));
    }

    #[test]
    fn a_path_is_escaped_and_a_path_that_is_not_usable_is_refused() {
        let mut escaped: LaunchAgentDefinition = definition();
        escaped.state_directory = PathBuf::from("/Users/a&b/<state>");
        let text: String = render(&escaped).unwrap();
        assert!(text.contains("<string>/Users/a&amp;b/&lt;state&gt;</string>"));

        let mut relative: LaunchAgentDefinition = definition();
        relative.program = PathBuf::from("svalnir-agent");
        assert_eq!(render(&relative), Err(LaunchAgentError::RelativePath));

        let mut control: LaunchAgentDefinition = definition();
        control.log = PathBuf::from("/tmp/a\nb.log");
        assert_eq!(render(&control), Err(LaunchAgentError::PathText));
    }

    #[test]
    fn a_rendered_definition_is_written_only_where_a_test_puts_it() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(super::LAUNCH_AGENT_FILE_NAME);
        std::fs::write(&path, render(&definition()).unwrap()).unwrap();
        let read: String = std::fs::read_to_string(&path).unwrap();
        assert!(read.starts_with("<?xml"));
        assert!(read.ends_with("</plist>\n"));
    }

    #[test]
    fn a_path_with_a_character_that_xml_does_not_permit_is_refused() {
        for text in [
            "/opt/svalnir/bin/agent\u{FFFE}",
            "/opt/svalnir/bin/agent\u{FFFF}",
        ] {
            let mut definition = definition();
            definition.program = PathBuf::from(text);
            assert_eq!(render(&definition), Err(LaunchAgentError::PathText));
        }
    }
}
