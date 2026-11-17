//! The inputs of an invocation that come from the process environment.
//!
//! One value holds the state-directory override, the home directory, and the
//! invocation directory, so that a test supplies each of them and no command
//! reads the process environment directly. `docs/INTERFACES.md` section 4
//! owns the state-directory contract.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::interrupt::Interrupt;
use crate::output::{ErrorBody, ErrorFamily, ErrorStage, NextAction};
use crate::seams::Seams;

/// The environment variable that replaces the state directory.
pub(crate) const STATE_DIRECTORY_VARIABLE: &str = "SVALNIR_STATE_DIR";

/// The state directory below the home directory of the user.
const DEFAULT_STATE_DIRECTORY: &str = "Library/Application Support/Svalnir";

/// The file name of the configuration proposal in the state directory.
const CONFIG_FILE_NAME: &str = "config.toml";

/// The directory of the plan documents in the state directory.
const PLAN_DIRECTORY_NAME: &str = "plans";

/// The file name of the log of the agent in the state directory.
const AGENT_LOG_FILE_NAME: &str = "agent.log";

/// The file name of the catalog store in the state directory. It holds scan
/// records and metric samples, which are rebuildable. The operation journal
/// of `docs/ARCHITECTURE.md` section 12 is a different file.
const CATALOG_FILE_NAME: &str = "catalog.sqlite";

/// The environment of one invocation.
#[derive(Debug, Clone)]
pub(crate) struct Environment {
    /// The value of [`STATE_DIRECTORY_VARIABLE`], when it is set.
    pub(crate) state_directory_override: Option<OsString>,
    /// The home directory of the user.
    pub(crate) home: Option<PathBuf>,
    /// The directory in which the user started the command. A relative path
    /// argument is resolved against it.
    pub(crate) current_directory: Option<PathBuf>,
    /// The interrupt request of the user.
    pub(crate) interrupt: Interrupt,
    /// The host effects that a test replaces.
    pub(crate) seams: Seams,
}

impl Environment {
    /// Reads the environment of the process.
    pub(crate) fn from_process() -> Self {
        Self {
            state_directory_override: std::env::var_os(STATE_DIRECTORY_VARIABLE),
            home: std::env::var_os("HOME")
                .filter(|home| !home.is_empty())
                .map(PathBuf::from),
            current_directory: std::env::current_dir().ok(),
            interrupt: Interrupt::for_process(),
            seams: Seams::default(),
        }
    }

    /// The state directory. This function is the only place that selects it.
    ///
    /// The function does not create the directory. A command that must write
    /// calls [`Environment::create_state_directory`].
    ///
    /// # Errors
    ///
    /// Returns an error when the override is not an absolute path, or when
    /// there is no override and no home directory.
    pub(crate) fn state_directory(&self) -> Result<PathBuf, ErrorBody> {
        if let Some(text) = &self.state_directory_override {
            let path: &Path = Path::new(text);
            if !path.is_absolute() {
                return Err(request_error(
                    "invalid_state_directory",
                    format!("`{STATE_DIRECTORY_VARIABLE}` must be an absolute path"),
                ));
            }
            return Ok(path.to_path_buf());
        }
        match &self.home {
            Some(home) if home.is_absolute() => Ok(home.join(DEFAULT_STATE_DIRECTORY)),
            _ => Err(ErrorBody {
                code: "state_directory_unavailable".into(),
                family: ErrorFamily::Native,
                stage: ErrorStage::Dispatch,
                message: format!(
                    "the home directory is not known; set `{STATE_DIRECTORY_VARIABLE}` to an absolute path"
                ),
                fields: &[],
                operation_id: None,
                plan_id: None,
                next_action: NextAction::None,
            }),
        }
    }

    /// The path of the configuration proposal of the user.
    pub(crate) fn config_path(&self) -> Result<PathBuf, ErrorBody> {
        Ok(self.state_directory()?.join(CONFIG_FILE_NAME))
    }

    /// The path of the catalog store.
    pub(crate) fn catalog_path(&self) -> Result<PathBuf, ErrorBody> {
        Ok(self.state_directory()?.join(CATALOG_FILE_NAME))
    }

    /// The path of the operation journal.
    pub(crate) fn journal_path(&self) -> Result<PathBuf, ErrorBody> {
        Ok(svalnir_agent::runtime::journal_path(
            &self.state_directory()?,
        ))
    }

    /// The directory of the plan documents.
    pub(crate) fn plan_directory(&self) -> Result<PathBuf, ErrorBody> {
        Ok(self.state_directory()?.join(PLAN_DIRECTORY_NAME))
    }

    /// The path of the log of the agent.
    pub(crate) fn agent_log_path(&self) -> Result<PathBuf, ErrorBody> {
        Ok(self.state_directory()?.join(AGENT_LOG_FILE_NAME))
    }

    /// Creates the state directory, for a command that must write.
    ///
    /// A new directory is readable only by its owner, because the records can
    /// name private paths.
    pub(crate) fn create_state_directory(&self) -> Result<PathBuf, ErrorBody> {
        let directory: PathBuf = self.state_directory()?;
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            builder.mode(0o700);
        }
        builder.create(&directory).map_err(|error| ErrorBody {
            code: "state_directory_not_writable".into(),
            family: ErrorFamily::Recording,
            stage: ErrorStage::Storage,
            message: format!("the state directory cannot be created: {}", error.kind()),
            fields: &[],
            operation_id: None,
            plan_id: None,
            next_action: NextAction::None,
        })?;
        Ok(directory)
    }

    /// Resolves a path argument against the invocation directory. `fields`
    /// names the argument in an error.
    ///
    /// # Errors
    ///
    /// Returns an error for a relative path when the invocation directory is
    /// not known.
    pub(crate) fn resolve(
        &self,
        path: &Path,
        fields: &'static [&'static str],
    ) -> Result<PathBuf, ErrorBody> {
        if path.is_absolute() {
            return Ok(path.to_path_buf());
        }
        match &self.current_directory {
            Some(directory) => Ok(directory.join(path)),
            None => Err(ErrorBody {
                code: "invocation_directory_unavailable".into(),
                family: ErrorFamily::Request,
                stage: ErrorStage::Arguments,
                message: "the invocation directory is not known; give an absolute path".to_owned(),
                fields,
                operation_id: None,
                plan_id: None,
                next_action: NextAction::CorrectRequest,
            }),
        }
    }
}

fn request_error(code: &'static str, message: String) -> ErrorBody {
    ErrorBody {
        code: code.into(),
        family: ErrorFamily::Request,
        stage: ErrorStage::Arguments,
        message,
        fields: &[],
        operation_id: None,
        plan_id: None,
        next_action: NextAction::CorrectRequest,
    }
}
