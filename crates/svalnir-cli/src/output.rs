//! Machine-output envelope and exit status.
//!
//! `docs/INTERFACES.md` sections 7 and 8 own this contract.

use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

/// Major version of the machine-output schema.
pub const SCHEMA_VERSION: u32 = 1;

/// Exit status of the `svalnir` process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitStatus {
    /// The query succeeded, the waited mutation settled, or admission was accepted.
    Success,
    /// A known operation failure or an internal execution failure.
    Failure,
    /// Invalid arguments, configuration, or request shape.
    Usage,
    /// A required capability or authorization is unavailable or denied.
    Unavailable,
    /// A partial read scope or a partial or incomplete operation.
    Partial,
    /// Stale or conflicting state, or an unknown outcome.
    Conflict,
    /// The user interrupted the client.
    Interrupted,
    /// A transient coordinator stopped on `SIGTERM`.
    Terminated,
    /// A transient coordinator stopped on `SIGHUP`.
    HungUp,
}

impl ExitStatus {
    /// The numeric process exit code.
    pub fn code(self) -> u8 {
        match self {
            Self::Success => 0,
            Self::Failure => 1,
            Self::Usage => 2,
            Self::Unavailable => 3,
            Self::Partial => 4,
            Self::Conflict => 5,
            Self::Interrupted => 130,
            Self::Terminated => 143,
            Self::HungUp => 129,
        }
    }
}

impl From<ExitStatus> for ExitCode {
    fn from(status: ExitStatus) -> Self {
        Self::from(status.code())
    }
}

pub use svalnir_core::id::RequestId;

/// Makes the correlation identity of one invocation from the wall clock and
/// the process ID.
pub fn generate_request_id() -> RequestId {
    let nanoseconds: u128 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    RequestId::from_client_parts(nanoseconds, std::process::id())
}

/// Variant of a JSON response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// A resource or state view.
    Snapshot,
    /// A plan, validation, simulation, history, or diagnostic result.
    Report,
    /// An asynchronous admission.
    Accepted,
    /// The state of an operation.
    Operation,
    /// A request or command error.
    Error,
}

/// The JSON response of one command.
#[derive(Debug, Serialize)]
pub struct Envelope<T> {
    pub schema_version: u32,
    pub request_id: RequestId,
    pub kind: Kind,
    pub result: Option<T>,
    pub error: Option<ErrorBody>,
    pub warnings: Vec<Warning>,
}

impl<T> Envelope<T> {
    /// A response that carries a result.
    pub fn result(request_id: RequestId, kind: Kind, result: T) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            request_id,
            kind,
            result: Some(result),
            error: None,
            warnings: Vec::new(),
        }
    }

    /// The same response with advisory findings.
    #[must_use]
    pub fn with_warnings(mut self, warnings: Vec<Warning>) -> Self {
        self.warnings = warnings;
        self
    }
}

impl Envelope<()> {
    /// A response that carries a request or command error.
    pub fn error(request_id: RequestId, error: ErrorBody) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            request_id,
            kind: Kind::Error,
            result: None,
            error: Some(error),
            warnings: Vec::new(),
        }
    }
}

/// A structured advisory finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Warning {
    pub code: Box<str>,
    pub message: String,
}

/// A structured request or command error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ErrorBody {
    /// Stable identifier of the error.
    pub code: Box<str>,
    pub family: ErrorFamily,
    pub stage: ErrorStage,
    /// Text that is safe to show. It contains no payload from another party.
    pub message: String,
    /// Names of the request fields that caused the error.
    pub fields: &'static [&'static str],
    /// The operation, when the error has one. The text is boxed so that
    /// the record stays small as an error value.
    pub operation_id: Option<Box<str>>,
    /// The plan, when the error has one.
    pub plan_id: Option<Box<str>>,
    pub next_action: NextAction,
}

pub use svalnir_core::action::ErrorFamily;

/// The exit status of an error in `family` before admission.
///
/// `docs/ACTION_CONTRACTS.md` section 10 owns the families and
/// `docs/INTERFACES.md` section 8 owns the mapping. A family that this
/// build does not recognize needs reconciliation, as an unknown outcome.
pub fn family_exit_status(family: &ErrorFamily) -> ExitStatus {
    match family {
        ErrorFamily::Request => ExitStatus::Usage,
        ErrorFamily::Authority | ErrorFamily::Eligibility | ErrorFamily::Native => {
            ExitStatus::Unavailable
        }
        ErrorFamily::Evidence
        | ErrorFamily::Limits
        | ErrorFamily::Outcome
        | ErrorFamily::Unrecognized(_) => ExitStatus::Conflict,
        ErrorFamily::Recording => ExitStatus::Failure,
    }
}

impl ErrorBody {
    /// An error with no field reference and no operation or plan ID. The
    /// next action is that of the family before a submission.
    pub fn new(
        code: impl Into<Box<str>>,
        family: ErrorFamily,
        stage: ErrorStage,
        message: impl Into<String>,
    ) -> Self {
        let next_action: NextAction = match &family {
            ErrorFamily::Request => NextAction::CorrectRequest,
            ErrorFamily::Authority => NextAction::ResolveAuthority,
            ErrorFamily::Evidence => NextAction::RefreshObservation,
            ErrorFamily::Limits => NextAction::RespectLimits,
            ErrorFamily::Outcome | ErrorFamily::Unrecognized(_) => NextAction::Reconcile,
            ErrorFamily::Eligibility | ErrorFamily::Recording | ErrorFamily::Native => {
                NextAction::None
            }
        };
        Self {
            code: code.into(),
            family,
            stage,
            message: message.into(),
            fields: &[],
            operation_id: None,
            plan_id: None,
            next_action,
        }
    }

    /// The same error with the request fields that caused it.
    #[must_use]
    pub fn with_fields(mut self, fields: &'static [&'static str]) -> Self {
        self.fields = fields;
        self
    }

    /// The same error with the plan that it is about.
    #[must_use]
    pub fn with_plan(mut self, plan_id: &str) -> Self {
        self.plan_id = Some(plan_id.into());
        self
    }

    /// The same error with the operation that it is about.
    #[must_use]
    pub fn with_operation(mut self, operation_id: &str) -> Self {
        self.operation_id = Some(operation_id.into());
        self
    }

    /// The same error with a different next action.
    #[must_use]
    pub fn with_next_action(mut self, next_action: NextAction) -> Self {
        self.next_action = next_action;
        self
    }

    /// The exit status of the error.
    pub fn exit_status(&self) -> ExitStatus {
        family_exit_status(&self.family)
    }
}

/// Stage at which an error occurred.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorStage {
    /// Validation of the arguments in the client.
    Arguments,
    /// Selection of the service that runs the command.
    Dispatch,
    /// Reading of an input that the request names, for example a
    /// configuration file.
    Input,
    /// Collection of observations from the host.
    Collection,
    /// Reading or writing of the local state store.
    Storage,
    /// Admission of a plan or of a control request.
    Admission,
    /// Execution of an admitted operation.
    Execution,
}

/// The action that the caller is permitted to take next.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NextAction {
    /// No action changes the result.
    None,
    /// Correct the request and send it again.
    CorrectRequest,
    /// Make a new observation: list the targets or scan again. The command
    /// is read-only, so a repeated request has no side effect.
    RefreshObservation,
    /// Resolve the authority: activate a configuration, enable a policy, or
    /// give the acceptance that the request needs.
    ResolveAuthority,
    /// Respect the limit: wait for the cooldown, the lease, or the queue.
    RespectLimits,
    /// Prepare a new plan. The plan of the request cannot be applied.
    PrepareNewPlan,
    /// Query the operation by its ID. Do not send the request again as new
    /// work.
    QueryOperation,
    /// Reconcile: the effect is not known. Start no conflicting work.
    Reconcile,
}

#[cfg(test)]
mod tests {
    use super::{ErrorFamily, ExitStatus, family_exit_status};

    #[test]
    fn each_error_family_has_its_exit_status() {
        let expected = [
            (ErrorFamily::Request, 2, "request"),
            (ErrorFamily::Authority, 3, "authority"),
            (ErrorFamily::Evidence, 5, "evidence"),
            (ErrorFamily::Eligibility, 3, "eligibility"),
            (ErrorFamily::Limits, 5, "limits"),
            (ErrorFamily::Recording, 1, "recording"),
            (ErrorFamily::Native, 3, "native"),
            (ErrorFamily::Outcome, 5, "outcome"),
        ];
        assert_eq!(expected.len(), ErrorFamily::ALL.len());
        for (family, code, text) in expected {
            assert_eq!(family_exit_status(&family).code(), code, "{family}");
            // The spelling that the CLI emits.
            assert_eq!(
                serde_json::to_string(&family).unwrap(),
                format!("\"{text}\"")
            );
        }
        assert_eq!(
            family_exit_status(&ErrorFamily::from_wire("quota")),
            ExitStatus::Conflict
        );
    }
}
