//! The fixture path of an action. It writes nothing and sends nothing: it
//! gives the state that its script names, for tests and screenshots.

use super::{
    Action, ActionPort, ActionState, AuthorityPath, StopProposal, StopTarget, Unavailable,
};
use crate::data::{
    DataSource as _,
    fixture::{FixtureScenario, FixtureSource},
    model::OperationPhase,
};
use std::time::{Duration, SystemTime};

/// The answer of the fixture path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionScript {
    /// Each action is accepted. A stop waits for the exit, and the next
    /// read of its operation gives `Completed`.
    Accept,
    /// Each action is refused with `policy_revision_changed`.
    Refuse,
    /// No agent holds the coordinator lock.
    Unavailable,
    /// No answer comes. A stop waits for an admission that does not come.
    Pending,
}

impl ActionScript {
    /// Every script.
    pub const ALL: [Self; 4] = [Self::Accept, Self::Refuse, Self::Unavailable, Self::Pending];

    /// The name on the command line.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Accept => "accept",
            Self::Refuse => "refuse",
            Self::Unavailable => "unavailable",
            Self::Pending => "pending",
        }
    }

    /// The script with `name`.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|script| script.name() == name)
    }

    /// The script of a scenario: no agent for `agent-absent` and
    /// `unavailable`, a refusal for `drift`, and acceptance for the others.
    #[must_use]
    pub const fn of(scenario: FixtureScenario) -> Self {
        match scenario {
            FixtureScenario::AgentAbsent | FixtureScenario::Unavailable => Self::Unavailable,
            FixtureScenario::Drift => Self::Refuse,
            FixtureScenario::Healthy | FixtureScenario::Pressure | FixtureScenario::Stale => {
                Self::Accept
            }
        }
    }
}

/// The lifetime of a fixture stop plan.
const PLAN_LIFETIME: Duration = Duration::from_secs(300);

/// An action path that changes nothing.
#[derive(Debug)]
pub struct FixturePort {
    scenario: FixtureScenario,
    script: ActionScript,
}

impl FixturePort {
    /// Creates the path of `scenario` with `script`.
    #[must_use]
    pub const fn new(scenario: FixtureScenario, script: ActionScript) -> Self {
        Self { scenario, script }
    }
}

const FIXTURE_NOTE: &str = "(Fixture: nothing was written.)";

/// The helper processes that a fixture stop plan binds after the members
/// of the process list.
pub const FIXTURE_HELPERS: i32 = 14;

/// A bound process of a fixture plan, with synthetic identity evidence.
fn fixture_target(pid: i32, name: String, group: &str) -> StopTarget {
    let start: u64 = 1_794_830_400_000_000 + u64::from(pid.unsigned_abs()) * 1_250;
    let bundle: String = group.to_lowercase().replace(' ', "-");
    StopTarget {
        pid,
        name,
        start_time: start,
        uid: 501,
        executable: Some(format!("/Applications/{group}.app/Contents/MacOS/{group}")),
        file: Some(format!(
            "device 16777230, inode {}",
            4_000_000 + pid.unsigned_abs()
        )),
        signature: (pid % 5 != 0).then(|| format!("dev.fixture.{bundle} (FIXTURE01)")),
    }
}

/// Whether `action` changes the authority record rather than writing a
/// request to the queue.
const fn is_authority(action: &Action) -> bool {
    matches!(
        action,
        Action::Pause { .. } | Action::Resume | Action::Enable { .. } | Action::Disable { .. }
    )
}

fn accepted(action: &Action) -> ActionState {
    ActionState::Accepted {
        detail: format!("{} is accepted.", action.verb()),
    }
}

impl ActionPort for FixturePort {
    fn submit(&self, action: &Action) -> ActionState {
        let state: ActionState = match self.script {
            ActionScript::Refuse => ActionState::refused("policy_revision_changed"),
            // With no agent, a change of the authority record is written
            // directly, as the CLI does; a request of the queue is refused.
            ActionScript::Unavailable if is_authority(action) => {
                AuthorityPath::NoAgent.annotate(accepted(action))
            }
            ActionScript::Unavailable => ActionState::Unavailable(Unavailable::NoAgent),
            ActionScript::Pending => match action {
                Action::Stop { proposal, .. } => ActionState::AwaitingAdmission {
                    request: "gui-request-fixture".to_owned(),
                    since: SystemTime::now(),
                    until: proposal.expires_at + super::ADMISSION_GRACE,
                },
                _ => ActionState::Pending,
            },
            ActionScript::Accept => match action {
                Action::Stop { .. } => ActionState::WaitingForExit {
                    operation: "op-fixture-stop".to_owned(),
                    since: SystemTime::now(),
                },
                _ if is_authority(action) => AuthorityPath::Agent.annotate(accepted(action)),
                _ => accepted(action),
            },
        };
        match state {
            ActionState::Accepted { detail } => ActionState::Accepted {
                detail: format!("{detail} {FIXTURE_NOTE}"),
            },
            other => other,
        }
    }

    fn prepare_stop(&self, instance: &str, name: &str) -> Result<StopProposal, ActionState> {
        if self.script == ActionScript::Unavailable {
            return Err(ActionState::Unavailable(Unavailable::NoAgent));
        }
        let processes = FixtureSource::new(self.scenario)
            .processes()
            .map_err(|_| ActionState::refused("group_not_found"))?;
        let mut targets: Vec<StopTarget> = processes
            .processes
            .iter()
            .filter(|process| process.group.as_deref() == Some(name))
            .map(|process| {
                fixture_target(
                    process.pid,
                    process.name.clone().unwrap_or_else(|| name.to_owned()),
                    name,
                )
            })
            .collect();
        if targets.is_empty() {
            targets.push(fixture_target(1000, name.to_owned(), name));
        }
        // A group of a browser or an editor has many helper processes. The
        // fixture plan binds helpers too, so that the list scrolls.
        let base: i32 = targets.last().map_or(1000, |target| target.pid);
        for index in 1..=FIXTURE_HELPERS {
            targets.push(fixture_target(
                base + 100 + index,
                format!("{name} Helper (Renderer) {index}"),
                name,
            ));
        }
        Ok(StopProposal {
            instance: instance.to_owned(),
            name: name.to_owned(),
            targets,
            expires_at: SystemTime::now() + PLAN_LIFETIME,
            quit: None,
            force: None,
        })
    }

    fn operation_phase(&self, _operation: &str) -> Option<OperationPhase> {
        match self.script {
            ActionScript::Accept => Some(OperationPhase::Completed),
            _ => None,
        }
    }

    fn admission_state(&self, _request: &str) -> Option<ActionState> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_script_has_its_name() {
        for script in ActionScript::ALL {
            assert_eq!(ActionScript::from_name(script.name()), Some(script));
        }
        assert_eq!(ActionScript::from_name("other"), None);
    }

    #[test]
    fn a_fixture_says_that_it_wrote_nothing() {
        let port = FixturePort::new(FixtureScenario::Healthy, ActionScript::Accept);
        let state = port.submit(&Action::Resume);
        assert!(
            matches!(&state, ActionState::Accepted { detail } if detail.ends_with(FIXTURE_NOTE)),
            "{state:?}"
        );
    }

    #[test]
    fn the_scenario_gives_the_default_script() {
        assert_eq!(
            ActionScript::of(FixtureScenario::AgentAbsent),
            ActionScript::Unavailable
        );
        assert_eq!(
            ActionScript::of(FixtureScenario::Drift),
            ActionScript::Refuse
        );
        assert_eq!(
            ActionScript::of(FixtureScenario::Healthy),
            ActionScript::Accept
        );
    }

    #[test]
    fn a_fixture_stop_binds_the_processes_of_the_group() {
        let port = FixturePort::new(FixtureScenario::Healthy, ActionScript::Accept);
        let groups = FixtureSource::new(FixtureScenario::Healthy)
            .processes()
            .unwrap_or_else(|error| panic!("{error}"));
        let group = groups
            .applications
            .first()
            .unwrap_or_else(|| panic!("the fixture has no group"));
        let proposal = port
            .prepare_stop(&group.instance, &group.name)
            .unwrap_or_else(|state| panic!("{state:?}"));
        assert_ne!(proposal.targets, Vec::new());
        assert!(!proposal.expired(SystemTime::now()));
        let unavailable = FixturePort::new(FixtureScenario::Healthy, ActionScript::Unavailable);
        assert!(
            unavailable
                .prepare_stop(&group.instance, &group.name)
                .is_err()
        );
    }
}
