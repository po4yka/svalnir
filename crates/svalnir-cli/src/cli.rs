//! Argument definitions for the `svalnir` command.
//!
//! This module only describes and parses arguments. It makes no policy
//! decision and has no side effect. `docs/INTERFACES.md` owns the contract.

use std::path::PathBuf;
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};
use clap_complete::Shell;
use svalnir_core::duration::parse_duration;

/// Parses a duration that is longer than zero.
///
/// A zero wait, grace period, or pause has no meaning, and a zero grace period
/// would make `--force-after-timeout` an immediate force.
fn positive_duration(text: &str) -> Result<Duration, String> {
    let duration: Duration = parse_duration(text).map_err(|error| error.to_string())?;
    if duration.is_zero() {
        return Err(format!("the duration `{text}` must be longer than zero"));
    }
    Ok(duration)
}

/// Local macOS resource manager.
#[derive(Debug, Parser)]
#[command(name = "svalnir", version, about, propagate_version = true)]
pub struct Cli {
    #[command(flatten)]
    pub common: CommonOptions,
    #[command(subcommand)]
    pub command: Command,
}

/// Options that each command accepts.
#[derive(Debug, Args)]
pub struct CommonOptions {
    /// Output encoding. `ndjson` applies only to streaming commands.
    #[arg(long, global = true, value_enum, default_value_t = Format::Text)]
    pub format: Format,
    /// Maximum time that the client waits. It does not cancel admitted work.
    #[arg(long, global = true, value_name = "DURATION", value_parser = positive_duration)]
    pub timeout: Option<Duration>,
    /// Color of the human-readable output. Machine output has no color.
    #[arg(long, global = true, value_enum, default_value_t = ColorChoice::Auto)]
    pub color: ColorChoice,
}

/// Output encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Format {
    /// Human-readable text.
    Text,
    /// One versioned JSON value.
    Json,
    /// One JSON event on each line.
    Ndjson,
}

/// Color selection for human-readable output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ColorChoice {
    Auto,
    Always,
    Never,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Summarize disk, memory, agent, and policy state.
    Status,
    /// Analyze a selected storage scope.
    Scan(ScanArgs),
    /// Inspect a recorded scan.
    Report(ReportArgs),
    /// Prepare, inspect, and apply a cleanup plan.
    Clean {
        #[command(subcommand)]
        command: CleanCommand,
    },
    /// Stream live resource observations.
    Monitor(MonitorArgs),
    /// Show memory pressure, composition, and growth signals.
    Memory {
        #[command(subcommand)]
        command: MemoryCommand,
    },
    /// Show global swap usage and recent activity.
    Swap {
        #[command(subcommand)]
        command: SwapCommand,
    },
    /// Rank, inspect, and stop verified application or process targets.
    Processes {
        #[command(subcommand)]
        command: ProcessesCommand,
    },
    /// Query, await, cancel, or acknowledge an admitted operation.
    Operations {
        #[command(subcommand)]
        command: OperationsCommand,
    },
    /// Manage the Svalnir background service.
    Agent {
        #[command(subcommand)]
        command: AgentCommand,
    },
    /// Inspect and manage standing policies.
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    /// Validate, show, and activate configuration.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Inspect actions and observed outcomes.
    History(HistoryArgs),
    /// Diagnose permissions, service identity, APIs, and degraded state.
    Doctor,
    /// Generate a shell completion script.
    Completions(CompletionsArgs),
    /// Display the license of Svalnir.
    License,
}

impl Command {
    /// The command words, for example `clean apply`.
    pub fn path(&self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::Scan(_) => "scan",
            Self::Report(_) => "report",
            Self::Clean { command } => match command {
                CleanCommand::Plan(_) => "clean plan",
                CleanCommand::Show(_) => "clean show",
                CleanCommand::Apply(_) => "clean apply",
            },
            Self::Monitor(_) => "monitor",
            Self::Memory {
                command: MemoryCommand::Status,
            } => "memory status",
            Self::Swap {
                command: SwapCommand::Status,
            } => "swap status",
            Self::Processes { command } => match command {
                ProcessesCommand::Top(_) => "processes top",
                ProcessesCommand::Show(_) => "processes show",
                ProcessesCommand::Stop(_) => "processes stop",
            },
            Self::Operations { command } => match command {
                OperationsCommand::Show(_) => "operations show",
                OperationsCommand::Wait(_) => "operations wait",
                OperationsCommand::Cancel(_) => "operations cancel",
                OperationsCommand::Acknowledge(_) => "operations acknowledge",
            },
            Self::Agent { command } => match command {
                AgentCommand::Install(_) => "agent install",
                AgentCommand::Status => "agent status",
                AgentCommand::Pause(_) => "agent pause",
                AgentCommand::Resume => "agent resume",
                AgentCommand::Uninstall(_) => "agent uninstall",
            },
            Self::Policy { command } => match command {
                PolicyCommand::List => "policy list",
                PolicyCommand::Show(_) => "policy show",
                PolicyCommand::Enable(_) => "policy enable",
                PolicyCommand::Disable(_) => "policy disable",
                PolicyCommand::Simulate(_) => "policy simulate",
                PolicyCommand::Rearm(_) => "policy rearm",
            },
            Self::Config { command } => match command {
                ConfigCommand::Validate(_) => "config validate",
                ConfigCommand::Show(_) => "config show",
                ConfigCommand::Apply(_) => "config apply",
            },
            Self::History(_) => "history",
            Self::Doctor => "doctor",
            Self::Completions(_) => "completions",
            Self::License => "license",
        }
    }

    /// Whether the command emits a stream of events.
    pub fn is_streaming(&self) -> bool {
        matches!(self, Self::Monitor(_))
    }
}

#[derive(Debug, Args)]
pub struct ScanArgs {
    /// Root of the storage scope.
    pub path: PathBuf,
    /// Retain the scan catalog for later reports and plans.
    #[arg(long)]
    pub save: bool,
}

/// The shortest interval between two samples of `monitor`. The kernel gives
/// cached host statistics to a process that reads them more frequently.
pub const MIN_MONITOR_INTERVAL: Duration = Duration::from_secs(1);

/// The longest interval between two samples of `monitor`.
pub const MAX_MONITOR_INTERVAL: Duration = Duration::from_secs(3600);

/// Parses the sample interval of `monitor`.
fn monitor_interval(text: &str) -> Result<Duration, String> {
    let interval: Duration = positive_duration(text)?;
    if !(MIN_MONITOR_INTERVAL..=MAX_MONITOR_INTERVAL).contains(&interval) {
        return Err(format!("the interval `{text}` must be from 1s to 1h"));
    }
    Ok(interval)
}

#[derive(Debug, Args)]
pub struct MonitorArgs {
    /// Time between two samples, from 1s to 1h.
    #[arg(long, value_name = "DURATION", default_value = "2s", value_parser = monitor_interval)]
    pub interval: Duration,
}

#[derive(Debug, Args)]
pub struct ReportArgs {
    /// Identifier of a recorded scan.
    #[arg(long, value_name = "SCAN_ID")]
    pub scan: String,
}

#[derive(Debug, Subcommand)]
pub enum CleanCommand {
    /// Prepare a bounded cleanup plan. This command changes no file.
    Plan(CleanPlanArgs),
    /// Explain the targets, estimates, exclusions, and expiry of a plan.
    Show(PlanRef),
    /// Revalidate and execute an authorized plan.
    Apply(CleanApplyArgs),
}

#[derive(Debug, Args)]
pub struct CleanPlanArgs {
    /// Identifier of the scan that supplies the candidates.
    #[arg(long, value_name = "SCAN_ID")]
    pub scan: String,
    /// Selection preset that filters candidates. It grants no authority.
    #[arg(long, value_name = "PRESET")]
    pub profile: Option<String>,
    /// Removal mode.
    #[arg(long, value_enum, default_value_t = CleanMode::Trash)]
    pub mode: CleanMode,
    /// Reviewed cleanup rule. Only the `evict` mode accepts it, and requires it.
    #[arg(long, value_name = "RULE_ID", required_if_eq("mode", "evict"))]
    pub rule: Option<String>,
    /// An entry of the saved scan to select, by its exact path. Repeat it
    /// for each entry. With none, the `trash` and `permanent` modes list the
    /// candidates of the scan and make no plan. The `evict` mode takes no
    /// entry.
    #[arg(long = "entry", value_name = "PATH")]
    pub entries: Vec<PathBuf>,
}

/// Manual cleanup mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CleanMode {
    /// Move the selected entries to Trash.
    Trash,
    /// Permanently delete the selected entries.
    Permanent,
    /// Permanently remove the candidates of one reviewed rule.
    Evict,
}

#[derive(Debug, Args)]
pub struct PlanRef {
    /// Identifier of a prepared plan.
    #[arg(long, value_name = "PLAN_ID")]
    pub plan: String,
}

#[derive(Debug, Args)]
pub struct CleanApplyArgs {
    #[command(flatten)]
    pub plan: PlanRef,
    #[command(flatten)]
    pub apply: ApplyOptions,
}

/// Options of a command that applies a plan.
#[derive(Debug, Args)]
pub struct ApplyOptions {
    /// Approve the plan without a prompt. Exclusions and stale-plan checks stay in effect.
    #[arg(long)]
    pub yes: bool,
    /// Return the admitted operation reference and do not wait for completion.
    #[arg(long)]
    pub no_wait: bool,
}

#[derive(Debug, Subcommand)]
pub enum MemoryCommand {
    /// Show pressure, memory composition, and growth signals.
    Status,
}

#[derive(Debug, Subcommand)]
pub enum SwapCommand {
    /// Show global swap usage and recent activity.
    Status,
}

#[derive(Debug, Subcommand)]
pub enum ProcessesCommand {
    /// Rank applications or processes by a selected metric.
    Top(ProcessesTopArgs),
    /// Explain a target and its policy eligibility.
    Show(TargetRef),
    /// Request termination of a verified target.
    Stop(ProcessesStopArgs),
}

#[derive(Debug, Args)]
pub struct ProcessesTopArgs {
    /// Metric that orders the result.
    #[arg(long, value_enum, default_value_t = ProcessSort::Footprint)]
    pub sort: ProcessSort,
    /// Maximum number of entries.
    #[arg(long, value_name = "COUNT", value_parser = clap::value_parser!(u32).range(1..))]
    pub limit: Option<u32>,
}

/// Metric that orders `processes top`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ProcessSort {
    /// Physical footprint.
    Footprint,
    /// Resident set size.
    Rss,
    /// Recent footprint growth.
    Growth,
    /// CPU usage.
    Cpu,
}

#[derive(Debug, Args)]
pub struct TargetRef {
    /// Identifier of a verified target.
    #[arg(long, value_name = "TARGET_ID")]
    pub target: String,
}

#[derive(Debug, Args)]
pub struct ProcessesStopArgs {
    #[command(flatten)]
    pub target: TargetRef,
    /// Time that the target has to exit after the graceful request.
    #[arg(long, value_name = "DURATION", value_parser = positive_duration)]
    pub grace: Option<Duration>,
    /// Force termination immediately. Hard protections stay in effect.
    #[arg(long, conflicts_with = "force_after_timeout")]
    pub force: bool,
    /// Force termination if the target is still present after the grace period.
    #[arg(long)]
    pub force_after_timeout: bool,
    #[command(flatten)]
    pub apply: ApplyOptions,
}

#[derive(Debug, Subcommand)]
pub enum OperationsCommand {
    /// Show the recorded state of an operation.
    Show(OperationRef),
    /// Wait for the result of an operation.
    Wait(OperationRef),
    /// Stop the later steps of an operation.
    Cancel(OperationRef),
    /// Accept that the outcome of an operation stays unknown, and release its leases.
    Acknowledge(OperationRef),
}

#[derive(Debug, Args)]
pub struct OperationRef {
    /// Identifier of an admitted operation.
    #[arg(long, value_name = "OPERATION_ID")]
    pub operation: String,
}

#[derive(Debug, Subcommand)]
pub enum AgentCommand {
    /// Register the user-session agent in observation mode.
    Install(AgentServiceArgs),
    /// Show the state of the agent.
    Status,
    /// Suspend new automatic interventions.
    Pause(AgentPauseArgs),
    /// Resume automatic interventions.
    Resume,
    /// Remove the registered services of Svalnir.
    Uninstall(AgentServiceArgs),
}

/// Options of a command that changes the registered services of the host.
#[derive(Debug, Args)]
pub struct AgentServiceArgs {
    /// Approve the change of the registered services without a prompt.
    #[arg(long)]
    pub yes: bool,
}

#[derive(Debug, Args)]
pub struct AgentPauseArgs {
    /// Time after which the pause ends.
    #[arg(long = "for", value_name = "DURATION", value_parser = positive_duration)]
    pub duration: Option<Duration>,
}

#[derive(Debug, Subcommand)]
pub enum PolicyCommand {
    /// List the standing policies.
    List,
    /// Show one policy.
    Show(PolicyRef),
    /// Enable a policy and record the accepted action classes.
    Enable(PolicyEnableArgs),
    /// Disable a policy.
    Disable(PolicyRef),
    /// Explain which targets are eligible at the current snapshot.
    Simulate(PolicySimulateArgs),
    /// Authorize a new budget generation for an incident.
    Rearm(PolicyRearmArgs),
}

/// A standing policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum PolicyName {
    DiskGuard,
    MemoryGuard,
}

#[derive(Debug, Args)]
pub struct PolicyRef {
    /// Name of the policy.
    #[arg(value_enum)]
    pub policy: PolicyName,
}

#[derive(Debug, Args)]
pub struct PolicyEnableArgs {
    #[command(flatten)]
    pub policy: PolicyRef,
    /// Accept permanent eviction of approved regenerable data.
    #[arg(long)]
    pub accept_permanent_eviction: bool,
    /// Accept force quit of eligible applications.
    #[arg(long)]
    pub accept_force_quit: bool,
    /// Policy revision that was reviewed.
    #[arg(long, value_name = "POLICY_REVISION")]
    pub expected_revision: Option<String>,
}

#[derive(Debug, Args)]
pub struct PolicySimulateArgs {
    #[command(flatten)]
    pub policy: PolicyRef,
    #[command(flatten)]
    pub proposal: ProposalOption,
}

#[derive(Debug, Args)]
pub struct PolicyRearmArgs {
    #[command(flatten)]
    pub policy: PolicyRef,
    /// Identifier of the incident.
    #[arg(long, value_name = "INCIDENT_ID")]
    pub incident: String,
    /// Current budget generation of the incident.
    #[arg(long, value_name = "GENERATION")]
    pub generation: String,
}

/// Selection of a configuration file as a proposal.
#[derive(Debug, Args)]
pub struct ProposalOption {
    /// Configuration file to use as a proposal. This option does not activate the file.
    #[arg(long, value_name = "PATH")]
    pub config: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Validate a configuration proposal.
    Validate(ProposalOption),
    /// Show configuration values.
    Show(ConfigShowArgs),
    /// Activate a validated configuration revision.
    Apply(ConfigApplyArgs),
}

#[derive(Debug, Args)]
pub struct ConfigShowArgs {
    /// Show the resolved values with their provenance.
    #[arg(long)]
    pub effective: bool,
}

#[derive(Debug, Args)]
pub struct ConfigApplyArgs {
    /// Configuration file to activate.
    #[arg(long, value_name = "PATH")]
    pub config: PathBuf,
    /// Policy revision that the proposal replaces.
    #[arg(long, value_name = "POLICY_REVISION")]
    pub expected_revision: String,
}

#[derive(Debug, Args)]
pub struct HistoryArgs {
    /// Maximum number of records.
    #[arg(long, value_name = "COUNT", value_parser = clap::value_parser!(u32).range(1..))]
    pub limit: Option<u32>,
}

#[derive(Debug, Args)]
pub struct CompletionsArgs {
    /// Shell that reads the script.
    #[arg(value_enum)]
    pub shell: Shell,
}
