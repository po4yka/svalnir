//! The Diagnostics screen: two labeled capability lists (the summary of
//! the agent from its status record, and the probes of this window), the
//! status record of the agent, a start-failure record, and the journal
//! file. The screen shows state only.

use super::agent_state::span;
use super::common::{
    CardWidth, Shown, ago, body_line, bytes_text, caption, card, fact, failed_body, inset,
    problem_lines, screen, shown, skeleton_rows,
};
use crate::{
    data::{
        live::STATUS_FRESH,
        model::Measured,
        records::{
            AgentStatusRow, CapabilityLevel, CapabilityRow, DiagnosticsSnapshot, Need,
            StartFailureRow, Verdict,
        },
        store::AppModel,
    },
    theme::tokens::{self, Tokens, to_hsla},
    ui::{
        pill::{MonoTag, StatusPill, Tone},
        provenance::ProvenanceLine,
        surface::ShellHeader,
    },
};
use gpui_kit::{
    AnyElement, Context, Entity, FontWeight, IntoElement, ParentElement, Render, Role,
    SharedString, Styled, TestSupportExt as _, Window,
    component::{ActiveTheme as _, IconName, h_flex, v_flex},
    div,
    prelude::*,
    px,
};
use std::time::{Duration, SystemTime};

/// The capability summary of the agent from its status record, or the
/// reason that it is not shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentCapabilities {
    /// The status record is current and has the capability check of the
    /// start of the agent.
    Current {
        /// The verdict, as the agent wrote it: `ready`, `unverified`, or
        /// `blocked`.
        verdict: String,
        /// The required capabilities that the agent does not have.
        missing: Vec<String>,
        /// The age of the status record.
        age: Duration,
    },
    /// No current summary: one sentence with the reason.
    Unavailable(String),
}

/// The capability summary of the agent in `snapshot`. The summary is the
/// state of a running agent only when its status record is at most 90 s
/// old (three status intervals) and the agent did not record a stop.
#[must_use]
pub fn agent_capabilities(snapshot: &DiagnosticsSnapshot) -> AgentCapabilities {
    let status: &AgentStatusRow = match &snapshot.agent {
        Measured::Value(status) => status,
        Measured::Unavailable(reason) => {
            return AgentCapabilities::Unavailable(format!(
                "No agent capability summary: {reason}"
            ));
        }
    };
    let age: Duration = match snapshot.captured_at.duration_since(status.written_at) {
        Ok(age) => age,
        Err(ahead) if ahead.duration() <= STATUS_FRESH => Duration::ZERO,
        Err(_) => {
            return AgentCapabilities::Unavailable(
                "No agent capability summary: the status record has a time later than the clock of this window, so its age is not known.".to_owned(),
            );
        }
    };
    if age > STATUS_FRESH {
        return AgentCapabilities::Unavailable(format!(
            "No agent capability summary: the status record is {} old, so the agent does not run or does not write. The summary of that time is not the state of an agent now.",
            span(age)
        ));
    }
    if status.run_state == "stopped" {
        return AgentCapabilities::Unavailable(
            "No agent capability summary: the agent recorded that it stopped.".to_owned(),
        );
    }
    match &status.capability_verdict {
        Some(verdict) => AgentCapabilities::Current {
            verdict: verdict.clone(),
            missing: status.required_not_available.clone(),
            age,
        },
        None => AgentCapabilities::Unavailable(
            "No agent capability summary: the status record has no capability check of the agent."
                .to_owned(),
        ),
    }
}

/// The pill text and the tone of a verdict that the agent wrote as text.
/// A text that this build does not know is "Not known".
#[must_use]
pub fn agent_verdict_pill(verdict: &str) -> (&'static str, Tone) {
    match verdict {
        "ready" => verdict_pill(Verdict::Ready),
        "unverified" => verdict_pill(Verdict::Unverified),
        "blocked" => verdict_pill(Verdict::Blocked),
        _ => ("Not known", Tone::Warning),
    }
}

/// The pill text, the tone, and the icon of a capability state. Each state
/// has a different text, so the tone is not the only signal.
#[must_use]
pub fn level_pill(level: CapabilityLevel) -> (&'static str, Tone, IconName) {
    match level {
        CapabilityLevel::Available => ("Available", Tone::Positive, IconName::Check),
        CapabilityLevel::Denied => ("Denied", Tone::Negative, IconName::CircleX),
        CapabilityLevel::Unsupported => ("Not supported", Tone::Neutral, IconName::Minus),
        CapabilityLevel::Unknown => ("Unknown", Tone::Warning, IconName::TriangleAlert),
    }
}

/// The pill text and tone of a verdict.
#[must_use]
pub const fn verdict_pill(verdict: Verdict) -> (&'static str, Tone) {
    match verdict {
        Verdict::Ready => ("Ready", Tone::Positive),
        Verdict::Unverified => ("Not verified", Tone::Warning),
        Verdict::Blocked => ("Blocked", Tone::Negative),
    }
}

/// The sentence of a verdict.
#[must_use]
pub const fn verdict_sentence(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Ready => "Each required capability is available.",
        Verdict::Unverified => "A probe of a required capability gave no result.",
        Verdict::Blocked => "A required capability is denied or not supported.",
    }
}

/// The accessible sentence of one capability.
#[must_use]
pub fn capability_label(row: &CapabilityRow) -> String {
    let mut text: String = format!(
        "{}, {}, {}: {}",
        row.title,
        row.need.label(),
        level_pill(row.level).0,
        row.detail
    );
    if let Some(remediation) = &row.remediation {
        text = format!("{text} Fix: {remediation}");
    }
    text
}

/// The number of capabilities that are not available, without the entries
/// that only inform.
#[must_use]
pub fn not_available_count(rows: &[CapabilityRow]) -> usize {
    rows.iter()
        .filter(|row| row.need != Need::Informational && row.level != CapabilityLevel::Available)
        .count()
}

/// The Diagnostics screen entity.
#[derive(Debug)]
pub struct DiagnosticsScreen {
    model: Entity<AppModel>,
    activation: u64,
}

impl DiagnosticsScreen {
    /// Creates the screen and observes the model.
    pub fn new(model: Entity<AppModel>, cx: &mut Context<Self>) -> Self {
        cx.observe(&model, |_, _, cx| cx.notify()).detach();
        Self {
            model,
            activation: 1,
        }
    }

    /// Marks a new activation of the screen: the cards enter again.
    pub fn activate(&mut self, cx: &mut Context<Self>) {
        self.activation += 1;
        cx.notify();
    }
}

fn capability_row(row: &CapabilityRow, tokens: &Tokens) -> AnyElement {
    let (text, tone, icon) = level_pill(row.level);
    let id: &str = &row.id;
    let mut block = v_flex()
        .id(SharedString::from(format!("diagnostics-capability-{id}")))
        .test_support()
        .aria_label(capability_label(row))
        .gap(tokens::SPACE_1)
        .child(
            h_flex()
                .gap(tokens::SPACE_2)
                .items_center()
                .child(
                    div()
                        .flex_1()
                        .min_w_0()
                        .text_size(px(14.0))
                        .font_weight(FontWeight::MEDIUM)
                        .child(row.title.clone()),
                )
                .child(MonoTag::new(
                    SharedString::from(format!("diagnostics-id-{id}")),
                    row.id.clone(),
                ))
                .child(
                    StatusPill::new(text, tone)
                        .icon(icon)
                        .id(SharedString::from(format!("diagnostics-level-{id}"))),
                ),
        )
        .child(
            div()
                .text_size(px(12.0))
                .text_color(to_hsla(tokens.muted_foreground))
                .child(format!("{}. {}", row.need.label(), row.detail)),
        );
    if row.level != CapabilityLevel::Available {
        block = block.child(
            div()
                .text_size(px(12.0))
                .text_color(to_hsla(tokens.muted_foreground))
                .child(format!("Enables: {}", row.enables)),
        );
    }
    if let Some(remediation) = &row.remediation {
        block = block.child(caption(
            SharedString::from(format!("diagnostics-fix-{id}")),
            format!("Fix: {remediation}"),
            tokens,
        ));
    }
    inset(block, tokens)
}

/// The label of one of the two capability lists.
fn list_title(id: &'static str, text: &'static str, tokens: &Tokens) -> AnyElement {
    div()
        .id(id)
        .role(Role::Heading)
        .test_support()
        .aria_label(text)
        .text_size(px(13.0))
        .font_weight(FontWeight::SEMIBOLD)
        .text_color(to_hsla(tokens.foreground))
        .child(text)
        .into_any_element()
}

/// The list "Agent": the capability summary of the status record of the
/// agent, with its age, or the reason that it is not shown.
fn agent_list(value: &DiagnosticsSnapshot, mono: &SharedString, tokens: &Tokens) -> AnyElement {
    let mut list = v_flex()
        .gap(tokens::SPACE_1)
        .child(list_title("diagnostics-list-agent", "Agent", tokens))
        .child(caption(
            "diagnostics-agent-scope",
            "The capability check that the agent made at its start, from its status record.",
            tokens,
        ));
    match agent_capabilities(value) {
        AgentCapabilities::Unavailable(reason) => {
            list = list.child(body_line(
                "diagnostics-agent-summary-none",
                reason,
                true,
                tokens,
            ));
        }
        AgentCapabilities::Current {
            verdict,
            missing,
            age,
        } => {
            let (text, tone) = agent_verdict_pill(&verdict);
            list = list
                .child(
                    h_flex()
                        .gap(tokens::SPACE_2)
                        .items_center()
                        .child(StatusPill::new(text, tone).id("diagnostics-agent-verdict"))
                        .child(fact(
                            "diagnostics-agent-summary-age",
                            "Status record written",
                            format!("{} ago", span(age)),
                            mono,
                            false,
                            tokens,
                        )),
                )
                .child(body_line(
                    "diagnostics-agent-summary",
                    if missing.is_empty() {
                        "The agent has each required capability.".to_owned()
                    } else {
                        format!(
                            "The agent does not have {} required {}:",
                            missing.len(),
                            if missing.len() == 1 {
                                "capability"
                            } else {
                                "capabilities"
                            }
                        )
                    },
                    false,
                    tokens,
                ));
            for id in &missing {
                list = list.child(
                    h_flex()
                        .id(SharedString::from(format!(
                            "diagnostics-agent-missing-{id}"
                        )))
                        .test_support()
                        .aria_label(format!("{id}: not available to the agent"))
                        .gap(tokens::SPACE_2)
                        .child(MonoTag::new(
                            SharedString::from(format!("diagnostics-agent-missing-tag-{id}")),
                            id.clone(),
                        ))
                        .child(StatusPill::new("Not available", Tone::Negative)),
                );
            }
            list = list.child(caption(
                "diagnostics-agent-summary-limit",
                "The record has the verdict and the required capabilities that are not available, not the state of each capability.",
                tokens,
            ));
        }
    }
    inset(list, tokens)
}

fn capabilities_card(
    diagnostics: &Shown<DiagnosticsSnapshot>,
    mono: &SharedString,
    tokens: &Tokens,
) -> AnyElement {
    let header: ShellHeader =
        ShellHeader::new(IconName::Inspector, "Capabilities").subtitle("The agent and this window");
    let body: AnyElement = match diagnostics {
        Shown::Loading => skeleton_rows(6),
        Shown::Failed(reason) => failed_body("diagnostics-value", reason, tokens),
        Shown::Data { value, .. } => {
            let (text, tone) = verdict_pill(value.verdict);
            let missing: usize = not_available_count(&value.capabilities);
            let mut window_list = v_flex()
                .gap(tokens::SPACE_2)
                .child(
                    h_flex()
                        .gap(tokens::SPACE_2)
                        .items_center()
                        .child(list_title("diagnostics-list-window", "This window", tokens))
                        .child(StatusPill::new(text, tone).id("diagnostics-verdict")),
                )
                .child(body_line(
                    "diagnostics-verdict-sentence",
                    format!(
                        "{} {missing} of {} capabilities that the product uses are not available.",
                        verdict_sentence(value.verdict),
                        value
                            .capabilities
                            .iter()
                            .filter(|row| row.need != Need::Informational)
                            .count()
                    ),
                    false,
                    tokens,
                ));
            for row in &value.capabilities {
                window_list = window_list.child(capability_row(row, tokens));
            }
            if value.capabilities.is_empty() {
                window_list = window_list.child(body_line(
                    "diagnostics-empty",
                    "The report has no capability.",
                    true,
                    tokens,
                ));
            }
            window_list = window_list
                .child(caption(
                    "diagnostics-scope",
                    format!(
                        "{}. The probes of this window are not the capabilities of the agent, which runs as a different process.",
                        value.subject
                    ),
                    tokens,
                ))
                .child(
                    ProvenanceLine::new("capability probes", value.captured_at, "this process")
                        .id("diagnostics-provenance"),
                );
            v_flex()
                .gap(tokens::SPACE_3)
                .child(agent_list(value, mono, tokens))
                .child(window_list)
                .into_any_element()
        }
    };
    card(header, body)
}

fn start_failure_block(
    failure: &StartFailureRow,
    now: SystemTime,
    mono: &SharedString,
    tokens: &Tokens,
) -> AnyElement {
    let when: String = failure.failed_at.map_or_else(
        || "at a time that is not known".to_owned(),
        |time| ago(time, now),
    );
    inset(
        v_flex()
            .gap(tokens::SPACE_2)
            .child(
                h_flex()
                    .gap(tokens::SPACE_2)
                    .items_center()
                    .justify_between()
                    .child(body_line(
                        "diagnostics-start-failure",
                        format!("The agent did not start {when}: {}.", failure.message),
                        false,
                        tokens,
                    ))
                    .child(
                        StatusPill::new("Start failed", Tone::Negative)
                            .icon(IconName::CircleX)
                            .id("diagnostics-start-failure-pill"),
                    ),
            )
            .child(fact(
                "diagnostics-start-failure-code",
                "Reason",
                failure.code.clone(),
                mono,
                false,
                tokens,
            ))
            .child(fact(
                "diagnostics-start-failure-version",
                "Agent version",
                failure.agent_version.clone(),
                mono,
                false,
                tokens,
            ))
            .child(caption(
                "diagnostics-start-failure-fix",
                "Fix: correct the cause, then start the agent again. The system does not restart the agent after this failure.",
                tokens,
            )),
        tokens,
    )
}

fn agent_facts(
    status: &AgentStatusRow,
    now: SystemTime,
    mono: &SharedString,
    tokens: &Tokens,
) -> Vec<AnyElement> {
    let footprint: String = format!(
        "{} of {}",
        bytes_text(&status.footprint),
        bytes_text(&Measured::Value(status.budget))
    );
    let mut rows: Vec<AnyElement> = vec![
        fact(
            "diagnostics-agent-state",
            "Run state in the record",
            status.run_state,
            mono,
            false,
            tokens,
        ),
        fact(
            "diagnostics-agent-written",
            "Record written",
            ago(status.written_at, now),
            mono,
            false,
            tokens,
        ),
        fact(
            "diagnostics-agent-started",
            "Agent started",
            ago(status.started_at, now),
            mono,
            false,
            tokens,
        ),
        fact(
            "diagnostics-agent-pid",
            "Process ID",
            status.process_id.to_string(),
            mono,
            false,
            tokens,
        ),
        fact(
            "diagnostics-agent-revision",
            "Evaluates revision",
            status
                .revision
                .clone()
                .unwrap_or_else(|| "none: the agent only observes".to_owned()),
            mono,
            false,
            tokens,
        ),
        fact(
            "diagnostics-agent-footprint",
            "Footprint of budget",
            footprint,
            mono,
            false,
            tokens,
        ),
        fact(
            "diagnostics-agent-unclean",
            "Stops in sequence that were not clean",
            status.unclean_stops.to_string(),
            mono,
            false,
            tokens,
        ),
    ];
    rows.extend(agent_notes(status, tokens));
    rows
}

/// The lines below the facts of the agent: each condition that limits it.
fn agent_notes(status: &AgentStatusRow, tokens: &Tokens) -> Vec<AnyElement> {
    let mut rows: Vec<AnyElement> = Vec::new();
    if let Some(problem) = &status.policy_problem {
        rows.push(caption(
            "diagnostics-agent-policy-problem",
            format!("Problem: the agent cannot use the authority record: {problem}."),
            tokens,
        ));
    }
    if !status.degraded.is_empty() {
        rows.push(caption(
            "diagnostics-agent-degraded",
            format!("Reduced function: {}.", status.degraded.join(", ")),
            tokens,
        ));
    }
    if status.restart_backoff {
        rows.push(caption(
            "diagnostics-agent-backoff",
            "The restart backoff inhibits automatic work.",
            tokens,
        ));
    }
    rows.push(caption(
        "diagnostics-agent-note",
        "The record is evidence of an agent at the time it was written. It does not show that an agent runs now.",
        tokens,
    ));
    rows
}

fn agent_card(
    diagnostics: &Shown<DiagnosticsSnapshot>,
    now: SystemTime,
    mono: &SharedString,
    tokens: &Tokens,
) -> AnyElement {
    let header: ShellHeader =
        ShellHeader::new(IconName::Cpu, "Agent").subtitle("Status record of the journal");
    let body: AnyElement = match diagnostics {
        Shown::Loading => skeleton_rows(4),
        Shown::Failed(reason) => failed_body("diagnostics-agent-value", reason, tokens),
        Shown::Data { value, .. } => {
            let mut body = v_flex().gap(tokens::SPACE_2);
            if let Some(failure) = &value.start_failure {
                body = body.child(start_failure_block(failure, now, mono, tokens));
            }
            body = match &value.agent {
                Measured::Value(status) => body.children(agent_facts(status, now, mono, tokens)),
                Measured::Unavailable(reason) => body.child(body_line(
                    "diagnostics-agent-none",
                    reason.clone(),
                    true,
                    tokens,
                )),
            };
            body.into_any_element()
        }
    };
    card(header, body)
}

fn journal_card(
    diagnostics: &Shown<DiagnosticsSnapshot>,
    mono: &SharedString,
    tokens: &Tokens,
) -> AnyElement {
    let header: ShellHeader =
        ShellHeader::new(IconName::HardDrive, "Journal and client").subtitle("Read-only");
    let body: AnyElement = match diagnostics {
        Shown::Loading => skeleton_rows(3),
        Shown::Failed(reason) => failed_body("diagnostics-journal-value", reason, tokens),
        Shown::Data { value, .. } => {
            let journal = &value.journal;
            let mut body = v_flex()
                .gap(tokens::SPACE_2)
                .child(fact(
                    "diagnostics-journal-path",
                    "Journal file",
                    journal
                        .path
                        .as_ref()
                        .map_or_else(|| "\u{2014}".to_owned(), |path| path.display().to_string()),
                    mono,
                    false,
                    tokens,
                ))
                .child(fact(
                    "diagnostics-journal-present",
                    "Exists",
                    if journal.present { "Yes" } else { "No" },
                    mono,
                    false,
                    tokens,
                ))
                .child(fact(
                    "diagnostics-journal-size",
                    "Size and size limit",
                    format!(
                        "{} of {}",
                        bytes_text(&journal.size),
                        bytes_text(&journal.limit)
                    ),
                    mono,
                    false,
                    tokens,
                ))
                .child(fact(
                    "diagnostics-client-version",
                    "Version of this window",
                    value.client_version,
                    mono,
                    false,
                    tokens,
                ));
            body = body.children(problem_lines("diagnostics", &value.problems, tokens));
            body = body.child(caption(
                "diagnostics-read-only-note",
                "The reads of the window open the journal for reading only and make no file. Only an action that you start on the Automation, History, or Applications screen writes to the journal, and it first reads the coordinator lock to find the agent.",
                tokens,
            ));
            body.into_any_element()
        }
    };
    card(header, body)
}

impl Render for DiagnosticsScreen {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tokens: &Tokens = Tokens::for_dark(cx.theme().is_dark());
        let mono: SharedString = cx.theme().mono_font_family.clone();
        let model: &AppModel = self.model.read(cx);
        let now: SystemTime = SystemTime::now();
        let diagnostics = shown(&model.diagnostics, now, |diagnostics| {
            diagnostics.captured_at
        });
        let cards: Vec<(CardWidth, AnyElement)> = vec![
            (
                CardWidth::Full,
                capabilities_card(&diagnostics, &mono, tokens),
            ),
            (
                CardWidth::Share,
                agent_card(&diagnostics, now, &mono, tokens),
            ),
            (CardWidth::Share, journal_card(&diagnostics, &mono, tokens)),
        ];
        screen("Diagnostics", cards, self.activation, cx.reduce_motion())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(need: Need, level: CapabilityLevel, remediation: Option<&str>) -> CapabilityRow {
        CapabilityRow {
            id: "privacy.full_disk_access".to_owned(),
            title: "Full Disk Access".to_owned(),
            need,
            level,
            detail: "A protected location refused the read.".to_owned(),
            enables: "A scan.".to_owned(),
            remediation: remediation.map(str::to_owned),
        }
    }

    /// The healthy fixture with the status record `edit` makes from its
    /// record, or with no record.
    fn snapshot_with(
        edit: impl FnOnce(AgentStatusRow, SystemTime) -> Measured<AgentStatusRow>,
    ) -> DiagnosticsSnapshot {
        use crate::data::{
            DataSource as _,
            fixture::{FixtureScenario, FixtureSource},
        };
        let mut snapshot = FixtureSource::new(FixtureScenario::Healthy).diagnostics();
        let Measured::Value(status) = snapshot.agent.clone() else {
            panic!("the healthy fixture has a status record");
        };
        snapshot.agent = edit(status, snapshot.captured_at);
        snapshot
    }

    #[test]
    fn a_current_status_record_gives_the_summary_of_the_agent() {
        let snapshot = snapshot_with(|mut status, now| {
            status.capability_verdict = Some("blocked".to_owned());
            status.required_not_available = vec!["privacy.full_disk_access".to_owned()];
            status.written_at = now - Duration::from_secs(30);
            Measured::Value(status)
        });
        assert_eq!(
            agent_capabilities(&snapshot),
            AgentCapabilities::Current {
                verdict: "blocked".to_owned(),
                missing: vec!["privacy.full_disk_access".to_owned()],
                age: Duration::from_secs(30),
            }
        );
        assert_eq!(agent_verdict_pill("blocked"), ("Blocked", Tone::Negative));
        assert_eq!(agent_verdict_pill("other"), ("Not known", Tone::Warning));
    }

    #[test]
    fn an_old_stopped_future_or_empty_record_gives_no_summary() {
        type Edit = fn(AgentStatusRow, SystemTime) -> Measured<AgentStatusRow>;
        let cases: Vec<(Edit, &str)> = vec![
            (
                |_, _| Measured::Unavailable("No journal exists.".to_owned()),
                "No journal exists.",
            ),
            (
                |mut status, now| {
                    status.written_at = now - Duration::from_secs(91);
                    Measured::Value(status)
                },
                "1 min old",
            ),
            (
                |mut status, now| {
                    status.written_at = now;
                    status.run_state = "stopped";
                    Measured::Value(status)
                },
                "recorded that it stopped",
            ),
            (
                |mut status, now| {
                    status.written_at = now + Duration::from_secs(600);
                    Measured::Value(status)
                },
                "later than the clock",
            ),
            (
                |mut status, now| {
                    status.written_at = now;
                    status.capability_verdict = None;
                    Measured::Value(status)
                },
                "no capability check",
            ),
        ];
        for (edit, expected) in cases {
            let summary = agent_capabilities(&snapshot_with(edit));
            let AgentCapabilities::Unavailable(reason) = summary else {
                panic!("a summary: {summary:?}");
            };
            assert!(
                reason.starts_with("No agent capability summary: "),
                "{reason}"
            );
            assert!(reason.contains(expected), "{reason}");
        }
    }

    #[test]
    fn each_capability_state_has_its_own_text_and_tone() {
        let texts: Vec<(&str, Tone)> = [
            CapabilityLevel::Available,
            CapabilityLevel::Denied,
            CapabilityLevel::Unsupported,
            CapabilityLevel::Unknown,
        ]
        .into_iter()
        .map(|level| {
            let (text, tone, _) = level_pill(level);
            (text, tone)
        })
        .collect();
        assert_eq!(
            texts,
            [
                ("Available", Tone::Positive),
                ("Denied", Tone::Negative),
                ("Not supported", Tone::Neutral),
                ("Unknown", Tone::Warning),
            ]
        );
    }

    #[test]
    fn an_unknown_capability_is_not_available() {
        let rows = [
            row(Need::Required, CapabilityLevel::Unknown, None),
            row(Need::Optional, CapabilityLevel::Denied, None),
            row(Need::Optional, CapabilityLevel::Available, None),
            row(Need::Informational, CapabilityLevel::Unsupported, None),
        ];
        assert_eq!(not_available_count(&rows), 2);
    }

    #[test]
    fn the_label_has_the_state_and_the_fix() {
        assert_eq!(
            capability_label(&row(
                Need::Optional,
                CapabilityLevel::Denied,
                Some("Add the component.")
            )),
            "Full Disk Access, Optional, Denied: A protected location refused the read. Fix: Add the component."
        );
    }

    #[test]
    fn a_verdict_that_is_not_verified_is_a_warning() {
        assert_eq!(verdict_pill(Verdict::Ready), ("Ready", Tone::Positive));
        assert_eq!(
            verdict_pill(Verdict::Unverified),
            ("Not verified", Tone::Warning)
        );
        assert_eq!(verdict_pill(Verdict::Blocked), ("Blocked", Tone::Negative));
    }
}
