//! The Diagnostics screen: the capabilities of this process, the status
//! record of the agent, a start-failure record, and the journal file. The
//! screen shows state only.

use super::common::{
    CardWidth, Shown, ago, body_line, bytes_text, caption, card, fact, failed_body, inset,
    problem_lines, screen, shown, skeleton_rows,
};
use crate::{
    data::{
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
    AnyElement, Context, Entity, FontWeight, IntoElement, ParentElement, Render, SharedString,
    Styled, TestSupportExt as _, Window,
    component::{ActiveTheme as _, IconName, h_flex, v_flex},
    div,
    prelude::*,
    px,
};
use std::time::SystemTime;

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

fn capabilities_card(diagnostics: &Shown<DiagnosticsSnapshot>, tokens: &Tokens) -> AnyElement {
    let mut header: ShellHeader =
        ShellHeader::new(IconName::Inspector, "Capabilities").subtitle("Probes of this process");
    let body: AnyElement = match diagnostics {
        Shown::Loading => skeleton_rows(6),
        Shown::Failed(reason) => failed_body("diagnostics-value", reason, tokens),
        Shown::Data { value, .. } => {
            let (text, tone) = verdict_pill(value.verdict);
            header = header.aside(StatusPill::new(text, tone).id("diagnostics-verdict"));
            let missing: usize = not_available_count(&value.capabilities);
            let mut body = v_flex().gap(tokens::SPACE_2).child(body_line(
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
                body = body.child(capability_row(row, tokens));
            }
            if value.capabilities.is_empty() {
                body = body.child(body_line(
                    "diagnostics-empty",
                    "The report has no capability.",
                    true,
                    tokens,
                ));
            }
            body = body
                .child(caption(
                    "diagnostics-scope",
                    format!(
                        "{}. A capability of the agent can be different; see the status record of the agent.",
                        value.subject
                    ),
                    tokens,
                ))
                .child(
                    ProvenanceLine::new("capability probes", value.captured_at, "this process")
                        .id("diagnostics-provenance"),
                );
            body.into_any_element()
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
            "diagnostics-agent-capabilities",
            "Capability check of the agent",
            status
                .capability_verdict
                .clone()
                .unwrap_or_else(|| "\u{2014}".to_owned()),
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
    if !status.required_not_available.is_empty() {
        rows.push(caption(
            "diagnostics-agent-missing",
            format!(
                "The agent does not have these required capabilities: {}.",
                status.required_not_available.join(", ")
            ),
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
                    "Size of limit",
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
            (CardWidth::Full, capabilities_card(&diagnostics, tokens)),
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
