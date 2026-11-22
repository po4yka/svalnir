//! The Cleanup section of the Storage screen (`DESIGN.md` §4, §7, §11): the
//! reviewed cleanup rules with their inspection, the options of a manual
//! plan, the confirmation of the sealed plan, and the state of its apply.
//!
//! An inspection reads and changes nothing. A plan is made only when the
//! user asks for it, and it is recorded and sent to the agent only after
//! the confirmation. With no agent, or for a rule in the lifecycle state
//! `proposed`, the plan is refused and nothing is written.

use crate::{
    actions::{
        Slot,
        cleanup::{
            CleanupDraft, CleanupOptions, CleanupProposal, CleanupSnapshot, MIN_SIZES, PlanKind,
            RuleInspection, UnitRow, bytes_label, plan_gate,
        },
    },
    data::{model::Loadable, store::AppModel},
    screens::{
        common::{ago, body_line, caption, failed_body, inset, skeleton_rows, until},
        controls::{TARGET_LIST_HEIGHT, focus_ring, footer, list_scroll, open_state_detail},
    },
    theme::tokens::{self, Tokens, to_hsla},
    ui::{
        action_button::{ActionButton, ButtonVariant},
        action_status::{action_status, action_status_short},
        pill::{MonoTag, StatusPill, Tone},
        segmented::SegmentedControl,
        surface::{Panel, Shell, ShellHeader},
    },
};
use gpui_kit::{
    AnyElement, App, Entity, FocusHandle, InteractiveElement as _, IntoElement, ParentElement as _,
    Role, ScrollHandle, SharedString, StatefulInteractiveElement as _, Styled as _,
    TestSupportExt as _, Window,
    component::{
        ActiveTheme as _, IconName, WindowExt as _, checkbox::Checkbox, dialog::Dialog, h_flex,
        v_flex,
    },
    div, point, px,
};
use std::{sync::Arc, time::SystemTime};

/// The step of an arrow key in the target list.
const TARGET_ROW_STEP: f32 = 24.0;

/// The consent sentence of a rule whose command removes the whole cache.
pub const CLEAR_CONSENT: &str = "I understand that the command removes the whole cache, also data that a project uses now. The next build downloads or compiles it again.";

/// The sentence at the top of the section.
const INTRO: &str = "An inspection reads the roots of each rule and changes nothing. A plan is made only when you ask for it, and nothing is removed until you confirm the plan and the agent admits it.";

/// The tone of a lifecycle state: `brand` for a validated state, neutral
/// for `proposed`. A state is a fact, not an alarm.
fn lifecycle_tone(lifecycle: &str) -> Tone {
    if lifecycle.contains("validated") {
        Tone::Brand
    } else {
        Tone::Neutral
    }
}

/// The text of the size of a unit: the size and what it is, or an em dash.
#[must_use]
pub fn unit_size(unit: &UnitRow) -> String {
    match unit.size {
        Some(bytes) => {
            let partial: &str = if unit.partial { ", partial" } else { "" };
            format!(
                "{} {}{partial}",
                bytes_label(bytes),
                unit.size_kind.caption()
            )
        }
        None => "— not measured".to_owned(),
    }
}

fn unit_line(
    rule: &str,
    index: usize,
    unit: &UnitRow,
    mono: &SharedString,
    tokens: &Tokens,
) -> AnyElement {
    let size: String = unit_size(unit);
    let reason: Option<String> = unit
        .reason
        .as_ref()
        .map(|reason| format!("Not eligible now: {reason}"));
    let label: String = match &reason {
        Some(reason) => format!("{}: {size}. {reason}", unit.path),
        None => format!("{}: {size}", unit.path),
    };
    v_flex()
        .id(SharedString::from(format!("cleanup-unit-{rule}-{index}")))
        .role(Role::ListItem)
        .test_support()
        .aria_label(label)
        .min_w_0()
        .child(
            div()
                .font_family(mono.clone())
                .text_size(px(12.0))
                .min_w_0()
                .child(unit.path.clone()),
        )
        .child(
            h_flex()
                .gap(tokens::SPACE_2)
                .flex_wrap()
                .text_size(px(12.0))
                .text_color(to_hsla(tokens.muted_foreground))
                .child(div().font_family(mono.clone()).child(size))
                .children(
                    reason.map(|reason| div().text_color(to_hsla(tokens.warning)).child(reason)),
                ),
        )
        .into_any_element()
}

/// A checkbox in a wrapper that has the id, so that the keyboard, the
/// pointer, and a test reach it.
fn option_checkbox(
    id: &str,
    label: &'static str,
    checked: bool,
    model: &Entity<AppModel>,
    rule: &str,
    change: fn(&mut CleanupOptions, bool),
) -> AnyElement {
    let model: Entity<AppModel> = model.clone();
    let rule: String = rule.to_owned();
    h_flex()
        .id(SharedString::from(id.to_owned()))
        .test_support()
        .aria_label(format!(
            "{label} ({})",
            if checked { "checked" } else { "not checked" }
        ))
        .child(
            Checkbox::new(SharedString::from(format!("{id}-box")))
                .label(label)
                .checked(checked)
                .on_click(move |value, _, cx| {
                    let value: bool = *value;
                    model.update(cx, |model, cx| {
                        let mut options: CleanupOptions = model.cleanup_book.options(&rule);
                        change(&mut options, value);
                        model.set_cleanup_options(&rule, options, cx);
                    });
                }),
        )
        .into_any_element()
}

fn min_size_control(
    rule: &str,
    options: CleanupOptions,
    model: &Entity<AppModel>,
    tokens: &Tokens,
) -> AnyElement {
    let active: usize = MIN_SIZES
        .iter()
        .position(|(size, _)| *size == options.min_size)
        .unwrap_or(0);
    let model: Entity<AppModel> = model.clone();
    let owned: String = rule.to_owned();
    h_flex()
        .gap(tokens::SPACE_2)
        .items_center()
        .flex_wrap()
        .child(
            div()
                .text_size(px(13.0))
                .text_color(to_hsla(tokens.muted_foreground))
                .child("Minimum size"),
        )
        .child(
            SegmentedControl::new(
                SharedString::from(format!("cleanup-min-{rule}")),
                MIN_SIZES
                    .iter()
                    .enumerate()
                    .map(|(index, (_, label))| {
                        (
                            SharedString::from(format!("cleanup-min-{rule}-{index}")),
                            SharedString::from(*label),
                        )
                    })
                    .collect(),
                active,
            )
            .track(to_hsla(tokens.surface_inset))
            .on_change(move |index, _, cx| {
                if let Some((size, _)) = MIN_SIZES.get(index) {
                    let size: Option<u64> = *size;
                    model.update(cx, |model, cx| {
                        let mut options: CleanupOptions = model.cleanup_book.options(&owned);
                        options.min_size = size;
                        model.set_cleanup_options(&owned, options, cx);
                    });
                }
            }),
        )
        .into_any_element()
}

/// The plan control of a rule, the reason when it is off, and the state of
/// its last plan.
fn plan_controls(
    rule: &RuleInspection,
    model_entity: &Entity<AppModel>,
    model: &AppModel,
    tokens: &Tokens,
) -> Vec<AnyElement> {
    let Some(kind) = rule.plan else {
        return vec![caption(
            format!("cleanup-gate-{}", rule.rule),
            "Inspection only: this build has no plan for this rule.",
            tokens,
        )];
    };
    let options: CleanupOptions = model.cleanup_book.options(&rule.rule);
    let slot: Slot = Slot::Cleanup(rule.rule.clone());
    let busy: bool = model.actions.is_busy(&slot);
    let open: Option<&str> = model.cleanup_book.open_rule();
    let reason: Option<&'static str> = plan_gate(rule, &options).or_else(|| {
        open.filter(|open| *open != rule.rule).map(
            |_| "The plan of a different rule is open, so this control is off until it closes.",
        )
    });
    let mut out: Vec<AnyElement> = Vec::new();
    let opener: Entity<AppModel> = model_entity.clone();
    let id: String = rule.rule.clone();
    out.push(
        h_flex()
            .gap(tokens::SPACE_2)
            .items_center()
            .flex_wrap()
            .child(
                ActionButton::new(
                    SharedString::from(format!("cleanup-plan-{}", rule.rule)),
                    match kind {
                        PlanKind::Evict => "Make eviction plan…",
                        PlanKind::Owner => "Make command plan…",
                    },
                )
                .variant(ButtonVariant::Secondary)
                .loading(busy)
                .disabled(reason.is_some())
                .on_click(move |_, window, cx| {
                    open_cleanup(&opener, &id, kind, window, cx);
                }),
            )
            .into_any_element(),
    );
    if let Some(reason) = reason {
        out.push(caption(
            format!("cleanup-gate-{}", rule.rule),
            format!("Plan is off: {reason}"),
            tokens,
        ));
    }
    if let Some(state) = model.actions.state(&slot) {
        let opener: Entity<AppModel> = model_entity.clone();
        let title: String = format!("Last plan of {}", rule.rule);
        let detail_slot: Slot = slot.clone();
        out.push(
            h_flex()
                .w_full()
                .min_w_0()
                .items_start()
                .gap(tokens::SPACE_2)
                .child(div().flex_1().min_w_0().child(action_status_short(
                    SharedString::from(format!("cleanup-state-{}", rule.rule)),
                    state,
                    tokens,
                )))
                .child(
                    ActionButton::new(
                        SharedString::from(format!("cleanup-details-{}", rule.rule)),
                        "Details",
                    )
                    .variant(ButtonVariant::Quiet)
                    .on_click(move |_, window, cx| {
                        open_state_detail(&opener, detail_slot.clone(), title.clone(), window, cx);
                    }),
                )
                .into_any_element(),
        );
    }
    out
}

/// The first line of a rule: its identity, family, producer, revision, and
/// lifecycle state.
fn rule_heading(rule: &RuleInspection, tokens: &Tokens) -> AnyElement {
    let id: &str = rule.rule.as_str();
    h_flex()
        .gap(tokens::SPACE_2)
        .items_center()
        .flex_wrap()
        .child(MonoTag::new(
            SharedString::from(format!("cleanup-tag-{id}")),
            id.to_owned(),
        ))
        .child(
            div()
                .text_size(px(13.0))
                .text_color(to_hsla(tokens.muted_foreground))
                .child(format!(
                    "{} · {} · revision {}",
                    rule.family.label(),
                    rule.producer,
                    rule.revision
                )),
        )
        .child(
            StatusPill::new(rule.lifecycle.clone(), lifecycle_tone(&rule.lifecycle))
                .id(SharedString::from(format!("cleanup-lifecycle-{id}"))),
        )
        .into_any_element()
}

/// The roots and the units of the inspection of a rule.
fn rule_findings(rule: &RuleInspection, mono: &SharedString, tokens: &Tokens) -> Vec<AnyElement> {
    let id: &str = rule.rule.as_str();
    let mut out: Vec<AnyElement> = Vec::new();
    for (index, root) in rule.roots.iter().enumerate() {
        out.push(
            div()
                .id(SharedString::from(format!("cleanup-root-{id}-{index}")))
                .test_support()
                .aria_label(format!("Root {}: {}", root.path, root.state))
                .text_size(px(12.0))
                .text_color(to_hsla(tokens.muted_foreground))
                .child(
                    h_flex()
                        .gap(tokens::SPACE_2)
                        .flex_wrap()
                        .child("Root")
                        .child(div().font_family(mono.clone()).child(root.path.clone()))
                        .child(root.state.clone()),
                )
                .into_any_element(),
        );
    }
    if !rule.units.is_empty() {
        let mut list = v_flex()
            .id(SharedString::from(format!("cleanup-units-{id}")))
            .role(Role::List)
            .gap(tokens::SPACE_2)
            .min_w_0();
        for (index, unit) in rule.units.iter().enumerate() {
            list = list.child(unit_line(id, index, unit, mono, tokens));
        }
        if rule.units_omitted > 0 {
            list = list.child(caption(
                format!("cleanup-units-more-{id}"),
                format!("And {} more units.", rule.units_omitted),
                tokens,
            ));
        }
        out.push(div().w_full().child(inset(list, tokens)).into_any_element());
    }
    out
}

/// The owner command of a rule as the inspection resolved it.
fn owner_inset(rule: &RuleInspection, mono: &SharedString, tokens: &Tokens) -> Option<AnyElement> {
    let owner = rule.owner.as_ref()?;
    let id: &str = rule.rule.as_str();
    Some(
        div()
            .w_full()
            .child(inset(
                v_flex()
                    .gap(tokens::SPACE_1)
                    .child(
                        div()
                            .id(SharedString::from(format!("cleanup-command-{id}")))
                            .test_support()
                            .aria_label(format!("Command ({}): {}", owner.kind, owner.command))
                            .font_family(mono.clone())
                            .text_size(px(12.0))
                            .child(owner.command.clone()),
                    )
                    .children(owner.environment.iter().map(|entry| {
                        div()
                            .font_family(mono.clone())
                            .text_size(px(11.0))
                            .text_color(to_hsla(tokens.muted_foreground))
                            .child(entry.clone())
                    }))
                    .child(
                        div()
                            .text_size(px(12.0))
                            .text_color(to_hsla(tokens.muted_foreground))
                            .child(format!("{} {}", owner.effect, owner.consequence)),
                    ),
                tokens,
            ))
            .into_any_element(),
    )
}

/// The options of the plan of a rule that the rule permits.
fn plan_options(
    rule: &RuleInspection,
    options: CleanupOptions,
    model_entity: &Entity<AppModel>,
    tokens: &Tokens,
) -> Vec<AnyElement> {
    let id: &str = rule.rule.as_str();
    let mut out: Vec<AnyElement> = Vec::new();
    if rule.plan.is_none() {
        return out;
    }
    if rule.project_options {
        out.push(option_checkbox(
            &format!("cleanup-active-{id}"),
            "Include active projects. A busy project is never included.",
            options.include_active,
            model_entity,
            id,
            |options, value| options.include_active = value,
        ));
        out.push(min_size_control(id, options, model_entity, tokens));
    }
    if rule.needs_clear {
        out.push(option_checkbox(
            &format!("cleanup-clear-{id}"),
            CLEAR_CONSENT,
            options.include_clear,
            model_entity,
            id,
            |options, value| options.include_clear = value,
        ));
    }
    out
}

fn rule_block(
    rule: &RuleInspection,
    model_entity: &Entity<AppModel>,
    model: &AppModel,
    mono: &SharedString,
    tokens: &Tokens,
) -> AnyElement {
    let id: &str = rule.rule.as_str();
    let options: CleanupOptions = model.cleanup_book.options(id);
    v_flex()
        .id(SharedString::from(format!("cleanup-rule-{id}")))
        .test_support()
        .aria_label(format!(
            "Rule {id}, revision {}, {}, lifecycle state {}",
            rule.revision,
            rule.family.label(),
            rule.lifecycle
        ))
        .items_start()
        .gap(tokens::SPACE_2)
        .py(tokens::SPACE_3)
        .border_t_1()
        .border_color(to_hsla(tokens.border))
        .child(rule_heading(rule, tokens))
        .children(rule_findings(rule, mono, tokens))
        .children(owner_inset(rule, mono, tokens))
        .children(
            rule.problem
                .as_ref()
                .map(|problem| caption(format!("cleanup-problem-{id}"), problem.clone(), tokens)),
        )
        .children(plan_options(rule, options, model_entity, tokens))
        .children(plan_controls(rule, model_entity, model, tokens))
        .into_any_element()
}

/// The Cleanup card of the Storage screen.
pub fn cleanup_card(
    model_entity: &Entity<AppModel>,
    model: &AppModel,
    mono: &SharedString,
    now: SystemTime,
    tokens: &Tokens,
) -> AnyElement {
    let refresher: Entity<AppModel> = model_entity.clone();
    let header: ShellHeader = ShellHeader::new(IconName::Delete, "Cleanup rules")
        .subtitle("Manual plans of the reviewed rules")
        .aside(
            ActionButton::new("cleanup-inspect", "Inspect again")
                .variant(ButtonVariant::Quiet)
                .loading(model.is_inspecting())
                .on_click(move |_, _, cx| {
                    refresher.update(cx, AppModel::inspect_cleanup);
                }),
        );
    let body: AnyElement = match &model.cleanup {
        Loadable::Loading => skeleton_rows(4),
        Loadable::Unavailable(reason) => failed_body("cleanup-failed", reason, tokens),
        Loadable::Ready(snapshot) | Loadable::Stale(snapshot) => {
            rules_body(snapshot, model_entity, model, mono, now, tokens)
        }
    };
    Shell::new()
        .child(header)
        .child(
            Panel::new().child(
                v_flex()
                    .gap(tokens::SPACE_2)
                    .child(caption("cleanup-intro", INTRO, tokens))
                    .child(body),
            ),
        )
        .into_any_element()
}

fn rules_body(
    snapshot: &CleanupSnapshot,
    model_entity: &Entity<AppModel>,
    model: &AppModel,
    mono: &SharedString,
    now: SystemTime,
    tokens: &Tokens,
) -> AnyElement {
    v_flex()
        .id("cleanup-rules")
        .test_support()
        .aria_label(format!("{} cleanup rules", snapshot.rules.len()))
        .children(
            snapshot
                .rules
                .iter()
                .map(|rule| rule_block(rule, model_entity, model, mono, tokens)),
        )
        .child(caption(
            "cleanup-provenance",
            format!(
                "Inspection of this window, read {}. A size is not a reclaim figure unless it says \"private allocated\"; a move to Trash or a removal shows its observed change in History.",
                ago(snapshot.captured_at, now)
            ),
            tokens,
        ))
        .into_any_element()
}

/// The list of the targets of a plan: bounded, a focus stop, and the arrow
/// keys, Page Up, Page Down, Space, Home, and End scroll it.
fn target_list(
    proposal: &CleanupProposal,
    scroll: &ScrollHandle,
    focus: &FocusHandle,
    mono: &SharedString,
    tokens: &Tokens,
) -> AnyElement {
    let key_scroll: ScrollHandle = scroll.clone();
    let mut list = div()
        .id("confirm-targets")
        .role(Role::List)
        .test_support()
        .aria_label(format!(
            "{} bound targets. The arrow keys, Page Up, Page Down, Space, Home, and End scroll the list.",
            proposal.target_count
        ))
        .track_focus(focus)
        .track_scroll(scroll)
        .overflow_y_scroll()
        .max_h(px(TARGET_LIST_HEIGHT))
        .w_full()
        .rounded(tokens::INSET_RADIUS)
        .bg(to_hsla(tokens.inset_tint))
        .focus_visible(move |style| style.shadow(focus_ring(tokens)))
        .on_key_down(move |event, window, cx| {
            let offset = key_scroll.offset();
            let max: f32 = f32::from(key_scroll.max_offset().y);
            let page: f32 = (TARGET_LIST_HEIGHT - TARGET_ROW_STEP).max(TARGET_ROW_STEP);
            if let Some(y) = list_scroll(
                event.keystroke.key.as_str(),
                f32::from(offset.y),
                max,
                TARGET_ROW_STEP,
                page,
            ) {
                key_scroll.set_offset(point(offset.x, px(y)));
                window.refresh();
                cx.stop_propagation();
            }
        });
    for (index, target) in proposal.targets.iter().enumerate() {
        let estimate: String = target.estimate.map_or_else(
            || "estimate not known".to_owned(),
            |bytes| format!("about {}", bytes_label(bytes)),
        );
        list = list.child(
            h_flex()
                .id(SharedString::from(format!("confirm-target-{index}")))
                .role(Role::ListItem)
                .test_support()
                .aria_label(format!("{}: {estimate}", target.path))
                .px(tokens::SPACE_2)
                .py(tokens::SPACE_1)
                .gap(tokens::SPACE_2)
                .justify_between()
                .child(
                    div()
                        .min_w_0()
                        .font_family(mono.clone())
                        .text_size(px(12.0))
                        .child(target.path.clone()),
                )
                .child(
                    div()
                        .flex_none()
                        .font_family(mono.clone())
                        .text_size(px(12.0))
                        .text_color(to_hsla(tokens.muted_foreground))
                        .child(estimate),
                ),
        );
    }
    if proposal.target_count > proposal.targets.len() {
        list = list.child(
            div()
                .px(tokens::SPACE_2)
                .py(tokens::SPACE_1)
                .text_size(px(12.0))
                .text_color(to_hsla(tokens.muted_foreground))
                .child(format!(
                    "And {} more targets that the plan binds.",
                    proposal.target_count - proposal.targets.len()
                )),
        );
    }
    list.into_any_element()
}

/// The object sentence of a plan.
#[must_use]
pub fn plan_object(proposal: &CleanupProposal) -> String {
    let count: usize = proposal.target_count;
    let entries: &str = if count == 1 { "entry" } else { "entries" };
    match proposal.kind {
        PlanKind::Evict => format!(
            "The plan of {} binds {count} {entries}, each with the identity that the discovery read. The agent checks each entry again before it removes it, and leaves out an entry that changed.",
            proposal.rule
        ),
        PlanKind::Owner => format!(
            "The plan of {} binds one command of its producer on the scope below. The agent makes the command again from the rule and checks the executable and the scope before it starts it.",
            proposal.rule
        ),
    }
}

/// The label of the apply button of a plan.
#[must_use]
pub fn apply_label(proposal: &CleanupProposal) -> String {
    match proposal.kind {
        PlanKind::Evict => format!("Clear {}", proposal.rule),
        PlanKind::Owner => format!("Run the command of {}", proposal.rule),
    }
}

fn plan_body(
    proposal: &CleanupProposal,
    now: SystemTime,
    scroll: &ScrollHandle,
    focus: &FocusHandle,
    mono: &SharedString,
    tokens: &Tokens,
) -> AnyElement {
    let estimate: String = match proposal.estimate {
        Some(bytes) => format!(
            "Estimated: about {}. {}",
            bytes_label(bytes),
            proposal.estimate_statement
        ),
        None => format!("Estimated: not known. {}", proposal.estimate_statement),
    };
    let mut body = v_flex()
        .gap(tokens::SPACE_2)
        .child(body_line(
            "confirm-object",
            plan_object(proposal),
            false,
            tokens,
        ))
        .child(target_list(proposal, scroll, focus, mono, tokens))
        .child(caption("confirm-estimate", estimate, tokens));
    if let Some(owner) = &proposal.owner {
        let mut lines = v_flex().gap(tokens::SPACE_1).child(
            div()
                .id("confirm-command")
                .test_support()
                .aria_label(format!("Exact command ({}): {}", owner.kind, owner.command))
                .font_family(mono.clone())
                .text_size(px(12.0))
                .child(owner.command.clone()),
        );
        for entry in &owner.environment {
            lines = lines.child(
                div()
                    .font_family(mono.clone())
                    .text_size(px(11.0))
                    .text_color(to_hsla(tokens.muted_foreground))
                    .child(entry.clone()),
            );
        }
        body = body.child(inset(lines, tokens)).child(body_line(
            "confirm-effect",
            format!("Effect: {} {}", owner.effect, owner.consequence),
            false,
            tokens,
        ));
    }
    for (index, warning) in proposal.warnings.iter().enumerate() {
        body = body.child(
            div()
                .id(SharedString::from(format!("confirm-warning-{index}")))
                .test_support()
                .aria_label(format!("Warning: {warning}"))
                .text_size(px(13.0))
                .text_color(to_hsla(tokens.warning))
                .child(format!("Warning: {warning}")),
        );
    }
    if proposal.omitted_count > 0 {
        let mut omitted = v_flex().gap(tokens::SPACE_1);
        for (path, reason) in proposal.omitted.iter().take(8) {
            omitted = omitted.child(
                div()
                    .font_family(mono.clone())
                    .text_size(px(11.0))
                    .text_color(to_hsla(tokens.muted_foreground))
                    .child(format!("{path}  {reason}")),
            );
        }
        body = body
            .child(caption(
                "confirm-omitted",
                format!(
                    "Left out of the plan: {} entries. The agent does not touch them.",
                    proposal.omitted_count
                ),
                tokens,
            ))
            .child(omitted);
    }
    body.child(body_line(
        "confirm-consequence",
        if proposal.permanent {
            format!("Permanent deletion. {}", proposal.consequence)
        } else {
            proposal.consequence.clone()
        },
        false,
        tokens,
    ))
    .child(caption(
        "confirm-expiry",
        until(proposal.expires_at, now).map_or_else(
            || "The plan expires now.".to_owned(),
            |left| format!("The plan expires {left}."),
        ),
        tokens,
    ))
    .into_any_element()
}

fn cancel_button(model: Entity<AppModel>) -> AnyElement {
    ActionButton::new("confirm-cancel", "Cancel")
        .variant(ButtonVariant::Secondary)
        .fit()
        .on_click(move |_, window, cx| {
            model.update(cx, AppModel::close_cleanup);
            window.close_dialog(cx);
        })
        .into_any_element()
}

/// Opens the plan dialog of `rule` and makes its plan in the background.
/// The dialog shows the sealed plan; it sends nothing until the apply
/// button is pressed, and it removes that button when the plan expires.
/// While a plan dialog is open, it opens no second one.
pub fn open_cleanup(
    model: &Entity<AppModel>,
    rule: &str,
    kind: PlanKind,
    window: &mut Window,
    cx: &mut App,
) {
    let rule: String = rule.to_owned();
    if !model.update(cx, |model, cx| model.prepare_cleanup(&rule, kind, cx)) {
        return;
    }
    let model: Entity<AppModel> = model.clone();
    let scroll: ScrollHandle = ScrollHandle::new();
    let focus: FocusHandle = cx.focus_handle();
    window.open_dialog(cx, move |dialog: Dialog, _window, cx| {
        let tokens: &Tokens = Tokens::for_dark(cx.theme().is_dark());
        let mono: SharedString = cx.theme().mono_font_family.clone();
        let now: SystemTime = SystemTime::now();
        let close_model: Entity<AppModel> = model.clone();
        let dialog = dialog
            .title(format!("Plan of {rule}"))
            .overlay_closable(false)
            .close_button(false)
            .on_close(move |_, _, cx| {
                close_model.update(cx, AppModel::close_cleanup);
            });
        let draft: Option<CleanupDraft> = model
            .read(cx)
            .cleanup_book
            .dialog
            .as_ref()
            .filter(|(open, _)| *open == rule)
            .map(|(_, draft)| draft.clone());
        match draft {
            None | Some(CleanupDraft::Preparing) => dialog
                .child(body_line(
                    "confirm-preparing",
                    "Reading the rule and making the plan. Nothing is recorded yet.",
                    true,
                    tokens,
                ))
                .footer(footer(vec![cancel_button(model.clone())])),
            Some(CleanupDraft::Failed(state)) => dialog
                .child(action_status("confirm-failed", &state, tokens))
                .footer(footer(vec![cancel_button(model.clone())])),
            Some(CleanupDraft::Ready(proposal)) if !proposal.has_targets() => dialog
                .child(body_line(
                    "confirm-empty",
                    "No entry of this rule is a candidate now, so there is no plan to apply. Nothing was recorded.",
                    false,
                    tokens,
                ))
                .footer(footer(vec![cancel_button(model.clone())])),
            Some(CleanupDraft::Ready(proposal)) if proposal.expired(now) => {
                let again: Entity<AppModel> = model.clone();
                let rule: String = rule.clone();
                dialog
                    .child(body_line(
                        "confirm-expired",
                        "The plan expired, so it cannot be sent. Make a new plan from a new reading of the rule.",
                        false,
                        tokens,
                    ))
                    .footer(footer(vec![
                        cancel_button(model.clone()),
                        ActionButton::new("confirm-again", "Make a new plan")
                            .variant(ButtonVariant::Secondary)
                            .fit()
                            .on_click(move |_, _, cx| {
                                again.update(cx, |model, cx| model.renew_cleanup(&rule, kind, cx));
                            })
                            .into_any_element(),
                    ]))
            }
            Some(CleanupDraft::Ready(proposal)) => {
                let action = crate::actions::Action::Clean {
                    proposal: Arc::clone(&proposal),
                };
                let sender: Entity<AppModel> = model.clone();
                dialog
                    .child(plan_body(&proposal, now, &scroll, &focus, &mono, tokens))
                    .footer(footer(vec![
                        cancel_button(model.clone()),
                        ActionButton::new("confirm-ok", apply_label(&proposal))
                            .variant(ButtonVariant::Secondary)
                            .fit()
                            .on_click(move |_, window, cx| {
                                let action = action.clone();
                                sender.update(cx, |model, cx| model.run_action(action, cx));
                                window.close_dialog(cx);
                            })
                            .into_any_element(),
                    ]))
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::cleanup::SizeKind;

    #[test]
    fn a_size_says_what_it_is_and_an_unmeasured_unit_has_no_zero() {
        let mut unit = UnitRow {
            path: "/p".to_owned(),
            size: Some(1536),
            size_kind: SizeKind::WholeCache,
            partial: true,
            reason: None,
        };
        assert_eq!(
            unit_size(&unit),
            "1.5 KiB whole cache, not a reclaim figure, partial"
        );
        unit.size = None;
        assert_eq!(unit_size(&unit), "— not measured");
    }

    #[test]
    fn a_lifecycle_state_is_not_an_alarm() {
        assert_eq!(lifecycle_tone("proposed"), Tone::Neutral);
        assert_eq!(lifecycle_tone("manual_action_validated"), Tone::Brand);
    }
}
