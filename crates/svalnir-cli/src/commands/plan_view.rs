//! The text form of a plan explanation, for `clean plan`, `clean show`,
//! the approval question of `clean apply`, and `processes stop`.

use serde::Serialize;
use svalnir_core::file::LosslessPath;
use svalnir_core::plan::{PlanExplanation, TargetExplanation};

use crate::text::{escape, human_bytes, human_duration, put_line};

/// The largest number of lines of one list in the text form.
pub(crate) const TEXT_LIST_LIMIT: usize = 40;

/// The serialized name of a plain enumeration value.
pub(crate) fn wire<T: Serialize>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(text)) => escape(&text),
        Ok(other) => escape(&other.to_string()),
        Err(_) => "unknown".to_owned(),
    }
}

/// The stable name of the reason that an entry was left out.
pub(crate) fn wire_reason(reason: svalnir_core::plan::OmissionReason) -> String {
    match serde_json::to_value(reason) {
        Ok(value) => value
            .get("reason")
            .and_then(serde_json::Value::as_str)
            .map_or_else(|| "unknown".to_owned(), escape),
        Err(_) => "unknown".to_owned(),
    }
}

/// The text of a plan mode, for example `cleanup: permanent`.
pub(crate) fn mode_text(mode: svalnir_core::plan::PlanMode) -> String {
    match serde_json::to_value(mode) {
        Ok(value) => format!(
            "{}: {}",
            value
                .get("kind")
                .and_then(serde_json::Value::as_str)
                .map_or_else(|| "unknown".to_owned(), escape),
            value
                .get("mode")
                .and_then(serde_json::Value::as_str)
                .map_or_else(|| "unknown".to_owned(), escape),
        ),
        Err(_) => "unknown".to_owned(),
    }
}

fn optional_bytes(bytes: Option<svalnir_core::quantity::Bytes>) -> String {
    bytes.map_or_else(|| "not known".to_owned(), |bytes| human_bytes(bytes.get()))
}

fn render_summary(explanation: &PlanExplanation, out: &mut String) {
    if let Some(plan) = &explanation.plan {
        put_line!(out, "Plan {}", plan.plan_id);
        put_line!(out, "  Digest: {}", escape(plan.digest.as_str()));
        put_line!(out, "  Mode: {}", mode_text(explanation.mode));
        put_line!(
            out,
            "  Policy revision: {}",
            plan.revisions.authority.policy_revision
        );
        let expiry: String = if plan.expiry.expired {
            "expired; prepare a new plan".to_owned()
        } else {
            plan.expiry.remaining.map_or_else(
                || "not known".to_owned(),
                |remaining| format!("valid for {} more", human_duration(remaining)),
            )
        };
        put_line!(out, "  Expiry: {expiry}");
    } else {
        put_line!(out, "No plan: no entry is in the plan");
        put_line!(out, "  Mode: {}", mode_text(explanation.mode));
    }
    put_line!(out, "  Consequence: {}", explanation.consequence_statement);
    put_line!(
        out,
        "  Counts as reclaimed capacity: {}",
        if explanation.counts_as_reclaimed_capacity {
            "an observed capacity change is reported separately; the estimates are not a promise"
        } else {
            "no"
        }
    );
    put_line!(
        out,
        "  Targets: {}   Estimated logical size: {}   Estimated reclaimable: {}",
        explanation.totals.targets,
        optional_bytes(explanation.totals.estimated_logical_bytes),
        optional_bytes(explanation.totals.estimated_reclaimable_bytes),
    );
}

fn render_target(target: &TargetExplanation, out: &mut String) {
    match target {
        TargetExplanation::File {
            target_id,
            path,
            object_type,
            estimate,
            ..
        } => put_line!(
            out,
            "  {}  {}  {}",
            wire(object_type),
            optional_bytes(estimate.logical_bytes),
            path.as_ref()
                .map_or_else(|| target_id.to_string(), LosslessPath::display_label),
        ),
        TargetExplanation::Application {
            instance_id,
            members,
            ..
        } => {
            put_line!(out, "  application instance {instance_id}");
            for member in members {
                put_line!(
                    out,
                    "    {}  pid {}  {}",
                    member.generation_id,
                    member.pid.get(),
                    member.executable.as_ref().map_or_else(
                        || "no executable evidence".to_owned(),
                        LosslessPath::display_label
                    ),
                );
            }
        }
    }
}

/// Renders the scope and the consequence of a plan.
pub(crate) fn render(explanation: &PlanExplanation, out: &mut String) {
    render_summary(explanation, out);
    if !explanation.targets.is_empty() {
        out.push_str("\nTargets\n");
    }
    for target in explanation.targets.iter().take(TEXT_LIST_LIMIT) {
        render_target(target, out);
    }
    if explanation.targets.len() > TEXT_LIST_LIMIT {
        put_line!(
            out,
            "  ... and {} more; `--format json` has each target",
            explanation.targets.len() - TEXT_LIST_LIMIT
        );
    }
    if !explanation.omitted.is_empty() {
        put_line!(out, "\nLeft out ({} entries)", explanation.omitted.len());
    }
    for omission in explanation.omitted.iter().take(TEXT_LIST_LIMIT) {
        let reasons: Vec<String> = omission.reasons.iter().copied().map(wire_reason).collect();
        put_line!(
            out,
            "  {}  {}",
            reasons.join(", "),
            omission.path.as_ref().map_or_else(
                || omission.target_id.to_string(),
                LosslessPath::display_label
            ),
        );
    }
    if explanation.omitted.len() > TEXT_LIST_LIMIT {
        out.push_str("  ...\n");
    }
    put_line!(out, "\n{}", explanation.estimate_statement);
}
