//! The manual cleanup of one reviewed rule: the inspection of each rule,
//! the options of a plan, the sealed plan that the confirmation shows, and
//! the open plan dialog.
//!
//! The client makes a plan and shows it; nothing is recorded until the
//! user confirms it. The confirmed plan goes to the agent through the queue
//! of the journal, as a stop does ([`super::Action::Clean`]). A released
//! build has each rule in the lifecycle state `proposed`, so each plan is
//! refused with `rule_mode_not_validated` before a directory is read.

use super::ActionState;
use std::{collections::HashMap, sync::Arc, time::SystemTime};
use svalnir_core::action::Plan;

/// The most units of one rule that an inspection keeps for the view.
pub const UNIT_LIMIT: usize = 32;

/// The most targets and left-out entries that a proposal keeps for the
/// view. The sealed plan binds each target; the view names how many more
/// there are.
pub const TARGET_LIMIT: usize = 200;

/// The minimum sizes that the `min-size` option offers, in bytes. `None`
/// is no minimum.
pub const MIN_SIZES: [(Option<u64>, &str); 3] = [
    (None, "Any size"),
    (Some(100 * 1024 * 1024), "100 MiB or more"),
    (Some(1024 * 1024 * 1024), "1 GiB or more"),
];

/// The family of a rule, for the label of its row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleFamily {
    /// A dependency directory of a project.
    Project,
    /// A package or build cache of a producer.
    Cache,
    /// The owner operation of a producer: its own cleanup command.
    Owner,
    /// A clear rule: the contents of a cache directory of a producer that
    /// has no safe cleanup command.
    Clear,
    /// A linked Git worktree.
    Worktree,
    /// The derived data of Xcode.
    Xcode,
}

impl RuleFamily {
    /// The label of the family.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Project => "Project",
            Self::Cache => "Cache",
            Self::Owner => "Owner command",
            Self::Clear => "Clear cache",
            Self::Worktree => "Worktree",
            Self::Xcode => "Xcode",
        }
    }
}

/// The plan that a rule offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanKind {
    /// The permanent eviction of the candidates of the rule
    /// (`clean plan --mode evict`).
    Evict,
    /// The fixed command of the producer on its measured scope
    /// (`clean plan --mode owner`).
    Owner,
}

impl PlanKind {
    /// The mode name of the CLI.
    #[must_use]
    pub const fn mode(self) -> &'static str {
        match self {
            Self::Evict => "evict",
            Self::Owner => "owner",
        }
    }
}

/// One root of an inspection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootRow {
    /// The path, or the text that says that it is not resolved.
    pub path: String,
    /// The result: `examined`, `absent`, or the reason of a refusal.
    pub state: String,
}

/// The kind of the size of a unit. No size is a reclaim figure unless it
/// says so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SizeKind {
    /// The allocated bytes that no file outside the unit shares.
    PrivateAllocated,
    /// The allocated bytes, an upper estimate: clones and snapshots can
    /// share them.
    AllocatedUpperBound,
    /// The allocated bytes. The rule gives no reclaim figure: the data can
    /// share blocks with projects or with clones.
    AllocatedNotReclaim,
    /// The allocated bytes of the whole cache, of which the producer
    /// removes only a part.
    WholeCache,
}

impl SizeKind {
    /// The caption after the size.
    #[must_use]
    pub const fn caption(self) -> &'static str {
        match self {
            Self::PrivateAllocated => "private allocated",
            Self::AllocatedUpperBound => "allocated, upper estimate",
            Self::AllocatedNotReclaim => "allocated, not a reclaim figure",
            Self::WholeCache => "whole cache, not a reclaim figure",
        }
    }
}

/// One unit of an inspection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitRow {
    /// The path of the unit.
    pub path: String,
    /// The measured size, when the unit was measured.
    pub size: Option<u64>,
    /// What the size is.
    pub size_kind: SizeKind,
    /// Whether the measurement is not complete.
    pub partial: bool,
    /// Why the unit is not a candidate now, as the stable names of the
    /// rule. `None` when the inspection found no reason.
    pub reason: Option<String>,
}

/// The owner command of a rule: the facts of its inspection or of its
/// sealed plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerFacts {
    /// `prune` or `clear`.
    pub kind: String,
    /// The exact command: the executable and its arguments.
    pub command: String,
    /// The only entries of the environment of the command, `NAME=value`.
    pub environment: Vec<String>,
    /// The expected effect statement of the rule.
    pub effect: String,
    /// The consequence of the command.
    pub consequence: String,
    /// The scope root.
    pub scope: String,
}

/// The inspection of one rule. The inspection makes no plan and removes
/// nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleInspection {
    /// The rule identity.
    pub rule: String,
    /// The rule revision.
    pub revision: String,
    /// The family of the rule.
    pub family: RuleFamily,
    /// The producer.
    pub producer: String,
    /// The lifecycle state of the layouts of the rule, for example
    /// `proposed`.
    pub lifecycle: String,
    /// Each layout of the rule with its lifecycle state.
    pub layouts: Vec<(String, String)>,
    /// The plan that the rule offers. `None`: inspection only.
    pub plan: Option<PlanKind>,
    /// Whether the lifecycle state permits the manual plan of the rule.
    pub permits_plan: bool,
    /// Whether a plan needs the explicit consent to a `clear` command.
    pub needs_clear: bool,
    /// Whether the plan takes the project options: include the active
    /// projects, and the minimum size.
    pub project_options: bool,
    /// The roots of the inspection.
    pub roots: Vec<RootRow>,
    /// The units, at most [`UNIT_LIMIT`].
    pub units: Vec<UnitRow>,
    /// The number of units that are not in `units`.
    pub units_omitted: usize,
    /// The owner command, for a rule that has one.
    pub owner: Option<OwnerFacts>,
    /// Facts of the rule for the user, for example what a clear rule
    /// keeps.
    pub notes: Vec<String>,
    /// Why the inspection is not complete or did not run.
    pub problem: Option<String>,
}

/// The inspections of the rules of this build, and when they were read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupSnapshot {
    /// One inspection for each rule, in the order of the registry.
    pub rules: Vec<RuleInspection>,
    /// The wall-clock time of the read.
    pub captured_at: SystemTime,
}

/// The options of the plan of one rule.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CleanupOptions {
    /// Also select the units of a project whose activity state is
    /// `active` (`--include-active`). A busy project is never selected.
    pub include_active: bool,
    /// Leave out each candidate whose estimate is smaller (`--min-size`).
    pub min_size: Option<u64>,
    /// The consent to a `clear` command (`--include-clear`).
    pub include_clear: bool,
}

/// The request of a plan for one rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupRequest {
    /// The rule.
    pub rule: String,
    /// The plan of the rule.
    pub kind: PlanKind,
    /// The options.
    pub options: CleanupOptions,
}

/// Why the control that makes a plan is off, as one sentence. `None`: the
/// control is on. The agent and the plan builder check each condition
/// again; this is the explanation of the control, not the authorization.
#[must_use]
pub fn plan_gate(inspection: &RuleInspection, options: &CleanupOptions) -> Option<&'static str> {
    if inspection.plan.is_none() {
        return Some(
            "This rule has the inspection mode only in this build, so it has no plan here.",
        );
    }
    if inspection.needs_clear && !options.include_clear {
        return Some(
            "This rule clears a cache, also data that a project uses now. Check the consent above to make a plan.",
        );
    }
    None
}

/// One target of a proposal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupTarget {
    /// The path that the sealed plan binds.
    pub path: String,
    /// The estimate of reclaimable bytes, when the plan has one.
    pub estimate: Option<u64>,
}

/// The sealed plan of one rule, made from one discovery, with what the
/// confirmation shows. Nothing is recorded until the user confirms it.
#[derive(Debug, Clone)]
pub struct CleanupProposal {
    /// The rule.
    pub rule: String,
    /// The plan of the rule.
    pub kind: PlanKind,
    /// The plan identity, when a plan was made.
    pub plan_id: Option<String>,
    /// The targets, at most [`TARGET_LIMIT`].
    pub targets: Vec<CleanupTarget>,
    /// The number of targets of the plan.
    pub target_count: usize,
    /// The estimated reclaimable bytes of the plan, when known.
    pub estimate: Option<u64>,
    /// The statement of the plan builder about the estimate.
    pub estimate_statement: String,
    /// The entries that the plan leaves out, with the reasons, at most
    /// [`TARGET_LIMIT`].
    pub omitted: Vec<(String, String)>,
    /// The number of entries that the plan leaves out.
    pub omitted_count: usize,
    /// The warnings, for example that a unit holds a Git repository.
    pub warnings: Vec<String>,
    /// The owner command that the plan binds.
    pub owner: Option<OwnerFacts>,
    /// The consequence statement of the plan builder.
    pub consequence: String,
    /// Whether the plan removes data permanently.
    pub permanent: bool,
    /// Whether the plan clears a cache: it also removes data that a
    /// project uses now, with the consent of the user.
    pub clear: bool,
    /// The wall-clock time at which the plan expires.
    pub expires_at: SystemTime,
    /// The sealed plan. `None` for a fixture, and for a plan with no
    /// target.
    pub plan: Option<Arc<Plan>>,
}

impl CleanupProposal {
    /// Whether the plan expired at `now`.
    #[must_use]
    pub fn expired(&self, now: SystemTime) -> bool {
        now >= self.expires_at
    }

    /// Whether the plan has a target, so that it can be applied.
    #[must_use]
    pub const fn has_targets(&self) -> bool {
        self.target_count > 0
    }
}

/// The plan of the dialog that is open.
#[derive(Debug, Clone)]
pub enum CleanupDraft {
    /// The client reads the rule and makes the plan.
    Preparing,
    /// The plan is ready for the confirmation.
    Ready(Arc<CleanupProposal>),
    /// No plan was made.
    Failed(ActionState),
}

/// The options of each rule, and the plan dialog that is open.
#[derive(Debug, Default)]
pub struct CleanupBook {
    options: HashMap<String, CleanupOptions>,
    /// The plan dialog: the rule and its plan.
    pub dialog: Option<(String, CleanupDraft)>,
    /// The number of the latest preparation. A result of an earlier
    /// preparation is not kept.
    request: u64,
}

impl CleanupBook {
    /// The options of `rule`.
    #[must_use]
    pub fn options(&self, rule: &str) -> CleanupOptions {
        self.options.get(rule).copied().unwrap_or_default()
    }

    /// Sets the options of `rule`.
    pub fn set_options(&mut self, rule: &str, options: CleanupOptions) {
        self.options.insert(rule.to_owned(), options);
    }

    /// Opens the plan dialog of `rule` with a plan that is being made, and
    /// gives the number of this preparation. Gives `None` and changes
    /// nothing while a plan dialog is open: the window has at most one
    /// plan confirmation.
    pub fn open(&mut self, rule: &str) -> Option<u64> {
        if self.dialog.is_some() {
            return None;
        }
        self.request = self.request.wrapping_add(1);
        self.dialog = Some((rule.to_owned(), CleanupDraft::Preparing));
        Some(self.request)
    }

    /// Makes a new plan in the open dialog of `rule`. Gives `None` when no
    /// dialog of `rule` is open.
    pub fn renew(&mut self, rule: &str) -> Option<u64> {
        match &mut self.dialog {
            Some((open, draft)) if open == rule => {
                *draft = CleanupDraft::Preparing;
                self.request = self.request.wrapping_add(1);
                Some(self.request)
            }
            _ => None,
        }
    }

    /// The rule whose plan dialog is open.
    #[must_use]
    pub fn open_rule(&self) -> Option<&str> {
        self.dialog.as_ref().map(|(rule, _)| rule.as_str())
    }

    /// Records the plan of the preparation `request`. Returns `false` and
    /// keeps nothing when the dialog closed or a later preparation started.
    pub fn finish(&mut self, request: u64, draft: CleanupDraft) -> bool {
        if request != self.request {
            return false;
        }
        match &mut self.dialog {
            Some((_, open)) => {
                *open = draft;
                true
            }
            None => false,
        }
    }

    /// Closes the plan dialog. A preparation that runs keeps no result.
    pub fn close(&mut self) {
        self.request = self.request.wrapping_add(1);
        self.dialog = None;
    }
}

/// The text of a byte count with a binary unit, for example "1.5 GiB".
#[must_use]
pub fn bytes_label(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["bytes", "KiB", "MiB", "GiB", "TiB"];
    let mut value: u64 = bytes;
    let mut rest: u64 = 0;
    let mut unit: usize = 0;
    while value >= 1024 && unit + 1 < UNITS.len() {
        rest = value % 1024;
        value /= 1024;
        unit += 1;
    }
    if unit == 0 {
        return format!("{bytes} bytes");
    }
    // One decimal, rounded down, so that a size is never shown larger
    // than it is.
    let tenth: u64 = rest * 10 / 1024;
    format!("{value}.{tenth} {}", UNITS[unit])
}

/// The snake-case name of a `Debug` name such as `ActiveProducer`.
#[must_use]
pub fn snake_name(debug: &str) -> String {
    let head: &str = debug.split([' ', '{', '(']).next().unwrap_or(debug);
    let mut out: String = String::with_capacity(head.len() + 4);
    for (index, character) in head.chars().enumerate() {
        if character.is_ascii_uppercase() {
            if index > 0 {
                out.push('_');
            }
            out.push(character.to_ascii_lowercase());
        } else {
            out.push(character);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inspection(plan: Option<PlanKind>, needs_clear: bool) -> RuleInspection {
        RuleInspection {
            rule: "go.build-cache".to_owned(),
            revision: "1".to_owned(),
            family: RuleFamily::Owner,
            producer: "go".to_owned(),
            lifecycle: "proposed".to_owned(),
            layouts: Vec::new(),
            plan,
            permits_plan: false,
            needs_clear,
            project_options: false,
            roots: Vec::new(),
            units: Vec::new(),
            units_omitted: 0,
            owner: None,
            notes: Vec::new(),
            problem: None,
        }
    }

    #[test]
    fn a_clear_rule_needs_the_consent_before_a_plan() {
        let rule = inspection(Some(PlanKind::Owner), true);
        let mut options = CleanupOptions::default();
        assert!(plan_gate(&rule, &options).is_some_and(|reason| reason.contains("consent")));
        options.include_clear = true;
        assert_eq!(plan_gate(&rule, &options), None);
    }

    #[test]
    fn an_inspection_only_rule_has_no_plan() {
        let rule = inspection(None, false);
        assert!(plan_gate(&rule, &CleanupOptions::default()).is_some());
    }

    #[test]
    fn a_proposed_rule_still_offers_its_plan_so_the_refusal_names_the_code() {
        // The lifecycle check is the decision of the plan builder and of the
        // agent; the control only explains, so it stays on.
        let rule = inspection(Some(PlanKind::Evict), false);
        assert_eq!(plan_gate(&rule, &CleanupOptions::default()), None);
    }

    #[test]
    fn the_window_has_at_most_one_plan_dialog() {
        let mut book = CleanupBook::default();
        let first = book.open("a").expect("opens");
        assert_eq!(book.open("b"), None);
        assert_eq!(book.open_rule(), Some("a"));
        let second = book.renew("a").expect("renews");
        assert!(!book.finish(first, CleanupDraft::Preparing));
        assert!(book.finish(second, CleanupDraft::Preparing));
        book.close();
        assert!(!book.finish(second, CleanupDraft::Preparing));
        assert_eq!(book.open_rule(), None);
    }

    #[test]
    fn the_options_are_kept_for_each_rule() {
        let mut book = CleanupBook::default();
        let options = CleanupOptions {
            include_active: true,
            min_size: Some(1),
            include_clear: false,
        };
        book.set_options("a", options);
        assert_eq!(book.options("a"), options);
        assert_eq!(book.options("b"), CleanupOptions::default());
    }

    #[test]
    fn a_size_is_never_shown_larger_than_it_is() {
        assert_eq!(bytes_label(512), "512 bytes");
        assert_eq!(bytes_label(1536), "1.5 KiB");
        assert_eq!(bytes_label(1024 * 1024 - 1), "1023.9 KiB");
        assert_eq!(bytes_label(3 * 1024 * 1024 * 1024), "3.0 GiB");
    }

    #[test]
    fn a_debug_name_becomes_the_stable_name() {
        assert_eq!(snake_name("ActiveProducer"), "active_producer");
        assert_eq!(
            snake_name("EligibilityNotSatisfied { predicate: X }"),
            "eligibility_not_satisfied"
        );
    }
}
