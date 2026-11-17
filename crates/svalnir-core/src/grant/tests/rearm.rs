//! Tests of the budget generation of an incident and of its rearm.

use super::super::{
    Acceptance, GenerationBasis, IncidentBudget, IncidentCondition, IncidentUsage,
    InstanceInhibition, MAX_BUDGET_GENERATIONS, RearmRefusal, RearmRequest, rearm,
};
use super::{
    USER, active_state, clock, config, enabled, enabled_state, incident_id, monotonic, wall,
};
use crate::authority::Generation;
use crate::id::{BootId, ClockDomainId, IncidentId};
use crate::policy::{Cooldown, CooldownCause, PolicyId, WorkUsage};
use crate::process::Uid;
use crate::quantity::{Bytes, EntryCount};

const DISK: PolicyId = PolicyId::DiskGuard;
const MEMORY: PolicyId = PolicyId::MemoryGuard;

fn memory_budget() -> IncidentBudget {
    IncidentBudget::open(
        incident_id(),
        MEMORY,
        &enabled_state(),
        &InstanceInhibition::default(),
        wall(50),
    )
}

fn memory_usage(consumed: u32, reserved: u32) -> IncidentUsage {
    IncidentUsage::Memory {
        consumed_slots: consumed,
        reserved_slots: reserved,
    }
}

fn settled(usage: IncidentUsage) -> IncidentCondition<'static> {
    IncidentCondition {
        usage,
        outstanding_operation: false,
        unknown_outcome: false,
        cooldowns: &[],
    }
}

fn request(generation: u64) -> RearmRequest {
    RearmRequest {
        principal: USER,
        policy: MEMORY,
        incident_id: incident_id(),
        generation: Generation::new(generation),
    }
}

fn cooldown(cause: CooldownCause, until: u64) -> Cooldown {
    Cooldown {
        cause,
        until: monotonic(until),
        clock_domain: ClockDomainId::new("clock_main").unwrap(),
        boot_id: BootId::new("boot_1").unwrap(),
    }
}

#[test]
fn an_incident_opens_with_the_first_budget_generation() {
    let budget = memory_budget();
    assert_eq!(budget.generation, Generation::new(1));
    assert_eq!(budget.policy, MEMORY);
    assert_eq!(budget.history.len(), 1);
    let first = &budget.history[0];
    assert_eq!(first.generation, Generation::new(1));
    assert_eq!(first.basis, GenerationBasis::IncidentOpened);
    assert_eq!(first.authorized_by, None);
    assert_eq!(first.started_at, wall(50));
    assert_eq!(first.final_usage, None);
    // The base configuration has no critical-memory exception.
    assert!(!budget.volatile_exception_at_open);
    let json = serde_json::to_string(&budget).unwrap();
    assert_eq!(
        serde_json::from_str::<IncidentBudget>(&json).unwrap(),
        budget
    );
}

#[test]
fn the_critical_memory_exception_is_recorded_only_when_it_is_in_effect_at_the_open() {
    let volatile = config(&[(
        "allow_volatile_journal_on_critical = false",
        "allow_volatile_journal_on_critical = true",
    )]);
    let none = InstanceInhibition::default();
    let open = |state, policy| {
        IncidentBudget::open(incident_id(), policy, state, &none, wall(50))
            .volatile_exception_at_open
    };
    // Configured, and no enabled guard.
    let state = active_state(&volatile);
    assert!(!open(&state, MEMORY));
    // Configured and granted.
    let granted = enabled(&state, MEMORY, &[Acceptance::ForceQuit]);
    assert!(open(&granted, MEMORY));
    // A disk incident never has the exception.
    let both = enabled(&granted, DISK, &[Acceptance::PermanentEviction]);
    assert!(!open(&both, DISK));
    // Granted for an earlier revision, and not configured now.
    assert!(!open(&enabled_state(), MEMORY));
}

#[test]
fn a_rearm_with_the_current_generation_records_a_new_generation() {
    let state = enabled_state();
    let budget = memory_budget();
    let usage = memory_usage(3, 0);
    let at = clock(600);
    let result = rearm(
        &state,
        &budget,
        &settled(usage),
        &request(1),
        &at,
        wall(600),
    )
    .unwrap();
    assert_eq!(result.previous_generation, Generation::new(1));
    assert_eq!(result.new_generation, Generation::new(2));
    assert_eq!(result.retained_usage, usage);
    assert_eq!(result.cooldowns_in_force, []);
    let next = &result.budget;
    assert_eq!(next.generation, Generation::new(2));
    assert_eq!(next.incident_id, budget.incident_id);
    assert_eq!(
        next.volatile_exception_at_open,
        budget.volatile_exception_at_open
    );
    // The history keeps the usage of the generation that ended.
    assert_eq!(next.history.len(), 2);
    assert_eq!(next.history[0].final_usage, Some(usage));
    assert_eq!(next.history[0].started_at, wall(50));
    let second = &next.history[1];
    assert_eq!(second.generation, Generation::new(2));
    assert_eq!(second.basis, GenerationBasis::Rearmed);
    assert_eq!(second.authorized_by, Some(USER));
    assert_eq!(second.started_at, wall(600));
    assert_eq!(second.final_usage, None);
    // The rearm does not change the authority record.
    assert_eq!(state, enabled_state());

    // A second rearm keeps the two earlier entries.
    let later = rearm(
        &state,
        next,
        &settled(memory_usage(2, 0)),
        &request(2),
        &at,
        wall(700),
    )
    .unwrap();
    assert_eq!(later.budget.history.len(), 3);
    assert_eq!(later.budget.history[0], next.history[0]);
    assert_eq!(
        later.budget.history[1].final_usage,
        Some(memory_usage(2, 0))
    );
}

#[test]
fn a_rearm_with_a_stale_generation_is_a_conflict() {
    let state = enabled_state();
    let budget = memory_budget();
    let at = clock(600);
    let condition = settled(memory_usage(3, 0));
    let first = rearm(&state, &budget, &condition, &request(1), &at, wall(600)).unwrap();
    // The same request again: one generation gives one rearm.
    assert_eq!(
        rearm(
            &state,
            &first.budget,
            &condition,
            &request(1),
            &at,
            wall(601)
        ),
        Err(RearmRefusal::GenerationConflict {
            requested: Generation::new(1),
            current: Generation::new(2),
        })
    );
    // A generation that does not exist yet.
    assert_eq!(
        rearm(&state, &budget, &condition, &request(2), &at, wall(600)),
        Err(RearmRefusal::GenerationConflict {
            requested: Generation::new(2),
            current: Generation::new(1),
        })
    );
}

#[test]
fn a_rearm_does_not_end_a_cooldown() {
    let state = enabled_state();
    let budget = memory_budget();
    let at = clock(600);
    let active = cooldown(CooldownCause::ApplicationRelaunch, 900);
    let elapsed = cooldown(CooldownCause::PassPacing, 500);
    let other_boot = Cooldown {
        boot_id: BootId::new("boot_0").unwrap(),
        ..cooldown(CooldownCause::NoEffectBackoff, 100)
    };
    let cooldowns = [active.clone(), elapsed, other_boot.clone()];
    let condition = IncidentCondition {
        cooldowns: &cooldowns,
        ..settled(memory_usage(3, 0))
    };
    let result = rearm(&state, &budget, &condition, &request(1), &at, wall(600)).unwrap();
    assert_eq!(result.new_generation, Generation::new(2));
    // The cooldown that is not complete, and the one whose end is not
    // known, stay in force with the values that the caller gave.
    assert_eq!(result.cooldowns_in_force, [active, other_boot]);
}

#[test]
fn a_rearm_is_refused_while_an_effect_is_not_resolved() {
    let state = enabled_state();
    let budget = memory_budget();
    let at = clock(600);
    let refused = |condition: &IncidentCondition<'_>| {
        rearm(&state, &budget, condition, &request(1), &at, wall(600)).unwrap_err()
    };
    let unsettled = IncidentCondition {
        outstanding_operation: true,
        ..settled(memory_usage(1, 0))
    };
    assert_eq!(refused(&unsettled), RearmRefusal::OperationUnsettled);
    // A reservation is a dispatch that is not resolved.
    assert_eq!(
        refused(&settled(memory_usage(1, 1))),
        RearmRefusal::OperationUnsettled
    );
    let unknown = IncidentCondition {
        unknown_outcome: true,
        ..settled(memory_usage(1, 0))
    };
    assert_eq!(refused(&unknown), RearmRefusal::UnknownOutcome);
    // The unknown outcome is the reason also when the operation is not
    // settled.
    let both = IncidentCondition {
        outstanding_operation: true,
        ..unknown
    };
    assert_eq!(refused(&both), RearmRefusal::UnknownOutcome);
}

#[test]
fn a_rearm_request_is_checked_against_the_record() {
    let state = enabled_state();
    let budget = memory_budget();
    let at = clock(600);
    let condition = settled(memory_usage(3, 0));
    let refused = |request: &RearmRequest| {
        rearm(&state, &budget, &condition, request, &at, wall(600)).unwrap_err()
    };
    let other_user = RearmRequest {
        principal: Uid::new(502),
        ..request(1)
    };
    assert_eq!(refused(&other_user), RearmRefusal::WrongPrincipal);
    let other_incident = RearmRequest {
        incident_id: IncidentId::new("incident_2").unwrap(),
        ..request(1)
    };
    assert_eq!(refused(&other_incident), RearmRefusal::UnknownIncident);
    let other_guard = RearmRequest {
        policy: DISK,
        ..request(1)
    };
    assert_eq!(refused(&other_guard), RearmRefusal::UnknownIncident);
    // The usage of the other guard.
    let disk_usage = IncidentUsage::Disk {
        usage: WorkUsage::default(),
        passes_started: 1,
    };
    assert_eq!(
        rearm(
            &state,
            &budget,
            &settled(disk_usage),
            &request(1),
            &at,
            wall(600)
        ),
        Err(RearmRefusal::UsageMismatch)
    );
    // A record whose last entry is not the current generation.
    let mut broken = budget.clone();
    broken.history[0].generation = Generation::new(7);
    assert_eq!(
        rearm(&state, &broken, &condition, &request(1), &at, wall(600)),
        Err(RearmRefusal::RecordNotUsable)
    );
    let mut exhausted = budget;
    exhausted.generation = Generation::MAX;
    let last = RearmRequest {
        generation: Generation::MAX,
        ..request(1)
    };
    assert_eq!(
        rearm(&state, &exhausted, &condition, &last, &at, wall(600)),
        Err(RearmRefusal::RecordNotUsable)
    );
}

#[test]
fn a_disk_incident_keeps_its_work_usage() {
    let state = enabled_state();
    let budget = IncidentBudget::open(
        incident_id(),
        DISK,
        &state,
        &InstanceInhibition::default(),
        wall(50),
    );
    let usage = IncidentUsage::Disk {
        usage: WorkUsage {
            consumed_bytes: Bytes::new(1 << 30),
            reserved_bytes: Bytes::ZERO,
            consumed_items: EntryCount::new(400),
            reserved_items: EntryCount::ZERO,
        },
        passes_started: 2,
    };
    let disk_request = RearmRequest {
        policy: DISK,
        ..request(1)
    };
    let at = clock(600);
    let result = rearm(
        &state,
        &budget,
        &settled(usage),
        &disk_request,
        &at,
        wall(600),
    )
    .unwrap();
    assert_eq!(result.budget.history[0].final_usage, Some(usage));
    // A reserved entry is a dispatch that is not resolved.
    let reserved = IncidentUsage::Disk {
        usage: WorkUsage {
            reserved_items: EntryCount::new(1),
            ..WorkUsage::default()
        },
        passes_started: 1,
    };
    assert_eq!(
        rearm(
            &state,
            &budget,
            &settled(reserved),
            &disk_request,
            &at,
            wall(600)
        ),
        Err(RearmRefusal::OperationUnsettled)
    );
}

#[test]
fn the_history_of_an_incident_is_bounded_and_never_shortened() {
    let state = enabled_state();
    let at = clock(600);
    let condition = settled(memory_usage(1, 0));
    let mut budget = memory_budget();
    for generation in 1..MAX_BUDGET_GENERATIONS {
        let generation = u64::try_from(generation).unwrap();
        budget = rearm(
            &state,
            &budget,
            &condition,
            &request(generation),
            &at,
            wall(600),
        )
        .unwrap()
        .budget;
    }
    assert_eq!(budget.history.len(), MAX_BUDGET_GENERATIONS);
    let last = u64::try_from(MAX_BUDGET_GENERATIONS).unwrap();
    assert_eq!(
        rearm(&state, &budget, &condition, &request(last), &at, wall(600)),
        Err(RearmRefusal::HistoryFull)
    );
    // Each earlier generation has its usage.
    assert!(
        budget.history[..MAX_BUDGET_GENERATIONS - 1]
            .iter()
            .all(|record| record.final_usage == Some(memory_usage(1, 0)))
    );
}
