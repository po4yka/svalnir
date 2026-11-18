//! Budget reservations, incident allowances, cooldowns, and leases.
//!
//! `docs/ACTION_CONTRACTS.md` section 5 and `docs/POLICY_SPEC.md` sections
//! 11 and 14 own the rules. The ledger is in memory and belongs to one
//! executor lifetime. It never gives an incident more allowance than the
//! journal and the earlier calls show: a counter of consumed work only
//! increases, a restart reads the usage row of the incident in the
//! journal, and a restart that possibly lost volatile counts starts with
//! the slots of the incident exhausted.

use std::collections::BTreeMap;

use svalnir_core::action::{
    BudgetError, BudgetScope, ErrorFamily, LeaseResource, ResourceLease, ScopedAllowance,
    SlotAllowance, WorkAllowance, WorkBudget, WorkCharge,
};
use svalnir_core::authority::Generation;
use svalnir_core::id::{ExecutorEpochId, IncidentId, OperationId};
use svalnir_core::quantity::{ByteDelta, Bytes, Nanoseconds};
use svalnir_core::time::MonotonicNanos;

use super::error::code;
use super::ports::IdSource;

/// The largest number of incidents that the ledger keeps.
pub const MAX_INCIDENTS: usize = 64;

/// The largest number of leases that the ledger holds.
pub const MAX_LEASES: usize = 8192;

/// The largest exponent of the backoff: the cooldown is at most the base
/// cooldown times two to this power, and at most the stated maximum.
const MAX_BACKOFF_LEVEL: u32 = 16;

/// The pacing of an incident after an action with a low benefit or a
/// failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pacing {
    /// The cooldown after the first such action.
    pub cooldown: Nanoseconds,
    /// The largest cooldown. Each consecutive such action doubles the
    /// cooldown to this maximum.
    pub max_cooldown: Nanoseconds,
    /// The smallest observed capacity gain that counts as a benefit of a
    /// filesystem operation. An unavailable measurement is not a benefit.
    pub min_capacity_gain: Bytes,
}

/// The allowance of one incident, as the policy module computed it. The
/// controller gives it with an automatic apply request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncidentAllowance {
    /// The incident.
    pub incident_id: IncidentId,
    /// The budget generation. A rearm gives a larger generation.
    pub generation: Generation,
    /// The executor lifetime in which this budget generation started. A
    /// generation of an earlier lifetime gets the conservative restart
    /// rules.
    pub opened_in: ExecutorEpochId,
    /// The application slots of a memory incident, with the usage that
    /// the controller restored.
    pub slots: Option<SlotAllowance>,
    /// The work ceilings of a disk incident: batch, pass, rule, incident,
    /// grant, and executor, with the usage that the controller restored.
    pub work: Option<WorkBudget>,
    /// The pacing after a low-benefit or failed action.
    pub pacing: Pacing,
}

/// What the journal shows about the consumed work of an incident.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum JournalUsage {
    /// The consumed dispatches of the incident.
    Known {
        /// The operations with a consumed application step.
        slots: u32,
        /// The sum of the charges of the consumed filesystem steps.
        work: WorkCharge,
    },
    /// The journal gave no complete list. The allowance is exhausted.
    Unknown,
}

/// A refusal of the ledger. It changed nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct LedgerRefusal {
    /// The error code.
    pub(super) code: &'static str,
}

impl LedgerRefusal {
    const fn new(code: &'static str) -> Self {
        Self { code }
    }

    /// The error family of the refusal: `recording` for a read of the
    /// journal that a lock prevented, `request` for an allowance of a
    /// different budget generation, and `limits` for each other code.
    pub(super) fn family(self) -> ErrorFamily {
        match self.code {
            code::ADMISSION_NOT_RECORDED => ErrorFamily::Recording,
            code::INCIDENT_MISMATCH => ErrorFamily::Request,
            _ => ErrorFamily::Limits,
        }
    }
}

/// The benefit of a settled automatic operation, for the pacing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Benefit {
    /// The measurements show an improvement.
    Observed,
    /// The operation failed, its effect is not known, or the measurements
    /// show no improvement or are not available.
    LowOrFailed,
    /// No call was submitted. The pacing does not change.
    NoCall,
}

/// The budget that an admitted operation holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Hold {
    /// The one-shot work limit of a manual filesystem plan.
    ManualWork(WorkAllowance),
    /// The one-shot slot of a manual application plan.
    ManualSlot {
        allowance: SlotAllowance,
        charged: bool,
    },
    /// A reservation in the work budget of an incident.
    IncidentWork { incident_id: IncidentId },
    /// A reserved slot of a memory incident.
    IncidentSlot {
        incident_id: IncidentId,
        charged: bool,
    },
}

impl Hold {
    /// The incident of an automatic hold.
    pub(super) const fn incident(&self) -> Option<&IncidentId> {
        match self {
            Self::IncidentWork { incident_id } | Self::IncidentSlot { incident_id, .. } => {
                Some(incident_id)
            }
            Self::ManualWork(_) | Self::ManualSlot { .. } => None,
        }
    }
}

impl IncidentEntry {
    /// Whether an admitted operation has a reservation in the record.
    fn has_reservation(&self) -> bool {
        self.slots.is_some_and(|slots| slots.reserved() > 0)
            || self.work.as_ref().is_some_and(|work| {
                work.allowances()
                    .iter()
                    .any(|scoped| scoped.allowance.reserved() != WorkCharge::ZERO)
            })
    }
}

#[derive(Debug)]
struct IncidentEntry {
    generation: Generation,
    slots: Option<SlotAllowance>,
    work: Option<WorkBudget>,
    pacing: Pacing,
    cooldown_until: Option<MonotonicNanos>,
    backoff_level: u32,
    /// True when the slots were exhausted because the usage of the budget
    /// generation is not known. A larger ceiling for the same generation
    /// then gives no slot back.
    slots_exhausted: bool,
    /// The same for the work scopes that are not for one request.
    work_exhausted: bool,
}

/// The ledger of one executor lifetime.
#[derive(Debug)]
pub(super) struct Ledger {
    epoch: ExecutorEpochId,
    /// True when the lifetime before this one did not stop cleanly, so
    /// volatile counts were possibly lost.
    unclean_start: bool,
    started_at: MonotonicNanos,
    incidents: BTreeMap<IncidentId, IncidentEntry>,
    leases: BTreeMap<LeaseResource, ResourceLease>,
    /// The resources of each `UnknownOutcome` operation of an earlier
    /// lifetime that is not acknowledged. They conflict as a lease does,
    /// and two such operations can name one resource.
    held: BTreeMap<OperationId, Vec<LeaseResource>>,
}

/// Moves a consumed charge back to the reservation of an allowance.
fn unconsume_work(
    allowance: &WorkAllowance,
    charge: WorkCharge,
) -> Result<WorkAllowance, BudgetError> {
    let consumed: WorkCharge = allowance
        .consumed()
        .checked_sub(charge)
        .ok_or(BudgetError::NotReserved)?;
    let reserved: WorkCharge = allowance
        .reserved()
        .checked_add(charge)
        .ok_or(BudgetError::Overflow)?;
    WorkAllowance::with_usage(allowance.ceiling(), consumed, reserved)
}

fn unconsume_budget(budget: &WorkBudget, charge: WorkCharge) -> Result<WorkBudget, BudgetError> {
    let mut allowances: Vec<ScopedAllowance> = Vec::with_capacity(budget.allowances().len());
    for scoped in budget.allowances() {
        allowances.push(ScopedAllowance {
            scope: scoped.scope.clone(),
            allowance: unconsume_work(&scoped.allowance, charge)?,
        });
    }
    WorkBudget::new(allowances).map_err(|_| BudgetError::NotReserved)
}

fn unconsume_slot(allowance: &SlotAllowance) -> Result<SlotAllowance, BudgetError> {
    let consumed: u32 = allowance
        .consumed()
        .checked_sub(1)
        .ok_or(BudgetError::NotReserved)?;
    let reserved: u32 = allowance
        .reserved()
        .checked_add(1)
        .ok_or(BudgetError::Overflow)?;
    SlotAllowance::with_usage(allowance.ceiling(), consumed, reserved)
}

fn exhausted_work(ceiling: WorkCharge) -> WorkAllowance {
    WorkAllowance::with_usage(ceiling, ceiling, WorkCharge::ZERO)
        .unwrap_or_else(|_| WorkAllowance::new(WorkCharge::ZERO))
}

fn is_per_request(scope: &BudgetScope) -> bool {
    matches!(scope, BudgetScope::Batch | BudgetScope::Pass)
}

impl Ledger {
    pub(super) const fn new(
        epoch: ExecutorEpochId,
        unclean_start: bool,
        started_at: MonotonicNanos,
    ) -> Self {
        Self {
            epoch,
            unclean_start,
            started_at,
            incidents: BTreeMap::new(),
            leases: BTreeMap::new(),
            held: BTreeMap::new(),
        }
    }

    /// Whether the ledger has a record of `incident_id` for `generation`.
    pub(super) fn knows(&self, incident_id: &IncidentId, generation: Generation) -> bool {
        self.incidents
            .get(incident_id)
            .is_some_and(|entry| entry.generation == generation)
    }

    /// Whether the ledger has a record of `incident_id`.
    pub(super) fn has(&self, incident_id: &IncidentId) -> bool {
        self.incidents.contains_key(incident_id)
    }

    /// Takes the allowance of an incident from the controller.
    ///
    /// A new record takes the larger usage of the given allowance and of
    /// the journal; with no journal usage, a budget generation of an
    /// earlier lifetime is exhausted. A later record of the same
    /// generation takes a new ceiling and never a smaller consumed
    /// counter. A new generation (a rearm) starts with the given usage.
    /// Each record keeps the reservations of the admitted operations and
    /// the cooldown.
    pub(super) fn observe_incident(
        &mut self,
        given: &IncidentAllowance,
        journal: Option<JournalUsage>,
        now: MonotonicNanos,
    ) -> Result<(), LedgerRefusal> {
        let carried_over: bool = given.opened_in != self.epoch;
        if !self.incidents.contains_key(&given.incident_id) && self.incidents.len() >= MAX_INCIDENTS
        {
            // An incident with no admitted operation makes room: its
            // usage is in the journal. A record whose cooldown is in
            // force, or whose allowance was exhausted because its usage
            // is not known, stays: the journal has neither value.
            self.incidents.retain(|_, entry| {
                entry.has_reservation()
                    || entry.slots_exhausted
                    || entry.work_exhausted
                    || entry.cooldown_until.is_some_and(|until| now < until)
            });
            if self.incidents.len() >= MAX_INCIDENTS {
                return Err(LedgerRefusal::new(code::BUDGET_EXHAUSTED));
            }
        }
        let known: Option<&IncidentEntry> = self.incidents.get(&given.incident_id);
        // A budget generation only increases. An allowance of a
        // generation before the recorded one is not a rearm, and it does
        // not replace the usage of the recorded generation.
        if known.is_some_and(|entry| given.generation < entry.generation) {
            return Err(LedgerRefusal::new(code::INCIDENT_ALLOWANCE_MISSING));
        }
        let same_generation: bool = known.is_some_and(|entry| entry.generation == given.generation);
        // The lower bound of the consumed counters of a new record.
        let floor: Option<JournalUsage> = match (known, journal) {
            (None, Some(usage)) => Some(usage),
            (None, None) if carried_over => Some(JournalUsage::Unknown),
            (Some(_), _) | (None, None) => None,
        };
        let unknown_floor: bool = matches!(floor, Some(JournalUsage::Unknown));
        let slots_exhausted: bool =
            unknown_floor || (same_generation && known.is_some_and(|entry| entry.slots_exhausted));
        let work_exhausted: bool =
            unknown_floor || (same_generation && known.is_some_and(|entry| entry.work_exhausted));
        let slots: Option<SlotAllowance> = match (known.and_then(|entry| entry.slots), given.slots)
        {
            (earlier, Some(given)) => {
                let reserved: u32 = earlier.map_or(0, |earlier| earlier.reserved());
                let consumed: u32 = match (earlier, floor) {
                    _ if slots_exhausted => given.ceiling(),
                    (Some(earlier), _) if same_generation => {
                        earlier.consumed().max(given.consumed())
                    }
                    (_, Some(JournalUsage::Known { slots, .. })) => slots.max(given.consumed()),
                    (_, Some(JournalUsage::Unknown)) => given.ceiling(),
                    _ => given.consumed(),
                };
                let merged = SlotAllowance::with_usage(
                    given.ceiling(),
                    consumed.min(given.ceiling().saturating_sub(reserved)),
                    reserved,
                );
                // A ceiling below the reservations keeps the earlier
                // allowance, which has them.
                Some(merged.unwrap_or_else(|_| {
                    earlier.unwrap_or_else(|| SlotAllowance::exhausted(given.ceiling()))
                }))
            }
            (earlier, None) => earlier,
        };
        let work: Option<WorkBudget> =
            match (known.and_then(|entry| entry.work.as_ref()), &given.work) {
                (earlier, Some(given)) => {
                    merge_budgets(earlier, given, same_generation, floor, work_exhausted)
                }
                (earlier, None) => earlier.cloned(),
            };
        let (cooldown_until, backoff_level) = match known {
            Some(entry) => (entry.cooldown_until, entry.backoff_level),
            // The cooldown and the backoff of an earlier lifetime are not
            // in the journal, so an incident that continues starts with
            // the longest cooldown. A restart does not shorten one.
            None if carried_over => (
                Some(
                    self.started_at
                        .checked_add(given.pacing.max_cooldown.max(given.pacing.cooldown))
                        .unwrap_or(MonotonicNanos::new(u64::MAX)),
                ),
                MAX_BACKOFF_LEVEL,
            ),
            None => (None, 0),
        };
        self.incidents.insert(
            given.incident_id.clone(),
            IncidentEntry {
                generation: given.generation,
                slots,
                work,
                pacing: given.pacing,
                cooldown_until,
                backoff_level,
                slots_exhausted,
                work_exhausted,
            },
        );
        Ok(())
    }

    /// Exhausts the slots of an incident: a restart possibly lost the
    /// volatile counts of its budget generation.
    pub(super) fn exhaust_slots_if_volatile_lost(
        &mut self,
        given: &IncidentAllowance,
        volatile_exception: bool,
    ) {
        if !(self.unclean_start && volatile_exception && given.opened_in != self.epoch) {
            return;
        }
        if let Some(entry) = self.incidents.get_mut(&given.incident_id)
            && let Some(slots) = &entry.slots
        {
            entry.slots = Some(SlotAllowance::exhausted(slots.ceiling()));
            entry.slots_exhausted = true;
        }
    }

    /// Reserves the one-shot limit of a manual plan.
    pub(super) fn reserve_manual(
        limit: Option<WorkCharge>,
        total: Option<WorkCharge>,
    ) -> Result<Hold, LedgerRefusal> {
        match (limit, total) {
            (Some(limit), Some(total)) => {
                let mut allowance = WorkAllowance::new(limit);
                allowance
                    .reserve(total)
                    .map_err(|_| LedgerRefusal::new(code::BUDGET_EXHAUSTED))?;
                Ok(Hold::ManualWork(allowance))
            }
            (None, None) => {
                let mut allowance = SlotAllowance::new(1);
                allowance
                    .reserve()
                    .map_err(|_| LedgerRefusal::new(code::BUDGET_EXHAUSTED))?;
                Ok(Hold::ManualSlot {
                    allowance,
                    charged: false,
                })
            }
            _ => Err(LedgerRefusal::new(code::PLAN_NOT_EXECUTABLE)),
        }
    }

    /// Reserves the charge of an automatic plan in its incident. `total`
    /// is the sum of the charges of a filesystem plan, or `None` for an
    /// application plan.
    pub(super) fn reserve_incident(
        &mut self,
        incident_id: &IncidentId,
        total: Option<WorkCharge>,
        now: MonotonicNanos,
    ) -> Result<Hold, LedgerRefusal> {
        let entry: &mut IncidentEntry = self
            .incidents
            .get_mut(incident_id)
            .ok_or(LedgerRefusal::new(code::INCIDENT_ALLOWANCE_MISSING))?;
        if entry.cooldown_until.is_some_and(|until| now < until) {
            return Err(LedgerRefusal::new(code::COOLDOWN_ACTIVE));
        }
        if let Some(total) = total {
            let budget: &mut WorkBudget = entry
                .work
                .as_mut()
                .ok_or(LedgerRefusal::new(code::INCIDENT_ALLOWANCE_MISSING))?;
            budget
                .reserve(total)
                .map_err(|_| LedgerRefusal::new(code::BUDGET_EXHAUSTED))?;
            Ok(Hold::IncidentWork {
                incident_id: incident_id.clone(),
            })
        } else {
            let slots: &mut SlotAllowance = entry
                .slots
                .as_mut()
                .ok_or(LedgerRefusal::new(code::INCIDENT_ALLOWANCE_MISSING))?;
            slots
                .reserve()
                .map_err(|_| LedgerRefusal::new(code::BUDGET_EXHAUSTED))?;
            Ok(Hold::IncidentSlot {
                incident_id: incident_id.clone(),
                charged: false,
            })
        }
    }

    /// Charges one step together with its dispatch consumption. `charge`
    /// is the charge of a filesystem step. An application operation is
    /// charged one slot at its first step, and its later steps charge
    /// nothing. The result says whether this call charged.
    pub(super) fn charge(
        &mut self,
        hold: &mut Hold,
        charge: Option<WorkCharge>,
    ) -> Result<bool, BudgetError> {
        match (hold, charge) {
            (Hold::ManualWork(allowance), Some(charge)) => allowance.consume(charge).map(|()| true),
            (Hold::IncidentWork { incident_id }, Some(charge)) => self
                .incidents
                .get_mut(incident_id)
                .and_then(|entry| entry.work.as_mut())
                .ok_or(BudgetError::NotReserved)?
                .consume(charge)
                .map(|()| true),
            (Hold::ManualSlot { allowance, charged }, None) => {
                if *charged {
                    return Ok(false);
                }
                allowance.consume()?;
                *charged = true;
                Ok(true)
            }
            (
                Hold::IncidentSlot {
                    incident_id,
                    charged,
                },
                None,
            ) => {
                if *charged {
                    return Ok(false);
                }
                self.incidents
                    .get_mut(incident_id)
                    .and_then(|entry| entry.slots.as_mut())
                    .ok_or(BudgetError::NotReserved)?
                    .consume()?;
                *charged = true;
                Ok(true)
            }
            _ => Err(BudgetError::NotReserved),
        }
    }

    /// Takes back a charge of [`Ledger::charge`], for a step whose
    /// executor established that no external call was issued. The charge
    /// is a reservation again.
    pub(super) fn refund(
        &mut self,
        hold: &mut Hold,
        charge: Option<WorkCharge>,
    ) -> Result<(), BudgetError> {
        match (hold, charge) {
            (Hold::ManualWork(allowance), Some(charge)) => {
                *allowance = unconsume_work(allowance, charge)?;
                Ok(())
            }
            (Hold::IncidentWork { incident_id }, Some(charge)) => {
                let entry: &mut IncidentEntry = self
                    .incidents
                    .get_mut(incident_id)
                    .ok_or(BudgetError::NotReserved)?;
                let budget: &WorkBudget = entry.work.as_ref().ok_or(BudgetError::NotReserved)?;
                entry.work = Some(unconsume_budget(budget, charge)?);
                Ok(())
            }
            (Hold::ManualSlot { allowance, charged }, None) if *charged => {
                *allowance = unconsume_slot(allowance)?;
                *charged = false;
                Ok(())
            }
            (
                Hold::IncidentSlot {
                    incident_id,
                    charged,
                },
                None,
            ) if *charged => {
                let entry: &mut IncidentEntry = self
                    .incidents
                    .get_mut(incident_id)
                    .ok_or(BudgetError::NotReserved)?;
                let slots: &SlotAllowance = entry.slots.as_ref().ok_or(BudgetError::NotReserved)?;
                entry.slots = Some(unconsume_slot(slots)?);
                *charged = false;
                Ok(())
            }
            _ => Err(BudgetError::NotReserved),
        }
    }

    /// Releases the reservation that an operation did not use: `unused`
    /// for a filesystem operation, the slot for an application operation
    /// that charged none.
    pub(super) fn release(&mut self, hold: &mut Hold, unused: Option<WorkCharge>) {
        // A release that does not fit shows that the charge was consumed;
        // the allowance then stays as it is.
        match (hold, unused) {
            (Hold::ManualWork(allowance), Some(unused)) => {
                let _kept: Result<(), BudgetError> = allowance.release(unused);
            }
            (Hold::IncidentWork { incident_id }, Some(unused)) => {
                if let Some(budget) = self
                    .incidents
                    .get_mut(incident_id)
                    .and_then(|entry| entry.work.as_mut())
                {
                    let _kept: Result<(), BudgetError> = budget.release(unused);
                }
            }
            (Hold::ManualSlot { allowance, charged }, _) if !*charged => {
                let _kept: Result<(), BudgetError> = allowance.release();
            }
            (
                Hold::IncidentSlot {
                    incident_id,
                    charged,
                },
                _,
            ) if !*charged => {
                if let Some(slots) = self
                    .incidents
                    .get_mut(incident_id)
                    .and_then(|entry| entry.slots.as_mut())
                {
                    let _kept: Result<(), BudgetError> = slots.release();
                }
            }
            _ => {}
        }
    }

    /// Applies the pacing of an incident after an operation settled.
    pub(super) fn pace(&mut self, incident_id: &IncidentId, benefit: Benefit, now: MonotonicNanos) {
        let Some(entry) = self.incidents.get_mut(incident_id) else {
            return;
        };
        match benefit {
            Benefit::NoCall => {}
            Benefit::Observed => entry.backoff_level = 0,
            Benefit::LowOrFailed => {
                let factor: u64 = 1_u64 << entry.backoff_level.min(MAX_BACKOFF_LEVEL);
                let cooldown: Nanoseconds = entry
                    .pacing
                    .cooldown
                    .get()
                    .checked_mul(factor)
                    .map_or(entry.pacing.max_cooldown, Nanoseconds::new)
                    .min(entry.pacing.max_cooldown.max(entry.pacing.cooldown));
                // A time that does not fit keeps the incident in cooldown.
                let until: MonotonicNanos = now
                    .checked_add(cooldown)
                    .unwrap_or(MonotonicNanos::new(u64::MAX));
                entry.cooldown_until = Some(
                    entry
                        .cooldown_until
                        .map_or(until, |earlier| earlier.max(until)),
                );
                entry.backoff_level = entry.backoff_level.saturating_add(1).min(MAX_BACKOFF_LEVEL);
            }
        }
    }

    /// The end of the cooldown of an incident, when one is recorded.
    pub(super) fn cooldown_until(&self, incident_id: &IncidentId) -> Option<MonotonicNanos> {
        self.incidents
            .get(incident_id)
            .and_then(|entry| entry.cooldown_until)
    }

    /// The smallest capacity gain that is a benefit for an incident.
    pub(super) fn min_capacity_gain(&self, incident_id: &IncidentId) -> Option<ByteDelta> {
        let entry: &IncidentEntry = self.incidents.get(incident_id)?;
        ByteDelta::new(i128::from(entry.pacing.min_capacity_gain.get())).ok()
    }

    /// The remaining slots of an incident.
    pub(super) fn remaining_slots(&self, incident_id: &IncidentId) -> Option<u32> {
        self.incidents
            .get(incident_id)
            .and_then(|entry| entry.slots.as_ref())
            .map(SlotAllowance::remaining)
    }

    /// Takes a lease on each resource for `owner`, or takes none.
    ///
    /// A lease of a different operation is a conflict until that
    /// operation is settled, also after its expiry: the expiry of a lease
    /// does not show that the work stopped.
    pub(super) fn acquire_leases(
        &mut self,
        resources: &[LeaseResource],
        owner: &OperationId,
        expires_at: MonotonicNanos,
        ids: &mut dyn IdSource,
    ) -> Result<Vec<ResourceLease>, LedgerRefusal> {
        if resources.iter().any(|resource| {
            self.leases
                .get(resource)
                .is_some_and(|lease| &lease.owner != owner)
                || self
                    .held
                    .iter()
                    .any(|(holder, held)| holder != owner && held.contains(resource))
        }) {
            return Err(LedgerRefusal::new(code::LEASE_UNAVAILABLE));
        }
        if self.leases.len().saturating_add(resources.len()) > MAX_LEASES {
            return Err(LedgerRefusal::new(code::LEASE_UNAVAILABLE));
        }
        let mut leases: Vec<ResourceLease> = Vec::with_capacity(resources.len());
        for resource in resources {
            let lease_id = ids
                .lease_id()
                .ok_or(LedgerRefusal::new(code::IDENTITY_UNAVAILABLE))?;
            leases.push(ResourceLease {
                lease_id,
                resource: resource.clone(),
                owner: owner.clone(),
                executor_epoch: self.epoch.clone(),
                expires_at,
            });
        }
        for lease in &leases {
            self.leases.insert(lease.resource.clone(), lease.clone());
        }
        Ok(leases)
    }

    /// Releases each lease of `owner`.
    pub(super) fn release_leases(&mut self, owner: &OperationId) {
        self.leases.retain(|_, lease| &lease.owner != owner);
    }

    /// Holds the resources of an `UnknownOutcome` operation of an earlier
    /// lifetime until a reconciliation settles it or a user acknowledges
    /// it (`docs/ACTION_CONTRACTS.md` section 12). A second call replaces
    /// the resources of the first.
    pub(super) fn hold_unknown(&mut self, owner: &OperationId, resources: Vec<LeaseResource>) {
        self.held.insert(owner.clone(), resources);
    }

    /// Releases the resources that [`Ledger::hold_unknown`] holds for
    /// `owner`. Returns true when it held some.
    pub(super) fn release_unknown(&mut self, owner: &OperationId) -> bool {
        self.held.remove(owner).is_some()
    }

    /// The `UnknownOutcome` operations of an earlier lifetime whose
    /// resources the ledger holds.
    pub(super) fn held_unknown(&self) -> impl Iterator<Item = &OperationId> {
        self.held.keys()
    }

    /// Whether `owner` holds each of `leases` at `now`.
    pub(super) fn holds(
        &self,
        leases: &[ResourceLease],
        owner: &OperationId,
        now: MonotonicNanos,
    ) -> bool {
        leases.iter().all(|lease| {
            lease.is_held_by(owner, &self.epoch, now)
                && self
                    .leases
                    .get(&lease.resource)
                    .is_some_and(|held| held.lease_id == lease.lease_id)
        })
    }
}

/// The work budget of a record: the ceilings of `given`, the reservations
/// of `earlier`, and consumed counters that do not go below the earlier
/// counter of the same generation or the journal usage of a new record.
/// A batch and a pass belong to one request of the controller, so their
/// consumed counters are the given ones.
fn merge_budgets(
    earlier: Option<&WorkBudget>,
    given: &WorkBudget,
    same_generation: bool,
    floor: Option<JournalUsage>,
    exhausted: bool,
) -> Option<WorkBudget> {
    let mut allowances: Vec<ScopedAllowance> = Vec::with_capacity(given.allowances().len());
    for scoped in given.allowances() {
        let before: Option<WorkAllowance> = earlier.and_then(|earlier| {
            earlier
                .allowances()
                .iter()
                .find(|before| before.scope == scoped.scope)
                .map(|before| before.allowance)
        });
        let reserved: WorkCharge = before.map_or(WorkCharge::ZERO, |before| before.reserved());
        let ceiling: WorkCharge = scoped.allowance.ceiling();
        let given_consumed: WorkCharge = scoped.allowance.consumed();
        let larger = |other: WorkCharge| {
            WorkCharge::new(
                given_consumed.work_bytes.max(other.work_bytes),
                given_consumed.items.max(other.items),
            )
        };
        let consumed: WorkCharge = if is_per_request(&scoped.scope) {
            given_consumed
        } else {
            match (before, floor) {
                _ if exhausted => ceiling,
                (Some(before), _) if same_generation => larger(before.consumed()),
                (_, Some(JournalUsage::Known { work, .. })) => larger(work),
                (_, Some(JournalUsage::Unknown)) => ceiling,
                _ => given_consumed,
            }
        };
        // A usage that does not fit the new ceiling keeps the earlier
        // allowance with its reservations, or exhausts a new one.
        let allowance: WorkAllowance = WorkAllowance::with_usage(ceiling, consumed, reserved)
            .unwrap_or_else(|_| before.unwrap_or_else(|| exhausted_work(ceiling)));
        allowances.push(ScopedAllowance {
            scope: scoped.scope.clone(),
            allowance,
        });
    }
    WorkBudget::new(allowances).ok()
}
