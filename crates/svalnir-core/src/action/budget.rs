//! Budgets and resource leases.
//!
//! `docs/ACTION_CONTRACTS.md` section 5 and `docs/CLEANUP_RULES.md`
//! section 7 own the contract. A budget is reserved at admission, consumed
//! together with the dispatch, and released only when no external call was
//! submitted. The arithmetic is checked: an overflow or a charge that does
//! not fit is an error, and nothing saturates or wraps.
//!
//! The policy module computes what a plan can charge from usage that the
//! caller gives it. The types here are the usage records that the
//! coordinator and the journal keep.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::id::{
    CapacityDomainId, ExecutorEpochId, IncidentId, LeaseId, OperationId, ProcessGenerationId,
    RootId, RuleId, VolumeId,
};
use crate::policy::CapacityDomainKey;
use crate::quantity::{Bytes, EntryCount};
use crate::time::MonotonicNanos;

/// The reason a budget change was rejected. The allowance is not changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum BudgetError {
    /// The charge is larger than the remaining allowance.
    #[error("the charge is larger than the remaining allowance")]
    Exhausted,
    /// The amount is larger than the reserved amount.
    #[error("the amount is larger than the reserved amount")]
    NotReserved,
    /// The sum is larger than the largest value of the quantity.
    #[error("the budget arithmetic overflowed")]
    Overflow,
    /// The consumed and reserved amounts are larger than the ceiling.
    #[error("the usage is larger than the ceiling")]
    OverCeiling,
}

/// The charge of one filesystem unit: the conservative `work_bytes` of the
/// rule and the entry count. The two limits apply independently.
///
/// A charge is always known. An unknown charge has no value of this type,
/// so it cannot be reserved as zero. The type has no default value: the
/// caller states each part.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkCharge {
    /// The `work_bytes` charge. It is not reclaimable bytes.
    pub work_bytes: Bytes,
    /// The number of entries.
    pub items: EntryCount,
}

impl WorkCharge {
    /// The charge of no work.
    pub const ZERO: Self = Self::new(Bytes::ZERO, EntryCount::ZERO);

    /// Makes the charge.
    pub const fn new(work_bytes: Bytes, items: EntryCount) -> Self {
        Self { work_bytes, items }
    }

    /// The sum of the two charges. `None` on overflow.
    #[must_use]
    pub const fn checked_add(self, other: Self) -> Option<Self> {
        match (
            self.work_bytes.checked_add(other.work_bytes),
            self.items.checked_add(other.items),
        ) {
            (Some(work_bytes), Some(items)) => Some(Self { work_bytes, items }),
            _ => None,
        }
    }

    /// This charge less `other`. `None` when a part of `other` is larger.
    #[must_use]
    pub const fn checked_sub(self, other: Self) -> Option<Self> {
        match (
            self.work_bytes.checked_sub(other.work_bytes),
            self.items.checked_sub(other.items),
        ) {
            (Some(work_bytes), Some(items)) => Some(Self { work_bytes, items }),
            _ => None,
        }
    }

    /// Whether this charge fits in `limit`: each part is not larger.
    pub fn fits_in(&self, limit: &Self) -> bool {
        self.work_bytes <= limit.work_bytes && self.items <= limit.items
    }

    /// The smaller of each part.
    #[must_use]
    pub fn min(self, other: Self) -> Self {
        Self {
            work_bytes: self.work_bytes.min(other.work_bytes),
            items: self.items.min(other.items),
        }
    }
}

/// One filesystem allowance: a ceiling with its consumed and reserved
/// charges. `consumed + reserved` is never larger than the ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "WorkAllowanceWire")]
pub struct WorkAllowance {
    ceiling: WorkCharge,
    consumed: WorkCharge,
    reserved: WorkCharge,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkAllowanceWire {
    ceiling: WorkCharge,
    consumed: WorkCharge,
    reserved: WorkCharge,
}

impl TryFrom<WorkAllowanceWire> for WorkAllowance {
    type Error = BudgetError;

    fn try_from(wire: WorkAllowanceWire) -> Result<Self, Self::Error> {
        Self::with_usage(wire.ceiling, wire.consumed, wire.reserved)
    }
}

impl WorkAllowance {
    /// An allowance with no usage.
    pub const fn new(ceiling: WorkCharge) -> Self {
        Self {
            ceiling,
            consumed: WorkCharge::ZERO,
            reserved: WorkCharge::ZERO,
        }
    }

    /// An allowance with recorded usage.
    ///
    /// # Errors
    ///
    /// Returns [`BudgetError::Overflow`] when the sum of the usage
    /// overflows, and [`BudgetError::OverCeiling`] when the usage is larger
    /// than the ceiling.
    pub fn with_usage(
        ceiling: WorkCharge,
        consumed: WorkCharge,
        reserved: WorkCharge,
    ) -> Result<Self, BudgetError> {
        let used: WorkCharge = consumed
            .checked_add(reserved)
            .ok_or(BudgetError::Overflow)?;
        if !used.fits_in(&ceiling) {
            return Err(BudgetError::OverCeiling);
        }
        Ok(Self {
            ceiling,
            consumed,
            reserved,
        })
    }

    /// The ceiling.
    pub const fn ceiling(&self) -> WorkCharge {
        self.ceiling
    }

    /// The consumed charge.
    pub const fn consumed(&self) -> WorkCharge {
        self.consumed
    }

    /// The reserved charge.
    pub const fn reserved(&self) -> WorkCharge {
        self.reserved
    }

    /// `ceiling - consumed - reserved`.
    pub fn remaining(&self) -> WorkCharge {
        // The invariant `consumed + reserved <= ceiling` makes each
        // subtraction exact.
        WorkCharge {
            work_bytes: Bytes::new(
                self.ceiling.work_bytes.get()
                    - self.consumed.work_bytes.get()
                    - self.reserved.work_bytes.get(),
            ),
            items: EntryCount::new(
                self.ceiling.items.get() - self.consumed.items.get() - self.reserved.items.get(),
            ),
        }
    }

    /// Reserves the full charge of one indivisible unit.
    ///
    /// # Errors
    ///
    /// Returns [`BudgetError::Exhausted`] when the charge does not fit in
    /// the remaining allowance. The unit is skipped; the limit is not
    /// raised and the unit is not divided.
    pub fn reserve(&mut self, charge: WorkCharge) -> Result<(), BudgetError> {
        if !charge.fits_in(&self.remaining()) {
            return Err(BudgetError::Exhausted);
        }
        self.reserved = self
            .reserved
            .checked_add(charge)
            .ok_or(BudgetError::Overflow)?;
        Ok(())
    }

    /// Moves a reserved charge to the consumed charge. Do this together
    /// with the dispatch consumption, before the external call.
    ///
    /// # Errors
    ///
    /// Returns [`BudgetError::NotReserved`] when the charge is larger than
    /// the reserved charge.
    pub fn consume(&mut self, charge: WorkCharge) -> Result<(), BudgetError> {
        let reserved: WorkCharge = self
            .reserved
            .checked_sub(charge)
            .ok_or(BudgetError::NotReserved)?;
        self.consumed = self
            .consumed
            .checked_add(charge)
            .ok_or(BudgetError::Overflow)?;
        self.reserved = reserved;
        Ok(())
    }

    /// Releases a reserved charge. Do this only when the executor
    /// established that no external call was submitted. A consumed charge
    /// has no release.
    ///
    /// # Errors
    ///
    /// Returns [`BudgetError::NotReserved`] when the charge is larger than
    /// the reserved charge.
    pub fn release(&mut self, charge: WorkCharge) -> Result<(), BudgetError> {
        self.reserved = self
            .reserved
            .checked_sub(charge)
            .ok_or(BudgetError::NotReserved)?;
        Ok(())
    }
}

/// The level of one filesystem allowance.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "scope", content = "id", rename_all = "snake_case")]
pub enum BudgetScope {
    /// One batch.
    Batch,
    /// One pass of an incident.
    Pass,
    /// One cleanup rule.
    Rule(RuleId),
    /// One incident.
    Incident(IncidentId),
    /// The ceiling of the action grant.
    Grant,
    /// The ceiling of the executor.
    Executor,
}

/// The allowances that bound one filesystem operation. The effective limit
/// is the minimum of the remaining allowances.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "Vec<ScopedAllowance>", into = "Vec<ScopedAllowance>")]
pub struct WorkBudget {
    allowances: Vec<ScopedAllowance>,
}

/// One allowance with its level.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedAllowance {
    /// The level.
    pub scope: BudgetScope,
    /// The allowance.
    pub allowance: WorkAllowance,
}

/// The reason a budget was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum WorkBudgetError {
    /// The budget has no allowance. Unbounded work is not admissible.
    #[error("the budget has no allowance")]
    Unbounded,
    /// Two allowances have the same level.
    #[error("two allowances have the same level")]
    DuplicateScope,
}

impl TryFrom<Vec<ScopedAllowance>> for WorkBudget {
    type Error = WorkBudgetError;

    fn try_from(allowances: Vec<ScopedAllowance>) -> Result<Self, Self::Error> {
        Self::new(allowances)
    }
}

impl From<WorkBudget> for Vec<ScopedAllowance> {
    fn from(budget: WorkBudget) -> Self {
        budget.allowances
    }
}

impl WorkBudget {
    /// Makes the budget.
    ///
    /// # Errors
    ///
    /// Returns a [`WorkBudgetError`] when the list is empty or when two
    /// allowances have the same level.
    pub fn new(allowances: Vec<ScopedAllowance>) -> Result<Self, WorkBudgetError> {
        if allowances.is_empty() {
            return Err(WorkBudgetError::Unbounded);
        }
        for (index, entry) in allowances.iter().enumerate() {
            if allowances[..index]
                .iter()
                .any(|earlier| earlier.scope == entry.scope)
            {
                return Err(WorkBudgetError::DuplicateScope);
            }
        }
        Ok(Self { allowances })
    }

    /// The allowances.
    pub fn allowances(&self) -> &[ScopedAllowance] {
        &self.allowances
    }

    /// The effective limit: the minimum of the remaining allowances.
    pub fn remaining(&self) -> WorkCharge {
        self.allowances
            .iter()
            .map(|entry| entry.allowance.remaining())
            .reduce(WorkCharge::min)
            .unwrap_or(WorkCharge::ZERO)
    }

    /// Reserves the charge at each level, or at no level.
    ///
    /// # Errors
    ///
    /// Returns the [`BudgetError`] of the first level that the charge does
    /// not fit in. No level is changed.
    pub fn reserve(&mut self, charge: WorkCharge) -> Result<(), BudgetError> {
        self.apply(charge, WorkAllowance::reserve)
    }

    /// Consumes a reserved charge at each level, or at no level.
    ///
    /// # Errors
    ///
    /// Returns the [`BudgetError`] of the first level that rejects the
    /// charge. No level is changed.
    pub fn consume(&mut self, charge: WorkCharge) -> Result<(), BudgetError> {
        self.apply(charge, WorkAllowance::consume)
    }

    /// Releases a reserved charge at each level, or at no level.
    ///
    /// # Errors
    ///
    /// Returns the [`BudgetError`] of the first level that rejects the
    /// charge. No level is changed.
    pub fn release(&mut self, charge: WorkCharge) -> Result<(), BudgetError> {
        self.apply(charge, WorkAllowance::release)
    }

    fn apply(
        &mut self,
        charge: WorkCharge,
        update: fn(&mut WorkAllowance, WorkCharge) -> Result<(), BudgetError>,
    ) -> Result<(), BudgetError> {
        let mut updated: Vec<ScopedAllowance> = self.allowances.clone();
        for entry in &mut updated {
            update(&mut entry.allowance, charge)?;
        }
        self.allowances = updated;
        Ok(())
    }
}

/// The application slots of one memory incident, or the one-shot limit of
/// a manual operation. `consumed + reserved` is never larger than the
/// ceiling.
///
/// A graceful step and its force step use one slot. A submitted attempt
/// that fails, times out, or becomes uncertain keeps its slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "SlotAllowanceWire")]
pub struct SlotAllowance {
    ceiling: u32,
    consumed: u32,
    reserved: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SlotAllowanceWire {
    ceiling: u32,
    consumed: u32,
    reserved: u32,
}

impl TryFrom<SlotAllowanceWire> for SlotAllowance {
    type Error = BudgetError;

    fn try_from(wire: SlotAllowanceWire) -> Result<Self, Self::Error> {
        Self::with_usage(wire.ceiling, wire.consumed, wire.reserved)
    }
}

impl SlotAllowance {
    /// An allowance with no usage.
    pub const fn new(ceiling: u32) -> Self {
        Self {
            ceiling,
            consumed: 0,
            reserved: 0,
        }
    }

    /// An allowance with recorded usage.
    ///
    /// # Errors
    ///
    /// Returns [`BudgetError::Overflow`] when the sum of the usage
    /// overflows, and [`BudgetError::OverCeiling`] when the usage is larger
    /// than the ceiling.
    pub fn with_usage(ceiling: u32, consumed: u32, reserved: u32) -> Result<Self, BudgetError> {
        let used: u32 = consumed
            .checked_add(reserved)
            .ok_or(BudgetError::Overflow)?;
        if used > ceiling {
            return Err(BudgetError::OverCeiling);
        }
        Ok(Self {
            ceiling,
            consumed,
            reserved,
        })
    }

    /// An allowance that is exhausted. Use this value when a restart
    /// cannot establish the usage of the earlier incident: an unknown
    /// budget is not replenished.
    pub const fn exhausted(ceiling: u32) -> Self {
        Self {
            ceiling,
            consumed: ceiling,
            reserved: 0,
        }
    }

    /// The ceiling.
    pub const fn ceiling(&self) -> u32 {
        self.ceiling
    }

    /// The consumed slots.
    pub const fn consumed(&self) -> u32 {
        self.consumed
    }

    /// The reserved slots.
    pub const fn reserved(&self) -> u32 {
        self.reserved
    }

    /// `ceiling - consumed - reserved`.
    pub const fn remaining(&self) -> u32 {
        self.ceiling - self.consumed - self.reserved
    }

    /// Reserves one slot at admission.
    ///
    /// # Errors
    ///
    /// Returns [`BudgetError::Exhausted`] when no slot remains.
    pub fn reserve(&mut self) -> Result<(), BudgetError> {
        if self.remaining() == 0 {
            return Err(BudgetError::Exhausted);
        }
        self.reserved += 1;
        Ok(())
    }

    /// Moves one reserved slot to the consumed slots. Do this together
    /// with the dispatch consumption of the first termination step.
    ///
    /// # Errors
    ///
    /// Returns [`BudgetError::NotReserved`] when no slot is reserved.
    pub fn consume(&mut self) -> Result<(), BudgetError> {
        if self.reserved == 0 {
            return Err(BudgetError::NotReserved);
        }
        self.reserved -= 1;
        self.consumed += 1;
        Ok(())
    }

    /// Releases one reserved slot. Do this only when the executor
    /// established that no external call was submitted.
    ///
    /// # Errors
    ///
    /// Returns [`BudgetError::NotReserved`] when no slot is reserved.
    pub fn release(&mut self) -> Result<(), BudgetError> {
        if self.reserved == 0 {
            return Err(BudgetError::NotReserved);
        }
        self.reserved -= 1;
        Ok(())
    }
}

/// The conflict domain of a lease.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "resource", content = "id", rename_all = "snake_case")]
pub enum LeaseResource {
    /// One process generation of an application intervention.
    ProcessGeneration(ProcessGenerationId),
    /// One approved cleanup root.
    CleanupRoot(RootId),
    /// One verified shared-capacity domain.
    CapacityDomain(CapacityDomainId),
    /// One volume with exclusive free space.
    Volume(VolumeId),
}

impl From<CapacityDomainKey> for LeaseResource {
    fn from(key: CapacityDomainKey) -> Self {
        match key {
            CapacityDomainKey::Domain(id) => Self::CapacityDomain(id),
            CapacityDomainKey::Volume(id) => Self::Volume(id),
        }
    }
}

/// Ownership of one conflict domain for bounded work, as the coordinator
/// issued it.
///
/// A lease coordinates Svalnir sessions. It does not stop another writer
/// or an application relaunch, and its expiry does not prove that a
/// submitted effect stopped.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceLease {
    /// The identity of the lease.
    pub lease_id: LeaseId,
    /// The conflict domain.
    pub resource: LeaseResource,
    /// The operation that owns the lease.
    pub owner: OperationId,
    /// The executor lifetime that issued the lease. A lease of an earlier
    /// lifetime is not held.
    pub executor_epoch: ExecutorEpochId,
    /// The monotonic time at which the lease expires, in the clock domain
    /// of the executor lifetime.
    pub expires_at: MonotonicNanos,
}

impl ResourceLease {
    /// Whether `operation` holds this lease at `now` in the executor
    /// lifetime `epoch`. The loss of a lease blocks the next step.
    pub fn is_held_by(
        &self,
        operation: &OperationId,
        epoch: &ExecutorEpochId,
        now: MonotonicNanos,
    ) -> bool {
        &self.owner == operation && &self.executor_epoch == epoch && now < self.expires_at
    }

    /// Whether a lease on `resource` for `operation` conflicts with this
    /// lease: the same domain and a different owner. The expiry is not
    /// read: a successor reconciles the work of the earlier owner before a
    /// conflicting dispatch.
    pub fn conflicts_with(&self, resource: &LeaseResource, operation: &OperationId) -> bool {
        &self.resource == resource && &self.owner != operation
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        BudgetError, BudgetScope, LeaseResource, ResourceLease, ScopedAllowance, SlotAllowance,
        WorkAllowance, WorkBudget, WorkBudgetError, WorkCharge,
    };
    use crate::id::{
        CapacityDomainId, ExecutorEpochId, LeaseId, OperationId, ProcessGenerationId, RootId,
        RuleId, VolumeId,
    };
    use crate::policy::CapacityDomainKey;
    use crate::quantity::{Bytes, EntryCount};
    use crate::time::MonotonicNanos;

    fn charge(bytes: u64, items: u64) -> WorkCharge {
        WorkCharge::new(Bytes::new(bytes), EntryCount::new(items))
    }

    #[test]
    fn a_charge_uses_checked_arithmetic() {
        assert_eq!(charge(1, 2).checked_add(charge(3, 4)), Some(charge(4, 6)));
        assert_eq!(charge(u64::MAX, 0).checked_add(charge(1, 0)), None);
        assert_eq!(charge(0, u64::MAX).checked_add(charge(0, 1)), None);
        assert_eq!(
            charge(u64::MAX - 1, 0).checked_add(charge(1, 0)),
            Some(charge(u64::MAX, 0))
        );
        assert_eq!(
            charge(4, 6).checked_sub(charge(4, 6)),
            Some(WorkCharge::ZERO)
        );
        assert_eq!(charge(4, 6).checked_sub(charge(5, 0)), None);
        assert_eq!(charge(4, 6).checked_sub(charge(0, 7)), None);
        assert!(charge(4, 6).fits_in(&charge(4, 6)));
        assert!(!charge(5, 6).fits_in(&charge(4, 6)));
        assert!(!charge(4, 7).fits_in(&charge(4, 6)));
        assert_eq!(charge(4, 9).min(charge(7, 6)), charge(4, 6));
    }

    #[test]
    fn an_allowance_reserves_to_its_limit_and_not_past_it() {
        let mut allowance = WorkAllowance::new(charge(100, 3));
        allowance.reserve(charge(60, 1)).unwrap();
        assert_eq!(allowance.remaining(), charge(40, 2));
        // The bytes fit and the entries do not.
        assert_eq!(
            allowance.reserve(charge(10, 3)),
            Err(BudgetError::Exhausted)
        );
        // The entries fit and the bytes do not.
        assert_eq!(
            allowance.reserve(charge(41, 1)),
            Err(BudgetError::Exhausted)
        );
        assert_eq!(allowance.remaining(), charge(40, 2));
        // The exact remainder fits.
        allowance.reserve(charge(40, 2)).unwrap();
        assert_eq!(allowance.remaining(), WorkCharge::ZERO);
        assert_eq!(allowance.reserve(charge(0, 1)), Err(BudgetError::Exhausted));
        assert_eq!(allowance.reserve(charge(1, 0)), Err(BudgetError::Exhausted));
        // A zero charge is a known charge and fits.
        allowance.reserve(WorkCharge::ZERO).unwrap();
    }

    #[test]
    fn a_consumed_charge_is_not_released() {
        let mut allowance = WorkAllowance::new(charge(100, 10));
        allowance.reserve(charge(30, 2)).unwrap();
        assert_eq!(
            allowance.consume(charge(31, 2)),
            Err(BudgetError::NotReserved)
        );
        allowance.consume(charge(30, 2)).unwrap();
        assert_eq!(allowance.consumed(), charge(30, 2));
        assert_eq!(allowance.reserved(), WorkCharge::ZERO);
        assert_eq!(
            allowance.release(charge(30, 2)),
            Err(BudgetError::NotReserved)
        );
        assert_eq!(allowance.remaining(), charge(70, 8));
        // A reservation with no submitted call is released.
        allowance.reserve(charge(70, 8)).unwrap();
        allowance.release(charge(70, 8)).unwrap();
        assert_eq!(allowance.remaining(), charge(70, 8));
        assert_eq!(allowance.ceiling(), charge(100, 10));
    }

    #[test]
    fn an_allowance_at_the_largest_value_does_not_wrap() {
        let mut allowance = WorkAllowance::new(charge(u64::MAX, u64::MAX));
        allowance.reserve(charge(u64::MAX, u64::MAX)).unwrap();
        assert_eq!(allowance.reserve(charge(1, 0)), Err(BudgetError::Exhausted));
        allowance.consume(charge(u64::MAX, u64::MAX)).unwrap();
        assert_eq!(allowance.remaining(), WorkCharge::ZERO);
        assert_eq!(
            WorkAllowance::with_usage(charge(u64::MAX, 0), charge(u64::MAX, 0), charge(1, 0)),
            Err(BudgetError::Overflow)
        );
        assert_eq!(
            WorkAllowance::with_usage(charge(10, 1), charge(6, 0), charge(5, 0)),
            Err(BudgetError::OverCeiling)
        );
        assert!(WorkAllowance::with_usage(charge(10, 1), charge(6, 0), charge(4, 1)).is_ok());
    }

    #[test]
    fn an_allowance_round_trips_and_rejects_usage_over_its_ceiling() {
        let mut allowance = WorkAllowance::new(charge(100, 3));
        allowance.reserve(charge(60, 1)).unwrap();
        let value = serde_json::to_value(allowance).unwrap();
        assert_eq!(
            value,
            json!({
                "ceiling": { "work_bytes": "100", "items": "3" },
                "consumed": { "work_bytes": "0", "items": "0" },
                "reserved": { "work_bytes": "60", "items": "1" },
            })
        );
        assert_eq!(
            serde_json::from_value::<WorkAllowance>(value).unwrap(),
            allowance
        );
        let over = json!({
            "ceiling": { "work_bytes": "1", "items": "1" },
            "consumed": { "work_bytes": "2", "items": "0" },
            "reserved": { "work_bytes": "0", "items": "0" },
        });
        assert!(serde_json::from_value::<WorkAllowance>(over).is_err());
        // An exact integer is a string, not a JSON number.
        assert!(
            serde_json::from_value::<WorkCharge>(json!({ "work_bytes": 1, "items": "1" })).is_err()
        );
    }

    fn budget() -> WorkBudget {
        let rule = RuleId::new("svalnir.expired-temporary").unwrap();
        WorkBudget::new(vec![
            ScopedAllowance {
                scope: BudgetScope::Batch,
                allowance: WorkAllowance::new(charge(50, 100)),
            },
            ScopedAllowance {
                scope: BudgetScope::Pass,
                allowance: WorkAllowance::new(charge(200, 5)),
            },
            ScopedAllowance {
                scope: BudgetScope::Rule(rule),
                allowance: WorkAllowance::new(charge(80, 50)),
            },
        ])
        .unwrap()
    }

    #[test]
    fn the_effective_limit_is_the_minimum_of_the_levels() {
        let mut budget = budget();
        assert_eq!(budget.remaining(), charge(50, 5));
        budget.reserve(charge(50, 4)).unwrap();
        assert_eq!(budget.remaining(), charge(0, 1));
        // The pass and the rule have bytes; the batch has none.
        assert_eq!(budget.reserve(charge(1, 1)), Err(BudgetError::Exhausted));
        budget.reserve(charge(0, 1)).unwrap();
        assert_eq!(budget.remaining(), WorkCharge::ZERO);
    }

    #[test]
    fn a_budget_change_applies_to_each_level_or_to_none() {
        let mut budget = budget();
        let before = budget.clone();
        // The charge fits in the batch and in the rule, and not in the
        // pass. The batch is not charged.
        assert_eq!(budget.reserve(charge(10, 6)), Err(BudgetError::Exhausted));
        assert_eq!(budget, before);
        budget.reserve(charge(10, 1)).unwrap();
        assert_eq!(budget.consume(charge(11, 1)), Err(BudgetError::NotReserved));
        assert_eq!(budget.release(charge(10, 2)), Err(BudgetError::NotReserved));
        budget.consume(charge(10, 1)).unwrap();
        for entry in budget.allowances() {
            assert_eq!(entry.allowance.consumed(), charge(10, 1));
            assert_eq!(entry.allowance.reserved(), WorkCharge::ZERO);
        }
        assert_eq!(budget.release(charge(10, 1)), Err(BudgetError::NotReserved));
    }

    #[test]
    fn a_budget_needs_a_bound_and_distinct_levels() {
        assert_eq!(WorkBudget::new(Vec::new()), Err(WorkBudgetError::Unbounded));
        let entry = ScopedAllowance {
            scope: BudgetScope::Grant,
            allowance: WorkAllowance::new(charge(1, 1)),
        };
        assert_eq!(
            WorkBudget::new(vec![entry.clone(), entry]),
            Err(WorkBudgetError::DuplicateScope)
        );
        let budget = budget();
        let value = serde_json::to_value(&budget).unwrap();
        assert_eq!(value[0]["scope"], json!({ "scope": "batch" }));
        assert_eq!(
            value[2]["scope"],
            json!({ "scope": "rule", "id": "svalnir.expired-temporary" })
        );
        assert_eq!(serde_json::from_value::<WorkBudget>(value).unwrap(), budget);
        assert!(serde_json::from_value::<WorkBudget>(json!([])).is_err());
        assert!(serde_json::from_value::<BudgetScope>(json!({ "scope": "week" })).is_err());
    }

    #[test]
    fn a_slot_allowance_counts_each_slot_one_time() {
        let mut slots = SlotAllowance::new(2);
        slots.reserve().unwrap();
        slots.reserve().unwrap();
        assert_eq!(slots.reserve(), Err(BudgetError::Exhausted));
        slots.consume().unwrap();
        assert_eq!(
            (slots.consumed(), slots.reserved(), slots.remaining()),
            (1, 1, 0)
        );
        slots.release().unwrap();
        assert_eq!(slots.remaining(), 1);
        assert_eq!(slots.release(), Err(BudgetError::NotReserved));
        assert_eq!(slots.consume(), Err(BudgetError::NotReserved));
        // A consumed slot stays consumed.
        assert_eq!(slots.consumed(), 1);

        let mut none = SlotAllowance::new(0);
        assert_eq!(none.reserve(), Err(BudgetError::Exhausted));
        let mut unknown = SlotAllowance::exhausted(3);
        assert_eq!(unknown.remaining(), 0);
        assert_eq!(unknown.reserve(), Err(BudgetError::Exhausted));

        let mut full = SlotAllowance::new(u32::MAX);
        for _ in 0..3 {
            full.reserve().unwrap();
        }
        assert_eq!(full.remaining(), u32::MAX - 3);
        assert_eq!(
            SlotAllowance::with_usage(u32::MAX, u32::MAX, 1),
            Err(BudgetError::Overflow)
        );
        assert_eq!(
            SlotAllowance::with_usage(2, 2, 1),
            Err(BudgetError::OverCeiling)
        );
        let exact = SlotAllowance::with_usage(u32::MAX, u32::MAX - 1, 1).unwrap();
        assert_eq!(exact.remaining(), 0);
    }

    #[test]
    fn a_slot_allowance_round_trips() {
        let slots = SlotAllowance::with_usage(3, 1, 1).unwrap();
        let value = serde_json::to_value(slots).unwrap();
        assert_eq!(value, json!({ "ceiling": 3, "consumed": 1, "reserved": 1 }));
        assert_eq!(
            serde_json::from_value::<SlotAllowance>(value).unwrap(),
            slots
        );
        assert!(
            serde_json::from_value::<SlotAllowance>(
                json!({ "ceiling": 1, "consumed": 1, "reserved": 1 })
            )
            .is_err()
        );
        assert_eq!(slots.ceiling(), 3);
    }

    fn lease(resource: LeaseResource) -> ResourceLease {
        ResourceLease {
            lease_id: LeaseId::new("lease_1").unwrap(),
            resource,
            owner: OperationId::new("operation_1").unwrap(),
            executor_epoch: ExecutorEpochId::new("epoch_1").unwrap(),
            expires_at: MonotonicNanos::new(1_000),
        }
    }

    #[test]
    fn a_lease_is_held_by_its_owner_in_its_epoch_before_expiry() {
        let root = LeaseResource::CleanupRoot(RootId::new("root_1").unwrap());
        let lease = lease(root.clone());
        let owner = OperationId::new("operation_1").unwrap();
        let other = OperationId::new("operation_2").unwrap();
        let epoch = ExecutorEpochId::new("epoch_1").unwrap();
        let later_epoch = ExecutorEpochId::new("epoch_2").unwrap();
        assert!(lease.is_held_by(&owner, &epoch, MonotonicNanos::new(999)));
        assert!(!lease.is_held_by(&owner, &epoch, MonotonicNanos::new(1_000)));
        assert!(!lease.is_held_by(&other, &epoch, MonotonicNanos::new(1)));
        assert!(!lease.is_held_by(&owner, &later_epoch, MonotonicNanos::new(1)));

        assert!(lease.conflicts_with(&root, &other));
        assert!(!lease.conflicts_with(&root, &owner));
        let other_root = LeaseResource::CleanupRoot(RootId::new("root_2").unwrap());
        assert!(!lease.conflicts_with(&other_root, &other));
        // The same text in a different domain is a different resource.
        let generation =
            LeaseResource::ProcessGeneration(ProcessGenerationId::new("root_1").unwrap());
        assert!(!lease.conflicts_with(&generation, &other));
    }

    #[test]
    fn a_lease_round_trips_and_an_unknown_resource_is_rejected() {
        let domain = CapacityDomainId::new("domain_1").unwrap();
        let resource = LeaseResource::from(CapacityDomainKey::Domain(domain));
        let lease = lease(resource);
        let value = serde_json::to_value(&lease).unwrap();
        assert_eq!(
            value,
            json!({
                "lease_id": "lease_1",
                "resource": { "resource": "capacity_domain", "id": "domain_1" },
                "owner": "operation_1",
                "executor_epoch": "epoch_1",
                "expires_at": "1000",
            })
        );
        assert_eq!(
            serde_json::from_value::<ResourceLease>(value).unwrap(),
            lease
        );
        let volume = VolumeId::new("volume_1").unwrap();
        assert_eq!(
            LeaseResource::from(CapacityDomainKey::Volume(volume.clone())),
            LeaseResource::Volume(volume)
        );
        assert!(
            serde_json::from_value::<LeaseResource>(json!({ "resource": "network", "id": "x" }))
                .is_err()
        );
    }
}
