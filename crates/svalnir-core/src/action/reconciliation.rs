//! The result of the reconciliation of one step.
//!
//! `docs/ACTION_CONTRACTS.md` section 12 owns the contract. Reconciliation
//! is observational: it reads the record of a step and the current
//! condition of its target, and it writes what the evidence establishes.

/// What one reconciliation attempt did with one step that an earlier
/// executor lifetime left unsettled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepReconciliation {
    /// The journal has what the evidence establishes. That can be the
    /// state `UnknownOutcome` when the evidence settles nothing.
    Recorded,
    /// A write of the journal failed. The record of the step is as it was,
    /// the reconciliation stays pending, and a later attempt reads the
    /// step again.
    NotRecorded,
    /// Not settled, inspected: the step was inspected, and the state
    /// machine or the result check refused the result that the evidence
    /// gave. The step is recorded as `UnknownOutcome`, and its
    /// reconciliation is complete. A later write cannot change a record
    /// that the state machine refuses, so a repeated attempt is not
    /// necessary to admit new work.
    Inspected,
}

impl StepReconciliation {
    /// Whether the reconciliation of the step is complete: each result
    /// except [`StepReconciliation::NotRecorded`].
    #[must_use]
    pub const fn is_complete(self) -> bool {
        !matches!(self, Self::NotRecorded)
    }
}

#[cfg(test)]
mod tests {
    use super::StepReconciliation;

    #[test]
    fn only_a_failed_write_keeps_the_reconciliation_pending() {
        assert!(StepReconciliation::Recorded.is_complete());
        assert!(StepReconciliation::Inspected.is_complete());
        assert!(!StepReconciliation::NotRecorded.is_complete());
    }
}
