//! Prerequisite checks before a pay period may be closed (#651).
//!
//! Closing a pay period is a one-way, irreversible transition: once closed,
//! no new payment instructions can be submitted, pending approvals are voided,
//! and the period's settlement window is sealed.  Skipping the required
//! pre-conditions risks closing a period that still has outstanding
//! obligations, leaving employees unpaid with no on-chain recovery path.
//!
//! This module defines the *closure gate* — a set of invariants that must all
//! hold before the transition is allowed:
//!
//! 1. **No pending payment instructions** — every instruction submitted for
//!    the period must have been either executed or explicitly expired.
//! 2. **No pending approval quorum** — if an approval threshold is configured,
//!    either it must have been met (the run was finalized) or the run must have
//!    been voided; a period must not be closed while a run is still waiting
//!    for approvals.
//! 3. **Reconciliation complete** — a close-stage reconciliation checkpoint
//!    must have been recorded for the period, confirming that reserved and
//!    actual balances match.
//!
//! Each failing condition is reported as a distinct [`PeriodClosureError`] so
//! operators receive an actionable error rather than a generic "not allowed".
//!
//! Privacy: only counts, booleans, and period IDs are inspected.  No salary
//! amount, employee identity, or proof material is read or surfaced.

use soroban_sdk::contracterror;

/// Reasons a pay-period closure may be blocked.
#[contracterror]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum PeriodClosureError {
    /// One or more payment instructions for this period are still pending
    /// (neither executed nor expired).
    PendingPaymentInstructions = 1,
    /// The approval quorum for the period's payroll run has not been resolved;
    /// the run must be finalized or voided before the period can close.
    PendingApprovalQuorum = 2,
    /// A close-stage reconciliation checkpoint has not been recorded for this
    /// period, or the recorded checkpoint is not reconciled.
    ReconciliationIncomplete = 3,
}

/// Snapshot of all prerequisite checks for a period closure attempt.
///
/// All three fields must be `true` for [`assert_closure_prerequisites`] to
/// succeed.  Clients may call [`check_closure_prerequisites`] first to display
/// a structured status without triggering an error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeriodClosurePrerequisites {
    /// `true` when no payment instructions for the period are still pending.
    pub no_pending_instructions: bool,
    /// `true` when no approval quorum is waiting to be resolved.
    pub approval_quorum_resolved: bool,
    /// `true` when a close-stage reconciliation checkpoint is complete.
    pub reconciliation_complete: bool,
}

impl PeriodClosurePrerequisites {
    /// Returns `true` when every prerequisite is satisfied.
    pub fn all_satisfied(&self) -> bool {
        self.no_pending_instructions
            && self.approval_quorum_resolved
            && self.reconciliation_complete
    }

    /// Returns the first unsatisfied prerequisite, or `None` if all pass.
    pub fn first_unmet(&self) -> Option<PeriodClosureError> {
        if !self.no_pending_instructions {
            return Some(PeriodClosureError::PendingPaymentInstructions);
        }
        if !self.approval_quorum_resolved {
            return Some(PeriodClosureError::PendingApprovalQuorum);
        }
        if !self.reconciliation_complete {
            return Some(PeriodClosureError::ReconciliationIncomplete);
        }
        None
    }
}

/// Build a [`PeriodClosurePrerequisites`] snapshot from caller-supplied state.
///
/// The arguments are deliberately primitive so callers can supply whatever
/// state source is appropriate (storage, computed values, etc.) without this
/// module depending on any specific storage layout.
///
/// - `pending_instruction_count` — number of instructions that are neither
///   executed nor expired.
/// - `approval_quorum_pending` — `true` if a run is still awaiting approvals.
/// - `reconciliation_complete` — `true` if a close-stage checkpoint exists
///   and its `is_reconciled` field is `true`.
pub fn check_closure_prerequisites(
    pending_instruction_count: u32,
    approval_quorum_pending: bool,
    reconciliation_complete: bool,
) -> PeriodClosurePrerequisites {
    PeriodClosurePrerequisites {
        no_pending_instructions: pending_instruction_count == 0,
        approval_quorum_resolved: !approval_quorum_pending,
        reconciliation_complete,
    }
}

/// Assert that all closure prerequisites are satisfied.
///
/// Returns `Ok(())` when the period may be closed.  Returns the first
/// [`PeriodClosureError`] that describes the blocking condition otherwise.
pub fn assert_closure_prerequisites(
    pending_instruction_count: u32,
    approval_quorum_pending: bool,
    reconciliation_complete: bool,
) -> Result<(), PeriodClosureError> {
    let prereqs = check_closure_prerequisites(
        pending_instruction_count,
        approval_quorum_pending,
        reconciliation_complete,
    );
    match prereqs.first_unmet() {
        None => Ok(()),
        Some(err) => Err(err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_conditions_met_allows_closure() {
        assert!(assert_closure_prerequisites(0, false, true).is_ok());
    }

    #[test]
    fn pending_instructions_block_closure() {
        assert_eq!(
            assert_closure_prerequisites(3, false, true),
            Err(PeriodClosureError::PendingPaymentInstructions),
        );
    }

    #[test]
    fn pending_approval_quorum_blocks_closure() {
        assert_eq!(
            assert_closure_prerequisites(0, true, true),
            Err(PeriodClosureError::PendingApprovalQuorum),
        );
    }

    #[test]
    fn incomplete_reconciliation_blocks_closure() {
        assert_eq!(
            assert_closure_prerequisites(0, false, false),
            Err(PeriodClosureError::ReconciliationIncomplete),
        );
    }

    #[test]
    fn pending_instructions_takes_priority_over_quorum() {
        // When multiple conditions fail, the first is reported.
        assert_eq!(
            assert_closure_prerequisites(1, true, false),
            Err(PeriodClosureError::PendingPaymentInstructions),
        );
    }

    #[test]
    fn quorum_takes_priority_over_reconciliation() {
        assert_eq!(
            assert_closure_prerequisites(0, true, false),
            Err(PeriodClosureError::PendingApprovalQuorum),
        );
    }

    #[test]
    fn snapshot_reports_all_satisfied_correctly() {
        let prereqs = check_closure_prerequisites(0, false, true);
        assert!(prereqs.all_satisfied());
        assert!(prereqs.first_unmet().is_none());
    }

    #[test]
    fn snapshot_reports_individual_failures() {
        let prereqs = check_closure_prerequisites(2, false, true);
        assert!(!prereqs.all_satisfied());
        assert!(!prereqs.no_pending_instructions);
        assert!(prereqs.approval_quorum_resolved);
        assert!(prereqs.reconciliation_complete);
    }
}
