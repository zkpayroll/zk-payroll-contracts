//! Multi-batch execution progress tracking (#643).
//!
//! Large payroll runs are executed as a sequence of bounded batches
//! (`batch_process_payroll_bounded`, at most 50 payments per call). Before
//! this feature, each bounded batch left behind an isolated
//! [`crate::BatchCheckpoint`] keyed by `(employer, batch_root, asset, nonce)`.
//! Operators had no single, privacy-safe record of how far the *whole*
//! multi-batch execution had progressed: how many batches and payments were
//! planned, how many had completed, whether the execution was still running,
//! finished, or had failed.
//!
//! This module provides the pure, deterministic core of that aggregate view.
//! Storage, authorization, and events live in
//! [`crate::Payroll`](crate::Payroll); everything here is side-effect free so
//! it can be unit-tested without a Soroban host.
//!
//! The tracker is opt-in and additive: existing batch flows
//! (`BatchCheckpoint`, `BatchResumePlan`, `batch_process_payroll_bounded`)
//! are untouched. A caller opens a tracker with
//! `begin_multi_batch_execution`, advances it with
//! `record_multi_batch_progress`, optionally marks it failed with
//! `mark_multi_batch_failed`, and polls it with `get_multi_batch_progress` /
//! `is_multi_batch_complete`.
//!
//! Everything is privacy-safe: only opaque execution identifiers and
//! aggregate counts are stored, checked, and emitted. No salary amount,
//! employee identity, commitment, or proof material is read or surfaced.

use soroban_sdk::{contracttype, Address, BytesN};

/// Maximum number of batches a single multi-batch execution may plan.
///
/// Mirrors [`crate::MAX_BATCH`]-style bounded execution: keeping the ceiling
/// small bounds ledger entries, event payloads, and dashboard polling loops.
pub const MAX_MULTI_BATCH_BATCHES: u32 = 50;

/// Maximum number of payments a single multi-batch execution may plan.
///
/// `50 batches x 50 payments` matches the largest execution that can be built
/// from bounded batches without reusing an execution identifier.
pub const MAX_MULTI_BATCH_PAYMENTS: u32 = 2500;

/// Lifecycle status of a multi-batch execution (#643).
///
/// Serialized as a stable ordinal so off-chain clients can persist and
/// pattern-match on it across contract upgrades.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum MultiBatchStatus {
    /// Execution is open and accepting progress records.
    InProgress = 0,
    /// All planned batches and payments completed. Terminal.
    Completed = 1,
    /// Execution was explicitly marked failed. Terminal.
    Failed = 2,
}

/// Privacy-safe aggregate progress for one multi-batch execution (#643).
///
/// Carries only the opaque execution identifier and aggregate counts, so it
/// is safe to surface to dashboards, SDKs, and indexers.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultiBatchExecutionProgress {
    /// Opaque caller-supplied execution identifier (must be non-zero).
    pub execution_id: BytesN<32>,
    /// Planned batch count (`1..=50`).
    pub total_batches: u32,
    /// Batches completed so far (`0..=total_batches`, monotonic).
    pub completed_batches: u32,
    /// Planned payment count (`1..=2500`, `>= total_batches`).
    pub total_payments: u32,
    /// Payments processed so far (`0..=total_payments`, monotonic).
    pub processed_payments: u32,
    /// Current lifecycle status.
    pub status: MultiBatchStatus,
    /// Ledger timestamp when the tracker was opened.
    pub started_at: u64,
    /// Ledger timestamp of the latest write to this record.
    pub last_updated: u64,
    /// Admin that performed the latest write.
    pub updated_by: Address,
}

/// Structured reason a multi-batch progress validation failed (#643).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MultiBatchProgressIssue {
    /// `total_batches` is zero.
    EmptyBatches,
    /// `total_batches` exceeds [`MAX_MULTI_BATCH_BATCHES`].
    TooManyBatches,
    /// `total_payments` is zero.
    EmptyPayments,
    /// `total_payments` exceeds [`MAX_MULTI_BATCH_PAYMENTS`].
    TooManyPayments,
    /// Fewer planned payments than planned batches (each batch holds >= 1).
    PaymentsBelowBatches,
    /// `completed_batches` exceeds the planned `total_batches`.
    BatchesOverTotal,
    /// `processed_payments` exceeds the planned `total_payments`.
    PaymentsOverTotal,
    /// New progress regresses a previously recorded cursor.
    ProgressRegression,
    /// New progress advances neither cursor (no forward progress).
    NoForwardProgress,
    /// Record targets a terminal (`Completed` / `Failed`) execution.
    AlreadyTerminal,
}

impl MultiBatchProgressIssue {
    /// Stable, integration-friendly code for this issue.
    pub fn as_str(&self) -> &'static str {
        match self {
            MultiBatchProgressIssue::EmptyBatches => "empty_batches",
            MultiBatchProgressIssue::TooManyBatches => "too_many_batches",
            MultiBatchProgressIssue::EmptyPayments => "empty_payments",
            MultiBatchProgressIssue::TooManyPayments => "too_many_payments",
            MultiBatchProgressIssue::PaymentsBelowBatches => "payments_below_batches",
            MultiBatchProgressIssue::BatchesOverTotal => "batches_over_total",
            MultiBatchProgressIssue::PaymentsOverTotal => "payments_over_total",
            MultiBatchProgressIssue::ProgressRegression => "progress_regression",
            MultiBatchProgressIssue::NoForwardProgress => "no_forward_progress",
            MultiBatchProgressIssue::AlreadyTerminal => "already_terminal",
        }
    }
}

/// Validate planned totals for a new multi-batch execution.
///
/// Returns the first applicable [`MultiBatchProgressIssue`]; `Ok(())` means
/// the totals may be stored.
pub fn validate_begin_totals(
    total_batches: u32,
    total_payments: u32,
) -> Result<(), MultiBatchProgressIssue> {
    if total_batches == 0 {
        return Err(MultiBatchProgressIssue::EmptyBatches);
    }
    if total_batches > MAX_MULTI_BATCH_BATCHES {
        return Err(MultiBatchProgressIssue::TooManyBatches);
    }
    if total_payments == 0 {
        return Err(MultiBatchProgressIssue::EmptyPayments);
    }
    if total_payments > MAX_MULTI_BATCH_PAYMENTS {
        return Err(MultiBatchProgressIssue::TooManyPayments);
    }
    if total_payments < total_batches {
        return Err(MultiBatchProgressIssue::PaymentsBelowBatches);
    }
    Ok(())
}

/// Validate a progress record against the stored tracker.
///
/// `current` is the persisted record; (`completed_batches`,
/// `processed_payments`) is the caller-supplied next cursor. Checks run in a
/// fixed order so callers get one actionable reason: terminal first, then
/// bounds, then monotonicity, then forward progress.
pub fn validate_progress_record(
    current: &MultiBatchExecutionProgress,
    completed_batches: u32,
    processed_payments: u32,
) -> Result<(), MultiBatchProgressIssue> {
    if current.status != MultiBatchStatus::InProgress {
        return Err(MultiBatchProgressIssue::AlreadyTerminal);
    }
    if completed_batches > current.total_batches {
        return Err(MultiBatchProgressIssue::BatchesOverTotal);
    }
    if processed_payments > current.total_payments {
        return Err(MultiBatchProgressIssue::PaymentsOverTotal);
    }
    if completed_batches < current.completed_batches
        || processed_payments < current.processed_payments
    {
        return Err(MultiBatchProgressIssue::ProgressRegression);
    }
    if completed_batches == current.completed_batches
        && processed_payments == current.processed_payments
    {
        return Err(MultiBatchProgressIssue::NoForwardProgress);
    }
    Ok(())
}

/// Return `true` when the tracker has reached both planned totals.
pub fn is_complete(progress: &MultiBatchExecutionProgress) -> bool {
    progress.status == MultiBatchStatus::Completed
        || (progress.completed_batches == progress.total_batches
            && progress.processed_payments == progress.total_payments)
}

/// Return the number of batches still outstanding.
///
/// Safe without checked arithmetic: callers guarantee
/// `completed_batches <= total_batches` via [`validate_progress_record`] and
/// [`validate_begin_totals`], so the subtraction cannot underflow. Saturating
/// defensively keeps a hypothetical corrupt record from wrapping.
pub fn remaining_batches(progress: &MultiBatchExecutionProgress) -> u32 {
    progress
        .total_batches
        .saturating_sub(progress.completed_batches)
}

/// Return the number of payments still outstanding.
///
/// See [`remaining_batches`] for the underflow argument.
pub fn remaining_payments(progress: &MultiBatchExecutionProgress) -> u32 {
    progress
        .total_payments
        .saturating_sub(progress.processed_payments)
}

/// Return `true` when the status is terminal (`Completed` or `Failed`).
pub fn is_terminal(status: MultiBatchStatus) -> bool {
    matches!(
        status,
        MultiBatchStatus::Completed | MultiBatchStatus::Failed
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use soroban_sdk::{testutils::Address as _, Env};

    fn stub_progress(env: &Env) -> MultiBatchExecutionProgress {
        MultiBatchExecutionProgress {
            execution_id: BytesN::from_array(env, &[0x11; 32]),
            total_batches: 4,
            completed_batches: 1,
            total_payments: 100,
            processed_payments: 25,
            status: MultiBatchStatus::InProgress,
            started_at: 1_700_000_000,
            last_updated: 1_700_000_001,
            updated_by: Address::generate(env),
        }
    }

    #[test]
    fn begin_totals_accept_valid_plans() {
        assert!(validate_begin_totals(1, 1).is_ok());
        assert!(validate_begin_totals(50, 2500).is_ok());
        assert!(validate_begin_totals(4, 100).is_ok());
    }

    #[test]
    fn begin_totals_reject_empty_and_over_cap() {
        assert_eq!(
            validate_begin_totals(0, 10),
            Err(MultiBatchProgressIssue::EmptyBatches)
        );
        assert_eq!(
            validate_begin_totals(51, 51),
            Err(MultiBatchProgressIssue::TooManyBatches)
        );
        assert_eq!(
            validate_begin_totals(1, 0),
            Err(MultiBatchProgressIssue::EmptyPayments)
        );
        assert_eq!(
            validate_begin_totals(1, 2501),
            Err(MultiBatchProgressIssue::TooManyPayments)
        );
    }

    #[test]
    fn begin_totals_reject_payments_below_batches() {
        // Each batch holds at least one payment.
        assert_eq!(
            validate_begin_totals(4, 3),
            Err(MultiBatchProgressIssue::PaymentsBelowBatches)
        );
    }

    #[test]
    fn record_accepts_monotonic_forward_progress() {
        let env = Env::default();
        let current = stub_progress(&env);
        assert!(validate_progress_record(&current, 2, 25).is_ok());
        assert!(validate_progress_record(&current, 1, 50).is_ok());
        assert!(validate_progress_record(&current, 4, 100).is_ok());
    }

    #[test]
    fn record_rejects_terminal_first() {
        let env = Env::default();
        let mut completed = stub_progress(&env);
        completed.status = MultiBatchStatus::Completed;
        assert_eq!(
            validate_progress_record(&completed, 99, 9999),
            Err(MultiBatchProgressIssue::AlreadyTerminal)
        );
        let mut failed = stub_progress(&env);
        failed.status = MultiBatchStatus::Failed;
        assert_eq!(
            validate_progress_record(&failed, 2, 50),
            Err(MultiBatchProgressIssue::AlreadyTerminal)
        );
    }

    #[test]
    fn record_rejects_over_total_before_monotonicity() {
        let env = Env::default();
        let current = stub_progress(&env);
        assert_eq!(
            validate_progress_record(&current, 5, 25),
            Err(MultiBatchProgressIssue::BatchesOverTotal)
        );
        assert_eq!(
            validate_progress_record(&current, 2, 101),
            Err(MultiBatchProgressIssue::PaymentsOverTotal)
        );
    }

    #[test]
    fn record_rejects_regression_and_no_op() {
        let env = Env::default();
        let current = stub_progress(&env);
        assert_eq!(
            validate_progress_record(&current, 0, 25),
            Err(MultiBatchProgressIssue::ProgressRegression)
        );
        assert_eq!(
            validate_progress_record(&current, 1, 24),
            Err(MultiBatchProgressIssue::ProgressRegression)
        );
        assert_eq!(
            validate_progress_record(&current, 1, 25),
            Err(MultiBatchProgressIssue::NoForwardProgress)
        );
    }

    #[test]
    fn remaining_counts_saturate_without_underflow() {
        let env = Env::default();
        let current = stub_progress(&env);
        assert_eq!(remaining_batches(&current), 3);
        assert_eq!(remaining_payments(&current), 75);
        let mut done = current.clone();
        done.completed_batches = 4;
        done.processed_payments = 100;
        assert_eq!(remaining_batches(&done), 0);
        assert_eq!(remaining_payments(&done), 0);
    }

    #[test]
    fn terminal_classification_is_stable() {
        assert!(!is_terminal(MultiBatchStatus::InProgress));
        assert!(is_terminal(MultiBatchStatus::Completed));
        assert!(is_terminal(MultiBatchStatus::Failed));
    }

    #[test]
    fn issue_codes_are_stable() {
        assert_eq!(
            MultiBatchProgressIssue::BatchesOverTotal.as_str(),
            "batches_over_total"
        );
        assert_eq!(
            MultiBatchProgressIssue::NoForwardProgress.as_str(),
            "no_forward_progress"
        );
        assert_eq!(
            MultiBatchProgressIssue::AlreadyTerminal.as_str(),
            "already_terminal"
        );
    }
}
