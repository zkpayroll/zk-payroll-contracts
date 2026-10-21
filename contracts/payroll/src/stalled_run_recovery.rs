//! Stalled payroll run recovery guidance (#XXX / #702).
//!
//! A pending payroll run that has not been finalized or cancelled within a
//! threshold window is considered stalled. This module provides read-only
//! recovery assessments that dashboards and SDK clients can surface to
//! operators so they can take appropriate corrective action without guessing.
//!
//! Privacy: assessments expose only the run ID, timing information, and a
//! recommended action code. No salary amounts, employee identities, or proof
//! material are included.

use soroban_sdk::{contracttype, Env};

use crate::DataKey;

/// Seconds after preparation before a pending run is considered stalled.
pub const STALLED_RUN_THRESHOLD_SECONDS: u64 = 86_400; // 24 hours

/// Recommended operator action for a stalled run.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum StalledRunRecoveryAction {
    /// The run should be finalized or cancelled — no partial payments have
    /// been attempted so either path is safe.
    CancelOrFinalize = 0,
    /// The run's batch checkpoint halted mid-execution; resume or cancel.
    ResumeOrCancel = 1,
    /// The run has expired; no action is required beyond verifying treasury
    /// reservation release.
    AlreadyExpired = 2,
}

/// Why a stalled-run assessment was generated.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum StalledRunRecoveryReason {
    /// Run has been pending longer than [`STALLED_RUN_THRESHOLD_SECONDS`].
    PendingTooLong = 0,
    /// A batch checkpoint is in the `Failed` state.
    FailedBatchCheckpoint = 1,
}

/// Why a stalled-run recovery assessment could not be produced.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum StalledRunRecoveryError {
    /// No pending run exists for this run ID.
    RunNotFound = 1,
    /// The run exists but is not yet stalled.
    NotStalled = 2,
}

/// A privacy-safe assessment of a stalled pending run.
///
/// Contains only opaque run identifiers, timing fields, and a recommended
/// action code. Never includes employee addresses, salary values, or proof
/// material.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StalledRunRecoveryAssessment {
    /// The pending run this assessment applies to.
    pub run_id: u64,
    /// Whether the run meets the stalled criteria.
    pub is_stalled: bool,
    /// Ledger timestamp when the run was prepared.
    pub prepared_at: u64,
    /// Ledger timestamp of the assessment.
    pub assessed_at: u64,
    /// Seconds elapsed since the run was prepared.
    pub age_seconds: u64,
    /// Reason the run is considered stalled.
    pub reason: StalledRunRecoveryReason,
    /// Recommended operator action.
    pub recommended_action: StalledRunRecoveryAction,
}

/// Return a stalled-run assessment for `run_id` if the run exists, is
/// pending, and meets the stall threshold. Returns `None` otherwise so
/// callers can distinguish "nothing to recover" from "stalled, act now".
pub fn assess(e: &Env, run_id: u64) -> Option<StalledRunRecoveryAssessment> {
    let pending = e
        .storage()
        .persistent()
        .get::<DataKey, crate::PendingPayrollRun>(&DataKey::PendingRun(run_id))?;

    let now = e.ledger().timestamp();
    let age = now.saturating_sub(pending.prepared_at);

    if age <= STALLED_RUN_THRESHOLD_SECONDS {
        return None;
    }

    Some(StalledRunRecoveryAssessment {
        run_id,
        is_stalled: true,
        prepared_at: pending.prepared_at,
        assessed_at: now,
        age_seconds: age,
        reason: StalledRunRecoveryReason::PendingTooLong,
        recommended_action: StalledRunRecoveryAction::CancelOrFinalize,
    })
}

/// Like [`assess`] but panics with an actionable message when the run is not
/// stalled, so the `record_stalled_run_recovery` entrypoint can gate the
/// write on an actual stall condition.
pub fn require_stalled(e: &Env, run_id: u64) -> StalledRunRecoveryAssessment {
    match assess(e, run_id) {
        Some(assessment) => assessment,
        None => {
            let exists = e
                .storage()
                .persistent()
                .has(&DataKey::PendingRun(run_id));
            if exists {
                panic!(
                    "Payroll run is not stalled: the run has been pending for less than {} seconds; \
                     wait until the threshold has elapsed before recording a recovery assessment",
                    STALLED_RUN_THRESHOLD_SECONDS
                );
            } else {
                panic!(
                    "Payroll run not found: no pending run exists for run ID {} \
                     (StalledRunRecoveryError::RunNotFound)",
                    run_id
                );
            }
        }
    }
}
