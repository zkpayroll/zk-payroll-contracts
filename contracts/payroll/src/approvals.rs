//! Configurable payroll approval threshold.
//!
//! An employer can require `N` distinct authorized reviewers to approve a
//! prepared payroll run before `finalize_payroll_run` will execute it. The
//! policy is opt-in, mirroring `set_max_reviewers`: while no threshold is
//! configured, the review workflow behaves exactly as it did before this
//! feature existed.
//!
//! An approval counts toward the threshold only while:
//! - its reviewer is still authorized (revoking a reviewer immediately
//!   withdraws their approvals), and
//! - it is within `DEFAULT_APPROVAL_EXPIRY_SECONDS` of when it was recorded.
//!
//! A rejection or change request clears every recorded approval for the run,
//! so execution always requires a fresh quorum after an objection. A
//! withdrawn approval (#522) removes only that reviewer's approval, and a
//! superseded approval moves to the superseding reviewer.
//!
//! Only reviewer addresses, counts, and timestamps are stored or reported;
//! salary amounts, employee identities, and proof material never are.

use soroban_sdk::{contracttype, Address, Env, Vec};

use crate::{DataKey, ReviewDecision, RunReview, DEFAULT_APPROVAL_EXPIRY_SECONDS};

/// Largest configurable approval threshold. Bounds the per-run approval list
/// and therefore the cost of counting approvals at finalization.
pub const MAX_APPROVAL_THRESHOLD: u32 = 10;

/// Maximum number of live approvals stored per run. Revoked and expired
/// approvals are pruned before this limit is checked.
pub const MAX_RUN_APPROVALS: u32 = 2 * MAX_APPROVAL_THRESHOLD;

/// One reviewer's approval of a payroll run.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunApproval {
    pub reviewer: Address,
    pub approved_at: u64,
}

/// Privacy-safe view of how close a run is to its approval threshold.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalProgress {
    /// Configured threshold, or `0` when no threshold is configured.
    pub required: u32,
    /// Approvals that currently count toward the threshold.
    pub approved: u32,
    /// `true` when the run may be finalized as far as approvals are concerned.
    pub threshold_met: bool,
}

pub(crate) fn threshold(e: &Env) -> Option<u32> {
    e.storage().persistent().get(&DataKey::ApprovalThreshold)
}

pub(crate) fn run_approvals(e: &Env, run_id: u64) -> Vec<RunApproval> {
    e.storage()
        .persistent()
        .get(&DataKey::RunApprovals(run_id))
        .unwrap_or_else(|| Vec::new(e))
}

fn is_reviewer(e: &Env, reviewer: &Address) -> bool {
    e.storage()
        .persistent()
        .get(&DataKey::AuthorizedReviewer(reviewer.clone()))
        .unwrap_or(false)
}

/// Same boundary as `is_payroll_approval_expired`: an approval is still
/// valid at exactly `approved_at + DEFAULT_APPROVAL_EXPIRY_SECONDS`.
fn is_live(e: &Env, approval: &RunApproval, now: u64) -> bool {
    now <= approval
        .approved_at
        .saturating_add(DEFAULT_APPROVAL_EXPIRY_SECONDS)
        && is_reviewer(e, &approval.reviewer)
}

fn live_approvals(e: &Env, run_id: u64) -> Vec<RunApproval> {
    let now = e.ledger().timestamp();
    let mut live = Vec::new(e);
    for approval in run_approvals(e, run_id).iter() {
        if is_live(e, &approval, now) {
            live.push_back(approval);
        }
    }
    live
}

/// Record `reviewer`'s approval of `run_id`. The caller must already have
/// verified that `reviewer` is authorized and has signed.
pub(crate) fn record_approval(e: &Env, run_id: u64, reviewer: &Address) {
    let mut approvals = live_approvals(e, run_id);
    if approvals
        .iter()
        .any(|approval| approval.reviewer == *reviewer)
    {
        panic!("Duplicate approval: reviewer has already approved this payroll run");
    }
    if approvals.len() >= MAX_RUN_APPROVALS {
        panic!("Approval limit reached for this payroll run");
    }
    approvals.push_back(RunApproval {
        reviewer: reviewer.clone(),
        approved_at: e.ledger().timestamp(),
    });
    e.storage()
        .persistent()
        .set(&DataKey::RunApprovals(run_id), &approvals);
}

/// Drop `reviewer`'s approval of `run_id`, if any, so it no longer counts
/// toward the threshold.
pub(crate) fn remove_approval(e: &Env, run_id: u64, reviewer: &Address) {
    let mut remaining = Vec::new(e);
    for approval in run_approvals(e, run_id).iter() {
        if approval.reviewer != *reviewer {
            remaining.push_back(approval);
        }
    }
    if remaining.is_empty() {
        clear_approvals(e, run_id);
    } else {
        e.storage()
            .persistent()
            .set(&DataKey::RunApprovals(run_id), &remaining);
    }
}

pub(crate) fn clear_approvals(e: &Env, run_id: u64) {
    e.storage()
        .persistent()
        .remove(&DataKey::RunApprovals(run_id));
}

pub(crate) fn progress(e: &Env, run_id: u64) -> ApprovalProgress {
    let approved = live_approvals(e, run_id).len();
    let required = threshold(e).unwrap_or(0);
    ApprovalProgress {
        required,
        approved,
        threshold_met: approved >= required,
    }
}

/// Reject finalization of `run_id` unless the configured threshold (if any)
/// is met by live approvals and no objection is outstanding.
pub(crate) fn require_threshold_met(e: &Env, run_id: u64) {
    let Some(required) = threshold(e) else {
        return;
    };

    let latest_review: Option<RunReview> =
        e.storage().persistent().get(&DataKey::RunReview(run_id));
    if let Some(review) = latest_review {
        if matches!(
            review.decision,
            ReviewDecision::Rejected | ReviewDecision::ChangesRequested
        ) {
            panic!(
                "Payroll run has an outstanding rejection or change request: collect fresh approvals before finalizing"
            );
        }
    }

    let approved = live_approvals(e, run_id).len();
    if approved < required {
        panic!(
            "Insufficient payroll approvals: {} of {} required approvals recorded",
            approved, required
        );
    }
}

/// Direct execution entrypoints assign a run ID at execution time, leaving
/// no window to collect approvals, so they are unavailable while a
/// threshold is configured.
pub(crate) fn require_no_threshold_for_direct_execution(e: &Env) {
    if threshold(e).is_some() {
        panic!(
            "Approval threshold configured: use prepare_payroll_run, collect reviewer approvals, then finalize_payroll_run"
        );
    }
}
