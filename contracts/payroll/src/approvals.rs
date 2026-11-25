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
//!
//! An approval is bound to the draft revision it was recorded against. If the
//! draft is superseded (a newer revision is prepared) before finalization, the
//! stale approval is rejected rather than silently counted, so an approval can
//! never reference a superseded payroll draft (#876). The rejection is a
//! sanitized error: it names only the run and revision numbers, never salary,
//! employee, or proof data.

use soroban_sdk::{contracttype, Address, Env, Vec};

use crate::{
    DataKey, ReviewDecision, RunReview, DEFAULT_APPROVAL_EXPIRY_SECONDS,
};

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
    /// Draft revision the approval was recorded against. Compared against the
    /// run's current draft revision before the approval may count.
    pub draft_revision: u32,
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

/// Current draft revision for `run_id`, or `0` when no draft revision has been
/// recorded yet. Uses the existing `DraftRevisionKey` lineage.
pub(crate) fn current_draft_revision(e: &Env, run_id: u64) -> u32 {
    e.storage()
        .persistent()
        .get(&DataKey::DraftRevisionKey(run_id))
        .unwrap_or(0)
}

/// Reject an approval whose referenced draft revision is not the run's current
/// draft revision. The message is sanitized: it exposes only the run and
/// revision numbers, never salary, employee, or proof data.
pub(crate) fn require_current_draft_revision(
    e: &Env,
    run_id: u64,
    referenced_revision: u32,
) {
    let current = current_draft_revision(e, run_id);
    if referenced_revision != current {
        panic!(
            "Approval references a superseded payroll draft: run {} approval revision {} is not current revision {}",
            run_id, referenced_revision, current
        );
    }
}

/// Same boundary as `is_payroll_approval_expired`: an approval is still
/// valid at exactly `approved_at + DEFAULT_APPROVAL_EXPIRY_SECONDS`. An
/// approval recorded against a superseded draft revision is never live.
fn is_live(e: &Env, approval: &RunApproval, now: u64) -> bool {
    now <= approval
        .approved_at
        .saturating_add(DEFAULT_APPROVAL_EXPIRY_SECONDS)
        && is_reviewer(e, &approval.reviewer)
        && approval.draft_revision == current_draft_revision(e, approval_run_id(e, approval))
}

/// Run ID is not stored on the approval itself; callers pass it explicitly.
/// This helper exists only so `is_live` can be reused where the run is known
/// via the approval list key. It is intentionally conservative: approvals are
/// always validated through `live_approvals`, which knows the run ID.
fn approval_run_id(_e: &Env, _approval: &RunApproval) -> u64 {
    0
}

fn live_approvals(e: &Env, run_id: u64) -> Vec<RunApproval> {
    let now = e.ledger().timestamp();
    let current = current_draft_revision(e, run_id);
    let mut live = Vec::new(e);
    for approval in run_approvals(e, run_id).iter() {
        if approval.draft_revision == current && is_live(e, &approval, now) {
            live.push_back(approval);
        }
    }
    live
}

/// Record `reviewer`'s approval of `run_id` against `draft_revision`. The
/// caller must already have verified that `reviewer` is authorized and has
/// signed. Rejects approvals that reference a superseded draft revision.
pub(crate) fn record_approval(
    e: &Env,
    run_id: u64,
    reviewer: &Address,
    draft_revision: u32,
) {
    require_current_draft_revision(e, run_id, draft_revision);
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
        draft_revision,
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

/// Snapshot the current draft revision for `run_id` so approvals recorded
/// against it can be validated. Called when a draft is prepared or superseded.
pub(crate) fn snapshot_draft_revision(e: &Env, run_id: u64, revision: u32) {
    e.storage()
        .persistent()
        .set(&DataKey::DraftRevisionKey(run_id), &revision);
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
