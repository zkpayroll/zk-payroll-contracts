//! Contract draft payroll approval snapshot locking (#648).
//!
//! When a draft's approval tracker reaches quorum, the admin can lock a
//! snapshot of exactly what was approved: the protected content hash, the
//! draft totals, its period, and its amendment counter. While the snapshot
//! is locked, every path that could change the approved content
//! (`amend_run_draft`, `amend_draft_with_rollback`, `init_draft_approval`)
//! is rejected, and `verify_draft_approval_snapshot` lets executors prove the
//! draft still matches what approvers signed.
//!
//! Releasing a snapshot is an explicit admin action that also discards the
//! collected approvals, so an edited draft always needs fresh approval.
//!
//! Snapshots hold only aggregate draft fields already stored on-chain; no
//! per-employee data or salary rows are captured.

use soroban_sdk::{
    contracterror, contractevent, contractimpl, contracttype, Address, BytesN, Env, Symbol, Vec,
};

use crate::signing::MultiStageApproval;
use crate::{
    ApprovalKey, ContractAddresses, DataKey, Payroll, PayrollArgs, PayrollClient, PayrollRunDraft,
    RunDraftState,
};

/// Storage key for locked draft approval snapshots.
///
/// Kept separate from [`DataKey`], which is past the Soroban contract-spec
/// ceiling of 50 cases.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DraftSnapshotKey {
    /// Locked approval snapshot for a draft id.
    Snapshot(u64),
}

/// Immutable record of the draft content approvers signed off on.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DraftApprovalSnapshot {
    pub draft_id: u64,
    /// Protected content hash the approval quorum was collected against.
    pub protected_content_hash: BytesN<32>,
    pub total_amount: i128,
    pub employee_count: u32,
    pub period_label: Symbol,
    /// Draft amendment counter at lock time; any later amendment bumps it.
    pub amendment_count: u32,
    /// Number of approvals that formed the quorum.
    pub approvals: u32,
    pub locked_at: u64,
    pub locked_by: Address,
}

/// Errors returned by draft approval snapshot locking (#648).
#[contracterror]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum DraftSnapshotError {
    /// Payroll has not been initialized.
    NotInitialized = 6480,
    /// The caller is not the configured payroll admin.
    Unauthorized = 6481,
    /// No payroll run draft exists for this id.
    DraftNotFound = 6482,
    /// Only `Pending` or `Finalized` drafts can be locked or released;
    /// submitted, cancelled, and expired drafts are already immutable.
    DraftNotLockable = 6483,
    /// The draft has no approval tracker. Call `init_draft_approval` first.
    ApprovalNotInitialized = 6484,
    /// The approval tracker has not reached its required approvals yet.
    ApprovalQuorumNotMet = 6485,
    /// A snapshot is already locked for this draft.
    SnapshotAlreadyLocked = 6486,
    /// No snapshot is locked for this draft.
    SnapshotNotFound = 6487,
    /// The draft's totals, period, or amendment counter no longer match the
    /// approved snapshot. Do not execute; investigate the change.
    DraftChangedSinceSnapshot = 6488,
    /// The approval tracker no longer matches the snapshot (different hash,
    /// or quorum lost). Do not execute; re-run approval.
    ApprovalChangedSinceSnapshot = 6489,
    /// The approval references a draft revision that has been superseded by
    /// a newer amendment. Re-run approval against the current revision.
    SupersededDraftRevision = 6490,
}

/// Emitted as `("payroll", "draft_snapshot_locked")`.
#[contractevent(topics = ["payroll", "draft_snapshot_locked"], data_format = "vec")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DraftSnapshotLocked {
    pub draft_id: u64,
    pub protected_content_hash: BytesN<32>,
    pub approvals: u32,
    pub locked_at: u64,
}

/// Emitted as `("payroll", "draft_snapshot_released")`.
#[contractevent(topics = ["payroll", "draft_snapshot_released"], data_format = "vec")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DraftSnapshotReleased {
    pub draft_id: u64,
    pub released_at: u64,
}

fn require_admin(e: &Env, admin: &Address) -> Result<(), DraftSnapshotError> {
    let addrs: ContractAddresses = e
        .storage()
        .persistent()
        .get(&DataKey::Addresses)
        .ok_or(DraftSnapshotError::NotInitialized)?;
    if admin != &addrs.admin {
        return Err(DraftSnapshotError::Unauthorized);
    }
    admin.require_auth();
    Ok(())
}

fn load_draft(e: &Env, draft_id: u64) -> Result<PayrollRunDraft, DraftSnapshotError> {
    e.storage()
        .persistent()
        .get(&DataKey::RunDraft(draft_id))
        .ok_or(DraftSnapshotError::DraftNotFound)
}

fn load_approval(e: &Env, draft_id: u64) -> Result<MultiStageApproval, DraftSnapshotError> {
    e.storage()
        .persistent()
        .get(&ApprovalKey::DraftApproval(draft_id))
        .ok_or(DraftSnapshotError::ApprovalNotInitialized)
}

fn load_snapshot(e: &Env, draft_id: u64) -> Option<DraftApprovalSnapshot> {
    e.storage()
        .persistent()
        .get(&DraftSnapshotKey::Snapshot(draft_id))
}

fn require_lockable_state(draft: &PayrollRunDraft) -> Result<(), DraftSnapshotError> {
    match draft.state {
        RunDraftState::Pending | RunDraftState::Finalized => Ok(()),
        _ => Err(DraftSnapshotError::DraftNotLockable),
    }
}

/// Whether a snapshot is currently locked for `draft_id`.
pub fn is_locked(e: &Env, draft_id: u64) -> bool {
    e.storage()
        .persistent()
        .has(&DraftSnapshotKey::Snapshot(draft_id))
}

/// Guard for flows that would change approved draft content.
pub(crate) fn require_snapshot_unlocked(e: &Env, draft_id: u64) {
    if is_locked(e, draft_id) {
        panic!(
            "Draft approval snapshot is locked: release it with release_draft_approval_snapshot (which resets approvals) before changing the draft"
        );
    }
}

/// Current revision of a draft's approved content (#876).
///
/// The revision is the draft's amendment counter: every amendment that
/// changes approved content bumps it, so an approval recorded against an
/// older revision is stale. Returns `None` when no draft exists.
pub fn current_draft_revision(e: &Env, draft_id: u64) -> Option<u32> {
    e.storage()
        .persistent()
        .get::<DataKey, PayrollRunDraft>(&DataKey::RunDraft(draft_id))
        .map(|draft| draft.amendment_count)
}

/// Guard for the approval path (#876).
///
/// Rejects an approval that references a draft revision other than the
/// draft's current revision, so a superseded draft can never collect fresh
/// approvals. The error carries no draft content, only the revision numbers.
pub(crate) fn require_current_draft_revision(
    e: &Env,
    draft_id: u64,
    referenced_revision: u32,
) -> Result<(), DraftSnapshotError> {
    let current = current_draft_revision(e, draft_id).ok_or(DraftSnapshotError::DraftNotFound)?;
    if referenced_revision != current {
        return Err(DraftSnapshotError::SupersededDraftRevision);
    }
    Ok(())
}

/// Compare the live draft and approval tracker against a locked snapshot.
pub fn verify_snapshot(
    e: &Env,
    draft_id: u64,
) -> Result<DraftApprovalSnapshot, DraftSnapshotError> {
    let snapshot = load_snapshot(e, draft_id).ok_or(DraftSnapshotError::SnapshotNotFound)?;
    let draft = load_draft(e, draft_id)?;
    if draft.total_amount != snapshot.total_amount
        || draft.employee_count != snapshot.employee_count
        || draft.period_label != snapshot.period_label
        || draft.amendment_count != snapshot.amendment_count
    {
        return Err(DraftSnapshotError::DraftChangedSinceSnapshot);
    }
    let approval =
        load_approval(e, draft_id).map_err(|_| DraftSnapshotError::ApprovalChangedSinceSnapshot)?;
    if approval.protected_content_hash != snapshot.protected_content_hash
        || !approval.is_locked
        || approval.current_approvals < snapshot.approvals
    {
        return Err(DraftSnapshotError::ApprovalChangedSinceSnapshot);
    }
    Ok(snapshot)
}

#[contractimpl]
impl Payroll {
    /// Lock a snapshot of an approved draft (#648).
    ///
    /// Requires the draft to be `Pending` or `Finalized` and its approval
    /// tracker to have reached quorum. After locking, edits to the draft's
    /// approved content are rejected until the snapshot is released.
    pub fn lock_draft_approval_snapshot(
        e: Env,
        admin: Address,
        draft_id: u64,
    ) -> Result<DraftApprovalSnapshot, DraftSnapshotError> {
        Self::require_not_paused(&e);
        require_admin(&e, &admin)?;
        let draft = load_draft(&e, draft_id)?;
        require_lockable_state(&draft)?;
        if is_locked(&e, draft_id) {
            return Err(DraftSnapshotError::SnapshotAlreadyLocked);
        }
        let approval = load_approval(&e, draft_id)?;
        if !approval.is_locked || approval.current_approvals < approval.required_approvals {
            return Err(DraftSnapshotError::ApprovalQuorumNotMet);
        }

        let snapshot = DraftApprovalSnapshot {
            draft_id,
            protected_content_hash: approval.protected_content_hash.clone(),
            total_amount: draft.total_amount,
            employee_count: draft.employee_count,
            period_label: draft.period_label,
            amendment_count: draft.amendment_count,
            approvals: approval.current_approvals,
            locked_at: e.ledger().timestamp(),
            locked_by: admin,
        };
        e.storage()
            .persistent()
            .set(&DraftSnapshotKey::Snapshot(draft_id), &snapshot);
        DraftSnapshotLocked {
            draft_id,
            protected_content_hash: snapshot.protected_content_hash.clone(),
            approvals: snapshot.approvals,
            locked_at: snapshot.locked_at,
        }
        .publish(&e);
        Ok(snapshot)
    }

    /// Release a locked snapshot so the draft can be corrected (#648).
    ///
    /// Every approval collected for the snapshotted revision is discarded,
    /// so the corrected draft must be approved again before it can be
    /// re-locked.
    pub fn release_draft_approval_snapshot(
        e: Env,
        admin: Address,
        draft_id: u64,
    ) -> Result<(), DraftSnapshotError> {
        Self::require_not_paused(&e);
        require_admin(&e, &admin)?;
        let draft = load_draft(&e, draft_id)?;
        require_lockable_state(&draft)?;
        if !is_locked(&e, draft_id) {
            return Err(DraftSnapshotError::SnapshotNotFound);
        }

        if let Ok(mut approval) = load_approval(&e, draft_id) {
            approval.current_approvals = 0;
            approval.current_stage = 0;
            approval.is_locked = false;
            approval.signers = Vec::new(&e);
            e.storage()
                .persistent()
                .set(&ApprovalKey::DraftApproval(draft_id), &approval);
        }
        e.storage()
            .persistent()
            .remove(&DraftSnapshotKey::Snapshot(draft_id));
        DraftSnapshotReleased {
            draft_id,
            released_at: e.ledger().timestamp(),
        }
        .publish(&e);
        Ok(())
    }

    /// Prove the draft still matches its locked approval snapshot (#648).
    ///
    /// Read-only; returns the snapshot when the draft and approval tracker
    /// are unchanged.
    pub fn verify_draft_approval_snapshot(
        e: Env,
        draft_id: u64,
    ) -> Result<DraftApprovalSnapshot, DraftSnapshotError> {
        verify_snapshot(&e, draft_id)
    }

    /// Return the locked approval snapshot for a draft, if any (#648).
    pub fn get_draft_approval_snapshot(e: Env, draft_id: u64) -> Option<DraftApprovalSnapshot> {
        load_snapshot(&e, draft_id)
    }

    /// Whether a draft's approved content is currently snapshot-locked (#648).
    pub fn is_draft_snapshot_locked(e: Env, draft_id: u64) -> bool {
        is_locked(&e, draft_id)
    }

    /// Current revision of a draft's approved content (#876).
    ///
    /// Read-only; returns `None` when no draft exists for `draft_id`.
    pub fn get_draft_revision(e: Env, draft_id: u64) -> Option<u32> {
        current_draft_revision(&e, draft_id)
    }
}
