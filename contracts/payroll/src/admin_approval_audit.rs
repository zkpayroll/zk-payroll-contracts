//! Contract administrator approval audit history (#791).
//!
//! Some decisions in this contract are taken by the contract admin alone:
//! finalizing a prepared payroll run (which releases its payments) and
//! approving a pending emergency treasury withdrawal. Before this module those
//! approvals left only events, so an auditor had to rebuild who approved what,
//! and when, from an indexer.
//!
//! This module keeps that history on chain. Every admin approval appends one
//! [`AdminApprovalRecord`] to a contract-wide history. The history is:
//!
//! - **Append-only.** Records are written once and never changed or removed.
//! - **Ordered.** Records are numbered 1, 2, 3... in the order they happened.
//! - **Bounded to read.** [`page`] returns at most [`MAX_ADMIN_APPROVAL_PAGE`]
//!   records per call and rejects an empty or oversized page with a typed
//!   [`AdminApprovalAuditError`] instead of silently clamping it.
//!
//! A record is written only after the approving entrypoint has authorized the
//! admin and passed every check, in the same invocation, so a rejected
//! approval writes nothing.
//!
//! Privacy: only the approver address, the kind of approval, an opaque target
//! id, and ledger time are stored and emitted. No salary amount, employee
//! identity, commitment, or proof material is read or surfaced.

use soroban_sdk::{contracterror, contractevent, contracttype, Address, Env, Vec};

/// Most records returned by one page of
/// [`crate::Payroll::get_admin_approval_history`].
pub const MAX_ADMIN_APPROVAL_PAGE: u32 = 50;

/// Storage keys for the admin approval history.
///
/// Deliberately separate from [`crate::DataKey`]: that enum is already past the
/// Soroban contract-spec ceiling of 50 cases, so this feature is keyed on its
/// own enum to leave every existing storage key untouched.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdminApprovalAuditKey {
    /// Number of admin approvals recorded.
    Count,
    /// The approval with this 1-based sequence number.
    Entry(u64),
}

/// What the admin approved.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum AdminApprovalKind {
    /// `finalize_payroll_run`: the admin approved a prepared run for
    /// execution. `target_id` is the run id.
    PayrollRunFinalized = 1,
    /// `approve_emergency_withdrawal`: the admin approved the pending
    /// emergency withdrawal. There is at most one pending request, so
    /// `target_id` is `0`.
    EmergencyWithdrawal = 2,
}

/// One recorded admin approval.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdminApprovalRecord {
    /// 1-based position in the history.
    pub sequence: u64,
    /// The admin who approved (and authorized the call).
    pub approver: Address,
    pub kind: AdminApprovalKind,
    /// The approved object's id (see [`AdminApprovalKind`]); `0` when the
    /// approval has no separate target.
    pub target_id: u64,
    /// Ledger timestamp of the approval.
    pub approved_at: u64,
    /// Ledger sequence of the approval.
    pub ledger_sequence: u32,
}

/// Emitted as `("payroll", "admin_approval_recorded")` for every record, with
/// data `(sequence, approver, kind as u32, target_id, approved_at)`.
#[contractevent(topics = ["payroll", "admin_approval_recorded"], data_format = "vec")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminApprovalRecorded {
    pub sequence: u64,
    pub approver: Address,
    pub kind: u32,
    pub target_id: u64,
    pub approved_at: u64,
}

/// Why a history page request was rejected. Codes are scoped to issue #791.
#[contracterror]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum AdminApprovalAuditError {
    /// `limit` was `0`; ask for at least one record.
    PageLimitZero = 7910,
    /// `limit` was above [`MAX_ADMIN_APPROVAL_PAGE`]; page through the history
    /// in smaller requests.
    PageLimitTooLarge = 7911,
}

/// Validate a requested page size.
pub fn check_page_limit(limit: u32) -> Result<u32, AdminApprovalAuditError> {
    if limit == 0 {
        return Err(AdminApprovalAuditError::PageLimitZero);
    }
    if limit > MAX_ADMIN_APPROVAL_PAGE {
        return Err(AdminApprovalAuditError::PageLimitTooLarge);
    }
    Ok(limit)
}

/// Number of admin approvals recorded.
pub fn count(e: &Env) -> u64 {
    e.storage()
        .persistent()
        .get(&AdminApprovalAuditKey::Count)
        .unwrap_or(0)
}

/// The approval with `sequence` (1-based), if recorded.
pub fn entry(e: &Env, sequence: u64) -> Option<AdminApprovalRecord> {
    e.storage()
        .persistent()
        .get(&AdminApprovalAuditKey::Entry(sequence))
}

/// Append an approval to the history, emit `admin_approval_recorded`, and
/// return the record.
///
/// The caller has already authorized `approver` as the contract admin and
/// passed every check of the approving entrypoint; this only writes.
pub fn record(
    e: &Env,
    approver: &Address,
    kind: AdminApprovalKind,
    target_id: u64,
) -> AdminApprovalRecord {
    let sequence = count(e).saturating_add(1);
    let record = AdminApprovalRecord {
        sequence,
        approver: approver.clone(),
        kind,
        target_id,
        approved_at: e.ledger().timestamp(),
        ledger_sequence: e.ledger().sequence(),
    };
    e.storage()
        .persistent()
        .set(&AdminApprovalAuditKey::Entry(sequence), &record);
    e.storage()
        .persistent()
        .set(&AdminApprovalAuditKey::Count, &sequence);

    AdminApprovalRecorded {
        sequence: record.sequence,
        approver: record.approver.clone(),
        kind: record.kind as u32,
        target_id: record.target_id,
        approved_at: record.approved_at,
    }
    .publish(e);
    record
}

/// Records with a sequence greater than `after_sequence`, oldest first, at
/// most `limit` of them. `after_sequence` at or past the end yields an empty
/// page.
pub fn page(
    e: &Env,
    after_sequence: u64,
    limit: u32,
) -> Result<Vec<AdminApprovalRecord>, AdminApprovalAuditError> {
    let limit = check_page_limit(limit)?;
    let total = count(e);
    let mut out = Vec::new(e);
    let mut sequence = after_sequence.saturating_add(1);
    while sequence <= total && out.len() < limit {
        if let Some(record) = entry(e, sequence) {
            out.push_back(record);
        }
        sequence += 1;
    }
    Ok(out)
}
