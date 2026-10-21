//! Payroll responsibility delegation audit (#714).
//!
//! A pending payroll run has one responsible party: its admin.
//! `transfer_pending_run_admin` lets the current admin hand that responsibility
//! to another address. Before this module the handover left only an event, and
//! the run itself kept just the current admin. Once the run was finalized,
//! cancelled, or expired, nothing on chain said who had been responsible for it
//! along the way, and an auditor had to rebuild the chain of custody from an
//! indexer.
//!
//! This module keeps that chain on chain. Every handover appends one
//! [`DelegationRecord`] to the run's audit trail, and the trail outlives the
//! pending run. The trail is:
//!
//! - **Append-only.** Records are written once and never changed or removed.
//! - **Bounded.** At most [`MAX_DELEGATIONS_PER_RUN`] handovers per run, so the
//!   trail and the work to verify it stay bounded.
//! - **Verifiable.** [`verify_records`] checks that the records are numbered
//!   without gaps, that each handover starts from the previous one's delegate,
//!   and, while the run is still pending, that the last delegate is the admin
//!   the run currently has.
//!
//! The trail begins at the first handover: the first record's delegator is the
//! run's admin at the time it was prepared, so the chain of custody is complete
//! without recording anything at preparation.
//!
//! Storage, authorization, and events live in [`crate::Payroll`]; the decisions
//! here are pure so they can be unit-tested without a Soroban host.
//!
//! Privacy: only addresses, sequence numbers, and ledger times are stored and
//! emitted. No salary amount, employee identity, commitment, or proof material
//! is read or surfaced.

use soroban_sdk::{contracttype, Address, Env, Vec};

/// Most handovers recorded for a single run.
///
/// A run is prepared, handed to whoever will finalize it, and finalized. A
/// hundred handovers is far beyond any real workflow; the ceiling keeps the
/// trail and the cost of verifying it bounded.
pub const MAX_DELEGATIONS_PER_RUN: u32 = 100;

/// Most records returned by one page of
/// [`crate::Payroll::get_run_delegation_audit`].
pub const MAX_DELEGATION_AUDIT_PAGE: u32 = 50;

/// Storage keys for the delegation audit trail.
///
/// Deliberately separate from [`crate::DataKey`]: that enum is already past the
/// Soroban contract-spec ceiling of 50 cases, so this feature is keyed on its
/// own enum to leave every existing storage key untouched.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DelegationAuditKey {
    /// Number of handovers recorded for a run.
    Count(u64),
    /// The handover with this 1-based sequence number for a run.
    Entry(u64, u32),
}

/// One recorded handover of a run's responsibility.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DelegationRecord {
    pub run_id: u64,
    /// 1-based position in the run's trail.
    pub sequence: u32,
    /// The admin who handed responsibility over (and authorized the call).
    pub delegator: Address,
    /// The admin who took responsibility.
    pub delegate: Address,
    /// Ledger timestamp of the handover.
    pub delegated_at: u64,
    /// Ledger sequence of the handover.
    pub ledger_sequence: u32,
}

/// What [`verify_records`] found wrong with a trail.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum DelegationAuditIssue {
    /// The trail is consistent.
    ///
    /// A sentinel rather than wrapping this enum in `Option` in
    /// [`DelegationAuditVerdict`]: soroban-sdk's `#[repr(u32)]` enum codegen
    /// does not support `Option<T>` as a struct field.
    NoIssue = 0,
    /// A record is missing or out of order: sequence numbers must run 1, 2, 3...
    SequenceGap = 1,
    /// A handover does not start from the previous handover's delegate.
    BrokenChain = 2,
    /// A record hands responsibility from an address to itself.
    SelfDelegation = 3,
    /// The last delegate is not the admin the pending run currently has.
    CurrentHolderMismatch = 4,
}

impl DelegationAuditIssue {
    /// Stable code for logs, dashboards, and tests.
    pub fn as_str(&self) -> &'static str {
        match self {
            DelegationAuditIssue::NoIssue => "no_issue",
            DelegationAuditIssue::SequenceGap => "sequence_gap",
            DelegationAuditIssue::BrokenChain => "broken_chain",
            DelegationAuditIssue::SelfDelegation => "self_delegation",
            DelegationAuditIssue::CurrentHolderMismatch => "current_holder_mismatch",
        }
    }
}

/// Result of verifying a run's delegation trail.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DelegationAuditVerdict {
    pub run_id: u64,
    /// Number of handovers recorded.
    pub entries: u32,
    /// `true` when [`Self::issue`] is [`DelegationAuditIssue::NoIssue`].
    pub consistent: bool,
    pub issue: DelegationAuditIssue,
    /// Sequence number of the record the issue was found at; `0` when consistent.
    pub issue_at: u32,
    /// Whether the run is still pending (so its current admin is known).
    pub run_pending: bool,
    /// The run's current admin while pending; otherwise the last delegate, or
    /// `None` if the run was never handed over.
    pub current_holder: Option<Address>,
}

/// Why a handover may not be recorded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DelegationIssue {
    /// The run already has [`MAX_DELEGATIONS_PER_RUN`] handovers.
    LimitReached,
}

/// Whether one more handover may be recorded on a run that already has `count`.
pub fn check_can_record(count: u32) -> Result<u32, DelegationIssue> {
    if count >= MAX_DELEGATIONS_PER_RUN {
        return Err(DelegationIssue::LimitReached);
    }
    Ok(count + 1)
}

/// Clamp a requested page size to `0..=MAX_DELEGATION_AUDIT_PAGE`.
pub fn clamp_page_size(limit: u32) -> u32 {
    limit.min(MAX_DELEGATION_AUDIT_PAGE)
}

/// Check a run's records, oldest first.
///
/// `current_admin` is the admin of the run if it is still pending, which the
/// last handover must have ended on; pass `None` for a run that no longer
/// exists. Returns the first problem found and the sequence it was found at,
/// or `(NoIssue, 0)`.
pub fn verify_records(
    records: &Vec<DelegationRecord>,
    current_admin: Option<&Address>,
) -> (DelegationAuditIssue, u32) {
    let mut previous: Option<DelegationRecord> = None;
    let mut index: u32 = 0;
    for record in records.iter() {
        index += 1;
        if record.sequence != index {
            return (DelegationAuditIssue::SequenceGap, index);
        }
        if record.delegator == record.delegate {
            return (DelegationAuditIssue::SelfDelegation, index);
        }
        if let Some(prev) = &previous {
            if record.delegator != prev.delegate {
                return (DelegationAuditIssue::BrokenChain, index);
            }
        }
        previous = Some(record);
    }

    if let (Some(last), Some(admin)) = (&previous, current_admin) {
        if &last.delegate != admin {
            return (DelegationAuditIssue::CurrentHolderMismatch, last.sequence);
        }
    }
    (DelegationAuditIssue::NoIssue, 0)
}

/// Number of handovers recorded for `run_id`.
pub fn count(e: &Env, run_id: u64) -> u32 {
    e.storage()
        .persistent()
        .get(&DelegationAuditKey::Count(run_id))
        .unwrap_or(0)
}

/// The handover with `sequence` (1-based) for `run_id`, if recorded.
pub fn entry(e: &Env, run_id: u64, sequence: u32) -> Option<DelegationRecord> {
    e.storage()
        .persistent()
        .get(&DelegationAuditKey::Entry(run_id, sequence))
}

/// Append a handover to the run's trail and return it.
///
/// The caller has already authorized `delegator` and checked it is the run's
/// current admin; this only writes. Panics when the trail is full.
pub fn append(e: &Env, run_id: u64, delegator: &Address, delegate: &Address) -> DelegationRecord {
    let current = count(e, run_id);
    let sequence = match check_can_record(current) {
        Ok(sequence) => sequence,
        Err(DelegationIssue::LimitReached) => panic!(
            "Delegation limit reached: this run has already been handed over {} times; finalize or cancel it instead of transferring again",
            MAX_DELEGATIONS_PER_RUN
        ),
    };

    let record = DelegationRecord {
        run_id,
        sequence,
        delegator: delegator.clone(),
        delegate: delegate.clone(),
        delegated_at: e.ledger().timestamp(),
        ledger_sequence: e.ledger().sequence(),
    };
    e.storage()
        .persistent()
        .set(&DelegationAuditKey::Entry(run_id, sequence), &record);
    e.storage()
        .persistent()
        .set(&DelegationAuditKey::Count(run_id), &sequence);
    record
}

/// Records with a sequence greater than `after`, oldest first, at most
/// `limit` (clamped to [`MAX_DELEGATION_AUDIT_PAGE`]) of them.
pub fn page(e: &Env, run_id: u64, after: u32, limit: u32) -> Vec<DelegationRecord> {
    let mut out = Vec::new(e);
    let total = count(e, run_id);
    let limit = clamp_page_size(limit);
    let mut sequence = after.saturating_add(1);
    while sequence <= total && out.len() < limit {
        if let Some(record) = entry(e, run_id, sequence) {
            out.push_back(record);
        }
        sequence += 1;
    }
    out
}

/// Every record for `run_id`, oldest first. Bounded by [`MAX_DELEGATIONS_PER_RUN`].
pub fn all(e: &Env, run_id: u64) -> Vec<DelegationRecord> {
    let mut out = Vec::new(e);
    for sequence in 1..=count(e, run_id) {
        if let Some(record) = entry(e, run_id, sequence) {
            out.push_back(record);
        }
    }
    out
}
