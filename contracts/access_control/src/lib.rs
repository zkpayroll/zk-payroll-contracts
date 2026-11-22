#![no_std]

//! Employer role change enforcement for the ZK Payroll system (issues #950, #951).
//!
//! This module owns:
//!
//! * [`EmployerRoleError`] — stable, typed errors for every failure path in
//!   employer role transitions.  Error codes are assigned from the 800–899
//!   range (reserved for access-control / employer-role errors) and must
//!   never change once released.
//!
//! * [`EmployerRoleRecord`] — the on-chain record that the access control
//!   layer maintains for each registered employer.
//!
//! * [`PendingRoleTransfer`] — the two-step transfer proposal stored while a
//!   handoff is in-flight.
//!
//! * Free functions that implement every guarded state transition.  Callers
//!   (registry, payroll contract, etc.) import these functions rather than
//!   duplicating the checks inline.
//!
//! # Privacy contract
//!
//! None of the error variants, event data, or preflight return values carry
//! salary amounts, employee addresses, commitment hashes, or any other
//! private payroll data.  Failure messages name only the failing caller or
//! the role kind involved.

use soroban_sdk::{contracterror, contracttype, Address, Env, Symbol};

// ─────────────────────────────────────────────────────────────────────────────
// Error types  (#951)
// ─────────────────────────────────────────────────────────────────────────────

/// Typed errors for employer role transitions.
///
/// Codes 800–899 are reserved for employer-role / access-control errors.
/// Each code is permanently assigned and must not be reused.
///
/// All variants are intentionally free of salary, commitment, and employee
/// data so that any error surfaced to an SDK or dashboard is safe to log and
/// display verbatim.
#[contracterror]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum EmployerRoleError {
    /// The company record does not exist.
    CompanyNotFound = 800,

    /// The caller is not the registered employer for this company and cannot
    /// initiate or complete a role change.
    UnauthorizedEmployer = 801,

    /// A role transfer for this company is already in progress.  The pending
    /// transfer must be accepted or cancelled before another can be proposed.
    PendingTransferExists = 802,

    /// No pending role transfer exists; nothing to accept or cancel.
    NoPendingTransfer = 803,

    /// The incoming address does not match the pending transfer target.
    InvalidTransferTarget = 804,

    /// The employer role for this company has been revoked.  Revoked employers
    /// cannot initiate new role changes or any employer-only operations.
    EmployerRevoked = 805,

    /// An employer cannot transfer the role to themselves; that is a no-op.
    SelfTransferNotAllowed = 806,

    /// The employer role is already active for this company; re-granting is not
    /// supported.
    AlreadyActive = 807,
}

impl EmployerRoleError {
    /// Returns a fixed, actionable message that is safe to surface to end users
    /// and operators.
    ///
    /// The message never contains salary, employee, or commitment data.
    pub fn message(self) -> &'static str {
        match self {
            Self::CompanyNotFound => {
                "Company not found. Check the company ID and try again."
            }
            Self::UnauthorizedEmployer => {
                "Only the registered employer may perform this action. \
                 Check that the signing address matches the company's employer record."
            }
            Self::PendingTransferExists => {
                "A role transfer is already pending for this company. \
                 Accept or cancel the existing transfer before proposing a new one."
            }
            Self::NoPendingTransfer => {
                "No pending role transfer exists for this company. \
                 Propose a transfer before trying to accept or cancel one."
            }
            Self::InvalidTransferTarget => {
                "The accepting address does not match the pending transfer target. \
                 The correct recipient must sign the acceptance."
            }
            Self::EmployerRevoked => {
                "The employer role for this company has been revoked. \
                 Contact the registry admin to restore access through the authorized flow."
            }
            Self::SelfTransferNotAllowed => {
                "The transfer target must differ from the current employer. \
                 Propose a transfer to a different address."
            }
            Self::AlreadyActive => {
                "The employer role is already active for this company. \
                 No action is required."
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Storage types
// ─────────────────────────────────────────────────────────────────────────────

/// On-chain employer role record for a company.
///
/// Stored under `DataKey::EmployerRole(company_id)`.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmployerRoleRecord {
    /// Current employer address for this company.
    pub employer: Address,
    /// Whether the employer role has been administratively revoked.
    pub revoked: bool,
    /// Ledger timestamp of the last confirmed role change (initial grant or
    /// most recent accepted transfer).  Zero for newly registered companies.
    pub last_changed_at: u64,
}

/// A two-step employer role transfer that is in-flight.
///
/// Stored under `DataKey::PendingEmployerTransfer(company_id)` while the
/// incoming employer has not yet accepted.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingRoleTransfer {
    /// The incoming employer who must call `accept_employer_role_transfer`.
    pub incoming: Address,
    /// The current employer who initiated the transfer.
    pub initiated_by: Address,
    /// Ledger timestamp when the proposal was recorded.
    pub proposed_at: u64,
}

/// Storage discriminants for the access-control module.
#[contracttype]
#[derive(Clone, Debug)]
pub enum DataKey {
    /// Employer role record keyed by company ID.
    EmployerRole(u64),
    /// In-flight two-step employer role transfer keyed by company ID.
    PendingEmployerTransfer(u64),
}

// ─────────────────────────────────────────────────────────────────────────────
// Guards and state-transition functions  (#950)
// ─────────────────────────────────────────────────────────────────────────────

/// Assert that the caller is the active, non-revoked employer for `company_id`.
///
/// Panics with [`EmployerRoleError::CompanyNotFound`],
/// [`EmployerRoleError::EmployerRevoked`], or
/// [`EmployerRoleError::UnauthorizedEmployer`] on failure.
/// Calls `caller.require_auth()` on success so the Soroban host records the
/// authorization.
///
/// # Privacy
/// The panic message names only the error code; it carries no salary,
/// employee, or commitment data.
pub fn require_active_employer(env: &Env, company_id: u64, caller: &Address) {
    let record = get_employer_role(env, company_id);
    if record.revoked {
        panic_with_error!(env, EmployerRoleError::EmployerRevoked);
    }
    if *caller != record.employer {
        panic_with_error!(env, EmployerRoleError::UnauthorizedEmployer);
    }
    caller.require_auth();
}

/// Register the initial employer role for a newly created company.
///
/// Panics with [`EmployerRoleError::AlreadyActive`] if a role record already
/// exists for `company_id`.
pub fn register_employer(env: &Env, company_id: u64, employer: &Address) {
    let key = DataKey::EmployerRole(company_id);
    if env.storage().persistent().has(&key) {
        panic_with_error!(env, EmployerRoleError::AlreadyActive);
    }
    let record = EmployerRoleRecord {
        employer: employer.clone(),
        revoked: false,
        last_changed_at: env.ledger().timestamp(),
    };
    env.storage().persistent().set(&key, &record);
    emit_role_registered(env, company_id, employer);
}

/// Propose a two-step employer role transfer (step 1 of 2).
///
/// The current employer proposes `incoming` as successor.  The proposal is
/// stored and the `incoming` address must call [`accept_employer_role_transfer`]
/// to complete the handoff.
///
/// # Failure modes
/// * [`EmployerRoleError::CompanyNotFound`] — no role record for `company_id`.
/// * [`EmployerRoleError::EmployerRevoked`] — employer is already revoked.
/// * [`EmployerRoleError::UnauthorizedEmployer`] — caller ≠ current employer.
/// * [`EmployerRoleError::SelfTransferNotAllowed`] — `incoming` == current
///   employer.
/// * [`EmployerRoleError::PendingTransferExists`] — a prior proposal is still
///   open.
pub fn propose_employer_role_transfer(
    env: &Env,
    company_id: u64,
    current_employer: &Address,
    incoming: &Address,
) {
    let record = get_employer_role(env, company_id);
    if record.revoked {
        panic_with_error!(env, EmployerRoleError::EmployerRevoked);
    }
    if *current_employer != record.employer {
        panic_with_error!(env, EmployerRoleError::UnauthorizedEmployer);
    }
    current_employer.require_auth();

    if *incoming == record.employer {
        panic_with_error!(env, EmployerRoleError::SelfTransferNotAllowed);
    }

    let pending_key = DataKey::PendingEmployerTransfer(company_id);
    if env.storage().persistent().has(&pending_key) {
        panic_with_error!(env, EmployerRoleError::PendingTransferExists);
    }

    let proposal = PendingRoleTransfer {
        incoming: incoming.clone(),
        initiated_by: current_employer.clone(),
        proposed_at: env.ledger().timestamp(),
    };
    env.storage().persistent().set(&pending_key, &proposal);
    emit_transfer_proposed(env, company_id, current_employer, incoming);
}

/// Accept a pending employer role transfer (step 2 of 2).
///
/// Only the `incoming` address named in the proposal may call this.  On
/// success the employer record is updated and the pending proposal is cleared.
///
/// # Failure modes
/// * [`EmployerRoleError::CompanyNotFound`] — no role record.
/// * [`EmployerRoleError::EmployerRevoked`] — role is revoked (transfer still
///   blocked; must restore via admin flow first).
/// * [`EmployerRoleError::NoPendingTransfer`] — nothing to accept.
/// * [`EmployerRoleError::InvalidTransferTarget`] — `incoming` ≠ proposal
///   target.
pub fn accept_employer_role_transfer(env: &Env, company_id: u64, incoming: &Address) {
    let pending_key = DataKey::PendingEmployerTransfer(company_id);
    let proposal: PendingRoleTransfer = env
        .storage()
        .persistent()
        .get(&pending_key)
        .unwrap_or_else(|| panic_with_error!(env, EmployerRoleError::NoPendingTransfer));

    if *incoming != proposal.incoming {
        panic_with_error!(env, EmployerRoleError::InvalidTransferTarget);
    }

    // Verify the base record still exists and is non-revoked.
    let mut record = get_employer_role(env, company_id);
    if record.revoked {
        panic_with_error!(env, EmployerRoleError::EmployerRevoked);
    }

    incoming.require_auth();

    let old_employer = record.employer.clone();
    record.employer = incoming.clone();
    record.last_changed_at = env.ledger().timestamp();

    env.storage()
        .persistent()
        .set(&DataKey::EmployerRole(company_id), &record);
    env.storage().persistent().remove(&pending_key);

    emit_transfer_accepted(env, company_id, &old_employer, incoming);
}

/// Cancel a pending employer role transfer.
///
/// Only the current employer (the one who proposed the transfer) may cancel it.
///
/// # Failure modes
/// * [`EmployerRoleError::CompanyNotFound`] — no role record.
/// * [`EmployerRoleError::EmployerRevoked`] — role is revoked.
/// * [`EmployerRoleError::UnauthorizedEmployer`] — caller ≠ current employer.
/// * [`EmployerRoleError::NoPendingTransfer`] — nothing to cancel.
pub fn cancel_employer_role_transfer(
    env: &Env,
    company_id: u64,
    current_employer: &Address,
) {
    let record = get_employer_role(env, company_id);
    if record.revoked {
        panic_with_error!(env, EmployerRoleError::EmployerRevoked);
    }
    if *current_employer != record.employer {
        panic_with_error!(env, EmployerRoleError::UnauthorizedEmployer);
    }
    current_employer.require_auth();

    let pending_key = DataKey::PendingEmployerTransfer(company_id);
    if !env.storage().persistent().has(&pending_key) {
        panic_with_error!(env, EmployerRoleError::NoPendingTransfer);
    }
    env.storage().persistent().remove(&pending_key);
    emit_transfer_cancelled(env, company_id, current_employer);
}

/// Revoke the employer role for `company_id`.
///
/// After revocation all employer-gated operations on this company are blocked.
/// The company record and historical payroll state are preserved — only the
/// active employer authorization is lifted.
///
/// # Failure modes
/// * [`EmployerRoleError::CompanyNotFound`] — no role record.
/// * [`EmployerRoleError::UnauthorizedEmployer`] — caller ≠ current employer.
/// * [`EmployerRoleError::EmployerRevoked`] — already revoked.
pub fn revoke_employer_role(env: &Env, company_id: u64, current_employer: &Address) {
    let mut record = get_employer_role(env, company_id);
    if record.revoked {
        panic_with_error!(env, EmployerRoleError::EmployerRevoked);
    }
    if *current_employer != record.employer {
        panic_with_error!(env, EmployerRoleError::UnauthorizedEmployer);
    }
    current_employer.require_auth();

    record.revoked = true;
    record.last_changed_at = env.ledger().timestamp();
    env.storage()
        .persistent()
        .set(&DataKey::EmployerRole(company_id), &record);
    emit_role_revoked(env, company_id, current_employer);
}

// ─────────────────────────────────────────────────────────────────────────────
// Read-only helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Return the employer role record for `company_id`.
///
/// Panics with [`EmployerRoleError::CompanyNotFound`] when absent.
pub fn get_employer_role(env: &Env, company_id: u64) -> EmployerRoleRecord {
    env.storage()
        .persistent()
        .get(&DataKey::EmployerRole(company_id))
        .unwrap_or_else(|| panic_with_error!(env, EmployerRoleError::CompanyNotFound))
}

/// Return any in-flight role transfer proposal for `company_id`.
pub fn get_pending_transfer(env: &Env, company_id: u64) -> Option<PendingRoleTransfer> {
    env.storage()
        .persistent()
        .get(&DataKey::PendingEmployerTransfer(company_id))
}

/// Return `true` iff the employer role for `company_id` is active (not revoked)
/// and `address` matches the registered employer.
pub fn is_active_employer(env: &Env, company_id: u64, address: &Address) -> bool {
    match env
        .storage()
        .persistent()
        .get::<DataKey, EmployerRoleRecord>(&DataKey::EmployerRole(company_id))
    {
        Some(record) => !record.revoked && record.employer == *address,
        None => false,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Private event helpers
// ─────────────────────────────────────────────────────────────────────────────

fn emit_role_registered(env: &Env, company_id: u64, employer: &Address) {
    env.events().publish(
        (Symbol::new(env, "employer_role_registered"), company_id),
        (employer.clone(), env.ledger().timestamp()),
    );
}

fn emit_transfer_proposed(
    env: &Env,
    company_id: u64,
    current: &Address,
    incoming: &Address,
) {
    env.events().publish(
        (Symbol::new(env, "employer_role_transfer_proposed"), company_id),
        (current.clone(), incoming.clone(), env.ledger().timestamp()),
    );
}

fn emit_transfer_accepted(
    env: &Env,
    company_id: u64,
    old_employer: &Address,
    new_employer: &Address,
) {
    env.events().publish(
        (Symbol::new(env, "employer_role_transfer_accepted"), company_id),
        (
            old_employer.clone(),
            new_employer.clone(),
            env.ledger().timestamp(),
        ),
    );
}

fn emit_transfer_cancelled(env: &Env, company_id: u64, employer: &Address) {
    env.events().publish(
        (Symbol::new(env, "employer_role_transfer_cancelled"), company_id),
        (employer.clone(), env.ledger().timestamp()),
    );
}

fn emit_role_revoked(env: &Env, company_id: u64, employer: &Address) {
    env.events().publish(
        (Symbol::new(env, "employer_role_revoked"), company_id),
        (employer.clone(), env.ledger().timestamp()),
    );
}
