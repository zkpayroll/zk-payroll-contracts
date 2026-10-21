//! Employee consent commitment lifecycle (#350).
//!
//! Privacy-first payroll requires proof that an employee has consented to be
//! enrolled in private payroll flows. This module records consent commitments
//! keyed by (employer, employee) pairs, enforces that an active consent exists
//! before payroll enrollment, and supports replacement and revocation lifecycle
//! transitions.
//!
//! Design principles:
//! - **Active consent required before enrollment.** Employees cannot be
//!   enrolled in payroll without a recorded active consent commitment.
//! - **Consent replacement.** A new `record_consent` call supersedes any
//!   existing active consent for the same (employer, employee) pair, keeping
//!   only one active record at a time.
//! - **Revocation is terminal.** A revoked consent blocks future enrollment
//!   until a fresh consent is recorded.
//! - **Privacy by design.** Events carry only addresses and state transitions —
//!   never personal data, signed documents, or salary information.
//!
//! Storage is keyed by a separate `ConsentKey` enum to avoid exhausting the
//! `DataKey` variant ceiling.

use soroban_sdk::{contracttype, symbol_short, Address, BytesN, Env, Symbol};

/// Lifecycle state of an employee consent commitment.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum ConsentState {
    /// Consent is valid and active; the employee may be enrolled in payroll.
    Active = 0,
    /// Consent was explicitly revoked; the employee cannot be enrolled until
    /// a fresh consent commitment is recorded.
    Revoked = 1,
    /// Consent was superseded by a newer commitment from the same employee
    /// under the same employer. Terminal for this record; the replacement is
    /// `Active`.
    Superseded = 2,
}

/// A recorded employee consent commitment.
///
/// The `commitment_hash` is a ZK commitment to off-chain consent material
/// (e.g. a hash of a signed employment agreement). The contract never stores
/// the underlying document — only the commitment.
///
/// Privacy note: carries only addresses, a commitment hash, state, and
/// timestamps. No personal data, salary values, or document contents are stored.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsentCommitment {
    /// The employee this consent applies to.
    pub employee: Address,
    /// The employer under whom consent was recorded.
    pub employer: Address,
    /// ZK commitment to the off-chain consent artifact.
    pub commitment_hash: BytesN<32>,
    /// Current lifecycle state.
    pub state: ConsentState,
    /// Ledger timestamp when consent was first recorded.
    pub created_at: u64,
    /// Ledger timestamp of the last state update.
    pub updated_at: u64,
}

/// Why a consent operation was rejected.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum ConsentError {
    /// The employee has no active consent commitment; enrollment is blocked.
    NoActiveConsent = 1,
    /// The consent is already in the `Revoked` state.
    ConsentAlreadyRevoked = 2,
    /// No consent record exists for this (employer, employee) pair.
    ConsentNotFound = 3,
    /// The caller is not authorized to perform the requested consent action.
    UnauthorizedConsentAction = 4,
    /// The commitment hash is the zero hash, which is not a valid commitment.
    InvalidCommitmentHash = 5,
}

impl ConsentError {
    pub fn code(self) -> u32 {
        self as u32
    }
}

/// Storage keys for consent commitment records.
///
/// Deliberately separate from [`crate::DataKey`] to avoid exhausting the
/// variant ceiling of that enum.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConsentKey {
    /// Active (or most recently updated) consent record for an
    /// (employer, employee) pair.
    EmployeeConsent(Address, Address),
}

// ── Zero-hash sentinel ────────────────────────────────────────────────────────

/// Return `true` when every byte of `hash` is zero.
///
/// The zero hash is used as a sentinel meaning "no commitment"; it is not a
/// valid ZK commitment and is rejected by [`record_consent`].
fn commitment_is_zero(e: &Env, hash: &BytesN<32>) -> bool {
    hash == &BytesN::from_array(e, &[0u8; 32])
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Record (or replace) an employee consent commitment.
///
/// If an active consent already exists for this (employer, employee) pair, it
/// is transitioned to `Superseded` and a fresh `Active` record is written.
/// If a revoked record exists, it is overwritten with a new `Active` record
/// (re-consent after revocation).
///
/// Validates:
/// - `employer` matches the caller authorization
/// - `commitment_hash` is not the zero hash
///
/// Requires `employer.require_auth()`.
/// Emits `("registry", "consent_recorded")`.
pub fn record_consent(
    e: &Env,
    employer: Address,
    employee: Address,
    commitment_hash: BytesN<32>,
) {
    employer.require_auth();

    if commitment_is_zero(e, &commitment_hash) {
        panic!(
            "Invalid commitment hash: the zero hash is not a valid consent commitment (ConsentError::{})",
            ConsentError::InvalidCommitmentHash.code()
        );
    }

    let now = e.ledger().timestamp();
    let key = ConsentKey::EmployeeConsent(employer.clone(), employee.clone());

    // Determine created_at: preserve original timestamp on re-consent.
    let created_at = e
        .storage()
        .persistent()
        .get::<ConsentKey, ConsentCommitment>(&key)
        .map(|existing| existing.created_at)
        .unwrap_or(now);

    let record = ConsentCommitment {
        employee: employee.clone(),
        employer: employer.clone(),
        commitment_hash: commitment_hash.clone(),
        state: ConsentState::Active,
        created_at,
        updated_at: now,
    };

    e.storage().persistent().set(&key, &record);

    e.events().publish(
        (
            symbol_short!("registry"),
            Symbol::new(e, "consent_recorded"),
        ),
        (employer, employee, commitment_hash, now),
    );
}

/// Revoke the active consent commitment for an employee.
///
/// Transitions the record from `Active` to `Revoked`. A revoked employee
/// cannot be re-enrolled until `record_consent` is called again.
///
/// Panics if:
/// - No consent record exists (`ConsentError::ConsentNotFound`)
/// - The consent is already revoked (`ConsentError::ConsentAlreadyRevoked`)
///
/// Requires `employer.require_auth()`.
/// Emits `("registry", "consent_revoked")`.
pub fn revoke_consent(e: &Env, employer: Address, employee: Address) {
    employer.require_auth();

    let key = ConsentKey::EmployeeConsent(employer.clone(), employee.clone());
    let mut record: ConsentCommitment = e
        .storage()
        .persistent()
        .get(&key)
        .unwrap_or_else(|| {
            panic!(
                "Consent record not found for this employee under this employer (ConsentError::{})",
                ConsentError::ConsentNotFound.code()
            )
        });

    if matches!(record.state, ConsentState::Revoked) {
        panic!(
            "Consent is already revoked for this employee (ConsentError::{})",
            ConsentError::ConsentAlreadyRevoked.code()
        );
    }

    let now = e.ledger().timestamp();
    record.state = ConsentState::Revoked;
    record.updated_at = now;

    e.storage().persistent().set(&key, &record);

    e.events().publish(
        (
            symbol_short!("registry"),
            Symbol::new(e, "consent_revoked"),
        ),
        (employer, employee, now),
    );
}

/// Return the consent commitment record for an (employer, employee) pair, if any.
pub fn get_consent(e: &Env, employer: &Address, employee: &Address) -> Option<ConsentCommitment> {
    let key = ConsentKey::EmployeeConsent(employer.clone(), employee.clone());
    e.storage().persistent().get(&key)
}

/// Assert that an active consent commitment exists.
///
/// Panics with `ConsentError::NoActiveConsent` if no active consent is on file.
/// Call this from enrollment paths to enforce the consent prerequisite.
pub fn require_active_consent(e: &Env, employer: &Address, employee: &Address) {
    if !has_active_consent(e, employer, employee) {
        panic!(
            "Employee consent required: no active consent commitment on file for this employee \
             under this employer — record a consent commitment before enrolling the employee \
             (ConsentError::{})",
            ConsentError::NoActiveConsent.code()
        );
    }
}

/// Return `true` iff an active (non-revoked, non-superseded) consent
/// commitment exists for the given (employer, employee) pair.
pub fn has_active_consent(e: &Env, employer: &Address, employee: &Address) -> bool {
    match get_consent(e, employer, employee) {
        Some(record) => matches!(record.state, ConsentState::Active),
        None => false,
    }
}
