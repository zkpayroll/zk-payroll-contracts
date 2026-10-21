//! Temporary approver delegation controls (#636).
//!
//! An authorized reviewer may temporarily delegate their approval authority
//! to another authorized reviewer for a bounded duration. The delegation is
//! stored persistently and expires automatically after the configured window.
//!
//! Design principles:
//! - **Self-delegation is rejected.** A delegator and delegate must be
//!   distinct addresses.
//! - **Delegate must already be a reviewer.** Delegation does not grant new
//!   reviewer authority; it redirects an existing authority.
//! - **One active delegation per delegator.** A delegator may only have one
//!   active delegation at a time; revoke the existing one before creating a
//!   new one.
//! - **Bounded duration.** Duration must be > 0 and <= 30 days in seconds.
//! - **Expiry is checked on read.** Expired delegations are treated as absent
//!   rather than stored forever; callers should revoke expired delegations to
//!   reclaim storage, but they are never enforced after expiry.
//!
//! Privacy: only addresses, timestamps, and a short reason string are stored
//! or emitted. No salary amounts, employee identities, commitment hashes, or
//! proof material are involved.

use soroban_sdk::{contracttype, symbol_short, Address, Env, String};

use crate::DataKey;

/// Maximum delegation duration: 30 days expressed in seconds.
pub const MAX_DELEGATION_DURATION_SECONDS: u64 = 30 * 24 * 60 * 60;

/// Why a delegation operation was rejected.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum DelegationError {
    /// Caller is not authorized to perform the requested delegation action.
    NotAuthorized = 1,
    /// An active delegation already exists for this delegator.
    AlreadyDelegated = 2,
    /// The delegation has expired and is no longer active.
    DelegationExpired = 3,
    /// Duration is zero or exceeds `MAX_DELEGATION_DURATION_SECONDS`.
    InvalidDuration = 4,
    /// The proposed delegate is not a registered authorized reviewer.
    DelegateNotReviewer = 5,
    /// The delegator and delegate are the same address.
    SelfDelegation = 6,
}

impl DelegationError {
    pub fn code(self) -> u32 {
        self as u32
    }
}

/// A record of one active approver delegation.
///
/// Privacy note: carries only addresses, timestamps, and a user-supplied
/// reason string. No salary, employee identity, or commitment data.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApproverDelegationRecord {
    /// The reviewer delegating their approval authority.
    pub delegator: Address,
    /// The reviewer receiving delegated approval authority.
    pub delegate: Address,
    /// Ledger timestamp after which the delegation is expired and inactive.
    pub expires_at: u64,
    /// Human-readable reason supplied by the delegator.
    pub reason: String,
    /// Ledger timestamp when the delegation was created.
    pub created_at: u64,
}

/// Storage keys for approver delegation records.
///
/// Deliberately separate from [`crate::DataKey`]: that enum is already past
/// the Soroban contract-spec ceiling of 50 cases, so this feature keeps its
/// own key enum to leave every existing storage key untouched.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DelegationKey {
    /// Active delegation record for a delegating reviewer.
    ActiveDelegation(Address),
}

fn is_reviewer(e: &Env, address: &Address) -> bool {
    e.storage()
        .persistent()
        .get(&DataKey::AuthorizedReviewer(address.clone()))
        .unwrap_or(false)
}

/// Create a temporary delegation from `delegator` to `delegate`.
///
/// Validates:
/// - `delegator != delegate` (no self-delegation)
/// - `delegate` is a registered authorized reviewer
/// - No existing active delegation for `delegator`
/// - `duration_seconds > 0` and `<= MAX_DELEGATION_DURATION_SECONDS`
///
/// Requires `delegator.require_auth()`.
/// Emits `("payroll", "approver_delegated")`.
pub fn delegate_approver(
    e: &Env,
    delegator: Address,
    delegate: Address,
    duration_seconds: u64,
    reason: String,
) {
    delegator.require_auth();

    if delegator == delegate {
        panic!(
            "Self-delegation rejected: delegator and delegate must be distinct addresses (DelegationError::{})",
            DelegationError::SelfDelegation.code()
        );
    }

    if !is_reviewer(e, &delegate) {
        panic!(
            "Delegate is not an authorized reviewer: the delegate must be a registered reviewer before accepting a delegation (DelegationError::{})",
            DelegationError::DelegateNotReviewer.code()
        );
    }

    if duration_seconds == 0 || duration_seconds > MAX_DELEGATION_DURATION_SECONDS {
        panic!(
            "Invalid delegation duration: must be between 1 second and {} seconds (30 days) (DelegationError::{})",
            MAX_DELEGATION_DURATION_SECONDS,
            DelegationError::InvalidDuration.code()
        );
    }

    let now = e.ledger().timestamp();
    let key = DelegationKey::ActiveDelegation(delegator.clone());

    // Check for existing active delegation
    if let Some(existing) = e
        .storage()
        .persistent()
        .get::<DelegationKey, ApproverDelegationRecord>(&key)
    {
        if existing.expires_at > now {
            panic!(
                "Active delegation already exists: revoke the current delegation before creating a new one (DelegationError::{})",
                DelegationError::AlreadyDelegated.code()
            );
        }
        // Expired delegation — allow overwrite
    }

    let expires_at = now.saturating_add(duration_seconds);
    let record = ApproverDelegationRecord {
        delegator: delegator.clone(),
        delegate: delegate.clone(),
        expires_at,
        reason,
        created_at: now,
    };

    e.storage().persistent().set(&key, &record);

    e.events().publish(
        (symbol_short!("payroll"), soroban_sdk::Symbol::new(e, "approver_delegated")),
        (delegator, delegate, expires_at),
    );
}

/// Revoke the active delegation for `delegator`.
///
/// Requires `delegator.require_auth()`.
/// Emits `("payroll", "delegation_revoked")`.
/// Panics if no delegation record exists (expired or never created).
pub fn revoke_delegation(e: &Env, delegator: Address) {
    delegator.require_auth();

    let key = DelegationKey::ActiveDelegation(delegator.clone());
    if !e.storage().persistent().has(&key) {
        panic!("No active delegation found for this delegator");
    }

    e.storage().persistent().remove(&key);

    e.events().publish(
        (symbol_short!("payroll"), soroban_sdk::Symbol::new(e, "delegation_revoked")),
        (delegator,),
    );
}

/// Return the active, non-expired delegation for `delegator`, if any.
///
/// Returns `None` when no delegation has been created or when the delegation
/// has expired. Expired records are left in storage until explicitly revoked
/// (or overwritten by a new delegation).
pub fn get_active_delegation(e: &Env, delegator: &Address) -> Option<ApproverDelegationRecord> {
    let key = DelegationKey::ActiveDelegation(delegator.clone());
    let record: Option<ApproverDelegationRecord> = e.storage().persistent().get(&key);
    match record {
        Some(r) if r.expires_at > e.ledger().timestamp() => Some(r),
        _ => None,
    }
}

/// Resolve the effective approver for `approver`.
///
/// If `approver` has an active, non-expired delegation, returns the delegate.
/// Otherwise returns `approver` unchanged.
pub fn resolve_effective_approver(e: &Env, approver: &Address) -> Address {
    match get_active_delegation(e, approver) {
        Some(record) => record.delegate,
        None => approver.clone(),
    }
}

/// Return `true` iff `delegator` has a current, non-expired delegation.
pub fn is_delegation_active(e: &Env, delegator: &Address) -> bool {
    get_active_delegation(e, delegator).is_some()
}
