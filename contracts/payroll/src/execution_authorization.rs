//! Contract execution initiator authorization validation (issue #620).
//!
//! A *contract execution initiator* is the address that triggers an on-chain
//! payroll execution — `prepare_payroll_run`, `batch_process_payroll`,
//! `batch_process_payroll_idempotent`, or `batch_process_payroll_bounded`.
//!
//! Before this module, each of those entrypoints only checked
//! `ContractAddresses::admin.require_auth()` deep inside the function body,
//! after unrelated validation work had already run, and the contract exposed
//! no way for a client to ask up front whether an address would be accepted as
//! an initiator. This module centralizes that single decision so that:
//!
//! * every execution path shares one authorization check,
//! * an unauthorized initiator fails fast with an actionable error instead of
//!   after dozens of unrelated checks, and
//! * SDKs and dashboards can preflight the answer with a read-only call.
//!
//! Everything here is privacy-safe: it inspects only the configured address
//! book and caller-supplied addresses. It never reads, emits, or returns
//! salary amounts, employee identities, or proof material.

use soroban_sdk::{contracttype, Address, Env};

use crate::{ContractAddresses, DataKey};

/// Whether an address is authorized to initiate a contract execution.
///
/// Serialized as a stable ordinal so off-chain consumers can persist and
/// pattern-match on it across contract upgrades.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum ExecutionInitiatorRole {
    /// The address is the registered payroll admin and may initiate executions.
    Authorized = 0,
    /// The address is not authorized to initiate a contract execution.
    Unauthorized = 1,
}

/// Privacy-safe snapshot of an execution-initiator authorization check.
///
/// Carries only the checked address, the boolean verdict, the resolved role,
/// and whether the contract has been initialized. It never exposes salary
/// amounts, employee addresses, or proof material, so it is safe to surface to
/// dashboards and integrators.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionInitiatorAuthorization {
    /// The address that was checked.
    pub initiator: Address,
    /// `true` if and only if `initiator` may initiate a contract execution.
    pub authorized: bool,
    /// The role the check resolved to.
    pub role: ExecutionInitiatorRole,
    /// `false` before `initialize` has stored the address book.
    pub initialized: bool,
}

/// The address currently authorized to initiate a contract execution.
///
/// This is the payroll admin recorded by `initialize` (and updated by the
/// admin rotation/handover flows). Returns `None` when the contract has not
/// been initialized yet, so callers can distinguish "not configured" from
/// "configured, but this address is not the initiator".
pub(crate) fn authorized_initiator(e: &Env) -> Option<Address> {
    e.storage()
        .persistent()
        .get::<DataKey, ContractAddresses>(&DataKey::Addresses)
        .map(|addresses| addresses.admin)
}

/// Read-only authorization check for `initiator`.
pub(crate) fn check(e: &Env, initiator: &Address) -> ExecutionInitiatorAuthorization {
    match authorized_initiator(e) {
        Some(admin) if admin == *initiator => ExecutionInitiatorAuthorization {
            initiator: initiator.clone(),
            authorized: true,
            role: ExecutionInitiatorRole::Authorized,
            initialized: true,
        },
        Some(_) => ExecutionInitiatorAuthorization {
            initiator: initiator.clone(),
            authorized: false,
            role: ExecutionInitiatorRole::Unauthorized,
            initialized: true,
        },
        None => ExecutionInitiatorAuthorization {
            initiator: initiator.clone(),
            authorized: false,
            role: ExecutionInitiatorRole::Unauthorized,
            initialized: false,
        },
    }
}

/// Enforce that `initiator` is authorized to initiate a contract execution.
///
/// The configured admin is compared before `require_auth()` is called so an
/// unauthorized address is rejected deterministically rather than relying on
/// host signature checks alone, mirroring the pattern used by the review and
/// rotation entrypoints.
///
/// # Panics
/// * `initiator` is not the registered payroll admin.
/// * The contract has not been initialized with an address book yet.
/// * `initiator` failed host authorization (`require_auth`).
pub(crate) fn require_authorized(e: &Env, initiator: &Address) {
    let Some(admin) = authorized_initiator(e) else {
        panic!(
            "Contract not initialized: configure the payroll address book before validating an execution initiator"
        );
    };
    if admin != *initiator {
        panic!(
            "Unauthorized contract execution initiator: only the registered payroll admin may initiate a contract execution"
        );
    }
    initiator.require_auth();
}
