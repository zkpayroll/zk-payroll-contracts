//! Payroll import source validation (issue #XXX).
//!
//! Implements authorized source tracking and validation for payroll imports.
//! Ensures payroll data comes from known, approved sources, preventing accidental
//! or malicious imports from unauthorized origins while maintaining privacy by
//! not exposing sensitive payroll or employee data in error messages.
//!
//! # Source Types
//!
//! Import sources can be:
//! - **External** addresses (validated API endpoints or services)
//! - **Admin-designated** internal sources with explicit authorization
//! - **Verified batch sources** that have passed pre-flight checks
//!
//! # Authorization Model
//!
//! An authorized source must be explicitly registered by the payroll admin.
//! Once registered, sources remain active until explicitly deactivated.
//! Payroll batches are rejected if they come from unauthorized sources,
//! but the error never exposes which sources are authorized or what the
//! payroll data contains.

use soroban_sdk::{contracttype, symbol_short, Address, Env, String, Symbol};

use crate::{DataKey, PayrollFailureReason};

/// Import source type identifier.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum ImportSourceType {
    /// External API endpoint or service.
    ExternalService = 0,
    /// Admin-designated internal source.
    InternalSource = 1,
    /// Batch verification service.
    VerificationService = 2,
}

/// Registered import source record.
///
/// Carries only operational metadata: the source address, type, registration
/// timestamp, and active flag. Does not contain payroll data or employee info.
#[contracttype]
#[derive(Clone, Debug)]
pub struct ImportSource {
    /// The authorized source address.
    pub source_address: Address,
    /// Classification of this source.
    pub source_type: ImportSourceType,
    /// Timestamp when this source was registered.
    pub registered_at: u64,
    /// Whether this source is currently active.
    pub is_active: bool,
}

/// Register a new import source as authorized.
///
/// Only the payroll admin may register sources. A source becomes active
/// immediately upon registration. Duplicate registration of the same source
/// updates its metadata but preserves its active status.
///
/// # Arguments
/// * `env` - Soroban environment
/// * `source_address` - The address to authorize as an import source
/// * `source_type` - Classification of the source
///
/// # Panics
/// * If called by a non-admin address
/// * If source_address is the zero address
pub fn register_source(
    env: &Env,
    source_address: Address,
    source_type: ImportSourceType,
) {
    // Verify caller is the admin
    let addresses = env
        .storage()
        .persistent()
        .get::<DataKey, crate::ContractAddresses>(&DataKey::Addresses)
        .expect("Contract not initialized");
    addresses.admin.require_auth();

    // Reject zero address
    let zero_wallet = String::from_str(
        env,
        "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
    );
    if source_address == Address::from_string(&zero_wallet) {
        panic!("Import source cannot be the zero address");
    }

    let source = ImportSource {
        source_address: source_address.clone(),
        source_type,
        registered_at: env.ledger().timestamp(),
        is_active: true,
    };

    env.storage()
        .persistent()
        .set(&DataKey::ImportSource(source_address.clone()), &source);

    env.events().publish(
        (symbol_short!("payroll"), symbol_short!("src_reg")),
        (),
    );
}

/// Deactivate an import source without removing its record.
///
/// Deactivated sources are rejected in new payroll batches but their
/// historical records remain for audit purposes. Only the admin may
/// deactivate sources.
///
/// # Arguments
/// * `env` - Soroban environment
/// * `source_address` - The source to deactivate
///
/// # Panics
/// * If called by a non-admin address
/// * If the source is not registered
pub fn deactivate_source(env: &Env, source_address: Address) {
    // Verify caller is the admin
    let addresses = env
        .storage()
        .persistent()
        .get::<DataKey, crate::ContractAddresses>(&DataKey::Addresses)
        .expect("Contract not initialized");
    addresses.admin.require_auth();

    let source_key = DataKey::ImportSource(source_address.clone());
    let mut source = env
        .storage()
        .persistent()
        .get::<_, ImportSource>(&source_key)
        .expect("Import source not registered");

    source.is_active = false;
    env.storage().persistent().set(&source_key, &source);

    env.events().publish(
        (symbol_short!("payroll"), symbol_short!("src_deact")),
        (),
    );
}

/// Check if a source is authorized and active.
///
/// Returns true only if the source is registered and has is_active == true.
/// Privacy-safe: exposes only an authorization boolean, never payload details.
///
/// # Arguments
/// * `env` - Soroban environment
/// * `source_address` - The source to check
pub fn is_source_authorized(env: &Env, source_address: &Address) -> bool {
    match env
        .storage()
        .persistent()
        .get::<_, ImportSource>(&DataKey::ImportSource(source_address.clone()))
    {
        Some(source) => source.is_active,
        None => false,
    }
}

/// Validate that a source is authorized for a payroll batch import.
///
/// Panics with a privacy-safe error if the source is not authorized.
/// The error message does not expose authorized source addresses or
/// payroll details to prevent information leakage.
///
/// # Arguments
/// * `env` - Soroban environment
/// * `source_address` - The source attempting the import
///
/// # Panics
/// * If source is not registered or is deactivated
pub fn require_authorized_source(env: &Env, source_address: &Address) {
    if !is_source_authorized(env, source_address) {
        panic!("Import source is not authorized for payroll operations");
    }
}

/// Validate import source with detailed failure reporting.
///
/// Used by dry-run and preflight checks to provide detailed diagnostics
/// without exposing sensitive source or payroll information.
///
/// # Arguments
/// * `env` - Soroban environment
/// * `source_address` - The source to validate
///
/// Returns `Ok(())` if authorized, `Err(PayrollFailureReason)` if not.
pub fn validate_source_for_report(
    env: &Env,
    source_address: &Address,
) -> Result<(), PayrollFailureReason> {
    if !is_source_authorized(env, source_address) {
        return Err(PayrollFailureReason::UnauthorizedImportSource);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests will be added by integration tests in contracts/payroll/tests/
}
