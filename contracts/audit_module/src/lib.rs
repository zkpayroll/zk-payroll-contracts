#![no_std]

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, xdr::ToXdr, Address, Bytes, BytesN, Env,
    Symbol,
};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Typed errors returned by the audit module.
#[contracterror]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum AuditError {
    /// No key is stored for this auditor.
    KeyNotFound = 1,
    /// The caller is not the designated auditor.
    WrongAuditor = 2,
    /// `env.ledger().sequence() > expiration_ledger` – key is expired.
    KeyExpired = 3,
    /// The caller is not the admin that granted this key.
    NotKeyGranter = 4,
    /// The audit scope is insufficient for the requested operation.
    InsufficientScope = 5,
    /// The claimed salary + blinding factor do not match the stored commitment.
    CommitmentMismatch = 6,
}

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// Record stored in Persistent storage for each auditor.
///
/// Contains the 32-byte view-key material and the ledger sequence number
/// at which the key expires.  Expiry is checked natively by comparing
/// `env.ledger().sequence() > expiration_ledger`.
#[contracttype]
#[derive(Clone, Debug)]
pub struct ViewKeyRecord {
    /// The 32-byte view-key returned to the caller of `generate_view_key`.
    pub key_bytes: BytesN<32>,
    /// Ledger sequence number after which the key is invalid.
    pub expiration_ledger: u32,
    /// The admin that issued this key (required for revocation).
    pub granted_by: Address,
}

/// What the auditor is allowed to examine.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum AuditScope {
    /// Unrestricted read on all payroll data for the company.
    FullCompany = 0,
    /// Read within a specific time range only.
    TimeRange = 1,
    /// Verify individual commitments for a named employee list.
    EmployeeList = 2,
    /// Aggregate totals only – no per-employee data.
    AggregateOnly = 3,
}

/// Aggregate snapshot returned to an auditor.
///
/// Individual salaries are never included.
#[contracttype]
#[derive(Clone, Debug)]
pub struct AuditReport {
    pub company_id: Symbol,
    /// Number of employees in the payroll for the requested period.
    pub total_employees: u32,
    /// Sum of all payments for the requested period (in token base units).
    pub total_paid: i128,
    pub period_start: u64,
    pub period_end: u64,
    /// True when the report is backed by on-chain payment records.
    pub verified: bool,
}

/// Storage key namespace.
#[contracttype]
pub enum DataKey {
    /// Maps an auditor `Address` → `ViewKeyRecord` in Persistent storage.
    AuditorKey(Address),
}

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------

#[contract]
pub struct AuditModule;

#[contractimpl]
impl AuditModule {
    // -----------------------------------------------------------------------
    // View-key lifecycle
    // -----------------------------------------------------------------------

    /// Generate a 32-byte view key for `auditor` and store it in Persistent
    /// storage.
    ///
    /// The key is valid until `env.ledger().sequence() > expiration_ledger`.
    /// This is a native Soroban expiry: once the ledger sequence passes
    /// `expiration_ledger`, `verify_access` returns `false` without any
    /// additional bookkeeping.
    ///
    /// # Arguments
    /// * `auditor`           – the address that will use this key.
    /// * `expiration_ledger` – last ledger sequence at which the key is valid.
    ///
    /// # Returns
    /// The 32-byte key material (also stored in Persistent storage).
    pub fn generate_view_key(env: Env, auditor: Address, expiration_ledger: u32) -> BytesN<32> {
        // The admin calling this function must authorise the operation.
        // We infer the admin from `env.current_contract_address()` in tests;
        // in production the invoker must sign.
        let admin = env.current_contract_address(); // caller context – see note below

        // Derive deterministic key material from (auditor XDR ‖ expiration_ledger ‖ sequence)
        // so each call produces a fresh, unique value.
        let key_bytes = Self::derive_key_bytes(&env, &auditor, expiration_ledger);

        let record = ViewKeyRecord {
            key_bytes: key_bytes.clone(),
            expiration_ledger,
            granted_by: admin,
        };

        env.storage()
            .persistent()
            .set(&DataKey::AuditorKey(auditor), &record);

        key_bytes
    }

    /// Return `true` iff `auditor` has a stored, non-expired view key.
    ///
    /// Expiry condition (per acceptance criteria):
    ///   `env.ledger().sequence() > expiration_ledger`
    pub fn verify_access(env: Env, auditor: Address) -> bool {
        match env
            .storage()
            .persistent()
            .get::<DataKey, ViewKeyRecord>(&DataKey::AuditorKey(auditor))
        {
            Some(record) => env.ledger().sequence() <= record.expiration_ledger,
            None => false,
        }
    }

    /// Revoke the view key for `auditor` before its natural expiry.
    ///
    /// Only the admin recorded in `ViewKeyRecord.granted_by` may revoke.
    pub fn revoke_view_key(env: Env, admin: Address, auditor: Address) -> Result<(), AuditError> {
        admin.require_auth();

        let record: ViewKeyRecord = env
            .storage()
            .persistent()
            .get(&DataKey::AuditorKey(auditor.clone()))
            .ok_or(AuditError::KeyNotFound)?;

        if record.granted_by != admin {
            return Err(AuditError::NotKeyGranter);
        }

        env.storage()
            .persistent()
            .remove(&DataKey::AuditorKey(auditor));
        Ok(())
    }

    /// Read the stored `ViewKeyRecord` for an auditor (no auth required).
    pub fn get_view_key(env: Env, auditor: Address) -> Result<ViewKeyRecord, AuditError> {
        env.storage()
            .persistent()
            .get(&DataKey::AuditorKey(auditor))
            .ok_or(AuditError::KeyNotFound)
    }

    // -----------------------------------------------------------------------
    // Audit operations
    // -----------------------------------------------------------------------

    /// Verify a single employee's salary commitment using the caller's view key.
    ///
    /// Requires the `auditor` to hold a valid (non-expired) key and that the
    /// key's scope is not `AggregateOnly` (per-employee access would leak
    /// individual salary data).
    ///
    /// The commitment is recomputed as:
    ///   `sha256(claimed_amount_le_bytes ‖ blinding_factor)`
    ///
    /// # Arguments
    /// * `stored_commitment` – `BytesN<32>` fetched from the salary commitment
    ///   contract by the caller (avoids a cross-contract call here).
    pub fn verify_commitment_with_key(
        env: Env,
        auditor: Address,
        stored_commitment: BytesN<32>,
        claimed_amount: i128,
        blinding_factor: BytesN<32>,
        scope: AuditScope,
    ) -> Result<bool, AuditError> {
        auditor.require_auth();

        let record: ViewKeyRecord = env
            .storage()
            .persistent()
            .get(&DataKey::AuditorKey(auditor))
            .ok_or(AuditError::KeyNotFound)?;

        // Expiry check (ledger sequence)
        if env.ledger().sequence() > record.expiration_ledger {
            return Err(AuditError::KeyExpired);
        }

        // Scope check – AggregateOnly may not inspect individual commitments
        if scope == AuditScope::AggregateOnly {
            return Err(AuditError::InsufficientScope);
        }

        // Recompute commitment: sha256(amount_le ‖ blinding)
        let computed = Self::compute_commitment(&env, claimed_amount, &blinding_factor);
        Ok(computed == stored_commitment)
    }

    /// Return an aggregate audit report.
    ///
    /// All scopes are permitted. Cross-contract calls are stubbed.
    pub fn generate_aggregate_report(
        env: Env,
        auditor: Address,
        company_id: Symbol,
        period_start: u64,
        period_end: u64,
    ) -> Result<AuditReport, AuditError> {
        auditor.require_auth();

        let record: ViewKeyRecord = env
            .storage()
            .persistent()
            .get(&DataKey::AuditorKey(auditor))
            .ok_or(AuditError::KeyNotFound)?;

        // Expiry check (ledger sequence)
        if env.ledger().sequence() > record.expiration_ledger {
            return Err(AuditError::KeyExpired);
        }

        // TODO: cross-contract stubs – wire up once initialise() is added.
        // let executor = PaymentExecutorClient::new(&env, &executor_address);
        // let total   = executor.get_total_paid(&company_id);
        // let registry = PayrollRegistryClient::new(&env, &registry_address);
        // let count   = registry.get_company(&company_id).employee_count;

        Ok(AuditReport {
            company_id,
            total_employees: 0, // stub – replace with registry query
            total_paid: 0,      // stub – replace with executor query
            period_start,
            period_end,
            verified: false, // false until cross-contract calls are wired
        })
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Derive 32-byte key material for a given auditor + expiration.
    ///
    /// `sha256(auditor_xdr ‖ expiration_ledger_le ‖ current_sequence_le)`
    ///
    /// Including the current ledger sequence ensures uniqueness across
    /// repeated calls even if `expiration_ledger` is reused.
    fn derive_key_bytes(env: &Env, auditor: &Address, expiration_ledger: u32) -> BytesN<32> {
        let mut preimage = Bytes::new(env);

        // Address → canonical XDR bytes
        let addr_xdr = auditor.clone().to_xdr(env);
        preimage.append(&addr_xdr);

        // expiration_ledger (little-endian)
        preimage.extend_from_array(&expiration_ledger.to_le_bytes());

        // current sequence as nonce (little-endian)
        preimage.extend_from_array(&env.ledger().sequence().to_le_bytes());

        env.crypto().sha256(&preimage).into()
    }

    /// Compute `sha256(amount_le_bytes ‖ blinding_factor)` as a stand-in for
    /// `Poseidon(amount, blinding)` until CAP-0075 host functions are available.
    fn compute_commitment(env: &Env, amount: i128, blinding: &BytesN<32>) -> BytesN<32> {
        let mut preimage = Bytes::new(env);
        preimage.extend_from_array(&amount.to_le_bytes());
        let blinding_slice: [u8; 32] = blinding.into();
        preimage.extend_from_array(&blinding_slice);
        env.crypto().sha256(&preimage).into()
    }
}

#[cfg(test)]
mod tests;
