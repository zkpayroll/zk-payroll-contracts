#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, contracterror, xdr::ToXdr, Address, Bytes, BytesN, Env, Symbol};


// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Typed errors returned by the audit module.
///
/// Using `contracterror` means callers get a typed `Error` variant instead
/// of an opaque host-level panic, enabling `try_*` assertions in tests.
#[contracterror]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum AuditError {
    /// The requested view key does not exist in storage.
    KeyNotFound = 1,
    /// The view key exists but the caller is not the designated auditor.
    WrongAuditor = 2,
    /// The view key has passed its `expires_at` timestamp.
    KeyExpired = 3,
    /// The caller is not the original `granted_by` admin.
    NotKeyGranter = 4,
    /// The audit scope is insufficient for the requested operation.
    InsufficientScope = 5,
    /// The claimed salary + blinding factor do not match the stored commitment.
    CommitmentMismatch = 6,
}

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// An ephemeral constraint: a scoped, time-bounded view key issued to one
/// auditor by a company admin.  No salary figures are stored here – the key
/// only records *who* is allowed to inspect *what* and *until when*.
#[contracttype]
#[derive(Clone, Debug)]
pub struct ViewKey {
    /// Unique 32-byte identifier (sha256 of company_id ‖ auditor ‖ nonce).
    pub id: BytesN<32>,
    /// The company this key grants access to.
    pub company_id: Symbol,
    /// The auditor that may use this key.
    pub auditor: Address,
    /// The admin that generated and may revoke this key.
    pub granted_by: Address,
    /// Ledger timestamp at creation.
    pub created_at: u64,
    /// Ledger timestamp after which the key is invalid.
    pub expires_at: u64,
    /// Scope of access this key grants.
    pub scope: AuditScope,
    /// Monotonic nonce so the same admin can issue multiple keys to the same
    /// auditor without collision.
    pub nonce: u32,
}

/// What the auditor is allowed to examine.
///
/// Scopes are ordered from broadest (`FullCompany`) to narrowest
/// (`AggregateOnly`).  Operations requiring a minimum scope will
/// reject keys with a narrower scope.
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
/// Individual salaries are never included; auditors can only confirm totals
/// and verify their own computation against on-chain commitments.
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
    /// Stores a `ViewKey`.  Uses `Temporary` storage so the host
    /// automatically purges it after the TTL without manual cleanup.
    ViewKey(BytesN<32>),
    /// Monotonic nonce per `(company_id, auditor)` pair, stored in
    /// `Persistent` storage to prevent key-ID collisions across generations.
    Nonce(Symbol, Address),
}

// ---------------------------------------------------------------------------
// Ledger TTL constants
// ---------------------------------------------------------------------------

/// Temporary storage TTL bump – add to the ledger sequence at key creation.
/// Each ledger is ~5 s, so 17_280 ≈ 1 day.
/// We set a generous upper bound of 365 days to accommodate any duration_days.
const MAX_TTL_LEDGERS: u32 = 17_280 * 365;

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

    /// Issue an ephemeral view key to `auditor` on behalf of `company_admin`.
    ///
    /// The key is placed in **temporary** ledger storage so the Soroban host
    /// reclaims it automatically once its TTL passes – no revocation required
    /// for expired keys.  An explicit `revoke_view_key` call is still
    /// available for early invalidation.
    ///
    /// # Arguments
    /// * `duration_days` – how many calendar days the key should be valid.
    pub fn generate_view_key(
        env: Env,
        company_id: Symbol,
        company_admin: Address,
        auditor: Address,
        scope: AuditScope,
        duration_days: u64,
    ) -> ViewKey {
        company_admin.require_auth();

        let current_time = env.ledger().timestamp();
        let expires_at = current_time + duration_days * 24 * 60 * 60;

        // Read & bump nonce so multiple keys for the same (company, auditor)
        // pair always produce distinct IDs.
        let nonce_key = DataKey::Nonce(company_id.clone(), auditor.clone());
        let nonce: u32 = env
            .storage()
            .persistent()
            .get(&nonce_key)
            .unwrap_or(0u32);
        env.storage().persistent().set(&nonce_key, &(nonce + 1));

        let key_id = Self::derive_key_id(&env, &company_id, &auditor, nonce);

        let view_key = ViewKey {
            id: key_id.clone(),
            company_id,
            auditor,
            granted_by: company_admin,
            created_at: current_time,
            expires_at,
            scope,
            nonce,
        };

        // Store in Temporary storage – host auto-purges after TTL.
        let storage_key = DataKey::ViewKey(key_id);
        env.storage().temporary().set(&storage_key, &view_key);
        env.storage()
            .temporary()
            .extend_ttl(&storage_key, MAX_TTL_LEDGERS, MAX_TTL_LEDGERS);

        view_key
    }

    /// Return `true` if `auditor` holds a non-expired view key with `key_id`.
    pub fn verify_access(env: Env, key_id: BytesN<32>, auditor: Address) -> bool {
        let storage_key = DataKey::ViewKey(key_id);
        match env
            .storage()
            .temporary()
            .get::<DataKey, ViewKey>(&storage_key)
        {
            Some(vk) => {
                let now = env.ledger().timestamp();
                vk.auditor == auditor && vk.expires_at > now
            }
            None => false,
        }
    }

    /// Revoke a view key before its natural expiry.
    ///
    /// Only the `granted_by` admin recorded in the key may revoke it.
    pub fn revoke_view_key(
        env: Env,
        company_admin: Address,
        key_id: BytesN<32>,
    ) -> Result<(), AuditError> {
        company_admin.require_auth();

        let storage_key = DataKey::ViewKey(key_id);
        let view_key: ViewKey = env
            .storage()
            .temporary()
            .get(&storage_key)
            .ok_or(AuditError::KeyNotFound)?;

        if view_key.granted_by != company_admin {
            return Err(AuditError::NotKeyGranter);
        }

        env.storage().temporary().remove(&storage_key);
        Ok(())
    }

    /// Fetch the raw `ViewKey` record (read-only, no auth required).
    pub fn get_view_key(env: Env, key_id: BytesN<32>) -> Result<ViewKey, AuditError> {
        let storage_key = DataKey::ViewKey(key_id);
        env.storage()
            .temporary()
            .get(&storage_key)
            .ok_or(AuditError::KeyNotFound)
    }

    // -----------------------------------------------------------------------
    // Audit operations
    // -----------------------------------------------------------------------

    /// Verify a single employee's salary commitment using a view key.
    ///
    /// Requires scope ≤ `EmployeeList` (i.e. `FullCompany`, `TimeRange`, or
    /// `EmployeeList`).  `AggregateOnly` keys are intentionally rejected here
    /// because per-employee verification would leak individual salary data.
    ///
    /// The commitment is recomputed as:
    ///   `sha256(claimed_amount_le_bytes ‖ blinding_factor)`
    /// and compared against the value stored by `salary_commitment` contract.
    /// This mirrors the placeholder hash used in `SalaryCommitmentContract`
    /// and will be upgraded to Poseidon once CAP-0075 host functions land.
    ///
    /// # Arguments
    /// * `stored_commitment` – the `BytesN<32>` fetched from the salary
    ///   commitment contract by the caller (avoids a cross-contract call here).
    pub fn verify_commitment_with_key(
        env: Env,
        key_id: BytesN<32>,
        auditor: Address,
        stored_commitment: BytesN<32>,
        claimed_amount: i128,
        blinding_factor: BytesN<32>,
    ) -> Result<bool, AuditError> {
        auditor.require_auth();

        let storage_key = DataKey::ViewKey(key_id);
        let view_key: ViewKey = env
            .storage()
            .temporary()
            .get(&storage_key)
            .ok_or(AuditError::KeyNotFound)?;

        // Auth check
        if view_key.auditor != auditor {
            return Err(AuditError::WrongAuditor);
        }
        let now = env.ledger().timestamp();
        if view_key.expires_at <= now {
            return Err(AuditError::KeyExpired);
        }

        // Scope check – AggregateOnly may not inspect individual commitments
        if view_key.scope == AuditScope::AggregateOnly {
            return Err(AuditError::InsufficientScope);
        }

        // Recompute commitment: sha256(amount_le ‖ blinding)
        let computed = Self::compute_commitment(&env, claimed_amount, &blinding_factor);
        if computed != stored_commitment {
            return Ok(false);
        }

        Ok(true)
    }

    /// Return an aggregate audit report for the company.
    ///
    /// All scopes are permitted for this operation.  Individual salary
    /// amounts are **never** included in the response.
    ///
    /// Cross-contract calls to the `payment_executor` and `payroll_registry`
    /// are stubbed until contract addresses are introduced via initialisation;
    /// the `verified` flag on the returned report reflects whether live data
    /// was fetched.
    pub fn generate_aggregate_report(
        env: Env,
        key_id: BytesN<32>,
        auditor: Address,
        period_start: u64,
        period_end: u64,
    ) -> Result<AuditReport, AuditError> {
        auditor.require_auth();

        let storage_key = DataKey::ViewKey(key_id);
        let view_key: ViewKey = env
            .storage()
            .temporary()
            .get(&storage_key)
            .ok_or(AuditError::KeyNotFound)?;

        if view_key.auditor != auditor {
            return Err(AuditError::WrongAuditor);
        }
        let now = env.ledger().timestamp();
        if view_key.expires_at <= now {
            return Err(AuditError::KeyExpired);
        }

        // TODO: cross-contract stubs – wire up once initialise() is added.
        // let executor = PaymentExecutorClient::new(&env, &executor_address);
        // let total   = executor.get_total_paid(&view_key.company_id);
        // let registry = PayrollRegistryClient::new(&env, &registry_address);
        // let count   = registry.get_company(&view_key.company_id).employee_count;

        Ok(AuditReport {
            company_id: view_key.company_id,
            total_employees: 0, // stub – replace with registry query
            total_paid: 0,      // stub – replace with executor query
            period_start,
            period_end,
            verified: false,    // false until cross-contract calls are wired
        })
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Derive a deterministic, collision-resistant key ID.
    ///
    /// `sha256( company_id_bytes ‖ auditor_bytes ‖ nonce_le_bytes )`
    ///
    /// The nonce is incremented per `(company_id, auditor)` pair so the same
    /// admin can issue multiple keys to the same auditor over time.
    fn derive_key_id(
        env: &Env,
        company_id: &Symbol,
        auditor: &Address,
        nonce: u32,
    ) -> BytesN<32> {
        // Build a Bytes buffer: symbol_payload(8) ‖ auditor_xdr(var) ‖ nonce_le(4)
        let mut preimage = Bytes::new(env);

        // Symbol → stable 8-byte payload
        let sym_bytes = company_id.to_val().get_payload().to_le_bytes();
        preimage.extend_from_array(&sym_bytes);

        // Address → stable XDR bytes (the canonical Soroban serialization)
        let addr_xdr = auditor.clone().to_xdr(env);
        preimage.append(&addr_xdr);

        // Nonce (little-endian)
        preimage.extend_from_array(&nonce.to_le_bytes());

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
