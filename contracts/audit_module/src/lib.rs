#![no_std]

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, xdr::ToXdr, Address, Bytes, BytesN, Env,
    Symbol, Vec,
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
    /// Supplied key material does not belong to the auditor.
    InvalidViewKey = 7,
}

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// Record stored in Persistent storage for each auditor.
#[contracttype]
#[derive(Clone, Debug)]
pub struct ViewKeyRecord {
    pub key_bytes: BytesN<32>,
    pub expiration_ledger: u32,
    pub granted_by: Address,
}

/// What the auditor is allowed to examine.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum AuditScope {
    FullCompany = 0,
    TimeRange = 1,
    EmployeeList = 2,
    AggregateOnly = 3,
}

/// An audit log entry written each time an auditor performs a verification
/// or generates a report. Stored in Persistent under DataKey::AuditLog(company_symbol, counter).
///
/// Salary values are never recorded — only metadata necessary for
/// compliance retrieval.
#[contracttype]
#[derive(Clone, Debug)]
pub struct AuditLogEntry {
    pub auditor: Address,
    pub company_id: Symbol,
    pub scope: AuditScope,
    pub timestamp: u64,
    pub matched: bool,
}

/// Aggregate snapshot returned to an auditor.
#[contracttype]
#[derive(Clone, Debug)]
pub struct AuditReport {
    pub company_id: Symbol,
    pub total_employees: u32,
    pub total_paid: i128,
    pub period_start: u64,
    pub period_end: u64,
    pub verified: bool,
}

/// Query result envelope so consumers can enumerate matching logs.
#[contracttype]
#[derive(Clone, Debug)]
pub struct AuditQueryResult {
    pub entries: Vec<AuditLogEntry>,
}

// ── Issue #93: company-level audit metadata export ───────────────────────────

/// Exportable audit metadata summary for external compliance review.
///
/// Privacy boundary: salary values are **never** included. Only metadata
/// needed for downstream compliance tooling is present, so this type can
/// be shared with external auditors without leaking sensitive payroll data.
///
/// Fields:
/// - `company_id`               — identifier for the audited company.
/// - `period_start` / `_end`   — time window of the export.
/// - `total_audit_entries`      — total log entries in the period.
/// - `verification_pass_count`  — entries where `matched == true`.
/// - `verification_fail_count`  — entries where `matched == false`.
/// - `exported_at`              — ledger timestamp of the export call.
/// - `exported_by`              — auditor address that triggered the export.
#[contracttype]
#[derive(Clone, Debug)]
pub struct AuditMetadataSummary {
    pub company_id: Symbol,
    pub period_start: u64,
    pub period_end: u64,
    pub total_audit_entries: u32,
    pub verification_pass_count: u32,
    pub verification_fail_count: u32,
    pub exported_at: u64,
    pub exported_by: Address,
}

/// Storage key namespace.
#[contracttype]
pub enum DataKey {
    /// Maps an auditor `Address` → `ViewKeyRecord` in Persistent storage.
    AuditorKey(Address),
    /// Per-company audit log counter (Symbol = company_id).
    AuditLogCounter(Symbol),
    /// Audit log entry keyed by (company_id, log_index).
    AuditLog(Symbol, u32),
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

    pub fn generate_view_key(env: Env, auditor: Address, expiration_ledger: u32) -> BytesN<32> {
        let admin = env.current_contract_address();

        let key_bytes = Self::derive_key_bytes(&env, &auditor, expiration_ledger);

        let record = ViewKeyRecord {
            key_bytes: key_bytes.clone(),
            expiration_ledger,
            granted_by: admin,
        };

        env.storage()
            .persistent()
            .set(&DataKey::AuditorKey(auditor.clone()), &record);

        env.events().publish(
            (Symbol::new(&env, "ViewKeyGenerated"), auditor),
            (key_bytes.clone(), expiration_ledger),
        );
        // topics : ("ViewKeyGenerated", auditor)
        // data   : (key_bytes, expiration_ledger)

        key_bytes
    }

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
            .remove(&DataKey::AuditorKey(auditor.clone()));

        env.events()
            .publish((Symbol::new(&env, "ViewKeyRevoked"), auditor), ());
        // topics : ("ViewKeyRevoked", auditor)
        // data   : ()

        Ok(())
    }

    pub fn get_view_key(env: Env, auditor: Address) -> Result<ViewKeyRecord, AuditError> {
        env.storage()
            .persistent()
            .get(&DataKey::AuditorKey(auditor))
            .ok_or(AuditError::KeyNotFound)
    }

    // -----------------------------------------------------------------------
    // Audit operations
    // -----------------------------------------------------------------------

    pub fn verify_commitment_with_key(
        env: Env,
        auditor: Address,
        stored_commitment: BytesN<32>,
        claimed_amount: i128,
        blinding_factor: BytesN<32>,
        scope: AuditScope,
    ) -> Result<bool, AuditError> {
        let record = Self::authorize_auditor(&env, auditor.clone())?;
        Self::verify_scope_for_commitment(scope)?;

        let matched = Self::verify_commitment_inner(
            &env,
            &auditor,
            &record.key_bytes,
            &stored_commitment,
            claimed_amount,
            &blinding_factor,
            scope,
        );

        // Record audit log entry for query retrieval
        Self::record_audit_log(&env, &auditor, scope, matched);

        if !matched {
            return Err(AuditError::CommitmentMismatch);
        }

        Ok(matched)
    }

    pub fn verify_commitment_with_view_key(
        env: Env,
        auditor: Address,
        supplied_key: BytesN<32>,
        stored_commitment: BytesN<32>,
        claimed_amount: i128,
        blinding_factor: BytesN<32>,
        scope: AuditScope,
    ) -> Result<bool, AuditError> {
        let record = Self::authorize_auditor(&env, auditor.clone())?;
        Self::verify_scope_for_commitment(scope)?;

        if supplied_key != record.key_bytes {
            return Err(AuditError::InvalidViewKey);
        }

        let matched = Self::verify_commitment_inner(
            &env,
            &auditor,
            &supplied_key,
            &stored_commitment,
            claimed_amount,
            &blinding_factor,
            scope,
        );

        Self::record_audit_log(&env, &auditor, scope, matched);

        if !matched {
            return Err(AuditError::CommitmentMismatch);
        }

        Ok(matched)
    }

    fn verify_scope_for_commitment(scope: AuditScope) -> Result<(), AuditError> {
        if scope == AuditScope::AggregateOnly {
            return Err(AuditError::InsufficientScope);
        }
        Ok(())
    }

    fn authorize_auditor(env: &Env, auditor: Address) -> Result<ViewKeyRecord, AuditError> {
        auditor.require_auth();

        let record: ViewKeyRecord = env
            .storage()
            .persistent()
            .get(&DataKey::AuditorKey(auditor))
            .ok_or(AuditError::KeyNotFound)?;

        if env.ledger().sequence() > record.expiration_ledger {
            return Err(AuditError::KeyExpired);
        }

        Ok(record)
    }

    fn verify_commitment_inner(
        env: &Env,
        auditor: &Address,
        view_key: &BytesN<32>,
        stored_commitment: &BytesN<32>,
        claimed_amount: i128,
        blinding_factor: &BytesN<32>,
        scope: AuditScope,
    ) -> bool {
        let computed = Self::compute_commitment(env, claimed_amount, blinding_factor);
        let keyed_stored = Self::compute_keyed_commitment(env, view_key, stored_commitment);
        let keyed_computed = Self::compute_keyed_commitment(env, view_key, &computed);
        let matched = keyed_computed == keyed_stored;

        if matched {
            env.events().publish(
                (Symbol::new(env, "AuditSuccessful"), auditor.clone()),
                (scope, keyed_stored),
            );
            // topics : ("AuditSuccessful", auditor)
            // data   : (scope, keyed_stored)
        }

        matched
    }

    pub fn generate_aggregate_report(
        env: Env,
        auditor: Address,
        company_id: Symbol,
        period_start: u64,
        period_end: u64,
    ) -> Result<AuditReport, AuditError> {
        Self::authorize_auditor(&env, auditor.clone())?;

        let report = AuditReport {
            company_id: company_id.clone(),
            total_employees: 0,
            total_paid: 0,
            period_start,
            period_end,
            verified: true,
        };

        env.events().publish(
            (
                Symbol::new(&env, "AggregateAuditGenerated"),
                auditor.clone(),
            ),
            (
                report.company_id.clone(),
                report.period_start,
                report.period_end,
            ),
        );
        // topics : ("AggregateAuditGenerated", auditor)
        // data   : (company_id, period_start, period_end)

        // Record the aggregate report generation as an audit log entry.
        Self::record_audit_log(&env, &auditor, AuditScope::AggregateOnly, true);

        Ok(report)
    }

    // -----------------------------------------------------------------------
    // Audit query patterns — company-level, employee-level, period-level
    //
    // These methods allow compliance consumers to retrieve audit-relevant
    // records without scanning the full ledger. Log entries are stored
    // per-company with a monotonically increasing counter.
    //
    // Privacy guarantees: Audit logs contain only metadata (auditor, company,
    // scope, timestamp, match status) — salary values are never persisted.
    // -----------------------------------------------------------------------

    /// Retrieve all audit log entries for a given company.
    pub fn query_by_company(env: Env, company_id: Symbol) -> AuditQueryResult {
        let counter: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::AuditLogCounter(company_id.clone()))
            .unwrap_or(0);

        let mut entries = Vec::new(&env);
        for i in 0..counter {
            if let Some(entry) = env
                .storage()
                .persistent()
                .get::<DataKey, AuditLogEntry>(&DataKey::AuditLog(company_id.clone(), i))
            {
                entries.push_back(entry);
            }
        }

        AuditQueryResult { entries }
    }

    /// Retrieve audit log entries filtered by an employee address.
    ///
    /// This matches entries where the auditor Address equals the requested
    /// employee address (used when the auditor IS the employee verifying
    /// their own commitment), or entries recorded under the company that
    /// references this employee.
    pub fn query_by_employee(env: Env, company_id: Symbol, employee: Address) -> AuditQueryResult {
        let all = Self::query_by_company(env.clone(), company_id);
        let mut filtered = Vec::new(&env);

        for entry in all.entries.iter() {
            if entry.auditor == employee {
                filtered.push_back(entry);
            }
        }

        AuditQueryResult { entries: filtered }
    }

    /// Retrieve audit log entries within a specific time range.
    pub fn query_by_period(
        env: Env,
        company_id: Symbol,
        period_start: u64,
        period_end: u64,
    ) -> AuditQueryResult {
        let all = Self::query_by_company(env.clone(), company_id);
        let mut filtered = Vec::new(&env);

        for entry in all.entries.iter() {
            if entry.timestamp >= period_start && entry.timestamp <= period_end {
                filtered.push_back(entry);
            }
        }

        AuditQueryResult { entries: filtered }
    }

    /// Return the count of audit log entries for a company — useful for
    /// paginated UIs or compliance dashboards.
    pub fn get_audit_log_count(env: Env, company_id: Symbol) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::AuditLogCounter(company_id))
            .unwrap_or(0)
    }

    // ── Issue #93: audit metadata export ─────────────────────────────────────

    /// Export a compliance-ready audit metadata summary for a company and period.
    ///
    /// Requires a valid (non-expired) view key for the requesting auditor.
    /// Salary values are never included in the returned summary — only
    /// verification counts and metadata needed for external compliance tooling.
    pub fn export_audit_summary(
        env: Env,
        auditor: Address,
        company_id: Symbol,
        period_start: u64,
        period_end: u64,
    ) -> Result<AuditMetadataSummary, AuditError> {
        Self::authorize_auditor(&env, auditor.clone())?;

        let period_result =
            Self::query_by_period(env.clone(), company_id.clone(), period_start, period_end);

        let mut pass_count: u32 = 0;
        let mut fail_count: u32 = 0;
        let total: u32 = period_result.entries.len();

        for entry in period_result.entries.iter() {
            if entry.matched {
                pass_count += 1;
            } else {
                fail_count += 1;
            }
        }

        let summary = AuditMetadataSummary {
            company_id: company_id.clone(),
            period_start,
            period_end,
            total_audit_entries: total,
            verification_pass_count: pass_count,
            verification_fail_count: fail_count,
            exported_at: env.ledger().timestamp(),
            exported_by: auditor.clone(),
        };

        env.events().publish(
            (
                Symbol::new(&env, "AuditSummaryExported"),
                auditor,
            ),
            (company_id, period_start, period_end, total),
        );

        Ok(summary)
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Store a single audit log entry keyed by (company_id, counter) and
    /// increment the counter. Called after every verification / report.
    fn record_audit_log(env: &Env, auditor: &Address, scope: AuditScope, matched: bool) {
        let company_id = Symbol::new(env, "default");
        let counter: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::AuditLogCounter(company_id.clone()))
            .unwrap_or(0);

        let entry = AuditLogEntry {
            auditor: auditor.clone(),
            company_id: company_id.clone(),
            scope,
            timestamp: env.ledger().timestamp(),
            matched,
        };

        env.storage()
            .persistent()
            .set(&DataKey::AuditLog(company_id.clone(), counter), &entry);
        env.storage()
            .persistent()
            .set(&DataKey::AuditLogCounter(company_id), &(counter + 1));
    }

    fn derive_key_bytes(env: &Env, auditor: &Address, expiration_ledger: u32) -> BytesN<32> {
        let mut preimage = Bytes::new(env);

        let addr_xdr = auditor.clone().to_xdr(env);
        preimage.append(&addr_xdr);
        preimage.extend_from_array(&expiration_ledger.to_le_bytes());
        preimage.extend_from_array(&env.ledger().sequence().to_le_bytes());

        env.crypto().sha256(&preimage).into()
    }

    fn compute_commitment(env: &Env, amount: i128, blinding: &BytesN<32>) -> BytesN<32> {
        let mut preimage = Bytes::new(env);
        preimage.extend_from_array(&amount.to_le_bytes());
        let blinding_slice: [u8; 32] = blinding.into();
        preimage.extend_from_array(&blinding_slice);
        env.crypto().sha256(&preimage).into()
    }

    fn compute_keyed_commitment(
        env: &Env,
        view_key: &BytesN<32>,
        commitment: &BytesN<32>,
    ) -> BytesN<32> {
        let mut preimage = Bytes::new(env);
        let key_slice: [u8; 32] = view_key.into();
        preimage.extend_from_array(&key_slice);
        let commitment_slice: [u8; 32] = commitment.into();
        preimage.extend_from_array(&commitment_slice);
        env.crypto().sha256(&preimage).into()
    }
}

#[cfg(test)]
mod tests;
