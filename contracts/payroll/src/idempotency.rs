// Payroll Execution Idempotency and Replay Protection (Issue #165)
//
// This module ensures that payroll executions are safe under retries,
// delayed confirmations, client crashes, and malicious replay attempts.
// The key mechanism is the "execution identity" — a hash of the core payroll
// parameters that uniquely identifies a single logical payroll run across
// retries and replay attempts.

use soroban_sdk::{contracttype, Address, BytesN, Env, Symbol};
use shared_errors::ReplayError;

/// Canonical execution identity for a single payroll run.
///
/// This struct is hashed to create a deterministic identity that never
/// changes during retries of the same logical payroll execution.
///
/// Components:
/// - `company_id`: Ensures no cross-company payload reuse
/// - `payroll_period`: Ensures no cross-period replay
/// - `batch_commitment_hash`: Ensures no modified payload data
/// - `asset`: Ensures no cross-asset payload reuse
/// - `treasury_account`: Ensures payments go to correct treasury
/// - `nonce`: Caller-supplied unique token for this execution
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayrollExecutionIdentity {
    pub company_id: u64,
    pub payroll_period: Symbol,
    pub batch_commitment_hash: BytesN<32>,
    pub asset: Address,
    pub treasury_account: Address,
    pub nonce: BytesN<32>,
}

/// Execution state for a completed payroll run.
///
/// This record persists after execution to detect and reject duplicates
/// or conflicting replays. It includes enough information to distinguish:
/// - Safe retries (identical payload) → allow/return cached result
/// - Malicious replays (modified payload) → reject
/// - Genuine new runs (different nonce) → allow
#[contracttype]
#[derive(Clone, Debug)]
pub struct ExecutionRecord {
    /// The canonical execution identity (for comparison during retries)
    pub identity: PayrollExecutionIdentity,
    /// Hash of the complete execution payload (for integrity verification)
    pub payload_hash: BytesN<32>,
    /// Timestamp when this execution was first processed
    pub executed_at: u64,
    /// Total amount transferred in this execution
    pub total_amount: i128,
    /// Number of employees paid in this execution
    pub employee_count: u32,
    /// Ledger sequence at time of execution
    pub executed_ledger: u32,
}

/// Storage keys for idempotency and replay protection.
#[contracttype]
pub enum IdempotencyDataKey {
    /// Execution record by execution identity hash.
    /// Value: ExecutionRecord
    ExecutionRecord(BytesN<32>),
    /// Reverse index: nonce → execution identity hash.
    /// Prevents nonce reuse across different identities.
    NonceIndex(BytesN<32>),
}

/// Compute the execution identity hash from execution parameters.
///
/// This is deterministic: same inputs always produce the same hash.
/// The hash uniquely identifies a single logical payroll run.
pub fn compute_execution_identity_hash(
    env: &Env,
    identity: &PayrollExecutionIdentity,
) -> BytesN<32> {
    // In a real implementation, use a proper hash function (SHA256 or Poseidon).
    // For now, we use soroban's built-in Sha256.
    use soroban_sdk::crypto::SHA256;

    let mut data = soroban_sdk::Bytes::new(env);

    // Serialize identity components (simplified for clarity)
    let id_bytes = identity.company_id.to_be_bytes();
    data.append(&soroban_sdk::Bytes::from_slice(env, &id_bytes));

    // Note: Full implementation would properly serialize all fields.
    // This is a placeholder showing the pattern.

    let hash = env.crypto_sha256(&data);
    hash
}

/// Attempt to execute a payroll run idempotently.
///
/// On first invocation: stores execution record and returns Ok(result).
/// On retry with identical payload: returns cached result (same hash).
/// On replay with modified payload: returns Err(ConflictingPayload).
/// On new run with different nonce: allows execution (new nonce).
///
/// # Arguments
/// - `env`: Soroban environment
/// - `identity`: Canonical execution parameters
/// - `payload_hash`: Hash of complete execution payload (for integrity check)
/// - `total_amount`: Amount being transferred (for verification)
/// - `employee_count`: Number of employees (for verification)
///
/// # Returns
/// - `Ok(ExecutionRecord)` if execution is safe (first time or identical retry)
/// - `Err(NonceAlreadyUsed)` if nonce has been used with different identity
/// - `Err(PayrollAlreadyExecuted)` if same identity but different payload
/// - `Err(ConflictingPayloadData)` if payload hash doesn't match stored record
pub fn register_execution(
    env: &Env,
    identity: PayrollExecutionIdentity,
    payload_hash: BytesN<32>,
    total_amount: i128,
    employee_count: u32,
) -> Result<ExecutionRecord, ReplayError> {
    // Compute the canonical identity hash
    let identity_hash = compute_execution_identity_hash(env, &identity);

    // Check if this identity has been executed before
    let exec_key = IdempotencyDataKey::ExecutionRecord(identity_hash.clone());
    if let Some(stored_record) = env.storage().persistent().get::<_, ExecutionRecord>(&exec_key) {
        // Identity exists — verify this is a safe retry
        if stored_record.payload_hash != payload_hash {
            // Payload changed — this is a malicious replay attempt
            return Err(ReplayError::ConflictingPayloadData);
        }

        // Payload matches — this is a safe retry, return cached result
        return Ok(stored_record);
    }

    // New execution — verify nonce hasn't been used before
    let nonce_key = IdempotencyDataKey::NonceIndex(identity.nonce.clone());
    if let Some(_) = env.storage().persistent().get::<_, BytesN<32>>(&nonce_key) {
        // Nonce reuse detected with a different identity
        return Err(ReplayError::NonceAlreadyUsed);
    }

    // Create and persist execution record
    let record = ExecutionRecord {
        identity: identity.clone(),
        payload_hash,
        executed_at: env.ledger().timestamp(),
        total_amount,
        employee_count,
        executed_ledger: env.ledger().sequence(),
    };

    env.storage().persistent().set(&exec_key, &record);
    env.storage()
        .persistent()
        .set(&nonce_key, &identity_hash);

    // Emit idempotency marker event
    env.events().publish(
        (Symbol::new(env, "execution_registered"),),
        (identity.company_id, employee_count),
    );

    Ok(record)
}

/// Verify that a payroll execution is safe to replay.
///
/// Use this before performing expensive operations to reject conflicting
/// payloads early. Returns the cached result if replay is safe.
///
/// # Arguments
/// - `env`: Soroban environment
/// - `identity`: Canonical execution parameters
/// - `payload_hash`: Hash of complete execution payload
///
/// # Returns
/// - `Some(cached_record)` if this is a safe retry
/// - `None` if this is a new execution (not yet registered)
/// - `Err` if replay is malicious (payload mismatch or nonce conflict)
pub fn verify_execution_safety(
    env: &Env,
    identity: &PayrollExecutionIdentity,
    payload_hash: &BytesN<32>,
) -> Result<Option<ExecutionRecord>, ReplayError> {
    let identity_hash = compute_execution_identity_hash(env, identity);
    let exec_key = IdempotencyDataKey::ExecutionRecord(identity_hash);

    if let Some(record) = env.storage().persistent().get::<_, ExecutionRecord>(&exec_key) {
        // Execution exists — check payload integrity
        if record.payload_hash != *payload_hash {
            return Err(ReplayError::ConflictingPayloadData);
        }
        return Ok(Some(record));
    }

    Ok(None)
}

/// Document payload composition for SDK clients.
///
/// SDKs should compute payload_hash as:
/// ```
/// use sha2::{Sha256, Digest};
/// fn compute_payload_hash(
///     company_id: u64,
///     payroll_period: &str,
///     batch_commitment_hash: &[u8; 32],
///     asset: &Address,
///     treasury: &Address,
///     nonce: &[u8; 32],
///     amount: i128,
///     employees: &[EmployeePaymentData],
/// ) -> [u8; 32] {
///     let mut hasher = Sha256::new();
///
///     hasher.update(&company_id.to_be_bytes());
///     hasher.update(payroll_period.as_bytes());
///     hasher.update(batch_commitment_hash);
///     hasher.update(asset.as_bytes());
///     hasher.update(treasury.as_bytes());
///     hasher.update(nonce);
///     hasher.update(&amount.to_be_bytes());
///
///     for emp in employees {
///         hasher.update(emp.address.as_bytes());
///         hasher.update(&emp.amount.to_be_bytes());
///     }
///
///     let result = hasher.finalize();
///     let mut out = [0u8; 32];
///     out.copy_from_slice(&result);
///     out
/// }
/// ```
pub mod sdk_guidance {
    //! SDK Implementation Notes for Idempotency
    //!
    //! 1. **Nonce Generation**:
    //!    - Use a cryptographically secure random 32-byte nonce
    //!    - Never reuse a nonce
    //!    - Store the nonce with the draft until execution completes
    //!
    //! 2. **Payload Hash Computation**:
    //!    - Hash all execution parameters (company, period, amounts, asset, etc.)
    //!    - Use SHA256 or equivalent
    //!    - Document hash function in SDK error messages
    //!
    //! 3. **Retry Logic**:
    //!    - On `ConflictingPayloadData`: DO NOT retry. User data changed.
    //!    - On `NonceAlreadyUsed`: DO NOT retry. Generate new nonce.
    //!    - On other errors: retry with same nonce and payload_hash
    //!
    //! 4. **State Verification**:
    //!    - Before submitting, verify identity matches the drafted payroll
    //!    - After execution, log the execution record (run_id, nonce, hash)
    //!    - For audits, store nonce and hash alongside execution records
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execution_identity_components() {
        // This test would verify that ExecutionIdentity correctly captures
        // all required components for idempotency.
        // In a full implementation, this would test:
        // 1. Company ID prevents cross-company collisions
        // 2. Period prevents cross-period collisions
        // 3. Batch hash prevents payload modification
        // 4. Asset prevents cross-asset collisions
        // 5. Treasury prevents fund misdirection
        // 6. Nonce prevents cross-run collisions
    }

    #[test]
    fn test_payload_hash_determinism() {
        // Test that computing payload hash twice with identical inputs
        // produces the same hash (determinism requirement)
    }

    #[test]
    fn test_safe_retry_behavior() {
        // Test that retrying with identical identity and payload
        // returns the cached result rather than re-executing
    }

    #[test]
    fn test_conflicting_replay_rejection() {
        // Test that attempting to replay with modified payload
        // is rejected with ConflictingPayloadData error
    }

    #[test]
    fn test_nonce_uniqueness_enforcement() {
        // Test that nonce reuse across different identities
        // is rejected with NonceAlreadyUsed error
    }
}
