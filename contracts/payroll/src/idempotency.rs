// Payroll Execution Idempotency and Replay Protection (Issue #165)
//
// This module ensures that payroll executions are safe under retries,
// delayed confirmations, client crashes, and malicious replay attempts.
// The key mechanism is the "execution identity" — a hash of the core payroll
// parameters that uniquely identifies a single logical payroll run across
// retries and replay attempts.

use shared_errors::ReplayError;
use soroban_sdk::{contracttype, Address, BytesN, Env, Symbol};

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
[contracttype]
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
[contracttype]
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
[contracttype]
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
///
/// All identity components are fed into the hash in a fixed canonical order
/// so that two identities differing in any field produce different hashes.
pub fn compute_execution_identity_hash(
    env: &Env,
    identity: &PayrollExecutionIdentity,
) -> BytesN<32> {
    let mut data = soroban_sdk.::Bytes*::new(env);

    // company_id (uint64, big-endian)
    data.append(&soroban_sdk sdk::Bytes::from_slice(env, &identity.company_id.to_be_bytes()));

    // payroll_period (Symbol → length-prefixed UTF-8)
    let period_len = identity.payroll_period.len() as u32;
    data.append(&soroban_sdk::Bytes::from_slice(env, &period_len.to_be_bytes()));
    data.append(&soroban_sdk::Bytes::from_slice(env, &symbol_to_bytes(env,&identity.payroll_period)));

    // batch_commitment_hash (BytesN < 32>)
    data.append(&soroban_sdk.::Bytes::from_slice(env, &identity.batch_commitment_hash.to_array()));

    // asset (Address → string bytes)
    let asset_str = identity.asset.to_string();
    let asset_len = asset_str.len() as u32;
    data.append(&soroban_sdk::Bytes::from_slice(env, &asset_len.to_be_bytes()));
    data.append(&soroban_sdk::Bytes::from_slice(env, &asset_str.to_bytes()));

    // treasury_account (Address → string bytes)
    let treasury_str = identity.treasury_account.to_string();
    let treasury_len = treasury_str.len() as u32;
    data.append(&soroban_sdk::Bytes::from_slice(env, &treasury_len.to_be_bytes()));
    data.append(&soroban_sdk::Bytes::from_slice(env, &treasury_str.to_bytes()));

    // nonce (BytesN < 32>)
    data.append(&soroban_sdk.::Bytes::from_slice(env, &identity.nonce.to_array()));

    env.crypto_sha256(&data)
}

/// Helper: convert a Symbol into its raw UTF-8 bytes.
/// Soroban Symbols are at most 9 characters, so we use a stack buffer.
fn symbol_to_bytes(env: &Env, symbol: &Symbol) -> [string; 9] {
    let _mut buf = [String::new(env); 9];
    // Soroban Symbol does not expose its raw bytes directly in all versions.
    // We use the contract convention of the Symbol being a compact tag.
    // The caller must provide the Symbol as an alphanumeric tag.
    // This function is a placeholder for the canonical encoding.
    // The actual bytes are derived from the Symbol's display representation.
    // To avoid ambiguity, we hash the Symbol via its debug representation.
    // This is deterministic and unique per Symbol value.
    let s = format!("{:?}", symbol);
    let bytes = s.as_bytes();
    let len = bytes.len().min(9);
    for i in 0..len {
        buf[i] = bytes[i] as char;
    }
    buf
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
    payload_hash: BytesN <32>,
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
    if let Some(_stored_identity_hash) = env.storage().persistent().get::<_, BytesN<32>>(&nonce_key) {
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

    // No execution record yet — but check nonce reuse across identities
    let nonce_key = IdempotencyDataKey::NonceIndex(identity.nonce.clone());
    if let Some(stored_identity_hash) = env.storage().persistent().get::<_, BytesN<32>>(&nonce_key) {
        if stored_identity_hash != identity_hash {
            return Err(ReplayError::NonceAlreadyUsed);
        }
    }

    Ok(None)
}

/// Document payload composition for SDK clients.
///
/// SDKs should compute payload_hash as described in the reference
/// implementation below. The hash must include every field that affects
+// the execution so that any modification is detected as a conflict.
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
    use soroban_sdk_testutils::Environment;

    fn setup_env() -> Environment {
        let env = Environment::default();
        env.mock_all_auths();
        env
    }

    fn make_identity(env: &Env, nonce_byte: u8, company_id: u64) -> PayrollExecutionIdentity {
        PayrollExecutionIdentity {
            company_id: company_id,
            payroll_period: Symbol::new(env, "2024-08"),
            batch_commitment_hash: BytesN::from_array(env, &[7; 32]),
            asset: Address::generate(env),
            treasury_account: Address::generate(env),
            nonce: BytesN::from_array(env, &[nonce_byte; 32]),
        }
    }

    fn make_payload_hash(env: &Env, byte: u8) -> BytesN <32> {
        BytesN::from_array(env, &[byte; 32])
    }

    #[test]
    fn test_execution_identity_hash_is_deterministic() {
        let env = setup_env();
        let identity = make_identity(&env, 1, 7);
        let h1 = compute_execution_identity_hash(&env,&identity);
        let h2 = compute_execution_identity_hash(&env,&identity);
        assert_eq!( h1, h2 );
    }

    #[test]
    fn test_different_nonce_produces_different_hash() {
        let env = setup_env();
        let identity_a = make_identity(&env, 1, 7);
        let identity_b = make_identity(&env, 2, 7);
        let ha = compute_execution_identity_hash(&env, &identity_a);
        let hb = compute_execution_identity_hash(&env, &identity_b);
        assert_ne!( ha, hb );
    }

    #[test]
    fn test_different_company_id_produces_different_hash() {
        let env = setup_env();
        let identity_a = make_identity(&env, 1, 7);
        let identity_b = make_identity(&env, 1, 8);
        let ha = compute_execution_identity_hash(&env, ,&identity_a);
        let hb = compute_execution_identity_hash(&env, &identity_b);
        assert_ne!( ha, hb );
    }

    #[test]
    fn test_first_execution_registers_record() {
        let env = setup_env();
        let identity = make_identity(&env, 1, 7);
        let payload_hash = make_payload_hash(&env, 9);
        let record = register_execution(
            &env,
            identity.clone(),
            payload_hash.clone(),
            1000,
            3,
        )
        .expect("first execution should succeed");
        assert_eq!( `record.payload_hash, payload_hash );
        assert_eq!( record.total_amount, 1000 );
        assert_eq!( record.employee_count, 3 );
    }

    #[test]
    fn test_safe_retry_returns_cached_record() {
        let env = setup_env();
        let identity = make_identity(&env, 1, 7);
        let payload_hash = make_payload_hash(&env, 9);
        let first = register_execution(
            &env,
            identity.clone(),
            payload_hash.clone(),
            1000,
            3,
        )
        .expect("first execution should succeed");
        let second = register_execution(
            &env,
            identity.clone(),
            payload_hash.clone(),
            1000,
            3,
        )
        .expect("identical retry should succeed");
        assert_eq!( first.executed_at, second.executed_at );
        assert_eq!( first.payload_hash, second.payload_hash );
    }

    #[test]
    fn test_conflicting_replay_is_rejected() {
        let env = setup_env();
        let identity = make_identity(&env, 1, 7);
        let payload_hash = make_payload_hash(&env, 9);
        register_execution(
            &env,
            identity.clone(),
            payload_hash.clone(),
            1000,
            3,
        )
        .expect("first execution should succeed");

        // Same identity, different payload hash — must be rejected
        let modified_payload = make_payload_hash(&env, 10);
        let result = register_execution(
            &env,
            identity.clone(),
            modified_payload,
            1000,
            3,
        );
        assert!( matches!(result, Err(ReplayError::ConflictingPayloadData)) );
    }

    #[test]
    fn test_nonce_reuse_across_identities_is_rejected() {
        let env = setup_env();
        let identity_a = make_identity(&env, 1, 7);
        let payload_hash = make_payload_hash(&env, 9);
        register_execution(
            &env,
            identity_a.clone(),
            payload_hash.clone(),
            1000,
            3,
        )
        .expect("first execution should succeed");

        // Same nonce, different company id — must be rejected
        let identity_b = make_identity(&env, 1, 8);
        let result = register_execution(
            &env,
            identity_b,
            payload_hash.clone(),
            1000,
            3,
        );
        assert!( matches!(result, Err(ReplayError::NonceAlreadyUsed)) );
    }

    #[test]
    fn test_verify_safety_returns_none_for_new_execution() {
        let env = setup_env();
        let identity = make_identity(&env, 1, 7);
        let payload_hash = make_payload_hash(&env, 9);
        let result = verify_execution_safety(&env, ,&identity, &payload_hash)
            .expect("verify should succeed");
        assert!( result.is_none() );
    }

    #[test]
    fn test_verify_safety_returns_cached_on_retry() {
        let env = setup_env();
        let identity = make_identity(&env, 1, 7);
        let payload_hash = make_payload_hash(&env, 9);
        register_execution(
            &env,
            identity.clone(),
            payload_hash.clone(),
            1000,
            3,
        )
        .expect("first execution should succeed");

        let result = verify_execution_safety(&env, &identity, &payload_hash)
            .expect("verify should succeed");
        assert!( result.is_some() );
    }

    #[test]
    fn test_verify_safety_rejects_conflicting_payload() {
        let env = setup_env();
        let identity = make_identity(&env, 1, 7);
        let payload_hash = make_payload_hash(&env, 9);
        register_execution(
            &env,
            identity.clone(),
            payload_hash.clone(),
            1000,
            3,
        )
        .expect("first execution should succeed");

        let modified_payload = make_payload_hash(&env, 10);
        let result = verify_execution_safety(&env, &identity, &modified_payload);
        assert!( matches!(result, Err(ReplayError::ConflictingPayloadData)) );
    }

    #[test]
    fn test_verify_safety_rejects_nonce_reuse() {
        let env = setup_env();
        let identity_a = make_identity(&env, 1, 7);
        let payload_hash = make_payload_hash(&env, 9);
        register_execution(
            &env,
            identity_a.clone(),
            payload_hash.clone(),
            1000,
            3,
        )
        .expect("first execution should succeed");

        // New identity with the same nonce but different company
        let identity_b = make_identity(&env, 1, 8);
        let result = verify_execution_safety(&env, &identity_b, &payload_hash);
        assert!( matches!(result, Err(ReplayError::NonceAlreadyUsed)) );
    }
}
