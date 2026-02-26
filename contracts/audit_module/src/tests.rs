use super::*;
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{Env, Symbol};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn setup() -> (Env, soroban_sdk::Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, AuditModule);
    (env, contract_id)
}

// ---------------------------------------------------------------------------
// generate_view_key / verify_access
// ---------------------------------------------------------------------------

/// A generated key is stored in Persistent storage and verify_access returns
/// true for that auditor while the ledger sequence ≤ expiration_ledger.
#[test]
fn test_generate_view_key_stores_and_verify_access_succeeds() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let current_seq = env.ledger().sequence();
    let expiration = current_seq + 1_000; // valid for 1 000 ledgers

    let key_bytes = client.generate_view_key(&auditor, &expiration);

    // Key material must be 32 bytes and non-zero
    assert_eq!(key_bytes.len(), 32);

    // verify_access: auditor holds a valid key
    assert!(client.verify_access(&auditor));

    // Fetching the record returns the same key bytes and expiration
    let record = client.get_view_key(&auditor);
    assert_eq!(record.key_bytes, key_bytes);
    assert_eq!(record.expiration_ledger, expiration);
}

/// Two successive generate_view_key calls for the same auditor produce
/// different key bytes (because the ledger sequence is included in the hash
/// preimage), and the second call overwrites the first in Persistent storage.
#[test]
fn test_successive_generate_produces_unique_keys() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();

    let key_a = client.generate_view_key(&auditor, &(seq + 500));

    // Advance the ledger so the sequence nonce changes.
    env.ledger().set_sequence_number(seq + 1);

    let key_b = client.generate_view_key(&auditor, &(seq + 500));

    assert_ne!(key_a, key_b, "successive keys must be distinct");

    // Only the most recent key must be live.
    let live = client.get_view_key(&auditor);
    assert_eq!(live.key_bytes, key_b);
}

// ---------------------------------------------------------------------------
// Expiry (ledger sequence)
// ---------------------------------------------------------------------------

/// verify_access returns false when env.ledger().sequence() > expiration_ledger.
#[test]
fn test_verify_access_expired_fails() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    let expiration = seq + 10;

    client.generate_view_key(&auditor, &expiration);

    // Key is still valid at expiration_ledger itself.
    env.ledger().set_sequence_number(expiration);
    assert!(client.verify_access(&auditor));

    // One ledger past expiration – key becomes invalid.
    env.ledger().set_sequence_number(expiration + 1);
    assert!(!client.verify_access(&auditor));
}

/// An auditor that was never issued a key must get false from verify_access.
#[test]
fn test_verify_access_no_key_returns_false() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let stranger = soroban_sdk::Address::generate(&env);
    assert!(!client.verify_access(&stranger));
}

// ---------------------------------------------------------------------------
// Revocation
// ---------------------------------------------------------------------------

/// The original admin can revoke a key; after that verify_access returns false.
#[test]
fn test_revoke_removes_key() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    client.generate_view_key(&auditor, &(seq + 1_000));

    assert!(client.verify_access(&auditor));

    // The contract address is used as `granted_by` in generate_view_key.
    let admin = contract_id.clone();
    client.revoke_view_key(&admin, &auditor);

    assert!(!client.verify_access(&auditor));

    // get_view_key must now return KeyNotFound.
    assert!(client.try_get_view_key(&auditor).is_err());
}

/// A different address attempting to revoke must receive NotKeyGranter.
#[test]
fn test_revoke_wrong_admin_fails() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    client.generate_view_key(&auditor, &(seq + 1_000));

    let interloper = soroban_sdk::Address::generate(&env);
    assert!(client.try_revoke_view_key(&interloper, &auditor).is_err());
}

// ---------------------------------------------------------------------------
// Commitment verification
// ---------------------------------------------------------------------------

/// verify_commitment_with_key returns true for matching amount + blinding and
/// false for a wrong amount.
#[test]
fn test_verify_commitment_with_key_matches() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    client.generate_view_key(&auditor, &(seq + 1_000));

    let amount: i128 = 5_000_00;
    let blinding = BytesN::from_array(&env, &[0xAB; 32]);

    // Build stored_commitment the same way the contract does.
    let mut preimage = soroban_sdk::Bytes::new(&env);
    preimage.extend_from_array(&amount.to_le_bytes());
    let blinding_slice: [u8; 32] = (&blinding).into();
    preimage.extend_from_array(&blinding_slice);
    let stored: BytesN<32> = env.crypto().sha256(&preimage).into();

    assert!(client.verify_commitment_with_key(
        &auditor,
        &stored,
        &amount,
        &blinding,
        &AuditScope::EmployeeList
    ));

    // Wrong amount must not match.
    assert!(!client.verify_commitment_with_key(
        &auditor,
        &stored,
        &999_i128,
        &blinding,
        &AuditScope::EmployeeList
    ));
}

/// AggregateOnly scope must be rejected by verify_commitment_with_key.
#[test]
fn test_aggregate_only_scope_rejects_commitment_verification() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    client.generate_view_key(&auditor, &(seq + 1_000));

    let dummy = BytesN::from_array(&env, &[0u8; 32]);
    assert!(client
        .try_verify_commitment_with_key(&auditor, &dummy, &0_i128, &dummy, &AuditScope::AggregateOnly)
        .is_err());
}

// ---------------------------------------------------------------------------
// Aggregate report
// ---------------------------------------------------------------------------

/// generate_aggregate_report succeeds for a valid key and returns a report
/// with the correct company_id and period.
#[test]
fn test_generate_aggregate_report_valid_key() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    client.generate_view_key(&auditor, &(seq + 1_000));

    let company_id = Symbol::new(&env, "ACME");
    let now = env.ledger().timestamp();
    let report =
        client.generate_aggregate_report(&auditor, &company_id, &now, &(now + 86_400));

    assert_eq!(report.company_id, company_id);
    assert_eq!(report.period_start, now);

    // An unknown auditor must fail.
    let stranger = soroban_sdk::Address::generate(&env);
    assert!(client
        .try_generate_aggregate_report(&stranger, &company_id, &now, &(now + 86_400))
        .is_err());
}
