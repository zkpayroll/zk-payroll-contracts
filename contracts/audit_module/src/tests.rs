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

/// Issue a view key with the given scope and duration, returning (client, admin, auditor, key).
fn issue_key<'a>(
    env: &'a Env,
    contract_id: &'a soroban_sdk::Address,
    scope: AuditScope,
    duration_days: u64,
) -> (
    AuditModuleClient<'a>,
    soroban_sdk::Address, // admin
    soroban_sdk::Address, // auditor
    ViewKey,
) {
    let client = AuditModuleClient::new(env, contract_id);
    let company_id = Symbol::new(env, "ACME");
    let admin = soroban_sdk::Address::generate(env);
    let auditor = soroban_sdk::Address::generate(env);

    let key = client.generate_view_key(&company_id, &admin, &auditor, &scope, &duration_days);
    (client, admin, auditor, key)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// A generated key stores the correct metadata and returns a non-zero ID.
#[test]
fn test_generate_view_key_stores_and_returns() {
    let (env, contract_id) = setup();
    let (client, _admin, auditor, key) =
        issue_key(&env, &contract_id, AuditScope::AggregateOnly, 30);

    let company_id = Symbol::new(&env, "ACME");
    assert_eq!(key.company_id, company_id);
    assert_eq!(key.auditor, auditor);
    assert_eq!(key.scope, AuditScope::AggregateOnly);
    assert_eq!(key.nonce, 0);

    // Verify the key can be fetched back from storage.
    let fetched = client.get_view_key(&key.id);
    assert_eq!(fetched.id, key.id);
}

/// verify_access returns true for the correct auditor and false for any other address.
#[test]
fn test_verify_access_wrong_auditor_fails() {
    let (env, contract_id) = setup();
    let (client, _admin, auditor, key) =
        issue_key(&env, &contract_id, AuditScope::AggregateOnly, 30);

    assert!(client.verify_access(&key.id, &auditor));

    let imposter = soroban_sdk::Address::generate(&env);
    assert!(!client.verify_access(&key.id, &imposter));
}

/// verify_access returns false once the ledger timestamp passes expires_at.
#[test]
fn test_verify_access_expired_fails() {
    let (env, contract_id) = setup();
    let (client, _admin, auditor, key) =
        issue_key(&env, &contract_id, AuditScope::AggregateOnly, 1); // 1-day key

    // Fast-forward ledger by 2 days (in seconds).
    env.ledger().set_timestamp(env.ledger().timestamp() + 2 * 24 * 60 * 60);

    assert!(!client.verify_access(&key.id, &auditor));
}

/// The original admin can revoke a key before expiry; after revocation the
/// key must not be accessible.
#[test]
fn test_revoke_removes_key() {
    let (env, contract_id) = setup();
    let (client, admin, auditor, key) =
        issue_key(&env, &contract_id, AuditScope::FullCompany, 30);

    assert!(client.verify_access(&key.id, &auditor));

    client.revoke_view_key(&admin, &key.id);

    // Access must now be denied.
    assert!(!client.verify_access(&key.id, &auditor));

    // get_view_key must panic (KeyNotFound) when the key is gone.
    let result = client.try_get_view_key(&key.id);
    assert!(result.is_err());
}

/// A different admin attempting to revoke a key they did not grant must
/// receive `NotKeyGranter`.
#[test]
fn test_revoke_wrong_admin_fails() {
    let (env, contract_id) = setup();
    let (client, _real_admin, _auditor, key) =
        issue_key(&env, &contract_id, AuditScope::FullCompany, 30);

    let interloper = soroban_sdk::Address::generate(&env);
    let result = client.try_revoke_view_key(&interloper, &key.id);
    assert!(result.is_err());
}

/// verify_commitment_with_key returns true when the caller supplies the same
/// amount + blinding that were used to produce the stored commitment.
#[test]
fn test_verify_commitment_with_key_matches() {
    let (env, contract_id) = setup();
    let (client, _admin, auditor, key) =
        issue_key(&env, &contract_id, AuditScope::EmployeeList, 30);

    let amount: i128 = 5_000_00; // e.g. 5,000.00 USDC (2 dp)
    let blinding = BytesN::from_array(&env, &[0xAB; 32]);

    // Build the on-chain commitment the same way the contract does internally,
    // using the test environment's crypto host.
    let mut preimage = soroban_sdk::Bytes::new(&env);
    preimage.extend_from_array(&amount.to_le_bytes());
    let blinding_slice: [u8; 32] = (&blinding).into();
    preimage.extend_from_array(&blinding_slice);
    let stored_commitment: BytesN<32> = env.crypto().sha256(&preimage).into();

    let ok = client
        .verify_commitment_with_key(&key.id, &auditor, &stored_commitment, &amount, &blinding);
    assert!(ok);

    // Wrong amount must not match.
    let wrong_amount: i128 = 999;
    let mismatch = client
        .verify_commitment_with_key(
            &key.id,
            &auditor,
            &stored_commitment,
            &wrong_amount,
            &blinding,
        );
    assert!(!mismatch);
}

/// An `AggregateOnly` key must not be usable for per-employee commitment
/// verification; the contract must return `InsufficientScope`.
#[test]
fn test_aggregate_only_scope_rejects_commitment_verification() {
    let (env, contract_id) = setup();
    let (client, _admin, auditor, key) =
        issue_key(&env, &contract_id, AuditScope::AggregateOnly, 30);

    let stored = BytesN::from_array(&env, &[0u8; 32]);
    let result =
        client.try_verify_commitment_with_key(&key.id, &auditor, &stored, &1000_i128, &stored);
    assert!(result.is_err());
}

/// generate_aggregate_report returns a valid stub report when the key is
/// valid and the caller is the designated auditor.
#[test]
fn test_generate_aggregate_report_requires_valid_key() {
    let (env, contract_id) = setup();
    let (client, _admin, auditor, key) =
        issue_key(&env, &contract_id, AuditScope::AggregateOnly, 30);

    let now = env.ledger().timestamp();
    let report = client.generate_aggregate_report(&key.id, &auditor, &now, &(now + 86_400));

    let company_id = Symbol::new(&env, "ACME");
    assert_eq!(report.company_id, company_id);
    assert_eq!(report.period_start, now);

    // A wrong auditor must receive an error.
    let interloper = soroban_sdk::Address::generate(&env);
    let err = client
        .try_generate_aggregate_report(&key.id, &interloper, &now, &(now + 86_400));
    assert!(err.is_err());
}
