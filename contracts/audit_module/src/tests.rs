use super::*;
use soroban_sdk::testutils::{Address as _, Events, Ledger as _};
use soroban_sdk::{Env, Symbol, TryIntoVal};

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

#[test]
fn test_generate_view_key_stores_and_verify_access_succeeds() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let current_seq = env.ledger().sequence();
    let expiration = current_seq + 1_000;

    let key_bytes = client.generate_view_key(&auditor, &expiration);

    assert_eq!(key_bytes.len(), 32);

    let after = env.events().all().len();
    assert_eq!(after, 1);

    let event = env.events().all().get(0).unwrap();
    assert_eq!(event.1.len(), 2);
    let sym0: Symbol = event.1.get(0).unwrap().try_into_val(&env.clone()).unwrap();
    assert_eq!(sym0, Symbol::new(&env, "ViewKeyGenerated"));
    let addr0: Address = event.1.get(1).unwrap().try_into_val(&env.clone()).unwrap();
    assert_eq!(addr0, auditor);

    // verify_access: auditor holds a valid key
    assert!(client.verify_access(&auditor));

    let record = client.get_view_key(&auditor);
    assert_eq!(record.key_bytes, key_bytes);
    assert_eq!(record.expiration_ledger, expiration);
}

#[test]
fn test_successive_generate_produces_unique_keys() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();

    let key_a = client.generate_view_key(&auditor, &(seq + 500));

    env.ledger().set_sequence_number(seq + 1);

    let key_b = client.generate_view_key(&auditor, &(seq + 500));

    assert_ne!(key_a, key_b, "successive keys must be distinct");

    let live = client.get_view_key(&auditor);
    assert_eq!(live.key_bytes, key_b);
}

// ---------------------------------------------------------------------------
// Expiry (ledger sequence)
// ---------------------------------------------------------------------------

#[test]
fn test_verify_access_expired_fails() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    let expiration = seq + 10;

    client.generate_view_key(&auditor, &expiration);

    env.ledger().set_sequence_number(expiration);
    assert!(client.verify_access(&auditor));

    env.ledger().set_sequence_number(expiration + 1);
    assert!(!client.verify_access(&auditor));
}

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

#[test]
fn test_revoke_removes_key() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    client.generate_view_key(&auditor, &(seq + 1_000));

    assert!(client.verify_access(&auditor));

    let admin = contract_id.clone();
    let before = env.events().all().len();
    client.revoke_view_key(&admin, &auditor);
    let after = env.events().all().len();
    assert_eq!(after, before + 1);

    let event = env.events().all().get(after - 1).unwrap();
    assert_eq!(event.1.len(), 3);
    let sym0: Symbol = event.1.get(0).unwrap().try_into_val(&env.clone()).unwrap();
    assert_eq!(sym0, Symbol::new(&env, "AuditAccessRevoked"));
    let addr0: Address = event.1.get(1).unwrap().try_into_val(&env.clone()).unwrap();
    assert_eq!(addr0, admin);
    let addr1: Address = event.1.get(2).unwrap().try_into_val(&env.clone()).unwrap();
    assert_eq!(addr1, auditor);

    assert!(!client.verify_access(&auditor));

    assert!(client.try_get_view_key(&auditor).is_err());
}

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

#[test]
fn test_verify_commitment_with_key_matches() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    client.generate_view_key(&auditor, &(seq + 1_000));

    let amount: i128 = 500_000;
    let blinding = BytesN::from_array(&env, &[0xAB; 32]);

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

    // Wrong amount must return CommitmentMismatch error
    let result = client.try_verify_commitment_with_key(
        &auditor,
        &stored,
        &999_i128,
        &blinding,
        &AuditScope::EmployeeList,
    );
    assert!(result.is_err());
}

#[test]
fn test_verify_commitment_with_supplied_key_matches() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    let key = client.generate_view_key(&auditor, &(seq + 1_000));

    let amount: i128 = 120_000;
    let blinding = BytesN::from_array(&env, &[0xCD; 32]);

    let mut preimage = soroban_sdk::Bytes::new(&env);
    preimage.extend_from_array(&amount.to_le_bytes());
    let blinding_slice: [u8; 32] = (&blinding).into();
    preimage.extend_from_array(&blinding_slice);
    let stored: BytesN<32> = env.crypto().sha256(&preimage).into();

    assert!(client.verify_commitment_with_view_key(
        &auditor,
        &key,
        &stored,
        &amount,
        &blinding,
        &AuditScope::EmployeeList
    ));
}

#[test]
fn test_verify_commitment_with_supplied_key_rejects_wrong_key() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    client.generate_view_key(&auditor, &(seq + 1_000));
    let wrong_key = BytesN::from_array(&env, &[0xEE; 32]);

    let amount: i128 = 120_000;
    let blinding = BytesN::from_array(&env, &[0xCD; 32]);
    let mut preimage = soroban_sdk::Bytes::new(&env);
    preimage.extend_from_array(&amount.to_le_bytes());
    let blinding_slice: [u8; 32] = (&blinding).into();
    preimage.extend_from_array(&blinding_slice);
    let stored: BytesN<32> = env.crypto().sha256(&preimage).into();

    assert!(client
        .try_verify_commitment_with_view_key(
            &auditor,
            &wrong_key,
            &stored,
            &amount,
            &blinding,
            &AuditScope::EmployeeList
        )
        .is_err());
}

#[test]
fn test_cross_auditor_key_contamination_is_rejected() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor_a = soroban_sdk::Address::generate(&env);
    let auditor_b = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    let key_a = client.generate_view_key(&auditor_a, &(seq + 1_000));
    client.generate_view_key(&auditor_b, &(seq + 1_000));

    let amount: i128 = 77_000;
    let blinding = BytesN::from_array(&env, &[0x11; 32]);
    let mut preimage = soroban_sdk::Bytes::new(&env);
    preimage.extend_from_array(&amount.to_le_bytes());
    let blinding_slice: [u8; 32] = (&blinding).into();
    preimage.extend_from_array(&blinding_slice);
    let stored: BytesN<32> = env.crypto().sha256(&preimage).into();

    assert!(client
        .try_verify_commitment_with_view_key(
            &auditor_b,
            &key_a,
            &stored,
            &amount,
            &blinding,
            &AuditScope::EmployeeList
        )
        .is_err());
}

#[test]
fn test_aggregate_only_scope_rejects_commitment_verification() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    client.generate_view_key(&auditor, &(seq + 1_000));

    let dummy = BytesN::from_array(&env, &[0u8; 32]);
    assert!(client
        .try_verify_commitment_with_key(
            &auditor,
            &dummy,
            &0_i128,
            &dummy,
            &AuditScope::AggregateOnly
        )
        .is_err());
}

#[test]
fn test_successful_commitment_audit_emits_event() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    client.generate_view_key(&auditor, &(seq + 1_000));

    let amount: i128 = 42_000;
    let blinding = BytesN::from_array(&env, &[0x99; 32]);
    let mut preimage = soroban_sdk::Bytes::new(&env);
    preimage.extend_from_array(&amount.to_le_bytes());
    let blinding_slice: [u8; 32] = (&blinding).into();
    preimage.extend_from_array(&blinding_slice);
    let stored: BytesN<32> = env.crypto().sha256(&preimage).into();

    let before = env.events().all().len();
    assert!(client.verify_commitment_with_key(
        &auditor,
        &stored,
        &amount,
        &blinding,
        &AuditScope::EmployeeList
    ));
    let after = env.events().all().len();
    assert_eq!(after, before + 1);
}

// ---------------------------------------------------------------------------
// Aggregate report
// ---------------------------------------------------------------------------

#[test]
fn test_generate_aggregate_report_valid_key() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    client.generate_view_key(&auditor, &(seq + 1_000));

    let company_id = Symbol::new(&env, "ACME");
    let now = env.ledger().timestamp();
    let before = env.events().all().len();
    let report = client.generate_aggregate_report(&auditor, &company_id, &now, &(now + 86_400));
    let after = env.events().all().len();

    assert_eq!(report.company_id, company_id);
    assert_eq!(report.period_start, now);
    assert_eq!(after, before + 1);

    let stranger = soroban_sdk::Address::generate(&env);
    assert!(client
        .try_generate_aggregate_report(&stranger, &company_id, &now, &(now + 86_400))
        .is_err());
}

// ---------------------------------------------------------------------------
// Audit query patterns — company-level, employee-level, period-level
// ---------------------------------------------------------------------------

#[test]
fn test_query_by_company_returns_audit_log_entries() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    client.generate_view_key(&auditor, &(seq + 1_000));

    let amount: i128 = 100_000;
    let blinding = BytesN::from_array(&env, &[0xBB; 32]);
    let mut preimage = soroban_sdk::Bytes::new(&env);
    preimage.extend_from_array(&amount.to_le_bytes());
    let blinding_slice: [u8; 32] = (&blinding).into();
    preimage.extend_from_array(&blinding_slice);
    let stored: BytesN<32> = env.crypto().sha256(&preimage).into();

    client.verify_commitment_with_key(
        &auditor,
        &stored,
        &amount,
        &blinding,
        &AuditScope::EmployeeList,
    );

    let company_id = Symbol::new(&env, "default");
    let result = client.query_by_company(&company_id);

    assert!(!result.entries.is_empty());
}

#[test]
fn test_query_by_employee_filters_by_auditor() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    client.generate_view_key(&auditor, &(seq + 1_000));

    let amount: i128 = 50_000;
    let blinding = BytesN::from_array(&env, &[0xCC; 32]);
    let mut preimage = soroban_sdk::Bytes::new(&env);
    preimage.extend_from_array(&amount.to_le_bytes());
    let blinding_slice: [u8; 32] = (&blinding).into();
    preimage.extend_from_array(&blinding_slice);
    let stored: BytesN<32> = env.crypto().sha256(&preimage).into();

    client.verify_commitment_with_key(
        &auditor,
        &stored,
        &amount,
        &blinding,
        &AuditScope::EmployeeList,
    );

    let company_id = Symbol::new(&env, "default");
    let result = client.query_by_employee(&company_id, &auditor);

    assert!(!result.entries.is_empty());
}

#[test]
fn test_query_by_period_filters_by_time_range() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    client.generate_view_key(&auditor, &(seq + 1_000));

    let amount: i128 = 75_000;
    let blinding = BytesN::from_array(&env, &[0xDD; 32]);
    let mut preimage = soroban_sdk::Bytes::new(&env);
    preimage.extend_from_array(&amount.to_le_bytes());
    let blinding_slice: [u8; 32] = (&blinding).into();
    preimage.extend_from_array(&blinding_slice);
    let stored: BytesN<32> = env.crypto().sha256(&preimage).into();

    let ts = env.ledger().timestamp();
    client.verify_commitment_with_key(
        &auditor,
        &stored,
        &amount,
        &blinding,
        &AuditScope::EmployeeList,
    );

    let company_id = Symbol::new(&env, "default");
    let result = client.query_by_period(&company_id, &ts, &(ts + 10_000));

    assert!(!result.entries.is_empty());
}

#[test]
fn test_get_audit_log_count_increments() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    client.generate_view_key(&auditor, &(seq + 1_000));

    let company_id = Symbol::new(&env, "default");
    let count_before = client.get_audit_log_count(&company_id);

    let amount: i128 = 25_000;
    let blinding = BytesN::from_array(&env, &[0xEE; 32]);
    let mut preimage = soroban_sdk::Bytes::new(&env);
    preimage.extend_from_array(&amount.to_le_bytes());
    let blinding_slice: [u8; 32] = (&blinding).into();
    preimage.extend_from_array(&blinding_slice);
    let stored: BytesN<32> = env.crypto().sha256(&preimage).into();

    client.verify_commitment_with_key(
        &auditor,
        &stored,
        &amount,
        &blinding,
        &AuditScope::EmployeeList,
    );

    let count_after = client.get_audit_log_count(&company_id);
    assert!(count_after > count_before);
}

// ---------------------------------------------------------------------------
// Audit Access Revocation Verification (Issue #135)
// ---------------------------------------------------------------------------

#[test]
fn test_revoke_emits_audit_event() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    client.generate_view_key(&auditor, &(seq + 1_000));

    assert!(client.verify_access(&auditor));

    let admin = contract_id.clone();
    let before_count = env.events().all().len();

    client.revoke_view_key(&admin, &auditor);

    let after_count = env.events().all().len();
    assert!(after_count > before_count, "revoke should emit an event");

    // Verify the auditor can no longer verify access
    assert!(!client.verify_access(&auditor));
}

#[test]
fn test_revoke_requires_correct_admin_authorization() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    client.generate_view_key(&auditor, &(seq + 1_000));

    assert!(client.verify_access(&auditor));

    // Wrong admin attempts revocation
    let wrong_admin = soroban_sdk::Address::generate(&env);
    let result = client.try_revoke_view_key(&wrong_admin, &auditor);

    // Should fail with NotKeyGranter or authorization error
    assert!(result.is_err(), "wrong admin should not be able to revoke");

    // Verify access is still valid
    assert!(client.verify_access(&auditor), "access should remain after failed revocation");
}

#[test]
fn test_revoke_fails_for_nonexistent_key() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let admin = contract_id.clone();
    let nonexistent_auditor = soroban_sdk::Address::generate(&env);

    let result = client.try_revoke_view_key(&admin, &nonexistent_auditor);

    // Should fail with KeyNotFound
    assert!(result.is_err(), "revoke should fail for nonexistent key");
}

#[test]
fn test_revoked_key_cannot_be_used_for_verification() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    let key = client.generate_view_key(&auditor, &(seq + 1_000));

    let amount: i128 = 750_000;
    let blinding = BytesN::from_array(&env, &[0xEE; 32]);
    let mut preimage = soroban_sdk::Bytes::new(&env);
    preimage.extend_from_array(&amount.to_le_bytes());
    let blinding_slice: [u8; 32] = (&blinding).into();
    preimage.extend_from_array(&blinding_slice);
    let stored: BytesN<32> = env.crypto().sha256(&preimage).into();

    // Verify access works before revocation
    assert!(client.verify_access(&auditor));
    let verify_before = client.try_verify_commitment_with_key(
        &auditor,
        &stored,
        &amount,
        &blinding,
        &AuditScope::EmployeeList
    );
    assert!(verify_before.is_ok());

    // Revoke the key
    let admin = contract_id.clone();
    client.revoke_view_key(&admin, &auditor);

    // Verify access is now denied
    assert!(!client.verify_access(&auditor), "access should be denied after revocation");

    // Attempt to use the key for verification (should fail)
    let result = client.try_verify_commitment_with_view_key(
        &auditor,
        &key,
        &stored,
        &amount,
        &blinding,
        &AuditScope::EmployeeList,
    );
    assert!(result.is_err(), "verification should fail with revoked key");
}

#[test]
fn test_revoke_idempotent_safe_on_second_attempt() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    client.generate_view_key(&auditor, &(seq + 1_000));

    let admin = contract_id.clone();

    // First revocation succeeds
    let first_revoke = client.try_revoke_view_key(&admin, &auditor);
    assert!(first_revoke.is_ok(), "first revocation should succeed");

    // Second revocation attempt should fail with KeyNotFound
    // (because the key no longer exists)
    let second_revoke = client.try_revoke_view_key(&admin, &auditor);
    assert!(
        second_revoke.is_err(),
        "second revocation should fail (key already removed)"
    );
}
