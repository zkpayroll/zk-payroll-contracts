use audit_module::{AuditError, AuditModule, AuditModuleClient, AuditScope};
use soroban_sdk::testutils::{Address as _, Ledger};
use soroban_sdk::{Address, BytesN, Env, Symbol};

fn setup() -> (Env, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AuditModule, ());
    (env, contract_id)
}

#[test]
fn test_auditor_access_after_payroll_archival_success() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = Address::generate(&env);
    let seq = env.ledger().sequence();
    let expiration = seq + 1_000;

    // Grant auditor view key
    client.generate_view_key(&auditor, &expiration);
    assert!(client.verify_access(&auditor));

    // Simulate payroll run archival: archived metadata hash computed for run #42
    let archived_hash = BytesN::from_array(&env, &[0x42u8; 32]);
    let expected_hash = BytesN::from_array(&env, &[0x42u8; 32]);

    // Auditor verifies archived run audit successfully
    let company_id = Symbol::new(&env, "default");
    let count_before = client.get_audit_log_count(&company_id);
    let result = client.verify_archived_run_audit(
        &auditor,
        &42u64,
        &archived_hash,
        &expected_hash,
        &AuditScope::FullCompany,
    );
    assert!(result);
    let count_after = client.get_audit_log_count(&company_id);
    assert_eq!(count_after, count_before + 1);
}

#[test]
fn test_auditor_access_after_payroll_archival_mismatch() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = Address::generate(&env);
    let seq = env.ledger().sequence();
    client.generate_view_key(&auditor, &(seq + 1_000));

    let archived_hash = BytesN::from_array(&env, &[0x11u8; 32]);
    let corrupted_hash = BytesN::from_array(&env, &[0x99u8; 32]);

    // Tampered or mismatched expected hash returns false without revealing private amounts
    let result = client.verify_archived_run_audit(
        &auditor,
        &42u64,
        &archived_hash,
        &corrupted_hash,
        &AuditScope::FullCompany,
    );
    assert!(!result);
}

#[test]
fn test_auditor_access_after_payroll_archival_expired_grant_rejected() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = Address::generate(&env);
    let seq = env.ledger().sequence();
    let expiration = seq + 100;
    client.generate_view_key(&auditor, &expiration);

    // Fast-forward past expiration ledger (payroll was archived, but auditor key expired)
    env.ledger().set_sequence_number(expiration + 1);
    assert!(!client.verify_access(&auditor));

    let archived_hash = BytesN::from_array(&env, &[0x42u8; 32]);
    let expected_hash = BytesN::from_array(&env, &[0x42u8; 32]);

    let res = client.try_verify_archived_run_audit(
        &auditor,
        &42u64,
        &archived_hash,
        &expected_hash,
        &AuditScope::FullCompany,
    );
    assert!(res.is_err());
    assert_eq!(res.unwrap_err().unwrap(), AuditError::KeyExpired);
}

#[test]
fn test_auditor_access_after_payroll_archival_revoked_grant_rejected() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = Address::generate(&env);
    let seq = env.ledger().sequence();
    client.generate_view_key(&auditor, &(seq + 1_000));

    // Admin revokes auditor grant
    client.revoke_view_key(&contract_id, &auditor);
    assert!(!client.verify_access(&auditor));

    let archived_hash = BytesN::from_array(&env, &[0x42u8; 32]);
    let expected_hash = BytesN::from_array(&env, &[0x42u8; 32]);

    let res = client.try_verify_archived_run_audit(
        &auditor,
        &42u64,
        &archived_hash,
        &expected_hash,
        &AuditScope::FullCompany,
    );
    assert!(res.is_err());
    assert_eq!(res.unwrap_err().unwrap(), AuditError::KeyNotFound);
}

#[test]
fn test_auditor_access_after_payroll_archival_insufficient_scope_rejected() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = Address::generate(&env);
    let seq = env.ledger().sequence();
    client.generate_view_key(&auditor, &(seq + 1_000));

    let archived_hash = BytesN::from_array(&env, &[0x42u8; 32]);
    let expected_hash = BytesN::from_array(&env, &[0x42u8; 32]);

    // AggregateOnly scope cannot perform detailed run audits
    let res = client.try_verify_archived_run_audit(
        &auditor,
        &42u64,
        &archived_hash,
        &expected_hash,
        &AuditScope::AggregateOnly,
    );
    assert!(res.is_err());
    assert_eq!(res.unwrap_err().unwrap(), AuditError::InsufficientScope);
}

#[test]
#[should_panic(expected = "Metadata hash cannot be all-zero digest")]
fn test_auditor_access_boundary_all_zero_hash_panics() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = Address::generate(&env);
    let seq = env.ledger().sequence();
    client.generate_view_key(&auditor, &(seq + 1_000));

    let zero_hash = BytesN::from_array(&env, &[0u8; 32]);
    let valid_hash = BytesN::from_array(&env, &[0x42u8; 32]);

    client.verify_archived_run_audit(
        &auditor,
        &42u64,
        &zero_hash,
        &valid_hash,
        &AuditScope::FullCompany,
    );
}
