//! Tests for features #360, #361, and #362:
//! - Storage version migration checks
//! - Compliance evidence pointer validation
//! - Payroll run nonce monotonicity enforcement

#![cfg(test)]

use soroban_sdk::{testutils::{Address as _, Ledger as _}, Address, BytesN, Env, Symbol};
use payroll::{Payroll, PayrollClient, ComplianceEvidencePointer, EvidencePointerScope};
use ::token::{Token, TokenClient};
use proof_verifier::{ProofVerifier, VerificationKey};
use salary_commitment::SalaryCommitmentContract;

fn mock_proof(env: &Env) -> BytesN<256> {
    BytesN::from_array(env, &[0u8; 256])
}

fn test_nonce(env: &Env, seed: u8) -> BytesN<32> {
    let mut arr = [0u8; 32];
    arr[0] = seed;
    BytesN::from_array(env, &arr)
}

fn mock_vk(env: &Env) -> VerificationKey {
    VerificationKey {
        alpha: BytesN::from_array(env, &[0u8; 64]),
        beta: BytesN::from_array(env, &[0u8; 128]),
        gamma: BytesN::from_array(env, &[0u8; 128]),
        delta: BytesN::from_array(env, &[0u8; 128]),
        ic: soroban_sdk::Vec::from_array(
            env,
            [
                BytesN::from_array(env, &[0u8; 64]),
                BytesN::from_array(env, &[0u8; 64]),
                BytesN::from_array(env, &[0u8; 64]),
                BytesN::from_array(env, &[0u8; 64]),
            ],
        ),
    }
}

fn setup_simple_payroll(env: &Env) -> (PayrollClient<'_>, Address, Address, Address, Address) {
    env.mock_all_auths();

    let verifier_id = env.register_contract(None, ProofVerifier);
    let verifier_client = ProofVerifierClient::new(env, &verifier_id);
    let verifier_admin = Address::generate(env);
    verifier_client.init_verifier_admin(&verifier_admin);
    verifier_client.initialize_verifier(&mock_vk(env));

    let commitment_id = env.register_contract(None, SalaryCommitmentContract);
    let commitment_client = SalaryCommitmentContractClient::new(env, &commitment_id);
    let commitment_admin = Address::generate(env);
    commitment_client.init_commitment_admin(&commitment_admin);

    let token_id = env.register_contract(None, Token);
    let token_client = TokenClient::new(env, &token_id);

    let payroll_id = env.register_contract(None, Payroll);
    let payroll_client = PayrollClient::new(env, &payroll_id);

    let treasury = Address::generate(env);
    let admin = Address::generate(env);
    let treasury_owner = Address::generate(env);
    // Mint enough tokens so transfer calls in tests succeed.
    token_client.mint(&treasury, &1_000_000i128);
    payroll_client.initialize(
        &admin,
        &token_id,
        &verifier_id,
        &commitment_id,
        &treasury,
        &treasury_owner,
    );

    commitment_client.set_payroll_operator(&payroll_id);

    let employee = Address::generate(env);
    commitment_client.store_commitment(&employee, &BytesN::from_array(env, &[0u8; 32]));

    (payroll_client, admin, treasury, treasury_owner, employee)
}

fn single_payment_batch(
    env: &Env,
    employee: &Address,
    amount: i128,
) -> (soroban_sdk::Vec<BytesN<256>>, soroban_sdk::Vec<i128>, soroban_sdk::Vec<Address>) {
    let mut proofs = soroban_sdk::Vec::new(env);
    proofs.push_back(mock_proof(env));
    let mut amounts = soroban_sdk::Vec::new(env);
    amounts.push_back(amount);
    let mut employees = soroban_sdk::Vec::new(env);
    employees.push_back(employee.clone());
    (proofs, amounts, employees)
}

// ═════════════════════════════════════════════════════════════════════════════
// #362: Payroll Run Nonce Monotonicity Enforcement Tests
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn test_nonce_monotonicity_sequential_nonces_accepted() {
    let env = Env::default();
    let (payroll_client, _admin, _treasury, _treasury_owner, employee) =
        setup_simple_payroll(&env);

    // First nonce should be accepted
    let nonce1 = test_nonce(&env, 1);
    let (proofs1, amounts1, employees1) = single_payment_batch(&env, &employee, 1000);
    payroll_client.batch_process_payroll(&proofs1, &amounts1, &employees1, &1000, &nonce1, &None);

    // Second nonce (greater than first) should be accepted
    let nonce2 = test_nonce(&env, 2);
    let (proofs2, amounts2, employees2) = single_payment_batch(&env, &employee, 1000);
    payroll_client.batch_process_payroll(&proofs2, &amounts2, &employees2, &1000, &nonce2, &None);

    // Verify nonce sequence tracking
    let sequence = payroll_client.get_employer_nonce_sequence(&_admin);
    assert!(sequence.is_some());
    let seq = sequence.unwrap();
    assert_eq!(seq.current_sequence, 2);
    assert_eq!(seq.last_nonce, nonce2);
}

#[test]
fn test_nonce_monotonicity_repeated_nonce_rejected() {
    let env = Env::default();
    let (payroll_client, _admin, _treasury, _treasury_owner, employee) =
        setup_simple_payroll(&env);

    // First nonce should be accepted
    let nonce = test_nonce(&env, 10);
    let (proofs1, amounts1, employees1) = single_payment_batch(&env, &employee, 1000);
    payroll_client.batch_process_payroll(&proofs1, &amounts1, &employees1, &1000, &nonce, &None);

    // Second call with the same nonce must fail (replay attack)
    let (proofs2, amounts2, employees2) = single_payment_batch(&env, &employee, 1000);
    let result = payroll_client.try_batch_process_payroll(
        &proofs2,
        &amounts2,
        &employees2,
        &1000,
        &nonce,
        &None,
    );
    assert!(result.is_err());
}

#[test]
fn test_nonce_monotonicity_stale_nonce_rejected() {
    let env = Env::default();
    let (payroll_client, _admin, _treasury, _treasury_owner, employee) =
        setup_simple_payroll(&env);

    // First nonce (higher value) should be accepted
    let nonce1 = test_nonce(&env, 20);
    let (proofs1, amounts1, employees1) = single_payment_batch(&env, &employee, 1000);
    payroll_client.batch_process_payroll(&proofs1, &amounts1, &employees1, &1000, &nonce1, &None);

    // Second nonce (lower value - stale) must fail
    let nonce2 = test_nonce(&env, 10);
    let (proofs2, amounts2, employees2) = single_payment_batch(&env, &employee, 1000);
    let result = payroll_client.try_batch_process_payroll(
        &proofs2,
        &amounts2,
        &employees2,
        &1000,
        &nonce2,
        &None,
    );
    assert!(result.is_err());
}

#[test]
fn test_nonce_monotonicity_skipped_nonces_allowed() {
    let env = Env::default();
    let (payroll_client, _admin, _treasury, _treasury_owner, employee) =
        setup_simple_payroll(&env);

    // First nonce should be accepted
    let nonce1 = test_nonce(&env, 1);
    let (proofs1, amounts1, employees1) = single_payment_batch(&env, &employee, 1000);
    payroll_client.batch_process_payroll(&proofs1, &amounts1, &employees1, &1000, &nonce1, &None);

    // Skipped nonce (5) should be accepted (monotonically increasing)
    let nonce2 = test_nonce(&env, 5);
    let (proofs2, amounts2, employees2) = single_payment_batch(&env, &employee, 1000);
    payroll_client.batch_process_payroll(&proofs2, &amounts2, &employees2, &1000, &nonce2, &None);

    // Verify sequence tracking shows skipped nonce
    let sequence = payroll_client.get_employer_nonce_sequence(&_admin);
    assert!(sequence.is_some());
    let seq = sequence.unwrap();
    assert_eq!(seq.current_sequence, 2);
    assert_eq!(seq.last_nonce, nonce2);
}

#[test]
fn test_nonce_monotonicity_prepare_payroll_run() {
    let env = Env::default();
    let (payroll_client, _admin, _treasury, _treasury_owner, employee) =
        setup_simple_payroll(&env);

    // First nonce should be accepted for prepare_payroll_run
    let nonce1 = test_nonce(&env, 100);
    let (proofs1, amounts1, employees1) = single_payment_batch(&env, &employee, 1000);
    payroll_client.prepare_payroll_run(&proofs1, &amounts1, &employees1, &1000, &nonce1, &None);

    // Second nonce (greater) should be accepted
    let nonce2 = test_nonce(&env, 101);
    let (proofs2, amounts2, employees2) = single_payment_batch(&env, &employee, 1000);
    payroll_client.prepare_payroll_run(&proofs2, &amounts2, &employees2, &1000, &nonce2, &None);

    // Stale nonce should be rejected
    let nonce3 = test_nonce(&env, 50);
    let (proofs3, amounts3, employees3) = single_payment_batch(&env, &employee, 1000);
    let result = payroll_client.try_prepare_payroll_run(
        &proofs3,
        &amounts3,
        &employees3,
        &1000,
        &nonce3,
        &None,
    );
    assert!(result.is_err());
}

// ═════════════════════════════════════════════════════════════════════════════
// #361: Compliance Evidence Pointer Validation Tests
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn test_evidence_pointer_creation_valid() {
    let env = Env::default();
    let (payroll_client, admin, _treasury, _treasury_owner, _employee) =
        setup_simple_payroll(&env);

    let content_hash = BytesN::from_array(&env, &[0xabu8; 32]);
    let target = Address::generate(&env);

    let pointer_id = payroll_client.create_evidence_pointer(
        &admin,
        &content_hash,
        &EvidencePointerScope::Employer,
        &target,
        &None,
    );

    // Verify pointer was created
    let pointer = payroll_client.get_evidence_pointer(&pointer_id);
    assert_eq!(pointer.content_hash, content_hash);
    assert_eq!(pointer.scope, EvidencePointerScope::Employer);
    assert_eq!(pointer.target, target);

    // Verify deduplication index
    assert!(payroll_client.evidence_pointer_exists(&content_hash));
}

#[test]
fn test_evidence_pointer_creation_empty_hash_rejected() {
    let env = Env::default();
    let (payroll_client, admin, _treasury, _treasury_owner, _employee) =
        setup_simple_payroll(&env);

    let zero_hash = BytesN::from_array(&env, &[0u8; 32]);
    let target = Address::generate(&env);

    let result = payroll_client.try_create_evidence_pointer(
        &admin,
        &zero_hash,
        &EvidencePointerScope::Employer,
        &target,
        &None,
    );
    assert!(result.is_err());
}

#[test]
fn test_evidence_pointer_creation_duplicate_rejected() {
    let env = Env::default();
    let (payroll_client, admin, _treasury, _treasury_owner, _employee) =
        setup_simple_payroll(&env);

    let content_hash = BytesN::from_array(&env, &[0xcd_u8; 32]);
    let target = Address::generate(&env);

    // First creation should succeed
    payroll_client.create_evidence_pointer(
        &admin,
        &content_hash,
        &EvidencePointerScope::Employer,
        &target,
        &None,
    );

    // Second creation with same content hash should fail
    let result = payroll_client.try_create_evidence_pointer(
        &admin,
        &content_hash,
        &EvidencePointerScope::Period,
        &target,
        &None,
    );
    assert!(result.is_err());
}

#[test]
fn test_evidence_pointer_scoping() {
    let env = Env::default();
    let (payroll_client, admin, _treasury, _treasury_owner, _employee) =
        setup_simple_payroll(&env);

    let employer = Address::generate(&env);
    let period = Address::generate(&env);
    let review_case = Address::generate(&env);

    // Create pointers for different scopes
    let hash1 = BytesN::from_array(&env, &[0x11u8; 32]);
    let pointer1 = payroll_client.create_evidence_pointer(
        &admin,
        &hash1,
        &EvidencePointerScope::Employer,
        &employer,
        &None,
    );

    let hash2 = BytesN::from_array(&env, &[0x22u8; 32]);
    let pointer2 = payroll_client.create_evidence_pointer(
        &admin,
        &hash2,
        &EvidencePointerScope::Period,
        &period,
        &None,
    );

    let hash3 = BytesN::from_array(&env, &[0x33u8; 32]);
    let pointer3 = payroll_client.create_evidence_pointer(
        &admin,
        &hash3,
        &EvidencePointerScope::ReviewCase,
        &review_case,
        &None,
    );

    // Verify each pointer has correct scope
    let p1 = payroll_client.get_evidence_pointer(&pointer1);
    assert_eq!(p1.scope, EvidencePointerScope::Employer);
    assert_eq!(p1.target, employer);

    let p2 = payroll_client.get_evidence_pointer(&pointer2);
    assert_eq!(p2.scope, EvidencePointerScope::Period);
    assert_eq!(p2.target, period);

    let p3 = payroll_client.get_evidence_pointer(&pointer3);
    assert_eq!(p3.scope, EvidencePointerScope::ReviewCase);
    assert_eq!(p3.target, review_case);
}

#[test]
fn test_evidence_pointer_deduplication() {
    let env = Env::default();
    let (payroll_client, admin, _treasury, _treasury_owner, _employee) =
        setup_simple_payroll(&env);

    let content_hash = BytesN::from_array(&env, &[0x44u8; 32]);
    let target = Address::generate(&env);

    // First pointer should be created
    assert!(!payroll_client.evidence_pointer_exists(&content_hash));
    
    payroll_client.create_evidence_pointer(
        &admin,
        &content_hash,
        &EvidencePointerScope::Employer,
        &target,
        &None,
    );

    // Now the content hash should exist
    assert!(payroll_client.evidence_pointer_exists(&content_hash));
}

// ═════════════════════════════════════════════════════════════════════════════
// #360: Storage Version Migration Checks Tests
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn test_storage_version_initialized_on_contract_init() {
    let env = Env::default();
    let (payroll_client, _admin, _treasury, _treasury_owner, _employee) =
        setup_simple_payroll(&env);

    // Storage version should be initialized
    let version = payroll_client.get_storage_version();
    assert!(version.is_some());
    
    let version_state = version.unwrap();
    assert_eq!(version_state.version, 1); // CURRENT_STORAGE_VERSION
    assert!(version_state.migration_complete);
}

#[test]
fn test_storage_version_is_supported() {
    let env = Env::default();
    let (payroll_client, _admin, _treasury, _treasury_owner, _employee) =
        setup_simple_payroll(&env);

    // Current version should be supported
    assert!(payroll_client.is_storage_version_supported());
}

#[test]
fn test_storage_version_no_migration_required() {
    let env = Env::default();
    let (payroll_client, _admin, _treasury, _treasury_owner, _employee) =
        setup_simple_payroll(&env);

    // No migration should be required for current version
    assert!(!payroll_client.is_migration_required());
}

#[test]
fn test_storage_version_readiness_check() {
    let env = Env::default();
    let (payroll_client, _admin, _treasury, _treasury_owner, _employee) =
        setup_simple_payroll(&env);

    // Migration readiness should show ready
    let readiness = payroll_client.check_migration_readiness();
    assert!(readiness.ready);
    assert_eq!(readiness.current_version, 1);
    assert_eq!(readiness.min_supported, 1);
    assert_eq!(readiness.max_supported, 1);
}

#[test]
fn test_storage_version_set_by_admin() {
    let env = Env::default();
    let (payroll_client, admin, _treasury, _treasury_owner, _employee) =
        setup_simple_payroll(&env);

    // Admin should be able to set storage version
    let description = soroban_sdk::String::from_str(&env, "Test version");
    payroll_client.set_storage_version(&admin, &1, &description);

    // Verify version was set
    let version = payroll_client.get_storage_version().unwrap();
    assert_eq!(version.version, 1);
}

#[test]
fn test_storage_version_sensitive_operations_work() {
    let env = Env::default();
    let (payroll_client, _admin, _treasury, _treasury_owner, employee) =
        setup_simple_payroll(&env);

    // Sensitive operations should work with supported version
    let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
    let run_id = payroll_client.batch_process_payroll(
        &proofs,
        &amounts,
        &employees,
        &1000,
        &test_nonce(&env, 200),
        &None,
    );
    assert!(run_id > 0);
}

#[test]
fn test_storage_version_backward_compatibility() {
    let env = Env::default();
    // Test that contract works without explicit version initialization
    // (backward compatibility with existing deployments)
    
    let verifier_id = env.register_contract(None, ProofVerifier);
    let verifier_client = ProofVerifierClient::new(&env, &verifier_id);
    let verifier_admin = Address::generate(&env);
    verifier_client.init_verifier_admin(&verifier_admin);
    verifier_client.initialize_verifier(&mock_vk(&env));

    let commitment_id = env.register_contract(None, SalaryCommitmentContract);
    let commitment_client = SalaryCommitmentContractClient::new(&env, &commitment_id);
    let commitment_admin = Address::generate(&env);
    commitment_client.init_commitment_admin(&commitment_admin);

    let token_id = env.register_contract(None, Token);
    let token_client = TokenClient::new(&env, &token_id);

    let payroll_id = env.register_contract(None, Payroll);
    let payroll_client = PayrollClient::new(&env, &payroll_id);

    let treasury = Address::generate(&env);
    let admin = Address::generate(&env);
    let treasury_owner = Address::generate(&env);
    token_client.mint(&treasury, &1_000_000i128);
    payroll_client.initialize(
        &admin,
        &token_id,
        &verifier_id,
        &commitment_id,
        &treasury,
        &treasury_owner,
    );

    commitment_client.set_payroll_operator(&payroll_id);

    let employee = Address::generate(&env);
    commitment_client.store_commitment(&employee, &BytesN::from_array(&env, &[0u8; 32]));

    // Should work without explicit version initialization
    let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
    env.mock_all_auths();
    let run_id = payroll_client.batch_process_payroll(
        &proofs,
        &amounts,
        &employees,
        &1000,
        &test_nonce(&env, 201),
        &None,
    );
    assert!(run_id > 0);
}

// ═════════════════════════════════════════════════════════════════════════════
// #401: Batch Lock Timestamp Query Helper Integration Tests
// ═════════════════════════════════════════════════════════════════════════

#[test]
fn test_feature_batch_lock_timestamp() {
    let env = Env::default();
    let (payroll_client, _admin, _treasury, _treasury_owner, employee) =
        setup_simple_payroll(&env);

    let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 2000);
    let nonce = test_nonce(&env, 202);

    let run_id = payroll_client.prepare_payroll_run(
        &proofs,
        &amounts,
        &employees,
        &2000,
        &nonce,
        &None,
    );

    let lock_ts = payroll_client.get_batch_lock_timestamp(&run_id);
    assert!(lock_ts.is_some());
    assert_eq!(lock_ts.unwrap(), env.ledger().timestamp());
}

// ═════════════════════════════════════════════════════════════════════════════
// #402: Safe Treasury Summary View Integration Tests
// ═════════════════════════════════════════════════════════════════════════

#[test]
fn test_feature_safe_treasury_summary() {
    let env = Env::default();
    let (payroll_client, _admin, _treasury, _treasury_owner, employee) =
        setup_simple_payroll(&env);

    let addrs = payroll_client.get_addresses();
    let summary = payroll_client.get_safe_treasury_summary(&addrs.token);
    assert_eq!(summary.total_balance, 1_000_000);
    assert_eq!(summary.available_balance, 1_000_000);
    assert_eq!(summary.reserved_balance, 0);
    assert_eq!(summary.blocked_balance, 0);

    let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 30_000);
    let nonce = test_nonce(&env, 203);
    let _run_id = payroll_client.prepare_payroll_run(
        &proofs,
        &amounts,
        &employees,
        &30_000,
        &nonce,
        &None,
    );

    let summary_after_lock = payroll_client.get_safe_treasury_summary(&addrs.token);
    assert_eq!(summary_after_lock.reserved_balance, 30_000);
    assert_eq!(summary_after_lock.available_balance, 970_000);
}

// ═════════════════════════════════════════════════════════════════════════════
// #403: Payroll Approval Expiry Validation Integration Tests
// ═════════════════════════════════════════════════════════════════════════

#[test]
fn test_feature_approval_expiry_validation() {
    let env = Env::default();
    let (payroll_client, admin, _treasury, _treasury_owner, employee) =
        setup_simple_payroll(&env);

    let reviewer = Address::generate(&env);
    payroll_client.add_reviewer(&admin, &reviewer);

    let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 15_000);
    let nonce = test_nonce(&env, 204);
    let run_id = payroll_client.prepare_payroll_run(
        &proofs,
        &amounts,
        &employees,
        &15_000,
        &nonce,
        &None,
    );

    payroll_client.approve_payroll_run(&reviewer, &run_id);
    assert!(!payroll_client.is_payroll_approval_expired(&run_id, &(7 * 24 * 60 * 60)));

    env.ledger().with_mut(|li| {
        li.timestamp += (7 * 24 * 60 * 60) + 50;
    });
    assert!(payroll_client.is_payroll_approval_expired(&run_id, &(7 * 24 * 60 * 60)));
}

// ═════════════════════════════════════════════════════════════════════════════
// #404: Cancelled Batch Read Status Integration Tests
// ═════════════════════════════════════════════════════════════════════════

#[test]
fn test_feature_cancelled_batch_status() {
    let env = Env::default();
    let (payroll_client, admin, _treasury, _treasury_owner, employee) =
        setup_simple_payroll(&env);

    let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 40_000);
    let nonce = test_nonce(&env, 205);
    let run_id = payroll_client.prepare_payroll_run(
        &proofs,
        &amounts,
        &employees,
        &40_000,
        &nonce,
        &None,
    );

    assert_eq!(payroll_client.get_cancelled_batch_status(&run_id), None);

    payroll_client.cancel_payroll_run(
        &admin,
        &run_id,
        &Symbol::new(&env, "duplicate"),
    );

    let status = payroll_client.get_cancelled_batch_status(&run_id).unwrap();
    assert_eq!(status.run_id, run_id);
    assert_eq!(status.cancelled_by, admin);
    assert_eq!(status.reason, Symbol::new(&env, "duplicate"));
    assert_eq!(status.total_amount, 40_000);
    assert!(status.is_cancelled);
}