// Retry Invariant Tests (Issue #551 + Issue #136)
//
// These tests verify that payout batch retry mechanisms preserve invariants
// under all failure, success, and boundary conditions.
//
// Invariants under test:
//   R-1. Settlement Receipt Idempotency: receipt check before state mutation,
//        recorded only after full batch success.
//   R-2. Nullifier Global Uniqueness: each nullifier consumed at most once globally.
//   R-3. Per-Employee Per-Period Uniqueness: (emp, period) paid at most once.
//   R-4. Batch-Level Atomicity Boundary: partial failures leave early payments permanent.
//   R-5. Closed Period Barrier: closed periods reject all new payments.
//   R-6. Pre-Validation Before State Mutation: array mismatches don't touch state.
//   R-7. Total Paid Monotonicity: failed retries don't decrease the total.

use ::token::{Token, TokenClient};
use payment_executor::{ContractAddresses, PaymentError, PaymentExecutor, PaymentExecutorClient};
use payroll_registry::{PayrollRegistry, PayrollRegistryClient};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, Vec};

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn mock_vk(env: &Env) -> VerificationKey {
    VerificationKey {
        alpha: BytesN::from_array(env, &[0u8; 64]),
        beta: BytesN::from_array(env, &[0u8; 128]),
        gamma: BytesN::from_array(env, &[0u8; 128]),
        delta: BytesN::from_array(env, &[0u8; 128]),
        ic: Vec::from_array(
            env,
            [
                BytesN::from_array(env, &[0u8; 64]),
                BytesN::from_array(env, &[0u8; 64]),
                BytesN::from_array(env, &[0u8; 64]),
            ],
        ),
    }
}

fn setup_system<'a>(
    env: &'a Env,
) -> (
    PaymentExecutorClient<'a>,
    PayrollRegistryClient<'a>,
    SalaryCommitmentContractClient<'a>,
    TokenClient<'a>,
    u64,
    Address,
    Address,
) {
    env.mock_all_auths();

    let executor_id = env.register(PaymentExecutor, ());
    let registry_id = env.register(PayrollRegistry, ());
    let commitment_id = env.register(SalaryCommitmentContract, ());
    let verifier_id = env.register(ProofVerifier, ());
    let token_id = env.register(Token, ());

    let executor = PaymentExecutorClient::new(env, &executor_id);
    let registry = PayrollRegistryClient::new(env, &registry_id);
    let commitment_client = SalaryCommitmentContractClient::new(env, &commitment_id);
    let verifier = ProofVerifierClient::new(env, &verifier_id);
    let token = TokenClient::new(env, &token_id);

    let addresses = ContractAddresses {
        registry: registry_id,
        commitment: commitment_id,
        verifier: verifier_id,
        token: token_id,
    };

    executor.initialize(&addresses);
    verifier.init_verifier_admin(&Address::generate(env));
    verifier.initialize_verifier(&mock_vk(env));

    let commitment_admin = Address::generate(env);
    commitment_client.init_commitment_admin(&commitment_admin);
    commitment_client.set_payroll_operator(&executor_id);

    let admin = Address::generate(env);
    let treasury = Address::generate(env);
    let company_id = registry.register_company(&admin, &treasury);

    executor.create_period(&company_id);
    token.mint(&treasury, &500_000);

    executor.set_executor_admin(&Address::generate(env));
    executor.set_asset_decimals(&executor.get_addresses().token, &7u32);

    let tax_addr = Address::generate(env);
    executor.set_withholding_config(
        &company_id,
        &0u32,
        &0u32,
        &tax_addr,
        &tax_addr,
        &0i128,
        &0i128,
    );

    (
        executor,
        registry,
        commitment_client,
        token,
        company_id,
        admin,
        treasury,
    )
}

fn register_employee(
    env: &Env,
    registry: &PayrollRegistryClient,
    commitment_client: &SalaryCommitmentContractClient,
    company_id: u64,
    seed: u8,
) -> (Address, BytesN<32>) {
    let employee = Address::generate(env);
    let commitment = BytesN::from_array(env, &[seed; 32]);
    commitment_client.store_commitment(&employee, &commitment);
    registry.add_employee(&company_id, &employee, &commitment);
    (employee, commitment)
}

fn make_proof(env: &Env, seed: u8) -> (BytesN<64>, BytesN<128>, BytesN<64>, BytesN<32>) {
    (
        BytesN::from_array(env, &[seed; 64]),
        BytesN::from_array(env, &[seed; 128]),
        BytesN::from_array(env, &[seed; 64]),
        BytesN::from_array(env, &[seed; 32]),
    )
}

// ===========================================================================
// R-1: Settlement Receipt Idempotency
// ===========================================================================

/// Receipt must be rejected if already consumed, without state mutation.
#[test]
fn test_receipt_idempotency_rejects_duplicate() {
    let env = Env::default();
    let (executor, registry, commitment_client, _token, company_id, _admin, _treasury) =
        setup_system(&env);

    let (emp, _) = register_employee(&env, &registry, &commitment_client, company_id, 10);
    let (pa, pb, pc, null) = make_proof(&env, 10);
    let receipt = BytesN::from_array(&env, &[0xAAu8; 32]);

    let mut employees = Vec::new(&env);
    let mut amounts = Vec::new(&env);
    let mut proofs_a = Vec::new(&env);
    let mut proofs_b = Vec::new(&env);
    let mut proofs_c = Vec::new(&env);
    let mut nullifiers = Vec::new(&env);

    employees.push_back(emp.clone());
    amounts.push_back(5000i128);
    proofs_a.push_back(pa.clone());
    proofs_b.push_back(pb.clone());
    proofs_c.push_back(pc.clone());
    nullifiers.push_back(null.clone());

    // First call with this receipt: succeeds.
    let result1 = executor.execute_batch_with_receipt(
        &company_id,
        &employees,
        &amounts,
        &proofs_a,
        &proofs_b,
        &proofs_c,
        &nullifiers,
        &1,
        &receipt,
    );
    assert_eq!(result1.len(), employees.len(), "first call should succeed");

    // Second call with the same receipt: rejected immediately.
    let result2 = executor.try_execute_batch_with_receipt(
        &company_id,
        &employees,
        &amounts,
        &proofs_a,
        &proofs_b,
        &proofs_c,
        &nullifiers,
        &1,
        &receipt,
    );
    assert_eq!(
        result2.unwrap_err().unwrap(),
        PaymentError::SettlementReceiptAlreadyUsed,
        "duplicate receipt must be rejected"
    );
}

/// Receipt remains unconsumed if batch fails partway through.
/// This allows retry with the same receipt ID.
#[test]
fn test_receipt_not_consumed_on_partial_batch_failure() {
    let env = Env::default();
    let (executor, registry, commitment_client, token, company_id, _admin, treasury) =
        setup_system(&env);

    let (emp1, _) = register_employee(&env, &registry, &commitment_client, company_id, 11);
    let (emp2, _) = register_employee(&env, &registry, &commitment_client, company_id, 12);

    let (pa1, pb1, pc1, null1) = make_proof(&env, 11);
    let (pa2, pb2, pc2, null2) = make_proof(&env, 12);

    let mut employees = Vec::new(&env);
    let mut amounts = Vec::new(&env);
    let mut proofs_a = Vec::new(&env);
    let mut proofs_b = Vec::new(&env);
    let mut proofs_c = Vec::new(&env);
    let mut nullifiers = Vec::new(&env);

    employees.push_back(emp1.clone());
    amounts.push_back(200_000i128); // huge amount to trigger failure

    employees.push_back(emp2.clone());
    amounts.push_back(1000i128);

    proofs_a.push_back(pa1.clone());
    proofs_b.push_back(pb1.clone());
    proofs_c.push_back(pc1.clone());
    nullifiers.push_back(null1.clone());

    proofs_a.push_back(pa2.clone());
    proofs_b.push_back(pb2.clone());
    proofs_c.push_back(pc2.clone());
    nullifiers.push_back(null2.clone());

    let receipt = BytesN::from_array(&env, &[0xBBu8; 32]);

    // Drain treasury so first payment fails due to insufficient balance.
    token.transfer(&treasury, &Address::generate(&env), &500_000);

    // First attempt: batch fails at emp1; receipt should not be consumed.
    let result1 = executor.try_execute_batch_with_receipt(
        &company_id,
        &employees,
        &amounts,
        &proofs_a,
        &proofs_b,
        &proofs_c,
        &nullifiers,
        &1,
        &receipt,
    );
    assert!(
        result1.is_err(),
        "batch should fail due to insufficient balance"
    );

    // Verify receipt was not consumed.
    assert!(
        !executor.is_settlement_receipt_used(&receipt),
        "receipt must NOT be consumed on failure"
    );

    // Refund treasury and retry with same receipt.
    token.mint(&treasury, &200_000);
    let result2 = executor.execute_batch_with_receipt(
        &company_id,
        &employees,
        &amounts,
        &proofs_a,
        &proofs_b,
        &proofs_c,
        &nullifiers,
        &1,
        &receipt,
    );
    assert_eq!(
        result2.len(),
        employees.len(),
        "retry with same receipt should succeed"
    );
    assert!(
        executor.is_settlement_receipt_used(&receipt),
        "receipt must be consumed on success"
    );
}

// ===========================================================================
// R-2: Nullifier Global Uniqueness
// ===========================================================================

/// Same nullifier used in different periods fails with ProofAlreadyUsed.
#[test]
fn test_nullifier_global_uniqueness_across_periods() {
    let env = Env::default();
    let (executor, registry, commitment_client, _token, company_id, _admin, _treasury) =
        setup_system(&env);

    let (emp1, _) = register_employee(&env, &registry, &commitment_client, company_id, 20);
    let (emp2, _) = register_employee(&env, &registry, &commitment_client, company_id, 21);

    // Use the same nullifier for both proofs
    let (pa1, pb1, pc1, null_shared) = make_proof(&env, 20);
    let (pa2, pb2, pc2, _) = make_proof(&env, 21);

    // First payment in period 1 with nullifier.
    executor.execute_payment(
        &company_id,
        &emp1,
        &1000,
        &pa1,
        &pb1,
        &pc1,
        &null_shared,
        &1,
    );
    assert_eq!(executor.get_total_paid(&company_id), 1000);

    // Close period 1 and open period 2.
    executor.close_period(&company_id, &1);
    executor.create_period(&company_id);

    // Attempt second payment in period 2 with the same nullifier.
    let result = executor.try_execute_payment(
        &company_id,
        &emp2,
        &2000,
        &pa2,
        &pb2,
        &pc2,
        &null_shared,
        &2,
    );

    assert_eq!(
        result.unwrap_err().unwrap(),
        PaymentError::ProofAlreadyUsed,
        "same nullifier across periods must be rejected"
    );

    // Total must be unchanged after the rejected attempt.
    assert_eq!(executor.get_total_paid(&company_id), 1000);
}

// ===========================================================================
// R-3: Per-Employee Per-Period Uniqueness
// ===========================================================================

/// Same employee cannot be paid twice in the same period, even with fresh proof.
#[test]
fn test_already_paid_rejects_second_payment_same_period() {
    let env = Env::default();
    let (executor, registry, commitment_client, _token, company_id, _admin, _treasury) =
        setup_system(&env);

    let (emp, _) = register_employee(&env, &registry, &commitment_client, company_id, 30);
    let (pa1, pb1, pc1, null1) = make_proof(&env, 30);
    let (pa2, pb2, pc2, null2) = make_proof(&env, 31); // fresh proof, different nullifier

    // First payment succeeds.
    executor.execute_payment(&company_id, &emp, &5000, &pa1, &pb1, &pc1, &null1, &1);
    assert!(executor.is_paid(&emp, &1));

    // Second payment with fresh proof still fails with AlreadyPaid.
    let result =
        executor.try_execute_payment(&company_id, &emp, &3000, &pa2, &pb2, &pc2, &null2, &1);
    assert_eq!(
        result.unwrap_err().unwrap(),
        PaymentError::AlreadyPaid,
        "second payment in same period must be rejected"
    );

    // Total must be unchanged (only the first payment counts).
    assert_eq!(executor.get_total_paid(&company_id), 5000);
}

/// Same employee can be paid in different periods (with fresh proofs).
#[test]
fn test_same_employee_payable_across_periods() {
    let env = Env::default();
    let (executor, registry, commitment_client, _token, company_id, _admin, _treasury) =
        setup_system(&env);

    let (emp, _) = register_employee(&env, &registry, &commitment_client, company_id, 40);
    let (pa1, pb1, pc1, null1) = make_proof(&env, 40);
    let (pa2, pb2, pc2, null2) = make_proof(&env, 41);

    // Pay in period 1.
    executor.execute_payment(&company_id, &emp, &5000, &pa1, &pb1, &pc1, &null1, &1);
    assert_eq!(executor.get_total_paid(&company_id), 5000);

    // Close period 1 and open period 2.
    executor.close_period(&company_id, &1);
    executor.create_period(&company_id);

    // Pay the same employee in period 2 with a fresh proof.
    executor.execute_payment(&company_id, &emp, &3000, &pa2, &pb2, &pc2, &null2, &2);
    assert_eq!(
        executor.get_total_paid(&company_id),
        8000,
        "second payment in new period should succeed"
    );
}

// ===========================================================================
// R-4: Batch-Level Atomicity Boundary
// ===========================================================================

/// Partial batch failure leaves early payments permanent.
#[test]
fn test_partial_batch_failure_leaves_early_payments_intact() {
    let env = Env::default();
    let (executor, registry, commitment_client, token, company_id, _admin, treasury) =
        setup_system(&env);

    let (emp1, _) = register_employee(&env, &registry, &commitment_client, company_id, 50);
    let (emp2, _) = register_employee(&env, &registry, &commitment_client, company_id, 51);
    let (emp3, _) = register_employee(&env, &registry, &commitment_client, company_id, 52);

    let (pa1, pb1, pc1, null1) = make_proof(&env, 50);
    let (pa2, pb2, pc2, null2) = make_proof(&env, 51);
    let (pa3, pb3, pc3, null3) = make_proof(&env, 52);

    let mut employees = Vec::new(&env);
    let mut amounts = Vec::new(&env);
    let mut proofs_a = Vec::new(&env);
    let mut proofs_b = Vec::new(&env);
    let mut proofs_c = Vec::new(&env);
    let mut nullifiers = Vec::new(&env);

    employees.push_back(emp1.clone());
    amounts.push_back(1000i128);
    proofs_a.push_back(pa1.clone());
    proofs_b.push_back(pb1.clone());
    proofs_c.push_back(pc1.clone());
    nullifiers.push_back(null1.clone());

    employees.push_back(emp2.clone());
    amounts.push_back(500_000i128); // excessive; will cause failure
    proofs_a.push_back(pa2.clone());
    proofs_b.push_back(pb2.clone());
    proofs_c.push_back(pc2.clone());
    nullifiers.push_back(null2.clone());

    employees.push_back(emp3.clone());
    amounts.push_back(1000i128);
    proofs_a.push_back(pa3.clone());
    proofs_b.push_back(pb3.clone());
    proofs_c.push_back(pc3.clone());
    nullifiers.push_back(null3.clone());

    // Drain treasury to trigger failure at emp2.
    token.transfer(&treasury, &Address::generate(&env), &499_000);

    // Batch fails at emp2; emp1 should be paid, emp3 not processed.
    let result = executor.try_execute_batch_payroll(
        &company_id,
        &employees,
        &amounts,
        &proofs_a,
        &proofs_b,
        &proofs_c,
        &nullifiers,
        &1,
    );
    assert!(result.is_err(), "batch should fail at emp2");

    // Verify emp1 was paid.
    assert!(executor.is_paid(&emp1, &1), "emp1 must be permanently paid");
    assert_eq!(executor.get_total_paid(&company_id), 1000);

    // Verify emp2 and emp3 were not paid.
    assert!(!executor.is_paid(&emp2, &1));
    assert!(!executor.is_paid(&emp3, &1));
}

// ===========================================================================
// R-6: Pre-Validation Before State Mutation
// ===========================================================================

/// Array length mismatch fails before touching state.
#[test]
fn test_array_length_mismatch_fails_before_state_mutation() {
    let env = Env::default();
    let (executor, _registry, _commitment_client, _token, company_id, _admin, _treasury) =
        setup_system(&env);

    let mut employees = Vec::new(&env);
    let mut amounts = Vec::new(&env);
    let mut proofs_a = Vec::new(&env);
    let proofs_b = Vec::new(&env);
    let proofs_c = Vec::new(&env);
    let nullifiers = Vec::new(&env);

    employees.push_back(Address::generate(&env));
    amounts.push_back(1000i128);
    proofs_a.push_back(BytesN::from_array(&env, &[1u8; 64]));
    // proofs_b, proofs_c, nullifiers are empty, causing mismatch

    let total_before = executor.get_total_paid(&company_id);

    let result = executor.try_execute_batch_payroll(
        &company_id,
        &employees,
        &amounts,
        &proofs_a,
        &proofs_b,
        &proofs_c,
        &nullifiers,
        &1,
    );

    assert_eq!(
        result.unwrap_err().unwrap(),
        PaymentError::ArrayLengthMismatch,
        "array length mismatch must be detected"
    );

    // Total must be unchanged.
    assert_eq!(executor.get_total_paid(&company_id), total_before);
}

// ===========================================================================
// R-7: Total Paid Monotonicity on Retry
// ===========================================================================

/// Failed retry does not decrease the total.
#[test]
fn test_total_monotonicity_failed_retry_does_not_decrease() {
    let env = Env::default();
    let (executor, registry, commitment_client, _token, company_id, _admin, _treasury) =
        setup_system(&env);

    let (emp, _) = register_employee(&env, &registry, &commitment_client, company_id, 60);
    let (pa, pb, pc, null) = make_proof(&env, 60);

    // First payment succeeds.
    executor.execute_payment(&company_id, &emp, &5000, &pa, &pb, &pc, &null, &1);
    let total_after_success = executor.get_total_paid(&company_id);
    assert_eq!(total_after_success, 5000);

    // Retry (with different proof) in same period: fails with AlreadyPaid.
    let (pa2, pb2, pc2, null2) = make_proof(&env, 61);
    let result =
        executor.try_execute_payment(&company_id, &emp, &10_000, &pa2, &pb2, &pc2, &null2, &1);
    assert_eq!(result.unwrap_err().unwrap(), PaymentError::AlreadyPaid);

    // Total must not have changed.
    assert_eq!(executor.get_total_paid(&company_id), total_after_success);
}

// ===========================================================================
// Payout Batch Retry Regression Tests
// ===========================================================================

/// R-4 + R-1: After a partial batch failure, retrying only the remaining
/// unpaid employees with the same settlement receipt succeeds without
/// double-paying the already-paid employee.
#[test]
fn test_partial_batch_failure_retry_remaining_with_same_receipt() {
    let env = Env::default();
    let (executor, registry, commitment_client, token, company_id, _admin, treasury) =
        setup_system(&env);

    let (emp1, _) = register_employee(&env, &registry, &commitment_client, company_id, 70);
    let (emp2, _) = register_employee(&env, &registry, &commitment_client, company_id, 71);
    let (emp3, _) = register_employee(&env, &registry, &commitment_client, company_id, 72);

    let (pa1, pb1, pc1, null1) = make_proof(&env, 70);
    let (pa2, pb2, pc2, null2) = make_proof(&env, 71);
    let (pa3, pb3, pc3, null3) = make_proof(&env, 72);

    let mut employees = Vec::new(&env);
    let mut amounts = Vec::new(&env);
    let mut proofs_a = Vec::new(&env);
    let mut proofs_b = Vec::new(&env);
    let mut proofs_c = Vec::new(&env);
    let mut nullifiers = Vec::new(&env);

    employees.push_back(emp1.clone());
    amounts.push_back(1000i128);
    proofs_a.push_back(pa1);
    proofs_b.push_back(pb1);
    proofs_c.push_back(pc1);
    nullifiers.push_back(null1);

    employees.push_back(emp2.clone());
    amounts.push_back(500_000i128); // exceeds remaining treasury balance
    proofs_a.push_back(pa2.clone());
    proofs_b.push_back(pb2.clone());
    proofs_c.push_back(pc2.clone());
    nullifiers.push_back(null2.clone());

    employees.push_back(emp3.clone());
    amounts.push_back(1000i128);
    proofs_a.push_back(pa3.clone());
    proofs_b.push_back(pb3.clone());
    proofs_c.push_back(pc3.clone());
    nullifiers.push_back(null3.clone());

    let receipt = BytesN::from_array(&env, &[0xCCu8; 32]);

    // Leave only 1000 in treasury so emp1 succeeds and emp2 fails.
    token.transfer(&treasury, &Address::generate(&env), &499_000);

    let first_attempt = executor.try_execute_batch_with_receipt(
        &company_id,
        &employees,
        &amounts,
        &proofs_a,
        &proofs_b,
        &proofs_c,
        &nullifiers,
        &1,
        &receipt,
    );
    assert!(first_attempt.is_err(), "batch should fail at emp2");
    assert!(executor.is_paid(&emp1, &1), "emp1 should remain paid");
    assert!(!executor.is_paid(&emp2, &1), "emp2 should remain unpaid");
    assert!(!executor.is_paid(&emp3, &1), "emp3 should remain unpaid");
    assert_eq!(executor.get_total_paid(&company_id), 1000);
    assert!(
        !executor.is_settlement_receipt_used(&receipt),
        "receipt must remain unconsumed after partial failure"
    );

    // Top up treasury and retry only the unpaid employees with the same receipt.
    token.mint(&treasury, &10_000);

    let mut retry_employees = Vec::new(&env);
    let mut retry_amounts = Vec::new(&env);
    let mut retry_proofs_a = Vec::new(&env);
    let mut retry_proofs_b = Vec::new(&env);
    let mut retry_proofs_c = Vec::new(&env);
    let mut retry_nullifiers = Vec::new(&env);

    retry_employees.push_back(emp2.clone());
    retry_amounts.push_back(2000i128);
    retry_proofs_a.push_back(pa2);
    retry_proofs_b.push_back(pb2);
    retry_proofs_c.push_back(pc2);
    retry_nullifiers.push_back(null2);

    retry_employees.push_back(emp3.clone());
    retry_amounts.push_back(1000i128);
    retry_proofs_a.push_back(pa3);
    retry_proofs_b.push_back(pb3);
    retry_proofs_c.push_back(pc3);
    retry_nullifiers.push_back(null3);

    let retry_result = executor.execute_batch_with_receipt(
        &company_id,
        &retry_employees,
        &retry_amounts,
        &retry_proofs_a,
        &retry_proofs_b,
        &retry_proofs_c,
        &retry_nullifiers,
        &1,
        &receipt,
    );
    assert_eq!(retry_result.len(), 2);
    assert!(executor.is_settlement_receipt_used(&receipt));
    assert!(executor.is_paid(&emp1, &1));
    assert!(executor.is_paid(&emp2, &1));
    assert!(executor.is_paid(&emp3, &1));
    assert_eq!(executor.get_total_paid(&company_id), 4000);
}

/// R-4 + R-3: Mistakenly retrying the full batch (including an already-paid
/// employee with a fresh proof) fails with AlreadyPaid and leaves the receipt
/// unconsumed and totals unchanged.
#[test]
fn test_retry_full_batch_after_partial_failure_rejects_already_paid() {
    let env = Env::default();
    let (executor, registry, commitment_client, token, company_id, _admin, treasury) =
        setup_system(&env);

    let (emp1, _) = register_employee(&env, &registry, &commitment_client, company_id, 73);
    let (emp2, _) = register_employee(&env, &registry, &commitment_client, company_id, 74);

    let (pa1, pb1, pc1, null1) = make_proof(&env, 73);
    let (pa2, pb2, pc2, null2) = make_proof(&env, 74);

    let mut employees = Vec::new(&env);
    let mut amounts = Vec::new(&env);
    let mut proofs_a = Vec::new(&env);
    let mut proofs_b = Vec::new(&env);
    let mut proofs_c = Vec::new(&env);
    let mut nullifiers = Vec::new(&env);

    employees.push_back(emp1.clone());
    amounts.push_back(1000i128);
    proofs_a.push_back(pa1);
    proofs_b.push_back(pb1);
    proofs_c.push_back(pc1);
    nullifiers.push_back(null1);

    employees.push_back(emp2.clone());
    amounts.push_back(500_000i128);
    proofs_a.push_back(pa2.clone());
    proofs_b.push_back(pb2.clone());
    proofs_c.push_back(pc2.clone());
    nullifiers.push_back(null2.clone());

    let receipt = BytesN::from_array(&env, &[0xCDu8; 32]);

    token.transfer(&treasury, &Address::generate(&env), &499_000);

    let first_attempt = executor.try_execute_batch_with_receipt(
        &company_id,
        &employees,
        &amounts,
        &proofs_a,
        &proofs_b,
        &proofs_c,
        &nullifiers,
        &1,
        &receipt,
    );
    assert!(first_attempt.is_err());
    assert!(executor.is_paid(&emp1, &1));
    assert!(!executor.is_paid(&emp2, &1));

    // Top up treasury, but mistakenly include emp1 again with a fresh proof.
    token.mint(&treasury, &500_000);
    let (pa1_new, pb1_new, pc1_new, null1_new) = make_proof(&env, 75);

    let mut retry_proofs_a = Vec::new(&env);
    let mut retry_proofs_b = Vec::new(&env);
    let mut retry_proofs_c = Vec::new(&env);
    let mut retry_nullifiers = Vec::new(&env);

    retry_proofs_a.push_back(pa1_new);
    retry_proofs_b.push_back(pb1_new);
    retry_proofs_c.push_back(pc1_new);
    retry_nullifiers.push_back(null1_new);

    retry_proofs_a.push_back(pa2);
    retry_proofs_b.push_back(pb2);
    retry_proofs_c.push_back(pc2);
    retry_nullifiers.push_back(null2);

    let retry_attempt = executor.try_execute_batch_with_receipt(
        &company_id,
        &employees,
        &amounts,
        &retry_proofs_a,
        &retry_proofs_b,
        &retry_proofs_c,
        &retry_nullifiers,
        &1,
        &receipt,
    );
    assert_eq!(
        retry_attempt.unwrap_err().unwrap(),
        PaymentError::AlreadyPaid,
        "retrying an already-paid employee in the same period must fail with AlreadyPaid"
    );
    assert!(!executor.is_settlement_receipt_used(&receipt));
    assert!(!executor.is_paid(&emp2, &1));
    assert_eq!(executor.get_total_paid(&company_id), 1000);
}

// ===========================================================================
// R-5: Closed Period Barrier on Batch Retry
// ===========================================================================

/// Retrying a batch against a closed period returns PeriodClosed without
/// consuming the receipt or mutating state, allowing retry in a new period.
#[test]
fn test_closed_period_rejects_batch_retry_and_preserves_receipt() {
    let env = Env::default();
    let (executor, registry, commitment_client, _token, company_id, _admin, _treasury) =
        setup_system(&env);

    let (emp, _) = register_employee(&env, &registry, &commitment_client, company_id, 80);
    let (pa, pb, pc, null) = make_proof(&env, 80);
    let receipt = BytesN::from_array(&env, &[0xCEu8; 32]);

    let mut employees = Vec::new(&env);
    let mut amounts = Vec::new(&env);
    let mut proofs_a = Vec::new(&env);
    let mut proofs_b = Vec::new(&env);
    let mut proofs_c = Vec::new(&env);
    let mut nullifiers = Vec::new(&env);

    employees.push_back(emp.clone());
    amounts.push_back(2500i128);
    proofs_a.push_back(pa);
    proofs_b.push_back(pb);
    proofs_c.push_back(pc);
    nullifiers.push_back(null);

    // Close period 1 before the batch executes.
    executor.close_period(&company_id, &1);

    let closed_attempt = executor.try_execute_batch_with_receipt(
        &company_id,
        &employees,
        &amounts,
        &proofs_a,
        &proofs_b,
        &proofs_c,
        &nullifiers,
        &1,
        &receipt,
    );
    assert_eq!(
        closed_attempt.unwrap_err().unwrap(),
        PaymentError::PeriodClosed,
        "batch targeting a closed period must be rejected with PeriodClosed"
    );
    assert!(!executor.is_settlement_receipt_used(&receipt));
    assert!(!executor.is_paid(&emp, &1));
    assert_eq!(executor.get_total_paid(&company_id), 0);

    // Open period 2 and retry with the same receipt.
    executor.create_period(&company_id);
    let retry_result = executor.execute_batch_with_receipt(
        &company_id,
        &employees,
        &amounts,
        &proofs_a,
        &proofs_b,
        &proofs_c,
        &nullifiers,
        &2,
        &receipt,
    );
    assert_eq!(retry_result.len(), 1);
    assert!(executor.is_settlement_receipt_used(&receipt));
    assert!(executor.is_paid(&emp, &2));
    assert_eq!(executor.get_total_paid(&company_id), 2500);
}

// ===========================================================================
// R-6: Pre-Validation Failures Preserve Receipt for Retry
// ===========================================================================

/// Empty batch fails with EmptyBatch before consuming the receipt, allowing
/// retry with a populated batch and the same receipt.
#[test]
fn test_empty_batch_preserves_receipt_for_retry() {
    let env = Env::default();
    let (executor, registry, commitment_client, _token, company_id, _admin, _treasury) =
        setup_system(&env);

    let receipt = BytesN::from_array(&env, &[0xCFu8; 32]);

    let empty_employees = Vec::new(&env);
    let empty_amounts = Vec::new(&env);
    let empty_proofs_a = Vec::new(&env);
    let empty_proofs_b = Vec::new(&env);
    let empty_proofs_c = Vec::new(&env);
    let empty_nullifiers = Vec::new(&env);

    let empty_attempt = executor.try_execute_batch_with_receipt(
        &company_id,
        &empty_employees,
        &empty_amounts,
        &empty_proofs_a,
        &empty_proofs_b,
        &empty_proofs_c,
        &empty_nullifiers,
        &1,
        &receipt,
    );
    assert_eq!(
        empty_attempt.unwrap_err().unwrap(),
        PaymentError::EmptyBatch
    );
    assert!(!executor.is_settlement_receipt_used(&receipt));
    assert_eq!(executor.get_total_paid(&company_id), 0);

    // Retry with a valid batch and the same receipt.
    let (emp, _) = register_employee(&env, &registry, &commitment_client, company_id, 81);
    let (pa, pb, pc, null) = make_proof(&env, 81);

    let mut employees = Vec::new(&env);
    let mut amounts = Vec::new(&env);
    let mut proofs_a = Vec::new(&env);
    let mut proofs_b = Vec::new(&env);
    let mut proofs_c = Vec::new(&env);
    let mut nullifiers = Vec::new(&env);

    employees.push_back(emp.clone());
    amounts.push_back(1500i128);
    proofs_a.push_back(pa);
    proofs_b.push_back(pb);
    proofs_c.push_back(pc);
    nullifiers.push_back(null);

    let retry_result = executor.execute_batch_with_receipt(
        &company_id,
        &employees,
        &amounts,
        &proofs_a,
        &proofs_b,
        &proofs_c,
        &nullifiers,
        &1,
        &receipt,
    );
    assert_eq!(retry_result.len(), 1);
    assert!(executor.is_settlement_receipt_used(&receipt));
    assert!(executor.is_paid(&emp, &1));
    assert_eq!(executor.get_total_paid(&company_id), 1500);
}

/// Oversized batch fails with BatchTooLarge before mutating state or consuming
/// the receipt, allowing retry with a within-limit batch and the same receipt.
#[test]
fn test_oversized_batch_preserves_receipt_for_retry() {
    let env = Env::default();
    let (executor, registry, commitment_client, _token, company_id, _admin, _treasury) =
        setup_system(&env);

    executor.set_max_batch_size(&company_id, &1u32);

    let (emp1, _) = register_employee(&env, &registry, &commitment_client, company_id, 82);
    let (emp2, _) = register_employee(&env, &registry, &commitment_client, company_id, 83);

    let (pa1, pb1, pc1, null1) = make_proof(&env, 82);
    let (pa2, pb2, pc2, null2) = make_proof(&env, 83);
    let receipt = BytesN::from_array(&env, &[0xD0u8; 32]);

    let mut employees = Vec::new(&env);
    let mut amounts = Vec::new(&env);
    let mut proofs_a = Vec::new(&env);
    let mut proofs_b = Vec::new(&env);
    let mut proofs_c = Vec::new(&env);
    let mut nullifiers = Vec::new(&env);

    employees.push_back(emp1.clone());
    amounts.push_back(1000i128);
    proofs_a.push_back(pa1.clone());
    proofs_b.push_back(pb1.clone());
    proofs_c.push_back(pc1.clone());
    nullifiers.push_back(null1.clone());

    employees.push_back(emp2.clone());
    amounts.push_back(1000i128);
    proofs_a.push_back(pa2);
    proofs_b.push_back(pb2);
    proofs_c.push_back(pc2);
    nullifiers.push_back(null2);

    let oversized_attempt = executor.try_execute_batch_with_receipt(
        &company_id,
        &employees,
        &amounts,
        &proofs_a,
        &proofs_b,
        &proofs_c,
        &nullifiers,
        &1,
        &receipt,
    );
    assert_eq!(
        oversized_attempt.unwrap_err().unwrap(),
        PaymentError::BatchTooLarge
    );
    assert!(!executor.is_settlement_receipt_used(&receipt));
    assert!(!executor.is_paid(&emp1, &1));
    assert!(!executor.is_paid(&emp2, &1));
    assert_eq!(executor.get_total_paid(&company_id), 0);

    // Retry with a single-employee batch within the configured limit.
    let mut retry_employees = Vec::new(&env);
    let mut retry_amounts = Vec::new(&env);
    let mut retry_proofs_a = Vec::new(&env);
    let mut retry_proofs_b = Vec::new(&env);
    let mut retry_proofs_c = Vec::new(&env);
    let mut retry_nullifiers = Vec::new(&env);

    retry_employees.push_back(emp1.clone());
    retry_amounts.push_back(1000i128);
    retry_proofs_a.push_back(pa1);
    retry_proofs_b.push_back(pb1);
    retry_proofs_c.push_back(pc1);
    retry_nullifiers.push_back(null1);

    let retry_result = executor.execute_batch_with_receipt(
        &company_id,
        &retry_employees,
        &retry_amounts,
        &retry_proofs_a,
        &retry_proofs_b,
        &retry_proofs_c,
        &retry_nullifiers,
        &1,
        &receipt,
    );
    assert_eq!(retry_result.len(), 1);
    assert!(executor.is_settlement_receipt_used(&receipt));
    assert!(executor.is_paid(&emp1, &1));
    assert_eq!(executor.get_total_paid(&company_id), 1000);
}

/// R-2 + R-1: A batch containing a reused nullifier fails with ProofAlreadyUsed
/// and leaves the receipt unconsumed so retrying with a fresh proof succeeds.
#[test]
fn test_batch_reused_nullifier_preserves_receipt_for_fresh_retry() {
    let env = Env::default();
    let (executor, registry, commitment_client, _token, company_id, _admin, _treasury) =
        setup_system(&env);

    let (emp1, _) = register_employee(&env, &registry, &commitment_client, company_id, 84);
    let (emp2, _) = register_employee(&env, &registry, &commitment_client, company_id, 85);

    let (pa1, pb1, pc1, null1) = make_proof(&env, 84);
    let (pa2, pb2, pc2, null2) = make_proof(&env, 85);
    let receipt = BytesN::from_array(&env, &[0xD1u8; 32]);

    // Pay emp1 individually, consuming null1.
    executor.execute_payment(&company_id, &emp1, &1000, &pa1, &pb1, &pc1, &null1, &1);
    assert_eq!(executor.get_total_paid(&company_id), 1000);

    // Attempt batch for emp2 reusing null1.
    let mut employees = Vec::new(&env);
    let mut amounts = Vec::new(&env);
    let mut proofs_a = Vec::new(&env);
    let mut proofs_b = Vec::new(&env);
    let mut proofs_c = Vec::new(&env);
    let mut stale_nullifiers = Vec::new(&env);

    employees.push_back(emp2.clone());
    amounts.push_back(2000i128);
    proofs_a.push_back(pa2.clone());
    proofs_b.push_back(pb2.clone());
    proofs_c.push_back(pc2.clone());
    stale_nullifiers.push_back(null1);

    let stale_attempt = executor.try_execute_batch_with_receipt(
        &company_id,
        &employees,
        &amounts,
        &proofs_a,
        &proofs_b,
        &proofs_c,
        &stale_nullifiers,
        &1,
        &receipt,
    );
    assert_eq!(
        stale_attempt.unwrap_err().unwrap(),
        PaymentError::ProofAlreadyUsed
    );
    assert!(!executor.is_settlement_receipt_used(&receipt));
    assert!(!executor.is_paid(&emp2, &1));
    assert_eq!(executor.get_total_paid(&company_id), 1000);

    // Retry with a fresh nullifier and the same receipt.
    let mut fresh_nullifiers = Vec::new(&env);
    fresh_nullifiers.push_back(null2);

    let retry_result = executor.execute_batch_with_receipt(
        &company_id,
        &employees,
        &amounts,
        &proofs_a,
        &proofs_b,
        &proofs_c,
        &fresh_nullifiers,
        &1,
        &receipt,
    );
    assert_eq!(retry_result.len(), 1);
    assert!(executor.is_settlement_receipt_used(&receipt));
    assert!(executor.is_paid(&emp2, &1));
    assert_eq!(executor.get_total_paid(&company_id), 3000);
}
