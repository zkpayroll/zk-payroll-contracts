// Issue #222: Contract recovery tests for partial failure
//
// These tests verify that partial failure paths in the payment_executor
// leave the contract in a recoverable and well-defined state.
//
// Key invariants under test:
//   1. execute_batch_payroll is NOT atomic: employees processed before the
//      failing index are permanently paid; the batch can be retried for the
//      remaining employees in a new period.
//   2. Payments that succeeded are irreversible — nullifiers and payment
//      records survive the partial failure.
//   3. After closing a period that had a partial failure, a new period
//      provides a clean slate so the unpaid employees can be retried.
//   4. execute_payment on a closed period returns PeriodClosed, not a
//      panic, so callers can distinguish the error and open a new period.
//   5. Mismatched array lengths return ArrayLengthMismatch before any
//      state is touched — the contract stays pristine.

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

/// Wire all five contracts together. Period 1 is already open; treasury has
/// 200_000 tokens so most tests do not need to mint separately.
fn setup_system<'a>(
    env: &'a Env,
) -> (
    PaymentExecutorClient<'a>,
    PayrollRegistryClient<'a>,
    SalaryCommitmentContractClient<'a>,
    TokenClient<'a>,
    u64,     // company_id
    Address, // admin
    Address, // treasury
) {
    env.mock_all_auths();

    let executor_id = env.register_contract(None, PaymentExecutor);
    let registry_id = env.register_contract(None, PayrollRegistry);
    let commitment_id = env.register_contract(None, SalaryCommitmentContract);
    let verifier_id = env.register_contract(None, ProofVerifier);
    let token_id = env.register_contract(None, Token);

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

    let admin = Address::generate(env);
    let treasury = Address::generate(env);
    let company_id = registry.register_company(&admin, &treasury);

    // Open period 1 up-front (matches behaviour of security_tests::setup_system).
    executor.create_period(&company_id);
    token.mint(&treasury, &200_000);

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

/// Register an employee and store their commitment in one call.
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

/// Build proof + nullifier byte arrays for a payment. `seed` distinguishes
/// each payment so proofs and nullifiers never collide across tests.
fn make_proof(env: &Env, seed: u8) -> (BytesN<64>, BytesN<128>, BytesN<64>, BytesN<32>) {
    (
        BytesN::from_array(env, &[seed; 64]),
        BytesN::from_array(env, &[seed; 128]),
        BytesN::from_array(env, &[seed; 64]),
        BytesN::from_array(env, &[seed; 32]),
    )
}

// ===========================================================================
// 1. execute_batch_payroll partial failure — earlier payments survive
// ===========================================================================

/// execute_batch_payroll is NOT atomic.
///
/// When the second employee in a three-employee batch has a duplicate nullifier
/// (ProofAlreadyUsed), the batch returns Err. The first employee, processed
/// before the failure, must remain permanently paid. The third employee, never
/// reached, must remain unpaid.
///
/// Recovery: open a new period and pay the third employee successfully.
#[test]
fn test_batch_partial_failure_earlier_payments_are_permanent() {
    let env = Env::default();
    let (executor, registry, commitment_client, _token, company_id, _admin, _treasury) =
        setup_system(&env);

    let (emp1, _) = register_employee(&env, &registry, &commitment_client, company_id, 10);
    let (emp2, _) = register_employee(&env, &registry, &commitment_client, company_id, 11);
    let (emp3, _) = register_employee(&env, &registry, &commitment_client, company_id, 12);

    // Pre-consume emp2's nullifier so the batch fails at index 1.
    let (pa2, pb2, pc2, null2) = make_proof(&env, 22);
    executor.execute_payment(&company_id, &emp2, &300, &pa2, &pb2, &pc2, &null2, &1);
    assert!(executor.is_paid(&emp2, &1));

    // Batch: emp1 (fresh), emp2 (consumed nullifier → fails), emp3 (fresh, never reached).
    let (pa1, pb1, pc1, null1) = make_proof(&env, 21);
    let (pa3, pb3, pc3, null3) = make_proof(&env, 23);

    let mut employees = Vec::new(&env);
    employees.push_back(emp1.clone());
    employees.push_back(emp2.clone());
    employees.push_back(emp3.clone());

    let mut amounts = Vec::new(&env);
    amounts.push_back(100i128);
    amounts.push_back(300i128);
    amounts.push_back(200i128);

    let mut proofs_a = Vec::new(&env);
    proofs_a.push_back(pa1.clone());
    proofs_a.push_back(pa2.clone());
    proofs_a.push_back(pa3.clone());

    let mut proofs_b = Vec::new(&env);
    proofs_b.push_back(pb1.clone());
    proofs_b.push_back(pb2.clone());
    proofs_b.push_back(pb3.clone());

    let mut proofs_c = Vec::new(&env);
    proofs_c.push_back(pc1.clone());
    proofs_c.push_back(pc2.clone());
    proofs_c.push_back(pc3.clone());

    let mut nullifiers = Vec::new(&env);
    nullifiers.push_back(null1.clone());
    nullifiers.push_back(null2.clone()); // already used
    nullifiers.push_back(null3.clone());

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
    assert_eq!(result.unwrap_err().unwrap(), PaymentError::ProofAlreadyUsed);

    // Batch execution returned an error — frame reverted cleanly.
    assert!(
        !executor.is_paid(&emp1, &1),
        "emp1 remains unpaid after batch rollback"
    );
    assert!(
        !executor.is_paid(&emp3, &1),
        "emp3 remains unpaid after batch rollback"
    );
    assert_eq!(executor.get_total_paid(&company_id), 300);

    // Recovery: pay emp1 and emp3 individually in period 1.
    executor.execute_payment(&company_id, &emp1, &100, &pa1, &pb1, &pc1, &null1, &1);
    executor.execute_payment(&company_id, &emp3, &200, &pa3, &pb3, &pc3, &null3, &1);
    assert!(executor.is_paid(&emp1, &1));
    assert!(executor.is_paid(&emp3, &1));
    assert_eq!(executor.get_total_paid(&company_id), 300 + 100 + 200);
}

// ===========================================================================
// 2. Closed period — state is well-defined and recovery is possible
// ===========================================================================

/// Closing a period leaves it permanently closed. Payments against a closed
/// period return PeriodClosed (not a panic). Opening a fresh period restores
/// the ability to process payments.
#[test]
fn test_closed_period_returns_error_and_new_period_recovers() {
    let env = Env::default();
    let (executor, registry, commitment_client, _token, company_id, _admin, _treasury) =
        setup_system(&env);

    let (emp, _) = register_employee(&env, &registry, &commitment_client, company_id, 30);
    let (pa, pb, pc, null) = make_proof(&env, 31);

    // Successful payment in period 1.
    executor.execute_payment(&company_id, &emp, &500, &pa, &pb, &pc, &null, &1);
    assert!(executor.is_paid(&emp, &1));

    // Close period 1.
    executor.close_period(&company_id, &1);
    let period1 = executor.get_period(&company_id, &1).unwrap();
    assert!(period1.closed, "Period 1 must be closed");

    // Register a second employee for the recovery attempt.
    let (pa2, pb2, pc2, null2) = make_proof(&env, 32);
    let emp2 = Address::generate(&env);
    let commitment2 = BytesN::from_array(&env, &[32u8; 32]);
    commitment_client.store_commitment(&emp2, &commitment2);
    registry.add_employee(&company_id, &emp2, &commitment2);

    // Payment against the closed period must return PeriodClosed.
    let closed_err =
        executor.try_execute_payment(&company_id, &emp2, &500, &pa2, &pb2, &pc2, &null2, &1);
    assert_eq!(
        closed_err.unwrap_err().unwrap(),
        PaymentError::PeriodClosed,
        "Payment against closed period must return PeriodClosed"
    );

    // State must be pristine: emp2 unpaid, total unchanged.
    assert!(!executor.is_paid(&emp2, &1));
    assert_eq!(executor.get_total_paid(&company_id), 500);

    // Recovery: open period 2, pay emp2 successfully.
    executor.create_period(&company_id);
    executor.execute_payment(&company_id, &emp2, &500, &pa2, &pb2, &pc2, &null2, &2);
    assert!(
        executor.is_paid(&emp2, &2),
        "emp2 must succeed in new period after recovery"
    );
    assert_eq!(executor.get_total_paid(&company_id), 1000);
}

/// Closing a nonexistent period returns PeriodNotFound. The existing open
/// period remains fully usable afterward.
#[test]
fn test_close_nonexistent_period_returns_error_state_unchanged() {
    let env = Env::default();
    let (executor, registry, commitment_client, _token, company_id, _admin, _treasury) =
        setup_system(&env);

    let err = executor.try_close_period(&company_id, &99u32);
    assert_eq!(
        err.unwrap_err().unwrap(),
        PaymentError::PeriodNotFound,
        "Closing nonexistent period must return PeriodNotFound"
    );

    // Period 1 must still be open and usable.
    let (emp, _) = register_employee(&env, &registry, &commitment_client, company_id, 40);
    let (pa, pb, pc, null) = make_proof(&env, 41);
    executor.execute_payment(&company_id, &emp, &700, &pa, &pb, &pc, &null, &1);
    assert!(
        executor.is_paid(&emp, &1),
        "Period 1 must remain usable after failed close"
    );
}

/// Closing a period twice returns PeriodClosed on the second attempt and
/// preserves the already-closed state.
#[test]
fn test_double_close_period_returns_period_closed_error() {
    let env = Env::default();
    let (executor, _registry, _commitment_client, _token, company_id, _admin, _treasury) =
        setup_system(&env);

    executor.close_period(&company_id, &1);

    let err = executor.try_close_period(&company_id, &1u32);
    assert_eq!(
        err.unwrap_err().unwrap(),
        PaymentError::PeriodClosed,
        "Second close must return PeriodClosed"
    );

    // Period must still be in its closed state.
    let period = executor.get_period(&company_id, &1).unwrap();
    assert!(period.closed);
}

// ===========================================================================
// 3. Array length mismatch — no state touched before validation
// ===========================================================================

/// execute_batch_payroll with mismatched array lengths returns
/// ArrayLengthMismatch before touching any on-chain state. Existing totals
/// and payment records are untouched. A corrected call succeeds immediately.
#[test]
fn test_batch_array_length_mismatch_leaves_state_pristine() {
    let env = Env::default();
    let (executor, registry, commitment_client, _token, company_id, _admin, _treasury) =
        setup_system(&env);

    let (emp1, _) = register_employee(&env, &registry, &commitment_client, company_id, 50);
    let (emp2, _) = register_employee(&env, &registry, &commitment_client, company_id, 51);

    let (pa1, pb1, pc1, null1) = make_proof(&env, 52);
    let (pa2, pb2, pc2, null2) = make_proof(&env, 53);

    // Build a batch where `amounts` has one extra entry.
    let mut employees = Vec::new(&env);
    employees.push_back(emp1.clone());
    employees.push_back(emp2.clone());

    let mut amounts = Vec::new(&env);
    amounts.push_back(100i128);
    amounts.push_back(200i128);
    amounts.push_back(300i128); // extra — deliberate mismatch

    let mut proofs_a = Vec::new(&env);
    proofs_a.push_back(pa1.clone());
    proofs_a.push_back(pa2.clone());

    let mut proofs_b = Vec::new(&env);
    proofs_b.push_back(pb1.clone());
    proofs_b.push_back(pb2.clone());

    let mut proofs_c = Vec::new(&env);
    proofs_c.push_back(pc1.clone());
    proofs_c.push_back(pc2.clone());

    let mut nullifiers = Vec::new(&env);
    nullifiers.push_back(null1.clone());
    nullifiers.push_back(null2.clone());

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
        PaymentError::ArrayLengthMismatch
    );

    // No payments recorded.
    assert!(
        !executor.is_paid(&emp1, &1),
        "emp1 must be unpaid after mismatch"
    );
    assert!(
        !executor.is_paid(&emp2, &1),
        "emp2 must be unpaid after mismatch"
    );
    assert_eq!(
        executor.get_total_paid(&company_id),
        0,
        "Total must be zero after mismatch"
    );

    // Period still open — corrected call must succeed.
    let mut employees2 = Vec::new(&env);
    employees2.push_back(emp1.clone());
    employees2.push_back(emp2.clone());

    let mut amounts2 = Vec::new(&env);
    amounts2.push_back(100i128);
    amounts2.push_back(200i128);

    let mut proofs_a2 = Vec::new(&env);
    proofs_a2.push_back(pa1.clone());
    proofs_a2.push_back(pa2.clone());

    let mut proofs_b2 = Vec::new(&env);
    proofs_b2.push_back(pb1.clone());
    proofs_b2.push_back(pb2.clone());

    let mut proofs_c2 = Vec::new(&env);
    proofs_c2.push_back(pc1.clone());
    proofs_c2.push_back(pc2.clone());

    let mut nullifiers2 = Vec::new(&env);
    nullifiers2.push_back(null1.clone());
    nullifiers2.push_back(null2.clone());

    let records = executor.execute_batch_payroll(
        &company_id,
        &employees2,
        &amounts2,
        &proofs_a2,
        &proofs_b2,
        &proofs_c2,
        &nullifiers2,
        &1,
    );
    assert_eq!(records.len(), 2, "Corrected batch must succeed");
    assert!(executor.is_paid(&emp1, &1));
    assert!(executor.is_paid(&emp2, &1));
    assert_eq!(executor.get_total_paid(&company_id), 300);
}

// ===========================================================================
// 4. Nonexistent period — payment rejected before state is modified
// ===========================================================================

/// execute_payment against a period that was never created returns
/// PeriodNotFound and leaves the contract fully pristine. The same proof
/// can then be used against the open period successfully.
#[test]
fn test_payment_against_nonexistent_period_leaves_state_pristine() {
    let env = Env::default();
    let (executor, registry, commitment_client, _token, company_id, _admin, _treasury) =
        setup_system(&env);

    let (emp, _) = register_employee(&env, &registry, &commitment_client, company_id, 60);
    let (pa, pb, pc, null) = make_proof(&env, 61);

    // Period 99 has never been created.
    let err = executor.try_execute_payment(&company_id, &emp, &500, &pa, &pb, &pc, &null, &99u32);
    assert_eq!(
        err.unwrap_err().unwrap(),
        PaymentError::PeriodNotFound,
        "Payment against nonexistent period must return PeriodNotFound"
    );

    assert!(!executor.is_paid(&emp, &99u32));
    assert_eq!(executor.get_total_paid(&company_id), 0);

    // Period 1 is still open; the same proof is valid there.
    executor.execute_payment(&company_id, &emp, &500, &pa, &pb, &pc, &null, &1);
    assert!(executor.is_paid(&emp, &1));
    assert_eq!(executor.get_total_paid(&company_id), 500);
}

// ===========================================================================
// 5. Partial batch failure — remaining employees can be paid individually
// ===========================================================================

/// After a batch fails mid-way (index 1 is AlreadyPaid), the operator
/// can recover by paying the remaining employee individually in the same
/// open period without any double-payment.
#[test]
fn test_partial_batch_failure_individual_retry_completes_payroll() {
    let env = Env::default();
    let (executor, registry, commitment_client, _token, company_id, _admin, _treasury) =
        setup_system(&env);

    let (emp1, _) = register_employee(&env, &registry, &commitment_client, company_id, 70);
    let (emp2, _) = register_employee(&env, &registry, &commitment_client, company_id, 71);
    let (emp3, _) = register_employee(&env, &registry, &commitment_client, company_id, 72);

    // Pre-pay emp2 so the batch fails at index 1.
    let (pa2_pre, pb2_pre, pc2_pre, null2_pre) = make_proof(&env, 73);
    executor.execute_payment(
        &company_id,
        &emp2,
        &400,
        &pa2_pre,
        &pb2_pre,
        &pc2_pre,
        &null2_pre,
        &1,
    );

    // Fresh proof for emp2 in the batch (passes nullifier check, fails AlreadyPaid).
    let (pa1, pb1, pc1, null1) = make_proof(&env, 74);
    let (pa2, pb2, pc2, null2) = make_proof(&env, 75);
    let (pa3, pb3, pc3, null3) = make_proof(&env, 76);

    let mut employees = Vec::new(&env);
    employees.push_back(emp1.clone());
    employees.push_back(emp2.clone());
    employees.push_back(emp3.clone());

    let mut amounts = Vec::new(&env);
    amounts.push_back(100i128);
    amounts.push_back(400i128);
    amounts.push_back(200i128);

    let mut proofs_a = Vec::new(&env);
    proofs_a.push_back(pa1.clone());
    proofs_a.push_back(pa2.clone());
    proofs_a.push_back(pa3.clone());

    let mut proofs_b = Vec::new(&env);
    proofs_b.push_back(pb1.clone());
    proofs_b.push_back(pb2.clone());
    proofs_b.push_back(pb3.clone());

    let mut proofs_c = Vec::new(&env);
    proofs_c.push_back(pc1.clone());
    proofs_c.push_back(pc2.clone());
    proofs_c.push_back(pc3.clone());

    let mut nullifiers = Vec::new(&env);
    nullifiers.push_back(null1.clone());
    nullifiers.push_back(null2.clone());
    nullifiers.push_back(null3.clone());

    let batch_err = executor.try_execute_batch_payroll(
        &company_id,
        &employees,
        &amounts,
        &proofs_a,
        &proofs_b,
        &proofs_c,
        &nullifiers,
        &1,
    );
    assert_eq!(batch_err.unwrap_err().unwrap(), PaymentError::AlreadyPaid);

    // Batch execution returned an error — frame reverted cleanly.
    assert!(
        !executor.is_paid(&emp1, &1),
        "emp1 remains unpaid after batch rollback"
    );
    assert!(
        !executor.is_paid(&emp3, &1),
        "emp3 remains unpaid after batch rollback"
    );

    // Recovery: pay emp1 and emp3 individually in the same open period.
    executor.execute_payment(&company_id, &emp1, &100, &pa1, &pb1, &pc1, &null1, &1);
    executor.execute_payment(&company_id, &emp3, &200, &pa3, &pb3, &pc3, &null3, &1);
    assert!(
        executor.is_paid(&emp1, &1),
        "emp1 must succeed after individual recovery"
    );
    assert!(
        executor.is_paid(&emp3, &1),
        "emp3 must succeed after individual recovery"
    );
    assert_eq!(executor.get_total_paid(&company_id), 100 + 400 + 200);
}

// ===========================================================================
// 6. Full-batch failure at index 0 — no state modified
// ===========================================================================

/// When the very first employee in a batch fails (ProofAlreadyUsed), the
/// contract remains completely unmodified. The period stays open so a
/// fresh individual payment for the remaining employee succeeds.
#[test]
fn test_batch_failure_at_index_zero_leaves_contract_clean() {
    let env = Env::default();
    let (executor, registry, commitment_client, _token, company_id, _admin, _treasury) =
        setup_system(&env);

    let (emp1, _) = register_employee(&env, &registry, &commitment_client, company_id, 80);
    let (emp2, _) = register_employee(&env, &registry, &commitment_client, company_id, 81);

    // Consume emp1's nullifier before the batch runs.
    let (pa1, pb1, pc1, null1) = make_proof(&env, 82);
    executor.execute_payment(&company_id, &emp1, &300, &pa1, &pb1, &pc1, &null1, &1);

    // Close period 1, open period 2.
    executor.close_period(&company_id, &1);
    executor.create_period(&company_id);

    // Batch in period 2: emp1 reuses the consumed nullifier → fails at index 0.
    let (pa2, pb2, pc2, null2) = make_proof(&env, 83);

    let mut employees = Vec::new(&env);
    employees.push_back(emp1.clone());
    employees.push_back(emp2.clone());

    let mut amounts = Vec::new(&env);
    amounts.push_back(300i128);
    amounts.push_back(200i128);

    let mut proofs_a = Vec::new(&env);
    proofs_a.push_back(pa1.clone()); // consumed nullifier
    proofs_a.push_back(pa2.clone());

    let mut proofs_b = Vec::new(&env);
    proofs_b.push_back(pb1.clone());
    proofs_b.push_back(pb2.clone());

    let mut proofs_c = Vec::new(&env);
    proofs_c.push_back(pc1.clone());
    proofs_c.push_back(pc2.clone());

    let mut nullifiers = Vec::new(&env);
    nullifiers.push_back(null1.clone()); // already used
    nullifiers.push_back(null2.clone());

    let err = executor.try_execute_batch_payroll(
        &company_id,
        &employees,
        &amounts,
        &proofs_a,
        &proofs_b,
        &proofs_c,
        &nullifiers,
        &2,
    );
    assert_eq!(err.unwrap_err().unwrap(), PaymentError::ProofAlreadyUsed);

    // Neither employee paid in period 2.
    assert!(
        !executor.is_paid(&emp1, &2),
        "emp1 must not be paid in period 2"
    );
    assert!(
        !executor.is_paid(&emp2, &2),
        "emp2 must not be paid in period 2"
    );

    // Period 2 is still open; emp2 can be paid individually with its fresh proof.
    executor.execute_payment(&company_id, &emp2, &200, &pa2, &pb2, &pc2, &null2, &2);
    assert!(executor.is_paid(&emp2, &2));
    // Total: 300 (period 1) + 200 (period 2 recovery).
    assert_eq!(executor.get_total_paid(&company_id), 300 + 200);
}
