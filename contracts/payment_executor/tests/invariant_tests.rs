// Issue #221: Contract invariant tests for payroll totals
//
// These tests verify that the financial invariants of the payment_executor
// contract are preserved across all operations that touch totals,
// commitments, or state transitions.
//
// Invariants under test:
//   I-1. get_total_paid strictly equals the sum of all individual payment
//        amounts that succeeded within a company, regardless of period.
//   I-2. get_total_paid never decreases — it is a monotonically increasing
//        accumulator; even after closing a period the total is preserved.
//   I-3. is_paid is keyed per (employee, period): paying the same employee
//        in different periods produces independent paid-flags.
//   I-4. A nullifier is global: reusing it across periods returns
//        ProofAlreadyUsed and does NOT update the running total.
//   I-5. A closed period returns PeriodClosed for any new payment attempt
//        and the total remains unchanged.
//   I-6. Batch execution total equals the sum of individual amounts.
//   I-7. Payments for different companies are isolated — one company's
//        total is never contaminated by another's.
//   I-8. A period starts with payment_count == 0 and the count increments
//        exactly once per successful payment.
//   I-9. An AlreadyPaid retry does not alter the running total.
//   I-10. Zero-amount payments are included in is_paid but contribute 0
//         to get_total_paid.

use ::token::{Token, TokenClient};
use payment_executor::{ContractAddresses, PaymentError, PaymentExecutor, PaymentExecutorClient};
use payroll_registry::{PayrollRegistry, PayrollRegistryClient};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, Vec};

// ---------------------------------------------------------------------------
// Shared helpers (mirrors the pattern used in recovery_tests.rs)
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

/// Wire all five contracts together.
/// Period 1 is pre-opened; treasury is pre-funded with `treasury_balance` tokens.
fn setup_system<'a>(
    env: &'a Env,
    treasury_balance: i128,
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
    commitment_client.set_payroll_operator(&executor_id);

    let admin = Address::generate(env);
    let treasury = Address::generate(env);
    let company_id = registry.register_company(&admin, &treasury);

    executor.create_period(&company_id);

    if treasury_balance > 0 {
        token.mint(&treasury, &treasury_balance);
    }

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

/// Build proof + nullifier byte arrays for a payment.
/// `seed` must be unique per payment so proofs/nullifiers never collide.
fn make_proof(env: &Env, seed: u8) -> (BytesN<64>, BytesN<128>, BytesN<64>, BytesN<32>) {
    (
        BytesN::from_array(env, &[seed; 64]),
        BytesN::from_array(env, &[seed; 128]),
        BytesN::from_array(env, &[seed; 64]),
        BytesN::from_array(env, &[seed; 32]),
    )
}

// ===========================================================================
// I-1. get_total_paid equals the arithmetic sum of all successful amounts
// ===========================================================================

/// Pay three employees with distinct amounts inside the same period.
/// The running total must equal the exact arithmetic sum at every step and
/// must not drift due to rounding, truncation, or double-counting.
#[test]
fn test_total_equals_sum_of_individual_payments() {
    let env = Env::default();
    let (executor, registry, commitment_client, _token, company_id, _admin, _treasury) =
        setup_system(&env, 500_000);

    let amounts: [i128; 3] = [10_000, 25_500, 7_777];
    let mut expected_total: i128 = 0;

    for (i, &amount) in amounts.iter().enumerate() {
        let seed = (10 + i) as u8;
        let (emp, _) = register_employee(&env, &registry, &commitment_client, company_id, seed);
        let (pa, pb, pc, null) = make_proof(&env, seed);
        executor.execute_payment(&company_id, &emp, &amount, &pa, &pb, &pc, &null, &1);

        expected_total += amount;
        assert_eq!(
            executor.get_total_paid(&company_id),
            expected_total,
            "running total mismatch after payment {i}"
        );
    }

    // Final assertion: total == sum of all amounts
    assert_eq!(
        executor.get_total_paid(&company_id),
        amounts.iter().sum::<i128>()
    );
}

// ===========================================================================
// I-2. get_total_paid is monotonically non-decreasing
// ===========================================================================

/// After closing a period and opening a new one, the running total is
/// preserved from the previous period and only grows from that baseline.
#[test]
fn test_total_is_preserved_across_period_close_and_reopen() {
    let env = Env::default();
    let (executor, registry, commitment_client, _token, company_id, _admin, _treasury) =
        setup_system(&env, 500_000);

    // Pay one employee in period 1.
    let (emp1, _) = register_employee(&env, &registry, &commitment_client, company_id, 20);
    let (pa1, pb1, pc1, null1) = make_proof(&env, 20);
    executor.execute_payment(&company_id, &emp1, &30_000, &pa1, &pb1, &pc1, &null1, &1);
    let total_after_period1 = executor.get_total_paid(&company_id);
    assert_eq!(total_after_period1, 30_000);

    // Close period 1 and open period 2.
    executor.close_period(&company_id, &1);
    executor.create_period(&company_id);

    // Total must not have changed after the close/reopen cycle.
    assert_eq!(
        executor.get_total_paid(&company_id),
        total_after_period1,
        "total must be preserved after closing a period"
    );

    // Pay a second employee in period 2 — total must grow monotonically.
    let (emp2, _) = register_employee(&env, &registry, &commitment_client, company_id, 21);
    let (pa2, pb2, pc2, null2) = make_proof(&env, 21);
    executor.execute_payment(&company_id, &emp2, &15_000, &pa2, &pb2, &pc2, &null2, &2);

    assert_eq!(
        executor.get_total_paid(&company_id),
        45_000,
        "total must grow after a payment in the new period"
    );
}

// ===========================================================================
// I-3. is_paid is scoped to (employee, period) — independent across periods
// ===========================================================================

/// The same employee can receive exactly one payment per period. Paying them
/// in period 1 must not mark them as paid in period 2, and vice versa.
#[test]
fn test_is_paid_is_scoped_to_employee_and_period() {
    let env = Env::default();
    let (executor, registry, commitment_client, _token, company_id, _admin, _treasury) =
        setup_system(&env, 500_000);

    let (emp, _) = register_employee(&env, &registry, &commitment_client, company_id, 30);

    // Pay in period 1 with nullifier seed 31.
    let (pa1, pb1, pc1, null1) = make_proof(&env, 31);
    executor.execute_payment(&company_id, &emp, &5_000, &pa1, &pb1, &pc1, &null1, &1);

    assert!(executor.is_paid(&emp, &1), "should be paid in period 1");
    assert!(
        !executor.is_paid(&emp, &2),
        "must NOT be marked paid in period 2 yet"
    );

    // Open period 2 and pay with a fresh nullifier.
    executor.close_period(&company_id, &1);
    executor.create_period(&company_id);
    let (pa2, pb2, pc2, null2) = make_proof(&env, 32);
    executor.execute_payment(&company_id, &emp, &6_000, &pa2, &pb2, &pc2, &null2, &2);

    assert!(
        executor.is_paid(&emp, &1),
        "period 1 paid flag must still be set"
    );
    assert!(executor.is_paid(&emp, &2), "should now be paid in period 2");
}

// ===========================================================================
// I-4. Nullifier uniqueness is global — reuse across periods is rejected
//      and does NOT update the running total
// ===========================================================================

/// Submitting the exact same nullifier in a different period must return
/// ProofAlreadyUsed. The running total must remain at its pre-attempt value.
#[test]
fn test_reused_nullifier_is_rejected_and_total_unchanged() {
    let env = Env::default();
    let (executor, registry, commitment_client, _token, company_id, _admin, _treasury) =
        setup_system(&env, 500_000);

    let (emp1, _) = register_employee(&env, &registry, &commitment_client, company_id, 40);
    let (emp2, _) = register_employee(&env, &registry, &commitment_client, company_id, 41);

    // First payment — establishes the nullifier globally.
    let (pa, pb, pc, null) = make_proof(&env, 40);
    executor.execute_payment(&company_id, &emp1, &20_000, &pa, &pb, &pc, &null, &1);
    let total_before = executor.get_total_paid(&company_id);
    assert_eq!(total_before, 20_000);

    // Open period 2.
    executor.close_period(&company_id, &1);
    executor.create_period(&company_id);

    // Replay the same nullifier for a different employee in period 2.
    let result =
        executor.try_execute_payment(&company_id, &emp2, &20_000, &pa, &pb, &pc, &null, &2);
    assert_eq!(
        result.unwrap_err().unwrap(),
        PaymentError::ProofAlreadyUsed,
        "duplicate nullifier must be rejected"
    );

    // Total must not have changed after the rejected replay.
    assert_eq!(
        executor.get_total_paid(&company_id),
        total_before,
        "total must be unchanged after a rejected duplicate nullifier"
    );
}

// ===========================================================================
// I-5. Closed period rejects payments — total unchanged
// ===========================================================================

#[test]
fn test_closed_period_rejects_payment_and_total_unchanged() {
    let env = Env::default();
    let (executor, registry, commitment_client, _token, company_id, _admin, _treasury) =
        setup_system(&env, 500_000);

    let (emp1, _) = register_employee(&env, &registry, &commitment_client, company_id, 50);
    let (pa1, pb1, pc1, null1) = make_proof(&env, 50);
    executor.execute_payment(&company_id, &emp1, &8_000, &pa1, &pb1, &pc1, &null1, &1);
    let total_before_close = executor.get_total_paid(&company_id);

    executor.close_period(&company_id, &1);

    let (emp2, _) = register_employee(&env, &registry, &commitment_client, company_id, 51);
    let (pa2, pb2, pc2, null2) = make_proof(&env, 51);
    let result =
        executor.try_execute_payment(&company_id, &emp2, &5_000, &pa2, &pb2, &pc2, &null2, &1);
    assert_eq!(result.unwrap_err().unwrap(), PaymentError::PeriodClosed);
    assert_eq!(
        executor.get_total_paid(&company_id),
        total_before_close,
        "total must be unchanged after a PeriodClosed rejection"
    );
}

// ===========================================================================
// I-6. Batch total equals sum of individual amounts
// ===========================================================================

#[test]
fn test_batch_total_equals_sum_of_amounts() {
    let env = Env::default();
    let (executor, registry, commitment_client, _token, company_id, _admin, _treasury) =
        setup_system(&env, 500_000);

    let batch_amounts: [i128; 4] = [1_000, 2_000, 3_000, 4_000];
    let mut employees = soroban_sdk::Vec::new(&env);
    let mut amounts = soroban_sdk::Vec::new(&env);
    let mut proofs_a = soroban_sdk::Vec::new(&env);
    let mut proofs_b = soroban_sdk::Vec::new(&env);
    let mut proofs_c = soroban_sdk::Vec::new(&env);
    let mut nullifiers = soroban_sdk::Vec::new(&env);

    for (i, &amount) in batch_amounts.iter().enumerate() {
        let seed = (60 + i) as u8;
        let (emp, _) = register_employee(&env, &registry, &commitment_client, company_id, seed);
        let (pa, pb, pc, null) = make_proof(&env, seed);
        employees.push_back(emp);
        amounts.push_back(amount);
        proofs_a.push_back(pa);
        proofs_b.push_back(pb);
        proofs_c.push_back(pc);
        nullifiers.push_back(null);
    }

    executor.execute_batch_payroll(
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
        executor.get_total_paid(&company_id),
        batch_amounts.iter().sum::<i128>(),
        "batch total must equal sum of individual amounts"
    );
}

// ===========================================================================
// I-7. Totals for different companies are fully isolated
// ===========================================================================

#[test]
fn test_company_totals_are_isolated() {
    let env = Env::default();
    let (executor, registry, commitment_client, token, company_id_a, _admin_a, _treasury_a) =
        setup_system(&env, 100_000);

    // Register a second independent company on the same executor.
    let admin_b = soroban_sdk::Address::generate(&env);
    let treasury_b = soroban_sdk::Address::generate(&env);
    let company_id_b = registry.register_company(&admin_b, &treasury_b);
    executor.create_period(&company_id_b);
    token.mint(&treasury_b, &100_000);

    let (emp_a, _) = register_employee(&env, &registry, &commitment_client, company_id_a, 70);
    let (emp_b, _) = register_employee(&env, &registry, &commitment_client, company_id_b, 71);

    let (pa_a, pb_a, pc_a, null_a) = make_proof(&env, 70);
    let (pa_b, pb_b, pc_b, null_b) = make_proof(&env, 71);

    executor.execute_payment(
        &company_id_a,
        &emp_a,
        &40_000,
        &pa_a,
        &pb_a,
        &pc_a,
        &null_a,
        &1,
    );
    executor.execute_payment(
        &company_id_b,
        &emp_b,
        &55_000,
        &pa_b,
        &pb_b,
        &pc_b,
        &null_b,
        &1,
    );

    assert_eq!(
        executor.get_total_paid(&company_id_a),
        40_000,
        "company A total contaminated"
    );
    assert_eq!(
        executor.get_total_paid(&company_id_b),
        55_000,
        "company B total contaminated"
    );
}

// ===========================================================================
// I-8. period.payment_count increments exactly once per successful payment
// ===========================================================================

#[test]
fn test_period_payment_count_increments_per_payment() {
    let env = Env::default();
    let (executor, registry, commitment_client, _token, company_id, _admin, _treasury) =
        setup_system(&env, 500_000);

    let period_before = executor.get_period(&company_id, &1).unwrap();
    assert_eq!(
        period_before.payment_count, 0,
        "fresh period must start at 0"
    );

    for i in 0u8..3 {
        let seed = 80 + i;
        let (emp, _) = register_employee(&env, &registry, &commitment_client, company_id, seed);
        let (pa, pb, pc, null) = make_proof(&env, seed);
        let res = executor.try_execute_payment(&company_id, &emp, &1_000, &pa, &pb, &pc, &null, &1);
        assert!(res.is_ok(), "execute_payment failed: {:?}", res);

        let period = executor.get_period(&company_id, &1).unwrap();
        assert_eq!(
            period.payment_count,
            (i + 1) as u32,
            "payment_count must be {} after {} payments",
            i + 1,
            i + 1
        );
    }
}

// ===========================================================================
// I-9. AlreadyPaid retry does not alter the running total
// ===========================================================================

#[test]
fn test_already_paid_retry_does_not_alter_total() {
    let env = Env::default();
    let (executor, registry, commitment_client, _token, company_id, _admin, _treasury) =
        setup_system(&env, 500_000);

    let (emp, _) = register_employee(&env, &registry, &commitment_client, company_id, 90);
    let (pa, pb, pc, null) = make_proof(&env, 90);
    executor.execute_payment(&company_id, &emp, &12_000, &pa, &pb, &pc, &null, &1);
    let total_after_first = executor.get_total_paid(&company_id);

    // Different nullifier so it doesn't fail on ProofAlreadyUsed first.
    let (pa2, pb2, pc2, null2) = make_proof(&env, 91);
    let result =
        executor.try_execute_payment(&company_id, &emp, &12_000, &pa2, &pb2, &pc2, &null2, &1);
    assert_eq!(result.unwrap_err().unwrap(), PaymentError::AlreadyPaid);
    assert_eq!(
        executor.get_total_paid(&company_id),
        total_after_first,
        "total must be unchanged after an AlreadyPaid rejection"
    );
}

// ===========================================================================
// I-10. Zero-amount payments set is_paid but contribute 0 to total
// ===========================================================================

#[test]
fn test_zero_amount_sets_paid_flag_but_contributes_zero_to_total() {
    let env = Env::default();
    let (executor, registry, commitment_client, _token, company_id, _admin, _treasury) =
        setup_system(&env, 500_000);

    let (emp, _) = register_employee(&env, &registry, &commitment_client, company_id, 100);
    let (pa, pb, pc, null) = make_proof(&env, 100);
    executor.execute_payment(&company_id, &emp, &0, &pa, &pb, &pc, &null, &1);

    assert!(
        executor.is_paid(&emp, &1),
        "zero-amount employee must be marked paid"
    );
    assert_eq!(
        executor.get_total_paid(&company_id),
        0,
        "zero-amount payment must contribute 0 to total"
    );
}

// ===========================================================================
// I-11. Multi-period cumulative total correctness
//       Payments across N periods must sum correctly into a single total
// ===========================================================================

#[test]
fn test_cumulative_total_across_multiple_periods() {
    let env = Env::default();
    let (executor, registry, commitment_client, _token, company_id, _admin, _treasury) =
        setup_system(&env, 500_000);

    let period_amounts: [i128; 3] = [10_000, 20_000, 30_000];
    let mut expected = 0i128;

    for (period_idx, &amount) in period_amounts.iter().enumerate() {
        let period_num = (period_idx + 1) as u32;
        let seed = (110 + period_idx) as u8;

        let (emp, _) = register_employee(&env, &registry, &commitment_client, company_id, seed);
        let (pa, pb, pc, null) = make_proof(&env, seed);
        executor.execute_payment(
            &company_id,
            &emp,
            &amount,
            &pa,
            &pb,
            &pc,
            &null,
            &period_num,
        );

        expected += amount;
        assert_eq!(executor.get_total_paid(&company_id), expected);

        // Close current period and open the next (unless it's the last).
        if period_idx < period_amounts.len() - 1 {
            executor.close_period(&company_id, &period_num);
            executor.create_period(&company_id);
        }
    }

    assert_eq!(
        executor.get_total_paid(&company_id),
        period_amounts.iter().sum::<i128>(),
        "cumulative total across periods must equal sum of all payments"
    );
}
