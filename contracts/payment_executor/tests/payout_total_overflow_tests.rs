//! Issue #814: explicit overflow checks on aggregate payout totals.
//!
//! `execute_payment` maintains two aggregate counters:
//! - `TotalPaid(company_id)`: cumulative `i128` amount paid by the company.
//! - `PayrollPeriod::payment_count`: `u32` number of payments in the period.
//!
//! Both are now updated with checked arithmetic that runs before any token
//! transfer or storage write, and `execute_batch_payroll` (and so
//! `execute_batch_with_receipt`) pre-flights the whole batch. An overflow is
//! returned as `PaymentError::Overflow` (code 20), and the rejected call
//! leaves balances, payment records, counters, nullifiers and settlement
//! receipts unchanged.
//!
//! Counters close to their limits are seeded directly in contract storage,
//! since reaching `u32::MAX` payments or `i128::MAX` of volume through real
//! payments is not practical in a unit test.

use ::token::{Token, TokenClient};
use payment_executor::{
    ContractAddresses, DataKey, PaymentError, PaymentExecutor, PaymentExecutorClient, PayrollPeriod,
};
use payroll_registry::{PayrollRegistry, PayrollRegistryClient};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, Vec};

struct Fixture<'a> {
    executor: PaymentExecutorClient<'a>,
    registry: PayrollRegistryClient<'a>,
    commitments: SalaryCommitmentContractClient<'a>,
    token: TokenClient<'a>,
    company_id: u64,
    treasury: Address,
}

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

/// Wires executor, registry, commitments, verifier and token, registers one
/// company with an unfunded treasury and opens period 1.
fn setup(env: &Env) -> Fixture<'_> {
    env.mock_all_auths();

    let executor_id = env.register(PaymentExecutor, ());
    let registry_id = env.register(PayrollRegistry, ());
    let commitment_id = env.register(SalaryCommitmentContract, ());
    let verifier_id = env.register(ProofVerifier, ());
    let token_id = env.register(Token, ());

    let executor = PaymentExecutorClient::new(env, &executor_id);
    let registry = PayrollRegistryClient::new(env, &registry_id);
    let commitments = SalaryCommitmentContractClient::new(env, &commitment_id);
    let verifier = ProofVerifierClient::new(env, &verifier_id);
    let token = TokenClient::new(env, &token_id);

    executor.initialize(&ContractAddresses {
        registry: registry_id,
        commitment: commitment_id,
        verifier: verifier_id,
        token: token_id.clone(),
    });
    verifier.init_verifier_admin(&Address::generate(env));
    verifier.initialize_verifier(&mock_vk(env));
    commitments.init_commitment_admin(&Address::generate(env));

    let treasury = Address::generate(env);
    let company_id = registry.register_company(&Address::generate(env), &treasury);
    executor.create_period(&company_id);

    executor.set_executor_admin(&Address::generate(env));
    executor.set_asset_decimals(&token_id, &7u32);
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

    Fixture {
        executor,
        registry,
        commitments,
        token,
        company_id,
        treasury,
    }
}

fn onboard(env: &Env, f: &Fixture, seed: u8) -> Address {
    let employee = Address::generate(env);
    let commitment = BytesN::from_array(env, &[seed; 32]);
    f.commitments.store_commitment(&employee, &commitment);
    f.registry
        .add_employee(&f.company_id, &employee, &commitment);
    employee
}

fn pay(env: &Env, f: &Fixture, employee: &Address, amount: i128, seed: u8, period: u32) {
    f.executor.execute_payment(
        &f.company_id,
        employee,
        &amount,
        &BytesN::from_array(env, &[seed; 64]),
        &BytesN::from_array(env, &[seed; 128]),
        &BytesN::from_array(env, &[seed; 64]),
        &BytesN::from_array(env, &[seed; 32]),
        &period,
    );
}

fn pay_err(
    env: &Env,
    f: &Fixture,
    employee: &Address,
    amount: i128,
    seed: u8,
    period: u32,
) -> PaymentError {
    f.executor
        .try_execute_payment(
            &f.company_id,
            employee,
            &amount,
            &BytesN::from_array(env, &[seed; 64]),
            &BytesN::from_array(env, &[seed; 128]),
            &BytesN::from_array(env, &[seed; 64]),
            &BytesN::from_array(env, &[seed; 32]),
            &period,
        )
        .unwrap_err()
        .unwrap()
}

/// Batch arguments for `rows` of `(employee, amount, seed)`.
#[allow(clippy::type_complexity)]
fn batch_args(
    env: &Env,
    rows: &[(&Address, i128, u8)],
) -> (
    Vec<Address>,
    Vec<i128>,
    Vec<BytesN<64>>,
    Vec<BytesN<128>>,
    Vec<BytesN<64>>,
    Vec<BytesN<32>>,
) {
    let mut employees = Vec::new(env);
    let mut amounts = Vec::new(env);
    let mut proofs_a = Vec::new(env);
    let mut proofs_b = Vec::new(env);
    let mut proofs_c = Vec::new(env);
    let mut nullifiers = Vec::new(env);
    for (employee, amount, seed) in rows {
        employees.push_back((*employee).clone());
        amounts.push_back(*amount);
        proofs_a.push_back(BytesN::from_array(env, &[*seed; 64]));
        proofs_b.push_back(BytesN::from_array(env, &[*seed; 128]));
        proofs_c.push_back(BytesN::from_array(env, &[*seed; 64]));
        nullifiers.push_back(BytesN::from_array(env, &[*seed; 32]));
    }
    (employees, amounts, proofs_a, proofs_b, proofs_c, nullifiers)
}

fn seed_total_paid(env: &Env, f: &Fixture, total: i128) {
    env.as_contract(&f.executor.address, || {
        env.storage()
            .persistent()
            .set(&DataKey::TotalPaid(f.company_id), &total);
    });
}

fn seed_payment_count(env: &Env, f: &Fixture, period: u32, count: u32) {
    env.as_contract(&f.executor.address, || {
        let key = DataKey::Period(f.company_id, period);
        let mut record: PayrollPeriod = env.storage().persistent().get(&key).unwrap();
        record.payment_count = count;
        env.storage().persistent().set(&key, &record);
    });
}

fn payment_count(f: &Fixture, period: u32) -> u32 {
    f.executor
        .get_period(&f.company_id, &period)
        .unwrap()
        .payment_count
}

// ---------------------------------------------------------------------------
// Single payment: TotalPaid (i128)
// ---------------------------------------------------------------------------

/// Success / boundary: real payments that bring the running total to exactly
/// `i128::MAX` are accepted.
#[test]
fn test_payments_reaching_exactly_i128_max_total_succeed() {
    let env = Env::default();
    let f = setup(&env);
    let employee = onboard(&env, &f, 1);

    f.token.mint(&f.treasury, &(i128::MAX - 500));
    pay(&env, &f, &employee, i128::MAX - 500, 10, 1);

    f.executor.close_period(&f.company_id, &1);
    f.executor.create_period(&f.company_id);
    f.token.mint(&f.treasury, &500);
    pay(&env, &f, &employee, 500, 11, 2);

    assert_eq!(f.executor.get_total_paid(&f.company_id), i128::MAX);
    assert_eq!(f.token.balance(&employee), i128::MAX);
    assert_eq!(payment_count(&f, 1), 1);
    assert_eq!(payment_count(&f, 2), 1);
}

/// Rejected: one unit past `i128::MAX` returns `Overflow` with no side
/// effects. The same nullifier then succeeds at exactly `i128::MAX`, which
/// proves the failed attempt did not consume it.
#[test]
fn test_payment_overflowing_total_paid_is_rejected_without_side_effects() {
    let env = Env::default();
    let f = setup(&env);
    let employee = onboard(&env, &f, 2);

    seed_total_paid(&env, &f, i128::MAX - 99);
    f.token.mint(&f.treasury, &100);

    assert_eq!(
        pay_err(&env, &f, &employee, 100, 20, 1),
        PaymentError::Overflow
    );
    assert_eq!(f.executor.get_total_paid(&f.company_id), i128::MAX - 99);
    assert_eq!(f.token.balance(&f.treasury), 100);
    assert_eq!(f.token.balance(&employee), 0);
    assert!(!f.executor.is_paid(&employee, &1));
    assert_eq!(payment_count(&f, 1), 0);

    // Boundary: same proof/nullifier, amount that lands exactly on i128::MAX.
    pay(&env, &f, &employee, 99, 20, 1);
    assert_eq!(f.executor.get_total_paid(&f.company_id), i128::MAX);
    assert_eq!(f.token.balance(&employee), 99);
    assert!(f.executor.is_paid(&employee, &1));
}

// ---------------------------------------------------------------------------
// Single payment: period payment_count (u32)
// ---------------------------------------------------------------------------

/// Boundary then rejection: the count may reach `u32::MAX`, and the next
/// payment in that period returns `Overflow` without paying anyone.
#[test]
fn test_period_payment_count_at_u32_max_rejects_next_payment() {
    let env = Env::default();
    let f = setup(&env);
    let first = onboard(&env, &f, 3);
    let second = onboard(&env, &f, 4);
    f.token.mint(&f.treasury, &1_000);

    seed_payment_count(&env, &f, 1, u32::MAX - 1);
    pay(&env, &f, &first, 300, 30, 1);
    assert_eq!(payment_count(&f, 1), u32::MAX);
    assert_eq!(f.executor.get_total_paid(&f.company_id), 300);

    assert_eq!(
        pay_err(&env, &f, &second, 300, 31, 1),
        PaymentError::Overflow
    );
    assert_eq!(payment_count(&f, 1), u32::MAX);
    assert_eq!(f.executor.get_total_paid(&f.company_id), 300);
    assert_eq!(f.token.balance(&f.treasury), 700);
    assert_eq!(f.token.balance(&second), 0);
    assert!(!f.executor.is_paid(&second, &1));
}

// ---------------------------------------------------------------------------
// Batch execution
// ---------------------------------------------------------------------------

/// Boundary: a batch whose rows bring the total to exactly `i128::MAX`
/// succeeds.
#[test]
fn test_batch_reaching_exactly_i128_max_total_succeeds() {
    let env = Env::default();
    let f = setup(&env);
    let a = onboard(&env, &f, 5);
    let b = onboard(&env, &f, 6);
    f.token.mint(&f.treasury, &150);
    seed_total_paid(&env, &f, i128::MAX - 150);

    let (employees, amounts, pa, pb, pc, nullifiers) =
        batch_args(&env, &[(&a, 100, 50), (&b, 50, 51)]);
    f.executor.execute_batch_payroll(
        &f.company_id,
        &employees,
        &amounts,
        &pa,
        &pb,
        &pc,
        &nullifiers,
        &1,
    );

    assert_eq!(f.executor.get_total_paid(&f.company_id), i128::MAX);
    assert_eq!(payment_count(&f, 1), 2);
    assert!(f.executor.is_paid(&a, &1));
    assert!(f.executor.is_paid(&b, &1));
}

/// Rejected: every row fits on its own, but the batch sum overflows. The
/// whole batch is rejected up front and no row is paid.
#[test]
fn test_batch_whose_sum_overflows_total_paid_is_rejected_atomically() {
    let env = Env::default();
    let f = setup(&env);
    let a = onboard(&env, &f, 7);
    let b = onboard(&env, &f, 8);
    f.token.mint(&f.treasury, &200);
    seed_total_paid(&env, &f, i128::MAX - 150);

    let (employees, amounts, pa, pb, pc, nullifiers) =
        batch_args(&env, &[(&a, 100, 60), (&b, 100, 61)]);
    let err = f
        .executor
        .try_execute_batch_payroll(
            &f.company_id,
            &employees,
            &amounts,
            &pa,
            &pb,
            &pc,
            &nullifiers,
            &1,
        )
        .unwrap_err()
        .unwrap();

    assert_eq!(err, PaymentError::Overflow);
    assert_eq!(f.executor.get_total_paid(&f.company_id), i128::MAX - 150);
    assert_eq!(f.token.balance(&f.treasury), 200);
    assert_eq!(f.token.balance(&a), 0);
    assert_eq!(f.token.balance(&b), 0);
    assert!(!f.executor.is_paid(&a, &1));
    assert!(!f.executor.is_paid(&b, &1));
    assert_eq!(payment_count(&f, 1), 0);
}

/// Rejected: a batch that would push the period count past `u32::MAX` is
/// rejected before any row is paid.
#[test]
fn test_batch_overflowing_period_payment_count_is_rejected() {
    let env = Env::default();
    let f = setup(&env);
    let a = onboard(&env, &f, 9);
    let b = onboard(&env, &f, 10);
    f.token.mint(&f.treasury, &200);
    seed_payment_count(&env, &f, 1, u32::MAX - 1);

    let (employees, amounts, pa, pb, pc, nullifiers) =
        batch_args(&env, &[(&a, 100, 70), (&b, 100, 71)]);
    let err = f
        .executor
        .try_execute_batch_payroll(
            &f.company_id,
            &employees,
            &amounts,
            &pa,
            &pb,
            &pc,
            &nullifiers,
            &1,
        )
        .unwrap_err()
        .unwrap();

    assert_eq!(err, PaymentError::Overflow);
    assert_eq!(payment_count(&f, 1), u32::MAX - 1);
    assert_eq!(f.executor.get_total_paid(&f.company_id), 0);
    assert_eq!(f.token.balance(&f.treasury), 200);
    assert!(!f.executor.is_paid(&a, &1));
    assert!(!f.executor.is_paid(&b, &1));
}

/// An overflowing receipt-backed batch does not consume its settlement
/// receipt, so a corrected retry with the same receipt ID succeeds.
#[test]
fn test_batch_with_receipt_overflow_leaves_receipt_unused() {
    let env = Env::default();
    let f = setup(&env);
    let a = onboard(&env, &f, 11);
    let b = onboard(&env, &f, 12);
    f.token.mint(&f.treasury, &200);
    seed_total_paid(&env, &f, i128::MAX - 150);
    let receipt = BytesN::from_array(&env, &[0xAB; 32]);

    let (employees, amounts, pa, pb, pc, nullifiers) =
        batch_args(&env, &[(&a, 100, 80), (&b, 100, 81)]);
    let err = f
        .executor
        .try_execute_batch_with_receipt(
            &f.company_id,
            &employees,
            &amounts,
            &pa,
            &pb,
            &pc,
            &nullifiers,
            &1,
            &receipt,
        )
        .unwrap_err()
        .unwrap();
    assert_eq!(err, PaymentError::Overflow);
    assert!(!f.executor.is_settlement_receipt_used(&receipt));

    let (employees, amounts, pa, pb, pc, nullifiers) =
        batch_args(&env, &[(&a, 100, 80), (&b, 50, 81)]);
    f.executor.execute_batch_with_receipt(
        &f.company_id,
        &employees,
        &amounts,
        &pa,
        &pb,
        &pc,
        &nullifiers,
        &1,
        &receipt,
    );
    assert!(f.executor.is_settlement_receipt_used(&receipt));
    assert_eq!(f.executor.get_total_paid(&f.company_id), i128::MAX);
}

/// The error is a bare, stable code: it carries no employee address, amount
/// or commitment that could leak private payroll data.
#[test]
fn test_overflow_error_code_is_stable() {
    assert_eq!(PaymentError::Overflow as u32, 20);
}
