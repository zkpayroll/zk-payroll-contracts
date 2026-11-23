//! Issue #816: transaction replay protection across payroll periods.
//!
//! Replay protection in `payment_executor` is the nullifier set
//! (`DataKey::Nullifier`). A nullifier is consumed by the first successful
//! payment that uses it, and the key is global: it is not scoped to the
//! period, the employee, or the company. The existing unit test only replays
//! a proof inside the period where it was first used. These tests pin down the
//! cross-period behaviour:
//!
//! - replay into the next period (same or different employee),
//! - replay after the original period is closed, and into a reopened period,
//! - replay after the original proof's freshness window has elapsed (so the
//!   nullifier is the only remaining defence),
//! - replay many periods later,
//! - replay under a different company,
//! - replay through `execute_batch_payroll` and `execute_batch_with_receipt`.
//!
//! Every rejected replay must return `PaymentError::ProofAlreadyUsed` and
//! leave `TotalPaid`, period `payment_count`, token balances, payment records
//! and settlement receipts unchanged. A fresh nullifier must keep working, so
//! the protection blocks replays and nothing else.

use ::token::{Token, TokenClient};
use payment_executor::{ContractAddresses, PaymentError, PaymentExecutor, PaymentExecutorClient};
use payroll_registry::{PayrollRegistry, PayrollRegistryClient};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
use soroban_sdk::testutils::{Address as _, Ledger};
use soroban_sdk::{Address, BytesN, Env, Vec};

const SALARY: i128 = 1_000;

struct Fixture<'a> {
    executor: PaymentExecutorClient<'a>,
    registry: PayrollRegistryClient<'a>,
    commitments: SalaryCommitmentContractClient<'a>,
    token: TokenClient<'a>,
}

struct Company {
    id: u64,
    treasury: Address,
}

/// One proof submission: the Groth16 proof bytes and nullifier are all
/// derived from `seed`, so equal seeds mean an identical (replayed) payload.
#[derive(Clone, Copy)]
struct Proof(u8);

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
    executor.set_executor_admin(&Address::generate(env));
    executor.set_asset_decimals(&token_id, &7u32);

    Fixture {
        executor,
        registry,
        commitments,
        token,
    }
}

/// Registers a company with a funded treasury, a zero-rate withholding
/// config and an open first period.
fn company(env: &Env, f: &Fixture) -> Company {
    let treasury = Address::generate(env);
    let id = f
        .registry
        .register_company(&Address::generate(env), &treasury);
    let tax = Address::generate(env);
    f.executor
        .set_withholding_config(&id, &0u32, &0u32, &tax, &tax, &0i128, &0i128);
    f.executor.create_period(&id);
    f.token.mint(&treasury, &(SALARY * 100));
    Company { id, treasury }
}

fn employee(env: &Env, f: &Fixture, c: &Company, seed: u8) -> Address {
    let employee = Address::generate(env);
    let commitment = BytesN::from_array(env, &[seed; 32]);
    f.commitments.store_commitment(&employee, &commitment);
    f.registry.add_employee(&c.id, &employee, &commitment);
    employee
}

fn pay(env: &Env, f: &Fixture, c: &Company, who: &Address, p: Proof, period: u32) {
    f.executor.execute_payment(
        &c.id,
        who,
        &SALARY,
        &BytesN::from_array(env, &[p.0; 64]),
        &BytesN::from_array(env, &[p.0; 128]),
        &BytesN::from_array(env, &[p.0; 64]),
        &BytesN::from_array(env, &[p.0; 32]),
        &period,
    );
}

fn pay_err(
    env: &Env,
    f: &Fixture,
    c: &Company,
    who: &Address,
    p: Proof,
    period: u32,
) -> PaymentError {
    f.executor
        .try_execute_payment(
            &c.id,
            who,
            &SALARY,
            &BytesN::from_array(env, &[p.0; 64]),
            &BytesN::from_array(env, &[p.0; 128]),
            &BytesN::from_array(env, &[p.0; 64]),
            &BytesN::from_array(env, &[p.0; 32]),
            &period,
        )
        .unwrap_err()
        .unwrap()
}

#[allow(clippy::type_complexity)]
fn batch(
    env: &Env,
    rows: &[(&Address, Proof)],
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
    let mut a = Vec::new(env);
    let mut b = Vec::new(env);
    let mut c = Vec::new(env);
    let mut nullifiers = Vec::new(env);
    for (who, p) in rows {
        employees.push_back((*who).clone());
        amounts.push_back(SALARY);
        a.push_back(BytesN::from_array(env, &[p.0; 64]));
        b.push_back(BytesN::from_array(env, &[p.0; 128]));
        c.push_back(BytesN::from_array(env, &[p.0; 64]));
        nullifiers.push_back(BytesN::from_array(env, &[p.0; 32]));
    }
    (employees, amounts, a, b, c, nullifiers)
}

/// Closes the currently open period and opens the next one.
fn next_period(f: &Fixture, c: &Company, current: u32) -> u32 {
    f.executor.close_period(&c.id, &current);
    f.executor.create_period(&c.id).period_id
}

fn count(f: &Fixture, c: &Company, period: u32) -> u32 {
    f.executor.get_period(&c.id, &period).unwrap().payment_count
}

/// Snapshot of everything a replay must not change for a company.
#[derive(Debug, PartialEq)]
struct Totals {
    total_paid: i128,
    treasury: i128,
}

fn totals(f: &Fixture, c: &Company) -> Totals {
    Totals {
        total_paid: f.executor.get_total_paid(&c.id),
        treasury: f.token.balance(&c.treasury),
    }
}

// ---------------------------------------------------------------------------
// Success: the protection blocks replays, not new payments
// ---------------------------------------------------------------------------

/// A fresh nullifier pays the same employee again in the next period.
#[test]
fn test_fresh_nullifier_pays_same_employee_in_next_period() {
    let env = Env::default();
    let f = setup(&env);
    let co = company(&env, &f);
    let alice = employee(&env, &f, &co, 1);

    pay(&env, &f, &co, &alice, Proof(10), 1);
    let p2 = next_period(&f, &co, 1);
    pay(&env, &f, &co, &alice, Proof(11), p2);

    assert!(f.executor.is_paid(&alice, &1));
    assert!(f.executor.is_paid(&alice, &p2));
    assert_eq!(f.executor.get_total_paid(&co.id), SALARY * 2);
    assert_eq!(count(&f, &co, 1), 1);
    assert_eq!(count(&f, &co, p2), 1);
}

// ---------------------------------------------------------------------------
// Rejected: single-payment replays across periods
// ---------------------------------------------------------------------------

/// Replaying a closed period's proof into the next period is rejected, even
/// though the employee has no payment record there yet, so `AlreadyPaid`
/// cannot catch it.
#[test]
fn test_replay_into_next_period_same_employee_is_rejected() {
    let env = Env::default();
    let f = setup(&env);
    let co = company(&env, &f);
    let alice = employee(&env, &f, &co, 2);

    pay(&env, &f, &co, &alice, Proof(20), 1);
    let p2 = next_period(&f, &co, 1);
    let before = totals(&f, &co);

    assert_eq!(
        pay_err(&env, &f, &co, &alice, Proof(20), p2),
        PaymentError::ProofAlreadyUsed
    );
    assert_eq!(totals(&f, &co), before);
    assert_eq!(count(&f, &co, p2), 0);
    assert!(!f.executor.is_paid(&alice, &p2));
    assert_eq!(f.token.balance(&alice), SALARY);
}

/// Redirecting a consumed proof to a different employee in the next period
/// is rejected.
#[test]
fn test_replay_into_next_period_different_employee_is_rejected() {
    let env = Env::default();
    let f = setup(&env);
    let co = company(&env, &f);
    let alice = employee(&env, &f, &co, 3);
    let mallory = employee(&env, &f, &co, 4);

    pay(&env, &f, &co, &alice, Proof(30), 1);
    let p2 = next_period(&f, &co, 1);
    let before = totals(&f, &co);

    assert_eq!(
        pay_err(&env, &f, &co, &mallory, Proof(30), p2),
        PaymentError::ProofAlreadyUsed
    );
    assert_eq!(totals(&f, &co), before);
    assert_eq!(count(&f, &co, p2), 0);
    assert_eq!(f.token.balance(&mallory), 0);
}

/// After the original period closes, replaying into that closed period hits
/// `PeriodClosed`. Once it is reopened, the period check passes and the
/// nullifier alone rejects the replay.
#[test]
fn test_replay_into_closed_then_reopened_period_is_rejected() {
    let env = Env::default();
    let f = setup(&env);
    let co = company(&env, &f);
    let alice = employee(&env, &f, &co, 5);
    let bob = employee(&env, &f, &co, 6);

    pay(&env, &f, &co, &alice, Proof(50), 1);
    f.executor.close_period(&co.id, &1);
    assert_eq!(
        pay_err(&env, &f, &co, &bob, Proof(50), 1),
        PaymentError::PeriodClosed
    );

    f.executor.reopen_period(&co.id, &1);
    let before = totals(&f, &co);
    assert_eq!(
        pay_err(&env, &f, &co, &bob, Proof(50), 1),
        PaymentError::ProofAlreadyUsed
    );
    assert_eq!(totals(&f, &co), before);
    assert_eq!(count(&f, &co, 1), 1);
    assert!(!f.executor.is_paid(&bob, &1));
}

/// Boundary: the original proof is past its freshness window, but the next
/// period is brand new, so `ProofExpired` does not apply. The replay is
/// rejected by the nullifier, including on the last second of the new
/// period's window.
#[test]
fn test_replay_after_freshness_window_elapsed_is_rejected_by_nullifier() {
    let env = Env::default();
    let f = setup(&env);
    let co = company(&env, &f);
    let alice = employee(&env, &f, &co, 7);
    let max_age = f.executor.get_max_proof_age();

    pay(&env, &f, &co, &alice, Proof(70), 1);

    env.ledger().set_timestamp(max_age + 1);
    let p2 = next_period(&f, &co, 1);
    let p2_created = f.executor.get_period(&co.id, &p2).unwrap().created_at;

    // Last second inside the new period's freshness window.
    env.ledger().set_timestamp(p2_created + max_age);
    let before = totals(&f, &co);
    assert_eq!(
        pay_err(&env, &f, &co, &alice, Proof(70), p2),
        PaymentError::ProofAlreadyUsed
    );
    assert_eq!(totals(&f, &co), before);
    assert_eq!(count(&f, &co, p2), 0);

    // At that same instant a fresh proof is accepted.
    pay(&env, &f, &co, &alice, Proof(71), p2);
    assert_eq!(count(&f, &co, p2), 1);
}

/// Nullifiers never expire: a replay several periods later is still
/// rejected.
#[test]
fn test_replay_many_periods_later_is_rejected() {
    let env = Env::default();
    let f = setup(&env);
    let co = company(&env, &f);
    let alice = employee(&env, &f, &co, 8);

    pay(&env, &f, &co, &alice, Proof(80), 1);
    let mut period = 1;
    for _ in 0..4 {
        period = next_period(&f, &co, period);
    }
    assert_eq!(period, 5);

    let before = totals(&f, &co);
    assert_eq!(
        pay_err(&env, &f, &co, &alice, Proof(80), period),
        PaymentError::ProofAlreadyUsed
    );
    assert_eq!(totals(&f, &co), before);
    assert_eq!(count(&f, &co, period), 0);
}

/// Nullifiers are global across companies: another company cannot reuse a
/// proof consumed by the first, in its own period 1.
#[test]
fn test_replay_under_different_company_is_rejected() {
    let env = Env::default();
    let f = setup(&env);
    let acme = company(&env, &f);
    let globex = company(&env, &f);
    let alice = employee(&env, &f, &acme, 9);
    let bob = employee(&env, &f, &globex, 10);

    pay(&env, &f, &acme, &alice, Proof(90), 1);
    let before = totals(&f, &globex);

    assert_eq!(
        pay_err(&env, &f, &globex, &bob, Proof(90), 1),
        PaymentError::ProofAlreadyUsed
    );
    assert_eq!(totals(&f, &globex), before);
    assert_eq!(count(&f, &globex, 1), 0);
    assert_eq!(f.executor.get_total_paid(&acme.id), SALARY);
}

// ---------------------------------------------------------------------------
// Rejected: batch replays
// ---------------------------------------------------------------------------

/// A batch in the next period that mixes a fresh proof with a replayed one
/// is rejected as a whole. The fresh row runs first and is rolled back with
/// it.
#[test]
fn test_batch_replaying_previous_period_nullifier_is_rejected_atomically() {
    let env = Env::default();
    let f = setup(&env);
    let co = company(&env, &f);
    let alice = employee(&env, &f, &co, 11);
    let bob = employee(&env, &f, &co, 12);

    pay(&env, &f, &co, &alice, Proof(110), 1);
    let p2 = next_period(&f, &co, 1);
    let before = totals(&f, &co);

    let (employees, amounts, a, b, c, nullifiers) =
        batch(&env, &[(&bob, Proof(111)), (&alice, Proof(110))]);
    let err = f
        .executor
        .try_execute_batch_payroll(&co.id, &employees, &amounts, &a, &b, &c, &nullifiers, &p2)
        .unwrap_err()
        .unwrap();

    assert_eq!(err, PaymentError::ProofAlreadyUsed);
    assert_eq!(totals(&f, &co), before);
    assert_eq!(count(&f, &co, p2), 0);
    assert!(!f.executor.is_paid(&bob, &p2));
    assert!(!f.executor.is_paid(&alice, &p2));

    // Bob's fresh proof was not consumed by the rejected batch.
    pay(&env, &f, &co, &bob, Proof(111), p2);
    assert!(f.executor.is_paid(&bob, &p2));
}

/// The same nullifier twice inside one batch is rejected, and neither row
/// is paid.
#[test]
fn test_batch_with_duplicate_nullifier_is_rejected_atomically() {
    let env = Env::default();
    let f = setup(&env);
    let co = company(&env, &f);
    let alice = employee(&env, &f, &co, 13);
    let bob = employee(&env, &f, &co, 14);
    let before = totals(&f, &co);

    let (employees, amounts, a, b, c, nullifiers) =
        batch(&env, &[(&alice, Proof(130)), (&bob, Proof(130))]);
    let err = f
        .executor
        .try_execute_batch_payroll(&co.id, &employees, &amounts, &a, &b, &c, &nullifiers, &1)
        .unwrap_err()
        .unwrap();

    assert_eq!(err, PaymentError::ProofAlreadyUsed);
    assert_eq!(totals(&f, &co), before);
    assert_eq!(count(&f, &co, 1), 0);
    assert!(!f.executor.is_paid(&alice, &1));
    assert!(!f.executor.is_paid(&bob, &1));
}

/// A fresh settlement receipt cannot launder a replayed nullifier. The batch
/// is rejected and the receipt stays unused for a corrected retry.
#[test]
fn test_batch_with_receipt_replaying_nullifier_is_rejected_and_receipt_unused() {
    let env = Env::default();
    let f = setup(&env);
    let co = company(&env, &f);
    let alice = employee(&env, &f, &co, 15);

    pay(&env, &f, &co, &alice, Proof(150), 1);
    let p2 = next_period(&f, &co, 1);
    let receipt = BytesN::from_array(&env, &[0xC1; 32]);
    let before = totals(&f, &co);

    let (employees, amounts, a, b, c, nullifiers) = batch(&env, &[(&alice, Proof(150))]);
    let err = f
        .executor
        .try_execute_batch_with_receipt(
            &co.id,
            &employees,
            &amounts,
            &a,
            &b,
            &c,
            &nullifiers,
            &p2,
            &receipt,
        )
        .unwrap_err()
        .unwrap();
    assert_eq!(err, PaymentError::ProofAlreadyUsed);
    assert_eq!(totals(&f, &co), before);
    assert!(!f.executor.is_settlement_receipt_used(&receipt));

    let (employees, amounts, a, b, c, nullifiers) = batch(&env, &[(&alice, Proof(151))]);
    f.executor.execute_batch_with_receipt(
        &co.id,
        &employees,
        &amounts,
        &a,
        &b,
        &c,
        &nullifiers,
        &p2,
        &receipt,
    );
    assert!(f.executor.is_settlement_receipt_used(&receipt));
    assert!(f.executor.is_paid(&alice, &p2));
}
