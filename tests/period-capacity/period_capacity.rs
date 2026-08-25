//! Per-Period Payroll Capacity Limit Tests (issue #338)
//!
//! Verifies that employer-configured capacity limits (max batches, max
//! employees, max committed value) are enforced per payroll period before a
//! batch is locked in (`prepare_payroll_run`) or executed
//! (`batch_process_payroll`), that usage counters are scoped correctly per
//! period, and that the feature is fully opt-in (no policy configured means
//! no behavior change for existing callers).

use payroll::{Payroll, PayrollClient};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, Symbol, Vec};
use token::{Token, TokenClient};

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
                BytesN::from_array(env, &[0u8; 64]),
            ],
        ),
    }
}

fn mock_proof(env: &Env) -> BytesN<256> {
    BytesN::from_array(env, &[1u8; 256])
}

fn test_nonce(env: &Env, seed: u16) -> BytesN<32> {
    let mut bytes = [0u8; 32];
    bytes[0] = (seed & 0xFF) as u8;
    bytes[1] = (seed >> 8) as u8;
    bytes[31] = 0xAA;
    BytesN::from_array(env, &bytes)
}

struct TestContext<'a> {
    env: Env,
    payroll_client: PayrollClient<'a>,
    admin: Address,
}

fn setup_test_context() -> TestContext<'static> {
    let env = Env::default();
    env.mock_all_auths();

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

    token_client.mint(&treasury, &10_000_000i128);

    payroll_client.initialize(
        &admin,
        &token_id,
        &verifier_id,
        &commitment_id,
        &treasury,
        &treasury_owner,
    );

    commitment_client.set_payroll_operator(&payroll_id);

    TestContext {
        env,
        payroll_client,
        admin,
    }
}

/// Builds a batch of `n` employees, each paid `amount_each`, using fresh
/// addresses (no commitment registration needed since `prepare_payroll_run`
/// does not touch the commitment or proof-verifier contracts).
fn batch_of(
    env: &Env,
    n: u32,
    amount_each: i128,
) -> (Vec<BytesN<256>>, Vec<i128>, Vec<Address>, i128) {
    let mut proofs = Vec::new(env);
    let mut amounts = Vec::new(env);
    let mut employees = Vec::new(env);
    let mut total = 0i128;
    for _ in 0..n {
        proofs.push_back(mock_proof(env));
        amounts.push_back(amount_each);
        employees.push_back(Address::generate(env));
        total += amount_each;
    }
    (proofs, amounts, employees, total)
}

fn prepare_batch(ctx: &TestContext, seed: u16, n: u32, amount_each: i128) -> u64 {
    let (proofs, amounts, employees, total) = batch_of(&ctx.env, n, amount_each);
    ctx.payroll_client.prepare_payroll_run(
        &proofs,
        &amounts,
        &employees,
        &total,
        &test_nonce(&ctx.env, seed),
        &None,
    )
}

/// Attempts to prepare a batch and returns whether the call failed
/// (rejected by validation, e.g. a capacity limit).
fn try_prepare_batch_fails(ctx: &TestContext, seed: u16, n: u32, amount_each: i128) -> bool {
    let (proofs, amounts, employees, total) = batch_of(&ctx.env, n, amount_each);
    let result = ctx.payroll_client.try_prepare_payroll_run(
        &proofs,
        &amounts,
        &employees,
        &total,
        &test_nonce(&ctx.env, seed),
        &None,
    );
    result.is_err()
}

// ── Backward compatibility: capacity limits are fully opt-in ───────────────

#[test]
fn test_no_policy_configured_means_no_enforcement() {
    let ctx = setup_test_context();
    assert!(ctx.payroll_client.get_capacity_limits().is_none());

    // Many batches with no policy configured must all succeed.
    for i in 0..5u16 {
        prepare_batch(&ctx, i, 3, 1_000i128);
    }
}

#[test]
fn test_policy_without_open_period_is_noop() {
    let ctx = setup_test_context();
    ctx.payroll_client
        .set_capacity_limits(&ctx.admin, &1u32, &1u32, &1_000i128);

    // No period has been opened yet, so enforcement does not apply even
    // though a policy exists.
    let run_id_1 = prepare_batch(&ctx, 1, 5, 10_000i128);
    let run_id_2 = prepare_batch(&ctx, 2, 5, 10_000i128);
    assert_ne!(run_id_1, run_id_2);
}

// ── Boundary behavior: exact-limit and over-limit cases ─────────────────────

#[test]
fn test_batch_count_exact_limit_succeeds() {
    let ctx = setup_test_context();
    ctx.payroll_client
        .set_capacity_limits(&ctx.admin, &2u32, &100u32, &1_000_000i128);
    let period = Symbol::new(&ctx.env, "P2026_01");
    ctx.payroll_client.open_capacity_period(&ctx.admin, &period);

    prepare_batch(&ctx, 1, 1, 1_000i128);
    prepare_batch(&ctx, 2, 1, 1_000i128);

    let usage = ctx.payroll_client.get_period_usage(&period);
    assert_eq!(usage.batch_count, 2);
}

#[test]
fn test_batch_count_over_limit_fails() {
    let ctx = setup_test_context();
    ctx.payroll_client
        .set_capacity_limits(&ctx.admin, &2u32, &100u32, &1_000_000i128);
    let period = Symbol::new(&ctx.env, "P2026_01");
    ctx.payroll_client.open_capacity_period(&ctx.admin, &period);

    prepare_batch(&ctx, 1, 1, 1_000i128);
    prepare_batch(&ctx, 2, 1, 1_000i128);

    let failed = try_prepare_batch_fails(&ctx, 3, 1, 1_000i128);
    assert!(failed, "Third batch must exceed the batch-count limit");

    // The rejected batch must not have been counted.
    let usage = ctx.payroll_client.get_period_usage(&period);
    assert_eq!(usage.batch_count, 2);
}

#[test]
#[should_panic(expected = "Capacity limit exceeded: batch count")]
fn test_batch_count_limit_error_identifies_category() {
    let ctx = setup_test_context();
    ctx.payroll_client
        .set_capacity_limits(&ctx.admin, &1u32, &100u32, &1_000_000i128);
    let period = Symbol::new(&ctx.env, "P2026_01");
    ctx.payroll_client.open_capacity_period(&ctx.admin, &period);

    prepare_batch(&ctx, 1, 1, 1_000i128);
    prepare_batch(&ctx, 2, 1, 1_000i128);
}

#[test]
fn test_employee_count_exact_limit_succeeds() {
    let ctx = setup_test_context();
    ctx.payroll_client
        .set_capacity_limits(&ctx.admin, &10u32, &3u32, &1_000_000i128);
    let period = Symbol::new(&ctx.env, "P2026_02");
    ctx.payroll_client.open_capacity_period(&ctx.admin, &period);

    prepare_batch(&ctx, 1, 3, 1_000i128);

    let usage = ctx.payroll_client.get_period_usage(&period);
    assert_eq!(usage.employee_count, 3);
}

#[test]
fn test_employee_count_over_limit_fails() {
    let ctx = setup_test_context();
    ctx.payroll_client
        .set_capacity_limits(&ctx.admin, &10u32, &3u32, &1_000_000i128);
    let period = Symbol::new(&ctx.env, "P2026_02");
    ctx.payroll_client.open_capacity_period(&ctx.admin, &period);

    let failed = try_prepare_batch_fails(&ctx, 1, 4, 1_000i128);
    assert!(
        failed,
        "A 4-employee batch must exceed the employee-count limit of 3"
    );
}

#[test]
#[should_panic(expected = "Capacity limit exceeded: employee count")]
fn test_employee_count_limit_error_identifies_category() {
    let ctx = setup_test_context();
    ctx.payroll_client
        .set_capacity_limits(&ctx.admin, &10u32, &2u32, &1_000_000i128);
    let period = Symbol::new(&ctx.env, "P2026_02");
    ctx.payroll_client.open_capacity_period(&ctx.admin, &period);

    prepare_batch(&ctx, 1, 3, 1_000i128);
}

#[test]
fn test_total_value_exact_limit_succeeds() {
    let ctx = setup_test_context();
    ctx.payroll_client
        .set_capacity_limits(&ctx.admin, &10u32, &100u32, &10_000i128);
    let period = Symbol::new(&ctx.env, "P2026_03");
    ctx.payroll_client.open_capacity_period(&ctx.admin, &period);

    prepare_batch(&ctx, 1, 1, 10_000i128);

    let usage = ctx.payroll_client.get_period_usage(&period);
    assert_eq!(usage.total_value, 10_000i128);
}

#[test]
fn test_total_value_over_limit_fails() {
    let ctx = setup_test_context();
    ctx.payroll_client
        .set_capacity_limits(&ctx.admin, &10u32, &100u32, &10_000i128);
    let period = Symbol::new(&ctx.env, "P2026_03");
    ctx.payroll_client.open_capacity_period(&ctx.admin, &period);

    let failed = try_prepare_batch_fails(&ctx, 1, 1, 10_001i128);
    assert!(
        failed,
        "A batch of 10,001 must exceed the 10,000 value limit"
    );
}

#[test]
#[should_panic(expected = "Capacity limit exceeded: total value")]
fn test_total_value_limit_error_identifies_category() {
    let ctx = setup_test_context();
    ctx.payroll_client
        .set_capacity_limits(&ctx.admin, &10u32, &100u32, &5_000i128);
    let period = Symbol::new(&ctx.env, "P2026_03");
    ctx.payroll_client.open_capacity_period(&ctx.admin, &period);

    prepare_batch(&ctx, 1, 1, 6_000i128);
}

// ── Period scoping and reset behavior ───────────────────────────────────────

#[test]
fn test_period_counters_scoped_independently() {
    let ctx = setup_test_context();
    ctx.payroll_client
        .set_capacity_limits(&ctx.admin, &1u32, &100u32, &1_000_000i128);

    let period_a = Symbol::new(&ctx.env, "P2026_01");
    ctx.payroll_client
        .open_capacity_period(&ctx.admin, &period_a);
    prepare_batch(&ctx, 1, 1, 1_000i128);

    // Period A is now at its max_batches=1 limit; a second batch under A fails.
    let failed_a = try_prepare_batch_fails(&ctx, 2, 1, 1_000i128);
    assert!(failed_a);

    // Opening a new period gives fresh (zeroed) counters, so the same batch
    // succeeds under period B even though the policy is unchanged.
    let period_b = Symbol::new(&ctx.env, "P2026_02");
    ctx.payroll_client
        .open_capacity_period(&ctx.admin, &period_b);
    prepare_batch(&ctx, 3, 1, 1_000i128);

    let usage_a = ctx.payroll_client.get_period_usage(&period_a);
    let usage_b = ctx.payroll_client.get_period_usage(&period_b);
    assert_eq!(usage_a.batch_count, 1);
    assert_eq!(usage_b.batch_count, 1);
}

#[test]
fn test_reopening_a_period_resumes_its_existing_counters() {
    let ctx = setup_test_context();
    ctx.payroll_client
        .set_capacity_limits(&ctx.admin, &2u32, &100u32, &1_000_000i128);

    let period_a = Symbol::new(&ctx.env, "P2026_01");
    ctx.payroll_client
        .open_capacity_period(&ctx.admin, &period_a);
    prepare_batch(&ctx, 1, 1, 1_000i128);

    let period_b = Symbol::new(&ctx.env, "P2026_02");
    ctx.payroll_client
        .open_capacity_period(&ctx.admin, &period_b);
    prepare_batch(&ctx, 2, 1, 1_000i128);

    // Re-open period A: its usage counter should resume from 1, not reset to 0.
    ctx.payroll_client
        .open_capacity_period(&ctx.admin, &period_a);
    prepare_batch(&ctx, 3, 1, 1_000i128);
    let usage_a = ctx.payroll_client.get_period_usage(&period_a);
    assert_eq!(usage_a.batch_count, 2);

    // A third batch under period A now exceeds its max_batches=2 limit.
    let failed = try_prepare_batch_fails(&ctx, 4, 1, 1_000i128);
    assert!(failed);
}

#[test]
fn test_get_period_usage_defaults_to_zero_for_unused_period() {
    let ctx = setup_test_context();
    let usage = ctx
        .payroll_client
        .get_period_usage(&Symbol::new(&ctx.env, "NEVER_USED"));
    assert_eq!(usage.batch_count, 0);
    assert_eq!(usage.employee_count, 0);
    assert_eq!(usage.total_value, 0);
}

// ── Authorization ────────────────────────────────────────────────────────────

#[test]
fn test_unauthorized_caller_cannot_set_capacity_limits() {
    let ctx = setup_test_context();
    let outsider = Address::generate(&ctx.env);
    let result = ctx
        .payroll_client
        .try_set_capacity_limits(&outsider, &10u32, &10u32, &10_000i128);
    assert!(result.is_err());
}

#[test]
fn test_unauthorized_caller_cannot_open_capacity_period() {
    let ctx = setup_test_context();
    let outsider = Address::generate(&ctx.env);
    let period = Symbol::new(&ctx.env, "P2026_01");
    let result = ctx
        .payroll_client
        .try_open_capacity_period(&outsider, &period);
    assert!(result.is_err());
}
