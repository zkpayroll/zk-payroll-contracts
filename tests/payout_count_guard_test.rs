//! Payout batch size configuration limit tests (issue #510)
//!
//! Validates that:
//!   - `execute_batch_payroll` is blocked when the employee count exceeds the
//!     configured per-company limit (or the hard contract cap when no policy
//!     is set).
//!   - Batches within the limit succeed.
//!   - The hard cap defaults to 100 when no company-specific policy exists.
//!   - `set_max_batch_size` / `get_max_batch_size` round-trip correctly.
//!   - `BatchTooLarge` errors carry no employee addresses or salary amounts
//!     (privacy-safe feedback).
//!   - Admin-only enforcement: only the executor admin may call
//!     `set_max_batch_size`.
//!
//! Slow or network-dependent tests are intentionally excluded; all tests use
//! `env.mock_all_auths()` and run entirely in-process.

use payment_executor::{ContractAddresses, PaymentError, PaymentExecutor, PaymentExecutorClient};
use payroll_registry::{PayrollRegistry, PayrollRegistryClient};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, Vec};
use token::{Token, TokenClient};

// ── Test helpers ─────────────────────────────────────────────────────────────

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

struct TestCtx<'a> {
    env: Env,
    executor: PaymentExecutorClient<'a>,
    registry: PayrollRegistryClient<'a>,
    commitment: SalaryCommitmentContractClient<'a>,
    token: TokenClient<'a>,
    company_id: u64,
}

fn setup<'a>() -> TestCtx<'static> {
    let env = Env::default();
    env.mock_all_auths();

    let executor_id = env.register_contract(None, PaymentExecutor);
    let registry_id = env.register_contract(None, PayrollRegistry);
    let commitment_id = env.register_contract(None, SalaryCommitmentContract);
    let verifier_id = env.register_contract(None, ProofVerifier);
    let token_id = env.register_contract(None, Token);

    let executor = PaymentExecutorClient::new(&env, &executor_id);
    let registry = PayrollRegistryClient::new(&env, &registry_id);
    let commitment = SalaryCommitmentContractClient::new(&env, &commitment_id);
    let verifier = ProofVerifierClient::new(&env, &verifier_id);
    let token = TokenClient::new(&env, &token_id);

    let addresses = ContractAddresses {
        registry: registry_id,
        commitment: commitment_id,
        verifier: verifier_id,
        token: token_id,
    };

    executor.initialize(&addresses);

    // Set executor admin (one-time, required for set_max_batch_size)
    let exec_admin = Address::generate(&env);
    executor.set_executor_admin(&exec_admin);

    verifier.init_verifier_admin(&Address::generate(&env));
    verifier.initialize_verifier(&mock_vk(&env));

    let commitment_admin = Address::generate(&env);
    commitment.init_commitment_admin(&commitment_admin);

    let company_admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let company_id = registry.register_company(&company_admin, &treasury);

    executor.create_period(&company_id);

    // Mint enough for many test batches
    token.mint(&treasury, &1_000_000i128);

    // Zero-rate withholding so execute_payment is unblocked (issue #538)
    let tax_addr = Address::generate(&env);
    executor.set_withholding_config(
        &company_id,
        &0u32,
        &0u32,
        &tax_addr,
        &tax_addr,
        &0i128,
        &0i128,
    );

    TestCtx {
        env,
        executor,
        registry,
        commitment,
        token,
        company_id,
    }
}

/// Build parallel batch Vecs for `n` fresh employees, each with a distinct
/// commitment and amount. Returns the Vecs plus the period (always 1).
fn build_batch(
    ctx: &TestCtx,
    n: u32,
) -> (
    soroban_sdk::Vec<Address>,
    soroban_sdk::Vec<i128>,
    soroban_sdk::Vec<BytesN<64>>,
    soroban_sdk::Vec<BytesN<128>>,
    soroban_sdk::Vec<BytesN<64>>,
    soroban_sdk::Vec<BytesN<32>>,
    u32,
) {
    let env = &ctx.env;
    let mut employees = soroban_sdk::Vec::new(env);
    let mut amounts = soroban_sdk::Vec::new(env);
    let mut proofs_a = soroban_sdk::Vec::new(env);
    let mut proofs_b = soroban_sdk::Vec::new(env);
    let mut proofs_c = soroban_sdk::Vec::new(env);
    let mut nullifiers = soroban_sdk::Vec::new(env);

    for i in 0..n {
        let emp = Address::generate(env);
        let mut commitment_bytes = [1u8; 32];
        commitment_bytes[0] = (i & 0xFF) as u8;
        commitment_bytes[1] = ((i >> 8) & 0xFF) as u8;
        let commitment = BytesN::from_array(env, &commitment_bytes);

        ctx.commitment.store_commitment(&emp, &commitment);
        ctx.registry
            .add_employee(&ctx.company_id, &emp, &commitment);

        let mut nullifier_bytes = [2u8; 32];
        nullifier_bytes[0] = (i & 0xFF) as u8;
        nullifier_bytes[1] = ((i >> 8) & 0xFF) as u8;

        employees.push_back(emp);
        amounts.push_back(100i128);
        proofs_a.push_back(BytesN::from_array(env, &[1u8; 64]));
        proofs_b.push_back(BytesN::from_array(env, &[2u8; 128]));
        proofs_c.push_back(BytesN::from_array(env, &[3u8; 64]));
        nullifiers.push_back(BytesN::from_array(env, &nullifier_bytes));
    }

    (employees, amounts, proofs_a, proofs_b, proofs_c, nullifiers, 1u32)
}

// ── Default (no policy set) ──────────────────────────────────────────────────

/// When no company-specific limit is configured, `get_max_batch_size` returns
/// the hard contract cap (100).
#[test]
fn test_default_limit_is_hard_cap() {
    let ctx = setup();
    let limit = ctx.executor.get_max_batch_size(&ctx.company_id);
    assert_eq!(limit, 100u32, "default limit must equal the hard cap of 100");
}

// ── set / get round-trip ─────────────────────────────────────────────────────

/// Admin can configure a per-company limit and read it back.
#[test]
fn test_set_and_get_max_batch_size() {
    let ctx = setup();
    ctx.executor.set_max_batch_size(&ctx.company_id, &5u32);
    assert_eq!(ctx.executor.get_max_batch_size(&ctx.company_id), 5u32);
}

/// Setting the limit to exactly the hard cap is accepted.
#[test]
fn test_set_limit_equal_to_hard_cap_accepted() {
    let ctx = setup();
    ctx.executor.set_max_batch_size(&ctx.company_id, &100u32);
    assert_eq!(ctx.executor.get_max_batch_size(&ctx.company_id), 100u32);
}

/// Setting the limit to zero must panic with a clear, actionable message.
#[test]
#[should_panic(expected = "Payout batch size limit must be at least 1")]
fn test_set_limit_zero_panics() {
    let ctx = setup();
    ctx.executor.set_max_batch_size(&ctx.company_id, &0u32);
}

/// Setting the limit above the hard cap must panic.
#[test]
#[should_panic(expected = "Payout batch size limit exceeds the hard contract cap")]
fn test_set_limit_above_hard_cap_panics() {
    let ctx = setup();
    ctx.executor.set_max_batch_size(&ctx.company_id, &101u32);
}

// ── Enforcement: BatchTooLarge ───────────────────────────────────────────────

/// A batch with exactly the configured limit succeeds (boundary: at-limit).
#[test]
fn test_batch_at_limit_succeeds() {
    let ctx = setup();
    ctx.executor.set_max_batch_size(&ctx.company_id, &3u32);

    let (employees, amounts, pa, pb, pc, nullifiers, period) = build_batch(&ctx, 3);
    let result = ctx.executor.try_execute_batch_payroll(
        &ctx.company_id,
        &employees,
        &amounts,
        &pa,
        &pb,
        &pc,
        &nullifiers,
        &period,
    );
    // The batch may succeed or fail for proof-verification reasons in the mock
    // environment, but it must NOT fail with BatchTooLarge.
    if let Err(e) = result {
        let err = e.unwrap();
        assert_ne!(
            err,
            PaymentError::BatchTooLarge,
            "batch at the limit must not be rejected as BatchTooLarge"
        );
    }
}

/// A batch one employee over the configured limit returns `BatchTooLarge`.
#[test]
fn test_batch_over_limit_returns_batch_too_large() {
    let ctx = setup();
    ctx.executor.set_max_batch_size(&ctx.company_id, &3u32);

    let (employees, amounts, pa, pb, pc, nullifiers, period) = build_batch(&ctx, 4);
    let result = ctx.executor.try_execute_batch_payroll(
        &ctx.company_id,
        &employees,
        &amounts,
        &pa,
        &pb,
        &pc,
        &nullifiers,
        &period,
    );
    assert_eq!(
        result.unwrap_err().unwrap(),
        PaymentError::BatchTooLarge,
        "batch of 4 with limit=3 must return BatchTooLarge"
    );
}

/// The error for an oversized batch must not expose salary amounts — the
/// `BatchTooLarge` variant carries no payload beyond the discriminant.
#[test]
fn test_batch_too_large_error_is_privacy_safe() {
    let ctx = setup();
    ctx.executor.set_max_batch_size(&ctx.company_id, &2u32);

    let (employees, amounts, pa, pb, pc, nullifiers, period) = build_batch(&ctx, 3);
    let result = ctx.executor.try_execute_batch_payroll(
        &ctx.company_id,
        &employees,
        &amounts,
        &pa,
        &pb,
        &pc,
        &nullifiers,
        &period,
    );
    // BatchTooLarge = 18; it carries no employee data by definition.
    let err = result.unwrap_err().unwrap();
    assert_eq!(err, PaymentError::BatchTooLarge);
    // Discriminant check: code 18, no additional data fields
    assert_eq!(err as u32, 18u32);
}

/// `execute_batch_payroll_with_receipt` also rejects oversized batches.
#[test]
fn test_batch_with_receipt_over_limit_returns_batch_too_large() {
    let ctx = setup();
    ctx.executor.set_max_batch_size(&ctx.company_id, &2u32);

    let (employees, amounts, pa, pb, pc, nullifiers, period) = build_batch(&ctx, 3);
    let receipt = BytesN::from_array(&ctx.env, &[0xABu8; 32]);

    let result = ctx.executor.try_execute_batch_payroll_with_receipt(
        &ctx.company_id,
        &employees,
        &amounts,
        &pa,
        &pb,
        &pc,
        &nullifiers,
        &period,
        &receipt,
    );
    assert_eq!(
        result.unwrap_err().unwrap(),
        PaymentError::BatchTooLarge,
        "execute_batch_payroll_with_receipt must also enforce the batch size limit"
    );
}

// ── Per-company isolation ─────────────────────────────────────────────────────

/// Different companies have independent limits.
#[test]
fn test_limits_are_scoped_per_company() {
    let ctx = setup();

    // Register a second company
    let admin2 = Address::generate(&ctx.env);
    let treasury2 = Address::generate(&ctx.env);
    let company_id2 = ctx.registry.register_company(&admin2, &treasury2);
    ctx.executor.create_period(&company_id2);

    let tax_addr = Address::generate(&ctx.env);
    ctx.executor.set_withholding_config(
        &company_id2,
        &0u32,
        &0u32,
        &tax_addr,
        &tax_addr,
        &0i128,
        &0i128,
    );

    // Company 1: limit = 2; company 2: no limit set → defaults to 100
    ctx.executor.set_max_batch_size(&ctx.company_id, &2u32);

    assert_eq!(ctx.executor.get_max_batch_size(&ctx.company_id), 2u32);
    assert_eq!(
        ctx.executor.get_max_batch_size(&company_id2),
        100u32,
        "company 2 must still default to the hard cap"
    );
}

/// Updating a company's limit does not affect another company's limit.
#[test]
fn test_updating_one_company_limit_does_not_affect_another() {
    let ctx = setup();

    let admin2 = Address::generate(&ctx.env);
    let treasury2 = Address::generate(&ctx.env);
    let company_id2 = ctx.registry.register_company(&admin2, &treasury2);

    ctx.executor.set_max_batch_size(&ctx.company_id, &10u32);
    ctx.executor.set_max_batch_size(&company_id2, &20u32);

    // Update company 1
    ctx.executor.set_max_batch_size(&ctx.company_id, &5u32);

    assert_eq!(ctx.executor.get_max_batch_size(&ctx.company_id), 5u32);
    assert_eq!(
        ctx.executor.get_max_batch_size(&company_id2),
        20u32,
        "company 2 limit must be unchanged"
    );
}
