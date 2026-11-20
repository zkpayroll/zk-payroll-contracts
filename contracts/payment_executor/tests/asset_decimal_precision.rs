use ::token::{Token, TokenClient};
use payment_executor::{ContractAddresses, PaymentError, PaymentExecutor, PaymentExecutorClient};
use payroll_registry::{PayrollRegistry, PayrollRegistryClient};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, Vec};

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

struct Ctx<'a> {
    executor: PaymentExecutorClient<'a>,
    registry: PayrollRegistryClient<'a>,
    commitment: SalaryCommitmentContractClient<'a>,
    token: TokenClient<'a>,
    token_id: Address,
}

fn setup(env: &Env) -> Ctx<'_> {
    env.mock_all_auths();

    let executor_id = env.register_contract(None, PaymentExecutor);
    let registry_id = env.register_contract(None, PayrollRegistry);
    let commitment_id = env.register_contract(None, SalaryCommitmentContract);
    let verifier_id = env.register_contract(None, ProofVerifier);
    let token_id = env.register_contract(None, Token);

    let executor = PaymentExecutorClient::new(env, &executor_id);
    let registry = PayrollRegistryClient::new(env, &registry_id);
    let commitment = SalaryCommitmentContractClient::new(env, &commitment_id);
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

    let commitment_admin = Address::generate(env);
    commitment.init_commitment_admin(&commitment_admin);
    commitment.set_payroll_operator(&executor_id);

    executor.set_executor_admin(&Address::generate(env));

    Ctx {
        executor,
        registry,
        commitment,
        token,
        token_id,
    }
}

fn register_company_and_employee(env: &Env, ctx: &Ctx, seed: u8) -> (u64, Address, Address) {
    let admin = Address::generate(env);
    let treasury = Address::generate(env);
    let employee = Address::generate(env);
    let company_id = ctx.registry.register_company(&admin, &treasury);
    ctx.executor.create_period(&company_id);

    let emp_commitment = BytesN::from_array(env, &[seed; 32]);
    ctx.commitment.store_commitment(&employee, &emp_commitment);
    ctx.registry
        .add_employee(&company_id, &employee, &emp_commitment);

    let tax = Address::generate(env);
    ctx.executor.set_withholding_config(&company_id, &0u32, &0u32, &tax, &tax, &0i128, &0i128);

    (company_id, treasury, employee)
}

fn proof(env: &Env, seed: u8) -> (BytesN<64>, BytesN<128>, BytesN<64>, BytesN<32>) {
    (
        BytesN::from_array(env, &[seed; 64]),
        BytesN::from_array(env, &[seed; 128]),
        BytesN::from_array(env, &[seed; 64]),
        BytesN::from_array(env, &[seed; 32]),
    )
}

#[test]
#[should_panic(expected = "Asset decimals must be greater than zero")]
fn test_set_asset_decimals_rejects_zero() {
    let env = Env::default();
    let ctx = setup(&env);
    ctx.executor.set_asset_decimals(&ctx.token_id, &0u32);
}

#[test]
#[should_panic(expected = "Asset decimals must not exceed 18")]
fn test_set_asset_decimals_rejects_above_eighteen() {
    let env = Env::default();
    let ctx = setup(&env);
    ctx.executor.set_asset_decimals(&ctx.token_id, &19u32);
}

#[test]
fn test_set_asset_decimals_accepts_valid_bounds() {
    let env = Env::default();
    let ctx = setup(&env);

    ctx.executor.set_asset_decimals(&ctx.token_id, &1u32);
    assert_eq!(ctx.executor.get_asset_decimals(&ctx.token_id), 1u32);

    ctx.executor.set_asset_decimals(&ctx.token_id, &18u32);
    assert_eq!(ctx.executor.get_asset_decimals(&ctx.token_id), 18u32);
}

#[test]
fn test_execute_payment_rejects_when_decimals_not_configured() {
    let env = Env::default();
    let ctx = setup(&env);
    let (company_id, treasury, employee) = register_company_and_employee(&env, &ctx, 1);
    ctx.token.mint(&treasury, &10_000);

    let (a, b, c, n) = proof(&env, 1);
    let result = ctx
        .executor
        .try_execute_payment(&company_id, &employee, &1_000, &a, &b, &c, &n, &1);

    assert_eq!(
        result.unwrap_err().unwrap(),
        PaymentError::AssetDecimalsMissing
    );
    assert_eq!(ctx.token.balance(&treasury), 10_000);
    assert_eq!(ctx.executor.get_total_paid(&company_id), 0);
}

#[test]
fn test_execute_payment_rejects_when_configured_decimals_do_not_match_token() {
    let env = Env::default();
    let ctx = setup(&env);
    let (company_id, treasury, employee) = register_company_and_employee(&env, &ctx, 2);
    ctx.token.mint(&treasury, &10_000);

    // Token mock reports 7 decimals; configuring 6 must be rejected at execution.
    ctx.executor.set_asset_decimals(&ctx.token_id, &6u32);

    let (a, b, c, n) = proof(&env, 2);
    let result = ctx
        .executor
        .try_execute_payment(&company_id, &employee, &1_000, &a, &b, &c, &n, &1);

    assert_eq!(
        result.unwrap_err().unwrap(),
        PaymentError::AssetDecimalsMismatch
    );
    assert_eq!(ctx.token.balance(&treasury), 10_000);
    assert_eq!(ctx.token.balance(&employee), 0);
    assert!(!ctx.executor.is_paid(&employee, &1));
}

#[test]
fn test_execute_payment_succeeds_with_matching_token_decimals() {
    let env = Env::default();
    let ctx = setup(&env);
    let (company_id, treasury, employee) = register_company_and_employee(&env, &ctx, 3);
    ctx.token.mint(&treasury, &10_000);

    ctx.executor.set_asset_decimals(&ctx.token_id, &7u32);

    let (a, b, c, n) = proof(&env, 3);
    ctx.executor
        .execute_payment(&company_id, &employee, &2_500, &a, &b, &c, &n, &1);

    assert_eq!(ctx.token.balance(&treasury), 7_500);
    assert_eq!(ctx.token.balance(&employee), 2_500);
    assert_eq!(ctx.executor.get_total_paid(&company_id), 2_500);
    assert!(ctx.executor.is_paid(&employee, &1));
}

#[test]
fn test_precision_regression_non_round_amounts_preserved_with_enforced_decimals() {
    let env = Env::default();
    let ctx = setup(&env);
    let (company_id, treasury, employee) = register_company_and_employee(&env, &ctx, 4);
    ctx.token.mint(&treasury, &2_000_000_000);
    ctx.executor.set_asset_decimals(&ctx.token_id, &7u32);

    let amounts: [i128; 3] = [1, 333_333_333, 999_999_937];
    let mut expected = 0i128;
    for (i, amount) in amounts.into_iter().enumerate() {
        if i > 0 {
            ctx.executor.close_period(&company_id, &(i as u32));
            ctx.executor.create_period(&company_id);
        }
        let (a, b, c, n) = proof(&env, 10 + i as u8);
        ctx.executor.execute_payment(
            &company_id,
            &employee,
            &amount,
            &a,
            &b,
            &c,
            &n,
            &((i + 1) as u32),
        );
        expected += amount;
    }

    assert_eq!(ctx.executor.get_total_paid(&company_id), expected);
    assert_eq!(ctx.token.balance(&employee), expected);
}

#[test]
fn test_execute_batch_rejects_mismatched_decimals_without_partial_state_changes() {
    let env = Env::default();
    let ctx = setup(&env);
    let (company_id, treasury, employee) = register_company_and_employee(&env, &ctx, 5);
    ctx.token.mint(&treasury, &10_000);

    ctx.executor.set_asset_decimals(&ctx.token_id, &8u32);

    let (a, b, c, n) = proof(&env, 5);
    let employees = Vec::from_array(&env, [employee.clone()]);
    let amounts = Vec::from_array(&env, [1_000i128]);
    let pa = Vec::from_array(&env, [a]);
    let pb = Vec::from_array(&env, [b]);
    let pc = Vec::from_array(&env, [c]);
    let nulls = Vec::from_array(&env, [n]);

    let result = ctx.executor.try_execute_batch_payroll(
        &company_id,
        &employees,
        &amounts,
        &pa,
        &pb,
        &pc,
        &nulls,
        &1,
    );

    assert_eq!(
        result.unwrap_err().unwrap(),
        PaymentError::AssetDecimalsMismatch
    );
    assert_eq!(ctx.token.balance(&treasury), 10_000);
    assert_eq!(ctx.executor.get_total_paid(&company_id), 0);
    assert!(!ctx.executor.is_paid(&employee, &1));
}
