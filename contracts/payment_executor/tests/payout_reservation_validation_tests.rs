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

fn setup_system<'a>(
    env: &'a Env,
) -> (
    PaymentExecutorClient<'a>,
    PayrollRegistryClient<'a>,
    u64,
    Address,
    Address,
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
    token.mint(&treasury, &1_000_000);

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
        company_id,
        admin,
        treasury,
    )
}

#[test]
fn test_validate_payout_against_reserved_funds_success() {
    let env = Env::default();
    let (executor, _registry, company_id, _admin, _treasury) = setup_system(&env);

    // Reserve 500_000 for the company
    assert_eq!(executor.get_reserved_funds(&company_id), 0);
    executor.set_reserved_funds(&company_id, &500_000);
    assert_eq!(executor.get_reserved_funds(&company_id), 500_000);

    // Payout equal to reserved funds -> valid
    let result = executor.validate_payout_reserve(&company_id, &500_000);
    assert!(result);

    // Payout less than reserved funds -> valid
    let result = executor.validate_payout_reserve(&company_id, &350_000);
    assert!(result);
}

#[test]
fn test_validate_payout_against_reserved_funds_exceeds_rejected() {
    let env = Env::default();
    let (executor, _registry, company_id, _admin, _treasury) = setup_system(&env);

    // Reserve 100_000
    executor.set_reserved_funds(&company_id, &100_000);

    // Payout 1 unit above reserved funds -> rejected
    let res = executor.try_validate_payout_reserve(&company_id, &100_001);
    assert!(res.is_err());
    assert_eq!(res.unwrap_err().unwrap(), PaymentError::PayoutExceedsReservedFunds);

    // Substantially higher payout -> rejected
    let res = executor.try_validate_payout_reserve(&company_id, &250_000);
    assert!(res.is_err());
    assert_eq!(res.unwrap_err().unwrap(), PaymentError::PayoutExceedsReservedFunds);
}

#[test]
fn test_validate_payout_boundary_zero_and_negative() {
    let env = Env::default();
    let (executor, _registry, company_id, _admin, _treasury) = setup_system(&env);

    // When 0 is reserved, 0 payout is accepted
    assert_eq!(executor.get_reserved_funds(&company_id), 0);
    assert!(executor.validate_payout_reserve(&company_id, &0));

    // Any positive payout when 0 is reserved -> rejected
    let res = executor.try_validate_payout_reserve(&company_id, &1);
    assert!(res.is_err());
    assert_eq!(res.unwrap_err().unwrap(), PaymentError::PayoutExceedsReservedFunds);

    // Negative payout -> rejected as InvalidReservedAmount
    let res = executor.try_validate_payout_reserve(&company_id, &-500);
    assert!(res.is_err());
    assert_eq!(res.unwrap_err().unwrap(), PaymentError::InvalidReservedAmount);

    // Setting negative reserved funds -> rejected
    let res = executor.try_set_reserved_funds(&company_id, &-1000);
    assert!(res.is_err());
    assert_eq!(res.unwrap_err().unwrap(), PaymentError::InvalidReservedAmount);
}

#[test]
fn test_batch_payout_respects_reserved_funds() {
    let env = Env::default();
    let (executor, _registry, company_id, _admin, _treasury) = setup_system(&env);

    // Reserve 2_000 for the company
    executor.set_reserved_funds(&company_id, &2_000);

    let emp1 = Address::generate(&env);
    let emp2 = Address::generate(&env);

    let employees = Vec::from_array(&env, [emp1, emp2]);
    let amounts_exceeding = Vec::from_array(&env, [1_500i128, 600i128]); // sum = 2_100 > 2_000

    let dummy_a = Vec::from_array(&env, [BytesN::from_array(&env, &[0u8; 64]), BytesN::from_array(&env, &[0u8; 64])]);
    let dummy_b = Vec::from_array(&env, [BytesN::from_array(&env, &[0u8; 128]), BytesN::from_array(&env, &[0u8; 128])]);
    let dummy_c = Vec::from_array(&env, [BytesN::from_array(&env, &[0u8; 64]), BytesN::from_array(&env, &[0u8; 64])]);
    let dummy_nullifiers = Vec::from_array(&env, [BytesN::from_array(&env, &[1u8; 32]), BytesN::from_array(&env, &[2u8; 32])]);

    // Batch exceeding reserved funds -> rejected with PayoutExceedsReservedFunds
    let res = executor.try_execute_batch_payroll(
        &company_id,
        &employees,
        &amounts_exceeding,
        &dummy_a,
        &dummy_b,
        &dummy_c,
        &dummy_nullifiers,
        &1u32,
    );
    assert!(res.is_err());
    assert_eq!(res.unwrap_err().unwrap(), PaymentError::PayoutExceedsReservedFunds);
}
