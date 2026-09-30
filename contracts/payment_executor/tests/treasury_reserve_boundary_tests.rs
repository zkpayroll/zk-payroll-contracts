use ::token::{Token, TokenClient};
use payment_executor::{ContractAddresses, PaymentExecutor, PaymentExecutorClient};
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
    treasury_balance: i128,
) -> (
    PaymentExecutorClient<'a>,
    PayrollRegistryClient<'a>,
    SalaryCommitmentContractClient<'a>,
    TokenClient<'a>,
    u64,
    Address,
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
    let commitment = SalaryCommitmentContractClient::new(env, &commitment_id);
    let verifier = ProofVerifierClient::new(env, &verifier_id);
    let token = TokenClient::new(env, &token_id);

    executor.initialize(&ContractAddresses {
        registry: registry_id,
        commitment: commitment_id,
        verifier: verifier_id,
        token: token_id,
    });
    verifier.init_verifier_admin(&Address::generate(env));
    verifier.initialize_verifier(&mock_vk(env));

    let commitment_admin = Address::generate(env);
    commitment.init_commitment_admin(&commitment_admin);
    commitment.set_payroll_operator(&executor_id);

    let admin = Address::generate(env);
    let treasury = Address::generate(env);
    let employee = Address::generate(env);
    let company_id = registry.register_company(&admin, &treasury);
    executor.create_period(&company_id);
    token.mint(&treasury, &treasury_balance);

    let employee_commitment = BytesN::from_array(env, &[1u8; 32]);
    commitment.store_commitment(&employee, &employee_commitment);
    registry.add_employee(&company_id, &employee, &employee_commitment);

    (
        executor, registry, commitment, token, company_id, treasury, employee, admin,
    )
}

fn payment_inputs(env: &Env, seed: u8) -> (BytesN<64>, BytesN<128>, BytesN<64>, BytesN<32>) {
    (
        BytesN::from_array(env, &[seed; 64]),
        BytesN::from_array(env, &[seed; 128]),
        BytesN::from_array(env, &[seed; 64]),
        BytesN::from_array(env, &[seed; 32]),
    )
}

#[test]
fn exact_treasury_reserve_covers_payment() {
    let env = Env::default();
    let (executor, _registry, _commitment, token, company_id, treasury, employee, _admin) =
        setup_system(&env, 1_000);
    let (proof_a, proof_b, proof_c, nullifier) = payment_inputs(&env, 1);

    executor.execute_payment(
        &company_id,
        &employee,
        &1_000,
        &proof_a,
        &proof_b,
        &proof_c,
        &nullifier,
        &1,
    );

    assert_eq!(token.balance(&treasury), 0);
    assert_eq!(token.balance(&employee), 1_000);
    assert_eq!(executor.get_total_paid(&company_id), 1_000);
    assert!(executor.is_paid(&employee, &1));
}

#[test]
fn one_unit_below_payment_reserve_is_rejected_without_state_changes() {
    let env = Env::default();
    let (executor, _registry, _commitment, token, company_id, treasury, employee, _admin) =
        setup_system(&env, 999);
    let (proof_a, proof_b, proof_c, nullifier) = payment_inputs(&env, 2);

    let result = executor.try_execute_payment(
        &company_id,
        &employee,
        &1_000,
        &proof_a,
        &proof_b,
        &proof_c,
        &nullifier,
        &1,
    );

    assert!(result.is_err());
    assert_eq!(token.balance(&treasury), 999);
    assert_eq!(token.balance(&employee), 0);
    assert_eq!(executor.get_total_paid(&company_id), 0);
    assert!(!executor.is_paid(&employee, &1));
}

#[test]
fn zero_treasury_reserve_is_rejected_without_state_changes() {
    let env = Env::default();
    let (executor, _registry, _commitment, token, company_id, treasury, employee, _admin) =
        setup_system(&env, 0);
    let (proof_a, proof_b, proof_c, nullifier) = payment_inputs(&env, 3);

    let result = executor.try_execute_payment(
        &company_id,
        &employee,
        &1,
        &proof_a,
        &proof_b,
        &proof_c,
        &nullifier,
        &1,
    );

    assert!(result.is_err());
    assert_eq!(token.balance(&treasury), 0);
    assert_eq!(token.balance(&employee), 0);
    assert_eq!(executor.get_total_paid(&company_id), 0);
    assert!(!executor.is_paid(&employee, &1));
}
