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
    treasury_balance: i128,
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
        executor, registry, commitment, token, company_id, treasury, employee,
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

fn one_employee_batch(
    env: &Env,
    employee: &Address,
    amount: i128,
    seed: u8,
) -> (
    Vec<Address>,
    Vec<i128>,
    Vec<BytesN<64>>,
    Vec<BytesN<128>>,
    Vec<BytesN<64>>,
    Vec<BytesN<32>>,
) {
    let (a, b, c, nullifier) = payment_inputs(env, seed);
    (
        Vec::from_array(env, [employee.clone()]),
        Vec::from_array(env, [amount]),
        Vec::from_array(env, [a]),
        Vec::from_array(env, [b]),
        Vec::from_array(env, [c]),
        Vec::from_array(env, [nullifier]),
    )
}

#[test]
fn test_all_zero_receipt_is_single_use_and_replay_is_rejected() {
    let env = Env::default();
    let (executor, _reg, _com, token, company_id, treasury, employee) = setup_system(&env, 2_000);
    let receipt = BytesN::from_array(&env, &[0u8; 32]);

    let (e1, a1, pa1, pb1, pc1, n1) = one_employee_batch(&env, &employee, 500, 21);
    executor.execute_batch_with_receipt(&company_id, &e1, &a1, &pa1, &pb1, &pc1, &n1, &1, &receipt);

    let treasury_before = token.balance(&treasury);
    let total_before = executor.get_total_paid(&company_id);

    executor.close_period(&company_id, &1);
    executor.create_period(&company_id);
    let (e2, a2, pa2, pb2, pc2, n2) = one_employee_batch(&env, &employee, 400, 22);
    let replay = executor.try_execute_batch_with_receipt(
        &company_id,
        &e2,
        &a2,
        &pa2,
        &pb2,
        &pc2,
        &n2,
        &2,
        &receipt,
    );

    assert_eq!(replay, Err(Ok(PaymentError::SettlementReceiptAlreadyUsed)));
    assert_eq!(token.balance(&treasury), treasury_before);
    assert_eq!(executor.get_total_paid(&company_id), total_before);
    assert!(!executor.is_paid(&employee, &2));
}

#[test]
fn test_duplicate_receipt_replay_is_noop_for_state_and_funds() {
    let env = Env::default();
    let (executor, _reg, _com, token, company_id, treasury, employee) = setup_system(&env, 3_000);
    let receipt = BytesN::from_array(&env, &[99u8; 32]);

    let (e1, a1, pa1, pb1, pc1, n1) = one_employee_batch(&env, &employee, 700, 31);
    executor.execute_batch_with_receipt(&company_id, &e1, &a1, &pa1, &pb1, &pc1, &n1, &1, &receipt);

    let treasury_before = token.balance(&treasury);
    let employee_before = token.balance(&employee);
    let total_before = executor.get_total_paid(&company_id);
    let period_before = executor.get_period(&company_id, &1).unwrap();

    executor.close_period(&company_id, &1);
    executor.create_period(&company_id);
    let (e2, a2, pa2, pb2, pc2, n2) = one_employee_batch(&env, &employee, 100, 32);
    let replay = executor.try_execute_batch_with_receipt(
        &company_id,
        &e2,
        &a2,
        &pa2,
        &pb2,
        &pc2,
        &n2,
        &2,
        &receipt,
    );

    assert_eq!(replay, Err(Ok(PaymentError::SettlementReceiptAlreadyUsed)));
    assert!(executor.is_settlement_receipt_used(&receipt));
    assert_eq!(token.balance(&treasury), treasury_before);
    assert_eq!(token.balance(&employee), employee_before);
    assert_eq!(executor.get_total_paid(&company_id), total_before);
    let period_after = executor.get_period(&company_id, &1).unwrap();
    assert_eq!(period_after.payment_count, period_before.payment_count);
    assert!(!executor.is_paid(&employee, &2));
}

#[test]
fn test_receipt_reuse_across_companies_is_rejected() {
    let env = Env::default();
    let (executor, registry, commitment, token, company_a, _treasury_a, employee_a) =
        setup_system(&env, 2_000);
    let receipt = BytesN::from_array(&env, &[77u8; 32]);

    let (e1, a1, pa1, pb1, pc1, n1) = one_employee_batch(&env, &employee_a, 500, 41);
    executor.execute_batch_with_receipt(&company_a, &e1, &a1, &pa1, &pb1, &pc1, &n1, &1, &receipt);

    // Register a second, valid company and attempt to reuse the same receipt.
    let admin_b = Address::generate(&env);
    let treasury_b = Address::generate(&env);
    let employee_b = Address::generate(&env);
    let company_b = registry.register_company(&admin_b, &treasury_b);
    executor.create_period(&company_b);
    token.mint(&treasury_b, &2_000);
    let commitment_b = BytesN::from_array(&env, &[2u8; 32]);
    commitment.store_commitment(&employee_b, &commitment_b);
    registry.add_employee(&company_b, &employee_b, &commitment_b);
    let tax_b = Address::generate(&env);
    executor.set_withholding_config(&company_b, &0u32, &0u32, &tax_b, &tax_b, &0i128, &0i128);

    let (e2, a2, pa2, pb2, pc2, n2) = one_employee_batch(&env, &employee_b, 300, 42);
    let replay = executor
        .try_execute_batch_with_receipt(&company_b, &e2, &a2, &pa2, &pb2, &pc2, &n2, &1, &receipt);

    assert_eq!(replay, Err(Ok(PaymentError::SettlementReceiptAlreadyUsed)));
    assert_eq!(executor.get_total_paid(&company_b), 0);
    assert!(!executor.is_paid(&employee_b, &1));
}

#[test]
fn test_batch_too_large_with_receipt_does_not_consume_receipt() {
    let env = Env::default();
    let (executor, registry, commitment, token, company_id, treasury, employee1) =
        setup_system(&env, 10_000);
    let receipt = BytesN::from_array(&env, &[55u8; 32]);

    let employee2 = Address::generate(&env);
    let commitment2 = BytesN::from_array(&env, &[3u8; 32]);
    commitment.store_commitment(&employee2, &commitment2);
    registry.add_employee(&company_id, &employee2, &commitment2);

    // Limit batch size to 1 so a 2-employee batch is rejected after receipt guard.
    executor.set_max_batch_size(&company_id, &1);

    let (a1, b1, c1, n1) = payment_inputs(&env, 51);
    let (a2, b2, c2, n2) = payment_inputs(&env, 52);
    let employees = Vec::from_array(&env, [employee1.clone(), employee2.clone()]);
    let amounts = Vec::from_array(&env, [500i128, 500i128]);
    let pa = Vec::from_array(&env, [a1.clone(), a2.clone()]);
    let pb = Vec::from_array(&env, [b1.clone(), b2.clone()]);
    let pc = Vec::from_array(&env, [c1.clone(), c2.clone()]);
    let nulls = Vec::from_array(&env, [n1.clone(), n2.clone()]);

    let failed = executor.try_execute_batch_with_receipt(
        &company_id,
        &employees,
        &amounts,
        &pa,
        &pb,
        &pc,
        &nulls,
        &1,
        &receipt,
    );
    assert_eq!(failed, Err(Ok(PaymentError::BatchTooLarge)));
    assert!(!executor.is_settlement_receipt_used(&receipt));
    assert_eq!(executor.get_total_paid(&company_id), 0);
    assert_eq!(token.balance(&treasury), 10_000);

    // A corrected single-employee retry with the same receipt succeeds.
    executor.set_max_batch_size(&company_id, &10);
    let (e_ok, a_ok, pa_ok, pb_ok, pc_ok, n_ok) = one_employee_batch(&env, &employee1, 500, 51);
    let records = executor.execute_batch_with_receipt(
        &company_id,
        &e_ok,
        &a_ok,
        &pa_ok,
        &pb_ok,
        &pc_ok,
        &n_ok,
        &1,
        &receipt,
    );
    assert_eq!(records.len(), 1);
    assert!(executor.is_settlement_receipt_used(&receipt));
}
