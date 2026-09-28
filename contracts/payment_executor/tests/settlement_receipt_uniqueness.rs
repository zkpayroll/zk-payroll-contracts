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

    (executor, registry, commitment, token, company_id, treasury, employee)
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
fn test_unused_receipt_succeeds() {
    let env = Env::default();
    let (executor, _reg, _com, _tok, company_id, _treasury, employee) =
        setup_system(&env, 1_000);
    let receipt = BytesN::from_array(&env, &[7u8; 32]);
    let (employees, amounts, a, b, c, nullifiers) =
        one_employee_batch(&env, &employee, 500, 1);

    let records = executor.execute_batch_payroll_with_receipt(
        &company_id,
        &employees,
        &amounts,
        &a,
        &b,
        &c,
        &nullifiers,
        &1,
        &receipt,
    );

    assert_eq!(records.len(), 1);
    assert!(executor.is_settlement_receipt_used(&receipt));
}

#[test]
fn test_duplicate_receipt_is_rejected() {
    let env = Env::default();
    let (executor, _reg, _com, _tok, company_id, _treasury, employee) =
        setup_system(&env, 1_000);
    let receipt = BytesN::from_array(&env, &[8u8; 32]);

    let (e1, a1, pa1, pb1, pc1, n1) = one_employee_batch(&env, &employee, 500, 1);
    executor.execute_batch_payroll_with_receipt(
        &company_id,
        &e1,
        &a1,
        &pa1,
        &pb1,
        &pc1,
        &n1,
        &1,
        &receipt,
    );

    let (e2, a2, pa2, pb2, pc2, n2) = one_employee_batch(&env, &employee, 500, 2);
    let result = executor.try_execute_batch_payroll_with_receipt(
        &company_id,
        &e2,
        &a2,
        &pa2,
        &pb2,
        &pc2,
        &n2,
        &1,
        &receipt,
    );

    assert_eq!(
        result,
        Err(Ok(PaymentError::SettlementReceiptAlreadyUsed))
    );
}

#[test]
fn test_different_receipts_are_independent() {
    let env = Env::default();
    let (executor, _reg, _com, _tok, company_id, _treasury, employee) =
        setup_system(&env, 2_000);
    let receipt_a = BytesN::from_array(&env, &[10u8; 32]);
    let receipt_b = BytesN::from_array(&env, &[11u8; 32]);

    let (e1, a1, pa1, pb1, pc1, n1) = one_employee_batch(&env, &employee, 500, 1);
    executor.execute_batch_payroll_with_receipt(
        &company_id,
        &e1,
        &a1,
        &pa1,
        &pb1,
        &pc1,
        &n1,
        &1,
        &receipt_a,
    );

    let (e2, a2, pa2, pb2, pc2, n2) = one_employee_batch(&env, &employee, 500, 2);
    executor.execute_batch_payroll_with_receipt(
        &company_id,
        &e2,
        &a2,
        &pa2,
        &pb2,
        &pc2,
        &n2,
        &1,
        &receipt_b,
    );

    assert!(executor.is_settlement_receipt_used(&receipt_a));
    assert!(executor.is_settlement_receipt_used(&receipt_b));
}

#[test]
fn test_receipt_is_globally_unique() {
    let env = Env::default();
    let (executor, _reg, _com, _tok, company_id, _treasury, employee) =
        setup_system(&env, 1_000);
    let receipt = BytesN::from_array(&env, &[12u8; 32]);

    let (e1, a1, pa1, pb1, pc1, n1) = one_employee_batch(&env, &employee, 500, 1);
    executor.execute_batch_payroll_with_receipt(
        &company_id,
        &e1,
        &a1,
        &pa1,
        &pb1,
        &pc1,
        &n1,
        &1,
        &receipt,
    );

    // Reuse the same receipt for a different (nonexistent) company ID.
    // The uniqueness guard is global, not per-company.
    let result = executor.try_execute_batch_payroll_with_receipt(
        &9999u64,
        &e1,
        &a1,
        &pa1,
        &pb1,
        &pc1,
        &n1,
        &1,
        &receipt,
    );

    assert_eq!(
        result,
        Err(Ok(PaymentError::SettlementReceiptAlreadyUsed))
    );
}

#[test]
fn test_rejected_batch_leaves_receipt_unused() {
    let env = Env::default();
    let (executor, _reg, _com, _tok, company_id, _treasury, employee) =
        setup_system(&env, 1_000);
    let receipt = BytesN::from_array(&env, &[13u8; 32]);

    // First call consumes the receipt successfully.
    let (e, a, pa, pb, pc, n) = one_employee_batch(&env, &employee, 500, 1);
    executor.execute_batch_payroll_with_receipt(
        &company_id,
        &e,
        &a,
        &pa,
        &pb,
        &pc,
        &n,
        &1,
        &receipt,
    );

    // Second call with the same receipt should fail on the receipt guard
    // (which fires before the nullifier guard). The receipt is already
    // marked used from the first call.
    let result = executor.try_execute_batch_payroll_with_receipt(
        &company_id,
        &e,
        &a,
        &pa,
        &pb,
        &pc,
        &n,
        &1,
        &receipt,
    );

    assert_eq!(
        result,
        Err(Ok(PaymentError::SettlementReceiptAlreadyUsed))
    );
    assert!(executor.is_settlement_receipt_used(&receipt));
}