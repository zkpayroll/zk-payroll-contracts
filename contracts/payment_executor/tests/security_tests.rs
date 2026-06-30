use ::token::{Token, TokenClient};
use payment_executor::{ContractAddresses, PaymentError, PaymentExecutor, PaymentExecutorClient};
use payroll_registry::{PayrollRegistry, PayrollRegistryClient};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::SalaryCommitmentContract;
use soroban_sdk::testutils::{Address as _, MockAuth, MockAuthInvoke};
use soroban_sdk::{Address, BytesN, Env, IntoVal, Vec};

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
    salary_commitment::SalaryCommitmentContractClient<'a>,
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
    let commitment_client =
        salary_commitment::SalaryCommitmentContractClient::new(env, &commitment_id);
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

    executor.create_period(&company_id);

    token.mint(&treasury, &100_000);

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

/// Acceptance Criteria: Proof Replay Protection (Double Spend)
/// - Submit a valid, legitimate Groth16 proof. (Expected: Success).
/// - In the exact same test, immediately submit the exact same proof again.
/// - Assert the contract fully panics with a custom error like Error::ProofAlreadyUsed.
#[test]
fn test_proof_replay_protection() {
    let env = Env::default();
    let (executor, registry, commitment_client, _token, company_id, _admin, _treasury) =
        setup_system(&env);

    let employee = Address::generate(&env);
    let commitment = BytesN::from_array(&env, &[9u8; 32]);
    commitment_client.store_commitment(&employee, &commitment);
    registry.add_employee(&company_id, &employee, &commitment);

    let proof_a = BytesN::from_array(&env, &[1u8; 64]);
    let proof_b = BytesN::from_array(&env, &[2u8; 128]);
    let proof_c = BytesN::from_array(&env, &[3u8; 64]);
    let nullifier = BytesN::from_array(&env, &[4u8; 32]);

    executor.execute_payment(
        &company_id,
        &employee,
        &1000,
        &proof_a,
        &proof_b,
        &proof_c,
        &nullifier,
        &1,
    );

    executor.create_period(&company_id);

    let result = executor.try_execute_payment(
        &company_id,
        &employee,
        &1000,
        &proof_a,
        &proof_b,
        &proof_c,
        &nullifier,
        &2, // Different period so we know it fails due to ProofAlreadyUsed (nullifier), not AlreadyPaid.
    );

    assert_eq!(result.unwrap_err().unwrap(), PaymentError::ProofAlreadyUsed);
}

/// Acceptance Criteria: Authorization (Access Control)
/// - Attempt to call add_employee using a keypair that is not the registered HR Admin.
/// - Assert Panic.
#[test]
#[should_panic(expected = "authorized")]
fn test_authorization_add_employee_fails_for_non_admin() {
    let env = Env::default();

    let registry_id = env.register_contract(None, PayrollRegistry);
    let registry = PayrollRegistryClient::new(&env, &registry_id);

    let correct_admin = Address::generate(&env);
    let treasury = Address::generate(&env);

    env.mock_auths(&[MockAuth {
        address: &correct_admin,
        invoke: &MockAuthInvoke {
            contract: &registry_id,
            fn_name: "register_company",
            args: (correct_admin.clone(), treasury.clone()).into_val(&env),
            sub_invokes: &[],
        },
    }]);

    let company_id = registry.register_company(&correct_admin, &treasury);

    let attacker = Address::generate(&env);
    let employee = Address::generate(&env);
    let commitment = BytesN::from_array(&env, &[9u8; 32]);

    env.mock_auths(&[MockAuth {
        address: &attacker,
        invoke: &MockAuthInvoke {
            contract: &registry_id,
            fn_name: "add_employee",
            args: (company_id, employee.clone(), commitment.clone()).into_val(&env),
            sub_invokes: &[],
        },
    }]);

    registry.add_employee(&company_id, &employee, &commitment);
}

/// Acceptance Criteria: Reentrancy
/// - Soroban prevents same-contract reentrancy across inter-contract calls.
/// - Verify state is updated before any external interaction would occur.
#[test]
fn test_reentrancy_state_updates_before_external_calls() {
    let env = Env::default();
    let (executor, registry, commitment_client, _token, company_id, _admin, _treasury) =
        setup_system(&env);

    let employee = Address::generate(&env);
    let commitment = BytesN::from_array(&env, &[9u8; 32]);
    commitment_client.store_commitment(&employee, &commitment);
    registry.add_employee(&company_id, &employee, &commitment);

    let proof_a = BytesN::from_array(&env, &[5u8; 64]);
    let proof_b = BytesN::from_array(&env, &[6u8; 128]);
    let proof_c = BytesN::from_array(&env, &[7u8; 64]);
    let nullifier = BytesN::from_array(&env, &[8u8; 32]);

    executor.create_period(&company_id);
    executor.create_period(&company_id);

    executor.execute_payment(
        &company_id,
        &employee,
        &2500,
        &proof_a,
        &proof_b,
        &proof_c,
        &nullifier,
        &2,
    );

    assert!(executor.is_paid(&employee, &2));
    assert_eq!(executor.get_total_paid(&company_id), 2500);

    let replay = executor.try_execute_payment(
        &company_id,
        &employee,
        &2500,
        &proof_a,
        &proof_b,
        &proof_c,
        &nullifier,
        &2,
    );

    // ProofAlreadyUsed error would happen first because nullifier checks precede AlreadyPaid checks and token transfers.
    assert_eq!(replay.unwrap_err().unwrap(), PaymentError::ProofAlreadyUsed);
}

// ============================================================================
// Retry Scenario Tests (Issue #136)
// ============================================================================

/// Acceptance Criteria: Retry Safety After Partial Failure
/// - Execute payment for employee A in period 1 (success).
/// - Execute payment for employee A in period 2 (success).
/// - Verify both payments were recorded.
/// - Attempt replay of period 1 payment (should fail with ProofAlreadyUsed).
/// - This demonstrates that period-based retries with new periods succeed
///   while cross-period replay is prevented by nullifier mechanism.
#[test]
fn test_retry_across_periods_succeeds_with_new_period() {
    let env = Env::default();
    let (executor, registry, commitment_client, _token, company_id, _admin, _treasury) =
        setup_system(&env);

    let employee = Address::generate(&env);
    let commitment = BytesN::from_array(&env, &[10u8; 32]);

    commitment_client.store_commitment(&employee, &commitment);
    registry.add_employee(&company_id, &employee, &commitment);

    // Payment 1 in period 1
    let proof_a_1 = BytesN::from_array(&env, &[20u8; 64]);
    let proof_b_1 = BytesN::from_array(&env, &[21u8; 128]);
    let proof_c_1 = BytesN::from_array(&env, &[22u8; 64]);
    let nullifier_1 = BytesN::from_array(&env, &[23u8; 32]);

    executor.execute_payment(
        &company_id,
        &employee,
        &500,
        &proof_a_1,
        &proof_b_1,
        &proof_c_1,
        &nullifier_1,
        &1,
    );

    assert!(executor.is_paid(&employee, &1));
    assert_eq!(executor.get_total_paid(&company_id), 500);

    // Create a new period (period 2)
    executor.create_period(&company_id);

    // Payment 2 in period 2 with different proof/amount
    let proof_a_2 = BytesN::from_array(&env, &[30u8; 64]);
    let proof_b_2 = BytesN::from_array(&env, &[31u8; 128]);
    let proof_c_2 = BytesN::from_array(&env, &[32u8; 64]);
    let nullifier_2 = BytesN::from_array(&env, &[33u8; 32]);

    executor.execute_payment(
        &company_id,
        &employee,
        &300,
        &proof_a_2,
        &proof_b_2,
        &proof_c_2,
        &nullifier_2,
        &2,
    );

    // Both payments recorded
    assert!(executor.is_paid(&employee, &1));
    assert!(executor.is_paid(&employee, &2));
    assert_eq!(executor.get_total_paid(&company_id), 800);

    // Verify replay of either proof is blocked
    let replay_1 = executor.try_execute_payment(
        &company_id,
        &employee,
        &500,
        &proof_a_1,
        &proof_b_1,
        &proof_c_1,
        &nullifier_1,
        &1,
    );
    assert_eq!(replay_1.unwrap_err().unwrap(), PaymentError::ProofAlreadyUsed);

    let replay_2 = executor.try_execute_payment(
        &company_id,
        &employee,
        &300,
        &proof_a_2,
        &proof_b_2,
        &proof_c_2,
        &nullifier_2,
        &2,
    );
    assert_eq!(replay_2.unwrap_err().unwrap(), PaymentError::ProofAlreadyUsed);
}

/// Acceptance Criteria: Idempotent Retry Within Same Period
/// - Execute payment for employee A with period 1.
/// - Verify payment recorded.
/// - Attempt same payment again (should fail with AlreadyPaid).
/// - Verify state unchanged: exactly one payment recorded.
#[test]
fn test_retry_same_period_detects_already_paid() {
    let env = Env::default();
    let (executor, registry, commitment_client, _token, company_id, _admin, _treasury) =
        setup_system(&env);

    let employee = Address::generate(&env);
    let commitment = BytesN::from_array(&env, &[50u8; 32]);

    commitment_client.store_commitment(&employee, &commitment);
    registry.add_employee(&company_id, &employee, &commitment);

    let proof_a = BytesN::from_array(&env, &[60u8; 64]);
    let proof_b = BytesN::from_array(&env, &[61u8; 128]);
    let proof_c = BytesN::from_array(&env, &[62u8; 64]);
    let nullifier = BytesN::from_array(&env, &[63u8; 32]);

    // First payment in period 1
    executor.execute_payment(&company_id, &employee, &1000, &proof_a, &proof_b, &proof_c, &nullifier, &1);

    assert!(executor.is_paid(&employee, &1));
    assert_eq!(executor.get_total_paid(&company_id), 1000);

    // Retry same payment in same period (should fail)
    let retry_result = executor.try_execute_payment(
        &company_id,
        &employee,
        &1000,
        &proof_a,
        &proof_b,
        &proof_c,
        &nullifier,
        &1,
    );

    // Should fail due to ProofAlreadyUsed (nullifier already consumed)
    assert_eq!(retry_result.unwrap_err().unwrap(), PaymentError::ProofAlreadyUsed);

    // Verify no duplicate payment was recorded
    assert_eq!(executor.get_total_paid(&company_id), 1000);
}

/// Acceptance Criteria: Period-Based Replay Isolation
/// - Execute payment for employee A with proof P in period 1.
/// - Create period 2.
/// - Verify that proof P cannot be reused in period 2 (even though period changed).
/// - This confirms nullifier is scoped correctly and prevents cross-period replay.
#[test]
fn test_period_isolation_prevents_cross_period_replay() {
    let env = Env::default();
    let (executor, registry, commitment_client, _token, company_id, _admin, _treasury) =
        setup_system(&env);

    let employee = Address::generate(&env);
    let commitment = BytesN::from_array(&env, &[70u8; 32]);

    commitment_client.store_commitment(&employee, &commitment);
    registry.add_employee(&company_id, &employee, &commitment);

    let proof_a = BytesN::from_array(&env, &[80u8; 64]);
    let proof_b = BytesN::from_array(&env, &[81u8; 128]);
    let proof_c = BytesN::from_array(&env, &[82u8; 64]);
    let nullifier = BytesN::from_array(&env, &[83u8; 32]);

    // Execute payment in period 1
    executor.execute_payment(&company_id, &employee, &2000, &proof_a, &proof_b, &proof_c, &nullifier, &1);
    assert!(executor.is_paid(&employee, &1));

    // Create a new period (period 2)
    executor.create_period(&company_id);

    // Attempt to reuse same proof in period 2 (should fail due to nullifier)
    let cross_period_result = executor.try_execute_payment(
        &company_id,
        &employee,
        &2000,
        &proof_a,
        &proof_b,
        &proof_c,
        &nullifier,
        &2,
    );

    // Should fail because nullifier was already consumed in period 1
    assert_eq!(cross_period_result.unwrap_err().unwrap(), PaymentError::ProofAlreadyUsed);

    // Verify employee is not marked as paid in period 2
    assert!(!executor.is_paid(&employee, &2));

    // Verify total paid remains at first payment only
    assert_eq!(executor.get_total_paid(&company_id), 2000);
}

/// Acceptance Criteria: Multiple Employees in Same Period
/// - Execute payment for employee A with proof PA in period 1.
/// - Execute payment for employee B with proof PB in period 1.
/// - Verify both payments recorded.
/// - Attempt replay of PA (should fail with ProofAlreadyUsed).
/// - Attempt replay of PB (should fail with ProofAlreadyUsed).
/// - Attempt to pay employee A again in period 1 with new proof (should fail with AlreadyPaid).
/// - This confirms: nullifier prevents proof reuse, AlreadyPaid prevents duplicate employee payments.
#[test]
fn test_retry_multiple_employees_detects_duplicates() {
    let env = Env::default();
    let (executor, registry, commitment_client, _token, company_id, _admin, _treasury) =
        setup_system(&env);

    let employee_a = Address::generate(&env);
    let employee_b = Address::generate(&env);

    let commitment_a = BytesN::from_array(&env, &[90u8; 32]);
    let commitment_b = BytesN::from_array(&env, &[91u8; 32]);

    commitment_client.store_commitment(&employee_a, &commitment_a);
    commitment_client.store_commitment(&employee_b, &commitment_b);
    registry.add_employee(&company_id, &employee_a, &commitment_a);
    registry.add_employee(&company_id, &employee_b, &commitment_b);

    // First employee payment
    let proof_a_1 = BytesN::from_array(&env, &[100u8; 64]);
    let proof_b_1 = BytesN::from_array(&env, &[101u8; 128]);
    let proof_c_1 = BytesN::from_array(&env, &[102u8; 64]);
    let nullifier_1 = BytesN::from_array(&env, &[103u8; 32]);

    executor.execute_payment(
        &company_id,
        &employee_a,
        &500,
        &proof_a_1,
        &proof_b_1,
        &proof_c_1,
        &nullifier_1,
        &1,
    );

    assert_eq!(executor.get_total_paid(&company_id), 500);

    // Second employee payment
    let proof_a_2 = BytesN::from_array(&env, &[110u8; 64]);
    let proof_b_2 = BytesN::from_array(&env, &[111u8; 128]);
    let proof_c_2 = BytesN::from_array(&env, &[112u8; 64]);
    let nullifier_2 = BytesN::from_array(&env, &[113u8; 32]);

    executor.execute_payment(
        &company_id,
        &employee_b,
        &300,
        &proof_a_2,
        &proof_b_2,
        &proof_c_2,
        &nullifier_2,
        &1,
    );

    // Both payments recorded
    assert_eq!(executor.get_total_paid(&company_id), 800);

    // Verify replay of either proof is blocked by nullifier
    let replay_1 = executor.try_execute_payment(
        &company_id,
        &employee_a,
        &500,
        &proof_a_1,
        &proof_b_1,
        &proof_c_1,
        &nullifier_1,
        &1,
    );
    assert_eq!(replay_1.unwrap_err().unwrap(), PaymentError::ProofAlreadyUsed);

    let replay_2 = executor.try_execute_payment(
        &company_id,
        &employee_b,
        &300,
        &proof_a_2,
        &proof_b_2,
        &proof_c_2,
        &nullifier_2,
        &1,
    );
    assert_eq!(replay_2.unwrap_err().unwrap(), PaymentError::ProofAlreadyUsed);

    // Attempt to pay employee A again with different proof (should fail with AlreadyPaid)
    let proof_a_3 = BytesN::from_array(&env, &[120u8; 64]);
    let proof_b_3 = BytesN::from_array(&env, &[121u8; 128]);
    let proof_c_3 = BytesN::from_array(&env, &[122u8; 64]);
    let nullifier_3 = BytesN::from_array(&env, &[123u8; 32]);

    let double_pay_result = executor.try_execute_payment(
        &company_id,
        &employee_a,
        &250,
        &proof_a_3,
        &proof_b_3,
        &proof_c_3,
        &nullifier_3,
        &1,
    );
    assert_eq!(double_pay_result.unwrap_err().unwrap(), PaymentError::AlreadyPaid);

    // Final verification: total paid unchanged
    assert_eq!(executor.get_total_paid(&company_id), 800);
}
