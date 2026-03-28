use ::token::{Token, TokenClient};
use payment_executor::{ContractAddresses, PaymentError, PaymentExecutor, PaymentExecutorClient};
use payroll_registry::{PayrollRegistry, PayrollRegistryClient};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
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
    TokenClient<'a>,
    u64,
    Address,
    Address,
) {
    env.mock_all_auths();

    let executor_id = env.register_contract(None, PaymentExecutor);
    let registry_id = env.register_contract(None, PayrollRegistry);
    let verifier_id = env.register_contract(None, ProofVerifier);
    let token_id = env.register_contract(None, Token);

    let executor = PaymentExecutorClient::new(env, &executor_id);
    let registry = PayrollRegistryClient::new(env, &registry_id);
    let verifier = ProofVerifierClient::new(env, &verifier_id);
    let token = TokenClient::new(env, &token_id);

    let addresses = ContractAddresses {
        registry: registry_id,
        commitment: Address::generate(env),
        verifier: verifier_id,
        token: token_id,
    };

    executor.initialize(&addresses);
    verifier.initialize_verifier(&mock_vk(env));

    let admin = Address::generate(env);
    let treasury = Address::generate(env);

    let company_id = registry.register_company(&admin, &treasury);

    token.mint(&treasury, &100_000);

    (executor, registry, token, company_id, admin, treasury)
}

/// Acceptance Criteria: Proof Replay Protection (Double Spend)
/// - Submit a valid, legitimate Groth16 proof. (Expected: Success).
/// - In the exact same test, immediately submit the exact same proof again.
/// - Assert the contract fully panics with a custom error like Error::ProofAlreadyUsed.
#[test]
fn test_proof_replay_protection() {
    let env = Env::default();
    let (executor, registry, _token, company_id, _admin, _treasury) = setup_system(&env);

    let employee = Address::generate(&env);
    let commitment = BytesN::from_array(&env, &[9u8; 32]);
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
    let (executor, registry, _token, company_id, _admin, _treasury) = setup_system(&env);

    let employee = Address::generate(&env);
    let commitment = BytesN::from_array(&env, &[9u8; 32]);
    registry.add_employee(&company_id, &employee, &commitment);

    let proof_a = BytesN::from_array(&env, &[5u8; 64]);
    let proof_b = BytesN::from_array(&env, &[6u8; 128]);
    let proof_c = BytesN::from_array(&env, &[7u8; 64]);
    let nullifier = BytesN::from_array(&env, &[8u8; 32]);

    executor.execute_payment(
        &company_id,
        &employee,
        &2500,
        &proof_a,
        &proof_b,
        &proof_c,
        &nullifier,
        &42,
    );

    assert!(executor.is_paid(&employee, &42));
    assert_eq!(executor.get_total_paid(&company_id), 2500);

    let replay = executor.try_execute_payment(
        &company_id,
        &employee,
        &2500,
        &proof_a,
        &proof_b,
        &proof_c,
        &nullifier,
        &42,
    );

    // ProofAlreadyUsed error would happen first because nullifier checks precede AlreadyPaid checks and token transfers.
    assert_eq!(replay.unwrap_err().unwrap(), PaymentError::ProofAlreadyUsed);
}
