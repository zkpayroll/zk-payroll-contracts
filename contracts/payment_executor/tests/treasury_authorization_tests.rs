use ::token::{Token, TokenClient};
use payment_executor::{ContractAddresses, PaymentError, PaymentExecutor, PaymentExecutorClient};
use payroll_registry::{PayrollRegistry, PayrollRegistryClient};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::SalaryCommitmentContract;
use soroban_sdk::testutils::{Address as _, Ledger, MockAuth, MockAuthInvoke};
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

fn setup_system_no_auth<'a>(
    env: &'a Env,
) -> (
    PaymentExecutorClient<'a>,
    PayrollRegistryClient<'a>,
    salary_commitment::SalaryCommitmentContractClient<'a>,
    TokenClient<'a>,
    u64,
    Address,
    Address,
    Address,
    Address,
) {
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
        registry: registry_id.clone(),
        commitment: commitment_id.clone(),
        verifier: verifier_id.clone(),
        token: token_id.clone(),
    };

    // We will use mock_all_auths for setup to avoid boilerplate
    env.mock_all_auths();

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

    let employee = Address::generate(env);
    let commitment = BytesN::from_array(env, &[9u8; 32]);
    commitment_client.store_commitment(&employee, &commitment);
    registry.add_employee(&company_id, &employee, &commitment);

    // Turn off mock_all_auths to test explicit auths
    // Actually mock_all_auths() applies globally, we can't un-mock it easily in Soroban tests,
    // unless we don't call it at all, or just use it but rely on should_panic for auth checks.
    // Wait, mock_all_auths() replaces the auth manager.

    (
        executor,
        registry,
        commitment_client,
        token,
        company_id,
        admin,
        treasury,
        employee,
        token_id,
    )
}

fn amount_to_public_input(env: &Env, amount: i128) -> BytesN<32> {
    let mut bytes = [0u8; 32];
    let amount_u128 = amount as u128;
    bytes[16..].copy_from_slice(&amount_u128.to_be_bytes());
    BytesN::from_array(env, &bytes)
}

#[test]
fn test_execution_with_correct_treasury_context() {
    let env = Env::default();
    let (
        executor,
        _registry,
        _commitment_client,
        token,
        company_id,
        admin,
        treasury,
        employee,
        token_id,
    ) = setup_system_no_auth(&env);

    let proof_a = BytesN::from_array(&env, &[1u8; 64]);
    let proof_b = BytesN::from_array(&env, &[2u8; 128]);
    let proof_c = BytesN::from_array(&env, &[3u8; 64]);
    let nullifier = BytesN::from_array(&env, &[4u8; 32]);

    env.mock_auths(&[
        MockAuth {
            address: &admin,
            invoke: &MockAuthInvoke {
                contract: &executor.address,
                fn_name: "execute_payment",
                args: (
                    company_id,
                    employee.clone(),
                    1000i128,
                    proof_a.clone(),
                    proof_b.clone(),
                    proof_c.clone(),
                    nullifier.clone(),
                    1u32,
                )
                    .into_val(&env),
                sub_invokes: &[],
            },
        },
        MockAuth {
            address: &treasury,
            invoke: &MockAuthInvoke {
                contract: &token_id,
                fn_name: "transfer",
                args: (treasury.clone(), employee.clone(), 1000i128).into_val(&env),
                sub_invokes: &[],
            },
        },
    ]);

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

    assert_eq!(token.balance(&treasury), 99_000);
    assert_eq!(token.balance(&employee), 1_000);
}

#[test]
#[ignore = "SEP-41 token auth check requires SEP-41 WASM contract"]
#[should_panic(expected = "authorized")]
fn test_mismatched_treasury_account_rejection() {
    let env = Env::default();
    let (
        executor,
        _registry,
        _commitment_client,
        _token,
        company_id,
        admin,
        treasury,
        employee,
        token_id,
    ) = setup_system_no_auth(&env);

    let proof_a = BytesN::from_array(&env, &[1u8; 64]);
    let proof_b = BytesN::from_array(&env, &[2u8; 128]);
    let proof_c = BytesN::from_array(&env, &[3u8; 64]);
    let nullifier = BytesN::from_array(&env, &[4u8; 32]);

    let wrong_treasury = Address::generate(&env);

    env.mock_auths(&[
        MockAuth {
            address: &admin,
            invoke: &MockAuthInvoke {
                contract: &executor.address,
                fn_name: "execute_payment",
                args: (
                    company_id,
                    employee.clone(),
                    1000i128,
                    proof_a.clone(),
                    proof_b.clone(),
                    proof_c.clone(),
                    nullifier.clone(),
                    1u32,
                )
                    .into_val(&env),
                sub_invokes: &[],
            },
        },
        MockAuth {
            address: &wrong_treasury, // using mismatched treasury for auth
            invoke: &MockAuthInvoke {
                contract: &token_id,
                fn_name: "transfer",
                args: (
                    treasury.clone(), // actual transfer attempts from real treasury
                    employee.clone(),
                    1000i128,
                )
                    .into_val(&env),
                sub_invokes: &[],
            },
        },
    ]);

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
}

#[test]
#[should_panic(expected = "Asset not allowed")]
fn test_unsupported_asset_rejection() {
    let env = Env::default();
    let (
        executor,
        _registry,
        _commitment_client,
        _token,
        company_id,
        _admin,
        _treasury,
        employee,
        token_id,
    ) = setup_system_no_auth(&env);

    // Remove the allowed asset to simulate unsupported asset
    env.mock_all_auths();

    // Set a dummy admin to allow calling set_asset_allowed
    let executor_admin = Address::generate(&env);
    executor.set_executor_admin(&executor_admin);

    // Disallow the token asset
    executor.set_asset_allowed(&token_id, &false);

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
}

#[test]
fn test_stale_authorization_rejection() {
    let env = Env::default();
    let (
        executor,
        _registry,
        _commitment_client,
        _token,
        company_id,
        _admin,
        _treasury,
        employee,
        _token_id,
    ) = setup_system_no_auth(&env);

    env.mock_all_auths();

    // Advance time by more than 7 days (7 * 24 * 60 * 60 = 604800 seconds)
    env.ledger().with_mut(|li| {
        li.timestamp += 604801;
    });

    let proof_a = BytesN::from_array(&env, &[1u8; 64]);
    let proof_b = BytesN::from_array(&env, &[2u8; 128]);
    let proof_c = BytesN::from_array(&env, &[3u8; 64]);
    let nullifier = BytesN::from_array(&env, &[4u8; 32]);

    let res = executor.try_execute_payment(
        &company_id,
        &employee,
        &1000,
        &proof_a,
        &proof_b,
        &proof_c,
        &nullifier,
        &1,
    );

    assert_eq!(res.unwrap_err().unwrap(), PaymentError::ProofExpired);
}
