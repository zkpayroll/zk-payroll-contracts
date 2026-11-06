use ::token::{Token, TokenClient};
use payment_executor::{ContractAddresses, PaymentExecutor, PaymentExecutorClient};
use payroll_registry::{PayrollRegistry, PayrollRegistryClient};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::SalaryCommitmentContract;
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

fn setup_test_context<'a>(
    env: &'a Env,
) -> (
    PaymentExecutorClient<'a>,
    PayrollRegistryClient<'a>,
    u64,
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
    let _token = TokenClient::new(env, &token_id);

    let addresses = ContractAddresses {
        registry: registry_id.clone(),
        commitment: commitment_id.clone(),
        verifier: verifier_id.clone(),
        token: token_id.clone(),
    };

    env.mock_all_auths();

    executor.initialize(&addresses);
    verifier.init_verifier_admin(&Address::generate(env));
    verifier.initialize_verifier(&mock_vk(env));

    let commitment_admin = Address::generate(env);
    commitment_client.init_commitment_admin(&commitment_admin);
    commitment_client.set_payroll_operator(&executor_id);

    let admin = Address::generate(env);
    let treasury = Address::generate(env);

    let company_id = registry.register_company(&admin, &treasury);

    (executor, registry, company_id, admin, treasury)
}

#[test]
fn test_check_payout_authorization_success() {
    let env = Env::default();
    let (executor, _registry, company_id, admin, _treasury) = setup_test_context(&env);

    // Current registry owner/company admin must return true
    let is_authorized = executor.check_payout_authorization(&company_id, &admin);
    assert!(is_authorized, "Current registry owner must be authorized for payouts");
}

#[test]
fn test_check_payout_authorization_rejected_for_non_admin() {
    let env = Env::default();
    let (executor, _registry, company_id, _admin, _treasury) = setup_test_context(&env);

    let non_admin = Address::generate(&env);

    // Any caller other than the registered company admin must return false
    let is_authorized = executor.check_payout_authorization(&company_id, &non_admin);
    assert!(!is_authorized, "Non-admin caller must not be authorized");
}

#[test]
fn test_check_payout_authorization_rejected_for_revoked_admin() {
    let env = Env::default();
    let (executor, registry, company_id, admin, _treasury) = setup_test_context(&env);

    // Revoke the company admin in the registry
    registry.revoke_company_admin(&company_id, &admin);

    // Revoked admin must be rejected
    let is_authorized = executor.check_payout_authorization(&company_id, &admin);
    assert!(!is_authorized, "Revoked company admin must not be authorized for payouts");
}

#[test]
fn test_check_payout_authorization_boundary_unregistered_company() {
    let env = Env::default();
    let (executor, _registry, _company_id, admin, _treasury) = setup_test_context(&env);

    // Boundary case: company_id that exceeds registered sequence
    let is_auth_nonexistent = executor.check_payout_authorization(&9999u64, &admin);
    assert!(!is_auth_nonexistent, "Non-existent company_id must be rejected");

    let is_auth_far_bound = executor.check_payout_authorization(&u64::MAX, &admin);
    assert!(!is_auth_far_bound, "u64::MAX company_id must be rejected");
}

#[test]
fn test_check_payout_authorization_after_admin_rotation() {
    let env = Env::default();
    let (executor, registry, company_id, old_admin, _treasury) = setup_test_context(&env);

    let new_admin = Address::generate(&env);

    // Two-step admin rotation: propose and accept
    registry.propose_admin_rotation(&company_id, &old_admin, &new_admin);
    registry.accept_admin_rotation(&company_id, &new_admin);

    // Old admin should no longer be authorized
    let is_old_auth = executor.check_payout_authorization(&company_id, &old_admin);
    assert!(!is_old_auth, "Former admin must not be authorized after rotation");

    // New active registry owner must now be authorized
    let is_new_auth = executor.check_payout_authorization(&company_id, &new_admin);
    assert!(is_new_auth, "New registry owner must be authorized for payouts");
}
