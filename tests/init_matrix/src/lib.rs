#![cfg(test)]

use pause_manager::{PauseManager, PauseManagerClient};
use payment_executor::{
    ContractAddresses as ExecutorAddresses, PaymentExecutor, PaymentExecutorClient,
};
use payroll::{
    CompanyState, ContractAddresses as PayrollAddresses, Payroll, PayrollClient,
};
use payroll_registry::{PayrollRegistry, PayrollRegistryClient};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
use soroban_sdk::{
    testutils::{Address as _, Ledger},
    Address, BytesN, Env, String, Vec,
};
use token::{Token, TokenClient};

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

// ─────────────────────────────────────────────────────────────────────────────
// Payroll initialization smoke matrix
// ─────────────────────────────────────────────────────────────────────────────

mod payroll_init {
    use super::*;

    #[test]
    fn test_minimal_initialization_succeeds() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let treasury_owner = Address::generate(&env);
        let token_id = env.register_contract(None, Token);
        let verifier_id = env.register_contract(None, ProofVerifier);
        let verifier_client = ProofVerifierClient::new(&env, &verifier_id);
        verifier_client.init_verifier_admin(&admin);
        verifier_client.initialize_verifier(&mock_vk(&env));
        let commitment_id = env.register_contract(None, SalaryCommitmentContract);
        let commitment_client = SalaryCommitmentContractClient::new(&env, &commitment_id);
        commitment_client.init_commitment_admin(&admin);

        let payroll_id = env.register_contract(None, Payroll);
        let payroll_client = PayrollClient::new(&env, &payroll_id);

        payroll_client.initialize(
            &admin,
            &token_id,
            &verifier_id,
            &commitment_id,
            &treasury,
            &treasury_owner,
        );

        let addrs = payroll_client.get_addresses();
        assert_eq!(addrs.admin, admin);
        assert_eq!(addrs.token, token_id);
        assert_eq!(addrs.verifier, verifier_id);
        assert_eq!(addrs.commitment, commitment_id);
        assert_eq!(addrs.treasury, treasury);
        assert_eq!(addrs.treasury_owner, treasury_owner);
    }

    #[test]
    fn test_full_initialization_creates_expected_defaults() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let treasury_owner = Address::generate(&env);
        let token_id = env.register_contract(None, Token);
        let verifier_id = env.register_contract(None, ProofVerifier);
        let verifier_client = ProofVerifierClient::new(&env, &verifier_id);
        verifier_client.init_verifier_admin(&admin);
        verifier_client.initialize_verifier(&mock_vk(&env));
        let commitment_id = env.register_contract(None, SalaryCommitmentContract);
        let commitment_client = SalaryCommitmentContractClient::new(&env, &commitment_id);
        commitment_client.init_commitment_admin(&admin);

        let payroll_id = env.register_contract(None, Payroll);
        let payroll_client = PayrollClient::new(&env, &payroll_id);

        payroll_client.initialize(
            &admin,
            &token_id,
            &verifier_id,
            &commitment_id,
            &treasury,
            &treasury_owner,
        );

        assert_eq!(payroll_client.get_run_counter(), 0u64);
        assert_eq!(payroll_client.get_company_state(), CompanyState::Active);
        assert_eq!(payroll_client.get_treasury_owner(), treasury_owner);
        assert_eq!(payroll_client.get_treasury_balance(&admin), 0i128);

        let version = payroll_client.get_storage_version().expect("storage version must be set");
        assert_eq!(version.version, 1);
        assert!(version.migration_complete);

        assert!(payroll_client.get_emergency_request().is_none());
        assert!(payroll_client.get_pending_admin_rotation().is_none());
        assert!(payroll_client.get_pending_treasury_rotation().is_none());
    }

    #[test]
    #[should_panic(expected = "Already initialized")]
    fn test_repeated_initialization_fails() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let treasury_owner = Address::generate(&env);
        let token_id = env.register_contract(None, Token);
        let verifier_id = env.register_contract(None, ProofVerifier);
        let commitment_id = env.register_contract(None, SalaryCommitmentContract);

        let payroll_id = env.register_contract(None, Payroll);
        let payroll_client = PayrollClient::new(&env, &payroll_id);

        payroll_client.initialize(
            &admin,
            &token_id,
            &verifier_id,
            &commitment_id,
            &treasury,
            &treasury_owner,
        );
        payroll_client.initialize(
            &admin,
            &token_id,
            &verifier_id,
            &commitment_id,
            &treasury,
            &treasury_owner,
        );
    }

    #[test]
    fn test_storage_version_and_roles_always_set() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let treasury_owner = Address::generate(&env);
        let token_id = env.register_contract(None, Token);
        let verifier_id = env.register_contract(None, ProofVerifier);
        let verifier_client = ProofVerifierClient::new(&env, &verifier_id);
        verifier_client.init_verifier_admin(&admin);
        verifier_client.initialize_verifier(&mock_vk(&env));
        let commitment_id = env.register_contract(None, SalaryCommitmentContract);
        let commitment_client = SalaryCommitmentContractClient::new(&env, &commitment_id);
        commitment_client.init_commitment_admin(&admin);

        let payroll_id = env.register_contract(None, Payroll);
        let payroll_client = PayrollClient::new(&env, &payroll_id);

        payroll_client.initialize(
            &admin,
            &token_id,
            &verifier_id,
            &commitment_id,
            &treasury,
            &treasury_owner,
        );

        let version = payroll_client.get_storage_version().expect("storage version must be set");
        assert_eq!(version.version, 1);
        assert!(version.migration_complete);
        assert_eq!(version.version_description, String::from_str(&env, "Initial version"));

        let addrs = payroll_client.get_addresses();
        assert_eq!(addrs.admin, admin);
        assert_eq!(addrs.treasury_owner, treasury_owner);
    }

    #[test]
    fn test_different_admin_and_treasury_owner_profiles() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let treasury_owner = Address::generate(&env);
        let token_id = env.register_contract(None, Token);
        let verifier_id = env.register_contract(None, ProofVerifier);
        let verifier_client = ProofVerifierClient::new(&env, &verifier_id);
        verifier_client.init_verifier_admin(&admin);
        verifier_client.initialize_verifier(&mock_vk(&env));
        let commitment_id = env.register_contract(None, SalaryCommitmentContract);
        let commitment_client = SalaryCommitmentContractClient::new(&env, &commitment_id);
        commitment_client.init_commitment_admin(&admin);

        let payroll_id = env.register_contract(None, Payroll);
        let payroll_client = PayrollClient::new(&env, &payroll_id);

        payroll_client.initialize(
            &admin,
            &token_id,
            &verifier_id,
            &commitment_id,
            &treasury,
            &treasury_owner,
        );

        let addrs = payroll_client.get_addresses();
        assert_ne!(addrs.admin, addrs.treasury_owner);
    }

    #[test]
    fn test_allowed_asset_set_to_token_on_init() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let treasury_owner = Address::generate(&env);
        let token_id = env.register_contract(None, Token);
        let verifier_id = env.register_contract(None, ProofVerifier);
        let verifier_client = ProofVerifierClient::new(&env, &verifier_id);
        verifier_client.init_verifier_admin(&admin);
        verifier_client.initialize_verifier(&mock_vk(&env));
        let commitment_id = env.register_contract(None, SalaryCommitmentContract);
        let commitment_client = SalaryCommitmentContractClient::new(&env, &commitment_id);
        commitment_client.init_commitment_admin(&admin);

        let payroll_id = env.register_contract(None, Payroll);
        let payroll_client = PayrollClient::new(&env, &payroll_id);

        payroll_client.initialize(
            &admin,
            &token_id,
            &verifier_id,
            &commitment_id,
            &treasury,
            &treasury_owner,
        );

        assert!(payroll_client.is_asset_allowed(&token_id));
    }

    #[test]
    fn test_uninitialized_payroll_asset_allowed_defaults_false() {
        let env = Env::default();
        env.mock_all_auths();

        let token_id = env.register_contract(None, Token);
        let payroll_id = env.register_contract(None, Payroll);
        let payroll_client = PayrollClient::new(&env, &payroll_id);

        assert!(!payroll_client.is_asset_allowed(&token_id));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PaymentExecutor initialization smoke matrix
// ─────────────────────────────────────────────────────────────────────────────

mod executor_init {
    use super::*;

    #[test]
    fn test_minimal_initialization_succeeds() {
        let env = Env::default();
        env.mock_all_auths();

        let registry_id = env.register_contract(None, PayrollRegistry);
        let commitment_id = env.register_contract(None, SalaryCommitmentContract);
        let verifier_id = env.register_contract(None, ProofVerifier);
        let token_id = env.register_contract(None, Token);

        let executor_id = env.register_contract(None, PaymentExecutor);
        let executor_client = PaymentExecutorClient::new(&env, &executor_id);

        let addrs = ExecutorAddresses {
            registry: registry_id,
            commitment: commitment_id,
            verifier: verifier_id,
            token: token_id.clone(),
        };

        executor_client.initialize(&addrs);

        let stored = executor_client.get_addresses();
        assert_eq!(stored.registry, addrs.registry);
        assert_eq!(stored.commitment, addrs.commitment);
        assert_eq!(stored.verifier, addrs.verifier);
        assert_eq!(stored.token, addrs.token);
    }

    #[test]
    fn test_full_initialization_creates_expected_defaults() {
        let env = Env::default();
        env.mock_all_auths();

        let registry_id = env.register_contract(None, PayrollRegistry);
        let commitment_id = env.register_contract(None, SalaryCommitmentContract);
        let verifier_id = env.register_contract(None, ProofVerifier);
        let token_id = env.register_contract(None, Token);

        let executor_id = env.register_contract(None, PaymentExecutor);
        let executor_client = PaymentExecutorClient::new(&env, &executor_id);

        let addrs = ExecutorAddresses {
            registry: registry_id,
            commitment: commitment_id,
            verifier: verifier_id,
            token: token_id.clone(),
        };

        executor_client.initialize(&addrs);

        assert_eq!(executor_client.get_storage_version(), 1u32);
        assert!(executor_client.is_asset_allowed(&token_id));

        let random_token = Address::generate(&env);
        assert!(!executor_client.is_asset_allowed(&random_token));

        assert_eq!(executor_client.get_total_paid(&1u64), 0i128);
        assert_eq!(executor_client.get_period_sequence(&1u64), 0u32);
        assert!(executor_client.get_period(&1u64, &1u32).is_none());
    }

    #[test]
    #[should_panic(expected = "Already initialized")]
    fn test_repeated_initialization_fails() {
        let env = Env::default();
        env.mock_all_auths();

        let registry_id = env.register_contract(None, PayrollRegistry);
        let commitment_id = env.register_contract(None, SalaryCommitmentContract);
        let verifier_id = env.register_contract(None, ProofVerifier);
        let token_id = env.register_contract(None, Token);

        let executor_id = env.register_contract(None, PaymentExecutor);
        let executor_client = PaymentExecutorClient::new(&env, &executor_id);

        let addrs = ExecutorAddresses {
            registry: registry_id,
            commitment: commitment_id,
            verifier: verifier_id,
            token: token_id.clone(),
        };

        executor_client.initialize(&addrs);
        executor_client.initialize(&addrs);
    }

    #[test]
    fn test_storage_version_created_after_init() {
        let env = Env::default();
        env.mock_all_auths();

        let registry_id = env.register_contract(None, PayrollRegistry);
        let commitment_id = env.register_contract(None, SalaryCommitmentContract);
        let verifier_id = env.register_contract(None, ProofVerifier);
        let token_id = env.register_contract(None, Token);

        let executor_id = env.register_contract(None, PaymentExecutor);
        let executor_client = PaymentExecutorClient::new(&env, &executor_id);

        let addrs = ExecutorAddresses {
            registry: registry_id,
            commitment: commitment_id,
            verifier: verifier_id,
            token: token_id.clone(),
        };

        executor_client.initialize(&addrs);

        let version = executor_client.get_storage_version();
        assert_eq!(version, 1u32);
    }

    #[test]
    fn test_different_token_assets_profile() {
        let env = Env::default();
        env.mock_all_auths();

        let registry_id = env.register_contract(None, PayrollRegistry);
        let commitment_id = env.register_contract(None, SalaryCommitmentContract);
        let verifier_id = env.register_contract(None, ProofVerifier);
        let token_a = env.register_contract(None, Token);
        let token_b = env.register_contract(None, Token);

        let executor_id = env.register_contract(None, PaymentExecutor);
        let executor_client = PaymentExecutorClient::new(&env, &executor_id);

        let addrs = ExecutorAddresses {
            registry: registry_id,
            commitment: commitment_id,
            verifier: verifier_id,
            token: token_a.clone(),
        };

        executor_client.initialize(&addrs);

        assert!(executor_client.is_asset_allowed(&token_a));
        assert!(!executor_client.is_asset_allowed(&token_b));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PauseManager initialization smoke matrix
// ─────────────────────────────────────────────────────────────────────────────

mod pause_manager_init {
    use super::*;

    #[test]
    fn test_minimal_initialization_succeeds() {
        let env = Env::default();
        env.mock_all_auths();

        let pm_id = env.register_contract(None, PauseManager);
        let pm_client = PauseManagerClient::new(&env, &pm_id);
        let operator = Address::generate(&env);

        pm_client.initialize(&operator);

        assert_eq!(pm_client.get_operator(), operator);
        assert!(!pm_client.is_paused());
    }

    #[test]
    #[should_panic(expected = "Already initialized")]
    fn test_repeated_initialization_fails() {
        let env = Env::default();
        env.mock_all_auths();

        let pm_id = env.register_contract(None, PauseManager);
        let pm_client = PauseManagerClient::new(&env, &pm_id);
        let operator = Address::generate(&env);

        pm_client.initialize(&operator);
        pm_client.initialize(&operator);
    }

    #[test]
    fn test_default_policy_is_unpaused() {
        let env = Env::default();
        env.mock_all_auths();

        let pm_id = env.register_contract(None, PauseManager);
        let pm_client = PauseManagerClient::new(&env, &pm_id);
        let operator = Address::generate(&env);

        pm_client.initialize(&operator);

        assert!(!pm_client.is_paused());
        assert!(pm_client.get_pending_operator_rotation().is_none());
    }

    #[test]
    fn test_different_operator_profiles() {
        let env = Env::default();
        env.mock_all_auths();

        let pm_id = env.register_contract(None, PauseManager);
        let pm_client = PauseManagerClient::new(&env, &pm_id);
        let operator_a = Address::generate(&env);
        let operator_b = Address::generate(&env);

        pm_client.initialize(&operator_a);
        assert_eq!(pm_client.get_operator(), operator_a);

        pm_client.propose_operator_rotation(&operator_a, &operator_b);
        pm_client.accept_operator_rotation(&operator_b);
        assert_eq!(pm_client.get_operator(), operator_b);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ProofVerifier initialization smoke matrix
// ─────────────────────────────────────────────────────────────────────────────

mod verifier_init {
    use super::*;

    #[test]
    fn test_minimal_admin_initialization_succeeds() {
        let env = Env::default();
        env.mock_all_auths();

        let verifier_id = env.register_contract(None, ProofVerifier);
        let verifier_client = ProofVerifierClient::new(&env, &verifier_id);
        let admin = Address::generate(&env);

        verifier_client.init_verifier_admin(&admin);

        assert_eq!(verifier_client.get_verifier_admin(), admin);
    }

    #[test]
    #[should_panic(expected = "Already initialized")]
    fn test_repeated_admin_init_fails() {
        let env = Env::default();
        env.mock_all_auths();

        let verifier_id = env.register_contract(None, ProofVerifier);
        let verifier_client = ProofVerifierClient::new(&env, &verifier_id);
        let admin = Address::generate(&env);

        verifier_client.init_verifier_admin(&admin);
        verifier_client.init_verifier_admin(&admin);
    }

    #[test]
    fn test_full_verifier_initialization() {
        let env = Env::default();
        env.mock_all_auths();

        let verifier_id = env.register_contract(None, ProofVerifier);
        let verifier_client = ProofVerifierClient::new(&env, &verifier_id);
        let admin = Address::generate(&env);

        verifier_client.init_verifier_admin(&admin);
        verifier_client.initialize_verifier(&mock_vk(&env));

        let vk = verifier_client.get_verification_key();
        assert_eq!(vk.alpha, BytesN::from_array(&env, &[0u8; 64]));
    }

    #[test]
    #[should_panic(expected = "Verifier already initialized")]
    fn test_repeated_vk_init_fails() {
        let env = Env::default();
        env.mock_all_auths();

        let verifier_id = env.register_contract(None, ProofVerifier);
        let verifier_client = ProofVerifierClient::new(&env, &verifier_id);
        let admin = Address::generate(&env);

        verifier_client.init_verifier_admin(&admin);
        verifier_client.initialize_verifier(&mock_vk(&env));
        verifier_client.initialize_verifier(&mock_vk(&env));
    }

    #[test]
    fn test_role_is_required_before_vk_setup() {
        let env = Env::default();
        env.mock_all_auths();

        let verifier_id = env.register_contract(None, ProofVerifier);
        let verifier_client = ProofVerifierClient::new(&env, &verifier_id);
        let admin = Address::generate(&env);

        verifier_client.init_verifier_admin(&admin);

        assert_eq!(verifier_client.get_verifier_admin(), admin);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SalaryCommitment initialization smoke matrix
// ─────────────────────────────────────────────────────────────────────────────

mod commitment_init {
    use super::*;

    #[test]
    fn test_minimal_initialization_succeeds() {
        let env = Env::default();
        env.mock_all_auths();

        let commitment_id = env.register_contract(None, SalaryCommitmentContract);
        let commitment_client = SalaryCommitmentContractClient::new(&env, &commitment_id);
        let admin = Address::generate(&env);

        commitment_client.init_commitment_admin(&admin);

        assert_eq!(commitment_client.get_commitment_admin(), admin);
        assert!(commitment_client.get_payroll_operator().is_none());
    }

    #[test]
    #[should_panic(expected = "Already initialized")]
    fn test_repeated_admin_init_fails() {
        let env = Env::default();
        env.mock_all_auths();

        let commitment_id = env.register_contract(None, SalaryCommitmentContract);
        let commitment_client = SalaryCommitmentContractClient::new(&env, &commitment_id);
        let admin = Address::generate(&env);

        commitment_client.init_commitment_admin(&admin);
        commitment_client.init_commitment_admin(&admin);
    }

    #[test]
    fn test_default_commitment_state_after_init() {
        let env = Env::default();
        env.mock_all_auths();

        let commitment_id = env.register_contract(None, SalaryCommitmentContract);
        let commitment_client = SalaryCommitmentContractClient::new(&env, &commitment_id);
        let admin = Address::generate(&env);
        let employee = Address::generate(&env);

        commitment_client.init_commitment_admin(&admin);

        assert_eq!(commitment_client.get_commitment_admin(), admin);
        assert!(!commitment_client.has_commitment(&employee));
        assert!(!commitment_client.is_commitment_locked(&employee));

        let nullifier = BytesN::from_array(&env, &[0u8; 32]);
        assert!(!commitment_client.is_nullifier_used(&nullifier));
        assert!(commitment_client.get_pending_admin_rotation().is_none());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Token initialization smoke matrix
// ─────────────────────────────────────────────────────────────────────────────

mod token_init {
    use super::*;

    #[test]
    fn test_minimal_token_initialization_accepts_params() {
        let env = Env::default();
        env.mock_all_auths();

        let token_id = env.register_contract(None, Token);
        let token_client = TokenClient::new(&env, &token_id);
        let admin = Address::generate(&env);

        token_client.initialize(
            &admin,
            &7,
            &String::from_str(&env, "TestToken"),
            &String::from_str(&env, "TST"),
        );

        assert_eq!(token_client.balance(&admin), 0i128);
    }

    #[test]
    fn test_different_token_denominations_profile() {
        let env = Env::default();
        env.mock_all_auths();

        let token_id = env.register_contract(None, Token);
        let token_client = TokenClient::new(&env, &token_id);
        let admin = Address::generate(&env);

        token_client.initialize(
            &admin,
            &18,
            &String::from_str(&env, "HighPrecision"),
            &String::from_str(&env, "HP"),
        );

        token_client.mint(&admin, &1_000);
        assert_eq!(token_client.balance(&admin), 1_000i128);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Cross-contract initialization sequence smoke test
// ─────────────────────────────────────────────────────────────────────────────

mod cross_contract_init {
    use super::*;

    #[test]
    fn test_full_system_initialization_sequence() {
        let env = Env::default();
        env.mock_all_auths();
        env.ledger().with_mut(|l| l.timestamp = 1000);

        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let treasury_owner = Address::generate(&env);
        let _employee = Address::generate(&env);

        // 1. Token
        let token_id = env.register_contract(None, Token);
        let token_client = TokenClient::new(&env, &token_id);
        token_client.initialize(
            &admin,
            &7,
            &String::from_str(&env, "USD"),
            &String::from_str(&env, "USDC"),
        );
        token_client.mint(&treasury, &1_000_000);

        // 2. PauseManager
        let pm_id = env.register_contract(None, PauseManager);
        let pm_client = PauseManagerClient::new(&env, &pm_id);
        pm_client.initialize(&admin);

        // 3. ProofVerifier
        let verifier_id = env.register_contract(None, ProofVerifier);
        let verifier_client = ProofVerifierClient::new(&env, &verifier_id);
        verifier_client.init_verifier_admin(&admin);
        verifier_client.initialize_verifier(&mock_vk(&env));

        // 4. SalaryCommitment
        let commitment_id = env.register_contract(None, SalaryCommitmentContract);
        let commitment_client = SalaryCommitmentContractClient::new(&env, &commitment_id);
        commitment_client.init_commitment_admin(&admin);

        // 5. PayrollRegistry
        let registry_id = env.register_contract(None, PayrollRegistry);
        let registry_client = PayrollRegistryClient::new(&env, &registry_id);
        let company_id = registry_client.register_company(&admin, &treasury);

        // 6. PaymentExecutor
        let executor_id = env.register_contract(None, PaymentExecutor);
        let executor_client = PaymentExecutorClient::new(&env, &executor_id);
        let executor_addrs = ExecutorAddresses {
            registry: registry_id,
            commitment: commitment_id.clone(),
            verifier: verifier_id.clone(),
            token: token_id.clone(),
        };
        executor_client.initialize(&executor_addrs);

        // 7. Payroll
        let payroll_id = env.register_contract(None, Payroll);
        let payroll_client = PayrollClient::new(&env, &payroll_id);
        let payroll_addrs = PayrollAddresses {
            admin: admin.clone(),
            token: token_id,
            verifier: verifier_id,
            commitment: commitment_id,
            treasury: treasury.clone(),
            treasury_owner: treasury_owner.clone(),
        };
        payroll_client.initialize(
            &payroll_addrs.admin,
            &payroll_addrs.token,
            &payroll_addrs.verifier,
            &payroll_addrs.commitment,
            &payroll_addrs.treasury,
            &payroll_addrs.treasury_owner,
        );

        // Assert all contracts initialized correctly
        assert_eq!(token_client.balance(&treasury), 1_000_000i128);
        assert_eq!(pm_client.get_operator(), admin);
        assert_eq!(verifier_client.get_verifier_admin(), admin);
        assert_eq!(commitment_client.get_commitment_admin(), admin);
        assert_eq!(registry_client.get_company(&company_id).admin, admin);
        assert_eq!(executor_client.get_storage_version(), 1);
        assert_eq!(payroll_client.get_run_counter(), 0);
        assert_eq!(payroll_client.get_company_state(), CompanyState::Active);
    }

    #[test]
    #[should_panic(expected = "Run not found")]
    fn test_payroll_uninitialized_run_lookup_panics_after_init() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let treasury_owner = Address::generate(&env);
        let token_id = env.register_contract(None, Token);
        let verifier_id = env.register_contract(None, ProofVerifier);
        let verifier_client = ProofVerifierClient::new(&env, &verifier_id);
        verifier_client.init_verifier_admin(&admin);
        verifier_client.initialize_verifier(&mock_vk(&env));
        let commitment_id = env.register_contract(None, SalaryCommitmentContract);
        let commitment_client = SalaryCommitmentContractClient::new(&env, &commitment_id);
        commitment_client.init_commitment_admin(&admin);

        let payroll_id = env.register_contract(None, Payroll);
        let payroll_client = PayrollClient::new(&env, &payroll_id);

        payroll_client.initialize(
            &admin,
            &token_id,
            &verifier_id,
            &commitment_id,
            &treasury,
            &treasury_owner,
        );

        payroll_client.get_payroll_run(&999u64);
    }

    #[test]
    #[should_panic(expected = "Draft not found")]
    fn test_payroll_uninitialized_draft_lookup_panics_after_init() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let treasury_owner = Address::generate(&env);
        let token_id = env.register_contract(None, Token);
        let verifier_id = env.register_contract(None, ProofVerifier);
        let verifier_client = ProofVerifierClient::new(&env, &verifier_id);
        verifier_client.init_verifier_admin(&admin);
        verifier_client.initialize_verifier(&mock_vk(&env));
        let commitment_id = env.register_contract(None, SalaryCommitmentContract);
        let commitment_client = SalaryCommitmentContractClient::new(&env, &commitment_id);
        commitment_client.init_commitment_admin(&admin);

        let payroll_id = env.register_contract(None, Payroll);
        let payroll_client = PayrollClient::new(&env, &payroll_id);

        payroll_client.initialize(
            &admin,
            &token_id,
            &verifier_id,
            &commitment_id,
            &treasury,
            &treasury_owner,
        );

        payroll_client.get_run_draft(&999u64);
    }

    #[test]
    #[should_panic(expected = "Executor admin not set")]
    fn test_executor_uninitialized_admin_lookup_panics_after_init() {
        let env = Env::default();
        env.mock_all_auths();

        let registry_id = env.register_contract(None, PayrollRegistry);
        let commitment_id = env.register_contract(None, SalaryCommitmentContract);
        let verifier_id = env.register_contract(None, ProofVerifier);
        let token_id = env.register_contract(None, Token);

        let executor_id = env.register_contract(None, PaymentExecutor);
        let executor_client = PaymentExecutorClient::new(&env, &executor_id);

        let addrs = ExecutorAddresses {
            registry: registry_id,
            commitment: commitment_id,
            verifier: verifier_id,
            token: token_id,
        };

        executor_client.initialize(&addrs);

        executor_client.get_executor_admin();
    }
}
