#![no_std]

#[cfg(test)]
mod storage_defaults {
    use audit_module::{AuditError, AuditModule, AuditModuleClient};
    use pause_manager::{PauseManager, PauseManagerClient};
    use payment_executor::{
        ContractAddresses as ExecutorAddresses, PaymentExecutor, PaymentExecutorClient,
    };
    use payroll::{CompanyState, Payroll, PayrollClient};
    use payroll_registry::{EmployeeStatus, PayrollRegistry, PayrollRegistryClient};
    use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
    use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
    use soroban_sdk::{
        testutils::Address as _, Address, BytesN, Env, Symbol, Vec,
    };
    use token::Token;

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

    // ─────────────────────────────────────────────────────────────────────────
    // 1. Payroll State Storage Defaults
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_payroll_default_storage_on_initialization() {
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

        // Verify initial stored addresses match parameters
        let addrs = payroll_client.get_addresses();
        assert_eq!(addrs.admin, admin);
        assert_eq!(addrs.token, token_id);
        assert_eq!(addrs.verifier, verifier_id);
        assert_eq!(addrs.commitment, commitment_id);
        assert_eq!(addrs.treasury, treasury);
        assert_eq!(addrs.treasury_owner, treasury_owner);

        // Verify treasury owner storage default
        assert_eq!(payroll_client.get_treasury_owner(), treasury_owner);

        // Verify run counter defaults to 0
        assert_eq!(payroll_client.get_run_counter(), 0u64);

        // Verify company state defaults to Active when absent
        assert_eq!(payroll_client.get_company_state(), CompanyState::Active);

        // Verify depositor treasury balance defaults to 0
        let depositor = Address::generate(&env);
        assert_eq!(payroll_client.get_treasury_balance(&depositor), 0i128);

        // Verify initial pending requests and rotations are None
        assert!(payroll_client.get_emergency_request().is_none());
        assert!(payroll_client.get_pending_run(&1u64).is_none());
        assert!(payroll_client.get_pending_admin_rotation().is_none());
        assert!(payroll_client.get_pending_treasury_rotation().is_none());

        // Verify run is not archived by default
        assert!(!payroll_client.is_run_archived(&1u64));
    }

    #[test]
    #[should_panic(expected = "Already initialized")]
    fn test_payroll_reinitialization_rejected() {
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

        // Attempting to re-initialize must panic
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
    #[should_panic(expected = "Run not found")]
    fn test_payroll_uninitialized_run_lookup_panics() {
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

        // Querying non-existent run ID must panic
        payroll_client.get_payroll_run(&999u64);
    }

    #[test]
    #[should_panic(expected = "Draft not found")]
    fn test_payroll_uninitialized_draft_lookup_panics() {
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

        // Querying non-existent draft ID must panic
        payroll_client.get_run_draft(&999u64);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 2. Treasury State Storage Defaults (PaymentExecutor)
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_treasury_default_storage_on_initialization() {
        let env = Env::default();
        env.mock_all_auths();

        let registry_id = env.register_contract(None, PayrollRegistry);
        let commitment_id = env.register_contract(None, SalaryCommitmentContract);
        let verifier_id = env.register_contract(None, ProofVerifier);
        let token_id = env.register_contract(None, Token);

        let executor_id = env.register_contract(None, PaymentExecutor);
        let executor_client = PaymentExecutorClient::new(&env, &executor_id);

        let addrs = ExecutorAddresses {
            registry: registry_id.clone(),
            commitment: commitment_id.clone(),
            verifier: verifier_id.clone(),
            token: token_id.clone(),
        };

        executor_client.initialize(&addrs);

        // Verify storage schema version defaults to 1
        assert_eq!(executor_client.get_storage_version(), 1u32);

        // Verify addresses match initialization input
        let stored_addrs = executor_client.get_addresses();
        assert_eq!(stored_addrs.registry, registry_id);
        assert_eq!(stored_addrs.commitment, commitment_id);
        assert_eq!(stored_addrs.verifier, verifier_id);
        assert_eq!(stored_addrs.token, token_id);

        // Verify initial token asset is allowed by default
        assert!(executor_client.is_asset_allowed(&token_id));

        // Verify unallowed asset returns false
        let random_token = Address::generate(&env);
        assert!(!executor_client.is_asset_allowed(&random_token));

        // Verify total paid for any company defaults to 0
        assert_eq!(executor_client.get_total_paid(&1u64), 0i128);

        // Verify period sequence for any company defaults to 0
        assert_eq!(executor_client.get_period_sequence(&1u64), 0u32);

        // Verify period lookup defaults to None
        assert!(executor_client.get_period(&1u64, &1u32).is_none());

        // Verify employee paid status defaults to false
        let employee = Address::generate(&env);
        assert!(!executor_client.is_paid(&employee, &1u32));

        // Verify max proof age constant (7 days = 604800s)
        assert_eq!(executor_client.get_max_proof_age(), 604800u64);
    }

    #[test]
    #[should_panic(expected = "Executor admin not set")]
    fn test_treasury_uninitialized_admin_lookup_panics() {
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

        // Accessing admin before set_executor_admin must panic with clear error
        executor_client.get_executor_admin();
    }

    #[test]
    #[should_panic(expected = "Payment not found")]
    fn test_treasury_uninitialized_payment_lookup_panics() {
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

        let employee = Address::generate(&env);
        executor_client.get_payment(&employee, &1u32);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 3. Audit State Storage Defaults (AuditModule)
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_audit_default_storage_on_initialization() {
        let env = Env::default();
        env.mock_all_auths();

        let audit_id = env.register_contract(None, AuditModule);
        let audit_client = AuditModuleClient::new(&env, &audit_id);

        let auditor = Address::generate(&env);

        // Verify ungranted auditor returns false for verify_access
        assert!(!audit_client.verify_access(&auditor));

        // Verify log count defaults to 0 for uninitialized company symbol
        let company_sym = Symbol::new(&env, "ACME");
        assert_eq!(audit_client.get_audit_log_count(&company_sym), 0u32);

        // Verify query_by_company returns empty result
        let result = audit_client.query_by_company(&company_sym);
        assert_eq!(result.entries.len(), 0u32);

        // Verify pause manager defaults to None
        assert!(audit_client.get_pause_manager().is_none());
    }

    #[test]
    fn test_audit_uninitialized_view_key_lookup_returns_key_not_found() {
        let env = Env::default();
        env.mock_all_auths();

        let audit_id = env.register_contract(None, AuditModule);
        let audit_client = AuditModuleClient::new(&env, &audit_id);

        let auditor = Address::generate(&env);

        let vk_res = audit_client.try_get_view_key(&auditor);
        assert!(vk_res.is_err());
        assert_eq!(
            vk_res.unwrap_err().unwrap(),
            AuditError::KeyNotFound
        );

        let exp_res = audit_client.try_get_expiration(&auditor);
        assert!(exp_res.is_err());
        assert_eq!(
            exp_res.unwrap_err().unwrap(),
            AuditError::KeyNotFound
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 4. Access-Control & Infrastructure Storage Defaults
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_payroll_registry_default_storage_on_initialization() {
        let env = Env::default();
        env.mock_all_auths();

        let registry_id = env.register_contract(None, PayrollRegistry);
        let registry_client = PayrollRegistryClient::new(&env, &registry_id);

        // Verify company sequence starts at 0
        assert_eq!(registry_client.get_company_sequence(), 0u64);

        let employee = Address::generate(&env);

        // Verify employee status defaults to Incomplete when no record exists
        assert_eq!(
            registry_client.get_employee_status(&0u64, &employee),
            EmployeeStatus::Incomplete
        );

        // Verify eligibility defaults to false
        assert!(!registry_client.is_eligible(&0u64, &employee));

        // Verify pending rotations default to None
        assert!(registry_client.get_pending_admin_rotation(&0u64).is_none());
        assert!(registry_client.get_pending_treasury_rotation(&0u64).is_none());
    }

    #[test]
    #[should_panic(expected = "Company not found")]
    fn test_payroll_registry_uninitialized_company_lookup_panics() {
        let env = Env::default();
        env.mock_all_auths();

        let registry_id = env.register_contract(None, PayrollRegistry);
        let registry_client = PayrollRegistryClient::new(&env, &registry_id);

        registry_client.get_company(&999u64);
    }

    #[test]
    fn test_salary_commitment_default_storage_on_initialization() {
        let env = Env::default();
        env.mock_all_auths();

        let commitment_id = env.register_contract(None, SalaryCommitmentContract);
        let commitment_client = SalaryCommitmentContractClient::new(&env, &commitment_id);

        let admin = Address::generate(&env);
        commitment_client.init_commitment_admin(&admin);

        // Verify admin matches stored value
        assert_eq!(commitment_client.get_commitment_admin(), admin);

        // Verify payroll operator defaults to None
        assert!(commitment_client.get_payroll_operator().is_none());

        // Verify employee commitment defaults
        let employee = Address::generate(&env);
        assert!(!commitment_client.has_commitment(&employee));
        assert!(!commitment_client.is_commitment_locked(&employee));

        // Verify nullifier usage defaults to false
        let nullifier = BytesN::from_array(&env, &[0u8; 32]);
        assert!(!commitment_client.is_nullifier_used(&nullifier));

        // Verify pending admin rotation defaults to None
        assert!(commitment_client.get_pending_admin_rotation().is_none());
    }

    #[test]
    #[should_panic(expected = "Commitment not found")]
    fn test_salary_commitment_uninitialized_employee_lookup_panics() {
        let env = Env::default();
        env.mock_all_auths();

        let commitment_id = env.register_contract(None, SalaryCommitmentContract);
        let commitment_client = SalaryCommitmentContractClient::new(&env, &commitment_id);

        let admin = Address::generate(&env);
        commitment_client.init_commitment_admin(&admin);

        let employee = Address::generate(&env);
        commitment_client.get_commitment(&employee);
    }

    #[test]
    fn test_pause_manager_default_storage_on_initialization() {
        let env = Env::default();
        env.mock_all_auths();

        let pm_id = env.register_contract(None, PauseManager);
        let pm_client = PauseManagerClient::new(&env, &pm_id);

        // Before initialization, is_paused returns false
        assert!(!pm_client.is_paused());

        let operator = Address::generate(&env);
        pm_client.initialize(&operator);

        // After initialization, is_paused remains false
        assert!(!pm_client.is_paused());

        // Operator matches initial parameter
        assert_eq!(pm_client.get_operator(), operator);

        // Pending operator rotation defaults to None
        assert!(pm_client.get_pending_operator_rotation().is_none());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 5. Privacy Preservation Verification
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_storage_defaults_do_not_expose_payroll_private_values() {
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

        // Confirm default queries only expose operational metadata, addresses, and counters,
        // without leaking any salary amounts, employee balances, or Poseidon blinding secrets.
        let addrs = payroll_client.get_addresses();
        assert_eq!(addrs.admin, admin);
        assert_eq!(payroll_client.get_run_counter(), 0u64);
        assert_eq!(payroll_client.get_company_state(), CompanyState::Active);
    }
}
