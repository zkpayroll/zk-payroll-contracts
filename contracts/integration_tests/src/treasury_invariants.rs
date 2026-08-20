#[cfg(test)]
mod treasury_invariants {
    use payroll::{Payroll, PayrollClient, ReconciliationStatus, PayrollRunState};
    use payroll_registry::{PayrollRegistry, PayrollRegistryClient};
    use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
    use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
    use soroban_sdk::{
        testutils::{Address as _},
        Address, BytesN, Env, Vec, Symbol
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

    fn mock_proof(env: &Env) -> BytesN<256> {
        BytesN::from_array(env, &[0u8; 256])
    }

    fn test_nonce(env: &Env, seed: u8) -> BytesN<32> {
        let mut arr = [0u8; 32];
        arr[0] = seed;
        BytesN::from_array(env, &arr)
    }

    struct TestContext<'a> {
        env: Env,
        admin: Address,
        treasury: Address,
        treasury_owner: Address,
        alice: Address,
        company_id: u64,
        token_client: TokenClient<'a>,
        registry_client: PayrollRegistryClient<'a>,
        commitment_client: SalaryCommitmentContractClient<'a>,
        payroll_client: PayrollClient<'a>,
    }

    fn setup() -> TestContext<'static> {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let treasury_owner = Address::generate(&env);
        let alice = Address::generate(&env);

        let verifier_id = env.register_contract(None, ProofVerifier);
        let verifier_client = ProofVerifierClient::new(&env, &verifier_id);
        verifier_client.init_verifier_admin(&admin);
        verifier_client.initialize_verifier(&mock_vk(&env));

        let commitment_id = env.register_contract(None, SalaryCommitmentContract);
        let commitment_client_init = SalaryCommitmentContractClient::new(&env, &commitment_id);
        commitment_client_init.init_commitment_admin(&admin);

        let token_id = env.register_contract(None, Token);

        let registry_id = env.register_contract(None, PayrollRegistry);
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

        let commitment_client = SalaryCommitmentContractClient::new(&env, &commitment_id);
        commitment_client.set_payroll_operator(&payroll_id);

        let token_client = TokenClient::new(&env, &token_id);
        let registry_client = PayrollRegistryClient::new(&env, &registry_id);

        let company_id = registry_client.register_company(&admin, &treasury);
        
        // Mint tokens to the treasury owner to use for deposits
        token_client.mint(&treasury_owner, &1_000_000);

        TestContext {
            env,
            admin,
            treasury,
            treasury_owner,
            alice,
            company_id,
            token_client,
            registry_client,
            commitment_client,
            payroll_client,
        }
    }

    fn onboard_alice(ctx: &TestContext) -> BytesN<32> {
        let env = &ctx.env;
        let mut blinding_bytes = [0u8; 32];
        blinding_bytes[31] = 123u8;
        let blinding_factor = BytesN::from_array(env, &blinding_bytes);
        let commitment = ctx.commitment_client.compute_commitment(&5000u64, &blinding_factor);
        
        ctx.commitment_client.store_commitment(&ctx.alice, &commitment);
        ctx.registry_client.add_employee(&ctx.company_id, &ctx.alice, &commitment);
        
        commitment
    }

    #[test]
    fn test_treasury_deposit_execute_settle_lifecycle() {
        let ctx = setup();
        onboard_alice(&ctx);
        let env = &ctx.env;
        
        let initial_treasury = ctx.token_client.balance(&ctx.treasury);
        assert_eq!(initial_treasury, 0);
        
        let deposit_amount = 10_000i128;
        
        // DEPOSIT
        ctx.payroll_client.deposit(
            &ctx.treasury_owner, 
            &deposit_amount, 
            &test_nonce(env, 1)
        );
        
        // Validate Deposit Accounting
        let treasury_balance_after_deposit = ctx.token_client.balance(&ctx.treasury);
        let recorded_balance = ctx.payroll_client.get_treasury_balance(&ctx.treasury_owner);
        assert_eq!(treasury_balance_after_deposit, deposit_amount);
        assert_eq!(recorded_balance, deposit_amount);
        
        // EXECUTE
        let payment_amount = 5_000i128;
        let mut proofs = Vec::new(env);
        proofs.push_back(mock_proof(env));
        let mut amounts = Vec::new(env);
        amounts.push_back(payment_amount);
        let mut employees = Vec::new(env);
        employees.push_back(ctx.alice.clone());

        let run_id = ctx.payroll_client.batch_process_payroll(
            &proofs,
            &amounts,
            &employees,
            &payment_amount,
            &test_nonce(env, 2),
            &None,
        );
        
        // Validate Execution Accounting
        let expected_treasury = deposit_amount - payment_amount;
        assert_eq!(ctx.token_client.balance(&ctx.treasury), expected_treasury);
        // get_treasury_balance (deposits track) is unchanged
        assert_eq!(ctx.payroll_client.get_treasury_balance(&ctx.treasury_owner), deposit_amount);
        assert_eq!(ctx.token_client.balance(&ctx.alice), payment_amount);
        
        // SETTLE
        ctx.payroll_client.update_reconciliation_status(
            &ctx.admin,
            &run_id,
            &ReconciliationStatus::Reconciled
        );
        
        // Validate Settlement Accounting
        assert_eq!(ctx.token_client.balance(&ctx.treasury), expected_treasury);
        assert_eq!(ctx.payroll_client.get_treasury_balance(&ctx.treasury_owner), deposit_amount);
        assert_eq!(ctx.payroll_client.get_payroll_run_state(&run_id), PayrollRunState::Completed);
    }

    #[test]
    fn test_treasury_deposit_cancel_lifecycle() {
        let ctx = setup();
        let env = &ctx.env;
        
        let deposit_amount = 20_000i128;
        
        // DEPOSIT
        ctx.payroll_client.deposit(
            &ctx.treasury_owner, 
            &deposit_amount, 
            &test_nonce(env, 10)
        );
        
        let treasury_balance_after_deposit = ctx.token_client.balance(&ctx.treasury);
        assert_eq!(treasury_balance_after_deposit, deposit_amount);
        
        // PREPARE RUN
        let payment_amount = 5_000i128;
        let mut proofs = Vec::new(env);
        proofs.push_back(mock_proof(env));
        let mut amounts = Vec::new(env);
        amounts.push_back(payment_amount);
        let mut employees = Vec::new(env);
        employees.push_back(ctx.alice.clone());

        let run_id = ctx.payroll_client.prepare_payroll_run(
            &proofs,
            &amounts,
            &employees,
            &payment_amount,
            &test_nonce(env, 11),
            &None,
        );
        
        // CANCEL RUN
        ctx.payroll_client.cancel_payroll_run(
            &ctx.admin,
            &run_id,
            &Symbol::new(env, "Error")
        );
        
        // Validate Cancellation Accounting
        assert_eq!(ctx.token_client.balance(&ctx.treasury), deposit_amount, "Cancellation must not incorrectly remove funds");
        assert_eq!(ctx.payroll_client.get_treasury_balance(&ctx.treasury_owner), deposit_amount);
    }

    #[test]
    fn test_failed_operations_do_not_unexpectedly_change_treasury_balance() {
        let ctx = setup();
        onboard_alice(&ctx);
        let env = &ctx.env;
        
        let deposit_amount = 15_000i128;
        ctx.payroll_client.deposit(
            &ctx.treasury_owner, 
            &deposit_amount, 
            &test_nonce(env, 20)
        );
        
        let initial_treasury = ctx.token_client.balance(&ctx.treasury);
        
        // Failed execution: amount mismatch
        let mut proofs = Vec::new(env);
        proofs.push_back(mock_proof(env));
        let mut amounts = Vec::new(env);
        amounts.push_back(5_000i128);
        let mut employees = Vec::new(env);
        employees.push_back(ctx.alice.clone());

        let res = ctx.payroll_client.try_batch_process_payroll(
            &proofs,
            &amounts,
            &employees,
            &10_000i128, // wrong expected total spend
            &test_nonce(env, 21),
            &None,
        );
        assert!(res.is_err());
        
        // Ensure balance is unchanged
        assert_eq!(ctx.token_client.balance(&ctx.treasury), initial_treasury);
        assert_eq!(ctx.payroll_client.get_treasury_balance(&ctx.treasury_owner), deposit_amount);
        
        // Failed deposit: zero amount
        let res_dep = ctx.payroll_client.try_deposit(
            &ctx.treasury_owner, 
            &0i128, 
            &test_nonce(env, 22)
        );
        assert!(res_dep.is_err());
        assert_eq!(ctx.token_client.balance(&ctx.treasury), initial_treasury);
        assert_eq!(ctx.payroll_client.get_treasury_balance(&ctx.treasury_owner), deposit_amount);
    }

    #[test]
    fn test_multiple_deposits_and_executions_preserve_accounting() {
        let ctx = setup();
        onboard_alice(&ctx);
        let env = &ctx.env;
        
        // MULTIPLE DEPOSITS
        let dep1 = 10_000i128;
        let dep2 = 5_000i128;
        ctx.payroll_client.deposit(&ctx.treasury_owner, &dep1, &test_nonce(env, 30));
        ctx.payroll_client.deposit(&ctx.treasury_owner, &dep2, &test_nonce(env, 31));
        
        let expected_total_deposits = dep1 + dep2;
        assert_eq!(ctx.payroll_client.get_treasury_balance(&ctx.treasury_owner), expected_total_deposits);
        assert_eq!(ctx.token_client.balance(&ctx.treasury), expected_total_deposits);
        
        // EXECUTION
        let payment1 = 3_000i128;
        let mut proofs = Vec::new(env);
        proofs.push_back(mock_proof(env));
        let mut amounts = Vec::new(env);
        amounts.push_back(payment1);
        let mut employees = Vec::new(env);
        employees.push_back(ctx.alice.clone());

        ctx.payroll_client.batch_process_payroll(
            &proofs,
            &amounts,
            &employees,
            &payment1,
            &test_nonce(env, 32),
            &None,
        );
        
        let expected_treasury = expected_total_deposits - payment1;
        assert_eq!(ctx.token_client.balance(&ctx.treasury), expected_treasury);
        // get_treasury_balance tracks deposits only
        assert_eq!(ctx.payroll_client.get_treasury_balance(&ctx.treasury_owner), expected_total_deposits);
    }
}
