/// Issue #485: Payroll run status query helper tests
///
/// Tests the concise status view of payroll runs for dashboards and client visibility
/// without exposing sensitive payroll data.

#[cfg(test)]
mod tests {
    use payroll::{
        Payroll, PayrollClient, PayrollRunState, PayrollRunStatusKind,
    };
    use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
    use salary_commitment::SalaryCommitmentContractClient;
    use soroban_sdk::{
        testutils::{Address as _, Ledger as _},
        Address, BytesN, Env, Vec,
    };
    use token::{Token, TokenClient};

    fn mock_vk(env: &Env) -> VerificationKey {
        VerificationKey {
            alpha: BytesN::from_array(env, &[0u8; 64]),
            beta: BytesN::from_array(env, &[128u8; 128]),
            gamma: BytesN::from_array(env, &[64u8; 128]),
            delta: BytesN::from_array(env, &[32u8; 128]),
            ic: Vec::from_array(
                env,
                [
                    BytesN::from_array(env, &[0u8; 64]),
                    BytesN::from_array(env, &[1u8; 64]),
                    BytesN::from_array(env, &[2u8; 64]),
                    BytesN::from_array(env, &[3u8; 64]),
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
        alice: Address,
        bob: Address,
        token_client: TokenClient<'a>,
        payroll_client: PayrollClient<'a>,
        commitment_client: SalaryCommitmentContractClient<'a>,
    }

    fn setup(env: &Env) -> TestContext {
        env.ledger().set_sequence_number(100);
        env.ledger().set_timestamp(1000);

        let token = Address::random(env);
        let admin = Address::random(env);
        let treasury = Address::random(env);
        let verifier = Address::random(env);
        let commitment_contract = Address::random(env);

        let token_client = TokenClient::new(env, &token);
        token_client.initialize(
            &Address::random(env),
            &9u32,
            &"USDC".into(),
            &"USD Coin".into(),
        );

        let payroll = Address::random(env);
        let payroll_client = PayrollClient::new(env, &payroll);

        let verifier_client = ProofVerifierClient::new(env, &verifier);
        verifier_client.initialize(&mock_vk(env));

        let commitment_client = SalaryCommitmentContractClient::new(env, &commitment_contract);
        commitment_client.initialize(&Address::random(env));

        token_client.mint(&treasury, &100000000i128);

        payroll_client.initialize(
            &admin,
            &token,
            &verifier,
            &commitment_contract,
            &treasury,
            &Address::random(env),
        );

        let alice = Address::random(env);
        let bob = Address::random(env);

        // Register employees
        let mut alice_blinding = [0u8; 32];
        alice_blinding[31] = 123u8;
        let alice_commitment = commitment_client.compute_commitment(
            &5000u64,
            &BytesN::from_array(env, &alice_blinding),
        );
        commitment_client.register_employee(&alice, &alice_commitment);

        let mut bob_blinding = [0u8; 32];
        bob_blinding[31] = 124u8;
        let bob_commitment = commitment_client.compute_commitment(
            &3000u64,
            &BytesN::from_array(env, &bob_blinding),
        );
        commitment_client.register_employee(&bob, &bob_commitment);

        TestContext {
            env: env.clone(),
            admin,
            treasury,
            alice,
            bob,
            token_client,
            payroll_client,
            commitment_client,
        }
    }

    #[test]
    fn test_get_payroll_status_after_execution() {
        let env = Env::default();
        let ctx = setup(&env);

        ctx.admin.require_auth_for_next_call();

        let proofs = Vec::from_array(&env, [mock_proof(&env)]);
        let amounts = Vec::from_array(&env, [5000i128]);
        let employees = Vec::from_array(&env, [ctx.alice.clone()]);

        let run_id = ctx.payroll_client.batch_process_payroll(
            &proofs,
            &amounts,
            &employees,
            &5000i128,
            &test_nonce(&env, 1),
            &None,
        );

        let status = ctx
            .payroll_client
            .get_payroll_run_status(&run_id)
            .expect("Status should exist");

        assert_eq!(status.run_id, run_id);
        assert_eq!(status.status, PayrollRunStatusKind::Completed);
        assert_eq!(status.employee_count, 1u32);
        assert_eq!(status.total_amount, 5000i128);
    }

    #[test]
    fn test_status_reflects_batch_details() {
        let env = Env::default();
        let ctx = setup(&env);

        ctx.admin.require_auth_for_next_call();

        let proofs = Vec::from_array(&env, [mock_proof(&env), mock_proof(&env)]);
        let amounts = Vec::from_array(&env, [5000i128, 3000i128]);
        let employees = Vec::from_array(&env, [ctx.alice.clone(), ctx.bob.clone()]);

        let run_id = ctx.payroll_client.batch_process_payroll(
            &proofs,
            &amounts,
            &employees,
            &8000i128,
            &test_nonce(&env, 2),
            &None,
        );

        let status = ctx
            .payroll_client
            .get_payroll_run_status(&run_id)
            .expect("Status should exist");

        assert_eq!(status.employee_count, 2u32);
        assert_eq!(status.total_amount, 8000i128);
    }

    #[test]
    fn test_nonexistent_run_returns_none() {
        let env = Env::default();
        let ctx = setup(&env);

        let status = ctx.payroll_client.get_payroll_run_status(&99999u64);
        assert!(status.is_none(), "Non-existent run should return None");
    }

    #[test]
    fn test_status_has_valid_timestamp() {
        let env = Env::default();
        let ctx = setup(&env);

        let initial_time = env.ledger().timestamp();

        ctx.admin.require_auth_for_next_call();

        let proofs = Vec::from_array(&env, [mock_proof(&env)]);
        let amounts = Vec::from_array(&env, [5000i128]);
        let employees = Vec::from_array(&env, [ctx.alice.clone()]);

        let run_id = ctx.payroll_client.batch_process_payroll(
            &proofs,
            &amounts,
            &employees,
            &5000i128,
            &test_nonce(&env, 3),
            &None,
        );

        let status = ctx
            .payroll_client
            .get_payroll_run_status(&run_id)
            .expect("Status should exist");

        assert!(
            status.last_updated >= initial_time,
            "Status timestamp should reflect execution time"
        );
    }
}
