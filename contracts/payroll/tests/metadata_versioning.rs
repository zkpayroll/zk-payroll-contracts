/// Issue #478: Payroll run metadata versioning tests
///
/// Tests that metadata versioning is properly recorded for contract evolution safety,
/// allowing later contract changes to handle different schema versions.

#[cfg(test)]
mod tests {
    use payroll::{Payroll, PayrollClient};
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

        // Register employee
        let mut alice_blinding = [0u8; 32];
        alice_blinding[31] = 123u8;
        let alice_commitment = commitment_client.compute_commitment(
            &5000u64,
            &BytesN::from_array(env, &alice_blinding),
        );
        commitment_client.register_employee(&alice, &alice_commitment);

        TestContext {
            env: env.clone(),
            admin,
            treasury,
            alice,
            token_client,
            payroll_client,
            commitment_client,
        }
    }

    #[test]
    fn test_metadata_version_recorded_after_execution() {
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

        let version = ctx
            .payroll_client
            .get_metadata_version(&run_id)
            .expect("Metadata version should be recorded");

        assert_eq!(version.run_id, run_id);
        assert_eq!(version.schema_version, 1u32);
        assert!(version.created_at > 0);
    }

    #[test]
    fn test_metadata_version_has_valid_timestamp() {
        let env = Env::default();
        let ctx = setup(&env);

        let current_time = env.ledger().timestamp();

        ctx.admin.require_auth_for_next_call();

        let proofs = Vec::from_array(&env, [mock_proof(&env)]);
        let amounts = Vec::from_array(&env, [5000i128]);
        let employees = Vec::from_array(&env, [ctx.alice.clone()]);

        let run_id = ctx.payroll_client.batch_process_payroll(
            &proofs,
            &amounts,
            &employees,
            &5000i128,
            &test_nonce(&env, 2),
            &None,
        );

        let version = ctx
            .payroll_client
            .get_metadata_version(&run_id)
            .expect("Metadata version should be recorded");

        assert!(
            version.created_at >= current_time,
            "Timestamp should reflect execution time"
        );
    }

    #[test]
    fn test_nonexistent_run_metadata_returns_none() {
        let env = Env::default();
        let ctx = setup(&env);

        let version = ctx.payroll_client.get_metadata_version(&99999u64);
        assert!(
            version.is_none(),
            "Non-existent run should return None for metadata"
        );
    }

    #[test]
    fn test_multiple_runs_have_independent_versions() {
        let env = Env::default();
        let ctx = setup(&env);

        ctx.admin.require_auth_for_next_call();

        let proofs1 = Vec::from_array(&env, [mock_proof(&env)]);
        let amounts1 = Vec::from_array(&env, [5000i128]);
        let employees1 = Vec::from_array(&env, [ctx.alice.clone()]);

        let run_id_1 = ctx.payroll_client.batch_process_payroll(
            &proofs1,
            &amounts1,
            &employees1,
            &5000i128,
            &test_nonce(&env, 3),
            &None,
        );

        env.ledger().set_sequence_number(200);
        ctx.admin.require_auth_for_next_call();

        let proofs2 = Vec::from_array(&env, [mock_proof(&env)]);
        let amounts2 = Vec::from_array(&env, [5000i128]);
        let employees2 = Vec::from_array(&env, [ctx.alice.clone()]);

        let run_id_2 = ctx.payroll_client.batch_process_payroll(
            &proofs2,
            &amounts2,
            &employees2,
            &5000i128,
            &test_nonce(&env, 4),
            &None,
        );

        let version1 = ctx
            .payroll_client
            .get_metadata_version(&run_id_1)
            .expect("First run should have metadata");

        let version2 = ctx
            .payroll_client
            .get_metadata_version(&run_id_2)
            .expect("Second run should have metadata");

        assert_eq!(version1.run_id, run_id_1);
        assert_eq!(version2.run_id, run_id_2);
        assert!(version2.created_at >= version1.created_at);
    }
}
