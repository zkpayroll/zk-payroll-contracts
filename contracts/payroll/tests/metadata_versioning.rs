//! Issue #478: Payroll run metadata versioning tests
//!
//! Tests that metadata versioning is properly recorded for contract evolution safety,
//! allowing later contract changes to handle different schema versions.

#[cfg(test)]
mod tests {
    use payroll::{Payroll, PayrollClient};
    use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
    use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
    use soroban_sdk::{
        testutils::{Address as _, Ledger as _},
        Address, BytesN, Env, String, Vec,
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
        _env: Env,
        _admin: Address,
        _treasury: Address,
        alice: Address,
        _token_client: TokenClient<'a>,
        payroll_client: PayrollClient<'a>,
        commitment_client: SalaryCommitmentContractClient<'a>,
        source: Address,
    }

    fn setup(env: &Env) -> TestContext<'_> {
        env.mock_all_auths();
        env.ledger().set_sequence_number(100);
        env.ledger().set_timestamp(1000);

        let token = env.register(Token, ());
        let admin = Address::generate(env);
        let treasury = Address::generate(env);
        let verifier = env.register(ProofVerifier, ());
        let commitment_contract = env.register(SalaryCommitmentContract, ());

        let token_client = TokenClient::new(env, &token);
        token_client.initialize(
            &Address::generate(env),
            &9u32,
            &String::from_str(env, "USDC"),
            &String::from_str(env, "USD Coin"),
        );

        let payroll = env.register(Payroll, ());
        let payroll_client = PayrollClient::new(env, &payroll);

        let verifier_client = ProofVerifierClient::new(env, &verifier);
        verifier_client.init_verifier_admin(&Address::generate(env));
        verifier_client.initialize_verifier(&mock_vk(env));

        let commitment_client = SalaryCommitmentContractClient::new(env, &commitment_contract);
        commitment_client.init_commitment_admin(&Address::generate(env));

        token_client.mint(&treasury, &100000000i128);

        payroll_client.initialize(
            &admin,
            &token,
            &verifier,
            &commitment_contract,
            &treasury,
            &Address::generate(env),
        );

        commitment_client.set_payroll_operator(&payroll);

        let source = Address::generate(env);
        payroll_client.register_import_source(&source, &0u32);

        let alice = Address::generate(env);

        // Register employee
        let mut alice_blinding = [0u8; 32];
        alice_blinding[31] = 123u8;
        let alice_commitment = commitment_client
            .compute_commitment(&5000u64, &BytesN::from_array(env, &alice_blinding));
        commitment_client.store_commitment(&alice, &alice_commitment);

        TestContext {
            _env: env.clone(),
            _admin: admin,
            _treasury: treasury,
            alice,
            _token_client: token_client,
            payroll_client,
            commitment_client,
            source,
        }
    }

    #[test]
    fn test_metadata_version_recorded_after_execution() {
        let env = Env::default();
        let ctx = setup(&env);

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
            &ctx.source,
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
            &ctx.source,
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
            &ctx.source,
        );

        env.ledger().set_sequence_number(200);

        let bob = Address::generate(&env);
        ctx.commitment_client
            .store_commitment(&bob, &BytesN::from_array(&env, &[7u8; 32]));
        let proofs2 = Vec::from_array(&env, [BytesN::from_array(&env, &[1u8; 256])]);
        let amounts2 = Vec::from_array(&env, [5000i128]);
        let employees2 = Vec::from_array(&env, [bob]);

        let run_id_2 = ctx.payroll_client.batch_process_payroll(
            &proofs2,
            &amounts2,
            &employees2,
            &5000i128,
            &test_nonce(&env, 4),
            &None,
            &ctx.source,
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
