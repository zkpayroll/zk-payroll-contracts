/// Issue #482: Duplicate employee validation tests
///
/// Ensures that the same employee cannot be paid multiple times in a single payroll run,
/// preventing accidental overpayment due to duplicate entries.

#[cfg(test)]
mod tests {
    use payroll::{Payroll, PayrollClient, PayrollRunState};
    use payroll_registry::{PayrollRegistry, PayrollRegistryClient};
    use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
    use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
    use soroban_sdk::{
        testutils::{Address as _, Ledger as _},
        Address, BytesN, Env, Symbol, Vec,
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
    fn test_payroll_with_duplicate_employee_should_fail() {
        let env = Env::default();
        let ctx = setup(&env);

        ctx.admin.require_auth_for_next_call();

        // Attempt to pay Alice twice in the same batch
        let proofs = Vec::from_array(&env, [mock_proof(&env), mock_proof(&env)]);
        let amounts = Vec::from_array(&env, [5000i128, 5000i128]);
        let employees = Vec::from_array(&env, [ctx.alice.clone(), ctx.alice.clone()]);

        let result = ctx.payroll_client.try_batch_process_payroll(
            &proofs,
            &amounts,
            &employees,
            &10000i128,
            &test_nonce(&env, 1),
            &None,
        );

        assert!(result.is_err(), "Duplicate employee should be rejected");
    }

    #[test]
    fn test_payroll_with_no_duplicates_succeeds() {
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

        assert!(run_id > 0, "Payroll run should be created successfully");
        assert_eq!(
            ctx.token_client.balance(&ctx.alice),
            5000i128,
            "Alice should receive payment"
        );
        assert_eq!(
            ctx.token_client.balance(&ctx.bob),
            3000i128,
            "Bob should receive payment"
        );
    }

    #[test]
    fn test_different_runs_can_pay_same_employee() {
        let env = Env::default();
        let ctx = setup(&env);

        ctx.admin.require_auth_for_next_call();

        // First run: pay Alice
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

        assert!(run_id_1 > 0);

        env.ledger().set_sequence_number(200);

        ctx.admin.require_auth_for_next_call();

        // Second run: pay Alice again (different run, should be allowed)
        let proofs2 = Vec::from_array(&env, [mock_proof(&env)]);
        let amounts2 = Vec::from_array(&env, [6000i128]);
        let employees2 = Vec::from_array(&env, [ctx.alice.clone()]);

        let run_id_2 = ctx.payroll_client.batch_process_payroll(
            &proofs2,
            &amounts2,
            &employees2,
            &6000i128,
            &test_nonce(&env, 4),
            &None,
        );

        assert!(run_id_2 > run_id_1, "Second run should have higher ID");
        assert_eq!(
            ctx.token_client.balance(&ctx.alice),
            11000i128,
            "Alice should have cumulative payments"
        );
    }
}
