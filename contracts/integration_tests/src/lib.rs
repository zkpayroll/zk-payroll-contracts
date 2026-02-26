#![no_std]

// Proof generation helper — only compiled in test mode.
// Provides `try_generate_proof` which spawns `node generate_proof.js` and
// parses the output into Soroban-compatible byte arrays.
#[cfg(test)]
mod proof_helper;

/// End-to-end integration tests for the ZK Payroll protocol.
///
/// These tests validate the full protocol flow across all smart contracts:
///   Registry → Commitment → Verifier → Payroll Execution
///
/// The happy-path test exercises:
///   1. SETUP    – Register a company with admin privileges
///   2. ONBOARDING – Enrol Alice with a salary commitment
///      representing Poseidon_Hash(salary=5000, blinding=123)
///   3. EXECUTION  – Generate a mock Groth16 proof and run batch payroll
///   4. ASSERTIONS – Treasury decreases by 5 000; Alice's balance increases by 5 000;
///      payment event is emitted; double-payment is rejected;
///      unregistered employees cannot be paid.
#[cfg(test)]
mod e2e {
    use payroll::{Payroll, PayrollClient};
    use payroll_registry::{PayrollRegistry, PayrollRegistryClient};
    use proof_verifier::{Groth16Proof, ProofVerifier, ProofVerifierClient, VerificationKey};
    use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
    use soroban_sdk::{
        testutils::{Address as _, Events},
        Address, BytesN, Env, Vec,
    };
    use token::{Token, TokenClient};

    // ── Helpers ──────────────────────────────────────────────────────────────

    /// Build a mock Groth16 verification key (all-zero curve points).
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

    /// Build a mock Groth16 proof (distinguishable byte patterns per point).
    fn mock_proof(env: &Env) -> Groth16Proof {
        Groth16Proof {
            a: BytesN::from_array(env, &[1u8; 64]),
            b: BytesN::from_array(env, &[2u8; 128]),
            c: BytesN::from_array(env, &[3u8; 64]),
        }
    }

    /// Compute the salary commitment used across tests.
    ///
    /// In production this will use the Poseidon host function (CAP-0075).
    /// The placeholder `compute_commitment` currently returns all-zeroes,
    /// so both the commitment contract and the registry receive the same value.
    fn alice_salary_commitment(commitment_client: &SalaryCommitmentContractClient) -> BytesN<32> {
        let env = commitment_client.env.clone();
        // blinding factor = 123 encoded as a big-endian 32-byte value
        let mut blinding_bytes = [0u8; 32];
        blinding_bytes[31] = 123u8;
        let blinding_factor = BytesN::from_array(&env, &blinding_bytes);
        commitment_client.compute_commitment(&5000u64, &blinding_factor)
    }

    // ── Helper: register & initialise all five contracts ─────────────────────

    struct TestContext<'a> {
        env: Env,
        admin: Address,
        treasury: Address,
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

        // ── Register contracts ───────────────────────────────────────────────
        let verifier_id = env.register_contract(None, ProofVerifier);
        let verifier_client = ProofVerifierClient::new(&env, &verifier_id);
        verifier_client.initialize_verifier(&mock_vk(&env));

        let commitment_id = env.register_contract(None, SalaryCommitmentContract);

        let token_id = env.register_contract(None, Token);

        let registry_id = env.register_contract(None, PayrollRegistry);

        let payroll_id = env.register_contract(None, Payroll);

        // ── Actors ────────────────────────────────────────────────────────────
        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let alice = Address::generate(&env);

        // ── Initialise payroll executor ───────────────────────────────────────
        let payroll_client = PayrollClient::new(&env, &payroll_id);
        payroll_client.initialize(&admin, &token_id, &verifier_id, &commitment_id, &treasury);

        // ── Build typed clients ───────────────────────────────────────────────
        let token_client = TokenClient::new(&env, &token_id);
        let registry_client = PayrollRegistryClient::new(&env, &registry_id);
        let commitment_client = SalaryCommitmentContractClient::new(&env, &commitment_id);

        // Register a company up-front; first ID is always 0.
        let company_id = registry_client.register_company(&admin, &treasury);

        TestContext {
            env,
            admin,
            treasury,
            alice,
            company_id,
            token_client,
            registry_client,
            commitment_client,
            payroll_client,
        }
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    /// Full happy-path: Setup → Onboarding → Execution → Assertions.
    #[test]
    fn test_e2e_full_payroll_flow() {
        let ctx = setup();
        let env = &ctx.env;

        // ── PHASE 1: SETUP ────────────────────────────────────────────────────
        // company is already registered in setup(); company_id == 0.

        // ── PHASE 2: ONBOARDING ───────────────────────────────────────────────
        // Compute Alice's commitment: Poseidon_Hash(salary=5000, blinding=123).
        let commitment = alice_salary_commitment(&ctx.commitment_client);

        // Store the commitment on-chain so the payroll executor can retrieve it.
        ctx.commitment_client
            .store_commitment(&ctx.alice, &commitment);
        assert!(ctx.commitment_client.has_commitment(&ctx.alice));

        // Register Alice in the registry with the same commitment.
        ctx.registry_client
            .add_employee(&ctx.company_id, &ctx.alice, &commitment);

        // ── PHASE 3: EXECUTION ────────────────────────────────────────────────
        // Mint tokens into the company treasury.
        let initial_treasury: i128 = 10_000;
        ctx.token_client.mint(&ctx.treasury, &initial_treasury);
        assert_eq!(ctx.token_client.balance(&ctx.treasury), initial_treasury);
        assert_eq!(ctx.token_client.balance(&ctx.alice), 0);

        // Build payroll batch for Alice (salary = 5000, single entry).
        let payment_amount: i128 = 5_000;
        let proof = mock_proof(env);

        let mut proofs = Vec::new(env);
        proofs.push_back(proof);
        let mut amounts = Vec::new(env);
        amounts.push_back(payment_amount);
        let mut employees = Vec::new(env);
        employees.push_back(ctx.alice.clone());

        // Execute batch payroll: verifier checks proof, commitment is retrieved,
        // nullifier is recorded, and the token transfer is executed.
        ctx.payroll_client
            .batch_process_payroll(&proofs, &amounts, &employees);

        // ── ASSERTIONS ────────────────────────────────────────────────────────

        // 1. Treasury decreased by exactly the payment amount.
        assert_eq!(
            ctx.token_client.balance(&ctx.treasury),
            initial_treasury - payment_amount,
            "Treasury must decrease by payment amount"
        );

        // 2. Alice's balance increased by exactly the payment amount.
        assert_eq!(
            ctx.token_client.balance(&ctx.alice),
            payment_amount,
            "Alice's balance must increase by payment amount"
        );

        // 3. The nullifier for batch index 0 is now marked as used (double-payment guard).
        let nullifier = BytesN::from_array(env, &[0u8; 32]);
        assert!(
            ctx.commitment_client.is_nullifier_used(&nullifier),
            "Payment nullifier must be recorded after execution"
        );

        // 4. A `payment_executed` event was emitted for Alice's payment.
        //    The payroll contract publishes one event per processed employee.
        let events = env.events().all();
        assert_eq!(
            events.len(),
            1,
            "Exactly one payment_executed event must be emitted for a single-employee batch"
        );
    }

    /// Paying an employee who has no commitment on-chain must panic.
    #[test]
    #[should_panic(expected = "Commitment not found")]
    fn test_unregistered_employee_cannot_be_paid() {
        let ctx = setup();
        let env = &ctx.env;

        // Register company (no employees added) — company is pre-registered in setup.

        // Mint tokens so the transfer wouldn't be blocked by balance.
        ctx.token_client.mint(&ctx.treasury, &10_000i128);

        // Attempt to pay Alice who has no stored commitment – must panic.
        let mut proofs = Vec::new(env);
        proofs.push_back(mock_proof(env));
        let mut amounts = Vec::new(env);
        amounts.push_back(5_000i128);
        let mut employees = Vec::new(env);
        employees.push_back(ctx.alice.clone());

        ctx.payroll_client
            .batch_process_payroll(&proofs, &amounts, &employees);
    }

    /// Running payroll twice for the same employee reuses the nullifier and must panic.
    #[test]
    #[should_panic(expected = "Nullifier already used")]
    fn test_double_payment_rejected() {
        let ctx = setup();
        let env = &ctx.env;

        // Full setup so the first payment succeeds — company pre-registered in setup().
        let commitment = alice_salary_commitment(&ctx.commitment_client);
        ctx.commitment_client
            .store_commitment(&ctx.alice, &commitment);
        ctx.registry_client
            .add_employee(&ctx.company_id, &ctx.alice, &commitment);

        ctx.token_client.mint(&ctx.treasury, &20_000i128);

        let make_batch = |env: &Env, alice: &Address| {
            let mut proofs = Vec::new(env);
            proofs.push_back(mock_proof(env));
            let mut amounts = Vec::new(env);
            amounts.push_back(5_000i128);
            let mut employees = Vec::new(env);
            employees.push_back(alice.clone());
            (proofs, amounts, employees)
        };

        // First payroll run succeeds.
        let (proofs, amounts, employees) = make_batch(env, &ctx.alice);
        ctx.payroll_client
            .batch_process_payroll(&proofs, &amounts, &employees);

        // Second payroll run with the same nullifier (batch index 0) must panic.
        let (proofs2, amounts2, employees2) = make_batch(env, &ctx.alice);
        ctx.payroll_client
            .batch_process_payroll(&proofs2, &amounts2, &employees2);
    }

    /// Array length mismatches must be rejected immediately.
    #[test]
    #[should_panic(expected = "Array length mismatch")]
    fn test_mismatched_arrays_rejected() {
        let ctx = setup();
        let env = &ctx.env;

        // company is pre-registered in setup().

        // Two proofs but only one amount → length mismatch.
        let mut proofs = Vec::new(env);
        proofs.push_back(mock_proof(env));
        proofs.push_back(mock_proof(env));
        let mut amounts = Vec::new(env); // only one entry
        amounts.push_back(5_000i128);
        let mut employees = Vec::new(env);
        employees.push_back(ctx.alice.clone());
        employees.push_back(ctx.alice.clone());

        ctx.payroll_client
            .batch_process_payroll(&proofs, &amounts, &employees);
    }

    // ── Dynamic proof generation test ─────────────────────────────────────────

    /// Tests the full proof-generation pipeline using a dynamically generated proof.
    #[test]
    fn test_dynamic_proof_integration() {
        use crate::proof_helper::try_generate_proof;

        let proof_data = match try_generate_proof(5000, 123) {
            Some(p) => p,
            None => return, // Node.js not available — skip gracefully.
        };

        let ctx = setup();
        let env = &ctx.env;

        let proof = Groth16Proof {
            a: BytesN::from_array(env, &proof_data.pi_a),
            b: BytesN::from_array(env, &proof_data.pi_b),
            c: BytesN::from_array(env, &proof_data.pi_c),
        };
        let salary_commitment = BytesN::from_array(env, &proof_data.salary_commitment);

        ctx.registry_client
            .register_company(&ctx.admin, &ctx.treasury);
        ctx.commitment_client
            .store_commitment(&ctx.alice, &salary_commitment);
        ctx.registry_client
            .add_employee(&ctx.company_id, &ctx.alice, &salary_commitment);

        let initial_treasury: i128 = 10_000;
        let payment_amount: i128 = 5_000;
        ctx.token_client.mint(&ctx.treasury, &initial_treasury);

        let mut proofs = Vec::new(env);
        let mut amounts = Vec::new(env);
        let mut employees = Vec::new(env);
        proofs.push_back(proof);
        amounts.push_back(payment_amount);
        employees.push_back(ctx.alice.clone());

        ctx.payroll_client
            .batch_process_payroll(&proofs, &amounts, &employees);

        assert_eq!(
            ctx.token_client.balance(&ctx.treasury),
            initial_treasury - payment_amount
        );
        assert_eq!(ctx.token_client.balance(&ctx.alice), payment_amount);

        let expected_nullifier = BytesN::from_array(env, &[0u8; 32]);
        assert!(ctx.commitment_client.is_nullifier_used(&expected_nullifier));
    }
}
