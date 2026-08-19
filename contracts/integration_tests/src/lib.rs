#![no_std]

// Fixture datasets for local testing — Issue #81.
// Provides deterministic test data for companies, employees, and payroll periods.
#[cfg(test)]
mod fixtures;

// Upgrade simulation tests — Issue #108.
#[cfg(test)]
mod upgrade_simulation;

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
    use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
    use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
    use soroban_sdk::{
        testutils::{Address as _, Events},
        Address, BytesN, Env, Symbol, TryIntoVal, Vec,
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

    /// Build a mock Groth16 proof (256-byte payload).
    fn mock_proof(env: &Env) -> BytesN<256> {
        BytesN::from_array(env, &[0u8; 256])
    }

    /// Generates a unique 32-byte nonce from a counter seed for tests.
    fn test_nonce(env: &Env, seed: u8) -> BytesN<32> {
        let mut arr = [0u8; 32];
        arr[0] = seed;
        BytesN::from_array(env, &arr)
    }

    /// Compute the salary commitment used across tests.
    ///
    /// In production this will use the Poseidon host function (CAP-0075).
    /// The current contract implementation uses a deterministic SHA-256
    /// fallback so the commitment contract and the registry receive the same value.
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

        // ── Initialise payroll executor ───────────────────────────────────────
        let payroll_client = PayrollClient::new(&env, &payroll_id);
        payroll_client.initialize(
            &admin,
            &token_id,
            &verifier_id,
            &commitment_id,
            &treasury,
            &treasury_owner,
        );

        let commitment_client_init = SalaryCommitmentContractClient::new(&env, &commitment_id);
        commitment_client_init.set_payroll_operator(&payroll_id);

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
        ctx.payroll_client.batch_process_payroll(
            &proofs,
            &amounts,
            &employees,
            &payment_amount,
            &test_nonce(env, 1),
            &None,
        );

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

        // 4. Events must have been emitted across the full flow:
        //      - `CompanyRegistered`  from payroll_registry.register_company (setup)
        //      - `CommitmentUpdated`  from salary_commitment.store_commitment (onboarding)
        //      - `EmployeeAdded`      from payroll_registry.add_employee    (onboarding)
        //      - `CommitmentLocked`   from salary_commitment.lock_commitment_updates (execution)
        //      - `payment_executed`   from payroll.batch_process_payroll     (execution)
        //      - `run_executed`       from payroll.batch_process_payroll     (execution)
        let events = env.events().all();
        assert!(events.len() >= 6, "Expected at least 6 events emitted");

        let has_event = |sym: &str| {
            events.iter().any(|e| {
                e.1.iter().any(|val| {
                    if let Ok(s) = val.try_into_val(env) {
                        let symbol: Symbol = s;
                        symbol == Symbol::new(env, sym)
                    } else {
                        false
                    }
                })
            })
        };

        assert!(has_event("CompanyRegistered"), "CompanyRegistered event must be emitted");
        assert!(has_event("CommitmentUpdated"), "CommitmentUpdated event must be emitted");
        assert!(has_event("EmployeeAdded"), "EmployeeAdded event must be emitted");
        assert!(has_event("CommitmentLocked"), "CommitmentLocked event must be emitted");
        assert!(has_event("payment_executed"), "payment_executed event must be emitted");
        assert!(has_event("run_executed"), "run_executed event must be emitted");
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

        ctx.payroll_client.batch_process_payroll(
            &proofs,
            &amounts,
            &employees,
            &5_000i128,
            &test_nonce(env, 2),
            &None,
        );
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
        ctx.payroll_client.batch_process_payroll(
            &proofs,
            &amounts,
            &employees,
            &5_000i128,
            &test_nonce(env, 3),
            &None,
        );

        // Second payroll run with the same nullifier (batch index 0) must panic.
        let (proofs2, amounts2, employees2) = make_batch(env, &ctx.alice);
        ctx.payroll_client.batch_process_payroll(
            &proofs2,
            &amounts2,
            &employees2,
            &5_000i128,
            &test_nonce(env, 4),
            &None,
        );
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

        ctx.payroll_client.batch_process_payroll(
            &proofs,
            &amounts,
            &employees,
            &5_000i128,
            &test_nonce(env, 5),
            &None,
        );
    }

    // ── Dynamic proof generation test ─────────────────────────────────────────

    /// Tests the full proof-generation pipeline using a dynamically generated proof.
    ///
    /// This test bridges Circom/SnarkJS with the Soroban test framework by:
    ///
    /// 1. Invoking `node circuits/generate_proof.js 5000 123` as a subprocess.
    /// 2. Reading and parsing the resulting `proof_bytes.json` into Rust byte
    ///    arrays via [`crate::proof_helper::try_generate_proof`].
    /// 3. Constructing Soroban `BytesN` types from those bytes.
    /// 4. Running the full payroll flow — commitment storage, employee
    ///    registration, treasury funding, and batch payroll execution.
    /// 5. Asserting that treasury and employee balances change correctly and
    ///    that the payment nullifier is recorded on-chain.
    ///
    /// **Graceful skip**: if Node.js is not installed or
    /// `circuits/generate_proof.js` is not found the test logs a warning to
    /// stderr and returns without failing, so Rust-only CI pipelines continue
    /// to pass.
    ///
    /// When SnarkJS and compiled circuit artefacts are present, `generate_proof.js`
    /// produces a real Groth16 proof; otherwise it produces a deterministic
    /// mock proof in identical format.  The Soroban verifier currently accepts
    /// structurally valid proofs, so both paths exercise the complete
    /// deserialization and execution pipeline.
    #[test]
    fn test_dynamic_proof_integration() {
        use crate::proof_helper::try_generate_proof;

        let proof_data = match try_generate_proof(5000, 123) {
            Some(p) => p,
            None => return, // Node.js not available — skip gracefully.
        };

        let ctx = setup();
        let env = &ctx.env;
        let mut proof_bytes = [0u8; 256];
        proof_bytes[..64].copy_from_slice(&proof_data.pi_a);
        proof_bytes[64..192].copy_from_slice(&proof_data.pi_b);
        proof_bytes[192..].copy_from_slice(&proof_data.pi_c);
        let proof = BytesN::from_array(env, &proof_bytes);
        let salary_commitment = BytesN::from_array(env, &proof_data.salary_commitment);

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

        ctx.payroll_client.batch_process_payroll(
            &proofs,
            &amounts,
            &employees,
            &payment_amount,
            &test_nonce(env, 6),
            &None,
        );

        assert_eq!(
            ctx.token_client.balance(&ctx.treasury),
            initial_treasury - payment_amount
        );
        assert_eq!(ctx.token_client.balance(&ctx.alice), payment_amount);

        let expected_nullifier = BytesN::from_array(env, &[0u8; 32]);
        assert!(ctx.commitment_client.is_nullifier_used(&expected_nullifier));
    }

    /// End-to-end metadata hash verification (issue #177).
    ///
    /// Full flow: commit metadata hash → execute batch → bind metadata to run
    /// → verify on-chain hash matches the committed value → verify mismatch
    /// detection.
    #[test]
    fn test_e2e_metadata_hash_verification() {
        let ctx = setup();
        let env = &ctx.env;

        // ── PHASE 1: Setup employee and treasury ─────────────────────────────
        let commitment = alice_salary_commitment(&ctx.commitment_client);
        ctx.commitment_client
            .store_commitment(&ctx.alice, &commitment);
        ctx.registry_client
            .add_employee(&ctx.company_id, &ctx.alice, &commitment);

        let initial_treasury: i128 = 10_000;
        ctx.token_client.mint(&ctx.treasury, &initial_treasury);

        // ── PHASE 2: Execute payroll ─────────────────────────────────────────
        let payment_amount: i128 = 5_000;
        let proof = mock_proof(env);

        let mut proofs = Vec::new(env);
        proofs.push_back(proof);
        let mut amounts = Vec::new(env);
        amounts.push_back(payment_amount);
        let mut employees = Vec::new(env);
        employees.push_back(ctx.alice.clone());

        let run_id = ctx.payroll_client.batch_process_payroll(
            &proofs,
            &amounts,
            &employees,
            &payment_amount,
            &test_nonce(env, 7),
            &None,
        );
        assert!(run_id > 0);

        // ── PHASE 3: Metadata hash defaults to zero ──────────────────────────
        let zero_hash = BytesN::from_array(env, &[0u8; 32]);
        let stored_hash = ctx.payroll_client.get_metadata_hash(&run_id);
        assert_eq!(stored_hash, zero_hash);
        assert!(ctx.payroll_client.verify_metadata_hash(&run_id, &zero_hash));

        // ── PHASE 4: Commit and bind metadata hash ───────────────────────────
        let meta_hash = BytesN::from_array(env, &[0xAB; 32]);
        ctx.payroll_client
            .commit_metadata_hash(&ctx.admin, &meta_hash);
        ctx.payroll_client
            .set_run_metadata(&ctx.admin, &run_id, &meta_hash);

        // ── PHASE 5: Verify on-chain hash matches committed value ────────────
        let retrieved = ctx.payroll_client.get_metadata_hash(&run_id);
        assert_eq!(retrieved, meta_hash);
        assert!(ctx.payroll_client.verify_metadata_hash(&run_id, &meta_hash));

        // ── PHASE 6: Verify mismatch detection ───────────────────────────────
        let wrong_hash = BytesN::from_array(env, &[0xCD; 32]);
        assert!(!ctx
            .payroll_client
            .verify_metadata_hash(&run_id, &wrong_hash));
    }

    /// Issue #201: Verify end-to-end failed payroll execution rollback across all contracts.
    /// Ensures partial state is not retained in SalaryCommitment, Registry, Token, or Payroll.
    #[test]
    fn test_e2e_failed_payroll_execution_rollback() {
        let ctx = setup();
        let env = &ctx.env;

        // Onboard Alice
        let alice_commitment = alice_salary_commitment(&ctx.commitment_client);
        ctx.commitment_client
            .store_commitment(&ctx.alice, &alice_commitment);
        ctx.registry_client
            .add_employee(&ctx.company_id, &ctx.alice, &alice_commitment);

        // Mint treasury tokens
        let initial_treasury: i128 = 10_000;
        ctx.token_client.mint(&ctx.treasury, &initial_treasury);

        // Create an un-onboarded employee Bob
        let bob = Address::generate(env);

        // Build a batch targeting [Alice, Bob]
        let mut proofs = Vec::new(env);
        proofs.push_back(mock_proof(env));
        proofs.push_back(mock_proof(env));

        let mut amounts = Vec::new(env);
        amounts.push_back(5_000i128);
        amounts.push_back(5_000i128);

        let mut employees = Vec::new(env);
        employees.push_back(ctx.alice.clone());
        employees.push_back(bob.clone());

        let nonce = test_nonce(env, 201);

        // Execution fails because Bob has no commitment stored
        let res = ctx.payroll_client.try_batch_process_payroll(
            &proofs,
            &amounts,
            &employees,
            &10_000i128,
            &nonce,
            &None,
        );
        assert!(
            res.is_err(),
            "Batch processing must fail when Bob is missing commitment"
        );

        // 1. Treasury balance remains completely unchanged
        assert_eq!(
            ctx.token_client.balance(&ctx.treasury),
            initial_treasury,
            "Treasury balance must be unchanged after failed run"
        );

        // 2. Alice balance is still 0
        assert_eq!(
            ctx.token_client.balance(&ctx.alice),
            0,
            "Alice balance must be 0 after failed run"
        );

        // 3. Alice's nullifier was not recorded as used
        let alice_nullifier = BytesN::from_array(env, &[0u8; 32]);
        assert!(
            !ctx.commitment_client.is_nullifier_used(&alice_nullifier),
            "Alice's nullifier must not be used after failed run"
        );

        // 4. Alice's commitment updates were not locked
        assert!(
            !ctx.commitment_client.is_commitment_locked(&ctx.alice),
            "Alice's commitment updates must not be locked after failed run"
        );

        // 5. Retrying with a valid batch for Alice succeeds completely
        let mut valid_proofs = Vec::new(env);
        valid_proofs.push_back(mock_proof(env));
        let mut valid_amounts = Vec::new(env);
        valid_amounts.push_back(5_000i128);
        let mut valid_employees = Vec::new(env);
        valid_employees.push_back(ctx.alice.clone());

        let run_id = ctx.payroll_client.batch_process_payroll(
            &valid_proofs,
            &valid_amounts,
            &valid_employees,
            &5_000i128,
            &nonce,
            &None,
        );
        assert!(
            run_id > 0,
            "Valid payroll run must succeed after previous failure rollback"
        );

        // Verify post-retry success states
        assert_eq!(ctx.token_client.balance(&ctx.alice), 5_000i128);
        assert_eq!(
            ctx.token_client.balance(&ctx.treasury),
            initial_treasury - 5_000i128
        );
        assert!(ctx.commitment_client.is_nullifier_used(&alice_nullifier));
        assert!(ctx.commitment_client.is_commitment_locked(&ctx.alice));
    }
}
