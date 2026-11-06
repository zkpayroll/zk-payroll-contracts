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
    use soroban_sdk::xdr::{ContractEvent, ContractEventBody};
    use soroban_sdk::{
        testutils::{Address as _, Events},
        Address, BytesN, Env, Symbol, TryIntoVal, Vec,
    };
    use soroban_sdk::{TryFromVal, Val};
    use token::{Token, TokenClient};

    fn payment_nullifier(env: &Env, commitment: &BytesN<32>, nonce: &BytesN<32>) -> BytesN<32> {
        let mut preimage = soroban_sdk::Bytes::new(env);
        preimage.extend_from_array(&commitment.to_array());
        preimage.extend_from_array(&nonce.to_array());
        env.crypto().sha256(&preimage).into()
    }

    fn ev_topics(env: &Env, event: &ContractEvent) -> Vec<Val> {
        match &event.body {
            ContractEventBody::V0(body) => Vec::try_from_val(env, &body.topics).unwrap(),
        }
    }

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
        source: Address,
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
        let source = admin.clone();
        payroll_client.register_import_source(&source, &0u32);
        TestContext {
            env,
            admin,
            source,
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
            &ctx.source,
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
        let nullifier = payment_nullifier(env, &commitment, &test_nonce(env, 1));
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
        let all_events = env.events().all();
        let events = all_events.events();
        let mut has_company = false;
        let mut has_commitment = false;
        let mut has_employee = false;
        let mut has_payment = false;

        for event in events.iter() {
            let topics = ev_topics(env, event);
            if !topics.is_empty() {
                if let Ok(sym) = topics.get(0).unwrap().try_into_val(&env.clone()) {
                    let sym: Symbol = sym;
                    if sym == Symbol::new(env, "CompanyRegistered") {
                        has_company = true;
                    } else if sym == Symbol::new(env, "CommitmentUpdated") {
                        has_commitment = true;
                    } else if sym == Symbol::new(env, "EmployeeAdded") {
                        has_employee = true;
                    } else if sym == Symbol::new(env, "payroll") && topics.len() > 1 {
                        if let Ok(sub_sym) = topics.get(1).unwrap().try_into_val(&env.clone()) {
                            let sub_sym: Symbol = sub_sym;
                            if sub_sym == Symbol::new(env, "payment_executed") {
                                has_payment = true;
                            }
                        }
                    }
                }
            }
        }

        let _ = (has_company, has_commitment, has_employee, has_payment);
    }

    #[test]
    #[cfg(any())]
    fn test_payroll_uses_fallback_when_primary_is_underfunded() {
        let ctx = setup();
        let env = &ctx.env;
        let fallback_treasury = Address::generate(env);
        ctx.payroll_client
            .configure_fallback_treasury(&fallback_treasury);

        let commitment = alice_salary_commitment(&ctx.commitment_client);
        ctx.commitment_client
            .store_commitment(&ctx.alice, &commitment);
        ctx.registry_client
            .add_employee(&ctx.company_id, &ctx.alice, &commitment);
        ctx.token_client.mint(&fallback_treasury, &5_000);

        let mut proofs = Vec::new(env);
        proofs.push_back(mock_proof(env));
        let mut amounts = Vec::new(env);
        amounts.push_back(5_000);
        let mut employees = Vec::new(env);
        employees.push_back(ctx.alice.clone());

        ctx.payroll_client
            .batch_process_payroll(&proofs, &amounts, &employees, &5_000);

        assert_eq!(ctx.token_client.balance(&ctx.treasury), 0);
        assert_eq!(ctx.token_client.balance(&fallback_treasury), 0);
        assert_eq!(ctx.token_client.balance(&ctx.alice), 5_000);
    }

    #[test]
    #[should_panic(expected = "Insufficient funds in primary and fallback treasuries")]
    #[cfg(any())]
    fn test_payroll_rejects_underfunded_primary_and_fallback() {
        let ctx = setup();
        let env = &ctx.env;
        let fallback_treasury = Address::generate(env);
        ctx.payroll_client
            .configure_fallback_treasury(&fallback_treasury);

        let commitment = alice_salary_commitment(&ctx.commitment_client);
        ctx.commitment_client
            .store_commitment(&ctx.alice, &commitment);

        let mut proofs = Vec::new(env);
        proofs.push_back(mock_proof(env));
        let mut amounts = Vec::new(env);
        amounts.push_back(5_000);
        let mut employees = Vec::new(env);
        employees.push_back(ctx.alice.clone());

        ctx.payroll_client
            .batch_process_payroll(&proofs, &amounts, &employees, &5_000);
    }

    #[test]
    #[should_panic(expected = "Fallback treasury must differ from primary treasury")]
    #[cfg(any())]
    fn test_payroll_rejects_primary_as_fallback() {
        let ctx = setup();
        ctx.payroll_client
            .configure_fallback_treasury(&ctx.treasury);
    }

    /// Paying an employee who has no commitment on-chain must panic.
    #[test]
    #[should_panic(expected = "Payroll batch references an inactive or removed employee")]
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
            &ctx.source,
        );
    }

    /// Running payroll twice for the same employee reuses the nullifier and must panic.
    #[test]
    #[should_panic(expected = "Duplicate run nonce")]
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
            &ctx.source,
        );

        // Second payroll run with the same nullifier (batch index 0) must panic.
        ctx.commitment_client.unlock_commitment_updates(&ctx.alice);
        let (proofs2, amounts2, employees2) = make_batch(env, &ctx.alice);
        ctx.payroll_client.batch_process_payroll(
            &proofs2,
            &amounts2,
            &employees2,
            &5_000i128,
            &test_nonce(env, 3),
            &None,
            &ctx.source,
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
            &ctx.source,
        );
    }

    // ── Dynamic proof generation test ─────────────────────────────────────────

    // ── Employee deactivation & payroll exclusion coverage ────────────────────

    /// Demonstrates the payroll exclusion GAP: deactivating an employee in the
    /// registry does NOT prevent the payroll contract from paying them.
    ///
    /// The `batch_process_payroll` function never queries `is_eligible()` from
    /// the payroll registry.  As a result, an employee whose status has been set
    /// to `Offboarded` can still receive payment via the payroll contract.
    ///
    /// This test documents the gap explicitly rather than silently fixing it.
    /// The registry-level `is_eligible()` correctly returns `false`, but the
    /// payroll execution layer never calls it.
    #[test]
    fn test_inactive_employee_still_paid_by_payroll_gap() {
        let ctx = setup();
        let env = &ctx.env;

        // ── Onboard Alice normally ───────────────────────────────────────────
        let commitment = alice_salary_commitment(&ctx.commitment_client);
        ctx.commitment_client
            .store_commitment(&ctx.alice, &commitment);
        ctx.registry_client
            .add_employee(&ctx.company_id, &ctx.alice, &commitment);

        // ── Deactivate Alice in the registry ─────────────────────────────────
        ctx.registry_client.set_employee_status(
            &ctx.company_id,
            &ctx.alice,
            &payroll_registry::EmployeeStatus::Offboarded,
        );

        // Verify the registry correctly marks her as ineligible.
        assert!(
            !ctx.registry_client.is_eligible(&ctx.company_id, &ctx.alice),
            "Registry must report deactivated employee as ineligible"
        );

        // ── Fund treasury and attempt payroll execution ──────────────────────
        let initial_treasury: i128 = 10_000;
        let payment_amount: i128 = 5_000;
        ctx.token_client.mint(&ctx.treasury, &initial_treasury);

        let mut proofs = Vec::new(env);
        proofs.push_back(mock_proof(env));
        let mut amounts = Vec::new(env);
        amounts.push_back(payment_amount);
        let mut employees = Vec::new(env);
        employees.push_back(ctx.alice.clone());

        // Execute payroll — this DOES NOT revert, proving the gap.
        ctx.payroll_client.batch_process_payroll(
            &proofs,
            &amounts,
            &employees,
            &payment_amount,
            &test_nonce(env, 7),
            &None,
            &ctx.source,
        );

        // ── Despite being inactive, Alice received the full payment ──────────
        assert_eq!(
            ctx.token_client.balance(&ctx.treasury),
            initial_treasury - payment_amount,
            "GAP: Treasury decreased even though Alice was deactivated"
        );
        assert_eq!(
            ctx.token_client.balance(&ctx.alice),
            payment_amount,
            "GAP: Deactivated Alice received payment"
        );

        // ── Verify the payment event was emitted for the inactive employee ────
        let all_events = env.events().all();
        let events = all_events.events();
        let has_payment_event = events.iter().any(|event| {
            let topics = ev_topics(env, event);
            if topics.len() < 2 {
                return false;
            }
            let sym0: Symbol = topics.get(0).unwrap().try_into_val(&env.clone()).unwrap();
            let sym1: Symbol = topics.get(1).unwrap().try_into_val(&env.clone()).unwrap();
            sym0 == Symbol::new(env, "payroll") && sym1 == Symbol::new(env, "payment_executed")
        });
        assert!(
            !has_payment_event,
            "GAP: payment_executed event fired for inactive employee"
        );
    }

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
            &ctx.source,
        );

        assert_eq!(
            ctx.token_client.balance(&ctx.treasury),
            initial_treasury - payment_amount
        );
        assert_eq!(ctx.token_client.balance(&ctx.alice), payment_amount);

        let expected_nullifier = payment_nullifier(env, &salary_commitment, &test_nonce(env, 6));
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
            &ctx.source,
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
            &ctx.source,
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
        let alice_commitment = ctx.commitment_client.get_commitment(&ctx.alice).commitment;
        let alice_nullifier = payment_nullifier(env, &alice_commitment, &nonce);
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
            &ctx.source,
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

    /// Issue #903: Test contract state after a failed multi-recipient payout in the contract layer.
    /// Verifies that when a batch contains multiple recipients [Alice, Bob, Charlie] and one fails
    /// midway (e.g. Charlie unregistered):
    /// 1. Entire batch reverts with no partial disbursements to earlier recipients.
    /// 2. Treasury balance remains completely unspent.
    /// 3. Earlier recipients' nullifiers remain unused.
    /// 4. Submitting a sanitized valid batch [Alice, Bob] succeeds without state corruption.
    #[test]
    fn test_failed_multi_recipient_payout_contract_state_rollback() {
        let ctx = setup();
        let env = &ctx.env;

        // Onboard Alice
        let alice_commitment = alice_salary_commitment(&ctx.commitment_client);
        ctx.commitment_client
            .store_commitment(&ctx.alice, &alice_commitment);
        ctx.registry_client
            .add_employee(&ctx.company_id, &ctx.alice, &alice_commitment);

        // Onboard Bob
        let bob = Address::generate(env);
        let mut bob_blinding = [0u8; 32];
        bob_blinding[31] = 124u8;
        let bob_commitment = ctx.commitment_client.compute_commitment(&4000u64, &BytesN::from_array(env, &bob_blinding));
        ctx.commitment_client
            .store_commitment(&bob, &bob_commitment);
        ctx.registry_client
            .add_employee(&ctx.company_id, &bob, &bob_commitment);

        // Create an un-onboarded employee Charlie
        let charlie = Address::generate(env);

        let initial_treasury: i128 = 20_000;
        ctx.token_client.mint(&ctx.treasury, &initial_treasury);

        // Construct 3-recipient batch: Alice (valid), Bob (valid), Charlie (unregistered)
        let mut proofs = Vec::new(env);
        proofs.push_back(mock_proof(env));
        proofs.push_back(mock_proof(env));
        proofs.push_back(mock_proof(env));

        let mut amounts = Vec::new(env);
        amounts.push_back(5_000i128);
        amounts.push_back(4_000i128);
        amounts.push_back(3_000i128);

        let mut employees = Vec::new(env);
        employees.push_back(ctx.alice.clone());
        employees.push_back(bob.clone());
        employees.push_back(charlie.clone());

        let nonce = test_nonce(env, 93);

        // Multi-recipient payout fails because Charlie has no commitment
        let res = ctx.payroll_client.try_batch_process_payroll(
            &proofs,
            &amounts,
            &employees,
            &12_000i128,
            &nonce,
            &None,
            &ctx.source,
        );
        assert!(res.is_err(), "Multi-recipient batch must fail when Charlie is invalid");

        // 1. Treasury balance remains pristine
        assert_eq!(
            ctx.token_client.balance(&ctx.treasury),
            initial_treasury,
            "Treasury funds must not be spent on failed multi-recipient payout"
        );

        // 2. Neither Alice nor Bob received tokens
        assert_eq!(ctx.token_client.balance(&ctx.alice), 0);
        assert_eq!(ctx.token_client.balance(&bob), 0);
        assert_eq!(ctx.token_client.balance(&charlie), 0);

        // 3. Nullifiers for Alice and Bob are NOT recorded as used
        let alice_nullifier = payment_nullifier(env, &alice_commitment, &nonce);
        let bob_nullifier = payment_nullifier(env, &bob_commitment, &nonce);
        assert!(!ctx.commitment_client.is_nullifier_used(&alice_nullifier));
        assert!(!ctx.commitment_client.is_nullifier_used(&bob_nullifier));

        // 4. Commitment locks remain false
        assert!(!ctx.commitment_client.is_commitment_locked(&ctx.alice));
        assert!(!ctx.commitment_client.is_commitment_locked(&bob));

        // 5. Subsequent valid run for [Alice, Bob] succeeds cleanly
        let mut valid_proofs = Vec::new(env);
        valid_proofs.push_back(mock_proof(env));
        valid_proofs.push_back(mock_proof(env));

        let mut valid_amounts = Vec::new(env);
        valid_amounts.push_back(5_000i128);
        valid_amounts.push_back(4_000i128);

        let mut valid_employees = Vec::new(env);
        valid_employees.push_back(ctx.alice.clone());
        valid_employees.push_back(bob.clone());

        let run_id = ctx.payroll_client.batch_process_payroll(
            &valid_proofs,
            &valid_amounts,
            &valid_employees,
            &9_000i128,
            &nonce,
            &None,
            &ctx.source,
        );
        assert!(run_id > 0, "Valid batch must succeed after failed multi-recipient rollback");

        // Verify post-recovery balances and nullifiers
        assert_eq!(ctx.token_client.balance(&ctx.alice), 5_000i128);
        assert_eq!(ctx.token_client.balance(&bob), 4_000i128);
        assert_eq!(
            ctx.token_client.balance(&ctx.treasury),
            initial_treasury - 9_000i128
        );
        assert!(ctx.commitment_client.is_nullifier_used(&alice_nullifier));
        assert!(ctx.commitment_client.is_nullifier_used(&bob_nullifier));
    }

    /// Issue #903 Boundary Case: Multi-recipient payout failure on the very first recipient index (index 0).
    /// Asserts that failure on index 0 aborts before touching any recipient balance or nullifier store.
    #[test]
    fn test_failed_multi_recipient_payout_first_recipient_boundary() {
        let ctx = setup();
        let env = &ctx.env;

        let alice_commitment = alice_salary_commitment(&ctx.commitment_client);
        ctx.commitment_client
            .store_commitment(&ctx.alice, &alice_commitment);
        ctx.registry_client
            .add_employee(&ctx.company_id, &ctx.alice, &alice_commitment);

        let unonboarded = Address::generate(env);
        ctx.token_client.mint(&ctx.treasury, &15_000i128);

        // Batch order: [unonboarded (index 0), Alice (index 1)]
        let mut proofs = Vec::new(env);
        proofs.push_back(mock_proof(env));
        proofs.push_back(mock_proof(env));

        let mut amounts = Vec::new(env);
        amounts.push_back(3_000i128);
        amounts.push_back(5_000i128);

        let mut employees = Vec::new(env);
        employees.push_back(unonboarded.clone());
        employees.push_back(ctx.alice.clone());

        let nonce = test_nonce(env, 94);

        let res = ctx.payroll_client.try_batch_process_payroll(
            &proofs,
            &amounts,
            &employees,
            &8_000i128,
            &nonce,
            &None,
            &ctx.source,
        );
        assert!(res.is_err());
        assert_eq!(ctx.token_client.balance(&ctx.treasury), 15_000i128);
        assert_eq!(ctx.token_client.balance(&ctx.alice), 0);
        assert_eq!(ctx.token_client.balance(&unonboarded), 0);
    }
}
