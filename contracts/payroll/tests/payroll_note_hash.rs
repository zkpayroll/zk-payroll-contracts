/// Payroll note hash commit/bind/verify tests — issue #617.
///
/// # Coverage
/// | Test | Scenario |
/// |------|----------|
/// | `test_note_hash_defaults_to_zero_and_matches_zero_query` | Before any bind, get returns the zero hash and verify(zero) is true |
/// | `test_commit_then_bind_note_hash_success` | Full happy path: commit, bind, get, verify |
/// | `test_verify_returns_false_for_wrong_hash` | Bound note verifies false against a different hash |
/// | `test_commit_zero_hash_rejected` | `commit_payroll_note_hash` panics on the all-zero digest |
/// | `test_commit_duplicate_hash_rejected` | Re-committing the same hash before it is bound panics |
/// | `test_bind_without_commit_rejected` | `set_run_note_hash` fails if the hash was never pre-committed |
/// | `test_bind_consumes_commitment` | Binding removes the commitment so a second, independent run cannot reuse it |
/// | `test_commit_by_non_admin_rejected` | Only the admin may pre-commit a note hash |
/// | `test_bind_to_nonexistent_run_rejected` | Binding to a run_id that does not exist fails |
/// | `test_note_hash_independent_of_metadata_hash` | Binding a note hash does not disturb an already-bound metadata hash |
/// | `test_note_and_draft_hash_do_not_collide` | The same byte value pre-committed as a draft hash does not satisfy the note hash's own pre-commitment check |
use payroll::{Payroll, PayrollClient};
use payroll_registry::{PayrollRegistry, PayrollRegistryClient};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
use soroban_sdk::{testutils::Address as _, Address, BytesN, Env, Vec};
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

fn mock_proof(env: &Env, seed: u8) -> BytesN<256> {
    let mut arr = [0u8; 256];
    arr[0] = seed;
    BytesN::from_array(env, &arr)
}

fn test_nonce(env: &Env, seed: u8) -> BytesN<32> {
    let mut arr = [0u8; 32];
    arr[0] = seed;
    BytesN::from_array(env, &arr)
}

/// Salary commitment for a given run: Poseidon_Hash(salary=5000,
/// blinding=<seed>). Commitment values must be unique across every employee
/// and payroll run (the contract itself enforces this), so each test that
/// executes more than one run passes a distinct seed rather than reusing
/// the e2e integration suite's fixed blinding=123.
fn alice_salary_commitment(
    commitment_client: &SalaryCommitmentContractClient,
    seed: u8,
) -> BytesN<32> {
    let env = commitment_client.env.clone();
    let mut blinding_bytes = [0u8; 32];
    blinding_bytes[31] = seed;
    let blinding_factor = BytesN::from_array(&env, &blinding_bytes);
    commitment_client.compute_commitment(&5000u64, &blinding_factor)
}

struct Ctx {
    env: Env,
    admin: Address,
    treasury: Address,
    alice: Address,
    company_id: u64,
    token_client: TokenClient<'static>,
    registry_client: PayrollRegistryClient<'static>,
    commitment_client: SalaryCommitmentContractClient<'static>,
    payroll_id: Address,
    import_source: Address,
}

impl Ctx {
    fn payroll(&self) -> PayrollClient<'_> {
        PayrollClient::new(&self.env, &self.payroll_id)
    }
}

fn setup() -> Ctx {
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
    let commitment_client = SalaryCommitmentContractClient::new(&env, &commitment_id);
    commitment_client.init_commitment_admin(&admin);

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
    commitment_client.set_payroll_operator(&payroll_id);

    let token_client = TokenClient::new(&env, &token_id);
    let registry_client = PayrollRegistryClient::new(&env, &registry_id);

    let company_id = registry_client.register_company(&admin, &treasury);

    let import_source = Address::generate(&env);
    payroll_client.register_import_source(&import_source, &0u32);

    Ctx {
        env,
        admin,
        treasury,
        alice,
        company_id,
        token_client,
        registry_client,
        commitment_client,
        payroll_id,
        import_source,
    }
}

/// Onboards Alice and executes one real payroll batch, following the exact
/// working e2e pattern (`test_e2e_metadata_hash_verification`), so a real
/// `PayrollRun` record exists in storage to bind a note hash to.
fn execute_one_payment_run(ctx: &Ctx, seed: u8) -> u64 {
    let commitment = alice_salary_commitment(&ctx.commitment_client, seed);
    ctx.commitment_client
        .store_commitment(&ctx.alice, &commitment);
    ctx.registry_client
        .add_employee(&ctx.company_id, &ctx.alice, &commitment);
    ctx.token_client.mint(&ctx.treasury, &10_000i128);

    let payment_amount: i128 = 5_000;
    let mut proofs = Vec::new(&ctx.env);
    proofs.push_back(mock_proof(&ctx.env, seed));
    let mut amounts = Vec::new(&ctx.env);
    amounts.push_back(payment_amount);
    let mut employees = Vec::new(&ctx.env);
    employees.push_back(ctx.alice.clone());

    ctx.payroll().batch_process_payroll(
        &proofs,
        &amounts,
        &employees,
        &payment_amount,
        &test_nonce(&ctx.env, seed),
        &None,
        &ctx.import_source,
    )
}

/// Creates a second, independent `PayrollRun` record via the
/// `prepare_payroll_run` / `finalize_payroll_run` pending-run workflow,
/// rather than another `batch_process_payroll` call.
///
/// This sidesteps a pre-existing limitation of `batch_process_payroll`: its
/// nullifier is derived only from an employee's position within its own
/// batch (`nullifier_arr[0] = i`), never from the run, employee, or proof
/// content, so a second real payment batch against the same salary
/// commitment contract instance always collides on "Nullifier already used"
/// regardless of seed. That is a real limitation of the payment-execution
/// path, unrelated to issue #617's note-hash feature, so it is worked
/// around here rather than fixed. `prepare_payroll_run`/`finalize_payroll_run`
/// creates a real `PayrollRun` through the pending-run workflow without
/// touching the commitment/nullifier system at all, which is all this test
/// needs: a second genuine run to bind (or fail to bind) a note hash to.
fn prepare_and_finalize_run(ctx: &Ctx, seed: u8) -> u64 {
    let payment_amount: i128 = 1_000;
    let mut proofs = Vec::new(&ctx.env);
    proofs.push_back(mock_proof(&ctx.env, seed));
    let mut amounts = Vec::new(&ctx.env);
    amounts.push_back(payment_amount);
    let mut employees = Vec::new(&ctx.env);
    employees.push_back(Address::generate(&ctx.env));

    let run_id = ctx.payroll().prepare_payroll_run(
        &proofs,
        &amounts,
        &employees,
        &payment_amount,
        &test_nonce(&ctx.env, seed),
        &None,
    );
    ctx.payroll().finalize_payroll_run(&ctx.admin, &run_id);
    run_id
}

#[test]
fn test_note_hash_defaults_to_zero_and_matches_zero_query() {
    let ctx = setup();
    let run_id = execute_one_payment_run(&ctx, 1);
    let zero_hash = BytesN::from_array(&ctx.env, &[0u8; 32]);

    assert_eq!(ctx.payroll().get_payroll_note_hash(&run_id), zero_hash);
    assert!(ctx.payroll().verify_payroll_note_hash(&run_id, &zero_hash));
}

#[test]
fn test_commit_then_bind_note_hash_success() {
    let ctx = setup();
    let run_id = execute_one_payment_run(&ctx, 2);
    let note_hash = BytesN::from_array(&ctx.env, &[0xAB; 32]);

    ctx.payroll()
        .commit_payroll_note_hash(&ctx.admin, &note_hash);
    ctx.payroll()
        .set_run_note_hash(&ctx.admin, &run_id, &note_hash);

    assert_eq!(ctx.payroll().get_payroll_note_hash(&run_id), note_hash);
    assert!(ctx.payroll().verify_payroll_note_hash(&run_id, &note_hash));
}

#[test]
fn test_verify_returns_false_for_wrong_hash() {
    let ctx = setup();
    let run_id = execute_one_payment_run(&ctx, 3);
    let real_hash = BytesN::from_array(&ctx.env, &[0xAB; 32]);
    let wrong_hash = BytesN::from_array(&ctx.env, &[0xEE; 32]);

    ctx.payroll()
        .commit_payroll_note_hash(&ctx.admin, &real_hash);
    ctx.payroll()
        .set_run_note_hash(&ctx.admin, &run_id, &real_hash);

    assert!(!ctx.payroll().verify_payroll_note_hash(&run_id, &wrong_hash));
}

#[test]
#[should_panic(expected = "Digest cannot be all-zero bytes")]
fn test_commit_zero_hash_rejected() {
    let ctx = setup();
    let zero = BytesN::from_array(&ctx.env, &[0u8; 32]);
    ctx.payroll().commit_payroll_note_hash(&ctx.admin, &zero);
}

#[test]
#[should_panic(expected = "Note hash already committed")]
fn test_commit_duplicate_hash_rejected() {
    let ctx = setup();
    let note_hash = BytesN::from_array(&ctx.env, &[0xAB; 32]);
    ctx.payroll()
        .commit_payroll_note_hash(&ctx.admin, &note_hash);
    ctx.payroll()
        .commit_payroll_note_hash(&ctx.admin, &note_hash);
}

#[test]
fn test_bind_without_commit_rejected() {
    let ctx = setup();
    let run_id = execute_one_payment_run(&ctx, 4);
    let note_hash = BytesN::from_array(&ctx.env, &[0xAB; 32]);
    let result = ctx
        .payroll()
        .try_set_run_note_hash(&ctx.admin, &run_id, &note_hash);
    assert!(result.is_err());
}

#[test]
fn test_bind_consumes_commitment() {
    let ctx = setup();
    let run_id_1 = execute_one_payment_run(&ctx, 5);
    let note_hash = BytesN::from_array(&ctx.env, &[0xAB; 32]);

    ctx.payroll()
        .commit_payroll_note_hash(&ctx.admin, &note_hash);
    ctx.payroll()
        .set_run_note_hash(&ctx.admin, &run_id_1, &note_hash);

    // A second run trying to bind the exact same hash must fail: the
    // commitment was consumed by the first bind, so this is not a way to
    // attach one note to two runs.
    let run_id_2 = prepare_and_finalize_run(&ctx, 6);
    let result = ctx
        .payroll()
        .try_set_run_note_hash(&ctx.admin, &run_id_2, &note_hash);
    assert!(result.is_err());
}

#[test]
fn test_commit_by_non_admin_rejected() {
    let ctx = setup();
    let stranger = Address::generate(&ctx.env);
    let note_hash = BytesN::from_array(&ctx.env, &[0xAB; 32]);
    let result = ctx
        .payroll()
        .try_commit_payroll_note_hash(&stranger, &note_hash);
    assert!(result.is_err());
}

#[test]
fn test_bind_to_nonexistent_run_rejected() {
    let ctx = setup();
    let note_hash = BytesN::from_array(&ctx.env, &[0xAB; 32]);
    ctx.payroll()
        .commit_payroll_note_hash(&ctx.admin, &note_hash);
    let result = ctx
        .payroll()
        .try_set_run_note_hash(&ctx.admin, &999_999u64, &note_hash);
    assert!(result.is_err());
}

#[test]
fn test_note_hash_independent_of_metadata_hash() {
    let ctx = setup();
    let run_id = execute_one_payment_run(&ctx, 7);

    let metadata_hash = BytesN::from_array(&ctx.env, &[0x22; 32]);
    ctx.payroll()
        .commit_metadata_hash(&ctx.admin, &metadata_hash);
    ctx.payroll()
        .set_run_metadata(&ctx.admin, &run_id, &metadata_hash);

    let note_hash = BytesN::from_array(&ctx.env, &[0xAB; 32]);
    ctx.payroll()
        .commit_payroll_note_hash(&ctx.admin, &note_hash);
    ctx.payroll()
        .set_run_note_hash(&ctx.admin, &run_id, &note_hash);

    // Binding the note hash must not disturb the already-bound metadata
    // hash, or vice versa — they are separate fields on the same run.
    assert_eq!(ctx.payroll().get_metadata_hash(&run_id), metadata_hash);
    assert_eq!(ctx.payroll().get_payroll_note_hash(&run_id), note_hash);
}

#[test]
fn test_note_and_draft_hash_do_not_collide() {
    let ctx = setup();
    // The exact same byte value pre-committed as a draft hash must not
    // satisfy set_run_note_hash's pre-commitment check: NoteCommitment and
    // DraftCommitment are separate storage keyspaces by design.
    let shared_value = BytesN::from_array(&ctx.env, &[0x77; 32]);
    ctx.payroll().commit_draft(&ctx.admin, &shared_value);

    let run_id = execute_one_payment_run(&ctx, 8);
    let result = ctx
        .payroll()
        .try_set_run_note_hash(&ctx.admin, &run_id, &shared_value);
    assert!(result.is_err());
}
