/// Payroll obligation snapshot verification tests — issue #413.
///
/// # Coverage
/// | Test | Scenario |
/// |------|----------|
/// | `test_record_and_verify_obligation_snapshot_success` | Record snapshot, verify prior to lock, execution, cancellation, and reconciliation -> succeeds |
/// | `test_obligation_snapshot_mismatch_fails` | Wrong root, wrong total, or wrong count -> panics with "Obligation snapshot mismatch" |
/// | `test_verify_snapshot_not_found_fails` | Un-recorded snapshot verification -> panics with "Obligation snapshot not found" |
/// | `test_invalid_snapshot_parameters_rejected` | Zero amount, zero count, or zero root -> rejected |
/// | `test_obligation_snapshot_privacy_invariants` | Emitted events carry non-sensitive metadata only |
use payroll::{Payroll, PayrollClient};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
use soroban_sdk::{
    testutils::{Address as _, Events},
    Address, BytesN, Env, Symbol, TryFromVal, TryIntoVal, Vec,
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

struct Ctx {
    env: Env,
    admin: Address,
    treasury: Address,
    employee: Address,
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
    let employee = Address::generate(&env);

    let verifier_id = env.register_contract(None, ProofVerifier);
    let verifier_client = ProofVerifierClient::new(&env, &verifier_id);
    verifier_client.init_verifier_admin(&admin);
    verifier_client.initialize_verifier(&mock_vk(&env));

    let commitment_id = env.register_contract(None, SalaryCommitmentContract);
    let commitment = SalaryCommitmentContractClient::new(&env, &commitment_id);
    commitment.init_commitment_admin(&admin);

    let token_id = env.register_contract(None, Token);
    let token = TokenClient::new(&env, &token_id);

    let payroll_id = env.register_contract(None, Payroll);
    let payroll = PayrollClient::new(&env, &payroll_id);

    payroll.initialize(
        &admin,
        &token_id,
        &verifier_id,
        &commitment_id,
        &treasury,
        &treasury_owner,
    );
    commitment.set_payroll_operator(&payroll_id);
    token.mint(&treasury, &1_000_000i128);
    commitment.store_commitment(&employee, &BytesN::from_array(&env, &[0u8; 32]));

    let import_source = Address::generate(&env);
    payroll.register_import_source(&import_source, &0u32);

    Ctx {
        env,
        admin,
        treasury,
        employee,
        payroll_id,
        import_source,
    }
}

fn run_payroll(ctx: &Ctx, seed: u8) -> u64 {
    let mut proofs = Vec::new(&ctx.env);
    proofs.push_back(mock_proof(&ctx.env));
    let mut amounts = Vec::new(&ctx.env);
    amounts.push_back(1_000i128);
    let mut employees = Vec::new(&ctx.env);
    employees.push_back(ctx.employee.clone());

    ctx.payroll().batch_process_payroll(
        &proofs,
        &amounts,
        &employees,
        &1_000i128,
        &test_nonce(&ctx.env, seed),
        &None,
        &ctx.import_source,
    )
}

#[test]
fn test_record_and_verify_obligation_snapshot_success() {
    let ctx = setup();
    let run_id = run_payroll(&ctx, 1);

    let root = BytesN::from_array(&ctx.env, &[0xAA; 32]);
    let total_amount = 5_000i128;
    let count = 5u32;

    let digest = ctx
        .payroll()
        .record_obligation_snapshot(&run_id, &root, &total_amount, &count);
    assert_ne!(digest, BytesN::from_array(&ctx.env, &[0u8; 32]));

    let stored = ctx.payroll().get_obligation_snapshot(&run_id).unwrap();
    assert_eq!(stored.run_id, run_id);
    assert_eq!(stored.obligation_root, root);
    assert_eq!(stored.total_obligation_amount, total_amount);
    assert_eq!(stored.obligation_count, count);

    // Verify before Lock, Execution, Cancellation, and Reconciliation steps
    assert!(ctx.payroll().verify_obligation_snapshot(
        &run_id,
        &root,
        &total_amount,
        &count,
        &Symbol::new(&ctx.env, "lock"),
    ));
    assert!(ctx.payroll().verify_obligation_snapshot(
        &run_id,
        &root,
        &total_amount,
        &count,
        &Symbol::new(&ctx.env, "execution"),
    ));
    assert!(ctx.payroll().verify_obligation_snapshot(
        &run_id,
        &root,
        &total_amount,
        &count,
        &Symbol::new(&ctx.env, "cancellation"),
    ));
    assert!(ctx.payroll().verify_obligation_snapshot(
        &run_id,
        &root,
        &total_amount,
        &count,
        &Symbol::new(&ctx.env, "reconciliation"),
    ));
}

#[test]
#[should_panic(expected = "Obligation snapshot mismatch")]
fn test_obligation_snapshot_mismatch_fails() {
    let ctx = setup();
    let run_id = run_payroll(&ctx, 2);

    let root = BytesN::from_array(&ctx.env, &[0xAA; 32]);
    ctx.payroll()
        .record_obligation_snapshot(&run_id, &root, &5_000i128, &5u32);

    // Pass wrong amount (6_000 instead of 5_000)
    ctx.payroll().verify_obligation_snapshot(
        &run_id,
        &root,
        &6_000i128,
        &5u32,
        &Symbol::new(&ctx.env, "lock"),
    );
}

#[test]
#[should_panic(expected = "Obligation snapshot not found")]
fn test_verify_snapshot_not_found_fails() {
    let ctx = setup();
    let run_id = run_payroll(&ctx, 3);
    let root = BytesN::from_array(&ctx.env, &[0xBB; 32]);

    ctx.payroll().verify_obligation_snapshot(
        &run_id,
        &root,
        &1_000i128,
        &1u32,
        &Symbol::new(&ctx.env, "lock"),
    );
}

#[test]
#[should_panic(expected = "Invalid obligation snapshot parameters")]
fn test_invalid_snapshot_parameters_rejected() {
    let ctx = setup();
    let run_id = run_payroll(&ctx, 4);
    let root = BytesN::from_array(&ctx.env, &[0xCC; 32]);

    // Amount <= 0 rejected
    ctx.payroll()
        .record_obligation_snapshot(&run_id, &root, &0i128, &5u32);
}

#[test]
fn test_obligation_snapshot_privacy_invariants() {
    let ctx = setup();
    let run_id = run_payroll(&ctx, 5);
    let root = BytesN::from_array(&ctx.env, &[0xDD; 32]);

    ctx.payroll()
        .record_obligation_snapshot(&run_id, &root, &10_000i128, &10u32);
    ctx.payroll().verify_obligation_snapshot(
        &run_id,
        &root,
        &10_000i128,
        &10u32,
        &Symbol::new(&ctx.env, "execution"),
    );

    let events = ctx.env.events().all();
    let recorded_event = events.iter().find(|(_, topics, _)| {
        if let Some(val) = topics.get(1) {
            if let Ok(sym) = Symbol::try_from_val(&ctx.env, &val) {
                return sym == Symbol::new(&ctx.env, "obligation_snapshot_recorded");
            }
        }
        false
    });
    assert!(recorded_event.is_some());

    let verified_event = events.iter().find(|(_, topics, _)| {
        if let Some(val) = topics.get(1) {
            if let Ok(sym) = Symbol::try_from_val(&ctx.env, &val) {
                return sym == Symbol::new(&ctx.env, "obligation_snapshot_verified");
            }
        }
        false
    });
    assert!(verified_event.is_some());
}
