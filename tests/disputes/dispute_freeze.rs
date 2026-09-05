//! Dispute Freeze and Thaw Control Tests (issue #342)
//!
//! Verifies that an active payroll dispute freezes irreversible lifecycle
//! actions (finalize, archive, prune) for the disputed run, that only
//! authorized roles (the admin or an explicitly granted dispute authority)
//! may open or resolve disputes, and that a resolved dispute allows normal
//! lifecycle continuation.

use payroll::{DisputeStatus, Payroll, PayrollClient};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, Symbol, Vec};
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
    BytesN::from_array(env, &[1u8; 256])
}

fn test_nonce(env: &Env, seed: u8) -> BytesN<32> {
    let mut bytes = [0u8; 32];
    bytes[0] = seed;
    bytes[31] = 0xAA;
    BytesN::from_array(env, &bytes)
}

fn batch_root(env: &Env, seed: u8) -> BytesN<32> {
    let mut bytes = [0u8; 32];
    bytes[0] = seed;
    bytes[1] = 0xEE;
    BytesN::from_array(env, &bytes)
}

struct TestContext<'a> {
    env: Env,
    payroll_client: PayrollClient<'a>,
    admin: Address,
    employee: Address,
}

fn setup_test_context() -> TestContext<'static> {
    let env = Env::default();
    env.mock_all_auths();

    let verifier_id = env.register_contract(None, ProofVerifier);
    let verifier_client = ProofVerifierClient::new(&env, &verifier_id);
    let verifier_admin = Address::generate(&env);
    verifier_client.init_verifier_admin(&verifier_admin);
    verifier_client.initialize_verifier(&mock_vk(&env));

    let commitment_id = env.register_contract(None, SalaryCommitmentContract);
    let commitment_client = SalaryCommitmentContractClient::new(&env, &commitment_id);
    let commitment_admin = Address::generate(&env);
    commitment_client.init_commitment_admin(&commitment_admin);

    let token_id = env.register_contract(None, Token);
    let token_client = TokenClient::new(&env, &token_id);

    let payroll_id = env.register_contract(None, Payroll);
    let payroll_client = PayrollClient::new(&env, &payroll_id);

    let treasury = Address::generate(&env);
    let admin = Address::generate(&env);
    let treasury_owner = Address::generate(&env);

    token_client.mint(&treasury, &10_000_000i128);

    payroll_client.initialize(
        &admin,
        &token_id,
        &verifier_id,
        &commitment_id,
        &treasury,
        &treasury_owner,
    );

    commitment_client.set_payroll_operator(&payroll_id);

    let employee = Address::generate(&env);
    commitment_client.store_commitment(&employee, &BytesN::from_array(&env, &[0x42u8; 32]));

    TestContext {
        env,
        payroll_client,
        admin,
        employee,
    }
}

fn single_payment_batch(
    env: &Env,
    employee: &Address,
    amount: i128,
) -> (Vec<BytesN<256>>, Vec<i128>, Vec<Address>) {
    let mut proofs = Vec::new(env);
    proofs.push_back(mock_proof(env));
    let mut amounts = Vec::new(env);
    amounts.push_back(amount);
    let mut employees = Vec::new(env);
    employees.push_back(employee.clone());
    (proofs, amounts, employees)
}

/// Prepares a pending run and returns its run_id.
fn prepare_run(ctx: &TestContext, seed: u8, amount: i128) -> u64 {
    let (proofs, amounts, employees) = single_payment_batch(&ctx.env, &ctx.employee, amount);
    let nonce = test_nonce(&ctx.env, seed);
    ctx.payroll_client
        .prepare_payroll_run(&proofs, &amounts, &employees, &amount, &nonce, &None)
}

// ── Freeze: active disputes block irreversible lifecycle actions ───────────

#[test]
fn test_active_dispute_blocks_finalization() {
    let ctx = setup_test_context();
    let run_id = prepare_run(&ctx, 1, 10_000i128);

    let period = Symbol::new(&ctx.env, "PERIOD_2026_01");
    let root = batch_root(&ctx.env, 1);
    let reason = Symbol::new(&ctx.env, "DISCREPANCY");
    ctx.payroll_client
        .open_dispute(&ctx.admin, &run_id, &period, &root, &reason);

    assert!(ctx.payroll_client.is_run_disputed(&run_id));

    let result = ctx
        .payroll_client
        .try_finalize_payroll_run(&ctx.admin, &run_id);
    assert!(result.is_err(), "Finalizing a disputed run must fail");
}

#[test]
fn test_active_dispute_blocks_archival() {
    let ctx = setup_test_context();
    let run_id = prepare_run(&ctx, 2, 10_000i128);
    ctx.payroll_client.finalize_payroll_run(&ctx.admin, &run_id);

    let period = Symbol::new(&ctx.env, "PERIOD_2026_01");
    let root = batch_root(&ctx.env, 2);
    let reason = Symbol::new(&ctx.env, "DISCREPANCY");
    ctx.payroll_client
        .open_dispute(&ctx.admin, &run_id, &period, &root, &reason);

    let result = ctx
        .payroll_client
        .try_archive_payroll_run(&ctx.admin, &run_id);
    assert!(result.is_err(), "Archiving a disputed run must fail");
}

#[test]
fn test_active_dispute_blocks_pruning() {
    let ctx = setup_test_context();
    let run_id = prepare_run(&ctx, 3, 10_000i128);
    ctx.payroll_client.finalize_payroll_run(&ctx.admin, &run_id);
    ctx.payroll_client.archive_payroll_run(&ctx.admin, &run_id);

    let period = Symbol::new(&ctx.env, "PERIOD_2026_01");
    let root = batch_root(&ctx.env, 3);
    let reason = Symbol::new(&ctx.env, "DISCREPANCY");
    ctx.payroll_client
        .open_dispute(&ctx.admin, &run_id, &period, &root, &reason);

    let result = ctx
        .payroll_client
        .try_prune_payroll_run(&ctx.admin, &run_id);
    assert!(result.is_err(), "Pruning a disputed run must fail");
}

#[test]
fn test_pruning_requires_archived_run() {
    let ctx = setup_test_context();
    let run_id = prepare_run(&ctx, 4, 10_000i128);
    ctx.payroll_client.finalize_payroll_run(&ctx.admin, &run_id);

    // Not yet archived, so pruning must fail even without a dispute.
    let result = ctx
        .payroll_client
        .try_prune_payroll_run(&ctx.admin, &run_id);
    assert!(
        result.is_err(),
        "Pruning a non-archived run must fail regardless of dispute state"
    );
}

// ── Thaw: resolved disputes allow normal lifecycle continuation ────────────

#[test]
fn test_resolved_dispute_allows_finalization() {
    let ctx = setup_test_context();
    let run_id = prepare_run(&ctx, 5, 10_000i128);

    let period = Symbol::new(&ctx.env, "PERIOD_2026_01");
    let root = batch_root(&ctx.env, 5);
    let open_reason = Symbol::new(&ctx.env, "DISCREPANCY");
    let dispute_id =
        ctx.payroll_client
            .open_dispute(&ctx.admin, &run_id, &period, &root, &open_reason);

    let resolution_reason = Symbol::new(&ctx.env, "VERIFIED_OK");
    ctx.payroll_client
        .resolve_dispute(&ctx.admin, &dispute_id, &resolution_reason);

    assert!(!ctx.payroll_client.is_run_disputed(&run_id));

    // Finalization now proceeds normally.
    ctx.payroll_client.finalize_payroll_run(&ctx.admin, &run_id);
    let run = ctx.payroll_client.get_payroll_run(&run_id);
    assert_eq!(run.run_id, run_id);
}

#[test]
fn test_resolved_dispute_allows_archive_and_prune() {
    let ctx = setup_test_context();
    let run_id = prepare_run(&ctx, 6, 10_000i128);
    ctx.payroll_client.finalize_payroll_run(&ctx.admin, &run_id);

    let period = Symbol::new(&ctx.env, "PERIOD_2026_01");
    let root = batch_root(&ctx.env, 6);
    let open_reason = Symbol::new(&ctx.env, "DISCREPANCY");
    let dispute_id =
        ctx.payroll_client
            .open_dispute(&ctx.admin, &run_id, &period, &root, &open_reason);

    let resolution_reason = Symbol::new(&ctx.env, "VERIFIED_OK");
    ctx.payroll_client
        .resolve_dispute(&ctx.admin, &dispute_id, &resolution_reason);

    ctx.payroll_client.archive_payroll_run(&ctx.admin, &run_id);
    assert!(ctx.payroll_client.is_run_archived(&run_id));

    ctx.payroll_client.prune_payroll_run(&ctx.admin, &run_id);
    assert!(!ctx.payroll_client.is_run_archived(&run_id));
}

#[test]
fn test_dispute_record_scoped_to_employer_period_and_batch_root() {
    let ctx = setup_test_context();
    let run_id = prepare_run(&ctx, 7, 10_000i128);

    let period = Symbol::new(&ctx.env, "PERIOD_2026_02");
    let root = batch_root(&ctx.env, 7);
    let reason = Symbol::new(&ctx.env, "AMOUNT_MISMATCH");
    let dispute_id = ctx
        .payroll_client
        .open_dispute(&ctx.admin, &run_id, &period, &root, &reason);

    let dispute = ctx.payroll_client.get_dispute(&dispute_id);
    assert_eq!(dispute.run_id, run_id);
    assert_eq!(dispute.employer, ctx.admin);
    assert_eq!(dispute.period, period);
    assert_eq!(dispute.batch_root, root);
    assert_eq!(dispute.open_reason, reason);
    assert_eq!(dispute.status, DisputeStatus::Active);
    assert!(dispute.resolved_by.is_none());
}

#[test]
fn test_resolve_dispute_records_resolver_and_reason() {
    let ctx = setup_test_context();
    let run_id = prepare_run(&ctx, 8, 10_000i128);

    let period = Symbol::new(&ctx.env, "PERIOD_2026_02");
    let root = batch_root(&ctx.env, 8);
    let open_reason = Symbol::new(&ctx.env, "AMOUNT_MISMATCH");
    let dispute_id =
        ctx.payroll_client
            .open_dispute(&ctx.admin, &run_id, &period, &root, &open_reason);

    let resolution_reason = Symbol::new(&ctx.env, "CORRECTED_AND_VERIFIED");
    ctx.payroll_client
        .resolve_dispute(&ctx.admin, &dispute_id, &resolution_reason);

    let dispute = ctx.payroll_client.get_dispute(&dispute_id);
    assert_eq!(dispute.status, DisputeStatus::Resolved);
    assert_eq!(dispute.resolved_by, Some(ctx.admin.clone()));
    assert_eq!(dispute.resolution_reason, Some(resolution_reason));
    assert!(dispute.resolved_at.is_some());
}

// ── Authorization: only admin or a granted dispute authority may act ───────

#[test]
fn test_unauthorized_caller_cannot_open_dispute() {
    let ctx = setup_test_context();
    let run_id = prepare_run(&ctx, 9, 10_000i128);
    let outsider = Address::generate(&ctx.env);

    let period = Symbol::new(&ctx.env, "PERIOD_2026_01");
    let root = batch_root(&ctx.env, 9);
    let reason = Symbol::new(&ctx.env, "DISCREPANCY");

    let result = ctx
        .payroll_client
        .try_open_dispute(&outsider, &run_id, &period, &root, &reason);
    assert!(
        result.is_err(),
        "Unauthorized caller must not be able to open a dispute"
    );
}

#[test]
fn test_unauthorized_caller_cannot_resolve_dispute() {
    let ctx = setup_test_context();
    let run_id = prepare_run(&ctx, 10, 10_000i128);
    let outsider = Address::generate(&ctx.env);

    let period = Symbol::new(&ctx.env, "PERIOD_2026_01");
    let root = batch_root(&ctx.env, 10);
    let open_reason = Symbol::new(&ctx.env, "DISCREPANCY");
    let dispute_id =
        ctx.payroll_client
            .open_dispute(&ctx.admin, &run_id, &period, &root, &open_reason);

    let resolution_reason = Symbol::new(&ctx.env, "VERIFIED_OK");
    let result = ctx
        .payroll_client
        .try_resolve_dispute(&outsider, &dispute_id, &resolution_reason);
    assert!(
        result.is_err(),
        "Unauthorized caller must not be able to resolve a dispute"
    );

    // The run must remain frozen since the resolution attempt failed.
    assert!(ctx.payroll_client.is_run_disputed(&run_id));
}

#[test]
fn test_granted_dispute_authority_can_open_and_resolve() {
    let ctx = setup_test_context();
    let run_id = prepare_run(&ctx, 11, 10_000i128);
    let auditor = Address::generate(&ctx.env);

    // Not yet authorized.
    assert!(!ctx.payroll_client.is_dispute_authority(&auditor));

    ctx.payroll_client
        .add_dispute_authority(&ctx.admin, &auditor);
    assert!(ctx.payroll_client.is_dispute_authority(&auditor));

    let period = Symbol::new(&ctx.env, "PERIOD_2026_01");
    let root = batch_root(&ctx.env, 11);
    let open_reason = Symbol::new(&ctx.env, "DISCREPANCY");
    let dispute_id =
        ctx.payroll_client
            .open_dispute(&auditor, &run_id, &period, &root, &open_reason);

    assert!(ctx.payroll_client.is_run_disputed(&run_id));

    let resolution_reason = Symbol::new(&ctx.env, "VERIFIED_OK");
    ctx.payroll_client
        .resolve_dispute(&auditor, &dispute_id, &resolution_reason);

    assert!(!ctx.payroll_client.is_run_disputed(&run_id));
}

#[test]
fn test_removed_dispute_authority_cannot_open_dispute() {
    let ctx = setup_test_context();
    let run_id = prepare_run(&ctx, 12, 10_000i128);
    let auditor = Address::generate(&ctx.env);

    ctx.payroll_client
        .add_dispute_authority(&ctx.admin, &auditor);
    ctx.payroll_client
        .remove_dispute_authority(&ctx.admin, &auditor);
    assert!(!ctx.payroll_client.is_dispute_authority(&auditor));

    let period = Symbol::new(&ctx.env, "PERIOD_2026_01");
    let root = batch_root(&ctx.env, 12);
    let reason = Symbol::new(&ctx.env, "DISCREPANCY");

    let result = ctx
        .payroll_client
        .try_open_dispute(&auditor, &run_id, &period, &root, &reason);
    assert!(
        result.is_err(),
        "A revoked dispute authority must not be able to open a dispute"
    );
}

// ── Edge cases ───────────────────────────────────────────────────────────────

#[test]
fn test_cannot_open_duplicate_active_dispute_for_same_run() {
    let ctx = setup_test_context();
    let run_id = prepare_run(&ctx, 13, 10_000i128);

    let period = Symbol::new(&ctx.env, "PERIOD_2026_01");
    let root = batch_root(&ctx.env, 13);
    let reason = Symbol::new(&ctx.env, "DISCREPANCY");
    ctx.payroll_client
        .open_dispute(&ctx.admin, &run_id, &period, &root, &reason);

    let result = ctx
        .payroll_client
        .try_open_dispute(&ctx.admin, &run_id, &period, &root, &reason);
    assert!(
        result.is_err(),
        "A run must not be able to have two simultaneous active disputes"
    );
}

#[test]
fn test_cannot_resolve_already_resolved_dispute() {
    let ctx = setup_test_context();
    let run_id = prepare_run(&ctx, 14, 10_000i128);

    let period = Symbol::new(&ctx.env, "PERIOD_2026_01");
    let root = batch_root(&ctx.env, 14);
    let open_reason = Symbol::new(&ctx.env, "DISCREPANCY");
    let dispute_id =
        ctx.payroll_client
            .open_dispute(&ctx.admin, &run_id, &period, &root, &open_reason);

    let resolution_reason = Symbol::new(&ctx.env, "VERIFIED_OK");
    ctx.payroll_client
        .resolve_dispute(&ctx.admin, &dispute_id, &resolution_reason);

    let result =
        ctx.payroll_client
            .try_resolve_dispute(&ctx.admin, &dispute_id, &resolution_reason);
    assert!(
        result.is_err(),
        "Resolving an already-resolved dispute must fail"
    );
}

#[test]
fn test_cannot_open_dispute_for_nonexistent_run() {
    let ctx = setup_test_context();

    let period = Symbol::new(&ctx.env, "PERIOD_2026_01");
    let root = batch_root(&ctx.env, 15);
    let reason = Symbol::new(&ctx.env, "DISCREPANCY");

    let result = ctx
        .payroll_client
        .try_open_dispute(&ctx.admin, &999u64, &period, &root, &reason);
    assert!(
        result.is_err(),
        "Opening a dispute against a nonexistent run must fail"
    );
}

#[test]
fn test_dispute_can_be_opened_against_pending_run_before_finalization() {
    let ctx = setup_test_context();
    let run_id = prepare_run(&ctx, 16, 10_000i128);

    // Run is still pending (not finalized) at this point.
    let period = Symbol::new(&ctx.env, "PERIOD_2026_01");
    let root = batch_root(&ctx.env, 16);
    let reason = Symbol::new(&ctx.env, "PRE_FINALIZATION_HOLD");
    let dispute_id = ctx
        .payroll_client
        .open_dispute(&ctx.admin, &run_id, &period, &root, &reason);

    assert!(ctx.payroll_client.is_run_disputed(&run_id));
    let dispute = ctx.payroll_client.get_dispute(&dispute_id);
    assert_eq!(dispute.status, DisputeStatus::Active);
}
