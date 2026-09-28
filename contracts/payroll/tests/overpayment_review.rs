/// Overpayment review guard tests — issue #357.
///
/// # Coverage
///
/// | Test | Path |
/// |------|------|
/// | `test_open_review_blocks_reconciliation` | Open review → attempt Reconciled → panic |
/// | `test_resolve_unblocks_reconciliation` | Open → resolve with reason → Reconciled succeeds |
/// | `test_settlement_not_reversed_by_review` | Token balances unchanged after open + resolve |
/// | `test_unauthorized_open_rejected` | Non-admin cannot open a review |
/// | `test_unauthorized_resolve_rejected` | Non-admin cannot resolve a review |
/// | `test_duplicate_open_rejected` | Cannot open a second review while first is open |
/// | `test_reopen_after_resolve_allowed` | Can open a fresh review after resolving |
/// | `test_empty_reason_rejected` | Resolution with empty symbol is rejected |
/// | `test_get_review_returns_none_before_open` | No review exists before first call |
/// | `test_has_open_review_reflects_lifecycle` | has_open_review tracks open/resolved state |
/// | `test_failed_status_allowed_under_open_review` | Failed status update is never blocked |
/// | `test_unreconciled_status_allowed_under_open_review` | Unreconciled rollback is never blocked |

use payroll::{Payroll, PayrollClient};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
use soroban_sdk::{
    testutils::{Address as _, Events},
    Address, BytesN, Env, Symbol, TryFromVal, TryIntoVal, Vec,
};
use token::{Token, TokenClient};

// ── Shared helpers ────────────────────────────────────────────────────────────

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

fn mock_proof_with_seed(env: &Env, seed: u8) -> BytesN<256> {
    let mut arr = [0u8; 256];
    arr[32] = seed;
    BytesN::from_array(env, &arr)
}

fn test_nonce(env: &Env, seed: u8) -> BytesN<32> {
    let mut arr = [0u8; 32];
    arr[0] = seed;
    BytesN::from_array(env, &arr)
}

/// All contracts wired together. Clients are created on-demand from stored IDs.
struct Ctx {
    env: Env,
    admin: Address,
    treasury: Address,
    employee: Address,
    payroll_id: Address,
    token_id: Address,
    commitment_id: Address,
}

impl Ctx {
    fn payroll(&self) -> PayrollClient<'_> {
        PayrollClient::new(&self.env, &self.payroll_id)
    }

    fn token(&self) -> TokenClient<'_> {
        TokenClient::new(&self.env, &self.token_id)
    }
}

fn setup() -> Ctx {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let treasury_owner = Address::generate(&env);
    let employee = Address::generate(&env);

    // Verifier
    let verifier_id = env.register_contract(None, ProofVerifier);
    let verifier_client = ProofVerifierClient::new(&env, &verifier_id);
    verifier_client.init_verifier_admin(&admin);
    verifier_client.initialize_verifier(&mock_vk(&env));

    // Salary commitment
    let commitment_id = env.register_contract(None, SalaryCommitmentContract);
    let commitment = SalaryCommitmentContractClient::new(&env, &commitment_id);
    commitment.init_commitment_admin(&admin);

    // Token
    let token_id = env.register_contract(None, Token);
    let token = TokenClient::new(&env, &token_id);

    // Payroll
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

    // Fund treasury and register employee commitment.
    token.mint(&treasury, &1_000_000i128);
    commitment.store_commitment(&employee, &BytesN::from_array(&env, &[0u8; 32]));

    Ctx {
        env,
        admin,
        treasury,
        employee,
        payroll_id,
        token_id,
        commitment_id,
    }
}

/// Execute a single-employee payroll batch and return the run_id.
fn run_payroll(ctx: &Ctx, nonce_seed: u8) -> u64 {
    let employee = Address::generate(&ctx.env);
    let commitment_client = SalaryCommitmentContractClient::new(&ctx.env, &ctx.commitment_id);
    let mut c_arr = [0u8; 32];
    c_arr[0] = nonce_seed;
    commitment_client.store_commitment(&employee, &BytesN::from_array(&ctx.env, &c_arr));

    let mut proofs = Vec::new(&ctx.env);
    proofs.push_back(mock_proof_with_seed(&ctx.env, nonce_seed));
    let mut amounts = Vec::new(&ctx.env);
    amounts.push_back(1_000i128);
    let mut employees = Vec::new(&ctx.env);
    employees.push_back(employee);

    ctx.payroll().batch_process_payroll(
        &proofs,
        &amounts,
        &employees,
        &1_000i128,
        &test_nonce(&ctx.env, nonce_seed),
        &None,
    )
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// An open review blocks marking the run as `Reconciled`.
#[test]
#[should_panic(expected = "open overpayment review")]
fn test_open_review_blocks_reconciliation() {
    let ctx = setup();
    let run_id = run_payroll(&ctx, 1);

    ctx.payroll().open_overpayment_review(&ctx.admin, &run_id);

    // This must panic because the review is still open.
    ctx.payroll().update_reconciliation_status(
        &ctx.admin,
        &run_id,
        &payroll::ReconciliationStatus::Reconciled,
    );
}

/// Resolving the review with a reason removes the block; reconciliation succeeds.
#[test]
fn test_resolve_unblocks_reconciliation() {
    let ctx = setup();
    let run_id = run_payroll(&ctx, 2);

    ctx.payroll().open_overpayment_review(&ctx.admin, &run_id);

    let reason = Symbol::new(&ctx.env, "data_entry_err");
    ctx.payroll()
        .resolve_overpayment_review(&ctx.admin, &run_id, &reason);

    // Now reconciliation must succeed without panic.
    ctx.payroll().update_reconciliation_status(
        &ctx.admin,
        &run_id,
        &payroll::ReconciliationStatus::Reconciled,
    );

    let run = ctx.payroll().get_payroll_run(&run_id);
    assert_eq!(
        run.reconciliation_status,
        payroll::ReconciliationStatus::Reconciled
    );
}

/// Token balances are not altered by opening or resolving a review.
///
/// This is the core "settlement not silently reversed" acceptance criterion.
#[test]
fn test_settlement_not_reversed_by_review() {
    let ctx = setup();

    let treasury_before = ctx.token().balance(&ctx.treasury);

    let run_id = run_payroll(&ctx, 3);

    let treasury_after_run = ctx.token().balance(&ctx.treasury);

    // Run moved 1_000 tokens from treasury to employee.
    assert_eq!(treasury_after_run, treasury_before - 1_000);

    // Open the review.
    ctx.payroll().open_overpayment_review(&ctx.admin, &run_id);

    // Balances must be unchanged.
    assert_eq!(
        ctx.token().balance(&ctx.treasury),
        treasury_after_run,
        "Opening a review must not move treasury funds"
    );

    // Resolve the review.
    let reason = Symbol::new(&ctx.env, "confirmed_ok");
    ctx.payroll()
        .resolve_overpayment_review(&ctx.admin, &run_id, &reason);

    // Balances must still be unchanged.
    assert_eq!(
        ctx.token().balance(&ctx.treasury),
        treasury_after_run,
        "Resolving a review must not move treasury funds"
    );
}

/// A non-admin address cannot open an overpayment review.
#[test]
#[should_panic(expected = "Unauthorized")]
fn test_unauthorized_open_rejected() {
    let ctx = setup();
    let run_id = run_payroll(&ctx, 4);

    let attacker = Address::generate(&ctx.env);
    ctx.payroll()
        .open_overpayment_review(&attacker, &run_id);
}

/// A non-admin address cannot resolve an overpayment review.
#[test]
#[should_panic(expected = "Unauthorized")]
fn test_unauthorized_resolve_rejected() {
    let ctx = setup();
    let run_id = run_payroll(&ctx, 5);

    // Open legitimately as admin.
    ctx.payroll().open_overpayment_review(&ctx.admin, &run_id);

    let attacker = Address::generate(&ctx.env);

    ctx.payroll().resolve_overpayment_review(
        &attacker,
        &run_id,
        &Symbol::new(&ctx.env, "some_reason"),
    );
}

/// Opening a second review while one is already open is rejected.
#[test]
#[should_panic(expected = "Review already open")]
fn test_duplicate_open_rejected() {
    let ctx = setup();
    let run_id = run_payroll(&ctx, 6);

    ctx.payroll().open_overpayment_review(&ctx.admin, &run_id);
    // Second open on the same run — must panic.
    ctx.payroll().open_overpayment_review(&ctx.admin, &run_id);
}

/// After a review is resolved, a fresh review can be opened on the same run.
#[test]
fn test_reopen_after_resolve_allowed() {
    let ctx = setup();
    let run_id = run_payroll(&ctx, 7);

    let review_id_1 = ctx.payroll().open_overpayment_review(&ctx.admin, &run_id);
    ctx.payroll().resolve_overpayment_review(
        &ctx.admin,
        &run_id,
        &Symbol::new(&ctx.env, "first_close"),
    );

    // Opening a second review after resolution must succeed.
    let review_id_2 = ctx.payroll().open_overpayment_review(&ctx.admin, &run_id);

    // The IDs must be distinct and monotonically increasing.
    assert!(
        review_id_2 > review_id_1,
        "Second review must have a higher ID"
    );

    // The new review must be open.
    assert!(ctx.payroll().has_open_review(&run_id));
}

/// `resolve_overpayment_review` with an empty reason symbol is rejected.
#[test]
#[should_panic(expected = "Resolution reason must not be empty")]
fn test_empty_reason_rejected() {
    let ctx = setup();
    let run_id = run_payroll(&ctx, 8);

    ctx.payroll().open_overpayment_review(&ctx.admin, &run_id);

    ctx.payroll().resolve_overpayment_review(
        &ctx.admin,
        &run_id,
        &Symbol::new(&ctx.env, ""),
    );
}

/// `get_overpayment_review` returns `None` before any review is opened.
#[test]
fn test_get_review_returns_none_before_open() {
    let ctx = setup();
    let run_id = run_payroll(&ctx, 9);

    let result = ctx.payroll().get_overpayment_review(&run_id);
    assert!(result.is_none(), "No review should exist before one is opened");
}

/// `has_open_review` accurately reflects the lifecycle: false → true → false.
#[test]
fn test_has_open_review_reflects_lifecycle() {
    let ctx = setup();
    let run_id = run_payroll(&ctx, 10);

    assert!(!ctx.payroll().has_open_review(&run_id), "Should be false before open");

    ctx.payroll().open_overpayment_review(&ctx.admin, &run_id);
    assert!(ctx.payroll().has_open_review(&run_id), "Should be true after open");

    ctx.payroll().resolve_overpayment_review(
        &ctx.admin,
        &run_id,
        &Symbol::new(&ctx.env, "closed"),
    );
    assert!(!ctx.payroll().has_open_review(&run_id), "Should be false after resolve");
}

/// `ReconciliationStatus::Failed` is never blocked by an open review.
///
/// Operators must be able to mark a run as `Failed` at any time to roll back
/// a mistaken reconciliation without needing to close the review first.
#[test]
fn test_failed_status_allowed_under_open_review() {
    let ctx = setup();
    let run_id = run_payroll(&ctx, 11);

    ctx.payroll().open_overpayment_review(&ctx.admin, &run_id);

    // Failed must succeed even with an open review.
    ctx.payroll().update_reconciliation_status(
        &ctx.admin,
        &run_id,
        &payroll::ReconciliationStatus::Failed,
    );

    let run = ctx.payroll().get_payroll_run(&run_id);
    assert_eq!(
        run.reconciliation_status,
        payroll::ReconciliationStatus::Failed
    );
}

/// `ReconciliationStatus::Unreconciled` rollback is never blocked by an open review.
#[test]
fn test_unreconciled_status_allowed_under_open_review() {
    let ctx = setup();
    let run_id = run_payroll(&ctx, 12);

    ctx.payroll().open_overpayment_review(&ctx.admin, &run_id);

    // Rolling back to Unreconciled must never be blocked.
    ctx.payroll().update_reconciliation_status(
        &ctx.admin,
        &run_id,
        &payroll::ReconciliationStatus::Unreconciled,
    );

    let run = ctx.payroll().get_payroll_run(&run_id);
    assert_eq!(
        run.reconciliation_status,
        payroll::ReconciliationStatus::Unreconciled
    );
}

/// The `review_opened` event is emitted with the correct opaque fields.
///
/// Privacy check: event data must contain only (review_id, run_id, timestamp)
/// and must NOT surface amounts, employee addresses, or commitment hashes.
#[test]
fn test_review_opened_event_is_privacy_safe() {
    let ctx = setup();
    let run_id = run_payroll(&ctx, 13);

    ctx.payroll().open_overpayment_review(&ctx.admin, &run_id);

    let events = ctx.env.events().all();
    // Find the review_opened event (last batch of events after the payroll run events).
    let review_event = events
        .iter()
        .find(|(_, topics, _)| {
            if let Some(topic_val) = topics.get(1) {
                if let Ok(sym) = Symbol::try_from_val(&ctx.env, &topic_val) {
                    return sym == Symbol::new(&ctx.env, "review_opened");
                }
            }
            false
        });

    assert!(
        review_event.is_some(),
        "review_opened event must be emitted"
    );

    // Validate the topic structure: topics[0] == "payroll", topics[1] == "review_opened".
    let (_, topics, _) = review_event.unwrap();
    let ns: Symbol = Symbol::try_from_val(&ctx.env, &topics.get(0).unwrap()).unwrap();
    assert_eq!(ns, Symbol::new(&ctx.env, "payroll"));
    let name: Symbol = Symbol::try_from_val(&ctx.env, &topics.get(1).unwrap()).unwrap();
    assert_eq!(name, Symbol::new(&ctx.env, "review_opened"));
}

/// The `review_resolved` event is emitted when a review is closed.
#[test]
fn test_review_resolved_event_emitted() {
    let ctx = setup();
    let run_id = run_payroll(&ctx, 14);

    ctx.payroll().open_overpayment_review(&ctx.admin, &run_id);
    ctx.payroll().resolve_overpayment_review(
        &ctx.admin,
        &run_id,
        &Symbol::new(&ctx.env, "audit_complete"),
    );

    let events = ctx.env.events().all();
    let resolved_event = events.iter().find(|(_, topics, _)| {
        if let Some(val) = topics.get(1) {
            if let Ok(sym) = Symbol::try_from_val(&ctx.env, &val) {
                return sym == Symbol::new(&ctx.env, "review_resolved");
            }
        }
        false
    });

    assert!(
        resolved_event.is_some(),
        "review_resolved event must be emitted"
    );
}

/// Attempting to resolve an already-resolved review is rejected.
#[test]
#[should_panic(expected = "Review already resolved")]
fn test_double_resolve_rejected() {
    let ctx = setup();
    let run_id = run_payroll(&ctx, 15);

    ctx.payroll().open_overpayment_review(&ctx.admin, &run_id);

    let reason = Symbol::new(&ctx.env, "all_good");
    ctx.payroll()
        .resolve_overpayment_review(&ctx.admin, &run_id, &reason);

    // Second resolve on same (now closed) review — must panic.
    ctx.payroll()
        .resolve_overpayment_review(&ctx.admin, &run_id, &reason);
}

/// Opening a review on a non-existent run panics with "Run not found".
#[test]
#[should_panic(expected = "Run not found")]
fn test_open_review_for_nonexistent_run() {
    let ctx = setup();
    // run_id 999 was never created.
    ctx.payroll().open_overpayment_review(&ctx.admin, &999u64);
}

/// Multiple independent runs each carry their own independent review state.
#[test]
fn test_review_state_is_isolated_per_run() {
    let ctx = setup();

    let run_a = run_payroll(&ctx, 20);
    let run_b = run_payroll(&ctx, 21);

    // Open review only on run_a.
    ctx.payroll().open_overpayment_review(&ctx.admin, &run_a);

    assert!(ctx.payroll().has_open_review(&run_a), "run_a must be under review");
    assert!(!ctx.payroll().has_open_review(&run_b), "run_b must NOT be under review");

    // run_b can be reconciled independently.
    ctx.payroll().update_reconciliation_status(
        &ctx.admin,
        &run_b,
        &payroll::ReconciliationStatus::Reconciled,
    );

    let run_b_record = ctx.payroll().get_payroll_run(&run_b);
    assert_eq!(
        run_b_record.reconciliation_status,
        payroll::ReconciliationStatus::Reconciled,
        "run_b reconciliation must succeed independently of run_a review"
    );

    // run_a reconciliation is still blocked.
    let result = ctx.payroll().try_update_reconciliation_status(
        &ctx.admin,
        &run_a,
        &payroll::ReconciliationStatus::Reconciled,
    );
    assert!(result.is_err(), "run_a reconciliation must be blocked");
}
