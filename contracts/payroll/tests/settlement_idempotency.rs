/// Settlement idempotency lock tests — issue #358.
///
/// # Coverage
///
/// | Test | Acceptance criterion |
/// |------|----------------------|
/// | `test_settled_batch_marker_written_on_success` | `SettledBatch` key exists after a successful run |
/// | `test_is_settled_returns_true_after_run` | `is_settled()` is true after settlement |
/// | `test_is_settled_returns_false_before_run` | `is_settled()` is false before any settlement |
/// | `test_get_settled_at_returns_timestamp` | `get_settled_at()` returns the execution timestamp |
/// | `test_get_settled_at_returns_none_before_run` | `get_settled_at()` returns `None` for unsettled id |
/// | `test_duplicate_nonce_prevents_double_settlement` | Same nonce rejected → batch cannot pay twice |
/// | `test_duplicate_nonce_error_is_stable` | Duplicate attempt returns a consistent failure |
/// | `test_funds_not_transferred_on_duplicate_attempt` | Treasury balance unchanged after duplicate attempt |
/// | `test_employee_balance_unchanged_on_duplicate_attempt` | Employee balance unchanged after duplicate attempt |
/// | `test_retry_with_new_nonce_creates_independent_run` | Retry with fresh nonce → new independent run |
/// | `test_multiple_employees_settled_once_each` | Multi-employee batch — each paid exactly once |
/// | `test_read_confirmation_available_after_settlement` | `get_payroll_run` readable any number of times |
/// | `test_is_settled_multiple_reads_are_stable` | `is_settled()` idempotent across repeated calls |
/// | `test_distinct_run_ids_have_independent_settlement_state` | Two separate runs — each has its own marker |
/// | `test_settlement_marker_survives_reconciliation_update` | `SettledBatch` persists after status update |
/// | `test_settlement_marker_survives_overpayment_review` | `SettledBatch` persists through review lifecycle |
/// | `test_failed_batch_does_not_leave_settlement_marker` | Panicking batch rolls back `SettledBatch` write |
/// | `test_prepared_run_not_marked_settled` | `prepare_payroll_run` alone does not mark settled |
/// | `test_cancelled_run_not_marked_settled` | Cancelled pending run is never marked settled |
/// | `test_is_settled_for_nonexistent_run_returns_false` | Unknown run id → false, never panic |
use payroll::{Payroll, PayrollClient, ReconciliationStatus};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
use soroban_sdk::{testutils::Address as _, Address, BytesN, Env, Symbol, Vec};
use token::{Token, TokenClient};

// ── Shared helpers ─────────────────────────────────────────────────────────────

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

/// Build a deterministic 32-byte nonce from a single-byte seed.
/// Seeds must be unique across a test to avoid nonce collisions.
fn nonce(env: &Env, seed: u8) -> BytesN<32> {
    let mut arr = [0u8; 32];
    arr[0] = seed;
    BytesN::from_array(env, &arr)
}

/// All contracts wired up and ready. Clients are constructed on demand
/// using the stored contract IDs so tests stay concise.
struct Ctx {
    env: Env,
    admin: Address,
    treasury: Address,
    treasury_owner: Address,
    /// A pre-registered employee with a stored commitment.
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

    fn commitment(&self) -> SalaryCommitmentContractClient<'_> {
        SalaryCommitmentContractClient::new(&self.env, &self.commitment_id)
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

    // Fund the treasury and give the employee a salary commitment.
    token.mint(&treasury, &10_000_000i128);
    commitment.store_commitment(&employee, &BytesN::from_array(&env, &[0u8; 32]));

    Ctx {
        env,
        admin,
        treasury,
        treasury_owner,
        employee,
        payroll_id,
        token_id,
        commitment_id,
    }
}

/// Execute a single-employee batch and return the resulting `run_id`.
fn settle_one(ctx: &Ctx, employee: &Address, amount: i128, nonce_seed: u8) -> u64 {
    let mut proofs = Vec::new(&ctx.env);
    proofs.push_back(mock_proof(&ctx.env));
    let mut amounts = Vec::new(&ctx.env);
    amounts.push_back(amount);
    let mut employees = Vec::new(&ctx.env);
    employees.push_back(employee.clone());

    ctx.payroll().batch_process_payroll(
        &proofs,
        &amounts,
        &employees,
        &amount,
        &nonce(&ctx.env, nonce_seed),
        &None,
    )
}

// ── Settlement marker presence ─────────────────────────────────────────────────

/// After a successful `batch_process_payroll`, `SettledBatch` is written
/// and `is_settled()` reflects that.
#[test]
fn test_settled_batch_marker_written_on_success() {
    let ctx = setup();
    let run_id = settle_one(&ctx, &ctx.employee, 1_000, 1);

    assert!(
        ctx.payroll().is_settled(&run_id),
        "SettledBatch marker must exist after a successful settlement"
    );
}

#[test]
fn test_is_settled_returns_true_after_run() {
    let ctx = setup();
    let run_id = settle_one(&ctx, &ctx.employee, 500, 2);
    assert!(ctx.payroll().is_settled(&run_id));
}

#[test]
fn test_is_settled_returns_false_before_run() {
    let ctx = setup();
    // run_id 42 has never been executed — must return false without panic.
    assert!(!ctx.payroll().is_settled(&42u64));
}

/// `get_settled_at()` returns the ledger timestamp recorded at execution.
#[test]
fn test_get_settled_at_returns_timestamp() {
    let ctx = setup();
    let run_id = settle_one(&ctx, &ctx.employee, 1_000, 3);

    let ts = ctx
        .payroll()
        .get_settled_at(&run_id)
        .expect("get_settled_at must return Some after settlement");

    // In the Soroban test environment the ledger timestamp defaults to 0.
    // We just verify the value is present and consistent with get_payroll_run.
    let run = ctx.payroll().get_payroll_run(&run_id);
    assert_eq!(ts, run.executed_at, "settled_at and executed_at must match");
}

#[test]
fn test_get_settled_at_returns_none_before_run() {
    let ctx = setup();
    assert!(ctx.payroll().get_settled_at(&99u64).is_none());
}

// ── Duplicate-settlement prevention ───────────────────────────────────────────

/// The primary idempotency guard: submitting the same nonce a second time is
/// rejected before any funds move.  This simulates a network retry or a
/// user double-click.
#[test]
fn test_duplicate_nonce_prevents_double_settlement() {
    let ctx = setup();
    let shared_nonce = nonce(&ctx.env, 10);

    let mut proofs = Vec::new(&ctx.env);
    proofs.push_back(mock_proof(&ctx.env));
    let mut amounts = Vec::new(&ctx.env);
    amounts.push_back(1_000i128);
    let mut employees = Vec::new(&ctx.env);
    employees.push_back(ctx.employee.clone());

    // First call succeeds.
    ctx.payroll().batch_process_payroll(
        &proofs,
        &amounts,
        &employees,
        &1_000,
        &shared_nonce,
        &None,
    );

    // Second call with identical nonce must fail.
    let result = ctx.payroll().try_batch_process_payroll(
        &proofs,
        &amounts,
        &employees,
        &1_000,
        &shared_nonce,
        &None,
    );

    assert!(
        result.is_err(),
        "A duplicate settlement attempt must be rejected"
    );
}

/// The error returned by a duplicate attempt must be deterministic — callers
/// that catch the error and inspect it should always see the same signal.
#[test]
fn test_duplicate_nonce_error_is_stable() {
    let ctx = setup();
    let shared_nonce = nonce(&ctx.env, 11);

    let mut proofs = Vec::new(&ctx.env);
    proofs.push_back(mock_proof(&ctx.env));
    let mut amounts = Vec::new(&ctx.env);
    amounts.push_back(500i128);
    let mut employees = Vec::new(&ctx.env);
    employees.push_back(ctx.employee.clone());

    ctx.payroll()
        .batch_process_payroll(&proofs, &amounts, &employees, &500, &shared_nonce, &None);

    // Call the duplicate twice — both must fail, not only the first retry.
    let r1 = ctx.payroll().try_batch_process_payroll(
        &proofs,
        &amounts,
        &employees,
        &500,
        &shared_nonce,
        &None,
    );
    let r2 = ctx.payroll().try_batch_process_payroll(
        &proofs,
        &amounts,
        &employees,
        &500,
        &shared_nonce,
        &None,
    );

    assert!(r1.is_err(), "first duplicate must fail");
    assert!(r2.is_err(), "second duplicate must also fail");
}

/// After a rejected duplicate attempt, the treasury balance must be unchanged
/// relative to its state after the original settlement.
#[test]
fn test_funds_not_transferred_on_duplicate_attempt() {
    let ctx = setup();
    let shared_nonce = nonce(&ctx.env, 12);

    let mut proofs = Vec::new(&ctx.env);
    proofs.push_back(mock_proof(&ctx.env));
    let mut amounts = Vec::new(&ctx.env);
    amounts.push_back(2_000i128);
    let mut employees = Vec::new(&ctx.env);
    employees.push_back(ctx.employee.clone());

    ctx.payroll().batch_process_payroll(
        &proofs,
        &amounts,
        &employees,
        &2_000,
        &shared_nonce,
        &None,
    );

    let treasury_after_first = ctx.token().balance(&ctx.treasury);

    // Duplicate attempt — must fail, treasury must not change.
    let _ = ctx.payroll().try_batch_process_payroll(
        &proofs,
        &amounts,
        &employees,
        &2_000,
        &shared_nonce,
        &None,
    );

    assert_eq!(
        ctx.token().balance(&ctx.treasury),
        treasury_after_first,
        "Treasury balance must not change after a rejected duplicate"
    );
}

/// Employee balance is also unchanged after a rejected duplicate attempt.
#[test]
fn test_employee_balance_unchanged_on_duplicate_attempt() {
    let ctx = setup();
    let shared_nonce = nonce(&ctx.env, 13);

    let mut proofs = Vec::new(&ctx.env);
    proofs.push_back(mock_proof(&ctx.env));
    let mut amounts = Vec::new(&ctx.env);
    amounts.push_back(3_000i128);
    let mut employees = Vec::new(&ctx.env);
    employees.push_back(ctx.employee.clone());

    ctx.payroll().batch_process_payroll(
        &proofs,
        &amounts,
        &employees,
        &3_000,
        &shared_nonce,
        &None,
    );

    let employee_after_first = ctx.token().balance(&ctx.employee);

    let _ = ctx.payroll().try_batch_process_payroll(
        &proofs,
        &amounts,
        &employees,
        &3_000,
        &shared_nonce,
        &None,
    );

    assert_eq!(
        ctx.token().balance(&ctx.employee),
        employee_after_first,
        "Employee balance must not change after a rejected duplicate"
    );
}

// ── Safe retry paths ───────────────────────────────────────────────────────────

/// A legitimate retry (e.g. a fresh payroll cycle) that uses a brand-new
/// nonce and a fresh employee commitment must succeed and produce an
/// independent run with its own `run_id` and settlement marker.
#[test]
fn test_retry_with_new_nonce_creates_independent_run() {
    let ctx = setup();

    // Register a second employee so the second run has a different commitment
    // and does not collide on ZK nullifiers.
    let emp2 = Address::generate(&ctx.env);
    ctx.commitment()
        .store_commitment(&emp2, &BytesN::from_array(&ctx.env, &[1u8; 32]));

    let run_id_1 = settle_one(&ctx, &ctx.employee, 1_000, 20);

    let mut proofs = Vec::new(&ctx.env);
    proofs.push_back(mock_proof(&ctx.env));
    let mut amounts = Vec::new(&ctx.env);
    amounts.push_back(1_000i128);
    let mut employees = Vec::new(&ctx.env);
    employees.push_back(emp2.clone());

    let run_id_2 = ctx.payroll().batch_process_payroll(
        &proofs,
        &amounts,
        &employees,
        &1_000,
        &nonce(&ctx.env, 21), // different nonce — fresh run
        &None,
    );

    assert_ne!(run_id_1, run_id_2, "Each run must have a unique ID");
    assert!(ctx.payroll().is_settled(&run_id_1));
    assert!(ctx.payroll().is_settled(&run_id_2));
}

// ── Multi-employee batch ───────────────────────────────────────────────────────

/// A batch with several employees settles each exactly once; the single
/// `SettledBatch` marker covers the entire batch.
#[test]
fn test_multiple_employees_settled_once_each() {
    let ctx = setup();

    // Register extra employees.
    let emp2 = Address::generate(&ctx.env);
    let emp3 = Address::generate(&ctx.env);
    ctx.commitment()
        .store_commitment(&emp2, &BytesN::from_array(&ctx.env, &[2u8; 32]));
    ctx.commitment()
        .store_commitment(&emp3, &BytesN::from_array(&ctx.env, &[3u8; 32]));

    let mut proofs = Vec::new(&ctx.env);
    proofs.push_back(mock_proof(&ctx.env));
    proofs.push_back(mock_proof(&ctx.env));
    proofs.push_back(mock_proof(&ctx.env));

    let mut amounts = Vec::new(&ctx.env);
    amounts.push_back(500i128);
    amounts.push_back(600i128);
    amounts.push_back(700i128);

    let mut employees = Vec::new(&ctx.env);
    employees.push_back(ctx.employee.clone());
    employees.push_back(emp2.clone());
    employees.push_back(emp3.clone());

    let run_id = ctx.payroll().batch_process_payroll(
        &proofs,
        &amounts,
        &employees,
        &1_800,
        &nonce(&ctx.env, 30),
        &None,
    );

    assert!(ctx.payroll().is_settled(&run_id));

    // Verify the run recorded the correct employee count and total.
    let run = ctx.payroll().get_payroll_run(&run_id);
    assert_eq!(run.employee_count, 3);
    assert_eq!(run.total_amount, 1_800);

    // Retry with the same nonce must fail — no employee was paid twice.
    let dup = ctx.payroll().try_batch_process_payroll(
        &proofs,
        &amounts,
        &employees,
        &1_800,
        &nonce(&ctx.env, 30),
        &None,
    );
    assert!(
        dup.is_err(),
        "Duplicate multi-employee batch must be rejected"
    );
}

// ── Read-only confirmation ─────────────────────────────────────────────────────

/// `get_payroll_run` can be called repeatedly without side effects.
/// This is the stable read-only confirmation path required by the acceptance criteria.
#[test]
fn test_read_confirmation_available_after_settlement() {
    let ctx = setup();
    let run_id = settle_one(&ctx, &ctx.employee, 1_000, 40);

    // Read the run multiple times — each call must return consistent data.
    let run_a = ctx.payroll().get_payroll_run(&run_id);
    let run_b = ctx.payroll().get_payroll_run(&run_id);
    let run_c = ctx.payroll().get_payroll_run(&run_id);

    assert_eq!(run_a.run_id, run_id);
    assert_eq!(run_a.total_amount, run_b.total_amount);
    assert_eq!(run_b.reconciliation_status, run_c.reconciliation_status);
}

/// `is_settled()` must return the same value on every call after settlement.
#[test]
fn test_is_settled_multiple_reads_are_stable() {
    let ctx = setup();
    let run_id = settle_one(&ctx, &ctx.employee, 750, 41);

    for _ in 0..5 {
        assert!(
            ctx.payroll().is_settled(&run_id),
            "is_settled() must be stable across repeated reads"
        );
    }
}

// ── Independent settlement state ───────────────────────────────────────────────

/// Two separate payroll runs have independent settlement markers — checking
/// one does not affect the other.
#[test]
fn test_distinct_run_ids_have_independent_settlement_state() {
    let ctx = setup();

    let emp2 = Address::generate(&ctx.env);
    ctx.commitment()
        .store_commitment(&emp2, &BytesN::from_array(&ctx.env, &[4u8; 32]));

    let run_id_a = settle_one(&ctx, &ctx.employee, 1_000, 50);

    let mut proofs = Vec::new(&ctx.env);
    proofs.push_back(mock_proof(&ctx.env));
    let mut amounts = Vec::new(&ctx.env);
    amounts.push_back(1_000i128);
    let mut employees = Vec::new(&ctx.env);
    employees.push_back(emp2.clone());

    let run_id_b = ctx.payroll().batch_process_payroll(
        &proofs,
        &amounts,
        &employees,
        &1_000,
        &nonce(&ctx.env, 51),
        &None,
    );

    assert_ne!(run_id_a, run_id_b);
    assert!(ctx.payroll().is_settled(&run_id_a));
    assert!(ctx.payroll().is_settled(&run_id_b));

    // A fabricated id that was never settled must be false.
    let fake_id: u64 = 9999;
    assert!(!ctx.payroll().is_settled(&fake_id));
}

// ── Settlement marker durability ───────────────────────────────────────────────

/// Updating the reconciliation status of a run must not remove or alter the
/// `SettledBatch` marker.
#[test]
fn test_settlement_marker_survives_reconciliation_update() {
    let ctx = setup();
    let run_id = settle_one(&ctx, &ctx.employee, 1_000, 60);

    assert!(ctx.payroll().is_settled(&run_id));

    ctx.payroll().update_reconciliation_status(
        &ctx.admin,
        &run_id,
        &ReconciliationStatus::Reconciled,
    );

    assert!(
        ctx.payroll().is_settled(&run_id),
        "SettledBatch must persist after reconciliation status update"
    );
}

/// Opening and resolving an overpayment review must not remove or alter the
/// `SettledBatch` marker.
#[test]
fn test_settlement_marker_survives_overpayment_review() {
    let ctx = setup();
    let run_id = settle_one(&ctx, &ctx.employee, 1_000, 61);

    assert!(ctx.payroll().is_settled(&run_id));

    ctx.payroll().open_overpayment_review(&ctx.admin, &run_id);
    assert!(
        ctx.payroll().is_settled(&run_id),
        "SettledBatch must persist while a review is open"
    );

    ctx.payroll().resolve_overpayment_review(
        &ctx.admin,
        &run_id,
        &Symbol::new(&ctx.env, "confirmed_ok"),
    );
    assert!(
        ctx.payroll().is_settled(&run_id),
        "SettledBatch must persist after review is resolved"
    );
}

// ── Rollback on failure ────────────────────────────────────────────────────────

/// A batch that panics mid-execution (e.g. mismatched total spend) must NOT
/// leave a `SettledBatch` marker in storage, because Soroban transactions are
/// atomic and all writes roll back on panic.
#[test]
fn test_failed_batch_does_not_leave_settlement_marker() {
    let ctx = setup();

    let mut proofs = Vec::new(&ctx.env);
    proofs.push_back(mock_proof(&ctx.env));
    let mut amounts = Vec::new(&ctx.env);
    amounts.push_back(500i128);
    let mut employees = Vec::new(&ctx.env);
    employees.push_back(ctx.employee.clone());

    // Deliberately wrong expected_total_spend — causes a panic mid-execution.
    let wrong_total = 999i128;
    let result = ctx.payroll().try_batch_process_payroll(
        &proofs,
        &amounts,
        &employees,
        &wrong_total,
        &nonce(&ctx.env, 70),
        &None,
    );

    assert!(result.is_err(), "Mismatched total must cause failure");

    // No run should have been recorded; run_id 1 was never created.
    // We cannot predict the run_id from outside, but we can verify that no
    // settlement marker was written by checking the first possible id.
    assert!(
        !ctx.payroll().is_settled(&1u64),
        "A failed batch must not leave a SettledBatch marker"
    );
}

// ── Prepare/cancel do not mark settled ────────────────────────────────────────

/// `prepare_payroll_run` reserves a nonce and stores a `PendingRun` but must
/// NOT write a `SettledBatch` marker — settlement has not occurred yet.
#[test]
fn test_prepared_run_not_marked_settled() {
    let ctx = setup();

    let mut proofs = Vec::new(&ctx.env);
    proofs.push_back(mock_proof(&ctx.env));
    let mut amounts = Vec::new(&ctx.env);
    amounts.push_back(1_000i128);
    let mut employees = Vec::new(&ctx.env);
    employees.push_back(ctx.employee.clone());

    let run_id = ctx.payroll().prepare_payroll_run(
        &proofs,
        &amounts,
        &employees,
        &1_000,
        &nonce(&ctx.env, 80),
        &None,
    );

    assert!(
        !ctx.payroll().is_settled(&run_id),
        "A prepared-but-not-finalized run must not be marked settled"
    );
}

/// After a pending run is cancelled, it must not be marked settled.
#[test]
fn test_cancelled_run_not_marked_settled() {
    let ctx = setup();

    let mut proofs = Vec::new(&ctx.env);
    proofs.push_back(mock_proof(&ctx.env));
    let mut amounts = Vec::new(&ctx.env);
    amounts.push_back(1_000i128);
    let mut employees = Vec::new(&ctx.env);
    employees.push_back(ctx.employee.clone());

    let run_id = ctx.payroll().prepare_payroll_run(
        &proofs,
        &amounts,
        &employees,
        &1_000,
        &nonce(&ctx.env, 81),
        &None,
    );

    ctx.payroll().cancel_payroll_run(&ctx.admin, &run_id);

    assert!(
        !ctx.payroll().is_settled(&run_id),
        "A cancelled run must not be marked settled"
    );
}

// ── Edge cases ─────────────────────────────────────────────────────────────────

/// Querying `is_settled` for an id that was never created must return `false`
/// and must never panic.
#[test]
fn test_is_settled_for_nonexistent_run_returns_false() {
    let ctx = setup();

    assert!(!ctx.payroll().is_settled(&0u64));
    assert!(!ctx.payroll().is_settled(&1u64));
    assert!(!ctx.payroll().is_settled(&u64::MAX));
}
