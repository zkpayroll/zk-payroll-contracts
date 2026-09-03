//! Issue #373: Cross-period payroll liability invariant tests.
//!
//! Proves that payroll liabilities, reservations, settlements, refunds, and
//! period-close reconciliation markers remain balanced across multiple payroll
//! periods.
//!
//! Core invariant (conservation of payroll obligations):
//!   total_liabilities == reserved + settled + released
//!
//! Where:
//!   - `reserved`  — funds locked for pending (prepared) payroll runs
//!   - `settled`   — finalized or batch-executed runs awaiting or past reconciliation
//!   - `released`  — cancelled runs whose reservations were refunded to treasury

use ::token::{Token, TokenClient};
use payroll::{
    Payroll, PayrollClient, PayrollRunState, ReconciliationStatus, RunDraftState,
};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, Symbol, Vec};

// ---------------------------------------------------------------------------
// Liability ledger — tracks reserved / settled / released across periods
// ---------------------------------------------------------------------------

/// Per-period payroll liability buckets used to verify cross-period balance.
#[derive(Clone, Debug, Default)]
struct PeriodLiability {
    reserved: i128,
    settled: i128,
    released: i128,
}

impl PeriodLiability {
    fn total(&self) -> i128 {
        self.reserved + self.settled + self.released
    }
}

/// Cross-period fixture aggregating liability state and on-chain clients.
struct CrossPeriodFixture<'a> {
    env: &'a Env,
    payroll: PayrollClient<'a>,
    admin: Address,
    token: Address,
    employee: Address,
    /// Cumulative payroll obligations ever recorded (prepare or execute).
    total_liabilities: i128,
    /// Per-period liability breakdown keyed by period label string.
    periods: [PeriodLiability; 4],
}

impl<'a> CrossPeriodFixture<'a> {
    fn total_reserved(&self) -> i128 {
        self.periods.iter().map(|p| p.reserved).sum()
    }

    fn assert_global_invariant(&self, context: &str) {
        let locked = self.payroll.get_locked_funds(&self.token);
        let cross_period_sum: i128 = self.periods.iter().map(|p| p.total()).sum();

        assert_eq!(
            self.total_liabilities, cross_period_sum,
            "{context}: liabilities must equal reserved + settled + released across all periods"
        );

        assert_eq!(
            locked,
            self.total_reserved(),
            "{context}: on-chain locked funds must match aggregate reserved bucket"
        );

        let summary = self.payroll.get_safe_treasury_summary(&self.token);
        assert_eq!(
            summary.reserved_balance,
            self.total_reserved(),
            "{context}: treasury summary reserved must match aggregate ledger"
        );
        assert_eq!(
            summary.available_balance,
            summary.total_balance - summary.reserved_balance - summary.blocked_balance,
            "{context}: available balance must be consistent"
        );
    }

    fn record_prepare(&mut self, period_idx: usize, amount: i128) {
        self.total_liabilities += amount;
        self.periods[period_idx].reserved += amount;
    }

    fn record_settle(&mut self, period_idx: usize, amount: i128) {
        self.periods[period_idx].reserved -= amount;
        self.periods[period_idx].settled += amount;
    }

    fn record_direct_settle(&mut self, period_idx: usize, amount: i128) {
        self.total_liabilities += amount;
        self.periods[period_idx].settled += amount;
    }

    fn record_release(&mut self, period_idx: usize, amount: i128) {
        self.periods[period_idx].reserved -= amount;
        self.periods[period_idx].released += amount;
    }
}

// ---------------------------------------------------------------------------
// Shared setup helpers
// ---------------------------------------------------------------------------

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

fn period_label(env: &Env, name: &str) -> Symbol {
    Symbol::new(env, name)
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

fn setup_cross_period_fixture(env: &Env) -> CrossPeriodFixture<'_> {
    env.mock_all_auths();

    let verifier_id = env.register_contract(None, ProofVerifier);
    let verifier_client = ProofVerifierClient::new(env, &verifier_id);
    verifier_client.init_verifier_admin(&Address::generate(env));
    verifier_client.initialize_verifier(&mock_vk(env));

    let commitment_id = env.register_contract(None, SalaryCommitmentContract);
    let commitment_client = SalaryCommitmentContractClient::new(env, &commitment_id);
    commitment_client.init_commitment_admin(&Address::generate(env));

    let token_id = env.register_contract(None, Token);
    let token_client = TokenClient::new(env, &token_id);

    let payroll_id = env.register_contract(None, Payroll);
    let payroll_client = PayrollClient::new(env, &payroll_id);

    let treasury = Address::generate(env);
    let admin = Address::generate(env);
    let treasury_owner = Address::generate(env);
    token_client.mint(&treasury, &2_000_000i128);

    payroll_client.initialize(
        &admin,
        &token_id,
        &verifier_id,
        &commitment_id,
        &treasury,
        &treasury_owner,
    );

    commitment_client.set_payroll_operator(&payroll_id);

    let employee = Address::generate(env);
    commitment_client.store_commitment(&employee, &BytesN::from_array(env, &[0u8; 32]));

    CrossPeriodFixture {
        env,
        payroll: payroll_client,
        admin,
        token: token_id,
        employee,
        total_liabilities: 0,
        periods: Default::default(),
    }
}

/// Close a payroll period by finalizing its draft and reconciling the run.
fn close_period_with_reconciliation(
    fixture: &mut CrossPeriodFixture<'_>,
    period_idx: usize,
    period_name: &str,
    draft_amount: i128,
    run_amount: i128,
    nonce_seed: u8,
) -> u64 {
    let env = fixture.env;
    let label = period_label(env, period_name);

    let draft_id = fixture.payroll.create_run_draft(
        &fixture.admin,
        &draft_amount,
        &1u32,
        &label,
    );
    fixture.payroll.finalize_run_draft(&fixture.admin, &draft_id);
    fixture.payroll.submit_run_draft(&fixture.admin, &draft_id);

    let draft = fixture.payroll.get_run_draft(&draft_id);
    assert_eq!(draft.state, RunDraftState::Submitted);
    assert_eq!(draft.period_label, label);

    let (proofs, amounts, employees) =
        single_payment_batch(env, &fixture.employee, run_amount);
    let run_id = fixture.payroll.batch_process_payroll(
        &proofs,
        &amounts,
        &employees,
        &run_amount,
        &test_nonce(env, nonce_seed),
        &None,
    );

    fixture.record_direct_settle(period_idx, run_amount);
    fixture.assert_global_invariant("after batch execution");

    fixture.payroll.update_reconciliation_status(
        &fixture.admin,
        &run_id,
        &ReconciliationStatus::Reconciled,
    );

    let run = fixture.payroll.get_payroll_run(&run_id);
    assert_eq!(run.reconciliation_status, ReconciliationStatus::Reconciled);
    assert_eq!(
        fixture.payroll.get_payroll_run_state(&run_id),
        PayrollRunState::Completed
    );

    fixture.assert_global_invariant("after period close reconciliation");
    run_id
}

// ---------------------------------------------------------------------------
// I-1. Multi-period mixed lifecycle — reservations, settlements, refunds
// ---------------------------------------------------------------------------

#[test]
fn test_cross_period_liability_balanced_after_mixed_lifecycle() {
    let env = Env::default();
    let mut fixture = setup_cross_period_fixture(&env);

    // Period 1 (2026-01): batch execute + reconcile (settled & closed)
    let run_p1 = close_period_with_reconciliation(
        &mut fixture,
        0,
        "2026-01",
        100_000,
        100_000,
        1,
    );
    assert!(run_p1 > 0);

    // Period 2 (2026-02): prepare then cancel (released / refunded reservation)
    let (proofs_p2, amounts_p2, employees_p2) =
        single_payment_batch(&env, &fixture.employee, 40_000);
    let run_p2 = fixture.payroll.prepare_payroll_run(
        &proofs_p2,
        &amounts_p2,
        &employees_p2,
        &40_000,
        &test_nonce(&env, 2),
        &None,
    );
    fixture.record_prepare(1, 40_000);
    fixture.assert_global_invariant("period 2 after prepare");

    fixture.payroll.cancel_payroll_run(
        &fixture.admin,
        &run_p2,
        &Symbol::new(&env, "recalc"),
    );
    fixture.record_release(1, 40_000);
    fixture.assert_global_invariant("period 2 after cancel refund");

    // Period 3 (2026-03): prepare then finalize (reserved -> settled)
    let (proofs_p3, amounts_p3, employees_p3) =
        single_payment_batch(&env, &fixture.employee, 25_000);
    let run_p3 = fixture.payroll.prepare_payroll_run(
        &proofs_p3,
        &amounts_p3,
        &employees_p3,
        &25_000,
        &test_nonce(&env, 3),
        &None,
    );
    fixture.record_prepare(2, 25_000);
    fixture.assert_global_invariant("period 3 after prepare");

    fixture.payroll.finalize_payroll_run(&fixture.admin, &run_p3);
    fixture.record_settle(2, 25_000);
    fixture.assert_global_invariant("period 3 after finalize settlement");

    // Period 4 (2026-04): direct batch execute, leave unreconciled
    let (proofs_p4, amounts_p4, employees_p4) =
        single_payment_batch(&env, &fixture.employee, 15_000);
    let run_p4 = fixture.payroll.batch_process_payroll(
        &proofs_p4,
        &amounts_p4,
        &employees_p4,
        &15_000,
        &test_nonce(&env, 4),
        &None,
    );
    fixture.record_direct_settle(3, 15_000);
    fixture.assert_global_invariant("period 4 after batch execute");

    let run_p4_record = fixture.payroll.get_payroll_run(&run_p4);
    assert_eq!(
        run_p4_record.reconciliation_status,
        ReconciliationStatus::Unreconciled
    );

    // Global cross-period invariant: liabilities == reserved + settled + released
    assert_eq!(fixture.total_liabilities, 100_000 + 40_000 + 25_000 + 15_000);
    let aggregate: i128 = fixture.periods.iter().map(|p| p.total()).sum();
    assert_eq!(fixture.total_liabilities, aggregate);

    // Period-level breakdown after mixed lifecycle outcomes.
    assert_eq!(fixture.periods[0].settled, 100_000);
    assert_eq!(fixture.periods[1].released, 40_000);
    assert_eq!(fixture.periods[2].settled, 25_000);
    assert_eq!(fixture.periods[3].settled, 15_000);
    assert_eq!(fixture.payroll.get_locked_funds(&fixture.token), 0);
}

// ---------------------------------------------------------------------------
// I-2. Closed periods preserve reconciliation markers
// ---------------------------------------------------------------------------

#[test]
fn test_closed_period_preserves_reconciliation_markers() {
    let env = Env::default();
    let mut fixture = setup_cross_period_fixture(&env);

    let run_id = close_period_with_reconciliation(
        &mut fixture,
        0,
        "2026-05",
        60_000,
        60_000,
        10,
    );

    // Simulate subsequent period activity that must not mutate closed markers.
    let (proofs, amounts, employees) = single_payment_batch(&env, &fixture.employee, 10_000);
    let _pending = fixture.payroll.prepare_payroll_run(
        &proofs,
        &amounts,
        &employees,
        &10_000,
        &test_nonce(&env, 11),
        &None,
    );
    fixture.record_prepare(1, 10_000);

    // Closed period reconciliation marker must remain intact.
    let closed_run = fixture.payroll.get_payroll_run(&run_id);
    assert_eq!(
        closed_run.reconciliation_status,
        ReconciliationStatus::Reconciled
    );
    assert_eq!(
        fixture.payroll.get_payroll_run_state(&run_id),
        PayrollRunState::Completed
    );
}

// ---------------------------------------------------------------------------
// I-3. Duplicate settlement attempts must fail
// ---------------------------------------------------------------------------

#[test]
fn test_duplicate_settlement_rejected() {
    let env = Env::default();
    let mut fixture = setup_cross_period_fixture(&env);

    let run_id = close_period_with_reconciliation(
        &mut fixture,
        0,
        "2026-06",
        30_000,
        30_000,
        20,
    );

    // First reconciliation already applied in close helper; replay must fail.
    let replay = fixture.payroll.try_update_reconciliation_status(
        &fixture.admin,
        &run_id,
        &ReconciliationStatus::Reconciled,
    );
    assert!(
        replay.is_err(),
        "duplicate settlement must be rejected for a Completed run"
    );

    // Attempting to move a reconciled run back to Failed must also fail.
    let reopen = fixture.payroll.try_update_reconciliation_status(
        &fixture.admin,
        &run_id,
        &ReconciliationStatus::Failed,
    );
    assert!(
        reopen.is_err(),
        "reopening a completed settlement must be rejected"
    );
}

// ---------------------------------------------------------------------------
// I-4. Duplicate refund (cancel) attempts must fail
// ---------------------------------------------------------------------------

#[test]
fn test_duplicate_refund_rejected() {
    let env = Env::default();
    let fixture = setup_cross_period_fixture(&env);

    let (proofs, amounts, employees) =
        single_payment_batch(&env, &fixture.employee, 20_000);
    let run_id = fixture.payroll.prepare_payroll_run(
        &proofs,
        &amounts,
        &employees,
        &20_000,
        &test_nonce(&env, 30),
        &None,
    );

    let reason = Symbol::new(&env, "duplicate_refund_test");
    fixture.payroll.cancel_payroll_run(&fixture.admin, &run_id, &reason);

    let status = fixture
        .payroll
        .get_cancelled_batch_status(&run_id)
        .expect("cancellation metadata must exist");
    assert!(status.is_cancelled);
    assert_eq!(status.total_amount, 20_000);

    // Second cancel attempt must fail — reservation already released.
    let duplicate = fixture.payroll.try_cancel_payroll_run_with_reason(
        &fixture.admin,
        &run_id,
        &reason,
    );
    assert!(
        duplicate.is_err(),
        "duplicate refund (cancel) must be rejected"
    );

    assert_eq!(fixture.payroll.get_locked_funds(&fixture.token), 0);
}

// ---------------------------------------------------------------------------
// I-5. Stale reservation cleanup
// ---------------------------------------------------------------------------

#[test]
fn test_stale_reservation_cleanup() {
    let env = Env::default();
    let fixture = setup_cross_period_fixture(&env);

    // Configure a short-lived reservation policy.
    fixture.payroll.set_reservation_expiry_policy(
        &fixture.admin,
        &fixture.token,
        &5_000i128,
        &3600u64,
    );

    let expiry_before = fixture
        .payroll
        .get_required_reservation_expiry(&fixture.token);
    assert_eq!(expiry_before.reserved_amount, 5_000);

    // Advance ledger time past expiry.
    env.ledger().set_timestamp(expiry_before.expires_at + 1);

    fixture.payroll.release_expired_reservation(&fixture.token);

    // Policy removed after cleanup; re-query must fail.
    let missing = fixture.payroll.try_get_required_reservation_expiry(&fixture.token);
    assert!(
        missing.is_err(),
        "stale reservation policy must be removed after cleanup"
    );
}

#[test]
#[should_panic(expected = "Reservation has not yet expired")]
fn test_stale_reservation_cleanup_rejects_unexpired() {
    let env = Env::default();
    let fixture = setup_cross_period_fixture(&env);

    fixture.payroll.set_reservation_expiry_policy(
        &fixture.admin,
        &fixture.token,
        &3_000i128,
        &86_400u64,
    );

    // Premature cleanup must fail.
    fixture.payroll.release_expired_reservation(&fixture.token);
}
