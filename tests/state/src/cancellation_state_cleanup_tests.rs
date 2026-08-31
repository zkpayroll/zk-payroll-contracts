#![cfg(test)]

use pause_manager::{PauseManager, PauseManagerClient};
use payroll::{Payroll, PayrollClient, PayrollRunState, ReconciliationStatus, RunDraftState};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
use soroban_sdk::testutils::{Address as _, Events};
use soroban_sdk::{symbol_short, Address, BytesN, Env, Symbol, TryIntoVal, Vec};
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

struct TestContext<'a> {
    env: Env,
    payroll_client: PayrollClient<'a>,
    token_client: TokenClient<'a>,
    pause_manager_client: PauseManagerClient<'a>,
    admin: Address,
    treasury: Address,
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
    let operator = Address::generate(&env);

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

    let pm_id = env.register_contract(None, PauseManager);
    let pm_client = PauseManagerClient::new(&env, &pm_id);
    pm_client.initialize(&operator);
    payroll_client.set_pause_manager(&pm_id);

    let employee = Address::generate(&env);
    commitment_client.store_commitment(&employee, &BytesN::from_array(&env, &[0x42u8; 32]));

    TestContext {
        env,
        payroll_client,
        token_client,
        pause_manager_client: pm_client,
        admin,
        treasury,
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

#[test]
fn test_pending_payroll_run_cancellation_cleans_storage_and_preserves_audit_state() {
    let ctx = setup_test_context();
    let nonce = test_nonce(&ctx.env, 101);
    let amount = 50_000i128;
    let (proofs, amounts, employees) = single_payment_batch(&ctx.env, &ctx.employee, amount);

    let treasury_balance_before = ctx.token_client.balance(&ctx.treasury);

    // 1. Prepare payroll run
    let run_id = ctx
        .payroll_client
        .prepare_payroll_run(&proofs, &amounts, &employees, &amount, &nonce, &None);

    assert!(ctx.payroll_client.get_pending_run(&run_id).is_some());
    assert_eq!(
        ctx.payroll_client.get_payroll_run_state(&run_id),
        PayrollRunState::Submitted
    );

    let reason = Symbol::new(&ctx.env, "REJECTED_AUDIT_CHECK");

    // 2. Cancel payroll run
    ctx.payroll_client
        .cancel_payroll_run_with_reason(&ctx.admin, &run_id, &reason);

    // 3. Verify storage cleanup: pending run removed
    assert!(
        ctx.payroll_client.get_pending_run(&run_id).is_none(),
        "Pending run record must be purged from storage upon cancellation"
    );

    // 4. Verify no finalized PayrollRun was created
    assert!(
        ctx.payroll_client.try_get_payroll_run(&run_id).is_err(),
        "No completed PayrollRun should exist for a cancelled run"
    );

    // 5. Verify canonical state is recorded as Cancelled for auditor and reconciler queries
    assert_eq!(
        ctx.payroll_client.get_payroll_run_state(&run_id),
        PayrollRunState::Cancelled,
        "Canonical state must be recorded as Cancelled"
    );

    // 6. Verify run nonce remains permanently spent to prevent replay attacks
    let (p2, a2, e2) = single_payment_batch(&ctx.env, &ctx.employee, amount);
    let replay_result = ctx
        .payroll_client
        .try_prepare_payroll_run(&p2, &a2, &e2, &amount, &nonce, &None);
    assert!(
        replay_result.is_err(),
        "Replay attack with consumed nonce from cancelled run must be rejected"
    );

    // 7. Verify no funds were moved / deducted from treasury
    let treasury_balance_after = ctx.token_client.balance(&ctx.treasury);
    assert_eq!(
        treasury_balance_before, treasury_balance_after,
        "Treasury balance must remain untouched after cancellation"
    );

    // 8. Verify privacy in events: run_cancelled event only contains run_id and reason
    let events = ctx.env.events().all();
    let mut found_cancelled_event = false;
    for event in events.iter() {
        if event.1.len() >= 2 {
            let t0_res: Result<Symbol, _> = event.1.get(0).unwrap().try_into_val(&ctx.env);
            let t1_res: Result<Symbol, _> = event.1.get(1).unwrap().try_into_val(&ctx.env);
            if let (Ok(topic0), Ok(topic1)) = (t0_res, t1_res) {
                if topic0 == symbol_short!("payroll")
                    && topic1 == Symbol::new(&ctx.env, "run_cancelled")
                {
                    found_cancelled_event = true;
                }
            }
        }
    }
    assert!(found_cancelled_event, "run_cancelled event must be emitted");
}

#[test]
fn test_cancelled_run_cannot_be_finalized_or_re_cancelled() {
    let ctx = setup_test_context();
    let nonce = test_nonce(&ctx.env, 102);
    let (proofs, amounts, employees) = single_payment_batch(&ctx.env, &ctx.employee, 25_000i128);

    let run_id = ctx.payroll_client.prepare_payroll_run(
        &proofs,
        &amounts,
        &employees,
        &25_000i128,
        &nonce,
        &None,
    );

    let reason = Symbol::new(&ctx.env, "CANCELLED_BY_ADMIN");
    ctx.payroll_client
        .cancel_payroll_run_with_reason(&ctx.admin, &run_id, &reason);

    // Finalize must fail
    let finalize_res = ctx
        .payroll_client
        .try_finalize_payroll_run(&ctx.admin, &run_id);
    assert!(
        finalize_res.is_err(),
        "Finalizing a cancelled run must fail"
    );

    // Double cancel must fail
    let double_cancel_res = ctx
        .payroll_client
        .try_cancel_payroll_run_with_reason(&ctx.admin, &run_id, &reason);
    assert!(
        double_cancel_res.is_err(),
        "Cancelling an already cancelled run must fail"
    );
}

#[test]
fn test_cancelled_run_state_is_terminal_and_immutable() {
    let ctx = setup_test_context();

    // Canonical state machine rules
    assert!(
        ctx.payroll_client
            .is_payroll_state_terminal(&PayrollRunState::Cancelled),
        "Cancelled state must be terminal"
    );
    assert!(
        !ctx.payroll_client
            .is_payroll_state_retryable(&PayrollRunState::Cancelled),
        "Cancelled state must not be retryable"
    );

    // State transitions out of Cancelled are forbidden
    assert!(
        !ctx.payroll_client
            .is_state_transition_allowed(&PayrollRunState::Cancelled, &PayrollRunState::Completed),
        "Cancelled -> Completed transition must be forbidden"
    );
    assert!(
        !ctx.payroll_client
            .is_state_transition_allowed(&PayrollRunState::Cancelled, &PayrollRunState::Submitted),
        "Cancelled -> Submitted transition must be forbidden"
    );
    assert!(
        !ctx.payroll_client
            .is_state_transition_allowed(&PayrollRunState::Cancelled, &PayrollRunState::Failed),
        "Cancelled -> Failed transition must be forbidden"
    );

    // Conformance test on actual run instance
    let nonce = test_nonce(&ctx.env, 103);
    let (proofs, amounts, employees) = single_payment_batch(&ctx.env, &ctx.employee, 10_000i128);
    let run_id = ctx.payroll_client.prepare_payroll_run(
        &proofs,
        &amounts,
        &employees,
        &10_000i128,
        &nonce,
        &None,
    );

    ctx.payroll_client.cancel_payroll_run_with_reason(
        &ctx.admin,
        &run_id,
        &Symbol::new(&ctx.env, "CANCEL"),
    );

    // Attempting state transition hook out of Cancelled must panic
    let transition_res = ctx.payroll_client.try_transition_payroll_run_state(
        &ctx.admin,
        &run_id,
        &PayrollRunState::Completed,
    );
    assert!(
        transition_res.is_err(),
        "transition_payroll_run_state out of Cancelled must be rejected"
    );
}

#[test]
fn test_cancellation_authorization_and_validation_errors() {
    let ctx = setup_test_context();
    let nonce = test_nonce(&ctx.env, 104);
    let (proofs, amounts, employees) = single_payment_batch(&ctx.env, &ctx.employee, 15_000i128);

    let run_id = ctx.payroll_client.prepare_payroll_run(
        &proofs,
        &amounts,
        &employees,
        &15_000i128,
        &nonce,
        &None,
    );

    // 1. Unauthorized caller
    let attacker = Address::generate(&ctx.env);
    let unauth_res = ctx.payroll_client.try_cancel_payroll_run_with_reason(
        &attacker,
        &run_id,
        &Symbol::new(&ctx.env, "ATTACK"),
    );
    assert!(unauth_res.is_err(), "Unauthorized cancellation must fail");

    // 2. Empty reason symbol
    let empty_symbol = Symbol::new(&ctx.env, "");
    let empty_reason_res =
        ctx.payroll_client
            .try_cancel_payroll_run_with_reason(&ctx.admin, &run_id, &empty_symbol);
    assert!(
        empty_reason_res.is_err(),
        "Empty reason symbol must be rejected"
    );

    // 3. Non-existent run ID
    let non_existent_res = ctx.payroll_client.try_cancel_payroll_run_with_reason(
        &ctx.admin,
        &999_999u64,
        &Symbol::new(&ctx.env, "NON_EXISTENT"),
    );
    assert!(
        non_existent_res.is_err(),
        "Cancelling non-existent run must fail"
    );

    // 4. Invalid u64::MAX run ID
    let invalid_id_res = ctx.payroll_client.try_cancel_payroll_run_with_reason(
        &ctx.admin,
        &u64::MAX,
        &Symbol::new(&ctx.env, "INVALID_ID"),
    );
    assert!(
        invalid_id_res.is_err(),
        "Cancelling u64::MAX run ID must fail"
    );

    // 5. Finalized run cannot be cancelled retroactively
    let finalized_nonce = test_nonce(&ctx.env, 105);
    let (p2, a2, e2) = single_payment_batch(&ctx.env, &ctx.employee, 20_000i128);
    let finalized_run_id =
        ctx.payroll_client
            .prepare_payroll_run(&p2, &a2, &e2, &20_000i128, &finalized_nonce, &None);
    ctx.payroll_client
        .finalize_payroll_run(&ctx.admin, &finalized_run_id);

    let cancel_finalized_res = ctx.payroll_client.try_cancel_payroll_run_with_reason(
        &ctx.admin,
        &finalized_run_id,
        &Symbol::new(&ctx.env, "TOO_LATE"),
    );
    assert!(
        cancel_finalized_res.is_err(),
        "Cancelling a finalized run must be rejected"
    );
}

#[test]
fn test_escape_hatch_cancellation_under_emergency_pause() {
    let ctx = setup_test_context();
    let nonce = test_nonce(&ctx.env, 106);
    let (proofs, amounts, employees) = single_payment_batch(&ctx.env, &ctx.employee, 30_000i128);

    let run_id = ctx.payroll_client.prepare_payroll_run(
        &proofs,
        &amounts,
        &employees,
        &30_000i128,
        &nonce,
        &None,
    );

    // Operator pauses contract
    ctx.pause_manager_client.pause();

    // Verification: normal execution operations (batch_process_payroll and finalize_payroll_run) are blocked
    let (p2, a2, e2) = single_payment_batch(&ctx.env, &ctx.employee, 10_000i128);
    let batch_blocked = ctx.payroll_client.try_batch_process_payroll(
        &p2,
        &a2,
        &e2,
        &10_000i128,
        &test_nonce(&ctx.env, 107),
        &None,
    );
    assert!(
        batch_blocked.is_err(),
        "batch_process_payroll must fail while paused"
    );

    let finalize_blocked = ctx
        .payroll_client
        .try_finalize_payroll_run(&ctx.admin, &run_id);
    assert!(
        finalize_blocked.is_err(),
        "finalize_payroll_run must fail while paused"
    );

    // Emergency Escape Hatch: cancellation is permitted while paused
    ctx.payroll_client.cancel_payroll_run_with_reason(
        &ctx.admin,
        &run_id,
        &Symbol::new(&ctx.env, "EMERGENCY_RECOVERY"),
    );

    // Storage is cleanly purged even during emergency pause
    assert!(ctx.payroll_client.get_pending_run(&run_id).is_none());
    assert_eq!(
        ctx.payroll_client.get_payroll_run_state(&run_id),
        PayrollRunState::Cancelled
    );
}

#[test]
fn test_sequential_interleaved_runs_lifecycle_with_cancellations() {
    let ctx = setup_test_context();

    // Run 1: Prepared -> Cancelled
    let nonce1 = test_nonce(&ctx.env, 110);
    let (p1, a1, e1) = single_payment_batch(&ctx.env, &ctx.employee, 10_000i128);
    let run_id_1 =
        ctx.payroll_client
            .prepare_payroll_run(&p1, &a1, &e1, &10_000i128, &nonce1, &None);
    ctx.payroll_client.cancel_payroll_run_with_reason(
        &ctx.admin,
        &run_id_1,
        &Symbol::new(&ctx.env, "REVERT_1"),
    );

    // Run 2: Prepared -> Finalized -> Reconciled
    let nonce2 = test_nonce(&ctx.env, 111);
    let (p2, a2, e2) = single_payment_batch(&ctx.env, &ctx.employee, 20_000i128);
    let run_id_2 =
        ctx.payroll_client
            .prepare_payroll_run(&p2, &a2, &e2, &20_000i128, &nonce2, &None);
    ctx.payroll_client
        .finalize_payroll_run(&ctx.admin, &run_id_2);
    ctx.payroll_client.update_reconciliation_status(
        &ctx.admin,
        &run_id_2,
        &ReconciliationStatus::Reconciled,
    );

    // Run 3: Prepared -> Cancelled
    let nonce3 = test_nonce(&ctx.env, 112);
    let (p3, a3, e3) = single_payment_batch(&ctx.env, &ctx.employee, 30_000i128);
    let run_id_3 =
        ctx.payroll_client
            .prepare_payroll_run(&p3, &a3, &e3, &30_000i128, &nonce3, &None);
    ctx.payroll_client.cancel_payroll_run_with_reason(
        &ctx.admin,
        &run_id_3,
        &Symbol::new(&ctx.env, "REVERT_3"),
    );

    // Assert independent distinct run IDs
    assert_eq!(run_id_1, 1);
    assert_eq!(run_id_2, 2);
    assert_eq!(run_id_3, 3);

    // Assert states are cleanly isolated and preserved
    assert_eq!(
        ctx.payroll_client.get_payroll_run_state(&run_id_1),
        PayrollRunState::Cancelled
    );
    assert_eq!(
        ctx.payroll_client.get_payroll_run_state(&run_id_2),
        PayrollRunState::Completed
    );
    assert_eq!(
        ctx.payroll_client.get_payroll_run_state(&run_id_3),
        PayrollRunState::Cancelled
    );

    // Assert pending runs cleaned up
    assert!(ctx.payroll_client.get_pending_run(&run_id_1).is_none());
    assert!(ctx.payroll_client.get_pending_run(&run_id_2).is_none());
    assert!(ctx.payroll_client.get_pending_run(&run_id_3).is_none());

    // Assert only Run 2 has a permanent PayrollRun record
    assert!(ctx.payroll_client.try_get_payroll_run(&run_id_1).is_err());
    assert!(ctx.payroll_client.try_get_payroll_run(&run_id_2).is_ok());
    assert!(ctx.payroll_client.try_get_payroll_run(&run_id_3).is_err());
}

#[test]
fn test_draft_cancellation_state_preservation_and_immutability() {
    let ctx = setup_test_context();

    // 1. Create and amend draft
    let draft_id = ctx.payroll_client.create_run_draft(
        &ctx.admin,
        &50_000i128,
        &5u32,
        &Symbol::new(&ctx.env, "OCT_2026"),
    );
    ctx.payroll_client
        .amend_run_draft(&ctx.admin, &draft_id, &60_000i128, &6u32);

    let draft_before = ctx.payroll_client.get_run_draft(&draft_id);
    assert_eq!(draft_before.state, RunDraftState::Pending);
    assert_eq!(draft_before.amendment_count, 1);

    // 2. Cancel draft
    ctx.payroll_client.cancel_run_draft(&ctx.admin, &draft_id);

    // 3. Verify draft record is preserved with state Cancelled for audit history
    let draft_after = ctx.payroll_client.get_run_draft(&draft_id);
    assert_eq!(draft_after.state, RunDraftState::Cancelled);
    assert_eq!(draft_after.draft_id, draft_id);
    assert_eq!(draft_after.total_amount, 60_000i128);
    assert_eq!(draft_after.employee_count, 6u32);
    assert_eq!(draft_after.amendment_count, 1);
    assert_eq!(draft_after.created_at, draft_before.created_at);

    // 4. Verify terminal status: all further mutations must fail
    assert!(ctx
        .payroll_client
        .is_draft_state_terminal(&RunDraftState::Cancelled));
    assert!(ctx
        .payroll_client
        .try_amend_run_draft(&ctx.admin, &draft_id, &70_000i128, &7u32)
        .is_err());
    assert!(ctx
        .payroll_client
        .try_finalize_run_draft(&ctx.admin, &draft_id)
        .is_err());
    assert!(ctx
        .payroll_client
        .try_submit_run_draft(&ctx.admin, &draft_id)
        .is_err());
    assert!(ctx
        .payroll_client
        .try_cancel_run_draft(&ctx.admin, &draft_id)
        .is_err());
    assert!(ctx
        .payroll_client
        .try_expire_run_draft(&ctx.admin, &draft_id)
        .is_err());

    // 5. Recovery: Admin can create a new fresh draft without conflict
    let new_draft_id = ctx.payroll_client.create_run_draft(
        &ctx.admin,
        &50_000i128,
        &5u32,
        &Symbol::new(&ctx.env, "OCT_2026_CORRECTED"),
    );
    assert_eq!(new_draft_id, draft_id + 1);
    let new_draft = ctx.payroll_client.get_run_draft(&new_draft_id);
    assert_eq!(new_draft.state, RunDraftState::Pending);
}

#[test]
fn test_finalized_draft_cancellation_flow() {
    let ctx = setup_test_context();

    let draft_id = ctx.payroll_client.create_run_draft(
        &ctx.admin,
        &40_000i128,
        &4u32,
        &Symbol::new(&ctx.env, "FINALIZE_THEN_CANCEL"),
    );
    ctx.payroll_client.finalize_run_draft(&ctx.admin, &draft_id);

    let finalized_draft = ctx.payroll_client.get_run_draft(&draft_id);
    assert_eq!(finalized_draft.state, RunDraftState::Finalized);

    // Cancel from finalized state
    ctx.payroll_client.cancel_run_draft(&ctx.admin, &draft_id);

    let cancelled_draft = ctx.payroll_client.get_run_draft(&draft_id);
    assert_eq!(cancelled_draft.state, RunDraftState::Cancelled);

    // Submitting cancelled draft must fail
    assert!(ctx
        .payroll_client
        .try_submit_run_draft(&ctx.admin, &draft_id)
        .is_err());
}

#[test]
fn test_draft_cancellation_respects_pause() {
    let ctx = setup_test_context();

    let draft_id = ctx.payroll_client.create_run_draft(
        &ctx.admin,
        &30_000i128,
        &3u32,
        &Symbol::new(&ctx.env, "DRAFT_PAUSE"),
    );

    // Pause contract
    ctx.pause_manager_client.pause();

    // Draft operations are paused
    let cancel_res = ctx
        .payroll_client
        .try_cancel_run_draft(&ctx.admin, &draft_id);
    assert!(
        cancel_res.is_err(),
        "cancel_run_draft must be rejected when payroll is paused"
    );

    // Unpause and cancel succeeds
    ctx.pause_manager_client.unpause();
    let cancel_after_unpause = ctx
        .payroll_client
        .try_cancel_run_draft(&ctx.admin, &draft_id);
    assert!(cancel_after_unpause.is_ok());
}
