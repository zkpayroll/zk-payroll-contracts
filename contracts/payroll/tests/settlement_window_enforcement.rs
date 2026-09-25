//! Settlement window enforcement tests (#316).
//!
//! Covers: boundary timestamps around the execution window, backward
//! compatibility when no period/window is configured, unauthorized period
//! edits, and the grace-period cancellation/expiration paths.

#![cfg(test)]

use ::token::{Token, TokenClient};
use payroll::{Payroll, PayrollClient, SettlementWindowStatus};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{Address, BytesN, Env, Symbol, Vec};

fn mock_proof(env: &Env) -> BytesN<256> {
    BytesN::from_array(env, &[0u8; 256])
}

fn test_nonce(env: &Env, seed: u8) -> BytesN<32> {
    let mut arr = [0u8; 32];
    arr[0] = seed;
    BytesN::from_array(env, &arr)
}

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

fn setup_payroll(env: &Env) -> (PayrollClient<'_>, Address, Address, Address, Address) {
    env.mock_all_auths();

    let verifier_id = env.register_contract(None, ProofVerifier);
    let verifier_client = ProofVerifierClient::new(env, &verifier_id);
    let verifier_admin = Address::generate(env);
    verifier_client.init_verifier_admin(&verifier_admin);
    verifier_client.initialize_verifier(&mock_vk(env));

    let commitment_id = env.register_contract(None, SalaryCommitmentContract);
    let commitment_client = SalaryCommitmentContractClient::new(env, &commitment_id);
    let commitment_admin = Address::generate(env);
    commitment_client.init_commitment_admin(&commitment_admin);

    let token_id = env.register_contract(None, Token);
    let token_client = TokenClient::new(env, &token_id);

    let payroll_id = env.register_contract(None, Payroll);
    let payroll_client = PayrollClient::new(env, &payroll_id);

    let treasury = Address::generate(env);
    let admin = Address::generate(env);
    let treasury_owner = Address::generate(env);
    token_client.mint(&treasury, &1_000_000i128);

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

    (payroll_client, admin, treasury, treasury_owner, employee)
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

fn set_timestamp(env: &Env, ts: u64) {
    env.ledger().with_mut(|li| {
        li.timestamp = ts;
    });
}

// Window fixture: open_at=1000, execution_start=2000, execution_end=3000, close_at=4000.
const OPEN_AT: u64 = 1000;
const EXEC_START: u64 = 2000;
const EXEC_END: u64 = 3000;
const CLOSE_AT: u64 = 4000;

fn open_period_with_window(payroll: &PayrollClient, admin: &Address, period: &Symbol) {
    payroll.open_capacity_period(admin, period);
    payroll.set_settlement_window(admin, period, &OPEN_AT, &EXEC_START, &EXEC_END, &CLOSE_AT);
}

#[test]
fn test_execute_before_execution_start_rejected() {
    let env = Env::default();
    let (payroll, admin, _treasury, _treasury_owner, employee) = setup_payroll(&env);
    let period = Symbol::new(&env, "period_a");
    open_period_with_window(&payroll, &admin, &period);

    set_timestamp(&env, EXEC_START - 1);

    let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 10_000);
    let nonce = test_nonce(&env, 1);
    let result =
        payroll.try_prepare_payroll_run(&proofs, &amounts, &employees, &10_000, &nonce, &None);
    assert!(result.is_err());
}

#[test]
fn test_execute_at_execution_start_boundary_succeeds() {
    let env = Env::default();
    let (payroll, admin, _treasury, _treasury_owner, employee) = setup_payroll(&env);
    let period = Symbol::new(&env, "period_a");
    open_period_with_window(&payroll, &admin, &period);

    set_timestamp(&env, EXEC_START);

    let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 10_000);
    let nonce = test_nonce(&env, 2);
    let run_id = payroll.prepare_payroll_run(&proofs, &amounts, &employees, &10_000, &nonce, &None);
    assert!(payroll.get_pending_run(&run_id).is_some());
}

#[test]
fn test_execute_at_execution_end_boundary_succeeds() {
    let env = Env::default();
    let (payroll, admin, _treasury, _treasury_owner, employee) = setup_payroll(&env);
    let period = Symbol::new(&env, "period_a");
    open_period_with_window(&payroll, &admin, &period);

    set_timestamp(&env, EXEC_END);

    let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 10_000);
    let nonce = test_nonce(&env, 3);
    let run_id = payroll.prepare_payroll_run(&proofs, &amounts, &employees, &10_000, &nonce, &None);
    assert!(payroll.get_pending_run(&run_id).is_some());
}

#[test]
fn test_execute_one_tick_after_execution_end_rejected() {
    let env = Env::default();
    let (payroll, admin, _treasury, _treasury_owner, employee) = setup_payroll(&env);
    let period = Symbol::new(&env, "period_a");
    open_period_with_window(&payroll, &admin, &period);

    set_timestamp(&env, EXEC_END + 1);

    let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 10_000);
    let nonce = test_nonce(&env, 4);
    let result =
        payroll.try_prepare_payroll_run(&proofs, &amounts, &employees, &10_000, &nonce, &None);
    assert!(result.is_err());
}

#[test]
fn test_execute_after_close_rejected() {
    let env = Env::default();
    let (payroll, admin, _treasury, _treasury_owner, employee) = setup_payroll(&env);
    let period = Symbol::new(&env, "period_a");
    open_period_with_window(&payroll, &admin, &period);

    set_timestamp(&env, CLOSE_AT + 100);

    let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 10_000);
    let nonce = test_nonce(&env, 5);
    let result =
        payroll.try_prepare_payroll_run(&proofs, &amounts, &employees, &10_000, &nonce, &None);
    assert!(result.is_err());
}

#[test]
fn test_batch_process_payroll_respects_window() {
    let env = Env::default();
    let (payroll, _admin, _treasury, _treasury_owner, employee) = setup_payroll(&env);
    let admin = _admin;
    let period = Symbol::new(&env, "period_a");
    open_period_with_window(&payroll, &admin, &period);

    // Before the window: batch_process_payroll should be rejected.
    set_timestamp(&env, EXEC_START - 1);
    let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 10_000);
    let nonce = test_nonce(&env, 6);
    let result =
        payroll.try_batch_process_payroll(&proofs, &amounts, &employees, &10_000, &nonce, &None);
    assert!(result.is_err());

    // Inside the window: batch_process_payroll should succeed.
    set_timestamp(&env, EXEC_START);
    let nonce2 = test_nonce(&env, 7);
    let run_id =
        payroll.batch_process_payroll(&proofs, &amounts, &employees, &10_000, &nonce2, &None);
    assert!(payroll.get_run_counter() >= run_id);
}

#[test]
fn test_no_current_period_is_unaffected_by_window_rules() {
    // No `open_capacity_period` call at all: execution must remain
    // unrestricted regardless of ledger time (backward compatibility).
    let env = Env::default();
    let (payroll, _admin, _treasury, _treasury_owner, employee) = setup_payroll(&env);

    set_timestamp(&env, 1);

    let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 10_000);
    let nonce = test_nonce(&env, 8);
    let run_id = payroll.prepare_payroll_run(&proofs, &amounts, &employees, &10_000, &nonce, &None);
    assert!(payroll.get_pending_run(&run_id).is_some());
}

#[test]
fn test_period_open_without_window_is_unaffected() {
    // Period opened for capacity accounting, but no settlement window
    // configured for it: execution must remain unrestricted (opt-in feature).
    let env = Env::default();
    let (payroll, admin, _treasury, _treasury_owner, employee) = setup_payroll(&env);
    let period = Symbol::new(&env, "period_b");
    payroll.open_capacity_period(&admin, &period);

    set_timestamp(&env, 1);

    let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 10_000);
    let nonce = test_nonce(&env, 9);
    let run_id = payroll.prepare_payroll_run(&proofs, &amounts, &employees, &10_000, &nonce, &None);
    assert!(payroll.get_pending_run(&run_id).is_some());
}

#[test]
fn test_unauthorized_set_settlement_window_rejected() {
    let env = Env::default();
    let (payroll, _admin, _treasury, _treasury_owner, _employee) = setup_payroll(&env);
    let not_admin = Address::generate(&env);
    let period = Symbol::new(&env, "period_a");

    let result = payroll.try_set_settlement_window(
        &not_admin,
        &period,
        &OPEN_AT,
        &EXEC_START,
        &EXEC_END,
        &CLOSE_AT,
    );
    assert!(result.is_err());
}

#[test]
fn test_set_settlement_window_invalid_ordering_rejected() {
    let env = Env::default();
    let (payroll, admin, _treasury, _treasury_owner, _employee) = setup_payroll(&env);
    let period = Symbol::new(&env, "period_a");

    // execution_start after execution_end: invalid ordering.
    let result = payroll.try_set_settlement_window(
        &admin,
        &period,
        &OPEN_AT,
        &EXEC_END,
        &EXEC_START,
        &CLOSE_AT,
    );
    assert!(result.is_err());
}

#[test]
fn test_settlement_window_status_transitions() {
    let env = Env::default();
    let (payroll, admin, _treasury, _treasury_owner, _employee) = setup_payroll(&env);
    let period = Symbol::new(&env, "period_a");
    open_period_with_window(&payroll, &admin, &period);

    set_timestamp(&env, EXEC_START - 1);
    assert_eq!(
        payroll.get_settlement_window_status(&period),
        Some(SettlementWindowStatus::PreOpen)
    );

    set_timestamp(&env, EXEC_START);
    assert_eq!(
        payroll.get_settlement_window_status(&period),
        Some(SettlementWindowStatus::Executable)
    );

    set_timestamp(&env, EXEC_END + 1);
    assert_eq!(
        payroll.get_settlement_window_status(&period),
        Some(SettlementWindowStatus::Grace)
    );

    set_timestamp(&env, CLOSE_AT + 1);
    assert_eq!(
        payroll.get_settlement_window_status(&period),
        Some(SettlementWindowStatus::Closed)
    );
}

#[test]
fn test_grace_period_cancellation_succeeds() {
    let env = Env::default();
    let (payroll, admin, _treasury, _treasury_owner, employee) = setup_payroll(&env);
    let period = Symbol::new(&env, "period_a");
    open_period_with_window(&payroll, &admin, &period);

    set_timestamp(&env, EXEC_START);
    let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 10_000);
    let nonce = test_nonce(&env, 10);
    let run_id = payroll.prepare_payroll_run(&proofs, &amounts, &employees, &10_000, &nonce, &None);

    // Move into the grace window (past execution_end, before close_at) and
    // confirm the admin can still explicitly cancel the pending run.
    set_timestamp(&env, EXEC_END + 1);
    let reason = Symbol::new(&env, "grace_cancel");
    payroll.cancel_payroll_run(&admin, &run_id, &reason);

    let status = payroll
        .get_cancelled_batch_status(&run_id)
        .expect("cancellation record expected");
    assert!(status.is_cancelled);
    assert_eq!(status.reason, reason);
    assert!(payroll.get_pending_run(&run_id).is_none());
}

#[test]
fn test_expire_pending_run_before_close_fails() {
    let env = Env::default();
    let (payroll, admin, _treasury, _treasury_owner, employee) = setup_payroll(&env);
    let period = Symbol::new(&env, "period_a");
    open_period_with_window(&payroll, &admin, &period);

    set_timestamp(&env, EXEC_START);
    let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 10_000);
    let nonce = test_nonce(&env, 11);
    let run_id = payroll.prepare_payroll_run(&proofs, &amounts, &employees, &10_000, &nonce, &None);

    // Still in grace, not yet at close_at: expiration must be rejected.
    set_timestamp(&env, EXEC_END + 1);
    let result = payroll.try_expire_pending_run(&admin, &run_id);
    assert!(result.is_err());
    assert!(payroll.get_pending_run(&run_id).is_some());
}

#[test]
fn test_expire_pending_run_after_close_succeeds() {
    let env = Env::default();
    let (payroll, admin, _treasury, _treasury_owner, employee) = setup_payroll(&env);
    let period = Symbol::new(&env, "period_a");
    open_period_with_window(&payroll, &admin, &period);

    set_timestamp(&env, EXEC_START);
    let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 10_000);
    let nonce = test_nonce(&env, 12);
    let run_id = payroll.prepare_payroll_run(&proofs, &amounts, &employees, &10_000, &nonce, &None);

    // At exactly close_at, the window has fully closed: expiration succeeds.
    set_timestamp(&env, CLOSE_AT);
    payroll.expire_pending_run(&admin, &run_id);

    assert!(payroll.get_pending_run(&run_id).is_none());
    let status = payroll
        .get_cancelled_batch_status(&run_id)
        .expect("expiration record expected");
    assert!(status.is_cancelled);
    assert_eq!(
        status.reason,
        Symbol::new(&env, "settlement_window_expired")
    );
}

#[test]
fn test_expire_already_executed_run_fails() {
    let env = Env::default();
    let (payroll, admin, _treasury, _treasury_owner, employee) = setup_payroll(&env);
    let period = Symbol::new(&env, "period_a");
    open_period_with_window(&payroll, &admin, &period);

    set_timestamp(&env, EXEC_START);
    let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 10_000);
    let nonce = test_nonce(&env, 13);
    let run_id = payroll.prepare_payroll_run(&proofs, &amounts, &employees, &10_000, &nonce, &None);
    payroll.finalize_payroll_run(&admin, &run_id);

    set_timestamp(&env, CLOSE_AT);
    let result = payroll.try_expire_pending_run(&admin, &run_id);
    assert!(result.is_err());
}

#[test]
fn test_unauthorized_expire_pending_run_rejected() {
    let env = Env::default();
    let (payroll, admin, _treasury, _treasury_owner, employee) = setup_payroll(&env);
    let period = Symbol::new(&env, "period_a");
    open_period_with_window(&payroll, &admin, &period);

    set_timestamp(&env, EXEC_START);
    let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 10_000);
    let nonce = test_nonce(&env, 14);
    let run_id = payroll.prepare_payroll_run(&proofs, &amounts, &employees, &10_000, &nonce, &None);

    set_timestamp(&env, CLOSE_AT);
    let not_admin = Address::generate(&env);
    let result = payroll.try_expire_pending_run(&not_admin, &run_id);
    assert!(result.is_err());
}
