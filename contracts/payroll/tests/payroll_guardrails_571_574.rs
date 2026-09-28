//! Focused guardrail tests for issues #571–#574.
//!
//! * #571 — payroll approval timestamp validation (future-skew, causality,
//!   freshness of reviewer approvals relative to run preparation).
//! * #572 — read-only query enumerating pending payroll obligations with a
//!   privacy-safe shape (no amounts, no employee addresses).
//! * #573 — payer account status gate on every payment-executing path.
//! * #574 — opaque receipt reference indexing with duplicate rejection and
//!   run lookup.
//!
//! Privacy: every assertion below works only with identifiers, timestamps,
//! counters, and status enums — never with salary amounts or employee data.

#![cfg(test)]

use ::token::{Token, TokenClient};
use payroll::{
    PayerAccountStatus, Payroll, PayrollClient, ReviewDecision, MAX_APPROVAL_CLOCK_SKEW_SECONDS,
    MAX_APPROVAL_LAG_SECONDS,
};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{Address, BytesN, Env, Vec};

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

// ── Issue #571: payroll approval timestamp validation ──────────────────────────

#[test]
fn test_approval_timestamp_window_query() {
    let env = Env::default();
    env.ledger().with_mut(|li| li.timestamp = 1_000_000);
    let (payroll, admin, _treasury, _treasury_owner, employee) = setup_payroll(&env);

    let reviewer = Address::generate(&env);
    payroll.add_reviewer(&admin, &reviewer);

    let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 10_000);
    let run_id = payroll.prepare_payroll_run(
        &proofs,
        &amounts,
        &employees,
        &10_000,
        &test_nonce(&env, 40),
        &None,
    );

    env.ledger().with_mut(|li| li.timestamp = 1_000_010);
    payroll.approve_payroll_run(&reviewer, &run_id);

    let window = payroll.get_approval_timestamp_window(&run_id).unwrap();
    assert_eq!(window.run_id, run_id);
    assert_eq!(window.prepared_at, 1_000_000);
    assert_eq!(window.approved_at, 1_000_010);
    assert_eq!(window.max_lag_seconds, MAX_APPROVAL_LAG_SECONDS);

    let review = payroll.get_run_review(&run_id).unwrap();
    assert_eq!(review.decision, ReviewDecision::Approved);
}

#[test]
#[should_panic(expected = "Run not found: cannot approve a payroll run that is not pending")]
fn test_approve_requires_pending_run() {
    let env = Env::default();
    let (payroll, admin, _treasury, _treasury_owner, _employee) = setup_payroll(&env);

    let reviewer = Address::generate(&env);
    payroll.add_reviewer(&admin, &reviewer);
    payroll.approve_payroll_run(&reviewer, &999u64);
}

#[test]
#[should_panic(
    expected = "Payroll approval window closed: run was prepared too long ago to approve"
)]
fn test_approve_rejected_after_max_lag() {
    let env = Env::default();
    let (payroll, admin, _treasury, _treasury_owner, employee) = setup_payroll(&env);

    let reviewer = Address::generate(&env);
    payroll.add_reviewer(&admin, &reviewer);

    let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 10_000);
    let run_id = payroll.prepare_payroll_run(
        &proofs,
        &amounts,
        &employees,
        &10_000,
        &test_nonce(&env, 41),
        &None,
    );

    env.ledger()
        .with_mut(|li| li.timestamp += MAX_APPROVAL_LAG_SECONDS + 10);
    payroll.approve_payroll_run(&reviewer, &run_id);
}

#[test]
fn test_approve_succeeds_within_window() {
    let env = Env::default();
    env.ledger().with_mut(|li| li.timestamp = 2_000_000);
    let (payroll, admin, _treasury, _treasury_owner, employee) = setup_payroll(&env);

    let reviewer = Address::generate(&env);
    payroll.add_reviewer(&admin, &reviewer);

    let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 10_000);
    let run_id = payroll.prepare_payroll_run(
        &proofs,
        &amounts,
        &employees,
        &10_000,
        &test_nonce(&env, 42),
        &None,
    );

    env.ledger().with_mut(|li| li.timestamp += 60);
    payroll.approve_payroll_run(&reviewer, &run_id);

    let review = payroll.get_run_review(&run_id).unwrap();
    assert_eq!(review.decision, ReviewDecision::Approved);
}

#[test]
#[should_panic(
    expected = "Payroll approval timestamp is invalid: approval predates run preparation"
)]
fn test_finalize_rejects_backdated_approval() {
    let env = Env::default();
    env.ledger().with_mut(|li| li.timestamp = 3_000_000);
    let (payroll, admin, _treasury, _treasury_owner, employee) = setup_payroll(&env);

    let reviewer = Address::generate(&env);
    payroll.add_reviewer(&admin, &reviewer);

    let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 10_000);
    let run_id = payroll.prepare_payroll_run(
        &proofs,
        &amounts,
        &employees,
        &10_000,
        &test_nonce(&env, 43),
        &None,
    );

    // Simulate a regressed ledger clock: the approval gets stamped within the
    // allowed skew, but before the run was prepared — undetectable at approval
    // time, so finalize must catch it.
    env.ledger().with_mut(|li| li.timestamp = 2_999_900);
    payroll.approve_payroll_run(&reviewer, &run_id);

    env.ledger().with_mut(|li| li.timestamp = 3_000_050);
    payroll.finalize_payroll_run(&admin, &run_id);
}

#[test]
#[should_panic(expected = "Payroll approval timestamp is invalid: it is too far in the future")]
fn test_finalize_rejects_future_dated_approval() {
    let env = Env::default();
    env.ledger().with_mut(|li| li.timestamp = 4_000_000);
    let (payroll, admin, _treasury, _treasury_owner, employee) = setup_payroll(&env);

    let reviewer = Address::generate(&env);
    payroll.add_reviewer(&admin, &reviewer);

    let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 10_000);
    let run_id = payroll.prepare_payroll_run(
        &proofs,
        &amounts,
        &employees,
        &10_000,
        &test_nonce(&env, 44),
        &None,
    );

    payroll.approve_payroll_run(&reviewer, &run_id);

    // Ledger clock regressed far below the approval stamp: the recorded
    // approval now appears to come from the future beyond the skew bound.
    env.ledger()
        .with_mut(|li| li.timestamp = 4_000_000 - MAX_APPROVAL_CLOCK_SKEW_SECONDS - 60);
    payroll.finalize_payroll_run(&admin, &run_id);
}

#[test]
fn test_finalize_succeeds_with_valid_approval_timestamps() {
    let env = Env::default();
    env.ledger().with_mut(|li| li.timestamp = 5_000_000);
    let (payroll, admin, _treasury, _treasury_owner, employee) = setup_payroll(&env);

    let reviewer = Address::generate(&env);
    payroll.add_reviewer(&admin, &reviewer);

    let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 10_000);
    let run_id = payroll.prepare_payroll_run(
        &proofs,
        &amounts,
        &employees,
        &10_000,
        &test_nonce(&env, 45),
        &None,
    );

    env.ledger().with_mut(|li| li.timestamp += 120);
    payroll.approve_payroll_run(&reviewer, &run_id);

    env.ledger().with_mut(|li| li.timestamp += 60);
    payroll.finalize_payroll_run(&admin, &run_id);

    assert_eq!(payroll.get_payroll_run(&run_id).run_id, run_id);
    assert!(payroll.get_pending_run(&run_id).is_none());
}

// ── Issue #573: payer account status validation ────────────────────────────────

#[test]
fn test_payer_status_defaults_to_active() {
    let env = Env::default();
    let (payroll, _admin, _treasury, _treasury_owner, _employee) = setup_payroll(&env);

    assert_eq!(
        payroll.get_payer_account_status(),
        PayerAccountStatus::Active
    );
    let record = payroll.get_payer_account_status_record();
    assert_eq!(record.last_changed_at, 0);
    assert_eq!(record.change_count, 0);
}

#[test]
#[should_panic(expected = "Payer account is paused; payroll execution is not permitted")]
fn test_payer_paused_blocks_batch_process() {
    let env = Env::default();
    let (payroll, admin, _treasury, _treasury_owner, employee) = setup_payroll(&env);

    payroll.set_payer_account_status(&admin, &PayerAccountStatus::Paused);

    let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 10_000);
    payroll.batch_process_payroll(
        &proofs,
        &amounts,
        &employees,
        &10_000,
        &test_nonce(&env, 50),
        &None,
    );
}

#[test]
#[should_panic(expected = "Payer account is archived; payroll execution is not permitted")]
fn test_payer_archived_blocks_prepare() {
    let env = Env::default();
    let (payroll, admin, _treasury, _treasury_owner, employee) = setup_payroll(&env);

    payroll.set_payer_account_status(&admin, &PayerAccountStatus::Archived);

    let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 10_000);
    payroll.prepare_payroll_run(
        &proofs,
        &amounts,
        &employees,
        &10_000,
        &test_nonce(&env, 51),
        &None,
    );
}

#[test]
#[should_panic(expected = "Payer account is paused; payroll execution is not permitted")]
fn test_payer_paused_blocks_finalize() {
    let env = Env::default();
    let (payroll, admin, _treasury, _treasury_owner, employee) = setup_payroll(&env);

    let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 10_000);
    let run_id = payroll.prepare_payroll_run(
        &proofs,
        &amounts,
        &employees,
        &10_000,
        &test_nonce(&env, 52),
        &None,
    );

    payroll.set_payer_account_status(&admin, &PayerAccountStatus::Paused);
    payroll.finalize_payroll_run(&admin, &run_id);
}

#[test]
#[should_panic(expected = "Payer account is paused; payroll execution is not permitted")]
fn test_payer_paused_blocks_emergency_withdrawal() {
    let env = Env::default();
    let (payroll, admin, _treasury, treasury_owner, _employee) = setup_payroll(&env);

    let recipient = Address::generate(&env);
    payroll.request_emergency_withdrawal(&treasury_owner, &1_000i128, &recipient);

    payroll.set_payer_account_status(&admin, &PayerAccountStatus::Paused);
    payroll.approve_emergency_withdrawal(&admin);
}

#[test]
fn test_payer_reactivation_restores_execution() {
    let env = Env::default();
    let (payroll, admin, _treasury, _treasury_owner, employee) = setup_payroll(&env);

    payroll.set_payer_account_status(&admin, &PayerAccountStatus::Paused);
    payroll.set_payer_account_status(&admin, &PayerAccountStatus::Active);

    let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 10_000);
    let run_id = payroll.batch_process_payroll(
        &proofs,
        &amounts,
        &employees,
        &10_000,
        &test_nonce(&env, 53),
        &None,
    );
    assert!(run_id > 0);

    let record = payroll.get_payer_account_status_record();
    assert_eq!(record.change_count, 2);
    assert_eq!(record.last_changed_at, env.ledger().timestamp());
}

#[test]
#[should_panic(expected = "Unauthorized")]
fn test_payer_status_change_is_admin_only() {
    let env = Env::default();
    let (payroll, _admin, _treasury, _treasury_owner, _employee) = setup_payroll(&env);

    let attacker = Address::generate(&env);
    payroll.set_payer_account_status(&attacker, &PayerAccountStatus::Paused);
}

#[test]
fn test_payer_status_noop_transition_not_counted() {
    let env = Env::default();
    let (payroll, admin, _treasury, _treasury_owner, _employee) = setup_payroll(&env);

    payroll.set_payer_account_status(&admin, &PayerAccountStatus::Active);
    let record = payroll.get_payer_account_status_record();
    assert_eq!(record.change_count, 0);
    assert_eq!(record.last_changed_at, 0);
}

// ── Issue #572: pending payroll obligations query ──────────────────────────────

#[test]
fn test_pending_obligations_empty() {
    let env = Env::default();
    let (payroll, _admin, _treasury, _treasury_owner, _employee) = setup_payroll(&env);

    let (items, remaining) = payroll.get_pending_payroll_obligations(&0u32, &10u32);
    assert_eq!(items.len(), 0);
    assert_eq!(remaining, 0);
}

#[test]
fn test_pending_obligations_track_lifecycle() {
    let env = Env::default();
    env.ledger().with_mut(|li| li.timestamp = 6_000_000);
    let (payroll, admin, _treasury, _treasury_owner, employee) = setup_payroll(&env);

    let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 10_000);
    let run_a = payroll.prepare_payroll_run(
        &proofs,
        &amounts,
        &employees,
        &10_000,
        &test_nonce(&env, 60),
        &None,
    );
    let run_b = payroll.prepare_payroll_run(
        &proofs.clone(),
        &amounts.clone(),
        &employees.clone(),
        &10_000,
        &test_nonce(&env, 61),
        &None,
    );

    let (items, remaining) = payroll.get_pending_payroll_obligations(&0u32, &10u32);
    assert_eq!(items.len(), 2);
    assert_eq!(remaining, 0); // full page: nothing beyond it
    assert_eq!(items.get(0).unwrap().run_id, run_a);
    assert_eq!(items.get(1).unwrap().run_id, run_b);
    assert!(items.get(0).unwrap().reservation_outstanding);
    assert_eq!(items.get(0).unwrap().employee_count, 1);
    assert_eq!(items.get(0).unwrap().prepared_at, 6_000_000);

    // Finalizing one obligation removes it from the pending set.
    payroll.finalize_payroll_run(&admin, &run_a);
    let (items, remaining) = payroll.get_pending_payroll_obligations(&0u32, &10u32);
    assert_eq!(items.len(), 1);
    assert_eq!(remaining, 0);
    assert_eq!(items.get(0).unwrap().run_id, run_b);

    // Cancelling the second drains the set completely.
    payroll.cancel_payroll_run(&admin, &run_b, &soroban_sdk::Symbol::new(&env, "ops"));
    let (items, remaining) = payroll.get_pending_payroll_obligations(&0u32, &10u32);
    assert_eq!(items.len(), 0);
    assert_eq!(remaining, 0);
}

#[test]
fn test_pending_obligations_pagination() {
    let env = Env::default();
    let (payroll, _admin, _treasury, _treasury_owner, employee) = setup_payroll(&env);

    let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 10_000);
    for seed in 62..65u8 {
        payroll.prepare_payroll_run(
            &proofs.clone(),
            &amounts.clone(),
            &employees.clone(),
            &10_000,
            &test_nonce(&env, seed),
            &None,
        );
    }

    let (page, remaining) = payroll.get_pending_payroll_obligations(&0u32, &2u32);
    assert_eq!(page.len(), 2);
    assert_eq!(remaining, 1); // third obligation is beyond this page

    let (page, remaining) = payroll.get_pending_payroll_obligations(&2u32, &2u32);
    assert_eq!(page.len(), 1);
    assert_eq!(remaining, 0);

    let (page, remaining) = payroll.get_pending_payroll_obligations(&5u32, &2u32);
    assert_eq!(page.len(), 0);
    assert_eq!(remaining, 0);
}

#[test]
#[should_panic(expected = "Limit must be positive")]
fn test_pending_obligations_rejects_zero_limit() {
    let env = Env::default();
    let (payroll, _admin, _treasury, _treasury_owner, _employee) = setup_payroll(&env);

    payroll.get_pending_payroll_obligations(&0u32, &0u32);
}

// ── Issue #574: payroll receipt reference indexing ─────────────────────────────

#[test]
fn test_receipt_reference_roundtrip() {
    let env = Env::default();
    let (payroll, admin, _treasury, _treasury_owner, employee) = setup_payroll(&env);

    let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 10_000);
    let run_id = payroll.batch_process_payroll(
        &proofs,
        &amounts,
        &employees,
        &10_000,
        &test_nonce(&env, 70),
        &None,
    );

    let reference = BytesN::from_array(&env, &[7u8; 32]);
    assert!(!payroll.has_receipt_reference(&reference.clone()));

    payroll.index_receipt_reference(&admin, &run_id, &reference.clone());

    assert!(payroll.has_receipt_reference(&reference.clone()));
    assert_eq!(
        payroll.get_run_by_receipt_reference(&reference.clone()),
        Some(run_id)
    );
    assert_eq!(payroll.get_receipt_reference_count(), 1);
}

#[test]
#[should_panic(expected = "Cannot index a receipt reference for a pending payroll run")]
fn test_receipt_reference_rejects_pending_run() {
    let env = Env::default();
    let (payroll, admin, _treasury, _treasury_owner, employee) = setup_payroll(&env);

    let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 10_000);
    let run_id = payroll.prepare_payroll_run(
        &proofs,
        &amounts,
        &employees,
        &10_000,
        &test_nonce(&env, 71),
        &None,
    );

    let reference = BytesN::from_array(&env, &[8u8; 32]);
    payroll.index_receipt_reference(&admin, &run_id, &reference);
}

#[test]
#[should_panic(expected = "Run not found")]
fn test_receipt_reference_rejects_unknown_run() {
    let env = Env::default();
    let (payroll, admin, _treasury, _treasury_owner, _employee) = setup_payroll(&env);

    let reference = BytesN::from_array(&env, &[9u8; 32]);
    payroll.index_receipt_reference(&admin, &999u64, &reference);
}

#[test]
#[should_panic(expected = "Digest cannot be all-zero bytes")]
fn test_receipt_reference_rejects_zero_reference() {
    let env = Env::default();
    let (payroll, admin, _treasury, _treasury_owner, employee) = setup_payroll(&env);

    let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 10_000);
    let run_id = payroll.batch_process_payroll(
        &proofs,
        &amounts,
        &employees,
        &10_000,
        &test_nonce(&env, 72),
        &None,
    );

    let reference = BytesN::from_array(&env, &[0u8; 32]);
    payroll.index_receipt_reference(&admin, &run_id, &reference);
}

#[test]
#[should_panic(expected = "Duplicate receipt reference: already bound to a payroll run")]
fn test_receipt_reference_rejects_duplicates() {
    let env = Env::default();
    let (payroll, admin, _treasury, _treasury_owner, employee) = setup_payroll(&env);

    // Run A executes payments; run B reaches the completed state via
    // prepare + finalize (nullifiers are single-use per batch, so a second
    // full batch would be rejected for an unrelated reason).
    let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 10_000);
    let run_a = payroll.batch_process_payroll(
        &proofs.clone(),
        &amounts.clone(),
        &employees.clone(),
        &10_000,
        &test_nonce(&env, 73),
        &None,
    );
    let run_b = payroll.prepare_payroll_run(
        &proofs.clone(),
        &amounts.clone(),
        &employees.clone(),
        &10_000,
        &test_nonce(&env, 74),
        &None,
    );
    payroll.finalize_payroll_run(&admin, &run_b);

    let reference = BytesN::from_array(&env, &[10u8; 32]);
    payroll.index_receipt_reference(&admin, &run_a, &reference.clone());
    payroll.index_receipt_reference(&admin, &run_b, &reference);
}

#[test]
#[should_panic(expected = "Unauthorized")]
fn test_receipt_reference_is_admin_only() {
    let env = Env::default();
    let (payroll, _admin, _treasury, _treasury_owner, employee) = setup_payroll(&env);

    let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 10_000);
    let run_id = payroll.batch_process_payroll(
        &proofs,
        &amounts,
        &employees,
        &10_000,
        &test_nonce(&env, 75),
        &None,
    );

    let outsider = Address::generate(&env);
    let reference = BytesN::from_array(&env, &[11u8; 32]);
    payroll.index_receipt_reference(&outsider, &run_id, &reference);
}

#[test]
fn test_unknown_receipt_reference_returns_none() {
    let env = Env::default();
    let (payroll, _admin, _treasury, _treasury_owner, _employee) = setup_payroll(&env);

    let reference = BytesN::from_array(&env, &[12u8; 32]);
    assert_eq!(
        payroll.get_run_by_receipt_reference(&reference.clone()),
        None
    );
    assert!(!payroll.has_receipt_reference(&reference.clone()));
    assert_eq!(payroll.get_receipt_reference_count(), 0);
}
