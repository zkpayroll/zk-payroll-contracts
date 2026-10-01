//! Stale approval cleanup tests (#548).
//!
//! `cleanup_stale_approval` removes an approval record that has aged past
//! `max_age_seconds`. It can never authorize a payout either way: `finalize_payroll_run`
//! already refuses to settle once `is_payroll_approval_expired` is true, so
//! cleanup only reclaims the ledger entry. These tests pin that an expired
//! approval is removed, an in-window one is left alone, and non-approval review
//! decisions are never treated as stale.
//!
//! Setup mirrors `approval_expiry.rs` (the #403 tests for the same feature
//! area): the payroll contract's own `initialize` registers the admin, and
//! `add_reviewer` gates reviewer authorization. `env.mock_all_auths()` stands
//! in for the `require_auth` checks on both entry-points.

#![cfg(test)]

use ::token::{Token, TokenClient};
use payroll::{Payroll, PayrollClient, DEFAULT_APPROVAL_EXPIRY_SECONDS};
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

/// Prepare a fresh run for `employee` and approve it with `reviewer`.
/// Returns the new `run_id`.
fn prepare_and_approve(
    payroll: &PayrollClient<'_>,
    env: &Env,
    reviewer: &Address,
    employee: &Address,
    nonce_seed: u8,
) -> u64 {
    let (proofs, amounts, employees) = single_payment_batch(env, employee, 10_000);
    let nonce = test_nonce(env, nonce_seed);
    let run_id = payroll.prepare_payroll_run(&proofs, &amounts, &employees, &10_000, &nonce, &None);
    payroll.approve_payroll_run(reviewer, &run_id);
    run_id
}

/// Happy path: an expired approval is removed, and the removal is reported
/// without disclosing any payroll value.
#[test]
fn cleanup_removes_expired_approval_and_reports_privacy_safe_result() {
    let env = Env::default();
    let (payroll, admin, _treasury, _treasury_owner, employee) = setup_payroll(&env);

    let reviewer = Address::generate(&env);
    payroll.add_reviewer(&admin, &reviewer);

    let run_id = prepare_and_approve(&payroll, &env, &reviewer, &employee, 40);
    assert!(payroll.get_run_review(&run_id).is_some());

    // The stale run's window elapses.
    env.ledger().with_mut(|li| {
        li.timestamp += DEFAULT_APPROVAL_EXPIRY_SECONDS + 1;
    });

    let status = payroll
        .get_stale_approval_status(&run_id, &DEFAULT_APPROVAL_EXPIRY_SECONDS)
        .expect("review exists");
    assert!(status.is_stale, "approval should be reported stale");

    let result = payroll.cleanup_stale_approval(&admin, &run_id, &DEFAULT_APPROVAL_EXPIRY_SECONDS);

    assert!(result.removed);
    assert_eq!(result.run_id, run_id);
    assert_eq!(
        result.expired_at,
        result.reviewed_at + DEFAULT_APPROVAL_EXPIRY_SECONDS
    );

    // The ledger entry is gone.
    assert!(
        payroll.get_run_review(&run_id).is_none(),
        "expired approval must be removed from storage"
    );

    // The status helper now reports nothing, since no review remains.
    assert!(payroll
        .get_stale_approval_status(&run_id, &DEFAULT_APPROVAL_EXPIRY_SECONDS)
        .is_none());
}

/// Happy path, mixed state: cleaning one run must not disturb another run's
/// still-valid approval. This is the "without affecting active ones" case.
#[test]
fn cleanup_of_stale_run_leaves_other_runs_approval_intact() {
    let env = Env::default();
    let (payroll, admin, _treasury, _treasury_owner, employee) = setup_payroll(&env);

    let reviewer = Address::generate(&env);
    payroll.add_reviewer(&admin, &reviewer);

    let stale_run = prepare_and_approve(&payroll, &env, &reviewer, &employee, 41);

    // Age the first approval past its window, then create a second, fresh one.
    env.ledger().with_mut(|li| {
        li.timestamp += DEFAULT_APPROVAL_EXPIRY_SECONDS + 1;
    });
    let fresh_run = prepare_and_approve(&payroll, &env, &reviewer, &employee, 42);

    // Only the first is stale.
    assert!(
        payroll
            .get_stale_approval_status(&stale_run, &DEFAULT_APPROVAL_EXPIRY_SECONDS)
            .expect("stale run has a review")
            .is_stale
    );
    assert!(
        !payroll
            .get_stale_approval_status(&fresh_run, &DEFAULT_APPROVAL_EXPIRY_SECONDS)
            .expect("fresh run has a review")
            .is_stale
    );

    payroll.cleanup_stale_approval(&admin, &stale_run, &DEFAULT_APPROVAL_EXPIRY_SECONDS);

    assert!(payroll.get_run_review(&stale_run).is_none());
    assert!(
        payroll.get_run_review(&fresh_run).is_some(),
        "an in-window approval must survive cleanup of a different run"
    );

    // The surviving approval is still valid, so the run can still finalize.
    assert!(!payroll.is_payroll_approval_expired(&fresh_run, &DEFAULT_APPROVAL_EXPIRY_SECONDS));
}

/// Edge case: nothing stale to remove. The routine rejects a still-valid
/// approval rather than silently deleting a live authorization.
#[test]
fn cleanup_of_in_window_approval_is_rejected_and_record_survives() {
    let env = Env::default();
    let (payroll, admin, _treasury, _treasury_owner, employee) = setup_payroll(&env);

    let reviewer = Address::generate(&env);
    payroll.add_reviewer(&admin, &reviewer);

    let run_id = prepare_and_approve(&payroll, &env, &reviewer, &employee, 43);

    // Freshly approved: well inside the window, nothing is stale.
    let result =
        payroll.try_cleanup_stale_approval(&admin, &run_id, &DEFAULT_APPROVAL_EXPIRY_SECONDS);
    assert!(result.is_err(), "an in-window approval is not stale");

    assert!(
        payroll.get_run_review(&run_id).is_some(),
        "a rejected cleanup must not remove the approval"
    );
    assert!(!payroll.is_payroll_approval_expired(&run_id, &DEFAULT_APPROVAL_EXPIRY_SECONDS));
}

/// Edge case: a run with no review at all. The routine must fail cleanly with
/// an actionable message rather than panicking on a missing key.
#[test]
fn cleanup_with_no_existing_approval_fails_cleanly() {
    let env = Env::default();
    let (payroll, admin, _treasury, _treasury_owner, employee) = setup_payroll(&env);

    let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 10_000);
    let nonce = test_nonce(&env, 44);
    // Prepare but never approve: there is no review to clean up.
    let run_id = payroll.prepare_payroll_run(&proofs, &amounts, &employees, &10_000, &nonce, &None);

    let result =
        payroll.try_cleanup_stale_approval(&admin, &run_id, &DEFAULT_APPROVAL_EXPIRY_SECONDS);
    assert!(result.is_err());
}

/// A `Rejected` decision is never stale under this definition, even long after
/// it was recorded. Cleanup must not erase a reviewer's refusal.
#[test]
fn cleanup_never_removes_a_rejection_even_when_old() {
    let env = Env::default();
    let (payroll, admin, _treasury, _treasury_owner, employee) = setup_payroll(&env);

    let reviewer = Address::generate(&env);
    payroll.add_reviewer(&admin, &reviewer);

    let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 10_000);
    let nonce = test_nonce(&env, 45);
    let run_id = payroll.prepare_payroll_run(&proofs, &amounts, &employees, &10_000, &nonce, &None);
    payroll.reject_payroll_run(&reviewer, &run_id, &soroban_sdk::Symbol::new(&env, "no"));

    env.ledger().with_mut(|li| {
        li.timestamp += DEFAULT_APPROVAL_EXPIRY_SECONDS * 10;
    });

    // Not reported as stale, and refused by the cleanup routine.
    assert!(payroll
        .get_stale_approval_status(&run_id, &DEFAULT_APPROVAL_EXPIRY_SECONDS)
        .is_none());
    assert!(payroll
        .try_cleanup_stale_approval(&admin, &run_id, &DEFAULT_APPROVAL_EXPIRY_SECONDS)
        .is_err());

    assert!(
        payroll.get_run_review(&run_id).is_some(),
        "a rejection must survive cleanup"
    );
}

/// Only the registered admin may clean up.
#[test]
fn cleanup_rejects_non_admin_caller() {
    let env = Env::default();
    let (payroll, admin, _treasury, _treasury_owner, employee) = setup_payroll(&env);

    let reviewer = Address::generate(&env);
    payroll.add_reviewer(&admin, &reviewer);

    let run_id = prepare_and_approve(&payroll, &env, &reviewer, &employee, 46);

    env.ledger().with_mut(|li| {
        li.timestamp += DEFAULT_APPROVAL_EXPIRY_SECONDS + 1;
    });

    let impostor = Address::generate(&env);
    assert!(payroll
        .try_cleanup_stale_approval(&impostor, &run_id, &DEFAULT_APPROVAL_EXPIRY_SECONDS)
        .is_err());
    assert!(
        payroll.get_run_review(&run_id).is_some(),
        "an unauthorized call must not remove anything"
    );
}

/// The exact expiry boundary is not stale: the cutoff is `> reviewed_at +
/// max_age_seconds`, matching `is_payroll_approval_expired`. Cleaning exactly
/// at the boundary must be refused, one tick later must succeed.
#[test]
fn cleanup_respects_exact_expiry_boundary() {
    let env = Env::default();
    let (payroll, admin, _treasury, _treasury_owner, employee) = setup_payroll(&env);

    let reviewer = Address::generate(&env);
    payroll.add_reviewer(&admin, &reviewer);

    let run_id = prepare_and_approve(&payroll, &env, &reviewer, &employee, 47);

    // Exactly at the boundary: still valid, so not cleanable.
    env.ledger().with_mut(|li| {
        li.timestamp += DEFAULT_APPROVAL_EXPIRY_SECONDS;
    });
    assert!(!payroll.is_payroll_approval_expired(&run_id, &DEFAULT_APPROVAL_EXPIRY_SECONDS));
    assert!(payroll
        .try_cleanup_stale_approval(&admin, &run_id, &DEFAULT_APPROVAL_EXPIRY_SECONDS)
        .is_err());
    assert!(payroll.get_run_review(&run_id).is_some());

    // One tick later: stale, and cleanable.
    env.ledger().with_mut(|li| {
        li.timestamp += 1;
    });
    assert!(payroll.is_payroll_approval_expired(&run_id, &DEFAULT_APPROVAL_EXPIRY_SECONDS));
    payroll.cleanup_stale_approval(&admin, &run_id, &DEFAULT_APPROVAL_EXPIRY_SECONDS);
    assert!(payroll.get_run_review(&run_id).is_none());
}
