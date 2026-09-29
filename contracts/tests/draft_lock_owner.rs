//! Tests for payroll draft lock owner query behavior (Issue #556).
//!
//! Verifies that:
//! 1. A new draft in `Pending` state is not locked, returning `None`.
//! 2. When a draft is finalized via `finalize_run_draft`, it transitions to locked, returning `Some(admin)`.
//! 3. When a finalized draft is submitted via `submit_run_draft`, the lock owner persists as `Some(admin)`.
//! 4. Cancelled and expired drafts are terminal and not locked, returning `None`.
//! 5. Non-existent draft IDs return `None`.
//! 6. Zero draft ID (`0u64`) triggers actionable validation panic (`Invalid draft ID: must be non-zero`).
//! 7. The query preserves privacy: returns strictly `Option<Address>` without exposing sensitive payroll amounts or employee counts.

#![cfg(test)]

use ::token::Token;
use payroll::{Payroll, PayrollClient};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, Symbol, Vec};

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

fn setup_payroll(env: &Env) -> (PayrollClient<'_>, Address) {
    env.mock_all_auths();
    let verifier_id = env.register_contract(None, ProofVerifier);
    let verifier_client = ProofVerifierClient::new(env, &verifier_id);
    verifier_client.init_verifier_admin(&Address::generate(env));
    verifier_client.initialize_verifier(&mock_vk(env));

    let commitment_id = env.register_contract(None, SalaryCommitmentContract);
    let commitment_client = SalaryCommitmentContractClient::new(env, &commitment_id);
    commitment_client.init_commitment_admin(&Address::generate(env));

    let token_id = env.register_contract(None, Token);
    let payroll_id = env.register_contract(None, Payroll);
    let payroll_client = PayrollClient::new(env, &payroll_id);

    let admin = Address::generate(env);
    payroll_client.initialize(
        &admin,
        &token_id,
        &verifier_id,
        &commitment_id,
        &Address::generate(env),
        &Address::generate(env),
    );
    (payroll_client, admin)
}

#[test]
fn test_draft_lock_owner_pending_returns_none() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);

    let period = Symbol::new(&env, "jan_2027");
    let draft_id = payroll.create_run_draft(&admin, &50_000i128, &5u32, &period);

    // Pending draft is not locked
    assert_eq!(payroll.get_draft_lock_owner(&draft_id), None);
}

#[test]
fn test_draft_lock_owner_finalized_returns_admin() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);

    let period = Symbol::new(&env, "feb_2027");
    let draft_id = payroll.create_run_draft(&admin, &75_000i128, &8u32, &period);

    // Finalize the draft
    payroll.finalize_run_draft(&admin, &draft_id);

    // Finalized draft is locked by admin
    assert_eq!(payroll.get_draft_lock_owner(&draft_id), Some(admin));
}

#[test]
fn test_draft_lock_owner_submitted_returns_admin() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);

    let period = Symbol::new(&env, "mar_2027");
    let draft_id = payroll.create_run_draft(&admin, &120_000i128, &12u32, &period);

    // Finalize and submit the draft
    payroll.finalize_run_draft(&admin, &draft_id);
    payroll.submit_run_draft(&admin, &draft_id);

    // Submitted draft remains in locked state with lock owner as admin
    assert_eq!(payroll.get_draft_lock_owner(&draft_id), Some(admin));
}

#[test]
fn test_draft_lock_owner_cancelled_returns_none() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);

    let period = Symbol::new(&env, "apr_2027");
    let draft_id = payroll.create_run_draft(&admin, &30_000i128, &3u32, &period);

    // Cancel the draft
    payroll.cancel_run_draft(&admin, &draft_id);

    // Cancelled draft is terminal and unlocked
    assert_eq!(payroll.get_draft_lock_owner(&draft_id), None);
}

#[test]
fn test_draft_lock_owner_expired_returns_none() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);

    let period = Symbol::new(&env, "may_2027");
    let draft_id = payroll.create_run_draft(&admin, &40_000i128, &4u32, &period);

    // Expire the draft
    payroll.expire_run_draft(&admin, &draft_id);

    // Expired draft is terminal and unlocked
    assert_eq!(payroll.get_draft_lock_owner(&draft_id), None);
}

#[test]
fn test_draft_lock_owner_nonexistent_returns_none() {
    let env = Env::default();
    let (payroll, _admin) = setup_payroll(&env);

    assert_eq!(payroll.get_draft_lock_owner(&999_999u64), None);
}

#[test]
#[should_panic(expected = "Invalid draft ID: must be non-zero")]
fn test_draft_lock_owner_zero_id_panics() {
    let env = Env::default();
    let (payroll, _admin) = setup_payroll(&env);

    payroll.get_draft_lock_owner(&0u64);
}

#[test]
fn test_draft_lock_owner_query_preserves_privacy() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);

    let period = Symbol::new(&env, "jun_2027");
    let draft_id = payroll.create_run_draft(&admin, &999_999_999i128, &500u32, &period);
    payroll.finalize_run_draft(&admin, &draft_id);

    let lock_owner = payroll.get_draft_lock_owner(&draft_id);
    assert_eq!(lock_owner, Some(admin));
}
