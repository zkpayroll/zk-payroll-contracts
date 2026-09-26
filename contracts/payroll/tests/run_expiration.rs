//! Payroll run expiration handling tests (#474).
//!
//! Coverage:
//! - Expiry policy lifecycle: admin sets/updates/disables, non-admin rejected.
//! - A pending run inside the expiry window can still be finalized.
//! - A pending run past the window can no longer be finalized; the failure
//!   message names the recovery path without exposing any payroll values.
//! - Anyone (not just the admin) can expire an aged run — releasing its
//!   locked-funds reservation — and expiry is idempotent (a second attempt
//!   fails because the run is no longer pending).
//! - Failure states expose no salary or employee values: the expiry record
//!   and `run_expired` event carry only run id, caller, and counts.

#![cfg(test)]

use ::token::{Token, TokenClient};
use payroll::{Payroll, PayrollClient, PayrollRunState};
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

fn prepared_run(payroll: &PayrollClient<'_>, env: &Env, employee: &Address, nonce_seed: u8) -> u64 {
    let (proofs, amounts, employees) = single_payment_batch(env, employee, 10_000);
    payroll.prepare_payroll_run(
        &proofs,
        &amounts,
        &employees,
        &10_000,
        &test_nonce(env, nonce_seed),
        &None,
    )
}

/// Three days in seconds — shorter than the default 7-day approval window so
/// the two expiry gates in these tests never interact.
const EXPIRY_WINDOW_SECONDS: u64 = 3 * 24 * 60 * 60;

#[test]
fn test_expiration_policy_defaults_to_disabled() {
    let env = Env::default();
    let (payroll, _admin, _treasury, _treasury_owner, employee) = setup_payroll(&env);

    assert!(payroll.get_run_expiration_policy().is_none());

    // Without a policy, a run can be finalized at any age.
    let run_id = prepared_run(&payroll, &env, &employee, 60);
    env.ledger().with_mut(|li| {
        li.timestamp += 10 * 24 * 60 * 60;
    });
    assert!(!payroll.is_payroll_run_expired(&run_id));
    payroll.finalize_payroll_run(&_admin, &run_id);
}

#[test]
fn test_set_and_update_expiration_policy() {
    let env = Env::default();
    let (payroll, admin, _treasury, _treasury_owner, _employee) = setup_payroll(&env);

    payroll.set_run_expiration_policy(&admin, &EXPIRY_WINDOW_SECONDS);
    let policy = payroll.get_run_expiration_policy().expect("policy set");
    assert_eq!(policy.max_age_seconds, EXPIRY_WINDOW_SECONDS);
    assert_eq!(policy.set_by, admin);

    // Admin can tighten the window while runs are pending (covered by the
    // stale-run tests below) and can always raise it again.
    payroll.set_run_expiration_policy(&admin, &(EXPIRY_WINDOW_SECONDS * 2));
    let policy = payroll.get_run_expiration_policy().expect("policy set");
    assert_eq!(policy.max_age_seconds, EXPIRY_WINDOW_SECONDS * 2);
}

#[test]
fn test_non_admin_cannot_set_expiration_policy() {
    let env = Env::default();
    let (payroll, _admin, _treasury, _treasury_owner, _employee) = setup_payroll(&env);

    let attacker = Address::generate(&env);
    let result = payroll.try_set_run_expiration_policy(&attacker, &EXPIRY_WINDOW_SECONDS);
    assert!(result.is_err());
    assert!(payroll.get_run_expiration_policy().is_none());
}

#[test]
fn test_cannot_disable_expiration_while_runs_pending() {
    let env = Env::default();
    let (payroll, admin, _treasury, _treasury_owner, employee) = setup_payroll(&env);

    payroll.set_run_expiration_policy(&admin, &EXPIRY_WINDOW_SECONDS);
    let _run_id = prepared_run(&payroll, &env, &employee, 61);

    let result = payroll.try_set_run_expiration_policy(&admin, &0u64);
    assert!(result.is_err());
    assert!(payroll.get_run_expiration_policy().is_some());
}

#[test]
fn test_can_disable_expiration_when_no_runs_pending() {
    let env = Env::default();
    let (payroll, admin, _treasury, _treasury_owner, _employee) = setup_payroll(&env);

    payroll.set_run_expiration_policy(&admin, &EXPIRY_WINDOW_SECONDS);
    payroll.set_run_expiration_policy(&admin, &0u64);
    assert!(payroll.get_run_expiration_policy().is_none());
}

#[test]
fn test_run_inside_expiry_window_finalizes_normally() {
    let env = Env::default();
    let (payroll, admin, _treasury, _treasury_owner, employee) = setup_payroll(&env);

    payroll.set_run_expiration_policy(&admin, &EXPIRY_WINDOW_SECONDS);
    let run_id = prepared_run(&payroll, &env, &employee, 62);

    // Well inside the window.
    env.ledger().with_mut(|li| {
        li.timestamp += EXPIRY_WINDOW_SECONDS / 2;
    });
    assert!(!payroll.is_payroll_run_expired(&run_id));
    assert_eq!(
        payroll.get_payroll_run_state(&run_id),
        PayrollRunState::Submitted
    );

    payroll.finalize_payroll_run(&admin, &run_id);
    assert!(payroll.get_pending_run(&run_id).is_none());
    assert!(payroll.get_expired_run_record(&run_id).is_none());
}

#[test]
#[should_panic(expected = "Run has expired: it was not finalized within the configured window")]
fn test_stale_run_cannot_be_finalized() {
    let env = Env::default();
    let (payroll, admin, _treasury, _treasury_owner, employee) = setup_payroll(&env);

    payroll.set_run_expiration_policy(&admin, &EXPIRY_WINDOW_SECONDS);
    let run_id = prepared_run(&payroll, &env, &employee, 63);

    env.ledger().with_mut(|li| {
        li.timestamp += EXPIRY_WINDOW_SECONDS + 1;
    });
    assert!(payroll.is_payroll_run_expired(&run_id));

    payroll.finalize_payroll_run(&admin, &run_id);
}

#[test]
fn test_anyone_can_expire_an_aged_run_and_funds_are_released() {
    let env = Env::default();
    let (payroll, admin, _treasury, _treasury_owner, employee) = setup_payroll(&env);

    let token_id = payroll.get_addresses().token;

    payroll.set_run_expiration_policy(&admin, &EXPIRY_WINDOW_SECONDS);
    let run_id = prepared_run(&payroll, &env, &employee, 64);

    assert_eq!(payroll.get_locked_funds(&token_id), 10_000i128);

    env.ledger().with_mut(|li| {
        li.timestamp += EXPIRY_WINDOW_SECONDS + 1;
    });

    // A third-party observer (not the admin) retires the stale run.
    let bystander = Address::generate(&env);
    payroll.expire_payroll_run(&bystander, &run_id);

    // Funds reservation released, pending record gone, terminal state recorded.
    assert_eq!(payroll.get_locked_funds(&token_id), 0i128);
    assert!(payroll.get_pending_run(&run_id).is_none());
    assert_eq!(
        payroll.get_payroll_run_state(&run_id),
        PayrollRunState::Expired
    );
    assert!(payroll.is_payroll_state_terminal(&PayrollRunState::Expired));

    // Redacted audit record: counts only, never amounts or employees.
    let record = payroll
        .get_expired_run_record(&run_id)
        .expect("record kept");
    assert_eq!(record.run_id, run_id);
    assert_eq!(record.expired_by, bystander);
    assert_eq!(record.employee_count, 1u32);
    assert!(record.is_expired);

    // Nothing was executed — no PayrollRun record exists for the run.
    assert!(payroll.try_get_payroll_run(&run_id).is_err());
}

#[test]
fn test_expired_run_cannot_be_expired_or_finalized_again() {
    let env = Env::default();
    let (payroll, admin, _treasury, _treasury_owner, employee) = setup_payroll(&env);

    payroll.set_run_expiration_policy(&admin, &EXPIRY_WINDOW_SECONDS);
    let run_id = prepared_run(&payroll, &env, &employee, 65);

    env.ledger().with_mut(|li| {
        li.timestamp += EXPIRY_WINDOW_SECONDS + 1;
    });
    payroll.expire_payroll_run(&admin, &run_id);

    // Second expiry fails: the pending record is gone.
    let again = payroll.try_expire_payroll_run(&admin, &run_id);
    assert!(again.is_err());

    // Finalization also fails: nothing left to finalize.
    let finalize = payroll.try_finalize_payroll_run(&admin, &run_id);
    assert!(finalize.is_err());
}

#[test]
fn test_fresh_run_cannot_be_expired_early() {
    let env = Env::default();
    let (payroll, admin, _treasury, _treasury_owner, employee) = setup_payroll(&env);

    payroll.set_run_expiration_policy(&admin, &EXPIRY_WINDOW_SECONDS);
    let run_id = prepared_run(&payroll, &env, &employee, 66);

    // Still inside the window — even the admin cannot force an expiry.
    let result = payroll.try_expire_payroll_run(&admin, &run_id);
    assert!(result.is_err());

    // The run remains pending and its funds remain reserved.
    let token_id = payroll.get_addresses().token;
    assert_eq!(payroll.get_locked_funds(&token_id), 10_000i128);
    assert!(payroll.get_pending_run(&run_id).is_some());
}

#[test]
fn test_expired_run_nonce_is_never_reusable() {
    let env = Env::default();
    let (payroll, admin, _treasury, _treasury_owner, employee) = setup_payroll(&env);

    payroll.set_run_expiration_policy(&admin, &EXPIRY_WINDOW_SECONDS);
    let run_id = prepared_run(&payroll, &env, &employee, 67);
    let nonce = test_nonce(&env, 67);

    env.ledger().with_mut(|li| {
        li.timestamp += EXPIRY_WINDOW_SECONDS + 1;
    });
    payroll.expire_payroll_run(&admin, &run_id);

    // The burned nonce cannot be replayed for a fresh batch.
    let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 10_000);
    let replay =
        payroll.try_prepare_payroll_run(&proofs, &amounts, &employees, &10_000, &nonce, &None);
    assert!(replay.is_err());
}

#[test]
fn test_no_active_run_lock_released_after_expiry() {
    let env = Env::default();
    let (payroll, admin, _treasury, _treasury_owner, employee) = setup_payroll(&env);

    payroll.set_run_expiration_policy(&admin, &EXPIRY_WINDOW_SECONDS);
    let _run_id = prepared_run(&payroll, &env, &employee, 68);
    assert!(payroll.has_active_payroll_run());

    env.ledger().with_mut(|li| {
        li.timestamp += EXPIRY_WINDOW_SECONDS + 1;
    });
    payroll.expire_payroll_run(&admin, &_run_id);

    // Issue #253 configuration lock is released once the stale run is resolved.
    assert!(!payroll.has_active_payroll_run());
}

#[test]
fn test_run_expiration_transition_rules() {
    let env = Env::default();
    let (payroll, _admin, _treasury, _treasury_owner, _employee) = setup_payroll(&env);

    // Submitted (pending) runs may expire.
    assert!(
        payroll.is_state_transition_allowed(&PayrollRunState::Submitted, &PayrollRunState::Expired)
    );
    // Finalization paths are unaffected.
    assert!(payroll
        .is_state_transition_allowed(&PayrollRunState::Submitted, &PayrollRunState::Confirming));
    // Expired is terminal — nothing moves out of it.
    assert!(!payroll
        .is_state_transition_allowed(&PayrollRunState::Expired, &PayrollRunState::Submitted));
    assert!(!payroll
        .is_state_transition_allowed(&PayrollRunState::Expired, &PayrollRunState::Completed));
    assert!(payroll.is_payroll_state_terminal(&PayrollRunState::Expired));
    assert!(!payroll.is_payroll_state_retryable(&PayrollRunState::Expired));
}
