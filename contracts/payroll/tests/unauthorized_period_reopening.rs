//! Contract tests for unauthorized period reopening (#484).
//!
//! Acceptance Criteria:
//! - Prove that only the appropriate role (admin) can reopen a finalized payroll period.
//! - Unauthorized callers cannot reopen a finalized/frozen payroll period.
//! - Failure states are actionable, predictable, and do not expose sensitive payroll values.
//! - Successful reopening allows authorized correction flows (new drafts can be created).
//! - Clear validation handling for non-frozen periods, paused state, and empty labels.

#![cfg(test)]

use ::token::{Token, TokenClient};
use pause_manager::{PauseManager, PauseManagerClient};
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

fn setup_payroll(env: &Env) -> (PayrollClient<'_>, Address, Address, Address, Address) {
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

/// Prove that an unauthorized caller cannot reopen a payroll period that was
/// finalized and auto-frozen via draft submission (#484).
#[test]
#[should_panic(expected = "Unauthorized")]
fn test_unauthorized_user_cannot_reopen_finalized_period() {
    let env = Env::default();
    let (payroll, admin, _treasury, _owner, _employee) = setup_payroll(&env);
    let period = Symbol::new(&env, "P2026_09");

    // 1. Create, finalize, and submit a draft to finalize the period
    let draft_id = payroll.create_run_draft(&admin, &5_000i128, &1u32, &period);
    payroll.finalize_run_draft(&admin, &draft_id);
    payroll.submit_run_draft(&admin, &draft_id);

    // Verify period is finalized and frozen
    assert!(payroll.is_period_frozen(&period));
    let freeze = payroll.get_period_freeze(&period).unwrap();
    assert_eq!(freeze.reason, Symbol::new(&env, "finalized"));

    // 2. An unauthorized user attempts to reopen/unfreeze the finalized period
    let attacker = Address::generate(&env);
    payroll.unfreeze_payroll_period(&attacker, &period);
}

/// Prove that an unauthorized caller cannot reopen a payroll period via the
/// `reopen_payroll_period` alias entrypoint (#484).
#[test]
#[should_panic(expected = "Unauthorized")]
fn test_unauthorized_caller_reopen_alias_fails() {
    let env = Env::default();
    let (payroll, admin, _treasury, _owner, _employee) = setup_payroll(&env);
    let period = Symbol::new(&env, "P2026_09");

    let draft_id = payroll.create_run_draft(&admin, &10_000i128, &2u32, &period);
    payroll.finalize_run_draft(&admin, &draft_id);
    payroll.submit_run_draft(&admin, &draft_id);

    assert!(payroll.is_period_frozen(&period));

    let outsider = Address::generate(&env);
    payroll.reopen_payroll_period(&outsider, &period);
}

/// Prove that an unauthorized caller cannot reopen a manually frozen period.
#[test]
#[should_panic(expected = "Unauthorized")]
fn test_unauthorized_cannot_reopen_manually_frozen_period() {
    let env = Env::default();
    let (payroll, admin, _treasury, _owner, _employee) = setup_payroll(&env);
    let period = Symbol::new(&env, "P2026_10");

    payroll.freeze_payroll_period(&admin, &period, &Symbol::new(&env, "audit_lock"));
    assert!(payroll.is_period_frozen(&period));

    let unauthorized = Address::generate(&env);
    payroll.unfreeze_payroll_period(&unauthorized, &period);
}

/// Successful path: only the contract admin can reopen a finalized period.
/// Once reopened, new drafts may be created under the period again.
#[test]
fn test_authorized_admin_can_reopen_finalized_period() {
    let env = Env::default();
    let (payroll, admin, _treasury, _owner, _employee) = setup_payroll(&env);
    let period = Symbol::new(&env, "P2026_09");

    // 1. Finalize period via draft submission
    let draft_id_1 = payroll.create_run_draft(&admin, &5_000i128, &1u32, &period);
    payroll.finalize_run_draft(&admin, &draft_id_1);
    payroll.submit_run_draft(&admin, &draft_id_1);

    assert!(payroll.is_period_frozen(&period));

    // While frozen, creating a new draft is rejected
    assert!(payroll
        .try_create_run_draft(&admin, &6_000i128, &1u32, &period)
        .is_err());

    // 2. Admin reopens the finalized period
    payroll.reopen_payroll_period(&admin, &period);

    // 3. Verify period is no longer frozen
    assert!(!payroll.is_period_frozen(&period));
    assert_eq!(payroll.get_period_freeze(&period), None);

    // 4. Draft creation succeeds again under the reopened period
    let draft_id_2 = payroll.create_run_draft(&admin, &6_000i128, &1u32, &period);
    assert_eq!(draft_id_2, 2);

    let draft_2 = payroll.get_run_draft(&draft_id_2);
    assert_eq!(draft_2.total_amount, 6_000i128);
    assert_eq!(draft_2.period_label, period);
}

/// Edge case: attempting to reopen a period that was never frozen must fail
/// with actionable feedback ("Payroll period is not frozen").
#[test]
#[should_panic(expected = "Payroll period is not frozen")]
fn test_reopen_non_frozen_period_is_rejected() {
    let env = Env::default();
    let (payroll, admin, _treasury, _owner, _employee) = setup_payroll(&env);
    let period = Symbol::new(&env, "NEVER_FROZEN");

    payroll.unfreeze_payroll_period(&admin, &period);
}

/// Edge case: attempting to reopen with an empty period label must be rejected.
#[test]
fn test_reopen_empty_period_label_is_rejected() {
    let env = Env::default();
    let (payroll, admin, _treasury, _owner, _employee) = setup_payroll(&env);
    let empty_period = Symbol::new(&env, "");

    let result = payroll.try_unfreeze_payroll_period(&admin, &empty_period);
    assert!(result.is_err());
}

/// Edge case: reopening while the contract is paused must be blocked.
#[test]
#[should_panic(expected = "Contract is paused")]
fn test_reopen_blocked_while_contract_is_paused() {
    let env = Env::default();
    let (payroll, admin, _treasury, _owner, _employee) = setup_payroll(&env);
    let period = Symbol::new(&env, "P2026_09");

    payroll.freeze_payroll_period(&admin, &period, &Symbol::new(&env, "manual"));
    assert!(payroll.is_period_frozen(&period));

    // Initialize and pause the contract
    let pm_id = env.register_contract(None, PauseManager);
    let pm = PauseManagerClient::new(&env, &pm_id);
    let pm_admin = Address::generate(&env);
    pm.initialize(&pm_admin);
    payroll.set_pause_manager(&pm_id);

    pm.pause();
    assert!(pm.is_paused());

    // Reopen attempt must fail while paused
    payroll.unfreeze_payroll_period(&admin, &period);
}

/// Privacy guarantee: verify that freeze metadata carries only non-sensitive
/// operational fields and never exposes employee addresses or salary figures.
#[test]
fn test_freeze_metadata_preserves_privacy() {
    let env = Env::default();
    let (payroll, admin, _treasury, _owner, _employee) = setup_payroll(&env);
    let period = Symbol::new(&env, "CONFIDENTIAL_PERIOD");

    let draft_id = payroll.create_run_draft(&admin, &250_000i128, &50u32, &period);
    payroll.finalize_run_draft(&admin, &draft_id);
    payroll.submit_run_draft(&admin, &draft_id);

    let freeze = payroll.get_period_freeze(&period).unwrap();
    assert_eq!(freeze.period_label, period);
    assert_eq!(freeze.frozen_by, admin);
    assert_eq!(freeze.reason, Symbol::new(&env, "finalized"));
    // Run count is an aggregate count, not individual employee data
    assert_eq!(freeze.runs_count, 0);
}
