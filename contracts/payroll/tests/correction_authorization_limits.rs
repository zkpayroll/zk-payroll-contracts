//! Correction authorization limits for payroll draft amendments (issue #577).
//!
//! Covers: limits are opt-in, a configured policy is readable and audited,
//! each of the three ceilings independently rejects the correction that would
//! exceed it, usage counters accumulate per period, a rejected correction
//! consumes no budget and mutates no draft state, and limits apply per period
//! rather than contract-wide.

#![cfg(test)]

use ::token::Token;
use payroll::correction_authorization::CorrectionUsage;
use payroll::{Payroll, PayrollClient};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
use soroban_sdk::testutils::{Address as _, Ledger as _};
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
    env.ledger().set_timestamp(1_700_000_000);

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

/// Set only the correction-count ceiling; the other two stay disabled.
fn set_count_ceiling(payroll: &PayrollClient<'_>, admin: &Address, max: u32) {
    payroll.set_correction_auth_limits(admin, &max, &0i128, &0u32);
}

#[test]
fn unconfigured_limits_leave_amendments_unrestricted() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);
    let period = Symbol::new(&env, "unconfigured");

    assert_eq!(payroll.get_correction_auth_limits(), None);

    let draft_id = payroll.create_run_draft(&admin, &1_000i128, &3u32, &period);
    // No policy configured: many amendments in the same period are all accepted.
    payroll.amend_run_draft(&admin, &draft_id, &1_100i128, &4u32);
    payroll.amend_run_draft(&admin, &draft_id, &1_200i128, &5u32);
    payroll.amend_run_draft(&admin, &draft_id, &1_000i128, &6u32);

    let draft = payroll.get_run_draft(&draft_id);
    assert_eq!(draft.amendment_count, 3);
    assert_eq!(draft.total_amount, 1_000);

    // Nothing is counted while the feature is unused.
    assert_eq!(payroll.get_correction_usage(&period), CorrectionUsage::ZERO);
}

#[test]
fn configured_limits_are_readable() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);

    payroll.set_correction_auth_limits(&admin, &7u32, &50_000i128, &40u32);

    let limits = payroll.get_correction_auth_limits().unwrap();
    assert_eq!(limits.max_corrections_per_period, 7);
    assert_eq!(limits.max_total_delta, 50_000);
    assert_eq!(limits.max_employees_corrected, 40);
    assert!(limits.is_effective());
}

#[test]
fn re_setting_limits_replaces_the_stored_policy() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);

    set_count_ceiling(&payroll, &admin, 3);
    assert_eq!(
        payroll
            .get_correction_auth_limits()
            .unwrap()
            .max_corrections_per_period,
        3
    );

    // A later call replaces the whole policy rather than merging with it.
    payroll.set_correction_auth_limits(&admin, &5u32, &1_000i128, &9u32);
    let limits = payroll.get_correction_auth_limits().unwrap();
    assert_eq!(limits.max_corrections_per_period, 5);
    assert_eq!(limits.max_total_delta, 1_000);
    assert_eq!(limits.max_employees_corrected, 9);
}

#[test]
fn correction_count_ceiling_blocks_further_corrections() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);
    let period = Symbol::new(&env, "count_cap");

    set_count_ceiling(&payroll, &admin, 1);
    let draft_id = payroll.create_run_draft(&admin, &1_000i128, &3u32, &period);

    // The first correction fits the budget.
    payroll.amend_run_draft(&admin, &draft_id, &1_100i128, &3u32);

    // The second would exceed it.
    let rejected = payroll.try_amend_run_draft(&admin, &draft_id, &1_200i128, &3u32);
    assert!(rejected.is_err());

    let draft = payroll.get_run_draft(&draft_id);
    assert_eq!(draft.amendment_count, 1);
    assert_eq!(draft.total_amount, 1_100);

    let usage = payroll.get_correction_usage(&period);
    assert_eq!(usage.correction_count, 1);
}

#[test]
fn correction_amount_ceiling_blocks_oversized_correction() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);
    let period = Symbol::new(&env, "amount_cap");

    payroll.set_correction_auth_limits(&admin, &0u32, &100i128, &0u32);
    let draft_id = payroll.create_run_draft(&admin, &1_000i128, &3u32, &period);

    // A 150 move exceeds the 100 budget.
    assert!(payroll
        .try_amend_run_draft(&admin, &draft_id, &1_150i128, &3u32)
        .is_err());

    // Exactly on the budget is accepted.
    payroll.amend_run_draft(&admin, &draft_id, &1_100i128, &3u32);
    assert_eq!(payroll.get_run_draft(&draft_id).total_amount, 1_100);

    let usage = payroll.get_correction_usage(&period);
    assert_eq!(usage.correction_count, 1);
    assert_eq!(usage.total_delta, 100);
}

#[test]
fn lowering_total_amount_also_consumes_the_amount_budget() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);
    let period = Symbol::new(&env, "lower_cap");

    payroll.set_correction_auth_limits(&admin, &0u32, &150i128, &0u32);
    let draft_id = payroll.create_run_draft(&admin, &1_000i128, &3u32, &period);

    // Lowering the total by 100 consumes 100 of the budget.
    payroll.amend_run_draft(&admin, &draft_id, &900i128, &3u32);
    assert_eq!(payroll.get_correction_usage(&period).total_delta, 100);

    // A further 100 move would total 200, past the 150 budget.
    assert!(payroll
        .try_amend_run_draft(&admin, &draft_id, &800i128, &3u32)
        .is_err());
}

#[test]
fn employee_ceiling_blocks_oversized_correction() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);
    let period = Symbol::new(&env, "employee_cap");

    payroll.set_correction_auth_limits(&admin, &0u32, &0i128, &5u32);
    let draft_id = payroll.create_run_draft(&admin, &1_000i128, &3u32, &period);

    // Carrying 6 employees exceeds the budget of 5.
    assert!(payroll
        .try_amend_run_draft(&admin, &draft_id, &1_100i128, &6u32)
        .is_err());

    // Exactly 5 fits.
    payroll.amend_run_draft(&admin, &draft_id, &1_100i128, &5u32);
    assert_eq!(payroll.get_run_draft(&draft_id).employee_count, 5);

    let usage = payroll.get_correction_usage(&period);
    assert_eq!(usage.employees_corrected, 5);
    assert_eq!(usage.correction_count, 1);
}

#[test]
fn usage_accumulates_across_corrections() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);
    let period = Symbol::new(&env, "accumulate");

    // A generous policy so the counters, not the ceilings, are under test.
    payroll.set_correction_auth_limits(&admin, &10u32, &10_000i128, &100u32);
    let draft_id = payroll.create_run_draft(&admin, &1_000i128, &2u32, &period);

    payroll.amend_run_draft(&admin, &draft_id, &1_100i128, &4u32);
    payroll.amend_run_draft(&admin, &draft_id, &1_050i128, &7u32);

    let usage = payroll.get_correction_usage(&period);
    assert_eq!(usage.correction_count, 2);
    assert_eq!(usage.total_delta, 100 + 50);
    assert_eq!(usage.employees_corrected, 4 + 7);
}

#[test]
fn limits_are_scoped_to_their_own_period() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);
    let period_a = Symbol::new(&env, "scope_a");
    let period_b = Symbol::new(&env, "scope_b");

    set_count_ceiling(&payroll, &admin, 1);

    let draft_a = payroll.create_run_draft(&admin, &1_000i128, &2u32, &period_a);
    payroll.amend_run_draft(&admin, &draft_a, &1_100i128, &2u32);
    // Period A is now exhausted.
    assert!(payroll
        .try_amend_run_draft(&admin, &draft_a, &1_200i128, &2u32)
        .is_err());

    // Period B has its own budget and is unaffected by period A's usage.
    let draft_b = payroll.create_run_draft(&admin, &2_000i128, &2u32, &period_b);
    payroll.amend_run_draft(&admin, &draft_b, &2_100i128, &2u32);

    assert_eq!(payroll.get_correction_usage(&period_a).correction_count, 1);
    assert_eq!(payroll.get_correction_usage(&period_b).correction_count, 1);
}

#[test]
fn rejected_correction_does_not_consume_budget() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);
    let period = Symbol::new(&env, "no_burn");

    payroll.set_correction_auth_limits(&admin, &0u32, &100i128, &0u32);
    let draft_id = payroll.create_run_draft(&admin, &1_000i128, &3u32, &period);

    assert!(payroll
        .try_amend_run_draft(&admin, &draft_id, &1_150i128, &3u32)
        .is_err());

    // The rejection wrote nothing, so the whole budget is still available.
    assert_eq!(payroll.get_correction_usage(&period), CorrectionUsage::ZERO);

    payroll.amend_run_draft(&admin, &draft_id, &1_100i128, &3u32);
    assert_eq!(payroll.get_correction_usage(&period).total_delta, 100);
}

#[test]
fn rejected_correction_leaves_the_draft_unchanged() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);
    let period = Symbol::new(&env, "unchanged");

    payroll.set_correction_auth_limits(&admin, &0u32, &10i128, &0u32);
    let draft_id = payroll.create_run_draft(&admin, &1_000i128, &3u32, &period);

    assert!(payroll
        .try_amend_run_draft(&admin, &draft_id, &1_500i128, &9u32)
        .is_err());

    let draft = payroll.get_run_draft(&draft_id);
    assert_eq!(draft.total_amount, 1_000);
    assert_eq!(draft.employee_count, 3);
    assert_eq!(draft.amendment_count, 0);
}

#[test]
fn zero_ceilings_disable_enforcement_but_are_still_readable() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);
    let period = Symbol::new(&env, "all_zero");

    // All-zero ceilings store a policy that constrains nothing.
    payroll.set_correction_auth_limits(&admin, &0u32, &0i128, &0u32);
    let limits = payroll.get_correction_auth_limits().unwrap();
    assert!(!limits.is_effective());

    let draft_id = payroll.create_run_draft(&admin, &1_000i128, &3u32, &period);
    payroll.amend_run_draft(&admin, &draft_id, &9_000i128, &9u32);
    payroll.amend_run_draft(&admin, &draft_id, &1_000i128, &1u32);

    let draft = payroll.get_run_draft(&draft_id);
    assert_eq!(draft.amendment_count, 2);

    // An ineffective policy counts nothing, exactly like an unset one.
    assert_eq!(payroll.get_correction_usage(&period), CorrectionUsage::ZERO);
}

#[test]
fn non_admin_cannot_set_limits() {
    let env = Env::default();
    let (payroll, _admin) = setup_payroll(&env);
    let stranger = Address::generate(&env);

    let result = payroll.try_set_correction_auth_limits(&stranger, &1u32, &1i128, &1u32);
    assert!(result.is_err());
    assert_eq!(payroll.get_correction_auth_limits(), None);
}

#[test]
fn negative_amount_ceiling_is_rejected() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);

    let result = payroll.try_set_correction_auth_limits(&admin, &0u32, &-1i128, &0u32);
    assert!(result.is_err());
    assert_eq!(payroll.get_correction_auth_limits(), None);
}

#[test]
fn clearing_limits_restores_unrestricted_amendments() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);
    let period = Symbol::new(&env, "cleared");

    set_count_ceiling(&payroll, &admin, 1);
    let draft_id = payroll.create_run_draft(&admin, &1_000i128, &3u32, &period);
    payroll.amend_run_draft(&admin, &draft_id, &1_100i128, &3u32);
    assert!(payroll
        .try_amend_run_draft(&admin, &draft_id, &1_200i128, &3u32)
        .is_err());

    // Replacing the policy with all-zero ceilings clears enforcement.
    payroll.set_correction_auth_limits(&admin, &0u32, &0i128, &0u32);
    payroll.amend_run_draft(&admin, &draft_id, &1_200i128, &3u32);
    assert_eq!(payroll.get_run_draft(&draft_id).amendment_count, 2);
}
