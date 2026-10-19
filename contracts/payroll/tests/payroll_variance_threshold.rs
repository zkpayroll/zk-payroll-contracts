//! Payroll variance threshold validation (issue #644).
//!
//! Covers: the policy is opt-in (unconfigured amendments are unrestricted),
//! a configured policy is readable and replaceable, amendments within the
//! ceiling (including exactly on the boundary) succeed, amendments past the
//! ceiling are rejected without mutating the draft or burning correction
//! budget, the zero-threshold strict edge case, the full-range boundary,
//! invalid thresholds and unauthorized callers are rejected, clearing
//! restores unrestricted behaviour, and the read-only preflight reports a
//! breach without writing state.

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

#[test]
fn unconfigured_threshold_leaves_amendments_unrestricted() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);
    let period = Symbol::new(&env, "unconfigured");

    assert_eq!(payroll.get_payroll_variance_threshold(), None);

    let draft_id = payroll.create_run_draft(&admin, &1_000i128, &3u32, &period);
    // No threshold configured: even a 9x move is accepted.
    payroll.amend_run_draft(&admin, &draft_id, &9_000i128, &3u32);
    assert_eq!(payroll.get_run_draft(&draft_id).total_amount, 9_000);

    // The preflight reports no configured threshold and always passes.
    let check = payroll.check_payroll_variance(&1_000i128, &9_000i128);
    assert!(check.within_threshold);
    assert!(!check.threshold_configured);
    assert_eq!(check.variance_bps, 80_000);
}

#[test]
fn threshold_is_readable_and_replaceable() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);

    payroll.set_payroll_variance_threshold(&admin, &1_000u32);
    assert_eq!(payroll.get_payroll_variance_threshold(), Some(1_000));

    // A later call replaces the whole policy.
    payroll.set_payroll_variance_threshold(&admin, &500u32);
    assert_eq!(payroll.get_payroll_variance_threshold(), Some(500));
}

#[test]
fn within_threshold_amendment_succeeds() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);
    let period = Symbol::new(&env, "within");

    payroll.set_payroll_variance_threshold(&admin, &1_000u32); // 10%
    let draft_id = payroll.create_run_draft(&admin, &1_000i128, &3u32, &period);

    // A 5% raise fits inside the 10% ceiling.
    payroll.amend_run_draft(&admin, &draft_id, &1_050i128, &3u32);
    let draft = payroll.get_run_draft(&draft_id);
    assert_eq!(draft.total_amount, 1_050);
    assert_eq!(draft.amendment_count, 1);
}

#[test]
fn exact_boundary_amendment_succeeds() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);
    let period_up = Symbol::new(&env, "bound_up");
    let period_down = Symbol::new(&env, "bound_down");

    payroll.set_payroll_variance_threshold(&admin, &1_000u32); // 10%

    // Exactly +10% (1000 bps) is accepted.
    let up = payroll.create_run_draft(&admin, &1_000i128, &3u32, &period_up);
    payroll.amend_run_draft(&admin, &up, &1_100i128, &3u32);
    assert_eq!(payroll.get_run_draft(&up).total_amount, 1_100);

    // Exactly -10% is accepted too.
    let down = payroll.create_run_draft(&admin, &1_000i128, &3u32, &period_down);
    payroll.amend_run_draft(&admin, &down, &900i128, &3u32);
    assert_eq!(payroll.get_run_draft(&down).total_amount, 900);
}

#[test]
fn exceeds_threshold_amendment_is_rejected_without_mutation() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);
    let period = Symbol::new(&env, "breach");

    payroll.set_payroll_variance_threshold(&admin, &1_000u32); // 10%
    let draft_id = payroll.create_run_draft(&admin, &1_000i128, &3u32, &period);

    // +11% (1100 bps) exceeds the 1000 bps ceiling.
    assert!(payroll
        .try_amend_run_draft(&admin, &draft_id, &1_110i128, &3u32)
        .is_err());

    let draft = payroll.get_run_draft(&draft_id);
    assert_eq!(draft.total_amount, 1_000);
    assert_eq!(draft.amendment_count, 0);
}

#[test]
fn lowering_total_beyond_threshold_is_rejected() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);
    let period = Symbol::new(&env, "breach_dn");

    payroll.set_payroll_variance_threshold(&admin, &1_000u32); // 10%
    let draft_id = payroll.create_run_draft(&admin, &1_000i128, &3u32, &period);

    // -20% exceeds the ceiling just as a raise would.
    assert!(payroll
        .try_amend_run_draft(&admin, &draft_id, &800i128, &3u32)
        .is_err());
    assert_eq!(payroll.get_run_draft(&draft_id).total_amount, 1_000);
}

#[test]
fn zero_threshold_requires_exact_match() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);
    let period = Symbol::new(&env, "strict");

    // 0 bps: only an identical total is accepted.
    payroll.set_payroll_variance_threshold(&admin, &0u32);
    let draft_id = payroll.create_run_draft(&admin, &5_000i128, &3u32, &period);

    payroll.amend_run_draft(&admin, &draft_id, &5_000i128, &4u32);
    assert_eq!(payroll.get_run_draft(&draft_id).amendment_count, 1);

    assert!(payroll
        .try_amend_run_draft(&admin, &draft_id, &5_001i128, &4u32)
        .is_err());
    assert_eq!(payroll.get_run_draft(&draft_id).amendment_count, 1);
}

#[test]
fn full_range_threshold_allows_doubling_but_not_more() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);
    let period = Symbol::new(&env, "fullrange");

    payroll.set_payroll_variance_threshold(&admin, &10_000u32); // 100%
    let draft_id = payroll.create_run_draft(&admin, &1_000i128, &3u32, &period);

    // Doubling is exactly a 100% move and fits.
    payroll.amend_run_draft(&admin, &draft_id, &2_000i128, &3u32);
    assert_eq!(payroll.get_run_draft(&draft_id).total_amount, 2_000);

    // Anything more does not.
    assert!(payroll
        .try_amend_run_draft(&admin, &draft_id, &4_001i128, &3u32)
        .is_err());
}

#[test]
fn rejected_variance_consumes_no_correction_budget() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);
    let period = Symbol::new(&env, "no_burn");

    // A generous correction policy plus a strict variance ceiling.
    payroll.set_correction_auth_limits(&admin, &10u32, &100_000i128, &100u32);
    payroll.set_payroll_variance_threshold(&admin, &1_000u32);
    let draft_id = payroll.create_run_draft(&admin, &1_000i128, &3u32, &period);

    // Variance rejects first: the correction budget must be untouched.
    assert!(payroll
        .try_amend_run_draft(&admin, &draft_id, &5_000i128, &3u32)
        .is_err());
    assert_eq!(payroll.get_correction_usage(&period), CorrectionUsage::ZERO);

    // A variance-conforming amendment still counts normally.
    payroll.amend_run_draft(&admin, &draft_id, &1_050i128, &3u32);
    assert_eq!(payroll.get_correction_usage(&period).correction_count, 1);
}

#[test]
fn invalid_threshold_is_rejected() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);

    // 10_001 bps is above the 100% maximum.
    assert!(payroll
        .try_set_payroll_variance_threshold(&admin, &10_001u32)
        .is_err());
    assert_eq!(payroll.get_payroll_variance_threshold(), None);
}

#[test]
fn non_admin_cannot_set_or_clear_threshold() {
    let env = Env::default();
    let (payroll, _admin) = setup_payroll(&env);
    let stranger = Address::generate(&env);

    assert!(payroll
        .try_set_payroll_variance_threshold(&stranger, &1_000u32)
        .is_err());
    assert_eq!(payroll.get_payroll_variance_threshold(), None);

    assert!(payroll
        .try_clear_payroll_variance_threshold(&stranger)
        .is_err());
}

#[test]
fn clearing_threshold_restores_unrestricted_amendments() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);
    let period = Symbol::new(&env, "cleared");

    payroll.set_payroll_variance_threshold(&admin, &1_000u32);
    let draft_id = payroll.create_run_draft(&admin, &1_000i128, &3u32, &period);
    assert!(payroll
        .try_amend_run_draft(&admin, &draft_id, &5_000i128, &3u32)
        .is_err());

    payroll.clear_payroll_variance_threshold(&admin);
    assert_eq!(payroll.get_payroll_variance_threshold(), None);

    payroll.amend_run_draft(&admin, &draft_id, &5_000i128, &3u32);
    assert_eq!(payroll.get_run_draft(&draft_id).total_amount, 5_000);
}

#[test]
fn check_preflight_reports_breach_without_writing_state() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);
    let period = Symbol::new(&env, "preflight");

    payroll.set_payroll_variance_threshold(&admin, &1_000u32);
    let draft_id = payroll.create_run_draft(&admin, &1_000i128, &3u32, &period);

    let breaching = payroll.check_payroll_variance(&1_000i128, &1_500i128);
    assert!(!breaching.within_threshold);
    assert!(breaching.threshold_configured);
    assert_eq!(breaching.max_variance_bps, 1_000);
    assert_eq!(breaching.variance_bps, 5_000);

    let passing = payroll.check_payroll_variance(&1_000i128, &1_050i128);
    assert!(passing.within_threshold);
    assert_eq!(passing.variance_bps, 500);

    // Preflight wrote nothing: the draft is untouched and still amendable.
    assert_eq!(payroll.get_run_draft(&draft_id).amendment_count, 0);
    payroll.amend_run_draft(&admin, &draft_id, &1_050i128, &3u32);
    assert_eq!(payroll.get_run_draft(&draft_id).amendment_count, 1);
}

#[test]
fn require_entrypoint_enforces_threshold_directly() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);

    payroll.set_payroll_variance_threshold(&admin, &1_000u32);

    // Passing call succeeds.
    payroll.require_payroll_variance(&1_000i128, &1_050i128);
    // Breaching call fails.
    assert!(payroll
        .try_require_payroll_variance(&1_000i128, &1_500i128)
        .is_err());

    // With no threshold configured, any totals pass.
    payroll.clear_payroll_variance_threshold(&admin);
    payroll.require_payroll_variance(&1_000i128, &99_000_000i128);
}
