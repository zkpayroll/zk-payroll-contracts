//! Correction request expiry handling (#622).
//!
//! A *correction request* is a `Pending` payroll run draft that can still be
//! amended. When an admin configures an expiry window, a request left untouched
//! past that window can no longer be corrected and may be retired by anyone.
//!
//! Coverage:
//! - The policy is opt-in: with no policy, amendments are unrestricted and the
//!   contract behaves exactly as it did before #622.
//! - The policy lifecycle: admin sets/updates/clears, non-admin rejected,
//!   `0` clears enforcement.
//! - An amendment inside the window (and exactly on the boundary) is accepted.
//! - An amendment past the window is rejected with an actionable message, and
//!   the rejected call mutates no draft state.
//! - The clock is an *inactivity* window: an accepted amendment refreshes it, so
//!   an actively-corrected request never lapses.
//! - Anyone can retire a lapsed request; a live request or one with expiry
//!   disabled cannot be retired; retirement is terminal/idempotent and frees the
//!   period for a fresh draft.
//! - Resolved drafts (finalized) and unknown ids never report as expired.

#![cfg(test)]

use ::token::Token;
use payroll::correction_request_expiry::CorrectionRequestExpiryPolicy;
use payroll::{Payroll, PayrollClient, RunDraftState};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{Address, BytesN, Env, Symbol, Vec};

/// One hour. Shorter than every other payroll window so the gates never interact.
const WINDOW: u64 = 3_600;

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

    let verifier_id = env.register(ProofVerifier, ());
    let verifier_client = ProofVerifierClient::new(env, &verifier_id);
    verifier_client.init_verifier_admin(&Address::generate(env));
    verifier_client.initialize_verifier(&mock_vk(env));

    let commitment_id = env.register(SalaryCommitmentContract, ());
    let commitment_client = SalaryCommitmentContractClient::new(env, &commitment_id);
    commitment_client.init_commitment_admin(&Address::generate(env));

    let token_id = env.register(Token, ());
    let payroll_id = env.register(Payroll, ());
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

/// Move the ledger clock forward `seconds`.
fn advance(env: &Env, seconds: u64) {
    env.ledger()
        .set_timestamp(env.ledger().timestamp() + seconds);
}

fn draft(payroll: &PayrollClient<'_>, admin: &Address, period: &Symbol) -> u64 {
    payroll.create_run_draft(admin, &1_000i128, &3u32, period)
}

fn policy(env: &Env, max_age_seconds: u64) -> CorrectionRequestExpiryPolicy {
    CorrectionRequestExpiryPolicy {
        max_age_seconds,
        set_at: 0,
        set_by: Address::generate(env),
    }
}

#[test]
fn unconfigured_policy_leaves_corrections_unrestricted() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);
    let period = Symbol::new(&env, "default_on");

    // No policy is configured out of the box.
    assert_eq!(payroll.get_correction_request_expiry(), None);

    let draft_id = draft(&payroll, &admin, &period);
    // However long the request sits idle, it never expires while disabled.
    advance(&env, 10 * WINDOW);
    assert!(!payroll.is_correction_request_expired(&draft_id));

    payroll.amend_run_draft(&admin, &draft_id, &1_100i128, &4u32);
    assert_eq!(payroll.get_run_draft(&draft_id).amendment_count, 1);
}

#[test]
fn configured_policy_is_readable() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);

    payroll.set_correction_request_expiry(&admin, &WINDOW);

    let policy = payroll.get_correction_request_expiry().expect("policy set");
    assert_eq!(policy.max_age_seconds, WINDOW);
    assert_eq!(policy.set_by, admin);
    assert_eq!(policy.set_at, env.ledger().timestamp());
}

#[test]
fn setting_the_policy_again_replaces_it() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);

    payroll.set_correction_request_expiry(&admin, &WINDOW);
    payroll.set_correction_request_expiry(&admin, &(WINDOW * 2));

    assert_eq!(
        payroll
            .get_correction_request_expiry()
            .unwrap()
            .max_age_seconds,
        WINDOW * 2
    );
}

#[test]
fn non_admin_cannot_set_the_policy() {
    let env = Env::default();
    let (payroll, _admin) = setup_payroll(&env);
    let stranger = Address::generate(&env);

    let result = payroll.try_set_correction_request_expiry(&stranger, &WINDOW);
    assert!(result.is_err());
    assert_eq!(payroll.get_correction_request_expiry(), None);
}

#[test]
fn zero_window_clears_enforcement() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);
    let period = Symbol::new(&env, "cleared");

    payroll.set_correction_request_expiry(&admin, &WINDOW);
    let draft_id = draft(&payroll, &admin, &period);
    advance(&env, WINDOW + 1);
    assert!(payroll.is_correction_request_expired(&draft_id));

    // Passing 0 clears the policy, restoring unrestricted corrections.
    payroll.set_correction_request_expiry(&admin, &0u64);
    assert_eq!(payroll.get_correction_request_expiry(), None);
    assert!(!payroll.is_correction_request_expired(&draft_id));

    payroll.amend_run_draft(&admin, &draft_id, &1_100i128, &4u32);
    assert_eq!(payroll.get_run_draft(&draft_id).amendment_count, 1);
}

#[test]
fn amendment_inside_the_window_is_accepted() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);
    let period = Symbol::new(&env, "inside");

    payroll.set_correction_request_expiry(&admin, &WINDOW);
    let draft_id = draft(&payroll, &admin, &period);
    advance(&env, WINDOW / 2);

    assert!(!payroll.is_correction_request_expired(&draft_id));
    payroll.amend_run_draft(&admin, &draft_id, &1_100i128, &4u32);
    assert_eq!(payroll.get_run_draft(&draft_id).total_amount, 1_100);
}

#[test]
fn amendment_exactly_on_the_boundary_is_accepted() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);
    let period = Symbol::new(&env, "boundary");

    payroll.set_correction_request_expiry(&admin, &WINDOW);
    let draft_id = draft(&payroll, &admin, &period);
    // Updated at `T`; the window is half-open, so `T + WINDOW` is still valid.
    advance(&env, WINDOW);

    assert!(!payroll.is_correction_request_expired(&draft_id));
    payroll.amend_run_draft(&admin, &draft_id, &1_100i128, &4u32);
    assert_eq!(payroll.get_run_draft(&draft_id).amendment_count, 1);
}

#[test]
fn expired_amendment_is_rejected_and_changes_nothing() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);
    let period = Symbol::new(&env, "lapsed");

    payroll.set_correction_request_expiry(&admin, &WINDOW);
    let draft_id = draft(&payroll, &admin, &period);
    advance(&env, WINDOW + 1);

    assert!(payroll.is_correction_request_expired(&draft_id));
    assert!(payroll
        .try_amend_run_draft(&admin, &draft_id, &1_500i128, &9u32)
        .is_err());

    // A rejected correction writes nothing: the draft is untouched.
    let stored = payroll.get_run_draft(&draft_id);
    assert_eq!(stored.state, RunDraftState::Pending);
    assert_eq!(stored.total_amount, 1_000);
    assert_eq!(stored.employee_count, 3);
    assert_eq!(stored.amendment_count, 0);
}

#[test]
fn an_active_amendment_refreshes_the_window() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);
    let period = Symbol::new(&env, "refresh");

    payroll.set_correction_request_expiry(&admin, &WINDOW);
    let draft_id = draft(&payroll, &admin, &period);

    // Correct at 60% of the window, which resets the inactivity clock.
    advance(&env, WINDOW / 2 + WINDOW / 10);
    payroll.amend_run_draft(&admin, &draft_id, &1_100i128, &3u32);

    // A further 60% of the window is past the *creation* window but inside the
    // window measured from the last amendment, so it is still accepted.
    advance(&env, WINDOW / 2 + WINDOW / 10);
    assert!(!payroll.is_correction_request_expired(&draft_id));
    payroll.amend_run_draft(&admin, &draft_id, &1_200i128, &3u32);
    assert_eq!(payroll.get_run_draft(&draft_id).amendment_count, 2);

    // Once the request has genuinely gone idle past the window it lapses.
    advance(&env, WINDOW + 1);
    assert!(payroll.is_correction_request_expired(&draft_id));
}

#[test]
fn anyone_can_retire_a_lapsed_request() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);
    let period = Symbol::new(&env, "retire");
    let bystander = Address::generate(&env);

    payroll.set_correction_request_expiry(&admin, &WINDOW);
    let draft_id = draft(&payroll, &admin, &period);
    advance(&env, WINDOW + 1);

    // Retiring stale work is permissionless, matching run expiration (#474).
    payroll.expire_correction_request(&bystander, &draft_id);

    let stored = payroll.get_run_draft(&draft_id);
    assert_eq!(stored.state, RunDraftState::Expired);
    // A resolved draft is no longer an open correction request.
    assert!(!payroll.is_correction_request_expired(&draft_id));
}

#[test]
fn retiring_a_lapsed_request_frees_the_period() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);
    let period = Symbol::new(&env, "freed");

    payroll.set_correction_request_expiry(&admin, &WINDOW);
    let stale = draft(&payroll, &admin, &period);
    advance(&env, WINDOW + 1);

    // The stale draft occupies the period's single pending slot (#398)...
    assert!(payroll
        .try_create_run_draft(&admin, &2_000i128, &2u32, &period)
        .is_err());

    payroll.expire_correction_request(&admin, &stale);

    // ...and retiring it releases the slot for a fresh draft.
    let fresh = draft(&payroll, &admin, &period);
    assert_eq!(payroll.get_run_draft(&fresh).state, RunDraftState::Pending);
}

#[test]
fn retiring_a_live_request_is_rejected() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);
    let period = Symbol::new(&env, "live");

    payroll.set_correction_request_expiry(&admin, &WINDOW);
    let draft_id = draft(&payroll, &admin, &period);
    advance(&env, WINDOW / 2);

    assert!(payroll
        .try_expire_correction_request(&admin, &draft_id)
        .is_err());
    assert_eq!(
        payroll.get_run_draft(&draft_id).state,
        RunDraftState::Pending
    );
}

#[test]
fn retiring_is_rejected_while_expiry_is_disabled() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);
    let period = Symbol::new(&env, "disabled");

    // No policy: `expire_correction_request` has no window to measure against.
    let draft_id = draft(&payroll, &admin, &period);
    advance(&env, 10 * WINDOW);

    assert!(payroll
        .try_expire_correction_request(&admin, &draft_id)
        .is_err());
    assert_eq!(
        payroll.get_run_draft(&draft_id).state,
        RunDraftState::Pending
    );
}

#[test]
fn retirement_is_terminal_and_idempotent() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);
    let period = Symbol::new(&env, "terminal");

    payroll.set_correction_request_expiry(&admin, &WINDOW);
    let draft_id = draft(&payroll, &admin, &period);
    advance(&env, WINDOW + 1);

    payroll.expire_correction_request(&admin, &draft_id);
    // A second attempt fails because the request is no longer pending.
    assert!(payroll
        .try_expire_correction_request(&admin, &draft_id)
        .is_err());
    assert_eq!(
        payroll.get_run_draft(&draft_id).state,
        RunDraftState::Expired
    );
}

#[test]
fn resolved_drafts_never_reference_a_lapsed_request() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);
    let period = Symbol::new(&env, "resolved");
    let unknown_period = Symbol::new(&env, "unknown");

    payroll.set_correction_request_expiry(&admin, &WINDOW);

    // An unknown draft id never reports as expired.
    assert!(!payroll.is_correction_request_expired(&999u64));

    // A finalized draft is not an open correction request, however old it is.
    let draft_id = draft(&payroll, &admin, &period);
    payroll.finalize_run_draft(&admin, &draft_id);
    advance(&env, WINDOW + 1);
    assert!(!payroll.is_correction_request_expired(&draft_id));

    // A fresh draft in a different period is unaffected by that history.
    let fresh = draft(&payroll, &admin, &unknown_period);
    assert!(!payroll.is_correction_request_expired(&fresh));
}

#[test]
fn raising_the_window_revives_a_lapsed_request() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);
    let period = Symbol::new(&env, "raised");

    payroll.set_correction_request_expiry(&admin, &WINDOW);
    let draft_id = draft(&payroll, &admin, &period);
    advance(&env, WINDOW + 1);
    assert!(payroll
        .try_amend_run_draft(&admin, &draft_id, &1_100i128, &3u32)
        .is_err());

    // Raising the window is the documented operator escape hatch.
    payroll.set_correction_request_expiry(&admin, &(WINDOW * 100));
    payroll.amend_run_draft(&admin, &draft_id, &1_100i128, &3u32);
    assert_eq!(payroll.get_run_draft(&draft_id).amendment_count, 1);
}

#[test]
fn expiry_rejection_consumes_no_correction_budget() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);
    let period = Symbol::new(&env, "budget");

    // A generous correction-authorization policy (#577) plus an expiry window.
    payroll.set_correction_auth_limits(&admin, &5u32, &10_000i128, &50u32);
    payroll.set_correction_request_expiry(&admin, &WINDOW);
    let draft_id = draft(&payroll, &admin, &period);
    advance(&env, WINDOW + 1);

    // The expiry gate fires before usage is recorded, so the period's
    // correction budget is untouched by the rejection.
    assert!(payroll
        .try_amend_run_draft(&admin, &draft_id, &1_100i128, &3u32)
        .is_err());
    let usage = payroll.get_correction_usage(&period);
    assert_eq!(usage.correction_count, 0);
    assert_eq!(usage.total_delta, 0);
}

// ── Pure expiry-window semantics ─────────────────────────────────────────────

#[test]
fn window_semantics_are_half_open_and_saturating() {
    let env = Env::default();

    // A request inside the window is still correctable.
    assert!(!policy(&env, 100).is_expired(1_000, 950));
    // Exactly on the boundary (`updated_at + max_age_seconds`) it is not expired.
    assert!(!policy(&env, 100).is_expired(1_050, 950));
    // One second past the boundary it has lapsed.
    assert!(policy(&env, 100).is_expired(1_051, 950));
    // A saturating add must not wrap a huge window into the past, which would
    // wrongly expire every request.
    assert!(!policy(&env, u64::MAX).is_expired(u64::MAX, 1));
}
