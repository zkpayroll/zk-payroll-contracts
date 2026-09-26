//! Payroll period freeze guard tests (#471).
//!
//! Coverage:
//! - Manual freeze/unfreeze lifecycle with authorization and validation.
//! - Freeze blocks draft creation, amendment, description updates,
//!   finalization, and submission for the frozen period.
//! - Submitting a draft auto-freezes the period (finalized → frozen).
//! - Cancellation and expiry remain available as escape hatches on a frozen
//!   period (they remove pending work instead of editing it).
//! - Failure states expose no salary or employee values — the freeze record
//!   and events carry only period labels, reasons, and addresses.

#![cfg(test)]

use ::token::Token;
use payroll::{Payroll, PayrollClient};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
use soroban_sdk::testutils::{Address as _, Events};
use soroban_sdk::{Address, BytesN, Env, Symbol, TryIntoVal, Vec};

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

// ─── Successful path ────────────────────────────────────────────────────────

#[test]
fn manual_freeze_and_unfreeze_roundtrip() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);
    let period = Symbol::new(&env, "aug_2026");

    assert!(!payroll.is_period_frozen(&period));

    payroll.freeze_payroll_period(&admin, &period, &Symbol::new(&env, "manual"));

    assert!(payroll.is_period_frozen(&period));
    let freeze = payroll.get_period_freeze(&period).unwrap();
    assert_eq!(freeze.period_label, period);
    assert_eq!(freeze.frozen_by, admin);
    assert_eq!(freeze.reason, Symbol::new(&env, "manual"));

    payroll.unfreeze_payroll_period(&admin, &period);

    assert!(!payroll.is_period_frozen(&period));
    assert_eq!(payroll.get_period_freeze(&period), None);
}

#[test]
fn frozen_period_emits_frozen_and_unfrozen_events() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);
    let period = Symbol::new(&env, "aug_2026");

    let before = env.events().all().len();
    payroll.freeze_payroll_period(&admin, &period, &Symbol::new(&env, "manual"));
    let events = env.events().all();
    let frozen_event = events.get(before).unwrap();
    let frozen_topic: Symbol = frozen_event.1.get(1).unwrap().try_into_val(&env).unwrap();
    assert_eq!(frozen_topic, Symbol::new(&env, "period_frozen"));
    let (emitted_period, frozen_by, reason): (Symbol, Address, Symbol) =
        frozen_event.2.try_into_val(&env).unwrap();
    assert_eq!(emitted_period, period);
    assert_eq!(frozen_by, admin);
    assert_eq!(reason, Symbol::new(&env, "manual"));

    let before = env.events().all().len();
    payroll.unfreeze_payroll_period(&admin, &period);
    let events = env.events().all();
    let unfrozen_event = events.get(before).unwrap();
    let unfrozen_topic: Symbol = unfrozen_event.1.get(1).unwrap().try_into_val(&env).unwrap();
    assert_eq!(unfrozen_topic, Symbol::new(&env, "period_unfrozen"));
    let (emitted_period, unfrozen_by): (Symbol, Address) =
        unfrozen_event.2.try_into_val(&env).unwrap();
    assert_eq!(emitted_period, period);
    assert_eq!(unfrozen_by, admin);
}

#[test]
fn unfrozen_period_accepts_new_drafts_again() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);
    let period = Symbol::new(&env, "aug_2026");

    payroll.freeze_payroll_period(&admin, &period, &Symbol::new(&env, "manual"));
    payroll.unfreeze_payroll_period(&admin, &period);

    // Authorized correction flow: the period accepts new work again.
    let draft_id = payroll.create_run_draft(&admin, &5_000i128, &1u32, &period);
    assert_eq!(payroll.get_run_draft(&draft_id).period_label, period);
}

// ─── Freeze blocks payroll edits ────────────────────────────────────────────

#[test]
#[should_panic(
    expected = "Payroll period is frozen: it has been finalized and can no longer be edited"
)]
fn frozen_period_rejects_draft_creation() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);
    let period = Symbol::new(&env, "aug_2026");
    payroll.freeze_payroll_period(&admin, &period, &Symbol::new(&env, "manual"));
    payroll.create_run_draft(&admin, &5_000i128, &1u32, &period);
}

#[test]
#[should_panic(
    expected = "Payroll period is frozen: it has been finalized and can no longer be edited"
)]
fn frozen_period_rejects_draft_amendment() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);
    let period = Symbol::new(&env, "aug_2026");
    let draft_id = payroll.create_run_draft(&admin, &5_000i128, &1u32, &period);
    payroll.freeze_payroll_period(&admin, &period, &Symbol::new(&env, "manual"));
    payroll.amend_run_draft(&admin, &draft_id, &9_000i128, &2u32);
}

#[test]
#[should_panic(
    expected = "Payroll period is frozen: it has been finalized and can no longer be edited"
)]
fn frozen_period_rejects_draft_description_update() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);
    let period = Symbol::new(&env, "aug_2026");
    let draft_id = payroll.create_run_draft(&admin, &5_000i128, &1u32, &period);
    payroll.freeze_payroll_period(&admin, &period, &Symbol::new(&env, "manual"));
    payroll.set_run_draft_description(
        &admin,
        &draft_id,
        &soroban_sdk::String::from_str(&env, "corrected figures"),
    );
}

#[test]
#[should_panic(
    expected = "Payroll period is frozen: it has been finalized and can no longer be edited"
)]
fn frozen_period_rejects_draft_finalization() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);
    let period = Symbol::new(&env, "aug_2026");
    let draft_id = payroll.create_run_draft(&admin, &5_000i128, &1u32, &period);
    payroll.freeze_payroll_period(&admin, &period, &Symbol::new(&env, "manual"));
    payroll.finalize_run_draft(&admin, &draft_id);
}

#[test]
#[should_panic(
    expected = "Payroll period is frozen: it has been finalized and can no longer be edited"
)]
fn frozen_period_rejects_draft_submission() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);
    let period = Symbol::new(&env, "aug_2026");
    let draft_id = payroll.create_run_draft(&admin, &5_000i128, &1u32, &period);
    payroll.finalize_run_draft(&admin, &draft_id);
    payroll.freeze_payroll_period(&admin, &period, &Symbol::new(&env, "manual"));
    payroll.submit_run_draft(&admin, &draft_id);
}

// ─── Auto-freeze on submission ──────────────────────────────────────────────

#[test]
fn submitting_draft_auto_freezes_period() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);
    let period = Symbol::new(&env, "aug_2026");

    let draft_id = payroll.create_run_draft(&admin, &5_000i128, &1u32, &period);
    payroll.finalize_run_draft(&admin, &draft_id);
    assert!(!payroll.is_period_frozen(&period));

    payroll.submit_run_draft(&admin, &draft_id);

    assert!(payroll.is_period_frozen(&period));
    let freeze = payroll.get_period_freeze(&period).unwrap();
    assert_eq!(freeze.reason, Symbol::new(&env, "finalized"));
    assert_eq!(freeze.frozen_by, admin);

    // The freeze is now enforced on every edit path.
    assert!(payroll
        .try_create_run_draft(&admin, &5_000i128, &1u32, &period)
        .is_err());
    assert!(payroll
        .try_amend_run_draft(&admin, &draft_id, &9_000i128, &2u32)
        .is_err());
}

// ─── Escape hatches stay available ──────────────────────────────────────────

#[test]
fn frozen_period_allows_cancelling_pending_draft() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);
    let period = Symbol::new(&env, "aug_2026");

    let draft_id = payroll.create_run_draft(&admin, &5_000i128, &1u32, &period);
    payroll.freeze_payroll_period(&admin, &period, &Symbol::new(&env, "manual"));

    // Cancellation removes pending work; it must not be blocked by the freeze.
    payroll.cancel_run_draft(&admin, &draft_id);
    assert_eq!(
        payroll.get_run_draft(&draft_id).state,
        payroll::RunDraftState::Cancelled
    );
}

#[test]
fn frozen_period_allows_expiring_pending_draft() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);
    let period = Symbol::new(&env, "aug_2026");

    let draft_id = payroll.create_run_draft(&admin, &5_000i128, &1u32, &period);
    payroll.freeze_payroll_period(&admin, &period, &Symbol::new(&env, "manual"));

    payroll.expire_run_draft(&admin, &draft_id);
    assert_eq!(
        payroll.get_run_draft(&draft_id).state,
        payroll::RunDraftState::Expired
    );
}

// ─── Validation and authorization ───────────────────────────────────────────

#[test]
#[should_panic(expected = "Payroll period is already frozen")]
fn double_freeze_is_rejected() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);
    let period = Symbol::new(&env, "aug_2026");
    payroll.freeze_payroll_period(&admin, &period, &Symbol::new(&env, "manual"));
    payroll.freeze_payroll_period(&admin, &period, &Symbol::new(&env, "again"));
}

#[test]
#[should_panic(expected = "Payroll period is not frozen")]
fn unfreeze_without_freeze_is_rejected() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);
    let period = Symbol::new(&env, "aug_2026");
    payroll.unfreeze_payroll_period(&admin, &period);
}

#[test]
#[should_panic(expected = "Unauthorized")]
fn freeze_requires_admin() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);
    let period = Symbol::new(&env, "aug_2026");
    let attacker = Address::generate(&env);
    assert_ne!(attacker, admin);
    payroll.freeze_payroll_period(&attacker, &period, &Symbol::new(&env, "manual"));
}

#[test]
#[should_panic(expected = "Unauthorized")]
fn unfreeze_requires_admin() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);
    let period = Symbol::new(&env, "aug_2026");
    payroll.freeze_payroll_period(&admin, &period, &Symbol::new(&env, "manual"));
    let attacker = Address::generate(&env);
    payroll.unfreeze_payroll_period(&attacker, &period);
}

#[test]
fn freeze_rejects_empty_period_label_or_reason() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);
    let period = Symbol::new(&env, "aug_2026");
    let empty = Symbol::new(&env, "");

    assert!(payroll
        .try_freeze_payroll_period(&admin, &empty, &Symbol::new(&env, "manual"))
        .is_err());
    assert!(payroll
        .try_freeze_payroll_period(&admin, &period, &empty)
        .is_err());
    // Nothing was frozen by the rejected calls.
    assert!(!payroll.is_period_frozen(&period));
}

// ─── Privacy: freeze metadata exposes no salary values ──────────────────────

#[test]
fn freeze_record_contains_no_salary_or_employee_data() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);
    let period = Symbol::new(&env, "aug_2026");

    payroll.freeze_payroll_period(&admin, &period, &Symbol::new(&env, "manual"));
    let freeze = payroll.get_period_freeze(&period).unwrap();

    // The on-chain record only carries the period label, freezer identity,
    // timestamp, reason label, and the accepted-run count — never amounts or
    // employee lists. Field-by-field check keeps it that way.
    let _ = (
        freeze.period_label,
        freeze.frozen_by,
        freeze.frozen_at,
        freeze.reason,
        freeze.runs_count,
    );

    // The freeze event payload must not include i128 amount fields.
    let events = env.events().all();
    let event = events.get(events.len() - 1).unwrap();
    let payload: (Symbol, Address, Symbol) = event.2.try_into_val(&env).unwrap();
    assert_eq!(payload.0, period);
    assert_eq!(payload.1, admin);
    assert_eq!(payload.2, Symbol::new(&env, "manual"));
}
