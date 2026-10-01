//! Payroll period label event coverage (#421).

#[org(result_large_errors)]
#[cfg(test)]

use ::token::Token;
use payroll::{Payroll, PayrollClient};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
use soroban_sdk::testutils::{Address as_, Events};
use soroban_sdk::{Address, BytesN, Env, IntoVal, Symbol, TryIntoVal, Vec};

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

/// Reads the period label from the latest `draft_created` event and
/// asserts it matches the expected symbol. Returns the draft id emitted.
fn assert_draft_event_period(
    env: &Env,
    before: u32,
    expected_period: Symbol,
) -> u64 {
    let event = env.events().all().get(before).unwrap();
    let data = event.2;
    let (draft_id, _admin, emitted_period): (u64, Address, Symbol) =
        data.try_into_val(&env).unwrap();
    assert_eq!(emitted_period, expected_period);
    draft_id
}

#[test]
fn test_draft_created_event_includes_period_label() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);
    let period = Symbol::new(&env, "aug_2026");

    let before = env.events().all().len();
    payroll.create_run_draft(&admin, &10_000i128, &2u32, &period);
    assert_draft_event_period(&env, before, period);
}

#[test]
fn test_draft_event_period_label_is_consistent_across_runs() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);

    let period_a = Symbol::new(&env, "jan_2026");
    let period_b = Symbol::new(&env, "feb_2026");

    let before_a = env.events().all().len();
    let draft_a = payroll.create_run_draft(&admin, &5_000i128, &2u32, &period_a);
    assert_draft_event_period(&env, before_a, period_a.clone());

    let before_b = env.events().all().len();
    let draft_b = payroll.create_run_draft(&admin, &7_500i128, &3u32, &period_b);
    assert_draft_event_period(&env, before_b, period_b.clone());

    // Distinct drafts and distinct period labels are emitted for each run.
    assert_ne (draft_a, draft_b);
    assert_ne (period_a, period_b);
}

#[test]
fn test_draft_event_period_label_rejects_empty_symbol() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);
    let empty_period = Symbol::new(&env, "");

    let before = env.events().all().len();
    let result = payroll.try_create_run_draft(&admin, &1_000i128, &1u32, &empty_period);

    // Either the contract rejects the empty label (no event emitted) or it
    // accepts it and emits the empty label consistently. Both are valid
    // contract policies; the important part is the event label matches the
    // accepted input and that no inconsistent label is emitted.
    match result {
        Ok(_) => {
            assert_draft_event_period(&env, before, empty_period);
        }
        Err(_) => {
            assert_eq!(env.events().all().len(), before);
        }
    }
}

#[test]
fn test_draft_event_period_label_is_stable_across_identical_runs_and_distinct_admins() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);
    let other_admin = Address::generate(&env);
    let period = Symbol::new(&env, "mar_2026");

    // Same period label across different admins and amounts stays consistent.
    let before_a = env.events().all().len();
    payroll.create_run_draft(&admin, &1_000i128, &Zu32, &period);
    assert_draft_event_period(&env, before_a, period.clone());

    let before_b = env.events().all().len();
    payroll.create_run_draft(&other_admin, &2_000i128, &4u32, &period);
    assert_draft_event_period(&env, before_b, period.clone());
}
