#![cfg(test)]

use payroll::{Payroll, PayrollClient, RunDraftState};
use proof_verifier::{ProofVerifier, VerificationKey};
use salary_commitment::SalaryCommitmentContract;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, Symbol, Vec};
use token::Token;

#[allow(dead_code)]
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

fn setup_payroll_environment(env: &Env) -> (PayrollClient<'static>, Address, Address) {
    env.mock_all_auths();

    let verifier_id = env.register_contract(None, ProofVerifier);
    let commitment_id = env.register_contract(None, SalaryCommitmentContract);
    let token_id = env.register_contract(None, Token);

    let treasury = Address::generate(env);
    let admin = Address::generate(env);
    let treasury_owner = Address::generate(env);

    let payroll_id = env.register_contract(None, Payroll);
    let payroll_client = PayrollClient::new(env, &payroll_id);

    payroll_client.initialize(
        &admin,
        &token_id,
        &verifier_id,
        &commitment_id,
        &treasury,
        &treasury_owner,
    );

    (payroll_client, admin, treasury_owner)
}

#[test]
fn test_draft_state_transitions_full_lifecycle_success() {
    let env = Env::default();
    let (client, admin, _) = setup_payroll_environment(&env);

    // 1. Created (starts in Pending state)
    let draft_id =
        client.create_run_draft(&admin, &50_000i128, &5u32, &Symbol::new(&env, "Q1_2026"));
    let draft = client.get_run_draft(&draft_id);
    assert_eq!(draft.state, RunDraftState::Pending);
    assert_eq!(draft.amendment_count, 0);
    assert!(!client.is_draft_state_terminal(&draft.state));

    // 2. Updated (amended)
    client.amend_run_draft(&admin, &draft_id, &55_000i128, &6u32);
    let draft = client.get_run_draft(&draft_id);
    assert_eq!(draft.state, RunDraftState::Pending);
    assert_eq!(draft.total_amount, 55_000i128);
    assert_eq!(draft.employee_count, 6u32);
    assert_eq!(draft.amendment_count, 1);

    // 3. Finalized
    client.finalize_run_draft(&admin, &draft_id);
    let draft = client.get_run_draft(&draft_id);
    assert_eq!(draft.state, RunDraftState::Finalized);

    // 4. Submitted
    client.submit_run_draft(&admin, &draft_id);
    let draft = client.get_run_draft(&draft_id);
    assert_eq!(draft.state, RunDraftState::Submitted);
    assert!(client.is_draft_state_terminal(&draft.state));
}

#[test]
fn test_draft_cancellation_flow() {
    let env = Env::default();
    let (client, admin, _) = setup_payroll_environment(&env);

    let draft_id =
        client.create_run_draft(&admin, &20_000i128, &2u32, &Symbol::new(&env, "CANCEL_ME"));
    client.cancel_run_draft(&admin, &draft_id);

    let draft = client.get_run_draft(&draft_id);
    assert_eq!(draft.state, RunDraftState::Cancelled);
    assert!(client.is_draft_state_terminal(&draft.state));

    // Attempting further modifications or transitions must fail
    assert!(client
        .try_amend_run_draft(&admin, &draft_id, &25_000i128, &3u32)
        .is_err());
    assert!(client.try_finalize_run_draft(&admin, &draft_id).is_err());
    assert!(client.try_submit_run_draft(&admin, &draft_id).is_err());
    assert!(client.try_cancel_run_draft(&admin, &draft_id).is_err());
    assert!(client.try_expire_run_draft(&admin, &draft_id).is_err());
}

#[test]
fn test_draft_expiration_flow() {
    let env = Env::default();
    let (client, admin, _) = setup_payroll_environment(&env);

    let draft_id =
        client.create_run_draft(&admin, &30_000i128, &3u32, &Symbol::new(&env, "EXPIRE_ME"));
    client.expire_run_draft(&admin, &draft_id);

    let draft = client.get_run_draft(&draft_id);
    assert_eq!(draft.state, RunDraftState::Expired);
    assert!(client.is_draft_state_terminal(&draft.state));

    // Cannot submit an expired draft
    assert!(client.try_submit_run_draft(&admin, &draft_id).is_err());
}

#[test]
fn test_unauthorized_draft_action_rejected() {
    let env = Env::default();
    let (client, admin, _) = setup_payroll_environment(&env);
    let unauthorized_user = Address::generate(&env);

    let draft_id =
        client.create_run_draft(&admin, &10_000i128, &1u32, &Symbol::new(&env, "UNAUTH"));

    assert!(client
        .try_amend_run_draft(&unauthorized_user, &draft_id, &12_000i128, &2u32)
        .is_err());
    assert!(client
        .try_finalize_run_draft(&unauthorized_user, &draft_id)
        .is_err());
    assert!(client
        .try_submit_run_draft(&unauthorized_user, &draft_id)
        .is_err());
    assert!(client
        .try_cancel_run_draft(&unauthorized_user, &draft_id)
        .is_err());
    assert!(client
        .try_expire_run_draft(&unauthorized_user, &draft_id)
        .is_err());
}

#[test]
fn test_draft_state_transition_matrix() {
    let env = Env::default();
    let (client, _, _) = setup_payroll_environment(&env);

    // Pending transitions
    assert!(client.is_draft_transition_allowed(&RunDraftState::Pending, &RunDraftState::Finalized));
    assert!(client.is_draft_transition_allowed(&RunDraftState::Pending, &RunDraftState::Submitted));
    assert!(client.is_draft_transition_allowed(&RunDraftState::Pending, &RunDraftState::Cancelled));
    assert!(client.is_draft_transition_allowed(&RunDraftState::Pending, &RunDraftState::Expired));

    // Finalized transitions
    assert!(
        client.is_draft_transition_allowed(&RunDraftState::Finalized, &RunDraftState::Submitted)
    );
    assert!(
        client.is_draft_transition_allowed(&RunDraftState::Finalized, &RunDraftState::Cancelled)
    );
    assert!(client.is_draft_transition_allowed(&RunDraftState::Finalized, &RunDraftState::Expired));

    // Forbidden transitions from terminal states
    assert!(!client.is_draft_transition_allowed(&RunDraftState::Submitted, &RunDraftState::Pending));
    assert!(
        !client.is_draft_transition_allowed(&RunDraftState::Cancelled, &RunDraftState::Finalized)
    );
    assert!(!client.is_draft_transition_allowed(&RunDraftState::Expired, &RunDraftState::Submitted));
}
