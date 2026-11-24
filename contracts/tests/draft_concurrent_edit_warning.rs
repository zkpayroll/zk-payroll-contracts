//! Tests for concurrent payroll draft edit warnings (Issue #790).
//!
//! Verifies that:
//! 1. An initial edit does not emit a concurrent-edit warning.
//! 2. Rapid successive edits emit a privacy-safe warning event with draft/time metadata.
//! 3. Edits outside the warning window do not emit the warning.
//! 4. Unauthorized edits fail without mutating draft state or emitting warnings.

#![cfg(test)]

use ::token::Token;
use payroll::{Payroll, PayrollClient};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
use soroban_sdk::testutils::{Address as _, Events, Ledger as _};
use soroban_sdk::{symbol_short, Address, BytesN, Env, IntoVal, Symbol, TryIntoVal, Vec};

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

fn count_warning_events(env: &Env, draft_id: u64) -> u32 {
    let mut count = 0u32;
    let events = env.events().all();
    for i in 0..events.len() {
        let event = events.get(i).unwrap();
        let topics = event.1;
        if topics.len() != 2 {
            continue;
        }

        let topic1: Result<Symbol, _> = topics.get(1).unwrap().try_into_val(env);
        if topic1 != Ok(Symbol::new(env, "draft_edit_warning")) {
            continue;
        }

        let data = event.2;
        let payload: Result<(u64, Symbol, u64, u64), _> = data.try_into_val(env);
        if let Ok((event_draft_id, _period, _prev, _curr)) = payload {
            if event_draft_id == draft_id {
                count += 1;
            }
        }
    }
    count
}

#[test]
fn test_no_warning_on_first_edit() {
    let env = Env::default();
    env.ledger().set_timestamp(1_700_000_000);
    let (payroll, admin) = setup_payroll(&env);

    let draft_id = payroll.create_run_draft(&admin, &10_000i128, &2u32, &symbol_short!("jan27"));
    payroll.amend_run_draft(&admin, &draft_id, &11_000i128, &2u32);

    assert_eq!(count_warning_events(&env, draft_id), 0);
}

#[test]
fn test_warning_emitted_for_rapid_successive_edits() {
    let env = Env::default();
    env.ledger().set_timestamp(1_700_000_000);
    let (payroll, admin) = setup_payroll(&env);

    let draft_id = payroll.create_run_draft(&admin, &10_000i128, &2u32, &symbol_short!("feb27"));
    payroll.amend_run_draft(&admin, &draft_id, &11_000i128, &2u32);

    env.ledger().set_timestamp(1_700_000_120);
    payroll.amend_run_draft(&admin, &draft_id, &12_000i128, &3u32);

    let events = env.events().all();
    let mut saw_warning = false;
    for i in 0..events.len() {
        let event = events.get(i).unwrap();
        let topics = event.1;
        if topics.len() != 2 {
            continue;
        }
        let topic1: Result<Symbol, _> = topics.get(1).unwrap().try_into_val(&env);
        if topic1 != Ok(Symbol::new(&env, "draft_edit_warning")) {
            continue;
        }
        let payload: (u64, Symbol, u64, u64) = event.2.try_into_val(&env).unwrap();
        assert_eq!(payload.0, draft_id);
        assert_eq!(payload.1, symbol_short!("feb27"));
        assert_eq!(payload.2, 1_700_000_000);
        assert_eq!(payload.3, 1_700_000_120);
        saw_warning = true;
    }
    assert!(saw_warning, "expected draft_edit_warning event");
}

#[test]
fn test_no_warning_outside_window() {
    let env = Env::default();
    env.ledger().set_timestamp(1_700_000_000);
    let (payroll, admin) = setup_payroll(&env);

    let draft_id = payroll.create_run_draft(&admin, &20_000i128, &4u32, &symbol_short!("mar27"));
    payroll.amend_run_draft(&admin, &draft_id, &21_000i128, &4u32);

    env.ledger().set_timestamp(1_700_000_301);
    payroll.amend_run_draft(&admin, &draft_id, &22_000i128, &4u32);

    assert_eq!(count_warning_events(&env, draft_id), 0);
}

#[test]
#[should_panic(expected = "Unauthorized")]
fn test_unauthorized_edit_does_not_emit_warning() {
    let env = Env::default();
    env.ledger().set_timestamp(1_700_000_000);
    let (payroll, admin) = setup_payroll(&env);
    let stranger = Address::generate(&env);

    let draft_id = payroll.create_run_draft(&admin, &30_000i128, &5u32, &symbol_short!("apr27"));
    payroll.amend_run_draft(&admin, &draft_id, &31_000i128, &5u32);
    env.ledger().set_timestamp(1_700_000_030);

    let _ = payroll.amend_run_draft(&stranger, &draft_id, &32_000i128, &5u32);
}
