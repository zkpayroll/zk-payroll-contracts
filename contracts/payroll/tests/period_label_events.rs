//! Payroll period label event coverage (#421).

#![cfg(test)]

use ::token::Token;
use payroll::{Payroll, PayrollClient};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
use soroban_sdk::testutils::{Address as _, Events};
use soroban_sdk::{Address, BytesN, Env, IntoVal, Symbol, TryIntoVal, Vec};

fn mock_vk(env: &Env) -> VerificationKey {
    VerificationKey {
        alpha: BytesN::from_array(env, &[0u8; 64]),
        beta: BytesN::from_array(env, &[0u8; 128]),
        gamma: BytesN::from_array(env, &[0u8; 128]),
        delta: BytesN::from_array(env, &[0u8; 128]),
        ic: Vec::from_array(env, [BytesN::from_array(env, &[0u8; 64]), BytesN::from_array(env, &[0u8; 64]), BytesN::from_array(env, &[0u8; 64]), BytesN::from_array(env, &[0u8; 64])]),
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
    payroll_client.initialize(&admin, &token_id, &verifier_id, &commitment_id, &Address::generate(env), &Address::generate(env));
    (payroll_client, admin)
}

#[test]
fn test_draft_created_event_includes_period_label() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);
    let period = Symbol::new(&env, "aug_2026");

    let before = env.events().all().len();
    payroll.create_run_draft(&admin, &10_000i128, &2u32, &period);
    let event = env.events().all().get(before).unwrap();

    let data = event.2;
    let emitted_period: Symbol = data
        .try_into_val(&env)
        .map(|(_draft_id, _admin, period): (u64, Address, Symbol)| period)
        .unwrap();

    assert_eq!(emitted_period, period);
}