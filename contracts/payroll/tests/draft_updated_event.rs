//! Payroll draft updated event snapshot coverage (#423).

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
fn test_draft_updated_event_snapshot_includes_period_and_update_counts() {
    let env = Env::default();
    let (payroll, admin) = setup_payroll(&env);
    let period = Symbol::new(&env, "aug_2026");
    let draft_id = payroll.create_run_draft(&admin, &10_000i128, &2u32, &period);

    let before = env.events().all().len();
    payroll.amend_run_draft(&admin, &draft_id, &12_500i128, &3u32);
    let event = env.events().all().get(before + 1).unwrap();

    let topic: Symbol = event.1.get(1).unwrap().try_into_val(&env).unwrap();
    assert_eq!(topic, Symbol::new(&env, "draft_updated"));

    let (emitted_draft_id, emitted_period, total, employee_count, amendment_count): (u64, Symbol, i128, u32, u32) =
        event.2.try_into_val(&env).unwrap();
    assert_eq!(emitted_draft_id, draft_id);
    assert_eq!(emitted_period, period);
    assert_eq!(total, 12_500i128);
    assert_eq!(employee_count, 3u32);
    assert_eq!(amendment_count, 1u32);
}