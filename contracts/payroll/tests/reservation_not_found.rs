//! Treasury reservation not-found coverage (#424).

#![cfg(test)]

use ::token::{Token, TokenClient};
use payroll::{Payroll, PayrollClient};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, Vec};

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
    let token_client = TokenClient::new(env, &token_id);

    let payroll_id = env.register_contract(None, Payroll);
    let payroll_client = PayrollClient::new(env, &payroll_id);

    let treasury = Address::generate(env);
    token_client.mint(&treasury, &1_000_000i128);

    payroll_client.initialize(
        &Address::generate(env),
        &token_id,
        &verifier_id,
        &commitment_id,
        &treasury,
        &Address::generate(env),
    );

    (payroll_client, token_id)
}

#[test]
fn test_missing_required_reservation_returns_error() {
    let env = Env::default();
    let (payroll, token_id) = setup_payroll(&env);

    let result = payroll.try_get_required_reservation_expiry(&token_id);
    assert!(result.is_err());
}

#[test]
fn test_required_reservation_returns_existing_policy() {
    let env = Env::default();
    let (payroll, token_id) = setup_payroll(&env);
    let admin = payroll.get_addresses().admin;

    payroll.set_reservation_expiry_policy(&admin, &token_id, &5000i128, &3600u64);

    let reservation = payroll.get_required_reservation_expiry(&token_id);
    assert_eq!(reservation.asset, token_id);
    assert_eq!(reservation.reserved_amount, 5000i128);
}