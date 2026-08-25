//! Admin Handover Integration Tests (#339)

use payroll::{Payroll, PayrollClient};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, Symbol, Vec};
use token::Token;

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

fn setup_payroll(env: &Env) -> (PayrollClient<'_>, Address, Address, Address) {
    env.mock_all_auths();

    let verifier_id = env.register_contract(None, ProofVerifier);
    let verifier_client = ProofVerifierClient::new(env, &verifier_id);
    let verifier_admin = Address::generate(env);
    verifier_client.init_verifier_admin(&verifier_admin);
    verifier_client.initialize_verifier(&mock_vk(env));

    let commitment_id = env.register_contract(None, SalaryCommitmentContract);
    let commitment_client = SalaryCommitmentContractClient::new(env, &commitment_id);
    let commitment_admin = Address::generate(env);
    commitment_client.init_commitment_admin(&commitment_admin);

    let token_id = env.register_contract(None, Token);

    let payroll_id = env.register_contract(None, Payroll);
    let payroll_client = PayrollClient::new(env, &payroll_id);

    let treasury = Address::generate(env);
    let admin = Address::generate(env);
    let treasury_owner = Address::generate(env);

    payroll_client.initialize(
        &admin,
        &token_id,
        &verifier_id,
        &commitment_id,
        &treasury,
        &treasury_owner,
    );

    (payroll_client, admin, treasury, treasury_owner)
}

#[test]
fn test_admin_handover_success_and_role_transfer() {
    let env = Env::default();
    let (client, current_admin, _treasury, _treasury_owner) = setup_payroll(&env);

    let pending_admin = Address::generate(&env);

    // Current admin starts handover
    client.request_admin_handover(&current_admin, &pending_admin);

    let record = client
        .get_pending_admin_handover()
        .expect("Pending handover record should exist");
    assert_eq!(record.current_admin, current_admin);
    assert_eq!(record.pending_admin, pending_admin);

    // Pending admin accepts handover
    client.accept_admin_handover(&pending_admin);

    assert!(client.get_pending_admin_handover().is_none());

    // Verify new admin can perform admin operations
    let draft_id = client.create_run_draft(
        &pending_admin,
        &10_000i128,
        &5u32,
        &Symbol::new(&env, "Q1"),
    );
    assert_eq!(draft_id, 1);
}

#[test]
fn test_admin_handover_cancellation_by_current_admin() {
    let env = Env::default();
    let (client, current_admin, _treasury, _treasury_owner) = setup_payroll(&env);

    let pending_admin = Address::generate(&env);
    client.request_admin_handover(&current_admin, &pending_admin);

    // Current admin cancels handover
    client.cancel_admin_handover(&current_admin);

    assert!(client.get_pending_admin_handover().is_none());
}

#[test]
#[should_panic(expected = "Unauthorized: caller is not current admin")]
fn test_admin_handover_unauthorized_initiator() {
    let env = Env::default();
    let (client, _current_admin, _treasury, _treasury_owner) = setup_payroll(&env);

    let attacker = Address::generate(&env);
    let pending_admin = Address::generate(&env);
    client.request_admin_handover(&attacker, &pending_admin);
}

#[test]
#[should_panic(expected = "Unauthorized: caller is not the pending admin")]
fn test_admin_handover_unauthorized_acceptance() {
    let env = Env::default();
    let (client, current_admin, _treasury, _treasury_owner) = setup_payroll(&env);

    let pending_admin = Address::generate(&env);
    client.request_admin_handover(&current_admin, &pending_admin);

    let attacker = Address::generate(&env);
    client.accept_admin_handover(&attacker);
}
