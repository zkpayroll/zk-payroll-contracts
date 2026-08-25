//! Signer Quorum Replay Protection Integration Tests (#334)

use payroll::{Payroll, PayrollClient, QuorumApprovalPayload};
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

fn test_nonce(env: &Env, seed: u8) -> BytesN<32> {
    let mut arr = [0u8; 32];
    arr[0] = seed;
    BytesN::from_array(env, &arr)
}

fn setup_payroll(env: &Env) -> (PayrollClient<'_>, Address, Address) {
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

    (payroll_client, admin, token_id)
}

#[test]
fn test_signer_quorum_approval_flow_and_cross_batch_replay_prevention() {
    let env = Env::default();
    let (client, employer, asset) = setup_payroll(&env);

    let signer1 = Address::generate(&env);
    let signer2 = Address::generate(&env);
    let mut signers = Vec::new(&env);
    signers.push_back(signer1);
    signers.push_back(signer2);

    let payload = QuorumApprovalPayload {
        batch_root: BytesN::from_array(&env, &[10u8; 32]),
        employer: employer.clone(),
        period: Symbol::new(&env, "AUGUST_2026"),
        asset: asset.clone(),
        nonce: test_nonce(&env, 99),
        policy_version: 1,
    };

    let q_hash = client.hash_quorum_payload(&payload);
    assert!(!client.is_quorum_consumed(&q_hash));

    // Valid quorum consumption
    let consumed_hash = client.verify_and_consume_quorum(&payload, &signers, &2u32);
    assert_eq!(q_hash, consumed_hash);
    assert!(client.is_quorum_consumed(&q_hash));

    // Cross-batch or same-payload replay attempt must fail
    let replay_result = client.try_verify_and_consume_quorum(&payload, &signers, &2u32);
    assert!(replay_result.is_err());
}

#[test]
#[should_panic(expected = "Insufficient signer quorum")]
fn test_quorum_rejection_insufficient_signers() {
    let env = Env::default();
    let (client, employer, asset) = setup_payroll(&env);

    let signer1 = Address::generate(&env);
    let mut signers = Vec::new(&env);
    signers.push_back(signer1);

    let payload = QuorumApprovalPayload {
        batch_root: BytesN::from_array(&env, &[11u8; 32]),
        employer,
        period: Symbol::new(&env, "AUGUST_2026"),
        asset,
        nonce: test_nonce(&env, 100),
        policy_version: 1,
    };

    // Requires quorum of 2, but only 1 signer present -> panics
    client.verify_and_consume_quorum(&payload, &signers, &2u32);
}
