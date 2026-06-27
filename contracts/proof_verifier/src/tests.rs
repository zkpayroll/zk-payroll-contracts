use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Env, Vec};

fn mock_verification_key(env: &Env) -> VerificationKey {
    VerificationKey {
        alpha: BytesN::from_array(env, &[1u8; 64]),
        beta: BytesN::from_array(env, &[2u8; 128]),
        gamma: BytesN::from_array(env, &[3u8; 128]),
        delta: BytesN::from_array(env, &[4u8; 128]),
        ic: Vec::from_array(
            env,
            [
                BytesN::from_array(env, &[5u8; 64]),
                BytesN::from_array(env, &[6u8; 64]),
                BytesN::from_array(env, &[7u8; 64]),
            ],
        ),
    }
}

fn mock_snarkjs_proof(env: &Env) -> BytesN<256> {
    BytesN::from_array(env, &[8u8; 256])
}

#[test]
fn test_initialize_stores_admin() {
    let env = Env::default();
    let contract_id = env.register_contract(None, ProofVerifier);
    let client = ProofVerifierClient::new(&env, &contract_id);
    let admin = soroban_sdk::Address::generate(&env);

    client.init_verifier_admin(&admin);
    assert_eq!(client.get_verifier_admin(), admin);
}

#[test]
fn test_initialize_verifier_stores_vk() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, ProofVerifier);
    let client = ProofVerifierClient::new(&env, &contract_id);

    let admin = soroban_sdk::Address::generate(&env);
    client.init_verifier_admin(&admin);

    let vk = mock_verification_key(&env);
    client.initialize_verifier(&vk);

    let stored_vk = client.get_verification_key();
    assert_eq!(stored_vk.alpha, vk.alpha);
    assert_eq!(stored_vk.beta, vk.beta);
    assert_eq!(stored_vk.gamma, vk.gamma);
    assert_eq!(stored_vk.delta, vk.delta);
    assert_eq!(stored_vk.ic, vk.ic);
}

#[test]
#[should_panic(expected = "Verifier already initialized")]
fn test_initialize_verifier_twice_panics() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, ProofVerifier);
    let client = ProofVerifierClient::new(&env, &contract_id);

    let admin = soroban_sdk::Address::generate(&env);
    client.init_verifier_admin(&admin);

    let vk = mock_verification_key(&env);
    client.initialize_verifier(&vk);
    client.initialize_verifier(&vk);
}

#[test]
#[should_panic(expected = "Verifier not initialized")]
fn test_get_vk_uninitialized_panics() {
    let env = Env::default();
    let contract_id = env.register_contract(None, ProofVerifier);
    let client = ProofVerifierClient::new(&env, &contract_id);

    client.get_verification_key();
}

#[test]
fn test_verify_payment_proof_interface() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, ProofVerifier);
    let client = ProofVerifierClient::new(&env, &contract_id);

    let admin = soroban_sdk::Address::generate(&env);
    client.init_verifier_admin(&admin);

    let vk = mock_verification_key(&env);
    client.initialize_verifier(&vk);

    let proof = mock_snarkjs_proof(&env);
    let public_inputs = Vec::from_array(
        &env,
        [
            BytesN::from_array(&env, &[11u8; 32]),
            BytesN::from_array(&env, &[12u8; 32]),
        ],
    );

    let is_valid = client.verify_payment_proof(&proof, &public_inputs);
    assert!(is_valid);
}

#[test]
fn test_verify_payment_proof_rejects_wrong_input_length() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, ProofVerifier);
    let client = ProofVerifierClient::new(&env, &contract_id);

    let admin = soroban_sdk::Address::generate(&env);
    client.init_verifier_admin(&admin);

    let vk = mock_verification_key(&env);
    client.initialize_verifier(&vk);

    let proof = mock_snarkjs_proof(&env);
    let short_inputs = Vec::from_array(&env, [BytesN::from_array(&env, &[11u8; 32])]);

    let is_valid = client.verify_payment_proof(&proof, &short_inputs);
    assert!(!is_valid);
}

#[test]
#[should_panic]
fn test_unauthorized_initialize_verifier_fails() {
    let env = Env::default();
    let contract_id = env.register_contract(None, ProofVerifier);
    let client = ProofVerifierClient::new(&env, &contract_id);

    let admin = soroban_sdk::Address::generate(&env);
    client.init_verifier_admin(&admin);

    let vk = mock_verification_key(&env);
    client.initialize_verifier(&vk);
}
