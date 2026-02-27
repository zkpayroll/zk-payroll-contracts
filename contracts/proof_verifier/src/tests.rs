use super::*;
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
                BytesN::from_array(env, &[5u8; 64]), // ic[0] - constant term
                BytesN::from_array(env, &[6u8; 64]), // ic[1] - corresponds to public_input[0]
                BytesN::from_array(env, &[7u8; 64]), // ic[2] - corresponds to public_input[1]
            ],
        ),
    }
}

// A mock 256 byte payload mimicking A (64), B (128), and C (64) concatenated
fn mock_snarkjs_proof(env: &Env) -> BytesN<256> {
    BytesN::from_array(env, &[8u8; 256])
}

#[test]
fn test_initialize_verifier_stores_vk() {
    let env = Env::default();
    let contract_id = env.register_contract(None, ProofVerifier);
    let client = ProofVerifierClient::new(&env, &contract_id);

    let vk = mock_verification_key(&env);
    
    // Initialize
    client.initialize_verifier(&vk);

    // Verify properties match what was stored
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
    let contract_id = env.register_contract(None, ProofVerifier);
    let client = ProofVerifierClient::new(&env, &contract_id);

    let vk = mock_verification_key(&env);
    client.initialize_verifier(&vk);
    
    // Attempting to initialize again should panic
    client.initialize_verifier(&vk);
}

#[test]
#[should_panic(expected = "Verifier not initialized")]
fn test_get_vk_uninitialized_panics() {
    let env = Env::default();
    let contract_id = env.register_contract(None, ProofVerifier);
    let client = ProofVerifierClient::new(&env, &contract_id);

    // Fetching before initialization triggers panic
    client.get_verification_key();
}

#[test]
fn test_verify_payment_proof_interface() {
    let env = Env::default();
    let contract_id = env.register_contract(None, ProofVerifier);
    let client = ProofVerifierClient::new(&env, &contract_id);

    let vk = mock_verification_key(&env);
    client.initialize_verifier(&vk);

    let proof = mock_snarkjs_proof(&env);
    
    // Create matching length of public inputs. Our mock VK has 3 `ic` points. 
    // The number of public inputs must be exactly `ic.len() - 1` = 2.
    let public_inputs = Vec::from_array(
        &env,
        [
            BytesN::from_array(&env, &[11u8; 32]),
            BytesN::from_array(&env, &[12u8; 32]),
        ],
    );

    let is_valid = client.verify_payment_proof(&proof, &public_inputs);
    // Our stub implementation always returns true for valid input structure
    assert!(is_valid);
}

#[test]
fn test_verify_payment_proof_rejects_wrong_input_length() {
    let env = Env::default();
    let contract_id = env.register_contract(None, ProofVerifier);
    let client = ProofVerifierClient::new(&env, &contract_id);

    let vk = mock_verification_key(&env);
    client.initialize_verifier(&vk);

    let proof = mock_snarkjs_proof(&env);
    
    // Provide 1 input instead of the expected 2
    let short_inputs = Vec::from_array(
        &env,
        [
            BytesN::from_array(&env, &[11u8; 32]),
        ],
    );

    // The interface must reject it
    let is_valid = client.verify_payment_proof(&proof, &short_inputs);
    assert!(!is_valid);
}
