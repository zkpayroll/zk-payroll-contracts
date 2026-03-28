use proof_verifier::{Groth16Proof, ProofVerifierClient, VerificationKey};
use soroban_sdk::{BytesN, Env, Vec};

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

fn mock_proof(env: &Env) -> Groth16Proof {
    Groth16Proof {
        a: BytesN::from_array(env, &[1u8; 64]),
        b: BytesN::from_array(env, &[2u8; 128]),
        c: BytesN::from_array(env, &[3u8; 64]),
    }
}

/// Test: verifier initializes and stores VK without panicking.
#[test]
fn integration_initialize_verifier() {
    let env = Env::default();
    let contract_id = env.register(proof_verifier::ProofVerifier, ());
    let client = ProofVerifierClient::new(&env, &contract_id);
    client.initialize_verifier(&mock_vk(&env));
}

/// Test: verify_payment_proof rejects an invalid mock proof.
///
/// Mock byte arrays are NOT valid BN254 curve points, so the pairing
/// check fails (or the host panics on invalid point deserialization).
/// This confirms that the contract does NOT blindly return `true`.
#[test]
#[should_panic]
fn integration_verify_rejects_invalid_proof() {
    let env = Env::default();
    let contract_id = env.register(proof_verifier::ProofVerifier, ());
    let client = ProofVerifierClient::new(&env, &contract_id);
    client.initialize_verifier(&mock_vk(&env));

    let proof = mock_proof(&env);
    let salary_commitment = BytesN::from_array(&env, &[9u8; 32]);
    let payment_nullifier = BytesN::from_array(&env, &[8u8; 32]);
    let recipient_hash = BytesN::from_array(&env, &[7u8; 32]);

    // This should panic because mock bytes are not valid BN254 points
    client.verify_payment_proof(&proof, &salary_commitment, &payment_nullifier, &recipient_hash);
}

/// Test: calling verify without initialization panics.
#[test]
#[should_panic(expected = "Verifier not initialized")]
fn integration_verify_without_init_panics() {
    let env = Env::default();
    let contract_id = env.register(proof_verifier::ProofVerifier, ());
    let client = ProofVerifierClient::new(&env, &contract_id);

    let proof = mock_proof(&env);
    let salary_commitment = BytesN::from_array(&env, &[9u8; 32]);
    let payment_nullifier = BytesN::from_array(&env, &[8u8; 32]);
    let recipient_hash = BytesN::from_array(&env, &[7u8; 32]);

    client.verify_payment_proof(&proof, &salary_commitment, &payment_nullifier, &recipient_hash);
}
