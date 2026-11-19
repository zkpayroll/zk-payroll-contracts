//! Issue #821: circuit input length validation before proof verification.
//!
//! `validate_public_inputs` returns a typed `ProofError` for a length
//! mismatch, while `verify` / `verify_payment_proof` keep their existing
//! `bool` contract (never panic, return `false`).

use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, Vec};

fn vk_with_ic_len(env: &Env, ic_len: u32) -> VerificationKey {
    let mut ic = Vec::new(env);
    for i in 0..ic_len {
        ic.push_back(BytesN::from_array(env, &[i as u8; 64]));
    }
    VerificationKey {
        alpha: BytesN::from_array(env, &[1u8; 64]),
        beta: BytesN::from_array(env, &[2u8; 128]),
        gamma: BytesN::from_array(env, &[3u8; 128]),
        delta: BytesN::from_array(env, &[4u8; 128]),
        ic,
    }
}

fn inputs(env: &Env, len: u32) -> Vec<BytesN<32>> {
    let mut v = Vec::new(env);
    for i in 0..len {
        v.push_back(BytesN::from_array(env, &[(i + 10) as u8; 32]));
    }
    v
}

fn proof_bytes(env: &Env) -> BytesN<256> {
    BytesN::from_array(env, &[7u8; 256])
}

fn groth16(env: &Env) -> Groth16Proof {
    Groth16Proof {
        a: BytesN::from_array(env, &[7u8; 64]),
        b: BytesN::from_array(env, &[7u8; 128]),
        c: BytesN::from_array(env, &[7u8; 64]),
    }
}

/// Verifier initialized with a key that has `ic_len` IC points, so it
/// expects `ic_len - 1` public inputs.
fn verifier(env: &Env, ic_len: u32) -> ProofVerifierClient<'_> {
    env.mock_all_auths();
    let client = ProofVerifierClient::new(env, &env.register(ProofVerifier, ()));
    client.init_verifier_admin(&Address::generate(env));
    client.initialize_verifier(&vk_with_ic_len(env, ic_len));
    client
}

fn length_error(client: &ProofVerifierClient, public_inputs: &Vec<BytesN<32>>) -> ProofError {
    client
        .try_validate_public_inputs(public_inputs)
        .unwrap_err()
        .unwrap()
}

// --- success -------------------------------------------------------------

/// The current v1 schema (2 inputs, `ic.len() == 3`) passes the length check
/// and still verifies through both bool entrypoints.
#[test]
fn test_correct_length_is_accepted_and_still_verifies() {
    let env = Env::default();
    let client = verifier(&env, 3);
    let ok = inputs(&env, 2);

    assert_eq!(client.validate_public_inputs(&ok), 2);
    assert!(client.verify_payment_proof(&proof_bytes(&env), &ok));
    assert!(client.verify(&groth16(&env), &ok));
}

// --- rejected ------------------------------------------------------------

/// Too short: the typed error is returned, and the bool API is unchanged
/// (`false`, no panic).
#[test]
fn test_too_short_is_rejected_with_typed_error() {
    let env = Env::default();
    let client = verifier(&env, 3);
    let short = inputs(&env, 1);

    assert_eq!(
        length_error(&client, &short),
        ProofError::InvalidPublicInputLength
    );
    assert!(!client.verify_payment_proof(&proof_bytes(&env), &short));
    assert!(!client.verify(&groth16(&env), &short));
}

/// Too long: for example the legacy v0 three-input schema against the v1
/// key.
#[test]
fn test_too_long_is_rejected_with_typed_error() {
    let env = Env::default();
    let client = verifier(&env, 3);
    let long = inputs(&env, 3);

    assert_eq!(
        length_error(&client, &long),
        ProofError::InvalidPublicInputLength
    );
    assert!(!client.verify_payment_proof(&proof_bytes(&env), &long));
    assert!(!client.verify(&groth16(&env), &long));
}

/// Empty input vector.
#[test]
fn test_empty_inputs_are_rejected_with_typed_error() {
    let env = Env::default();
    let client = verifier(&env, 3);
    let empty = inputs(&env, 0);

    assert_eq!(
        length_error(&client, &empty),
        ProofError::InvalidPublicInputLength
    );
    assert!(!client.verify_payment_proof(&proof_bytes(&env), &empty));
}

/// A reference-gated verification with a length mismatch is still refused
/// (`false`), even though the reference itself is valid.
#[test]
fn test_reference_verification_rejects_wrong_length() {
    let env = Env::default();
    let client = verifier(&env, 3);
    let admin = client.get_verifier_admin();
    let ref_id = BytesN::from_array(&env, &[9u8; 32]);
    let proof = proof_bytes(&env);
    client.register_proof_reference(&admin, &ref_id, &proof, &(env.ledger().sequence() + 10));

    assert!(client.verify_with_reference(&ref_id, &proof, &inputs(&env, 2)));
    assert!(!client.verify_with_reference(&ref_id, &proof, &inputs(&env, 1)));
    assert!(!client.verify_with_reference(&ref_id, &proof, &inputs(&env, 3)));
}

/// Without a stored key, validation returns `NotInitialized` instead of
/// panicking.
#[test]
fn test_validation_before_initialization_returns_not_initialized() {
    let env = Env::default();
    let client = ProofVerifierClient::new(&env, &env.register(ProofVerifier, ()));

    assert_eq!(
        length_error(&client, &inputs(&env, 2)),
        ProofError::NotInitialized
    );
}

// --- boundary ------------------------------------------------------------

/// Exactly `ic.len() - 1` is accepted and one either side is rejected, for
/// several key sizes, including a key with no public inputs at all.
#[test]
fn test_length_boundary_across_key_sizes() {
    for ic_len in [1u32, 2, 3, 5, 8] {
        let env = Env::default();
        let client = verifier(&env, ic_len);
        let expected = ic_len - 1;

        assert_eq!(
            client.validate_public_inputs(&inputs(&env, expected)),
            expected,
            "ic_len={ic_len}: exact length must be accepted"
        );
        assert!(client.verify_payment_proof(&proof_bytes(&env), &inputs(&env, expected)));

        assert_eq!(
            length_error(&client, &inputs(&env, expected + 1)),
            ProofError::InvalidPublicInputLength,
            "ic_len={ic_len}: one extra input must be rejected"
        );
        if expected > 0 {
            assert_eq!(
                length_error(&client, &inputs(&env, expected - 1)),
                ProofError::InvalidPublicInputLength,
                "ic_len={ic_len}: one missing input must be rejected"
            );
        }
    }
}

/// A malformed key with an empty `ic` (no constant term) accepts no input
/// vector, not even an empty one.
#[test]
fn test_key_with_empty_ic_accepts_no_input_vector() {
    let env = Env::default();
    let client = verifier(&env, 0);

    for len in [0u32, 1, 2] {
        assert_eq!(
            length_error(&client, &inputs(&env, len)),
            ProofError::InvalidPublicInputLength
        );
        assert!(!client.verify_payment_proof(&proof_bytes(&env), &inputs(&env, len)));
    }
}

/// The error is a bare, stable code with no input values attached.
#[test]
fn test_error_code_is_stable() {
    assert_eq!(ProofError::InvalidPublicInputLength as u32, 10);
}
