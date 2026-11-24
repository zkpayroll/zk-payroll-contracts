//! Issue #888 — proof verifier rejection of truncated public inputs.
//!
//! Expected behavior: the verifier derives the required public input count
//! from the active verification key (`vk.ic.len() - 1`). A submission whose
//! public inputs are a truncated prefix of a valid set — even when every
//! remaining value is genuine — is a structural rejection:
//!
//! - `validate_proof_inputs()` returns `ProofError::InvalidPublicInputCount`.
//! - `verify()`, `verify_payment_proof()` and `verify_with_reference()`
//!   return `false` without panicking.
//! - The rejection does not consume, revoke, or otherwise mutate a proof
//!   reference, so the full, untruncated input set still verifies afterwards.
//! - The error carries no proof bytes, input values, or salary data.

use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Env, Vec};

fn vk_with_ic_len(env: &Env, ic_len: u32) -> VerificationKey {
    let mut ic = Vec::new(env);
    for i in 0..ic_len {
        ic.push_back(BytesN::from_array(env, &[(i as u8).wrapping_add(60); 64]));
    }
    VerificationKey {
        alpha: BytesN::from_array(env, &[1u8; 64]),
        beta: BytesN::from_array(env, &[2u8; 128]),
        gamma: BytesN::from_array(env, &[3u8; 128]),
        delta: BytesN::from_array(env, &[4u8; 128]),
        ic,
    }
}

fn full_inputs(env: &Env, len: u32) -> Vec<BytesN<32>> {
    let mut inputs = Vec::new(env);
    for i in 0..len {
        inputs.push_back(BytesN::from_array(env, &[(i as u8).wrapping_add(90); 32]));
    }
    inputs
}

fn proof(env: &Env) -> BytesN<256> {
    BytesN::from_array(env, &[8u8; 256])
}

fn groth16_proof(env: &Env) -> Groth16Proof {
    Groth16Proof {
        a: BytesN::from_array(env, &[8u8; 64]),
        b: BytesN::from_array(env, &[8u8; 128]),
        c: BytesN::from_array(env, &[8u8; 64]),
    }
}

fn setup(env: &Env, ic_len: u32) -> (ProofVerifierClient<'_>, soroban_sdk::Address) {
    env.mock_all_auths();
    let contract_id = env.register(ProofVerifier, ());
    let client = ProofVerifierClient::new(env, &contract_id);
    let admin = soroban_sdk::Address::generate(env);
    client.init_verifier_admin(&admin);
    client.initialize_verifier(&vk_with_ic_len(env, ic_len));
    (client, admin)
}

fn assert_truncation_rejected(
    client: &ProofVerifierClient<'_>,
    env: &Env,
    inputs: &Vec<BytesN<32>>,
) {
    assert_eq!(
        client
            .try_validate_proof_inputs(inputs)
            .unwrap_err()
            .unwrap(),
        ProofError::InvalidPublicInputCount
    );
    assert!(!client.verify_payment_proof(&proof(env), inputs));
    assert!(!client.verify(&groth16_proof(env), inputs));
}

// -------------------------------------------------------------------------
// Success
// -------------------------------------------------------------------------

#[test]
fn full_public_inputs_are_accepted_by_every_entry_point() {
    let env = Env::default();
    let (client, admin) = setup(&env, 5); // expects 4 inputs
    let inputs = full_inputs(&env, 4);

    client.validate_proof_inputs(&inputs);
    assert!(client.verify_payment_proof(&proof(&env), &inputs));
    assert!(client.verify(&groth16_proof(&env), &inputs));

    let ref_id = BytesN::from_array(&env, &[31u8; 32]);
    client.register_proof_reference(&admin, &ref_id, &proof(&env), &1_000u32);
    assert!(client.verify_with_reference(&ref_id, &proof(&env), &inputs));
}

// -------------------------------------------------------------------------
// Rejection
// -------------------------------------------------------------------------

#[test]
fn every_truncated_prefix_of_valid_inputs_is_rejected() {
    let env = Env::default();
    let (client, _admin) = setup(&env, 6); // expects 5 inputs
    let inputs = full_inputs(&env, 5);

    for kept in 0..inputs.len() {
        let truncated = inputs.slice(0..kept);
        assert_eq!(truncated.len(), kept);
        assert_truncation_rejected(&client, &env, &truncated);
    }
}

#[test]
fn inputs_missing_leading_values_are_rejected() {
    // Truncation from the front (dropping the commitment) is just as
    // invalid as dropping trailing values.
    let env = Env::default();
    let (client, _admin) = setup(&env, 4); // expects 3 inputs
    let inputs = full_inputs(&env, 3);

    assert_truncation_rejected(&client, &env, &inputs.slice(1..3));
    assert_truncation_rejected(&client, &env, &inputs.slice(2..3));
}

#[test]
fn truncated_inputs_are_rejected_through_a_valid_reference() {
    let env = Env::default();
    let (client, admin) = setup(&env, 4); // expects 3 inputs
    let inputs = full_inputs(&env, 3);
    let ref_id = BytesN::from_array(&env, &[32u8; 32]);
    client.register_proof_reference(&admin, &ref_id, &proof(&env), &1_000u32);

    for kept in 0..inputs.len() {
        assert!(!client.verify_with_reference(&ref_id, &proof(&env), &inputs.slice(0..kept)));
    }
}

#[test]
fn truncated_rejection_leaves_reference_usable_for_full_inputs() {
    let env = Env::default();
    let (client, admin) = setup(&env, 3); // expects 2 inputs
    let inputs = full_inputs(&env, 2);
    let ref_id = BytesN::from_array(&env, &[33u8; 32]);
    let before = client.register_proof_reference(&admin, &ref_id, &proof(&env), &1_000u32);

    assert!(!client.verify_with_reference(&ref_id, &proof(&env), &inputs.slice(0..1)));

    assert_eq!(client.get_proof_reference(&ref_id), before);
    assert!(client.is_proof_reference_valid(&ref_id));
    assert!(client.verify_with_reference(&ref_id, &proof(&env), &inputs));
}

#[test]
fn truncation_error_is_generic_and_data_free() {
    let env = Env::default();
    let (client, _admin) = setup(&env, 3);
    let truncated = full_inputs(&env, 1);

    let err = client
        .try_validate_proof_inputs(&truncated)
        .unwrap_err()
        .unwrap();
    assert_eq!(err, ProofError::InvalidPublicInputCount);
    assert_eq!(err as u32, 10);
}

// -------------------------------------------------------------------------
// Boundary
// -------------------------------------------------------------------------

#[test]
fn dropping_only_the_last_input_is_rejected() {
    let env = Env::default();
    for ic_len in [2u32, 3, 8] {
        let (client, _admin) = setup(&env, ic_len);
        let expected = ic_len - 1;
        let inputs = full_inputs(&env, expected);

        assert!(client.verify_payment_proof(&proof(&env), &inputs));
        assert_truncation_rejected(&client, &env, &inputs.slice(0..expected - 1));
    }
}

#[test]
fn empty_inputs_accepted_only_when_vk_expects_zero_inputs() {
    let env = Env::default();

    // ic_len = 1 → zero public inputs expected; empty is the full set.
    let (zero_client, _admin) = setup(&env, 1);
    let empty = Vec::new(&env);
    zero_client.validate_proof_inputs(&empty);
    assert!(zero_client.verify_payment_proof(&proof(&env), &empty));

    // ic_len = 2 → one input expected; empty is a full truncation.
    let (one_client, _admin) = setup(&env, 2);
    assert_truncation_rejected(&one_client, &env, &Vec::new(&env));
}
