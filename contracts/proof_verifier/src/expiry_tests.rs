//! Issue #251 — proof reference expiry checks.
//!
//! Covers valid, expired, missing, and revoked proof references plus
//! boundary timing behaviour around `expires_at_ledger`.

use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::testutils::Ledger as _;
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

fn mock_proof(env: &Env) -> BytesN<256> {
    BytesN::from_array(env, &[8u8; 256])
}

fn other_proof(env: &Env) -> BytesN<256> {
    BytesN::from_array(env, &[9u8; 256])
}

fn public_inputs(env: &Env) -> Vec<BytesN<32>> {
    Vec::from_array(
        env,
        [
            BytesN::from_array(env, &[10u8; 32]),
            BytesN::from_array(env, &[11u8; 32]),
        ],
    )
}

fn setup(env: &Env) -> (ProofVerifierClient<'_>, soroban_sdk::Address) {
    env.mock_all_auths();
    let contract_id = env.register_contract(None, ProofVerifier);
    let client = ProofVerifierClient::new(env, &contract_id);
    let admin = soroban_sdk::Address::generate(env);
    client.init_verifier_admin(&admin);
    client.initialize_verifier(&mock_verification_key(env));
    (client, admin)
}

const REF: [u8; 32] = [42u8; 32];

/// Valid reference authorizes verification before its expiry.
#[test]
fn valid_reference_authorizes_verification() {
    let env = Env::default();
    let (client, admin) = setup(&env);

    let registered = client.register_proof_reference(
        &admin,
        &BytesN::from_array(&env, &REF),
        &mock_proof(&env),
        &(100u32),
    );

    assert_eq!(registered.registered_at_ledger, 0);
    assert_eq!(registered.expires_at_ledger, 100);
    assert!(!registered.revoked);

    assert!(client.is_proof_reference_valid(&BytesN::from_array(&env, &REF)));
    assert!(
        client.verify_with_reference(
            &BytesN::from_array(&env, &REF),
            &mock_proof(&env),
            &public_inputs(&env)
        ),
        "valid reference must authorize proof verification"
    );
}

/// A reference that was never registered must not authorize anything.
#[test]
fn missing_reference_is_rejected() {
    let env = Env::default();
    let (client, _admin) = setup(&env);

    let unknown = BytesN::from_array(&env, &[7u8; 32]);
    assert!(!client.is_proof_reference_valid(&unknown));
    assert_eq!(
        client
            .try_get_proof_reference(&unknown)
            .unwrap_err()
            .unwrap(),
        ProofError::ReferenceNotFound
    );
    assert!(
        !client.verify_with_reference(&unknown, &mock_proof(&env), &public_inputs(&env)),
        "missing reference must be rejected"
    );
}

/// An expired reference must not authorize verification.
#[test]
fn expired_reference_is_rejected() {
    let env = Env::default();
    let (client, admin) = setup(&env);

    client.register_proof_reference(
        &admin,
        &BytesN::from_array(&env, &REF),
        &mock_proof(&env),
        &(50u32),
    );

    env.ledger().set_sequence_number(60);

    assert!(!client.is_proof_reference_valid(&BytesN::from_array(&env, &REF)));
    assert!(
        !client.verify_with_reference(
            &BytesN::from_array(&env, &REF),
            &mock_proof(&env),
            &public_inputs(&env)
        ),
        "expired reference must be rejected"
    );
    // The record is still queryable for audit tooling.
    let stored = client.get_proof_reference(&BytesN::from_array(&env, &REF));
    assert_eq!(stored.expires_at_ledger, 50);
}

// -------------------------------------------------------------------------
// Boundary timing behaviour
// -------------------------------------------------------------------------

#[test]
fn boundary_valid_one_ledger_before_expiry() {
    let env = Env::default();
    let (client, admin) = setup(&env);

    let expires_at = 30u32;
    client.register_proof_reference(
        &admin,
        &BytesN::from_array(&env, &REF),
        &mock_proof(&env),
        &expires_at,
    );

    env.ledger().set_sequence_number(expires_at - 1);
    assert!(
        client.is_proof_reference_valid(&BytesN::from_array(&env, &REF)),
        "reference must remain usable at expires_at - 1"
    );

    // Matches audit_module's convention: still valid AT the expiry ledger.
    env.ledger().set_sequence_number(expires_at);
    assert!(
        client.is_proof_reference_valid(&BytesN::from_array(&env, &REF)),
        "reference must remain usable at expires_at itself"
    );
}

#[test]
fn boundary_expired_one_ledger_after_expiry() {
    let env = Env::default();
    let (client, admin) = setup(&env);

    let expires_at = 30u32;
    client.register_proof_reference(
        &admin,
        &BytesN::from_array(&env, &REF),
        &mock_proof(&env),
        &expires_at,
    );

    env.ledger().set_sequence_number(expires_at + 1);
    assert!(
        !client.is_proof_reference_valid(&BytesN::from_array(&env, &REF)),
        "reference must be expired from expires_at + 1 onward"
    );
    assert!(!client.verify_with_reference(
        &BytesN::from_array(&env, &REF),
        &mock_proof(&env),
        &public_inputs(&env)
    ));
}

#[test]
fn boundary_expired_verification_rejected_after_expiry() {
    let env = Env::default();
    let (client, admin) = setup(&env);

    let expires_at = 30u32;
    client.register_proof_reference(
        &admin,
        &BytesN::from_array(&env, &REF),
        &mock_proof(&env),
        &expires_at,
    );

    env.ledger().set_sequence_number(expires_at + 5);
    assert!(!client.is_proof_reference_valid(&BytesN::from_array(&env, &REF)));
    assert!(!client.verify_with_reference(
        &BytesN::from_array(&env, &REF),
        &mock_proof(&env),
        &public_inputs(&env)
    ));
}

// -------------------------------------------------------------------------
// Registration validation rules
// -------------------------------------------------------------------------

#[test]
fn registration_rejects_expiry_in_the_past_or_present() {
    let env = Env::default();
    let (client, admin) = setup(&env);

    env.ledger().set_sequence_number(10);

    // Equal to current ledger → invalid.
    assert_eq!(
        client
            .try_register_proof_reference(
                &admin,
                &BytesN::from_array(&env, &REF),
                &mock_proof(&env),
                &(10u32)
            )
            .unwrap_err()
            .unwrap(),
        ProofError::InvalidExpiry
    );

    // Before current ledger → invalid.
    assert_eq!(
        client
            .try_register_proof_reference(
                &admin,
                &BytesN::from_array(&env, &REF),
                &mock_proof(&env),
                &(5u32)
            )
            .unwrap_err()
            .unwrap(),
        ProofError::InvalidExpiry
    );
}

#[test]
fn registration_rejects_ttl_beyond_cap() {
    let env = Env::default();
    let (client, admin) = setup(&env);

    env.ledger().set_sequence_number(0);
    let too_far = MAX_REFERENCE_TTL_LEDGERS + 1;
    assert_eq!(
        client
            .try_register_proof_reference(
                &admin,
                &BytesN::from_array(&env, &REF),
                &mock_proof(&env),
                &too_far
            )
            .unwrap_err()
            .unwrap(),
        ProofError::ExpiryBeyondCap
    );

    // Exactly the cap is allowed.
    client.register_proof_reference(
        &admin,
        &BytesN::from_array(&env, &REF),
        &mock_proof(&env),
        &MAX_REFERENCE_TTL_LEDGERS,
    );
}

#[test]
fn duplicate_ref_id_is_rejected() {
    let env = Env::default();
    let (client, admin) = setup(&env);

    client.register_proof_reference(
        &admin,
        &BytesN::from_array(&env, &REF),
        &mock_proof(&env),
        &(100u32),
    );

    assert_eq!(
        client
            .try_register_proof_reference(
                &admin,
                &BytesN::from_array(&env, &REF),
                &other_proof(&env),
                &(200u32)
            )
            .unwrap_err()
            .unwrap(),
        ProofError::ReferenceAlreadyExists
    );
}

#[test]
fn non_admin_cannot_register() {
    let env = Env::default();
    // No mock_all_auths here: a non-admin address has no way to satisfy
    // admin.require_auth(), so registration must be rejected.
    let contract_id = env.register_contract(None, ProofVerifier);
    let client = ProofVerifierClient::new(&env, &contract_id);
    let attacker = soroban_sdk::Address::generate(&env);
    let result = client.try_register_proof_reference(
        &attacker,
        &BytesN::from_array(&env, &REF),
        &mock_proof(&env),
        &(100u32),
    );
    assert!(result.is_err(), "non-admin registration must be rejected");
}

// -------------------------------------------------------------------------
// Revocation and proof binding
// -------------------------------------------------------------------------

#[test]
fn revoked_reference_is_rejected_even_before_expiry() {
    let env = Env::default();
    let (client, admin) = setup(&env);

    client.register_proof_reference(
        &admin,
        &BytesN::from_array(&env, &REF),
        &mock_proof(&env),
        &(1000u32),
    );
    client.revoke_proof_reference(&admin, &BytesN::from_array(&env, &REF));

    assert!(!client.is_proof_reference_valid(&BytesN::from_array(&env, &REF)));
    assert!(!client.verify_with_reference(
        &BytesN::from_array(&env, &REF),
        &mock_proof(&env),
        &public_inputs(&env)
    ));
}

#[test]
fn revoking_unknown_reference_fails() {
    let env = Env::default();
    let (client, admin) = setup(&env);

    assert_eq!(
        client
            .try_revoke_proof_reference(&admin, &BytesN::from_array(&env, &REF))
            .unwrap_err()
            .unwrap(),
        ProofError::ReferenceNotFound
    );
}

#[test]
fn reference_does_not_authorize_different_proof_bytes() {
    let env = Env::default();
    let (client, admin) = setup(&env);

    client.register_proof_reference(
        &admin,
        &BytesN::from_array(&env, &REF),
        &mock_proof(&env),
        &(1000u32),
    );

    assert!(
        !client.verify_with_reference(
            &BytesN::from_array(&env, &REF),
            &other_proof(&env),
            &public_inputs(&env)
        ),
        "a reference must only authorize its own proof material"
    );
}

// -------------------------------------------------------------------------
// Existing workflows unaffected
// -------------------------------------------------------------------------

#[test]
fn unregistered_direct_verification_still_works() {
    let env = Env::default();
    let (client, _admin) = setup(&env);

    // Issue #251 must not break existing proof paths that do not use
    // references.
    assert!(
        client.verify_payment_proof(&mock_proof(&env), &public_inputs(&env)),
        "valid proofs continue to work without a reference"
    );
}
