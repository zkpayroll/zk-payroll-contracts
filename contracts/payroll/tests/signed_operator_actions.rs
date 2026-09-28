//! Signed, expiring operator authorizations (issue #519).

#![cfg(test)]

extern crate std;

mod common;

use ed25519_dalek::{Signer, SigningKey};
use payroll::signed_operator_actions::{SignedOperatorAction, SignedOperatorPayload};
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{Address, BytesN, Env};

const LEDGER_SEQUENCE: u32 = 1_000;

fn setup_with_operator_key(env: &Env) -> (payroll::PayrollClient<'_>, Address, SigningKey) {
    let (client, _token, _employee) = common::setup(env);
    env.ledger()
        .with_mut(|l| l.sequence_number = LEDGER_SEQUENCE);

    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let public_key = BytesN::from_array(env, signing_key.verifying_key().as_bytes());

    let admin = client.get_addresses().admin;
    client.register_operator_key(&admin, &public_key);

    (client, admin, signing_key)
}

fn sign_payload(
    env: &Env,
    signing_key: &SigningKey,
    payload: &SignedOperatorPayload,
) -> BytesN<64> {
    use soroban_sdk::xdr::ToXdr;
    let message = payload.clone().to_xdr(env);
    let signature = signing_key.sign(&message.to_alloc_vec());
    BytesN::from_array(env, &signature.to_bytes())
}

fn payload(
    env: &Env,
    reviewer: &Address,
    expires_at_ledger: u32,
    marker: u8,
) -> SignedOperatorPayload {
    SignedOperatorPayload {
        action: SignedOperatorAction::AddReviewer(reviewer.clone()),
        expires_at_ledger,
        nonce: common::nonce(env, marker),
    }
}

#[test]
fn valid_signed_authorization_grants_reviewer() {
    let env = Env::default();
    let (client, _admin, signing_key) = setup_with_operator_key(&env);
    let reviewer = Address::generate(&env);

    let p = payload(&env, &reviewer, LEDGER_SEQUENCE + 100, 1);
    let sig = sign_payload(&env, &signing_key, &p);

    client.signed_add_reviewer(&reviewer, &p, &sig);
    assert!(client.is_reviewer(&reviewer));
}

#[test]
#[should_panic]
fn expired_authorization_is_rejected() {
    let env = Env::default();
    let (client, _admin, signing_key) = setup_with_operator_key(&env);
    let reviewer = Address::generate(&env);

    // expires_at_ledger at or before the current ledger must be rejected.
    let p = payload(&env, &reviewer, LEDGER_SEQUENCE, 1);
    let sig = sign_payload(&env, &signing_key, &p);

    client.signed_add_reviewer(&reviewer, &p, &sig);
}

#[test]
#[should_panic]
fn expiry_beyond_max_ttl_is_rejected() {
    let env = Env::default();
    let (client, _admin, signing_key) = setup_with_operator_key(&env);
    let reviewer = Address::generate(&env);

    let p = payload(&env, &reviewer, LEDGER_SEQUENCE + 600_000, 1);
    let sig = sign_payload(&env, &signing_key, &p);

    client.signed_add_reviewer(&reviewer, &p, &sig);
}

#[test]
#[should_panic]
fn wrong_signing_key_is_rejected() {
    let env = Env::default();
    let (client, _admin, _signing_key) = setup_with_operator_key(&env);
    let reviewer = Address::generate(&env);

    let wrong_key = SigningKey::from_bytes(&[9u8; 32]);
    let p = payload(&env, &reviewer, LEDGER_SEQUENCE + 100, 1);
    let sig = sign_payload(&env, &wrong_key, &p);

    client.signed_add_reviewer(&reviewer, &p, &sig);
}

#[test]
#[should_panic]
fn replaying_the_same_authorization_is_rejected() {
    let env = Env::default();
    let (client, _admin, signing_key) = setup_with_operator_key(&env);
    let reviewer = Address::generate(&env);

    let p = payload(&env, &reviewer, LEDGER_SEQUENCE + 100, 1);
    let sig = sign_payload(&env, &signing_key, &p);

    client.signed_add_reviewer(&reviewer, &p, &sig);
    assert!(client.is_reviewer(&reviewer));

    // Replaying the exact same payload + signature a second time must be
    // rejected, even though the first grant already succeeded.
    client.signed_add_reviewer(&reviewer, &p, &sig);
}

#[test]
#[should_panic]
fn payload_action_mismatch_is_rejected() {
    let env = Env::default();
    let (client, _admin, signing_key) = setup_with_operator_key(&env);
    let reviewer = Address::generate(&env);
    let different_reviewer = Address::generate(&env);

    // The payload authorizes `different_reviewer`, but the call supplies
    // `reviewer` — must be rejected rather than silently granting the
    // supplied address using an authorization signed for someone else.
    let p = payload(&env, &different_reviewer, LEDGER_SEQUENCE + 100, 1);
    let sig = sign_payload(&env, &signing_key, &p);

    client.signed_add_reviewer(&reviewer, &p, &sig);
}

#[test]
#[should_panic]
fn no_operator_key_registered_is_rejected() {
    let env = Env::default();
    let (client, _token, _employee) = common::setup(&env);
    env.ledger()
        .with_mut(|l| l.sequence_number = LEDGER_SEQUENCE);
    let reviewer = Address::generate(&env);

    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let p = payload(&env, &reviewer, LEDGER_SEQUENCE + 100, 1);
    let sig = sign_payload(&env, &signing_key, &p);

    // No register_operator_key call was made.
    client.signed_add_reviewer(&reviewer, &p, &sig);
}

#[test]
#[should_panic]
fn revoked_operator_key_is_rejected() {
    let env = Env::default();
    let (client, admin, signing_key) = setup_with_operator_key(&env);
    client.revoke_operator_key(&admin);

    let reviewer = Address::generate(&env);
    let p = payload(&env, &reviewer, LEDGER_SEQUENCE + 100, 1);
    let sig = sign_payload(&env, &signing_key, &p);

    client.signed_add_reviewer(&reviewer, &p, &sig);
}

#[test]
fn signed_add_reviewer_respects_the_max_reviewers_cap() {
    let env = Env::default();
    let (client, admin, signing_key) = setup_with_operator_key(&env);
    client.set_max_reviewers(&admin, &1u32);

    let first = Address::generate(&env);
    let p1 = payload(&env, &first, LEDGER_SEQUENCE + 100, 1);
    let sig1 = sign_payload(&env, &signing_key, &p1);
    client.signed_add_reviewer(&first, &p1, &sig1);

    let second = Address::generate(&env);
    let p2 = payload(&env, &second, LEDGER_SEQUENCE + 100, 2);
    let sig2 = sign_payload(&env, &signing_key, &p2);

    let result = client.try_signed_add_reviewer(&second, &p2, &sig2);
    assert!(result.is_err(), "the reviewer cap must still apply");
}
