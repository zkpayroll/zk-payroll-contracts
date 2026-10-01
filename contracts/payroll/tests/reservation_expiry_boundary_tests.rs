//! Clock boundary tests for reservation expiry (#337).
//!
//! Covers: exact expiry boundaries, adjacent timestamp cases,
//! and edge conditions for funding reservation expiry and release.

#![cfg(test)]

use ::token::{Token, TokenClient};
use payroll::{Payroll, PayrollClient};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
use soroban_sdk::testutils::{Address as _, Ledger as _};
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

fn setup_payroll(env: &Env) -> (PayrollClient<'_>, Address, Address) {
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

    let admin = Address::generate(env);
    payroll_client.initialize(
        &admin,
        &token_id,
        &verifier_id,
        &commitment_id,
        &treasury,
        &Address::generate(env),
    );

    (payroll_client, token_id, admin)
}

fn set_timestamp(env: &Env, ts: u64) {
    env.ledger().with_mut(|li| {
        li.timestamp = ts;
    });
}

// ---------------------------------------------------------------------------
// Clock Boundary Tests for Reservation Expiry
// ---------------------------------------------------------------------------

#[test]
fn test_reservation_at_exact_expiry_boundary() {
    let env = Env::default();
    let (payroll, token_id, admin) = setup_payroll(&env);

    let initial_timestamp = 5000u64;
    let expiry_offset = 1000u64;
    set_timestamp(&env, initial_timestamp);

    payroll.set_reservation_expiry_policy(&admin, &token_id, &5000i128, &expiry_offset);

    let reservation = payroll.get_reservation_expiry(&token_id).unwrap();
    let expires_at = reservation.expires_at;

    // Exactly at expiry boundary - release should succeed
    set_timestamp(&env, expires_at);
    payroll.release_expired_reservation(&token_id);

    // Reservation should be removed
    assert!(payroll.get_reservation_expiry(&token_id).is_none());
}

#[test]
fn test_reservation_one_tick_before_expiry() {
    let env = Env::default();
    let (payroll, token_id, admin) = setup_payroll(&env);

    let initial_timestamp = 5000u64;
    let expiry_offset = 1000u64;
    set_timestamp(&env, initial_timestamp);

    payroll.set_reservation_expiry_policy(&admin, &token_id, &5000i128, &expiry_offset);

    let reservation = payroll.get_reservation_expiry(&token_id).unwrap();
    let expires_at = reservation.expires_at;

    // One tick before expiry - release should fail
    set_timestamp(&env, expires_at - 1);
    let result = payroll.try_release_expired_reservation(&token_id);
    assert!(result.is_err());

    // Reservation should still exist
    assert!(payroll.get_reservation_expiry(&token_id).is_some());
}

#[test]
fn test_reservation_one_tick_after_expiry() {
    let env = Env::default();
    let (payroll, token_id, admin) = setup_payroll(&env);

    let initial_timestamp = 5000u64;
    let expiry_offset = 1000u64;
    set_timestamp(&env, initial_timestamp);

    payroll.set_reservation_expiry_policy(&admin, &token_id, &5000i128, &expiry_offset);

    let reservation = payroll.get_reservation_expiry(&token_id).unwrap();
    let expires_at = reservation.expires_at;

    // One tick after expiry - release should succeed
    set_timestamp(&env, expires_at + 1);
    payroll.release_expired_reservation(&token_id);

    // Reservation should be removed
    assert!(payroll.get_reservation_expiry(&token_id).is_none());
}

#[test]
fn test_reservation_mid_lifetime_fails_release() {
    let env = Env::default();
    let (payroll, token_id, admin) = setup_payroll(&env);

    let initial_timestamp = 5000u64;
    let expiry_offset = 1000u64;
    set_timestamp(&env, initial_timestamp);

    payroll.set_reservation_expiry_policy(&admin, &token_id, &5000i128, &expiry_offset);

    let reservation = payroll.get_reservation_expiry(&token_id).unwrap();
    let expires_at = reservation.expires_at;

    // Midway through reservation lifetime - release should fail
    let mid_lifetime = initial_timestamp + expiry_offset / 2;
    set_timestamp(&env, mid_lifetime);
    let result = payroll.try_release_expired_reservation(&token_id);
    assert!(result.is_err());
}

#[test]
fn test_reservation_with_zero_expiry_offset() {
    let env = Env::default();
    let (payroll, token_id, admin) = setup_payroll(&env);

    let initial_timestamp = 5000u64;
    let expiry_offset = 0u64;
    set_timestamp(&env, initial_timestamp);

    payroll.set_reservation_expiry_policy(&admin, &token_id, &5000i128, &expiry_offset);

    let reservation = payroll.get_reservation_expiry(&token_id).unwrap();
    assert_eq!(reservation.expires_at, initial_timestamp);

    // With zero expiry offset, should be immediately releasable
    set_timestamp(&env, initial_timestamp);
    payroll.release_expired_reservation(&token_id);

    assert!(payroll.get_reservation_expiry(&token_id).is_none());
}

#[test]
fn test_reservation_creation_timestamp_accuracy() {
    let env = Env::default();
    let (payroll, token_id, admin) = setup_payroll(&env);

    let initial_timestamp = 5000u64;
    let expiry_offset = 1000u64;
    set_timestamp(&env, initial_timestamp);

    payroll.set_reservation_expiry_policy(&admin, &token_id, &5000i128, &expiry_offset);

    let reservation = payroll.get_reservation_expiry(&token_id).unwrap();
    assert_eq!(reservation.created_at, initial_timestamp);
    assert_eq!(reservation.expires_at, initial_timestamp + expiry_offset);
}

#[test]
fn test_reservation_expiry_calculation_accuracy() {
    let env = Env::default();
    let (payroll, token_id, admin) = setup_payroll(&env);

    let initial_timestamp = 5000u64;
    let expiry_offset = 3600u64; // 1 hour
    set_timestamp(&env, initial_timestamp);

    payroll.set_reservation_expiry_policy(&admin, &token_id, &10000i128, &expiry_offset);

    let reservation = payroll.get_reservation_expiry(&token_id).unwrap();
    assert_eq!(reservation.expires_at, initial_timestamp + expiry_offset);
    assert_eq!(reservation.reserved_amount, 10000i128);
}

#[test]
fn test_multiple_reservations_with_different_expiry_times() {
    let env = Env::default();
    let (payroll, token_id, admin) = setup_payroll(&env);

    let initial_timestamp = 5000u64;
    set_timestamp(&env, initial_timestamp);

    // First reservation with 1000 second expiry
    payroll.set_reservation_expiry_policy(&admin, &token_id, &5000i128, &1000u64);

    let reservation1 = payroll.get_reservation_expiry(&token_id).unwrap();
    let expires_at1 = reservation1.expires_at;

    // Create second token
    let token_id2 = env.register_contract(None, Token);
    let token_client2 = TokenClient::new(&env, &token_id2);
    let treasury2 = Address::generate(&env);
    token_client2.mint(&treasury2, &1_000_000i128);

    // Second reservation with 2000 second expiry
    set_timestamp(&env, initial_timestamp + 500);
    payroll.set_reservation_expiry_policy(&admin, &token_id2, &3000i128, &2000u64);

    let reservation2 = payroll.get_reservation_expiry(&token_id2).unwrap();
    let expires_at2 = reservation2.expires_at;

    assert_eq!(expires_at1, initial_timestamp + 1000);
    assert_eq!(expires_at2, initial_timestamp + 500 + 2000);

    // First reservation should expire first
    set_timestamp(&env, expires_at1);
    payroll.release_expired_reservation(&token_id);
    assert!(payroll.get_reservation_expiry(&token_id).is_none());
    assert!(payroll.get_reservation_expiry(&token_id2).is_some());

    // Second reservation should still be active
    set_timestamp(&env, expires_at2 - 1);
    let result = payroll.try_release_expired_reservation(&token_id2);
    assert!(result.is_err());

    // Second reservation should expire at its own expiry time
    set_timestamp(&env, expires_at2);
    payroll.release_expired_reservation(&token_id2);
    assert!(payroll.get_reservation_expiry(&token_id2).is_none());
}

#[test]
fn test_reservation_policy_update_before_expiry() {
    let env = Env::default();
    let (payroll, token_id, admin) = setup_payroll(&env);

    let initial_timestamp = 5000u64;
    let expiry_offset = 1000u64;
    set_timestamp(&env, initial_timestamp);

    payroll.set_reservation_expiry_policy(&admin, &token_id, &5000i128, &expiry_offset);

    // Update policy before expiry
    set_timestamp(&env, initial_timestamp + 500);
    payroll.set_reservation_expiry_policy(&admin, &token_id, &7000i128, &2000u64);

    let updated_reservation = payroll.get_reservation_expiry(&token_id).unwrap();
    assert_eq!(updated_reservation.reserved_amount, 7000i128);
    assert_eq!(
        updated_reservation.expires_at,
        initial_timestamp + 500 + 2000
    );
    assert_eq!(updated_reservation.created_at, initial_timestamp + 500);
}

#[test]
fn test_reservation_release_after_policy_update() {
    let env = Env::default();
    let (payroll, token_id, admin) = setup_payroll(&env);

    let initial_timestamp = 5000u64;
    let expiry_offset = 1000u64;
    set_timestamp(&env, initial_timestamp);

    payroll.set_reservation_expiry_policy(&admin, &token_id, &5000i128, &expiry_offset);

    // Update policy
    set_timestamp(&env, initial_timestamp + 500);
    payroll.set_reservation_expiry_policy(&admin, &token_id, &7000i128, &2000u64);

    let updated_reservation = payroll.get_reservation_expiry(&token_id).unwrap();
    let new_expires_at = updated_reservation.expires_at;

    // Release at new expiry time
    set_timestamp(&env, new_expires_at);
    payroll.release_expired_reservation(&token_id);

    assert!(payroll.get_reservation_expiry(&token_id).is_none());
}

#[test]
fn test_reservation_expiry_very_large_offset() {
    let env = Env::default();
    let (payroll, token_id, admin) = setup_payroll(&env);

    let initial_timestamp = 5000u64;
    let large_expiry_offset = u64::MAX / 2; // Very large offset
    set_timestamp(&env, initial_timestamp);

    payroll.set_reservation_expiry_policy(&admin, &token_id, &5000i128, &large_expiry_offset);

    let reservation = payroll.get_reservation_expiry(&token_id).unwrap();
    assert_eq!(
        reservation.expires_at,
        initial_timestamp + large_expiry_offset
    );

    // Should not be releasable at creation time
    set_timestamp(&env, initial_timestamp);
    let result = payroll.try_release_expired_reservation(&token_id);
    assert!(result.is_err());
}

#[test]
fn test_reservation_expiry_boundary_with_exact_timestamp_match() {
    let env = Env::default();
    let (payroll, token_id, admin) = setup_payroll(&env);

    let initial_timestamp = 10000u64;
    let expiry_offset = 500u64;
    set_timestamp(&env, initial_timestamp);

    payroll.set_reservation_expiry_policy(&admin, &token_id, &5000i128, &expiry_offset);

    let reservation = payroll.get_reservation_expiry(&token_id).unwrap();
    let expires_at = reservation.expires_at;

    // Test exact timestamp match - should succeed
    set_timestamp(&env, expires_at);
    payroll.release_expired_reservation(&token_id);
    assert!(payroll.get_reservation_expiry(&token_id).is_none());
}
