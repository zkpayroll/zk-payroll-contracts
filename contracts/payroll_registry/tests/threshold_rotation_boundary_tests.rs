//! Clock boundary tests for threshold rotation grace periods (#353).
//!
//! Covers: exact grace period boundaries, adjacent timestamp cases,
//! and edge conditions for threshold rotation activation.

#![cfg(test)]

use payroll_registry::PayrollRegistryClient;
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{Address, Env};

fn setup() -> (Env, Address, u64, Address) {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(payroll_registry::PayrollRegistry, ());
    let client = PayrollRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);

    let company_id = client.register_company(&admin, &treasury);

    (env, admin, company_id, contract_id)
}

fn set_timestamp(env: &Env, ts: u64) {
    env.ledger().with_mut(|li| {
        li.timestamp = ts;
    });
}

// ---------------------------------------------------------------------------
// Clock Boundary Tests for Threshold Rotation Grace Periods
// ---------------------------------------------------------------------------

#[test]
fn test_threshold_rotation_at_exact_grace_period_boundary() {
    let (env, admin, company_id, contract_id) = setup();
    let client = PayrollRegistryClient::new(&env, &contract_id);

    let grace_period = 1000u64;
    let initial_timestamp = 5000u64;
    set_timestamp(&env, initial_timestamp);

    let new_threshold = 3u32;
    client.propose_threshold_rotation(&company_id, &admin, &new_threshold, &grace_period);

    let pending = client.get_pending_threshold_rotation(&company_id).unwrap();
    let effective_after = pending.effective_after;

    // Exactly at the effective_after boundary - activation should succeed
    set_timestamp(&env, effective_after);
    client.activate_threshold_rotation(&company_id, &admin);

    let threshold = client.get_approval_threshold(&company_id).unwrap();
    assert_eq!(threshold.required_approvals, new_threshold);
    assert!(client.get_pending_threshold_rotation(&company_id).is_none());
}

#[test]
fn test_threshold_rotation_one_tick_before_grace_period() {
    let (env, admin, company_id, contract_id) = setup();
    let client = PayrollRegistryClient::new(&env, &contract_id);

    let grace_period = 1000u64;
    let initial_timestamp = 5000u64;
    set_timestamp(&env, initial_timestamp);

    let new_threshold = 3u32;
    client.propose_threshold_rotation(&company_id, &admin, &new_threshold, &grace_period);

    let pending = client.get_pending_threshold_rotation(&company_id).unwrap();
    let effective_after = pending.effective_after;

    // One tick before the effective_after boundary - activation should fail
    set_timestamp(&env, effective_after - 1);
    let result = client.try_activate_threshold_rotation(&company_id, &admin);
    assert!(result.is_err());

    // Pending rotation should still exist
    assert!(client.get_pending_threshold_rotation(&company_id).is_some());
    // Old threshold should still be active
    let old_threshold = client.get_approval_threshold(&company_id);
    assert!(old_threshold.is_none()); // No initial threshold set
}

#[test]
fn test_threshold_rotation_one_tick_after_grace_period() {
    let (env, admin, company_id, contract_id) = setup();
    let client = PayrollRegistryClient::new(&env, &contract_id);

    let grace_period = 1000u64;
    let initial_timestamp = 5000u64;
    set_timestamp(&env, initial_timestamp);

    let new_threshold = 3u32;
    client.propose_threshold_rotation(&company_id, &admin, &new_threshold, &grace_period);

    let pending = client.get_pending_threshold_rotation(&company_id).unwrap();
    let effective_after = pending.effective_after;

    // One tick after the effective_after boundary - activation should succeed
    set_timestamp(&env, effective_after + 1);
    client.activate_threshold_rotation(&company_id, &admin);

    let threshold = client.get_approval_threshold(&company_id).unwrap();
    assert_eq!(threshold.required_approvals, new_threshold);
}

#[test]
fn test_threshold_rotation_mid_grace_period_fails() {
    let (env, admin, company_id, contract_id) = setup();
    let client = PayrollRegistryClient::new(&env, &contract_id);

    let grace_period = 1000u64;
    let initial_timestamp = 5000u64;
    set_timestamp(&env, initial_timestamp);

    let new_threshold = 3u32;
    client.propose_threshold_rotation(&company_id, &admin, &new_threshold, &grace_period);

    let pending = client.get_pending_threshold_rotation(&company_id).unwrap();
    let effective_after = pending.effective_after;

    // Midway through the grace period - activation should fail
    let mid_grace = initial_timestamp + grace_period / 2;
    set_timestamp(&env, mid_grace);
    let result = client.try_activate_threshold_rotation(&company_id, &admin);
    assert!(result.is_err());
}

#[test]
fn test_threshold_rotation_with_zero_grace_period() {
    let (env, admin, company_id, contract_id) = setup();
    let client = PayrollRegistryClient::new(&env, &contract_id);

    let grace_period = 0u64;
    let initial_timestamp = 5000u64;
    set_timestamp(&env, initial_timestamp);

    let new_threshold = 3u32;
    client.propose_threshold_rotation(&company_id, &admin, &new_threshold, &grace_period);

    // With zero grace period, should be immediately activatable
    set_timestamp(&env, initial_timestamp);
    client.activate_threshold_rotation(&company_id, &admin);

    let threshold = client.get_approval_threshold(&company_id).unwrap();
    assert_eq!(threshold.required_approvals, new_threshold);
}

#[test]
fn test_threshold_rotation_cancellation_before_grace_period() {
    let (env, admin, company_id, contract_id) = setup();
    let client = PayrollRegistryClient::new(&env, &contract_id);

    let grace_period = 1000u64;
    let initial_timestamp = 5000u64;
    set_timestamp(&env, initial_timestamp);

    let new_threshold = 3u32;
    client.propose_threshold_rotation(&company_id, &admin, &new_threshold, &grace_period);

    // Cancel before grace period expires
    set_timestamp(&env, initial_timestamp + 500);
    client.cancel_threshold_rotation(&company_id, &admin);

    assert!(client.get_pending_threshold_rotation(&company_id).is_none());
}

#[test]
fn test_threshold_rotation_cancellation_after_grace_period() {
    let (env, admin, company_id, contract_id) = setup();
    let client = PayrollRegistryClient::new(&env, &contract_id);

    let grace_period = 1000u64;
    let initial_timestamp = 5000u64;
    set_timestamp(&env, initial_timestamp);

    let new_threshold = 3u32;
    client.propose_threshold_rotation(&company_id, &admin, &new_threshold, &grace_period);

    let pending = client.get_pending_threshold_rotation(&company_id).unwrap();
    let effective_after = pending.effective_after;

    // Cancel after grace period expires
    set_timestamp(&env, effective_after + 100);
    client.cancel_threshold_rotation(&company_id, &admin);

    assert!(client.get_pending_threshold_rotation(&company_id).is_none());
}

#[test]
fn test_threshold_rotation_with_initial_threshold() {
    let (env, admin, company_id, contract_id) = setup();
    let client = PayrollRegistryClient::new(&env, &contract_id);

    // Set initial threshold
    let initial_threshold = 2u32;
    client.set_initial_approval_threshold(&company_id, &admin, &initial_threshold);

    let grace_period = 1000u64;
    let initial_timestamp = 5000u64;
    set_timestamp(&env, initial_timestamp);

    let new_threshold = 3u32;
    client.propose_threshold_rotation(&company_id, &admin, &new_threshold, &grace_period);

    let pending = client.get_pending_threshold_rotation(&company_id).unwrap();
    let effective_after = pending.effective_after;

    // Before grace period - old threshold should still be active
    set_timestamp(&env, initial_timestamp + 500);
    let threshold = client.get_approval_threshold(&company_id).unwrap();
    assert_eq!(threshold.required_approvals, initial_threshold);

    // After grace period - new threshold should be active
    set_timestamp(&env, effective_after);
    client.activate_threshold_rotation(&company_id, &admin);

    let updated_threshold = client.get_approval_threshold(&company_id).unwrap();
    assert_eq!(updated_threshold.required_approvals, new_threshold);
}

#[test]
fn test_threshold_rotation_proposal_timestamp_accuracy() {
    let (env, admin, company_id, contract_id) = setup();
    let client = PayrollRegistryClient::new(&env, &contract_id);

    let grace_period = 1000u64;
    let initial_timestamp = 5000u64;
    set_timestamp(&env, initial_timestamp);

    let new_threshold = 3u32;
    client.propose_threshold_rotation(&company_id, &admin, &new_threshold, &grace_period);

    let pending = client.get_pending_threshold_rotation(&company_id).unwrap();
    assert_eq!(pending.proposed_at, initial_timestamp);
    assert_eq!(pending.effective_after, initial_timestamp + grace_period);
}

#[test]
fn test_multiple_threshold_rotations_with_overlapping_grace_periods() {
    let (env, admin, company_id, contract_id) = setup();
    let client = PayrollRegistryClient::new(&env, &contract_id);

    let grace_period = 1000u64;
    let initial_timestamp = 5000u64;
    set_timestamp(&env, initial_timestamp);

    // First proposal
    let threshold1 = 3u32;
    client.propose_threshold_rotation(&company_id, &admin, &threshold1, &grace_period);

    // Second proposal before first grace period expires
    set_timestamp(&env, initial_timestamp + 500);
    let threshold2 = 4u32;
    // The contract allows multiple proposals - this is the actual behavior
    client.propose_threshold_rotation(&company_id, &admin, &threshold2, &grace_period);

    let pending = client.get_pending_threshold_rotation(&company_id).unwrap();
    // The second proposal replaces the first
    assert_eq!(pending.new_threshold, threshold2);
    assert_eq!(pending.proposed_at, initial_timestamp + 500);
}

#[test]
fn test_threshold_rotation_activation_updates_configured_timestamp() {
    let (env, admin, company_id, contract_id) = setup();
    let client = PayrollRegistryClient::new(&env, &contract_id);

    let grace_period = 1000u64;
    let initial_timestamp = 5000u64;
    set_timestamp(&env, initial_timestamp);

    let new_threshold = 3u32;
    client.propose_threshold_rotation(&company_id, &admin, &new_threshold, &grace_period);

    let pending = client.get_pending_threshold_rotation(&company_id).unwrap();
    let effective_after = pending.effective_after;

    set_timestamp(&env, effective_after);
    client.activate_threshold_rotation(&company_id, &admin);

    let threshold = client.get_approval_threshold(&company_id).unwrap();
    assert_eq!(threshold.configured_at, effective_after);
    assert_eq!(threshold.configured_by, admin);
}
