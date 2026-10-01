//! Delegated approver (reviewer) assignment limits (issue #539).
//!
//! `add_reviewer` previously had no cap on how many addresses an admin could
//! authorize as reviewers. `set_max_reviewers` makes the cap opt-in, mirroring
//! `set_capacity_limits`: absent a policy, behavior is unchanged from before
//! this feature existed.

#![cfg(test)]

mod common;

use payroll::PayrollClient;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env};

fn setup_with_reviewers(env: &Env) -> (PayrollClient<'_>, Address) {
    let (client, _token, _employee) = common::setup(env);
    let admin = client.get_addresses().admin;
    (client, admin)
}

#[test]
fn add_reviewer_is_unlimited_by_default() {
    let env = Env::default();
    let (client, admin) = setup_with_reviewers(&env);

    // No cap configured: adding many reviewers must never be rejected.
    for _ in 0..10 {
        let reviewer = Address::generate(&env);
        client.add_reviewer(&admin, &reviewer);
    }
    assert_eq!(client.get_reviewer_count(), 10);
    assert_eq!(client.get_max_reviewers(), None);
}

#[test]
fn set_max_reviewers_caps_future_additions() {
    let env = Env::default();
    let (client, admin) = setup_with_reviewers(&env);

    client.set_max_reviewers(&admin, &2u32);
    assert_eq!(client.get_max_reviewers(), Some(2));

    client.add_reviewer(&admin, &Address::generate(&env));
    client.add_reviewer(&admin, &Address::generate(&env));
    assert_eq!(client.get_reviewer_count(), 2);
}

#[test]
#[should_panic(expected = "Reviewer limit reached")]
fn add_reviewer_beyond_cap_panics() {
    let env = Env::default();
    let (client, admin) = setup_with_reviewers(&env);

    client.set_max_reviewers(&admin, &1u32);
    client.add_reviewer(&admin, &Address::generate(&env));
    // The second distinct reviewer must be rejected.
    client.add_reviewer(&admin, &Address::generate(&env));
}

#[test]
fn readding_existing_reviewer_does_not_count_against_cap() {
    let env = Env::default();
    let (client, admin) = setup_with_reviewers(&env);

    client.set_max_reviewers(&admin, &1u32);
    let reviewer = Address::generate(&env);
    client.add_reviewer(&admin, &reviewer);
    // Re-adding the SAME reviewer must be a no-op with respect to the cap,
    // not rejected as "over the limit".
    client.add_reviewer(&admin, &reviewer);
    assert_eq!(client.get_reviewer_count(), 1);
}

#[test]
fn removing_a_reviewer_frees_capacity_for_a_new_one() {
    let env = Env::default();
    let (client, admin) = setup_with_reviewers(&env);

    client.set_max_reviewers(&admin, &1u32);
    let first = Address::generate(&env);
    client.add_reviewer(&admin, &first);
    assert_eq!(client.get_reviewer_count(), 1);

    client.remove_reviewer(&admin, &first);
    assert_eq!(client.get_reviewer_count(), 0);

    // Capacity freed by the removal must allow a new reviewer.
    let second = Address::generate(&env);
    client.add_reviewer(&admin, &second);
    assert_eq!(client.get_reviewer_count(), 1);
    assert!(client.is_reviewer(&second));
}

#[test]
fn removing_a_non_reviewer_does_not_underflow_the_count() {
    let env = Env::default();
    let (client, admin) = setup_with_reviewers(&env);

    // Removing an address that was never authorized must be a safe no-op,
    // not decrement the count below zero.
    client.remove_reviewer(&admin, &Address::generate(&env));
    assert_eq!(client.get_reviewer_count(), 0);
}

#[test]
fn lowering_cap_below_current_count_does_not_revoke_existing_reviewers() {
    let env = Env::default();
    let (client, admin) = setup_with_reviewers(&env);

    let first = Address::generate(&env);
    let second = Address::generate(&env);
    client.add_reviewer(&admin, &first);
    client.add_reviewer(&admin, &second);
    assert_eq!(client.get_reviewer_count(), 2);

    // Lowering the cap below the current count must not revoke anyone.
    client.set_max_reviewers(&admin, &1u32);
    assert!(client.is_reviewer(&first));
    assert!(client.is_reviewer(&second));
    assert_eq!(client.get_reviewer_count(), 2);
}

#[test]
#[should_panic]
fn set_max_reviewers_by_non_admin_panics() {
    let env = Env::default();
    let (client, _admin) = setup_with_reviewers(&env);
    client.set_max_reviewers(&Address::generate(&env), &5u32);
}

#[test]
#[should_panic(expected = "Reviewer limit must be positive")]
fn set_max_reviewers_rejects_zero() {
    let env = Env::default();
    let (client, admin) = setup_with_reviewers(&env);
    client.set_max_reviewers(&admin, &0u32);
}
