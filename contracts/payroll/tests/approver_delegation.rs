//! Tests for temporary approver delegation controls (#636).

#![cfg(test)]

use soroban_sdk::{testutils::Address as _, Address, BytesN, Env, String};

use payroll::{
    approver_delegation::{
        delegate_approver, get_active_delegation, is_delegation_active,
        resolve_effective_approver, revoke_delegation, DelegationKey,
        MAX_DELEGATION_DURATION_SECONDS,
    },
    DataKey,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn register_reviewer(e: &Env, reviewer: &Address) {
    e.storage()
        .persistent()
        .set(&DataKey::AuthorizedReviewer(reviewer.clone()), &true);
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[test]
fn test_delegate_approver_success() {
    let e = Env::default();
    e.mock_all_auths();

    let delegator = Address::generate(&e);
    let delegate = Address::generate(&e);

    // Both must be reviewers
    register_reviewer(&e, &delegator);
    register_reviewer(&e, &delegate);

    e.ledger().set_timestamp(1_000_000);
    let duration = 86_400u64; // 1 day

    delegate_approver(&e, delegator.clone(), delegate.clone(), duration, String::from_str(&e, "vacation cover"));

    let record = get_active_delegation(&e, &delegator).expect("delegation should exist");
    assert_eq!(record.delegator, delegator);
    assert_eq!(record.delegate, delegate);
    assert_eq!(record.expires_at, 1_000_000 + duration);
    assert!(is_delegation_active(&e, &delegator));
}

#[test]
#[should_panic(expected = "Self-delegation rejected")]
fn test_delegate_to_self_fails() {
    let e = Env::default();
    e.mock_all_auths();

    let delegator = Address::generate(&e);
    register_reviewer(&e, &delegator);

    delegate_approver(
        &e,
        delegator.clone(),
        delegator.clone(),
        86_400,
        String::from_str(&e, "self"),
    );
}

#[test]
fn test_expired_delegation_not_active() {
    let e = Env::default();
    e.mock_all_auths();

    let delegator = Address::generate(&e);
    let delegate = Address::generate(&e);

    register_reviewer(&e, &delegator);
    register_reviewer(&e, &delegate);

    // Create delegation at t=1000
    e.ledger().set_timestamp(1_000);
    delegate_approver(
        &e,
        delegator.clone(),
        delegate.clone(),
        500, // expires at t=1500
        String::from_str(&e, "short cover"),
    );

    // Advance time past expiry
    e.ledger().set_timestamp(2_000);

    assert!(!is_delegation_active(&e, &delegator));
    assert!(get_active_delegation(&e, &delegator).is_none());

    // resolve_effective_approver should return the delegator since delegation expired
    let resolved = resolve_effective_approver(&e, &delegator);
    assert_eq!(resolved, delegator);
}

#[test]
fn test_revoke_delegation() {
    let e = Env::default();
    e.mock_all_auths();

    let delegator = Address::generate(&e);
    let delegate = Address::generate(&e);

    register_reviewer(&e, &delegator);
    register_reviewer(&e, &delegate);

    e.ledger().set_timestamp(1_000_000);
    delegate_approver(
        &e,
        delegator.clone(),
        delegate.clone(),
        86_400,
        String::from_str(&e, "cover"),
    );
    assert!(is_delegation_active(&e, &delegator));

    revoke_delegation(&e, delegator.clone());
    assert!(!is_delegation_active(&e, &delegator));
    assert!(get_active_delegation(&e, &delegator).is_none());
}

#[test]
#[should_panic(expected = "Delegate is not an authorized reviewer")]
fn test_delegate_non_reviewer_fails() {
    let e = Env::default();
    e.mock_all_auths();

    let delegator = Address::generate(&e);
    let not_a_reviewer = Address::generate(&e);

    register_reviewer(&e, &delegator);
    // NOT registering not_a_reviewer

    e.ledger().set_timestamp(1_000_000);
    delegate_approver(
        &e,
        delegator.clone(),
        not_a_reviewer.clone(),
        86_400,
        String::from_str(&e, "invalid"),
    );
}

#[test]
#[should_panic(expected = "Invalid delegation duration")]
fn test_zero_duration_fails() {
    let e = Env::default();
    e.mock_all_auths();

    let delegator = Address::generate(&e);
    let delegate = Address::generate(&e);
    register_reviewer(&e, &delegator);
    register_reviewer(&e, &delegate);

    delegate_approver(&e, delegator, delegate, 0, String::from_str(&e, "zero"));
}

#[test]
fn test_resolve_effective_approver_with_active_delegation() {
    let e = Env::default();
    e.mock_all_auths();

    let delegator = Address::generate(&e);
    let delegate = Address::generate(&e);

    register_reviewer(&e, &delegator);
    register_reviewer(&e, &delegate);

    e.ledger().set_timestamp(1_000_000);
    delegate_approver(
        &e,
        delegator.clone(),
        delegate.clone(),
        86_400,
        String::from_str(&e, "cover"),
    );

    let resolved = resolve_effective_approver(&e, &delegator);
    assert_eq!(resolved, delegate);
}
