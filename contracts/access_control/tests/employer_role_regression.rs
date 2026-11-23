//! Regression tests for employer role changes (#949).
//!
//! These tests pin the observable behavior of the role-transition flow: only
//! one employer is active at a time, cancellation restores the previous state,
//! revocation during a pending handoff fails closed, and rejected transitions
//! never mutate storage or emit events.

#![cfg(test)]

use access_control::{
    accept_employer_role_transfer, cancel_employer_role_transfer, get_employer_role,
    get_pending_transfer, is_active_employer, propose_employer_role_transfer, register_employer,
    require_active_employer, revoke_employer_role,
};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env};

fn setup() -> (Env, u64, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let employer = Address::generate(&env);
    let company_id = 50;
    register_employer(&env, company_id, &employer);
    (env, company_id, employer)
}

#[test]
fn accepted_transfer_leaves_exactly_one_active_employer() {
    let (env, company_id, employer) = setup();
    let incoming = Address::generate(&env);
    let before = get_employer_role(&env, company_id);

    propose_employer_role_transfer(&env, company_id, &employer, &incoming);
    accept_employer_role_transfer(&env, company_id, &incoming);

    let after = get_employer_role(&env, company_id);
    assert_eq!(after.employer, incoming);
    assert!(!after.revoked);
    assert!(after.last_changed_at >= before.last_changed_at);
    assert!(get_pending_transfer(&env, company_id).is_none());
    assert!(is_active_employer(&env, company_id, &incoming));
    assert!(!is_active_employer(&env, company_id, &employer));

    require_active_employer(&env, company_id, &incoming);
    assert!(std::panic::catch_unwind(|| {
        require_active_employer(&env, company_id, &employer);
    })
    .is_err());
}

#[test]
fn cancelled_transfer_can_be_replaced_by_a_new_proposal() {
    let (env, company_id, employer) = setup();
    let first = Address::generate(&env);
    let second = Address::generate(&env);

    propose_employer_role_transfer(&env, company_id, &employer, &first);
    cancel_employer_role_transfer(&env, company_id, &employer);
    assert!(get_pending_transfer(&env, company_id).is_none());
    assert!(is_active_employer(&env, company_id, &employer));
    assert!(!is_active_employer(&env, company_id, &first));

    propose_employer_role_transfer(&env, company_id, &employer, &second);
    let pending = get_pending_transfer(&env, company_id).unwrap();
    assert_eq!(pending.incoming, second);
    assert_eq!(pending.initiated_by, employer);
    accept_employer_role_transfer(&env, company_id, &second);

    assert!(is_active_employer(&env, company_id, &second));
    assert!(!is_active_employer(&env, company_id, &employer));
}

#[test]
fn revocation_during_pending_transfer_fails_closed_without_clearing_proposal() {
    let (env, company_id, employer) = setup();
    let incoming = Address::generate(&env);
    propose_employer_role_transfer(&env, company_id, &employer, &incoming);
    revoke_employer_role(&env, company_id, &employer);

    assert!(std::panic::catch_unwind(|| accept_employer_role_transfer(
        &env, company_id, &incoming
    ))
    .is_err());

    let record = get_employer_role(&env, company_id);
    assert_eq!(record.employer, employer);
    assert!(record.revoked);
    assert!(get_pending_transfer(&env, company_id).is_some());
    assert!(!is_active_employer(&env, company_id, &incoming));
}

#[test]
fn failed_role_transitions_do_not_mutate_state_or_emit_events() {
    let (env, company_id, employer) = setup();
    let incoming = Address::generate(&env);
    let attacker = Address::generate(&env);
    let original_record = get_employer_role(&env, company_id);
    let original_events = env.events().all();

    assert!(std::panic::catch_unwind(|| {
        propose_employer_role_transfer(&env, company_id, &attacker, &incoming);
    })
    .is_err());
    assert!(std::panic::catch_unwind(|| {
        cancel_employer_role_transfer(&env, company_id, &attacker);
    })
    .is_err());
    assert!(std::panic::catch_unwind(|| {
        accept_employer_role_transfer(&env, company_id, &attacker);
    })
    .is_err());

    assert_eq!(get_employer_role(&env, company_id), original_record);
    assert!(get_pending_transfer(&env, company_id).is_none());
    assert_eq!(env.events().all(), original_events);
    assert!(is_active_employer(&env, company_id, &employer));
}

#[test]
fn absent_role_record_never_grants_employer_access() {
    let env = Env::default();
    env.mock_all_auths();
    let stranger = Address::generate(&env);

    assert!(!is_active_employer(&env, 99, &stranger));
    assert!(std::panic::catch_unwind(|| {
        require_active_employer(&env, 99, &stranger);
    })
    .is_err());
}
