//! Auditor grant expiry enforcement regressions (Issues #969, #970).
//!
//! A grant is valid while `ledger.sequence() <= expiration_ledger` and is
//! expired from `expiration_ledger + 1`. These tests pin the boundary and,
//! critically, verify that expired grants are immutable: lifecycle mutations
//! must fail with `KeyExpired` and only a fresh `generate_view_key` may revive
//! a grant. All checks share the same validator used by `verify_access` and
//! `authorize_auditor`, so read and write paths cannot drift.

use audit_module::{AuditError, AuditModule, AuditModuleClient, AuditScope};
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{Address, Env};

fn setup() -> (Env, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AuditModule, ());
    (env, contract_id)
}

#[test]
fn refresh_rejects_expired_grant_and_keeps_record() {
    let (env, admin) = setup();
    let client = AuditModuleClient::new(&env, &admin);
    let auditor = Address::generate(&env);
    let expiration = env.ledger().sequence() + 100;
    client.generate_view_key(&auditor, &expiration);

    assert_eq!(client.get_expiration(&auditor), expiration);

    env.ledger().set_sequence_number(expiration + 1);
    assert_eq!(
        client.try_refresh_view_key(&admin, &auditor, &(expiration + 500)),
        Err(Ok(AuditError::KeyExpired))
    );
    // The stored expiration is unchanged; no revival occurred.
    assert_eq!(client.get_expiration(&auditor), expiration);
    assert!(!client.verify_access(&auditor));
}

#[test]
fn set_delegation_policy_rejects_expired_grant() {
    let (env, admin) = setup();
    let client = AuditModuleClient::new(&env, &admin);
    let auditor = Address::generate(&env);
    let expiration = env.ledger().sequence() + 100;
    client.generate_view_key(&auditor, &expiration);

    env.ledger().set_sequence_number(expiration + 1);
    assert_eq!(
        client.try_set_delegation_policy(
            &admin,
            &auditor,
            &true,
            &AuditScope::FullCompany,
            &(expiration + 500),
        ),
        Err(Ok(AuditError::KeyExpired))
    );
}

#[test]
fn approve_delegation_rejects_expired_grant() {
    let (env, admin) = setup();
    let client = AuditModuleClient::new(&env, &admin);
    let auditor = Address::generate(&env);
    let expiration = env.ledger().sequence() + 100;
    client.generate_view_key(&auditor, &expiration);

    env.ledger().set_sequence_number(expiration + 1);
    assert_eq!(
        client.try_approve_delegation(
            &admin,
            &auditor,
            &true,
            &AuditScope::FullCompany,
            &(expiration + 500),
        ),
        Err(Ok(AuditError::KeyExpired))
    );
}

#[test]
fn generate_view_key_is_the_explicit_revival_path() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);
    let auditor = Address::generate(&env);
    let expiration = env.ledger().sequence() + 100;
    client.generate_view_key(&auditor, &expiration);

    env.ledger().set_sequence_number(expiration + 1);
    assert!(!client.verify_access(&auditor));

    // A fresh grant is the only way to revive access after expiry.
    let now = env.ledger().sequence();
    client.generate_view_key(&auditor, &(now + 100));
    assert!(client.verify_access(&auditor));
    assert_eq!(client.get_expiration(&auditor), now + 100);
}

#[test]
fn delegated_grant_expires_with_parent_and_cannot_be_mutated() {
    let (env, admin) = setup();
    let client = AuditModuleClient::new(&env, &admin);
    let parent_expiration = env.ledger().sequence() + 100;
    let parent = Address::generate(&env);
    let delegate = Address::generate(&env);

    client.generate_view_key(&parent, &parent_expiration);
    client.set_delegation_policy(
        &admin,
        &parent,
        &true,
        &AuditScope::FullCompany,
        &parent_expiration,
    );
    client.delegate_view_key(
        &parent,
        &delegate,
        &AuditScope::AggregateOnly,
        &parent_expiration,
    );
    assert!(client.verify_access(&delegate));

    // One ledger past the parent's expiry the delegate is also inactive.
    env.ledger().set_sequence_number(parent_expiration + 1);
    assert!(!client.verify_access(&delegate));
    assert_eq!(
        client.try_extend_delegated_access(&parent, &delegate, &(parent_expiration + 500)),
        Err(Ok(AuditError::KeyExpired))
    );
}
