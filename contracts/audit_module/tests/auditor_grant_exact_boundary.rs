//! Auditor grant expiration at the exact boundary (Issue #890).
//!
//! A grant is valid while `ledger.sequence() <= expiration_ledger`. These
//! tests pin `expiration - 1`, `expiration` and `expiration + 1` on every
//! read path, and check that a grant cannot be created already expired.

use audit_module::{AuditError, AuditModule, AuditModuleClient, AuditScope};
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{Address, Env};

const START: u32 = 1_000;

fn setup() -> (Env, Address) {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_sequence_number(START);
    let contract_id = env.register(AuditModule, ());
    (env, contract_id)
}

#[test]
fn access_is_valid_through_the_expiration_ledger_and_ends_after_it() {
    let (env, admin) = setup();
    let client = AuditModuleClient::new(&env, &admin);
    let auditor = Address::generate(&env);
    let expiration = START + 50;
    client.generate_view_key(&auditor, &expiration);

    env.ledger().set_sequence_number(expiration - 1);
    assert!(client.verify_access(&auditor));

    env.ledger().set_sequence_number(expiration);
    assert!(
        client.verify_access(&auditor),
        "expiration ledger itself is still valid"
    );
    assert_eq!(
        client.try_check_grant_expiry(&auditor, &0),
        Err(Ok(AuditError::GrantNotExpired))
    );

    env.ledger().set_sequence_number(expiration + 1);
    assert!(
        !client.verify_access(&auditor),
        "one ledger later the grant is expired"
    );
    assert_eq!(client.try_check_grant_expiry(&auditor, &0), Ok(Ok(())));
}

#[test]
fn refresh_at_the_expiration_ledger_still_succeeds() {
    let (env, admin) = setup();
    let client = AuditModuleClient::new(&env, &admin);
    let auditor = Address::generate(&env);
    let expiration = START + 50;
    client.generate_view_key(&auditor, &expiration);

    env.ledger().set_sequence_number(expiration);
    assert_eq!(
        client.try_refresh_view_key(&admin, &auditor, &expiration),
        Err(Ok(AuditError::ExpirationNotExtended))
    );
    client.refresh_view_key(&admin, &auditor, &(expiration + 1));
    assert_eq!(client.get_expiration(&auditor), expiration + 1);
}

#[test]
fn generate_accepts_the_current_ledger_and_rejects_a_past_one() {
    let (env, admin) = setup();
    let client = AuditModuleClient::new(&env, &admin);
    let current = Address::generate(&env);
    let past = Address::generate(&env);

    client.generate_view_key(&current, &START);
    assert!(client.verify_access(&current));

    // generate_view_key keeps its non-Result ABI, so the typed error surfaces
    // as a contract error code.
    let err = client
        .try_generate_view_key(&past, &(START - 1))
        .expect_err("a past expiration must be rejected")
        .expect("typed contract error");
    assert_eq!(
        err,
        soroban_sdk::Error::from_contract_error(AuditError::ExpirationInPast as u32)
    );
    assert_eq!(
        client.try_get_expiration(&past),
        Err(Ok(AuditError::KeyNotFound))
    );
}

#[test]
fn delegation_rejects_a_past_expiration_and_ends_with_the_parent() {
    let (env, admin) = setup();
    let client = AuditModuleClient::new(&env, &admin);
    let parent = Address::generate(&env);
    let delegate = Address::generate(&env);
    let expiration = START + 50;

    client.generate_view_key(&parent, &expiration);
    client.set_delegation_policy(
        &admin,
        &parent,
        &true,
        &AuditScope::FullCompany,
        &expiration,
    );

    assert_eq!(
        client.try_delegate_view_key(&parent, &delegate, &AuditScope::AggregateOnly, &(START - 1)),
        Err(Ok(AuditError::ExpirationInPast))
    );

    client.delegate_view_key(&parent, &delegate, &AuditScope::AggregateOnly, &expiration);
    env.ledger().set_sequence_number(expiration);
    assert!(client.verify_access(&delegate));
    env.ledger().set_sequence_number(expiration + 1);
    assert!(!client.verify_access(&delegate));
}

#[test]
fn past_expiration_message_is_actionable_and_private() {
    let msg = AuditError::ExpirationInPast.message();
    assert!(msg.contains("later ledger"));
    assert!(
        !msg.chars().any(|c| c.is_ascii_digit()),
        "message must not embed ledger numbers"
    );
}
