//! Privacy-safe, actionable errors for auditor grant expiry (issue #971).
//!
//! `check_grant_expiry` is a read-only diagnostic that reports exactly why a
//! grant is or is not prunable, using stable typed errors instead of opaque
//! boolean state.

use audit_module::{AuditError, AuditModule, AuditModuleClient};
use soroban_sdk::testutils::{Address as _, Events as _, Ledger as _};
use soroban_sdk::Env;

fn setup() -> (Env, soroban_sdk::Address, soroban_sdk::Address) {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register(AuditModule, ());
    let auditor = soroban_sdk::Address::generate(&env);
    (env, id, auditor)
}

/// The generated `try_` client returns a nested result.
fn expiry_check(
    client: &AuditModuleClient<'_>,
    auditor: &soroban_sdk::Address,
    retention: u32,
) -> Result<(), AuditError> {
    match client.try_check_grant_expiry(auditor, &retention) {
        Ok(Ok(())) => Ok(()),
        Err(Ok(error)) => Err(error),
        _ => panic!("unexpected host-level diagnostic failure"),
    }
}

#[test]
fn test_safe_messages_are_actionable_and_contain_no_private_data() {
    for error in [
        AuditError::KeyNotFound,
        AuditError::KeyExpired,
        AuditError::GrantNotExpired,
        AuditError::GrantNotYetPrunable,
        AuditError::NotKeyGranter,
        AuditError::DelegationRevoked,
    ] {
        let message = error.message();
        assert!(!message.is_empty());
        let lower = message.to_lowercase();
        assert!(!lower.contains("salary"));
        assert!(!lower.contains("employee"));
        assert!(!lower.contains("commitment"));
    }
    assert_eq!(AuditError::GrantNotExpired as u32, 22);
    assert_eq!(AuditError::GrantNotYetPrunable as u32, 23);
}

#[test]
fn test_missing_grant_reports_key_not_found() {
    let (env, id, auditor) = setup();
    let client = AuditModuleClient::new(&env, &id);

    assert_eq!(
        expiry_check(&client, &auditor, 0),
        Err(AuditError::KeyNotFound)
    );
}

#[test]
fn test_active_and_boundary_ledgers_report_grant_not_expired() {
    let (env, id, auditor) = setup();
    let client = AuditModuleClient::new(&env, &id);
    let expiration = env.ledger().sequence() + 100;
    client.generate_view_key(&auditor, &expiration);

    env.ledger().set_sequence_number(expiration - 1);
    assert_eq!(
        expiry_check(&client, &auditor, 10),
        Err(AuditError::GrantNotExpired)
    );

    // The grant is valid through its expiration ledger (inclusive).
    env.ledger().set_sequence_number(expiration);
    assert_eq!(
        expiry_check(&client, &auditor, 10),
        Err(AuditError::GrantNotExpired)
    );
}

#[test]
fn test_expired_grant_within_retention_reports_not_yet_prunable() {
    let (env, id, auditor) = setup();
    let client = AuditModuleClient::new(&env, &id);
    let expiration = env.ledger().sequence() + 100;
    let retention = 50;
    client.generate_view_key(&auditor, &expiration);

    env.ledger().set_sequence_number(expiration + 1);
    assert_eq!(
        expiry_check(&client, &auditor, retention),
        Err(AuditError::GrantNotYetPrunable)
    );

    env.ledger().set_sequence_number(expiration + retention - 1);
    assert_eq!(
        expiry_check(&client, &auditor, retention),
        Err(AuditError::GrantNotYetPrunable)
    );
}

#[test]
fn test_grant_is_prunable_exactly_at_retention_boundary() {
    let (env, id, auditor) = setup();
    let client = AuditModuleClient::new(&env, &id);
    let expiration = env.ledger().sequence() + 100;
    let retention = 50;
    client.generate_view_key(&auditor, &expiration);

    env.ledger().set_sequence_number(expiration + retention - 1);
    assert_eq!(
        expiry_check(&client, &auditor, retention),
        Err(AuditError::GrantNotYetPrunable)
    );

    env.ledger().set_sequence_number(expiration + retention);
    assert_eq!(expiry_check(&client, &auditor, retention), Ok(()));
}

#[test]
fn test_zero_retention_makes_an_expired_grant_immediately_prunable() {
    let (env, id, auditor) = setup();
    let client = AuditModuleClient::new(&env, &id);
    let expiration = env.ledger().sequence() + 100;
    client.generate_view_key(&auditor, &expiration);

    env.ledger().set_sequence_number(expiration + 1);
    assert_eq!(expiry_check(&client, &auditor, 0), Ok(()));
}

#[test]
fn test_max_expiry_retention_arithmetic_does_not_overflow() {
    let (env, id, auditor) = setup();
    let client = AuditModuleClient::new(&env, &id);
    let expiration = env.ledger().sequence() + 100;
    client.generate_view_key(&auditor, &expiration);

    // Choosing a retention that would overflow when added to the expiry must
    // saturate rather than wrap around and make a fresh grant look prunable.
    let overflowing_retention = u32::MAX - expiration + 1;
    env.ledger().set_sequence_number(expiration + 1);
    assert_eq!(
        expiry_check(&client, &auditor, overflowing_retention),
        Err(AuditError::GrantNotYetPrunable)
    );
}

#[test]
fn test_diagnostic_is_read_only_and_permissionless() {
    let (env, id, auditor) = setup();
    let client = AuditModuleClient::new(&env, &id);
    let expiration = env.ledger().sequence() + 100;
    client.generate_view_key(&auditor, &expiration);
    env.ledger().set_sequence_number(expiration + 200);

    // Drop the global auth mock: the query must still work without a signer.
    env.mock_auths(&[]);
    assert_eq!(expiry_check(&client, &auditor, 0), Ok(()));
    // A second identical query must not emit anything; DiagnosticEvent noise
    // from the auth mock reset is deliberately excluded by taking the
    // baseline after the first call.
    let before_events = env.events().all();
    assert_eq!(expiry_check(&client, &auditor, 0), Ok(()));
    assert_eq!(env.events().all(), before_events);
    assert!(client.try_get_view_key(&auditor).is_ok());
}
