//! Pause transitions while an auditor grant is active (issue #884).
//!
//! The audit module consults the pause manager for state-changing operations
//! (granting, revoking, pruning) but verifying access is a read. These tests
//! pin the resulting behavior across pause and unpause transitions:
//!
//! * an active grant keeps verifying while the system is paused,
//! * state-changing grant operations are rejected while paused and leave the
//!   grant untouched,
//! * operations resume after unpause with the grant intact,
//! * a grant that expires while paused still expires.

use audit_module::{AuditLifecycleStage, AuditModule, AuditModuleClient};
use pause_manager::{PauseManager, PauseManagerClient};
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{Address, Env};

/// Registers the audit module and a pause manager, and wires them together.
/// Returns the environment and the two contract ids; the audit module's own
/// address is its grant admin.
fn setup() -> (Env, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();

    let audit_id = env.register(AuditModule, ());
    let pm_id = env.register(PauseManager, ());

    PauseManagerClient::new(&env, &pm_id).initialize(&audit_id);
    AuditModuleClient::new(&env, &audit_id).set_pause_manager(&audit_id, &pm_id);
    (env, audit_id, pm_id)
}

#[test]
fn test_active_grant_still_verifies_while_paused() {
    let (env, audit_id, pm_id) = setup();
    let client = AuditModuleClient::new(&env, &audit_id);
    let pm_client = PauseManagerClient::new(&env, &pm_id);
    let auditor = Address::generate(&env);
    let expiration = env.ledger().sequence() + 100;
    client.generate_view_key(&auditor, &expiration);
    assert!(client.verify_access(&auditor));

    pm_client.pause();

    // Verification is read-only and is not blocked by a pause.
    assert!(pm_client.is_paused());
    assert!(client.verify_access(&auditor));
    assert_eq!(
        client.get_audit_lifecycle_stage(&auditor),
        AuditLifecycleStage::Granted
    );
}

#[test]
fn test_paused_system_rejects_revoking_an_active_grant_and_leaves_it_intact() {
    let (env, audit_id, pm_id) = setup();
    let client = AuditModuleClient::new(&env, &audit_id);
    let pm_client = PauseManagerClient::new(&env, &pm_id);
    let admin = audit_id.clone();
    let auditor = Address::generate(&env);
    let expiration = env.ledger().sequence() + 100;
    client.generate_view_key(&auditor, &expiration);

    pm_client.pause();

    assert!(client.try_revoke_view_key(&admin, &auditor).is_err());
    assert!(client.verify_access(&auditor));
    assert_eq!(client.get_expiration(&auditor), expiration);
    assert_eq!(
        client.get_audit_lifecycle_stage(&auditor),
        AuditLifecycleStage::Granted
    );
}

#[test]
fn test_paused_system_rejects_granting_a_new_key() {
    let (env, audit_id, pm_id) = setup();
    let client = AuditModuleClient::new(&env, &audit_id);
    let pm_client = PauseManagerClient::new(&env, &pm_id);
    let existing = Address::generate(&env);
    let newcomer = Address::generate(&env);
    let expiration = env.ledger().sequence() + 100;
    client.generate_view_key(&existing, &expiration);

    pm_client.pause();

    assert!(client
        .try_generate_view_key(&newcomer, &(expiration + 10))
        .is_err());
    assert!(!client.verify_access(&newcomer));
    // The existing grant is unaffected by the rejected request.
    assert!(client.verify_access(&existing));
}

#[test]
fn test_revoking_works_again_after_unpause_and_grant_survived_the_pause() {
    let (env, audit_id, pm_id) = setup();
    let client = AuditModuleClient::new(&env, &audit_id);
    let pm_client = PauseManagerClient::new(&env, &pm_id);
    let admin = audit_id.clone();
    let auditor = Address::generate(&env);
    let expiration = env.ledger().sequence() + 100;
    client.generate_view_key(&auditor, &expiration);

    pm_client.pause();
    assert!(client.try_revoke_view_key(&admin, &auditor).is_err());
    pm_client.unpause();

    // The grant came through the pause unchanged...
    assert!(client.verify_access(&auditor));
    assert_eq!(client.get_expiration(&auditor), expiration);

    // ...and can now be revoked.
    assert!(client.try_revoke_view_key(&admin, &auditor).is_ok());
    assert!(!client.verify_access(&auditor));
}

#[test]
fn test_repeated_pause_cycles_do_not_extend_or_shorten_a_grant() {
    let (env, audit_id, pm_id) = setup();
    let client = AuditModuleClient::new(&env, &audit_id);
    let pm_client = PauseManagerClient::new(&env, &pm_id);
    let auditor = Address::generate(&env);
    let expiration = env.ledger().sequence() + 100;
    client.generate_view_key(&auditor, &expiration);

    for _ in 0..3 {
        pm_client.pause();
        pm_client.unpause();
    }

    assert!(client.verify_access(&auditor));
    assert_eq!(client.get_expiration(&auditor), expiration);
}

#[test]
fn test_grant_that_expires_while_paused_stops_verifying_at_the_boundary() {
    let (env, audit_id, pm_id) = setup();
    let client = AuditModuleClient::new(&env, &audit_id);
    let pm_client = PauseManagerClient::new(&env, &pm_id);
    let auditor = Address::generate(&env);
    let expiration = env.ledger().sequence() + 100;
    client.generate_view_key(&auditor, &expiration);

    pm_client.pause();

    // A grant is valid while `sequence <= expiration_ledger`.
    env.ledger().set_sequence_number(expiration);
    assert!(client.verify_access(&auditor));

    env.ledger().set_sequence_number(expiration + 1);
    assert!(!client.verify_access(&auditor));

    // Unpausing does not resurrect an expired grant.
    pm_client.unpause();
    assert!(!client.verify_access(&auditor));
}
