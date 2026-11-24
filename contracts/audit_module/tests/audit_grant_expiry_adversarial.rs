//! Adversarial tests for auditor grant expiry and pruning (issue #973).
//!
//! Focus: a caller who can sign arbitrary transactions must never be able to
//! prune someone else's grant, prune an active grant, or use retention math to
//! turn a live grant into a prunable one. Every case also checks that a
//! rejected pruning attempt leaves the grant and its lifecycle untouched.

use audit_module::{
    AuditError, AuditLifecycleStage, AuditModule, AuditModuleClient, AuditScope,
};
use pause_manager::{PauseManager, PauseManagerClient};
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{Address, Env};

fn setup() -> (Env, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register(AuditModule, ());
    (env, id.clone(), id)
}

fn contract_error<T, E>(result: Result<T, Result<AuditError, E>>) -> AuditError {
    match result {
        Err(Ok(error)) => error,
        _ => panic!("expected a contract-level AuditError"),
    }
}

#[test]
fn test_wrong_admin_cannot_prune_another_grantors_expired_key() {
    let (env, id, admin) = setup();
    let client = AuditModuleClient::new(&env, &id);
    let auditor = Address::generate(&env);
    let attacker = Address::generate(&env);
    let expiration = env.ledger().sequence() + 100;
    client.generate_view_key(&auditor, &expiration);

    env.ledger().set_sequence_number(expiration + 200);
    assert_eq!(contract_error(client.try_prune_expired_view_key(&attacker, &auditor, &50)), AuditError::NotKeyGranter);

    // The legitimate grantor can still prune; the failed attempt changed nothing.
    assert!(client.try_get_view_key(&auditor).is_ok());
    client.prune_expired_view_key(&admin, &auditor, &50);
    assert!(client.try_get_view_key(&auditor).is_err());
}

#[test]
fn test_pruning_during_retention_leaves_key_and_lifecycle_unchanged() {
    let (env, id, admin) = setup();
    let client = AuditModuleClient::new(&env, &id);
    let auditor = Address::generate(&env);
    let expiration = env.ledger().sequence() + 100;
    let retention = 50;
    client.generate_view_key(&auditor, &expiration);
    let key_before = client.get_view_key(&auditor);

    env.ledger().set_sequence_number(expiration + retention - 1);
    assert_eq!(
        contract_error(client.try_prune_expired_view_key(&admin, &auditor, &retention)),
        AuditError::GrantNotYetPrunable
    );

    let key_after = client.get_view_key(&auditor);
    assert_eq!(key_after.key_bytes, key_before.key_bytes);
    assert_eq!(key_after.expiration_ledger, key_before.expiration_ledger);
    assert_eq!(
        client.get_audit_lifecycle_stage(&auditor),
        AuditLifecycleStage::Granted
    );
}

#[test]
fn test_refresh_inside_retention_renews_key_and_blocks_pruning() {
    let (env, id, admin) = setup();
    let client = AuditModuleClient::new(&env, &id);
    let auditor = Address::generate(&env);
    let expiration = env.ledger().sequence() + 100;
    let retention = 50;
    let old_key = client.generate_view_key(&auditor, &expiration);

    env.ledger().set_sequence_number(expiration + 1);
    assert_eq!(
        contract_error(client.try_prune_expired_view_key(&admin, &auditor, &retention)),
        AuditError::GrantNotYetPrunable
    );

    // An expired grant cannot be revived in place: refresh_view_key is
    // rejected with KeyExpired. A fresh generate_view_key is the explicit
    // revival path (#969, #970).
    let new_expiration = env.ledger().sequence() + 200;
    assert_eq!(
        contract_error(client.try_refresh_view_key(&admin, &auditor, &new_expiration)),
        AuditError::KeyExpired
    );
    assert!(!client.verify_access(&auditor));

    let new_key = client.generate_view_key(&auditor, &new_expiration);
    assert_ne!(new_key, old_key);
    assert_eq!(client.get_expiration(&auditor), new_expiration);
    assert_eq!(
        contract_error(client.try_prune_expired_view_key(&admin, &auditor, &retention)),
        AuditError::GrantNotExpired
    );
    assert!(client.verify_access(&auditor));
}

#[test]
fn test_pruning_parent_removes_all_delegate_grants() {
    let (env, id, admin) = setup();
    let client = AuditModuleClient::new(&env, &id);
    let auditor = Address::generate(&env);
    let delegate = Address::generate(&env);
    let grandchild = Address::generate(&env);
    let expiration = env.ledger().sequence() + 100;

    client.generate_view_key(&auditor, &expiration);
    client.set_delegation_policy(
        &admin,
        &auditor,
        &true,
        &AuditScope::FullCompany,
        &expiration,
    );
    client.delegate_view_key(&auditor, &delegate, &AuditScope::EmployeeList, &expiration);
    // The delegate inherits delegation rights from the parent grant, so a
    // grandchild can exist without the contract admin ever granting it one.
    client.delegate_view_key(&delegate, &grandchild, &AuditScope::EmployeeList, &expiration);

    env.ledger().set_sequence_number(expiration + 200);
    client.prune_expired_view_key(&admin, &auditor, &50);

    assert!(client.try_get_view_key(&auditor).is_err());
    assert!(client.try_get_view_key(&delegate).is_err());
    assert!(client.try_get_view_key(&grandchild).is_err());
    assert!(!client.verify_access(&delegate));
    assert_eq!(
        client.get_audit_lifecycle_stage(&auditor),
        AuditLifecycleStage::Pruned
    );
}

#[test]
fn test_pruning_one_auditor_does_not_touch_unrelated_grants() {
    let (env, id, admin) = setup();
    let client = AuditModuleClient::new(&env, &id);
    let expiring = Address::generate(&env);
    let ongoing = Address::generate(&env);
    let now = env.ledger().sequence();
    client.generate_view_key(&expiring, &(now + 100));
    client.generate_view_key(&ongoing, &(now + 1_000));

    env.ledger().set_sequence_number(now + 200);
    client.prune_expired_view_key(&admin, &expiring, &50);

    assert!(client.try_get_view_key(&expiring).is_err());
    assert!(client.try_get_view_key(&ongoing).is_ok());
    assert!(client.verify_access(&ongoing));
    assert_eq!(
        client.get_audit_lifecycle_stage(&ongoing),
        AuditLifecycleStage::Granted
    );
}

#[test]
fn test_pruning_twice_or_after_revocation_reports_key_not_found() {
    let (env, id, admin) = setup();
    let client = AuditModuleClient::new(&env, &id);
    let pruned = Address::generate(&env);
    let revoked = Address::generate(&env);
    let expiration = env.ledger().sequence() + 100;
    client.generate_view_key(&pruned, &expiration);
    client.generate_view_key(&revoked, &expiration);
    env.ledger().set_sequence_number(expiration + 200);

    client.prune_expired_view_key(&admin, &pruned, &50);
    assert_eq!(
        contract_error(client.try_prune_expired_view_key(&admin, &pruned, &50)),
        AuditError::KeyNotFound
    );

    client.revoke_view_key(&admin, &revoked);
    assert_eq!(
        contract_error(client.try_prune_expired_view_key(&admin, &revoked, &50)),
        AuditError::KeyNotFound
    );
}

#[test]
fn test_paused_contract_rejects_pruning_of_otherwise_prunable_grant() {
    let (env, id, admin) = setup();
    let client = AuditModuleClient::new(&env, &id);
    let auditor = Address::generate(&env);
    let expiration = env.ledger().sequence() + 100;
    client.generate_view_key(&auditor, &expiration);

    let pm_id = env.register(PauseManager, ());
    let pm_client = PauseManagerClient::new(&env, &pm_id);
    pm_client.initialize(&admin);
    pm_client.pause();
    client.set_pause_manager(&admin, &pm_id);

    env.ledger().set_sequence_number(expiration + 200);
    assert!(client.try_prune_expired_view_key(&admin, &auditor, &50).is_err());
    assert!(client.try_get_view_key(&auditor).is_ok());
}

#[test]
fn test_check_and_prune_agree_at_every_expiry_boundary() {
    let (env, id, admin) = setup();
    let client = AuditModuleClient::new(&env, &id);
    let auditor = Address::generate(&env);
    let expiration = env.ledger().sequence() + 100;
    let retention = 50;
    client.generate_view_key(&auditor, &expiration);

    for (ledger, expected) in [
        (expiration - 1, AuditError::GrantNotExpired),
        (expiration, AuditError::GrantNotExpired),
        (expiration + 1, AuditError::GrantNotYetPrunable),
        (expiration + retention - 1, AuditError::GrantNotYetPrunable),
    ] {
        env.ledger().set_sequence_number(ledger);
        assert_eq!(
            contract_error(client.try_check_grant_expiry(&auditor, &retention)),
            expected,
            "diagnostic disagrees at ledger {ledger}"
        );
        assert_eq!(
            contract_error(client.try_prune_expired_view_key(&admin, &auditor, &retention)),
            expected,
            "pruning disagrees at ledger {ledger}"
        );
        assert!(client.try_get_view_key(&auditor).is_ok());
    }

    env.ledger().set_sequence_number(expiration + retention);
    assert!(client.try_check_grant_expiry(&auditor, &retention).is_ok());
    client.prune_expired_view_key(&admin, &auditor, &retention);
    assert_eq!(
        client.get_audit_lifecycle_stage(&auditor),
        AuditLifecycleStage::Pruned
    );
}

#[test]
fn test_overflowing_retention_cannot_make_active_grant_prunable() {
    let (env, id, admin) = setup();
    let client = AuditModuleClient::new(&env, &id);
    let auditor = Address::generate(&env);
    let expiration = env.ledger().sequence() + 100;
    client.generate_view_key(&auditor, &expiration);

    let overflowing_retention = u32::MAX - expiration + 1;
    env.ledger().set_sequence_number(expiration + 1);
    assert_eq!(
        contract_error(client.try_prune_expired_view_key(&admin, &auditor, &overflowing_retention)),
        AuditError::GrantNotYetPrunable
    );
    assert!(client.try_get_view_key(&auditor).is_ok());
}
