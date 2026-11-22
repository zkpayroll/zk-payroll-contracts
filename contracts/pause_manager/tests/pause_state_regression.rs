//! Regression tests for administrative pause state (issue #994).
//!
//! These lock in the observable invariants of the pause manager: flag
//! isolation, global override semantics, idempotent transitions, and safe
//! defaults before initialization. No employee or salary data is involved.

mod common;

use common::{initialized, uninitialized};
use pause_manager::{PauseCategory, PauseManagerClient};
use soroban_sdk::testutils::Address as _;

#[test]
fn test_initialization_sets_operator_and_all_flags_unpaused() {
    let (env, id, operator) = initialized();
    let client = PauseManagerClient::new(&env, &id);

    assert_eq!(client.get_operator(), operator);
    let status = client.get_pause_status();
    assert!(!status.payroll_paused);
    assert!(!status.treasury_paused);
    assert!(!status.audit_paused);
    assert!(!status.admin_paused);
    assert!(!client.is_paused());
    assert!(client.get_pending_operator_rotation().is_none());
}

#[test]
fn test_all_categories_paused_individually_then_global_unpause_clears_every_flag() {
    let (env, id, _operator) = initialized();
    let client = PauseManagerClient::new(&env, &id);

    client.pause_category(&PauseCategory::Payroll);
    client.pause_category(&PauseCategory::Treasury);
    client.pause_category(&PauseCategory::Audit);
    client.pause_category(&PauseCategory::Admin);
    assert!(client.is_paused());

    client.unpause();
    let status = client.get_pause_status();
    assert!(!status.payroll_paused);
    assert!(!status.treasury_paused);
    assert!(!status.audit_paused);
    assert!(!status.admin_paused);
    assert!(!client.is_paused());
}

#[test]
fn test_unpausing_one_category_keeps_global_pause_while_others_remain_paused() {
    let (env, id, _operator) = initialized();
    let client = PauseManagerClient::new(&env, &id);

    client.pause();
    client.unpause_category(&PauseCategory::Payroll);

    let status = client.get_pause_status();
    assert!(!status.payroll_paused);
    assert!(status.treasury_paused);
    assert!(status.audit_paused);
    assert!(status.admin_paused);
    assert!(client.is_paused());
}

#[test]
fn test_repeated_global_and_category_cycles_leave_no_stale_flags() {
    let (env, id, _operator) = initialized();
    let client = PauseManagerClient::new(&env, &id);

    for _ in 0..3 {
        client.pause();
        client.pause();
        assert!(client.is_paused());
        client.unpause();
        client.unpause();
        assert!(!client.is_paused());
    }

    for category in [
        PauseCategory::Payroll,
        PauseCategory::Treasury,
        PauseCategory::Audit,
        PauseCategory::Admin,
    ] {
        client.pause_category(&category);
        client.pause_category(&category);
        assert!(client.is_category_paused(&category));
        client.unpause_category(&category);
        client.unpause_category(&category);
        assert!(!client.is_category_paused(&category));
    }

    assert!(!client.is_paused());
}

#[test]
fn test_rotation_preserves_mixed_pause_state() {
    let (env, id, operator) = initialized();
    let client = PauseManagerClient::new(&env, &id);
    let new_operator = soroban_sdk::Address::generate(&env);

    client.pause_category(&PauseCategory::Treasury);
    client.pause_category(&PauseCategory::Audit);
    client.propose_operator_rotation(&operator, &new_operator);
    client.accept_operator_rotation(&new_operator);

    let status = client.get_pause_status();
    assert!(!status.payroll_paused);
    assert!(status.treasury_paused);
    assert!(status.audit_paused);
    assert!(!status.admin_paused);
    assert_eq!(client.get_operator(), new_operator);
}

#[test]
fn test_pending_rotation_survives_pause_and_unpause_cycles() {
    let (env, id, operator) = initialized();
    let client = PauseManagerClient::new(&env, &id);
    let new_operator = soroban_sdk::Address::generate(&env);

    client.propose_operator_rotation(&operator, &new_operator);
    client.pause();
    client.unpause();

    let proposal = client
        .get_pending_operator_rotation()
        .expect("rotation must remain pending");
    assert_eq!(proposal.new_operator, new_operator);
    assert_eq!(proposal.proposed_by, operator);
    assert_eq!(client.get_operator(), operator);
}

#[test]
fn test_uninitialized_reads_are_safe_defaults() {
    let (env, id) = uninitialized();
    let client = PauseManagerClient::new(&env, &id);

    assert!(!client.is_paused());
    assert!(!client.is_category_paused(&PauseCategory::Admin));
    assert!(client.get_pending_operator_rotation().is_none());
    let status = client.get_pause_status();
    assert!(!status.payroll_paused);
    assert!(!status.treasury_paused);
    assert!(!status.audit_paused);
    assert!(!status.admin_paused);
}
