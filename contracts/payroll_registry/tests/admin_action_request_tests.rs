//! Issue #554: administrative action request identifier tests.
//!
//! Request identifiers make admin actions idempotent: identical resubmissions
//! are no-ops, identifiers reused for a different action are rejected, and
//! every processed identifier leaves a queryable audit record.

use payroll_registry::{
    AdminActionRequest, PayrollRegistryClient, ADMIN_ACTION_ACCEPT_ADMIN,
    ADMIN_ACTION_PROPOSE_ADMIN, ADMIN_ACTION_PROPOSE_TREASURY, ADMIN_ACTION_SET_PAUSE_MANAGER,
};
use soroban_sdk::testutils::{Address as _, Events as _};
use soroban_sdk::{Address, Env};

fn event_count(env: &Env, contract_id: &Address) -> usize {
    env.events()
        .all()
        .filter_by_contract(contract_id)
        .events()
        .len()
}

/// Consume the event buffer with a read-only call so the next count only
/// reflects events emitted after it.
fn drain_events(client: &PayrollRegistryClient, company_id: u64, admin: &Address) {
    let _ = client.get_employee_status(&company_id, admin);
}

#[test]
fn propose_admin_with_request_id_records_audit_entry() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(payroll_registry::PayrollRegistry, ());
    let client = PayrollRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let new_admin = Address::generate(&env);
    let company_id = client.register_company(&admin, &treasury);

    let request_id = soroban_sdk::BytesN::from_array(&env, &[1u8; 32]);
    drain_events(&client, company_id, &admin);
    client.propose_admin_with_request(&company_id, &admin, &new_admin, &request_id);
    assert_eq!(event_count(&env, &contract_id), 1);

    let record: AdminActionRequest = client
        .get_admin_action_request(&request_id)
        .expect("request record should exist");
    assert_eq!(record.action, ADMIN_ACTION_PROPOSE_ADMIN);
    assert_eq!(record.company_id, company_id);
    assert_eq!(record.actor, admin);
    assert_eq!(record.target, new_admin);
    assert_eq!(record.executed_at, env.ledger().timestamp());
}

#[test]
fn duplicate_request_id_with_identical_params_is_noop() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(payroll_registry::PayrollRegistry, ());
    let client = PayrollRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let new_admin = Address::generate(&env);
    let company_id = client.register_company(&admin, &treasury);

    let request_id = soroban_sdk::BytesN::from_array(&env, &[2u8; 32]);
    client.propose_admin_with_request(&company_id, &admin, &new_admin, &request_id);

    // Identical resubmission: no event, no state change (and in particular
    // no "pending rotation already exists" failure from the delegated call).
    drain_events(&client, company_id, &admin);
    client.propose_admin_with_request(&company_id, &admin, &new_admin, &request_id);
    assert_eq!(event_count(&env, &contract_id), 0);

    assert!(client.get_admin_action_request(&request_id).is_some());
    assert!(client.get_pending_admin_rotation(&company_id).is_some());
}

#[test]
#[should_panic(expected = "Admin action request identifier already used")]
fn request_id_reuse_for_different_action_panics() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(payroll_registry::PayrollRegistry, ());
    let client = PayrollRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let new_admin = Address::generate(&env);
    let company_id = client.register_company(&admin, &treasury);

    let request_id = soroban_sdk::BytesN::from_array(&env, &[3u8; 32]);
    client.propose_admin_with_request(&company_id, &admin, &new_admin, &request_id);
    // Same identifier, different action kind.
    client.propose_treasury_with_request(&company_id, &admin, &treasury, &request_id);
}

#[test]
#[should_panic(expected = "Admin action request identifier already used")]
fn request_id_reuse_with_different_target_panics() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(payroll_registry::PayrollRegistry, ());
    let client = PayrollRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let new_admin_a = Address::generate(&env);
    let new_admin_b = Address::generate(&env);
    let company_id = client.register_company(&admin, &treasury);

    let request_id = soroban_sdk::BytesN::from_array(&env, &[4u8; 32]);
    client.propose_admin_with_request(&company_id, &admin, &new_admin_a, &request_id);
    // Same identifier and action, but a different target.
    client.propose_admin_with_request(&company_id, &admin, &new_admin_b, &request_id);
}

#[test]
fn unknown_request_id_returns_none() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(payroll_registry::PayrollRegistry, ());
    let client = PayrollRegistryClient::new(&env, &contract_id);

    let request_id = soroban_sdk::BytesN::from_array(&env, &[5u8; 32]);
    assert!(client.get_admin_action_request(&request_id).is_none());
}

#[test]
fn accept_admin_with_request_id_rotates_admin() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(payroll_registry::PayrollRegistry, ());
    let client = PayrollRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let new_admin = Address::generate(&env);
    let company_id = client.register_company(&admin, &treasury);

    client.propose_admin_rotation(&company_id, &admin, &new_admin);

    let request_id = soroban_sdk::BytesN::from_array(&env, &[6u8; 32]);
    client.accept_admin_with_request(&company_id, &new_admin, &request_id);

    assert_eq!(client.get_company(&company_id).admin, new_admin);
    let record: AdminActionRequest = client.get_admin_action_request(&request_id).unwrap();
    assert_eq!(record.action, ADMIN_ACTION_ACCEPT_ADMIN);
    assert_eq!(record.actor, new_admin);
    assert_eq!(record.target, new_admin);
}

#[test]
fn propose_treasury_with_request_id_records_audit_entry() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(payroll_registry::PayrollRegistry, ());
    let client = PayrollRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let new_treasury = Address::generate(&env);
    let company_id = client.register_company(&admin, &treasury);

    let request_id = soroban_sdk::BytesN::from_array(&env, &[7u8; 32]);
    client.propose_treasury_with_request(&company_id, &admin, &new_treasury, &request_id);

    let record: AdminActionRequest = client.get_admin_action_request(&request_id).unwrap();
    assert_eq!(record.action, ADMIN_ACTION_PROPOSE_TREASURY);
    assert_eq!(record.target, new_treasury);
    assert!(client.get_pending_treasury_rotation(&company_id).is_some());
}

#[test]
fn set_pause_manager_with_request_is_idempotent() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(payroll_registry::PayrollRegistry, ());
    let client = PayrollRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let pause_manager = Address::generate(&env);

    let request_id = soroban_sdk::BytesN::from_array(&env, &[8u8; 32]);
    client.set_pause_manager_with_request(&admin, &pause_manager, &request_id);

    let record: AdminActionRequest = client.get_admin_action_request(&request_id).unwrap();
    assert_eq!(record.action, ADMIN_ACTION_SET_PAUSE_MANAGER);
    assert_eq!(record.company_id, 0);

    drain_events(&client, 0, &admin);
    client.set_pause_manager_with_request(&admin, &pause_manager, &request_id);
    assert_eq!(event_count(&env, &contract_id), 0);
}
