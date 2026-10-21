use payroll_registry::PayrollRegistryClient;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env};

#[test]
fn test_admin_config_version_initialized_on_registration() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(payroll_registry::PayrollRegistry, ());
    let client = PayrollRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);

    let company_id = client.register_company(&admin, &treasury);

    let version = client.get_admin_config_version(&company_id);
    assert!(version.is_some());
    let version_info = version.unwrap();
    assert_eq!(version_info.version, 1);
    assert_eq!(version_info.updated_by, admin);
}

#[test]
fn test_admin_config_version_increments_on_admin_rotation() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(payroll_registry::PayrollRegistry, ());
    let client = PayrollRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);

    let company_id = client.register_company(&admin, &treasury);

    let initial_version = client.get_admin_config_version(&company_id).unwrap();
    assert_eq!(initial_version.version, 1);

    let new_admin = Address::generate(&env);
    client.propose_admin_rotation(&company_id, &admin, &new_admin);
    client.accept_admin_rotation(&company_id, &new_admin);

    let updated_version = client.get_admin_config_version(&company_id).unwrap();
    assert_eq!(updated_version.version, 2);
    assert_eq!(updated_version.updated_by, new_admin);
}

#[test]
fn test_admin_config_version_increments_on_treasury_rotation() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(payroll_registry::PayrollRegistry, ());
    let client = PayrollRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);

    let company_id = client.register_company(&admin, &treasury);

    let initial_version = client.get_admin_config_version(&company_id).unwrap();
    assert_eq!(initial_version.version, 1);

    let new_treasury = Address::generate(&env);
    client.propose_treasury_rotation(&company_id, &admin, &new_treasury);
    client.accept_treasury_rotation(&company_id, &new_treasury);

    let updated_version = client.get_admin_config_version(&company_id).unwrap();
    assert_eq!(updated_version.version, 2);
    assert_eq!(updated_version.updated_by, new_treasury);
}

#[test]
fn test_admin_config_version_multiple_rotations() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(payroll_registry::PayrollRegistry, ());
    let client = PayrollRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);

    let company_id = client.register_company(&admin, &treasury);

    let mut version = client.get_admin_config_version(&company_id).unwrap();
    assert_eq!(version.version, 1);

    // First admin rotation
    let new_admin = Address::generate(&env);
    client.propose_admin_rotation(&company_id, &admin, &new_admin);
    client.accept_admin_rotation(&company_id, &new_admin);
    version = client.get_admin_config_version(&company_id).unwrap();
    assert_eq!(version.version, 2);

    // Treasury rotation
    let new_treasury = Address::generate(&env);
    client.propose_treasury_rotation(&company_id, &new_admin, &new_treasury);
    client.accept_treasury_rotation(&company_id, &new_treasury);
    version = client.get_admin_config_version(&company_id).unwrap();
    assert_eq!(version.version, 3);

    // Second admin rotation
    let newer_admin = Address::generate(&env);
    client.propose_admin_rotation(&company_id, &new_admin, &newer_admin);
    client.accept_admin_rotation(&company_id, &newer_admin);
    version = client.get_admin_config_version(&company_id).unwrap();
    assert_eq!(version.version, 4);
}

#[test]
fn test_admin_config_version_none_for_nonexistent_company() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(payroll_registry::PayrollRegistry, ());
    let client = PayrollRegistryClient::new(&env, &contract_id);

    let version = client.get_admin_config_version(&999);
    assert!(version.is_none());
}

// ── Issue #645: company configuration revision tracking ────────────────────

#[test]
fn test_admin_config_version_increments_on_company_revocation() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(payroll_registry::PayrollRegistry, ());
    let client = PayrollRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);

    let company_id = client.register_company(&admin, &treasury);

    let initial_version = client.get_admin_config_version(&company_id).unwrap();
    assert_eq!(initial_version.version, 1);
    assert_eq!(initial_version.updated_by, admin);

    // Revoking the company admin is a company configuration change.
    client.revoke_company_admin(&company_id, &admin);

    let updated_version = client.get_admin_config_version(&company_id).unwrap();
    assert_eq!(updated_version.version, 2);
    assert_eq!(updated_version.updated_by, admin);
}

#[test]
fn test_unauthorized_revocation_is_rejected_without_version_bump() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(payroll_registry::PayrollRegistry, ());
    let client = PayrollRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let stranger = Address::generate(&env);

    let company_id = client.register_company(&admin, &treasury);

    let before = client.get_admin_config_version(&company_id).unwrap();
    assert_eq!(before.version, 1);

    // A non-admin cannot revoke the company admin.
    let result = client.try_revoke_company_admin(&company_id, &stranger);
    assert!(result.is_err(), "stranger revocation must be rejected");

    // The revision must be unchanged by the failed attempt.
    let after = client.get_admin_config_version(&company_id).unwrap();
    assert_eq!(after.version, before.version);
    assert_eq!(after.updated_by, before.updated_by);
}

#[test]
fn test_double_revocation_is_rejected() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(payroll_registry::PayrollRegistry, ());
    let client = PayrollRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);

    let company_id = client.register_company(&admin, &treasury);

    // First revocation succeeds and bumps the revision.
    client.revoke_company_admin(&company_id, &admin);
    let first = client.get_admin_config_version(&company_id).unwrap();
    assert_eq!(first.version, 2);

    // A second revocation of an already-revoked admin is rejected.
    let result = client.try_revoke_company_admin(&company_id, &admin);
    assert!(
        result.is_err(),
        "double revocation of an already-revoked admin must be rejected"
    );

    // The revision must be unchanged by the failed attempt.
    let second = client.get_admin_config_version(&company_id).unwrap();
    assert_eq!(second.version, first.version);
}
