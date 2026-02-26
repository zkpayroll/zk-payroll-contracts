use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::Env;

fn setup() -> (Env, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, PayrollRegistry);
    (env, contract_id)
}

fn setup_no_auth_mock() -> (Env, Address) {
    let env = Env::default();
    let contract_id = env.register_contract(None, PayrollRegistry);
    (env, contract_id)
}

#[test]
fn test_register_company_returns_sequential_ids() {
    let (env, contract_id) = setup();
    let client = PayrollRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);

    let id0 = client.register_company(&admin, &treasury);
    let id1 = client.register_company(&admin, &treasury);

    assert_eq!(id0, 0u64);
    assert_eq!(id1, 1u64);
}

#[test]
fn test_register_company_requires_admin_auth() {
    let (env, contract_id) = setup_no_auth_mock();
    let client = PayrollRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);

    let result = client.try_register_company(&admin, &treasury);
    assert!(result.is_err());
}

#[test]
fn test_register_company_updates_company_sequence() {
    let (env, contract_id) = setup();
    let client = PayrollRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);

    client.register_company(&admin, &treasury);
    client.register_company(&admin, &treasury);

    let seq: u64 = env.as_contract(&contract_id, || {
        env.storage()
            .persistent()
            .get(&DataKey::CompanySequence)
            .expect("company sequence should be stored")
    });
    assert_eq!(seq, 2u64);
}

#[test]
fn test_add_employee_stores_commitment() {
    let (env, contract_id) = setup();
    let client = PayrollRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let employee = Address::generate(&env);
    let commitment = BytesN::from_array(&env, &[1u8; 32]);

    let company_id = client.register_company(&admin, &treasury);
    client.add_employee(&company_id, &employee, &commitment);

    let stored: BytesN<32> = env.as_contract(&contract_id, || {
        env.storage()
            .persistent()
            .get(&DataKey::Employee(company_id, employee))
            .expect("employee commitment should be stored")
    });
    assert_eq!(stored, commitment);
}

#[test]
fn test_remove_employee_hard_deletes() {
    let (env, contract_id) = setup();
    let client = PayrollRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let employee = Address::generate(&env);
    let commitment = BytesN::from_array(&env, &[2u8; 32]);

    let company_id = client.register_company(&admin, &treasury);
    client.add_employee(&company_id, &employee, &commitment);
    client.remove_employee(&company_id, &employee);

    let new_commitment = BytesN::from_array(&env, &[3u8; 32]);
    let result = client.try_update_commitment(&company_id, &employee, &new_commitment);
    assert!(result.is_err());
}

#[test]
fn test_update_commitment_replaces_value() {
    let (env, contract_id) = setup();
    let client = PayrollRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let employee = Address::generate(&env);
    let old_commitment = BytesN::from_array(&env, &[1u8; 32]);
    let new_commitment = BytesN::from_array(&env, &[9u8; 32]);

    let company_id = client.register_company(&admin, &treasury);
    client.add_employee(&company_id, &employee, &old_commitment);
    client.update_commitment(&company_id, &employee, &new_commitment);

    let stored: BytesN<32> = env.as_contract(&contract_id, || {
        env.storage()
            .persistent()
            .get(&DataKey::Employee(company_id, employee))
            .expect("employee commitment should be updated")
    });
    assert_eq!(stored, new_commitment);
}

#[test]
fn test_add_employee_unknown_company_panics() {
    let (env, contract_id) = setup();
    let client = PayrollRegistryClient::new(&env, &contract_id);
    let employee = Address::generate(&env);
    let commitment = BytesN::from_array(&env, &[0u8; 32]);

    let result = client.try_add_employee(&99u64, &employee, &commitment);
    assert!(result.is_err());
}

#[test]
fn test_register_company_stores_company_info() {
    let (env, contract_id) = setup();
    let client = PayrollRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);

    let company_id = client.register_company(&admin, &treasury);

    let stored: CompanyInfo = env.as_contract(&contract_id, || {
        env.storage()
            .persistent()
            .get(&DataKey::Company(company_id))
            .expect("company info should be stored")
    });
    assert_eq!(stored.admin, admin);
    assert_eq!(stored.treasury, treasury);
}
