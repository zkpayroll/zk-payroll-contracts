use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Env, IntoVal};

fn setup() -> (Env, Address) {
    let env = Env::default();
    env.mock_all_auths();
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

/// Acceptance Criteria: Authorization (Access Control)
/// - Attempt to call add_employee using a keypair that is not the registered HR Admin.
/// - Assert Panic.
#[test]
#[should_panic(expected = "authorized")]
fn test_authorization_add_employee_fails_for_non_admin() {
    let env = Env::default();

    // We intentionally do NOT mock_all_auths() here, because we want to test that
    // the registry correctly enforces `require_auth` dynamically against the correct admin.

    let contract_id = env.register_contract(None, PayrollRegistry);
    let registry = PayrollRegistryClient::new(&env, &contract_id);

    // Register a company with a specific admin address
    let correct_admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let company_id = registry.register_company(&correct_admin, &treasury);

    // Provide a random rogue address representing the non-registered user
    let attacker = Address::generate(&env);
    let mock_employee = Address::generate(&env);
    let fake_commitment = BytesN::from_array(&env, &[9u8; 32]);

    // The attacker tries to authorize themselves to act on the contract. Setting mock auths globally
    // to mimic the attacker signing the transaction with their *own* key.
    env.mock_auths(&[soroban_sdk::testutils::MockAuth {
        address: &attacker,
        invoke: &soroban_sdk::testutils::MockAuthInvoke {
            contract: &contract_id,
            fn_name: "add_employee",
            args: (company_id, mock_employee.clone(), fake_commitment.clone()).into_val(&env),
            sub_invokes: &[],
        },
    }]);

    // Attack: call `add_employee`. The registry calls `info.admin.require_auth()`.
    // The attacker's signature is in the auth list, but it does not match `info.admin` (which is `correct_admin`).
    // Expected: Panic from the Soroban host terminating the execution for a missing correct signature.
    registry.add_employee(&company_id, &mock_employee, &fake_commitment);
}
