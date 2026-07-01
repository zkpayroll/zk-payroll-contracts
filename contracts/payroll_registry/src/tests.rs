use super::*;
use soroban_sdk::testutils::{Address as _, Events};
use soroban_sdk::{Env, IntoVal, Symbol, TryIntoVal};

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
    env.mock_auths(&[soroban_sdk::testutils::MockAuth {
        address: &correct_admin,
        invoke: &soroban_sdk::testutils::MockAuthInvoke {
            contract: &contract_id,
            fn_name: "register_company",
            args: (correct_admin.clone(), treasury.clone()).into_val(&env),
            sub_invokes: &[],
        },
    }]);
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

#[test]
fn test_get_company_returns_company_info() {
    let (env, contract_id) = setup();
    let client = PayrollRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);

    let company_id = client.register_company(&admin, &treasury);
    let company = client.get_company(&company_id);

    assert_eq!(company.admin, admin);
    assert_eq!(company.treasury, treasury);
}

#[test]
fn test_get_commitment_returns_employee_commitment() {
    let (env, contract_id) = setup();
    let client = PayrollRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let employee = Address::generate(&env);
    let commitment = BytesN::from_array(&env, &[7u8; 32]);

    let company_id = client.register_company(&admin, &treasury);
    client.add_employee(&company_id, &employee, &commitment);

    let got = client.get_commitment(&company_id, &employee);
    assert_eq!(got, commitment);
}

// ── Issue #90: employee eligibility ──────────────────────────────────────────

#[test]
fn test_add_employee_sets_active_status() {
// ---------------------------------------------------------------------------
// Event emission tests
// ---------------------------------------------------------------------------

#[test]
fn test_register_company_emits_event() {
    let (env, contract_id) = setup();
    let client = PayrollRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let employee = Address::generate(&env);
    let commitment = BytesN::from_array(&env, &[1u8; 32]);

    let company_id = client.register_company(&admin, &treasury);
    client.add_employee(&company_id, &employee, &commitment);

    assert_eq!(
        client.get_employee_status(&company_id, &employee),
        EmployeeStatus::Active,
    );
    assert!(client.is_eligible(&company_id, &employee));
}

#[test]
fn test_set_employee_status_inactive_makes_ineligible() {

    let before = env.events().all().len();
    let company_id = client.register_company(&admin, &treasury);
    let after = env.events().all().len();
    assert_eq!(after, before + 1);

    let event = env.events().all().get(after - 1).unwrap();
    assert_eq!(event.1.len(), 2);
    let sym0: Symbol = event.1.get(0).unwrap().try_into_val(&env.clone()).unwrap();
    assert_eq!(sym0, Symbol::new(&env, "CompanyRegistered"));
    let comp_id: u64 = event.1.get(1).unwrap().try_into_val(&env.clone()).unwrap();
    assert_eq!(comp_id, company_id);
}

#[test]
fn test_add_employee_emits_event() {
    let (env, contract_id) = setup();
    let client = PayrollRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let employee = Address::generate(&env);
    let commitment = BytesN::from_array(&env, &[2u8; 32]);

    let company_id = client.register_company(&admin, &treasury);
    client.add_employee(&company_id, &employee, &commitment);

    client.set_employee_status(&company_id, &employee, &EmployeeStatus::Inactive);

    assert_eq!(
        client.get_employee_status(&company_id, &employee),
        EmployeeStatus::Inactive,
    );
    assert!(!client.is_eligible(&company_id, &employee));
}

#[test]
fn test_set_employee_status_incomplete_makes_ineligible() {
    let commitment = BytesN::from_array(&env, &[1u8; 32]);

    let company_id = client.register_company(&admin, &treasury);
    let before = env.events().all().len();
    client.add_employee(&company_id, &employee, &commitment);
    let after = env.events().all().len();
    assert_eq!(after, before + 1);

    let event = env.events().all().get(after - 1).unwrap();
    assert_eq!(event.1.len(), 3);
    let sym0: Symbol = event.1.get(0).unwrap().try_into_val(&env.clone()).unwrap();
    assert_eq!(sym0, Symbol::new(&env, "EmployeeAdded"));
    let comp_id: u64 = event.1.get(1).unwrap().try_into_val(&env.clone()).unwrap();
    assert_eq!(comp_id, company_id);
    let emp_addr: Address = event.1.get(2).unwrap().try_into_val(&env.clone()).unwrap();
    assert_eq!(emp_addr, employee);
}

#[test]
fn test_remove_employee_emits_event() {
    let (env, contract_id) = setup();
    let client = PayrollRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let employee = Address::generate(&env);
    let commitment = BytesN::from_array(&env, &[3u8; 32]);

    let company_id = client.register_company(&admin, &treasury);
    client.add_employee(&company_id, &employee, &commitment);

    client.set_employee_status(&company_id, &employee, &EmployeeStatus::Incomplete);

    assert!(!client.is_eligible(&company_id, &employee));
}

#[test]
fn test_unregistered_employee_is_not_eligible() {
    let (env, contract_id) = setup();
    let client = PayrollRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);

    let company_id = client.register_company(&admin, &treasury);
    let stranger = Address::generate(&env);

    assert!(!client.is_eligible(&company_id, &stranger));
}

#[test]
fn test_reactivating_inactive_employee_restores_eligibility() {
    let commitment = BytesN::from_array(&env, &[2u8; 32]);

    let company_id = client.register_company(&admin, &treasury);
    client.add_employee(&company_id, &employee, &commitment);
    let before = env.events().all().len();
    client.remove_employee(&company_id, &employee);
    let after = env.events().all().len();
    assert_eq!(after, before + 1);

    let event = env.events().all().get(after - 1).unwrap();
    assert_eq!(event.1.len(), 3);
    let sym0: Symbol = event.1.get(0).unwrap().try_into_val(&env.clone()).unwrap();
    assert_eq!(sym0, Symbol::new(&env, "EmployeeRemoved"));
    let comp_id: u64 = event.1.get(1).unwrap().try_into_val(&env.clone()).unwrap();
    assert_eq!(comp_id, company_id);
    let emp_addr: Address = event.1.get(2).unwrap().try_into_val(&env.clone()).unwrap();
    assert_eq!(emp_addr, employee);
}

#[test]
fn test_update_commitment_emits_event() {
    let (env, contract_id) = setup();
    let client = PayrollRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let employee = Address::generate(&env);
    let commitment = BytesN::from_array(&env, &[4u8; 32]);

    let company_id = client.register_company(&admin, &treasury);
    client.add_employee(&company_id, &employee, &commitment);
    client.set_employee_status(&company_id, &employee, &EmployeeStatus::Inactive);
    assert!(!client.is_eligible(&company_id, &employee));

    client.set_employee_status(&company_id, &employee, &EmployeeStatus::Active);
    assert!(client.is_eligible(&company_id, &employee));
}

// ── Issue #91: company admin/treasury rotation ────────────────────────────────

#[test]
fn test_admin_rotation_full_flow() {
    let (env, contract_id) = setup();
    let client = PayrollRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);

    let company_id = client.register_company(&admin, &treasury);
    let new_admin = Address::generate(&env);

    client.propose_admin_rotation(&company_id, &admin, &new_admin);
    client.accept_admin_rotation(&company_id, &new_admin);

    let info = client.get_company(&company_id);
    assert_eq!(info.admin, new_admin);
}

#[test]
#[should_panic(expected = "Unauthorized: caller is not the company admin")]
fn test_propose_admin_rotation_rejects_non_admin() {
    let (env, contract_id) = setup();
    let client = PayrollRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);

    let company_id = client.register_company(&admin, &treasury);
    let attacker = Address::generate(&env);
    let new_admin = Address::generate(&env);

    client.propose_admin_rotation(&company_id, &attacker, &new_admin);
}

#[test]
#[should_panic(expected = "Unauthorized: caller is not the proposed admin")]
fn test_accept_admin_rotation_rejects_wrong_address() {
    let (env, contract_id) = setup();
    let client = PayrollRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);

    let company_id = client.register_company(&admin, &treasury);
    let new_admin = Address::generate(&env);
    let impostor = Address::generate(&env);

    client.propose_admin_rotation(&company_id, &admin, &new_admin);
    client.accept_admin_rotation(&company_id, &impostor);
}

#[test]
fn test_cancel_admin_rotation_clears_proposal() {
    let (env, contract_id) = setup();
    let client = PayrollRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);

    let company_id = client.register_company(&admin, &treasury);
    let new_admin = Address::generate(&env);

    client.propose_admin_rotation(&company_id, &admin, &new_admin);
    client.cancel_admin_rotation(&company_id, &admin);

    // Admin should remain unchanged
    let info = client.get_company(&company_id);
    assert_eq!(info.admin, admin);
}

#[test]
fn test_treasury_rotation_full_flow() {
    let (env, contract_id) = setup();
    let client = PayrollRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);

    let company_id = client.register_company(&admin, &treasury);
    let new_treasury = Address::generate(&env);

    client.propose_treasury_rotation(&company_id, &admin, &new_treasury);
    client.accept_treasury_rotation(&company_id, &new_treasury);

    let info = client.get_company(&company_id);
    assert_eq!(info.treasury, new_treasury);
}

#[test]
#[should_panic(expected = "A pending admin rotation already exists for this company")]
fn test_duplicate_admin_rotation_proposal_rejected() {
    let (env, contract_id) = setup();
    let client = PayrollRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);

    let company_id = client.register_company(&admin, &treasury);
    let new_admin = Address::generate(&env);

    client.propose_admin_rotation(&company_id, &admin, &new_admin);
    client.propose_admin_rotation(&company_id, &admin, &new_admin);
    let old_commitment = BytesN::from_array(&env, &[1u8; 32]);
    let new_commitment = BytesN::from_array(&env, &[9u8; 32]);

    let company_id = client.register_company(&admin, &treasury);
    client.add_employee(&company_id, &employee, &old_commitment);
    let before = env.events().all().len();
    client.update_commitment(&company_id, &employee, &new_commitment);
    let after = env.events().all().len();
    assert_eq!(after, before + 1);

    let event = env.events().all().get(after - 1).unwrap();
    assert_eq!(event.1.len(), 3);
    let sym0: Symbol = event.1.get(0).unwrap().try_into_val(&env.clone()).unwrap();
    assert_eq!(sym0, Symbol::new(&env, "CommitmentUpdated"));
    let comp_id: u64 = event.1.get(1).unwrap().try_into_val(&env.clone()).unwrap();
    assert_eq!(comp_id, company_id);
    let emp_addr: Address = event.1.get(2).unwrap().try_into_val(&env.clone()).unwrap();
    assert_eq!(emp_addr, employee);
}
