use payroll_registry::{EmployeeStatus, PayrollRegistry, PayrollRegistryClient};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env};

fn setup_registry() -> (Env, PayrollRegistryClient<'static>, Address, u64, Address) {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(PayrollRegistry, ());
    let client = PayrollRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let employee = Address::generate(&env);

    let company_id = client.register_company(&admin, &treasury);
    let commitment = BytesN::from_array(&env, &[7u8; 32]);
    client.add_employee(&company_id, &employee, &commitment);

    (env, client, admin, company_id, employee)
}

#[test]
fn test_employee_status_lifecycle_transitions_and_queries() {
    let (_env, client, _admin, company_id, employee) = setup_registry();

    // Default status after registration is Active
    let initial_status = client.get_employee_status(&company_id, &employee);
    assert_eq!(initial_status, EmployeeStatus::Active);
    assert!(client.is_eligible(&company_id, &employee));

    // Suspend employee
    client.set_employee_status(&company_id, &employee, &EmployeeStatus::Suspended);
    assert_eq!(
        client.get_employee_status(&company_id, &employee),
        EmployeeStatus::Suspended
    );
    assert!(!client.is_eligible(&company_id, &employee));

    // Reactivate employee
    client.set_employee_status(&company_id, &employee, &EmployeeStatus::Active);
    assert_eq!(
        client.get_employee_status(&company_id, &employee),
        EmployeeStatus::Active
    );
    assert!(client.is_eligible(&company_id, &employee));

    // Offboard employee
    client.set_employee_status(&company_id, &employee, &EmployeeStatus::Offboarded);
    assert_eq!(
        client.get_employee_status(&company_id, &employee),
        EmployeeStatus::Offboarded
    );
    assert!(!client.is_eligible(&company_id, &employee));
}

#[test]
#[should_panic(expected = "Offboarded employee status cannot be changed")]
fn test_offboarded_employee_cannot_be_reassigned() {
    let (_env, client, _admin, company_id, employee) = setup_registry();

    client.set_employee_status(&company_id, &employee, &EmployeeStatus::Offboarded);
    // Attempting to change status of offboarded employee must panic
    client.set_employee_status(&company_id, &employee, &EmployeeStatus::Active);
}

#[test]
#[should_panic(expected = "Employee not found")]
fn test_set_status_for_unregistered_employee_fails() {
    let (env, client, _admin, company_id, _employee) = setup_registry();
    let unknown_emp = Address::generate(&env);

    client.set_employee_status(&company_id, &unknown_emp, &EmployeeStatus::Suspended);
}

#[test]
fn test_set_same_status_is_idempotent_noop() {
    let (_env, client, _admin, company_id, employee) = setup_registry();

    // Setting Active when already Active is a no-op
    client.set_employee_status(&company_id, &employee, &EmployeeStatus::Active);
    assert_eq!(
        client.get_employee_status(&company_id, &employee),
        EmployeeStatus::Active
    );
}
