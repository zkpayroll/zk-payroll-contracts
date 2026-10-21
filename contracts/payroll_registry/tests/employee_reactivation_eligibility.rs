use payroll_registry::{EmployeeStatus, PayrollRegistry, PayrollRegistryClient};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env};

fn setup() -> (Env, PayrollRegistryClient<'static>, u64, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(PayrollRegistry, ());
    let client = PayrollRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let company_id = client.register_company(&admin, &treasury);
    let employee = Address::generate(&env);
    let commitment = BytesN::from_array(&env, &[42; 32]);
    client.add_employee(&company_id, &employee, &commitment);
    (env, client, company_id, employee)
}

#[test]
fn suspended_employee_with_commitment_can_be_reactivated() {
    let (_env, client, company_id, employee) = setup();
    client.set_employee_status(&company_id, &employee, &EmployeeStatus::Suspended);

    assert!(client.is_reactivation_eligible(&company_id, &employee));
}

#[test]
fn active_and_offboarded_employees_cannot_be_reactivated() {
    let (_env, client, company_id, employee) = setup();
    assert!(!client.is_reactivation_eligible(&company_id, &employee));

    client.set_employee_status(&company_id, &employee, &EmployeeStatus::Offboarded);
    assert!(!client.is_reactivation_eligible(&company_id, &employee));
}

#[test]
fn missing_employee_is_not_reactivation_eligible() {
    let (env, client, company_id, _employee) = setup();
    let missing = Address::generate(&env);

    assert!(!client.is_reactivation_eligible(&company_id, &missing));
}
