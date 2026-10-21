use payroll::{Payroll, PayrollClient};
use payroll_registry::{EmployeeStatus, PayrollRegistry, PayrollRegistryClient};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, Vec};

fn setup(
    env: &Env,
) -> (
    PayrollClient<'_>,
    PayrollRegistryClient<'_>,
    Address,
    u64,
) {
    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let registry_address = env.register_contract(None, PayrollRegistry);
    let registry = PayrollRegistryClient::new(&env, &registry_address);
    let company_id = registry.register_company(&admin, &treasury);

    let payroll_address = env.register_contract(None, Payroll);
    let payroll = PayrollClient::new(&env, &payroll_address);
    payroll.initialize(
        &admin,
        &Address::generate(&env),
        &Address::generate(&env),
        &Address::generate(&env),
        &treasury,
        &Address::generate(&env),
    );
    payroll.configure_compensation_group(&admin, &registry_address, &company_id);

    (payroll, registry, admin, company_id)
}

fn prepare(
    env: &Env,
    payroll: &PayrollClient,
    employee: &Address,
    nonce_marker: u8,
) -> u64 {
    let mut nonce = [0u8; 32];
    nonce[0] = nonce_marker;
    payroll.prepare_payroll_run(
        &Vec::from_array(env, [BytesN::from_array(env, &[0u8; 256])]),
        &Vec::from_array(env, [100_i128]),
        &Vec::from_array(env, [employee.clone()]),
        &100_i128,
        &BytesN::from_array(env, &nonce),
        &None,
    )
}

#[test]
fn active_compensation_group_member_can_be_prepared() {
    let env = Env::default();
    env.mock_all_auths();
    let (payroll, registry, _admin, company_id) = setup(&env);
    let employee = Address::generate(&env);
    registry.add_employee(
        &company_id,
        &employee,
        &BytesN::from_array(&env, &[1u8; 32]),
    );

    let run_id = prepare(&env, &payroll, &employee, 1);

    assert!(run_id > 0);
    assert!(payroll.has_active_payroll_run());
}

#[test]
fn employee_outside_compensation_group_is_rejected_before_state_changes() {
    let env = Env::default();
    env.mock_all_auths();
    let (payroll, registry, _admin, company_id) = setup(&env);
    let employee = Address::generate(&env);

    assert!(payroll
        .try_prepare_payroll_run(
            &Vec::from_array(&env, [BytesN::from_array(&env, &[0u8; 256])]),
            &Vec::from_array(&env, [100_i128]),
            &Vec::from_array(&env, [employee.clone()]),
            &100_i128,
            &BytesN::from_array(&env, &[2u8; 32]),
            &None,
        )
        .is_err());
    assert!(!payroll.has_active_payroll_run());

    registry.add_employee(
        &company_id,
        &employee,
        &BytesN::from_array(&env, &[2u8; 32]),
    );
    assert!(prepare(&env, &payroll, &employee, 2) > 0);
}

#[test]
fn suspended_compensation_group_member_is_rejected_until_reactivated() {
    let env = Env::default();
    env.mock_all_auths();
    let (payroll, registry, _admin, company_id) = setup(&env);
    let employee = Address::generate(&env);
    registry.add_employee(
        &company_id,
        &employee,
        &BytesN::from_array(&env, &[3u8; 32]),
    );
    registry.set_employee_status(
        &company_id,
        &employee,
        &EmployeeStatus::Suspended,
    );

    assert!(payroll
        .try_prepare_payroll_run(
            &Vec::from_array(&env, [BytesN::from_array(&env, &[0u8; 256])]),
            &Vec::from_array(&env, [100_i128]),
            &Vec::from_array(&env, [employee.clone()]),
            &100_i128,
            &BytesN::from_array(&env, &[3u8; 32]),
            &None,
        )
        .is_err());
    assert!(!payroll.has_active_payroll_run());

    registry.set_employee_status(&company_id, &employee, &EmployeeStatus::Active);
    assert!(prepare(&env, &payroll, &employee, 3) > 0);
}

#[test]
fn payroll_runs_proceed_without_compensation_group_when_unconfigured() {
    let env = Env::default();
    env.mock_all_auths();
    let registry_address = env.register_contract(None, PayrollRegistry);
    let registry = PayrollRegistryClient::new(&env, &registry_address);
    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let company_id = registry.register_company(&admin, &treasury);

    let payroll_address = env.register_contract(None, Payroll);
    let payroll = PayrollClient::new(&env, &payroll_address);
    payroll.initialize(
        &admin,
        &Address::generate(&env),
        &Address::generate(&env),
        &Address::generate(&env),
        &treasury,
        &Address::generate(&env),
    );
    // No configure_compensation_group call - group is unconfigured

    let employee = Address::generate(&env);
    registry.add_employee(
        &company_id,
        &employee,
        &BytesN::from_array(&env, &[1u8; 32]),
    );

    // Without a compensation group configured, payroll should proceed
    // regardless of employee eligibility (backward compatibility).
    let run_id = payroll.prepare_payroll_run(
        &Vec::from_array(env, [BytesN::from_array(env, &[0u8; 256])]),
        &Vec::from_array(env, [100_i128]),
        &Vec::from_array(env, [employee.clone()]),
        &100_i128,
        &BytesN::from_array(env, &[1u8; 32]),
        &None,
    );

    assert!(run_id > 0);
    assert!(payroll.has_active_payroll_run());
}
