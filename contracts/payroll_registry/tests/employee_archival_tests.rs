//! Issue #511: employee record archival tests.
//!
//! Archived employees keep their commitment for audit, become permanently
//! ineligible, and emit an `EmployeeArchived` lifecycle event.

use payroll_registry::{DataKey, EmployeeStatus, PayrollRegistryClient};
use soroban_sdk::testutils::{Address as _, Events as _};
use soroban_sdk::xdr::ContractEventBody;
use soroban_sdk::{Address, Env, Symbol, TryIntoVal};

fn commit(env: &Env) -> soroban_sdk::BytesN<32> {
    soroban_sdk::BytesN::from_array(env, &[7u8; 32])
}

fn register_company_with_employee(env: &Env, client: &PayrollRegistryClient) -> (u64, Address) {
    let admin = Address::generate(env);
    let treasury = Address::generate(env);
    let employee = Address::generate(env);

    let company_id = client.register_company(&admin, &treasury);
    client.add_employee(&company_id, &employee, &commit(env));
    (company_id, employee)
}

fn contract_event_count(env: &Env, contract_id: &Address) -> usize {
    env.events()
        .all()
        .filter_by_contract(contract_id)
        .events()
        .len()
}

/// Consume the event buffer with a read-only call so the next count only
/// reflects events emitted after it.
fn drain_events(client: &PayrollRegistryClient, company_id: u64, employee: &Address) {
    let _ = client.get_employee_status(&company_id, employee);
}

#[test]
fn archive_employee_retains_commitment_and_emits_event() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(payroll_registry::PayrollRegistry, ());
    let client = PayrollRegistryClient::new(&env, &contract_id);

    let (company_id, employee) = register_company_with_employee(&env, &client);
    client.set_employee_status(&company_id, &employee, &EmployeeStatus::Offboarded);

    drain_events(&client, company_id, &employee);
    client.archive_employee(&company_id, &employee);

    // The event buffer reflects the last invocation only, so capture it
    // before any further client calls.
    let events = env
        .events()
        .all()
        .filter_by_contract(&contract_id)
        .events()
        .to_vec();
    assert_eq!(events.len(), 1);

    // The commitment is retained for audit even after archival (#511).
    let stored: soroban_sdk::BytesN<32> = env.as_contract(&contract_id, || {
        env.storage()
            .persistent()
            .get(&DataKey::Employee(company_id, employee.clone()))
            .expect("archived employee commitment should be retained")
    });
    assert_eq!(stored, commit(&env));

    assert_eq!(
        client.get_employee_status(&company_id, &employee),
        EmployeeStatus::Archived
    );
    assert!(!client.is_employee_active(&company_id, &employee));
    assert!(!client.is_eligible(&company_id, &employee));

    // Archival timestamp is recorded.
    let archived_at: u64 = env.as_contract(&contract_id, || {
        env.storage()
            .persistent()
            .get(&DataKey::ArchivedAt(company_id, employee.clone()))
            .expect("archived timestamp should be stored")
    });
    assert_eq!(archived_at, env.ledger().timestamp());

    // Event shape: topics ("EmployeeArchived", company_id, employee),
    // data (previous_status, new_status, ledger_sequence, timestamp).
    let last = events.first().expect("archival event should exist");
    let ContractEventBody::V0(v0) = &last.body else {
        panic!("expected V0 event body");
    };
    let topics = v0.topics.to_vec();
    assert_eq!(topics.len(), 3);
    let name: Symbol = topics[0].try_into_val(&env).unwrap();
    assert_eq!(name, Symbol::new(&env, "EmployeeArchived"));
    let soroban_sdk::xdr::ScVal::U64(topic_company) = topics[1] else {
        panic!("expected U64 company id topic");
    };
    assert_eq!(topic_company, company_id);
    let topic_employee: Address = topics[2].try_into_val(&env).unwrap();
    assert_eq!(topic_employee, employee);

    let soroban_sdk::xdr::ScVal::Vec(Some(data)) = &v0.data else {
        panic!("expected Vec event data");
    };
    let data = data.to_vec();
    assert_eq!(data.len(), 4);
    let prev_status: EmployeeStatus = data[0].try_into_val(&env).unwrap();
    assert_eq!(prev_status, EmployeeStatus::Offboarded);
    let new_status: EmployeeStatus = data[1].try_into_val(&env).unwrap();
    assert_eq!(new_status, EmployeeStatus::Archived);
}

#[test]
#[should_panic(expected = "Only offboarded employees can be archived")]
fn archive_employee_requires_offboarded_status() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(payroll_registry::PayrollRegistry, ());
    let client = PayrollRegistryClient::new(&env, &contract_id);

    let (company_id, employee) = register_company_with_employee(&env, &client);
    client.archive_employee(&company_id, &employee);
}

#[test]
fn archive_employee_twice_is_noop() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(payroll_registry::PayrollRegistry, ());
    let client = PayrollRegistryClient::new(&env, &contract_id);

    let (company_id, employee) = register_company_with_employee(&env, &client);
    client.set_employee_status(&company_id, &employee, &EmployeeStatus::Offboarded);
    client.archive_employee(&company_id, &employee);

    drain_events(&client, company_id, &employee);
    client.archive_employee(&company_id, &employee);
    let emitted = contract_event_count(&env, &contract_id);
    assert_eq!(emitted, 0);
}

#[test]
#[should_panic(expected = "Offboarded employee status cannot be changed")]
fn archived_employee_is_terminal() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(payroll_registry::PayrollRegistry, ());
    let client = PayrollRegistryClient::new(&env, &contract_id);

    let (company_id, employee) = register_company_with_employee(&env, &client);
    client.set_employee_status(&company_id, &employee, &EmployeeStatus::Offboarded);
    client.archive_employee(&company_id, &employee);
    client.set_employee_status(&company_id, &employee, &EmployeeStatus::Active);
}

#[test]
#[should_panic(expected = "Use archive_employee to archive an employee")]
fn set_employee_status_rejects_archived_variant() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(payroll_registry::PayrollRegistry, ());
    let client = PayrollRegistryClient::new(&env, &contract_id);

    let (company_id, employee) = register_company_with_employee(&env, &client);
    client.set_employee_status(&company_id, &employee, &EmployeeStatus::Offboarded);
    client.archive_employee(&company_id, &employee);
    client.set_employee_status(&company_id, &employee, &EmployeeStatus::Archived);
}

#[test]
#[should_panic(expected = "Employee not found")]
fn archive_unknown_employee_panics() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(payroll_registry::PayrollRegistry, ());
    let client = PayrollRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let company_id = client.register_company(&admin, &treasury);
    let employee = Address::generate(&env);
    client.archive_employee(&company_id, &employee);
}
