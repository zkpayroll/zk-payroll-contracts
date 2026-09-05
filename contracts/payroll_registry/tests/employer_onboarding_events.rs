//! Contract-level employer onboarding event tests (issue #405).
//!
//! Complements the schema snapshots in `tests/event_schema/src/employer_onboarding.rs`
//! by exercising the real registry contract emitters on success and failure paths.

use payroll_registry::{PayrollRegistry, PayrollRegistryClient};
use soroban_sdk::testutils::{Address as _, Events};
use soroban_sdk::{Address, BytesN, Env, String, Symbol, TryIntoVal};

const VALID_EMPLOYEE_WALLET: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";

fn setup() -> (Env, PayrollRegistryClient<'static>) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, PayrollRegistry);
    let client = PayrollRegistryClient::new(&env, &contract_id);
    (env, client)
}

fn event_topic0(env: &Env, index: u32) -> Symbol {
    let event = env.events().all().get(index).unwrap();
    event.1.get(0).unwrap().try_into_val(env).unwrap()
}

#[test]
fn employer_onboarding_success_emits_registry_events_in_order() {
    let (env, client) = setup();
    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let employee = Address::generate(&env);
    let commitment = BytesN::from_array(&env, &[42u8; 32]);

    let start = env.events().all().len();
    let company_id = client.register_company(&admin, &treasury);
    client.add_employee(&company_id, &employee, &commitment);
    let end = env.events().all().len();

    assert_eq!(end - start, 2, "onboarding must emit company then employee events");
    assert_eq!(
        event_topic0(&env, start),
        Symbol::new(&env, "CompanyRegistered")
    );
    assert_eq!(
        event_topic0(&env, start + 1),
        Symbol::new(&env, "EmployeeAdded")
    );

    let employee_event = env.events().all().get(start + 1).unwrap();
    let decoded: (BytesN<32>,) = employee_event.2.try_into_val(&env).unwrap();
    assert_eq!(
        decoded.0, commitment,
        "EmployeeAdded must carry the Poseidon commitment hash, not a salary value"
    );
}

#[test]
fn employer_onboarding_wallet_path_emits_employee_added() {
    let (env, client) = setup();
    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let commitment = BytesN::from_array(&env, &[43u8; 32]);
    let wallet = String::from_str(&env, VALID_EMPLOYEE_WALLET);

    let company_id = client.register_company(&admin, &treasury);
    let before = env.events().all().len();
    client.add_employee_by_wallet(&company_id, &wallet, &commitment);
    let after = env.events().all().len();

    assert_eq!(after, before + 1);
    assert_eq!(
        event_topic0(&env, after - 1),
        Symbol::new(&env, "EmployeeAdded")
    );
}

#[test]
fn employer_onboarding_unknown_company_emits_no_employee_event() {
    let (env, client) = setup();
    let employee = Address::generate(&env);
    let commitment = BytesN::from_array(&env, &[44u8; 32]);
    let before = env.events().all().len();

    let result = client.try_add_employee(&99, &employee, &commitment);
    assert!(result.is_err(), "unknown company must fail onboarding");

    assert_eq!(
        env.events().all().len(),
        before,
        "failed onboarding must not emit EmployeeAdded"
    );
}

#[test]
fn employer_onboarding_invalid_wallet_emits_no_employee_event() {
    let (env, client) = setup();
    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let commitment = BytesN::from_array(&env, &[45u8; 32]);
    let bad_wallet = String::from_str(&env, "not-a-stellar-wallet");

    let company_id = client.register_company(&admin, &treasury);
    let before = env.events().all().len();

    let result = client.try_add_employee_by_wallet(&company_id, &bad_wallet, &commitment);
    assert!(result.is_err(), "invalid wallet must fail onboarding");

    assert_eq!(
        env.events().all().len(),
        before,
        "invalid wallet onboarding must not emit EmployeeAdded"
    );
}

#[test]
fn duplicate_company_registration_emits_no_second_event() {
    let (env, client) = setup();
    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);

    client.register_company(&admin, &treasury);
    let before = env.events().all().len();

    let result = client.try_register_company(&admin, &treasury);
    assert!(result.is_err(), "duplicate company registration must fail");

    assert_eq!(
        env.events().all().len(),
        before,
        "duplicate registration must not emit another CompanyRegistered event"
    );
}
