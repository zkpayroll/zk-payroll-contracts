//! Payroll run identifier enforcement tests (issue #990).
//!
//! Coverage:
//!   - A valid identifier is registered and stored with correct metadata.
//!   - The all-zeros identifier is rejected as an uninitialised sentinel.
//!   - Registering the same identifier twice for the same company is rejected.
//!   - The same identifier bytes may be used by a different company (scoped).
//!   - `is_run_id_registered` and `get_run_identifier` reflect stored state.
//!   - `require_run_id_available` passes before registration and panics after.
//!   - Only the company admin may register an identifier.
//!   - An unknown company is rejected.
//!   - A single `RunIdentifierRegistered` event is emitted per registration.
//!   - Failed registrations write nothing and emit nothing.

use payroll_registry::{PayrollRegistry, PayrollRegistryClient};
use soroban_sdk::testutils::{Address as _, Events, Ledger};
use soroban_sdk::{Address, BytesN, Env, Symbol, TryIntoVal};

/// Ledger clock used by most tests.
const T0: u64 = 1_700_000_000;

fn setup() -> (Env, PayrollRegistryClient<'static>, Address, u64) {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().with_mut(|li| li.timestamp = T0);

    let contract_id = env.register_contract(None, PayrollRegistry);
    let client = PayrollRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let company_id = client.register_company(&admin, &treasury);

    (env, client, admin, company_id)
}

fn run_id(env: &Env, seed: u8) -> BytesN<32> {
    let mut arr = [1u8; 32];
    arr[0] = seed;
    BytesN::from_array(env, &arr)
}

// ---------------------------------------------------------------------------
// Success paths
// ---------------------------------------------------------------------------

#[test]
fn registration_stores_correct_metadata() {
    let (env, client, admin, company_id) = setup();
    let id = run_id(&env, 1);

    let record = client.register_payroll_run_id(&company_id, &admin, &id);

    assert_eq!(record.company_id, company_id);
    assert_eq!(record.run_id_bytes, id);
    assert_eq!(record.registered_at, T0);
    assert_eq!(record.registered_by, admin);
}

#[test]
fn registered_identifier_is_visible_via_query_helpers() {
    let (env, client, admin, company_id) = setup();
    let id = run_id(&env, 2);

    assert!(!client.is_run_id_registered(&company_id, &id));
    assert!(client.get_run_identifier(&company_id, &id).is_none());

    client.register_payroll_run_id(&company_id, &admin, &id);

    assert!(client.is_run_id_registered(&company_id, &id));
    let stored = client.get_run_identifier(&company_id, &id).unwrap();
    assert_eq!(stored.run_id_bytes, id);
}

#[test]
fn multiple_distinct_identifiers_may_be_registered_for_one_company() {
    let (env, client, admin, company_id) = setup();

    client.register_payroll_run_id(&company_id, &admin, &run_id(&env, 10));
    client.register_payroll_run_id(&company_id, &admin, &run_id(&env, 11));
    client.register_payroll_run_id(&company_id, &admin, &run_id(&env, 12));

    assert!(client.is_run_id_registered(&company_id, &run_id(&env, 10)));
    assert!(client.is_run_id_registered(&company_id, &run_id(&env, 11)));
    assert!(client.is_run_id_registered(&company_id, &run_id(&env, 12)));
}

#[test]
fn same_identifier_bytes_may_be_used_by_a_different_company() {
    let (env, client, admin, company_id) = setup();
    let other_admin = Address::generate(&env);
    let other_treasury = Address::generate(&env);
    let other_company = client.register_company(&other_admin, &other_treasury);

    let shared_bytes = run_id(&env, 20);
    client.register_payroll_run_id(&company_id, &admin, &shared_bytes);

    // The same 32-byte token is acceptable under a different company.
    let result =
        client.try_register_payroll_run_id(&other_company, &other_admin, &shared_bytes);
    assert!(
        result.is_ok(),
        "identical identifier bytes must be independent across companies"
    );
}

#[test]
fn require_run_id_available_passes_before_registration() {
    let (env, client, _admin, company_id) = setup();
    let id = run_id(&env, 30);

    // Read-only: no auth, no state change.
    client.require_run_id_available(&company_id, &id);
    // Still unregistered.
    assert!(!client.is_run_id_registered(&company_id, &id));
}

#[test]
fn registration_emits_exactly_one_privacy_safe_event() {
    let (env, client, admin, company_id) = setup();
    let id = run_id(&env, 40);

    let before = env.events().all().len();
    client.register_payroll_run_id(&company_id, &admin, &id);
    let after = env.events().all().len();

    assert_eq!(after - before, 1, "registration must emit exactly one event");

    let event = env.events().all().get(after - 1).unwrap();
    let topic0: Symbol = event.1.get(0).unwrap().try_into_val(&env).unwrap();
    let topic_company: u64 = event.1.get(1).unwrap().try_into_val(&env).unwrap();
    assert_eq!(topic0, Symbol::new(&env, "RunIdentifierRegistered"));
    assert_eq!(topic_company, company_id);

    // The event payload is the identifier bytes — no salary, no employee data.
    let payload: BytesN<32> = event.2.try_into_val(&env).unwrap();
    assert_eq!(payload, id);
}

// ---------------------------------------------------------------------------
// Failure paths
// ---------------------------------------------------------------------------

#[test]
fn duplicate_identifier_for_the_same_company_is_rejected() {
    let (env, client, admin, company_id) = setup();
    let id = run_id(&env, 50);

    client.register_payroll_run_id(&company_id, &admin, &id);

    let result = client.try_register_payroll_run_id(&company_id, &admin, &id);
    assert!(
        result.is_err(),
        "duplicate run identifier must be rejected"
    );
}

#[test]
fn zero_identifier_is_rejected() {
    let (env, client, admin, company_id) = setup();
    let zero = BytesN::from_array(&env, &[0u8; 32]);

    let result = client.try_register_payroll_run_id(&company_id, &admin, &zero);
    assert!(result.is_err(), "all-zeros identifier must be rejected");
    assert!(
        !client.is_run_id_registered(&company_id, &zero),
        "failed registration must not persist the zero key"
    );
}

#[test]
#[should_panic(expected = "already registered")]
fn require_run_id_available_panics_after_registration() {
    let (env, client, admin, company_id) = setup();
    let id = run_id(&env, 60);

    client.register_payroll_run_id(&company_id, &admin, &id);
    client.require_run_id_available(&company_id, &id);
}

#[test]
fn non_admin_cannot_register_a_run_identifier() {
    let (env, client, _admin, company_id) = setup();
    let impostor = Address::generate(&env);
    let id = run_id(&env, 70);

    let result = client.try_register_payroll_run_id(&company_id, &impostor, &id);
    assert!(result.is_err());
    assert!(!client.is_run_id_registered(&company_id, &id));
}

#[test]
fn unknown_company_registration_is_rejected() {
    let (env, client, admin, _company_id) = setup();
    let id = run_id(&env, 80);

    let result = client.try_register_payroll_run_id(&99, &admin, &id);
    assert!(result.is_err());
}

#[test]
fn failed_registration_emits_no_event() {
    let (env, client, admin, company_id) = setup();
    let id = run_id(&env, 90);

    client.register_payroll_run_id(&company_id, &admin, &id);
    let before = env.events().all().len();

    // Duplicate — must fail silently.
    let _ = client.try_register_payroll_run_id(&company_id, &admin, &id);
    assert_eq!(
        env.events().all().len(),
        before,
        "a rejected registration must not emit RunIdentifierRegistered"
    );
}

// ---------------------------------------------------------------------------
// Boundary / isolation
// ---------------------------------------------------------------------------

#[test]
fn registration_does_not_affect_employee_eligibility() {
    let (env, client, admin, company_id) = setup();
    let employee = Address::generate(&env);
    let commitment = BytesN::from_array(&env, &[7u8; 32]);

    client.add_employee(&company_id, &employee, &commitment);
    client.register_payroll_run_id(&company_id, &admin, &run_id(&env, 100));

    assert!(client.is_eligible(&company_id, &employee));
}

#[test]
fn identifiers_are_scoped_per_company_and_do_not_cross_contaminate() {
    let (env, client, admin, company_a) = setup();
    let admin_b = Address::generate(&env);
    let treasury_b = Address::generate(&env);
    let company_b = client.register_company(&admin_b, &treasury_b);

    let id = run_id(&env, 110);
    client.register_payroll_run_id(&company_a, &admin, &id);

    // Company B has never registered this identifier.
    assert!(
        !client.is_run_id_registered(&company_b, &id),
        "company A's identifier must not appear in company B's scope"
    );
    // Company B can still register the same bytes independently.
    assert!(client
        .try_register_payroll_run_id(&company_b, &admin_b, &id)
        .is_ok());
}
