//! Snapshot coverage for employer onboarding events (issue #405).
//!
//! These are the events SDK and dashboard consumers rely on when indexing a
//! new company and its first employees. Shapes are pinned separately from the
//! broader registry/salary_commitment domain fixtures so onboarding parsers
//! can depend on a single, stable contract.

use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, IntoVal, Symbol, TryIntoVal, Val, Vec as SVec};

use crate::support::{
    assert_matches_fixture, dynamic, field, last_event, new_env, sym, EventSchema, SchemaMap,
};

fn case_company_registered(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let company_id: u64 = 1;
    let admin = Address::generate(env);
    let treasury = Address::generate(env);
    env.as_contract(cid, || {
        payroll_events::emit_company_registered(env, company_id, admin.clone(), treasury.clone());
    });
    let (_, topics, data) = last_event(env);
    let expected_topics: SVec<Val> =
        (Symbol::new(env, "CompanyRegistered"), company_id).into_val(env);
    assert_eq!(
        topics, expected_topics,
        "onboarding.CompanyRegistered topics changed"
    );
    let decoded: (Address, Address) = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (admin, treasury),
        "onboarding.CompanyRegistered payload changed"
    );
    out.insert(
        "onboarding.CompanyRegistered".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("CompanyRegistered"), dynamic("u64")],
            data: vec![field("admin", "Address"), field("treasury", "Address")],
        },
    );
}

fn case_commitment_stored(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let employee = Address::generate(env);
    let commitment = BytesN::from_array(env, &[30u8; 32]);
    env.as_contract(cid, || {
        payroll_events::emit_commitment_stored(env, employee.clone(), commitment.clone());
    });
    let (_, topics, data) = last_event(env);
    let expected_topics: SVec<Val> =
        (Symbol::new(env, "CommitmentUpdated"), employee.clone()).into_val(env);
    assert_eq!(
        topics, expected_topics,
        "onboarding.CommitmentUpdated topics changed"
    );
    let decoded: (BytesN<32>,) = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (commitment,),
        "onboarding.CommitmentUpdated payload changed"
    );
    out.insert(
        "onboarding.CommitmentUpdated".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("CommitmentUpdated"), dynamic("Address")],
            data: vec![field("commitment", "BytesN<32>")],
        },
    );
}

fn case_employee_added(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let company_id: u64 = 2;
    let employee = Address::generate(env);
    let commitment = BytesN::from_array(env, &[31u8; 32]);
    env.as_contract(cid, || {
        payroll_events::emit_employee_added(env, company_id, employee.clone(), commitment.clone());
    });
    let (_, topics, data) = last_event(env);
    let expected_topics: SVec<Val> = (
        Symbol::new(env, "EmployeeAdded"),
        company_id,
        employee.clone(),
    )
        .into_val(env);
    assert_eq!(
        topics, expected_topics,
        "onboarding.EmployeeAdded topics changed"
    );
    let decoded: (BytesN<32>,) = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (commitment,),
        "onboarding.EmployeeAdded payload changed"
    );
    out.insert(
        "onboarding.EmployeeAdded".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("EmployeeAdded"), dynamic("u64"), dynamic("Address")],
            data: vec![field("commitment", "BytesN<32>")],
        },
    );
}

fn case_reference_id_set(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let employee = Address::generate(env);
    let reference_id = soroban_sdk::String::from_str(env, "EMP-ONB-0042");
    env.as_contract(cid, || {
        payroll_events::emit_reference_id_set(env, employee.clone(), reference_id.clone());
    });
    let (_, topics, data) = last_event(env);
    let expected_topics: SVec<Val> =
        (Symbol::new(env, "ReferenceIdSet"), employee.clone()).into_val(env);
    assert_eq!(
        topics, expected_topics,
        "onboarding.ReferenceIdSet topics changed"
    );
    let decoded: (soroban_sdk::String,) = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (reference_id,),
        "onboarding.ReferenceIdSet payload changed"
    );
    out.insert(
        "onboarding.ReferenceIdSet".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("ReferenceIdSet"), dynamic("Address")],
            data: vec![field("reference_id", "String")],
        },
    );
}

/// Canonical onboarding sequence: company registration, commitment store,
/// employee registry add. Order is part of the consumer contract for indexers
/// building roster state incrementally.
#[test]
fn employer_onboarding_event_order_is_stable() {
    let (env, cid) = new_env();
    let company_id: u64 = 0;
    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let employee = Address::generate(&env);
    let commitment = BytesN::from_array(&env, &[32u8; 32]);

    env.as_contract(&cid, || {
        payroll_events::emit_company_registered(&env, company_id, admin, treasury);
        payroll_events::emit_commitment_stored(&env, employee.clone(), commitment.clone());
        payroll_events::emit_employee_added(&env, company_id, employee, commitment);
    });

    let events = env.events().all();
    assert_eq!(events.len(), 3, "onboarding flow must emit exactly three events");

    let expected = [
        Symbol::new(&env, "CompanyRegistered"),
        Symbol::new(&env, "CommitmentUpdated"),
        Symbol::new(&env, "EmployeeAdded"),
    ];
    for (index, expected_name) in expected.iter().enumerate() {
        let topics = events.get(index as u32).unwrap().1;
        let name: Symbol = topics.get(0).unwrap().try_into_val(&env).unwrap();
        assert_eq!(
            name, *expected_name,
            "onboarding event order changed at index {index}"
        );
    }
}

#[test]
fn employer_onboarding_events_match_fixture() {
    let (env, cid) = new_env();
    let mut observed = SchemaMap::new();

    case_company_registered(&env, &cid, &mut observed);
    case_commitment_stored(&env, &cid, &mut observed);
    case_employee_added(&env, &cid, &mut observed);
    case_reference_id_set(&env, &cid, &mut observed);

    assert_matches_fixture(
        "employer_onboarding",
        include_str!("../fixtures/events/employer_onboarding.json"),
        observed,
    );
}
