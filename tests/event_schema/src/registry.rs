//! Snapshot coverage for every event emitted by the Payroll Registry
//! contract (`contracts/events/src/lib.rs`, "Payroll Registry Events"
//! section). Unlike the Payroll domain, each event here uses its own
//! PascalCase topic symbol (preserved for backward compatibility) rather
//! than a shared domain prefix.

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
        "registry.CompanyRegistered topics changed"
    );
    let decoded: (Address, Address) = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (admin, treasury),
        "registry.CompanyRegistered payload changed"
    );
    out.insert(
        "registry.CompanyRegistered".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("CompanyRegistered"), dynamic("u64")],
            data: vec![field("admin", "Address"), field("treasury", "Address")],
        },
    );
}

fn case_employee_added(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let company_id: u64 = 2;
    let employee = Address::generate(env);
    let commitment = BytesN::from_array(env, &[10u8; 32]);
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
        "registry.EmployeeAdded topics changed"
    );
    let decoded: (BytesN<32>,) = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (commitment,),
        "registry.EmployeeAdded payload changed"
    );
    out.insert(
        "registry.EmployeeAdded".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("EmployeeAdded"), dynamic("u64"), dynamic("Address")],
            data: vec![field("commitment", "BytesN<32>")],
        },
    );
}

fn case_employee_removed(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let company_id: u64 = 3;
    let employee = Address::generate(env);
    env.as_contract(cid, || {
        payroll_events::emit_employee_removed(env, company_id, employee.clone());
    });
    let (_, topics, data) = last_event(env);
    let expected_topics: SVec<Val> = (
        Symbol::new(env, "EmployeeRemoved"),
        company_id,
        employee.clone(),
    )
        .into_val(env);
    assert_eq!(
        topics, expected_topics,
        "registry.EmployeeRemoved topics changed"
    );
    let decoded: () = data.try_into_val(env).unwrap();
    assert_eq!(decoded, (), "registry.EmployeeRemoved payload changed");
    out.insert(
        "registry.EmployeeRemoved".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("EmployeeRemoved"), dynamic("u64"), dynamic("Address")],
            data: vec![],
        },
    );
}

fn case_commitment_updated(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let company_id: u64 = 4;
    let employee = Address::generate(env);
    let new_commitment = BytesN::from_array(env, &[11u8; 32]);
    env.as_contract(cid, || {
        payroll_events::emit_registry_commitment_updated(
            env,
            company_id,
            employee.clone(),
            new_commitment.clone(),
        );
    });
    let (_, topics, data) = last_event(env);
    let expected_topics: SVec<Val> = (
        Symbol::new(env, "CommitmentUpdated"),
        company_id,
        employee.clone(),
    )
        .into_val(env);
    assert_eq!(
        topics, expected_topics,
        "registry.CommitmentUpdated topics changed"
    );
    let decoded: (BytesN<32>,) = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (new_commitment,),
        "registry.CommitmentUpdated payload changed"
    );
    out.insert(
        "registry.CommitmentUpdated".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("CommitmentUpdated"), dynamic("u64"), dynamic("Address")],
            data: vec![field("new_commitment", "BytesN<32>")],
        },
    );
}

fn case_employee_status_changed(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let company_id: u64 = 5;
    let employee = Address::generate(env);
    let previous_status = Symbol::new(env, "active");
    let new_status = Symbol::new(env, "suspended");
    env.as_contract(cid, || {
        payroll_events::emit_employee_status_changed(
            env,
            company_id,
            employee.clone(),
            previous_status.clone(),
            new_status.clone(),
        );
    });
    let (_, topics, data) = last_event(env);
    let expected_topics: SVec<Val> = (
        Symbol::new(env, "EmployeeStatusChanged"),
        company_id,
        employee.clone(),
    )
        .into_val(env);
    assert_eq!(
        topics, expected_topics,
        "registry.EmployeeStatusChanged topics changed"
    );
    let decoded: (Symbol, Symbol) = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (previous_status, new_status),
        "registry.EmployeeStatusChanged payload changed"
    );
    out.insert(
        "registry.EmployeeStatusChanged".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![
                sym("EmployeeStatusChanged"),
                dynamic("u64"),
                dynamic("Address"),
            ],
            data: vec![
                field("previous_status", "Symbol"),
                field("new_status", "Symbol"),
            ],
        },
    );
}

fn case_registry_pause_manager_set(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let pause_manager = Address::generate(env);
    env.as_contract(cid, || {
        payroll_events::emit_registry_pause_manager_set(env, pause_manager.clone());
    });
    let (_, topics, data) = last_event(env);
    let expected_topics: SVec<Val> = (Symbol::new(env, "RegistryPauseMgrSet"),).into_val(env);
    assert_eq!(
        topics, expected_topics,
        "registry.RegistryPauseMgrSet topics changed"
    );
    let decoded: (Address,) = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (pause_manager,),
        "registry.RegistryPauseMgrSet payload changed"
    );
    out.insert(
        "registry.RegistryPauseMgrSet".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("RegistryPauseMgrSet")],
            data: vec![field("pause_manager", "Address")],
        },
    );
}

fn case_company_admin_proposed(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let company_id: u64 = 6;
    let current_admin = Address::generate(env);
    let new_admin = Address::generate(env);
    env.as_contract(cid, || {
        payroll_events::emit_company_admin_proposed(
            env,
            company_id,
            current_admin.clone(),
            new_admin.clone(),
        );
    });
    let (_, topics, data) = last_event(env);
    let expected_topics: SVec<Val> = (
        Symbol::new(env, "CompanyAdminProposed"),
        company_id,
        current_admin.clone(),
    )
        .into_val(env);
    assert_eq!(
        topics, expected_topics,
        "registry.CompanyAdminProposed topics changed"
    );
    let decoded: (Address,) = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (new_admin,),
        "registry.CompanyAdminProposed payload changed"
    );
    out.insert(
        "registry.CompanyAdminProposed".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![
                sym("CompanyAdminProposed"),
                dynamic("u64"),
                dynamic("Address"),
            ],
            data: vec![field("new_admin", "Address")],
        },
    );
}

fn case_company_admin_rotated(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let company_id: u64 = 7;
    let old_admin = Address::generate(env);
    let new_admin = Address::generate(env);
    env.as_contract(cid, || {
        payroll_events::emit_company_admin_rotated(
            env,
            company_id,
            old_admin.clone(),
            new_admin.clone(),
        );
    });
    let (_, topics, data) = last_event(env);
    let expected_topics: SVec<Val> = (
        Symbol::new(env, "CompanyAdminRotated"),
        company_id,
        old_admin.clone(),
    )
        .into_val(env);
    assert_eq!(
        topics, expected_topics,
        "registry.CompanyAdminRotated topics changed"
    );
    let decoded: (Address,) = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (new_admin,),
        "registry.CompanyAdminRotated payload changed"
    );
    out.insert(
        "registry.CompanyAdminRotated".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![
                sym("CompanyAdminRotated"),
                dynamic("u64"),
                dynamic("Address"),
            ],
            data: vec![field("new_admin", "Address")],
        },
    );
}

fn case_company_admin_rotation_cancelled(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let company_id: u64 = 8;
    let caller = Address::generate(env);
    env.as_contract(cid, || {
        payroll_events::emit_company_admin_rotation_cancelled(env, company_id, caller.clone());
    });
    let (_, topics, data) = last_event(env);
    let expected_topics: SVec<Val> = (
        Symbol::new(env, "CompanyAdminRotCancelled"),
        company_id,
        caller.clone(),
    )
        .into_val(env);
    assert_eq!(
        topics, expected_topics,
        "registry.CompanyAdminRotCancelled topics changed"
    );
    let decoded: () = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (),
        "registry.CompanyAdminRotCancelled payload changed"
    );
    out.insert(
        "registry.CompanyAdminRotCancelled".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![
                sym("CompanyAdminRotCancelled"),
                dynamic("u64"),
                dynamic("Address"),
            ],
            data: vec![],
        },
    );
}

fn case_company_treasury_proposed(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let company_id: u64 = 9;
    let current_admin = Address::generate(env);
    let new_treasury = Address::generate(env);
    env.as_contract(cid, || {
        payroll_events::emit_company_treasury_proposed(
            env,
            company_id,
            current_admin.clone(),
            new_treasury.clone(),
        );
    });
    let (_, topics, data) = last_event(env);
    let expected_topics: SVec<Val> = (
        Symbol::new(env, "CompanyTreasProposed"),
        company_id,
        current_admin.clone(),
    )
        .into_val(env);
    assert_eq!(
        topics, expected_topics,
        "registry.CompanyTreasProposed topics changed"
    );
    let decoded: (Address,) = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (new_treasury,),
        "registry.CompanyTreasProposed payload changed"
    );
    out.insert(
        "registry.CompanyTreasProposed".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![
                sym("CompanyTreasProposed"),
                dynamic("u64"),
                dynamic("Address"),
            ],
            data: vec![field("new_treasury", "Address")],
        },
    );
}

fn case_company_treasury_rotated(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let company_id: u64 = 10;
    let old_treasury = Address::generate(env);
    let new_treasury = Address::generate(env);
    env.as_contract(cid, || {
        payroll_events::emit_company_treasury_rotated(
            env,
            company_id,
            old_treasury.clone(),
            new_treasury.clone(),
        );
    });
    let (_, topics, data) = last_event(env);
    let expected_topics: SVec<Val> = (
        Symbol::new(env, "CompanyTreasRotated"),
        company_id,
        old_treasury.clone(),
    )
        .into_val(env);
    assert_eq!(
        topics, expected_topics,
        "registry.CompanyTreasRotated topics changed"
    );
    let decoded: (Address,) = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (new_treasury,),
        "registry.CompanyTreasRotated payload changed"
    );
    out.insert(
        "registry.CompanyTreasRotated".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![
                sym("CompanyTreasRotated"),
                dynamic("u64"),
                dynamic("Address"),
            ],
            data: vec![field("new_treasury", "Address")],
        },
    );
}

fn case_company_treasury_rotation_cancelled(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let company_id: u64 = 11;
    let caller = Address::generate(env);
    env.as_contract(cid, || {
        payroll_events::emit_company_treasury_rotation_cancelled(env, company_id, caller.clone());
    });
    let (_, topics, data) = last_event(env);
    let expected_topics: SVec<Val> = (
        Symbol::new(env, "CompanyTreasRotCancelled"),
        company_id,
        caller.clone(),
    )
        .into_val(env);
    assert_eq!(
        topics, expected_topics,
        "registry.CompanyTreasRotCancelled topics changed"
    );
    let decoded: () = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (),
        "registry.CompanyTreasRotCancelled payload changed"
    );
    out.insert(
        "registry.CompanyTreasRotCancelled".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![
                sym("CompanyTreasRotCancelled"),
                dynamic("u64"),
                dynamic("Address"),
            ],
            data: vec![],
        },
    );
}

#[test]
fn registry_events_match_fixture() {
    let (env, cid) = new_env();
    let mut observed = SchemaMap::new();

    case_company_registered(&env, &cid, &mut observed);
    case_employee_added(&env, &cid, &mut observed);
    case_employee_removed(&env, &cid, &mut observed);
    case_commitment_updated(&env, &cid, &mut observed);
    case_employee_status_changed(&env, &cid, &mut observed);
    case_registry_pause_manager_set(&env, &cid, &mut observed);
    case_company_admin_proposed(&env, &cid, &mut observed);
    case_company_admin_rotated(&env, &cid, &mut observed);
    case_company_admin_rotation_cancelled(&env, &cid, &mut observed);
    case_company_treasury_proposed(&env, &cid, &mut observed);
    case_company_treasury_rotated(&env, &cid, &mut observed);
    case_company_treasury_rotation_cancelled(&env, &cid, &mut observed);

    assert_matches_fixture(
        "registry",
        include_str!("../fixtures/events/registry.json"),
        observed,
    );
}
