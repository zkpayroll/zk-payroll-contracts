//! Snapshot coverage for every event emitted by the Audit Module contract
//! (`contracts/events/src/lib.rs`, "Audit Module Events" section).

use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env, IntoVal, Symbol, TryIntoVal, Val, Vec as SVec};

use crate::support::{
    assert_matches_fixture, dynamic, field, last_event, new_env, sym, EventSchema, SchemaMap,
};

fn case_view_key_generated(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let auditor = Address::generate(env);
    let expiration_ledger: u32 = 100_000;
    env.as_contract(cid, || {
        payroll_events::emit_view_key_generated(env, auditor.clone(), expiration_ledger);
    });
    let (_, topics, data) = last_event(env);
    let expected_topics: SVec<Val> =
        (Symbol::new(env, "ViewKeyGenerated"), auditor.clone()).into_val(env);
    assert_eq!(
        topics, expected_topics,
        "audit_module.ViewKeyGenerated topics changed"
    );
    let decoded: (u32,) = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (expiration_ledger,),
        "audit_module.ViewKeyGenerated payload changed"
    );
    out.insert(
        "audit_module.ViewKeyGenerated".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("ViewKeyGenerated"), dynamic("Address")],
            data: vec![field("expiration_ledger", "u32")],
        },
    );
}

fn case_audit_access_revoked(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let admin = Address::generate(env);
    let auditor = Address::generate(env);
    env.as_contract(cid, || {
        payroll_events::emit_audit_access_revoked(env, admin.clone(), auditor.clone());
    });
    let (_, topics, data) = last_event(env);
    let expected_topics: SVec<Val> = (
        Symbol::new(env, "AuditAccessRevoked"),
        admin.clone(),
        auditor.clone(),
    )
        .into_val(env);
    assert_eq!(
        topics, expected_topics,
        "audit_module.AuditAccessRevoked topics changed"
    );
    let decoded: () = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (),
        "audit_module.AuditAccessRevoked payload changed"
    );
    out.insert(
        "audit_module.AuditAccessRevoked".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![
                sym("AuditAccessRevoked"),
                dynamic("Address"),
                dynamic("Address"),
            ],
            data: vec![],
        },
    );
}

fn case_audit_successful(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let auditor = Address::generate(env);
    let scope = Symbol::new(env, "full");
    env.as_contract(cid, || {
        payroll_events::emit_audit_successful(env, auditor.clone(), scope.clone());
    });
    let (_, topics, data) = last_event(env);
    let expected_topics: SVec<Val> =
        (Symbol::new(env, "AuditSuccessful"), auditor.clone()).into_val(env);
    assert_eq!(
        topics, expected_topics,
        "audit_module.AuditSuccessful topics changed"
    );
    let decoded: (Symbol,) = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (scope,),
        "audit_module.AuditSuccessful payload changed"
    );
    out.insert(
        "audit_module.AuditSuccessful".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("AuditSuccessful"), dynamic("Address")],
            data: vec![field("scope", "Symbol")],
        },
    );
}

fn case_aggregate_audit_generated(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let auditor = Address::generate(env);
    let company_id = Symbol::new(env, "company_1");
    let period_start: u64 = 1_000;
    let period_end: u64 = 2_000;
    env.as_contract(cid, || {
        payroll_events::emit_aggregate_audit_generated(
            env,
            auditor.clone(),
            company_id.clone(),
            period_start,
            period_end,
        );
    });
    let (_, topics, data) = last_event(env);
    let expected_topics: SVec<Val> =
        (Symbol::new(env, "AggregateAuditGenerated"), auditor.clone()).into_val(env);
    assert_eq!(
        topics, expected_topics,
        "audit_module.AggregateAuditGenerated topics changed"
    );
    let decoded: (Symbol, u64, u64) = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (company_id, period_start, period_end),
        "audit_module.AggregateAuditGenerated payload changed"
    );
    out.insert(
        "audit_module.AggregateAuditGenerated".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("AggregateAuditGenerated"), dynamic("Address")],
            data: vec![
                field("company_id", "Symbol"),
                field("period_start", "u64"),
                field("period_end", "u64"),
            ],
        },
    );
}

fn case_audit_summary_exported(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let auditor = Address::generate(env);
    let company_id = Symbol::new(env, "company_2");
    let period_start: u64 = 3_000;
    let period_end: u64 = 4_000;
    let total: u32 = 12;
    env.as_contract(cid, || {
        payroll_events::emit_audit_summary_exported(
            env,
            auditor.clone(),
            company_id.clone(),
            period_start,
            period_end,
            total,
        );
    });
    let (_, topics, data) = last_event(env);
    let expected_topics: SVec<Val> =
        (Symbol::new(env, "AuditSummaryExported"), auditor.clone()).into_val(env);
    assert_eq!(
        topics, expected_topics,
        "audit_module.AuditSummaryExported topics changed"
    );
    let decoded: (Symbol, u64, u64, u32) = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (company_id, period_start, period_end, total),
        "audit_module.AuditSummaryExported payload changed"
    );
    out.insert(
        "audit_module.AuditSummaryExported".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("AuditSummaryExported"), dynamic("Address")],
            data: vec![
                field("company_id", "Symbol"),
                field("period_start", "u64"),
                field("period_end", "u64"),
                field("total", "u32"),
            ],
        },
    );
}

fn case_audit_pause_manager_set(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let pause_manager = Address::generate(env);
    env.as_contract(cid, || {
        payroll_events::emit_audit_pause_manager_set(env, pause_manager.clone());
    });
    let (_, topics, data) = last_event(env);
    let expected_topics: SVec<Val> = (Symbol::new(env, "AuditPauseMgrSet"),).into_val(env);
    assert_eq!(
        topics, expected_topics,
        "audit_module.AuditPauseMgrSet topics changed"
    );
    let decoded: (Address,) = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (pause_manager,),
        "audit_module.AuditPauseMgrSet payload changed"
    );
    out.insert(
        "audit_module.AuditPauseMgrSet".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("AuditPauseMgrSet")],
            data: vec![field("pause_manager", "Address")],
        },
    );
}

#[test]
fn audit_module_events_match_fixture() {
    let (env, cid) = new_env();
    let mut observed = SchemaMap::new();

    case_view_key_generated(&env, &cid, &mut observed);
    case_audit_access_revoked(&env, &cid, &mut observed);
    case_audit_successful(&env, &cid, &mut observed);
    case_aggregate_audit_generated(&env, &cid, &mut observed);
    case_audit_summary_exported(&env, &cid, &mut observed);
    case_audit_pause_manager_set(&env, &cid, &mut observed);

    assert_matches_fixture(
        "audit_module",
        include_str!("../fixtures/events/audit_module.json"),
        observed,
    );
}
