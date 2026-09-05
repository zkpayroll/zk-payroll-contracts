//! Snapshot coverage for every event emitted by the Payment Executor
//! contract (`contracts/events/src/lib.rs`, "Payment Executor Events"
//! section).

use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env, IntoVal, Symbol, TryIntoVal, Val, Vec as SVec};

use crate::support::{
    assert_matches_fixture, dynamic, field, last_event, new_env, sym, EventSchema, SchemaMap,
};

fn case_executor_initialized(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let registry = Address::generate(env);
    let token = Address::generate(env);
    env.as_contract(cid, || {
        payroll_events::emit_executor_initialized(env, registry.clone(), token.clone());
    });
    let (_, topics, data) = last_event(env);
    let expected_topics: SVec<Val> = (Symbol::new(env, "ExecutorInitialized"),).into_val(env);
    assert_eq!(
        topics, expected_topics,
        "payment_executor.ExecutorInitialized topics changed"
    );
    let decoded: (Address, Address) = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (registry, token),
        "payment_executor.ExecutorInitialized payload changed"
    );
    out.insert(
        "payment_executor.ExecutorInitialized".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("ExecutorInitialized")],
            data: vec![field("registry", "Address"), field("token", "Address")],
        },
    );
}

fn case_executor_admin_set(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let admin = Address::generate(env);
    env.as_contract(cid, || {
        payroll_events::emit_executor_admin_set(env, admin.clone());
    });
    let (_, topics, data) = last_event(env);
    let expected_topics: SVec<Val> = (Symbol::new(env, "ExecutorAdminSet"),).into_val(env);
    assert_eq!(
        topics, expected_topics,
        "payment_executor.ExecutorAdminSet topics changed"
    );
    let decoded: (Address,) = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (admin,),
        "payment_executor.ExecutorAdminSet payload changed"
    );
    out.insert(
        "payment_executor.ExecutorAdminSet".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("ExecutorAdminSet")],
            data: vec![field("admin", "Address")],
        },
    );
}

fn case_executor_pause_manager_set(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let pause_manager = Address::generate(env);
    env.as_contract(cid, || {
        payroll_events::emit_executor_pause_manager_set(env, pause_manager.clone());
    });
    let (_, topics, data) = last_event(env);
    let expected_topics: SVec<Val> = (Symbol::new(env, "ExecutorPauseMgrSet"),).into_val(env);
    assert_eq!(
        topics, expected_topics,
        "payment_executor.ExecutorPauseMgrSet topics changed"
    );
    let decoded: (Address,) = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (pause_manager,),
        "payment_executor.ExecutorPauseMgrSet payload changed"
    );
    out.insert(
        "payment_executor.ExecutorPauseMgrSet".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("ExecutorPauseMgrSet")],
            data: vec![field("pause_manager", "Address")],
        },
    );
}

fn case_period_created(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let company_id: u64 = 40;
    let period_id: u32 = 1;
    env.as_contract(cid, || {
        payroll_events::emit_period_created(env, company_id, period_id);
    });
    let (_, topics, data) = last_event(env);
    let expected_topics: SVec<Val> = (Symbol::new(env, "PeriodCreated"), company_id).into_val(env);
    assert_eq!(
        topics, expected_topics,
        "payment_executor.PeriodCreated topics changed"
    );
    let decoded: (u32,) = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (period_id,),
        "payment_executor.PeriodCreated payload changed"
    );
    out.insert(
        "payment_executor.PeriodCreated".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("PeriodCreated"), dynamic("u64")],
            data: vec![field("period_id", "u32")],
        },
    );
}

fn case_period_closed(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let company_id: u64 = 41;
    let period_id: u32 = 2;
    env.as_contract(cid, || {
        payroll_events::emit_period_closed(env, company_id, period_id);
    });
    let (_, topics, data) = last_event(env);
    let expected_topics: SVec<Val> = (Symbol::new(env, "PeriodClosed"), company_id).into_val(env);
    assert_eq!(
        topics, expected_topics,
        "payment_executor.PeriodClosed topics changed"
    );
    let decoded: (u32,) = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (period_id,),
        "payment_executor.PeriodClosed payload changed"
    );
    out.insert(
        "payment_executor.PeriodClosed".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("PeriodClosed"), dynamic("u64")],
            data: vec![field("period_id", "u32")],
        },
    );
}

fn case_executor_payment_processed(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let company_id: u64 = 42;
    let employee = Address::generate(env);
    let amount: i128 = 3_300;
    let period: u32 = 3;
    env.as_contract(cid, || {
        payroll_events::emit_executor_payment_processed(
            env,
            company_id,
            employee.clone(),
            amount,
            period,
        );
    });
    let (_, topics, data) = last_event(env);
    let expected_topics: SVec<Val> =
        (Symbol::new(env, "PayrollProcessed"), company_id).into_val(env);
    assert_eq!(
        topics, expected_topics,
        "payment_executor.PayrollProcessed topics changed"
    );
    let decoded: (Address, i128, u32) = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (employee, amount, period),
        "payment_executor.PayrollProcessed payload changed"
    );
    out.insert(
        "payment_executor.PayrollProcessed".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("PayrollProcessed"), dynamic("u64")],
            data: vec![
                field("employee", "Address"),
                field("amount", "i128"),
                field("period", "u32"),
            ],
        },
    );
}

fn case_asset_allowed_changed(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let asset = Address::generate(env);
    let allowed = true;
    env.as_contract(cid, || {
        payroll_events::emit_asset_allowed_changed(env, asset.clone(), allowed);
    });
    let (_, topics, data) = last_event(env);
    let expected_topics: SVec<Val> = (Symbol::new(env, "AssetAllowedChanged"),).into_val(env);
    assert_eq!(
        topics, expected_topics,
        "payment_executor.AssetAllowedChanged topics changed"
    );
    let decoded: (Address, bool) = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (asset, allowed),
        "payment_executor.AssetAllowedChanged payload changed"
    );
    out.insert(
        "payment_executor.AssetAllowedChanged".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("AssetAllowedChanged")],
            data: vec![field("asset", "Address"), field("allowed", "bool")],
        },
    );
}

#[test]
fn payment_executor_events_match_fixture() {
    let (env, cid) = new_env();
    let mut observed = SchemaMap::new();

    case_executor_initialized(&env, &cid, &mut observed);
    case_executor_admin_set(&env, &cid, &mut observed);
    case_executor_pause_manager_set(&env, &cid, &mut observed);
    case_period_created(&env, &cid, &mut observed);
    case_period_closed(&env, &cid, &mut observed);
    case_executor_payment_processed(&env, &cid, &mut observed);
    case_asset_allowed_changed(&env, &cid, &mut observed);

    assert_matches_fixture(
        "payment_executor",
        include_str!("../fixtures/events/payment_executor.json"),
        observed,
    );
}
