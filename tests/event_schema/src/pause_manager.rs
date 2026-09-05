//! Snapshot coverage for every event emitted by the Pause Manager contract
//! (`contracts/events/src/lib.rs`, "Pause Manager Events" section). Every
//! event here shares the `(Symbol("PauseManager"), Symbol(<action>))` topic
//! prefix.

use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env, IntoVal, Symbol, TryIntoVal, Val, Vec as SVec};

use crate::support::{
    assert_matches_fixture, field, last_event, new_env, sym, EventSchema, SchemaMap,
};

fn topic(env: &Env, action: &str) -> SVec<Val> {
    (Symbol::new(env, "PauseManager"), Symbol::new(env, action)).into_val(env)
}

fn case_initialized(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let operator = Address::generate(env);
    env.as_contract(cid, || {
        payroll_events::emit_pause_manager_initialized(env, operator.clone());
    });
    let (_, topics, data) = last_event(env);
    assert_eq!(
        topics,
        topic(env, "initialized"),
        "pause_manager.initialized topics changed"
    );
    let decoded: (Address,) = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (operator,),
        "pause_manager.initialized payload changed"
    );
    out.insert(
        "pause_manager.initialized".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("PauseManager"), sym("initialized")],
            data: vec![field("operator", "Address")],
        },
    );
}

fn case_paused(env: &Env, cid: &Address, out: &mut SchemaMap) {
    env.as_contract(cid, || {
        payroll_events::emit_paused(env);
    });
    let (_, topics, data) = last_event(env);
    assert_eq!(
        topics,
        topic(env, "paused"),
        "pause_manager.paused topics changed"
    );
    let decoded: () = data.try_into_val(env).unwrap();
    assert_eq!(decoded, (), "pause_manager.paused payload changed");
    out.insert(
        "pause_manager.paused".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("PauseManager"), sym("paused")],
            data: vec![],
        },
    );
}

fn case_unpaused(env: &Env, cid: &Address, out: &mut SchemaMap) {
    env.as_contract(cid, || {
        payroll_events::emit_unpaused(env);
    });
    let (_, topics, data) = last_event(env);
    assert_eq!(
        topics,
        topic(env, "unpaused"),
        "pause_manager.unpaused topics changed"
    );
    let decoded: () = data.try_into_val(env).unwrap();
    assert_eq!(decoded, (), "pause_manager.unpaused payload changed");
    out.insert(
        "pause_manager.unpaused".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("PauseManager"), sym("unpaused")],
            data: vec![],
        },
    );
}

fn case_operator_proposed(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let current = Address::generate(env);
    let new_op = Address::generate(env);
    env.as_contract(cid, || {
        payroll_events::emit_pause_operator_proposed(env, current.clone(), new_op.clone());
    });
    let (_, topics, data) = last_event(env);
    assert_eq!(
        topics,
        topic(env, "op_proposed"),
        "pause_manager.op_proposed topics changed"
    );
    let decoded: (Address, Address) = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (current, new_op),
        "pause_manager.op_proposed payload changed"
    );
    out.insert(
        "pause_manager.op_proposed".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("PauseManager"), sym("op_proposed")],
            data: vec![field("current", "Address"), field("new_op", "Address")],
        },
    );
}

fn case_operator_rotated(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let new_op = Address::generate(env);
    env.as_contract(cid, || {
        payroll_events::emit_pause_operator_rotated(env, new_op.clone());
    });
    let (_, topics, data) = last_event(env);
    assert_eq!(
        topics,
        topic(env, "op_rotated"),
        "pause_manager.op_rotated topics changed"
    );
    let decoded: Address = data.try_into_val(env).unwrap();
    assert_eq!(decoded, new_op, "pause_manager.op_rotated payload changed");
    out.insert(
        "pause_manager.op_rotated".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("PauseManager"), sym("op_rotated")],
            data: vec![field("new_op", "Address")],
        },
    );
}

fn case_operator_cancelled(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let current = Address::generate(env);
    env.as_contract(cid, || {
        payroll_events::emit_pause_operator_cancelled(env, current.clone());
    });
    let (_, topics, data) = last_event(env);
    assert_eq!(
        topics,
        topic(env, "op_cancelled"),
        "pause_manager.op_cancelled topics changed"
    );
    let decoded: Address = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded, current,
        "pause_manager.op_cancelled payload changed"
    );
    out.insert(
        "pause_manager.op_cancelled".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("PauseManager"), sym("op_cancelled")],
            data: vec![field("current", "Address")],
        },
    );
}

#[test]
fn pause_manager_events_match_fixture() {
    let (env, cid) = new_env();
    let mut observed = SchemaMap::new();

    case_initialized(&env, &cid, &mut observed);
    case_paused(&env, &cid, &mut observed);
    case_unpaused(&env, &cid, &mut observed);
    case_operator_proposed(&env, &cid, &mut observed);
    case_operator_rotated(&env, &cid, &mut observed);
    case_operator_cancelled(&env, &cid, &mut observed);

    assert_matches_fixture(
        "pause_manager",
        include_str!("../fixtures/events/pause_manager.json"),
        observed,
    );
}
