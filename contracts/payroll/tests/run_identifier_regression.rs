//! Regression tests for payroll run identifiers (issue #989).
//!
//! Run ids come from a single persistent counter. These tests pin monotonic
//! derivation, rejection of the reserved sentinel id, and the rule that a
//! rejected duplicate nonce does not consume a new id.

#![cfg(test)]

mod common;

use payroll::PayrollClient;
use soroban_sdk::{Address, Env};

fn prepare_run(client: &PayrollClient<'_>, env: &Env, employee: &Address, marker: u8) -> u64 {
    let (proofs, amounts, employees) = common::one_payment(env, employee);
    client.prepare_payroll_run(
        &proofs,
        &amounts,
        &employees,
        &100i128,
        &common::nonce(env, marker),
        &None,
    )
}

#[test]
fn test_run_ids_increase_monotonically() {
    let env = Env::default();
    let (client, _token, employee) = common::setup(&env);

    assert_eq!(client.get_run_counter(), 0);
    let first = prepare_run(&client, &env, &employee, 1);
    let second = prepare_run(&client, &env, &employee, 2);
    let third = prepare_run(&client, &env, &employee, 3);

    assert_eq!((first, second, third), (1, 2, 3));
    assert_eq!(client.get_run_counter(), 3);
    assert_eq!(client.get_pending_run(&first).unwrap().run_id, first);
    assert_eq!(client.get_pending_run(&third).unwrap().run_id, third);
}

#[test]
fn test_reserved_run_id_is_rejected() {
    let env = Env::default();
    let (client, _token, _employee) = common::setup(&env);

    assert!(client.try_get_payroll_run(&u64::MAX).is_err());
    // The pending-run read is a raw storage lookup and simply misses.
    assert!(client.get_pending_run(&u64::MAX).is_none());

    let admin = client.get_addresses().admin;
    assert!(client.try_finalize_payroll_run(&admin, &u64::MAX).is_err());
}

#[test]
fn test_duplicate_nonce_does_not_consume_a_run_id() {
    let env = Env::default();
    let (client, _token, employee) = common::setup(&env);

    let first = prepare_run(&client, &env, &employee, 7);
    assert_eq!(first, 1);
    assert_eq!(client.get_run_counter(), 1);

    let (proofs, amounts, employees) = common::one_payment(&env, &employee);
    let replay = client.try_prepare_payroll_run(
        &proofs,
        &amounts,
        &employees,
        &100i128,
        &common::nonce(&env, 7),
        &None,
    );
    assert!(replay.is_err(), "duplicate nonce must not create a new run");
    assert_eq!(client.get_run_counter(), 1);
}
