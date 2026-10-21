//! Payment asset deprecation (#708).
//!
//! Deprecating the payment asset stops *new* commitments (`deposit`,
//! `prepare_payroll_run`) while runs prepared beforehand still settle,
//! cancel, and release their reservation.

#![cfg(test)]

mod common;

use payroll::PayrollClient;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env, Symbol};

fn prepare(env: &Env, client: &PayrollClient, employee: &Address, marker: u8) -> u64 {
    let (proofs, amounts, employees) = common::one_payment(env, employee);
    client.prepare_payroll_run(
        &proofs,
        &amounts,
        &employees,
        &100,
        &common::nonce(env, marker),
        &None,
    )
}

#[test]
fn admin_deprecates_and_reads_back() {
    let env = Env::default();
    let (client, token, _employee) = common::setup(&env);

    assert!(!client.is_asset_deprecated(&token));
    client.deprecate_asset(&token);
    assert!(client.is_asset_deprecated(&token));
    // Deprecation is not removal: the asset stays allowed and listed.
    assert!(client.is_asset_allowed(&token));
    assert_eq!(client.get_supported_assets().len(), 1);

    client.undeprecate_asset(&token);
    assert!(!client.is_asset_deprecated(&token));
}

#[test]
fn deprecation_bumps_the_config_revision() {
    let env = Env::default();
    let (client, token, _employee) = common::setup(&env);

    let before = client.get_config_revision();
    client.deprecate_asset(&token);
    assert_eq!(client.get_config_revision(), before + 1);
}

#[test]
fn non_admin_cannot_deprecate() {
    let env = Env::default();
    let (client, token, _employee) = common::setup(&env);
    let admin = client.get_addresses().admin;

    // Authorize nobody: the admin's `require_auth` must fail.
    env.set_auths(&[]);
    assert!(client.try_deprecate_asset(&token).is_err());
    assert!(client.try_undeprecate_asset(&token).is_err());
    assert!(!client.is_asset_deprecated(&token));
}

#[test]
#[should_panic(expected = "Cross-asset treasury mismatch")]
fn foreign_asset_cannot_be_deprecated() {
    let env = Env::default();
    let (client, _token, _employee) = common::setup(&env);

    client.deprecate_asset(&Address::generate(&env));
}

#[test]
#[should_panic(expected = "Asset deprecated")]
fn deposit_on_a_deprecated_asset_panics() {
    let env = Env::default();
    let (client, token, _employee) = common::setup(&env);

    client.deprecate_asset(&token);
    client.deposit(&Address::generate(&env), &100, &common::nonce(&env, 9));
}

#[test]
#[should_panic(expected = "Asset deprecated")]
fn prepare_on_a_deprecated_asset_panics() {
    let env = Env::default();
    let (client, token, employee) = common::setup(&env);

    client.deprecate_asset(&token);
    prepare(&env, &client, &employee, 1);
}

#[test]
fn new_commitments_resume_after_undeprecate() {
    let env = Env::default();
    let (client, token, employee) = common::setup(&env);

    client.deprecate_asset(&token);
    client.undeprecate_asset(&token);
    let run_id = prepare(&env, &client, &employee, 1);

    assert!(client.get_pending_run(&run_id).is_some());
}

#[test]
fn run_prepared_before_deprecation_can_be_cancelled_and_released() {
    let env = Env::default();
    let (client, token, employee) = common::setup(&env);
    let admin = client.get_addresses().admin;

    let run_id = prepare(&env, &client, &employee, 1);
    assert_eq!(client.get_locked_funds(&token), 100);

    client.deprecate_asset(&token);
    client.cancel_payroll_run(&admin, &run_id, &Symbol::new(&env, "deprecated"));

    assert_eq!(client.get_locked_funds(&token), 0);
}

#[test]
fn run_prepared_before_deprecation_still_settles() {
    let env = Env::default();
    let (client, token, employee) = common::setup(&env);
    let admin = client.get_addresses().admin;

    let run_id = prepare(&env, &client, &employee, 1);
    client.deprecate_asset(&token);
    client.finalize_payroll_run(&admin, &run_id);

    assert_eq!(client.get_locked_funds(&token), 0);
}

#[test]
fn batch_process_still_works_on_a_deprecated_asset() {
    let env = Env::default();
    let (client, token, employee) = common::setup(&env);
    let source = common::authorized_source(&env, &client);

    client.deprecate_asset(&token);
    let (proofs, amounts, employees) = common::one_payment(&env, &employee);
    client.batch_process_payroll(
        &proofs,
        &amounts,
        &employees,
        &100,
        &common::nonce(&env, 2),
        &None,
        &source,
    );
}

#[test]
fn double_deprecate_is_idempotent() {
    let env = Env::default();
    let (client, token, _employee) = common::setup(&env);

    client.deprecate_asset(&token);
    client.deprecate_asset(&token);
    assert!(client.is_asset_deprecated(&token));

    client.undeprecate_asset(&token);
    client.undeprecate_asset(&token);
    assert!(!client.is_asset_deprecated(&token));
}

#[test]
fn deprecation_is_allowed_while_a_run_is_active() {
    let env = Env::default();
    let (client, token, employee) = common::setup(&env);

    prepare(&env, &client, &employee, 1);
    // `set_asset_allowed` is locked mid-run; deprecation must not be.
    assert!(client.try_set_asset_allowed(&token, &false).is_err());
    client.deprecate_asset(&token);
    assert!(client.is_asset_deprecated(&token));
}
