//! Read-only contract funding source readiness checks (#605).

#![cfg(test)]

mod common;

use payroll::{FundingSourceBlocker, Payroll, PayrollClient};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env};

#[test]
fn configured_funded_source_is_ready_for_exact_available_amount() {
    let env = Env::default();
    let (client, _token, _employee) = common::setup(&env);

    let result = client.check_funding_source_readiness(&1_000_000);
    assert!(result.ready);
    assert_eq!(result.blocker, FundingSourceBlocker::NotBlocked);
    assert_eq!(result.required_amount, 1_000_000);
    assert_eq!(result.available_balance, Some(1_000_000));
}

#[test]
fn insufficient_funds_returns_available_balance_and_blocker() {
    let env = Env::default();
    let (client, _token, _employee) = common::setup(&env);

    let result = client.check_funding_source_readiness(&1_000_001);
    assert!(!result.ready);
    assert_eq!(result.blocker, FundingSourceBlocker::InsufficientFunds);
    assert_eq!(result.available_balance, Some(1_000_000));
}

#[test]
fn readiness_uses_balance_after_pending_run_reservations() {
    let env = Env::default();
    let (client, _token, employee) = common::setup(&env);
    let (proofs, amounts, employees) = common::one_payment(&env, &employee);
    client.prepare_payroll_run(
        &proofs,
        &amounts,
        &employees,
        &100,
        &common::nonce(&env, 91),
        &None,
    );

    let result = client.check_funding_source_readiness(&1_000_000);
    assert!(!result.ready);
    assert_eq!(result.blocker, FundingSourceBlocker::InsufficientFunds);
    assert_eq!(result.available_balance, Some(999_900));
}

#[test]
fn non_positive_required_amount_is_rejected() {
    let env = Env::default();
    let (client, _token, _employee) = common::setup(&env);

    for amount in [0, -1] {
        let result = client.check_funding_source_readiness(&amount);
        assert!(!result.ready);
        assert_eq!(result.blocker, FundingSourceBlocker::InvalidRequiredAmount);
        assert_eq!(result.available_balance, None);
    }
}

#[test]
fn uninitialized_payroll_reports_missing_funding_configuration() {
    let env = Env::default();
    let contract_id = env.register_contract(None, Payroll);
    let client = PayrollClient::new(&env, &contract_id);

    let result = client.check_funding_source_readiness(&100);
    assert!(!result.ready);
    assert_eq!(result.blocker, FundingSourceBlocker::NotInitialized);
    assert_eq!(result.available_balance, None);
}

#[test]
fn deactivated_asset_is_reported_without_reading_balance() {
    let env = Env::default();
    let (client, token, _employee) = common::setup(&env);
    client.set_asset_allowed(&token, &false);

    let result = client.check_funding_source_readiness(&100);
    assert!(!result.ready);
    assert_eq!(result.blocker, FundingSourceBlocker::AssetNotAllowed);
    assert_eq!(result.available_balance, None);
}

#[test]
fn unavailable_token_contract_is_reported_cleanly() {
    let env = Env::default();
    let (existing, _token, _employee) = common::setup(&env);
    let existing_addresses = existing.get_addresses();
    let missing_token = Address::generate(&env);
    let payroll_id = env.register_contract(None, Payroll);
    let client = PayrollClient::new(&env, &payroll_id);

    client.initialize(
        &existing_addresses.admin,
        &missing_token,
        &existing_addresses.verifier,
        &existing_addresses.commitment,
        &existing_addresses.treasury,
        &existing_addresses.treasury_owner,
    );

    let result = client.check_funding_source_readiness(&100);
    assert!(!result.ready);
    assert_eq!(result.blocker, FundingSourceBlocker::TokenUnavailable);
    assert_eq!(result.available_balance, None);
}

#[test]
#[should_panic(expected = "Configured payroll asset is unavailable or does not implement the token balance interface")]
fn initialization_rejects_unavailable_asset_contract() {
    let env = Env::default();
    let (existing, _token, _employee) = common::setup(&env);
    let addresses = existing.get_addresses();
    let unavailable_asset = Address::generate(&env);
    let payroll_id = env.register_contract(None, Payroll);
    let client = PayrollClient::new(&env, &payroll_id);

    client.initialize(
        &addresses.admin,
        &unavailable_asset,
        &addresses.verifier,
        &addresses.commitment,
        &addresses.treasury,
        &addresses.treasury_owner,
    );
}

#[test]
#[should_panic(expected = "Configured payroll asset is unavailable or does not implement the token balance interface")]
fn initialization_rejects_contract_without_token_balance_interface() {
    let env = Env::default();
    let (existing, _token, _employee) = common::setup(&env);
    let addresses = existing.get_addresses();
    let payroll_id = env.register_contract(None, Payroll);
    let client = PayrollClient::new(&env, &payroll_id);

    client.initialize(
        &addresses.admin,
        &payroll_id,
        &addresses.verifier,
        &addresses.commitment,
        &addresses.treasury,
        &addresses.treasury_owner,
    );
}
