//! Contract payment asset compatibility validation (#646).

#![cfg(test)]

mod common;

use payroll::{PaymentAssetCompatibilityError, Payroll, PayrollClient};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

/// Implements the balance interface required by initialization, but has no decimals method.
#[contract]
struct BalanceOnlyToken;

#[contractimpl]
impl BalanceOnlyToken {
    pub fn balance(_env: Env, _owner: Address) -> i128 {
        1_000_000
    }
}

fn prepare(env: &Env, client: &PayrollClient, employee: &Address, marker: u8) -> Option<u64> {
    let (proofs, amounts, employees) = common::one_payment(env, employee);
    match client.try_prepare_payroll_run(
        &proofs,
        &amounts,
        &employees,
        &100,
        &common::nonce(env, marker),
        &None,
    ) {
        Ok(Ok(run_id)) => Some(run_id),
        _ => None,
    }
}

/// Payroll initialized against a Stellar Asset Contract, which reports
/// seven decimals.
fn setup_with_sac(env: &Env) -> (PayrollClient<'_>, Address, Address) {
    env.mock_all_auths();
    let sac = env
        .register_stellar_asset_contract_v2(Address::generate(env))
        .address();
    let contract = env.register(Payroll, ());
    let client = PayrollClient::new(env, &contract);
    let admin = Address::generate(env);
    client.initialize(
        &admin,
        &sac,
        &Address::generate(env),
        &Address::generate(env),
        &Address::generate(env),
        &Address::generate(env),
    );
    (client, admin, sac)
}

#[test]
fn canonical_allowed_asset_is_compatible_without_a_precision_pin() {
    let env = Env::default();
    let (client, token, _employee) = common::setup(&env);

    let result = client.check_payment_asset_compat(&token, &500);
    assert_eq!(result.asset, token);
    assert_eq!(result.amount, 500);
    assert_eq!(result.expected_decimals, None);
    assert_eq!(result.asset_decimals, None);
    assert_eq!(client.get_payment_asset_decimals(), None);
}

#[test]
fn pinned_precision_matching_the_token_is_compatible() {
    let env = Env::default();
    let (client, admin, sac) = setup_with_sac(&env);

    client.set_payment_asset_decimals(&admin, &7);
    assert_eq!(client.get_payment_asset_decimals(), Some(7));

    let result = client.check_payment_asset_compat(&sac, &1);
    assert_eq!(result.expected_decimals, Some(7));
    assert_eq!(result.asset_decimals, Some(7));
}

#[test]
fn pinned_precision_mismatch_is_rejected() {
    let env = Env::default();
    let (client, admin, sac) = setup_with_sac(&env);

    client.set_payment_asset_decimals(&admin, &6);
    assert_eq!(
        client.try_check_payment_asset_compat(&sac, &1),
        Err(Ok(PaymentAssetCompatibilityError::DecimalsMismatch))
    );
}

#[test]
fn foreign_asset_is_rejected() {
    let env = Env::default();
    let (client, _token, _employee) = common::setup(&env);

    assert_eq!(
        client.try_check_payment_asset_compat(&Address::generate(&env), &100),
        Err(Ok(PaymentAssetCompatibilityError::ForeignAsset))
    );
}

#[test]
fn disallowed_and_deprecated_assets_are_rejected_with_distinct_errors() {
    let env = Env::default();
    let (client, token, _employee) = common::setup(&env);

    client.deprecate_asset(&token);
    assert_eq!(
        client.try_check_payment_asset_compat(&token, &100),
        Err(Ok(PaymentAssetCompatibilityError::AssetDeprecated))
    );

    client.undeprecate_asset(&token);
    client.set_asset_allowed(&token, &false);
    assert_eq!(
        client.try_check_payment_asset_compat(&token, &100),
        Err(Ok(PaymentAssetCompatibilityError::AssetNotAllowed))
    );
}

#[test]
fn non_positive_amounts_are_rejected() {
    let env = Env::default();
    let (client, token, _employee) = common::setup(&env);

    assert_eq!(
        client.try_check_payment_asset_compat(&token, &0),
        Err(Ok(PaymentAssetCompatibilityError::NonPositiveAmount))
    );
    assert_eq!(
        client.try_check_payment_asset_compat(&token, &-1),
        Err(Ok(PaymentAssetCompatibilityError::NonPositiveAmount))
    );
}

#[test]
fn uninitialized_contract_reports_not_initialized() {
    let env = Env::default();
    let contract = env.register(Payroll, ());
    let client = PayrollClient::new(&env, &contract);

    assert_eq!(
        client.try_check_payment_asset_compat(&Address::generate(&env), &1),
        Err(Ok(PaymentAssetCompatibilityError::NotInitialized))
    );
}

#[test]
fn only_the_admin_can_pin_precision_and_it_is_range_checked() {
    let env = Env::default();
    let (client, _token, _employee) = common::setup(&env);
    let admin = client.get_addresses().admin;

    assert_eq!(
        client.try_set_payment_asset_decimals(&Address::generate(&env), &7),
        Err(Ok(PaymentAssetCompatibilityError::Unauthorized))
    );
    assert_eq!(
        client.try_set_payment_asset_decimals(&admin, &19),
        Err(Ok(PaymentAssetCompatibilityError::InvalidDecimals))
    );
    assert_eq!(client.get_payment_asset_decimals(), None);

    // The upper bound itself is accepted.
    client.set_payment_asset_decimals(&admin, &18);
    assert_eq!(client.get_payment_asset_decimals(), Some(18));
    client.clear_payment_asset_decimals(&admin);
    assert_eq!(client.get_payment_asset_decimals(), None);
}

#[test]
fn token_without_decimals_is_unreachable_once_precision_is_pinned() {
    let env = Env::default();
    let (client, token, employee) = common::setup(&env);
    let admin = client.get_addresses().admin;

    // Replace the normal seven-decimal fixture with one that really lacks decimals.
    env.register_at(&token, BalanceOnlyToken, ());
    client.set_payment_asset_decimals(&admin, &7);
    assert_eq!(
        client.try_check_payment_asset_compat(&token, &100),
        Err(Ok(PaymentAssetCompatibilityError::AssetUnreachable))
    );

    // Run preparation enforces the same pin, and clearing it restores the
    // original flow.
    assert!(prepare(&env, &client, &employee, 1).is_none());
    client.clear_payment_asset_decimals(&admin);
    let run_id = prepare(&env, &client, &employee, 2).expect("prepare after clearing pin");
    client.cancel_payroll_run(&admin, &run_id, &Symbol::new(&env, "test"));
}
