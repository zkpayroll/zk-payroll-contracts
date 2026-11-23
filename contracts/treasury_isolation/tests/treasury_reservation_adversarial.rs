//! Adversarial treasury reservation cases (#948).
//!
//! These tests attack the per-(company, asset) reservation ledger: invalid
//! amounts, exact boundaries, accumulation, asset isolation, authorization,
//! over-release, and execution debits. They assert both the typed error and
//! that rejected calls leave accounting state unchanged.

#![cfg(test)]

use soroban_sdk::testutils::Address as _;
use soroban_sdk::{symbol_short, Address, Env};
use treasury_isolation::{
    TreasuryIsolationContract, TreasuryIsolationContractClient, TreasuryIsolationError,
};

fn setup() -> (Env, Address, TreasuryIsolationContractClient<'static>) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(TreasuryIsolationContract, ());
    let admin = Address::generate(&env);
    let client = TreasuryIsolationContractClient::new(&env, &contract_id);
    client.initialize(&admin);
    (env, admin, client)
}

fn register_and_fund(
    env: &Env,
    client: &TreasuryIsolationContractClient<'_>,
    company_id: u64,
    amount: i128,
) -> Address {
    let asset = Address::generate(env);
    client.register_asset(
        &company_id,
        &asset,
        &Address::generate(env),
        &symbol_short!("USDC"),
    );
    client.credit(&company_id, &asset, &amount);
    asset
}

#[test]
fn treasury_error_messages_are_actionable_and_privacy_safe() {
    let private_terms = [
        "salary",
        "employee",
        "commitment",
        "proof",
        "nullifier",
        "blinding",
        "recipient",
    ];
    let cases = [
        (TreasuryIsolationError::NotInitialized, 1),
        (TreasuryIsolationError::AssetNotRegistered, 2),
        (TreasuryIsolationError::AssetAlreadyRegistered, 3),
        (TreasuryIsolationError::AssetMismatch, 4),
        (TreasuryIsolationError::InsufficientBalance, 5),
        (TreasuryIsolationError::InsufficientReserve, 6),
        (TreasuryIsolationError::Unauthorized, 7),
        (TreasuryIsolationError::IssuerMismatch, 8),
        (TreasuryIsolationError::InvalidAmount, 9),
    ];

    for (error, code) in cases {
        assert_eq!(error as u32, code);
        let message = error.message();
        assert!(message.ends_with('.'), "recovery step missing: {message}");
        assert!(
            error.code().starts_with("treasury_"),
            "unstable error code: {}",
            error.code()
        );
        for term in private_terms {
            assert!(
                !message.to_lowercase().contains(term),
                "{error:?} message leaks private term '{term}': {message}"
            );
        }
    }
}

#[test]
fn non_positive_amounts_cannot_create_or_reduce_reservations() {
    let (env, admin, client) = setup();
    let company_id = 20;
    let asset = register_and_fund(&env, &client, company_id, 1_000);

    for amount in [0i128, -1i128] {
        assert_eq!(
            client
                .try_reserve(&company_id, &asset, &amount)
                .unwrap_err()
                .unwrap(),
            TreasuryIsolationError::InvalidAmount
        );
        assert_eq!(
            client
                .try_release_reserve(&company_id, &asset, &amount, &admin)
                .unwrap_err()
                .unwrap(),
            TreasuryIsolationError::InvalidAmount
        );
    }

    let balance = client.get_balance(&company_id, &asset).unwrap();
    assert_eq!(balance.balance, 1_000);
    assert_eq!(balance.reserved, 0);
}

#[test]
fn reservations_accumulate_up_to_the_exact_available_boundary() {
    let (env, _admin, client) = setup();
    let company_id = 21;
    let asset = register_and_fund(&env, &client, company_id, 1_000);

    let reserved = client.reserve(&company_id, &asset, &600);
    assert_eq!(reserved.reserved, 600);

    assert_eq!(
        client
            .try_reserve(&company_id, &asset, &401)
            .unwrap_err()
            .unwrap(),
        TreasuryIsolationError::InsufficientBalance
    );

    let full = client.reserve(&company_id, &asset, &400);
    assert_eq!(full.reserved, 1_000);
    assert_eq!(
        client
            .try_reserve(&company_id, &asset, &1)
            .unwrap_err()
            .unwrap(),
        TreasuryIsolationError::InsufficientBalance
    );

    let balance = client.get_balance(&company_id, &asset).unwrap();
    assert_eq!(balance.balance, 1_000);
    assert_eq!(balance.reserved, 1_000);
}

#[test]
fn one_asset_shortfall_cannot_consume_another_assets_availability() {
    let (env, _admin, client) = setup();
    let company_id = 22;
    let primary = register_and_fund(&env, &client, company_id, 10_000);
    let secondary = register_and_fund(&env, &client, company_id, 100);

    let reserved = client.reserve(&company_id, &primary, &10_000);
    assert_eq!(reserved.reserved, 10_000);

    assert_eq!(
        client
            .try_reserve(&company_id, &secondary, &101)
            .unwrap_err()
            .unwrap(),
        TreasuryIsolationError::InsufficientBalance
    );
    assert!(client.is_treasury_ready(&company_id, &secondary, &100));
    assert!(!client.is_treasury_ready(&company_id, &primary, &1));
    assert_eq!(
        client
            .get_balance(&company_id, &secondary)
            .unwrap()
            .reserved,
        0
    );
}

#[test]
fn unauthorized_release_and_revoked_delegation_cannot_reduce_a_reserve() {
    let (env, _admin, client) = setup();
    let company_id = 23;
    let asset = register_and_fund(&env, &client, company_id, 5_000);
    let operator = Address::generate(&env);
    let rogue = Address::generate(&env);
    client.reserve(&company_id, &asset, &2_000);

    assert_eq!(
        client
            .try_release_reserve(&company_id, &asset, &100, &rogue)
            .unwrap_err()
            .unwrap(),
        TreasuryIsolationError::Unauthorized
    );

    client.set_reserve_authorizer(&company_id, &operator);
    let released = client.release_reserve(&company_id, &asset, &500, &operator);
    assert_eq!(released.reserved, 1_500);

    client.remove_reserve_authorizer(&company_id, &operator);
    assert_eq!(
        client
            .try_release_reserve(&company_id, &asset, &100, &operator)
            .unwrap_err()
            .unwrap(),
        TreasuryIsolationError::Unauthorized
    );
    assert_eq!(
        client.get_balance(&company_id, &asset).unwrap().reserved,
        1_500
    );
}

#[test]
fn release_above_reserved_is_rejected_without_underflow() {
    let (env, admin, client) = setup();
    let company_id = 24;
    let asset = register_and_fund(&env, &client, company_id, 5_000);
    client.reserve(&company_id, &asset, &500);

    assert_eq!(
        client
            .try_release_reserve(&company_id, &asset, &501, &admin)
            .unwrap_err()
            .unwrap(),
        TreasuryIsolationError::InsufficientReserve
    );
    assert_eq!(
        client.get_balance(&company_id, &asset).unwrap().reserved,
        500
    );

    assert_eq!(
        client
            .release_reserve(&company_id, &asset, &500, &admin)
            .reserved,
        0
    );
    assert_eq!(
        client
            .try_release_reserve(&company_id, &asset, &1, &admin)
            .unwrap_err()
            .unwrap(),
        TreasuryIsolationError::InsufficientReserve
    );
}

#[test]
fn execute_debit_rejects_mismatched_asset_without_touching_reservations() {
    let (env, _admin, client) = setup();
    let company_id = 25;
    let asset = register_and_fund(&env, &client, company_id, 5_000);
    let other_asset = Address::generate(&env);
    client.reserve(&company_id, &asset, &1_000);

    assert_eq!(
        client
            .try_execute_debit(&company_id, &other_asset, &asset, &1_000)
            .unwrap_err()
            .unwrap(),
        TreasuryIsolationError::AssetMismatch
    );

    let balance = client.get_balance(&company_id, &asset).unwrap();
    assert_eq!(balance.balance, 5_000);
    assert_eq!(balance.reserved, 1_000);

    let debited = client.execute_debit(&company_id, &asset, &asset, &1_000);
    assert_eq!(debited.balance, 4_000);
    assert_eq!(debited.reserved, 0);
}

#[test]
fn execute_debit_cannot_spend_unreserved_or_missing_balance() {
    let (env, _admin, client) = setup();
    let company_id = 26;
    let asset = register_and_fund(&env, &client, company_id, 1_000);

    assert_eq!(
        client
            .try_execute_debit(&company_id, &asset, &asset, &1)
            .unwrap_err()
            .unwrap(),
        TreasuryIsolationError::InsufficientReserve
    );

    client.reserve(&company_id, &asset, &400);
    assert_eq!(
        client
            .try_execute_debit(&company_id, &asset, &asset, &401)
            .unwrap_err()
            .unwrap(),
        TreasuryIsolationError::InsufficientReserve
    );
    assert_eq!(
        client
            .try_execute_debit(&company_id, &asset, &asset, &1_001)
            .unwrap_err()
            .unwrap(),
        TreasuryIsolationError::InsufficientBalance
    );

    let balance = client.get_balance(&company_id, &asset).unwrap();
    assert_eq!(balance.balance, 1_000);
    assert_eq!(balance.reserved, 400);
}
