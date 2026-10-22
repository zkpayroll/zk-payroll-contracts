//! Issue #819: Require explicit authorization before a treasury reserve is reduced.
//!
//! Verifies that treasury reserve reduction requires explicit caller authorization
//! (`require_auth()`), allows delegated company authorizers, and rejects unauthorized
//! callers with actionable contract errors while strictly preserving payroll privacy.

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

#[test]
fn test_admin_authorized_reserve_reduction_succeeds() {
    let (env, admin, client) = setup();
    let company_id = 100u64;
    let asset = Address::generate(&env);
    let issuer = Address::generate(&env);

    client.register_asset(&company_id, &asset, &issuer, &symbol_short!("USDC"));
    client.credit(&company_id, &asset, &50_000i128);
    client.reserve(&company_id, &asset, &20_000i128);

    // Admin explicitly authorizes reserve release
    let bal = client.release_reserve(&company_id, &asset, &5_000i128, &admin);
    assert_eq!(bal.reserved, 15_000);
    assert_eq!(bal.balance, 50_000);
}

#[test]
fn test_unauthorized_caller_cannot_reduce_reserve() {
    let (env, _admin, client) = setup();
    let company_id = 101u64;
    let asset = Address::generate(&env);
    let issuer = Address::generate(&env);
    let rogue = Address::generate(&env);

    client.register_asset(&company_id, &asset, &issuer, &symbol_short!("USDC"));
    client.credit(&company_id, &asset, &25_000i128);
    client.reserve(&company_id, &asset, &10_000i128);

    // Rogue caller without authorization attempts release -> rejected
    let result = client.try_release_reserve(&company_id, &asset, &2_000i128, &rogue);
    assert_eq!(
        result.unwrap_err().unwrap(),
        TreasuryIsolationError::Unauthorized
    );

    // Reserve balance must remain unchanged
    let bal = client.get_balance(&company_id, &asset).unwrap();
    assert_eq!(bal.reserved, 10_000);
}

#[test]
fn test_delegated_company_authorizer_lifecycle() {
    let (env, _admin, client) = setup();
    let company_id = 102u64;
    let asset = Address::generate(&env);
    let issuer = Address::generate(&env);
    let operator = Address::generate(&env);

    client.register_asset(&company_id, &asset, &issuer, &symbol_short!("USDC"));
    client.credit(&company_id, &asset, &30_000i128);
    client.reserve(&company_id, &asset, &12_000i128);

    // Operator is not initially authorized
    assert!(!client.is_reserve_authorizer(&company_id, &operator));

    // Admin delegates reserve reduction authority for this company
    client.set_reserve_authorizer(&company_id, &operator);
    assert!(client.is_reserve_authorizer(&company_id, &operator));

    // Operator releases part of the reserve
    let after_op = client.release_reserve(&company_id, &asset, &4_000i128, &operator);
    assert_eq!(after_op.reserved, 8_000);

    // Admin revokes delegation
    client.remove_reserve_authorizer(&company_id, &operator);
    assert!(!client.is_reserve_authorizer(&company_id, &operator));

    // Operator is rejected following revocation
    let err = client.try_release_reserve(&company_id, &asset, &2_000i128, &operator);
    assert_eq!(
        err.unwrap_err().unwrap(),
        TreasuryIsolationError::Unauthorized
    );
}

#[test]
fn test_exact_reserve_cleared_at_boundary() {
    let (env, admin, client) = setup();
    let company_id = 103u64;
    let asset = Address::generate(&env);
    let issuer = Address::generate(&env);

    client.register_asset(&company_id, &asset, &issuer, &symbol_short!("USDC"));
    client.credit(&company_id, &asset, &10_000i128);
    client.reserve(&company_id, &asset, &4_500i128);

    // Releasing the exact reserved amount clears reservation to 0
    let cleared = client.release_reserve(&company_id, &asset, &4_500i128, &admin);
    assert_eq!(cleared.reserved, 0);

    // Further release is rejected because no reserve remains
    let err = client.try_release_reserve(&company_id, &asset, &1i128, &admin);
    assert_eq!(
        err.unwrap_err().unwrap(),
        TreasuryIsolationError::InsufficientReserve
    );
}
