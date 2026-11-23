//! Treasury balances stay isolated when a debit fails (#873).
//!
//! A rejected `execute_debit` must leave the target company's asset untouched,
//! and must not change any other company or asset.

extern crate std;

use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{symbol_short, Address, Env};

fn setup() -> (Env, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(TreasuryIsolationContract, ());
    let admin = Address::generate(&env);
    TreasuryIsolationContractClient::new(&env, &contract_id).initialize(&admin);
    (env, contract_id)
}

/// Company 1 holds 100 of asset A (60 reserved) and 70 of asset B.
/// Company 2 holds 50 of asset A. Returns the asset addresses (a, b).
fn seed(env: &Env, contract_id: &Address) -> (Address, Address) {
    let client = TreasuryIsolationContractClient::new(env, contract_id);
    let issuer = Address::generate(env);
    let asset_a = Address::generate(env);
    let asset_b = Address::generate(env);

    client.register_asset(&1u64, &asset_a, &issuer, &symbol_short!("AAA"));
    client.register_asset(&1u64, &asset_b, &issuer, &symbol_short!("BBB"));
    client.register_asset(&2u64, &asset_a, &issuer, &symbol_short!("AAA"));

    client.credit(&1u64, &asset_a, &100i128);
    client.reserve(&1u64, &asset_a, &60i128);
    client.credit(&1u64, &asset_b, &70i128);
    client.credit(&2u64, &asset_a, &50i128);
    (asset_a, asset_b)
}

#[test]
fn failed_debit_leaves_company_and_other_balances_unchanged() {
    let (env, contract_id) = setup();
    let (asset_a, asset_b) = seed(&env, &contract_id);
    let client = TreasuryIsolationContractClient::new(&env, &contract_id);

    // 80 is within the 100 balance but exceeds the 60 reserved: rejected.
    let result = client.try_execute_debit(&1u64, &asset_a, &asset_a, &80i128);
    assert!(result.is_err());

    let a1 = client.get_balance(&1u64, &asset_a).unwrap();
    assert_eq!((a1.balance, a1.reserved), (100, 60));
    let b1 = client.get_balance(&1u64, &asset_b).unwrap();
    assert_eq!((b1.balance, b1.reserved), (70, 0));
    let a2 = client.get_balance(&2u64, &asset_a).unwrap();
    assert_eq!((a2.balance, a2.reserved), (50, 0));
}

#[test]
fn asset_mismatch_rejected_without_touching_any_balance() {
    let (env, contract_id) = setup();
    let (asset_a, asset_b) = seed(&env, &contract_id);
    let client = TreasuryIsolationContractClient::new(&env, &contract_id);

    let result = client.try_execute_debit(&1u64, &asset_a, &asset_b, &10i128);
    assert_eq!(
        result.unwrap_err().unwrap(),
        TreasuryIsolationError::AssetMismatch
    );

    let a1 = client.get_balance(&1u64, &asset_a).unwrap();
    assert_eq!((a1.balance, a1.reserved), (100, 60));
    let b1 = client.get_balance(&1u64, &asset_b).unwrap();
    assert_eq!((b1.balance, b1.reserved), (70, 0));
}

#[test]
fn debit_of_exactly_the_reserved_amount_succeeds_and_only_touches_that_company() {
    let (env, contract_id) = setup();
    let (asset_a, asset_b) = seed(&env, &contract_id);
    let client = TreasuryIsolationContractClient::new(&env, &contract_id);

    client.execute_debit(&1u64, &asset_a, &asset_a, &60i128);

    let a1 = client.get_balance(&1u64, &asset_a).unwrap();
    assert_eq!((a1.balance, a1.reserved), (40, 0));
    let b1 = client.get_balance(&1u64, &asset_b).unwrap();
    assert_eq!((b1.balance, b1.reserved), (70, 0));
    let a2 = client.get_balance(&2u64, &asset_a).unwrap();
    assert_eq!((a2.balance, a2.reserved), (50, 0));
}
