mod common;

use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env, Symbol};

#[test]
fn supported_assets_tracks_additions_removals_and_duplicate_updates() {
    let env = Env::default();
    let (payroll, default_asset, _) = common::setup(&env);
    let second_asset = Address::generate(&env);

    let initial = payroll.get_supported_assets();
    assert_eq!(initial.len(), 1);
    assert_eq!(initial.get(0).unwrap(), default_asset.clone());

    payroll.set_asset_allowed(&second_asset, &true);
    payroll.set_asset_allowed(&second_asset, &true);
    let supported = payroll.get_supported_assets();
    assert_eq!(supported.len(), 2);
    assert_eq!(supported.get(0).unwrap(), default_asset);
    assert_eq!(supported.get(1).unwrap(), second_asset.clone());

    payroll.set_asset_allowed(&second_asset, &false);
    assert!(!payroll.is_asset_allowed(&second_asset));
    assert_eq!(payroll.get_supported_assets().len(_), 1);
}

#[test]
fn asset_symbol_normalization_applies_when_checking_allowlist() {
    let env = Env::default();
    let (payroll, _, _) = common::setup(&env);

    let lowercase = Symbol::new(&env, "usdc");
    let uppercase = Symbol::new(&env, "USDC");
    let mixed = Symbol::new(&env, "Usdc");

    payroll.set_asset_allowed_by_symbol(&lowercase, &true);

    assert!(payroll.is_asset_allowed_by_symbol(&lowercase));
    assert!(payroll.is_asset_allowed_by_symbol(&uppercase));
    assert!(payroll.is_asset_allowed_by_symbol(&mixed));
}

#[test]
fn asset_symbol_normalization_rejects_unapproved_symbols() {
    let env = Env::default();
    let (payroll, _, _) = common::setup(&env);

    let unapproved = Symbol::new(&env, "eth");
    assert!(!payroll.is_asset_allowed_by_symbol(&unapproved));
}

#[test]
fn asset_symbol_normalization_trims_whitespace() {
    let env = Env::default();
    let (payroll, _, _) = common::setup(&env);

    let whitespace = Symbol::new(&env, "  usdc  ");
    let canonical = Symbol::new(&env, "USDC");

    payroll.set_asset_allowed_by_symbol(&canonical, &true);

    assert!(payroll.is_asset_allowed_by_symbol(&whitespace));
}