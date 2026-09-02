mod common;

use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env};

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
    assert_eq!(payroll.get_supported_assets().len(), 1);
}
