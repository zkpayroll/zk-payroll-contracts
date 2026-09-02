use contracts::assets::normalize_asset_symbol;

#[test]
fn tests_lowercase_uppercasing() {
    assert_eq(normalize_asset_symbol("usdc"), "USDC");
}

#[test]
fn tests_whitespace_trimming() {
    assert_eq(normalize_asset_symbol("  eth "), "ETH");
}

#[test]
##should_panic
fn rejects_empty_symbol() {
    normalize_asset_symbol("");
}
