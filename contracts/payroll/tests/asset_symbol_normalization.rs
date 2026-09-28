#![cfg(test)]

mod common;

#[test]
fn normalizes_asset_symbols_before_use() {
    assert_eq!(
        common::normalize_asset_symbol("  usdc  "),
        Ok("USDC".to_string())
    );
}

#[test]
fn rejects_asset_symbols_that_cannot_be_normalized() {
    assert_eq!(
        common::normalize_asset_symbol("usdc-"),
        Err("asset symbol must contain only alphanumeric characters")
    );
}
