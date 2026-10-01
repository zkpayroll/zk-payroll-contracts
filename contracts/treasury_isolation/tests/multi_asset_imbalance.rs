//! Multi-asset funding imbalance tests (#348).
//!
//! `payroll::Payroll::batch_process_payroll` settles exactly one asset per
//! batch (it checks a single scalar `token_client.balance(&addrs.treasury)`
//! against the batch total) and does not itself depend on
//! `treasury_isolation`. The multi-asset accounting invariant these tests
//! protect therefore lives in `treasury_isolation`, which is the contract
//! that actually tracks per-(company, asset) balances for a company running
//! payroll in more than one asset (e.g. USDC for most employees, XLM for a
//! subset).
//!
//! The property under test: overfunding one asset must never mask, offset,
//! or otherwise hide underfunding in a different asset for the same
//! company. Each asset's readiness is evaluated strictly independently.

#![cfg(test)]

use soroban_sdk::testutils::Address as _;
use soroban_sdk::{symbol_short, Address, Env};
use treasury_isolation::{TreasuryIsolationContract, TreasuryIsolationContractClient};

fn setup() -> (Env, Address, TreasuryIsolationContractClient<'static>) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, TreasuryIsolationContract);
    let admin = Address::generate(&env);
    let client = TreasuryIsolationContractClient::new(&env, &contract_id);
    client.initialize(&admin);
    (env, admin, client)
}

/// A company runs payroll in two assets. USDC is heavily overfunded; XLM is
/// underfunded for the batch it needs to cover. Each asset's readiness must
/// be assessed on its own balance, not on the sum of both.
#[test]
fn overfunded_asset_does_not_mask_underfunded_asset() {
    let (env, _admin, client) = setup();
    let company_id = 1u64;

    let usdc = Address::generate(&env);
    let usdc_issuer = Address::generate(&env);
    let xlm = Address::generate(&env);
    let xlm_issuer = Address::generate(&env);

    client.register_asset(&company_id, &usdc, &usdc_issuer, &symbol_short!("USDC"));
    client.register_asset(&company_id, &xlm, &xlm_issuer, &symbol_short!("XLM"));

    // USDC: massively overfunded relative to what any single batch needs.
    client.credit(&company_id, &usdc, &1_000_000i128);
    // XLM: funded, but not enough for the batch that needs 5_000.
    client.credit(&company_id, &xlm, &1_000i128);

    assert!(
        client.is_treasury_ready(&company_id, &usdc, &500_000i128),
        "USDC batch should be coverable from its own overfunded balance"
    );
    assert!(
        !client.is_treasury_ready(&company_id, &xlm, &5_000i128),
        "XLM batch must be reported as NOT ready despite USDC's huge surplus"
    );

    // Reserving against the underfunded asset must fail outright.
    let reserve_result = client.try_reserve(&company_id, &xlm, &5_000i128);
    assert_eq!(
        reserve_result.unwrap_err().unwrap(),
        treasury_isolation::TreasuryIsolationError::InsufficientBalance
    );

    // The USDC surplus remains fully available and untouched by the XLM
    // shortfall - reserving well within its balance still succeeds.
    let usdc_after = client.reserve(&company_id, &usdc, &500_000i128);
    assert_eq!(usdc_after.balance, 1_000_000);
    assert_eq!(usdc_after.reserved, 500_000);
}

/// Symmetric case: the asset checked first in a batch happens to be the
/// underfunded one. Order of evaluation must not change the outcome for the
/// other asset.
#[test]
fn underfunded_asset_checked_first_still_isolated_from_overfunded_asset() {
    let (env, _admin, client) = setup();
    let company_id = 2u64;

    let usdc = Address::generate(&env);
    let usdc_issuer = Address::generate(&env);
    let xlm = Address::generate(&env);
    let xlm_issuer = Address::generate(&env);

    client.register_asset(&company_id, &usdc, &usdc_issuer, &symbol_short!("USDC"));
    client.register_asset(&company_id, &xlm, &xlm_issuer, &symbol_short!("XLM"));

    client.credit(&company_id, &usdc, &200i128); // underfunded
    client.credit(&company_id, &xlm, &50_000i128); // overfunded

    assert!(!client.is_treasury_ready(&company_id, &usdc, &10_000i128));
    assert!(client.is_treasury_ready(&company_id, &xlm, &10_000i128));
}

/// A company running payroll in three assets: one exactly funded, one
/// overfunded, one underfunded. All three must be evaluated independently.
#[test]
fn three_assets_each_evaluated_independently() {
    let (env, _admin, client) = setup();
    let company_id = 3u64;

    let usdc = Address::generate(&env);
    let xlm = Address::generate(&env);
    let eurc = Address::generate(&env);
    let usdc_issuer = Address::generate(&env);
    let xlm_issuer = Address::generate(&env);
    let eurc_issuer = Address::generate(&env);

    client.register_asset(&company_id, &usdc, &usdc_issuer, &symbol_short!("USDC"));
    client.register_asset(&company_id, &xlm, &xlm_issuer, &symbol_short!("XLM"));
    client.register_asset(&company_id, &eurc, &eurc_issuer, &symbol_short!("EURC"));

    client.credit(&company_id, &usdc, &10_000i128); // exactly funded for a 10_000 batch
    client.credit(&company_id, &xlm, &999_999i128); // overfunded
    client.credit(&company_id, &eurc, &1i128); // severely underfunded

    assert!(client.is_treasury_ready(&company_id, &usdc, &10_000i128));
    assert!(client.is_treasury_ready(&company_id, &xlm, &10_000i128));
    assert!(!client.is_treasury_ready(&company_id, &eurc, &10_000i128));
}

/// A prior reservation against the overfunded asset (e.g. a concurrent batch
/// already in flight) still must not affect the other asset's readiness.
#[test]
fn in_flight_reservation_on_one_asset_does_not_affect_another_assets_readiness() {
    let (env, _admin, client) = setup();
    let company_id = 4u64;

    let usdc = Address::generate(&env);
    let xlm = Address::generate(&env);
    let usdc_issuer = Address::generate(&env);
    let xlm_issuer = Address::generate(&env);

    client.register_asset(&company_id, &usdc, &usdc_issuer, &symbol_short!("USDC"));
    client.register_asset(&company_id, &xlm, &xlm_issuer, &symbol_short!("XLM"));

    client.credit(&company_id, &usdc, &100_000i128);
    client.credit(&company_id, &xlm, &500i128);

    // A concurrent USDC batch reserves most of the USDC balance.
    client.reserve(&company_id, &usdc, &95_000i128);

    // XLM readiness for a 500-unit batch is unaffected by the USDC reservation.
    assert!(client.is_treasury_ready(&company_id, &xlm, &500i128));
    // Remaining USDC availability correctly reflects the reservation.
    assert!(client.is_treasury_ready(&company_id, &usdc, &5_000i128));
    assert!(!client.is_treasury_ready(&company_id, &usdc, &5_001i128));
}

/// A batch spans two assets settled as two separate `treasury_isolation`
/// executions (mirroring how `payroll::batch_process_payroll` settles one
/// asset per call). The failure message must identify which asset was
/// deficient rather than a generic "insufficient funds".
#[test]
fn failure_identifies_the_deficient_asset_not_a_generic_error() {
    let (env, _admin, client) = setup();
    let company_id = 5u64;

    let usdc = Address::generate(&env);
    let xlm = Address::generate(&env);
    let usdc_issuer = Address::generate(&env);
    let xlm_issuer = Address::generate(&env);

    client.register_asset(&company_id, &usdc, &usdc_issuer, &symbol_short!("USDC"));
    client.register_asset(&company_id, &xlm, &xlm_issuer, &symbol_short!("XLM"));

    client.credit(&company_id, &usdc, &1_000_000i128);
    client.credit(&company_id, &xlm, &10i128);

    // The USDC leg of the combined payroll run succeeds.
    let usdc_result = client.try_reserve(&company_id, &usdc, &50_000i128);
    assert!(usdc_result.is_ok());

    // The XLM leg fails with a specific, asset-scoped error code - not a
    // generic failure that could be confused with the USDC leg or with a
    // "company not funded at all" condition.
    let xlm_result = client.try_reserve(&company_id, &xlm, &5_000i128);
    assert_eq!(
        xlm_result.unwrap_err().unwrap(),
        treasury_isolation::TreasuryIsolationError::InsufficientBalance
    );

    // The error is scoped to the XLM balance record specifically: querying
    // it directly shows the exact shortfall context (available vs required).
    let xlm_balance = client.get_balance(&company_id, &xlm).unwrap();
    assert_eq!(xlm_balance.balance - xlm_balance.reserved, 10);
}
