//! Issue #787: Contract fallback funding source simulation.
//!
//! Verifies that payroll funding source readiness can simulate primary and fallback
//! funding sources without state mutation or sensitive payroll data exposure.

#![cfg(test)]

mod common;

use payroll::{FundingSourceBlocker, FundingSourceChoice};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env};
use token::TokenClient;

#[test]
fn primary_source_ready_selects_primary_without_evaluating_fallback() {
    let env = Env::default();
    let (client, _token, _employee) = common::setup(&env);

    let result = client.simulate_funding_fallback(&500_000);
    assert!(result.success);
    assert_eq!(result.selected_source, FundingSourceChoice::Primary);
    assert!(!result.fallback_evaluated);
    assert!(result.primary.ready);
    assert_eq!(result.primary.blocker, FundingSourceBlocker::NotBlocked);
}

#[test]
fn primary_insufficient_selects_configured_fallback_when_funded() {
    let env = Env::default();
    let (client, token, _employee) = common::setup(&env);
    let admin = client.get_addresses().admin;

    // Create a secondary reserve treasury for fallback with canonical token
    let fallback_treasury = Address::generate(&env);
    TokenClient::new(&env, &token).mint(&fallback_treasury, &5_000_000);

    // Configure fallback funding source
    client.set_fallback_funding_source(&admin, &fallback_treasury, &token);

    // Primary has 1,000,000; require 2,000,000 -> primary fails, fallback covers it
    let result = client.simulate_funding_fallback(&2_000_000);
    assert!(result.success);
    assert_eq!(result.selected_source, FundingSourceChoice::Fallback);
    assert!(result.fallback_evaluated);
    assert!(!result.primary.ready);
    assert_eq!(
        result.primary.blocker,
        FundingSourceBlocker::InsufficientFunds
    );

    let fallback_readiness = result.fallback;
    assert!(fallback_readiness.ready);
    assert_eq!(fallback_readiness.blocker, FundingSourceBlocker::NotBlocked);
    assert_eq!(fallback_readiness.available_balance, Some(5_000_000));
}

#[test]
fn primary_and_fallback_both_insufficient_reports_failure() {
    let env = Env::default();
    let (client, token, _employee) = common::setup(&env);
    let admin = client.get_addresses().admin;

    let fallback_treasury = Address::generate(&env);
    TokenClient::new(&env, &token).mint(&fallback_treasury, &500_000);

    client.set_fallback_funding_source(&admin, &fallback_treasury, &token);

    // Primary has 1,000,000, fallback has 500,000, require 3,000,000 -> both insufficient
    let result = client.simulate_funding_fallback(&3_000_000);
    assert!(!result.success);
    assert_eq!(result.selected_source, FundingSourceChoice::None);
    assert!(result.fallback_evaluated);
    assert!(!result.primary.ready);
    assert_eq!(
        result.primary.blocker,
        FundingSourceBlocker::InsufficientFunds
    );

    let fallback_readiness = result.fallback;
    assert!(!fallback_readiness.ready);
    assert_eq!(
        fallback_readiness.blocker,
        FundingSourceBlocker::InsufficientFunds
    );
    assert_eq!(fallback_readiness.available_balance, Some(500_000));
}

#[test]
fn primary_insufficient_with_no_fallback_configured_fails_gracefully() {
    let env = Env::default();
    let (client, _token, _employee) = common::setup(&env);

    // Require 2,000,000 when primary has 1,000,000 and no fallback configured
    let result = client.simulate_funding_fallback(&2_000_000);
    assert!(!result.success);
    assert_eq!(result.selected_source, FundingSourceChoice::None);
    assert!(!result.fallback_evaluated);
    assert!(!result.primary.ready);
    assert_eq!(
        result.primary.blocker,
        FundingSourceBlocker::InsufficientFunds
    );
}

#[test]
fn fallback_asset_not_allowed_is_detected() {
    let env = Env::default();
    let (client, _token, _employee) = common::setup(&env);
    let admin = client.get_addresses().admin;

    let unallowed_token = Address::generate(&env);
    let fallback_treasury = Address::generate(&env);

    // Configure fallback with unallowed asset
    client.set_fallback_funding_source(&admin, &fallback_treasury, &unallowed_token);

    let result = client.simulate_funding_fallback(&2_000_000);
    assert!(!result.success);
    assert_eq!(result.selected_source, FundingSourceChoice::None);
    assert!(result.fallback_evaluated);

    let fb = result.fallback;
    assert!(!fb.ready);
    assert_eq!(fb.blocker, FundingSourceBlocker::AssetNotAllowed);
}

#[test]
fn explicit_fallback_simulation_evaluates_candidate_without_storage_mutation() {
    let env = Env::default();
    let (client, token, _employee) = common::setup(&env);

    let candidate_treasury = Address::generate(&env);
    TokenClient::new(&env, &token).mint(&candidate_treasury, &4_000_000);

    // Fallback is NOT configured on-chain
    assert_eq!(client.get_fallback_funding_source(), None);

    // Simulate explicit candidate
    let result = client.simulate_explicit_fallback(&2_500_000, &candidate_treasury, &token);
    assert!(result.success);
    assert_eq!(result.selected_source, FundingSourceChoice::Fallback);
    assert!(result.fallback_evaluated);

    // Storage remains untouched
    assert_eq!(client.get_fallback_funding_source(), None);
}

#[test]
fn fallback_configuration_lifecycle() {
    let env = Env::default();
    let (client, token, _employee) = common::setup(&env);
    let admin = client.get_addresses().admin;

    assert_eq!(client.get_fallback_funding_source(), None);

    let fb_treasury = Address::generate(&env);
    client.set_fallback_funding_source(&admin, &fb_treasury, &token);

    let stored = client
        .get_fallback_funding_source()
        .expect("must be stored");
    assert_eq!(stored.treasury, fb_treasury);
    assert_eq!(stored.token, token);

    client.remove_fallback_funding_source(&admin);
    assert_eq!(client.get_fallback_funding_source(), None);
}
