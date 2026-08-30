//! `de_*` — Deployment wiring validation tests for the `payment_executor`
//! contract.

use crate::helpers::{deploy_contracts, valid_executor_params};
use payment_executor::{DeploymentError, PaymentExecutorClient};
use soroban_sdk::Env;

/// Valid wiring initializes cleanly; the initial supported asset is
/// allowlisted and the storage schema version is stamped.
#[test]
fn de_initialize_with_valid_params_succeeds() {
    let env = Env::default();
    env.mock_all_auths();
    let f = deploy_contracts(&env);
    let client = PaymentExecutorClient::new(&env, &f.executor_id);

    let result = client.try_initialize(&valid_executor_params(&f));
    assert!(result.is_ok());

    assert!(client.is_asset_allowed(&f.token));
    assert!(!client.is_asset_allowed(&f.registry));
    assert_eq!(client.get_storage_version(), 1);
}

/// Reusing one contract ID for two dependency roles is rejected — the classic
/// copy/paste deployment mistake.
#[test]
fn de_rejects_duplicate_dependency_addresses() {
    let env = Env::default();
    env.mock_all_auths();
    let f = deploy_contracts(&env);
    let client = PaymentExecutorClient::new(&env, &f.executor_id);

    // registry == token
    let mut params = valid_executor_params(&f);
    params.registry = params.token.clone();
    let result = client.try_initialize(&params);
    assert_eq!(
        result.unwrap_err().unwrap(),
        DeploymentError::DuplicateDependency
    );

    // verifier == commitment
    let f2 = deploy_contracts(&env);
    let client2 = PaymentExecutorClient::new(&env, &f2.executor_id);
    let mut params2 = valid_executor_params(&f2);
    params2.verifier = params2.commitment.clone();
    let result = client2.try_initialize(&params2);
    assert_eq!(
        result.unwrap_err().unwrap(),
        DeploymentError::DuplicateDependency
    );
}

/// A dependency address pointing at the executor itself is rejected.
#[test]
fn de_rejects_self_reference() {
    let env = Env::default();
    env.mock_all_auths();
    let f = deploy_contracts(&env);
    let client = PaymentExecutorClient::new(&env, &f.executor_id);

    let mut params = valid_executor_params(&f);
    params.token = f.executor_id.clone();
    let result = client.try_initialize(&params);
    assert_eq!(result.unwrap_err().unwrap(), DeploymentError::SelfReference);
}

/// Re-initialization is rejected with a typed error and leaves the original
/// wiring intact.
#[test]
fn de_rejects_reinitialization() {
    let env = Env::default();
    env.mock_all_auths();
    let f = deploy_contracts(&env);
    let client = PaymentExecutorClient::new(&env, &f.executor_id);

    client
        .try_initialize(&valid_executor_params(&f))
        .unwrap()
        .unwrap();

    let result = client.try_initialize(&valid_executor_params(&f));
    assert_eq!(
        result.unwrap_err().unwrap(),
        DeploymentError::AlreadyInitialized
    );

    // Original wiring still in place: initial asset remains allowed.
    assert!(client.is_asset_allowed(&f.token));
}
