//! `dp_*` — Deployment parameter validation tests for the `payroll` contract.

use crate::helpers::{deploy_contracts, network_id_of_len, valid_payroll_params, MAX_NETWORK_ID};
use payroll::{DeploymentError, PayrollClient};
use soroban_sdk::testutils::{Address as _, Events as _};
use soroban_sdk::{symbol_short, Address, Env, String, Symbol, TryIntoVal};

// ── Success path ─────────────────────────────────────────────────────────────

/// Valid parameters initialize cleanly and the initial supported asset is
/// automatically allowlisted.
#[test]
fn dp_initialize_with_valid_params_succeeds() {
    let env = Env::default();
    env.mock_all_auths();
    let f = deploy_contracts(&env);
    let client = PayrollClient::new(&env, &f.payroll_id);
    let (admin, token, verifier, commitment, treasury, treasury_owner) = valid_payroll_params(&f);

    let result = client.try_initialize(
        &admin,
        &token,
        &verifier,
        &commitment,
        &treasury,
        &treasury_owner,
    );
    assert!(result.is_ok());

    // Supported asset config: the payout token is allowlisted at init…
    assert!(client.is_asset_allowed(&token));
    // …and unrelated assets are not implicitly allowed.
    assert!(!client.is_asset_allowed(&Address::generate(&env)));

    // No network id is recorded until the operator sets one explicitly.
    assert_eq!(client.get_network_id(), None);
}

/// The initialization event carries only public configuration addresses —
/// never salary amounts, commitments, or other private payroll values.
#[test]
fn dp_initialized_event_exposes_only_public_config() {
    let env = Env::default();
    env.mock_all_auths();
    let f = deploy_contracts(&env);
    let client = PayrollClient::new(&env, &f.payroll_id);
    let (admin, token, verifier, commitment, treasury, treasury_owner) = valid_payroll_params(&f);

    client
        .try_initialize(
            &admin,
            &token,
            &verifier,
            &commitment,
            &treasury,
            &treasury_owner,
        )
        .unwrap()
        .unwrap();

    let events = env.events().all();
    assert_eq!(events.len(), 1);
    let event = events.get(0).unwrap();

    let t0: Symbol = event.1.get(0).unwrap().try_into_val(&env).unwrap();
    let t1: Symbol = event.1.get(1).unwrap().try_into_val(&env).unwrap();
    assert_eq!(t0, symbol_short!("payroll"));
    assert_eq!(t1, Symbol::new(&env, "initialized"));

    // Data is exactly the six public configuration addresses — no amounts,
    // commitments, or other private payroll values.
    let (a0, a1, a2, a3, a4, a5): (Address, Address, Address, Address, Address, Address) =
        event.2.try_into_val(&env).unwrap();
    let got = [a0, a1, a2, a3, a4, a5];
    for expected in [admin, token, verifier, commitment, treasury, treasury_owner] {
        assert!(got.contains(&expected), "unexpected address in init event");
    }
}

// ── Failure paths ────────────────────────────────────────────────────────────

/// Two dependency contracts wired to the same address are rejected.
#[test]
fn dp_rejects_duplicate_dependency_addresses() {
    let env = Env::default();
    env.mock_all_auths();
    let f = deploy_contracts(&env);
    let client = PayrollClient::new(&env, &f.payroll_id);

    // token == verifier
    let result = client.try_initialize(
        &f.admin,
        &f.token,
        &f.token,
        &f.commitment,
        &f.treasury,
        &f.treasury_owner,
    );
    assert_eq!(
        result.unwrap_err().unwrap(),
        DeploymentError::DuplicateDependency
    );

    // verifier == commitment
    let result = client.try_initialize(
        &f.admin,
        &f.token,
        &f.verifier,
        &f.verifier,
        &f.treasury,
        &f.treasury_owner,
    );
    assert_eq!(
        result.unwrap_err().unwrap(),
        DeploymentError::DuplicateDependency
    );
}

/// A role address pointing at a wired dependency contract is rejected.
#[test]
fn dp_rejects_role_colliding_with_dependency() {
    let env = Env::default();
    env.mock_all_auths();
    let f = deploy_contracts(&env);
    let client = PayrollClient::new(&env, &f.payroll_id);

    // Treasury pointing at the token contract would route payouts into the
    // token's own storage — reject it.
    let result = client.try_initialize(
        &f.admin,
        &f.token,
        &f.verifier,
        &f.commitment,
        &f.token,
        &f.treasury_owner,
    );
    assert_eq!(
        result.unwrap_err().unwrap(),
        DeploymentError::RoleConflictsWithDependency
    );

    // Admin pointing at the verifier would let verifier wiring changes gate
    // payroll administration — reject it too.
    let result = client.try_initialize(
        &f.commitment,
        &f.token,
        &f.verifier,
        &f.commitment,
        &f.treasury,
        &f.treasury_owner,
    );
    assert_eq!(
        result.unwrap_err().unwrap(),
        DeploymentError::RoleConflictsWithDependency
    );
}

/// No deployment parameter may point at the payroll contract itself.
#[test]
fn dp_rejects_self_reference() {
    let env = Env::default();
    env.mock_all_auths();
    let f = deploy_contracts(&env);
    let client = PayrollClient::new(&env, &f.payroll_id);

    let result = client.try_initialize(
        &f.admin,
        &f.payroll_id,
        &f.verifier,
        &f.commitment,
        &f.treasury,
        &f.treasury_owner,
    );
    assert_eq!(result.unwrap_err().unwrap(), DeploymentError::SelfReference);
}

/// Re-initialization is rejected with a typed error.
#[test]
fn dp_rejects_reinitialization() {
    let env = Env::default();
    env.mock_all_auths();
    let f = deploy_contracts(&env);
    let client = PayrollClient::new(&env, &f.payroll_id);
    let params = valid_payroll_params(&f);

    client
        .try_initialize(
            &params.0, &params.1, &params.2, &params.3, &params.4, &params.5,
        )
        .unwrap()
        .unwrap();

    let result = client.try_initialize(
        &params.0, &params.1, &params.2, &params.3, &params.4, &params.5,
    );
    assert_eq!(
        result.unwrap_err().unwrap(),
        DeploymentError::AlreadyInitialized
    );
}

// ── Edge cases ───────────────────────────────────────────────────────────────

/// Role addresses may coincide with each other (single-operator deployments).
#[test]
fn dp_allows_coinciding_role_addresses() {
    let env = Env::default();
    env.mock_all_auths();
    let f = deploy_contracts(&env);
    let client = PayrollClient::new(&env, &f.payroll_id);

    let result = client.try_initialize(
        &f.admin,
        &f.token,
        &f.verifier,
        &f.commitment,
        &f.admin,
        &f.admin,
    );
    assert!(result.is_ok());
}

/// An unrelated standalone contract may fill a role address — only collisions
/// with the wired dependencies are rejected.
#[test]
fn dp_allows_unrelated_contract_as_role() {
    let env = Env::default();
    env.mock_all_auths();
    let f = deploy_contracts(&env);
    let client = PayrollClient::new(&env, &f.payroll_id);

    let standalone_contract = env.register_contract(None, token::Token);
    let result = client.try_initialize(
        &f.admin,
        &f.token,
        &f.verifier,
        &f.commitment,
        &f.treasury,
        &standalone_contract,
    );
    assert!(result.is_ok());
}

// ── Network id record ────────────────────────────────────────────────────────

/// The admin can record the target network once; the value is readable and
/// announced via a public event.
#[test]
fn dp_network_id_roundtrip_and_event() {
    let env = Env::default();
    env.mock_all_auths();
    let f = deploy_contracts(&env);
    let client = PayrollClient::new(&env, &f.payroll_id);
    let params = valid_payroll_params(&f);
    client
        .try_initialize(
            &params.0, &params.1, &params.2, &params.3, &params.4, &params.5,
        )
        .unwrap()
        .unwrap();

    let passphrase = String::from_str(&env, "Test SDF Network ; September 2015");
    client
        .try_set_network_id(&f.admin, &passphrase)
        .unwrap()
        .unwrap();

    assert_eq!(client.get_network_id(), Some(passphrase.clone()));

    let events = env.events().all();
    let event = events.get(events.len() - 1).unwrap();
    let topic_sym: Symbol = event.1.get(0).unwrap().try_into_val(&env).unwrap();
    assert_eq!(topic_sym, Symbol::new(&env, "network_id_set"));
    let (recorded, _timestamp): (String, u64) = event.2.try_into_val(&env).unwrap();
    assert_eq!(recorded, passphrase);
}

/// An empty network id is rejected.
#[test]
fn dp_network_id_rejects_empty() {
    let env = Env::default();
    env.mock_all_auths();
    let f = deploy_contracts(&env);
    let client = PayrollClient::new(&env, &f.payroll_id);
    let params = valid_payroll_params(&f);
    client
        .try_initialize(
            &params.0, &params.1, &params.2, &params.3, &params.4, &params.5,
        )
        .unwrap()
        .unwrap();

    let result = client.try_set_network_id(&f.admin, &String::from_str(&env, ""));
    assert_eq!(
        result.unwrap_err().unwrap(),
        DeploymentError::InvalidNetworkId
    );
    assert_eq!(client.get_network_id(), None);
}

/// Network ids up to `MAX_NETWORK_ID_LEN` characters are accepted; anything
/// longer is rejected.
#[test]
fn dp_network_id_length_bounds() {
    let env = Env::default();
    env.mock_all_auths();
    let f = deploy_contracts(&env);
    let client = PayrollClient::new(&env, &f.payroll_id);
    let params = valid_payroll_params(&f);
    client
        .try_initialize(
            &params.0, &params.1, &params.2, &params.3, &params.4, &params.5,
        )
        .unwrap()
        .unwrap();

    // Exactly at the limit is accepted.
    let at_limit = network_id_of_len(&env, MAX_NETWORK_ID);
    client
        .try_set_network_id(&f.admin, &at_limit)
        .unwrap()
        .unwrap();
    assert_eq!(client.get_network_id(), Some(at_limit));

    // Over the limit on a fresh deployment is rejected.
    let f2 = deploy_contracts(&env);
    let client2 = PayrollClient::new(&env, &f2.payroll_id);
    let p2 = valid_payroll_params(&f2);
    client2
        .try_initialize(&p2.0, &p2.1, &p2.2, &p2.3, &p2.4, &p2.5)
        .unwrap()
        .unwrap();
    let over_limit = network_id_of_len(&env, MAX_NETWORK_ID + 1);
    let result = client2.try_set_network_id(&f2.admin, &over_limit);
    assert_eq!(
        result.unwrap_err().unwrap(),
        DeploymentError::InvalidNetworkId
    );
}

/// The network id is immutable once recorded.
#[test]
fn dp_network_id_immutable_after_set() {
    let env = Env::default();
    env.mock_all_auths();
    let f = deploy_contracts(&env);
    let client = PayrollClient::new(&env, &f.payroll_id);
    let params = valid_payroll_params(&f);
    client
        .try_initialize(
            &params.0, &params.1, &params.2, &params.3, &params.4, &params.5,
        )
        .unwrap()
        .unwrap();

    let first = String::from_str(&env, "Test SDF Network ; September 2015");
    client
        .try_set_network_id(&f.admin, &first)
        .unwrap()
        .unwrap();

    let second = String::from_str(&env, "Public Global Stellar Network ; September 2015");
    let result = client.try_set_network_id(&f.admin, &second);
    assert_eq!(
        result.unwrap_err().unwrap(),
        DeploymentError::NetworkIdAlreadySet
    );
    assert_eq!(client.get_network_id(), Some(first));
}

/// Only the configured admin can record the network id.
#[test]
#[should_panic(expected = "Unauthorized")]
fn dp_network_id_requires_admin() {
    let env = Env::default();
    env.mock_all_auths();
    let f = deploy_contracts(&env);
    let client = PayrollClient::new(&env, &f.payroll_id);
    let params = valid_payroll_params(&f);
    client
        .try_initialize(
            &params.0, &params.1, &params.2, &params.3, &params.4, &params.5,
        )
        .unwrap()
        .unwrap();

    let attacker = Address::generate(&env);
    client.set_network_id(
        &attacker,
        &String::from_str(&env, "Test SDF Network ; September 2015"),
    );
}

/// Configuration calls before initialization are rejected.
#[test]
fn dp_network_id_before_initialize_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let f = deploy_contracts(&env);
    let client = PayrollClient::new(&env, &f.payroll_id);

    let result = client.try_set_network_id(&f.admin, &String::from_str(&env, "Test SDF Network"));
    assert_eq!(
        result.unwrap_err().unwrap(),
        DeploymentError::NotInitialized
    );
}
