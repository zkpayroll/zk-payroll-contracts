//! Events emitted by the company admin rotation flow (#875).
//!
//! Each step of the two-step rotation (propose, accept, cancel) publishes an
//! event that carries the company id, so an indexer can follow key changes.

extern crate std;

use super::*;
use soroban_sdk::testutils::{Address as _, Events as _};
use soroban_sdk::{xdr, Address, Env};

fn setup() -> (Env, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(PayrollRegistry, ());
    (env, contract_id)
}

/// Topic names (first topic) of every event recorded by the last invocation.
fn topic_names(env: &Env) -> std::vec::Vec<std::string::String> {
    let recorded = env.events().all();
    recorded
        .events()
        .iter()
        .filter_map(|event| {
            let xdr::ContractEventBody::V0(body) = &event.body;
            match body.topics.first() {
                Some(xdr::ScVal::Symbol(symbol)) => {
                    Some(std::string::String::from_utf8_lossy(symbol.0.as_slice()).into_owned())
                }
                _ => None,
            }
        })
        .collect()
}

#[test]
fn propose_emits_company_admin_proposed() {
    let (env, contract_id) = setup();
    let client = PayrollRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let company_id = client.register_company(&admin, &treasury);
    let new_admin = Address::generate(&env);

    client.propose_admin_rotation(&company_id, &admin, &new_admin);

    assert!(topic_names(&env).iter().any(|name| name == "CompanyAdminProposed"));
}

#[test]
fn accept_emits_company_admin_rotated() {
    let (env, contract_id) = setup();
    let client = PayrollRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let company_id = client.register_company(&admin, &treasury);
    let new_admin = Address::generate(&env);
    client.propose_admin_rotation(&company_id, &admin, &new_admin);

    client.accept_admin_rotation(&company_id, &new_admin);

    assert!(topic_names(&env).iter().any(|name| name == "CompanyAdminRotated"));
}

#[test]
fn cancel_emits_rotation_cancelled() {
    let (env, contract_id) = setup();
    let client = PayrollRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let company_id = client.register_company(&admin, &treasury);
    let new_admin = Address::generate(&env);
    client.propose_admin_rotation(&company_id, &admin, &new_admin);

    client.cancel_admin_rotation(&company_id, &admin);

    assert!(topic_names(&env).iter().any(|name| name == "CompanyAdminRotCancelled"));
}

#[test]
fn non_admin_proposal_is_rejected_and_emits_nothing() {
    let (env, contract_id) = setup();
    let client = PayrollRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let attacker = Address::generate(&env);
    let treasury = Address::generate(&env);
    let company_id = client.register_company(&admin, &treasury);
    let new_admin = Address::generate(&env);

    let result = client.try_propose_admin_rotation(&company_id, &attacker, &new_admin);

    assert!(result.is_err());
    assert!(!topic_names(&env).iter().any(|name| name == "CompanyAdminProposed"));
}
