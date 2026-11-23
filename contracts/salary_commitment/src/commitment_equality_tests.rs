//! Salary commitment equality across distinct employees (#874).
//!
//! The commitment is `Poseidon(salary, blinding_factor)`: it does not depend on
//! who the employee is. Two employees with the same salary and blinding factor
//! therefore get equal commitment values, and storing one must not affect the
//! other. Different salaries must give different values.

extern crate std;

use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env};

fn setup() -> (Env, SalaryCommitmentContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(SalaryCommitmentContract, ());
    let admin = Address::generate(&env);
    let client = SalaryCommitmentContractClient::new(&env, &contract_id);
    client.init_commitment_admin(&admin);
    (env, client, admin)
}

#[test]
fn same_salary_and_blinding_give_equal_commitments_for_distinct_employees() {
    let (env, client, _admin) = setup();
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    let blinding = BytesN::from_array(&env, &[7u8; 32]);

    let c_alice = client.compute_commitment(&5_000u64, &blinding);
    let c_bob = client.compute_commitment(&5_000u64, &blinding);
    assert_eq!(c_alice, c_bob);

    client.store_commitment(&alice, &c_alice);
    client.store_commitment(&bob, &c_bob);

    assert_eq!(
        client.get_commitment(&alice).commitment,
        client.get_commitment(&bob).commitment
    );
    assert!(client.is_commitment_active(&alice));
    assert!(client.is_commitment_active(&bob));
}

#[test]
fn different_salaries_give_different_commitments() {
    let (env, client, _admin) = setup();
    let blinding = BytesN::from_array(&env, &[7u8; 32]);

    let c_5000 = client.compute_commitment(&5_000u64, &blinding);
    let c_5001 = client.compute_commitment(&5_001u64, &blinding);
    assert_ne!(c_5000, c_5001);
}

#[test]
fn storing_a_second_commitment_for_the_same_employee_is_rejected() {
    let (env, client, _admin) = setup();
    let alice = Address::generate(&env);
    let blinding = BytesN::from_array(&env, &[7u8; 32]);
    let commitment = client.compute_commitment(&5_000u64, &blinding);

    client.store_commitment(&alice, &commitment);

    let again = client.try_store_commitment(&alice, &commitment);
    assert!(again.is_err());
    assert_eq!(client.get_commitment(&alice).version, 1);
}
