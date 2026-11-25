//! Commitment scheme version validation (issue #897).
//!
//! A commitment produced under a scheme the payroll circuit cannot verify must
//! be rejected at store time, without reserving the commitment value or
//! leaving a partial record behind.
extern crate std;

use super::*;
use soroban_sdk::testutils::Address as _;

fn setup() -> (Env, SalaryCommitmentContractClient<'static>) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(SalaryCommitmentContract, ());
    let client = SalaryCommitmentContractClient::new(&env, &contract_id);
    client.init_commitment_admin(&Address::generate(&env));
    (env, client)
}

fn value(env: &Env, n: u8) -> BytesN<32> {
    BytesN::from_array(env, &[n; 32])
}

#[test]
fn supported_scheme_is_stored_and_reported() {
    let (env, client) = setup();
    let employee = Address::generate(&env);

    let stored = client.store_commitment_with_scheme(
        &employee,
        &value(&env, 1),
        &COMMITMENT_SCHEME_POSEIDON_V1,
    );

    assert_eq!(stored.version, 1);
    assert_eq!(
        client.get_commitment_scheme(&employee),
        Some(COMMITMENT_SCHEME_POSEIDON_V1)
    );
    assert!(client.is_commitment_active(&employee));
}

#[test]
fn legacy_store_reports_the_v1_scheme() {
    let (env, client) = setup();
    let employee = Address::generate(&env);
    client.store_commitment(&employee, &value(&env, 2));

    assert_eq!(
        client.get_commitment_scheme(&employee),
        Some(COMMITMENT_SCHEME_POSEIDON_V1)
    );
    assert_eq!(client.get_commitment_scheme(&Address::generate(&env)), None);
}

#[test]
fn supported_versions_are_exactly_the_published_list() {
    let (_env, client) = setup();
    assert!(client.is_supported_scheme_version(&COMMITMENT_SCHEME_POSEIDON_V1));
    for invalid in [0u32, 2, u32::MAX] {
        assert!(
            !client.is_supported_scheme_version(&invalid),
            "{invalid} must be unsupported"
        );
    }
}

#[test]
#[should_panic(expected = "Invalid commitment scheme version")]
fn zero_scheme_version_is_rejected() {
    let (env, client) = setup();
    client.store_commitment_with_scheme(&Address::generate(&env), &value(&env, 3), &0);
}

#[test]
#[should_panic(expected = "Invalid commitment scheme version")]
fn future_scheme_version_is_rejected() {
    let (env, client) = setup();
    client.store_commitment_with_scheme(
        &Address::generate(&env),
        &value(&env, 4),
        &(COMMITMENT_SCHEME_POSEIDON_V1 + 1),
    );
}

#[test]
fn rejected_scheme_leaves_no_record_and_does_not_reserve_the_value() {
    let (env, client) = setup();
    let employee = Address::generate(&env);
    let commitment = value(&env, 5);

    assert!(client
        .try_store_commitment_with_scheme(&employee, &commitment, &u32::MAX)
        .is_err());
    assert!(!client.has_commitment(&employee));
    assert_eq!(client.get_commitment_scheme(&employee), None);

    // The same employee and value can then be stored with a valid scheme.
    client.store_commitment_with_scheme(&employee, &commitment, &COMMITMENT_SCHEME_POSEIDON_V1);
    assert_eq!(client.get_commitment(&employee).commitment, commitment);
}
